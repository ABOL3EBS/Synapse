# Synapse IPS — Day Report
## 2026-07-20

---

## 1. What was built today

Milestone 1 was completed end-to-end: BPF capture → SCM_RIGHTS fd-passing → typed IPC → pf enforcement (block, unblock, kill state). Every component was verified against real terminal output — not summaries, not "should work."

### Commits (chronological)

| Hash | Description |
|---|---|
| `67b8d02` | BPF raw ioctls + IPv4+IPv6 filter — helper opens BPF, agent reads packets |
| `d0d2ee7` | Fix BPF filter name (`BPF_IPV4_IPV6_FILTER`) + STATUS.md |
| `53ef67b` | Update opencode.json permission config |
| `376e4df` | EnforcementBackend trait + MacOsEnforcementBackend (§4c) |
| `f2351f2` | apply_block() dedup fix — keeps original TTL on re-flag |
| `496f65c` | STATUS.md + crate context maps for agentic workflow |
| `b7c82a9` | Doc restructure — ~75% token reduction across context files |
| `0869168` | **KillState fix + SockFprog.len u32 + pf enable + anchor flush** |
| `20a6dd0` | context.md + STATUS.md updates for Step 3 |
| `7806d26` | opencode.md rewrite — full agent context with conventions and workflow |
| `c09fb23` | Futuristic README with ASCII title |

---

## 2. Bugs found and fixed

### Bug 1: `SockFprog.len` type mismatch
- **File:** `helper/main.rs` (struct `SockFprog`)
- **Was:** `len: u16` (2 bytes)
- **C struct:** `bf_len` is `unsigned int` (4 bytes)
- **Impact:** Kernel read garbage in upper 2 bytes → `EINVAL` on every BPF device. BIOCSETF silently failed on every `/dev/bpf*` — the BPF filter was never actually set.
- **Fix:** `u16` → `u32`
- **Found during:** Step 3, when testing KillState and discovering no states were created

### Bug 2: KillState pfctl syntax
- **File:** `helper/main.rs:285-304` (old)
- **Was:** `-k "proto from src to dst"` — one formatted string
- **Correct:** `-k src -k dst` — separate flags per `man pfctl`
- **Impact:** `pfctl` error on every KillState command
- **Fix:** Added `kill_state()` to `EnforcementBackend` trait, implemented with correct syntax

### Bug 3: PF never enabled
- **File:** `helper/main.rs`
- **Was:** Helper loaded rules but never called `pfctl -e`
- **Impact:** pf Status: Disabled. No rules evaluated. No states created. No blocks enforced.
- **Fix:** Added `pfctl -e` after `ensure_anchor()` — reference counted, safe to call

### Bug 4: Anchor never referenced from main ruleset
- **File:** `helper/main.rs` (`ensure_anchor()`)
- **Was:** Rules loaded into anchor via `pfctl -a com.synapse.ips -f -`, but `/etc/pf.conf` had no `anchor "com.synapse.ips"` line
- **Impact:** pf never dispatched to the anchor — rules existed but were never evaluated
- **Fix:** `ensure_anchor()` now checks `/etc/pf.conf`, appends the anchor line if missing, reloads main ruleset with `pfctl -f /etc/pf.conf`

### Bug 5: Stale anchor rules from manual testing
- **File:** `helper/main.rs` (`ensure_anchor()`)
- **Was:** No flush before loading rules
- **Impact:** Manual `pfctl -T add` tests from Step 2 left stale rules in the anchor that didn't match what our code writes
- **Fix:** Added `pfctl -a com.synapse.ips -F all` flush at the start of `ensure_anchor()`

---

## 3. Current architecture — detailed

### Process model

```
synapsed-helper (root, launchd)         synapse-agent (unprivileged)
┌──────────────────────────────┐       ┌───────────────────────────────┐
│ 1. Open /dev/bpf*            │       │ 1. Receive fd via SCM_RIGHTS  │
│ 2. Set buffer (BIOCSBLEN)    │       │ 2. Query BIOCGBLEN            │
│ 3. Bind interface (BIOCSETIF) │       │ 3. Raw read() from fd         │
│ 4. Immediate mode (BIOCIMMEDIATE)     │ 4. Parse BpfHdr (20 bytes)   │
│ 5. Set filter (BIOCSETF)     │──fd──▶│ 5. Parse IPv4/IPv6 frames    │
│ 6. Flush + load pf anchor    │       │ 6. Send typed Block/Unblock   │
│ 7. Enable pf (pfctl -e)      │◀─IPC──│    commands via bincode IPC   │
│ 8. SCM_RIGHTS fd handoff     │       │ 7. KillState via backend      │
│ 9. Enforcement loop           │       │                               │
│    Block → apply_block()     │       └───────────────────────────────┘
│    Unblock → remove_block()  │
│    KillState → kill_state()  │
└──────────────────────────────┘
```

### Privilege boundary

| Operation | Runs as | File |
|---|---|---|
| Open `/dev/bpf*` | root | `helper/main.rs` |
| Set BPF ioctls | root | `helper/main.rs` |
| SCM_RIGHTS fd-passing | root (send), unprivileged (recv) | `protocol.rs` |
| `pfctl` execution | root | `helper/enforce.rs` ONLY |
| pf anchor management | root | `helper/main.rs` |
| Packet parsing | unprivileged | `agent/main.rs` |
| IPC message handling | unprivileged | `agent/main.rs` |

A bug in packet parsing, DNS resolution, or ML inference is never a root exploit — it runs in the agent process.

### BPF setup — ioctl ordering

```
open(/dev/bpfN)
  → BIOCSBLEN (set buffer size, 1MB)
  → BIOCSETIF (bind to en0)
  → BIOCIMMEDIATE (deliver packets immediately)
  → BIOCSETF (set filter program)
```

**Critical:** BIOCSBLEN must come before BIOCSETIF. The bpf(4) man page says: "The buffer must be set before the file is attached to an interface with BIOCSETIF."

### BPF filter

5-instruction program that passes IPv4 (0x0800) and IPv6 (0x86DD) traffic, drops everything else:

```
[0] LD [12]              — load 2-byte EtherType from Ethernet header
[1] JEQ 0x0800, jt=2     — IPv4? → jump to [4]
[2] JEQ 0x86DD, jt=1     — IPv6? → jump to [4]
[3] RET 0                — neither → drop
[4] RET 65535            — pass full packet
```

### `SockFprog` struct (C interop)

```rust
#[repr(C)]
struct SockFprog {
    len: u32,              // MUST be u32 — matches C's unsigned int bf_len
    filter: *const SockFilter,
}
```

**Must be `repr(C)` and `len` must be `u32`.** The kernel reads 4 bytes for `bf_len`. If `len` is `u16`, the upper 2 bytes are garbage → `EINVAL`.

### BPF packet parsing

```
BpfHdr (20 bytes, timeval32):
  tv_sec:  i32     (4 bytes)
  tv_usec: i32     (4 bytes)
  bh_caplen: u32   (4 bytes)
  bh_datalen: u32  (4 bytes)
  bh_hdrlen: u16   (2 bytes)
  Total: 20 bytes

Next packet offset: BPF_WORDALIGN(bh_hdrlen + bh_caplen)
BPF_WORDALIGN = 4 (align up to 4-byte boundary)
```

### IPC protocol

**fd-passing (SCM_RIGHTS):**
- Helper sends BPF fd to agent via `sendmsg()` with `SCM_RIGHTS` control message
- Agent receives via `recvmsg()` with `CMSG_SPACE` buffer
- Helper drops its copy after sending — agent solely owns the fd

**Message framing:**
- 4-byte big-endian length prefix
- Bincode-serialized payload
- Max 1MB per message
- Magic bytes: `SYNP` (not currently checked on receive)

**Command types:**
```rust
enum EnforcementCommand {
    Block { ip: IpAddr, ttl: Duration },
    Unblock { ip: IpAddr },
    KillState { src: IpAddr, dst: IpAddr, proto: u8 },
}
```

All fields are typed (`IpAddr`, `Duration`, `u8`) — never strings. Shell injection is structurally impossible.

### EnforcementBackend trait

```rust
pub trait EnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
    fn kill_state(&mut self, src: IpAddr, dst: IpAddr, proto: u8) -> Result<EnforcementReceipt, String>;
    fn reconcile(&mut self, desired: &DesiredFirewallState) -> Result<ReconciliationReport, String>;
}
```

Only implementer: `MacOsEnforcementBackend` in `helper/enforce.rs`.

### MacOsEnforcementBackend

| Method | pfctl command | Notes |
|---|---|---|
| `apply_block()` | `pfctl -a com.synapse.ips -t synapse_blocklist -T add <ip>` | Idempotent — dedup in `HashSet`, keeps original TTL |
| `remove_block()` | `pfctl -a com.synapse.ips -t synapse_blocklist -T delete <ip>` | Removes from `active_blocks` |
| `kill_state()` | `pfctl -k <src> -k <dst>` | Kills all states for src→dst pair (no protocol filter) |
| `reconcile()` | Stub | Returns `ReconciliationReport::default()` |

**apply_block() dedup logic:**
- If IP already in `active_blocks`: re-issue `block_ip()` (idempotent), do NOT spawn a second timer
- Two timers for the same IP = whichever fires first unblocks it, losing the intended duration
- v1 tradeoff: one OS thread per active block, no cap

**kill_state() notes:**
- `pfctl -k` does NOT filter by protocol — it kills all states (TCP, UDP, etc.) for the src/dst pair
- The `proto` field is kept for logging and future use
- Verified: `killed 1 state from 1 sources and 1 destinations`, confirmed gone in `pfctl -s state -vv`

### pf anchor lifecycle

```
ensure_anchor():
  1. pfctl -a com.synapse.ips -F all        (flush stale rules)
  2. pfctl -a com.synapse.ips -f -           (load rules via stdin)
      table <synapse_blocklist> persist
      block out quick to <synapse_blocklist>
      block in quick from <synapse_blocklist>
  3. Check /etc/pf.conf for anchor line      (idempotent)
     Append: anchor "com.synapse.ips" all    (if missing)
  4. pfctl -f /etc/pf.conf                   (reload main ruleset)

pfctl -e                                      (enable pf, reference counted)
```

**Why each step matters:**
1. Flush: clears stale rules from previous runs or manual testing
2. Load: creates the table and block-out/block-in rules in the anchor
3. Anchor reference: without this, pf never evaluates the anchor — rules exist but are never dispatched to
4. Reload: makes the anchor reference active in the running ruleset
5. Enable: pf starts disabled — `pfctl -e` increments the enable count

### Anchor rules behavior

```
table <synapse_blocklist> persist          ← dynamic IP list
block out quick to <synapse_blocklist>     ← outbound TO blocked IPs blocked
block in quick from <synapse_blocklist>    ← inbound FROM blocked IPs blocked
```

When an IP is added to the table:
- Outbound traffic to that IP: blocked (SYN dropped before state creation)
- Inbound traffic from that IP: blocked (separate attack direction — stops
  remote hosts from initiating contact toward this machine, independent of
  whether we also block outbound to them)
- Existing states: killed via KillState command

**Note:** The original Milestone 1 rules used `pass out quick to <blocklist>`
instead of `block out`. This was a bug, not a design choice — outbound
connections to blocked IPs succeeded and created pf state entries. Confirmed
by curl/nc tests against 8.8.8.8 while in the blocklist: TCP connected and
pf state showed an entry. Fixed by changing `pass out` → `block out`.

---

## 4. File inventory

| File | Lines | Purpose |
|---|---|---|
| `crates/common/src/lib.rs` | 81 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, IPC constants |
| `crates/common/src/types.rs` | 62 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport` |
| `crates/platform-macos/src/helper/main.rs` | 347 | Root daemon — BPF ioctls, fd handoff, pf anchor, enforcement loop |
| `crates/platform-macos/src/helper/enforce.rs` | 180 | `MacOsEnforcementBackend` — only pfctl executor |
| `crates/agent/src/main.rs` | 289 | Unprivileged — BPF reads, IPv4+IPv6 parsing, IPC |
| `crates/platform-macos/src/protocol.rs` | 112 | SCM_RIGHTS fd-passing + bincode IPC |
| `crates/platform-macos/src/lib.rs` | 11 | Re-exports `pub mod protocol` |
| **Total** | **1,082** | |

### Dependencies

| Crate | Dependencies |
|---|---|
| `synapse-common` | serde 1.x, bincode 1.x |
| `synapse-platform-macos` | synapse-common, libc 0.2, serde 1.x, bincode 1.x, log 0.4, env_logger 0.11 |

### Documentation files

| File | Purpose |
|---|---|
| `opencode.md` | Agent context — hard rules, conventions, architecture, status |
| `doc/STATUS.md` | What's built (source of truth) |
| `doc/Synapse-IPS-Architecture.md` | Design blueprint (~500 lines) |
| `crates/common/context.md` | Module map + trait signatures |
| `crates/platform-macos/context.md` | Call trees with line numbers |
| `README.md` | Human-facing overview with ASCII art |

---

## 5. What's next (not built)

Per §6 architecture doc, the order is:

1. ~~BPF capture~~ ✅
2. ~~SCM_RIGHTS fd-passing~~ ✅
3. ~~Typed IPC (Block/Unblock/KillState)~~ ✅
4. ~~pf enforcement end-to-end~~ ✅
5. **Enrichment** — async DNS, geo, process attribution via libproc
6. **Detector framework** — `Detector` trait + Rule engine + ONNX inference
7. **Flow tracker** — in-memory session window (~100ms ticks)
8. **Decision engine** — weighted scoring, policy thresholds
9. **Storage** — SQLite (WAL mode), single-writer worker
10. **Dashboard** — Tauri + React

### Stub: `reconcile()`

Returns `Ok(ReconciliationReport::default())`. Real reconciliation (§4a) = detect-and-recover from anchor eviction by other tools. Separate work item.

---

## 6. Testing methodology

Every step was verified with real terminal output:

- `pfctl -s state -vv` before/after for state table changes
- `pfctl -a com.synapse.ips -t synapse_blocklist -T show` for table verification
- `pfctl -k src -k dst` with confirmed `killed 1 state` output
- `cargo build` after every code change
- `man pfctl` consulted before assuming syntax
- User ran all sudo commands manually (agent session cannot run sudo)

### Key test results

| Test | Result |
|---|---|
| BPF open + bind + filter | ✅ BPF filter set (IPv4 + IPv6) |
| Agent receives fd via SCM_RIGHTS | ✅ fd received, BIOCGBLEN returns 1048576 |
| Agent parses ICMP/TCP/UDP | ✅ IPv4 + IPv6 on en0 |
| Helper adds IP to pf table | ✅ `1/1 addresses added` |
| Helper removes IP from pf table | ✅ Table empty after delete |
| KillState kills real state | ✅ `killed 1 state from 1 sources and 1 destinations` |
| State confirmed gone | ✅ `pfctl -s state -vv \| grep 8.8.8.8` = empty |
| pf enabled after helper start | ✅ `Status: Enabled for 0 days 00:00:52` |
| Anchor active in main ruleset | ✅ `pfctl -sr \| grep synapse` shows rules |
| Outbound block verified | ✅ curl to 8.8.8.8 times out, `pfctl -s state -vv \| grep 8.8.8.8` = empty (no state created) |
