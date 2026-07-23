# Synapse IPS — Day Report

## 2026-07-22

---

### What was done today

**1. Port→PID cache — full pipeline built and verified end-to-end.**

Apple DTS confirmed there is no sysctl MIB to query which process owns a socket on macOS. The only mechanism is a per-process fd scan. Today we built the complete pipeline: `build_port_pid_cache()` scans all processes via `proc_listpids(PROC_ALL_PIDS)`, enumerates each process's fds via `proc_pidinfo(PROC_PIDLISTFDS)`, and probes each socket fd via `proc_pidinfo(PROC_PIDFDINFO)` to extract `SocketFDInfo`. The cache is serialized into `PortPidCache`, sent to the agent via the existing SCM_RIGHTS IPC channel every 5 seconds, and used to resolve `src_port → PID → executable path` on every packet.

**Port byte-order fix.** `insi_lport` and `insi_fport` in `InSockInfo` are stored as big-endian u16 in the first 2 bytes of a `c_int` field. On little-endian ARM, reading the full `c_int` as native-endian gives a wrong value (e.g., port 60202 → c_int 10987). Fixed with `read_port_be()` — reads 2 raw bytes at a hardcoded offset and applies `u16::from_be_bytes`. Offsets (268 for lport, 264 for fport) were verified by 3 independent tests against lsof ground truth.

**NULL pointer bug.** `proc_listpids` and `proc_pidinfo` distinguish NULL pointer (query size) from non-null with size=0 (returns 0 silently). Passing a zeroed buffer with size=0 returned 0 fds. Fixed by passing `std::ptr::null_mut()` for size queries.

**Stack-copy offset bug.** Computing struct field offsets via `&(*copy).field` on a `ptr::read()` copy gives garbage addresses — it measures distance to the stack-local copy, not the original struct. Fixed by using pointer arithmetic on the original struct.

**libproc integration.** Added `libproc = "0.14"` dependency to `platform-macos/Cargo.toml`. The crate provides typed `#[repr(C)]` structs (via bindgen) for all FFI: `SocketFDInfo` (792 bytes), `SocketInfo` (768), `SocketInfoProto` (528), `InSockInfo` (80), `ProcFDInfo` (8). Struct sizes verified by `test_struct_sizes`.

**IPC extended.** `IpcMessage` enum now carries `PortPidCache`. Agent-side IPC reader thread receives cache, stores in `Arc<Mutex<HashMap<(u16, u8), u32>>>`. Main loop locks cache, resolves `src_port` first, `dst_port` fallback, passes PID to flow tracker.

**Live E2E verified.** Helper sends 49–51 entries (~483 PIDs, ~6675 fds, ~7–8ms root scan). Agent receives cache, resolves Brave Browser connection to `pid=743 → Brave Browser Helper`.

---

**2. Flow tracker — in-memory session window built and verified.**

Replaced the placeholder per-destination `HashSet<IpAddr>` with a proper flow tracker. Every unique `(src_ip, src_port, dst_ip, dst_port, proto)` tuple creates a `FlowRecord` with timestamps, packet/byte counts, local_port, PID, and enrichment attachment slots.

**Direction-agnostic canonicalization.** `FlowKey` sorts `(ip, port)` as bound pairs — forward and response packets produce the same key. This means a TCP SYN and its ACK both update the same flow. The canonicalization is: if `(ip_a, port_a)` > `(ip_b, port_b)`, swap them. This is correct because flow tracking is about the session, not the direction.

**local_port stored separately.** The canonical key discards direction, but port→PID cache lookup requires knowing which side is local. `local_port` is set once at flow creation from the original packet's `src_port` (or `dst_port` if src is remote), independent of the key's ordering.

**PID stored once.** Resolved at creation from `local_port` via port→PID cache. Not updated after — process may change, but PID is a snapshot at creation time.

**poll()-based capture loop.** Replaced blocking `read()` with `poll()` + 100ms timeout. `tick()` fires on every iteration (even on timeout), expiring flows older than 5 seconds. This ensures memory is reclaimed on quiet networks, not only on packet arrival.

**MAX_FLOWS eviction.** Hard cap of 100,000 concurrent flows. On overflow, oldest flow (by `first_seen`) is evicted with a warning log. Prevents unbounded memory growth under heavy traffic.

**Enrichment attachment.** `attach_enrichment()` merges DNS, process path, GeoIP, and reputation results into the flow record. Results arrive asynchronously from the enrichment worker pool — never gate the hot path.

**9 unit tests pass.** Canonicalization (forward/response identity, loopback, IPv6, different protocols), new vs existing flow, forward+response same flow, max flows eviction, tick expiry, attach enrichment.

---

**3. Enrichment pipeline fixes.**

Added `flow_id: u64` field to `EnrichmentResult` so enrichment results can be routed back to the correct flow. All 7 `EnrichmentResult` constructors in `enrichment/mod.rs` updated. Main.rs capture loop now attaches results to flows via `tracker.attach_enrichment()`.

---

**4. Logging improvements.**

Flow creation now logs at INFO level: `flow N created: src → dst (proto=X, local_port=Y, pid=Z)`. Tick expiry logs at INFO level: `tick: expired M flows (N remaining)`. Failed enrichment results logged at DEBUG level. These changes made the flow tracker observable without needing `RUST_LOG=debug`.

---

### Architecture — detailed

#### Process model (current state)

```
synapsed-helper (root)                   synapse-agent (unprivileged)
┌──────────────────────────────┐        ┌────────────────────────────────────┐
│ 1. Open /dev/bpf*            │        │ 1. Receive fd via SCM_RIGHTS      │
│ 2. Set buffer (BIOCSBLEN)    │        │ 2. Query BIOCGBLEN                │
│ 3. Bind interface (BIOCSETIF) │        │ 3. Raw read() from fd             │
│ 4. Immediate mode            │──fd───▶│ 4. Parse BpfHdr + IPv4/IPv6       │
│ 5. Set filter (BIOCSETF)     │        │ 5. Resolve local_port + PID       │
│ 6. Flush + load pf anchor    │        │ 6. Feed to FlowTracker            │
│ 7. Enable pf (pfctl -e)      │        │ 7. Dispatch enrichment (async)    │
│ 8. SCM_RIGHTS fd handoff     │        │ 8. Attach results to flows        │
│ 9. Cache-push thread (5s)    │──IPC──▶│ 9. Send Block/Unblock commands    │
│    → PortPidCache            │◀───────│                                   │
│ 10. Enforcement loop         │        └────────────────────────────────────┘
│    Block → apply_block()     │
│    Unblock → remove_block()  │
│    KillState → kill_state()  │
└──────────────────────────────┘
```

#### Data flow — packet to flow record

```
BPF fd → read() → BpfHdr parsing → parse_ip_frame() → PacketInfo
                                                            │
                                                            ▼
                                              ┌─────────────────────────┐
                                              │ Port→PID Cache Lookup   │
                                              │  src_port → PID?        │
                                              │  else dst_port → PID?   │
                                              │  else (0, None)         │
                                              └────────────┬────────────┘
                                                           │
                                                           ▼
                                              ┌─────────────────────────┐
                                              │ FlowTracker::update()   │
                                              │  FlowKey::canonicalize() │
                                              │  if new: create record  │
                                              │  if existing: update    │
                                              └────────────┬────────────┘
                                                           │
                                                           ▼
                                              ┌─────────────────────────┐
                                              │ Enrichment Dispatch     │
                                              │  DnsReverse (getnameinfo)│
                                              │  ProcessAttribution     │
                                              │  GeoIp (stub)           │
                                              │  Reputation (stub)      │
                                              └────────────┬────────────┘
                                                           │
                                              ┌─────────────────────────┐
                                              │ drain_results()         │
                                              │  attach_enrichment()    │
                                              │  → FlowRecord populated │
                                              └─────────────────────────┘
```

#### FlowKey canonicalization

```rust
pub struct FlowKey {
    pub ip_a: IpAddr,   // lower IP
    pub port_a: u16,    // lower port
    pub ip_b: IpAddr,   // higher IP
    pub port_b: u16,    // higher port
    pub protocol: u8,
}
```

If `(src_ip, src_port)` > `(dst_ip, dst_port)` lexicographically, swap them. This ensures:
- `192.168.1.1:50000 → 8.8.8.8:443` and `8.8.8.8:443 → 192.168.1.1:50000` produce the same key
- Loopback (`127.0.0.1:12345 → 127.0.0.1:80`) is handled correctly
- IPv6 addresses compared by `Ord` implementation

#### Port→PID cache structure

```rust
// Key: (port, protocol) — u16 + u8
// Value: PID of the process owning that socket
type PortPidCache = HashMap<(u16, u8), u32>;
```

Lookup priority: `src_port` first (correct for outbound traffic), `dst_port` fallback (correct for inbound). Cache refreshed every 5 seconds by helper's root-scanning thread.

#### SocketFDInfo struct layout (verified by tests)

```
SocketFDInfo (792 bytes total):
  [0..24)    prefix (includes ProcFDInfo at offset 8)
  [24..792)  psi: SocketInfo (768 bytes)
             VInfoStat (136 bytes) at start
             soi_proto (SocketInfoProto, 528 bytes) at offset 264 from start
               pri_in: InSockInfo at offset 264
                 insi_fport: c_int at offset 264 (BE u16 in first 2 bytes)
                 insi_lport: c_int at offset 268 (BE u16 in first 2 bytes)
```

Hardcoded offsets `OFF_LPORT=268`, `OFF_FPORT=264` verified by 3 independent tests against lsof ground truth. Known shortcoming: fragile if Apple changes struct layout.

---

### Commits (chronological)

| Hash | Description |
|---|---|
| `2f304e5` | **feat: end-to-end port→PID cache with libproc typed structs and SCM_RIGHTS IPC** — 10 files, +766/-79. libproc FFI, `read_port_be()`, `build_port_pid_cache()`, `probe_socket()`, IPC reader thread, PID lookup wired in agent |
| `ee190bb` | **feat: in-memory flow tracker with direction-agnostic canonicalization, ~100ms ticks, and enrichment attachment** — 9 files, +915/-67. FlowTracker, FlowKey, FlowRecord, poll()-based capture loop, enrichment integration, 9 tests |

---

### Bugs found

#### Bug 7: Port byte-order on little-endian ARM
- **File:** `process_lookup.rs` (`probe_socket()`)
- **Was:** Reading `insi_lport`/`insi_fport` as `c_int` (native-endian) — gives wrong value on LE ARM (port 60202 → c_int 10987)
- **Fix:** `read_port_be()` — raw BE bytes at hardcoded offsets, `u16::from_be_bytes`
- **Verified:** `test_probe_socket_lport` and `test_probe_socket_fport` match lsof ground truth

#### Bug 8: NULL pointer vs non-null empty buffer
- **File:** `process_lookup.rs` (`list_all_pids()`, `list_pid_fds()`)
- **Was:** Passing zeroed buffer with size=0 to `proc_listpids`/`proc_pidinfo` — returns 0 silently (interprets as "no space" not "query size")
- **Fix:** Pass `std::ptr::null_mut()` for size queries
- **Impact:** Without this fix, port→PID cache was always empty

#### Bug 9: Stack-copy offset computation
- **File:** `process_lookup.rs` (`probe_socket()`)
- **Was:** `&(*copy).field` on a `ptr::read()` copy — measures distance to stack-local copy, not original struct
- **Fix:** Pointer arithmetic on original struct (`&mut si.field as *mut T as usize - &mut si as *mut T as usize`)
- **Impact:** All struct field offsets were garbage

---

### File inventory (current)

| File | Lines | Purpose |
|---|---|---|
| `crates/common/src/lib.rs` | 96 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `IpcMessage` re-export |
| `crates/common/src/types.rs` | 150 | `ValidatedBlock`, `BlockId`, `EnforcementReceipt`, `PortPidCache`, `IpcMessage`, `EnrichmentRequest/Result/Kind` |
| `crates/platform-macos/src/helper/main.rs` | 389 | Root daemon — BPF ioctls, fd handoff, pf anchor, enforcement loop, cache-push thread |
| `crates/platform-macos/src/helper/enforce.rs` | 178 | `MacOsEnforcementBackend` — only pfctl executor |
| `crates/platform-macos/src/protocol.rs` | 112 | SCM_RIGHTS fd-passing + bincode IPC |
| `crates/platform-macos/src/process_lookup.rs` | 668 | `libproc` FFI — `build_port_pid_cache`, `probe_socket`, `read_port_be`, `lookup_process` |
| `crates/agent/src/main.rs` | 626 | Unprivileged — BPF reads, IPv4/IPv6, flow tracker, enrichment, IPC reader thread, `determine_local_port()` extracted |
| `crates/agent/src/flow/mod.rs` | 574 | In-memory session window — `FlowKey`, `FlowRecord`, `FlowTracker`, canonicalization, eviction |
| `crates/agent/src/enrichment/mod.rs` | 495 | 4-thread worker pool — DNS reverse, process attribution, GeoIP/Reputation stubs |
| **Total** | **3,424** | |

---

### Test results (26 tests)

| Test | Result |
|---|---|
| `test_lookup_own_pid` | ✅ resolves own executable path and start time |
| `test_lookup_invalid_pid` | ✅ fails correctly for nonexistent PID |
| `test_build_port_pid_cache` | ✅ 39–53 entries, ~500 PIDs, ~5000 fds, ~2ms |
| `test_probe_socket_lport` | ✅ lport matches lsof ground truth |
| `test_probe_socket_fport` | ✅ fport matches lsof ground truth |
| `test_struct_sizes` | ✅ verifies struct sizes, offsets, read_port_be vs lsof |
| `test_enrichment_pool_dispatch_and_collect` | ✅ 4-thread pool dispatches and collects results |
| `test_is_public_ip` | ✅ public vs private IP classification |
| `test_dns_reverse_localhost` | ✅ resolves `127.0.0.1` to `localhost` |
| `test_canonicalization_forward_and_response_produce_same_key` | ✅ direction-agnostic |
| `test_canonicalization_same_ip_loopback` | ✅ loopback handled correctly |
| `test_canonicalization_ipv6` | ✅ IPv6 canonicalization works |
| `test_canonicalization_different_protocols_are_different_flows` | ✅ TCP≠UDP |
| `test_update_returns_new_vs_existing` | ✅ NewFlow vs ExistingFlow |
| `test_forward_and_response_update_same_flow` | ✅ SYN+ACK same flow |
| `test_max_flows_evicts_oldest` | ✅ oldest evicted at MAX_FLOWS |
| `test_tick_expires_old_flows` | ✅ flows expire after FLOW_EXPIRY_SECS |
| `test_attach_enrichment` | ✅ enrichment attaches to flow record |
| `test_canonicalization_swap_case_local_ip_larger` | ✅ swap case (local IP > remote IP) produces identical key |
| `test_local_port_independent_of_canonical_ordering` | ✅ local_port=50000, not canonical a_port=443 |
| `test_enrichment_dispatched_per_flow_not_per_ip` | ✅ per-flow dispatch (documented v1 inefficiency) |
| `test_tick_fires_on_wall_clock_not_packet_count` | ✅ expiry based on Instant::now(), not packet count |
| `test_determine_local_port_inbound_real_code_path` | ✅ inbound 8.8.8.8:443→local_ip:50000 → local_port=50000 (real code path) |
| `test_determine_local_port_outbound_real_code_path` | ✅ outbound local_ip:50000→8.8.8.8:443 → local_port=50000 (real code path) |
| `test_determine_local_port_neither_matches_fallback` | ✅ fallback returns src_port when neither IP matches |
| `test_detect_local_ip_returns_non_loopback` | ✅ detect_local_ip() returns valid non-loopback IP |

---

### Design review verification (4 items)

Four specific things from the design review were never confirmed. All four now verified with dedicated unit tests:

**1. Canonicalization — swap case verified.** `test_canonicalization_swap_case_local_ip_larger`: forward packet `192.168.1.100:50000 → 8.8.8.8:443` and response `8.8.8.8:443 → 192.168.1.100:50000` produce identical `FlowKey { a_ip: 8.8.8.8, a_port: 443, b_ip: 192.168.1.100, b_port: 50000 }`. The canonical ordering puts the smaller IP first. The previous test only covered the non-swap case (local IP < remote IP).

**2. Local port independent of canonical ordering verified.** `test_local_port_independent_of_canonical_ordering`: in the swap case (local IP 192.168.1.100 > remote IP 8.8.8.8), `FlowRecord.local_port = 50000` (the real local port), NOT `443` (the canonical `a_port`). PID resolved from `local_port=50000`, not from canonical key ordering. This is critical because port→PID cache lookup requires knowing which side is local — canonicalization discards that information.

**3. Enrichment dedup: per-flow (redundant), documented.** `test_enrichment_dispatched_per_flow_not_per_ip`: two flows to the same destination IP (same IP, different source ports) produce two `NewFlow` events, each triggering `enrich_pool.dispatch()`. DNS/GeoIP/Reputation are dispatched redundantly per-flow. **Known v1 inefficiency** — documented in `flow/mod.rs` header comment, `STATUS.md` shortcomings, and this report. Only process attribution is genuinely flow-specific (different processes can bind the same port). Fix deferred to v2: global `HashMap<IpAddr, EnrichmentState>` cache.

**4. Flow-count bound and tick cadence verified.** `MAX_FLOWS = 100_000` with oldest-eviction overflow (`test_max_flows_evicts_oldest`). `tick()` uses `Instant::now()` (wall-clock), fires on every `poll()` iteration (100ms timeout) — works even during quiet/stalled capture, not only on packet arrival. `test_tick_fires_on_wall_clock_not_packet_count` proves expiry based on real time elapsed, not packet count. This was the resource-exhaustion concern under §1a (actively hostile traffic) — now bounded.

### Known shortcomings (documented, not blocking)

1. **Hardcoded port offsets (268/264)** — `process_lookup.rs` reads `insi_lport`/`insi_fport` at fixed byte offsets. Fragile if Apple changes `SocketFDInfo` layout. Will revisit with dynamic offset computation.

2. **Per-flow DNS/GeoIP/Reputation dispatch** — enrichment is dispatched per-flow, not per-destination-IP. Redundant lookups for flows to the same IP. Fix: global `HashMap<IpAddr, EnrichmentState>` cache.

3. **`FlowRecord` fields `#[allow(dead_code)]`** — `flow_id`, `local_port`, `pid` exist for detector/decision pipeline but are not yet consumed.

4. **GeoIP and Reputation stubs** — return `success: false`. Real implementation deferred.

5. **`reconcile()` stub** — returns `ReconciliationReport::default()`. Real reconciliation deferred.

---

## 2026-07-21

---

### What was done today

**1. Outbound blocking bug — discovered and fixed.**

Milestone 1 was declared "verified working" on 07-20, but outbound blocking was never tested against a real reachable IP. Today's functional re-test against 8.8.8.8 revealed the anchor rules used `pass out quick to <blocklist>` — which ALLOWED outbound to blocked IPs and created pf state entries. TCP connected successfully (`Connected to 8.8.8.8 port 80`), pf state showed an entry (`ALL tcp 192.168.0.100:64323 -> 8.8.8.8:80 TIME_WAIT`). UDP also passed through. Fixed by changing `pass out` → `block out`. After helper restart: curl times out, `pfctl -s state -vv | grep 8.8.8.8` = empty for both TCP and UDP.

This was a real bug shipped as verified — not a refinement or cleanup. The TEST-NET address (198.51.100.1) used in initial tests couldn't distinguish "blocked" from "unreachable."

**2. Agent crate restructuring.**

Moved agent binary from `crates/platform-macos/src/agent/` to `crates/agent/` per architecture doc §5. The agent now lives in its own crate, depending on `platform-macos` only for `protocol.rs` (SCM_RIGHTS + bincode IPC). `platform-macos` retains only the root helper binary. Workspace updated, all three crates compile.

**3. Component context folders for agentic indexing.**

Created `doc/components/` with 6 context.md files: capture, ipc, enforcement, types, agent-engine, anchor-fix. Each covers code location, key structs, gotchas, and verified behavior — single-file context for agents without touching source. Added glob pattern to `opencode.json` instructions.

**4. Milestone 2: Enrichment pipeline — built and verified.**

Built the enrichment async side-channel (§4): worker pool, DNS reverse lookup, process attribution via libproc FFI, and stub providers for GeoIP/Reputation. Enrichment never blocks the hot path — dispatched on packet arrival, results collected non-blocking via `drain_results()`.

New files:
- `crates/agent/src/enrichment/mod.rs` (402 lines) — 4-thread worker pool (`std::thread` + `mpsc` + `Arc<Mutex<Receiver>>`), DNS reverse via libc `getnameinfo`, process attribution via libproc, GeoIP/Reputation stubs
- `crates/platform-macos/src/process_lookup.rs` (155 lines) — libproc FFI: `proc_pidpath` + `proc_pidinfo` (PROC_PIDTASKINFO) + mach2 timebase conversion for start-time

Modified files:
- `crates/common/src/types.rs` — added `EnrichmentKind`, `EnrichmentRequest`, `EnrichmentResult` types
- `crates/common/src/lib.rs` — re-exports new enrichment types
- `crates/platform-macos/src/lib.rs` — added `pub mod process_lookup`
- `crates/platform-macos/Cargo.toml` — added `mach2 = "0.4"` dependency
- `crates/agent/src/main.rs` — integrated enrichment pool (create, dispatch, collect results)

**Verified:** `cargo test --workspace` — 2/2 pass (`test_lookup_own_pid`, `test_lookup_invalid_pid`). Build + clippy clean. DNS reverse lookup resolves real hostnames. Process attribution resolves own PID to executable path and start time.

### Commits (chronological)

| Hash | Description |
|---|---|
| `68e1da1` | **fix: anchor rules block outbound to blocklist + move agent to own crate** — outbound blocking bug fix + crate restructuring + doc corrections |
| `1171a53` | docs: add per-component agentic context folders in doc/components/ |

### Bugs found

#### Bug 6: Outbound to blocked IPs not blocked
- **File:** `helper/main.rs` (`ensure_anchor()`)
- **Was:** `pass out quick to <synapse_blocklist>` — allowed outbound to blocked IPs
- **Should be:** `block out quick to <synapse_blocklist>` — blocks outbound to blocked IPs
- **Impact:** IPS did not block outbound traffic to known-bad IPs. C2 beaconing, data exfiltration, and lateral movement to blocked destinations were not prevented.
- **How found:** Functional re-test against 8.8.8.8 (real reachable IP) after Milestone 1 was declared verified. Initial tests used TEST-NET address (198.51.100.1) which couldn't distinguish "blocked" from "unreachable."
- **Fix:** Changed `pass out` → `block out` in `ensure_anchor()`. Added comment explaining why both `block out` and `block in` are needed.
- **Verified:** curl to 8.8.8.8 times out, `pfctl -s state -vv | grep 8.8.8.8` = empty (no state created)

---

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

## 4. File inventory (current as of 07-22)

| File | Lines | Purpose |
|---|---|---|
| `crates/common/src/lib.rs` | 96 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `IpcMessage` re-export |
| `crates/common/src/types.rs` | 150 | `ValidatedBlock`, `BlockId`, `EnforcementReceipt`, `PortPidCache`, `IpcMessage`, `EnrichmentRequest/Result/Kind` |
| `crates/platform-macos/src/helper/main.rs` | 389 | Root daemon — BPF ioctls, fd handoff, pf anchor, enforcement loop, cache-push thread |
| `crates/platform-macos/src/helper/enforce.rs` | 178 | `MacOsEnforcementBackend` — only pfctl executor |
| `crates/platform-macos/src/protocol.rs` | 112 | SCM_RIGHTS fd-passing + bincode IPC |
| `crates/platform-macos/src/process_lookup.rs` | 668 | `libproc` FFI — `build_port_pid_cache`, `probe_socket`, `read_port_be`, `lookup_process` |
| `crates/agent/src/main.rs` | 626 | Unprivileged — BPF reads, IPv4/IPv6, flow tracker, enrichment, IPC reader thread, `determine_local_port()` extracted |
| `crates/agent/src/flow/mod.rs` | 574 | In-memory session window — `FlowKey`, `FlowRecord`, `FlowTracker`, canonicalization, eviction |
| `crates/agent/src/enrichment/mod.rs` | 495 | 4-thread worker pool — DNS reverse, process attribution, GeoIP/Reputation stubs |
| **Total** | **3,424** | |

### Dependencies

| Crate | Dependencies |
|---|---|
| `synapse-common` | serde 1.x, bincode 1.x |
| `synapse-platform-macos` | synapse-common, libc 0.2, serde 1.x, bincode 1.x, log 0.4, env_logger 0.11, libproc 0.14 |
| `synapse-agent` | synapse-common, synapse-platform-macos, libc 0.2, log 0.4, env_logger 0.11 |

### Documentation files

| File | Purpose |
|---|---|
| `opencode.md` | Agent context — hard rules, conventions, architecture, status |
| `doc/STATUS.md` | What's built (source of truth) |
| `doc/report.md` | Day-by-day report with architecture, bugs, test results |
| `doc/Synapse-IPS-Architecture.md` | Design blueprint (~500 lines) |
| `doc/components/*/context.md` | Per-component agentic context (6 files) |
| `crates/common/context.md` | Module map + type inventory |
| `crates/platform-macos/context.md` | Call trees with line numbers |
| `crates/agent/src/flow/README.md` | Flow tracker agentic context |
| `README.md` | Human-facing overview with ASCII art |

---

## 5. What's next (not built)

Per §6 architecture doc, the order is:

1. ~~BPF capture~~ ✅
2. ~~SCM_RIGHTS fd-passing~~ ✅
3. ~~Typed IPC (Block/Unblock/KillState)~~ ✅
4. ~~pf enforcement end-to-end~~ ✅
5. ~~Enrichment~~ ✅ — async DNS, process attribution via libproc
6. ~~Port→PID cache~~ ✅ — libproc FFI, SCM_RIGHTS IPC, per-process fd scan
7. ~~Flow tracker~~ ✅ — in-memory session window, ~100ms ticks, direction-agnostic
8. **Detector framework** — `Detector` trait + Rule engine + ONNX inference
9. **Decision engine** — weighted scoring, policy thresholds
10. **Storage** — SQLite (WAL mode), single-writer worker
11. **Dashboard** — Tauri + React

### Stubs

- **`reconcile()`** — returns `ReconciliationReport::default()`. Real reconciliation (§4a) = detect-and-recover from anchor eviction.
- **GeoIP enrichment** — returns `success: false`. Real implementation deferred.
- **Reputation enrichment** — returns `success: false`. Real implementation deferred.

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
| Port→PID cache (07-22) | ✅ 49–51 entries, ~483 PIDs, ~6675 fds, ~7–8ms root scan |
| Port→PID live resolve (07-22) | ✅ Brave Browser → pid=743 → `Brave Browser Helper` |
| Flow tracker creation (07-22) | ✅ flows created for each unique session, INFO-level logs visible |
| DNS enrichment (07-22) | ✅ `ec2-44-203-161-176.compute-1.amazonaws.com`, `abbass-macbook-air.local` |
| Flow expiry (07-22) | ✅ `tick: expired M flows (N remaining)` logs after 5s silence |
| 26 unit tests (07-23) | ✅ all pass — 20 agent, 6 platform-macos |
| `determine_local_port()` inbound test | ✅ real code path with system-detected local IP — returns dst_port |
| `determine_local_port()` outbound test | ✅ real code path — returns src_port |
| `detect_local_ip()` returns valid IP | ✅ non-loopback, non-unspecified |
| Design review: canonicalization swap | ✅ `test_canonicalization_swap_case_local_ip_larger` — identical key |
| Design review: local_port independence | ✅ `test_local_port_independent_of_canonical_ordering` — correct port |
| Design review: enrichment dedup | ✅ `test_enrichment_dispatched_per_flow_not_per_ip` — per-flow (documented) |
| Design review: flow-count bound | ✅ `test_tick_fires_on_wall_clock_not_packet_count` — wall-clock expiry |
