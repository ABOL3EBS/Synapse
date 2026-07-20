# Implementation Status — Synapse IPS

This is a factual ledger, not a design doc. It answers one question only: **what actually exists in the code right now, verified against real files** — not what the architecture blueprint describes as the target. If this file and `Synapse-IPS-Architecture.md` ever disagree about what's built, this file wins; the architecture doc describes where the project is going, not where it is.

**Last verified:** 2026-07-20, against commit `f2351f2` ("fix: apply_block() dedup — keep original TTL on re-flag"), by direct file read and live traffic + pfctl table verification.

Update this file whenever you verify a change by actually reading the file that changed — not from memory, not from a commit message, not from an agent's description of what it wrote.

---

## Built and confirmed working

### `crates/common/` (75 + 62 lines)
- **`lib.rs`** — `EnforcementCommand` enum (`Block`/`Unblock`/`KillState`), `PacketInfo` struct, `EnforcementBackend` trait, protocol constants (`IPC_MAGIC`, `IPC_VERSION`). Re-exports types from `types.rs`.
- **`types.rs`** — `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`. Shared data contracts for the enforcement backend (§4c).
- Dependencies: `serde` (with derive), `bincode`

### `crates/platform-macos/src/helper/main.rs` (325 lines) — `synapsed-helper` binary
- Opens BPF device via **raw ioctls** (no pcap): `BIOCSBLEN` → `BIOCSETIF` → `BIOCIMMEDIATE` → `BIOCSETF`, in that exact order. BPF ioctl ordering is critical: "The buffer must be set before the file is attached to an interface with BIOCSETIF." — bpf(4).
- BPF filter: 5-instruction program matching both IPv4 (EtherType `0x0800`) and IPv6 (EtherType `0x86DD`), dropping other traffic.
- Sends BPF fd to agent via `SCM_RIGHTS` (using shared `protocol.rs`), drops own copy — agent now solely holds the fd.
- Initializes the `pf` anchor and `synapse_blocklist` table via `ensure_anchor()`.
- Listens for typed `EnforcementCommand`s over the agent↔helper channel.
- Enforcement loop: `Block`/`Unblock` go through `MacOsEnforcementBackend` (trait). `KillState` kept as direct pfctl call (broken syntax — see "Built but broken").
- Constants: `PF_ANCHOR_NAME = "com.synapse.ips"`, `PF_TABLE_NAME = "synapse_blocklist"`, `IPC_SOCKET_PATH = "/tmp/synapse-helper.sock"`
- Internal modules: `mod enforce` (the backend implementation)
- Dependencies: `synapse-common`, `libc`, `log`, `env_logger`

### `crates/platform-macos/src/helper/enforce.rs` (141 lines) — `MacOsEnforcementBackend`
- **The ONLY pfctl executor.** All `Command::new("pfctl").args([...])` calls live here, never in a shell.
- `block_ip(IpAddr)` — adds IP to pf table via `pfctl -a com.synapse.ips -t synapse_blocklist -T add <ip>`
- `unblock_ip(IpAddr)` — removes IP via `pfctl -T delete`
- `apply_block(ValidatedBlock)` — idempotent: if IP already in `active_blocks`, re-issues `block_ip()` but does NOT spawn a second TTL thread (keeps original TTL). Otherwise: blocks + spawns one background thread that sleeps for TTL then unblocks.
- `remove_block(BlockId)` — unblocks + removes from `active_blocks`.
- `reconcile()` — **STUB** returning `Ok(ReconciliationReport::default())`. Real reconciliation is tracked separate work (§4a).
- v1 tradeoff: one OS thread per active block, no cap.
- Verified against real pf: `pfctl -T show` before/after add/delete confirmed table manipulation works.

### `crates/platform-macos/src/agent/main.rs` (289 lines) — `synapse-agent` binary
- Receives BPF fd from helper via `SCM_RIGHTS` (does **not** open `/dev/bpf*` itself — privilege separation enforced structurally)
- Queries `BIOCGBLEN` for exact kernel buffer size, allocates matching read buffer
- Reads packets via raw `libc::read()` on the received fd (no pcap dependency in the agent)
- Parses `bpf_hdr` headers (20-byte macOS `timeval32` layout) with proper `BPF_WORDALIGN` (4-byte alignment)
- Parses both IPv4 and IPv6 frames from raw Ethernet: `parse_ipv4()` and `parse_ipv6()`
- Sends a `Block` command for a hardcoded test target (`192.168.1.100`) — milestone 1 test behavior
- Dependencies: `synapse-common`, `libc`, `log`, `env_logger`

### `crates/platform-macos/src/protocol.rs` (112 lines)
- `send_fd(stream, fd)` / `recv_fd(stream)` — SCM_RIGHTS fd-passing over Unix socket
- `send_message(stream, msg)` / `recv_message(stream)` — length-prefixed bincode serialization
- **Confirmed exercised** by the running path — helper sends fd via `send_fd`, agent receives via `recv_fd`.

### `crates/platform-macos/src/lib.rs` (11 lines)
- Re-exports `pub mod protocol`. The `helper/` and `agent/` binaries are NOT re-exported (binary directory names conflict with `pub mod` declarations).

---

### What was verified against real traffic (2026-07-20, commit `67b8d02`)

Live capture on `en0` with a long-running agent process (not synthetic single-packet tests):

- **IPv4 ICMP** (proto=1): echo request/reply pairs to `8.8.8.8` — `172.18.22.208:0 → 8.8.8.8:0 (proto=1)` and reply `8.8.8.8:0 → 172.18.22.208:0 (proto=1)`, multiple pairs over ~30 seconds of continuous ping. Ports correctly show as `0` (ICMP has no ports).
- **IPv4 TCP** (proto=6): HTTPS connections to various IPs (`104.17.91.187:443`, `52.108.8.12:443`, `18.210.236.250:443`, etc.)
- **IPv4 UDP** (proto=17): mDNS (`172.18.22.158:5353 → 224.0.0.251:5353`), DNS queries, QUIC traffic
- **IPv6 UDP** (proto=17): mDNS (`fe80::...:5353 → ff02::fb:5353`)
- **IPv6 ICMPv6** (proto=58): neighbor solicitation/advertisement (`fe80::... → ff02::1:ff...`, `fe80::... → fe80::...`)

### What was verified against real pfctl (2026-07-20, commit `376e4df`)

```
$ sudo pfctl -a com.synapse.ips -t synapse_blocklist -T show
(no output — table empty)

$ sudo pfctl -a com.synapse.ips -t synapse_blocklist -T add 192.168.1.200
1/1 addresses added.

$ sudo pfctl -a com.synapse.ips -t synapse_blocklist -T show
   192.168.1.200

$ sudo pfctl -a com.synapse.ips -t synapse_blocklist -T delete 192.168.1.200
1/1 addresses deleted.

$ sudo pfctl -a com.synapse.ips -t synapse_blocklist -T show
(no output — table empty)
```

---

## Built but broken — do not treat as working

- **`helper/main.rs`, KillState branch (~line 285–304):** `.args(["-k", &format!("{proto_str} from {src} to {dst}")])`. This is a **real functional bug**, not just a style issue. Real `pfctl -k` syntax takes a host/network per flag — kill both src and dst with **two separate `-k` flags**: `pfctl -k <src> -k <dst>` (see `man pfctl` — verified against FreeBSD/OpenBSD/macOS man pages directly, not inferred). A single formatted "proto from X to Y" sentence passed to one `-k` is not valid syntax as written. This will very likely either error or silently kill zero states (`killed 0 states` is the typical real-world symptom of this exact mistake). **No shell-injection risk** — this is a syntax/functionality bug, not a security bug. Needs fixing before the kill-state enforcement path can be trusted at all.

## Built as stub — functional but incomplete

- **`enforce.rs`, `reconcile()`:** Returns `Ok(ReconciliationReport::default())`. The trait method exists and compiles, but performs no actual pf table query or recovery. Real reconciliation (§4a — detect-and-recover from anchor eviction) is tracked as separate work.

## Not built at all

- Reconciliation logic (§4a) — `reconcile()` is a stub, not real logic
- `crossbeam`-based agent engine / worker threads
- `crates/agent/` subdirectories (`detectors/`, `enrichment/`, `flow/`, `decision/`, `storage/`) — directories exist, all empty, no code
- SQLite storage layer
- Tauri app shell / any UI code (`src-tauri/src/ui/` is an empty directory; no `Cargo.toml` for the Tauri app yet)
- ONNX models / any detector implementations
- Windows or Linux platform code (intentionally — see architecture §1b)

---

## Why this file exists

On 2026-07-18, two separate OpenCode sessions gave confident, detailed, and **contradictory** descriptions of what enforcement code existed — one described a fully-wired pipeline with functions that didn't exist yet, the other claimed nothing existed when real milestone-1 code did. A third pass, after being told to read actual files, got the code inventory right but initially asserted an incorrect `pfctl -k` syntax as fact before it was checked against the real man page. The pattern: fluent, specific-sounding answers are not a reliable signal of correctness, especially about (a) what's actually built vs. what's designed, and (b) exact CLI/API syntax of external tools. This file exists so "what's built" has one place to check that isn't dependent on an agent's summary of the architecture doc's tone. Keep it honest and current, or it's worse than not having it.
