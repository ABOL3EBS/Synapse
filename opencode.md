# Agent Context — Synapse IPS

## Project Overview

Synapse IPS is a reactive, session-level intrusion prevention system for macOS. It captures network traffic via BPF (no kernel extensions, no paid developer account), detects threats through a pluggable detector framework (rules, ONNX models, reputation feeds), and enforces decisions via the native `pf` firewall. The process model splits privileged work (BPF device open, `pf` state manipulation) into a helper daemon running as root, while all untrusted parsing, detection, and decision logic runs unprivileged in the agent.

Stack: Rust, BPF (raw ioctls, no pcap for capture), `pf` via `pfctl`, SCM_RIGHTS fd-passing over Unix sockets, bincode IPC. Future: ONNX Runtime for ML inference, SQLite (WAL) for storage, Tauri + React for the dashboard. macOS only for v1 — cross-platform, `tokio`, and a centralized control-plane backend are all rejected for v1 (see `doc/Synapse-IPS-Architecture.md` §1b).

## Key Commands

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo test --workspace
```

Helper (requires root):
```bash
sudo RUST_LOG=info cargo run --bin synapsed-helper
```

Agent (unprivileged):
```bash
cargo run --bin synapse-agent
```

## Verification Rules

After every code change, run `cargo build` to verify it compiles. After completing a step, run the full check chain:

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

If any step fails, fix it before proceeding. Do not tell the user something works without showing the terminal output proving it.

## Coding Conventions

- **No shell interpolation for pfctl.** Always `Command::new("pfctl").args([...])` — never `format!` into a string passed to `sh -c`.
- **Typed enforcement only.** `IpAddr`, `u16` port, `Duration` — never raw strings at the IPC or enforcement boundary.
- **One pfctl executor.** `MacOsEnforcementBackend` in `enforce.rs` is the only file that calls `pfctl`. All enforcement flows through the `EnforcementBackend` trait.
- **BPF ioctl ordering.** BIOCSBLEN before BIOCSETIF. `SockFprog.len` must be `u32` (matches C `bf_len`).
- **No async runtime.** `std::thread` + `crossbeam` only. No `tokio` in agent or platform-macos.
- **Detector findings are wrapped.** Every detector returns `DetectorFinding` with a latency budget and `status: Completed | TimedOut | Errored`.
- **Enrichment is async side-channel.** Never block the hot path waiting for DNS, geo, or reputation lookups.
- **Measurements include units.** `latency_us`, `ttl_ms` — never bare `latency` or `ttl`.
- **Enforcement fns are verb-first.** `apply_block`, `remove_block`, `kill_state`.
- **Crates: `synapse-*` | Modules: `snake_case` | Types: `PascalCase` | SQLite tables: `snake_case`.**

## Architecture & File Placement

```
crates/
├── common/          # Zero-logic. Shared types + EnforcementBackend trait.
│   └── src/
│       ├── lib.rs       # EnforcementCommand, PacketInfo, EnforcementBackend trait, IPC constants
│       └── types.rs     # ValidatedBlock, BlockId, EnforcementReceipt, ReconciliationReport, enrichment types
│
├── agent/           # Unprivileged. All parsing, detection, decision, storage.
│   └── src/
│       ├── main.rs          # Engine pipeline & worker threads
│       ├── detectors/       # Detector trait + Rule/ONNX/Reputation impls
│       ├── enrichment/      # Async DNS, geo, process attribution
│       ├── flow/            # In-memory session tracking
│       ├── decision/        # Weighted scoring, policy thresholds
│       └── storage/         # SQLite single-writer worker
│
└── platform-macos/  # macOS enforcement boundary. Only crate that knows BPF/pf.
    └── src/
        ├── lib.rs               # Re-exports pub mod protocol, pub mod process_lookup
        ├── protocol.rs          # SCM_RIGHTS fd-passing + bincode IPC
        ├── helper/
        │   ├── main.rs          # Root daemon: BPF open, fd handoff, enforcement loop
        │   └── enforce.rs       # MacOsEnforcementBackend — ONLY pfctl caller
        ├── capture.rs           # BPF/libpcap wrapper (runs unprivileged after fd received)
        └── process_lookup.rs    # libproc port→PID cache + process-start-time resolution
```

**Rules for new code:**
- New enforcement logic → `enforce.rs`, behind `EnforcementBackend` trait.
- New IPC command variants → `common/src/lib.rs` (enum) + `protocol.rs` (serialization).
- New detector → `crates/agent/src/detectors/`, implement `Detector` trait.
- Never add pfctl calls outside `enforce.rs`.
- Never open `/dev/bpf*` outside `helper/main.rs`.

## Hard rules

0. Architecture doc describes target design, not current state. Check `doc/STATUS.md` and real source files before assuming something exists.
1. Only `platform-macos/src/helper/` runs privileged. Only it calls `pfctl`. Agent never touches `/dev/bpf*`.
2. `pfctl` via `Command::new("pfctl").arg(...).arg(...)` — never shell, never string formatting.
3. No `tokio` in agent or platform-macos. `std::thread` + `crossbeam` only.
4. Every detector returns `DetectorFinding` with enforced timeout. No blocking detectors.
5. Enrichment never awaited inline on the hot path. Async side-channel only.
6. PID attribution carries process-start-time alongside PID.
7. Don't suggest: cross-platform, tokio, control-plane backend, or pre-creating platform crates. All rejected for v1 — see `doc/Synapse-IPS-Architecture.md` §1b.

## Agent workflow

- **Never commit unless explicitly asked.** After completing a step, show the diff and wait for the user to say "commit" or "ship it".
- **Never start a build unless explicitly asked or unless you just edited code.** If you edited code, run `cargo build` to verify it compiles. If it fails, fix it before proceeding.
- **After every successful step, update the md files** — `doc/STATUS.md`, `crates/common/context.md`, `crates/platform-macos/context.md`, and this file's status section. Show what changed.
- **Verify with real terminal output.** Don't say "this should work" — show the actual output. If the user needs to run sudo, give exact commands and wait for their output.
- **User runs sudo manually.** The agent session cannot run sudo. Give copy-paste command blocks.
- **When testing pfctl:** always show before/after `pfctl -s state -vv` output. `killed 0 states` is a silent failure — find a real active state first.
- **Check `man pfctl` before assuming pfctl syntax.** Don't guess flags — look them up.
- **pf requires explicit enable.** `pfctl -e` after loading rules.
- **Anchor must be in main ruleset.** `anchor "name" all` in `/etc/pf.conf` or pf never evaluates it.
- **Flush before reload.** `pfctl -a name -F all` before loading rules clears stale state.
- **Deep context lives in `doc/`.** `doc/STATUS.md` for what's built. `doc/report.md` for full architecture, bug history, struct layouts, and testing methodology. `doc/Synapse-IPS-Architecture.md` for design decisions. `doc/components/*/context.md` for per-component agentic context (capture, ipc, enforcement, types, agent-engine, anchor-fix).

## Current status summary

- **Built:** helper (BPF ioctls, SCM_RIGHTS fd-passing, pf anchor + flush + reload + enable, enforcement loop, cache-push thread every 5s), agent (BPF reads, IPv4+IPv6 parsing, IPC reader thread + cache storage, PID lookup wired src_port→PID→path), common (types, EnforcementBackend trait with apply_block/remove_block/kill_state/reconcile, enrichment types, IpcMessage enum), protocol.rs (SCM_RIGHTS, bincode IPC, stream split), process_lookup.rs (libproc FFI: lookup_process, build_port_pid_cache, probe_socket with raw BE port reading), enrichment/mod.rs (4-thread worker pool with DNS reverse + process attribution + stubs), flow/mod.rs (in-memory session window with ~100ms ticks, direction-agnostic canonicalization, MAX_FLOWS eviction, local_port + PID stored per-flow, enrichment attachment)
- **Verified:** ICMP/TCP/UDP over IPv4+IPv6 on en0. pfctl table add/delete/show. KillState kills real states (`killed 1 state`, confirmed gone in `pfctl -s state -vv`). pf enabled, anchor active. Process lookup: `test_lookup_own_pid` passes, resolves own executable path and start time. **Live E2E (2026-07-22):** helper sends PortPidCache (49–51 entries, ~7–8ms), agent receives and resolves Brave Browser connection → pid=743 → `Brave Browser Helper` via `lookup_process`. **Flow tracker (2026-07-22):** poll() timeout drives tick(), flows created for each unique session, enrichment dispatches per-flow, DNS reverse lookups succeed (`ec2-44-203-161-176.compute-1.amazonaws.com`, `abbass-macbook-air.local`). **Design review (07-22):** all 4 items verified — canonicalization swap case, local_port independence, enrichment per-flow (documented), MAX_FLOWS + wall-clock tick. **Bug fix (07-23):** `detect_local_ip()` via getifaddrs() at startup, PID lookup uses `is_local(ip)` direction check instead of src_port-first heuristic.
- **Stub:** `reconcile()` returns default. GeoIP and Reputation enrichment return `success: false`.
- **Shortcomings:** hardcoded port offsets (268/264) in process_lookup.rs (fragile if Apple changes struct layout), per-flow DNS/GeoIP/Reputation dispatch (redundant lookups for same IP — fix: global IP-keyed cache), FlowRecord fields `#[allow(dead_code)]` pending detector/decision pipeline.
- **Not built:** detectors, decision engine, storage, Tauri UI, ONNX

## Order of work

Follow §6 architecture doc literally: capture → typed IPC → pfctl block end-to-end, then enrichment, detectors, decision, storage. Don't start ML or UI before milestone 1 is proven.
