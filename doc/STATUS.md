# Implementation Status — Synapse IPS

**Last verified:** 2026-07-21. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Built and working

| Component | File | Lines | Key details |
|---|---|---|---|
| Common types | `crates/common/src/lib.rs` | 93 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `EnrichmentRequest`, `EnrichmentResult`, `EnrichmentKind`, IPC constants |
| Shared types | `crates/common/src/types.rs` | 122 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`, enrichment types |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 347 | BPF raw ioctls, SCM_RIGHTS fd handoff, pf anchor init, enforcement loop. Anchor rules: `block out` + `block in`. |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 180 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block, TTL auto-unblock, kill_state, stub reconcile |
| Process lookup | `crates/platform-macos/src/process_lookup.rs` | 155 | libproc FFI: `proc_pidpath` + `proc_pidinfo` (PROC_PIDTASKINFO) + mach timebase conversion for start-time. Tests pass. |
| Agent binary | `crates/agent/src/main.rs` | 353 | BPF reads, IPv4+IPv6 parsing, enrichment pool integration, dispatch on packet, non-blocking result collection |
| Enrichment pool | `crates/agent/src/enrichment/mod.rs` | 402 | 4-thread worker pool (`std::thread` + `mpsc` + `Arc<Mutex<Receiver>>`), DNS reverse via `getnameinfo`, process attribution via libproc, GeoIP/Reputation stubs |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 112 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed) |

**Verified:** ICMP/TCP/UDP over IPv4+IPv6 on en0. KillState kills real states. Outbound block: curl to 8.8.8.8 times out, pf state empty. Process lookup: `test_lookup_own_pid` passes, resolves own executable path and start time.

## Stub

- **`reconcile()`** (`enforce.rs`): Returns `Ok(ReconciliationReport::default())`. Real reconciliation = separate work.
- **GeoIP enrichment** (`enrichment/mod.rs`): Returns `success: false, error: "geoip not implemented in v1"`.
- **Reputation enrichment** (`enrichment/mod.rs`): Returns `success: false, error: "reputation lookup not implemented in v1"`.

## Not built

- Flow tracker (in-memory session window, ~100ms ticks) — enrichment dispatches but flow IDs are placeholder (per-destination counter)
- PID attribution from BPF (enrichment requests pass `pid: None` — needs BPF proc info or socket filter)
- Detector framework, decision engine, storage, Tauri UI, ONNX models
- Windows/Linux support (intentionally excluded — §1b)
