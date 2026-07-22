# Implementation Status — Synapse IPS

**Last verified:** 2026-07-22. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Built and working

| Component | File | Lines | Key details |
|---|---|---|---|
| Common types | `crates/common/src/lib.rs` | 93 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `EnrichmentRequest`, `EnrichmentResult`, `EnrichmentKind`, IPC constants |
| Shared types | `crates/common/src/types.rs` | 122 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`, `PortPidCache`, `PortPidEntry`, `IpcMessage` enum, enrichment types |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 347 | BPF raw ioctls, SCM_RIGHTS fd handoff, pf anchor init, enforcement loop, cache-push thread (5s interval). |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 180 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block, TTL auto-unblock, kill_state, stub reconcile |
| Process lookup | `crates/platform-macos/src/process_lookup.rs` | 668 | `libproc` crate (v0.14) typed structs for all FFI. **Port→PID cache** (`build_port_pid_cache`): per-process fd scan. **Port reading** via `read_port_be()` — raw BE bytes at verified offsets (268/264), bypasses c_int native-endian corruption on LE ARM. |
| Agent binary | `crates/agent/src/main.rs` | 353 | BPF reads, IPv4+IPv6 parsing, enrichment pool integration, stream split for IPC reader thread, PID lookup wired (src_port first, dst_port fallback) |
| Enrichment pool | `crates/agent/src/enrichment/mod.rs` | 489 | 4-thread worker pool (`std::thread` + `mpsc`), DNS reverse via `getnameinfo`, process attribution via libproc, GeoIP/Reputation stubs |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 112 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed), stream split via `try_clone()` |

**Verified end-to-end (2026-07-22):** Helper sends PortPidCache (49–51 entries, ~483 PIDs, ~6675 fds, 62–64 probe_ok, ~7–8ms root scan). Agent receives cache, looks up src_port on each packet, resolves to correct PID + executable path. Live test: Brave Browser connection to 142.251.142.74:443 resolved to pid=743 → `Brave Browser Helper`.

**Port→PID cache measured (unprivileged test binary):** 39–53 entries, ~500 PIDs, ~5000 fds, ~2ms. Well within 5s refresh budget.

### Critical bugs found and fixed

1. **NULL pointer vs non-null empty buffer:** `proc_listpids` and `proc_pidinfo` distinguish NULL pointer (query size) from non-null with size=0 (returns 0 silently). Fix: pass `std::ptr::null_mut()` for size queries.

2. **Port byte-order:** `insi_lport`/`insi_fport` are stored as BE u16 in the first 2 bytes of a `c_int` field. On little-endian ARM, reading as `c_int` (native-endian) gives wrong value (port 60202 → c_int 10987). Fix: `read_port_be()` reads 2 raw bytes at verified offsets and applies `u16::from_be_bytes`. Offsets (268/264) verified by 3 independent tests against lsof ground truth.

3. **Stack-copy offset bug:** Computing struct field offsets via `&(*copy).field` on a `ptr::read()` copy gives garbage addresses (measures distance to stack-local copy, not original struct). Fix: use pointer arithmetic on the original struct (`&mut si.field as *mut T as usize - &mut si as *mut T as usize`).

## Stub (known incomplete — not done)

- **`reconcile()`** (`enforce.rs`): Returns `Ok(ReconciliationReport::default())`.
- **GeoIP enrichment** (`enrichment/mod.rs`): Returns `success: false`.
- **Reputation enrichment** (`enrichment/mod.rs`): Returns `success: false`.

## Not built

- Flow tracker (in-memory session window, ~100ms ticks) — enrichment dispatches but flow IDs are placeholder (per-destination counter)
- Detector framework, decision engine, storage, Tauri UI, ONNX models
- Windows/Linux support (intentionally excluded — §1b)
