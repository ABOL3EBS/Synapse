# Implementation Status — Synapse IPS

**Last verified:** 2026-07-20, commit `0869168`. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Built and working

| Component | File | Lines | Key details |
|---|---|---|---|
| Common types | `crates/common/src/lib.rs` | 81 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait (apply_block, remove_block, kill_state, reconcile), IPC constants |
| Shared types | `crates/common/src/types.rs` | 62 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport` |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 347 | BPF raw ioctls (BIOCSBLEN→BIOCSETIF→BIOCIMMEDIATE→BIOCSETF), IPv4+IPv6 filter, SCM_RIGHTS fd handoff, pf anchor init (flush+reload+pfctl -e), enforcement loop. Anchor rules: `block out` + `block in` (fixed: was `pass out` bug). |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 180 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block (dedup), TTL auto-unblock threads, kill_state (pfctl -k src -k dst), stub reconcile |
| Agent binary | `crates/agent/src/main.rs` | 289 | BPF reads from received fd, `BpfHdr` (20-byte timeval32), IPv4+IPv6 parsing, test block target |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 112 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed) |

**Verified:** ICMP/TCP/UDP over IPv4+IPv6 on en0. pfctl table add/delete/show. KillState: pfctl -k src -k dst kills real state entries (killed 1 state, confirmed gone in pfctl -s state -vv). Outbound block: curl to 8.8.8.8 times out, pf state empty (no state created).

## Stub

- **`reconcile()`** (`enforce.rs`): Returns `Ok(ReconciliationReport::default())`. Real reconciliation = separate work.

## Not built

- `crates/agent/src/main.rs` (new crate) — agent binary moved from platform-macos
- `crates/agent/` subdirs (detectors, enrichment, flow, decision, storage) — empty scaffolding
- SQLite storage, Tauri UI, ONNX models, crossbeam engine, enrichment pipeline
- Windows/Linux support (intentionally excluded — §1b)
