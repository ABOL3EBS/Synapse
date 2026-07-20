# Implementation Status — Synapse IPS

**Last verified:** 2026-07-20, commit `f2351f2`. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Built and working

| Component | File | Lines | Key details |
|---|---|---|---|
| Common types | `crates/common/src/lib.rs` | 75 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, IPC constants |
| Shared types | `crates/common/src/types.rs` | 62 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport` |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 325 | BPF raw ioctls (BIOCSBLEN→BIOCSETIF→BIOCIMMEDIATE→BIOCSETF), IPv4+IPv6 filter, SCM_RIGHTS fd handoff, pf anchor init, enforcement loop |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 141 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block (dedup), TTL auto-unblock threads, stub reconcile |
| Agent binary | `crates/platform-macos/src/agent/main.rs` | 289 | BPF reads from received fd, `BpfHdr` (20-byte timeval32), IPv4+IPv6 parsing, test block target |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 112 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed) |

**Verified:** ICMP/TCP/UDP over IPv4+IPv6 on en0. pfctl table add/delete/show against real pf table.

## Built but broken

- **KillState** (`helper/main.rs:285-304`): Uses `-k "proto from src to dst"` — wrong. `pfctl -k` needs separate flags per host. Syntax bug, not security.

## Stub

- **`reconcile()`** (`enforce.rs:135-140`): Returns `Ok(ReconciliationReport::default())`. Real reconciliation = separate work.

## Not built

- `crates/agent/` subdirs (detectors, enrichment, flow, decision, storage) — all empty
- SQLite storage, Tauri UI, ONNX models, crossbeam engine, enrichment pipeline
- Windows/Linux support (intentionally excluded — §1b)
