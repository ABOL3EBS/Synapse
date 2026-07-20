# Agent Context — Synapse IPS

Read `doc/STATUS.md` before assuming anything exists. If STATUS.md doesn't say it's built, it isn't.

## Hard rules

0. Architecture doc describes target design, not current state. Check STATUS.md and real files before answering.
1. Only `platform-macos/src/helper/` runs privileged. Only it calls `pfctl`. Agent never touches `/dev/bpf*`.
2. `pfctl` via `Command::new("pfctl").arg(...).arg(...)` — never shell, never string formatting.
3. No `tokio` in agent or platform-macos. `std::thread` + `crossbeam` only.
4. Every detector returns `DetectorFinding` with enforced timeout. No blocking detectors.
5. Enrichment never awaited inline on the hot path. Async side-channel only.
6. PID attribution carries process start-time alongside PID.
7. Don't suggest: cross-platform, tokio, control-plane backend, or pre-creating platform crates. All rejected for v1 — see `doc/Synapse-IPS-Architecture.md` §1b if you need reasoning.

## Where to look

| Task | File / Section |
|---|---|
| What's built vs. planned | `doc/STATUS.md` |
| Adding/changing a detector | §4b architecture doc + `crates/agent/src/detectors/` |
| Touching pfctl or enforcement | §4c architecture doc + `crates/platform-macos/src/helper/enforce.rs` |
| BPF capture / fd passing | §1a + §2 architecture doc + `helper/main.rs` + `protocol.rs` |
| Enrichment (DNS/geo/process) | §4 architecture doc + `crates/agent/src/enrichment/` |
| pf anchor / coexistence | §4a architecture doc |
| Design decisions, rejected alternatives | `doc/Synapse-IPS-Architecture.md` §1b |

## Build

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo test --workspace
```

## Naming

- Crates: `synapse-*` | Modules: `snake_case` | Types: `PascalCase`
- SQLite tables: `snake_case` | Enforcement fns: verb-first (`apply_block`)
- Measurements include unit: `latency_us`, `ttl_ms` — never bare `latency`

## Current status summary

- **Built:** helper (BPF ioctls, SCM_RIGHTS fd-passing, pf anchor, enforcement loop), agent (BPF reads, IPv4+IPv6 parsing, IPC), common (types, EnforcementBackend trait), protocol.rs (SCM_RIGHTS, bincode IPC)
- **Broken:** KillState pfctl syntax (`-k` flags wrong — see STATUS.md)
- **Stub:** `reconcile()` returns default
- **Not built:** detectors, enrichment, flow tracker, decision engine, storage, Tauri UI, ONNX

## Order of work

Follow §6 architecture doc literally: capture → typed IPC → pfctl block end-to-end, then enrichment, detectors, decision, storage. Don't start ML or UI before milestone 1 is proven.
