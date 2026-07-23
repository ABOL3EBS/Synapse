# Implementation Status — Synapse IPS

**Last verified:** 2026-07-24. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Built and working

| Component | File | Lines | Key details |
|---|---|---|---|
| Common types | `crates/common/src/lib.rs` | 101 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `EnrichmentRequest`, `EnrichmentResult`, `EnrichmentKind`, IPC constants, re-exports `Detector`, `run_detector_with_timeout`, `DecisionConfig`, `Verdict`, `FlowFeatures` |
| Shared types | `crates/common/src/types.rs` | 438 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`, `PortPidCache` (HashMap-based), `IpcMessage` enum, enrichment types, `DetectorId` (enum), `Severity` (enum), `Evidence` (`description` + `detail`), `DetectorStatus`, `DetectorFinding`, `Detector` trait (returns single finding), `run_detector_with_timeout()`, `FlowRecord`, `DecisionConfig` (`ttl_by_severity: HashMap<Severity, Duration>`), `Verdict`, `FlowFeatures` (`from_flow()` constructor) |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 389 | BPF raw ioctls, SCM_RIGHTS fd handoff, pf anchor init, enforcement loop, cache-push thread (5s interval). |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 178 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block, TTL auto-unblock, kill_state, stub reconcile |
| Process lookup | `crates/platform-macos/src/process_lookup.rs` | 668 | `libproc` crate (v0.14) typed structs for all FFI. **Port→PID cache** (`build_port_pid_cache`): per-process fd scan. **Port reading** via `read_port_be()` — raw BE bytes at verified offsets (268/264), bypasses c_int native-endian corruption on LE ARM. |
| Agent binary | `crates/agent/src/main.rs` | 819 | BPF reads, IPv4+IPv6 parsing, enrichment pool integration, stream split for IPC reader thread, `detect_local_ip()` via getifaddrs (5s background refresh, benchmarked at 9.065 us/call), `determine_local_port()` with `is_local(ip)` direction check, flow tracker integration, detector framework wired on flow expiry, decision engine wired (log-only verdicts), active-flow re-evaluation |
| Detector framework | `crates/agent/src/detectors/mod.rs` | 343 | `RuleDetector` (placeholder v1 rules: dns_blocklist, suspicious_port, high_packet_count), timeout enforcement via `run_detector_with_timeout()`, `SlowDetector` test proving timeout works |
| Decision engine | `crates/agent/src/decision/mod.rs` | 397 | `DecisionEngine` with weighted scoring (score × confidence × status_weight), `Verdict` enum (Allow/Block/Alert), `FlowFeatures` extraction, `DecisionConfig` with block/alert thresholds + severity→TTL map. 11 unit tests. Wired into capture loop — log-only, zero enforcement calls. |
| Enrichment pool | `crates/agent/src/enrichment/mod.rs` | 495 | 4-thread worker pool (`std::thread` + `mpsc`), DNS reverse via `getnameinfo`, process attribution via libproc, GeoIP/Reputation stubs |
| Flow tracker | `crates/agent/src/flow/mod.rs` | 898 | In-memory session window with ~100ms ticks via `poll()` timeout. Direction-agnostic canonicalization, MAX_FLOWS eviction, local_port + PID stored per-flow, enrichment attachment, `last_evaluated` per-flow, `EVALUATION_INTERVAL_SECS` (1s), `MAX_RE_EVAL_PER_TICK` (100). `tick()` returns `(expired, due_for_re_evaluate)` tuple. |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 112 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed), stream split via `try_clone()` |

**Total:** 4,838 lines across 11 files.

**Verified end-to-end (2026-07-22):** Helper sends PortPidCache (49–51 entries, ~483 PIDs, ~6675 fds, 62–64 probe_ok, ~7–8ms root scan). Agent receives cache, looks up src_port on each packet, resolves to correct PID + executable path. Live test: Brave Browser connection to 142.251.142.74:443 resolved to pid=743 → `Brave Browser Helper`.

**Port→PID cache measured (unprivileged test binary):** 39–53 entries, ~500 PIDs, ~5000 fds, ~2ms. Well within 5s refresh budget.

### Design review verification (4 items)

1. **Canonicalization — swap case verified.** `test_canonicalization_swap_case_local_ip_larger`: forward packet `192.168.1.100:50000 → 8.8.8.8:443` and response `8.8.8.8:443 → 192.168.1.100:50000` produce identical `FlowKey { a_ip: 8.8.8.8, a_port: 443, b_ip: 192.168.1.100, b_port: 50000 }`. Canonical ordering puts smaller IP first.

2. **Local port independent of canonical ordering verified.** `test_local_port_independent_of_canonical_ordering`: in the swap case, `FlowRecord.local_port = 50000` (the real local port), NOT `443` (the canonical `a_port`). PID resolved from `local_port=50000`, not from canonical key. **Note:** `test_determine_local_port_inbound_real_code_path` exercises the actual `determine_local_port()` function with the real system-detected local IP — this is the production code path test that must pass.

3. **Enrichment dedup: per-flow (redundant), documented.** `test_enrichment_dispatched_per_flow_not_per_ip`: two flows to the same destination IP produce two `NewFlow` events, each triggering `enrich_pool.dispatch()`. DNS/GeoIP/Reputation are dispatched redundantly per-flow. **Known v1 inefficiency** — documented in `flow/mod.rs` header comment and `STATUS.md` shortcomings. Only process attribution is genuinely flow-specific.

4. **Flow-count bound and tick cadence verified.** `MAX_FLOWS = 100_000` with oldest-eviction overflow. `tick()` uses `Instant::now()` (wall-clock), fires on every `poll()` iteration (100ms timeout) — works even during quiet/stalled capture, not only on packet arrival. `test_tick_fires_on_wall_clock_not_packet_count` proves expiry based on real time elapsed.

### Critical bugs found and fixed

1. **NULL pointer vs non-null empty buffer:** `proc_listpids` and `proc_pidinfo` distinguish NULL pointer (query size) from non-null with size=0 (returns 0 silently). Fix: pass `std::ptr::null_mut()` for size queries.

2. **Port byte-order:** `insi_lport`/`insi_fport` are stored as BE u16 in the first 2 bytes of a `c_int` field. On little-endian ARM, reading as `c_int` (native-endian) gives wrong value (port 60202 → c_int 10987). Fix: `read_port_be()` reads 2 raw bytes at verified offsets and applies `u16::from_be_bytes`. Offsets (268/264) verified by 3 independent tests against lsof ground truth.

3. **Stack-copy offset bug:** Computing struct field offsets via `&(*copy).field` on a `ptr::read()` copy gives garbage addresses (measures distance to stack-local copy, not original struct). Fix: use pointer arithmetic on the original struct (`&mut si.field as *mut T as usize - &mut si as *mut T as usize`).

4. **Local port determination was direction-blind:** PID lookup used `src_port` first, `dst_port` fallback, with no `is_local(ip)` check. For inbound packets (src=remote, dst=local), `src_port` is remote — could return wrong PID if remote port was in cache. Fix: `detect_local_ip()` via `getifaddrs()` at startup, then `if src_ip == local_ip { src_port } else { dst_port }` for correct direction.

### Detector framework (§4b) — verified

- `Detector` trait + `DetectorFinding` + `run_detector_with_timeout()` in `common/src/types.rs`
- `RuleDetector` with placeholder v1 rules (dns_blocklist, suspicious_port, high_packet_count)
- Timeout enforcement: `run_detector_with_timeout()` runs `evaluate()` on its own thread, uses `recv_timeout()` with configurable budget. Returns `TimedOut` if exceeded.
- Wired into capture loop on flow expiry AND active-flow re-evaluation — log only
- **No `catch_unwind` yet** — panics silently detach (known limitation)
- **No circuit breaker** — consistently-failing detectors retried every interval (known limitation)

### Decision engine — verified (log-only)

- `DecisionEngine` in `crates/agent/src/decision/mod.rs`
- Weighted scoring: `score × confidence × status_weight`. TimedOut=0.1x, Errored=0.0x
- Block threshold=0.5, Alert threshold=0.2
- TTL from most severe Completed finding, clamped [30s, 24h]
- `Verdict` enum: `Allow`, `Block { ttl, reason }`, `Alert { reason }`
- `FlowFeatures` extracted from FlowRecord
- `DecisionConfig` with thresholds + severity→TTL map + min/max TTL clamps
- 11 unit tests pass
- Wired into capture loop — verdicts logged with `BLOCK`/`ALERT`/`RE-BLOCK`/`RE-ALERT` prefixes
- **Zero enforcement calls** — grep-confirmed

### Active-flow re-evaluation — verified

- `FlowRecord.last_evaluated: Instant` field
- `EVALUATION_INTERVAL_SECS = 1`, `MAX_RE_EVAL_PER_TICK = 100`
- `tick()` returns `(expired: Vec<u64>, due_for_re_evaluate: Vec<u64>)` — tuple
- `mark_evaluated(flow_id)` bumps `last_evaluated` regardless of finding status
- **Current implementation iterates `HashMap` for re-evaluation candidates — non-deterministic order, starvation risk** (known limitation, architecture plan approved for timing wheel scheduler)

## Stub (known incomplete — not done)

- **`reconcile()`** (`enforce.rs`): Returns `Ok(ReconciliationReport::default())`.
- **GeoIP enrichment** (`enrichment/mod.rs`): Returns `success: false`.
- **Reputation enrichment** (`enrichment/mod.rs`): Returns `success: false`.

## Known shortcomings (working but fragile)

1. **Hardcoded port offsets (268/264)** — `process_lookup.rs` reads `insi_lport`/`insi_fport` at fixed byte offsets verified by tests against lsof ground truth. Fragile if Apple changes `SocketFDInfo` layout. Will revisit with dynamic offset computation (pointer arithmetic on original struct, not stack copies — see bug #3 below).

2. **Per-flow DNS/GeoIP/Reputation dispatch** — enrichment is dispatched per-flow, not per-destination-IP. This means redundant lookups for flows to the same IP. Fix: global `HashMap<IpAddr, EnrichmentState>` cache. Only process attribution is genuinely flow-specific.

3. **No `catch_unwind` in detector timeout** — `run_detector_with_timeout()` spawns a thread for each detector. If the thread panics, it silently detaches. Fix: wrap `evaluate()` in `catch_unwind`, return `Errored` on panic.

4. **No circuit breaker for failing detectors** — `run_detectors()` retries all detectors every interval regardless of failure history. A consistently-errored detector wastes thread budget. Fix: per-detector `consecutive_failures` counter, skip after 5 failures.

5. **Re-evaluation uses HashMap iteration** — `tick()` collects re-evaluation candidates by iterating the entire `flows` HashMap, checking `last_evaluated`. Non-deterministic order, starvation risk for flows with high IDs. Fix: timing wheel scheduler (architecture plan approved).

6. **Decision engine has no uncertainty/findings_summary** — `Verdict::Block` and `Verdict::Alert` lack an `uncertainty` field and per-finding evidence summary. Fix: add fields for dashboard audit trail.

7. **All config is hardcoded** — block/alert thresholds, TTLs, detector budgets are constants in `DecisionConfig`. No TOML/YAML config file loading. Fix: config system with secure defaults.

## Not built

- Storage (SQLite WAL single-writer worker)
- Tauri UI dashboard
- ONNX model inference (detector framework exists, no model loaded)
- Windows/Linux support (intentionally excluded — §1b)
