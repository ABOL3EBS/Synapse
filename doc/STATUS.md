# Implementation Status — Synapse IPS

**Last verified:** 2026-07-25. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Built and working

| Component | File | Lines | Key details |
|---|---|---|---|
| Common types | `crates/common/src/lib.rs` | 114 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `EnrichmentRequest`, `EnrichmentResult`, `EnrichmentKind`, IPC constants (`PF_ANCHOR_NAME`, `PF_TABLE_NAME`, `IPC_SOCKET_PATH`), re-exports `Detector`, `run_detector_with_timeout`, `DecisionConfig`, `Verdict`, `FlowFeatures` |
| Shared types | `crates/common/src/types.rs` | 459 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`, `PortPidCache` (HashMap-based), `IpcMessage` enum, enrichment types, `DetectorId` (enum), `Severity` (enum), `Evidence` (`description` + `detail`), `DetectorStatus`, `DetectorFinding`, `Detector` trait (returns single finding), `run_detector_with_timeout()` with `catch_unwind` (panic → `Errored`), `FlowRecord` (canonical `a_ip`/`b_ip` ordering — NOT directional), `DecisionConfig` (`ttl_by_severity: HashMap<Severity, Duration>`), `Verdict`, `FlowFeatures` (`from_flow()` constructor) |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 488 | BPF raw ioctls, SCM_RIGHTS fd handoff, pf anchor init, reconnect loop (accept→enforce→accept), per-connection cache-push thread with `AtomicBool` cancellation. Socket 0666 with `getpeereid()` peer-credential auth. |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 196 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block with AtomicBool TTL cancellation, kill_state, stub reconcile |
| Process lookup | `crates/platform-macos/src/process_lookup.rs` | 668 | `libproc` crate (v0.14) typed structs for all FFI. **Port→PID cache** (`build_port_pid_cache`): per-process fd scan. **Port reading** via `read_port_be()` — raw BE bytes at verified offsets (268/264), bypasses c_int native-endian corruption on LE ARM. |
| Agent binary | `crates/agent/src/main.rs` | 975 | BPF reads, IPv4+IPv6 parsing, enrichment pool integration, stream split for IPC reader thread, `detect_local_ip()` via getifaddrs (5s background refresh, benchmarked at 9.065 us/call), `determine_local_port()` with `is_local(ip)` direction check, `determine_remote_ip()` for enforcement target resolution, local-IP allowlist (belt-and-suspenders: blocks enforcement if remote resolves to local), flow tracker integration, detector framework wired on flow expiry, decision engine wired (enforcement live via IPC), active-flow re-evaluation |
| Detector framework | `crates/agent/src/detectors/mod.rs` | 879 | `RuleDetector` (placeholder v1 rules: dns_blocklist, suspicious_port, high_packet_count), timeout enforcement via `run_detector_with_timeout()`, `catch_unwind` panic safety, `CircuitState` enum (Closed/Open/HalfOpen) with 30s cooldown and recovery, `run_detectors()` takes `&mut HashMap<DetectorId, CircuitState>`. 6 tests. |
| Decision engine | `crates/agent/src/decision/mod.rs` | 420 | `DecisionEngine` with weighted scoring (score × confidence × status_weight), `Verdict` enum (Allow/Block/Alert), `FlowFeatures` extraction, `DecisionConfig` with block/alert thresholds + severity→TTL map. 11 unit tests. Wired into capture loop — Block verdicts send `EnforcementCommand::Block` via IPC to helper |
| Enrichment pool | `crates/agent/src/enrichment/mod.rs` | 495 | 4-thread worker pool (`std::thread` + `mpsc`), DNS reverse via `getnameinfo`, process attribution via libproc, GeoIP/Reputation stubs |
| Flow tracker | `crates/agent/src/flow/mod.rs` | 975 | In-memory session window with ~100ms ticks via `poll()` timeout. Direction-agnostic canonicalization, MAX_FLOWS eviction with O(log n) `BinaryHeap`, local_port + PID stored per-flow, enrichment attachment, `last_evaluated` per-flow, `EVALUATION_INTERVAL_SECS` (1s), `MAX_RE_EVAL_PER_TICK` (100). `tick()` returns `(expired, due_for_re_evaluate)` tuple. Batched re-evaluation scan (every 10th tick). |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 112 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed), stream split via `try_clone()` |

**Total:** 5,797 lines across 11 files.

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
- `RuleDetector` with placeholder v1 rules — ALL THREE produce false positives against legitimate traffic until real tuning/allowlisting:
  - `dns_blocklist`: label-aware match on "malware"/"phish"/"c2". Fixed c2/ec2 false positive (2026-07-25). Still a placeholder — no real blocklist loaded.
  - `suspicious_port`: hardcoded ports 4444/5555/6666/7777/8888/9999/31337. Will false-positive on dev servers, game servers, and any legitimate service on these ports. Needs configurable allowlist.
  - `high_packet_count`: threshold >1000 packets/5s window. Will false-positive on video streaming, large downloads, and any high-bandwidth legitimate flow. Needs per-protocol tuning.
- Timeout enforcement: `run_detector_with_timeout()` runs `evaluate()` on its own thread, uses `recv_timeout()` with configurable budget. Returns `TimedOut` if exceeded.
- Panic safety: `evaluate()` wrapped in `catch_unwind` — panics produce `Errored` finding instead of crashing the thread.
- Wired into capture loop on flow expiry AND active-flow re-evaluation
- **c2 false-positive fix (2026-07-25):** `dns_blocklist` rule's `name.contains("c2")` matched inside `ec2` hostnames (e.g. `ec2-52-73-240-202.compute-1.amazonaws.com`). Fixed: `has_label()` splits on `.`/`-` and checks for standalone label. Regression tests for ec2, malwarebytes, phishing.

### Decision engine — verified (enforcement live)

- `DecisionEngine` in `crates/agent/src/decision/mod.rs`
- Weighted scoring: `score × confidence × status_weight`. TimedOut=0.1x, Errored=0.0x
- Block threshold=0.5, Alert threshold=0.2
- TTL from most severe Completed finding, clamped [30s, 24h]
- `Verdict` enum: `Allow`, `Block { ttl, reason }`, `Alert { reason }`
- `FlowFeatures` extracted from FlowRecord
- `DecisionConfig` with thresholds + severity→TTL map + max TTL clamps
- 11 unit tests pass
- Wired into capture loop — Block verdicts send `EnforcementCommand::Block` via IPC to helper

### Active-flow re-evaluation — verified

- `FlowRecord.last_evaluated: Instant` field
- `EVALUATION_INTERVAL_SECS = 1`, `MAX_RE_EVAL_PER_TICK = 100`
- `tick()` returns `(expired: Vec<u64>, due_for_re_evaluate: Vec<u64>)` — tuple
- `mark_evaluated(flow_id)` bumps `last_evaluated` regardless of finding status
- **Batched scan** — re-evaluation candidates collected every 10th tick (~1s), not every tick. Fixes starvation risk from non-deterministic HashMap iteration.

## Stub (known incomplete — not done)

- **`reconcile()`** (`enforce.rs`): Returns `Ok(ReconciliationReport::default())`.
- **GeoIP enrichment** (`enrichment/mod.rs`): Returns `success: false`.
- **Reputation enrichment** (`enrichment/mod.rs`): Returns `success: false`.

## Known limitations (security-relevant)

1. **Three `?` crash sites in helper reconnect loop** (`main.rs` ~lines 370, 396, 402) — `accept()`, `send_fd()`, `try_clone()` failures propagate via `?` and terminate the helper. Diagnostic wrapper (2026-07-24) logs the error before exit, but does not prevent or recover from the failure. Deliberately left as-is pending real error evidence — generic "catch everything and continue" hardening would mask the actual failure mode.

2. **Helper reconnect crash — root cause unconfirmed.** Helper crashed once during 3-cycle verification (2026-07-23, observed in cycle 2→3 transition). Diagnostic wrapper added (2026-07-24) to log fatal errors. Not reproduced across 6 reconnect cycles post-wrapper (two clean 3-cycle runs). Root cause remains unknown — may be low-probability timing-dependent condition that simply didn't trigger in subsequent runs.

## Known shortcomings (working but fragile)

1. **Hardcoded port offsets (268/264)** — `process_lookup.rs` reads `insi_lport`/`insi_fport` at fixed byte offsets verified by tests against lsof ground truth. Fragile if Apple changes `SocketFDInfo` layout. Will revisit with dynamic offset computation (pointer arithmetic on original struct, not stack copies — see bug #3 below).

2. **Per-flow DNS/GeoIP/Reputation dispatch** — enrichment is dispatched per-flow, not per-destination-IP. This means redundant lookups for flows to the same IP. Fix: global `HashMap<IpAddr, EnrichmentState>` cache. Only process attribution is genuinely flow-specific.

3. ~~No circuit breaker for failing detectors~~ ✅ — `CircuitState` enum (Closed/Open/HalfOpen) with 30s cooldown and recovery. `run_detectors()` takes `&mut HashMap<DetectorId, CircuitState>`. 6 tests.

4. **Decision engine has no uncertainty/findings_summary** — `Verdict::Block` and `Verdict::Alert` lack an `uncertainty` field and per-finding evidence summary. Fix: add fields for dashboard audit trail.

5. **Decision engine treats unavailable detectors as silent zeros** — A circuit-broken, timed-out, or errored detector returns `TimedOut { score: 0, confidence: 0 }`, contributing nothing to the verdict. A degraded pipeline (multiple detectors unavailable) produces normal-looking verdicts with reduced visibility. TODO in `decision/mod.rs` documents the planned `DetectorHealth` metadata fix.

6. **All config is hardcoded** — block/alert thresholds, TTLs, detector budgets are constants in `DecisionConfig`. No TOML/YAML config file loading. Fix: config system with secure defaults.

## Crash history

| Date | Error | Duration before crash | Backtrace | Reproduced? | Root cause |
|---|---|---|---|---|---|
| 2026-07-23 | `Os { code: 13, kind: PermissionDenied }` | ~18s | No | No — not reproduced across 60s run (30s+60s) or 10-minute run (73,500+ packets) | Unexplained, not reproduced |
| 2026-07-23 | Helper crash during 3-cycle reconnect test | Cycle 2→3 transition | No | No — not reproduced across 6 reconnect cycles post-diagnostic-wrapper (two clean 3-cycle runs) | Unconfirmed. Diagnostic wrapper logs error but does not prevent it. Root cause unknown. |
| 2026-07-25 | False-positive block of own machine (192.168.0.102) | N/A — not a crash | N/A | Yes — deterministic. `dns_blocklist` rule's `name.contains("c2")` matched inside `ec2` in AWS EC2 hostnames. Fixed: `has_label()` splits on `.`/`-` and checks for standalone label. Regression tests for ec2, malwarebytes, phishing. | Rule bug: substring match on `c2` matched within `ec2-...` hostnames. All AWS EC2 traffic false-positived. |
| 2026-07-25 | Enforcement targets local IP instead of remote | N/A — not a crash | N/A | Yes — deterministic. `common_flow.dst_ip` reads `flow.key.b_ip` (the numerically larger IP). For flows where local IP > remote IP (e.g. 192.168.0.102 > 52.73.240.202), `b_ip` is the local machine. Fixed: `determine_remote_ip()` uses `is_local(ip)` to identify the remote endpoint. `FlowRecord.dst_ip` renamed to `b_ip` to prevent future confusion. 4 regression tests. Live verified: pfctl table shows remote IPs (172.65.90.23, 17.57.146.59), not 192.168.0.102. | Same class of bug as the original local_port issue — canonical key ordering loses direction info. |

**Investigation performed (EACCES crash):** Agent code audited for file I/O outside BPF/IPC — zero matches. Grep for `File::open`, `fs::write`, `database`, `GeoIP` — all field-name false positives. `RUST_BACKTRACE=full` set for all subsequent runs. No backtrace captured because the crash did not reproduce.

**Investigation performed (helper reconnect crash):** Diagnostic wrapper added to `main()` — extracts `run() -> io::Result<()>`, logs `log::error!` with `{e:?}` and `{e}` on failure before `process::exit(1)`. The 3 `?` sites in the reconnect loop (`accept`, `send_fd`, `try_clone`) are left unchanged — any one could be the failure point. Wrapper did not catch the failure in any of the 6 subsequent reconnect cycles, meaning either (a) root cause was timing-dependent and didn't trigger, or (b) something about the wrapper environment incidentally avoided it.

**Status:** Two unexplained crash events. EACCES crash: one occurrence, not reproduced. Helper reconnect crash: one occurrence, not reproduced across 6 cycles post-wrapper. Root causes unknown for both. Treat as low-probability, unresolved risks, not fixed bugs. Will remain in this ledger as open items until either: (a) root cause is identified, or (b) sufficient run-time accumulates without recurrence to justify closing.

## Not built

- Storage (SQLite WAL single-writer worker)
- Tauri UI dashboard
- AI post-analysis (UI layer only — event summarization, KPI explanations, report generation, recommendations)
- Windows/Linux support (intentionally excluded — §1b)

## Audit fixes (2026-07-25)

9 fixes from Linus-style code audit, ordered easiest→hardest:

| # | Fix | File | Status |
|---|---|---|---|
| 1 | Deduplicated PF_ANCHOR_NAME/PF_TABLE_NAME/IPC_SOCKET_PATH | `common/src/lib.rs` | Verified |
| 2 | Removed dead code (TEST_TARGET_IP, BLOCK_TTL, blocked HashSet) | `agent/main.rs` | Verified |
| 3 | Updated stale line counts in docs | `doc/STATUS.md` | Verified |
| 4 | Added `catch_unwind` to `run_detector_with_timeout()` | `common/src/types.rs` | Verified |
| 5 | IPC socket permissions — code is 0o666 (audit fix #5 reverted in later commit) | `platform-macos/helper/main.rs` | Known — permissions remain 0o666 |
| 6 | TTL cancellation via `AtomicBool` in `apply_block()` | `platform-macos/helper/enforce.rs` | Verified |
| 7 | `From<flow::FlowRecord>` impl, eliminated `.clone().into()` boilerplate | `agent/flow/mod.rs` | Verified |
| 8 | O(log n) eviction via `BinaryHeap` (replaces linear scan) | `agent/flow/mod.rs` | Verified |
| 9 | Batched re-evaluation scan every 10th tick (~1s) | `agent/flow/mod.rs` | Verified |

| 10 | Helper reconnect loop (accept→enforce→accept) with per-connection cache-push cancellation via `Arc<AtomicBool>` | `platform-macos/helper/main.rs` | Verified |

All 63 tests pass. clippy clean. fmt clean.
