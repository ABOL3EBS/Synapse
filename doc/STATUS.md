# Implementation Status — Synapse IPS

**Last verified:** 2026-07-29. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Latest change (2026-07-30)

- **Storage subsystem built (crash-safe, tiered-durability SQLite).** Full implementation across 5 files (1140 lines). Key properties:
  - **Crash-safe spool:** separate SQLite (`synapse-spool.db`) with `synchronous=FULL; journal_mode=DELETE`. Every `EnforcementRequested` event is appended to the spool *before* the main DB write. On startup, unconfirmed spool entries are replayed via `INSERT OR IGNORE` (idempotent) into the main DB and then confirmed — enforcement records survive agent crash.
  - **Three `StorageEvent` variants:** `EnforcementRequested` (Critical — goes to spool first), `VerdictDecided` (Important — Alert/Block verdicts with full findings), `CircuitBreakerTransition` (Important — detector health history).
  - **Binary IP storage:** IPs stored as 16-byte BLOB (IPv4-mapped IPv6 form) for exact-match lookups plus TEXT (human-readable) for queries — both columns always populated.
  - **SQLite hardening:** `WAL; foreign_keys=ON; trusted_schema=OFF; secure_delete=ON` applied on every connection open.
  - **Versioned schema** via `PRAGMA user_version` — V1 DDL applied once, future versions apply `ALTER TABLE` incrementally.
  - **Retention:** enforcement_log 90d, verdicts+findings (CASCADE) 7d, CB events 7d — pruned every 2000th batch.
  - **Read path:** `StorageReader` (separate read-only connection, `query_only=ON`) with `recent_verdicts`, `verdict_findings`, `recent_enforcement`, `detector_health`, `kpi_since` — ready for Tauri IPC when wired up.
  - **Boot ID:** `timestamp_nanos XOR Fibonacci_hash(pid)` — unique per process startup, prefixed to event IDs so cross-restart `INSERT OR IGNORE` deduplication is correct.
  - 3 new tests: `test_ip_roundtrip_v4`, `test_ip_roundtrip_v6`, `test_spool_append_and_confirm`.

- **`decision/mod.rs`: `evaluate()` now returns `(Verdict, f32)`.** Composite score was computed internally and discarded; surfacing it as the second return value lets `capture.rs` store it in `VerdictDecided` without re-computation. All 15 decision tests updated.

- **`detectors/mod.rs`: `run_detectors()` now returns `(Vec<DetectorFinding>, Vec<CbTransition>)`.** Circuit breaker state transitions are collected during detection and returned as a second value rather than threading a `storage_tx` into the detector module. `capture.rs` calls `emit_cb_transitions()` with the returned vec — keeps all storage coupling at the capture layer. `CbTransition` struct added to `detectors/mod.rs`. All detector tests updated.

- **`capture.rs`: `handle_verdict()` emits `VerdictDecided` and `EnforcementRequested`.** Now emits `VerdictDecided` for Alert and Block verdicts (before enforcement IPC), then `EnforcementRequested` for Block verdicts (with `send_error: None/Some` tracking whether IPC succeeded). `emit_cb_transitions()` helper method added.

## Latest change (2026-07-29)

- **Bug #2 fixed: re-evaluation scheduling broken by VecDeque regression.** The `flow/mod.rs` VecDeque-based re-evaluation queue (`eaa1566`, Jul 28) had a logic error: `flow.last_evaluated >= entry_time` treated creation-time entries (where `last_evaluated == entry_time == now`) as stale and consumed them immediately, leaving the queue permanently empty. Fix:
  1. Changed stale check to `last_evaluated > entry_time` (strictly greater) — the creation-time `==` case no longer matches as stale.
  2. Added explicit wall-clock due check `now - last_evaluated < evaluation_interval_secs` → leave entry in queue; only pop when truly due.
  3. Removed `#[allow(dead_code)]` from `evaluation_interval_secs` — now actively used.
  4. Rewrote 3 re-evaluation tests that had bypassed the bug by directly injecting into `re_eval_queue` — they now exercise the real code path (creation-time entry → backdate last_evaluated → tick → due).

- Added `info!("[ALLOW] flow={}", flow_id)` to `handle_verdict()` in `capture.rs:620` — Allow verdicts were silently producing zero output, making the detector→decision→enforcement path appear broken. All normal traffic returns Allow (score < 0.3), and the empty match arm `Allow => {}` produced no log line. Now every flow's verdict is visible.

## Built and working

| Component | File | Lines | Key details |
|---|---|---|---|
| Common types | `crates/common/src/lib.rs` | 115 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `EnrichmentRequest`, `EnrichmentResult`, `EnrichmentKind`, IPC constants (`PF_ANCHOR_NAME`, `PF_TABLE_NAME`, `IPC_SOCKET_PATH`), re-exports `Detector`, `run_detector_with_timeout`, `DecisionConfig`, `Verdict`, `FlowFeatures` |
| Shared types | `crates/common/src/types.rs` | 803 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`, `PortPidCache` (HashMap-based), `IpcMessage` enum, enrichment types, `DetectorId` (8 variants: `CrossFlow`, `RuleEngine`, `ReputationEngine`, `DnsAnalyzer`, `ProcessCorrelator`, `FlowBehavior`, `IpReputation`, `DnsTunnelDetector`, `Custom(u16)`), `Severity`, `Evidence`, `DetectorStatus`, `DetectorFinding`, `Detector` trait, `run_detector_with_timeout()` with `catch_unwind`, `FlowRecord`, `DecisionConfig` (block=0.7, alert=0.3, `min_detectors_for_block: 2`, `override_threshold: 0.85`, `ttl_by_severity: HashMap<Severity, Duration>`), `Verdict`, `FlowFeatures` |
| Log formatter | `crates/common/src/log_format.rs` | 68 | Shared ANSI-colored formatter via `env_logger` + `colored`. `init_logging()` called once per binary. Message-content-aware coloring: `[BLOCK]`=red, `[ENFORCE]`=green, `[ALERT]`/`[SKIP]`=yellow, flow/enrich=cyan. HH:MM:SS timestamps. |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 488 | BPF raw ioctls, SCM_RIGHTS fd handoff, pf anchor init, reconnect loop (accept→enforce→accept), per-connection cache-push thread with `AtomicBool` cancellation. Socket 0666 with `getpeereid()` peer-credential auth. |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 196 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block with AtomicBool TTL cancellation, kill_state, stub reconcile |
| Process lookup | `crates/platform-macos/src/process_lookup.rs` | 673 | `libproc` crate (v0.14) typed structs for all FFI. **Port→PID cache** (`build_port_pid_cache`): per-process fd scan. **Port reading** via `read_port_be()` — raw BE bytes at verified offsets (268/264), bypasses c_int native-endian corruption on LE ARM. |
| Agent binary | `crates/agent/src/main.rs` | 316 | Startup + orchestration only. Loads `AgentConfig` (TOML), passes config to all components. BPF fd receive, IPC reader thread, local IP detection, GeoIP/feeds loading via config paths, CaptureEngine creation, capture loop delegation. 6 production detectors (incl. CrossFlow) registered. Tests for BPF wordalign, packet parsing. |
| Capture engine | `crates/agent/src/capture.rs` | 1528 | `CaptureEngine` struct: BPF read buffer, packet parsing (IPv4+IPv6 with `payload_length` parsing), flow tracker integration, enrichment dispatch, verdict handling via `handle_verdict()`, active-flow re-evaluation, `CrossFlowState` wired (record_connection on NewFlow, purge_expired on tick). Direction helpers. **Enforcement guards.** BpfHdr struct. `handle_verdict()` emits `VerdictDecided` (Alert+Block) and `EnforcementRequested` (Block) to storage worker. `emit_cb_transitions()` emits circuit-breaker state changes. 22 tests. |
| Config | `crates/agent/src/config.rs` | 518 | TOML config (`toml = "0.8"`) with `#[serde(default)]` on all structs. `AgentConfig::load()` reads from `SYNAPSE_CONFIG` env or `~/.synapse/synapse.toml`. Missing/malformed → all defaults. Env var overrides for GEOIP_DB_PATH, FEEDS_DIR, SYNAPSE_DB_PATH. Conversion methods: `decision_config()`, `flow_config()`, `circuit_breaker_config()`, `detector_timeout()`, `poll_timeout_ms()`, `geoip_db_path()`, `feeds_dir()`, `storage_db_path()`. 7 tests. |
| Detector framework | `crates/agent/src/detectors/mod.rs` | 718 | Circuit breaker, `run_detectors()`, `run_detector_with_timeout()` with `catch_unwind` panic safety. 6 production detector sub-modules (incl. CrossFlow). `run_detectors()` returns `(Vec<DetectorFinding>, Vec<CbTransition>)` — CB transitions bubbled to `capture.rs` for storage emission (keeps storage coupling out of detector module). `CbTransition { detector_id, from_state, to_state, consecutive_failures }` struct. 7 infrastructure tests. |
| DNS Analyzer | `crates/agent/src/detectors/dns_analyzer.rs` | 493 | `DetectorId::DnsAnalyzer` v1.0.0. 7 sub-detectors: entropy, length, longest label, label count, IP literal, blocklist, suspicious TLDs. **CDN carve-out removed** — CDN-hosted C2 evaluated normally. Allowlist short-circuit. Normalized score [0,1]. 11 unit tests. |
| CrossFlow Detector | `crates/agent/src/detectors/cross_flow.rs` | 303 | `DetectorId::CrossFlow` v1.0.0. Per-IP cross-flow analytics via `CrossFlowState` (Arc<Mutex>). 2 active sub-detectors (scan connection count, DNS query burst), 2 planned sub-detectors (beaconing, connection diversity — deferred, needs SQLite). Max-of-sub-detectors scoring. 5 unit tests. |
| Process Correlator | `crates/agent/src/detectors/process_correlator.rs` | 463 | `DetectorId::ProcessCorrelator` v1.0.0. Contextual behavioral scoring: temp dir execution, shell/interpreter network activity, uncommon binary location (with Homebrew/usr/local/app bundle recognition), unresolved process. **Known-safe allowlist** (31 entries: browsers, OS services, common CLI tools) → score 0.0 immediately. NOT rigid process→port mappings. 10 unit tests. |
| Flow Behavior | `crates/agent/src/detectors/flow_behavior.rs` | 355 | `DetectorId::FlowBehavior` v1.0.0. 6 sub-detectors: packet rate, bytes/packet (standard port exemption for 80/443/8443 using `remote_port` disambiguation), bulk transfer, scan pattern, burst, protocol/port mismatch. 8 unit tests. |
| IP Reputation | `crates/agent/src/detectors/ip_reputation.rs` | 366 | `DetectorId::IpReputation` v1.0.0. Blocklist/allowlist/RFC1918 awareness (checks **both** IPs) + enrichment reputation score. Allowlisted IPs reduce score. **Expanded blocklist (20 entries).** 7 unit tests. |
| DNS Tunnel Detector | `crates/agent/src/detectors/dns_tunnel.rs` | 387 | `DetectorId::DnsTunnelDetector` v1.0.0. Only triggers on DNS flows (UDP/53). DNS-over-HTTPS (port 443) returns early with 0.0. 4 sub-detectors: subdomain entropy, longest label, query frequency, payload size. 7 unit tests. |
| Decision engine | `crates/agent/src/decision/mod.rs` | 531 | `DecisionEngine` with weighted scoring, `Verdict` enum, `FlowFeatures` extraction, `DecisionConfig` (block=0.7, alert=0.3, `min_detectors_for_block: 2`, **`override_threshold: 0.85`**, severity→TTL map). **override_threshold allows single high-confidence detector to block.** `evaluate()` returns `(Verdict, f32)` — verdict plus composite score. 15 unit tests. Wired into capture loop — Block verdicts send `EnforcementCommand::Block` via IPC |
| Enrichment pool | `crates/agent/src/enrichment/mod.rs` | 715 | Configurable worker count (`std::thread` + `mpsc`), DNS reverse via `getnameinfo`, process attribution via libproc, **GeoIP via maxminddb 0.30** (`GeoIpDb` wrapper over `Arc<Reader<Vec<u8>>>`, `lookup()` returns `(country_code, asn)`, `is_public_ip()` free fn skips RFC1918/loopback/CGNAT/link-local), reputation store |
| Flow tracker | `crates/agent/src/flow/mod.rs` | 1045 | In-memory session window with configurable tick interval via `FlowConfig`. Direction-agnostic canonicalization, configurable `max_flows` eviction with O(log n) `BinaryHeap`, local_port + PID stored per-flow, enrichment attachment, `last_evaluated` per-flow. `tick()` returns `(expired, due_for_re_evaluate)` tuple. O(k) VecDeque-based re-evaluation scheduling with wall-clock due check. |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 164 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed), stream split via `try_clone()` |
| Storage worker | `crates/agent/src/storage/` (5 files) | 1140 | `StorageWorker` + `StorageEvent` enum (`EnforcementRequested`, `VerdictDecided`, `CircuitBreakerTransition`). Crash-safe spool (`CriticalSpool` — separate DB, `synchronous=FULL`). Idempotent replay via `INSERT OR IGNORE` + stable event IDs (`boot_id XOR fib_hash(pid)` prefix). Binary IP storage (16-byte BLOB + TEXT, always both). SQLite hardening PRAGMAs. V1 schema via `PRAGMA user_version`. Retention: enforcement_log 90d, verdicts+findings (CASCADE) 7d, CB events 7d. `StorageReader` (read-only connection, `query_only=ON`) with `recent_verdicts`, `verdict_findings`, `recent_enforcement`, `detector_health`, `kpi_since`. `#![allow(dead_code)]` on models/reader until Tauri IPC is wired. 3 tests. |

**Total:** 11,561 lines across 25 files. 157 tests (135 agent + 16 common + 6 platform-macos).

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
- **6 production detectors** (all implement `Detector` trait, return `DetectorFinding`):
  - `DnsAnalyzer`: entropy, length, longest label, label count, IP literal, blocklist, suspicious TLDs. CDN carve-out removed.
  - `ProcessCorrelator`: contextual behavioral scoring (temp dir execution, shell network activity, uncommon binary location, unresolved process).
  - `FlowBehavior`: packet rate, bytes/packet, bulk transfer, scan pattern, burst, protocol/port mismatch.
  - `IpReputation`: blocklist/allowlist/RFC1918 awareness + enrichment reputation score.
  - `DnsTunnelDetector`: subdomain entropy, longest label, query frequency, payload size (DNS flows only).
  - `CrossFlowDetector`: per-IP scan/DNS burst detection via shared CrossFlowState.
- **RuleDetector** (placeholder v1): `dns_blocklist`, `suspicious_port`, `high_packet_count` — ALL THREE produce false positives until real tuning. Kept for backward compat.
- Timeout enforcement: `run_detector_with_timeout()` runs `evaluate()` on its own thread, uses `recv_timeout()` with configurable budget. Returns `TimedOut` if exceeded.
- Panic safety: `evaluate()` wrapped in `catch_unwind` — panics produce `Errored` finding instead of crashing the thread.
- Wired into capture loop on flow expiry AND active-flow re-evaluation
- **c2 false-positive — RuleDetector fixed, DnsAnalyzer still vulnerable (2026-07-29):** The RuleDetector's `dns_blocklist` rule was fixed via `has_label()` (splits on `.`/`-`). **However, DnsAnalyzer's `score_blocklist()` method still uses `lower.contains(b.as_str())`** — substring matching, not label-aware. A hostname like `ec2-malware.com` would match a blocklist entry containing `malware` even though it's a completely different name. See Known shortcomings #6.

### Decision engine — verified (enforcement live)

- `DecisionEngine` in `crates/agent/src/decision/mod.rs`
- Weighted scoring: `score × confidence × status_weight`. TimedOut=0.1x, Errored=0.0x
- Block threshold=0.7, Alert threshold=0.2
- TTL from most severe Completed finding, clamped [30s, 24h]
- `Verdict` enum: `Allow`, `Block { ttl, reason }`, `Alert { reason }`
- `FlowFeatures` extracted from FlowRecord
- `DecisionConfig` with thresholds + severity→TTL map + max TTL clamps
- **`min_detectors_for_block: 2`** — single detector cannot trigger Block
- **`override_threshold: 0.85`** — single high-confidence detector CAN trigger Block
- 15 unit tests pass
- Wired into capture loop — Block verdicts send `EnforcementCommand::Block` via IPC to helper

### Active-flow re-evaluation — verified

- `FlowRecord.last_evaluated: Instant` field
- Configurable via `FlowConfig`: `evaluation_interval_secs = 1`, `max_re_eval_per_tick = 100`
- `tick()` returns `(expired: Vec<u64>, due_for_re_evaluate: Vec<u64>)` — tuple
- `mark_evaluated(flow_id)` bumps `last_evaluated` regardless of finding status
- **Batched scan** — re-evaluation candidates collected every 10th tick (~1s), not every tick. Fixes starvation risk from non-deterministic HashMap iteration.

## Stub (known incomplete — not done)

- **`reconcile()`** (`enforce.rs`): Returns `Ok(ReconciliationReport::default())`.
- **Reputation enrichment** (`enrichment/mod.rs`): `ReputationStore` loads blocklist/CIDR/CSV feeds but `lookup()` returns `None` for IPs not in any feed. No live reputation scoring yet.

## Known limitations (security-relevant)

1. **Three `?` crash sites in helper reconnect loop** (`main.rs` ~lines 370, 396, 402) — `accept()`, `send_fd()`, `try_clone()` failures propagate via `?` and terminate the helper. Diagnostic wrapper (2026-07-24) logs the error before exit, but does not prevent or recover from the failure. Deliberately left as-is pending real error evidence — generic "catch everything and continue" hardening would mask the actual failure mode.

2. **Helper reconnect crash — root cause unconfirmed.** Helper crashed once during 3-cycle verification (2026-07-23, observed in cycle 2→3 transition). Diagnostic wrapper added (2026-07-24) to log fatal errors. Not reproduced across 6 reconnect cycles post-wrapper (two clean 3-cycle runs). Root cause remains unknown — may be low-probability timing-dependent condition that simply didn't trigger in subsequent runs.

## Known shortcomings (working but fragile)

1. **Hardcoded port offsets (268/264)** — `process_lookup.rs` reads `insi_lport`/`insi_fport` at fixed byte offsets verified by tests against lsof ground truth. Fragile if Apple changes `SocketFDInfo` layout. Will revisit with dynamic offset computation (pointer arithmetic on original struct, not stack copies — see bug #3 below).

2. **Per-flow DNS/GeoIP/Reputation dispatch** — enrichment is dispatched per-flow, not per-destination-IP. This means redundant lookups for flows to the same IP. Fix: global `HashMap<IpAddr, EnrichmentState>` cache. Only process attribution is genuinely flow-specific.

3. ~~No circuit breaker for failing detectors~~ ✅ — `CircuitState` enum (Closed/Open/HalfOpen) with configurable cooldown via `CircuitBreakerConfig`. `run_detectors()` takes `&CircuitBreakerConfig`. 7 tests.

4. **Decision engine has no uncertainty/findings_summary** — `Verdict::Block` and `Verdict::Alert` lack an `uncertainty` field and per-finding evidence summary. Fix: add fields for dashboard audit trail.

5. **Decision engine treats unavailable detectors as silent zeros** — A circuit-broken, timed-out, or errored detector returns `TimedOut { score: 0, confidence: 0 }`, contributing nothing to the verdict. A degraded pipeline (multiple detectors unavailable) produces normal-looking verdicts with reduced visibility. TODO in `decision/mod.rs` documents the planned `DetectorHealth` metadata fix.

6. **DnsAnalyzer blocklist uses substring matching, not label-aware** — `score_blocklist()` at `dns_analyzer.rs:188` calls `lower.contains(b.as_str())`. A blocklist entry for `malware` matches any hostname containing `malware` anywhere (e.g. `legitimate-malware-analysis.com`). Same bug class as the original RuleDetector `ec2`/`c2` false-positive, but in a different code path. RuleDetector was fixed via `has_label()`; DnsAnalyzer remains unfixed because its blocklist is currently small (3 test entries) and the false-positive surface in probe testing was acceptable. Fix: replace `contains` with label-aware matching in a follow-up.

## Crash history

| Date | Error | Duration before crash | Backtrace | Reproduced? | Root cause |
|---|---|---|---|---|---|
| 2026-07-23 | `Os { code: 13, kind: PermissionDenied }` | ~18s | No | No — not reproduced across 60s run (30s+60s) or 10-minute run (73,500+ packets) | Unexplained, not reproduced |
| 2026-07-23 | Helper crash during 3-cycle reconnect test | Cycle 2→3 transition | No | No — not reproduced across 6 reconnect cycles post-diagnostic-wrapper (two clean 3-cycle runs) | Unconfirmed. Diagnostic wrapper logs error but does not prevent it. Root cause unknown. |
| 2026-07-25 | False-positive block of own machine (192.168.0.102) | N/A — not a crash | N/A | Yes — deterministic. RuleDetector's `dns_blocklist` rule's `name.contains("c2")` matched inside `ec2` in AWS EC2 hostnames. **RuleDetector fixed** via `has_label()`. **DnsAnalyzer still vulnerable** — see Known shortcomings #6. | Rule bug: substring match on `c2` matched within `ec2-...` hostnames. All AWS EC2 traffic false-positived. |
| 2026-07-25 | Enforcement targets local IP instead of remote | N/A — not a crash | N/A | Yes — deterministic. `common_flow.dst_ip` reads `flow.key.b_ip` (the numerically larger IP). For flows where local IP > remote IP (e.g. 192.168.0.102 > 52.73.240.202), `b_ip` is the local machine. Fixed: `determine_remote_ip()` uses `is_local(ip)` to identify the remote endpoint. `FlowRecord.dst_ip` renamed to `b_ip` to prevent future confusion. 4 regression tests. Live verified: pfctl table shows remote IPs (172.65.90.23, 17.57.146.59), not 192.168.0.102. | Same class of bug as the original local_port issue — canonical key ordering loses direction info. |
| 2026-07-28 | Mass false-positive blocking all legitimate traffic | N/A — not a crash | N/A | Yes — 3 design flaws combined. Fixed: (1) FlowBehavior bpp port check now uses `remote_port` via `local_port` disambiguation, not canonical `b_port`. (2) IpReputation RFC1918 check on both `a_ip` and `b_ip`. (3) DecisionEngine: block_threshold 0.5→0.7, alert_threshold 0.2→0.3, `min_detectors_for_block: 2`. (4) ProcessCorrelator known-safe allowlist (31 entries). (5) Deleted `/tmp/synapse-test.toml` (block_threshold=0.01 test config). 127 tests. | Test config with dangerously low threshold (`/tmp/synapse-test.toml`) plus FlowBehavior using canonical `b_port` (local ephemeral port) instead of remote port for standard port exemption. IpReputation only checked `b_ip` for RFC1918. |
| 2026-07-29 | Re-evaluation dead code (every flow evaluated once at expiry, never re-checked during lifetime) | N/A — not a crash | N/A | Yes — deterministic. VecDeque introduced in `eaa1566` (Jul 28) replaced working HashMap scan. `last_evaluated >= entry_time` treated creation-time entries as stale (both equal `now`) and consumed them immediately. Queue permanently empty. **Tests bypassed the bug** by injecting queue entries directly. Fix: strict `>` stale check + wall-clock due guard. All 3 re-eval tests rewritten to exercise real code path. | VecDeque logic error: stale check `>=` instead of `>`. No review — applied directly to main ("hot path optimizations"). No test exercised the real `update()`→queue→`tick()`→due cycle. |

**Investigation performed (EACCES crash):** Agent code audited for file I/O outside BPF/IPC — zero matches. Grep for `File::open`, `fs::write`, `database`, `GeoIP` — all field-name false positives. `RUST_BACKTRACE=full` set for all subsequent runs. No backtrace captured because the crash did not reproduce.

**Investigation performed (helper reconnect crash):** Diagnostic wrapper added to `main()` — extracts `run() -> io::Result<()>`, logs `log::error!` with `{e:?}` and `{e}` on failure before `process::exit(1)`. The 3 `?` sites in the reconnect loop (`accept`, `send_fd`, `try_clone`) are left unchanged — any one could be the failure point. Wrapper did not catch the failure in any of the 6 subsequent reconnect cycles, meaning either (a) root cause was timing-dependent and didn't trigger, or (b) something about the wrapper environment incidentally avoided it.

**Status:** Two unexplained crash events. EACCES crash: one occurrence, not reproduced. Helper reconnect crash: one occurrence, not reproduced across 6 cycles post-wrapper. Root causes unknown for both. Treat as low-probability, unresolved risks, not fixed bugs. Will remain in this ledger as open items until either: (a) root cause is identified, or (b) sufficient run-time accumulates without recurrence to justify closing.

## Not built

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

All 157 tests pass. clippy clean. fmt clean.
