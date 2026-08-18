# Implementation Status — Synapse IPS

**Last verified:** 2026-08-18. Ground-truth ledger — if this file and the architecture doc disagree, this file wins.

## Latest change (2026-08-18) — Steps A–F complete: canonical-vs-directional field migration

**Migration closed.** The recurring bug class where `FlowRecord.a_ip`/`b_ip` canonical fields were treated as directional (`src`/`dst`) is now structurally prevented across all layers — agent, detectors, storage, and dashboard.

### What changed

| Step | Layer | Change |
|---|---|---|
| A | `FlowRecord` / `flow/mod.rs` | Added `ResolvedFlow { local_ip, local_port, remote_ip, remote_port }` — direction resolved once at flow creation, stored on the record |
| B | `FlowBehavior` | Extract `remote_port` from `flow.resolved` (safe `.expect()` — catch_unwind protection documented) |
| C | `FlowFeatures::from_flow()` | Interim: `Option<Self>` + `warn!` for `resolved=None`; call sites guard before calling |
| D | `FlowFeatures::from_flow()` | Final: signature changed to `from_flow(&FlowRecord, &ResolvedFlow) -> Self` — compile error to call without direction resolved. No more `Option<Self>`. |
| E | `DnsTunnelDetector` | **Security-relevant false negative fixed** — `b_port` replaced with `resolved.remote_port` at both port check sites. Silent zero-score on all DNS flows where local IP > DNS server IP. Test fixture bug fixed (`b_port: 53` → `50000`). Regression test added. |
| F | Storage + dashboard | `VerdictDecided` carries `remote_ip: IpAddr`. Schema V5 adds `remote_ip_text` column. Dashboard reads it verbatim (no re-derivation); `pick_remote()` fallback for NULL pre-V5 rows. |

### Step F detail

- `StorageEvent::VerdictDecided` gains `remote_ip: IpAddr` field.
- `crates/agent/src/storage/schema.rs`: `SCHEMA_VERSION = 5`; idempotent V5 migration adds `ALTER TABLE verdicts ADD COLUMN remote_ip_text TEXT`.
- `crates/agent/src/storage/mod.rs`: flush handler computes `remote_ip.to_string()` and includes it as `?25` in INSERT + ON CONFLICT DO UPDATE.
- `capture.rs`: both `VerdictDecided` emit sites (Alert and Block paths in `handle_verdict()`) pass `remote_ip: remote` — already had `let remote = resolved.remote_ip` computed at line 1070.
- `src-tauri/src/lib.rs`: SELECT now fetches `v.remote_ip_text` (column 10). Mapper uses `stored_remote.unwrap_or_else(|| pick_remote(...))` — V5+ rows never re-derive; pre-V5 rows fall back to `pick_remote()` using `local_ip_text` (V3+).

### New tests (Step F)

- `test_verdict_remote_ip_text_roundtrip` — persists a `VerdictDecided` event and reads `remote_ip_text` back verbatim.
- `test_swap_case_remote_ip_text_correct` — constructs the swap-case flow (`local=192.168.1.1 > remote=8.8.8.8`, so `a_ip=8.8.8.8` canonical), confirms `remote_ip_text = "8.8.8.8"` (not `b_ip_text = "192.168.1.1"` which is the local machine). This is the test that closes the dashboard's instance of the bug class.

**Final test count:** 189 workspace tests, 0 failures. `cargo clippy -- -D warnings` clean. `cargo fmt --check` clean.

---

## Previous change (2026-08-18) — Step E: DnsTunnelDetector direction bug fix (security-relevant false negative)

**Finding type:** Silent false negative on an entire class of DNS flows — found via structural audit (Steps A–D), not a live incident.

**Root cause:** `DnsTunnelDetector::evaluate()` used `flow.b_port` to identify DNS flows (port 53) and DoH flows (port 443). `b_port` is the canonically *larger* port — it is the DNS server port only when the DNS server IP is numerically larger than the local IP. When local IP > DNS server IP (e.g., `local=10.0.0.100 > dns=8.8.8.8`), canonical ordering puts the DNS server at `a_ip`/`a_port=53`; `b_port` becomes the local ephemeral port (e.g., 50000). Both port checks then fail silently: `is_dns_flow(17, 50000) = false` → "Not a DNS flow" → score 0.0. All DNS tunnel analysis dropped for that flow class. Same bug class as the `src_ip`/`dst_ip` enforcement error (2026-07-25) — canonical field treated as directional without going through `resolved`.

**Fix:** Extract `remote_port` from `flow.resolved` at the top of `evaluate()` (`.expect()` — safe behind `catch_unwind` in `worker_loop`, same reasoning as `FlowBehavior`). Both port checks now use `remote_port` instead of `b_port`. Comment at each site documents why `.expect()` is correct.

**Test fixture fix:** `make_dns_flow` had `b_port: 53` — structurally wrong (b_ip is the local side; b_port should be the local ephemeral port). Changed to `b_port: 50000`. This masked the bug in every existing test. `test_doh_port_443_early_return` updated to set `resolved.remote_port=443` rather than overriding `b_port`.

**New regression test:** `test_dns_flow_local_ip_larger_than_server` — constructs the exact failure case (`local=10.0.0.100 > dns=8.8.8.8`, `b_port=50000`), confirms `score > 0` and no "Not a DNS flow" evidence. This test would have caught the bug from the start.

**Files:** `crates/agent/src/detectors/dns_tunnel.rs`. 8 tests → 8 tests (1 new). 222 total workspace tests, 0 failures.

## Latest change (2026-08-12) — dashboard UI polish (5 groups)

Five groups of UI improvements shipped and verified in the real Tauri window.

| Group | What | Files |
|---|---|---|
| 1 | Block verdict dot + badge → red (`bg-danger` / `text-danger bg-danger-light`) | `ActivityRow.tsx` |
| 2 | BlockRow shows detector findings as subtitle under IP (strips boilerplate prefix); composite score added to ActivityRow technical-details panel | `SettingsScreen.tsx`, `ActivityRow.tsx`, `src-tauri/src/lib.rs`, `db.ts` |
| 3 | Active block countdown ticks live (1 s) via `useNow` hook; Activity relative timestamps drift in real time | `SettingsScreen.tsx`, `ActivityRow.tsx`, `time.ts`, `hooks/useNow.ts` |
| 4 | Activity polls every 5 s (was 30 s); Protection polls every 10 s (was 30 s). `busy_timeout=5000` verified safe | `ActivityScreen.tsx`, `ProtectionScreen.tsx` |
| 5 | New verdict rows appearing between polls flash green (`rgba(16,185,129,0.22)` → white, 1.4 s). `seenIds` ref skips initial mount so only genuine new rows flash | `ActivityScreen.tsx`, `ActivityRow.tsx`, `index.css` |

**Composite score end-to-end (Group 2):** `composite_score: Option<f64>` added to `ActivityItem` Rust struct; SQL SELECT now fetches `v.composite_score`; TypeScript interface updated; `DetailRow` renders it between Location and Detectors in the expanded technical-details panel.

**`useNow` hook:** `src/hooks/useNow.ts` — `setInterval` tick every 1 s, returns `Date.now()`. Used by both `ActivityRow` (timestamps) and `BlockRow` (countdown: `remaining_ms − (now − fetchedAt)`).

## Latest change (2026-08-11) — true-positive validation pass (all active detectors)

Full E2E test of every detector capable of firing under RFC 5737 constraints. Test traffic targeted RFC 5737 ranges only (203.0.113.0/24, 198.51.100.0/24). Production thresholds throughout (block=0.70, alert=0.30, override=0.85, min_detectors_for_block=2). Agent and helper both running on real hardware (en0, VPN down for routing sanity).

### Results

| Detector | Scenario | Expected verdict | Actual verdict | Pass/Fail |
|---|---|---|---|---|
| CrossFlow (scan, medium-tier) | 120 TCP connections to 203.0.113.1:1–120 in <2s (Python socket.connect_ex) | Alert (CrossFlow alone: adjusted=0.56) | **Block** (CrossFlow + IpReputation + ProcessCorrelator co-fired) | PASS — block correct; co-fire documented below |
| CrossFlow (scan, high-tier / override) | 240 TCP connections to 203.0.113.1:1–240 in <2s (cooldown from Scenario 1 active) | Block (override: 0.90×0.95=0.855 ≥ 0.85) | **Block** confirmed in debug log (`score=0.90 conf=0.95`); re-enforcement suppressed by cooldown | PASS — override score confirmed; cooldown behavior expected |
| CrossFlow (beaconing) | 7 TCP connections to 198.51.100.1:9999 at 5s intervals (Python sleep loop) | Alert (score=0.60/0.60, adjusted=0.36 < 0.70; alert threshold passed) | **Alert** `score 0.61: Beacon-like periodicity: 7 connections, mean=5.0s, CV=0.001` | PASS |
| IpReputation | Single TCP connection to 203.0.113.1 after adding to blocklist | Block (IpReputation score=0.70, conf=0.80, adjusted=0.56; + RFC1918 evidence for 2 detectors) | **Block** `score 1.00: Destination IP matches blocklist; Source IP is RFC1918 (local network)` | PASS |
| DnsTunnelDetector | — | **UNTESTED** | — | — |
| ProcessCorrelator | — (passive; contributed unresolved-PID signal during Scenario 1 scan) | Nonzero contribution expected for short-lived Python sockets | Confirmed contributing (python3 connections fail PID attribution; `score_unresolved_process` fires) | PASS (passive verification) |
| FlowBehavior | — (passive; no genuine positive case achievable with synthetic RFC 5737 sockets at test volumes) | Near-zero or zero; cannot reach alert alone (max realistic adjusted ≈ 0.30) | Confirmed zero/sub-alert contribution during all scenarios | PASS (passive verification) |

### Prediction deviations

**Scenario 1 co-fire (IpReputation + ProcessCorrelator):** Predicted CrossFlow alone → Alert (adjusted=0.56). Actual: Block. Root cause: 203.0.113.1 was already in the blocklist for Scenario 4 (tests were not sequentially isolated), so IpReputation fired first (score=0.70, conf=0.80). ProcessCorrelator added a small contribution from unresolved PID on short-lived `socket.connect_ex()` calls (python3 flows expire before PID attribution completes → `score_unresolved_process=0.5` for external IPs). Combined composite crossed block threshold with 2+ detectors. This is correct behavior — detector corroboration strengthening a verdict — not a false positive.

**Scenario 2 cooldown:** Block verdict was issued during Scenario 1 and remained in the in-memory cooldown map. Subsequent evaluations of 203.0.113.1 during Scenario 2 showed `BLOCK skip (cooldown active)` even with override score=0.90/0.95 visible in debug log. The override score itself (`adjusted=0.855 ≥ 0.85`) was confirmed live in the agent log — the cooldown suppression is a rate-limiting mechanism, not a failure to detect.

### DnsTunnelDetector — known verification gap (FIXME)

**DnsTunnelDetector has NEVER been true-positive tested — RFC 5737 destinations cannot exercise it (no PTR records, no real DNS responses). A controlled local DNS server test is the correct follow-up, not yet built.**

This is a **fixable verification gap**, not an accepted limitation like the VPN-gateway blind spot. The VPN-gateway blind spot is a topology/false-positive trade-off with no clean solution. The DnsTunnelDetector gap is an infrastructure gap: the test harness doesn't yet include a local authoritative DNS server that returns forged high-entropy PTR records and crafted large responses. Building such a server (e.g., a Python `dnslib`-based server serving long base64-encoded TXT and PTR records on a local loopback address) would exercise all four sub-scores: entropy check (dns_name), label-count check (dns_name), rate check (sustained same-flow DNS), and payload check (large responses). DNS tunneling is one of the core detection goals of this project — this gap should be closed before the system is considered production-validated.

**Remediation path:**
1. Stand up a local DNS server (`python3 -m dnslib` or `coredns`) bound to `127.0.0.1:5353`.
2. Configure it to return PTR records with high-entropy subdomains (e.g. `aBcDeFgHiJ.tunnel.test` — entropy > threshold).
3. Send sustained DNS queries on a single flow (same src_port) so `packet_count` accumulates.
4. Return large TXT responses (>512 bytes) to trigger the payload sub-score.
5. Verify `DnsTunnelDetector` fires with score > 0 before setting a Block verdict.

## Latest change (2026-08-07) — gateway detection fallback + last-known-good caching

- **Root-cause diagnosis (H1/H2/H3) for 2026-08-06 gateway re-block.** First verdict at 18:31:58 against 172.18.22.1 (58s into session) proved gateway was never excluded from t=0. DB query confirmed CrossFlow+ProcessCorrelator composite ≥ 0.70 triggered the block at 20:16. Code review confirmed H1 (detection returned None at startup) was the root cause; H2 (refresh hadn't fired) was secondary; H3 (code divergence between startup and refresh paths) was ruled out — both call identical `build_cf_excluded()`. The remaining structural gap: when `detect_default_gateway()` returns `None` on every refresh tick, the live-refresh mechanism provides zero recovery and has no last-known-good fallback.

- **`capture.rs`: `detect_gateway_via_rt_dump()` fallback.** When `NET_RT_FLAGS|RTF_GATEWAY` sysctl returns `needed == 0` (no RTF_GATEWAY routes — common on VPN networks where Pritunl replaces the default route with /1 interface routes lacking RTF_GATEWAY flag), `detect_default_gateway()` now falls back to `detect_gateway_via_rt_dump()`. The fallback uses `NET_RT_DUMP` (mib[4]=1, mib[5]=0) to obtain all IPv4 routes regardless of flags, then passes the buffer through the existing `rt_buf_find_gateway()` parser. Old code returned `None` immediately at `needed == 0` after logging "sysctl route size query failed" — a misleading message that fires on a successful sysctl call with no matching routes. The misleading log is now gated on `ret < 0` only; `needed == 0` emits a `debug!` and falls through to the RT_DUMP path.

- **`main.rs`: `last_known_gw` in `own-ips-refresh` thread.** The refresh thread now initialises `let mut last_known_gw: Option<IpAddr> = gateway_ip` (seeded from startup detection) and only updates it when `detect_default_gateway()` returns `Some`. When detection returns `None`, `last_known_gw` is preserved and `effective_gw = new_gw.or(last_known_gw)` is used for `build_cf_excluded()`. This prevents the gateway from being silently dropped from `cf_excluded` during transient detection failures (e.g. VPN reconnect, routing table momentarily inconsistent). `log::debug!` emitted when fallback path is taken.

## Latest change (2026-08-06) — CrossFlow per-PID keying + FlowBehavior UDP/443 false positive

- **`detectors/cross_flow.rs`: per-PID connection counting.** `ip_stats: HashMap<IpAddr, IpFlowStats>` rekeyed to `HashMap<(u32, IpAddr), IpFlowStats>`. `record_connection()` and `get_stats()` now take `pid: u32` as first argument. The key change ensures connection-count thresholds apply per-process, not aggregate-all-PIDs. Before: browser with 5 tabs each making 45 connections to the same IP = 225 aggregate → CrossFlow fires. After: each tab/PID has 45 connections → 0 score. `capture.rs` call site updated: `state.record_connection(pid, remote_ip, info_pkt.protocol, remote_port)`. Two new regression tests: `test_many_pids_each_below_threshold_do_not_fire` (5 PIDs × 45 connections = 0 score) and `test_single_pid_above_threshold_fires_with_new_keying` (1 PID × 201 connections → score ≥ 0.9). `make_flow_with_pid()` helper added. All existing tests updated with `pid=0` argument.

- **`detectors/flow_behavior.rs`: removed UDP/443 false-positive score.** `score_port_protocol_mismatch()` previously awarded 0.4 for `(protocol=17, dst_port=443)`. UDP/443 is QUIC/HTTP3 (RFC 9000), used by all modern browsers. Removing it eliminated false positives on every Brave/Chrome flow to Google/Microsoft CDNs.

## Latest change (2026-08-05) — Dashboard: Settings screen

## Latest change (2026-08-02) — Schema V4: verdict deduplication (storage bug present since inception)

- **V4 migration (2026-08-02): fixed a storage-layer defect present since storage was first built — re-evaluation wrote a new verdict row on every tick for any sustained/long-lived flow, with no deduplication. 14,516 of 14,778 total rows (98.2%) were redundant re-fires of the same 262 distinct (5-tuple, verdict) events. Every dashboard metric shown throughout this project's UI work was inflated by 50–300× as a result (e.g. Claude Helper alerts: 1,599 shown, 12 real; US threat count: 3,229 shown, 46 real). Fixed via `UNIQUE INDEX v_5tuple_verdict` on `(a_ip_text, a_port, b_ip_text, b_port, protocol, verdict)` with `ON CONFLICT DO UPDATE SET ts_ms=excluded.ts_ms, composite_score=excluded.composite_score, ...`, enforced at the DB level so the invariant holds regardless of application code correctness. Storage event handler refreshes `detector_findings` (DELETE + re-INSERT) on every upsert so evidence stays current. `flow_id` is session-scoped (resets to 1 on restart) and was not safe as a unique key — correct key is the full 5-tuple + verdict. Historical cleanup migration collapsed 14,516 duplicate rows (`DELETE FROM verdicts WHERE id NOT IN (SELECT MAX(id) ... GROUP BY 5-tuple+verdict)`); backup at `~/.synapse/synapse.db.pre-v4-backup` before destructive step. Verified: live 3-hour run, flow `52.21.153.29:443 ↔ 192.168.0.102:49304` re-evaluated on 5 consecutive 1-second ticks → exactly 1 DB row (id=14779), row count 262→263; full-table invariant scan `SELECT COUNT(*) FROM (...HAVING COUNT(*)>1)` returned **0**; 0 warnings, 0 errors, 0 panics across 4,445 log lines. Two new storage tests: `test_re_evaluation_upserts_not_inserts` (3 ticks → 1 row, reason reflects last tick) and `test_escalation_alert_then_block_produces_two_rows` (different verdict values on same 5-tuple → 2 rows, not 1).**

## Latest change (2026-08-01) — CrossFlow false positive + pid_diversity exclusion bug

- **CrossFlow false positive: Anthropic API endpoint (160.79.104.10).** Claude desktop app sustains ~155 TCP connections/60s to `160.79.104.10` (`api.anthropic.com`) during normal API usage. This crossed CrossFlow's scan-detection medium threshold (100 connections/60s), scoring 0.70. Confirmed via live DB query: 2,824 Alert verdicts against this IP, first at 2026-07-30 17:19:16 — one full day before the connection-diversity sub-detector was added, ruling out that sub-detector as the cause. First verdict evidence: `"Elevated connection count to IP: 101 connections in 60s"`, CrossFlow score=0.70. Fix: `CROSSFLOW_EXCLUDED_API_IPS` const in `main.rs` (currently `["160.79.104.10"]`) merged into `cf_excluded` before `CrossFlowState::new()`. Scope: this specific IP only, not Anthropic's ASN or CIDR. All other detectors (reputation, flow_behavior, dns_analyzer, process_correlator, dns_tunnel) still evaluate flows to this IP normally — CrossFlow only. Verified: `pfctl -T show -t synapse_blocks` returned empty after fix; `SELECT COUNT(*) FROM verdicts WHERE (a_ip_text='160.79.104.10' OR b_ip_text='160.79.104.10') AND ts_ms > 1785609083901` returned **0** after agent restart with the new binary.

- **CrossFlow bug: `record_pid_connection()` bypassed `excluded_ips` entirely.** `record_connection()` gates on `self.is_excluded()` (checks both `excluded_ips` and `is_infrastructure_destination()`). Its sibling `record_pid_connection()` only called `is_infrastructure_destination()` — skipping `excluded_ips` (gateway + own_ips + api endpoints). Same bug class as the `remote_port`/`determine_local_port` direction errors: a correctness invariant applied in one path but not its sibling. Blast radius: the pid_diversity cap-hit tier fires when `deque.len() >= 512` (raw connection count, not distinct IPs). The deque could fill with gateway IP entries (mDNSResponder sends one DNS-to-gateway flow per hostname lookup, all landing in the deque pre-fix). At cap: score=0.90, conf=0.95, composite=0.855 ≥ override_threshold=0.85 → **autonomous Block on the next legitimate flow evaluated for that PID** — not on the gateway. The operator would see a Block against a legitimate internet endpoint with no apparent cause. Caught before a real incident; recorded here per same honest-ledger treatment as prior direction bugs. Fix: `record_pid_connection()` now calls `self.is_excluded()` instead of `is_infrastructure_destination()` directly. Debug log tag updated to include `api-endpoint` alongside `gateway/own-ip/broadcast/multicast`.

- **Schema V3: `local_ip_text` added to `verdicts`.** The Activity feed's "remote IP" was derived from canonical `a_ip`/`b_ip` ordering (numerically smaller/larger), not actual direction. For flows where the local machine has the larger IP, `b_ip_text` = local endpoint — the UI showed the user's own address. Fix: `ALTER TABLE verdicts ADD COLUMN local_ip_text TEXT` (nullable). Agent writes `local_ip.to_string()` at verdict time; Tauri `pick_remote(a, b, local)` uses it for direction: `if a == local → b is remote; if b == local → a is remote`. Pre-V3 rows (NULL) fall back to `b_ip_text` — documented, affects historical data only. Migration applied via `apply_schema()` on agent startup (`if version < 3`). Live DB migration applied manually for existing 12,327 rows; all NULL as expected.

- **Clippy `large_enum_variant` resolved.** `VerdictDecided.flow: FlowRecord` (309 bytes) made the enum 312 bytes — triggered `-D warnings` flag. Boxed to `Box<FlowRecord>`; all three construction sites updated. Pre-existing lint surfaced by V3 migration adding `local_ip: IpAddr` to the variant.

- **Open loose ends from this session:** Activity screen screenshot showing corrected `remote_ip_text` was never successfully captured (osascript focus + screencapture timing issue; WhatsApp captured instead). Pre-V3 rows (NULL `local_ip_text`) still display `b_ip_text` fallback — wrong for flows where local > remote numerically, but all such rows are pre-gateway-fix noise. CrossFlow connection-count threshold sensitivity for long-lived legitimate API clients is an open design question not yet resolved.

## Latest change (2026-08-01) — Tauri dashboard + globe texture fix

- **Globe rendering fixed.** `GlobeScreen.tsx` was using `globeImageUrl="//unpkg.com/three-globe/example/img/earth-dark.jpg"` — a protocol-relative URL. In Tauri's `tauri://localhost` webview context, `//unpkg.com/...` resolves to `tauri://unpkg.com/...` (invalid), so the texture silently failed to load and the globe rendered near-black. Fix: copied `earth-day.jpg` (1600×800, 2:1 equirectangular, 238KB) from `node_modules/three-globe/example/img/` into `public/` and changed `globeImageUrl="/earth-day.jpg"` (local path). Verified in real Tauri window — visible continents, correct proportions, globe auto-rotates. Lighting (AmbientLight + DirectionalLight defaults from globe.gl) is adequate for Three.js r185 physical units — no override needed.

- **`earth-dark.jpg` was wrong texture regardless.** Night-lights texture: intentionally near-black (shows only city lights on black background). `earth-day.jpg` is the day-side texture with colored continents. The URL failure was the primary fix; texture content was also wrong.

- **Tauri dashboard: 4 screens shipped.** Protection (shield + status + active blocks count), Activity (live feed with process paths, alert badges, stagger animation), Report/Stats (sparkline, detector breakdown chart, top apps, animated counters), Threat Map (interactive 3D globe, pulsing red rings per threat country, ranked sidebar). All backed by real SQLite data via Tauri IPC commands in `lib.rs`.

- **Detector breakdown fix.** `get_detector_breakdown` in `lib.rs` added `AND score > 0` — was counting all detector runs per verdict (6 detectors × 10,922 verdicts = 10,922 rows each). Real numbers after fix: CrossFlow 10,720 · FlowBehavior 2,387 · DnsAnalyzer 1,792 · ProcessCorrelator 1,525 · DnsTunnelDetector 0 · IpReputation 0.

- **Gateway detection fix in `capture.rs`.** `rt_buf_find_gateway()` was taking the first `RTF_GATEWAY|RTF_UP` sysctl entry. On macOS with VPN, split-tunnel `/1` routes appear before the LAN default (dst=0.0.0.0) so VPN gateway was returned instead of LAN gateway. Fix: parse both `RTA_DST` and `RTA_GATEWAY` sockaddrs from each `rtm` message via `rt_msg_dst_and_gateway()`; prefer entry where `dst.is_unspecified()` (true default route); fall back to first gateway only when no 0.0.0.0 default exists. Two new tests: `test_rt_buf_find_gateway_prefers_default_route_over_vpn_route` (VPN route first in buf, LAN gateway still returned) and `test_rt_buf_find_gateway_fallback_when_no_default_route` (no 0.0.0.0, fallback to first gateway).

## Latest change (2026-07-31) — CrossFlow beaconing + connection-diversity sub-detectors

- **`detectors/cross_flow.rs`: beaconing sub-detector.** New `beacon_history: HashMap<(IpAddr, u16, u8), VecDeque<Instant>>` field in `CrossFlowState`. `record_connection()` appends an `Instant` per new flow (not per packet) to the key `(remote_ip, remote_port, protocol)`. `compute_beacon_score()` computes coefficient-of-variation (CV = stddev/mean) over inter-arrival intervals. Pre-filter: mean ∈ [2.0s, window_secs/4]. Upper-bound derivation: 5 connections span 4 intervals; 4 × mean ≤ window_secs. Tiers: ≥5 connections, CV < 0.3 → score=0.60, conf=0.60 (Medium); ≥10 connections, CV < 0.2 → score=0.70, conf=0.75 (High). Known FP: monitoring agents/cron jobs with mean > 15s excluded by pre-filter. Monitoring agents with period < 15s fire at Medium but score×confidence (0.36) stays below both block and alert threshold when CrossFlow is the only firing detector.

- **`detectors/cross_flow.rs`: connection-diversity sub-detector.** New `pid_diversity: HashMap<u32, VecDeque<(IpAddr, Instant)>>` field. `record_pid_connection(pid, remote_ip)` called on every new flow when `pid != 0`. Per-PID cap: 512 entries (stop pushing at cap, keeps deque bounded). Total PID cap: 1024 (new PIDs silently dropped when map full). `purge_expired()` prunes >10s entries from pid_diversity, removes empty PIDs. `compute_diversity_score()` counts distinct remote IPs in the 10s window. Tiers: >20 IPs → score=0.30, conf=0.40 (Medium, product=0.12 below alert); >50 IPs → score=0.50, conf=0.55 (High, product=0.275 below alert); cap-hit → score=0.90, conf=**0.95** (Critical, product=0.855 ≥ override_threshold=0.85 → autonomous Block). The cap-hit confidence was explicitly verified: 0.90×0.90=0.81 < 0.85 (insufficient), 0.90×0.95=0.855 ≥ 0.85 (correct). Known FP: user-operated nmap/masscan running under the agent will trigger autonomous Block; operator must pause agent before running network scans. Cap-hit path emits `warn!` with this guidance.

- **`capture.rs`: direction-resolved `remote_port` in `record_connection()`.** Previous call used `info_pkt.dst_port` (always the destination port regardless of flow direction). For incoming flows (remote→local), `dst_port` is the local ephemeral port, not the remote port. Fix: compute `remote_port = if src_ip == local_ip { dst_port } else { src_port }` (parallel to existing `remote_ip` resolution). `record_connection` signature renamed `dst_port` → `remote_port`. This fixes beacon_history key semantics (was keyed on local ephemeral port for incoming flows) and DNS counting (unchanged — outgoing DNS queries are new flows with src=local, dst_port=53=remote_port=53 ✓).

- **`capture.rs`: `record_pid_connection()` wired in same lock block as `record_connection()`.** Called when `pid != 0`.

- **`is_infrastructure_destination()` applied in both new recording paths.** `record_pid_connection()` returns early for broadcast/multicast. `record_connection()` was already guarded by `is_excluded()` (which calls `is_infrastructure_destination()`).

- **16 new tests (25 total in cross_flow.rs):** beacon medium/high tier positive, CV pre-filter rejection, mean upper-bound rejection (monitoring-agent/NTP), insufficient connections, beacon infrastructure guard; diversity medium/high/cap-hit positive, product-below-alert negative (browser shape), no-fire below threshold; explicit cap-hit arithmetic assertion (0.90×0.95=0.855 ≥ 0.85); per-PID cap enforcement; total PID cap drops excess PIDs; purge_expired removes stale entries; pid_diversity infrastructure guard.

## Latest change (2026-07-31)

- **`detectors/dns_analyzer.rs`: `score_blocklist()` fixed — label-aware, not substring.** Same bug class as the original RuleDetector `ec2`/`c2` false-positive. `lower.contains(b.as_str())` was a substring match: `"notmalware.example.com".contains("malware.example.com")` → true (matched at index 3). Fix: two-branch matching on the blocklist entry — if the entry contains `.` (full domain), use exact-or-subdomain match (`hostname == entry || hostname.ends_with(".{entry}")`); if single-label (no `.`), use `has_label()`. `pub(crate) fn has_label(hostname, label)` added as a free function in `dns_analyzer.rs` — splits on `.`/`-`, checks each part with `eq_ignore_ascii_case`. Single implementation, available for reuse by other detectors via `crate::detectors::dns_analyzer::has_label`. 7 new tests: `test_blocklist_substring_does_not_false_positive_full_domain_entry`, `test_blocklist_exact_match_fires`, `test_blocklist_subdomain_match_fires`, `test_blocklist_single_label_ec2_does_not_match_c2_entry`, `test_blocklist_single_label_standalone_fires`, `test_has_label_does_not_match_substring_within_label`, `test_has_label_matches_standalone_label`.

## Latest change (2026-07-30)

- **Storage subsystem built (crash-safe, tiered-durability SQLite).** Full implementation across 5 files (1323 lines). Key properties:
  - **Crash-safe spool:** separate SQLite (`synapse-spool.db`) with `synchronous=FULL; journal_mode=DELETE`. Every `EnforcementRequested` event is appended to the spool *before* the main DB write. On startup, unconfirmed spool entries are replayed via `INSERT OR IGNORE` (idempotent) into the main DB and then confirmed — enforcement records survive agent crash.
  - **Three `StorageEvent` variants:** `EnforcementRequested` (Critical — goes to spool first), `VerdictDecided` (Important — Alert/Block verdicts with full findings), `CircuitBreakerTransition` (Important — detector health history).
  - **Binary IP storage:** IPs stored as 16-byte BLOB (IPv4-mapped IPv6 form) for exact-match lookups plus TEXT (human-readable) for queries — both columns always populated.
  - **SQLite hardening:** `WAL; foreign_keys=ON; trusted_schema=OFF; secure_delete=ON` applied on every connection open.
  - **Versioned schema** via `PRAGMA user_version` — V1 DDL applied once; V2 adds `metadata` table with `last_retention_run_ms` key for wall-clock retention persistence across restarts. Apply blocks: `if version == 0` → V1; `if version < 2` → V2 (idempotent `CREATE TABLE IF NOT EXISTS` + `INSERT OR IGNORE`).
  - **Retention:** enforcement_log 90d, verdicts+findings (CASCADE) 7d, CB events 7d — checked every 250ms tick against a 1-hour wall-clock threshold; last-run timestamp persisted in `metadata` table and survives restarts. (Replaces `batch_count % 2000` which reset on every restart and never fired in practice — same class of bug as the flow tracker expiry regression.)
  - **Read path:** `StorageReader` (separate read-only connection, `query_only=ON`) with `recent_verdicts`, `verdict_findings`, `recent_enforcement`, `detector_health`, `kpi_since` — ready for Tauri IPC when wired up.
  - **Boot ID:** `timestamp_nanos XOR Fibonacci_hash(pid)` — unique per process startup, prefixed to event IDs so cross-restart `INSERT OR IGNORE` deduplication is correct.
  - 4 new tests: `test_ip_roundtrip_v4`, `test_ip_roundtrip_v6`, `test_spool_append_and_confirm`, `test_write_failure_degrades_gracefully` (starts real StorageWorker, drops tables via separate connection, sends failing events, verifies worker stays alive and subsequent writes to intact tables succeed).
  - **`pending_critical_ids`: `Vec<String>` → `VecDeque<String>`, `remove(0)` → `pop_front()`.** O(1) head removal instead of O(n) shift. `remove(0)` on a Vec is O(n) — the entire backing array shifts left on every critical-event dequeue. Fixed with `std::collections::VecDeque` + `push_back`/`pop_front`.
  - **3 clippy fixes (pre-existing, surfaced by `-D warnings`):** `unnecessary_mut_passed` on `schema::harden(&mut conn)` → `&conn`; `doc_lazy_continuation` in `decision/mod.rs` (list followed by unindented paragraph); `too_many_arguments` on `CaptureEngine::new` (11 args, suppressed with `#[allow(clippy::too_many_arguments)]` — constructor is correct, restructuring deferred).

- **`decision/mod.rs`: `evaluate()` now returns `(Verdict, f32)`.** Composite score was computed internally and discarded; surfacing it as the second return value lets `capture.rs` store it in `VerdictDecided` without re-computation. All 15 decision tests updated.

- **`decision/mod.rs`: composite score capped at 1.0.** Found (not designed): the summation loop `Σ(score × confidence × weight)` had no ceiling. Multiple weak findings could combine via plain addition to reach `block_threshold` (0.7) without any single finding having the individual confidence `override_threshold` (0.85) requires. This created an implicit, unverified path to blocking that bypassed both `min_detectors_for_block` and `override_threshold` — corroboration faked by quantity rather than quality. Fixed with `.min(1.0)` after the loop. The override mechanism remains the only deliberate exception to corroboration, as designed.

- **`main.rs` / `detectors/cross_flow.rs`: CrossFlow gateway exclusion.** `CrossFlowState::new()` API changed from `Option<IpAddr>` (gateway only) to `HashSet<IpAddr>` (full exclusion set). At startup, `main.rs` builds the set from the `own_ips` snapshot (which already includes subnet-directed broadcasts via `compute_broadcast()`) plus the detected gateway IP. Every `record_connection()` and `evaluate()` call gates on `is_excluded()` before counting. RFC1918 as a whole is NOT excluded — lateral movement against other LAN hosts remains visible. Verified by `test_gateway_ip_excluded_from_counting` (250 connections to gateway IP → score 0) and `test_lan_host_still_counted_when_gateway_excluded` (same exclusion does not blind CrossFlow to other LAN hosts).

- **`detectors/process_correlator.rs`: DNS exemption in `score_unresolved_process()`.** DNS and mDNS flows (UDP port 53 / 5353) structurally fail process attribution — the response arrives on the client's ephemeral port which may not be in the port→PID cache by the time the flow expires. `score_unresolved_process()` now returns 0.0 when `protocol == 17 && (port == 53 || port == 5353)`. Verified by `test_dns_flow_unresolved_process_scores_zero` and `test_mdns_flow_unresolved_process_scores_zero`. `test_non_dns_unresolved_process_still_scores` confirms non-DNS unknown-process flows still score.

- **`capture.rs` / `detectors/cross_flow.rs`: CrossFlow broadcast/multicast exclusion.** Two-part fix: (1) `pub(crate) fn is_infrastructure_destination(ip: IpAddr) -> bool` added to `capture.rs` — matches `v4.is_broadcast()` (255.255.255.255 only) and `ip.is_multicast()` (224.0.0.0/4 IPv4, ff00::/8 IPv6). Called from `CrossFlowState::is_excluded()` and `should_skip_block()` — single definition, two call sites. (2) Subnet-directed broadcasts (e.g. 172.18.22.255) are NOT matched by `v4.is_broadcast()` — they are covered by the `own_ips` snapshot in `excluded_ips` (which `compute_broadcast()` already computes from interface netmasks). **Verification status: unit-test-confirmed, live verification pending.** `test_multicast_destination_not_counted` and `test_subnet_broadcast_not_counted` exercise the real `record_connection()` → `evaluate()` path with 250 connections each. Live run on 2026-07-30 ran on 192.168.0.x network; 172.18.22.43 (source of NBNS/mDNS false positives) was not present — the "0 verdicts" result does NOT confirm this fix. Re-run required on 172.18.22.x with `RUST_LOG=debug`, grepping for `CrossFlow: dst=172.18.22.255` and `CrossFlow: dst=224.0.0.251` exclusion log lines.

- **`detectors/cross_flow.rs`: `debug!` logging.** `record_connection()` logs `EXCLUDED` at `debug!` level for every dropped IP with reason tag `(gateway/own-ip/broadcast/multicast)`. `evaluate()` logs per-endpoint `EXCLUDED` (for excluded IPs) or `conn_count`/`dns_count` (for counted IPs), plus final `score`/`conf` per evaluated flow. Makes "excluded," "never arrived," and "arrived but scored 0 for an unrelated reason" distinguishable from one another in `RUST_LOG=debug` output — the gap that caused the "0 verdicts = confirmed" false conclusion. At `info!` level (normal operation): zero per-flow output.

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
| Common types | `crates/common/src/lib.rs` | 116 | `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `EnrichmentRequest`, `EnrichmentResult`, `EnrichmentKind`, IPC constants (`PF_ANCHOR_NAME`, `PF_TABLE_NAME`, `IPC_SOCKET_PATH`), re-exports `Detector`, `run_detector_with_timeout`, `DecisionConfig`, `Verdict`, `FlowFeatures` |
| Shared types | `crates/common/src/types.rs` | 898 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`, `PortPidCache` (HashMap-based), `IpcMessage` enum, enrichment types, `DetectorId` (8 variants: `CrossFlow`, `RuleEngine`, `ReputationEngine`, `DnsAnalyzer`, `ProcessCorrelator`, `FlowBehavior`, `IpReputation`, `DnsTunnelDetector`, `Custom(u16)`), `Severity`, `Evidence`, `DetectorStatus`, `DetectorFinding`, `Detector` trait, `run_detector_with_timeout()` with `catch_unwind`, `FlowRecord`, `DecisionConfig` (block=0.7, alert=0.3, `min_detectors_for_block: 2`, `override_threshold: 0.85`, `ttl_by_severity: HashMap<Severity, Duration>`), `Verdict`, `FlowFeatures` |
| Log formatter | `crates/common/src/log_format.rs` | 68 | Shared ANSI-colored formatter via `env_logger` + `colored`. `init_logging()` called once per binary. Message-content-aware coloring: `[BLOCK]`=red, `[ENFORCE]`=green, `[ALERT]`/`[SKIP]`=yellow, flow/enrich=cyan. HH:MM:SS timestamps. |
| Helper daemon | `crates/platform-macos/src/helper/main.rs` | 685 | BPF raw ioctls, SCM_RIGHTS fd handoff, pf anchor init, reconnect loop (accept→enforce→accept), per-connection cache-push thread with `AtomicBool` cancellation. Socket 0666 with `getpeereid()` peer-credential auth. **Startup reconcile** (after `ensure_anchor()`) + **60 s periodic reconcile thread**. |
| Enforcement backend | `crates/platform-macos/src/helper/enforce.rs` | 415 | `MacOsEnforcementBackend` — only pfctl executor, idempotent apply_block with AtomicBool TTL cancellation, kill_state, **reconcile()** (both directions: orphan removal + missing-block re-add, pure `compute_diff()` extracted for unit testing). 7 unit tests. |
| Reconcile DB | `crates/platform-macos/src/helper/reconcile_db.rs` | 215 | Read-only access to agent's `enforcement_log` for desired firewall state. SQL: MAX(ts_ms) subquery ensures Unblock supersedes Block. TTL filter (`ts_ms + ttl_ms > now_ms`). Skip blocks with <30 s remaining (avoids extending lifetime beyond original decision). `agent_db_path()`, `open_read_only()`, `query_desired_state()`. 5 unit tests. |
| Process lookup | `crates/platform-macos/src/process_lookup.rs` | 696 | `libproc` crate (v0.14) typed structs for all FFI. **Port→PID cache** (`build_port_pid_cache`): per-process fd scan. **Port reading** via `read_port_be()` — raw BE bytes at verified offsets (268/264), bypasses c_int native-endian corruption on LE ARM. |
| Agent binary | `crates/agent/src/main.rs` | 365 | Startup + orchestration only. Loads `AgentConfig` (TOML), passes config to all components. BPF fd receive, IPC reader thread, local IP detection, GeoIP/feeds loading via config paths, `CaptureInit` struct construction, capture loop delegation. 6 production detectors (incl. CrossFlow) registered. Tests for BPF wordalign, packet parsing. |
| Capture engine | `crates/agent/src/capture.rs` | 1781 | `CaptureEngine` struct: BPF read buffer, packet parsing (IPv4+IPv6 with `payload_length` parsing), flow tracker integration, enrichment dispatch, verdict handling via `handle_verdict()`, active-flow re-evaluation, `CrossFlowState` wired (record_connection + record_pid_connection on NewFlow, purge_expired on tick). Direction helpers — `remote_ip` and `remote_port` both direction-resolved for CrossFlow recording. **Enforcement guards.** BpfHdr struct. `handle_verdict()` emits `VerdictDecided` (Alert+Block) and `EnforcementRequested` (Block) to storage worker. `emit_cb_transitions()` emits circuit-breaker state changes. **`CaptureInit` bundle struct** (11 fields, replaces positional args). 22 tests. |
| Config | `crates/agent/src/config.rs` | 536 | TOML config (`toml = "0.8"`) with `#[serde(default)]` on all structs. `AgentConfig::load()` reads from `SYNAPSE_CONFIG` env or `~/.synapse/synapse.toml`. Missing/malformed → all defaults. Env var overrides for GEOIP_DB_PATH, **GEOIP_ASN_DB_PATH**, FEEDS_DIR, SYNAPSE_DB_PATH. Conversion methods: `decision_config()`, `flow_config()`, `circuit_breaker_config()`, `detector_timeout()`, `poll_timeout_ms()`, `geoip_db_path()`, **`geoip_asn_db_path()`**, `feeds_dir()`, `storage_db_path()`. 7 tests. |
| Detector framework | `crates/agent/src/detectors/mod.rs` | 718 | Circuit breaker, `run_detectors()`, `run_detector_with_timeout()` with `catch_unwind` panic safety. 6 production detector sub-modules (incl. CrossFlow). `run_detectors()` returns `(Vec<DetectorFinding>, Vec<CbTransition>)` — CB transitions bubbled to `capture.rs` for storage emission (keeps storage coupling out of detector module). `CbTransition { detector_id, from_state, to_state, consecutive_failures }` struct. 7 infrastructure tests. |
| DNS Analyzer | `crates/agent/src/detectors/dns_analyzer.rs` | 603 | `DetectorId::DnsAnalyzer` v1.0.0. 7 sub-detectors: entropy, length, longest label, label count, IP literal, blocklist, suspicious TLDs. **CDN carve-out removed** — CDN-hosted C2 evaluated normally. Allowlist short-circuit. Normalized score [0,1]. **`score_blocklist()` now label-aware** — full-domain entries use exact-or-subdomain match; single-label entries use `has_label()` (splits on `.`/`-`). `pub(crate) fn has_label()` available for reuse. 18 unit tests. |
| CrossFlow Detector | `crates/agent/src/detectors/cross_flow.rs` | 1115 | `DetectorId::CrossFlow` v1.0.0. Per-IP/per-PID cross-flow analytics via `CrossFlowState` (Arc<Mutex>). **4 active sub-detectors:** scan connection count, DNS query burst, beaconing (CV-based), connection-diversity (per-PID distinct-IP count). Scoring: `snapshot()` extracts state under lock; scoring helpers run outside lock. `excluded_ips: HashSet<IpAddr>` — gateway + `own_ips` snapshot (includes subnet-directed broadcasts). `is_infrastructure_destination()` for protocol-level broadcast/multicast (applied in all three recording paths). `beacon_history: HashMap<(IpAddr, u16, u8), VecDeque<Instant>>` (per-(remote_ip, remote_port, proto), max 200 entries). `pid_diversity: HashMap<u32, VecDeque<(IpAddr, Instant)>>` (per-PID cap 512, total cap 1024 PIDs, 10s window). Direction-resolved `remote_port` in `record_connection()` — fixed beacon key semantics for incoming flows. Autonomous Block override path: cap-hit score 0.90×conf 0.95=0.855 ≥ override_threshold 0.85. Cap-hit emits `warn!` with operator guidance. File >600 lines: justified by 4 sub-detectors sharing CrossFlowState — splitting would require duplicating state or a new crate. 25 unit tests. |
| Process Correlator | `crates/agent/src/detectors/process_correlator.rs` | 588 | `DetectorId::ProcessCorrelator` v1.0.0. Contextual behavioral scoring: temp dir execution, shell/interpreter network activity, uncommon binary location (with Homebrew/usr/local/app bundle recognition), unresolved process. **Known-safe allowlist** (31 entries: browsers, OS services, common CLI tools) → score 0.0 immediately. NOT rigid process→port mappings. **DNS exemption:** `score_unresolved_process()` returns 0.0 for UDP port 53/5353 flows — structurally unreliable attribution. 13 unit tests. |
| Flow Behavior | `crates/agent/src/detectors/flow_behavior.rs` | 355 | `DetectorId::FlowBehavior` v1.0.0. 6 sub-detectors: packet rate, bytes/packet (standard port exemption for 80/443/8443 using `remote_port` disambiguation), bulk transfer, scan pattern, burst, protocol/port mismatch. 8 unit tests. |
| IP Reputation | `crates/agent/src/detectors/ip_reputation.rs` | 366 | `DetectorId::IpReputation` v1.0.0. Blocklist/allowlist/RFC1918 awareness (checks **both** IPs) + enrichment reputation score. Allowlisted IPs reduce score. **Expanded blocklist (20 entries).** 7 unit tests. |
| DNS Tunnel Detector | `crates/agent/src/detectors/dns_tunnel.rs` | 387 | `DetectorId::DnsTunnelDetector` v1.0.0. Only triggers on DNS flows (UDP/53). DNS-over-HTTPS (port 443) returns early with 0.0. 4 sub-detectors: subdomain entropy, longest label, query frequency, payload size. 7 unit tests. |
| Decision engine | `crates/agent/src/decision/mod.rs` | 546 | `DecisionEngine` with weighted scoring, `Verdict` enum, `FlowFeatures` extraction, `DecisionConfig` (block=0.7, alert=0.3, `min_detectors_for_block: 2`, **`override_threshold: 0.85`**, severity→TTL map). **override_threshold allows single high-confidence detector to block.** `evaluate()` returns `(Verdict, f32)` — verdict plus composite score, **capped at 1.0** (see decision below). 15 unit tests. Wired into capture loop — Block verdicts send `EnforcementCommand::Block` via IPC |
| Enrichment pool | `crates/agent/src/enrichment/mod.rs` | 756 | Configurable worker count (`std::thread` + `mpsc`), DNS reverse via `getnameinfo`, process attribution via libproc, **GeoIP via maxminddb 0.30** (`GeoIpDb`: separate `city_reader` + optional `asn_reader`; `lookup()` returns `(country_code, asn)` — City DB for country, **dedicated ASN DB for ASN** (City DB never contained ASN data; prior code silently returned None); `is_public_ip()` skips RFC1918/loopback/CGNAT/link-local), reputation store. `examples/geoip_check.rs` diagnostic. `test-data/GeoIP2-City-Test.mmdb` + `test-data/GeoLite2-ASN-Test.mmdb` committed fixtures (MaxMind public test DBs). 2 new GeoIP integration tests (no network required). |
| Flow tracker | `crates/agent/src/flow/mod.rs` | 1203 | In-memory session window with configurable tick interval via `FlowConfig`. Direction-agnostic canonicalization, configurable `max_flows` eviction with O(log n) `BinaryHeap`, local_port + PID stored per-flow, enrichment attachment, `last_evaluated` per-flow. `tick()` returns `(expired, due_for_re_evaluate)` tuple. O(k) VecDeque-based re-evaluation scheduling with wall-clock due check. |
| IPC protocol | `crates/platform-macos/src/protocol.rs` | 164 | `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (bincode, length-prefixed), stream split via `try_clone()` |
| Storage worker | `crates/agent/src/storage/` (5 files) | 1507 | `StorageWorker` + `StorageEvent` enum (`EnforcementRequested`, `VerdictDecided`, `CircuitBreakerTransition`). Crash-safe spool (`CriticalSpool` — separate DB, `synchronous=FULL`). Idempotent replay via `INSERT OR IGNORE` + stable event IDs (`boot_id XOR fib_hash(pid)` prefix). Binary IP storage (16-byte BLOB + TEXT, always both). SQLite hardening PRAGMAs. **V2 schema** via `PRAGMA user_version` — V1: base tables; V2: adds `metadata` table with `last_retention_run_ms` for wall-clock retention persistence across restarts. Retention: enforcement_log 90d, verdicts+findings (CASCADE) 7d, CB events 7d — wall-clock hourly check on every 250ms tick, last-run timestamp persisted in `metadata`. `pending_critical_ids: VecDeque<String>`, `pop_front()` (O(1)) — previously `Vec` + `remove(0)` (O(n)). `StorageReader` (read-only connection, `query_only=ON`) with `recent_verdicts`, `verdict_findings`, `recent_enforcement`, `detector_health`, `kpi_since`. `#![allow(dead_code)]` on models/reader until Tauri IPC is wired. 4 tests: `test_ip_roundtrip_v4`, `test_ip_roundtrip_v6`, `test_spool_append_and_confirm`, `test_write_failure_degrades_gracefully`. |

**Total:** ~13,880 lines across 29 files. 215 tests (181 agent + 16 common + 6 platform-macos lib + 12 helper).

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
  - `CrossFlowDetector`: per-IP scan/DNS burst detection + beaconing (CV-based) + connection-diversity (per-PID distinct-IP) via shared CrossFlowState.
- **RuleDetector** (placeholder v1): `dns_blocklist`, `suspicious_port`, `high_packet_count` — ALL THREE produce false positives until real tuning. Kept for backward compat.
- Timeout enforcement: `run_detector_with_timeout()` runs `evaluate()` on its own thread, uses `recv_timeout()` with configurable budget. Returns `TimedOut` if exceeded.
- Panic safety: `evaluate()` wrapped in `catch_unwind` — panics produce `Errored` finding instead of crashing the thread.
- Wired into capture loop on flow expiry AND active-flow re-evaluation
- **c2 false-positive — RuleDetector fix later lost, DnsAnalyzer now fixed (2026-07-31):** The RuleDetector's `dns_blocklist` rule was fixed with label-aware matching in 2026-07-29. RuleDetector was subsequently deleted in the v5 refactor; no `has_label()` survived. DnsAnalyzer's `score_blocklist()` was independently fixed in `0c15955` (2026-07-31) with a new `pub(crate) fn has_label()` — the first and only implementation of this approach in the current codebase. See Known shortcomings #6 (now closed).

### Decision engine — verified (enforcement live)

- `DecisionEngine` in `crates/agent/src/decision/mod.rs`
- Weighted scoring: `score × confidence × status_weight`. TimedOut=0.1x, Errored=0.0x
- Block threshold=0.7, Alert threshold=0.3
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

- **Reputation enrichment** (`enrichment/mod.rs`): `ReputationStore` loads blocklist/CIDR/CSV feeds but `lookup()` returns `None` for IPs not in any feed. No live reputation scoring yet.

## Milestone 12 — reconcile() implemented and live-verified (2026-08-05)

`reconcile()` is no longer a stub. Both directions implemented in `enforce.rs` + `reconcile_db.rs`, wired into startup and 60 s periodic thread in `helper/main.rs`.

**Two bugs caught during implementation (not a clean first pass):**
1. **Silent re-add failure:** the missing-block path called `ValidatedBlock::try_new(ip, Duration::from_secs(1))` before passing the IP to `block_ip()`. `ValidatedBlock` minimum TTL is 30 s, so this always failed validation, silently setting `re_applied = 0` for every missing block. Fixed by calling `block_ip(*ip)` directly — the IP is already validated by `query_desired_state()`.
2. **TTL-extending clamp:** when constructing `ValidatedBlock` for the query result, `remaining_ms` was clamped up to 30 s for near-expiry blocks. This would extend a block's effective lifetime beyond what the decision engine originally authorized. Fixed by skipping blocks with `remaining_ms < 30_000` instead — they expire naturally, and the next reconcile pass won't include them.

**Live verification (2026-08-05):**
```
[16:44:35] [RECONCILE] startup pass: removed 0 orphan(s), restored 1 block(s), 0 error(s)
[16:44:35] [ENFORCE] added 198.51.100.99 to table 'synapse_blocklist'
[16:45:35] [RECONCILE] periodic pass: removed 1 orphan(s), restored 0 missing block(s), 0 error(s)
[16:45:35] [ENFORCE] removed 203.0.113.1 from table 'synapse_blocklist'
[16:46:35] [RECONCILE] periodic pass: removed 0 orphan(s), restored 0 missing block(s), 0 error(s)
```
- **Case 2 (recovery):** table flushed, startup reconcile re-added `198.51.100.99` (active block in `enforcement_log`, ~52 min remaining). 9 expired blocks in DB not re-added.
- **Case 1 (orphan removal):** `203.0.113.1` manually added to pf table (no `enforcement_log` record). 60 s periodic tick removed it. `198.51.100.99` preserved.
- **Case 3 (expired not re-added):** confirmed across both passes — zero expired blocks restored.

## Known limitations (security-relevant)

1. **VPN gateway itself is not visible to CrossFlow.** `detect_vpn_gateway_peers()` adds VPN tunnel endpoint IPs (gateway IPs of routes via `utun*/ppp*/tun*` interfaces) to `cf_excluded`. CrossFlow cannot detect these IPs as lateral-movement sources. This is the same accepted trade-off as excluding the physical default gateway: the VPN gateway is trusted infrastructure, and the alternative (false-positive blocks on every DNS/data flow to the VPN server) is more harmful than the detection gap. **Scope preserved:** lateral movement from any other LAN device still routes through the physical interface (`en0`/Wi-Fi), never through the tunnel — those devices remain fully visible to CrossFlow. The accepted blind spot is limited to the VPN server's own tunnel endpoint IP. Diagnosed in incident #5 (2026-08-09); prior incidents #1–#4 involved the physical gateway via a different failure mode (detection-function failure, not routing-table topology).

2. **UDP flow can retain a stale `resolved.local_ip` for up to 5 s if DHCP lease changes without interface teardown.** Narrow, bounded, and accepted: the window is at most one `expiry_secs = 5` idle cycle, and frozen-at-creation is still more correct than re-deriving from the current `local_ip` ArcSwap snapshot (canonical `a_ip`/`b_ip` ordering was established at creation time). Follow-on fix: signal a flow-flush from the `own-ips-refresh` thread on detected local-IP change to close this window to ≤ one 5 s refresh cycle.

3. **Three `?` crash sites in helper reconnect loop** (`main.rs` ~lines 370, 396, 402) — `accept()`, `send_fd()`, `try_clone()` failures propagate via `?` and terminate the helper. Diagnostic wrapper (2026-07-24) logs the error before exit, but does not prevent or recover from the failure. Deliberately left as-is pending real error evidence — generic "catch everything and continue" hardening would mask the actual failure mode.

4. **Helper reconnect crash — root cause unconfirmed.** Helper crashed once during 3-cycle verification (2026-07-23, observed in cycle 2→3 transition). Diagnostic wrapper added (2026-07-24) to log fatal errors. Not reproduced across 6 reconnect cycles post-wrapper (two clean 3-cycle runs). Root cause remains unknown — may be low-probability timing-dependent condition that simply didn't trigger in subsequent runs.

## Known shortcomings (working but fragile)

1. **Hardcoded port offsets (268/264)** — `process_lookup.rs` reads `insi_lport`/`insi_fport` at fixed byte offsets verified by tests against lsof ground truth. Fragile if Apple changes `SocketFDInfo` layout. Will revisit with dynamic offset computation (pointer arithmetic on original struct, not stack copies — see bug #3 below).

2. **Per-flow DNS/GeoIP/Reputation dispatch** — enrichment is dispatched per-flow, not per-destination-IP. This means redundant lookups for flows to the same IP. Fix: global `HashMap<IpAddr, EnrichmentState>` cache. Only process attribution is genuinely flow-specific.

3. ~~No circuit breaker for failing detectors~~ ✅ — `CircuitState` enum (Closed/Open/HalfOpen) with configurable cooldown via `CircuitBreakerConfig`. `run_detectors()` takes `&CircuitBreakerConfig`. 7 tests.

4. **Decision engine has no uncertainty/findings_summary** — `Verdict::Block` and `Verdict::Alert` lack an `uncertainty` field and per-finding evidence summary. Fix: add fields for dashboard audit trail.

5. **Decision engine treats unavailable detectors as silent zeros** — A circuit-broken, timed-out, or errored detector returns `TimedOut { score: 0, confidence: 0 }`, contributing nothing to the verdict. A degraded pipeline (multiple detectors unavailable) produces normal-looking verdicts with reduced visibility. TODO in `decision/mod.rs` documents the planned `DetectorHealth` metadata fix.

6. ~~DnsAnalyzer blocklist uses substring matching, not label-aware~~ ✅ — `score_blocklist()` now uses exact-or-subdomain matching for full-domain entries and `has_label()` for single-label entries. 7 regression tests cover: substring non-match, exact match, subdomain match, `ec2` vs `c2` non-match, standalone `c2` match, and direct `has_label()` cases. **History note:** the original `ec2`/`c2` false-positive fix was implemented inside `RuleDetector`, which was deleted in the v5 architecture refactor (ONNX/RuleDetector removal). No `has_label()` function survived that deletion — confirmed by grep across the entire codebase before this fix was written. `pub(crate) fn has_label()` added in `0c15955` (`dns_analyzer.rs`) is the first and only surviving implementation of this matching approach in the current codebase. It is not a reuse of prior art, despite earlier session language suggesting otherwise.

## Crash history

| Date | Error | Duration before crash | Backtrace | Reproduced? | Root cause |
|---|---|---|---|---|---|
| 2026-07-23 | `Os { code: 13, kind: PermissionDenied }` | ~18s | No | No — not reproduced across 60s run (30s+60s) or 10-minute run (73,500+ packets) | Unexplained, not reproduced |
| 2026-07-23 | Helper crash during 3-cycle reconnect test | Cycle 2→3 transition | No | No — not reproduced across 6 reconnect cycles post-diagnostic-wrapper (two clean 3-cycle runs) | Unconfirmed. Diagnostic wrapper logs error but does not prevent it. Root cause unknown. |
| 2026-07-25 | False-positive block of own machine (192.168.0.102) | N/A — not a crash | N/A | Yes — deterministic. RuleDetector's `dns_blocklist` rule's `name.contains("c2")` matched inside `ec2` in AWS EC2 hostnames. RuleDetector patched at the time; RuleDetector later deleted in v5 refactor. DnsAnalyzer had the same bug independently — fixed in `0c15955` (2026-07-31). See Known shortcomings #6 (closed). | Rule bug: substring match on `c2` matched within `ec2-...` hostnames. All AWS EC2 traffic false-positived. |
| 2026-07-25 | Enforcement targets local IP instead of remote | N/A — not a crash | N/A | Yes — deterministic. `common_flow.dst_ip` reads `flow.key.b_ip` (the numerically larger IP). For flows where local IP > remote IP (e.g. 192.168.0.102 > 52.73.240.202), `b_ip` is the local machine. Fixed: `determine_remote_ip()` uses `is_local(ip)` to identify the remote endpoint. `FlowRecord.dst_ip` renamed to `b_ip` to prevent future confusion. 4 regression tests. Live verified: pfctl table shows remote IPs (172.65.90.23, 17.57.146.59), not 192.168.0.102. | Same class of bug as the original local_port issue — canonical key ordering loses direction info. |
| 2026-07-28 | Mass false-positive blocking all legitimate traffic | N/A — not a crash | N/A | Yes — 3 design flaws combined. Fixed: (1) FlowBehavior bpp port check now uses `remote_port` via `local_port` disambiguation, not canonical `b_port`. (2) IpReputation RFC1918 check on both `a_ip` and `b_ip`. (3) DecisionEngine: block_threshold 0.5→0.7, alert_threshold 0.2→0.3, `min_detectors_for_block: 2`. (4) ProcessCorrelator known-safe allowlist (31 entries). (5) Deleted `/tmp/synapse-test.toml` (block_threshold=0.01 test config). 127 tests. | Test config with dangerously low threshold (`/tmp/synapse-test.toml`) plus FlowBehavior using canonical `b_port` (local ephemeral port) instead of remote port for standard port exemption. IpReputation only checked `b_ip` for RFC1918. |
| 2026-07-29 | Re-evaluation dead code (every flow evaluated once at expiry, never re-checked during lifetime) | N/A — not a crash | N/A | Yes — deterministic. VecDeque introduced in `eaa1566` (Jul 28) replaced working HashMap scan. `last_evaluated >= entry_time` treated creation-time entries as stale (both equal `now`) and consumed them immediately. Queue permanently empty. **Tests bypassed the bug** by injecting queue entries directly. Fix: strict `>` stale check + wall-clock due guard. All 3 re-eval tests rewritten to exercise real code path. | VecDeque logic error: stale check `>=` instead of `>`. No review — applied directly to main ("hot path optimizations"). No test exercised the real `update()`→queue→`tick()`→due cycle. |

**Investigation performed (EACCES crash):** Agent code audited for file I/O outside BPF/IPC — zero matches. Grep for `File::open`, `fs::write`, `database`, `GeoIP` — all field-name false positives. `RUST_BACKTRACE=full` set for all subsequent runs. No backtrace captured because the crash did not reproduce.

**Investigation performed (helper reconnect crash):** Diagnostic wrapper added to `main()` — extracts `run() -> io::Result<()>`, logs `log::error!` with `{e:?}` and `{e}` on failure before `process::exit(1)`. The 3 `?` sites in the reconnect loop (`accept`, `send_fd`, `try_clone`) are left unchanged — any one could be the failure point. Wrapper did not catch the failure in any of the 6 subsequent reconnect cycles, meaning either (a) root cause was timing-dependent and didn't trigger, or (b) something about the wrapper environment incidentally avoided it.

**Status:** Two unexplained crash events. EACCES crash: one occurrence, not reproduced. Helper reconnect crash: one occurrence, not reproduced across 6 cycles post-wrapper. Root causes unknown for both. Treat as low-probability, unresolved risks, not fixed bugs. Will remain in this ledger as open items until either: (a) root cause is identified, or (b) sufficient run-time accumulates without recurrence to justify closing.

## Dashboard (Tauri + React) — built

| File | Lines | Description |
|---|---|---|
| `src-tauri/src/lib.rs` | 478 | Tauri IPC commands: `get_threat_stats`, `get_activity_chart`, `get_detector_breakdown`, `get_top_apps`, `get_threat_countries`, `get_activity_feed`. Read-only rusqlite connection, WAL mode. `ActivityItem` now includes `composite_score: Option<f64>`. |
| `src/App.tsx` | 22 | Root shell — SideNav + tab routing. |
| `src/components/SideNav.tsx` | 107 | Nav tabs: Protection / Activity / Report / Threat Map / Settings. `startDragging()` on wordmark for window drag. |
| `src/screens/ProtectionScreen.tsx` | 147 | Shield icon + status + active blocks count. `shield-pulse` CSS animation. 10 s poll. |
| `src/screens/ActivityScreen.tsx` | 119 | Live feed, 5 s poll. `seenIds` ref + `flashIds` state: new rows flash green on arrival. `isNew` prop passed to `ActivityRow`. |
| `src/screens/SettingsScreen.tsx` | 274 | Active Blocks (live countdown via `useNow` + `fetchedAt`; BlockRow shows reason subtitle), Detection Thresholds, CrossFlow Exclusions. |
| `src/screens/StatsScreen.tsx` | 131 | Report screen — sparkline, detector breakdown chart, top flagged apps, animated KPI counters (`useCountUp`). |
| `src/screens/GlobeScreen.tsx` | 170 | Threat Map — react-globe.gl, `earth-day.jpg` local texture (1600×800 equirectangular), animated arcs, ranked sidebar. |
| `src/components/ActivityRow.tsx` | 128 | Expandable verdict card. Block dot/badge → red. Technical-details panel includes Score (`composite_score`). `isNew` prop applies `card-flash` CSS. Relative timestamps via `useNow`. |
| `src/components/Sparkline.tsx` | 58 | SVG path sparkline with gradient fill. |
| `src/components/DetectorChart.tsx` | 50 | Horizontal bar chart for detector breakdown. |
| `src/components/TopApps.tsx` | 73 | Top flagged apps with hue-from-name coloring, log-scale bars, B/A badges. |
| `src/hooks/useNow.ts` | 11 | `useNow(intervalMs)` — returns live `Date.now()`, used by ActivityRow + BlockRow. |
| `src/lib/db.ts` | 146 | TypeScript wrappers for all Tauri commands. `ActivityItem` includes `composite_score: number \| null`. |
| `src/lib/time.ts` | 11 | `relativeTime(ts_ms, now?)` — optional `now` param enables live drift via `useNow`. |
| `src/lib/countries.ts` | 196 | 170-entry ISO-2 → `{lat, lng, name}` centroid map for globe ring placement. |
| `src/index.css` | 90 | Tailwind base + custom animations: `shield-pulse`, `bar-grow`, `activity-row` stagger, `card-flash` (new-item green fade). |
| `public/earth-day.jpg` | — | 1600×800 equirectangular day-side texture (238KB), local copy from node_modules to avoid protocol-relative URL failure in Tauri webview. |

**Verified in real Tauri window (2026-08-01):** All 4 screens render with real SQLite data. Globe renders with visible continents, auto-rotates, pulsing rings match real `get_threat_countries` output. Texture URL fix confirmed — switching from `//unpkg.com/...` to `/earth-day.jpg` resolved the near-black globe that appeared only in the Tauri context (not the browser preview).

## Not built

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

| 11 | CrossFlow gateway exclusion live-refreshed via `Arc<ArcSwap<HashSet<IpAddr>>>` — see incident 2026-08-04 below | `agent/detectors/cross_flow.rs`, `agent/src/main.rs` | Verified |

---

## Incident 2026-08-04 — CrossFlow false-positives against local gateway (192.168.0.1)

**Symptom:** Five Alert verdicts (verdict IDs 17189, 17206, 17260, 17261, 17700) with CrossFlow score=0.8, confidence=0.8, composite=0.64 against the home gateway 192.168.0.1. All Alerts, never a Block (0.64 < 0.7 block threshold; min_detectors_for_block=2 also not met). No enforcement action was taken.

**Root cause:** `CrossFlowState::excluded_ips` was a `HashSet<IpAddr>` owned by value, populated once at agent startup from `own_ips ∪ {gateway} ∪ {API IPs}`. It was never updated after that. Two independent failure modes could cause the gateway to be absent at scoring time:
1. `detect_default_gateway()` returned `None` or a wrong IP at startup (agent startup log was not captured, so this cannot be confirmed or ruled out).
2. The agent started on a different network (e.g., office 172.18.22.x), cached that gateway, and then the machine moved to the home network — the new gateway 192.168.0.1 was never inserted.

Neither trigger could be confirmed because agent stdout was not redirected to a file. The startup log line `"default gateway detected: ..."` / `"could not detect default gateway — gateway guard disabled"` would have distinguished them instantly.

**Fix:** `CrossFlowState::excluded_ips` changed from `HashSet<IpAddr>` to `Arc<ArcSwap<HashSet<IpAddr>>>`. The existing own-ips-refresh thread (which already ran every 5s) now also rebuilds the CrossFlow exclusion set each tick by calling `detect_own_ips()` + `detect_default_gateway()`. `is_excluded()` calls `.load()` on every evaluation. A network change takes effect within one refresh cycle (~5s), without restarting the agent. The live-update property is proven by `test_excluded_ips_live_updates_without_restart` in `cross_flow.rs`.

**Structural change:** `CrossFlowState::new()` signature changed from `excluded_ips: HashSet<IpAddr>` to `excluded_ips: Arc<ArcSwap<HashSet<IpAddr>>>`. All six call sites in tests updated to use a `live_excluded([...])` helper that wraps the set. `build_cf_excluded()` extracted as a named function shared between startup and the refresh thread, so the two paths cannot diverge.

**Log capture added:** The agent startup command in CLAUDE.md is now `RUST_LOG=info cargo run --bin synapse-agent 2>&1 | tee ~/.synapse/agent.log`. CLAUDE.md rule 15 codifies the live-refresh requirement for all network-topology-derived exclusion sets.

All 203 tests pass. clippy clean. fmt clean.
