# Synapse IPS — Claude Code Context

> **Auto-load note:** This file is named `CLAUDE.md` (uppercase, exact spelling) so that Claude Code auto-loads it at session start. Claude Code reads `CLAUDE.md` from the repo root automatically — it does NOT read `opencode.md`, `opencode.json`, or any other filename. If you move or rename this file, the auto-load silently stops working.

## Project Overview

Synapse IPS is a reactive, session-level intrusion prevention system for macOS. It captures network traffic via BPF (no kernel extensions, no paid developer account), detects threats through a pluggable detector framework (rules, behavioral analysis, reputation feeds), and enforces decisions via the native `pf` firewall. The process model splits privileged work (BPF device open, `pf` state manipulation) into a helper daemon running as root, while all untrusted parsing, detection, and decision logic runs unprivileged in the agent.

Stack: Rust, BPF (raw ioctls, no pcap for capture), `pf` via `pfctl`, SCM_RIGHTS fd-passing over Unix sockets, bincode IPC, SQLite (WAL, two-database design — crash-safe spool + main audit DB). Tauri + React dashboard and AI post-analysis (UI layer only) not yet built. macOS only for v1 — cross-platform, `tokio`, and a centralized control-plane backend are all rejected for v1 (see `doc/Synapse-IPS-Architecture.md` §1b).

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

Agent (unprivileged — always capture logs):
```bash
RUST_LOG=info cargo run --bin synapse-agent 2>&1 | tee ~/.synapse/agent.log
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
- **Extract, don't duplicate.** Before writing a second similar block, extract the first into a reusable function.
- **Functions under 80 lines.** `main()` under 100. `main.rs` under 500.

## Structural Rules — Code Quality (non-negotiable)

These rules exist because the agent has a pattern of producing code that compiles and passes tests but is structurally bad. Follow them literally.

### Function size
- **No function body may exceed 80 lines.** If a function hits 60+ lines, start planning extraction. At 80, stop and refactor before adding more.
- **`main()` must be under 100 lines.** It orchestrates — it does not implement. Extract the capture loop body into a struct and its methods.

### Module size
- **`main.rs` must stay under 500 lines.** If it exceeds 400, the next feature must go in a new module file, not appended to main.
- **Any file over 600 lines needs justification.** Add a comment explaining why it can't be split.

### No copy-paste
- **If you write two similar code blocks (same structure, different variable names), you have already made a mistake.** Stop. Extract the common logic into a function with parameters.
- **Rule of three:** If the same pattern appears twice, note it. Three times, extract immediately. Don't wait for the refactor trigger.

### One responsibility per function
- **A function does one thing.** If a function name contains "and" (e.g., "parse_and_store"), split it.
- **A function's control flow should be readable top-to-bottom.** Deeply nested match/if chains inside a function that also does I/O means the function has too many responsibilities.

### Extraction discipline
- **Before writing a new for-loop body, check if a similar loop already exists.** Read the surrounding code. If there's a loop that does detector→decision→enforcement, reuse or extend it — don't write a new one.
- **The capture loop body (inside `loop {}`) is the highest-risk area for copy-paste.** Every new feature added to the capture loop must be reviewed against existing loop bodies before writing.

### Refactor triggers (if you see these, fix before proceeding)
- Two for-loops with >70% identical code
- A function that takes 5+ parameters (consider a struct)
- A function that does I/O AND computation AND logging (split)
- `main.rs` over 500 lines
- Any `.rs` file over 800 lines

## Architecture & File Placement

```
crates/
├── common/          # Zero-logic. Shared types + EnforcementBackend trait.
│   └── src/
│       ├── lib.rs       # EnforcementCommand, PacketInfo, EnforcementBackend trait, IPC constants, re-exports
│       └── types.rs     # ValidatedBlock, BlockId, EnforcementReceipt, ReconciliationReport, enrichment types, Detector trait, DecisionConfig, Verdict, FlowFeatures
│
├── agent/           # Unprivileged. All parsing, detection, decision.
│   └── src/
│       ├── main.rs          # Startup + orchestration only (< 500 lines)
│       ├── capture.rs       # CaptureEngine: BPF reads, packet parsing, capture loop, verdict handling
│       ├── detectors/       # Detector trait + RuleDetector impl
│       │   ├── mod.rs       # Circuit breaker, run_detectors(), run_detector_with_timeout()
│       │   ├── dns_analyzer.rs       # DNS hostname behavioral analysis
│       │   ├── process_correlator.rs # Process-to-network behavioral correlation
│       │   ├── flow_behavior.rs      # Per-flow traffic behavior analysis
│       │   ├── ip_reputation.rs      # IP reputation lookup
│       │   └── dns_tunnel.rs         # DNS tunnel detection
│       ├── enrichment/      # Async DNS, geo, process attribution
│       ├── flow/            # In-memory session tracking
│       └── decision/        # Weighted scoring, policy thresholds
│
└── platform-macos/  # macOS enforcement boundary. Only crate that knows BPF/pf.
    └── src/
        ├── lib.rs               # Re-exports pub mod protocol, pub mod process_lookup
        ├── protocol.rs          # SCM_RIGHTS fd-passing + bincode IPC
        ├── helper/
        │   ├── main.rs          # Root daemon: BPF open, fd handoff, enforcement loop
        │   └── enforce.rs       # MacOsEnforcementBackend — ONLY pfctl caller
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
8. **FlowRecord fields `a_ip`/`b_ip` are canonical (smaller/larger), NOT directional (src/dst).** Two confirmed bugs from the same root cause: `src_ip`/`dst_ip` naming invited the assumption that `dst_ip` = "remote endpoint." It's not — it's the numerically larger IP. For enforcement, always use `determine_remote_ip(a_ip, b_ip, local_ip)` to resolve the actual remote endpoint. Never assume `a_ip` or `b_ip` means "remote" based on field name.

9. **Before starting `synapse-agent` or `synapsed-helper` for ANY test, check for existing running instances first.**
   ```bash
   ps aux | grep -E 'synapse-agent|synapsed-helper' | grep -v grep
   ```
   Kill any that appear before starting fresh. A stale process left running with old code and old thresholds caused two real incidents in this project: blocking the operator's own gateway and approximately 70 legitimate service IPs, while the operator believed nothing was running. This check has caught a stale helper on multiple consecutive sessions.

10. **Tests for stateful mechanisms (queues, caches, trackers) must exercise the REAL public call path end-to-end.** Never construct or manipulate internal state directly as a substitute for going through the actual code that produces that state. Two separate silent failures in this project's flow re-evaluation subsystem were invisible specifically because tests bypassed the real mechanism and verified internal mechanics instead of integration — one bug dated to project inception, one was introduced in a later refactor. The test suite passed both times. "Tests pass" only means what the tests actually exercise.

11. **Direction must be resolved explicitly before any directional use of flow fields.** `FlowKey`/`FlowRecord` fields derived from canonical ordering (`a_ip`/`b_ip`, `a_port`/`b_port`) are never "local" or "remote" by virtue of position. Always call `is_local()`/`detect_local_ip()` before using a flow's IPs or ports for enforcement targeting, port→PID lookup, or directional logging. This exact bug shipped twice under different names (`determine_local_port` and `determine_remote_ip`) before the pattern was identified as a class error.

12. **Exemptions for false positives must be scoped to the specific thing causing the problem — never broadened to an entire address category as a shortcut.** The correct scope for a gateway false-positive fix is the detected gateway IP, not all of RFC1918. A blanket private-IP exemption would blind CrossFlow to lateral movement, which is explicitly in-scope per the threat model (§1a). When fixing a false positive, name the smallest possible exclusion that corrects it, document why that scope is correct, and explicitly confirm that the broader category remains visible.

13. **Any value that combines multiple detector findings via addition must have an explicit, documented ceiling.** An uncapped composite score existed in this project — not a design decision, just never noticed — that allowed multiple weak findings to reach block threshold via quantity, bypassing the `override_threshold: 0.85` single-finding safety margin that exists precisely to prevent that. The fix is `.min(1.0)` after the summation loop. Whenever you write or modify an aggregation path, state explicitly what ceiling applies and why.

14. **Verify Claude Code's auto-approval and permission settings before doing anything that touches `git push`, enforcement code, or `pfctl`.** Session-level "always allow" grants in Claude Code are NOT persisted to `~/.claude/settings.json` — they reset between sessions. An untracked auto-approval silently approved commits and pushes without a visible prompt during part of a session in this project. Check `cat ~/.claude/settings.json` and confirm `permissions.allow` contains only what you intend. When in doubt, use a fresh session with no prior approvals.

15. **Any exclusion or allowlist built from network-topology facts (own IPs, default gateway, known-good endpoints) must be live-refreshed via the shared `Arc<ArcSwap<HashSet<IpAddr>>>` mechanism — never computed once at startup and held as a static value.** On 2026-08-04, CrossFlow's `excluded_ips` was a frozen `HashSet` populated at agent startup. When the gateway changed (either because `detect_default_gateway()` returned `None` or a different IP at startup, or because the machine moved to a different network after the agent was running), the old gateway was not in the set. CrossFlow scored it at 0.8 and produced Alert verdicts for five legitimate gateway flows. The fix: `excluded_ips` is now an `Arc<ArcSwap<HashSet<IpAddr>>>` that the existing own-ips-refresh thread rebuilds every 5s (own_ips ∪ {gateway} ∪ hardcoded API IPs). `is_excluded()` calls `.load()` on every evaluation — the exclusion set is always current within one refresh cycle. The property is proven by `test_excluded_ips_live_updates_without_restart`: ArcSwap is swapped while CrossFlowState is alive, score changes from nonzero to 0 without a restart. Never introduce a second independent refresh mechanism for the same underlying data — one thread, both ArcSwaps.

16. **`detect_default_gateway()` can silently return `None` on VPN networks where the routing table has no RTF_GATEWAY-flagged routes** (`NET_RT_FLAGS|RTF_GATEWAY` sysctl returns `needed == 0`). On 2026-08-06, Pritunl VPN replaced the standard default route with /1 interface routes lacking the RTF_GATEWAY flag; the function returned None at startup and on every refresh tick; the LAN gateway (172.18.22.1) was never excluded from CrossFlow; 1h45min of DNS flows accumulated until composite score ≥ 0.70 triggered a block. Two fixes applied (2026-08-07): (a) `detect_gateway_via_rt_dump()` fallback — when `needed == 0`, retry with `NET_RT_DUMP` (all routes, no flag filter), pass buffer through existing `rt_buf_find_gateway()`. (b) `last_known_gw: Option<IpAddr>` in `own-ips-refresh` thread — seeded from startup detection; only updated when detection returns `Some`; on `None` tick, `effective_gw = new_gw.or(last_known_gw)` prevents the gateway from silently dropping from `cf_excluded` during transient detection failures. The live-refresh mechanism alone is not sufficient when the underlying detection function fails consistently — both the detection function and the caching layer must be hardened.

## Agent workflow

- **Never commit unless explicitly asked.** After completing a step, show the diff and wait for the user to say "commit" or "ship it".
- **Never start a build unless explicitly asked or unless you just edited code.** If you edited code, run `cargo build` to verify it compiles. If it fails, fix it before proceeding.
- **After every successful step, update all three doc files** — `doc/STATUS.md` (line counts, test counts, component descriptions), `doc/Synapse-IPS-Architecture.md` (§5 file-tree line counts, §changelog entry), and this file's status section. All three must stay in sync. Stale line counts in the architecture doc were found and corrected multiple times — check all three before committing, not just STATUS.md.
- **Verify with real terminal output.** Don't say "this should work" — show the actual output. If the user needs to run sudo, give exact commands and wait for their output.
- **User runs sudo manually.** The agent session cannot run sudo. Give copy-paste command blocks.
- **When testing pfctl:** always show before/after `pfctl -s state -vv` output. `killed 0 states` is a silent failure — find a real active state first.
- **Check `man pfctl` before assuming pfctl syntax.** Don't guess flags — look them up.
- **pf requires explicit enable.** `pfctl -e` after loading rules.
- **Anchor must be in main ruleset.** `anchor "name" all` in `/etc/pf.conf` or pf never evaluates it.
- **Flush before reload.** `pfctl -a name -F all` before loading rules clears stale state.
- **Deep context lives in `doc/`.** `doc/STATUS.md` for what's built. `doc/Synapse-IPS-Architecture.md` for design decisions. `doc/components/*/context.md` for per-component agentic context (capture, ipc, enforcement, types, agent-engine).
- **Before adding code to the capture loop, read the entire loop body.** Identify existing patterns. Reuse or extend — never duplicate.
- **After completing a step, check file sizes.** If main.rs is over 500 lines, the next step must include extracting a module.

## Current status summary

- **Built:** helper (BPF ioctls, SCM_RIGHTS fd-handoff, pf anchor init, reconnect loop (accept→enforce→accept), per-connection cache-push thread with AtomicBool cancellation, peer-credential auth via getpeereid(), **reconcile(): startup + 60 s periodic, both directions, live-verified 2026-08-05**), agent (BPF reads, IPv4+IPv6 parsing, IPC reader thread + cache storage, PID lookup wired src_port→PID→path), common (types, EnforcementBackend trait with apply_block/remove_block/kill_state/reconcile, enrichment types, IpcMessage enum), protocol.rs (SCM_RIGHTS, bincode IPC, stream split), process_lookup.rs (libproc FFI: lookup_process, build_port_pid_cache, probe_socket with raw BE port reading), capture.rs (CaptureEngine struct + CaptureInit bundle: BPF read buffer, packet parsing, flow tracker integration, enrichment dispatch, verdict handling via handle_verdict(), active-flow re-evaluation), enrichment/mod.rs (configurable worker pool with DNS reverse + process attribution + GeoIP via maxminddb 0.30 — GeoIpDb has separate city_reader + optional asn_reader; prior code tried to decode ASN from City DB which never contained it, silently returning None always; fixed 2026-07-31 + reputation stub), flow/mod.rs (in-memory session window with configurable tick interval via FlowConfig, direction-agnostic canonicalization, configurable max_flows eviction with O(log n) BinaryHeap, local_port + PID stored per-flow, enrichment attachment), detectors/mod.rs (circuit breaker with configurable CircuitBreakerConfig, run_detectors(), timeout enforcement, 5 production detector sub-modules), decision/mod.rs (DecisionEngine with weighted scoring, Verdict enum, FlowFeatures, DecisionConfig, 12 unit tests, log-only verdicts in capture loop, active-flow re-evaluation with 1s interval and MAX_RE_EVAL_PER_TICK=100, batched scan every 10th tick), config.rs (TOML config via `toml = "0.8"`, AgentConfig with #[serde(default)] on all structs, load() from SYNAPSE_CONFIG env or ~/.synapse/synapse.toml, missing/malformed → defaults, env var overrides for GEOIP_DB_PATH/GEOIP_ASN_DB_PATH/FEEDS_DIR/SYNAPSE_DB_PATH, conversion methods for DecisionConfig/FlowConfig/CircuitBreakerConfig/geoip_asn_db_path(), 7 tests)
- **Verified:** ICMP/TCP/UDP over IPv4+IPv6 on en0. pfctl table add/delete/show. KillState kills real states (`killed 1 state`, confirmed gone in `pfctl -s state -vv`). pf enabled, anchor active. Process lookup: `test_lookup_own_pid` passes, resolves own executable path and start time. **Live E2E (2026-07-22):** helper sends PortPidCache (49–51 entries, ~7–8ms), agent receives and resolves Brave Browser connection → pid=743 → `Brave Browser Helper` via `lookup_process`. **Flow tracker (2026-07-22):** poll() timeout drives tick(), flows created for each unique session, enrichment dispatches per-flow, DNS reverse lookups succeed (`ec2-44-203-161-176.compute-1.amazonaws.com`, `abbass-macbook-air.local`). **Design review (07-22):** all 4 items verified — canonicalization swap case, local_port independence, enrichment per-flow (documented), MAX_FLOWS + wall-clock tick. **Bug fix (07-23):** `detect_local_ip()` via getifaddrs() at startup, PID lookup uses `is_local(ip)` direction check instead of src_port-first heuristic. **Test (07-23):** `determine_local_port()` extracted as testable function, 4 new tests exercise real code path with system-detected local IP. **Benchmark (07-23):** `detect_local_ip()` measured at 9.065 us/call (100k iterations). Too expensive for per-packet at >10k pkt/s. Switched to 5s background refresh thread — capture loop reads shared `Arc<Mutex<Option<IpAddr>>>`, zero syscalls per packet. **Detector framework (07-23):** §4b implemented — Detector trait, DetectorFinding with timeout enforcement, RuleDetector (placeholder v1 rules), SlowDetector test proves timeout works (500ms sleeper with 50ms budget returns TimedOut within budget). Wired into flow expiry — log only. **Decision engine (07-24):** DecisionEngine with weighted scoring (score × confidence × status_weight), Verdict enum (Allow/Block/Alert), FlowFeatures, DecisionConfig. Active-flow re-evaluation: last_evaluated per-flow, 1s interval, MAX_RE_EVAL_PER_TICK=100. 47 tests pass. Zero enforcement calls — log-only verdicts. **Helper reconnect (07-25):** Helper is now a persistent daemon with accept→enforce→accept loop. Agent crashes do not take down the helper. Per-connection cache-push thread cancelled via `Arc<AtomicBool>` on disconnect. Verified: kill agent → helper logs `connection torn down` → agent restarts → `incoming connection` → `authenticated` → `enforcement loop active`. BPF opened once, reused across connections.
- **Stub:** Reputation enrichment: `ReputationStore` loads feeds but `lookup()` returns `None` for IPs not in any feed.
- **Shortcomings:** hardcoded port offsets (268/264) in process_lookup.rs (fragile if Apple changes struct layout), per-flow DNS/GeoIP/Reputation dispatch (redundant lookups for same IP — fix: global IP-keyed cache), decision engine has no uncertainty/findings_summary
- **Dashboard (Tauri + React):** 5 screens built and verified in real Tauri window. Protection (shield + active blocks), Activity (live feed, verdict badges, stagger animation), Report/Stats (sparkline, detector breakdown, top apps, animated counters), Threat Map (react-globe.gl, pulsing red rings per threat country, auto-rotate, ranked sidebar), Settings (active blocks with live countdown + reason subtitle, detection thresholds, CrossFlow exclusions, unblock button). All backed by real SQLite via Tauri IPC commands in `src-tauri/src/lib.rs`. UI polish (2026-08-12): Block dot/badge red (was green), composite score in technical-details panel, BlockRow reason subtitle (strips boilerplate prefix), live countdown via `useNow` hook, live relative timestamps, Activity polls every 5 s / Protection every 10 s, new-item green flash (`card-flash`) on Activity feed refresh.
- **Not built:** AI post-analysis (UI layer only), Windows/Linux support (intentionally excluded — §1b)
- **Note:** This "Current status summary" section is intentionally coarse. For accurate, current state including line counts, test counts, and per-component status, read `doc/STATUS.md` (rule 0).

## Order of work

Follow §6 architecture doc literally: capture → typed IPC → pfctl block end-to-end, then enrichment, detectors, decision, storage. Don't start UI before milestone 1 is proven.
