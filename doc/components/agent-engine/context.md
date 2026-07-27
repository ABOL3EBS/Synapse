# Agent Engine — BPF Reads + Flow Tracker + Enrichment + Detectors + Decision Engine

Unprivileged capture loop. Receives BPF fd from helper, reads raw packets, parses into `PacketInfo`, feeds flow tracker, dispatches enrichment, attaches results to flows, runs detectors, makes decisions (log-only).

## Code location

`crates/agent/src/main.rs` (279 lines) — standalone binary crate, startup + orchestration only
`crates/agent/src/capture.rs` (915 lines) — `CaptureEngine` struct: BPF reads, packet parsing, capture loop, verdict handling
`crates/agent/src/flow/mod.rs` (975 lines) — in-memory session window
`crates/agent/src/enrichment/mod.rs` (495 lines) — 4-thread enrichment worker pool
`crates/agent/src/detectors/mod.rs` (879 lines) — detector framework, RuleDetector, timeout enforcement, circuit breaker
`crates/agent/src/decision/mod.rs` (420 lines) — DecisionEngine, weighted scoring, Verdict, active-flow re-evaluation

## Startup sequence

1. Connect to helper via Unix socket (`/tmp/synapse-helper.sock`)
2. Receive BPF fd via `protocol::recv_fd()` (SCM_RIGHTS)
3. Query kernel buffer size via `ioctl(BIOCGBLEN)` — mandatory, read() fails with EINVAL otherwise
4. Allocate read buffer of exactly that size
5. Detect local IP via `getifaddrs()` — shared `Arc<Mutex<Option<IpAddr>>>` with 5s background refresh (benchmarked: 9.065 us/call, too expensive for per-packet)
6. Create enrichment worker pool (`enrichment::EnrichmentPool::new()`)
7. Create flow tracker (`flow::FlowTracker::new()`)
8. Create decision engine (`decision::DecisionEngine::new(DecisionConfig::default())`)
9. Spawn IPC reader thread (receives PortPidCache from helper every 5s)
10. Enter capture loop with `poll()` (100ms timeout)

## BpfHdr struct (20 bytes)

```rust
#[repr(C)]
struct BpfHdr {
    tv_sec: i32,      // timeval32.tv_sec
    tv_usec: i32,     // timeval32.tv_usec
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
}
```

Next packet offset: `BPF_WORDALIGN(bh_hdrlen + bh_caplen)` — word-aligned to 4 bytes.

## IP frame parsers

- `parse_ip_frame(frame)` — reads EtherType at offset 12-13, dispatches to IPv4 (0x0800) or IPv6 (0x86DD)
- `parse_ipv4(frame)` — IP header, protocol, src/dst IPs, TCP/UDP ports
- `parse_ipv6(frame)` — 40-byte fixed header, next-header, src/dst IPs, TCP/UDP ports

Returns `Option<PacketInfo>` — malformed frames silently skipped.

## Capture loop

```
loop {
    poll(bpf_fd, timeout=100ms)     // timeout ensures tick() fires on quiet networks
    let (expired, re_evaluate) = tracker.tick()  // expire stale + find flows due for re-eval

    // Re-evaluate active flows (1s interval, MAX_RE_EVAL_PER_TICK=100)
    for flow_id in re_evaluate:
        let record = tracker.get(flow_id)              // returns flow::FlowRecord
        let common_record = convert_to_common(record)  // flow::FlowRecord → common::types::FlowRecord
        let flow_age = record.age()                    // Instant::now() - first_seen
        let features = FlowFeatures::from_flow(&common_record, flow_age)
        let findings = run_detectors(&detectors, &common_record, DETECTOR_TIMEOUT)
        let verdict = decision_engine.evaluate(&features, &findings)
        match verdict:
            Block { .. } => log "RE-BLOCK: flow {flow_id} ..."
            Alert { .. } => log "RE-ALERT: flow {flow_id} ..."
            Allow => log "RE-ALLOW: flow {flow_id} ..."
        tracker.mark_evaluated(flow_id)

    // Expire old flows
    for flow_id in expired:
        // (detectors already ran on re-evaluation if needed)

    if data available:
        libc::read(bpf_fd, buf)      // one read can return multiple packets
        for each BpfHdr in buffer:
            parse_ip_frame(frame)
            // Resolve local_port + PID from port→PID cache
            (local_port, remote_port) = determine_local_port(src_ip, src_port, dst_ip, dst_port, local_ip)
            // local_port determined by is_local(ip) check against detected local_ip
            // Feed to flow tracker
            update = tracker.update(info, local_port, pid)
            if NewFlow(flow_id):
                log "flow N created: ..."
                enrich_pool.dispatch(EnrichmentRequest { flow_id, src_ip, dst_ip, src_port, dst_port, protocol, pid, kinds })
            if hit test target IP && not blocked:
                send_message(Block { ip, ttl })

    // Non-blocking result collection (never gates hot path)
    for result in enrich_pool.drain_results():
        attach result to tracker via attach_enrichment(flow_id, ...)
}
```

## Flow tracker (`flow/mod.rs`)

- `FlowKey`: direction-agnostic canonical `(ip, port)` pair — forward and response produce the same key
- `FlowRecord` (flow-tracker version, not `common::types::FlowRecord`): stores `flow_id`, `key`, `local_port`, `pid`, timestamps (`first_seen`, `last_seen`, `last_evaluated` as `Instant`), packet/byte counts, enrichment results
- `FlowTracker`: `HashMap<u64, FlowRecord>` + `HashMap<FlowKey, u64>` index
- `MAX_FLOWS = 100_000`, oldest-eviction on overflow
- `FLOW_EXPIRY_SECS = 5`, expired on every `tick()` call (100ms poll timeout)
- `tick()` returns `(expired: Vec<u64>, due_for_re_evaluate: Vec<u64>)` — tuple
- `EVALUATION_INTERVAL_SECS = 1`, `MAX_RE_EVAL_PER_TICK = 100`
- `mark_evaluated(flow_id)` bumps `last_evaluated` regardless of finding status
- Enrichment results attached via `attach_enrichment()` — DNS, process path, GeoIP, reputation

## Detector framework (`detectors/mod.rs`)

- `Detector` trait: `fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding` (single finding, not Vec)
- `run_detector_with_timeout(detector: Arc<dyn Detector>, flow: &FlowRecord, budget: Duration)` — runs on separate thread, `recv_timeout()` enforces budget
- `RuleDetector`: placeholder v1 rules (dns_blocklist, suspicious_port, high_packet_count)
- `run_detectors(detectors: &[Arc<dyn Detector>], flow: &FlowRecord, timeout: Duration) -> Vec<DetectorFinding>` — runs all with timeout, returns one finding per detector
- `catch_unwind` wraps `evaluate()` — panics produce `Errored` finding instead of crashing
- `CircuitState` enum (Closed/Open/HalfOpen) with 30s cooldown and recovery — `run_detectors()` takes `&mut HashMap<DetectorId, CircuitState>`

## Decision engine (`decision/mod.rs`)

- `DecisionEngine::new(config: DecisionConfig)` — creates engine
- `evaluate(features: &FlowFeatures, findings: &[DetectorFinding]) -> Verdict` — weighted scoring: `score × confidence × status_weight`
  - Completed=1.0x, TimedOut=0.1x, Errored=0.0x
  - Block threshold=0.5, Alert threshold=0.2
  - TTL from most severe Completed finding, clamped [min_ttl, max_ttl]
- `Verdict` enum: `Allow`, `Block { ttl, reason }`, `Alert { reason }`
- **No uncertainty/findings_summary fields yet** — known limitation
- **Log-only** — zero enforcement calls until detector pipeline is trusted

## Port→PID cache

- Received from helper every 5s via `IpcMessage::PortPidCache`
- Stored in `Arc<Mutex<HashMap<(u16, u8), u32>>>` (port, proto) → PID
- Lookup: `determine_local_port(src_ip, src_port, dst_ip, dst_port, local_ip)` — reads `local_ip` from `Arc<Mutex<Option<IpAddr>>>` refreshed every 5s
- PID passed to flow tracker at creation time (not updated after)

## Dependencies

`synapse-common` (EnforcementCommand, PacketInfo, EnrichmentKind, EnrichmentRequest, IpcMessage, Detector trait, DetectorFinding, DetectorId, FlowRecord, DecisionConfig, Verdict, FlowFeatures, run_detector_with_timeout), `synapse-platform-macos` (protocol, process_lookup), `libc`, `log`, `env_logger`

## Gotchas

- Agent never opens `/dev/bpf*` — receives pre-configured fd from helper
- Test target IP is hardcoded (192.168.1.100) — milestone 1 only
- Block TTL is hardcoded (300s) — milestone 1 only
- IPv6 `length` field is set to 0 — total-length is in jumbogram extension, not base header
- Flow creation/expiry logs at INFO level; flow internal details at DEBUG level
- DNS/GeoIP/Reputation are per-flow dispatch (known v1 inefficiency — redundant lookups for same IP)
- Process attribution is genuinely flow-specific (different processes on same port)
- PID lookup uses `determine_local_port()` with `is_local(ip)` check — correct for both inbound and outbound
- `determine_local_port()` extracted as testable function — 4 tests exercise real code path with system-detected local IP
- Re-evaluation candidates collected every 10th tick (~1s), not every tick — fixes starvation risk from non-deterministic HashMap iteration
- Decision engine is log-only — no enforcement calls yet
