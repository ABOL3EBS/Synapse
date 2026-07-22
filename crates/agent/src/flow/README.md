# Flow Tracker — Agentic Context

## Purpose

In-memory session window that tracks network flows with ~100ms tick resolution. Replaces the placeholder per-destination counter in agent main.rs.

## Files

- `crates/agent/src/flow/mod.rs` (574 lines) — `FlowKey`, `FlowRecord`, `FlowTracker`, `FlowUpdate` enum

## Key types

### FlowKey (direction-agnostic)

```rust
pub struct FlowKey {
    pub ip_a: IpAddr,   // lower IP in canonical ordering
    pub port_a: u16,    // lower port
    pub ip_b: IpAddr,   // higher IP
    pub port_b: u16,    // higher port
    pub protocol: u8,   // TCP=6, UDP=17
}
```

Forward and response packets produce the same `FlowKey` because `(ip, port)` pairs are sorted — direction is discarded. This is the correct behavior for flow tracking (same session, both directions).

### FlowRecord

```rust
pub struct FlowRecord {
    pub flow_id: u64,
    pub key: FlowKey,
    pub local_port: u16,        // set once at creation, independent of key ordering
    pub pid: Option<u32>,       // set once at creation from local_port cache lookup
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub packet_count: u64,
    pub byte_count: u64,
    // Enrichment results (attached async):
    pub dns_name: Option<String>,
    pub process_path: Option<String>,
    pub process_start_time: Option<f64>,
    pub country_code: Option<String>,
    pub reputation_score: Option<f32>,
}
```

### FlowUpdate

```rust
pub enum FlowUpdate {
    NewFlow(u64),      // caller should dispatch enrichment
    ExistingFlow(u64), // caller should update stats
}
```

## Constants

- `MAX_FLOWS = 100_000` — evict oldest on overflow
- `FLOW_EXPIRY_SECS = 5` — expire flows older than this

## API

- `FlowTracker::new()` → empty tracker
- `tracker.update(info, local_port, pid)` → `FlowUpdate` (NewFlow or ExistingFlow)
- `tracker.tick()` → `Vec<u64>` of expired flow IDs (must be called on every poll() iteration)
- `tracker.attach_enrichment(flow_id, dns, process, start_time, country, reputation)` — attach results
- `tracker.len()` → number of active flows

## Integration with main.rs

```
loop {
    poll(bpf_fd, timeout=100ms)
    tracker.tick()                    // expire stale flows

    if data available:
        read packets
        for each packet:
            (local_port, pid) = cache.lookup(src_port or dst_port)
            update = tracker.update(info, local_port, pid)
            if NewFlow:
                enrich_pool.dispatch(request)
        for result in enrich_pool.drain_results():
            tracker.attach_enrichment(result)
}
```

## Design decisions

1. **Direction-agnostic canonicalization** — `(ip, port)` sorted as bound pairs, never independently. This means forward and response produce the same key.
2. **local_port stored separately** — set once at flow creation from original packet direction, independent of canonical key ordering. Needed for port→PID cache lookup.
3. **pid stored once** — resolved at creation from local_port via port→PID cache. Not updated after (process may change, but PID is a snapshot).
4. **DNS/GeoIP/Reputation per-flow** — known v1 inefficiency (redundant lookups for same IP). Fix: global `HashMap<IpAddr, EnrichmentState>` cache.
5. **Process attribution per-flow** — genuinely flow-specific (different processes on same port).
6. **poll() timeout drives tick()** — ensures expiry fires on quiet networks, not only on packet arrival.

## Tests (9)

- `test_canonicalization_forward_and_response_produce_same_key`
- `test_canonicalization_same_ip_loopback`
- `test_canonicalization_ipv6`
- `test_canonicalization_different_protocols_are_different_flows`
- `test_update_returns_new_vs_existing`
- `test_forward_and_response_update_same_flow`
- `test_max_flows_evicts_oldest`
- `test_tick_expires_old_flows`
- `test_attach_enrichment`

## Shortcomings

1. **Hardcoded port offsets (268/264)** — fragile if Apple changes `SocketFDInfo` layout. Will revisit with dynamic offset computation later.
2. **Per-flow DNS/GeoIP/Reputation dispatch** — redundant lookups for flows to the same IP. Fix: global enrichment cache by IP.
3. **`FlowRecord` fields marked `#[allow(dead_code)]`** — `flow_id`, `local_port`, `pid` exist for detector/decision pipeline but are not yet consumed.
