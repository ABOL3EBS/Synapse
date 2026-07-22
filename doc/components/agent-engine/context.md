# Agent Engine — BPF Reads + Flow Tracker + Enrichment Integration

Unprivileged capture loop. Receives BPF fd from helper, reads raw packets, parses into `PacketInfo`, feeds flow tracker, dispatches enrichment, attaches results to flows.

## Code location

`crates/agent/src/main.rs` (526 lines) — standalone binary crate
`crates/agent/src/flow/mod.rs` (574 lines) — in-memory session window
`crates/agent/src/enrichment/mod.rs` (492 lines) — 4-thread enrichment worker pool

## Startup sequence

1. Connect to helper via Unix socket (`/tmp/synapse-helper.sock`)
2. Receive BPF fd via `protocol::recv_fd()` (SCM_RIGHTS)
3. Query kernel buffer size via `ioctl(BIOCGBLEN)` — mandatory, read() fails with EINVAL otherwise
4. Allocate read buffer of exactly that size
5. Create enrichment worker pool (`enrichment::EnrichmentPool::new()`)
6. Create flow tracker (`flow::FlowTracker::new()`)
7. Spawn IPC reader thread (receives PortPidCache from helper every 5s)
8. Enter capture loop with `poll()` (100ms timeout)

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
    tracker.tick()                   // expire stale flows, reclaim memory

    if data available:
        libc::read(bpf_fd, buf)      // one read can return multiple packets
        for each BpfHdr in buffer:
            parse_ip_frame(frame)
            // Resolve local_port + PID from port→PID cache
            (local_port, pid) = cache.lookup(src_port) or cache.lookup(dst_port)
            // Feed to flow tracker
            update = tracker.update(info, local_port, pid)
            if NewFlow(flow_id):
                log "flow N created: ..."
                enrich_pool.dispatch(EnrichmentRequest { flow_id, ... })
            if hit test target IP && not blocked:
                send_message(Block { ip, ttl })

    // Non-blocking result collection (never gates hot path)
    for result in enrich_pool.drain_results():
        attach result to tracker via attach_enrichment(flow_id, ...)
}
```

## Flow tracker (`flow/mod.rs`)

- `FlowKey`: direction-agnostic canonical `(ip, port)` pair — forward and response produce the same key
- `FlowRecord`: stores `flow_id`, `key`, `local_port`, `pid`, timestamps, packet/byte counts, enrichment results
- `FlowTracker`: `HashMap<u64, FlowRecord>` + `HashMap<FlowKey, u64>` index
- `MAX_FLOWS = 100_000`, oldest-eviction on overflow
- `FLOW_EXPIRY_SECS = 5`, expired on every `tick()` call (100ms poll timeout)
- Enrichment results attached via `attach_enrichment()` — DNS, process path, GeoIP, reputation

## Port→PID cache

- Received from helper every 5s via `IpcMessage::PortPidCache`
- Stored in `Arc<Mutex<HashMap<(u16, u8), u32>>>` (port, proto) → PID
- Lookup: try `src_port` first, then `dst_port` fallback
- PID passed to flow tracker at creation time (not updated after)

## Dependencies

`synapse-common` (EnforcementCommand, PacketInfo, EnrichmentKind, EnrichmentRequest, IpcMessage), `synapse-platform-macos` (protocol, process_lookup), `libc`, `log`, `env_logger`

## Gotchas

- Agent never opens `/dev/bpf*` — receives pre-configured fd from helper
- Test target IP is hardcoded (192.168.1.100) — milestone 1 only
- Block TTL is hardcoded (300s) — milestone 1 only
- IPv6 `length` field is set to 0 — total-length is in jumbogram extension, not base header
- Flow creation/expiry logs at INFO level; flow internal details at DEBUG level
- DNS/GeoIP/Reputation are per-flow dispatch (known v1 inefficiency — redundant lookups for same IP)
- Process attribution is genuinely flow-specific (different processes on same port)
- PID lookup uses src_port first, dst_port fallback — correct for outbound traffic
