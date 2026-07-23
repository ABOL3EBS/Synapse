# synapse-common — context

Zero-logic crate. Shared types and traits between helper (root) and agent (unprivileged).

## Files

| File | Contains |
|---|---|
| `src/lib.rs` | `EnforcementCommand` enum, `PacketInfo` struct, `EnforcementBackend` trait, `IPC_MAGIC`/`IPC_VERSION` constants, re-exports all public types from `types.rs` |
| `src/types.rs` | All shared types (see below) |

## Types (`src/types.rs`)

### Enforcement types

| Type | Purpose |
|---|---|
| `ValidatedBlock{ip, ttl}` | Validated block command with TTL |
| `BlockId(IpAddr)` | Unique block identifier |
| `DesiredFirewallState{blocks}` | Set of desired blocks for reconciliation |
| `EnforcementReceipt{block_id, success, message}` | Result of enforcement action |
| `ReconciliationReport{re_applied, evicted, errors}` | Result of reconcile() (currently stub) |

### IPC types

| Type | Purpose |
|---|---|
| `PortPidCache{entries: HashMap<(u16,u8),u32>, pid_count, fd_count, elapsed}` | Helper→agent port→PID mapping |
| `IpcMessage` enum | `PortPidCache(PortPidCache)` — all IPC messages |

**Note:** `PortPidCache.entries` is a `HashMap<(u16, u8), u32>` directly — there is no `PortPidEntry` struct.

### Enrichment types

| Type | Purpose |
|---|---|
| `EnrichmentKind` enum | `DnsReverse`, `ProcessAttribution`, `GeoIp`, `Reputation` |
| `EnrichmentRequest{flow_id, src_ip, dst_ip, src_port, dst_port, protocol, pid, kinds}` | Agent→enrichment worker request |
| `EnrichmentResult{flow_id, kind, success, dns_name, process_path, process_start_time, country_code, asn, reputation_score, error}` | Enrichment worker→agent result |

### Detector types

| Type | Purpose |
|---|---|
| `DetectorId` enum | `RuleEngine`, `OnnxModel`, `ReputationEngine`, `Custom(u16)` |
| `Severity` enum | `Low`, `Medium`, `High`, `Critical` |
| `Evidence{description: String, detail: Option<String>}` | Concrete evidence for a finding |
| `DetectorStatus` enum | `Completed`, `TimedOut`, `Errored` |
| `DetectorFinding` | Single detector result: `detector_id: DetectorId`, score, confidence, severity, evidence, latency_us, status |
| `DetectorConfig{id: DetectorId, timeout: Duration}` | Per-detector timeout config |
| `Detector` trait | `fn id() -> DetectorId`, `fn version() -> &str`, `fn evaluate(&FlowRecord) -> DetectorFinding` |
| `run_detector_with_timeout()` | Runs evaluate() on separate thread with recv_timeout budget |

### Decision types

| Type | Purpose |
|---|---|
| `Verdict` enum | `Allow`, `Block{ttl, reason}`, `Alert{reason}` |
| `FlowFeatures` | Extracted from FlowRecord: flow_id, packet/byte counts, duration_ms, packet_frequency, protocol, dst_port, has_dns_name, has_process_path, reputation_score |
| `DecisionConfig` | block_threshold, alert_threshold, ttl_by_severity (HashMap<Severity, Duration>), min_ttl, max_ttl, timed_out_weight, errored_weight |

### FlowRecord (types.rs)

```rust
pub struct FlowRecord {
    pub flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
    pub local_port, pid, packet_count, byte_count,
    pub dns_name, process_path, country_code, reputation_score,
}
```

**Note:** This is the common version passed to detectors. The flow tracker has its own `FlowRecord` with `Instant` timestamps.

## EnforcementBackend trait (§4c)

```rust
fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
fn kill_state(&mut self, src: IpAddr, dst: IpAddr, proto: u8) -> Result<EnforcementReceipt, String>;
fn reconcile(&mut self, desired: &DesiredFirewallState) -> Result<ReconciliationReport, String>;
```

Only implementer: `MacOsEnforcementBackend` in `platform-macos/src/helper/enforce.rs`.

## Dependencies

`serde` 1.x (derive), `bincode` 1.x
