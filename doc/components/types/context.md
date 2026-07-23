# Types — Shared Data Contracts + EnforcementBackend Trait + Detector Types + Decision Types

Zero-logic crate. Everything here is types, traits, and constants — no implementation.

## Code location

- `crates/common/src/lib.rs` (101 lines) — `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, `IPC_MAGIC`/`IPC_VERSION` constants, re-exports all public types from `types.rs`
- `crates/common/src/types.rs` (438 lines) — all shared types

## EnforcementCommand (wire format)

```rust
pub enum EnforcementCommand {
    Block { ip: IpAddr, ttl: Duration },
    Unblock { ip: IpAddr },
    KillState { src: IpAddr, dst: IpAddr, proto: u8 },
}
```

Sent from agent → helper via bincode IPC. All typed fields — no strings.

## PacketInfo (parsed packet metadata)

```rust
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub length: u16,
}
```

Populated by agent's IPv4/IPv6 parsers from raw BPF frames.

## EnforcementBackend trait

```rust
pub trait EnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
    fn kill_state(&mut self, src: IpAddr, dst: IpAddr, proto: u8) -> Result<EnforcementReceipt, String>;
    fn reconcile(&mut self, desired: &DesiredFirewallState) -> Result<ReconciliationReport, String>;
}
```

Enforces typed data + argv execution guarantees. Only implementer: `MacOsEnforcementBackend` in `platform-macos/src/helper/enforce.rs`.

## Enforcement types (types.rs)

| Type | Purpose |
|---|---|
| `ValidatedBlock { ip: IpAddr, ttl: Duration }` | Validated, safe-to-enforce block request |
| `BlockId(IpAddr)` | Unique handle for active blocks (newtype, Hash + Eq) |
| `DesiredFirewallState { blocks: Vec<ValidatedBlock> }` | Complete set of blocks agent wants enforced |
| `EnforcementReceipt { block_id, success, message }` | Return type for apply/remove/kill |
| `ReconciliationReport { re_applied, evicted, errors }` | Return type for reconcile (currently stub) |

## IPC types (types.rs)

| Type | Purpose |
|---|---|
| `IpcMessage::PortPidCache(PortPidCache)` | Helper → agent: port→PID mapping refresh |
| `PortPidCache { entries: HashMap<(u16, u8), u32>, pid_count: usize, fd_count: usize, elapsed: Duration }` | Serialized cache — entries maps `(local_port, protocol) → PID` |

**Note:** `PortPidCache` is a struct with a `HashMap` field (not a type alias). There is no `PortPidEntry` struct — the `entries` HashMap directly maps `(u16, u8) → u32`.

## Enrichment types (types.rs)

```rust
pub enum EnrichmentKind {
    DnsReverse,
    ProcessAttribution,
    GeoIp,
    Reputation,
}

pub struct EnrichmentRequest {
    pub flow_id: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub pid: Option<u32>,
    pub kinds: Vec<EnrichmentKind>,
}

pub struct EnrichmentResult {
    pub flow_id: u64,
    pub kind: EnrichmentKind,
    pub success: bool,
    pub dns_name: Option<String>,
    pub process_path: Option<String>,
    pub process_start_time: Option<f64>,
    pub country_code: Option<String>,
    pub asn: Option<u32>,
    pub reputation_score: Option<f32>,
    pub error: Option<String>,
}
```

`EnrichmentRequest` carries full 5-tuple + PID to the worker pool. `EnrichmentResult` has typed fields per kind — not a generic `data: String`.

## Detector types (types.rs)

```rust
pub enum DetectorId {
    RuleEngine,
    OnnxModel,
    ReputationEngine,
    Custom(u16),
}

pub enum Severity { Low, Medium, High, Critical }

pub struct Evidence {
    pub description: String,
    pub detail: Option<String>,
}

pub enum DetectorStatus { Completed, TimedOut, Errored }

pub struct DetectorFinding {
    pub detector_id: DetectorId,       // enum, not String
    pub detector_version: String,
    pub score: f32,
    pub confidence: f32,
    pub severity: Severity,
    pub evidence: Vec<Evidence>,
    pub latency_us: u64,
    pub status: DetectorStatus,
}

pub struct DetectorConfig {
    pub id: DetectorId,
    pub timeout: Duration,             // Duration, not timeout_ms: u64
}
```

### Detector trait

```rust
pub trait Detector: Send + Sync {
    fn id(&self) -> DetectorId;
    fn version(&self) -> &str;
    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding;  // returns single finding, not Vec
}
```

**Key differences from common misconceptions:**
- `id()` returns `DetectorId` enum (not `&str`)
- `evaluate()` takes only `&FlowRecord` (no `features` param) and returns a single `DetectorFinding` (not `Vec`)
- `Evidence` has `description: String` + `detail: Option<String>` (not `kind` + `detail`)
- `DetectorId` is an enum (not a `String`)
- `DetectorConfig` has `id: DetectorId` + `timeout: Duration` (not `timeout_ms: u64`)

### Helper functions on DetectorFinding

```rust
impl DetectorFinding {
    pub fn timed_out(detector_id: DetectorId, version: &str, latency_us: u64) -> Self;
    pub fn errored(detector_id: DetectorId, version: &str, error: &str, latency_us: u64) -> Self;
}
```

### run_detector_with_timeout()

```rust
pub fn run_detector_with_timeout(
    detector: Arc<dyn Detector>,
    flow: &FlowRecord,
    budget: Duration,
) -> DetectorFinding
```

Runs `evaluate()` on a separate thread, `recv_timeout()` enforces budget. Returns `TimedOut` or `Errored` finding on failure.

## Decision types (types.rs)

```rust
pub enum Verdict {
    Allow,
    Block { ttl: Duration, reason: String },
    Alert { reason: String },
}

pub struct FlowFeatures {
    pub flow_id: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub duration_ms: u64,              // flow age in milliseconds
    pub packet_frequency: f64,         // packets per second
    pub protocol: u8,
    pub dst_port: u16,
    pub has_dns_name: bool,
    pub has_process_path: bool,
    pub reputation_score: Option<f32>,
}

impl FlowFeatures {
    pub fn from_flow(flow: &FlowRecord, flow_age: Duration) -> Self;
}
```

**Key:** `FlowFeatures` does NOT have `src_ip`, `dst_ip`, or `src_port`. It has `flow_id`, derived statistics (`packet_frequency`, `duration_ms`), and enrichment booleans (`has_dns_name`, `has_process_path`). The constructor is `from_flow()`, not `From` trait.

```rust
pub struct DecisionConfig {
    pub block_threshold: f32,                  // default: 0.5
    pub alert_threshold: f32,                  // default: 0.2
    pub ttl_by_severity: HashMap<Severity, Duration>,  // Severity keys, not String
    pub min_ttl: Duration,                     // default: 30s
    pub max_ttl: Duration,                     // default: 24h
    pub timed_out_weight: f32,                 // default: 0.1
    pub errored_weight: f32,                   // default: 0.0
}
```

**Key:** `ttl_by_severity` uses `Severity` enum as keys (not `String`). There is no `detector: DetectorConfig` field — detector budgets are passed as a `Duration` parameter to `run_detectors()`.

## FlowRecord (types.rs — shared between agent and common)

```rust
pub struct FlowRecord {
    pub flow_id: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub local_port: u16,
    pub pid: Option<u32>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub dns_name: Option<String>,
    pub process_path: Option<String>,
    pub country_code: Option<String>,         // NOT geo_country
    pub reputation_score: Option<f32>,
}
```

**Note:** This is the `common::types::FlowRecord` — passed to detectors. There is a separate `flow::FlowRecord` in `crates/agent/src/flow/mod.rs` that the flow tracker uses internally (has `first_seen`, `last_seen`, `last_evaluated` as `Instant` fields). The agent converts between them at `main.rs:425-440`. The common version uses `country_code`, not `geo_country`.

## IPC constants

- `IPC_MAGIC: [u8; 4] = *b"SYNP"` — framing magic
- `IPC_VERSION: u8 = 1` — protocol version

## Dependencies

`serde` 1.x (derive), `bincode` 1.x — nothing else. This crate must stay zero-logic.
