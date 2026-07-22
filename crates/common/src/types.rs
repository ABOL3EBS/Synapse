// crates/common/src/types.rs
//
// Shared data contracts for the enforcement backend.
// §4c: "ValidatedBlock, BlockId, DesiredFirewallState, ReconciliationReport,
// and EnforcementReceipt belong in crates/common/src/types.rs"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Enforcement Backend Types (§4c)
// ---------------------------------------------------------------------------

/// A validated, safe-to-enforce block request.
/// Constructed only through a validation path the caller can't bypass —
/// "did you validate this?" is answered by the type system, not discipline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedBlock {
    pub ip: IpAddr,
    pub ttl: Duration,
}

/// Unique identifier for an active block. Currently the IP itself;
/// can become a UUID or opaque handle if the backend needs deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub IpAddr);

impl From<IpAddr> for BlockId {
    fn from(ip: IpAddr) -> Self {
        Self(ip)
    }
}

/// The complete set of blocks the agent wants enforced at any point in time.
/// §4a reconcile() uses this as the source of truth for what *should* be in
/// the pf table, then diffs it against what *is* there.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesiredFirewallState {
    pub blocks: Vec<ValidatedBlock>,
}

/// Result of applying or removing a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReceipt {
    pub block_id: BlockId,
    pub success: bool,
    pub message: String,
}

/// Result of a reconciliation pass (§4a/§4c).
/// Reports what had to be re-applied (anchor eviction recovery),
/// what was evicted that couldn't be recovered, and any errors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconciliationReport {
    /// Blocks that were re-applied after anchor eviction.
    pub re_applied: usize,
    /// Block IDs that were in DesiredFirewallState but could not be restored.
    pub evicted: Vec<BlockId>,
    /// Human-readable error strings for failures during reconciliation.
    pub errors: Vec<String>,
}

// ---------------------------------------------------------------------------
// Enrichment Types (§4 enrichment side-channel)
// ---------------------------------------------------------------------------

/// What kind of enrichment to perform on a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnrichmentKind {
    /// Reverse DNS lookup for the IP.
    DnsReverse,
    /// Process attribution via libproc (PID + start-time + executable path).
    ProcessAttribution,
    /// GeoIP country/ASN lookup (stub in v1).
    GeoIp,
    /// IP reputation feed lookup (stub in v1).
    Reputation,
}

/// A request to enrich a flow with contextual data.
/// Dispatched to the enrichment worker pool on flow creation.
/// The worker pool never blocks the hot path — results arrive asynchronously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentRequest {
    /// Monotonically increasing flow ID (assigned by the flow tracker).
    pub flow_id: u64,
    /// Source IP of the flow.
    pub src_ip: IpAddr,
    /// Destination IP of the flow.
    pub dst_ip: IpAddr,
    /// Source port (0 if not TCP/UDP).
    pub src_port: u16,
    /// Destination port (0 if not TCP/UDP).
    pub dst_port: u16,
    /// IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.).
    pub protocol: u8,
    /// PID of the local process, if known (from flow tracker / BPF).
    pub pid: Option<u32>,
    /// Which enrichments to perform.
    pub kinds: Vec<EnrichmentKind>,
}

/// Result of an enrichment lookup. One per `EnrichmentKind` requested.
/// Results attach to the flow record whenever they complete — they do not
/// gate feature extraction, detection, or decision-making (§4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// Which enrichment this result corresponds to.
    pub kind: EnrichmentKind,
    /// Whether the lookup succeeded.
    pub success: bool,
    /// Reverse DNS hostname (if DnsReverse succeeded).
    pub dns_name: Option<String>,
    /// Process executable path (if ProcessAttribution succeeded).
    pub process_path: Option<String>,
    /// Process start time as epoch seconds (if ProcessAttribution succeeded).
    /// Captured alongside PID to prevent PID-reuse/TOCTOU misattribution.
    pub process_start_time: Option<f64>,
    /// ISO 3166-1 alpha-2 country code (if GeoIp succeeded; stub in v1).
    pub country_code: Option<String>,
    /// Autonomous system number (if GeoIp succeeded; stub in v1).
    pub asn: Option<u32>,
    /// Reputation score 0.0–1.0, higher = more malicious (if Reputation; stub in v1).
    pub reputation_score: Option<f32>,
    /// Human-readable error string if the lookup failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Port→PID Cache (helper → agent via IPC)
// ---------------------------------------------------------------------------

/// Snapshot of the helper's port→PID cache, sent to the agent every ~5s.
/// Built by the helper's fd-scan thread; consumed by the agent's enrichment
/// pool to resolve (port, proto) → PID → process path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortPidCache {
    /// (local_port, protocol) → owning PID.
    pub entries: HashMap<(u16, u8), u32>,
    /// Number of PIDs scanned during the build.
    pub pid_count: usize,
    /// Number of file descriptors examined during the build.
    pub fd_count: usize,
    /// Wall-clock time to build the cache.
    pub elapsed: Duration,
}
