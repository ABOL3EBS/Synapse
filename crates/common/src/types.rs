// crates/common/src/types.rs
//
// Shared data contracts for the enforcement backend.
// §4c: "ValidatedBlock, BlockId, DesiredFirewallState, ReconciliationReport,
// and EnforcementReceipt belong in crates/common/src/types.rs"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Enforcement Backend Types (§4c)
// ---------------------------------------------------------------------------

/// Minimum TTL for a block — prevents rapid block/unblock cycling.
pub const MIN_BLOCK_TTL: Duration = Duration::from_secs(30);
/// Maximum TTL for a block — prevents permanent blocks from a single finding.
pub const MAX_BLOCK_TTL: Duration = Duration::from_secs(86400); // 24 hours
/// Maximum number of concurrent active blocks. Prevents table memory exhaustion
/// if a compromised or buggy agent floods block commands.
pub const MAX_CONCURRENT_BLOCKS: usize = 10_000;

/// Validation error for block requests — rejected before reaching pfctl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    TtlTooSmall { ttl: Duration, min: Duration },
    TtlTooLarge { ttl: Duration, max: Duration },
    LoopbackIp,
    MulticastIp,
    BroadcastIp,
    LinkLocalIp,
    UnspecifiedIp,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TtlTooSmall { ttl, min } => {
                write!(f, "TTL {ttl:?} is below minimum {min:?}")
            }
            Self::TtlTooLarge { ttl, max } => {
                write!(f, "TTL {ttl:?} exceeds maximum {max:?}")
            }
            Self::LoopbackIp => write!(f, "cannot block loopback address"),
            Self::MulticastIp => write!(f, "cannot block multicast address"),
            Self::BroadcastIp => write!(f, "cannot block broadcast address"),
            Self::LinkLocalIp => write!(f, "cannot block link-local address"),
            Self::UnspecifiedIp => write!(f, "cannot block unspecified address"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// A validated, safe-to-enforce block request.
/// Constructed only through `try_new()` — the type system ensures the caller
/// validated IP and TTL before reaching the enforcement boundary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedBlock {
    pub(crate) ip: IpAddr,
    pub(crate) ttl: Duration,
}

impl ValidatedBlock {
    /// Create a validated block request. Rejects dangerous IPs and out-of-range TTLs.
    pub fn try_new(ip: IpAddr, ttl: Duration) -> Result<Self, ValidationError> {
        if ttl < MIN_BLOCK_TTL {
            return Err(ValidationError::TtlTooSmall {
                ttl,
                min: MIN_BLOCK_TTL,
            });
        }
        if ttl > MAX_BLOCK_TTL {
            return Err(ValidationError::TtlTooLarge {
                ttl,
                max: MAX_BLOCK_TTL,
            });
        }
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    return Err(ValidationError::LoopbackIp);
                }
                if v4.is_broadcast() {
                    return Err(ValidationError::BroadcastIp);
                }
                if v4.is_multicast() {
                    return Err(ValidationError::MulticastIp);
                }
                if v4.is_link_local() {
                    return Err(ValidationError::LinkLocalIp);
                }
                if v4.is_unspecified() {
                    return Err(ValidationError::UnspecifiedIp);
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return Err(ValidationError::LoopbackIp);
                }
                if v6.is_multicast() {
                    return Err(ValidationError::MulticastIp);
                }
                if v6.is_unspecified() {
                    return Err(ValidationError::UnspecifiedIp);
                }
                // fe80::/10 — IPv6 link-local.
                if v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80 {
                    return Err(ValidationError::LinkLocalIp);
                }
            }
        }
        Ok(Self { ip, ttl })
    }

    /// The IP address to block.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }
    /// The block duration.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
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
    /// P4: Fixed array avoids heap allocation per request.
    pub kinds: [EnrichmentKind; 4],
}

/// Result of an enrichment lookup. One per `EnrichmentKind` requested.
/// Results attach to the flow record whenever they complete — they do not
/// gate feature extraction, detection, or decision-making (§4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    /// Flow ID this result belongs to (set by the enrichment worker from the request).
    pub flow_id: u64,
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

// ---------------------------------------------------------------------------
// Detector Framework (§4b)
// ---------------------------------------------------------------------------

/// Unique identifier for a detector implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectorId {
    /// Rule-based detection engine.
    RuleEngine,
    /// Reputation feed lookup (future).
    ReputationEngine,
    /// DNS hostname behavioral analysis — entropy, length, structure, blocklists.
    DnsAnalyzer,
    /// Process-to-network behavioral correlation — context-aware, not rigid mappings.
    ProcessCorrelator,
    /// Per-flow traffic behavior analysis — packet rate, byte patterns, timing.
    FlowBehavior,
    /// IP reputation lookup — blocklist, allowlist, RFC1918 awareness.
    IpReputation,
    /// DNS tunnel detection — high-entropy subdomains, label anomalies.
    DnsTunnelDetector,
    /// Cross-flow pattern detection — scan, beacon, DNS burst, connection diversity.
    CrossFlow,
    /// Catch-all for future detectors.
    Custom(u16),
}

/// How serious the finding is — separate from score/confidence so the
/// decision engine can apply policy-specific severity thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Concrete evidence for why a detector flagged a flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Human-readable description of what matched (e.g. "dns_name matches blocklist pattern").
    pub description: String,
    /// Optional supporting data (e.g. the specific rule name, the matched value).
    pub detail: Option<String>,
}

/// Whether the detector completed, timed out, or errored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectorStatus {
    Completed,
    TimedOut,
    Errored,
}

/// Result of a single detector evaluating a single flow.
/// §4b: "Every detector call returns a DetectorFinding, not a raw score."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorFinding {
    pub detector_id: DetectorId,
    pub detector_version: String,
    pub score: f32,
    pub confidence: f32,
    pub severity: Severity,
    pub evidence: Vec<Evidence>,
    pub latency_us: u64,
    pub status: DetectorStatus,
}

impl DetectorFinding {
    /// Create a TimedOut finding with zero/neutral values.
    pub fn timed_out(detector_id: DetectorId, version: &str, latency_us: u64) -> Self {
        Self {
            detector_id,
            detector_version: version.to_string(),
            score: 0.0,
            confidence: 0.0,
            severity: Severity::Low,
            evidence: vec![],
            latency_us,
            status: DetectorStatus::TimedOut,
        }
    }

    /// Create an Errored finding.
    pub fn errored(detector_id: DetectorId, version: &str, error: &str, latency_us: u64) -> Self {
        Self {
            detector_id,
            detector_version: version.to_string(),
            score: 0.0,
            confidence: 0.0,
            severity: Severity::Low,
            evidence: vec![Evidence {
                description: error.to_string(),
                detail: None,
            }],
            latency_us,
            status: DetectorStatus::Errored,
        }
    }
}

/// Per-detector configuration for the timeout enforcement mechanism.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    pub id: DetectorId,
    /// Maximum time the detector gets before being marked TimedOut.
    pub timeout: Duration,
}

/// Trait that all detectors implement (§4b).
/// Rules, ONNX, reputation — all implement the same interface.
pub trait Detector: Send + Sync {
    fn id(&self) -> DetectorId;
    fn version(&self) -> &str;
    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding;
}

/// Reference to a flow record passed to detectors.
/// Extracted from the flow tracker — contains everything a detector needs
/// without giving it mutable access to the tracker itself.
///
/// **Field ordering is canonical, not directional.** `a_ip`/`a_port` are the
/// numerically smaller endpoint; `b_ip`/`b_port` are the larger. This
/// discards which side is local. Use `determine_remote_ip()` (agent) to
/// resolve the actual remote endpoint before enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub flow_id: u64,
    pub a_ip: IpAddr,
    pub b_ip: IpAddr,
    pub a_port: u16,
    pub b_port: u16,
    pub protocol: u8,
    pub local_port: u16,
    pub pid: Option<u32>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub dns_name: Option<String>,
    pub process_path: Option<String>,
    pub process_start_time: Option<f64>,
    pub country_code: Option<String>,
    pub asn: Option<u32>,
    pub reputation_score: Option<f32>,
    pub flow_age: Duration,
}

// ---------------------------------------------------------------------------
// Decision Engine (§4 step 5)
// ---------------------------------------------------------------------------

/// Verdict produced by the decision engine after evaluating all detector
/// findings for a flow. This is the output that drives enforcement (future)
/// and logging (current).
#[derive(Debug, Clone)]
pub enum Verdict {
    /// No threshold exceeded — flow is allowed.
    Allow,
    /// Score exceeds block threshold — flow should be blocked.
    Block {
        /// TTL for the block, derived from the most severe Completed finding.
        ttl: Duration,
        /// Human-readable reason summarizing why the block was triggered.
        reason: String,
    },
    /// Score exceeds alert threshold but not block threshold — log but don't block.
    Alert {
        /// Human-readable reason for the alert.
        reason: String,
    },
}

/// Extracted features from a flow record, passed to the decision engine.
/// Separates flow statistics from enrichment results so the decision engine
/// can weight them independently.
#[derive(Debug, Clone)]
pub struct FlowFeatures {
    pub flow_id: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    /// Flow age in milliseconds (now - first_seen).
    pub duration_ms: u64,
    /// Packets per second (packet_count / duration_sec).
    pub packet_frequency: f64,
    pub protocol: u8,
    pub dst_port: u16,
    pub has_dns_name: bool,
    pub has_process_path: bool,
    pub reputation_score: Option<f32>,
}

impl FlowFeatures {
    /// Extract features from a FlowRecord.
    pub fn from_flow(flow: &FlowRecord) -> Self {
        let duration_ms = u64::try_from(flow.flow_age.as_millis()).unwrap_or(u64::MAX);
        let duration_sec = flow.flow_age.as_secs_f64();
        let packet_frequency = if duration_sec > 0.0 {
            flow.packet_count as f64 / duration_sec
        } else {
            0.0
        };

        // Compute remote port: the port that isn't local_port.
        let remote_port = if flow.a_port == flow.local_port {
            flow.b_port
        } else if flow.b_port == flow.local_port {
            flow.a_port
        } else {
            // local_port doesn't match either canonical port (ICMP or non-TCP/UDP).
            // Fall back to b_port (existing behavior).
            flow.b_port
        };

        Self {
            flow_id: flow.flow_id,
            packet_count: flow.packet_count,
            byte_count: flow.byte_count,
            duration_ms,
            packet_frequency,
            protocol: flow.protocol,
            dst_port: remote_port,
            has_dns_name: flow.dns_name.is_some(),
            has_process_path: flow.process_path.is_some(),
            reputation_score: flow.reputation_score,
        }
    }
}

/// Configuration for the decision engine's weighted scoring.
#[derive(Debug, Clone)]
pub struct DecisionConfig {
    /// Score threshold above which a Block verdict is produced.
    pub block_threshold: f32,
    /// Score threshold above which an Alert verdict is produced (below block_threshold).
    pub alert_threshold: f32,
    /// Minimum number of detectors that must have non-zero scores for a Block
    /// to be issued. Prevents a single noisy detector from blocking traffic.
    pub min_detectors_for_block: usize,
    /// TTL for blocks, keyed by the most severe Completed finding's severity.
    pub ttl_by_severity: std::collections::HashMap<Severity, Duration>,
    /// Minimum TTL floor — prevents rapid block/unblock cycling.
    pub min_ttl: Duration,
    /// Maximum TTL cap — prevents permanent blocks from a single finding.
    pub max_ttl: Duration,
    /// Status weight for TimedOut findings (down-weighted, not zeroed).
    pub timed_out_weight: f32,
    /// Status weight for Errored findings (zeroed).
    pub errored_weight: f32,
    /// Score threshold for single-finding override.
    /// If any single Completed finding's score × confidence >= this value,
    /// the min_detectors_for_block requirement is bypassed and a Block verdict
    /// is issued. Default 0.85 — no existing detector reaches this product
    /// (DnsAnalyzer 0.55, IpReputation 0.80, etc.). Only the CrossFlowDetector's
    /// heavy-scan sub-detector (0.9 × 0.95 = 0.855) crosses it.
    pub override_threshold: f32,
}

impl Default for DecisionConfig {
    fn default() -> Self {
        let mut ttl_by_severity = std::collections::HashMap::new();
        ttl_by_severity.insert(Severity::Critical, Duration::from_secs(3600)); // 1 hour
        ttl_by_severity.insert(Severity::High, Duration::from_secs(900)); // 15 min
        ttl_by_severity.insert(Severity::Medium, Duration::from_secs(300)); // 5 min
        ttl_by_severity.insert(Severity::Low, Duration::from_secs(60)); // 1 min

        Self {
            block_threshold: 0.7,
            alert_threshold: 0.3,
            min_detectors_for_block: 2,
            ttl_by_severity,
            min_ttl: Duration::from_secs(30),
            max_ttl: Duration::from_secs(86400), // 24 hours
            timed_out_weight: 0.1,
            errored_weight: 0.0,
            override_threshold: 0.85,
        }
    }
}

// ---------------------------------------------------------------------------
// Detector Worker Pool (R1: bounded workers, no per-call thread spawning)
// ---------------------------------------------------------------------------

/// Task sent to a detector worker thread.
struct DetectorTask {
    detector: Arc<dyn Detector>,
    flow: FlowRecord,
    result_tx: crossbeam_channel::Sender<DetectorFinding>,
}

/// Global bounded worker pool — initialized once at startup, reused for all
/// detector invocations. Eliminates per-flow OS thread spawning overhead.
static POOL_TX: OnceLock<crossbeam_channel::Sender<DetectorTask>> = OnceLock::new();
const DEFAULT_POOL_WORKERS: usize = 32;

/// Initialize the global detector worker pool with `num_workers` threads.
/// Call once at agent startup. If not called, a default pool (4 workers)
/// is lazily created on first use.
pub fn init_detector_pool(num_workers: usize) {
    let (tx, rx) = crossbeam_channel::bounded(num_workers * 4);
    for i in 0..num_workers {
        let rx = rx.clone();
        std::thread::Builder::new()
            .name(format!("det-worker-{i}"))
            .spawn(move || worker_loop(rx))
            .ok();
    }
    let _ = POOL_TX.set(tx);
}

/// Ensure the pool is available — lazy-init with defaults if not explicitly set.
fn ensure_pool() -> &'static crossbeam_channel::Sender<DetectorTask> {
    POOL_TX.get_or_init(|| {
        let num_workers = DEFAULT_POOL_WORKERS;
        let (tx, rx) = crossbeam_channel::bounded(num_workers * 4);
        for i in 0..num_workers {
            let rx = rx.clone();
            std::thread::Builder::new()
                .name(format!("det-worker-{i}"))
                .spawn(move || worker_loop(rx))
                .ok();
        }
        tx
    })
}

/// Worker loop — each thread pulls tasks from the shared channel.
/// Panic-safe: catch_unwind wraps every evaluate() call.
fn worker_loop(rx: crossbeam_channel::Receiver<DetectorTask>) {
    while let Ok(task) = rx.recv() {
        let start = Instant::now();
        let id = task.detector.id();
        let version = task.detector.version().to_string();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            task.detector.evaluate(&task.flow)
        }));

        let mut finding = match result {
            Ok(f) => f,
            Err(panic) => {
                let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "detector panicked (non-string payload)".to_string()
                };
                DetectorFinding::errored(id, &version, &msg, 0)
            }
        };
        finding.latency_us = start.elapsed().as_micros() as u64;
        let _ = task.result_tx.send(finding);
    }
}

/// Run a detector against a flow with an enforced timeout.
/// Uses the bounded worker pool — no OS thread is spawned per call.
/// Returns a DetectorFinding — either the detector's result or a TimedOut/Errored finding.
pub fn run_detector_with_timeout(
    detector: Arc<dyn Detector>,
    flow: Arc<FlowRecord>,
    budget: Duration,
) -> DetectorFinding {
    let tx = ensure_pool();
    let (result_tx, result_rx) = crossbeam_channel::bounded(1);

    let task = DetectorTask {
        detector: Arc::clone(&detector),
        flow: Arc::try_unwrap(flow).unwrap_or_else(|arc| (*arc).clone()),
        result_tx,
    };

    if tx.send(task).is_err() {
        return DetectorFinding::errored(
            detector.id(),
            detector.version(),
            "detector pool shut down",
            0,
        );
    }

    match result_rx.recv_timeout(budget) {
        Ok(finding) => finding,
        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
            DetectorFinding::timed_out(detector.id(), detector.version(), 0)
        }
        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => DetectorFinding::errored(
            detector.id(),
            detector.version(),
            "detector pool worker disconnected",
            0,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_validated_block_try_new_valid() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let block = ValidatedBlock::try_new(ip, Duration::from_secs(300)).unwrap();
        assert_eq!(block.ip(), ip);
        assert_eq!(block.ttl(), Duration::from_secs(300));
    }

    #[test]
    fn test_validated_block_ttl_too_small() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let err = ValidatedBlock::try_new(ip, Duration::from_secs(10)).unwrap_err();
        assert!(matches!(err, ValidationError::TtlTooSmall { .. }));
    }

    #[test]
    fn test_validated_block_ttl_too_large() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let err = ValidatedBlock::try_new(ip, Duration::from_secs(86401)).unwrap_err();
        assert!(matches!(err, ValidationError::TtlTooLarge { .. }));
    }

    #[test]
    fn test_validated_block_ttl_boundary_min() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(ValidatedBlock::try_new(ip, Duration::from_secs(30)).is_ok());
        assert!(ValidatedBlock::try_new(ip, Duration::from_secs(29)).is_err());
    }

    #[test]
    fn test_validated_block_ttl_boundary_max() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(ValidatedBlock::try_new(ip, Duration::from_secs(86400)).is_ok());
        assert!(ValidatedBlock::try_new(ip, Duration::from_secs(86401)).is_err());
    }

    #[test]
    fn test_validated_block_loopback_v4_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let err = ValidatedBlock::try_new(ip, Duration::from_secs(300)).unwrap_err();
        assert_eq!(err, ValidationError::LoopbackIp);
    }

    #[test]
    fn test_validated_block_loopback_v6_rejected() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let err = ValidatedBlock::try_new(ip, Duration::from_secs(300)).unwrap_err();
        assert_eq!(err, ValidationError::LoopbackIp);
    }

    #[test]
    fn test_validated_block_multicast_rejected() {
        let v4 = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
        assert_eq!(
            ValidatedBlock::try_new(v4, Duration::from_secs(300)).unwrap_err(),
            ValidationError::MulticastIp
        );
        let v6 = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(
            ValidatedBlock::try_new(v6, Duration::from_secs(300)).unwrap_err(),
            ValidationError::MulticastIp
        );
    }

    #[test]
    fn test_validated_block_broadcast_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
        let err = ValidatedBlock::try_new(ip, Duration::from_secs(300)).unwrap_err();
        assert_eq!(err, ValidationError::BroadcastIp);
    }

    #[test]
    fn test_validated_block_link_local_v4_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
        let err = ValidatedBlock::try_new(ip, Duration::from_secs(300)).unwrap_err();
        assert_eq!(err, ValidationError::LinkLocalIp);
    }

    #[test]
    fn test_validated_block_link_local_v6_rejected() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let err = ValidatedBlock::try_new(ip, Duration::from_secs(300)).unwrap_err();
        assert_eq!(err, ValidationError::LinkLocalIp);
    }

    #[test]
    fn test_validated_block_unspecified_rejected() {
        let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            ValidatedBlock::try_new(v4, Duration::from_secs(300)).unwrap_err(),
            ValidationError::UnspecifiedIp
        );
        let v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            ValidatedBlock::try_new(v6, Duration::from_secs(300)).unwrap_err(),
            ValidationError::UnspecifiedIp
        );
    }

    #[test]
    fn test_validated_block_serde_roundtrip() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let block = ValidatedBlock::try_new(ip, Duration::from_secs(600)).unwrap();
        let serialized = bincode::serialize(&block).unwrap();
        let deserialized: ValidatedBlock = bincode::deserialize(&serialized).unwrap();
        assert_eq!(block, deserialized);
        assert_eq!(deserialized.ip(), ip);
        assert_eq!(deserialized.ttl(), Duration::from_secs(600));
    }

    #[test]
    fn test_validated_block_display_error() {
        let err = ValidationError::TtlTooSmall {
            ttl: Duration::from_secs(5),
            min: Duration::from_secs(30),
        };
        let msg = format!("{err}");
        assert!(msg.contains("5s"));
        assert!(msg.contains("30s"));
    }

    #[test]
    fn test_flow_age_truncation_safety() {
        use std::time::Duration;
        let age = Duration::from_millis(u64::MAX);
        let flow = FlowRecord {
            flow_id: 1,
            a_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            b_ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            a_port: 1000,
            b_port: 2000,
            protocol: 6,
            local_port: 1000,
            pid: None,
            packet_count: 1,
            byte_count: 100,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code: None,
            asn: None,
            reputation_score: None,
            flow_age: age,
        };
        let features = FlowFeatures::from_flow(&flow);
        assert_eq!(features.duration_ms, u64::MAX);
    }
}
