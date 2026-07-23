// crates/common/src/types.rs
//
// Shared data contracts for the enforcement backend.
// §4c: "ValidatedBlock, BlockId, DesiredFirewallState, ReconciliationReport,
// and EnforcementReceipt belong in crates/common/src/types.rs"

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

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
    /// ONNX model inference (future).
    OnnxModel,
    /// Reputation feed lookup (future).
    ReputationEngine,
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
#[derive(Debug, Clone)]
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
    pub country_code: Option<String>,
    pub reputation_score: Option<f32>,
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
    /// Extract features from a FlowRecord and flow start time.
    pub fn from_flow(flow: &FlowRecord, flow_age: Duration) -> Self {
        let duration_ms = flow_age.as_millis() as u64;
        let duration_sec = flow_age.as_secs_f64();
        let packet_frequency = if duration_sec > 0.0 {
            flow.packet_count as f64 / duration_sec
        } else {
            0.0
        };

        Self {
            flow_id: flow.flow_id,
            packet_count: flow.packet_count,
            byte_count: flow.byte_count,
            duration_ms,
            packet_frequency,
            protocol: flow.protocol,
            dst_port: flow.dst_port,
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
}

impl Default for DecisionConfig {
    fn default() -> Self {
        let mut ttl_by_severity = std::collections::HashMap::new();
        ttl_by_severity.insert(Severity::Critical, Duration::from_secs(3600)); // 1 hour
        ttl_by_severity.insert(Severity::High, Duration::from_secs(900)); // 15 min
        ttl_by_severity.insert(Severity::Medium, Duration::from_secs(300)); // 5 min
        ttl_by_severity.insert(Severity::Low, Duration::from_secs(60)); // 1 min

        Self {
            block_threshold: 0.5,
            alert_threshold: 0.2,
            ttl_by_severity,
            min_ttl: Duration::from_secs(30),
            max_ttl: Duration::from_secs(86400), // 24 hours
            timed_out_weight: 0.1,
            errored_weight: 0.0,
        }
    }
}

/// Run a detector against a flow with an enforced timeout.
/// Returns a DetectorFinding — either the detector's result or a TimedOut/Errored finding.
/// The detector runs on its own thread; if it exceeds `budget`, we return TimedOut
/// without waiting for the detector thread to finish (it can finish later and be dropped).
pub fn run_detector_with_timeout(
    detector: Arc<dyn Detector>,
    flow: &FlowRecord,
    budget: Duration,
) -> DetectorFinding {
    let id = detector.id();
    let version = detector.version().to_string();
    let flow = flow.clone();

    // Channel for the detector thread to send its result back.
    let (tx, rx) = mpsc::channel::<DetectorFinding>();

    // Spawn the detector on its own thread.
    let _handle = thread::Builder::new()
        .name(format!("detector-{:?}", id))
        .spawn(move || {
            let result = detector.evaluate(&flow);
            // If the receiver has already been dropped (timeout fired),
            // this send will fail silently — the thread finishes and is dropped.
            let _ = tx.send(result);
        });

    let start = Instant::now();

    // Wait for the result with a timeout.
    match rx.recv_timeout(budget) {
        Ok(mut finding) => {
            // Detector completed within budget — record actual latency.
            finding.latency_us = start.elapsed().as_micros() as u64;
            finding
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Detector exceeded budget — return TimedOut.
            // The detector thread continues running but its result is dropped.
            let latency_us = start.elapsed().as_micros() as u64;
            DetectorFinding::timed_out(id, &version, latency_us)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Detector thread panicked or exited without sending a result.
            let latency_us = start.elapsed().as_micros() as u64;
            DetectorFinding::errored(id, &version, "detector thread disconnected", latency_us)
        }
    }
}
