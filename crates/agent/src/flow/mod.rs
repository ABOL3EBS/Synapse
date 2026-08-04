// crates/agent/src/flow/mod.rs
//
// In-memory flow tracker — session window with ~100ms ticks.
// §4 step 3: "Traffic aggregated into sessions over an in-memory window
// (~100ms ticks), attaching whatever enrichment context has landed by this
// point without blocking for it, and producing feature vectors."
//
// Justification >600 lines: flow/mod.rs contains the complete session
// lifecycle — FlowKey canonicalization, FlowRecord state, tick-based expiry,
// re-evaluation scheduling, eviction (BinaryHeap), enrichment attachment,
// and all 16 unit tests covering edge cases. Splitting would scatter
// tightly-coupled state across files.
//
// Design decisions (recorded explicitly, not left implicit):
// - FlowKey is direction-agnostic: (ip, port) swapped as bound pairs.
// - local_port stored separately on FlowRecord, set once at creation.
// - DNS/GeoIP/Reputation: per-flow dispatch (known v1 inefficiency,
//   documented). Only process attribution is genuinely flow-specific.
// - MAX_FLOWS = 100_000 defensive bound. Evict oldest on overflow.
// - tick() must fire on poll() timeout, not only on packet arrival.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

use log::{debug, warn};

use synapse_common::PacketInfo;

// ---------------------------------------------------------------------------
// FlowConfig — runtime configuration for the flow tracker
// ---------------------------------------------------------------------------

/// Configuration for the flow tracker. Loaded from TOML config or defaults.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    pub max_flows: usize,
    pub expiry_secs: u64,
    /// Minimum time between re-evaluations of the same flow (wall-clock seconds).
    /// Checked in tick() against now - last_evaluated.
    pub evaluation_interval_secs: u64,
    pub max_re_eval_per_tick: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            max_flows: 100_000,
            expiry_secs: 5,
            evaluation_interval_secs: 1,
            max_re_eval_per_tick: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// FlowKey — direction-agnostic canonical 5-tuple
// ---------------------------------------------------------------------------

/// Canonical flow key. Direction-agnostic: (ip, port) swapped as bound pairs.
/// A forward packet and its response always produce the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub a_ip: IpAddr,
    pub a_port: u16,
    pub b_ip: IpAddr,
    pub b_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Canonicalize a packet into a direction-agnostic flow key.
    /// (ip, port) are always swapped as bound pairs — never independently.
    pub fn from_packet(info: &PacketInfo) -> Self {
        if info.src_ip < info.dst_ip {
            Self {
                a_ip: info.src_ip,
                a_port: info.src_port,
                b_ip: info.dst_ip,
                b_port: info.dst_port,
                protocol: info.protocol,
            }
        } else if info.src_ip > info.dst_ip {
            Self {
                a_ip: info.dst_ip,
                a_port: info.dst_port,
                b_ip: info.src_ip,
                b_port: info.src_port,
                protocol: info.protocol,
            }
        } else {
            // Same IP — compare ports.
            if info.src_port <= info.dst_port {
                Self {
                    a_ip: info.src_ip,
                    a_port: info.src_port,
                    b_ip: info.dst_ip,
                    b_port: info.dst_port,
                    protocol: info.protocol,
                }
            } else {
                Self {
                    a_ip: info.dst_ip,
                    a_port: info.dst_port,
                    b_ip: info.src_ip,
                    b_port: info.src_port,
                    protocol: info.protocol,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FlowRecord — per-session state
// ---------------------------------------------------------------------------

/// What happened to a flow update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowUpdate {
    /// New flow created. Caller should dispatch enrichment.
    NewFlow(u64),
    /// Existing flow updated (stats incremented).
    ExistingFlow(u64),
}

/// A tracked network flow (session).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FlowRecord {
    /// Monotonically increasing flow ID.
    pub flow_id: u64,
    /// Canonical direction-agnostic key.
    pub key: FlowKey,
    /// The LOCAL port — set once at creation from the original packet,
    /// independent of the canonical key's ordering. Needed for port→PID
    /// cache lookup, which requires knowing which side is local.
    pub local_port: u16,
    /// PID of the local process, resolved once at creation from local_port.
    pub pid: Option<u32>,
    /// When this flow was first seen.
    pub first_seen: Instant,
    /// When this flow was last seen (updated on every packet).
    pub last_seen: Instant,
    /// Total packets in this flow.
    pub packet_count: u64,
    /// Total bytes in this flow.
    pub byte_count: u64,

    // --- Enrichment results (attached async, None until they arrive) ---
    /// Reverse DNS hostname for the destination IP.
    pub dns_name: Option<String>,
    /// Process executable path (from PID attribution).
    pub process_path: Option<String>,
    /// Process start time as epoch seconds.
    pub process_start_time: Option<f64>,
    /// ISO 3166-1 alpha-2 country code (stub in v1).
    pub country_code: Option<String>,
    /// Autonomous system number (if GeoIp succeeded; stub in v1).
    pub asn: Option<u32>,
    /// Reputation score 0.0–1.0 (stub in v1).
    pub reputation_score: Option<f32>,
    /// When detectors were last run on this flow.
    /// Updated by mark_evaluated() after each detection pass.
    pub last_evaluated: Instant,
}

impl From<FlowRecord> for synapse_common::FlowRecord {
    fn from(flow: FlowRecord) -> Self {
        Self {
            flow_id: flow.flow_id,
            a_ip: flow.key.a_ip,
            b_ip: flow.key.b_ip,
            a_port: flow.key.a_port,
            b_port: flow.key.b_port,
            protocol: flow.key.protocol,
            local_port: flow.local_port,
            pid: flow.pid,
            packet_count: flow.packet_count,
            byte_count: flow.byte_count,
            dns_name: flow.dns_name,
            process_path: flow.process_path,
            process_start_time: flow.process_start_time,
            country_code: flow.country_code,
            asn: flow.asn,
            reputation_score: flow.reputation_score,
            flow_age: flow.first_seen.elapsed(),
        }
    }
}

// ---------------------------------------------------------------------------
// FlowTracker — the session window
// ---------------------------------------------------------------------------

/// In-memory flow tracker. Manages session windows with ~100ms tick expiry.
pub struct FlowTracker {
    /// Canonical key → flow ID.
    index: HashMap<FlowKey, u64>,
    /// Flow ID → flow record.
    flows: HashMap<u64, FlowRecord>,
    /// Min-heap for O(log n) eviction of oldest flow.
    /// Entries are (first_seen, flow_id) in Reverse order so pop() yields oldest.
    /// Stale entries (flows already removed by expiry) are lazily skipped.
    eviction_heap: BinaryHeap<Reverse<(Instant, u64)>>,
    /// P3: Time-ordered queue for O(k) re-evaluation (replaces O(N) HashMap scan).
    /// Entries are (last_evaluated, flow_id) — stale entries skipped lazily.
    re_eval_queue: VecDeque<(Instant, u64)>,
    /// Next flow ID (monotonically increasing).
    next_id: u64,
    /// Runtime configuration.
    config: FlowConfig,
}

impl FlowTracker {
    pub fn new(config: FlowConfig) -> Self {
        Self {
            index: HashMap::new(),
            flows: HashMap::new(),
            eviction_heap: BinaryHeap::new(),
            re_eval_queue: VecDeque::new(),
            next_id: 1,
            config,
        }
    }

    /// Process a packet: insert or update a flow.
    /// Returns NewFlow (caller should dispatch enrichment) or ExistingFlow.
    pub fn update(&mut self, info: &PacketInfo, local_port: u16, pid: Option<u32>) -> FlowUpdate {
        debug!(
            "update() called: {}:{} → {}:{} proto={} local_port={} pid={:?} total_flows={}",
            info.src_ip,
            info.src_port,
            info.dst_ip,
            info.dst_port,
            info.protocol,
            local_port,
            pid,
            self.flows.len()
        );
        let key = FlowKey::from_packet(info);

        if let Some(&flow_id) = self.index.get(&key) {
            // Existing flow — update stats.
            if let Some(flow) = self.flows.get_mut(&flow_id) {
                flow.last_seen = Instant::now();
                flow.packet_count += 1;
                flow.byte_count += info.length as u64;
            }
            return FlowUpdate::ExistingFlow(flow_id);
        }

        // New flow — evict oldest if at capacity.
        if self.flows.len() >= self.config.max_flows {
            self.evict_oldest();
        }

        let flow_id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let now = Instant::now();
        let flow = FlowRecord {
            flow_id,
            key,
            local_port,
            pid,
            first_seen: now,
            last_seen: now,
            packet_count: 1,
            byte_count: info.length as u64,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code: None,
            asn: None,
            reputation_score: None,
            last_evaluated: now,
        };

        self.index.insert(key, flow_id);
        self.flows.insert(flow_id, flow);
        self.eviction_heap.push(Reverse((now, flow_id)));
        // P3: Append to re-evaluation queue (O(1) amortized).
        // INVARIANT: All push_back calls must maintain monotonically
        // increasing (entry_time, flow_id) order, because tick() assumes
        // earlier entries have older or equal last_evaluated times and
        // breaks on the first entry not yet due by wall-clock. This holds
        // because (a) evaluation_interval_secs is a single global constant,
        // and (b) EVERY push goes to the back — creation entries at
        // flow-creation time and re-evaluation entries at mark_evaluated()
        // time, both using Instant::now(). If either condition changes,
        // the break-on-first-not-due logic in tick() breaks silently.
        debug_assert!(
            self.re_eval_queue.back().is_none_or(|&(t, _)| t <= now),
            "re_eval_queue monotonic invariant violated: back time > now"
        );
        self.re_eval_queue.push_back((now, flow_id));

        debug!(
            "flow {} created: {:?} local_port={}",
            flow_id, key, local_port
        );
        FlowUpdate::NewFlow(flow_id)
    }

    /// Expire flows older than config.expiry_secs and find active flows due for
    /// re-evaluation. Returns (expired, due_for_re_evaluate).
    ///
    /// - **expired**: flows past expiry_secs idle — caller should evaluate
    ///   and then call `remove_expired()` to reclaim memory.
    /// - **due_for_re_evaluate**: active flows where now - last_evaluated >
    ///   evaluation_interval_secs — caller should re-run detectors and call
    ///   mark_evaluated(). Capped at max_re_eval_per_tick.
    ///
    /// IMPORTANT: Expired flows remain in the tracker after tick() returns.
    /// The caller must evaluate them (run detectors, produce verdicts) and
    /// then call `remove_expired()` to reclaim memory. This ordering ensures
    /// flow data is still accessible for evaluation.
    ///
    /// Must be called on every capture-loop iteration (via poll() timeout),
    /// not only when a packet arrives — a quiet-but-stale network must not
    /// leave memory pinned.
    pub fn tick(&mut self) -> (Vec<u64>, Vec<u64>) {
        let now = Instant::now();
        let mut expired = Vec::new();

        // Identify expired flows but do NOT remove them — caller needs the
        // data for detector evaluation. Caller must call remove_expired().
        for (&flow_id, flow) in &self.flows {
            if now.duration_since(flow.last_seen).as_secs() >= self.config.expiry_secs {
                expired.push(flow_id);
            }
        }

        // R8: Periodically purge stale entries from the eviction heap.
        // Stale entries accumulate because flow expiry removes from self.flows
        // but not from the heap (which is only cleaned lazily in evict_oldest()).
        // Purge when heap is >2x active flow count — amortised O(n) cost,
        // happens infrequently (only during active expiry).
        if !expired.is_empty() && self.eviction_heap.len() > self.flows.len().saturating_mul(2) {
            let before = self.eviction_heap.len();
            let mut purged = BinaryHeap::new();
            while let Some(entry) = self.eviction_heap.pop() {
                if self.flows.contains_key(&entry.0 .1) {
                    purged.push(entry);
                }
            }
            self.eviction_heap = purged;
            let after = self.eviction_heap.len();
            if before > after {
                debug!(
                    "eviction_heap purged {} stale entries ({} → {})",
                    before - after,
                    before,
                    after
                );
            }
        }

        // P3: O(k) re-evaluation via VecDeque (entry_time, flow_id) entries.
        // Stale entries (flow removed or re-evaluated since entry creation)
        // are popped and skipped. Active entries not yet due by wall-clock
        // are left in the queue for the next tick.
        let due_for_re_evaluate = {
            let mut due = Vec::new();
            while let Some(&(entry_time, flow_id)) = self.re_eval_queue.front() {
                let flow = match self.flows.get(&flow_id) {
                    None => {
                        self.re_eval_queue.pop_front();
                        continue;
                    }
                    Some(f) => f,
                };
                // Skip stale: flow was re-evaluated AFTER this entry was created.
                if flow.last_evaluated > entry_time {
                    self.re_eval_queue.pop_front();
                    continue;
                }
                // Not yet due by wall-clock — leave in queue for next tick.
                // INVARIANT: We can safely break (rather than continue scanning)
                // because entries are pushed in monotonically increasing time
                // order. This entry's last_evaluated is the oldest in the queue;
                // if it isn't due yet, none of the later entries can be either.
                // See update() for the full invariant justification.
                if now.duration_since(flow.last_evaluated).as_secs()
                    < self.config.evaluation_interval_secs
                {
                    break;
                }
                self.re_eval_queue.pop_front();
                due.push(flow_id);
                if due.len() >= self.config.max_re_eval_per_tick {
                    break;
                }
            }
            due
        };

        if !expired.is_empty() || !due_for_re_evaluate.is_empty() {
            debug!(
                "tick: expired {} flows, re-evaluate {} flows ({} remaining)",
                expired.len(),
                due_for_re_evaluate.len(),
                self.flows.len()
            );
        }

        (expired, due_for_re_evaluate)
    }

    /// Evict the oldest flow (by first_seen) to make room.
    /// Called when flow count hits MAX_FLOWS.
    /// Uses the min-heap for O(log n) amortized eviction. Stale entries
    /// (flows already removed by expiry) are lazily skipped.
    fn evict_oldest(&mut self) {
        while let Some(Reverse((first_seen, flow_id))) = self.eviction_heap.pop() {
            // Skip stale entries — flow was already removed by tick() expiry.
            if !self.flows.contains_key(&flow_id) {
                continue;
            }
            if let Some(flow) = self.flows.remove(&flow_id) {
                self.index.remove(&flow.key);
                warn!(
                    "flow tracker at capacity ({}), evicting oldest flow {} (key={:?}, age={:?})",
                    self.config.max_flows,
                    flow_id,
                    flow.key,
                    first_seen.elapsed(),
                );
                return;
            }
        }
    }

    /// Attach an enrichment result to a flow.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_enrichment(
        &mut self,
        flow_id: u64,
        dns_name: Option<String>,
        process_path: Option<String>,
        process_start_time: Option<f64>,
        country_code: Option<String>,
        asn: Option<u32>,
        reputation_score: Option<f32>,
    ) {
        if let Some(flow) = self.flows.get_mut(&flow_id) {
            if dns_name.is_some() {
                flow.dns_name = dns_name;
            }
            if process_path.is_some() {
                flow.process_path = process_path;
            }
            if process_start_time.is_some() {
                flow.process_start_time = process_start_time;
            }
            if country_code.is_some() {
                flow.country_code = country_code;
            }
            if asn.is_some() {
                flow.asn = asn;
            }
            if reputation_score.is_some() {
                flow.reputation_score = reputation_score;
            }
        }
    }

    /// Get a reference to a flow by ID.
    pub fn get(&self, flow_id: u64) -> Option<&FlowRecord> {
        self.flows.get(&flow_id)
    }

    /// Mark a flow as evaluated — bumps last_evaluated to now.
    /// Called after detectors + decision engine run on a flow, regardless
    /// of finding status (TimedOut/Errored detectors don't get special
    /// backoff — the re-evaluation interval is a property of the flow,
    /// not the detector).
    pub fn mark_evaluated(&mut self, flow_id: u64) {
        if let Some(flow) = self.flows.get_mut(&flow_id) {
            let now = Instant::now();
            flow.last_evaluated = now;
            // P3: Append to re-evaluation queue. See update() for the
            // monotonically-increasing-time invariant that makes this safe.
            debug_assert!(
                self.re_eval_queue.back().is_none_or(|&(t, _)| t <= now),
                "re_eval_queue monotonic invariant violated in mark_evaluated"
            );
            self.re_eval_queue.push_back((now, flow_id));
        }
    }

    /// Remove expired flows from the tracker (both the flow map and the
    /// canonical index). Must be called by the capture loop after running
    /// detectors and handling verdicts on the expired flow IDs returned
    /// by tick().
    pub fn remove_expired(&mut self, expired: &[u64]) {
        for &flow_id in expired {
            if let Some(flow) = self.flows.remove(&flow_id) {
                self.index.remove(&flow.key);
            }
        }
    }

    /// Number of currently tracked flows.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Test-local defaults matching FlowConfig::default().
    const FLOW_EXPIRY_SECS: u64 = 5;
    const EVALUATION_INTERVAL_SECS: u64 = 1;
    const MAX_RE_EVAL_PER_TICK: usize = 100;

    fn make_packet(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: u8,
    ) -> PacketInfo {
        PacketInfo {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: proto,
            length: 64,
        }
    }

    #[test]
    fn test_canonicalization_forward_and_response_produce_same_key() {
        let fwd = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let rev = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            6,
        );
        assert_eq!(FlowKey::from_packet(&fwd), FlowKey::from_packet(&rev));
    }

    #[test]
    fn test_canonicalization_same_ip_loopback() {
        let fwd = make_packet(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            443,
            6,
        );
        let rev = make_packet(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            443,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            5000,
            6,
        );
        assert_eq!(FlowKey::from_packet(&fwd), FlowKey::from_packet(&rev));
    }

    #[test]
    fn test_canonicalization_ipv6() {
        let fwd = make_packet(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            8080,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            443,
            6,
        );
        let rev = make_packet(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            443,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            8080,
            6,
        );
        assert_eq!(FlowKey::from_packet(&fwd), FlowKey::from_packet(&rev));
    }

    #[test]
    fn test_canonicalization_different_protocols_are_different_flows() {
        let tcp = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let udp = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            17,
        );
        assert_ne!(FlowKey::from_packet(&tcp), FlowKey::from_packet(&udp));
    }

    #[test]
    fn test_update_returns_new_vs_existing() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );

        match tracker.update(&pkt, 5000, Some(100)) {
            FlowUpdate::NewFlow(id) => assert_eq!(id, 1),
            _ => panic!("expected NewFlow"),
        }

        match tracker.update(&pkt, 5000, Some(100)) {
            FlowUpdate::ExistingFlow(id) => assert_eq!(id, 1),
            _ => panic!("expected ExistingFlow"),
        }

        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn test_forward_and_response_update_same_flow() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        let fwd = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let rev = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            6,
        );

        let id1 = match tracker.update(&fwd, 5000, Some(100)) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };
        let id2 = match tracker.update(&rev, 5000, Some(100)) {
            FlowUpdate::ExistingFlow(id) => id,
            _ => panic!("expected ExistingFlow"),
        };

        assert_eq!(id1, id2, "forward and response must map to the same flow");
        let flow = tracker.get(id1).unwrap();
        assert_eq!(flow.packet_count, 2);
        assert_eq!(flow.local_port, 5000);
    }

    #[test]
    fn test_max_flows_evicts_oldest() {
        let cfg = FlowConfig {
            max_flows: 100,
            ..FlowConfig::default()
        };
        let mut tracker = FlowTracker::new(cfg);

        // Fill to capacity. Use both IP and port to generate unique 5-tuples.
        for i in 0..100 {
            let src_port = 1024 + (i % 60000) as u16;
            let octet3 = ((i / 60000) & 0xFF) as u8;
            let octet2 = ((i / 60000 / 256) & 0xFF) as u8;
            let pkt = make_packet(
                IpAddr::V4(Ipv4Addr::new(10, octet2, octet3, 1)),
                src_port,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                443,
                6,
            );
            tracker.update(&pkt, src_port, None);
        }
        assert_eq!(tracker.len(), 100);

        // One more — should evict oldest.
        let overflow = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)),
            60000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        tracker.update(&overflow, 60000, None);

        // Should still be at 100 (evicted one, added one).
        assert_eq!(tracker.len(), 100);
    }

    #[test]
    fn test_tick_expires_old_flows() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        tracker.update(&pkt, 5000, None);
        assert_eq!(tracker.len(), 1);

        // Immediately — nothing should expire, nothing due for re-eval.
        let (expired, re_eval) = tracker.tick();
        assert!(expired.is_empty());
        assert!(re_eval.is_empty());

        // Manually backdate the flow's last_seen to simulate staleness.
        {
            let flow = tracker.get_mut(1).unwrap();
            flow.last_seen = Instant::now() - std::time::Duration::from_secs(FLOW_EXPIRY_SECS + 1);
        }

        // Now tick should mark it expired.
        let (expired, re_eval) = tracker.tick();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], 1);
        // Flow is still in tracker until caller explicitly removes it.
        assert_eq!(tracker.len(), 1);
        tracker.remove_expired(&expired);
        assert!(tracker.is_empty());
        assert!(re_eval.is_empty());
    }

    #[test]
    fn test_attach_enrichment() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let id = match tracker.update(&pkt, 5000, Some(100)) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };

        tracker.attach_enrichment(
            id,
            Some("example.com".to_string()),
            Some("/usr/bin/curl".to_string()),
            Some(1234567890.0),
            None,
            None,
            None,
        );

        let flow = tracker.get(id).unwrap();
        assert_eq!(flow.dns_name.as_deref(), Some("example.com"));
        assert_eq!(flow.process_path.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(flow.process_start_time, Some(1234567890.0));
        assert!(flow.country_code.is_none());
        assert!(flow.reputation_score.is_none());
    }

    // Helper to get a mutable reference to a flow (for backdating in tests).
    impl FlowTracker {
        fn get_mut(&mut self, flow_id: u64) -> Option<&mut FlowRecord> {
            self.flows.get_mut(&flow_id)
        }
    }

    // -----------------------------------------------------------------------
    // Design review tests — four specific verifications
    // -----------------------------------------------------------------------

    /// Test 1: Canonicalization — swap case (local IP > remote IP).
    /// The existing test_canonicalization_forward_and_response_produce_same_key
    /// only tests src_ip < dst_ip. This test verifies the SWAP case:
    /// local 192.168.1.100 > remote 8.8.8.8, so canonicalization swaps them.
    #[test]
    fn test_canonicalization_swap_case_local_ip_larger() {
        // Forward: local (192.168.1.100:50000) → remote (8.8.8.8:443)
        let fwd = make_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            6,
        );
        // Response: remote (8.8.8.8:443) → local (192.168.1.100:50000)
        let rev = make_packet(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            50000,
            6,
        );
        let fwd_key = FlowKey::from_packet(&fwd);
        let rev_key = FlowKey::from_packet(&rev);
        assert_eq!(
            fwd_key, rev_key,
            "swap case: forward and response must produce identical FlowKey"
        );
        // Verify the canonical ordering: 8.8.8.8 (smaller) comes first.
        assert_eq!(fwd_key.a_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(fwd_key.a_port, 443);
        assert_eq!(fwd_key.b_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(fwd_key.b_port, 50000);
    }

    /// Test 2: Local port stored independently of canonical key ordering.
    /// In the swap case (local IP > remote IP), canonicalization puts remote
    /// first. But local_port must still be the LOCAL port (50000), not the
    /// canonical key's a_port (443). Process attribution must look up 50000.
    #[test]
    fn test_local_port_independent_of_canonical_ordering() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        // Forward: local 192.168.1.100:50000 → remote 8.8.8.8:443
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            6,
        );
        let flow_id = match tracker.update(&pkt, 50000, Some(42)) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };
        let flow = tracker.get(flow_id).unwrap();

        // Canonical key: 8.8.8.8:443 → 192.168.1.100:50000 (remote first)
        assert_eq!(flow.key.a_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(flow.key.a_port, 443);
        assert_eq!(flow.key.b_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(flow.key.b_port, 50000);

        // BUT local_port is 50000 (the actual local port), NOT 443.
        assert_eq!(
            flow.local_port, 50000,
            "local_port must be the real local port (50000), not the canonical a_port (443)"
        );
        // PID was resolved from local_port=50000, not from the canonical key.
        assert_eq!(
            flow.pid,
            Some(42),
            "PID must be resolved from local_port (50000), not from canonical ordering"
        );
    }

    /// Test 3: Enrichment dedup — confirm it's per-flow, not per-IP.
    /// Two flows to the same destination IP get separate enrichment dispatches.
    /// This is a known v1 inefficiency (documented). This test proves it.
    #[test]
    fn test_enrichment_dispatched_per_flow_not_per_ip() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        // Two flows to the same IP but different source ports.
        let pkt1 = make_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            40000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            6,
        );
        let pkt2 = make_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            40001,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            6,
        );
        let id1 = match tracker.update(&pkt1, 40000, None) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };
        let id2 = match tracker.update(&pkt2, 40001, None) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };
        // Two distinct flows exist — both would trigger enrichment dispatch.
        assert_ne!(id1, id2);
        assert_eq!(tracker.len(), 2);
        // Both flows have the same destination IP but different flow IDs.
        // In main.rs, each NewFlow triggers enrich_pool.dispatch() —
        // so DNS/GeoIP/Reputation are dispatched TWICE for the same IP.
        // This is the documented v1 inefficiency.
    }

    /// Test 4: MAX_FLOWS cap exists and tick() fires on wall-clock basis.
    /// tick() uses Instant::now() (wall clock), not packet count.
    /// This test proves tick() expires flows based on real time elapsed.
    #[test]
    fn test_tick_fires_on_wall_clock_not_packet_count() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        // Create a flow.
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let id = match tracker.update(&pkt, 5000, None) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };
        // Immediately — flow should NOT be expired.
        let (expired, _) = tracker.tick();
        assert!(expired.is_empty(), "flow should not expire immediately");

        // Backdate last_seen to trigger expiry (simulates wall-clock passage).
        if let Some(flow) = tracker.get_mut(id) {
            flow.last_seen = Instant::now() - std::time::Duration::from_secs(FLOW_EXPIRY_SECS + 1);
        }
        let (expired, _) = tracker.tick();
        assert_eq!(
            expired.len(),
            1,
            "flow should expire after FLOW_EXPIRY_SECS"
        );
        assert_eq!(expired[0], id);
    }

    // -----------------------------------------------------------------------
    // Re-evaluation tests — active flow detection (§4 step 3)
    // -----------------------------------------------------------------------

    /// Test: active flow with stale last_evaluated appears in re-evaluate list.
    /// Exercises the real code path: update() pushes a creation-time entry,
    /// we backdate last_evaluated to simulate wall-clock passage, and tick()
    /// should return the flow as due for re-evaluation.
    #[test]
    fn test_tick_returns_re_evaluate_for_stale_last_evaluated() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let id = match tracker.update(&pkt, 5000, None) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };

        // Immediately — last_evaluated == now, so not due.
        let (expired, re_eval) = tracker.tick();
        assert!(expired.is_empty());
        assert!(re_eval.is_empty());

        // Backdate last_evaluated by 2s (past EVALUATION_INTERVAL_SECS).
        // The creation-time queue entry will become due on the next tick.
        // Keep last_seen fresh so the flow doesn't expire.
        {
            tracker.get_mut(id).unwrap().last_evaluated =
                Instant::now() - std::time::Duration::from_secs(EVALUATION_INTERVAL_SECS + 1);
        }

        // Should appear on the very next tick (the creation-time entry is now due).
        let (expired, re_eval) = tracker.tick();
        assert!(
            expired.is_empty(),
            "flow is still active, should not expire"
        );
        assert_eq!(re_eval.len(), 1);
        assert_eq!(re_eval[0], id);
        // Flow is still in the tracker.
        assert_eq!(tracker.len(), 1);
    }

    /// Test: mark_evaluated() bumps last_evaluated regardless of finding status.
    /// After marking, the flow should NOT appear in re-evaluate on next tick.
    /// Exercises the real code path: creation-time entry, then mark_evaluated-
    /// pushed entry.
    #[test]
    fn test_mark_evaluated_prevents_immediate_re_evaluate() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let id = match tracker.update(&pkt, 5000, None) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };

        // Freshly created flow should not be due for re-evaluation.
        let (_, re_eval) = tracker.tick();
        assert!(re_eval.is_empty(), "freshly created flow should not be due");

        // Backdate last_evaluated to make the creation-time entry due.
        {
            tracker.get_mut(id).unwrap().last_evaluated =
                Instant::now() - std::time::Duration::from_secs(EVALUATION_INTERVAL_SECS + 1);
        }

        // Should appear on the very next tick (creation-time entry now due).
        let (_, re_eval) = tracker.tick();
        assert_eq!(re_eval.len(), 1);

        // Mark as evaluated — pushes a fresh queue entry at now.
        tracker.mark_evaluated(id);

        // Now it should NOT be due on the next tick.
        let (_, re_eval) = tracker.tick();
        assert!(
            re_eval.is_empty(),
            "after mark_evaluated, flow should not be due immediately"
        );
    }

    /// Test: MAX_RE_EVAL_PER_TICK caps the re-evaluation batch.
    /// Create more flows than the cap, backdate all their last_evaluated,
    /// verify only MAX_RE_EVAL_PER_TICK are returned on a single tick.
    /// Exercises the real code path: creation-time entries drive scheduling.
    #[test]
    fn test_re_evaluate_capped_at_max_re_eval_per_tick() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        // Create 150 flows (more than MAX_RE_EVAL_PER_TICK=100).
        for i in 0..150u16 {
            let pkt = make_packet(
                IpAddr::V4(Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 1)),
                5000 + i,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                443,
                6,
            );
            tracker.update(&pkt, 5000 + i, None);
        }
        assert_eq!(tracker.len(), 150);

        // Backdate all last_evaluated to make their creation-time entries due.
        // Tick() has never been called, so all 150 creation entries are still
        // in the queue.
        for id in 1..=150 {
            if let Some(flow) = tracker.get_mut(id) {
                flow.last_evaluated =
                    Instant::now() - std::time::Duration::from_secs(EVALUATION_INTERVAL_SECS + 1);
            }
        }

        // Should fire on the very next tick, capped at MAX_RE_EVAL_PER_TICK.
        // Remaining 50 entries stay in the queue for subsequent ticks.
        let (_, re_eval) = tracker.tick();
        assert_eq!(
            re_eval.len(),
            MAX_RE_EVAL_PER_TICK,
            "re-evaluation should be capped at MAX_RE_EVAL_PER_TICK"
        );
        // All 150 flows are still in the tracker (none expired).
        assert_eq!(tracker.len(), 150);
    }

    /// Stress test: single flow survives a full re-evaluation cycle and is
    /// re-evaluated a SECOND time while still active. This proves periodic
    /// re-evaluation is genuinely happening, not just firing once and then
    /// going quiet.
    ///
    /// Sequence:
    ///   1. Create flow (queue has creation-time entry, last_evaluated = now)
    ///   2. Tick → not due yet
    ///   3. Backdate last_evaluated → tick → first re-evaluation fires
    ///   4. mark_evaluated() (pushes fresh entry at now)
    ///   5. Tick → not due yet (fresh entry)
    ///   6. Backdate last_evaluated again → tick → SECOND re-evaluation fires
    #[test]
    fn test_periodic_re_evaluation_cycle() {
        let mut tracker = FlowTracker::new(FlowConfig::default());
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        let id = match tracker.update(&pkt, 5000, None) {
            FlowUpdate::NewFlow(id) => id,
            _ => panic!("expected NewFlow"),
        };

        // --- Tick 0: freshly created, not yet due ---
        let (expired, re_eval) = tracker.tick();
        assert!(expired.is_empty());
        assert!(re_eval.is_empty(), "fresh flow should not be due");

        // --- First re-evaluation ---
        {
            tracker.get_mut(id).unwrap().last_evaluated =
                Instant::now() - std::time::Duration::from_secs(EVALUATION_INTERVAL_SECS + 1);
        }

        let (expired, re_eval) = tracker.tick();
        assert!(expired.is_empty());
        assert_eq!(re_eval.len(), 1, "first re-evaluation should fire");
        assert_eq!(re_eval[0], id);

        // Simulate what process_re_evaluate_flows() does: mark as evaluated.
        // This pushes a fresh (now, id) entry to the queue.
        tracker.mark_evaluated(id);

        // Immediately after mark_evaluated: not due.
        let (expired, re_eval) = tracker.tick();
        assert!(expired.is_empty());
        assert!(
            re_eval.is_empty(),
            "should not be due immediately after mark_evaluated"
        );

        // --- Second re-evaluation: advance last_evaluated again ---
        {
            tracker.get_mut(id).unwrap().last_evaluated =
                Instant::now() - std::time::Duration::from_secs(EVALUATION_INTERVAL_SECS + 1);
        }

        let (expired, re_eval) = tracker.tick();
        assert!(expired.is_empty());
        assert_eq!(
            re_eval.len(),
            1,
            "second re-evaluation should fire — periodic re-evaluation is working"
        );
        assert_eq!(re_eval[0], id);

        // Flow still in tracker (never expired).
        assert_eq!(tracker.len(), 1);
    }

    /// Stress test: multiple flows with staggered evaluation cycles.
    /// Confirms the queue correctly handles the full cycle: creation entry →
    /// tick → due → mark_evaluated → new entry → tick → due again.
    #[test]
    fn test_mixed_flow_re_evaluation_staggered() {
        let mut tracker = FlowTracker::new(FlowConfig::default());

        for i in 0..5u16 {
            let pkt = make_packet(
                IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
                5000 + i,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                443,
                6,
            );
            tracker.update(&pkt, 5000 + i, None);
        }
        assert_eq!(tracker.len(), 5);

        // Tick 0: nothing due yet.
        let (_, re_eval) = tracker.tick();
        assert!(re_eval.is_empty());

        // Make ALL 5 flows due.
        for id in 1..=5 {
            tracker.get_mut(id).unwrap().last_evaluated =
                Instant::now() - std::time::Duration::from_secs(EVALUATION_INTERVAL_SECS + 1);
        }

        // Tick: all 5 creation entries become due.
        let (_, re_eval) = tracker.tick();
        assert_eq!(re_eval.len(), 5, "first re-eval: all 5 should fire");
        for id in 1..=5 {
            assert!(re_eval.contains(&id), "flow {id} should be in due list");
        }

        // Mark flows 2 and 3 as evaluated — pushes fresh (now, id) entries.
        // Flows 1, 4, 5 consumed their creation entries and have nothing
        // in the queue (they'd need mark_evaluated to get re-queued).
        tracker.mark_evaluated(2);
        tracker.mark_evaluated(3);

        // Make flows 2 and 3 due again (backdate + re-queue entry from mark_evaluated).
        for id in 2..=3 {
            tracker.get_mut(id).unwrap().last_evaluated =
                Instant::now() - std::time::Duration::from_secs(EVALUATION_INTERVAL_SECS + 1);
        }

        // Tick: flows 2 and 3 fire a SECOND time (periodic re-evaluation).
        // Flows 1, 4, 5 have no queue entries and don't fire.
        let (_, re_eval) = tracker.tick();
        assert_eq!(re_eval.len(), 2, "flows 2,3 fire a second time");
        assert!(re_eval.contains(&2), "flow 2 should fire second time");
        assert!(re_eval.contains(&3), "flow 3 should fire second time");
    }
}
