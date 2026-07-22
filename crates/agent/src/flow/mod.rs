// crates/agent/src/flow/mod.rs
//
// In-memory flow tracker — session window with ~100ms ticks.
// §4 step 3: "Traffic aggregated into sessions over an in-memory window
// (~100ms ticks), attaching whatever enrichment context has landed by this
// point without blocking for it, and producing feature vectors."
//
// Design decisions (recorded explicitly, not left implicit):
// - FlowKey is direction-agnostic: (ip, port) swapped as bound pairs.
// - local_port stored separately on FlowRecord, set once at creation.
// - DNS/GeoIP/Reputation: per-flow dispatch (known v1 inefficiency,
//   documented). Only process attribution is genuinely flow-specific.
// - MAX_FLOWS = 100_000 defensive bound. Evict oldest on overflow.
// - tick() must fire on poll() timeout, not only on packet arrival.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use log::{debug, warn};

use crate::PacketInfo;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of flows tracked simultaneously.
/// Defensive bound against hostile traffic growing tables faster than
/// time-based expiry reclaims them. Evict oldest on overflow.
const MAX_FLOWS: usize = 100_000;

/// Default flow expiry duration. Flows with no packets for this long
/// are reclaimed on tick().
const FLOW_EXPIRY_SECS: u64 = 5;

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
    /// Reputation score 0.0–1.0 (stub in v1).
    pub reputation_score: Option<f32>,
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
    /// Next flow ID (monotonically increasing).
    next_id: u64,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            flows: HashMap::new(),
            next_id: 1,
        }
    }

    /// Process a packet: insert or update a flow.
    /// Returns NewFlow (caller should dispatch enrichment) or ExistingFlow.
    pub fn update(&mut self, info: &PacketInfo, local_port: u16, pid: Option<u32>) -> FlowUpdate {
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
        if self.flows.len() >= MAX_FLOWS {
            self.evict_oldest();
        }

        let flow_id = self.next_id;
        self.next_id += 1;

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
            reputation_score: None,
        };

        self.index.insert(key, flow_id);
        self.flows.insert(flow_id, flow);

        debug!(
            "flow {} created: {:?} local_port={}",
            flow_id, key, local_port
        );
        FlowUpdate::NewFlow(flow_id)
    }

    /// Expire flows older than FLOW_EXPIRY_SECS.
    /// Returns the list of expired flow IDs (for future detection handoff).
    /// Must be called on every capture-loop iteration (via poll() timeout),
    /// not only when a packet arrives — a quiet-but-stale network must not
    /// leave memory pinned.
    pub fn tick(&mut self) -> Vec<u64> {
        let now = Instant::now();
        let mut expired = Vec::new();

        self.flows.retain(|&flow_id, flow| {
            if now.duration_since(flow.last_seen).as_secs() >= FLOW_EXPIRY_SECS {
                expired.push(flow_id);
                false
            } else {
                true
            }
        });

        // Remove expired flows from the index.
        for &flow_id in &expired {
            if let Some(flow) = self.flows.get(&flow_id) {
                self.index.remove(&flow.key);
            }
        }

        if !expired.is_empty() {
            debug!(
                "tick: expired {} flows ({} remaining)",
                expired.len(),
                self.flows.len()
            );
        }

        expired
    }

    /// Evict the oldest flow (by first_seen) to make room.
    /// Called when flow count hits MAX_FLOWS.
    fn evict_oldest(&mut self) {
        if let Some((&oldest_id, _)) = self.flows.iter().min_by_key(|(_, flow)| flow.first_seen) {
            if let Some(flow) = self.flows.remove(&oldest_id) {
                self.index.remove(&flow.key);
                warn!(
                    "flow tracker at capacity ({}), evicting oldest flow {} (key={:?}, age={:?})",
                    MAX_FLOWS,
                    oldest_id,
                    flow.key,
                    flow.first_seen.elapsed(),
                );
            }
        }
    }

    /// Attach an enrichment result to a flow.
    pub fn attach_enrichment(
        &mut self,
        flow_id: u64,
        dns_name: Option<String>,
        process_path: Option<String>,
        process_start_time: Option<f64>,
        country_code: Option<String>,
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
            if reputation_score.is_some() {
                flow.reputation_score = reputation_score;
            }
        }
    }

    /// Get a reference to a flow by ID.
    #[allow(dead_code)]
    pub fn get(&self, flow_id: u64) -> Option<&FlowRecord> {
        self.flows.get(&flow_id)
    }

    /// Number of currently tracked flows.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether the tracker is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        let mut tracker = FlowTracker::new();
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
        let mut tracker = FlowTracker::new();
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
        let mut tracker = FlowTracker::new();

        // Fill to capacity. Use both IP and port to generate unique 5-tuples.
        for i in 0..MAX_FLOWS {
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
        assert_eq!(tracker.len(), MAX_FLOWS);

        // One more — should evict oldest.
        let overflow = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 255, 255, 2)),
            60000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        tracker.update(&overflow, 60000, None);

        // Should still be at MAX_FLOWS (evicted one, added one).
        assert_eq!(tracker.len(), MAX_FLOWS);
    }

    #[test]
    fn test_tick_expires_old_flows() {
        let mut tracker = FlowTracker::new();
        let pkt = make_packet(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            6,
        );
        tracker.update(&pkt, 5000, None);
        assert_eq!(tracker.len(), 1);

        // Immediately — nothing should expire.
        let expired = tracker.tick();
        assert!(expired.is_empty());

        // Manually backdate the flow's last_seen to simulate staleness.
        {
            let flow = tracker.get_mut(1).unwrap();
            flow.last_seen = Instant::now() - std::time::Duration::from_secs(FLOW_EXPIRY_SECS + 1);
        }

        // Now tick should expire it.
        let expired = tracker.tick();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], 1);
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_attach_enrichment() {
        let mut tracker = FlowTracker::new();
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
}
