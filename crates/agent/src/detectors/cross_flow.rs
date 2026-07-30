use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

#[derive(Debug, Clone)]
pub struct CrossFlowConfig {
    pub window_secs: u64,
    pub scan_connection_threshold_high: u64,
    pub scan_connection_threshold_medium: u64,
    pub dns_burst_threshold_high: u64,
    pub dns_burst_threshold_medium: u64,
}

impl Default for CrossFlowConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            scan_connection_threshold_high: 200,
            scan_connection_threshold_medium: 100,
            dns_burst_threshold_high: 80,
            dns_burst_threshold_medium: 30,
        }
    }
}

#[derive(Debug, Clone)]
struct IpFlowStats {
    connection_count: u64,
    dns_query_count: u64,
    last_seen: Instant,
}

pub struct CrossFlowState {
    ip_stats: HashMap<IpAddr, IpFlowStats>,
    config: CrossFlowConfig,
    // IPs excluded from per-destination counting. Caller populates this with
    // the default gateway and the own_ips snapshot (which already includes
    // subnet-directed broadcasts computed from interface netmasks). This is
    // intentionally narrow: RFC1918 as a whole is NOT excluded, so lateral
    // movement against other LAN hosts remains visible.
    //
    // Protocol-level infrastructure addresses (255.255.255.255, 224.0.0.0/4,
    // ff00::/8) are caught by is_infrastructure_destination() rather than this
    // set, since they're address-pattern checks that need no configuration.
    excluded_ips: HashSet<IpAddr>,
}

impl CrossFlowState {
    pub fn new(config: CrossFlowConfig, excluded_ips: HashSet<IpAddr>) -> Self {
        Self {
            ip_stats: HashMap::new(),
            config,
            excluded_ips,
        }
    }

    fn is_excluded(&self, ip: IpAddr) -> bool {
        self.excluded_ips.contains(&ip) || crate::capture::is_infrastructure_destination(ip)
    }

    pub fn record_connection(&mut self, remote_ip: IpAddr, protocol: u8, dst_port: u16) {
        if self.is_excluded(remote_ip) {
            log::debug!(
                "CrossFlow: dst={}:{} proto={} EXCLUDED (gateway/own-ip/broadcast/multicast)",
                remote_ip,
                dst_port,
                protocol
            );
            return;
        }
        let now = Instant::now();
        let stats = self.ip_stats.entry(remote_ip).or_insert(IpFlowStats {
            connection_count: 0,
            dns_query_count: 0,
            last_seen: now,
        });
        stats.connection_count = stats.connection_count.saturating_add(1);
        stats.last_seen = now;
        if protocol == 17 && dst_port == 53 {
            stats.dns_query_count = stats.dns_query_count.saturating_add(1);
        }
    }

    pub fn purge_expired(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(self.config.window_secs);
        self.ip_stats.retain(|_, stats| stats.last_seen >= cutoff);
    }

    pub fn get_stats(&self, ip: &IpAddr) -> Option<(u64, u64)> {
        self.ip_stats
            .get(ip)
            .map(|s| (s.connection_count, s.dns_query_count))
    }

    pub fn config(&self) -> &CrossFlowConfig {
        &self.config
    }
}

pub struct CrossFlowDetector {
    cross_flow_state: Arc<Mutex<CrossFlowState>>,
}

impl CrossFlowDetector {
    pub fn new(state: Arc<Mutex<CrossFlowState>>) -> Self {
        Self {
            cross_flow_state: state,
        }
    }
}

impl Detector for CrossFlowDetector {
    fn id(&self) -> DetectorId {
        DetectorId::CrossFlow
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding {
        let start = Instant::now();

        // Hold the lock only long enough to copy out the stats we need.
        // Scoring runs outside the lock so record_connection() on the hot
        // path is never blocked by a slow or timed-out detector evaluation.
        let (stats_a, stats_b, cfg) = {
            let state = match self.cross_flow_state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return DetectorFinding::errored(
                        DetectorId::CrossFlow,
                        "1.0.0",
                        "cross-flow state lock poisoned",
                        0,
                    );
                }
            };
            let a = if state.is_excluded(flow.a_ip) {
                log::debug!("CrossFlow eval: a_ip={} EXCLUDED", flow.a_ip);
                None
            } else {
                state.get_stats(&flow.a_ip)
            };
            let b = if state.is_excluded(flow.b_ip) {
                log::debug!("CrossFlow eval: b_ip={} EXCLUDED", flow.b_ip);
                None
            } else {
                state.get_stats(&flow.b_ip)
            };
            (a, b, state.config().clone())
            // MutexGuard drops here.
        };

        let mut evidence = Vec::new();
        let mut max_score = 0.0_f32;
        let mut max_conf = 0.0_f32;

        for (ip, stats_opt) in [(flow.a_ip, stats_a), (flow.b_ip, stats_b)] {
            let (conn_count, dns_count) = match stats_opt {
                Some(stats) => {
                    log::debug!(
                        "CrossFlow eval: ip={} conn_count={} dns_count={}",
                        ip,
                        stats.0,
                        stats.1
                    );
                    stats
                }
                None => continue,
            };

            let window = cfg.window_secs;

            if conn_count > cfg.scan_connection_threshold_high {
                max_score = max_score.max(0.9);
                max_conf = max_conf.max(0.95);
                evidence.push(Evidence {
                    description: format!(
                        "High connection count to IP: {} connections in {}s",
                        conn_count, window
                    ),
                    detail: Some(ip.to_string()),
                });
            } else if conn_count > cfg.scan_connection_threshold_medium {
                max_score = max_score.max(0.7);
                max_conf = max_conf.max(0.8);
                evidence.push(Evidence {
                    description: format!(
                        "Elevated connection count to IP: {} connections in {}s",
                        conn_count, window
                    ),
                    detail: Some(ip.to_string()),
                });
            }

            if dns_count > cfg.dns_burst_threshold_high {
                max_score = max_score.max(0.8);
                max_conf = max_conf.max(0.7);
                evidence.push(Evidence {
                    description: format!(
                        "DNS query burst: {} queries to IP in {}s",
                        dns_count, window
                    ),
                    detail: Some(ip.to_string()),
                });
            } else if dns_count > cfg.dns_burst_threshold_medium {
                max_score = max_score.max(0.5);
                max_conf = max_conf.max(0.5);
                evidence.push(Evidence {
                    description: format!(
                        "Elevated DNS queries: {} queries to IP in {}s",
                        dns_count, window
                    ),
                    detail: Some(ip.to_string()),
                });
            }
        }

        log::debug!(
            "CrossFlow: flow={} a_ip={} b_ip={} score={:.2} conf={:.2}",
            flow.flow_id,
            flow.a_ip,
            flow.b_ip,
            max_score,
            max_conf
        );

        let severity = if max_score > 0.7 {
            Severity::Critical
        } else if max_score > 0.4 {
            Severity::High
        } else {
            Severity::Low
        };

        DetectorFinding {
            detector_id: self.id(),
            detector_version: self.version().to_string(),
            score: max_score,
            confidence: max_conf,
            severity,
            evidence,
            latency_us: start.elapsed().as_micros() as u64,
            status: DetectorStatus::Completed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_flow(a_ip: IpAddr, b_ip: IpAddr) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            a_ip,
            b_ip,
            a_port: 50000,
            b_port: 443,
            protocol: 6,
            local_port: 50000,
            pid: Some(42),
            packet_count: 10,
            byte_count: 5000,
            dns_name: None,
            process_path: Some("/usr/bin/curl".to_string()),
            process_start_time: Some(1700000000.0),
            country_code: None,
            asn: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(5),
        }
    }

    #[test]
    fn test_detector_score_zero_when_no_state() {
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            HashSet::new(),
        )));
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        );
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "No cross-flow state → score 0");
        assert_eq!(finding.confidence, 0.0);
    }

    #[test]
    fn test_scan_detection_high_connection_count() {
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            HashSet::new(),
        )));
        let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202));
        // Simulate 201 connections to the remote IP.
        for _ in 0..201 {
            state.lock().unwrap().record_connection(remote, 6, 443);
        }
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(remote, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        let finding = detector.evaluate(&flow);
        assert!(finding.score >= 0.9, "High conn count should score ≥0.9");
        assert!(
            finding.confidence >= 0.9,
            "High conn count should have high confidence"
        );
        assert!(!finding.evidence.is_empty());
    }

    #[test]
    fn test_scan_medium_connection_count() {
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            HashSet::new(),
        )));
        let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202));
        for _ in 0..150 {
            state.lock().unwrap().record_connection(remote, 6, 443);
        }
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(remote, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        let finding = detector.evaluate(&flow);
        assert!(finding.score >= 0.7 && finding.score < 0.9);
        assert!(finding.confidence >= 0.8);
    }

    #[test]
    fn test_dns_burst_detection() {
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            HashSet::new(),
        )));
        let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        // Simulate 85 DNS queries — high threshold.
        for _ in 0..85 {
            state.lock().unwrap().record_connection(remote, 17, 53);
        }
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(remote, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score >= 0.8,
            "DNS burst should score ≥0.8, got {}",
            finding.score
        );
    }

    #[test]
    fn test_gateway_ip_excluded_from_counting() {
        let gateway: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            [gateway].into_iter().collect(),
        )));
        // Record many connections through the gateway — should not count.
        for _ in 0..250 {
            state.lock().unwrap().record_connection(gateway, 6, 443);
        }
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(gateway, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
        let finding = detector.evaluate(&flow);
        assert_eq!(
            finding.score, 0.0,
            "Gateway IP must not contribute to score"
        );
        assert!(finding.evidence.is_empty());
    }

    #[test]
    fn test_lan_host_still_counted_when_gateway_excluded() {
        let gateway: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let lan_host: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            [gateway].into_iter().collect(),
        )));
        for _ in 0..250 {
            state.lock().unwrap().record_connection(lan_host, 6, 445);
        }
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(lan_host, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score >= 0.9,
            "Lateral movement to LAN host must still score high, got {}",
            finding.score
        );
    }

    #[test]
    fn test_multicast_destination_not_counted() {
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            HashSet::new(),
        )));
        let mdns_multicast: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        for _ in 0..250 {
            state
                .lock()
                .unwrap()
                .record_connection(mdns_multicast, 17, 5353);
        }
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 43)), mdns_multicast);
        let finding = detector.evaluate(&flow);
        assert_eq!(
            finding.score, 0.0,
            "Multicast destination must not contribute to score"
        );
    }

    #[test]
    fn test_subnet_broadcast_not_counted() {
        let subnet_bcast: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 18, 22, 255));
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            [subnet_bcast].into_iter().collect(), // own_ips snapshot includes this
        )));
        for _ in 0..250 {
            state
                .lock()
                .unwrap()
                .record_connection(subnet_bcast, 17, 137);
        }
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(IpAddr::V4(Ipv4Addr::new(172, 18, 22, 43)), subnet_bcast);
        let finding = detector.evaluate(&flow);
        assert_eq!(
            finding.score, 0.0,
            "Subnet broadcast destination must not contribute to score"
        );
    }

    #[test]
    fn test_both_ips_checked() {
        let state = Arc::new(Mutex::new(CrossFlowState::new(
            CrossFlowConfig::default(),
            HashSet::new(),
        )));
        let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202));
        for _ in 0..250 {
            state.lock().unwrap().record_connection(remote, 6, 443);
        }
        // flow with local as a_ip, remote as b_ip (canonically larger).
        let detector = CrossFlowDetector::new(state);
        let flow = make_flow(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), remote);
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score >= 0.9,
            "Should detect remote IP regardless of canonical ordering"
        );
    }
}
