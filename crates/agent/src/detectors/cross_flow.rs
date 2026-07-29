use std::collections::HashMap;
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
}

impl CrossFlowState {
    pub fn new(config: CrossFlowConfig) -> Self {
        Self {
            ip_stats: HashMap::new(),
            config,
        }
    }

    pub fn record_connection(&mut self, remote_ip: IpAddr, protocol: u8, dst_port: u16) {
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

        let mut evidence = Vec::new();
        let mut max_score = 0.0_f32;
        let mut max_conf = 0.0_f32;

        for &ip in &[flow.a_ip, flow.b_ip] {
            let (conn_count, dns_count) = match state.get_stats(&ip) {
                Some(stats) => stats,
                None => continue,
            };

            let window = state.config().window_secs;

            if conn_count > state.config().scan_connection_threshold_high {
                max_score = max_score.max(0.9);
                max_conf = max_conf.max(0.95);
                evidence.push(Evidence {
                    description: format!(
                        "High connection count to IP: {} connections in {}s",
                        conn_count, window
                    ),
                    detail: Some(ip.to_string()),
                });
            } else if conn_count > state.config().scan_connection_threshold_medium {
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

            if dns_count > state.config().dns_burst_threshold_high {
                max_score = max_score.max(0.8);
                max_conf = max_conf.max(0.7);
                evidence.push(Evidence {
                    description: format!(
                        "DNS query burst: {} queries to IP in {}s",
                        dns_count, window
                    ),
                    detail: Some(ip.to_string()),
                });
            } else if dns_count > state.config().dns_burst_threshold_medium {
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
        let state = Arc::new(Mutex::new(CrossFlowState::new(CrossFlowConfig::default())));
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
        let state = Arc::new(Mutex::new(CrossFlowState::new(CrossFlowConfig::default())));
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
        let state = Arc::new(Mutex::new(CrossFlowState::new(CrossFlowConfig::default())));
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
        let state = Arc::new(Mutex::new(CrossFlowState::new(CrossFlowConfig::default())));
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
    fn test_both_ips_checked() {
        let state = Arc::new(Mutex::new(CrossFlowState::new(CrossFlowConfig::default())));
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
