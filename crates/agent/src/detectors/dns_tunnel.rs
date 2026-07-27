// crates/agent/src/detectors/dns_tunnel.rs
//
// DNS tunnel detection detector (Detector 5).
// Detects DNS tunneling by analyzing subdomain entropy, label length,
// query frequency, and payload size anomalies.
//
// Scope: DNS-over-UDP (port 53) is the primary v1 target. DNS-over-HTTPS
// (port 443) is not analyzed — encrypted DNS is opaque at the flow level
// and would require TLS termination to inspect. Port 443 flows return
// immediately with score 0.0.

use std::time::Instant;

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

/// DNS tunnel detection detector.
///
/// Only triggers on DNS flows (protocol 17/UDP, dst_port 53).
/// Evaluates four sub-detectors:
/// 1. Subdomain entropy (tunnel data is high-entropy)
/// 2. Longest label length (tunnel data uses long labels)
/// 3. Query count anomaly (many queries in short flow = tunnel)
/// 4. Payload size anomaly (large DNS responses = data exfil)
pub struct DnsTunnelDetector;

impl DnsTunnelDetector {
    /// Check if this is a DNS flow (UDP port 53).
    fn is_dns_flow(protocol: u8, dst_port: u16) -> bool {
        protocol == 17 && dst_port == 53
    }

    fn shannon_entropy(s: &str) -> f32 {
        if s.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in s.as_bytes() {
            counts[b as usize] += 1;
        }
        let len = s.len() as f32;
        let mut entropy = 0.0f32;
        for &c in &counts {
            if c > 0 {
                let p = c as f32 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Extract the subdomain portion (everything before the registered domain).
    /// Heuristic: take everything before the second-level domain.
    fn extract_subdomain(hostname: &str) -> &str {
        let parts: Vec<&str> = hostname.split('.').collect();
        if parts.len() <= 2 {
            return "";
        }
        // Everything except the last two labels is subdomain.
        let end = parts.len() - 2;
        &hostname[..parts[..end].iter().map(|s| s.len()).sum::<usize>() + end] // +dots
    }

    fn score_subdomain_entropy(subdomain: &str) -> f32 {
        if subdomain.is_empty() {
            return 0.0;
        }
        let entropy = Self::shannon_entropy(subdomain);
        if entropy > 4.0 {
            0.8
        } else if entropy > 3.5 {
            0.4
        } else {
            0.0
        }
    }

    fn score_longest_label(hostname: &str) -> f32 {
        let max_label = hostname.split('.').map(|s| s.len()).max().unwrap_or(0);
        if max_label > 50 {
            0.7
        } else if max_label > 30 {
            0.4
        } else {
            0.0
        }
    }

    fn score_query_frequency(packet_count: u64, flow_age_secs: f64) -> f32 {
        if flow_age_secs <= 0.0 {
            return 0.0;
        }
        let rate = packet_count as f64 / flow_age_secs;
        // Normal DNS: ~1-5 queries/sec. Tunnel: 10+ queries/sec sustained.
        if rate > 10.0 {
            0.6
        } else if rate > 5.0 {
            0.3
        } else {
            0.0
        }
    }

    fn score_payload_size(byte_count: u64, packet_count: u64) -> f32 {
        if packet_count == 0 {
            return 0.0;
        }
        let avg_size = byte_count as f64 / packet_count as f64;
        // Normal DNS: ~100-300 bytes/query. Tunnel: >500 bytes/query.
        if avg_size > 500.0 {
            0.5
        } else if avg_size > 300.0 {
            0.2
        } else {
            0.0
        }
    }
}

impl Default for DnsTunnelDetector {
    fn default() -> Self {
        Self
    }
}

impl Detector for DnsTunnelDetector {
    fn id(&self) -> DetectorId {
        DetectorId::DnsTunnelDetector
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding {
        let start = Instant::now();

        // DNS-over-HTTPS (port 443) is encrypted — tunnel detection is inapplicable.
        if flow.protocol == 17 && flow.b_port == 443 {
            return DetectorFinding {
                detector_id: self.id(),
                detector_version: self.version().to_string(),
                score: 0.0,
                confidence: 1.0,
                severity: Severity::Low,
                evidence: vec![Evidence {
                    description: "DNS-over-HTTPS — encrypted, not analyzed".to_string(),
                    detail: None,
                }],
                latency_us: start.elapsed().as_micros() as u64,
                status: DetectorStatus::Completed,
            };
        }

        // Short-circuit: not a DNS flow (UDP/53).
        if !Self::is_dns_flow(flow.protocol, flow.b_port) {
            return DetectorFinding {
                detector_id: self.id(),
                detector_version: self.version().to_string(),
                score: 0.0,
                confidence: 1.0,
                severity: Severity::Low,
                evidence: vec![Evidence {
                    description: "Not a DNS flow".to_string(),
                    detail: None,
                }],
                latency_us: start.elapsed().as_micros() as u64,
                status: DetectorStatus::Completed,
            };
        }

        let dns_name = flow.dns_name.as_deref().unwrap_or("");
        let subdomain = Self::extract_subdomain(dns_name);
        let duration_secs = flow.flow_age.as_secs_f64();

        let mut evidence = Vec::new();
        let mut total_score = 0.0f32;
        let mut max_possible = 0.0f32;

        let e = Self::score_subdomain_entropy(subdomain);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!(
                    "High-entropy subdomain: {:.2} bits/char",
                    Self::shannon_entropy(subdomain)
                ),
                detail: Some(subdomain.to_string()),
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_longest_label(dns_name);
        if e > 0.0 {
            let max_label = dns_name.split('.').map(|s| s.len()).max().unwrap_or(0);
            evidence.push(Evidence {
                description: format!("Long DNS label: {} chars", max_label),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_query_frequency(flow.packet_count, duration_secs);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!(
                    "High query rate: {:.1} pkt/s",
                    flow.packet_count as f64 / duration_secs
                ),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_payload_size(flow.byte_count, flow.packet_count);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Large DNS payload".to_string(),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let normalized = if max_possible > 0.0 {
            (total_score / max_possible).min(1.0)
        } else {
            0.0
        };

        let severity = if normalized > 0.6 {
            Severity::Critical
        } else if normalized > 0.4 {
            Severity::High
        } else if normalized > 0.2 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let confidence = if evidence.len() >= 3 {
            0.8
        } else if evidence.len() >= 2 {
            0.6
        } else if !evidence.is_empty() {
            0.4
        } else {
            1.0
        };

        DetectorFinding {
            detector_id: self.id(),
            detector_version: self.version().to_string(),
            score: normalized,
            confidence,
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
    use std::net::IpAddr;

    fn make_dns_flow(
        dns_name: Option<String>,
        packet_count: u64,
        byte_count: u64,
        flow_age_secs: u64,
    ) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            a_ip: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            b_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            a_port: 53,
            b_port: 53,
            protocol: 17, // UDP
            local_port: 50000,
            pid: Some(42),
            packet_count,
            byte_count,
            dns_name,
            process_path: Some("/usr/sbin/unbound".to_string()),
            process_start_time: Some(1700000000.0),
            country_code: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(flow_age_secs),
        }
    }

    #[test]
    fn test_not_dns_flow() {
        let detector = DnsTunnelDetector;
        let flow = make_dns_flow(Some("example.com".to_string()), 10, 1000, 5);
        // Override protocol to TCP — not DNS.
        let mut flow = flow;
        flow.protocol = 6;
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Non-DNS flow should score 0");
    }

    #[test]
    fn test_normal_dns_query() {
        let detector = DnsTunnelDetector;
        let flow = make_dns_flow(Some("www.example.com".to_string()), 3, 300, 2);
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Normal DNS query should score 0");
    }

    #[test]
    fn test_tunnel_high_entropy() {
        let detector = DnsTunnelDetector;
        // High-entropy subdomain — looks like base64-encoded data.
        let flow = make_dns_flow(
            Some("a7Bx9mK2qZ4wN8pL3vR6yH1jF5dT0gS.example.com".to_string()),
            20,
            10000,
            5,
        );
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "High-entropy subdomain should score > 0, got {}",
            finding.score
        );
    }

    #[test]
    fn test_tunnel_long_label() {
        let detector = DnsTunnelDetector;
        let long_label = "a".repeat(60);
        let flow = make_dns_flow(Some(format!("{}.example.com", long_label)), 5, 2000, 3);
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "Long label should score > 0");
    }

    #[test]
    fn test_tunnel_high_frequency() {
        let detector = DnsTunnelDetector;
        let flow = make_dns_flow(
            Some("data.example.com".to_string()),
            100,
            15000,
            3, // ~33 pkt/s
        );
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "High query rate should score > 0");
    }

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(
            DnsTunnelDetector::extract_subdomain("a.b.c.example.com"),
            "a.b.c."
        );
        assert_eq!(DnsTunnelDetector::extract_subdomain("example.com"), "");
    }

    #[test]
    fn test_doh_port_443_early_return() {
        let detector = DnsTunnelDetector;
        let flow = make_dns_flow(Some("data.example.com".to_string()), 100, 15000, 3);
        let mut flow = flow;
        flow.b_port = 443; // DNS-over-HTTPS
        let finding = detector.evaluate(&flow);
        assert_eq!(
            finding.score, 0.0,
            "DNS-over-HTTPS (port 443) should return early with 0.0"
        );
        assert_eq!(
            finding.confidence, 1.0,
            "DoH early return should have confidence 1.0"
        );
        assert!(finding
            .evidence
            .iter()
            .any(|e| e.description.contains("DNS-over-HTTPS")));
    }
}
