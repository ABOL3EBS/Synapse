// crates/agent/src/detectors/flow_behavior.rs
//
// Flow behavior analysis detector (Detector 3).
// Analyzes packet rate, byte patterns, timing, and protocol anomalies
// within a single flow.

use std::time::Instant;

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

/// Flow behavior analysis detector.
///
/// Evaluates six sub-detectors on per-flow traffic patterns:
/// 1. Packet rate (packets per second)
/// 2. Bytes per packet (payload density)
/// 3. Low packet count with high byte count (bulk transfer)
/// 4. High packet count with low byte count (scanning/beaconing)
/// 5. Very short flow duration with high packet count (burst)
/// 6. Protocol/port mismatch heuristic
pub struct FlowBehavior;

impl FlowBehavior {
    fn score_packet_rate(rate: f64) -> f32 {
        if rate > 1000.0 {
            0.7
        } else if rate > 500.0 {
            0.4
        } else if rate > 100.0 {
            0.1
        } else {
            0.0
        }
    }

    /// Standard ports where large packets are normal (TLS/HTTP2/QUIC MSS).
    const HIGH_MTU_PORTS: &'static [u16] = &[80, 443, 8443];

    fn score_bytes_per_packet(bpp: f64, dst_port: u16) -> f32 {
        // Very small packets (under 20 bytes avg) — scanning or tunneling.
        if bpp < 20.0 && bpp > 0.0 {
            return 0.5;
        }
        // Large packets on standard web ports — normal MSS/Jumbo, not suspicious.
        if bpp > 1400.0 && Self::HIGH_MTU_PORTS.contains(&dst_port) {
            return 0.0;
        }
        // Large packets on non-standard ports — possibly bulk transfer.
        if bpp > 1400.0 {
            return 0.2;
        }
        0.0
    }

    fn score_bulk_transfer(packet_count: u64, byte_count: u64) -> f32 {
        // Few packets but lots of data — possible exfil.
        if packet_count < 50 && byte_count > 1_000_000 {
            0.6
        } else {
            0.0
        }
    }

    fn score_scan_behavior(packet_count: u64, byte_count: u64, duration_secs: f64) -> f32 {
        // Many packets, very little data, sustained over time — scanning.
        if duration_secs > 2.0 && packet_count > 200 && byte_count < 10_000 {
            0.5
        } else {
            0.0
        }
    }

    fn score_burst(packet_count: u64, duration_secs: f64) -> f32 {
        // High packet count in very short time — burst or DDoS.
        if duration_secs < 0.5 && packet_count > 100 {
            0.6
        } else {
            0.0
        }
    }

    fn score_port_protocol_mismatch(protocol: u8, dst_port: u16) -> f32 {
        // Heuristic: protocol 6 (TCP) to port 53, or protocol 17 (UDP) to port 443.
        match (protocol, dst_port) {
            (6, 53) => 0.3,   // TCP DNS — unusual but valid
            (17, 443) => 0.4, // UDP to HTTPS port — suspicious
            _ => 0.0,
        }
    }
}

impl Default for FlowBehavior {
    fn default() -> Self {
        Self
    }
}

impl Detector for FlowBehavior {
    fn id(&self) -> DetectorId {
        DetectorId::FlowBehavior
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding {
        let start = Instant::now();

        let duration_secs = flow.flow_age.as_secs_f64();
        let packet_rate = if duration_secs > 0.0 {
            flow.packet_count as f64 / duration_secs
        } else {
            0.0
        };
        let bpp = if flow.packet_count > 0 {
            flow.byte_count as f64 / flow.packet_count as f64
        } else {
            0.0
        };

        let mut evidence = Vec::new();
        let mut total_score = 0.0f32;
        let mut max_possible = 0.0f32;

        let e = Self::score_packet_rate(packet_rate);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!("High packet rate: {:.0} pkt/s", packet_rate),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_bytes_per_packet(bpp, flow.b_port);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!("Unusual bytes/packet: {:.0}", bpp),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_bulk_transfer(flow.packet_count, flow.byte_count);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!(
                    "Bulk transfer: {} packets, {} bytes",
                    flow.packet_count, flow.byte_count
                ),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_scan_behavior(flow.packet_count, flow.byte_count, duration_secs);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Sustained scanning pattern".to_string(),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_burst(flow.packet_count, duration_secs);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!(
                    "Burst: {} packets in {:.2}s",
                    flow.packet_count, duration_secs
                ),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_port_protocol_mismatch(flow.protocol, flow.b_port);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Protocol/port mismatch heuristic".to_string(),
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
            Severity::High
        } else if normalized > 0.3 {
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

    fn make_flow_with_behavior(
        packet_count: u64,
        byte_count: u64,
        flow_age_secs: u64,
        protocol: u8,
    ) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            a_ip: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            b_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            a_port: 443,
            b_port: 50000,
            protocol,
            local_port: 50000,
            pid: Some(42),
            packet_count,
            byte_count,
            dns_name: None,
            process_path: Some("/usr/bin/curl".to_string()),
            process_start_time: Some(1700000000.0),
            country_code: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(flow_age_secs),
        }
    }

    #[test]
    fn test_high_packet_rate() {
        let detector = FlowBehavior;
        let flow = make_flow_with_behavior(2000, 200_000, 1, 6); // 2000 pkt/s
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "High packet rate should score > 0");
    }

    #[test]
    fn test_bulk_transfer() {
        let detector = FlowBehavior;
        let flow = make_flow_with_behavior(10, 5_000_000, 10, 6); // 10 packets, 5MB
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "Bulk transfer should score > 0");
    }

    #[test]
    fn test_scan_pattern() {
        let detector = FlowBehavior;
        let flow = make_flow_with_behavior(500, 5000, 5, 6); // many small packets
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "Scan pattern should score > 0");
    }

    #[test]
    fn test_burst() {
        let detector = FlowBehavior;
        let flow = make_flow_with_behavior(200, 20_000, 0, 6); // 200 packets in <1s
        let finding = detector.evaluate(&flow);
        assert!(finding.score > 0.0, "Burst should score > 0");
    }

    #[test]
    fn test_normal_flow() {
        let detector = FlowBehavior;
        let flow = make_flow_with_behavior(50, 25_000, 5, 6); // normal browsing
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Normal flow should score 0");
    }

    #[test]
    fn test_zero_packets() {
        let detector = FlowBehavior;
        let flow = make_flow_with_behavior(0, 0, 5, 6);
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Zero packets should score 0");
    }

    #[test]
    fn test_standard_port_high_bpp() {
        let detector = FlowBehavior;
        // 1500 bytes/packet on port 443 — normal TLS, should score 0 for bpp.
        let flow = make_flow_with_behavior(100, 150_000, 5, 6);
        // b_port defaults to 50000 — override to 443.
        let mut flow = flow;
        flow.b_port = 443;
        let finding = detector.evaluate(&flow);
        // bpp=1500 on port 443 should not trigger bpp heuristic.
        assert!(
            !finding
                .evidence
                .iter()
                .any(|e| e.description.contains("bytes/packet")),
            "Standard port 443 should be exempt from bpp > 1400 heuristic"
        );
    }

    #[test]
    fn test_non_standard_port_high_bpp() {
        let detector = FlowBehavior;
        // 1500 bytes/packet on port 8080 — non-standard, should trigger bpp heuristic.
        let flow = make_flow_with_behavior(100, 150_000, 5, 6);
        let mut flow = flow;
        flow.b_port = 8080;
        let finding = detector.evaluate(&flow);
        assert!(
            finding
                .evidence
                .iter()
                .any(|e| e.description.contains("bytes/packet")),
            "Non-standard port with bpp > 1400 should trigger heuristic"
        );
    }
}
