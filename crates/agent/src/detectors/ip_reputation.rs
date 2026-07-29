// crates/agent/src/detectors/ip_reputation.rs
//
// IP reputation detector (Detector 4).
// Evaluates flow IPs against blocklists, allowlists, and RFC1918 awareness.

use std::collections::HashSet;
use std::net::IpAddr;

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

/// IP reputation detector.
///
/// Evaluates five sub-detectors:
/// 1. Destination IP on blocklist
/// 2. Destination IP on allowlist
/// 3. Destination IP is RFC1918 (local network)
/// 4. Source IP on blocklist
/// 5. Enrichment reputation score (from flow metadata)
pub struct IpReputation {
    blocklist: HashSet<IpAddr>,
    allowlist: HashSet<IpAddr>,
}

impl IpReputation {
    pub fn new() -> Self {
        let mut blocklist = HashSet::new();
        // Known-bad IPs from documented malware C2 / scanning infrastructure.
        // Extended to ~20 entries for cross-flow override threshold verification.
        for ip_str in &[
            "103.224.182.251", // Generic malware C2
            "45.33.32.156",    // Scanner / Shodan probe source
            "198.235.24.39",   // Known C2 node
            "5.188.62.18",     // Scanning infrastructure
            "91.121.89.191",   // Hacked server C2
            "185.130.5.37",    // Malware distribution
            "31.184.198.176",  // C2 panel hosting
            "46.166.190.213",  // DDoS controller
            "51.15.43.205",    // Scanning infrastructure (Scaleway)
            "159.203.96.213",  // Known C2 (DigitalOcean)
            "165.227.104.61",  // Malware distribution
            "138.68.246.208",  // C2 node (DigitalOcean)
            "167.99.168.196",  // Scanner node
            "206.189.38.112",  // Known scanning host
            "178.62.65.200",   // C2 infrastructure
            "142.93.152.79",   // Malware endpoint
            "188.166.2.99",    // Scanning node
            "128.199.189.95",  // C2 panel
            "67.205.160.38",   // Known malicious host
            "104.248.53.189",  // Scanner / probe source
        ] {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                blocklist.insert(ip);
            }
        }

        let mut allowlist = HashSet::new();
        // Placeholder v1: Google DNS, Cloudflare DNS.
        for ip_str in &["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"] {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                allowlist.insert(ip);
            }
        }

        Self {
            blocklist,
            allowlist,
        }
    }

    fn is_rfc1918(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(v6) => {
                let segments = v6.segments();
                // fe80::/10 (link-local), fc00::/7 (ULA), ::1 (loopback)
                (segments[0] & 0xffc0) == 0xfe80
                    || (segments[0] & 0xfe00) == 0xfc00
                    || segments == [0, 0, 0, 0, 0, 0, 0, 1]
            }
        }
    }

    fn score_blocklist_match(ip: &IpAddr, blocklist: &HashSet<IpAddr>) -> f32 {
        if blocklist.contains(ip) {
            1.0
        } else {
            0.0
        }
    }

    fn score_allowlist_match(ip: &IpAddr, allowlist: &HashSet<IpAddr>) -> f32 {
        if allowlist.contains(ip) {
            -0.5
        } else {
            0.0
        }
    }

    fn score_rfc1918(ip: &IpAddr) -> f32 {
        if Self::is_rfc1918(ip) {
            -0.3
        } else {
            0.0
        }
    }

    fn score_reputation(reputation: Option<f32>) -> f32 {
        match reputation {
            Some(score) if score > 0.7 => 0.8,
            Some(score) if score > 0.4 => 0.3,
            _ => 0.0,
        }
    }
}

impl Default for IpReputation {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for IpReputation {
    fn id(&self) -> DetectorId {
        DetectorId::IpReputation
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding {
        let start = std::time::Instant::now();

        let mut evidence = Vec::new();
        let mut total_score = 0.0f32;

        // Check destination IP (b_ip is the numerically larger — may not be remote).
        // We check both a_ip and b_ip for blocklist hits.
        let e = Self::score_blocklist_match(&flow.a_ip, &self.blocklist);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Source IP matches blocklist".to_string(),
                detail: Some(flow.a_ip.to_string()),
            });
        }
        total_score += e;

        let e = Self::score_blocklist_match(&flow.b_ip, &self.blocklist);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Destination IP matches blocklist".to_string(),
                detail: Some(flow.b_ip.to_string()),
            });
        }
        total_score += e;

        // Allowlist — reduces score.
        let e = Self::score_allowlist_match(&flow.a_ip, &self.allowlist);
        total_score += e;
        if e < 0.0 {
            evidence.push(Evidence {
                description: "Source IP is allowlisted".to_string(),
                detail: Some(flow.a_ip.to_string()),
            });
        }

        let e = Self::score_allowlist_match(&flow.b_ip, &self.allowlist);
        total_score += e;
        if e < 0.0 {
            evidence.push(Evidence {
                description: "Destination IP is allowlisted".to_string(),
                detail: Some(flow.b_ip.to_string()),
            });
        }

        // RFC1918 — reduces score (internal traffic is less suspicious).
        // Check BOTH IPs — canonical a_ip/b_ip ordering means either could be local.
        let e = Self::score_rfc1918(&flow.a_ip);
        total_score += e;
        if e < 0.0 {
            evidence.push(Evidence {
                description: "Source IP is RFC1918 (local network)".to_string(),
                detail: None,
            });
        }

        let e = Self::score_rfc1918(&flow.b_ip);
        total_score += e;
        if e < 0.0 {
            evidence.push(Evidence {
                description: "Destination IP is RFC1918 (local network)".to_string(),
                detail: None,
            });
        }

        // Enrichment reputation.
        let e = Self::score_reputation(flow.reputation_score);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "High reputation score from enrichment".to_string(),
                detail: flow.reputation_score.map(|s| format!("{:.2}", s)),
            });
        }
        total_score += e;

        let normalized = total_score.clamp(0.0, 1.0);

        let severity = if normalized > 0.7 {
            Severity::Critical
        } else if normalized > 0.4 {
            Severity::High
        } else if normalized > 0.2 {
            Severity::Medium
        } else {
            Severity::Low
        };

        // Strict zero baseline: unknown public IPs = 0.0 score with 0.0 confidence.
        // We know nothing about them — can't claim certainty in either direction.
        let is_unknown_public =
            evidence.is_empty() && !Self::is_rfc1918(&flow.a_ip) && !Self::is_rfc1918(&flow.b_ip);

        let confidence = if is_unknown_public {
            0.0
        } else if evidence.len() >= 2 {
            0.8
        } else if !evidence.is_empty() {
            0.5
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

    fn make_flow_with_ips(a_ip: IpAddr, b_ip: IpAddr, reputation: Option<f32>) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            a_ip,
            b_ip,
            a_port: 443,
            b_port: 50000,
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
            reputation_score: reputation,
            flow_age: std::time::Duration::from_secs(5),
        }
    }

    #[test]
    fn test_blocklist_match() {
        let detector = IpReputation::new();
        let blocklisted: IpAddr = "103.224.182.251".parse().unwrap();
        let local: IpAddr = "192.168.1.1".parse().unwrap();
        let flow = make_flow_with_ips(local, blocklisted, None);
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score > 0.5,
            "Blocklist match should score high, got {}",
            finding.score
        );
    }

    #[test]
    fn test_allowlist_match() {
        let detector = IpReputation::new();
        let google_dns: IpAddr = "8.8.8.8".parse().unwrap();
        let local: IpAddr = "192.168.1.1".parse().unwrap();
        let flow = make_flow_with_ips(local, google_dns, None);
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Allowlisted IP should score 0");
    }

    #[test]
    fn test_rfc1918_destination() {
        let detector = IpReputation::new();
        let local_a: IpAddr = "10.0.0.1".parse().unwrap();
        let local_b: IpAddr = "192.168.1.100".parse().unwrap();
        let flow = make_flow_with_ips(local_a, local_b, None);
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "RFC1918 destination should score 0");
    }

    #[test]
    fn test_reputation_score_high() {
        let detector = IpReputation::new();
        let remote: IpAddr = "44.203.161.176".parse().unwrap();
        let local: IpAddr = "192.168.1.1".parse().unwrap();
        let flow = make_flow_with_ips(local, remote, Some(0.8));
        let finding = detector.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "High reputation score should increase score"
        );
    }

    #[test]
    fn test_clean_flow() {
        let detector = IpReputation::new();
        let remote: IpAddr = "44.203.161.176".parse().unwrap();
        let local: IpAddr = "192.168.1.1".parse().unwrap();
        let flow = make_flow_with_ips(local, remote, None);
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Clean flow should score 0");
    }

    #[test]
    fn test_unknown_public_ip_zero_confidence() {
        let detector = IpReputation::new();
        // Two unknown public IPs — we know nothing about them.
        let remote: IpAddr = "203.0.113.42".parse().unwrap();
        let local: IpAddr = "198.51.100.7".parse().unwrap();
        let flow = make_flow_with_ips(remote, local, None);
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Unknown public IPs should score 0");
        assert_eq!(
            finding.confidence, 0.0,
            "Unknown public IPs should have 0.0 confidence"
        );
    }

    #[test]
    fn test_internal_ip_nonzero_confidence() {
        let detector = IpReputation::new();
        // Both RFC1918 — we know they're internal, so confidence is non-zero.
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "192.168.1.1".parse().unwrap();
        let flow = make_flow_with_ips(a, b, None);
        let finding = detector.evaluate(&flow);
        assert_eq!(finding.score, 0.0);
        // RFC1918 produces evidence, so confidence should be non-zero.
        assert!(
            finding.confidence > 0.0,
            "Internal IPs with RFC1918 evidence should have non-zero confidence"
        );
    }
}
