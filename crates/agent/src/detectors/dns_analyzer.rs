// crates/agent/src/detectors/dns_analyzer.rs
//
// DNS hostname behavioral analysis detector (Detector 1).
// Analyzes flow DNS names for threat indicators: entropy, length, structure,
// blocklists, IP literals, suspicious TLDs, subdomain depth.

use std::collections::HashSet;
use std::time::Instant;

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

/// Returns true if `hostname` contains `label` as a standalone component when
/// split on `.` and `-`. Use this for single-label blocklist/denylist entries
/// (e.g., `"c2"`, `"malware"`) to prevent substring matches inside larger labels
/// — `"ec2-server.example.com"` must NOT match an entry for `"c2"`.
///
/// `pub(crate)` so other detectors can reuse the same implementation rather
/// than writing an independent version that may drift.
pub(crate) fn has_label(hostname: &str, label: &str) -> bool {
    hostname
        .split(['.', '-'])
        .any(|part| part.eq_ignore_ascii_case(label))
}

/// DNS hostname behavioral analysis detector.
///
/// Evaluates seven sub-detectors on each flow's `dns_name`:
/// 1. Shannon entropy of the hostname
/// 2. Total hostname length
/// 3. Individual label length
/// 4. Label count (subdomain depth)
/// 5. Embedded IP literals
/// 6. Blocklist match (hardcoded v1)
/// 7. Suspicious TLDs (hardcoded v1)
pub struct DnsAnalyzer {
    blocklist: HashSet<String>,
    suspicious_tlds: HashSet<&'static str>,
    allowlist: HashSet<String>,
}

impl DnsAnalyzer {
    pub fn new() -> Self {
        let mut blocklist = HashSet::new();
        blocklist.insert("malware.example.com".to_string());
        blocklist.insert("c2server.evil.net".to_string());
        blocklist.insert("phishing.scam.org".to_string());

        let mut suspicious_tlds = HashSet::new();
        for tld in &[
            "xyz", "top", "club", "work", "click", "info", "buzz", "gq", "ml", "cf", "ga",
        ] {
            suspicious_tlds.insert(*tld);
        }

        let mut allowlist = HashSet::new();
        for domain in &[
            "github.com",
            "google.com",
            "cloudflare.com",
            "amazonaws.com",
            "apple.com",
            "microsoft.com",
        ] {
            allowlist.insert(domain.to_string());
        }

        Self {
            blocklist,
            suspicious_tlds,
            allowlist,
        }
    }

    /// Shannon entropy of a string (bits per character).
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

    /// Count the number of labels (parts separated by '.').
    fn count_labels(hostname: &str) -> usize {
        hostname.split('.').filter(|s| !s.is_empty()).count()
    }

    /// Check if hostname contains an IP literal (e.g., "192.168.1.1.example.com").
    fn has_ip_literal(hostname: &str) -> bool {
        let parts: Vec<&str> = hostname.split('.').collect();
        // Check for 4 consecutive numeric labels that form a valid IPv4 address.
        if parts.len() >= 4 {
            for window in parts.windows(4) {
                let candidate = window.join(".");
                if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
                    return true;
                }
            }
        }
        false
    }

    /// Length of the longest label in the hostname.
    fn longest_label(hostname: &str) -> usize {
        hostname.split('.').map(|s| s.len()).max().unwrap_or(0)
    }

    /// Check if hostname is on the allowlist.
    fn is_allowlisted(hostname: &str, allowlist: &HashSet<String>) -> bool {
        let lower = hostname.to_ascii_lowercase();
        allowlist
            .iter()
            .any(|a| lower == a.as_str() || lower.ends_with(&format!(".{}", a)))
    }

    /// Score entropy of the hostname.
    fn score_entropy(entropy: f32) -> f32 {
        if entropy > 4.5 {
            0.8
        } else if entropy > 3.5 {
            0.4
        } else {
            0.0
        }
    }

    /// Score the total length of the hostname.
    fn score_length(len: usize) -> f32 {
        if len > 80 {
            0.6
        } else if len > 50 {
            0.3
        } else {
            0.0
        }
    }

    /// Score the longest label.
    fn score_longest_label(max_label: usize) -> f32 {
        if max_label > 40 {
            0.5
        } else if max_label > 25 {
            0.2
        } else {
            0.0
        }
    }

    /// Score the label count.
    fn score_label_count(labels: usize) -> f32 {
        if labels > 6 {
            0.4
        } else if labels > 4 {
            0.2
        } else {
            0.0
        }
    }

    /// Score IP literal presence.
    fn score_ip_literal(has_literal: bool) -> f32 {
        if has_literal {
            0.7
        } else {
            0.0
        }
    }

    /// Score blocklist match — label-aware, not substring.
    ///
    /// For full-domain entries (containing `.`): matches if the hostname is
    /// exactly the entry or is a subdomain of it. `"notmalware.example.com"`
    /// does NOT match an entry for `"malware.example.com"`;
    /// `"foo.malware.example.com"` does.
    ///
    /// For single-label entries (no `.`): delegates to `has_label()` —
    /// `"ec2-server.example.com"` does NOT match an entry for `"c2"`.
    fn score_blocklist(hostname: &str, blocklist: &HashSet<String>) -> f32 {
        let lower = hostname.to_ascii_lowercase();
        let matched = blocklist.iter().any(|b| {
            if b.contains('.') {
                lower == b.as_str() || lower.ends_with(&format!(".{b}"))
            } else {
                has_label(&lower, b.as_str())
            }
        });
        if matched {
            1.0
        } else {
            0.0
        }
    }

    /// Score suspicious TLD.
    fn score_suspicious_tld(hostname: &str, tlds: &HashSet<&str>) -> f32 {
        if let Some(tld) = hostname.rsplit('.').next() {
            if tlds.contains(tld.to_ascii_lowercase().as_str()) {
                return 0.3;
            }
        }
        0.0
    }
}

impl Default for DnsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for DnsAnalyzer {
    fn id(&self) -> DetectorId {
        DetectorId::DnsAnalyzer
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding {
        let start = Instant::now();

        let dns_name = match flow.dns_name.as_ref() {
            Some(name) => name.as_str(),
            None => {
                return DetectorFinding {
                    detector_id: self.id(),
                    detector_version: self.version().to_string(),
                    score: 0.0,
                    confidence: 1.0,
                    severity: Severity::Low,
                    evidence: vec![Evidence {
                        description: "No DNS name available".to_string(),
                        detail: None,
                    }],
                    latency_us: start.elapsed().as_micros() as u64,
                    status: DetectorStatus::Completed,
                };
            }
        };

        // Allowlist check — short-circuit.
        if Self::is_allowlisted(dns_name, &self.allowlist) {
            return DetectorFinding {
                detector_id: self.id(),
                detector_version: self.version().to_string(),
                score: 0.0,
                confidence: 1.0,
                severity: Severity::Low,
                evidence: vec![Evidence {
                    description: "DNS name is allowlisted".to_string(),
                    detail: Some(dns_name.to_string()),
                }],
                latency_us: start.elapsed().as_micros() as u64,
                status: DetectorStatus::Completed,
            };
        }

        let entropy = Self::shannon_entropy(dns_name);
        let length = dns_name.len();
        let max_label = Self::longest_label(dns_name);
        let labels = Self::count_labels(dns_name);
        let has_literal = Self::has_ip_literal(dns_name);

        let mut evidence = Vec::new();
        let mut total_score = 0.0f32;
        let mut max_possible = 0.0f32;

        let e = Self::score_entropy(entropy);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!("High entropy: {:.2} bits/char", entropy),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_length(length);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!("Long hostname: {} chars", length),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_longest_label(max_label);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!("Long label: {} chars", max_label),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_label_count(labels);
        if e > 0.0 {
            evidence.push(Evidence {
                description: format!("Many subdomains: {} labels", labels),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_ip_literal(has_literal);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "IP literal embedded in hostname".to_string(),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_blocklist(dns_name, &self.blocklist);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Hostname matches blocklist".to_string(),
                detail: Some(dns_name.to_string()),
            });
        }
        total_score += e;
        max_possible += 1.0;

        let e = Self::score_suspicious_tld(dns_name, &self.suspicious_tlds);
        if e > 0.0 {
            evidence.push(Evidence {
                description: "Suspicious TLD".to_string(),
                detail: None,
            });
        }
        total_score += e;
        max_possible += 1.0;

        // Normalize score to 0.0–1.0.
        let normalized = if max_possible > 0.0 {
            (total_score / max_possible).min(1.0)
        } else {
            0.0
        };

        let severity = if normalized > 0.7 {
            Severity::Critical
        } else if normalized > 0.5 {
            Severity::High
        } else if normalized > 0.3 {
            Severity::Medium
        } else {
            Severity::Low
        };

        let confidence = if evidence.len() >= 3 {
            0.9
        } else if evidence.len() >= 2 {
            0.7
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
    use std::net::IpAddr;

    fn make_flow_with_dns(dns_name: Option<String>) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            a_ip: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            b_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            a_port: 443,
            b_port: 50000,
            protocol: 6,
            local_port: 50000,
            pid: Some(42),
            packet_count: 10,
            byte_count: 5000,
            dns_name,
            process_path: Some("/usr/bin/curl".to_string()),
            process_start_time: Some(1700000000.0),
            country_code: None,
            asn: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(5),
        }
    }

    #[test]
    fn test_entropy_known_low() {
        let e = DnsAnalyzer::shannon_entropy("aaaaaaaaaa");
        assert!(e < 1.0, "Low entropy expected, got {}", e);
    }

    #[test]
    fn test_entropy_known_high() {
        let e = DnsAnalyzer::shannon_entropy("a7Bx9#mK2!qZ");
        assert!(e > 3.0, "High entropy expected, got {}", e);
    }

    #[test]
    fn test_has_ip_literal() {
        assert!(DnsAnalyzer::has_ip_literal("192.168.1.1.example.com"));
        assert!(!DnsAnalyzer::has_ip_literal("www.example.com"));
    }

    #[test]
    fn test_label_count() {
        assert_eq!(DnsAnalyzer::count_labels("a.b.c.d.e.f"), 6);
        assert_eq!(DnsAnalyzer::count_labels("example.com"), 2);
        assert_eq!(DnsAnalyzer::count_labels(""), 0);
    }

    #[test]
    fn test_allowlisted_domain() {
        let analyzer = DnsAnalyzer::new();
        let flow = make_flow_with_dns(Some("www.github.com".to_string()));
        let finding = analyzer.evaluate(&flow);
        assert_eq!(finding.score, 0.0, "Allowlisted domain should score 0");
    }

    #[test]
    fn test_blocklist_match() {
        let analyzer = DnsAnalyzer::new();
        let flow = make_flow_with_dns(Some("malware.example.com".to_string()));
        let finding = analyzer.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "Blocklist match should score > 0, got {}",
            finding.score
        );
        assert!(finding
            .evidence
            .iter()
            .any(|e| e.description.contains("blocklist")));
    }

    #[test]
    fn test_no_dns_name() {
        let analyzer = DnsAnalyzer::new();
        let flow = make_flow_with_dns(None);
        let finding = analyzer.evaluate(&flow);
        assert_eq!(finding.score, 0.0);
    }

    #[test]
    fn test_long_hostname() {
        let analyzer = DnsAnalyzer::new();
        let long_name = "a".repeat(90);
        let flow = make_flow_with_dns(Some(format!("{}.example.com", long_name)));
        let finding = analyzer.evaluate(&flow);
        assert!(finding.score > 0.0, "Long hostname should increase score");
    }

    #[test]
    fn test_cdn_now_scored_cloudfront() {
        let analyzer = DnsAnalyzer::new();
        // CDN carve-out removed — CloudFront domains are now scored for entropy/length/labels.
        let flow = make_flow_with_dns(Some("d1234abcdef.cloudfront.net".to_string()));
        let finding = analyzer.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "CloudFront CDN should now be scored (carve-out removed), got {}",
            finding.score
        );
    }

    #[test]
    fn test_cdn_label_count_now_scored() {
        let analyzer = DnsAnalyzer::new();
        // 7 labels — no longer exempt.
        let flow = make_flow_with_dns(Some("a.b.c.d.e.f.cloudfront.net".to_string()));
        let finding = analyzer.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "CDN domains should no longer be exempt from label count scoring, got {}",
            finding.score
        );
    }

    #[test]
    fn test_non_cdn_high_label_count() {
        let analyzer = DnsAnalyzer::new();
        let flow = make_flow_with_dns(Some("a.b.c.d.e.f.example.com".to_string()));
        let finding = analyzer.evaluate(&flow);
        assert!(
            finding.score > 0.0,
            "Non-CDN with 7 labels should score > 0"
        );
    }

    // -----------------------------------------------------------------------
    // Blocklist label-aware matching regression tests (score_blocklist fix)
    // -----------------------------------------------------------------------

    #[test]
    fn test_blocklist_substring_does_not_false_positive_full_domain_entry() {
        // "notmalware.example.com" contains the substring "malware.example.com"
        // starting at index 3. The old lower.contains() was true here — fixed.
        let blocklist: HashSet<String> = ["malware.example.com".to_string()].into();
        assert_eq!(
            DnsAnalyzer::score_blocklist("notmalware.example.com", &blocklist),
            0.0,
            "notmalware.example.com must not match blocklist entry malware.example.com"
        );
    }

    #[test]
    fn test_blocklist_exact_match_fires() {
        let blocklist: HashSet<String> = ["malware.example.com".to_string()].into();
        assert_eq!(
            DnsAnalyzer::score_blocklist("malware.example.com", &blocklist),
            1.0,
            "exact blocklist match must fire"
        );
    }

    #[test]
    fn test_blocklist_subdomain_match_fires() {
        // A subdomain of a blocked domain is also blocked.
        let blocklist: HashSet<String> = ["malware.example.com".to_string()].into();
        assert_eq!(
            DnsAnalyzer::score_blocklist("foo.malware.example.com", &blocklist),
            1.0,
            "subdomain of blocked domain must match"
        );
    }

    #[test]
    fn test_blocklist_single_label_ec2_does_not_match_c2_entry() {
        // "ec2" split on '-' is just ["ec2"]; "c2" is a separate label.
        // has_label("ec2.amazonaws.com", "c2") must be false.
        let blocklist: HashSet<String> = ["c2".to_string()].into();
        assert_eq!(
            DnsAnalyzer::score_blocklist("ec2.amazonaws.com", &blocklist),
            0.0,
            "ec2.amazonaws.com must not match single-label blocklist entry 'c2'"
        );
    }

    #[test]
    fn test_blocklist_single_label_standalone_fires() {
        // "c2.evil.com" has a standalone "c2" label — must match.
        let blocklist: HashSet<String> = ["c2".to_string()].into();
        assert_eq!(
            DnsAnalyzer::score_blocklist("c2.evil.com", &blocklist),
            1.0,
            "c2.evil.com must match single-label blocklist entry 'c2'"
        );
    }

    #[test]
    fn test_has_label_does_not_match_substring_within_label() {
        assert!(
            !has_label("ec2-server.example.com", "c2"),
            "has_label must not match 'c2' inside 'ec2'"
        );
        assert!(
            !has_label("ec2.amazonaws.com", "c2"),
            "has_label must not match 'c2' inside 'ec2'"
        );
    }

    #[test]
    fn test_has_label_matches_standalone_label() {
        assert!(has_label("c2.evil.com", "c2"));
        assert!(
            has_label("foo-c2.example.com", "c2"),
            "dash-separated label"
        );
        assert!(has_label("C2.Evil.Com", "c2"), "case-insensitive");
    }
}
