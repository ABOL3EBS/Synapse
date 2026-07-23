// crates/agent/src/detectors/mod.rs
//
// Detector framework (§4b). Every detector implements the Detector trait
// from synapse-common. The RuleDetector is the first real implementation —
// a simple rule engine for v1 placeholder rules.
//
// PLACEHOLDER RULES — these are test/demo rules for v1, NOT production
// detection logic. They exist to prove the framework and timeout mechanism
// work. Real detection rules will be loaded from configuration.

use std::sync::Arc;
use std::time::Duration;

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

use log::info;

// ---------------------------------------------------------------------------
// RuleDetector — simple rule engine for v1
// ---------------------------------------------------------------------------

/// A single detection rule.
struct Rule {
    name: &'static str,
    score: f32,
    severity: Severity,
    evaluate: fn(&FlowRecord) -> bool,
}

/// Simple rule-based detector. Scores a flow against a set of hardcoded rules.
/// For v1 — placeholder rules to prove the framework works.
pub struct RuleDetector {
    rules: Vec<Rule>,
}

impl RuleDetector {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Rule {
                    name: "dns_blocklist",
                    score: 0.8,
                    severity: Severity::High,
                    evaluate: |flow| {
                        // Placeholder: flag flows with dns_name containing "malware" or "phish"
                        // Real v1 would load from a blocklist file.
                        flow.dns_name.as_ref().is_some_and(|name| {
                            name.contains("malware")
                                || name.contains("phish")
                                || name.contains("c2")
                        })
                    },
                },
                Rule {
                    name: "suspicious_port",
                    score: 0.5,
                    severity: Severity::Medium,
                    evaluate: |flow| {
                        // Placeholder: flag flows to known-suspicious ports.
                        // Real v1 would load from a threat-intel feed.
                        matches!(
                            flow.dst_port,
                            4444 | 5555 | 6666 | 7777 | 8888 | 9999 | 31337
                        )
                    },
                },
                Rule {
                    name: "high_packet_count",
                    score: 0.3,
                    severity: Severity::Low,
                    evaluate: |flow| {
                        // Placeholder: flag flows with unusually high packet count
                        // in a 5-second window (>1000 packets).
                        flow.packet_count > 1000
                    },
                },
            ],
        }
    }
}

impl Detector for RuleDetector {
    fn id(&self) -> DetectorId {
        DetectorId::RuleEngine
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding {
        let start = std::time::Instant::now();
        let mut matched_rules = Vec::new();
        let mut total_score = 0.0_f32;
        let mut max_severity = Severity::Low;

        for rule in &self.rules {
            if (rule.evaluate)(flow) {
                matched_rules.push(rule.name);
                total_score += rule.score;
                if rule.severity > max_severity {
                    max_severity = rule.severity;
                }
            }
        }

        // Clamp score to [0.0, 1.0].
        let score = total_score.min(1.0);
        let confidence = if matched_rules.is_empty() {
            0.0
        } else {
            0.8 // Placeholder confidence for matched rules.
        };

        let latency_us = start.elapsed().as_micros() as u64;

        DetectorFinding {
            detector_id: DetectorId::RuleEngine,
            detector_version: self.version().to_string(),
            score,
            confidence,
            severity: max_severity,
            evidence: matched_rules
                .into_iter()
                .map(|name| Evidence {
                    description: format!("rule '{}' matched", name),
                    detail: None,
                })
                .collect(),
            latency_us,
            status: DetectorStatus::Completed,
        }
    }
}

// ---------------------------------------------------------------------------
// DetectorRunner — runs all registered detectors with timeout enforcement
// ---------------------------------------------------------------------------

/// Runs a set of detectors against a flow, enforcing per-detector timeouts.
/// Returns all findings (one per detector).
pub fn run_detectors(
    detectors: &[Arc<dyn Detector>],
    flow: &FlowRecord,
    timeout: Duration,
) -> Vec<DetectorFinding> {
    detectors
        .iter()
        .map(|d| {
            let finding = synapse_common::run_detector_with_timeout(Arc::clone(d), flow, timeout);
            info!(
                "detector {:?} on flow {}: score={:.2} status={:?} latency={}us",
                finding.detector_id,
                flow.flow_id,
                finding.score,
                finding.status,
                finding.latency_us
            );
            finding
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::thread;

    /// A deliberately slow detector that sleeps for longer than its budget.
    /// This is the test that proves the timeout mechanism works.
    struct SlowDetector {
        sleep_duration: Duration,
    }

    impl Detector for SlowDetector {
        fn id(&self) -> DetectorId {
            DetectorId::Custom(999)
        }

        fn version(&self) -> &str {
            "0.0.0"
        }

        fn evaluate(&self, _flow: &FlowRecord) -> DetectorFinding {
            thread::sleep(self.sleep_duration);
            DetectorFinding {
                detector_id: DetectorId::Custom(999),
                detector_version: self.version().to_string(),
                score: 1.0,
                confidence: 1.0,
                severity: Severity::Critical,
                evidence: vec![Evidence {
                    description: "should never reach here".to_string(),
                    detail: None,
                }],
                latency_us: 0,
                status: DetectorStatus::Completed,
            }
        }
    }

    fn make_test_flow() -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            src_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 50000,
            dst_port: 443,
            protocol: 6,
            local_port: 50000,
            pid: Some(42),
            packet_count: 10,
            byte_count: 5000,
            dns_name: None,
            process_path: Some("/usr/bin/curl".to_string()),
            country_code: None,
            reputation_score: None,
        }
    }

    /// THE critical test: a detector that sleeps 500ms must return TimedOut
    /// within the 50ms budget, not after 500ms.
    #[test]
    fn test_slow_detector_returns_timed_out_within_budget() {
        let detector: Arc<dyn Detector> = Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        });
        let flow = make_test_flow();
        let budget = Duration::from_millis(50);

        let start = std::time::Instant::now();
        let finding =
            synapse_common::run_detector_with_timeout(Arc::clone(&detector), &flow, budget);
        let elapsed = start.elapsed();

        assert_eq!(
            finding.status,
            DetectorStatus::TimedOut,
            "detector sleeping 500ms with 50ms budget must return TimedOut"
        );
        assert_eq!(finding.score, 0.0, "TimedOut finding must have zero score");
        assert!(
            elapsed < Duration::from_millis(200),
            "must return within budget, not after full sleep — elapsed={:?}",
            elapsed
        );
    }

    /// Slow detector completes normally when given enough budget.
    #[test]
    fn test_slow_detector_completes_when_given_enough_budget() {
        let detector: Arc<dyn Detector> = Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(10),
        });
        let flow = make_test_flow();
        let budget = Duration::from_millis(200);

        let finding =
            synapse_common::run_detector_with_timeout(Arc::clone(&detector), &flow, budget);

        assert_eq!(
            finding.status,
            DetectorStatus::Completed,
            "detector sleeping 10ms with 200ms budget must complete"
        );
        assert_eq!(finding.score, 1.0);
    }

    /// RuleDetector matches dns_blocklist rule.
    #[test]
    fn test_rule_detector_dns_blocklist() {
        let detector = RuleDetector::new();
        let mut flow = make_test_flow();
        flow.dns_name = Some("evil-malware.example.com".to_string());

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert!(finding.score > 0.0, "dns_blocklist should score > 0");
        assert_eq!(finding.severity, Severity::High);
        assert!(!finding.evidence.is_empty());
    }

    /// RuleDetector matches suspicious_port rule.
    #[test]
    fn test_rule_detector_suspicious_port() {
        let detector = RuleDetector::new();
        let mut flow = make_test_flow();
        flow.dst_port = 4444;

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert!(finding.score > 0.0, "suspicious_port should score > 0");
        assert_eq!(finding.severity, Severity::Medium);
    }

    /// RuleDetector matches high_packet_count rule.
    #[test]
    fn test_rule_detector_high_packet_count() {
        let detector = RuleDetector::new();
        let mut flow = make_test_flow();
        flow.packet_count = 2000;

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert!(finding.score > 0.0, "high_packet_count should score > 0");
    }

    /// RuleDetector returns zero score for clean flow.
    #[test]
    fn test_rule_detector_clean_flow() {
        let detector = RuleDetector::new();
        let flow = make_test_flow();

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert_eq!(finding.score, 0.0, "clean flow should score 0");
        assert!(finding.evidence.is_empty());
    }

    /// run_detectors() with timeout enforces budget across multiple detectors.
    #[test]
    fn test_run_detectors_with_timeout() {
        let detectors: Vec<Arc<dyn Detector>> = vec![
            Arc::new(RuleDetector::new()),
            Arc::new(SlowDetector {
                sleep_duration: Duration::from_millis(500),
            }),
        ];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(50);

        let findings = run_detectors(&detectors, &flow, timeout);

        assert_eq!(findings.len(), 2);
        // RuleDetector should complete.
        assert_eq!(findings[0].status, DetectorStatus::Completed);
        // SlowDetector should be timed out.
        assert_eq!(findings[1].status, DetectorStatus::TimedOut);
    }
}
