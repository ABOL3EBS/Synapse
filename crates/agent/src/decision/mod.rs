// crates/agent/src/decision/mod.rs
//
// Decision engine (§4 step 5). Merges all detector findings into a single
// verdict using weighted scoring. TimedOut/Errored findings are down-weighted
// or zeroed, not treated as silent zeros.
//
// "Weighted scoring merges all detector findings into a single verdict,
// weighting down or ignoring findings with a TimedOut/Errored status rather
// than treating a missing result as a silent zero." — §4
//
// TODO (decision engine reliability gap):
// DetectorFinding currently conflates four distinct states:
//   1. No threat found (Completed, score=0)
//   2. Detector unavailable — timed out or circuit-broken (TimedOut, score=0)
//   3. Detector error (Errored, score=0)
//   4. Detector skipped by circuit breaker (synthetic TimedOut, score=0)
//
// The engine treats all four as zero contribution to total_score. A degraded
// detection pipeline (multiple detectors circuit-broken) produces normal-looking
// verdicts with reduced visibility. When the dashboard exists, introduce
// DetectorHealth metadata:
//
//   DetectorHealth {
//       detector_id: DetectorId,
//       status: Available | Timeout | CircuitOpen | Error,
//       last_failure: Option<Instant>,
//       confidence_penalty: f32,  // reduces verdict confidence
//   }
//
// The DecisionEngine should incorporate detection coverage into verdict
// confidence — e.g., if 2/4 detectors are unavailable, the Allow verdict's
// confidence should be halved.

use synapse_common::{
    DecisionConfig, DetectorFinding, DetectorStatus, FlowFeatures, Severity, Verdict,
};

use log::debug;

// ---------------------------------------------------------------------------
// DecisionEngine
// ---------------------------------------------------------------------------

/// The decision engine. Takes a set of detector findings for a flow and
/// produces a Verdict (Allow, Block, or Alert) based on weighted scoring
/// against configurable thresholds.
pub struct DecisionEngine {
    config: DecisionConfig,
}

impl DecisionEngine {
    pub fn new(config: DecisionConfig) -> Self {
        Self { config }
    }

    /// Evaluate a set of detector findings for a flow and produce a verdict.
    ///
    /// Scoring:
    /// - For each Completed finding: `score × confidence × 1.0`
    /// - For each TimedOut finding: `score × confidence × timed_out_weight` (0.1)
    /// - For each Errored finding: `score × confidence × errored_weight` (0.0)
    /// - Sum all adjusted scores → compare against thresholds
    ///
    /// TTL (for Block verdicts):
    /// - Find the most severe Completed finding
    /// - Look up TTL from `ttl_by_severity` config
    /// - Clamp to [min_ttl, max_ttl]
    pub fn evaluate(&self, features: &FlowFeatures, findings: &[DetectorFinding]) -> Verdict {
        let mut total_score = 0.0_f32;
        let mut most_severe: Option<Severity> = None;
        let mut evidence_summary = Vec::new();

        for finding in findings {
            let weight = match finding.status {
                DetectorStatus::Completed => 1.0,
                DetectorStatus::TimedOut => self.config.timed_out_weight,
                DetectorStatus::Errored => self.config.errored_weight,
            };

            let adjusted = finding.score * finding.confidence * weight;
            total_score += adjusted;

            // Track the most severe Completed finding for TTL calculation.
            if finding.status == DetectorStatus::Completed && finding.score > 0.0 {
                if most_severe.is_none_or(|s| finding.severity > s) {
                    most_severe = Some(finding.severity);
                }
                // Collect evidence from Completed findings with non-zero scores.
                for ev in &finding.evidence {
                    evidence_summary.push(format!("{:?}: {}", finding.detector_id, ev.description));
                }
            }

            debug!(
                "decision: {:?} score={:.2} conf={:.2} status={:?} weight={:.1} adjusted={:.4}",
                finding.detector_id,
                finding.score,
                finding.confidence,
                finding.status,
                weight,
                adjusted
            );
        }

        debug!(
            "decision: flow={} total_score={:.4} threshold(block={:.2}, alert={:.2})",
            features.flow_id, total_score, self.config.block_threshold, self.config.alert_threshold
        );

        // Determine verdict based on thresholds.
        if total_score >= self.config.block_threshold {
            let ttl = self.compute_ttl(most_severe);
            let reason = if evidence_summary.is_empty() {
                format!("score {:.2} exceeds block threshold", total_score)
            } else {
                format!(
                    "score {:.2} exceeds block threshold: {}",
                    total_score,
                    evidence_summary.join("; ")
                )
            };
            Verdict::Block { ttl, reason }
        } else if total_score >= self.config.alert_threshold {
            let reason = if evidence_summary.is_empty() {
                format!("score {:.2} exceeds alert threshold", total_score)
            } else {
                format!(
                    "score {:.2} exceeds alert threshold: {}",
                    total_score,
                    evidence_summary.join("; ")
                )
            };
            Verdict::Alert { reason }
        } else {
            Verdict::Allow
        }
    }

    /// Compute TTL from the most severe Completed finding.
    /// Falls back to Medium (5 min) if no Completed findings.
    /// Clamped to [min_ttl, max_ttl].
    fn compute_ttl(&self, most_severe: Option<Severity>) -> std::time::Duration {
        let severity = most_severe.unwrap_or(Severity::Medium);
        let ttl = self
            .config
            .ttl_by_severity
            .get(&severity)
            .copied()
            .unwrap_or(std::time::Duration::from_secs(300));

        // Clamp to [min_ttl, max_ttl].
        if ttl < self.config.min_ttl {
            self.config.min_ttl
        } else if ttl > self.config.max_ttl {
            self.config.max_ttl
        } else {
            ttl
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use synapse_common::{DetectorId, Evidence};

    fn make_finding(
        score: f32,
        confidence: f32,
        severity: Severity,
        status: DetectorStatus,
    ) -> DetectorFinding {
        DetectorFinding {
            detector_id: DetectorId::RuleEngine,
            detector_version: "0.1.0".to_string(),
            score,
            confidence,
            severity,
            evidence: vec![Evidence {
                description: "test rule matched".to_string(),
                detail: None,
            }],
            latency_us: 100,
            status,
        }
    }

    fn make_features(flow_id: u64) -> FlowFeatures {
        FlowFeatures {
            flow_id,
            packet_count: 100,
            byte_count: 50000,
            duration_ms: 2000,
            packet_frequency: 50.0,
            protocol: 6,
            dst_port: 443,
            has_dns_name: false,
            has_process_path: false,
            reputation_score: None,
        }
    }

    #[test]
    fn test_no_findings_produces_allow() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        let verdict = engine.evaluate(&features, &[]);
        assert!(
            matches!(verdict, Verdict::Allow),
            "no findings should produce Allow"
        );
    }

    #[test]
    fn test_low_score_below_alert_threshold() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        let findings = vec![make_finding(
            0.05,
            0.8,
            Severity::Low,
            DetectorStatus::Completed,
        )];
        let verdict = engine.evaluate(&features, &findings);
        assert!(
            matches!(verdict, Verdict::Allow),
            "score 0.04 (0.05 * 0.8) below alert threshold 0.2"
        );
    }

    #[test]
    fn test_medium_score_triggers_alert() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        // score=0.3, confidence=0.8 → adjusted=0.24, above alert (0.2), below block (0.5)
        let findings = vec![make_finding(
            0.3,
            0.8,
            Severity::Low,
            DetectorStatus::Completed,
        )];
        let verdict = engine.evaluate(&features, &findings);
        assert!(
            matches!(verdict, Verdict::Alert { .. }),
            "adjusted score 0.24 should trigger Alert"
        );
    }

    #[test]
    fn test_high_score_triggers_block() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        // score=0.8, confidence=0.8 → adjusted=0.64, above block (0.5)
        let findings = vec![make_finding(
            0.8,
            0.8,
            Severity::High,
            DetectorStatus::Completed,
        )];
        let verdict = engine.evaluate(&features, &findings);
        match verdict {
            Verdict::Block { ttl, reason } => {
                assert_eq!(
                    ttl,
                    std::time::Duration::from_secs(900),
                    "High severity → 15 min TTL"
                );
                assert!(reason.contains("score"), "reason should mention score");
            }
            _ => panic!("adjusted score 0.64 should trigger Block"),
        }
    }

    #[test]
    fn test_timed_out_finding_down_weighted() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        // score=0.8, confidence=0.8, TimedOut → adjusted=0.8 * 0.8 * 0.1 = 0.064
        let findings = vec![make_finding(
            0.8,
            0.8,
            Severity::High,
            DetectorStatus::TimedOut,
        )];
        let verdict = engine.evaluate(&features, &findings);
        assert!(
            matches!(verdict, Verdict::Allow),
            "TimedOut finding should be down-weighted below alert threshold"
        );
    }

    #[test]
    fn test_errored_finding_zeroed() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        // score=0.8, confidence=0.8, Errored → adjusted=0.8 * 0.8 * 0.0 = 0.0
        let findings = vec![make_finding(
            0.8,
            0.8,
            Severity::High,
            DetectorStatus::Errored,
        )];
        let verdict = engine.evaluate(&features, &findings);
        assert!(
            matches!(verdict, Verdict::Allow),
            "Errored finding should be zeroed"
        );
    }

    #[test]
    fn test_ttl_from_most_severe_completed() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        // Two findings: Critical (Completed) and High (TimedOut).
        // Most severe Completed is Critical → 1 hour TTL.
        let findings = vec![
            make_finding(0.6, 0.9, Severity::Critical, DetectorStatus::Completed),
            make_finding(0.5, 0.8, Severity::High, DetectorStatus::TimedOut),
        ];
        let verdict = engine.evaluate(&features, &findings);
        match verdict {
            Verdict::Block { ttl, .. } => {
                assert_eq!(
                    ttl,
                    std::time::Duration::from_secs(3600),
                    "Critical → 1 hour TTL"
                );
            }
            _ => panic!("should be Block"),
        }
    }

    #[test]
    fn test_ttl_clamped_to_min() {
        let config = DecisionConfig {
            min_ttl: std::time::Duration::from_secs(120), // 2 min floor
            ..Default::default()
        };
        let engine = DecisionEngine::new(config);
        let features = make_features(1);
        // Low severity → 60s, but min_ttl is 120s → clamped to 120s.
        let findings = vec![make_finding(
            0.8,
            0.8,
            Severity::Low,
            DetectorStatus::Completed,
        )];
        let verdict = engine.evaluate(&features, &findings);
        match verdict {
            Verdict::Block { ttl, .. } => {
                assert_eq!(
                    ttl,
                    std::time::Duration::from_secs(120),
                    "should be clamped to min_ttl"
                );
            }
            _ => panic!("should be Block"),
        }
    }

    #[test]
    fn test_ttl_clamped_to_max() {
        let config = DecisionConfig {
            max_ttl: std::time::Duration::from_secs(600), // 10 min cap
            ..Default::default()
        };
        let engine = DecisionEngine::new(config);
        let features = make_features(1);
        // Critical severity → 3600s, but max_ttl is 600s → clamped to 600s.
        let findings = vec![make_finding(
            0.8,
            0.8,
            Severity::Critical,
            DetectorStatus::Completed,
        )];
        let verdict = engine.evaluate(&features, &findings);
        match verdict {
            Verdict::Block { ttl, .. } => {
                assert_eq!(
                    ttl,
                    std::time::Duration::from_secs(600),
                    "should be clamped to max_ttl"
                );
            }
            _ => panic!("should be Block"),
        }
    }

    #[test]
    fn test_multiple_findings_cumulative_score() {
        let engine = DecisionEngine::new(DecisionConfig::default());
        let features = make_features(1);
        // Two Low findings: each 0.3 * 0.8 = 0.24, total = 0.48
        // Below block (0.5) but above alert (0.2).
        let findings = vec![
            make_finding(0.3, 0.8, Severity::Low, DetectorStatus::Completed),
            make_finding(0.3, 0.8, Severity::Low, DetectorStatus::Completed),
        ];
        let verdict = engine.evaluate(&features, &findings);
        assert!(
            matches!(verdict, Verdict::Alert { .. }),
            "cumulative 0.48 should trigger Alert, not Block"
        );
    }

    #[test]
    fn test_default_config_thresholds() {
        let config = DecisionConfig::default();
        assert_eq!(config.block_threshold, 0.5);
        assert_eq!(config.alert_threshold, 0.2);
        assert_eq!(config.timed_out_weight, 0.1);
        assert_eq!(config.errored_weight, 0.0);
        assert_eq!(config.min_ttl, std::time::Duration::from_secs(30));
        assert_eq!(config.max_ttl, std::time::Duration::from_secs(86400));
    }
}
