// crates/agent/src/detectors/mod.rs
//
// Detector framework (§4b). Every detector implements the Detector trait
// from synapse-common. The RuleDetector is the first real implementation —
// a simple rule engine for v1 placeholder rules.
//
// PLACEHOLDER RULES — these are test/demo rules for v1, NOT production
// detection logic. They exist to prove the framework and timeout mechanism
// work. Real detection rules will be loaded from configuration.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

use log::{debug, info};

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
// Circuit Breaker — per-detector failure tracking with recovery
// ---------------------------------------------------------------------------

/// Number of consecutive failures before the circuit opens.
const MAX_FAILURES: u32 = 5;

/// How long the circuit stays open before attempting recovery.
const COOLDOWN: Duration = Duration::from_secs(30);

/// Per-detector circuit breaker state. Tracks failures, enables recovery via
/// half-open probe, records failure metadata for debugging.
#[derive(Debug, Clone)]
pub enum CircuitState {
    /// Normal operation. Counting consecutive failures.
    Closed { failures: u32 },
    /// Detector skipped. Waiting for cooldown to expire.
    Open {
        opened_at: Instant,
        last_failure_reason: Option<String>,
    },
    /// Cooldown expired — one trial attempt allowed.
    HalfOpen,
}

impl CircuitState {
    fn is_open(&self, now: Instant) -> bool {
        match self {
            CircuitState::Closed { .. } => false,
            CircuitState::Open { opened_at, .. } => now.duration_since(*opened_at) < COOLDOWN,
            CircuitState::HalfOpen => false,
        }
    }
}

// ---------------------------------------------------------------------------
// run_detectors
// ---------------------------------------------------------------------------

/// Runs a set of detectors against a flow, enforcing per-detector timeouts.
/// Returns all findings (one per detector).
///
/// Circuit breaker state machine per detector:
///
/// ```text
/// Closed (failures < MAX) ──failure──> Closed (failures++)
///     │                                      │
///     │ success                              │ failures >= MAX
///     │                                      ▼
///     ◄──────────────success──────────── Open (skip, wait COOLDOWN)
///     │                                      │
///     │                                      │ cooldown expires
///     │                                      ▼
///     ◄──success──────────────────────── HalfOpen (allow one probe)
///                                            │
///                                            │ failure
///                                            ▼
///                                          Open (reset timer)
/// ```
pub fn run_detectors(
    detectors: &[Arc<dyn Detector>],
    flow: &FlowRecord,
    timeout: Duration,
    circuit_breaker: &mut HashMap<DetectorId, CircuitState>,
) -> Vec<DetectorFinding> {
    let now = Instant::now();

    detectors
        .iter()
        .map(|d| {
            let id = d.id();

            // State check — decide whether to run or skip.
            let should_skip = match circuit_breaker.get(&id) {
                Some(CircuitState::Closed { .. }) => false,
                Some(state) if state.is_open(now) => true,
                Some(CircuitState::Open { .. }) => {
                    // Cooldown expired — transition to HalfOpen, allow probe.
                    debug!("detector {:?} cooldown expired → HalfOpen", id);
                    circuit_breaker.insert(id, CircuitState::HalfOpen);
                    false
                }
                Some(CircuitState::HalfOpen) => false,
                None => false,
            };

            if should_skip {
                let reason = match circuit_breaker.get(&id) {
                    Some(CircuitState::Open {
                        last_failure_reason,
                        ..
                    }) => last_failure_reason
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    _ => "unknown".to_string(),
                };
                debug!("detector {:?} skipped (circuit open: {})", id, reason);
                return DetectorFinding::timed_out(id, d.version(), 0);
            }

            let finding = synapse_common::run_detector_with_timeout(Arc::clone(d), flow, timeout);

            // State transition based on result.
            match finding.status {
                DetectorStatus::Completed => {
                    // Success — any state → Closed (reset).
                    circuit_breaker.remove(&id);
                }
                DetectorStatus::TimedOut | DetectorStatus::Errored => {
                    let reason = if finding.status == DetectorStatus::TimedOut {
                        "timed out".to_string()
                    } else {
                        finding
                            .evidence
                            .first()
                            .map(|e| e.description.clone())
                            .unwrap_or_else(|| "errored".to_string())
                    };

                    match circuit_breaker.get(&id) {
                        None => {
                            // First failure → Closed { failures: 1 }.
                            circuit_breaker.insert(id, CircuitState::Closed { failures: 1 });
                        }
                        Some(CircuitState::Closed { failures }) => {
                            let new_failures = failures + 1;
                            if new_failures >= MAX_FAILURES {
                                // Trip → Open.
                                debug!(
                                    "detector {:?} circuit open ({} consecutive failures)",
                                    id, new_failures
                                );
                                circuit_breaker.insert(
                                    id,
                                    CircuitState::Open {
                                        opened_at: Instant::now(),
                                        last_failure_reason: Some(reason),
                                    },
                                );
                            } else {
                                circuit_breaker.insert(
                                    id,
                                    CircuitState::Closed {
                                        failures: new_failures,
                                    },
                                );
                            }
                        }
                        Some(CircuitState::HalfOpen) => {
                            // Probe failed → back to Open.
                            debug!("detector {:?} probe failed → Open", id);
                            circuit_breaker.insert(
                                id,
                                CircuitState::Open {
                                    opened_at: Instant::now(),
                                    last_failure_reason: Some(reason),
                                },
                            );
                        }
                        Some(CircuitState::Open { .. }) => {
                            // Shouldn't happen (we allowed execution), but handle gracefully.
                        }
                    }
                }
            }

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

    /// A detector that always errors (never completes).
    struct ErrorDetector;

    impl Detector for ErrorDetector {
        fn id(&self) -> DetectorId {
            DetectorId::Custom(998)
        }

        fn version(&self) -> &str {
            "0.0.0"
        }

        fn evaluate(&self, _flow: &FlowRecord) -> DetectorFinding {
            DetectorFinding::errored(DetectorId::Custom(998), "0.0.0", "test error", 0)
        }
    }

    /// A controllable detector — can be told to succeed or fail.
    struct ControllableDetector {
        should_fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl Detector for ControllableDetector {
        fn id(&self) -> DetectorId {
            DetectorId::Custom(997)
        }

        fn version(&self) -> &str {
            "0.0.0"
        }

        fn evaluate(&self, _flow: &FlowRecord) -> DetectorFinding {
            if self.should_fail.load(std::sync::atomic::Ordering::Relaxed) {
                DetectorFinding::timed_out(DetectorId::Custom(997), "0.0.0", 0)
            } else {
                DetectorFinding {
                    detector_id: DetectorId::Custom(997),
                    detector_version: "0.0.0".to_string(),
                    score: 0.5,
                    confidence: 0.9,
                    severity: Severity::Medium,
                    evidence: vec![],
                    latency_us: 0,
                    status: DetectorStatus::Completed,
                }
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

    // -----------------------------------------------------------------------
    // Timeout enforcement (unchanged from before)
    // -----------------------------------------------------------------------

    #[test]
    fn test_slow_detector_returns_timed_out_within_budget() {
        let detector: Arc<dyn Detector> = Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        });
        let flow = make_test_flow();
        let budget = Duration::from_millis(50);

        let start = Instant::now();
        let finding =
            synapse_common::run_detector_with_timeout(Arc::clone(&detector), &flow, budget);
        let elapsed = start.elapsed();

        assert_eq!(finding.status, DetectorStatus::TimedOut);
        assert_eq!(finding.score, 0.0);
        assert!(elapsed < Duration::from_millis(200));
    }

    #[test]
    fn test_slow_detector_completes_when_given_enough_budget() {
        let detector: Arc<dyn Detector> = Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(10),
        });
        let flow = make_test_flow();
        let budget = Duration::from_millis(200);

        let finding =
            synapse_common::run_detector_with_timeout(Arc::clone(&detector), &flow, budget);

        assert_eq!(finding.status, DetectorStatus::Completed);
        assert_eq!(finding.score, 1.0);
    }

    // -----------------------------------------------------------------------
    // RuleDetector unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule_detector_dns_blocklist() {
        let detector = RuleDetector::new();
        let mut flow = make_test_flow();
        flow.dns_name = Some("evil-malware.example.com".to_string());

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert!(finding.score > 0.0);
        assert_eq!(finding.severity, Severity::High);
        assert!(!finding.evidence.is_empty());
    }

    #[test]
    fn test_rule_detector_suspicious_port() {
        let detector = RuleDetector::new();
        let mut flow = make_test_flow();
        flow.dst_port = 4444;

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert!(finding.score > 0.0);
        assert_eq!(finding.severity, Severity::Medium);
    }

    #[test]
    fn test_rule_detector_high_packet_count() {
        let detector = RuleDetector::new();
        let mut flow = make_test_flow();
        flow.packet_count = 2000;

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert!(finding.score > 0.0);
    }

    #[test]
    fn test_rule_detector_clean_flow() {
        let detector = RuleDetector::new();
        let flow = make_test_flow();

        let finding = detector.evaluate(&flow);
        assert_eq!(finding.status, DetectorStatus::Completed);
        assert_eq!(finding.score, 0.0);
        assert!(finding.evidence.is_empty());
    }

    // -----------------------------------------------------------------------
    // run_detectors integration
    // -----------------------------------------------------------------------

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
        let mut cb = HashMap::new();

        let findings = run_detectors(&detectors, &flow, timeout, &mut cb);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].status, DetectorStatus::Completed);
        assert_eq!(findings[1].status, DetectorStatus::TimedOut);
        // SlowDetector should have Closed { failures: 1 }.
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Closed { failures: 1 })
        ));
    }

    // -----------------------------------------------------------------------
    // Circuit breaker state machine tests
    // -----------------------------------------------------------------------

    /// Opens after MAX_FAILURES consecutive failures.
    #[test]
    fn test_circuit_opens_after_threshold() {
        let detectors: Vec<Arc<dyn Detector>> = vec![Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        })];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();

        // Fail MAX_FAILURES times.
        for _ in 0..MAX_FAILURES {
            let findings = run_detectors(&detectors, &flow, timeout, &mut cb);
            assert_eq!(findings[0].status, DetectorStatus::TimedOut);
        }
        // Should be Open now.
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Open { .. })
        ));
    }

    /// Skips detector while circuit is open.
    #[test]
    fn test_circuit_skips_while_open() {
        let detectors: Vec<Arc<dyn Detector>> = vec![Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        })];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();

        // Trip the circuit.
        for _ in 0..MAX_FAILURES {
            run_detectors(&detectors, &flow, timeout, &mut cb);
        }

        // Should skip — returns instantly with zero latency.
        let start = Instant::now();
        let findings = run_detectors(&detectors, &flow, timeout, &mut cb);
        let elapsed = start.elapsed();

        assert_eq!(findings[0].status, DetectorStatus::TimedOut);
        assert_eq!(findings[0].latency_us, 0);
        assert!(
            elapsed < Duration::from_millis(10),
            "skipped detector should return instantly",
        );
    }

    /// Transitions to HalfOpen after cooldown expires.
    #[test]
    fn test_circuit_half_open_after_cooldown() {
        let detectors: Vec<Arc<dyn Detector>> = vec![Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        })];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();

        // Trip the circuit.
        for _ in 0..MAX_FAILURES {
            run_detectors(&detectors, &flow, timeout, &mut cb);
        }
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Open { .. })
        ));

        // Manually set opened_at to the past so cooldown has expired.
        if let Some(CircuitState::Open {
            ref mut opened_at, ..
        }) = cb.get_mut(&DetectorId::Custom(999))
        {
            *opened_at = Instant::now() - COOLDOWN - Duration::from_secs(1);
        }

        // Next run should transition to HalfOpen and allow execution.
        let findings = run_detectors(&detectors, &flow, timeout, &mut cb);
        // SlowDetector will timeout again → should transition back to Open.
        assert_eq!(findings[0].status, DetectorStatus::TimedOut);
        // Should be Open again (probe failed).
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Open { .. })
        ));
    }

    /// Successful half-open probe closes the circuit.
    #[test]
    fn test_circuit_half_open_success_closes() {
        let should_fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let detectors: Vec<Arc<dyn Detector>> = vec![Arc::new(ControllableDetector {
            should_fail: should_fail.clone(),
        })];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(200);
        let mut cb = HashMap::new();

        // Trip the circuit (5 failures).
        for _ in 0..MAX_FAILURES {
            run_detectors(&detectors, &flow, timeout, &mut cb);
        }
        assert!(matches!(
            cb.get(&DetectorId::Custom(997)),
            Some(CircuitState::Open { .. })
        ));

        // Expire the cooldown.
        if let Some(CircuitState::Open {
            ref mut opened_at, ..
        }) = cb.get_mut(&DetectorId::Custom(997))
        {
            *opened_at = Instant::now() - COOLDOWN - Duration::from_secs(1);
        }

        // Now make the detector succeed.
        should_fail.store(false, std::sync::atomic::Ordering::Relaxed);

        // Half-open probe should succeed → circuit closes.
        let findings = run_detectors(&detectors, &flow, timeout, &mut cb);
        assert_eq!(findings[0].status, DetectorStatus::Completed);
        // Circuit should be cleared (Closed state removed = no entry).
        assert!(
            !cb.contains_key(&DetectorId::Custom(997)),
            "successful probe should clear circuit (remove entry)"
        );
    }

    /// Failed half-open probe reopens the circuit.
    #[test]
    fn test_circuit_half_open_failure_reopens() {
        let detectors: Vec<Arc<dyn Detector>> = vec![Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        })];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();

        // Trip the circuit.
        for _ in 0..MAX_FAILURES {
            run_detectors(&detectors, &flow, timeout, &mut cb);
        }

        // Expire the cooldown.
        if let Some(CircuitState::Open {
            ref mut opened_at, ..
        }) = cb.get_mut(&DetectorId::Custom(999))
        {
            *opened_at = Instant::now() - COOLDOWN - Duration::from_secs(1);
        }

        // Probe attempt — SlowDetector will timeout again.
        let findings = run_detectors(&detectors, &flow, timeout, &mut cb);
        assert_eq!(findings[0].status, DetectorStatus::TimedOut);

        // Should be back to Open with a fresh timer.
        match cb.get(&DetectorId::Custom(999)) {
            Some(CircuitState::Open { opened_at, .. }) => {
                // opened_at should be very recent (just reset).
                assert!(
                    opened_at.elapsed() < Duration::from_secs(2),
                    "Open timer should be freshly reset"
                );
            }
            other => panic!("expected Open, got {:?}", other),
        }
    }

    /// Multiple detectors maintain independent circuit breaker state.
    #[test]
    fn test_circuit_independent_per_detector() {
        let detectors: Vec<Arc<dyn Detector>> = vec![
            Arc::new(SlowDetector {
                sleep_duration: Duration::from_millis(500),
            }),
            Arc::new(ErrorDetector),
        ];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();

        // Run until SlowDetector trips (5 timeouts).
        for _ in 0..MAX_FAILURES {
            run_detectors(&detectors, &flow, timeout, &mut cb);
        }

        // SlowDetector should be Open.
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Open { .. })
        ));

        // ErrorDetector also tripped — 5 errors = MAX_FAILURES → Open.
        assert!(matches!(
            cb.get(&DetectorId::Custom(998)),
            Some(CircuitState::Open { .. })
        ));

        // Expire SlowDetector's cooldown.
        if let Some(CircuitState::Open {
            ref mut opened_at, ..
        }) = cb.get_mut(&DetectorId::Custom(999))
        {
            *opened_at = Instant::now() - COOLDOWN - Duration::from_secs(1);
        }

        // Run again — SlowDetector gets a probe (will timeout → back to Open),
        // ErrorDetector trips to Open.
        run_detectors(&detectors, &flow, timeout, &mut cb);

        // Both should be Open now.
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Open { .. })
        ));
        assert!(matches!(
            cb.get(&DetectorId::Custom(998)),
            Some(CircuitState::Open { .. })
        ));
    }

    /// Success resets the circuit breaker (any state → Closed cleared).
    #[test]
    fn test_circuit_success_resets() {
        let detectors: Vec<Arc<dyn Detector>> = vec![Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        })];
        let flow = make_test_flow();
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();

        // Fail 3 times (below threshold).
        for _ in 0..3 {
            run_detectors(&detectors, &flow, timeout, &mut cb);
        }
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Closed { failures: 3, .. })
        ));

        // Now use a detector that completes instantly.
        let fast: Vec<Arc<dyn Detector>> = vec![Arc::new(RuleDetector::new())];
        let findings = run_detectors(&fast, &flow, timeout, &mut cb);
        assert_eq!(findings[0].status, DetectorStatus::Completed);

        // RuleEngine should have no entry (clean reset).
        assert!(!cb.contains_key(&DetectorId::RuleEngine));
        // SlowDetector's state should be untouched.
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Closed { failures: 3, .. })
        ));
    }
}
