// crates/agent/src/detectors/mod.rs
//
// Detector framework (§4b). Every detector implements the Detector trait
// from synapse-common. Production detectors are in separate sub-modules:
// dns_analyzer, process_correlator, flow_behavior, ip_reputation, dns_tunnel.
//
// Justification >600 lines: detectors/mod.rs contains the circuit breaker,
// run_detectors() orchestration, timeout enforcement, catch_unwind panic
// safety, and RuleDetector (placeholder v1). Infrastructure is tightly
// coupled to detector lifecycle — splitting would scatter error handling
// across files.

pub mod dns_analyzer;
pub mod dns_tunnel;
pub mod flow_behavior;
pub mod ip_reputation;
pub mod process_correlator;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use synapse_common::{Detector, DetectorFinding, DetectorId, DetectorStatus, FlowRecord};

use log::{debug, info};

// ---------------------------------------------------------------------------
// Circuit Breaker — per-detector failure tracking with recovery
// ---------------------------------------------------------------------------

/// Configuration for the circuit breaker. Loaded from TOML config or defaults.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the circuit opens.
    pub max_failures: u32,
    /// How long the circuit stays open before attempting recovery.
    pub cooldown: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            cooldown: Duration::from_secs(30),
        }
    }
}

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
    fn is_open(&self, now: Instant, cooldown: Duration) -> bool {
        match self {
            CircuitState::Closed { .. } => false,
            CircuitState::Open { opened_at, .. } => now.duration_since(*opened_at) < cooldown,
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
    flow: Arc<FlowRecord>,
    timeout: Duration,
    circuit_breaker: &mut HashMap<DetectorId, CircuitState>,
    cb_config: &CircuitBreakerConfig,
) -> Vec<DetectorFinding> {
    let now = Instant::now();

    detectors
        .iter()
        .map(|d| {
            let id = d.id();

            // State check — decide whether to run or skip.
            let should_skip = match circuit_breaker.get(&id) {
                Some(CircuitState::Closed { .. }) => false,
                Some(state) if state.is_open(now, cb_config.cooldown) => true,
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

            let finding = synapse_common::run_detector_with_timeout(
                Arc::clone(d),
                Arc::clone(&flow),
                timeout,
            );

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
                            if new_failures >= cb_config.max_failures {
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
    use synapse_common::{Evidence, Severity};

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
            a_ip: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            b_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
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
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(5),
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
        let flow = Arc::new(make_test_flow());
        let budget = Duration::from_millis(50);

        let start = Instant::now();
        let finding =
            synapse_common::run_detector_with_timeout(Arc::clone(&detector), flow, budget);
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
        let flow = Arc::new(make_test_flow());
        let budget = Duration::from_millis(200);

        let finding =
            synapse_common::run_detector_with_timeout(Arc::clone(&detector), flow, budget);

        assert_eq!(finding.status, DetectorStatus::Completed);
        assert_eq!(finding.score, 1.0);
    }

    // -----------------------------------------------------------------------
    // run_detectors integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_detectors_with_timeout() {
        let detectors: Vec<Arc<dyn Detector>> = vec![
            Arc::new(dns_analyzer::DnsAnalyzer::new()),
            Arc::new(SlowDetector {
                sleep_duration: Duration::from_millis(500),
            }),
        ];
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();

        let findings = run_detectors(
            &detectors,
            flow,
            timeout,
            &mut cb,
            &CircuitBreakerConfig::default(),
        );

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

    /// Opens after max_failures consecutive failures.
    #[test]
    fn test_circuit_opens_after_threshold() {
        let detectors: Vec<Arc<dyn Detector>> = vec![Arc::new(SlowDetector {
            sleep_duration: Duration::from_millis(500),
        })];
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();
        let cb_config = CircuitBreakerConfig::default();

        // Fail max_failures times.
        for _ in 0..cb_config.max_failures {
            let findings =
                run_detectors(&detectors, Arc::clone(&flow), timeout, &mut cb, &cb_config);
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
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();
        let cb_config = CircuitBreakerConfig::default();

        // Trip the circuit.
        for _ in 0..cb_config.max_failures {
            run_detectors(&detectors, Arc::clone(&flow), timeout, &mut cb, &cb_config);
        }

        // Should skip — returns instantly with zero latency.
        let start = Instant::now();
        let findings = run_detectors(&detectors, flow, timeout, &mut cb, &cb_config);
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
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();
        let cb_config = CircuitBreakerConfig::default();

        // Trip the circuit.
        for _ in 0..cb_config.max_failures {
            run_detectors(&detectors, Arc::clone(&flow), timeout, &mut cb, &cb_config);
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
            *opened_at = Instant::now() - cb_config.cooldown - Duration::from_secs(1);
        }

        // Next run should transition to HalfOpen and allow execution.
        let findings = run_detectors(&detectors, flow, timeout, &mut cb, &cb_config);
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
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(200);
        let mut cb = HashMap::new();
        let cb_config = CircuitBreakerConfig::default();

        // Trip the circuit (5 failures).
        for _ in 0..cb_config.max_failures {
            run_detectors(&detectors, Arc::clone(&flow), timeout, &mut cb, &cb_config);
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
            *opened_at = Instant::now() - cb_config.cooldown - Duration::from_secs(1);
        }

        // Now make the detector succeed.
        should_fail.store(false, std::sync::atomic::Ordering::Relaxed);

        // Half-open probe should succeed → circuit closes.
        let findings = run_detectors(&detectors, flow, timeout, &mut cb, &cb_config);
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
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();
        let cb_config = CircuitBreakerConfig::default();

        // Trip the circuit.
        for _ in 0..cb_config.max_failures {
            run_detectors(&detectors, Arc::clone(&flow), timeout, &mut cb, &cb_config);
        }

        // Expire the cooldown.
        if let Some(CircuitState::Open {
            ref mut opened_at, ..
        }) = cb.get_mut(&DetectorId::Custom(999))
        {
            *opened_at = Instant::now() - cb_config.cooldown - Duration::from_secs(1);
        }

        // Probe attempt — SlowDetector will timeout again.
        let findings = run_detectors(&detectors, flow, timeout, &mut cb, &cb_config);
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
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();
        let cb_config = CircuitBreakerConfig::default();

        // Run until SlowDetector trips (5 timeouts).
        for _ in 0..cb_config.max_failures {
            run_detectors(&detectors, Arc::clone(&flow), timeout, &mut cb, &cb_config);
        }

        // SlowDetector should be Open.
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Open { .. })
        ));

        // ErrorDetector also tripped — 5 errors = max_failures → Open.
        assert!(matches!(
            cb.get(&DetectorId::Custom(998)),
            Some(CircuitState::Open { .. })
        ));

        // Expire SlowDetector's cooldown.
        if let Some(CircuitState::Open {
            ref mut opened_at, ..
        }) = cb.get_mut(&DetectorId::Custom(999))
        {
            *opened_at = Instant::now() - cb_config.cooldown - Duration::from_secs(1);
        }

        // Run again — SlowDetector gets a probe (will timeout → back to Open),
        // ErrorDetector trips to Open.
        run_detectors(&detectors, flow, timeout, &mut cb, &cb_config);

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
        let flow = Arc::new(make_test_flow());
        let timeout = Duration::from_millis(50);
        let mut cb = HashMap::new();
        let cb_config = CircuitBreakerConfig::default();

        // Fail 3 times (below threshold).
        for _ in 0..3 {
            run_detectors(&detectors, Arc::clone(&flow), timeout, &mut cb, &cb_config);
        }
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Closed { failures: 3, .. })
        ));

        // Now use a detector that completes instantly.
        let fast: Vec<Arc<dyn Detector>> = vec![Arc::new(dns_analyzer::DnsAnalyzer::new())];
        let findings = run_detectors(&fast, flow, timeout, &mut cb, &cb_config);
        assert_eq!(findings[0].status, DetectorStatus::Completed);

        // DnsAnalyzer should have no entry (clean reset — no failures).
        assert!(!cb.contains_key(&DetectorId::DnsAnalyzer));
        // SlowDetector's state should be untouched.
        assert!(matches!(
            cb.get(&DetectorId::Custom(999)),
            Some(CircuitState::Closed { failures: 3, .. })
        ));
    }
}
