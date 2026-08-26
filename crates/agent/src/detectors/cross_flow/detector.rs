use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use synapse_common::{Detector, DetectorFinding, DetectorId, DetectorStatus, FlowRecord, Severity};

use super::scoring::{compute_beacon_score, compute_diversity_score, score_scan_dns};
use super::state::CrossFlowState;
use super::CrossFlowConfig;

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

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

// Holds a snapshot of the state needed by evaluate(), copied while the lock
// is held so scoring runs outside the lock.
struct CrossFlowSnapshot {
    stats_a: Option<(u64, u64)>,
    stats_b: Option<(u64, u64)>,
    beacon_a: Option<VecDeque<Instant>>,
    beacon_b: Option<VecDeque<Instant>>,
    pid_conns: Option<VecDeque<(IpAddr, Instant)>>,
    pid_at_cap: bool,
    cfg: CrossFlowConfig,
}

impl CrossFlowDetector {
    fn snapshot(&self, flow: &FlowRecord) -> Result<CrossFlowSnapshot, &'static str> {
        let state = self
            .cross_flow_state
            .lock()
            .map_err(|_| "cross-flow state lock poisoned")?;
        let a_ok = !state.is_excluded(flow.a_ip);
        let b_ok = !state.is_excluded(flow.b_ip);
        if !a_ok {
            log::debug!("CrossFlow eval: a_ip={} EXCLUDED", flow.a_ip);
        }
        if !b_ok {
            log::debug!("CrossFlow eval: b_ip={} EXCLUDED", flow.b_ip);
        }
        // Use the flow's PID for the per-(pid, ip) lookup so the scan counter
        // reflects this process's connection rate, not all processes combined.
        let pid = flow.pid.unwrap_or(0);
        let stats_a = if a_ok {
            state.get_stats(pid, &flow.a_ip)
        } else {
            None
        };
        let stats_b = if b_ok {
            state.get_stats(pid, &flow.b_ip)
        } else {
            None
        };
        // Beacon history checked against both canonical (ip, port) pairs; the
        // one that matches the recorded remote endpoint will return Some.
        let beacon_a = if a_ok {
            state
                .get_beacon_history(flow.a_ip, flow.a_port, flow.protocol)
                .cloned()
        } else {
            None
        };
        let beacon_b = if b_ok {
            state
                .get_beacon_history(flow.b_ip, flow.b_port, flow.protocol)
                .cloned()
        } else {
            None
        };
        let (pid_conns, pid_at_cap) = match flow.pid {
            Some(pid) => (
                state.get_pid_diversity(pid).cloned(),
                state.pid_diversity_at_cap(pid),
            ),
            None => (None, false),
        };
        Ok(CrossFlowSnapshot {
            stats_a,
            stats_b,
            beacon_a,
            beacon_b,
            pid_conns,
            pid_at_cap,
            cfg: state.config().clone(),
        })
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
        let snap = match self.snapshot(flow) {
            Ok(s) => s,
            Err(msg) => {
                return DetectorFinding::errored(DetectorId::CrossFlow, "1.0.0", msg, 0);
            }
        };

        let mut evidence = Vec::new();
        let mut max_score = 0.0_f32;
        let mut max_conf = 0.0_f32;

        // Scan + DNS burst for each canonical IP.
        for (ip, opt) in [(flow.a_ip, snap.stats_a), (flow.b_ip, snap.stats_b)] {
            if let Some((conn, dns)) = opt {
                log::debug!("CrossFlow eval: ip={ip} conn_count={conn} dns_count={dns}");
                let (s, c, mut ev) = score_scan_dns(ip, conn, dns, &snap.cfg);
                if s > max_score {
                    max_score = s;
                    max_conf = c;
                }
                evidence.append(&mut ev);
            }
        }

        // Beaconing for each canonical (ip, port, protocol) key.
        for beacon in [snap.beacon_a.as_ref(), snap.beacon_b.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Some((s, c, ev)) = compute_beacon_score(beacon, &snap.cfg) {
                if s > max_score {
                    max_score = s;
                    max_conf = c;
                }
                evidence.push(ev);
            }
        }

        // Connection diversity for the flow's PID.
        if let (Some(conns), Some(pid)) = (snap.pid_conns.as_ref(), flow.pid) {
            if let Some((s, c, ev)) =
                compute_diversity_score(conns, pid, &snap.cfg, snap.pid_at_cap)
            {
                if s > max_score {
                    max_score = s;
                    max_conf = c;
                }
                evidence.push(ev);
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

        let severity = if max_score >= 0.85 {
            Severity::Critical
        } else if max_score >= 0.5 {
            Severity::High
        } else if max_score >= 0.3 {
            Severity::Medium
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
