use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use synapse_common::Evidence;

use super::CrossFlowConfig;

// ---------------------------------------------------------------------------
// Scoring helpers (module-private, free functions for testability)
// ---------------------------------------------------------------------------

pub(crate) fn score_scan_dns(
    ip: IpAddr,
    conn_count: u64,
    dns_count: u64,
    cfg: &CrossFlowConfig,
) -> (f32, f32, Vec<Evidence>) {
    let mut max_score = 0.0_f32;
    let mut max_conf = 0.0_f32;
    let mut ev: Vec<Evidence> = Vec::new();
    let w = cfg.window_secs;

    if conn_count > cfg.scan_connection_threshold_high {
        max_score = max_score.max(0.9);
        max_conf = max_conf.max(0.95);
        ev.push(Evidence {
            description: format!("High connection count to IP: {conn_count} connections in {w}s"),
            detail: Some(ip.to_string()),
        });
    } else if conn_count > cfg.scan_connection_threshold_medium {
        max_score = max_score.max(0.7);
        max_conf = max_conf.max(0.8);
        ev.push(Evidence {
            description: format!(
                "Elevated connection count to IP: {conn_count} connections in {w}s"
            ),
            detail: Some(ip.to_string()),
        });
    }
    if dns_count > cfg.dns_burst_threshold_high {
        max_score = max_score.max(0.8);
        max_conf = max_conf.max(0.7);
        ev.push(Evidence {
            description: format!("DNS query burst: {dns_count} queries to IP in {w}s"),
            detail: Some(ip.to_string()),
        });
    } else if dns_count > cfg.dns_burst_threshold_medium {
        max_score = max_score.max(0.5);
        max_conf = max_conf.max(0.5);
        ev.push(Evidence {
            description: format!("Elevated DNS queries: {dns_count} queries to IP in {w}s"),
            detail: Some(ip.to_string()),
        });
    }
    (max_score, max_conf, ev)
}

// Beaconing: coefficient-of-variation on per-endpoint inter-arrival times.
// Pre-filter: mean ∈ [beacon_mean_min_secs, window_secs/4].
// Upper bound derivation: 4 intervals × mean ≤ window_secs (5 connections span 4 intervals).
pub(crate) fn compute_beacon_score(
    history: &VecDeque<Instant>,
    cfg: &CrossFlowConfig,
) -> Option<(f32, f32, Evidence)> {
    let n = history.len();
    if n < cfg.beacon_min_connections_medium {
        return None;
    }
    let instants: Vec<Instant> = history.iter().cloned().collect();
    let intervals: Vec<f64> = instants
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_secs_f64())
        .collect();
    let n_f = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n_f;

    let mean_max = cfg.window_secs as f64 / 4.0;
    if mean < cfg.beacon_mean_min_secs || mean > mean_max {
        return None;
    }
    let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n_f;
    let stddev = variance.sqrt();
    if mean == 0.0 {
        return None;
    }
    let cv = stddev / mean;

    let ev = Evidence {
        description: format!(
            "Beacon-like periodicity: {n} connections, mean={mean:.1}s, CV={cv:.3}"
        ),
        detail: None,
    };
    if n >= cfg.beacon_min_connections_high && cv < cfg.beacon_cv_high {
        Some((0.70, 0.75, ev))
    } else if cv < cfg.beacon_cv_medium {
        Some((0.60, 0.60, ev))
    } else {
        None
    }
}

// Connection-diversity: distinct remote IPs from one PID in pid_diversity_window_secs.
// Returns (score, confidence, evidence).
//
// Score×confidence arithmetic (override_threshold = 0.85, block_threshold = 0.70):
//   >20 tier: 0.30×0.40 = 0.12 — below alert; browser page-loads stay quiet
//   >50 tier: 0.50×0.55 = 0.275 — below alert; legitimate multi-host tools stay quiet
//   cap-hit:  0.65×0.75 = 0.4875 — elevated signal, but requires corroboration to block;
//             cannot reach override_threshold (0.85) alone (intentional: cap is a
//             memory bound, not a detection verdict — we stopped counting, not proved malice)
pub(crate) fn compute_diversity_score(
    connections: &VecDeque<(IpAddr, Instant)>,
    pid: u32,
    cfg: &CrossFlowConfig,
    at_cap: bool,
) -> Option<(f32, f32, Evidence)> {
    if at_cap {
        let ev = Evidence {
            description: format!(
                "Connection-diversity tracking saturated: {}+ connections from pid={} in <{}s \
                 — corroboration required for enforcement",
                cfg.max_pid_entries, pid, cfg.pid_diversity_window_secs
            ),
            detail: Some(format!("pid={pid}")),
        };
        return Some((0.65, 0.75, ev));
    }
    let now = Instant::now();
    let window = Duration::from_secs(cfg.pid_diversity_window_secs);
    let distinct: HashSet<IpAddr> = connections
        .iter()
        .filter(|(_, t)| now.duration_since(*t) <= window)
        .map(|(ip, _)| *ip)
        .collect();
    let count = distinct.len();

    if count > cfg.pid_diversity_threshold_high {
        let ev = Evidence {
            description: format!(
                "Process pid={pid} connected to {count} distinct IPs in {}s",
                cfg.pid_diversity_window_secs
            ),
            detail: Some(format!("pid={pid}")),
        };
        Some((0.50, 0.55, ev))
    } else if count > cfg.pid_diversity_threshold_medium {
        let ev = Evidence {
            description: format!(
                "Process pid={pid} connected to {count} distinct IPs in {}s",
                cfg.pid_diversity_window_secs
            ),
            detail: Some(format!("pid={pid}")),
        };
        Some((0.30, 0.40, ev))
    } else {
        None
    }
}
