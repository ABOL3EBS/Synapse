use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::super::scoring::compute_beacon_score;
use super::*;

// Constructs a VecDeque of n Instants with spacing_secs between each entry.
// Oldest entry is at `now - (n-1) * spacing_secs`.
fn make_beacon_history(n: usize, spacing_secs: u64) -> VecDeque<Instant> {
    let now = Instant::now();
    (0..n)
        .map(|i| now - Duration::from_secs((n - 1 - i) as u64 * spacing_secs))
        .collect()
}

#[test]
fn test_beacon_fires_medium_tier() {
    // 5 connections at 3s intervals → n=5, mean=3s, stddev=0, CV=0 < 0.3
    // mean_max = 60/4 = 15s; 3s < 15s ✓; beacon_mean_min=2s; 3s > 2s ✓
    let history = make_beacon_history(5, 3);
    let cfg = CrossFlowConfig::default();
    let result = compute_beacon_score(&history, &cfg);
    assert!(
        result.is_some(),
        "5 uniform-interval connections should fire"
    );
    let (score, conf, _) = result.unwrap();
    assert!(
        (score - 0.60).abs() < 1e-6,
        "medium tier score must be 0.60"
    );
    assert!((conf - 0.60).abs() < 1e-6, "medium tier conf must be 0.60");
}

#[test]
fn test_beacon_fires_high_tier() {
    // 10 connections at 3s intervals → CV=0 < 0.2 → high tier
    let history = make_beacon_history(10, 3);
    let cfg = CrossFlowConfig::default();
    let result = compute_beacon_score(&history, &cfg);
    assert!(
        result.is_some(),
        "10 uniform-interval connections should fire at high tier"
    );
    let (score, conf, _) = result.unwrap();
    assert!((score - 0.70).abs() < 1e-6, "high tier score must be 0.70");
    assert!((conf - 0.75).abs() < 1e-6, "high tier conf must be 0.75");
}

#[test]
fn test_beacon_suppressed_when_mean_exceeds_upper_bound() {
    // Monitoring-agent-like traffic: regular 16s interval but mean (16s) > mean_max (15s).
    // Pre-filter must exclude it to avoid false-positives from cron jobs, NTP, etc.
    let history = make_beacon_history(5, 16);
    let cfg = CrossFlowConfig::default(); // mean_max = 60/4 = 15s
    let result = compute_beacon_score(&history, &cfg);
    assert!(
        result.is_none(),
        "mean=16s > mean_max=15s must be excluded by pre-filter"
    );
}

#[test]
fn test_beacon_suppressed_when_fewer_than_min_connections() {
    // Only 4 connections → below beacon_min_connections_medium (5)
    let history = make_beacon_history(4, 3);
    let cfg = CrossFlowConfig::default();
    assert!(compute_beacon_score(&history, &cfg).is_none());
}

#[test]
fn test_beacon_suppressed_when_cv_too_high() {
    // High CV (irregular traffic) must not fire even with ≥5 connections.
    // Construct irregular intervals by mixing short and long gaps.
    let now = Instant::now();
    let history: VecDeque<Instant> = vec![
        now - Duration::from_secs(60),
        now - Duration::from_secs(55),
        now - Duration::from_secs(30),
        now - Duration::from_secs(29),
        now - Duration::from_secs(3),
    ]
    .into_iter()
    .collect();
    // Intervals: 5s, 25s, 1s, 26s → mean≈14.25s, stddev large, CV>>0.3
    let cfg = CrossFlowConfig::default();
    let result = compute_beacon_score(&history, &cfg);
    // mean≈14.25s is within [2s, 15s] but CV >> 0.3 → must not fire
    assert!(result.is_none(), "high-CV irregular traffic must not fire");
}
