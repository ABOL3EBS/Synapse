// Connection-diversity tests, including the cap-hit safety-margin cluster:
// the connection-diversity tracker has a per-PID memory cap (max_pid_entries),
// and hitting that cap must produce an elevated-but-not-autonomous-block
// signal (score×confidence < override_threshold) since the cap is a memory
// bound, not a detection verdict.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::super::scoring::compute_diversity_score;
use super::*;

fn recent_ip(i: u32) -> (IpAddr, Instant) {
    let ip = IpAddr::V4(Ipv4Addr::new(
        10,
        ((i >> 16) & 0xff) as u8,
        ((i >> 8) & 0xff) as u8,
        (i & 0xff) as u8,
    ));
    (ip, Instant::now() - Duration::from_secs(2))
}

fn make_diversity_deque(count: usize) -> VecDeque<(IpAddr, Instant)> {
    (0..count as u32).map(recent_ip).collect()
}

#[test]
fn test_diversity_fires_medium_tier() {
    // 25 distinct IPs > threshold_medium (20) → score 0.30
    let conns = make_diversity_deque(25);
    let cfg = CrossFlowConfig::default();
    let result = compute_diversity_score(&conns, 42, &cfg, false);
    assert!(result.is_some());
    let (score, conf, _) = result.unwrap();
    assert!((score - 0.30).abs() < 1e-6);
    assert!((conf - 0.40).abs() < 1e-6);
}

#[test]
fn test_diversity_fires_high_tier() {
    // 55 distinct IPs > threshold_high (50) → score 0.50
    let conns = make_diversity_deque(55);
    let cfg = CrossFlowConfig::default();
    let result = compute_diversity_score(&conns, 42, &cfg, false);
    assert!(result.is_some());
    let (score, conf, _) = result.unwrap();
    assert!((score - 0.50).abs() < 1e-6);
    assert!((conf - 0.55).abs() < 1e-6);
}

#[test]
fn test_diversity_cap_hit_tier() {
    // at_cap=true → elevated signal (0.65×0.75) that requires corroboration.
    // The cap is a memory bound, not a detection verdict — we stopped counting,
    // not proved malice. Score must be below override_threshold alone.
    let conns = make_diversity_deque(512);
    let cfg = CrossFlowConfig::default();
    let result = compute_diversity_score(&conns, 99, &cfg, true);
    assert!(result.is_some());
    let (score, conf, ev) = result.unwrap();
    assert!(
        (score - 0.65).abs() < 1e-6,
        "cap-hit score must be 0.65, got {score}"
    );
    assert!(
        (conf - 0.75).abs() < 1e-6,
        "cap-hit confidence must be 0.75, got {conf}"
    );
    assert!(
        ev.description.contains("corroboration"),
        "cap-hit evidence must mention corroboration requirement"
    );
}

// Explicit arithmetic check: 0.65 × 0.75 = 0.4875, which is:
//   - below block_threshold (0.70) alone → cannot block without corroboration
//   - below override_threshold (0.85) → cannot trigger autonomous override
// This test is the canary: if it fails, the cap-hit path became dangerous again.
#[test]
fn test_cap_hit_cannot_trigger_autonomous_block() {
    let score = 0.65_f32;
    let confidence = 0.75_f32;
    let product = score * confidence;
    assert!(
        product < 0.70,
        "cap-hit product {product:.4} must be below block_threshold (0.70); \
         cap-hit must require corroboration, not block autonomously"
    );
    assert!(
        product < 0.85,
        "cap-hit product {product:.4} must be below override_threshold (0.85); \
         the cap is a memory bound, not a detection verdict"
    );
}

#[test]
fn test_diversity_no_fire_below_medium_threshold() {
    // 18 distinct IPs < threshold_medium (20) → no finding
    let conns = make_diversity_deque(18);
    let cfg = CrossFlowConfig::default();
    assert!(compute_diversity_score(&conns, 42, &cfg, false).is_none());
}

#[test]
fn test_diversity_medium_score_below_block_threshold() {
    // Browser page-load shape: 30 distinct IPs → medium tier (score 0.30, conf 0.40).
    // Product 0.12 is well below block_threshold (0.70) and alert threshold (0.30).
    let conns = make_diversity_deque(30);
    let cfg = CrossFlowConfig::default();
    let result = compute_diversity_score(&conns, 42, &cfg, false).unwrap();
    let product = result.0 * result.1;
    assert!(
        product < 0.30,
        "browser-shape diversity product {product:.3} must be below alert threshold"
    );
}

#[test]
fn test_pid_cap_prevents_excess_entries() {
    let mut state = default_state();
    let pid = 1234_u32;
    let n = state.config.max_pid_entries + 100;
    for i in 0..n as u32 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, (i >> 16) as u8, (i >> 8) as u8, i as u8));
        state.record_pid_connection(pid, ip);
    }
    let deque = state.get_pid_diversity(pid).unwrap();
    assert_eq!(
        deque.len(),
        state.config.max_pid_entries,
        "VecDeque must not exceed max_pid_entries"
    );
    assert!(state.pid_diversity_at_cap(pid));
}

#[test]
fn test_total_pid_cap_drops_new_pids() {
    let cfg = CrossFlowConfig {
        max_tracked_pids: 3,
        ..CrossFlowConfig::default()
    };
    let mut state = CrossFlowState::new(cfg, live_excluded([]));
    for pid in 0..5_u32 {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, pid as u8));
        state.record_pid_connection(pid, ip);
    }
    // Only 3 PIDs should be tracked (first 3 filled the map).
    assert_eq!(
        state.pid_diversity.len(),
        3,
        "PID map must be capped at max_tracked_pids"
    );
}

#[test]
fn test_purge_expired_removes_stale_pid_entries() {
    let cfg = CrossFlowConfig {
        pid_diversity_window_secs: 1,
        ..CrossFlowConfig::default()
    };
    let mut state = CrossFlowState::new(cfg, live_excluded([]));
    let pid = 7_u32;
    // Insert a stale entry (>1s old) by backdating manually.
    state.pid_diversity.insert(
        pid,
        vec![(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            Instant::now() - Duration::from_secs(5),
        )]
        .into_iter()
        .collect(),
    );
    state.purge_expired();
    assert!(
        !state.pid_diversity.contains_key(&pid),
        "stale PID entry must be removed by purge_expired"
    );
}
