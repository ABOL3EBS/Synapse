// Gateway / broadcast / multicast exclusion, and the ArcSwap live-refresh
// property (incident: 2026-08-04 — a static excluded_ips HashSet meant a
// post-startup gateway/network change left the old gateway un-excluded).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use super::*;

#[test]
fn test_gateway_ip_excluded_from_counting() {
    let gateway: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let state = Arc::new(Mutex::new(CrossFlowState::new(
        CrossFlowConfig::default(),
        live_excluded([gateway]),
    )));
    for _ in 0..250 {
        state.lock().unwrap().record_connection(0, gateway, 6, 443);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(gateway, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
    let finding = detector.evaluate(&flow);
    assert_eq!(
        finding.score, 0.0,
        "Gateway IP must not contribute to score"
    );
    assert!(finding.evidence.is_empty());
}

#[test]
fn test_lan_host_still_counted_when_gateway_excluded() {
    let gateway: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let lan_host: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    let state = Arc::new(Mutex::new(CrossFlowState::new(
        CrossFlowConfig::default(),
        live_excluded([gateway]),
    )));
    for _ in 0..250 {
        state.lock().unwrap().record_connection(0, lan_host, 6, 445);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(lan_host, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    let finding = detector.evaluate(&flow);
    assert!(
        finding.score >= 0.9,
        "Lateral movement to LAN host must still score high, got {}",
        finding.score
    );
}

#[test]
fn test_multicast_destination_not_counted() {
    let state = Arc::new(Mutex::new(default_state()));
    let mdns_multicast: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
    for _ in 0..250 {
        state
            .lock()
            .unwrap()
            .record_connection(0, mdns_multicast, 17, 5353);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 43)), mdns_multicast);
    let finding = detector.evaluate(&flow);
    assert_eq!(
        finding.score, 0.0,
        "Multicast destination must not contribute to score"
    );
}

#[test]
fn test_subnet_broadcast_not_counted() {
    let subnet_bcast: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 18, 22, 255));
    let state = Arc::new(Mutex::new(CrossFlowState::new(
        CrossFlowConfig::default(),
        live_excluded([subnet_bcast]),
    )));
    for _ in 0..250 {
        state
            .lock()
            .unwrap()
            .record_connection(0, subnet_bcast, 17, 137);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(IpAddr::V4(Ipv4Addr::new(172, 18, 22, 43)), subnet_bcast);
    let finding = detector.evaluate(&flow);
    assert_eq!(
        finding.score, 0.0,
        "Subnet broadcast destination must not contribute to score"
    );
}

#[test]
fn test_beacon_infrastructure_not_recorded() {
    // Broadcast and multicast must be excluded at record_connection time
    // and therefore never appear in beacon_history.
    let mut state = default_state();
    let bcast: IpAddr = IpAddr::V4(Ipv4Addr::BROADCAST);
    let mcast: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
    for _ in 0..20 {
        state.record_connection(0, bcast, 17, 9999);
        state.record_connection(0, mcast, 17, 9998);
    }
    assert!(
        state.get_beacon_history(bcast, 9999, 17).is_none(),
        "broadcast must not enter beacon_history"
    );
    assert!(
        state.get_beacon_history(mcast, 9998, 17).is_none(),
        "multicast must not enter beacon_history"
    );
}

#[test]
fn test_pid_infrastructure_not_recorded() {
    let mut state = default_state();
    let mcast: IpAddr = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
    state.record_pid_connection(999, mcast);
    assert!(
        state.get_pid_diversity(999).is_none(),
        "multicast must not enter pid_diversity"
    );
}

// ── Live-refresh property ────────────────────────────────────────────────
//
// This test proves the specific bug class closed on 2026-08-04:
// CrossFlowState::excluded_ips was a static HashSet, so a network change
// (new gateway, new own IP) after agent startup meant the old gateway IP
// remained un-excluded. The fix replaces the owned set with an
// Arc<ArcSwap<...>> that the own-ips-refresh thread updates every 5s.
//
// The test exercises the live-update path directly: the ArcSwap is swapped
// while CrossFlowState is alive and no restart occurs.
#[test]
fn test_excluded_ips_live_updates_without_restart() {
    let target: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let local: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // Start with empty exclusion set — target is NOT excluded.
    let live_set = live_excluded([]);
    let state = Arc::new(Mutex::new(CrossFlowState::new(
        CrossFlowConfig::default(),
        live_set.clone(),
    )));

    // Drive enough connections to trigger scan detection.
    for _ in 0..250 {
        state.lock().unwrap().record_connection(0, target, 6, 443);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(target, local);

    let before = detector.evaluate(&flow);
    assert!(
        before.score > 0.0,
        "target must score nonzero before exclusion (got {})",
        before.score
    );

    // Simulate the own-ips-refresh thread updating the ArcSwap: target IP
    // is now the gateway (or a new own IP). No CrossFlowState reconstruction.
    let mut new_set = HashSet::new();
    new_set.insert(target);
    live_set.store(Arc::new(new_set));

    // Same CrossFlowState, same CrossFlowDetector — score must now be 0.
    let after = detector.evaluate(&flow);
    assert_eq!(
        after.score, 0.0,
        "target must score 0 after ArcSwap refresh without restarting CrossFlowState"
    );
    assert!(
        after.evidence.is_empty(),
        "no evidence must be emitted for an excluded IP"
    );
}
