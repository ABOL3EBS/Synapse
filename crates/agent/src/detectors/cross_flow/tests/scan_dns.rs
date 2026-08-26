// Scan / DNS-burst detection, plus the per-PID keying regression tests and
// the direction-resolution end-to-end tests (both exercise record_connection's
// scan/DNS counters and the beacon-history key, so they live alongside the
// scan/DNS tests rather than in their own cluster).

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use super::*;

// ── Per-PID keying regression tests ─────────────────────────────────────
//
// These two tests prove the specific false-positive class closed by
// changing ip_stats from HashMap<IpAddr, _> to HashMap<(u32, IpAddr), _>.
//
// Scenario that triggered repeated false-positive waves:
//   • Chrome/Brave window with 20 tabs to AWS CDN endpoints
//   • Each tab's helper process (distinct PID) makes ~10 connections/min
//   • Aggregate to same remote IP = ~200 — old code crossed threshold
//   • Each individual PID only made ~10 — obviously not a scanner
//
// The two tests bracket the fix: the negative case proves the old
// false-positive path is eliminated; the positive case proves a real
// single-process scan still fires exactly as expected.

#[test]
fn test_many_pids_each_below_threshold_do_not_fire() {
    // Mirrors the actual incident pattern:
    //   • Brave Browser opens 5 renderer/helper processes to an AWS CDN
    //   • Each process makes ~45 connections in 60s (normal page-load + keep-alives)
    //   • Old IpAddr-keyed code: aggregate = 5 × 45 = 225 → crosses high threshold
    //     (200) → autonomous Block of legitimate CDN IP
    //   • New (pid, IpAddr)-keyed code: each PID counter = 45, which is below
    //     the medium threshold (100) → score = 0 for every process
    //
    // This test fails against the old code and passes against the new code.
    // Numbers are derived from the actual incident (201-204 connections total
    // spread across multiple Brave Helper processes, all to AWS/Microsoft ranges).
    let state = Arc::new(Mutex::new(default_state()));
    let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(13, 107, 6, 152)); // CDN representative
    let local: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
    let pids: [u32; 5] = [8001, 8002, 8003, 8004, 8005]; // 5 Brave renderer/helper processes

    for &pid in &pids {
        for _ in 0..45 {
            state.lock().unwrap().record_connection(pid, remote, 6, 443);
        }
    }
    // Total connections to remote IP = 225 → would have fired (>200) under old code.
    // Each individual PID = 45 → below medium threshold (100) under new code.

    let detector = CrossFlowDetector::new(Arc::clone(&state));

    for &pid in &pids {
        let flow = make_flow_with_pid(remote, local, pid);
        let finding = detector.evaluate(&flow);
        assert_eq!(
            finding.score, 0.0,
            "pid={pid}: 45 connections from one process must not fire \
             (per-PID count 45 < medium threshold 100); \
             old aggregate-all-PIDs code produced 225 total and Blocked"
        );
    }
}

#[test]
fn test_single_pid_above_threshold_fires_with_new_keying() {
    // Positive case: one PID makes 201 connections to one IP.
    // Proves the structural fix did NOT widen the gap on the attack side —
    // a real port-scanner or C2 beacon still crosses the threshold.
    let state = Arc::new(Mutex::new(default_state()));
    let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)); // RFC 5737 test
    let local: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
    let scanner_pid: u32 = 31337;

    for _ in 0..201 {
        state
            .lock()
            .unwrap()
            .record_connection(scanner_pid, remote, 6, 443);
    }

    let detector = CrossFlowDetector::new(state);
    let flow = make_flow_with_pid(remote, local, scanner_pid);
    let finding = detector.evaluate(&flow);

    assert!(
        finding.score >= 0.9,
        "single-PID scan (201 connections) must still score ≥0.9 after per-PID rekey, \
         got {:.3}",
        finding.score
    );
    assert!(
        finding.confidence >= 0.9,
        "confidence must be ≥0.9, got {:.3}",
        finding.confidence
    );
    assert!(
        !finding.evidence.is_empty(),
        "evidence must be populated for a genuine scan finding"
    );
}

// ── Existing scan / DNS-burst tests ─────────────────────────────────────

#[test]
fn test_detector_score_zero_when_no_state() {
    let state = Arc::new(Mutex::new(default_state()));
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
    );
    let finding = detector.evaluate(&flow);
    assert_eq!(finding.score, 0.0, "No cross-flow state → score 0");
    assert_eq!(finding.confidence, 0.0);
}

#[test]
fn test_scan_detection_high_connection_count() {
    let state = Arc::new(Mutex::new(default_state()));
    let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202));
    for _ in 0..201 {
        state.lock().unwrap().record_connection(0, remote, 6, 443);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(remote, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    let finding = detector.evaluate(&flow);
    assert!(finding.score >= 0.9, "High conn count should score ≥0.9");
    assert!(finding.confidence >= 0.9);
    assert!(!finding.evidence.is_empty());
}

#[test]
fn test_scan_medium_connection_count() {
    let state = Arc::new(Mutex::new(default_state()));
    let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202));
    for _ in 0..150 {
        state.lock().unwrap().record_connection(0, remote, 6, 443);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(remote, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    let finding = detector.evaluate(&flow);
    assert!(finding.score >= 0.7 && finding.score < 0.9);
    assert!(finding.confidence >= 0.8);
}

#[test]
fn test_dns_burst_detection() {
    let state = Arc::new(Mutex::new(default_state()));
    let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    for _ in 0..85 {
        state.lock().unwrap().record_connection(0, remote, 17, 53);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(remote, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
    let finding = detector.evaluate(&flow);
    assert!(
        finding.score >= 0.8,
        "DNS burst should score ≥0.8, got {}",
        finding.score
    );
}

#[test]
fn test_both_ips_checked() {
    let state = Arc::new(Mutex::new(default_state()));
    let remote: IpAddr = IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202));
    for _ in 0..250 {
        state.lock().unwrap().record_connection(0, remote, 6, 443);
    }
    let detector = CrossFlowDetector::new(state);
    let flow = make_flow(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), remote);
    let finding = detector.evaluate(&flow);
    assert!(
        finding.score >= 0.9,
        "Should detect remote IP regardless of canonical ordering"
    );
}

// ── Direction-resolution end-to-end tests ───────────────────────────────
//
// These test the corrected remote_port path that was latently buggy before
// today's fix. The old capture.rs call used info_pkt.dst_port always —
// which is wrong for inbound flows (dst_port = local service port, not remote).
// determine_remote_endpoint() is now the canonical source; these tests verify
// its output flows through record_connection() correctly into both the
// DNS-query counter and the beacon_history key.

#[test]
fn test_inbound_to_local_dns_server_not_counted_as_dns_query() {
    // Pre-fix bug: inbound connection to local:53 had dst_port=53 passed to
    // record_connection, making dns_query_count increment for the remote IP —
    // as if we had sent a DNS query to it. After the fix, remote_port=src_port
    // (the remote's ephemeral) which is not 53, so dns_query_count stays 0.
    let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let remote = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let remote_ephemeral = 47382_u16;

    // Simulate determine_remote_endpoint() result for inbound src=remote:eph, dst=local:53.
    let (r_ip, r_port) =
        crate::capture::determine_remote_endpoint(remote, remote_ephemeral, local, 53, local);

    let mut state = default_state();
    state.record_connection(0, r_ip, 17 /* UDP */, r_port);

    // Connection count increments (a connection did happen).
    // DNS count must NOT increment (r_port != 53 — this was the bug).
    assert_eq!(
        state.get_stats(0, &remote),
        Some((1, 0)),
        "inbound to local:53: dns_query_count must be 0 \
         (was 1 before the remote_port direction fix)"
    );
}

#[test]
fn test_outbound_dns_query_counted_correctly() {
    // Outbound DNS: src=local:ephemeral, dst=remote:53.
    // determine_remote_endpoint returns (remote, 53) → dns_query_count increments.
    let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    let (r_ip, r_port) = crate::capture::determine_remote_endpoint(local, 55000, remote, 53, local);

    let mut state = default_state();
    state.record_connection(0, r_ip, 17, r_port);

    assert_eq!(
        state.get_stats(0, &remote),
        Some((1, 1)),
        "outbound DNS query: dns_query_count must be 1"
    );
}

#[test]
fn test_inbound_flows_share_beacon_key_on_remote_port() {
    // Pre-fix bug: inbound connections from the same C2 server (C2:443 → local:eph)
    // had dst_port=local_eph as the beacon key — different per connection, so no
    // beacon accumulates. After the fix, key=(C2, 443, TCP) for all inbound
    // connections regardless of local ephemeral port.
    let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let c2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

    let mut state = default_state();

    // 5 inbound connections from C2:443 to different local ephemeral ports.
    for local_eph in [60000_u16, 60001, 60002, 60003, 60004] {
        let (r_ip, r_port) =
            crate::capture::determine_remote_endpoint(c2, 443, local, local_eph, local);
        state.record_connection(0, r_ip, 6 /* TCP */, r_port);
    }

    // All 5 must be under the single key (c2, 443, TCP) — the remote port.
    assert_eq!(
        state.get_beacon_history(c2, 443, 6).map(|d| d.len()),
        Some(5),
        "5 inbound C2 connections must accumulate under beacon key (c2, 443, TCP)"
    );

    // Pre-fix: one entry per local ephemeral port — verify those keys are empty.
    for local_eph in [60000_u16, 60001, 60002, 60003, 60004] {
        assert!(
            state.get_beacon_history(c2, local_eph, 6).is_none(),
            "beacon must NOT be keyed on local ephemeral port {local_eph} (pre-fix bug)"
        );
    }
}
