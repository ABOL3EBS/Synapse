// This file exceeds 600 lines because all four sub-detectors (scan, DNS-burst,
// beaconing, connection-diversity) share CrossFlowState — the in-process state
// machine that record_connection() and evaluate() both access. Splitting would
// require either duplicating shared state or a new crate; both are worse.
// Documented per CLAUDE.md §Structural Rules.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use synapse_common::{
    Detector, DetectorFinding, DetectorId, DetectorStatus, Evidence, FlowRecord, Severity,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CrossFlowConfig {
    pub window_secs: u64,
    // Scan detection.
    pub scan_connection_threshold_high: u64,
    pub scan_connection_threshold_medium: u64,
    // DNS burst detection.
    pub dns_burst_threshold_high: u64,
    pub dns_burst_threshold_medium: u64,
    // Beaconing detection.
    pub beacon_min_connections_medium: usize, // ≥5 connections required
    pub beacon_min_connections_high: usize,   // ≥10 connections required
    pub beacon_cv_medium: f64,                // CV < 0.3 for medium tier
    pub beacon_cv_high: f64,                  // CV < 0.2 for high tier
    pub beacon_mean_min_secs: f64,            // lower bound on mean interval (2.0s)
    pub max_beacon_entries: usize,            // per-(ip,port,proto) cap (200)
    // Connection-diversity detection.
    pub max_pid_entries: usize,         // per-PID VecDeque cap (512)
    pub max_tracked_pids: usize,        // total PID map cap (1024)
    pub pid_diversity_window_secs: u64, // rolling window for diversity (10s)
    pub pid_diversity_threshold_medium: usize, // >20 distinct IPs → medium
    pub pid_diversity_threshold_high: usize, // >50 distinct IPs → high
}

impl Default for CrossFlowConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            // 200/100: these thresholds apply per-(pid, remote_ip) — not the old
            // aggregate-all-PIDs counter. A single process making >200 connections
            // to one IP in 60s is genuinely anomalous; 20 browser tabs each making
            // 10 connections increments 20 separate (pid, ip) entries, none of
            // which crosses 200. Port scans operate in the thousands/min range.
            scan_connection_threshold_high: 200,
            scan_connection_threshold_medium: 100,
            dns_burst_threshold_high: 80,
            dns_burst_threshold_medium: 30,
            beacon_min_connections_medium: 5,
            beacon_min_connections_high: 10,
            beacon_cv_medium: 0.3,
            beacon_cv_high: 0.2,
            beacon_mean_min_secs: 2.0,
            max_beacon_entries: 200,
            max_pid_entries: 512,
            max_tracked_pids: 1024,
            pid_diversity_window_secs: 10,
            pid_diversity_threshold_medium: 20,
            pid_diversity_threshold_high: 50,
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct IpFlowStats {
    connection_count: u64,
    dns_query_count: u64,
    last_seen: Instant,
}

pub struct CrossFlowState {
    // Key: (pid, remote_ip). Keying by (pid, IpAddr) rather than IpAddr alone
    // ensures the scan-connection counter measures one *process*'s connection
    // rate to one IP — not the aggregate of every PID on the machine. The old
    // IpAddr-only key meant 20 browser tabs × 10 connections each = 200 against
    // the same AWS endpoint, identical signal to 1 malicious process × 200.
    // pid=0 is the sentinel for flows where PID attribution failed at BPF time.
    ip_stats: HashMap<(u32, IpAddr), IpFlowStats>,
    // Per-(remote_ip, remote_port, protocol) arrival timestamps for beaconing.
    beacon_history: HashMap<(IpAddr, u16, u8), VecDeque<Instant>>,
    // Per-PID remote IP history for connection-diversity.
    pid_diversity: HashMap<u32, VecDeque<(IpAddr, Instant)>>,
    config: CrossFlowConfig,
    // IPs excluded from per-destination counting. Live-refreshed: the caller
    // shares an Arc<ArcSwap<...>> that the own-ips-refresh thread updates every
    // 5s (own_ips ∪ {gateway} ∪ hardcoded API endpoints). is_excluded() calls
    // .load() on every evaluation so a network change takes effect within one
    // refresh cycle without restarting CrossFlowState.
    //
    // This is intentionally narrow: RFC1918 as a whole is NOT excluded, so
    // lateral movement against other LAN hosts remains visible. Protocol-level
    // infrastructure (255.255.255.255, 224.0.0.0/4, ff00::/8) is caught by
    // is_infrastructure_destination(), not this set.
    excluded_ips: Arc<ArcSwap<HashSet<IpAddr>>>,
}

impl CrossFlowState {
    pub fn new(config: CrossFlowConfig, excluded_ips: Arc<ArcSwap<HashSet<IpAddr>>>) -> Self {
        Self {
            ip_stats: HashMap::new(),
            beacon_history: HashMap::new(),
            pid_diversity: HashMap::new(),
            config,
            excluded_ips,
        }
    }

    fn is_excluded(&self, ip: IpAddr) -> bool {
        self.excluded_ips.load().contains(&ip) || crate::capture::is_infrastructure_destination(ip)
    }

    // Called for every new flow (not per-packet). remote_port is the
    // direction-resolved port of the remote endpoint, not info_pkt.dst_port.
    // pid=0 is the sentinel for flows where PID attribution failed at BPF time.
    pub fn record_connection(
        &mut self,
        pid: u32,
        remote_ip: IpAddr,
        protocol: u8,
        remote_port: u16,
    ) {
        if self.is_excluded(remote_ip) {
            log::debug!(
                "CrossFlow: dst={}:{} proto={} EXCLUDED (gateway/own-ip/api-endpoint/broadcast/multicast)",
                remote_ip,
                remote_port,
                protocol
            );
            return;
        }
        let now = Instant::now();
        let stats = self
            .ip_stats
            .entry((pid, remote_ip))
            .or_insert(IpFlowStats {
                connection_count: 0,
                dns_query_count: 0,
                last_seen: now,
            });
        stats.connection_count = stats.connection_count.saturating_add(1);
        stats.last_seen = now;
        // remote_port is already direction-resolved so port==53 means remote DNS.
        if protocol == 17 && remote_port == 53 {
            stats.dns_query_count = stats.dns_query_count.saturating_add(1);
        }
        let beacon = self
            .beacon_history
            .entry((remote_ip, remote_port, protocol))
            .or_default();
        if beacon.len() < self.config.max_beacon_entries {
            beacon.push_back(now);
        }
    }

    // Called for every new flow when the originating PID is known (pid != 0).
    pub fn record_pid_connection(&mut self, pid: u32, remote_ip: IpAddr) {
        if self.is_excluded(remote_ip) {
            return;
        }
        // Count-cap: don't add new PIDs when at capacity.
        if !self.pid_diversity.contains_key(&pid)
            && self.pid_diversity.len() >= self.config.max_tracked_pids
        {
            return;
        }
        let deque = self.pid_diversity.entry(pid).or_default();
        // Stop pushing at cap — evaluate() returns the cap-hit Critical tier.
        if deque.len() < self.config.max_pid_entries {
            deque.push_back((remote_ip, Instant::now()));
        }
    }

    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        let scan_cutoff = now - Duration::from_secs(self.config.window_secs);
        let pid_cutoff = now - Duration::from_secs(self.config.pid_diversity_window_secs);

        self.ip_stats.retain(|_, s| s.last_seen >= scan_cutoff); // key is (pid, IpAddr)

        self.beacon_history.retain(|_, deque| {
            while deque.front().is_some_and(|t| *t < scan_cutoff) {
                deque.pop_front();
            }
            !deque.is_empty()
        });

        self.pid_diversity.retain(|_, deque| {
            while deque.front().is_some_and(|(_, t)| *t < pid_cutoff) {
                deque.pop_front();
            }
            !deque.is_empty()
        });
    }

    pub fn get_stats(&self, pid: u32, ip: &IpAddr) -> Option<(u64, u64)> {
        self.ip_stats
            .get(&(pid, *ip))
            .map(|s| (s.connection_count, s.dns_query_count))
    }

    pub fn get_beacon_history(
        &self,
        ip: IpAddr,
        port: u16,
        proto: u8,
    ) -> Option<&VecDeque<Instant>> {
        self.beacon_history.get(&(ip, port, proto))
    }

    pub fn get_pid_diversity(&self, pid: u32) -> Option<&VecDeque<(IpAddr, Instant)>> {
        self.pid_diversity.get(&pid)
    }

    pub fn pid_diversity_at_cap(&self, pid: u32) -> bool {
        self.pid_diversity
            .get(&pid)
            .is_some_and(|d| d.len() >= self.config.max_pid_entries)
    }

    pub fn config(&self) -> &CrossFlowConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Scoring helpers (module-private, free functions for testability)
// ---------------------------------------------------------------------------

fn score_scan_dns(
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
fn compute_beacon_score(
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
// Returns (score, confidence, evidence, cap_hit).
// cap_hit = true means caller should emit an autonomous-override warn!.
//
// Score×confidence arithmetic (override_threshold = 0.85):
//   >20 tier: 0.30×0.40 = 0.12 — below alert; browser page-loads stay quiet
//   >50 tier: 0.50×0.55 = 0.275 — below alert; legitimate multi-host tools stay quiet
//   cap-hit:  0.90×0.95 = 0.855 ≥ 0.85 — crosses override_threshold → autonomous Block
fn compute_diversity_score(
    connections: &VecDeque<(IpAddr, Instant)>,
    pid: u32,
    cfg: &CrossFlowConfig,
    at_cap: bool,
) -> Option<(f32, f32, Evidence, bool)> {
    if at_cap {
        let ev = Evidence {
            description: format!(
                "Connection-diversity cap hit: {}+ distinct IPs from pid={} in <{}s",
                cfg.max_pid_entries, pid, cfg.pid_diversity_window_secs
            ),
            detail: Some(format!("pid={pid}")),
        };
        return Some((0.90, 0.95, ev, true));
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
        Some((0.50, 0.55, ev, false))
    } else if count > cfg.pid_diversity_threshold_medium {
        let ev = Evidence {
            description: format!(
                "Process pid={pid} connected to {count} distinct IPs in {}s",
                cfg.pid_diversity_window_secs
            ),
            detail: Some(format!("pid={pid}")),
        };
        Some((0.30, 0.40, ev, false))
    } else {
        None
    }
}

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
            if let Some((s, c, ev, cap_hit)) =
                compute_diversity_score(conns, pid, &snap.cfg, snap.pid_at_cap)
            {
                if cap_hit {
                    // Emitted at warn so it's distinct in operator logs.
                    // Known FP: nmap/masscan from the same user; see STATUS.md.
                    log::warn!(
                        "[BLOCK] AUTONOMOUS OVERRIDE: connection-diversity cap hit \
                         (512+ distinct IPs from pid={pid} in <10s) — \
                         if this was your own scan/audit tool, \
                         pause the agent before running network scans"
                    );
                }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn live_excluded(ips: impl IntoIterator<Item = IpAddr>) -> Arc<ArcSwap<HashSet<IpAddr>>> {
        Arc::new(ArcSwap::from_pointee(ips.into_iter().collect()))
    }

    fn make_flow(a_ip: IpAddr, b_ip: IpAddr) -> FlowRecord {
        FlowRecord {
            flow_id: 1,
            a_ip,
            b_ip,
            a_port: 50000,
            b_port: 443,
            protocol: 6,
            local_port: 50000,
            // pid: None → evaluate() uses unwrap_or(0) sentinel, matching test
            // record_connection calls which also use pid=0.
            pid: None,
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

    fn default_state() -> CrossFlowState {
        CrossFlowState::new(CrossFlowConfig::default(), live_excluded([]))
    }

    fn make_flow_with_pid(a_ip: IpAddr, b_ip: IpAddr, pid: u32) -> FlowRecord {
        FlowRecord {
            pid: Some(pid),
            ..make_flow(a_ip, b_ip)
        }
    }

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

    // ── Beaconing tests ─────────────────────────────────────────────────────

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

    // ── Connection-diversity tests ───────────────────────────────────────────

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
        let (score, conf, _, cap_hit) = result.unwrap();
        assert!((score - 0.30).abs() < 1e-6);
        assert!((conf - 0.40).abs() < 1e-6);
        assert!(!cap_hit);
    }

    #[test]
    fn test_diversity_fires_high_tier() {
        // 55 distinct IPs > threshold_high (50) → score 0.50
        let conns = make_diversity_deque(55);
        let cfg = CrossFlowConfig::default();
        let result = compute_diversity_score(&conns, 42, &cfg, false);
        assert!(result.is_some());
        let (score, conf, _, cap_hit) = result.unwrap();
        assert!((score - 0.50).abs() < 1e-6);
        assert!((conf - 0.55).abs() < 1e-6);
        assert!(!cap_hit);
    }

    #[test]
    fn test_diversity_cap_hit_tier() {
        // at_cap=true → Critical tier regardless of distinct-IP count.
        let conns = make_diversity_deque(512);
        let cfg = CrossFlowConfig::default();
        let result = compute_diversity_score(&conns, 99, &cfg, true);
        assert!(result.is_some());
        let (score, conf, _, cap_hit) = result.unwrap();
        assert!((score - 0.90).abs() < 1e-6, "cap-hit score must be 0.90");
        assert!(
            (conf - 0.95).abs() < 1e-6,
            "cap-hit confidence must be 0.95"
        );
        assert!(cap_hit);
    }

    // Explicit arithmetic check: 0.90 × 0.95 = 0.855 ≥ override_threshold (0.85).
    // If this fails, the cap-hit tier no longer triggers an autonomous Block.
    #[test]
    fn test_cap_hit_override_threshold_arithmetic() {
        let score = 0.90_f32;
        let confidence = 0.95_f32;
        let product = score * confidence;
        assert!(
            product >= 0.85,
            "cap-hit product {product:.4} must be ≥ 0.85 (override_threshold); \
             if this fails, cap-hit no longer triggers autonomous block"
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

        let (r_ip, r_port) =
            crate::capture::determine_remote_endpoint(local, 55000, remote, 53, local);

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
}
