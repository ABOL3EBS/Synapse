use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use super::CrossFlowConfig;

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
    pub(crate) pid_diversity: HashMap<u32, VecDeque<(IpAddr, Instant)>>,
    pub(crate) config: CrossFlowConfig,
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

    pub(crate) fn is_excluded(&self, ip: IpAddr) -> bool {
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
