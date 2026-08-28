// crates/agent/src/capture/mod.rs
//
// CaptureEngine — the hot-path core: BPF reads, flow tracker integration,
// enrichment dispatch, verdict handling, enforcement guards, and IPC send.
//
// This file used to be all of capture.rs (2306 lines) under a blanket claim
// that it couldn't be split because "everything shares CaptureEngine state."
// That claim was checked, not assumed: pure functions with zero `self`
// coupling were extracted out — BPF/IP parsing to `parse.rs` (verified 0
// `self` refs), direction resolution to `direction.rs` (0 `self` refs), and
// OS network-topology introspection (gateway/VPN/own-ips detection, called
// only from main.rs, never from CaptureEngine) to the top-level sibling
// `net_topology.rs`.
//
// What's left here is genuinely coupled: every method in `impl CaptureEngine`
// reads or mutates fields on `&mut self` — `bpf_fd`/`buf` (capture I/O),
// `tracker` (flow state), `cross_flow_state` (shared scan-detection state),
// `storage_tx`/`write_half` (IPC + persistence side effects), `caches`
// (lock-free ArcSwap snapshots read on every packet), `enrich_pool`,
// `decision_engine`, `detectors`/`circuit_breaker` (detector dispatch),
// `block_cooldown`, `pkt_count`, `ipc_failures`, and `config`. Splitting the
// `impl` block across files would not reduce that coupling — it would just
// add cross-file `self` field access. `handle_verdict` and
// `read_and_process_packets` still exceed the 80-line function limit; that
// is tracked separately (item 4b) as an internal-method extraction, the same
// pattern already used for `flush()`.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use log::{debug, error, info, warn};
use synapse_common::{EnforcementCommand, EnrichmentKind, EnrichmentRequest, ResolvedFlow};

use crate::detectors;
use crate::detectors::cross_flow::CrossFlowState;
use crate::enrichment::EnrichmentPool;
use crate::flow::{self, FlowTracker};
use crate::storage::StorageEvent;
use synapse_platform_macos::protocol;

mod direction;
mod parse;

use direction::determine_local_port;
pub use direction::determine_remote_endpoint;
use parse::{parse_ip_frame, BpfHdr};

// ---------------------------------------------------------------------------
// CaptureEngine configuration and shared-state bundles
// ---------------------------------------------------------------------------

/// Runtime tuning parameters — sourced from AgentConfig at startup.
/// Grouped to reduce CaptureEngine::new() argument count.
pub struct CaptureConfig {
    pub poll_timeout_ms: i32,
    pub detector_timeout: std::time::Duration,
    pub cb_config: detectors::CircuitBreakerConfig,
    pub gateway_ip: Option<IpAddr>,
}

/// Lock-free shared state updated by background threads (own-IPs refresh,
/// local-IP refresh, IPC port→PID cache). All reads on the hot path are
/// lock-free via ArcSwap::load().
pub struct NetworkCaches {
    pub local_ip: Arc<ArcSwap<Option<IpAddr>>>,
    pub own_ips: Arc<ArcSwap<HashSet<IpAddr>>>,
    pub port_pid: Arc<ArcSwap<HashMap<(u16, u8), u32>>>,
}

// ---------------------------------------------------------------------------
// CaptureEngine initialisation bundle
// ---------------------------------------------------------------------------

/// All arguments required to build a CaptureEngine, collected into a single
/// struct so CaptureEngine::new() stays under the clippy::too_many_arguments
/// threshold without suppression.
pub struct CaptureInit {
    // Capture I/O
    pub bpf_fd: RawFd,
    pub buf: Vec<u8>,
    pub write_half: UnixStream,
    // Runtime state
    pub caches: NetworkCaches,
    pub config: CaptureConfig,
    // Subsystem handles
    pub enrich_pool: EnrichmentPool,
    pub tracker: FlowTracker,
    pub decision_engine: crate::decision::DecisionEngine,
    pub detectors: Vec<Arc<dyn synapse_common::Detector>>,
    pub cross_flow_state: Arc<std::sync::Mutex<CrossFlowState>>,
    pub storage_tx: Option<crossbeam_channel::Sender<StorageEvent>>,
}

// ---------------------------------------------------------------------------
// CaptureEngine
// ---------------------------------------------------------------------------

pub struct CaptureEngine {
    bpf_fd: RawFd,
    buf: Vec<u8>,
    caches: NetworkCaches,
    enrich_pool: EnrichmentPool,
    tracker: FlowTracker,
    decision_engine: crate::decision::DecisionEngine,
    detectors: Vec<Arc<dyn synapse_common::Detector>>,
    config: CaptureConfig,
    circuit_breaker: HashMap<synapse_common::DetectorId, detectors::CircuitState>,
    block_cooldown: HashMap<IpAddr, Instant>,
    write_half: UnixStream,
    pkt_count: u64,
    /// Consecutive IPC send failures. Reset on success. Agent exits at threshold.
    ipc_failures: u32,
    /// Cross-flow state shared with CrossFlowDetector.
    cross_flow_state: Arc<std::sync::Mutex<CrossFlowState>>,
    /// Event sender for SQLite enforcement_log (None if storage unavailable).
    storage_tx: Option<crossbeam_channel::Sender<StorageEvent>>,
}

/// Consecutive IPC failures before the agent exits for launchd/systemd restart.
const MAX_IPC_FAILURES: u32 = 5;

/// Returns true if `ip` is a protocol-level infrastructure address that no
/// real host ever originates: the IPv4 limited broadcast (255.255.255.255),
/// any IPv4 multicast (224.0.0.0/4), or any IPv6 multicast (ff00::/8).
///
/// Subnet-directed broadcasts (e.g. 172.18.22.255) are NOT matched here —
/// they depend on the local subnet mask and are excluded via the own_ips
/// snapshot passed to CrossFlowState at startup.
///
/// Used by both should_skip_block() (enforcement guard) and
/// CrossFlowState::record_connection() (scan-detection counting), so both
/// sites share one definition and can't drift apart.
pub(crate) fn is_infrastructure_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(_) => ip.is_multicast(),
    }
}

impl CaptureEngine {
    pub fn new(init: CaptureInit) -> Self {
        Self {
            bpf_fd: init.bpf_fd,
            buf: init.buf,
            caches: init.caches,
            enrich_pool: init.enrich_pool,
            tracker: init.tracker,
            decision_engine: init.decision_engine,
            detectors: init.detectors,
            config: init.config,
            circuit_breaker: HashMap::new(),
            block_cooldown: HashMap::new(),
            write_half: init.write_half,
            pkt_count: 0,
            ipc_failures: 0,
            cross_flow_state: init.cross_flow_state,
            storage_tx: init.storage_tx,
        }
    }

    pub fn pkt_count(&self) -> u64 {
        self.pkt_count
    }

    pub fn flows_tracked(&self) -> usize {
        self.tracker.len()
    }

    /// Check IPC health — returns Err if consecutive failures exceed threshold.
    /// The main loop should exit cleanly so launchd/systemd can restart the agent.
    pub fn check_ipc_health(&self) -> io::Result<()> {
        if self.ipc_failures >= MAX_IPC_FAILURES {
            Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!(
                    "IPC channel dead — {MAX_IPC_FAILURES} consecutive enforcement send failures. \
                     Exiting for restart."
                ),
            ))
        } else {
            Ok(())
        }
    }

    /// poll() + tick(). Returns Ok(has_data) — true if packets available,
    /// false on timeout. On error, returns the error.
    pub fn run_tick(&mut self) -> io::Result<bool> {
        let mut pollfd = libc::pollfd {
            fd: self.bpf_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pollfd, 1, self.config.poll_timeout_ms) };

        if poll_ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            error!("poll error: {err}");
            return Err(err);
        }

        // Always tick on every iteration — even on timeout.
        // Expires stale flows and reclaims memory.
        let (expired, re_evaluate) = self.tracker.tick();
        debug!(
            "poll_ret={} expired={} re_evaluate={} flows={}",
            poll_ret,
            expired.len(),
            re_evaluate.len(),
            self.tracker.len()
        );

        // R6: Sweep block_cooldown on every tick, not only inside the
        // expired/re_evaluate guard — prevents stale entries from piling up
        // when the network is quiet (no flow expiry or re-evaluation).
        {
            let now = Instant::now();
            self.block_cooldown.retain(|_ip, expires_at| {
                if now >= *expires_at {
                    debug!("cooldown expired for {_ip}");
                    false
                } else {
                    true
                }
            });
        }

        // Purge expired entries from the cross-flow state on every tick.
        if let Ok(mut state) = self.cross_flow_state.lock() {
            state.purge_expired();
        }

        if !expired.is_empty() || !re_evaluate.is_empty() {
            debug!(
                "tick: expired {} flows, re-evaluate {} flows ({} remaining)",
                expired.len(),
                re_evaluate.len(),
                self.tracker.len()
            );

            self.process_expired_flows(&expired);
            self.tracker.remove_expired(&expired);
            self.process_re_evaluate_flows(&re_evaluate);
        }

        Ok(poll_ret > 0)
    }

    /// Run detectors + decision engine on expired flows.
    /// Verbatim extraction from main.rs lines 456-527.
    pub fn process_expired_flows(&mut self, expired: &[u64]) {
        for &flow_id in expired {
            if let Some(flow_ref) = self.tracker.get(flow_id) {
                let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                let Some(resolved) = common_flow.resolved.clone() else {
                    warn!("[SKIP] flow={} expired — resolved=None (startup window), detectors not run", flow_id);
                    continue;
                };
                let common_flow = std::sync::Arc::new(common_flow);
                let (findings, cb_transitions) = detectors::run_detectors(
                    &self.detectors,
                    std::sync::Arc::clone(&common_flow),
                    self.config.detector_timeout,
                    &mut self.circuit_breaker,
                    &self.config.cb_config,
                );
                self.emit_cb_transitions(cb_transitions);
                let features = synapse_common::FlowFeatures::from_flow(&common_flow, &resolved);
                let (verdict, score) = self.decision_engine.evaluate(&features, &findings);
                self.handle_verdict(flow_id, &common_flow, &findings, score, verdict);
            }
        }
    }

    /// Re-run detectors on active flows due for periodic re-evaluation.
    /// Verbatim extraction from main.rs lines 528-602.
    pub fn process_re_evaluate_flows(&mut self, re_evaluate: &[u64]) {
        for &flow_id in re_evaluate {
            if let Some(flow_ref) = self.tracker.get(flow_id) {
                let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                let Some(resolved) = common_flow.resolved.clone() else {
                    warn!("[SKIP] flow={} re-eval — resolved=None (startup window), detectors not run", flow_id);
                    continue;
                };
                let common_flow = std::sync::Arc::new(common_flow);
                let (findings, cb_transitions) = detectors::run_detectors(
                    &self.detectors,
                    std::sync::Arc::clone(&common_flow),
                    self.config.detector_timeout,
                    &mut self.circuit_breaker,
                    &self.config.cb_config,
                );
                self.emit_cb_transitions(cb_transitions);
                let features = synapse_common::FlowFeatures::from_flow(&common_flow, &resolved);
                let (verdict, score) = self.decision_engine.evaluate(&features, &findings);
                self.handle_verdict(flow_id, &common_flow, &findings, score, verdict);
                self.tracker.mark_evaluated(flow_id);
            }
        }
    }

    /// Handle a verdict — persist it, then enforce via IPC if Block.
    ///
    /// `flow` and `findings` are passed in (already available at every call
    /// site) so we can emit VerdictDecided without a second tracker lookup.
    /// `composite_score` is the raw weighted sum from the decision engine.
    fn handle_verdict(
        &mut self,
        flow_id: u64,
        flow: &synapse_common::FlowRecord,
        findings: &[synapse_common::DetectorFinding],
        composite_score: f32,
        verdict: synapse_common::Verdict,
    ) {
        // ResolvedFlow is set once at flow creation using per-packet direction.
        // None means the flow was created in the startup window before own-ips
        // was detected — direction is unknown, enforcing would risk a wrong target.
        let Some(ref resolved) = flow.resolved else {
            warn!("[SKIP] flow={} — resolved=None (startup window)", flow_id);
            return;
        };
        let remote = resolved.remote_ip;
        let local_ip = resolved.local_ip;

        match verdict {
            synapse_common::Verdict::Allow => {
                info!("[ALLOW] flow={}", flow_id);
            }
            synapse_common::Verdict::Alert { ref reason } => {
                info!("[ALERT] flow={} remote={} {}", flow_id, remote, reason);
                if let Some(ref tx) = self.storage_tx {
                    let _ = tx.send(StorageEvent::VerdictDecided {
                        flow: Box::new(flow.clone()),
                        local_ip,
                        remote_ip: remote,
                        verdict: "Alert".to_string(),
                        reason: reason.clone(),
                        composite_score,
                        ttl_ms: None,
                        findings: findings.to_vec(),
                    });
                }
            }
            synapse_common::Verdict::Block { ttl, ref reason } => {
                if let Some(skip_reason) = self.should_skip_block(remote) {
                    warn!("[SKIP] flow={} — {skip_reason}", flow_id);
                } else {
                    let dominated = self
                        .block_cooldown
                        .get(&remote)
                        .is_some_and(|&expires| Instant::now() < expires);
                    if dominated {
                        debug!("BLOCK skip flow={} {remote} (cooldown active)", flow_id);
                    } else {
                        info!(
                            "[BLOCK] flow={} remote={remote} ttl={ttl:?} {reason}",
                            flow_id,
                        );

                        // Persist the verdict decision before attempting enforcement.
                        if let Some(ref tx) = self.storage_tx {
                            let _ = tx.send(StorageEvent::VerdictDecided {
                                flow: Box::new(flow.clone()),
                                local_ip,
                                remote_ip: remote,
                                verdict: "Block".to_string(),
                                reason: reason.clone(),
                                composite_score,
                                ttl_ms: Some(ttl.as_millis() as u64),
                                findings: findings.to_vec(),
                            });
                        }

                        // Pick the top-scoring Completed detector for the enforcement log.
                        let top_detector = findings
                            .iter()
                            .filter(|f| f.status == synapse_common::DetectorStatus::Completed)
                            .max_by(|a, b| {
                                (a.score * a.confidence)
                                    .partial_cmp(&(b.score * b.confidence))
                                    .unwrap_or(std::cmp::Ordering::Equal)
                            })
                            .map(|f| format!("{:?}", f.detector_id));

                        let cmd = EnforcementCommand::Block { ip: remote, ttl };
                        if let Err(e) = protocol::send_message(&mut self.write_half, &cmd) {
                            self.ipc_failures += 1;
                            error!(
                                "enforcement send failed for {remote}: {e} — \
                                 consecutive failures: {}/{}",
                                self.ipc_failures, MAX_IPC_FAILURES,
                            );
                            if let Some(ref tx) = self.storage_tx {
                                let _ = tx.send(StorageEvent::EnforcementRequested {
                                    ip: remote,
                                    ttl_ms: ttl.as_millis() as u64,
                                    reason: reason.clone(),
                                    top_detector,
                                    composite_score,
                                    send_error: Some(format!("{e}")),
                                });
                            }
                        } else {
                            self.ipc_failures = 0;
                            info!("[ENFORCE] command sent: Block {remote} ttl={ttl:?}");
                            self.block_cooldown.insert(remote, Instant::now() + ttl);
                            if let Some(ref tx) = self.storage_tx {
                                let _ = tx.send(StorageEvent::EnforcementRequested {
                                    ip: remote,
                                    ttl_ms: ttl.as_millis() as u64,
                                    reason: reason.clone(),
                                    top_detector,
                                    composite_score,
                                    send_error: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Forward circuit breaker transitions to storage (health dashboard data).
    fn emit_cb_transitions(&self, transitions: Vec<detectors::CbTransition>) {
        if transitions.is_empty() {
            return;
        }
        let Some(ref tx) = self.storage_tx else {
            return;
        };
        for t in transitions {
            let _ = tx.send(StorageEvent::CircuitBreakerTransition {
                detector_id: format!("{:?}", t.detector_id),
                from_state: t.from_state,
                to_state: t.to_state,
                consecutive_failures: t.consecutive_failures,
            });
        }
    }

    /// Check whether a remote IP should be exempt from blocking.
    /// Returns Some(reason) if blocked, None if blocking is allowed.
    fn should_skip_block(&self, remote: IpAddr) -> Option<&'static str> {
        // Own IPs (all address families — v4 and v6).
        // P1: Lock-free snapshot via arc_swap.
        let own = self.caches.own_ips.load();
        if own.contains(&remote) {
            return Some("remote is own IP");
        }
        // Default gateway.
        if Some(remote) == self.config.gateway_ip {
            return Some("remote is default gateway");
        }
        if is_infrastructure_destination(remote) {
            return Some("remote is broadcast/multicast");
        }
        match remote {
            IpAddr::V4(v4) => {
                if v4.is_link_local() {
                    return Some("remote is link-local");
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return Some("remote is IPv6 loopback/unspecified");
                }
                // fe80::/10 — IPv6 link-local.
                if v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80 {
                    return Some("remote is IPv6 link-local");
                }
            }
        }
        None
    }

    /// Read BPF packets and process them. Returns Ok(false) on timeout/close.
    pub fn read_and_process_packets(&mut self) -> io::Result<bool> {
        let n = unsafe {
            libc::read(
                self.bpf_fd,
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(true);
            }
            error!("BPF read error: {err}");
            return Err(err);
        }
        if n == 0 {
            info!("BPF fd closed (helper exited?)");
            return Ok(false);
        }
        let n = n as usize;
        debug!("BPF read: {} bytes from fd={}", n, self.bpf_fd);

        let mut offset = 0usize;
        while offset + BpfHdr::SIZE <= n {
            let hdr = match BpfHdr::from_bytes(&self.buf[offset..]) {
                Some(h) => h,
                None => break,
            };

            let data_start = match offset.checked_add(hdr.bh_hdrlen as usize) {
                Some(v) => v,
                None => {
                    warn!("BPF header overflow at offset {offset}");
                    break;
                }
            };
            let data_end = match data_start.checked_add(hdr.bh_caplen as usize) {
                Some(v) => v,
                None => {
                    warn!("BPF caplen overflow at offset {data_start}");
                    break;
                }
            };
            if data_end > n {
                warn!("truncated packet at offset {offset}");
                break;
            }

            self.pkt_count += 1;
            let frame = &self.buf[data_start..data_end];

            if let Some(info_pkt) = parse_ip_frame(frame) {
                debug!(
                    "parsed packet: {}:{} → {}:{} proto={}",
                    info_pkt.src_ip,
                    info_pkt.src_port,
                    info_pkt.dst_ip,
                    info_pkt.dst_port,
                    info_pkt.protocol
                );
                if self.pkt_count.is_multiple_of(10) {
                    debug!(
                        "pkt#{}: {}:{} → {}:{} (proto={})",
                        self.pkt_count,
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        info_pkt.protocol,
                    );
                }

                // P1 + R10: Lock-free snapshot. Hoisted so both PID lookup and
                // CrossFlow recording use the same local_ip without a second ArcSwap read.
                let current_local_ip = match **self.caches.local_ip.load() {
                    Some(ip) => ip,
                    None => {
                        debug!("local_ip unknown — skipping packet (direction unknown)");
                        continue;
                    }
                };

                let (local_port, pid) = {
                    // P1: Lock-free snapshot via arc_swap — no mutex on hot path.
                    let cache = self.caches.port_pid.load();
                    let lookup = |port: u16, proto: u8| -> Option<(u16, u32)> {
                        let key = (port, proto);
                        cache.get(&key).map(|&pid| (port, pid))
                    };
                    let (local, _) = determine_local_port(
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        current_local_ip,
                    );
                    lookup(local, info_pkt.protocol).unwrap_or((0, 0))
                };

                let update = self.tracker.update(
                    &info_pkt,
                    local_port,
                    if pid != 0 { Some(pid) } else { None },
                );

                if let flow::FlowUpdate::NewFlow(flow_id) = update {
                    debug!(
                        "[FLOW] created #{}: {}:{} → {}:{} (proto={}, local_port={}, pid={:?})",
                        flow_id,
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        info_pkt.protocol,
                        local_port,
                        if pid != 0 { Some(pid) } else { None },
                    );

                    // Record cross-flow state (no IPC or blocking, just in-memory stats).
                    // current_local_ip was hoisted above the pid-lookup block so no
                    // second ArcSwap load is needed here.
                    let (remote_ip, remote_port) = determine_remote_endpoint(
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        current_local_ip,
                    );
                    if let Ok(mut state) = self.cross_flow_state.lock() {
                        state.record_connection(pid, remote_ip, info_pkt.protocol, remote_port);
                        if pid != 0 {
                            state.record_pid_connection(pid, remote_ip);
                        }
                    }

                    // Freeze direction-resolved endpoints on the flow record.
                    // Uses per-packet src/dst (genuine wire direction), not canonical
                    // a_ip/b_ip. See ResolvedFlow doc comment for safety analysis.
                    self.tracker.set_resolved(
                        flow_id,
                        ResolvedFlow {
                            local_ip: current_local_ip,
                            local_port,
                            remote_ip,
                            remote_port,
                        },
                    );

                    let request = EnrichmentRequest {
                        flow_id,
                        src_ip: info_pkt.src_ip,
                        dst_ip: info_pkt.dst_ip,
                        src_port: info_pkt.src_port,
                        dst_port: info_pkt.dst_port,
                        protocol: info_pkt.protocol,
                        pid: if pid != 0 { Some(pid) } else { None },
                        kinds: [
                            EnrichmentKind::DnsReverse,
                            EnrichmentKind::ProcessAttribution,
                            EnrichmentKind::GeoIp,
                            EnrichmentKind::Reputation,
                        ],
                    };

                    if let Err(e) = self.enrich_pool.dispatch(request) {
                        warn!("enrichment dispatch failed: {e}");
                    }
                }
            }

            match hdr.next_offset() {
                Some(next) => offset += next,
                None => {
                    warn!("BPF next_offset overflow at offset {offset}");
                    break;
                }
            }
        }

        Ok(true)
    }

    /// Collect enrichment results and attach to flows (non-blocking).
    /// P5: Batches results by flow_id — one attach_enrichment call per flow
    /// instead of one per enrichment kind (reduces HashMap lookups 4x).
    pub fn collect_enrichment_results(&mut self) {
        use std::collections::HashMap;

        let results = self.enrich_pool.drain_results();
        if results.is_empty() {
            return;
        }

        // Accumulate per-flow enrichment data.
        let mut batch: HashMap<u64, flow::FlowEnrichment> = HashMap::new();
        for result in results {
            if result.success {
                let entry = batch.entry(result.flow_id).or_default();
                match result.kind {
                    synapse_common::EnrichmentKind::DnsReverse => {
                        debug!(
                            "[ENRICH] dns → {}",
                            result.dns_name.as_deref().unwrap_or("?"),
                        );
                        entry.dns_name = result.dns_name;
                    }
                    synapse_common::EnrichmentKind::ProcessAttribution => {
                        debug!(
                            "[ENRICH] process → {} (start={:?})",
                            result.process_path.as_deref().unwrap_or("?"),
                            result.process_start_time,
                        );
                        entry.process_path = result.process_path;
                        entry.process_start_time = result.process_start_time;
                    }
                    synapse_common::EnrichmentKind::GeoIp => {
                        entry.country_code = result.country_code;
                        entry.asn = result.asn;
                    }
                    synapse_common::EnrichmentKind::Reputation => {
                        entry.reputation_score = result.reputation_score;
                    }
                }
            } else {
                debug!(
                    "enrich: {:?} failed for flow {}: {}",
                    result.kind,
                    result.flow_id,
                    result.error.as_deref().unwrap_or("unknown"),
                );
            }
        }

        // Single attach_enrichment call per flow (reduces HashMap lookups).
        for (flow_id, e) in batch {
            self.tracker.attach_enrichment(flow_id, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_resolved_flow_none_does_not_enforce() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        // Socket pair: write_half → CaptureEngine, read_half → test assertion.
        let (write_half, mut read_half) = UnixStream::pair().expect("UnixStream::pair");
        read_half
            .set_nonblocking(true)
            .expect("set_nonblocking on read_half");

        let excluded: Arc<ArcSwap<HashSet<IpAddr>>> =
            Arc::new(ArcSwap::from_pointee(HashSet::new()));
        let init = CaptureInit {
            bpf_fd: -1,
            buf: vec![0u8; 4096],
            write_half,
            caches: NetworkCaches {
                local_ip: Arc::new(ArcSwap::from_pointee(Some(IpAddr::V4(Ipv4Addr::new(
                    192, 168, 1, 1,
                ))))),
                own_ips: Arc::new(ArcSwap::from_pointee(HashSet::new())),
                port_pid: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            },
            config: CaptureConfig {
                poll_timeout_ms: 100,
                detector_timeout: std::time::Duration::from_millis(100),
                cb_config: detectors::CircuitBreakerConfig::default(),
                gateway_ip: None,
            },
            enrich_pool: crate::enrichment::EnrichmentPool::new(None, None, 1),
            tracker: crate::flow::FlowTracker::new(crate::flow::FlowConfig::default()),
            decision_engine: crate::decision::DecisionEngine::new(
                synapse_common::DecisionConfig::default(),
            ),
            detectors: vec![],
            cross_flow_state: Arc::new(std::sync::Mutex::new(
                detectors::cross_flow::CrossFlowState::new(
                    detectors::cross_flow::CrossFlowConfig::default(),
                    Arc::clone(&excluded),
                ),
            )),
            storage_tx: None,
        };

        let mut engine = CaptureEngine::new(init);

        // FlowRecord with resolved: None — the case the packet loop prevents in
        // production but which future refactors could accidentally introduce.
        let flow = synapse_common::FlowRecord {
            flow_id: 1,
            a_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            b_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            a_port: 443,
            b_port: 50001,
            protocol: 6,
            local_port: 50001,
            pid: None,
            packet_count: 5,
            byte_count: 500,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code: None,
            asn: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(2),
            resolved: None,
        };

        // Block verdict — the highest-severity path. If the resolved=None guard
        // were absent, this would attempt to send an EnforcementCommand on the socket.
        let verdict = synapse_common::Verdict::Block {
            ttl: std::time::Duration::from_secs(60),
            reason: "test block — must not reach enforcement".to_string(),
        };

        // Must not panic.
        engine.handle_verdict(1, &flow, &[], 0.9, verdict);

        // Nothing must have been written to the socket.
        let mut buf = [0u8; 64];
        let result = read_half.read(&mut buf);
        assert!(
            matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "handle_verdict must send no enforcement command when resolved=None; \
             socket read returned: {result:?}"
        );
    }

    /// Verify that process_expired_flows skips detector evaluation for flows with resolved=None.
    ///
    /// The packet loop prevents resolved=None in production (it skips packets when
    /// local_ip is unknown). This test bypasses that invariant by inserting a flow
    /// via tracker.update() without calling set_resolved(), then running
    /// process_expired_flows on it. A SentinelDetector asserts it is never called.
    ///
    /// Without the resolved=None guard, FlowBehavior::evaluate() would panic (its
    /// .expect() fires), caught by run_detectors' catch_unwind. With the guard,
    /// the flow is skipped before run_detectors — SentinelDetector::evaluate is
    /// never scheduled, and was_called stays false.
    #[test]
    fn test_detector_path_resolved_none_skipped() {
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SentinelDetector {
            was_called: Arc<AtomicBool>,
        }
        impl synapse_common::Detector for SentinelDetector {
            fn id(&self) -> synapse_common::DetectorId {
                synapse_common::DetectorId::Custom(0xDD)
            }
            fn version(&self) -> &str {
                "test"
            }
            fn evaluate(
                &self,
                _flow: &synapse_common::FlowRecord,
            ) -> synapse_common::DetectorFinding {
                self.was_called.store(true, Ordering::SeqCst);
                synapse_common::DetectorFinding::timed_out(self.id(), self.version(), 0)
            }
        }

        let was_called = Arc::new(AtomicBool::new(false));
        let (write_half, _read_half) = UnixStream::pair().expect("UnixStream::pair");
        let excluded: Arc<ArcSwap<HashSet<IpAddr>>> =
            Arc::new(ArcSwap::from_pointee(HashSet::new()));
        let init = CaptureInit {
            bpf_fd: -1,
            buf: vec![0u8; 4096],
            write_half,
            caches: NetworkCaches {
                local_ip: Arc::new(ArcSwap::from_pointee(Some(IpAddr::V4(Ipv4Addr::new(
                    192, 168, 1, 1,
                ))))),
                own_ips: Arc::new(ArcSwap::from_pointee(HashSet::new())),
                port_pid: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            },
            config: CaptureConfig {
                poll_timeout_ms: 100,
                detector_timeout: std::time::Duration::from_millis(100),
                cb_config: detectors::CircuitBreakerConfig::default(),
                gateway_ip: None,
            },
            enrich_pool: crate::enrichment::EnrichmentPool::new(None, None, 1),
            tracker: crate::flow::FlowTracker::new(crate::flow::FlowConfig::default()),
            decision_engine: crate::decision::DecisionEngine::new(
                synapse_common::DecisionConfig::default(),
            ),
            detectors: vec![Arc::new(SentinelDetector {
                was_called: Arc::clone(&was_called),
            })],
            cross_flow_state: Arc::new(std::sync::Mutex::new(
                detectors::cross_flow::CrossFlowState::new(
                    detectors::cross_flow::CrossFlowConfig::default(),
                    Arc::clone(&excluded),
                ),
            )),
            storage_tx: None,
        };
        let mut engine = CaptureEngine::new(init);

        // Insert a flow via tracker.update() WITHOUT calling set_resolved().
        // This leaves resolved=None — the state the packet loop prevents in production.
        let info = synapse_common::PacketInfo {
            src_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            src_port: 443,
            dst_port: 50001,
            protocol: 6,
            length: 100,
        };
        let flow_id = match engine.tracker.update(&info, 50001, None) {
            crate::flow::FlowUpdate::NewFlow(id) => id,
            other => panic!("expected NewFlow, got {other:?}"),
        };

        engine.process_expired_flows(&[flow_id]);

        assert!(
            !was_called.load(Ordering::SeqCst),
            "SentinelDetector::evaluate must not be called for resolved=None flows; \
             the guard in process_expired_flows must skip them before run_detectors"
        );
    }
}
