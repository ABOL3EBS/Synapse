// crates/agent/src/capture.rs
//
// CaptureEngine — extracted from main.rs to keep main under 500 lines.
// Pure structural extraction: all logic moved verbatim, no changes to
// internal behavior.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use log::{debug, error, info, warn};
use synapse_common::{EnforcementCommand, EnrichmentKind, EnrichmentRequest, PacketInfo};

use crate::detectors;
use crate::enrichment::EnrichmentPool;
use crate::flow::{self, FlowTracker};
use synapse_platform_macos::protocol;

// ---------------------------------------------------------------------------
// BPF constants
// ---------------------------------------------------------------------------

/// BPF word alignment — packets are padded to this boundary between entries.
/// On macOS/BSD this is 4 (sizeof(long) on 32-bit, traditional BPF alignment).
pub const BPF_WORDALIGN: usize = 4;

/// Align a BPF offset up to the next word boundary.
pub fn bpf_wordalign(offset: usize) -> usize {
    (offset + BPF_WORDALIGN - 1) & !(BPF_WORDALIGN - 1)
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfHdr {
    tv_sec: i32,
    tv_usec: i32,
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
}

impl BpfHdr {
    pub const SIZE: usize = std::mem::size_of::<Self>();

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            tv_sec: i32::from_ne_bytes(buf[0..4].try_into().ok()?),
            tv_usec: i32::from_ne_bytes(buf[4..8].try_into().ok()?),
            bh_caplen: u32::from_ne_bytes(buf[8..12].try_into().ok()?),
            bh_datalen: u32::from_ne_bytes(buf[12..16].try_into().ok()?),
            bh_hdrlen: u16::from_ne_bytes(buf[16..18].try_into().ok()?),
        })
    }

    pub fn next_offset(&self) -> usize {
        bpf_wordalign(self.bh_hdrlen as usize + self.bh_caplen as usize)
    }
}

// ---------------------------------------------------------------------------
// IP Frame Parser
// ---------------------------------------------------------------------------

pub fn parse_ip_frame(frame: &[u8]) -> Option<PacketInfo> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        0x0800 => parse_ipv4(frame),
        0x86DD => parse_ipv6(frame),
        _ => None,
    }
}

fn parse_ipv4(frame: &[u8]) -> Option<PacketInfo> {
    if frame.len() < 34 {
        return None;
    }
    let ip = 14;
    let hdr_len = ((frame[ip] & 0x0F) as usize) * 4;
    if hdr_len < 20 || frame.len() < ip + hdr_len + 4 {
        return None;
    }

    let protocol = frame[ip + 9];
    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        frame[ip + 12],
        frame[ip + 13],
        frame[ip + 14],
        frame[ip + 15],
    ));
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        frame[ip + 16],
        frame[ip + 17],
        frame[ip + 18],
        frame[ip + 19],
    ));
    let total_len = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]);

    let (sp, dp) = match protocol {
        6 | 17 => {
            let t = ip + hdr_len;
            (
                u16::from_be_bytes([frame[t], frame[t + 1]]),
                u16::from_be_bytes([frame[t + 2], frame[t + 3]]),
            )
        }
        _ => (0, 0),
    };

    Some(PacketInfo {
        src_ip,
        dst_ip,
        src_port: sp,
        dst_port: dp,
        protocol,
        length: total_len,
    })
}

fn parse_ipv6(frame: &[u8]) -> Option<PacketInfo> {
    if frame.len() < 54 {
        return None;
    }
    let ip = 14;
    let nh = frame[ip + 6];
    let src_ip = {
        let mut o = [0u8; 16];
        o.copy_from_slice(&frame[ip + 8..ip + 24]);
        IpAddr::V6(std::net::Ipv6Addr::from(o))
    };
    let dst_ip = {
        let mut o = [0u8; 16];
        o.copy_from_slice(&frame[ip + 24..ip + 40]);
        IpAddr::V6(std::net::Ipv6Addr::from(o))
    };
    let (sp, dp) = match nh {
        6 | 17 => {
            let t = ip + 40;
            (
                u16::from_be_bytes([frame[t], frame[t + 1]]),
                u16::from_be_bytes([frame[t + 2], frame[t + 3]]),
            )
        }
        _ => (0, 0),
    };
    Some(PacketInfo {
        src_ip,
        dst_ip,
        src_port: sp,
        dst_port: dp,
        protocol: nh,
        length: 0,
    })
}

// ---------------------------------------------------------------------------
// Direction helpers
// ---------------------------------------------------------------------------

/// Determine which port is local based on which IP matches the detected local IP.
/// Returns (local_port, remote_port).
pub fn determine_local_port(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    local_ip: IpAddr,
) -> (u16, u16) {
    if src_ip == local_ip {
        (src_port, dst_port)
    } else if dst_ip == local_ip {
        (dst_port, src_port)
    } else {
        // Neither IP matches local — fall back to src_port as local
        // (outbound default, but we have no better heuristic).
        (src_port, dst_port)
    }
}

/// Determine which IP is the remote endpoint for enforcement.
/// Mirrors the is_local() pattern from determine_local_port().
/// Never assume a_ip or b_ip means "remote" — canonical ordering
/// discards direction.
pub fn determine_remote_ip(a_ip: IpAddr, b_ip: IpAddr, local_ip: IpAddr) -> IpAddr {
    if a_ip == local_ip {
        b_ip
    } else if b_ip == local_ip {
        a_ip
    } else {
        // Neither matches local — default to b_ip (the larger address,
        // which is more likely to be external on a home network).
        b_ip
    }
}

/// Detect the local IP address from the network interface.
/// Uses getifaddrs() to find IPv4 addresses on non-loopback interfaces.
/// Returns the first non-loopback IPv4 address found.
pub fn detect_local_ip() -> Option<IpAddr> {
    use std::ffi::CStr;

    let mut ifa_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
    let ret = unsafe { libc::getifaddrs(&mut ifa_ptr) };
    if ret != 0 {
        return None;
    }

    let mut result = None;
    let mut ptr = ifa_ptr;
    while !ptr.is_null() {
        let ifa = unsafe { &*ptr };
        // Skip loopback interfaces.
        if ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0 {
            ptr = ifa.ifa_next;
            continue;
        }
        // Only IPv4 (AF_INET).
        if !ifa.ifa_addr.is_null() && unsafe { (*ifa.ifa_addr).sa_family } == libc::AF_INET as u8 {
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let octets = sin.sin_addr.s_addr.to_ne_bytes();
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            ));
            // Skip 0.0.0.0 and 255.255.255.255.
            if !ip.is_unspecified() {
                let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
                debug!("detected local IP: {} on {}", ip, name.to_string_lossy());
                result = Some(ip);
                break;
            }
        }
        ptr = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifa_ptr) };
    result
}

// ---------------------------------------------------------------------------
// CaptureEngine
// ---------------------------------------------------------------------------

pub struct CaptureEngine {
    bpf_fd: RawFd,
    buf: Vec<u8>,
    local_ip_cache: Arc<Mutex<Option<IpAddr>>>,
    port_pid_cache: Arc<Mutex<HashMap<(u16, u8), u32>>>,
    enrich_pool: EnrichmentPool,
    tracker: FlowTracker,
    decision_engine: crate::decision::DecisionEngine,
    detectors: Vec<Arc<dyn synapse_common::Detector>>,
    detector_timeout: std::time::Duration,
    circuit_breaker: HashMap<synapse_common::DetectorId, detectors::CircuitState>,
    block_cooldown: HashMap<IpAddr, Instant>,
    write_half: UnixStream,
    pkt_count: u64,
}

impl CaptureEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bpf_fd: RawFd,
        buf: Vec<u8>,
        local_ip_cache: Arc<Mutex<Option<IpAddr>>>,
        port_pid_cache: Arc<Mutex<HashMap<(u16, u8), u32>>>,
        enrich_pool: EnrichmentPool,
        tracker: FlowTracker,
        decision_engine: crate::decision::DecisionEngine,
        detectors: Vec<Arc<dyn synapse_common::Detector>>,
        detector_timeout: std::time::Duration,
        write_half: UnixStream,
    ) -> Self {
        Self {
            bpf_fd,
            buf,
            local_ip_cache,
            port_pid_cache,
            enrich_pool,
            tracker,
            decision_engine,
            detectors,
            detector_timeout,
            circuit_breaker: HashMap::new(),
            block_cooldown: HashMap::new(),
            write_half,
            pkt_count: 0,
        }
    }

    pub fn pkt_count(&self) -> u64 {
        self.pkt_count
    }

    pub fn flows_tracked(&self) -> usize {
        self.tracker.len()
    }

    /// poll() + tick(). Returns Ok(has_data) — true if packets available,
    /// false on timeout. On error, returns the error.
    pub fn run_tick(&mut self) -> io::Result<bool> {
        let mut pollfd = libc::pollfd {
            fd: self.bpf_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 100) };

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
        if !expired.is_empty() || !re_evaluate.is_empty() {
            info!(
                "tick: expired {} flows, re-evaluate {} flows ({} remaining)",
                expired.len(),
                re_evaluate.len(),
                self.tracker.len()
            );

            // Lazy cleanup of expired cooldown entries.
            let now = Instant::now();
            self.block_cooldown.retain(|_ip, expires_at| {
                if now >= *expires_at {
                    debug!("cooldown expired for {_ip}");
                    false
                } else {
                    true
                }
            });

            self.process_expired_flows(&expired);
            self.process_re_evaluate_flows(&re_evaluate);
        }

        Ok(poll_ret > 0)
    }

    /// Run detectors + decision engine on expired flows.
    /// Verbatim extraction from main.rs lines 456-527.
    pub fn process_expired_flows(&mut self, expired: &[u64]) {
        // Temporarily take local_ip to avoid borrow conflicts.
        let local_ip = self
            .local_ip_cache
            .lock()
            .ok()
            .and_then(|g| *g)
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

        for &flow_id in expired {
            if let Some(flow_ref) = self.tracker.get(flow_id) {
                let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                let findings = detectors::run_detectors(
                    &self.detectors,
                    &common_flow,
                    self.detector_timeout,
                    &mut self.circuit_breaker,
                );
                let features = synapse_common::FlowFeatures::from_flow(
                    &common_flow,
                    flow_ref.first_seen.elapsed(),
                );
                let verdict = self.decision_engine.evaluate(&features, &findings);
                self.handle_verdict(flow_id, verdict, local_ip);
            }
        }
    }

    /// Re-run detectors on active flows due for periodic re-evaluation.
    /// Verbatim extraction from main.rs lines 528-602.
    pub fn process_re_evaluate_flows(&mut self, re_evaluate: &[u64]) {
        // Temporarily take local_ip to avoid borrow conflicts.
        let local_ip = self
            .local_ip_cache
            .lock()
            .ok()
            .and_then(|g| *g)
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

        for &flow_id in re_evaluate {
            if let Some(flow_ref) = self.tracker.get(flow_id) {
                let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                let findings = detectors::run_detectors(
                    &self.detectors,
                    &common_flow,
                    self.detector_timeout,
                    &mut self.circuit_breaker,
                );
                let features = synapse_common::FlowFeatures::from_flow(
                    &common_flow,
                    flow_ref.first_seen.elapsed(),
                );
                let verdict = self.decision_engine.evaluate(&features, &findings);
                self.handle_verdict(flow_id, verdict, local_ip);
                self.tracker.mark_evaluated(flow_id);
            }
        }
    }

    /// Handle a verdict — enforcement via IPC. Verbatim from main.rs.
    /// Moved verbatim — no logic changes.
    fn handle_verdict(&mut self, flow_id: u64, verdict: synapse_common::Verdict, local_ip: IpAddr) {
        // We need common_flow.a_ip and common_flow.b_ip for determine_remote_ip.
        // Re-fetch the flow to get the canonical key.
        let (a_ip, b_ip) = if let Some(flow_ref) = self.tracker.get(flow_id) {
            (flow_ref.key.a_ip, flow_ref.key.b_ip)
        } else {
            return;
        };

        match verdict {
            synapse_common::Verdict::Allow => {}
            synapse_common::Verdict::Alert { ref reason } => {
                let remote = determine_remote_ip(a_ip, b_ip, local_ip);
                info!("ALERT flow={} remote={} {}", flow_id, remote, reason);
            }
            synapse_common::Verdict::Block { ttl, ref reason } => {
                let remote = determine_remote_ip(a_ip, b_ip, local_ip);
                // Belt-and-suspenders: never block the local IP, even if
                // determine_remote_ip() returns it (fallback path).
                if remote == local_ip {
                    warn!(
                        "BLOCK skip flow={} — remote resolved to local IP {remote} (fallback)",
                        flow_id,
                    );
                } else {
                    let dominated = self
                        .block_cooldown
                        .get(&remote)
                        .is_some_and(|&expires| Instant::now() < expires);
                    if dominated {
                        debug!("BLOCK skip flow={} {remote} (cooldown active)", flow_id,);
                    } else {
                        info!(
                            "BLOCK flow={} remote={remote} ttl={ttl:?} {reason}",
                            flow_id,
                        );
                        let cmd = EnforcementCommand::Block { ip: remote, ttl };
                        if let Err(e) = protocol::send_message(&mut self.write_half, &cmd) {
                            error!("enforcement send failed for {remote}: {e} — continuing");
                        } else {
                            info!("enforcement command sent: Block {remote} ttl={ttl:?}");
                            self.block_cooldown.insert(remote, Instant::now() + ttl);
                        }
                    }
                }
            }
        }
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

        let mut offset = 0usize;
        while offset + BpfHdr::SIZE <= n {
            let hdr = match BpfHdr::from_bytes(&self.buf[offset..]) {
                Some(h) => h,
                None => break,
            };

            let data_start = offset + hdr.bh_hdrlen as usize;
            let data_end = data_start + hdr.bh_caplen as usize;
            if data_end > n {
                warn!("truncated packet at offset {offset}");
                break;
            }

            self.pkt_count += 1;
            let frame = &self.buf[data_start..data_end];

            if let Some(info_pkt) = parse_ip_frame(frame) {
                if self.pkt_count.is_multiple_of(10) {
                    info!(
                        "pkt#{}: {}:{} → {}:{} (proto={})",
                        self.pkt_count,
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        info_pkt.protocol,
                    );
                }

                let (local_port, pid) = {
                    let cache_guard = self.port_pid_cache.lock().ok();
                    let cache = cache_guard.as_ref();
                    let lookup = |port: u16, proto: u8| -> Option<(u16, u32)> {
                        cache.and_then(|c| {
                            let key = (port, proto);
                            c.get(&key).map(|&pid| (port, pid))
                        })
                    };
                    let current_local_ip = self
                        .local_ip_cache
                        .lock()
                        .ok()
                        .and_then(|g| *g)
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
                    let (local, _remote) = determine_local_port(
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
                    info!(
                        "flow {} created: {}:{} → {}:{} (proto={}, local_port={}, pid={:?})",
                        flow_id,
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        info_pkt.protocol,
                        local_port,
                        if pid != 0 { Some(pid) } else { None },
                    );
                    let request = EnrichmentRequest {
                        flow_id,
                        src_ip: info_pkt.src_ip,
                        dst_ip: info_pkt.dst_ip,
                        src_port: info_pkt.src_port,
                        dst_port: info_pkt.dst_port,
                        protocol: info_pkt.protocol,
                        pid: if pid != 0 { Some(pid) } else { None },
                        kinds: vec![
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

            offset += hdr.next_offset();
        }

        Ok(true)
    }

    /// Collect enrichment results and attach to flows (non-blocking).
    pub fn collect_enrichment_results(&mut self) {
        for result in self.enrich_pool.drain_results() {
            if result.success {
                match result.kind {
                    synapse_common::EnrichmentKind::DnsReverse => {
                        info!(
                            "enrich: dns → {}",
                            result.dns_name.as_deref().unwrap_or("?"),
                        );
                        self.tracker.attach_enrichment(
                            result.flow_id,
                            result.dns_name,
                            None,
                            None,
                            None,
                            None,
                        );
                    }
                    synapse_common::EnrichmentKind::ProcessAttribution => {
                        info!(
                            "enrich: process → {} (start={:?})",
                            result.process_path.as_deref().unwrap_or("?"),
                            result.process_start_time,
                        );
                        self.tracker.attach_enrichment(
                            result.flow_id,
                            None,
                            result.process_path,
                            result.process_start_time,
                            None,
                            None,
                        );
                    }
                    synapse_common::EnrichmentKind::GeoIp => {
                        self.tracker.attach_enrichment(
                            result.flow_id,
                            None,
                            None,
                            None,
                            result.country_code,
                            None,
                        );
                    }
                    synapse_common::EnrichmentKind::Reputation => {
                        self.tracker.attach_enrichment(
                            result.flow_id,
                            None,
                            None,
                            None,
                            None,
                            result.reputation_score,
                        );
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Test the real determine_local_port() with an inbound packet.
    #[test]
    fn test_determine_local_port_inbound_real_code_path() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        let (local_port, remote_port) = determine_local_port(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            local_ip,
            50000,
            local_ip,
        );

        assert_eq!(
            local_port, 50000,
            "inbound packet: local_port must be 50000 (dst_port), NOT 443 (src_port). \
             This is the real production code path — determine_local_port() with the \
             actual system-detected local IP."
        );
        assert_eq!(remote_port, 443);
    }

    /// Test the real determine_local_port() with an outbound packet.
    #[test]
    fn test_determine_local_port_outbound_real_code_path() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        let (local_port, remote_port) = determine_local_port(
            local_ip,
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
            local_ip,
        );

        assert_eq!(local_port, 50000);
        assert_eq!(remote_port, 443);
    }

    /// Test determine_local_port() when neither IP matches local (fallback).
    #[test]
    fn test_determine_local_port_neither_matches_fallback() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        let (local_port, remote_port) = determine_local_port(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            local_ip,
        );

        assert_eq!(local_port, 12345);
        assert_eq!(remote_port, 443);
    }

    /// Test detect_local_ip() actually returns something on a live system.
    #[test]
    fn test_detect_local_ip_returns_non_loopback() {
        let ip = detect_local_ip().expect("detect_local_ip() returned None on live system");
        assert!(!ip.is_unspecified(), "local IP must not be 0.0.0.0");
        assert!(
            !ip.is_loopback(),
            "local IP must not be loopback (127.x.x.x)"
        );
    }

    /// Regression test: local IP numerically larger than remote IP.
    #[test]
    fn test_determine_remote_ip_local_larger_than_remote() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        let remote = determine_remote_ip(
            IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202)),
            local_ip,
            local_ip,
        );
        assert_eq!(
            remote,
            IpAddr::V4(Ipv4Addr::new(52, 73, 240, 202)),
            "must return remote IP (52.73.240.202), not local IP ({local_ip})"
        );
    }

    /// Regression test: local IP numerically smaller than remote IP.
    #[test]
    fn test_determine_remote_ip_local_smaller_than_remote() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        let remote = determine_remote_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), local_ip, local_ip);
        assert_eq!(
            remote,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            "must return remote IP (8.8.8.8), not local IP ({local_ip})"
        );
    }

    /// Test determine_remote_ip() when a_ip is local — returns b_ip.
    #[test]
    fn test_determine_remote_ip_a_ip_is_local() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        let remote =
            determine_remote_ip(local_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), local_ip);
        assert_eq!(remote, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    }

    /// Test determine_remote_ip() when neither IP matches local (fallback to b_ip).
    #[test]
    fn test_determine_remote_ip_neither_matches_fallback() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        let remote = determine_remote_ip(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_ip,
        );
        assert_eq!(
            remote,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            "fallback should return b_ip (the larger address)"
        );
    }

    // BPF header tests

    #[test]
    fn test_bpf_wordalign() {
        assert_eq!(bpf_wordalign(0), 0);
        assert_eq!(bpf_wordalign(1), 4);
        assert_eq!(bpf_wordalign(2), 4);
        assert_eq!(bpf_wordalign(3), 4);
        assert_eq!(bpf_wordalign(4), 4);
        assert_eq!(bpf_wordalign(5), 8);
        assert_eq!(bpf_wordalign(7), 8);
        assert_eq!(bpf_wordalign(8), 8);
    }

    #[test]
    fn test_bpf_hdr_size() {
        assert_eq!(BpfHdr::SIZE, 20);
    }

    #[test]
    fn test_bpf_hdr_from_bytes_too_short() {
        let buf = [0u8; 10];
        assert!(BpfHdr::from_bytes(&buf).is_none());
    }

    #[test]
    fn test_bpf_hdr_from_bytes_valid() {
        let mut buf = [0u8; 20];
        // tv_sec = 1 (0x00000001 in native bytes)
        buf[0..4].copy_from_slice(&1u32.to_ne_bytes());
        // tv_usec = 500000
        buf[4..8].copy_from_slice(&500000u32.to_ne_bytes());
        // bh_caplen = 100
        buf[8..12].copy_from_slice(&100u32.to_ne_bytes());
        // bh_datalen = 1500
        buf[12..16].copy_from_slice(&1500u32.to_ne_bytes());
        // bh_hdrlen = 20
        buf[16..18].copy_from_slice(&20u16.to_ne_bytes());

        let hdr = BpfHdr::from_bytes(&buf).unwrap();
        assert_eq!(hdr.tv_sec, 1);
        assert_eq!(hdr.tv_usec, 500000);
        assert_eq!(hdr.bh_caplen, 100);
        assert_eq!(hdr.bh_datalen, 1500);
        assert_eq!(hdr.bh_hdrlen, 20);
        // next_offset = wordalign(20 + 100) = wordalign(120) = 120
        assert_eq!(hdr.next_offset(), 120);
    }

    #[test]
    fn test_bpf_hdr_next_offset_word_aligned() {
        let mut buf = [0u8; 20];
        buf[8..12].copy_from_slice(&98u32.to_ne_bytes()); // caplen=98
        buf[16..18].copy_from_slice(&24u16.to_ne_bytes()); // hdrlen=24
                                                           // 24 + 98 = 122 → wordalign(122) = 124
        let hdr = BpfHdr::from_bytes(&buf).unwrap();
        assert_eq!(hdr.next_offset(), 124);
    }

    #[test]
    fn test_parse_ip_frame_too_short() {
        assert!(parse_ip_frame(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_ipv4_minimal() {
        // 54 bytes: 14 eth + 20 ip + 20 tcp (minimum for TCP ports)
        let mut frame = vec![0u8; 54];
        frame[12] = 0x08; // EtherType = IPv4
        frame[13] = 0x00;
        frame[14] = 0x45; // IHL=5, Version=4
        frame[23] = 6; // Protocol = TCP
                       // total length at 16..18
        frame[16] = 0x00;
        frame[17] = 0x36; // total_len = 54

        let pkt = parse_ip_frame(&frame).unwrap();
        assert_eq!(pkt.protocol, 6);
        assert_eq!(pkt.length, 54);
    }

    #[test]
    fn test_parse_ipv4_with_ports() {
        let mut frame = vec![0u8; 54]; // 14 eth + 20 ip + 20 tcp
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45; // IHL=5
        frame[23] = 6; // TCP
                       // Total length
        frame[16] = 0x00;
        frame[17] = 34;
        // TCP src port at offset 34 (14+20)
        frame[34] = 0x1F; // src port 8000 (0x1F40)
        frame[35] = 0x40;
        // TCP dst port at offset 36
        frame[36] = 0x01; // dst port 443 (0x01BB)
        frame[37] = 0xBB;

        let pkt = parse_ip_frame(&frame).unwrap();
        assert_eq!(pkt.src_port, 8000);
        assert_eq!(pkt.dst_port, 443);
    }

    #[test]
    fn test_parse_ipv6_minimal() {
        // 60 bytes: 14 eth + 40 ipv6 + 6 minimal TCP header (ports + data offset)
        let mut frame = vec![0u8; 60];
        frame[12] = 0x86;
        frame[13] = 0xDD; // EtherType = IPv6
        frame[20] = 0x06; // Next header = TCP

        let pkt = parse_ip_frame(&frame).unwrap();
        assert_eq!(pkt.protocol, 6);
    }

    #[test]
    fn test_parse_ipv6_too_short() {
        let mut frame = vec![0u8; 40];
        frame[12] = 0x86;
        frame[13] = 0xDD;
        assert!(parse_ip_frame(&frame).is_none());
    }
}
