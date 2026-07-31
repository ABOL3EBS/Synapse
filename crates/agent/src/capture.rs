// crates/agent/src/capture.rs
//
// CaptureEngine — extracted from main.rs to keep main under 500 lines.
// Pure structural extraction: all logic moved verbatim, no changes to
// internal behavior.
//
// Justification >600 lines: capture.rs owns the entire hot-path — BPF reads,
// packet parsing (IPv4+IPv6), direction resolution, flow tracker integration,
// enrichment dispatch, verdict handling, enforcement guards, and IPC send.
// Splitting any of these into separate modules would add import overhead
// without reducing complexity, since they share mutable state (CaptureEngine).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use log::{debug, error, info, warn};
use synapse_common::{EnforcementCommand, EnrichmentKind, EnrichmentRequest, PacketInfo};

use crate::detectors;
use crate::detectors::cross_flow::CrossFlowState;
use crate::enrichment::EnrichmentPool;
use crate::flow::{self, FlowTracker};
use crate::storage::StorageEvent;
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
        let hdr = Self {
            tv_sec: i32::from_ne_bytes(buf[0..4].try_into().ok()?),
            tv_usec: i32::from_ne_bytes(buf[4..8].try_into().ok()?),
            bh_caplen: u32::from_ne_bytes(buf[8..12].try_into().ok()?),
            bh_datalen: u32::from_ne_bytes(buf[12..16].try_into().ok()?),
            bh_hdrlen: u16::from_ne_bytes(buf[16..18].try_into().ok()?),
        };
        // S6: Sanity-check bh_hdrlen. Kernel sets this to sizeof(bpf_hdr) (20)
        // or sizeof(bpf_hdr32) (24) on macOS. A value >128 is impossible
        // from a valid kernel and indicates buffer corruption.
        if hdr.bh_hdrlen as usize > 128 {
            return None;
        }
        Some(hdr)
    }

    pub fn next_offset(&self) -> Option<usize> {
        let total = (self.bh_hdrlen as usize).checked_add(self.bh_caplen as usize)?;
        Some(bpf_wordalign(total))
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
            // S7: Validate frame has room for TCP/UDP header (4 bytes ports)
            // after the 40-byte IPv6 fixed header.
            let t = ip + 40;
            if frame.len() < t + 4 {
                return None;
            }
            (
                u16::from_be_bytes([frame[t], frame[t + 1]]),
                u16::from_be_bytes([frame[t + 2], frame[t + 3]]),
            )
        }
        _ => (0, 0),
    };
    // IPv6 payload_length is at bytes 4-5 of the IPv6 header (offset 18-19 in frame).
    let payload_len = u16::from_be_bytes([frame[ip + 4], frame[ip + 5]]);
    let total_len = if payload_len > 0 {
        payload_len
    } else {
        // Jumbo payload or extension header — approximate from captured frame length.
        (frame.len() - 14) as u16
    };
    Some(PacketInfo {
        src_ip,
        dst_ip,
        src_port: sp,
        dst_port: dp,
        protocol: nh,
        length: total_len,
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

/// Detect the default gateway IP via the macOS/BSD routing socket sysctl.
///
/// Calls sysctl(CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY)
/// which returns a packed buffer of rt_msghdr messages — one per gateway
/// route. We walk them and return the gateway address from the first entry
/// that has both RTF_GATEWAY and RTF_UP set and a non-loopback destination.
///
/// No subprocess is spawned; all work is done via libc.
pub fn detect_default_gateway() -> Option<IpAddr> {
    // sysctl mib: net.route.0.inet.flags.gateway
    // These are standard BSD/Darwin values; defined locally to avoid
    // relying on libc re-exporting every platform-specific routing constant.
    const NET_RT_FLAGS: libc::c_int = 2;

    let mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        NET_RT_FLAGS,
        libc::RTF_GATEWAY,
    ];

    // First call: determine required buffer size.
    let mut needed: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            6,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret < 0 || needed == 0 {
        warn!(
            "sysctl route size query failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }

    // Second call: fill buffer. Kernel may return a slightly smaller value
    // than `needed` if routes changed between calls — truncate to actual.
    let mut buf = vec![0u8; needed];
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            6,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut needed,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret < 0 {
        warn!(
            "sysctl route fill failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    buf.truncate(needed);

    rt_buf_find_gateway(&buf)
}

/// Walk a sysctl routing table buffer and return the gateway address from
/// the first entry with RTF_GATEWAY | RTF_UP. Helper for detect_default_gateway.
fn rt_buf_find_gateway(buf: &[u8]) -> Option<IpAddr> {
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
    let mut offset = 0usize;

    while offset + hdr_size <= buf.len() {
        // SAFETY: buf is kernel-provided, bounds-checked above.
        let rtm: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::rt_msghdr) };
        let msg_len = rtm.rtm_msglen as usize;
        if msg_len < hdr_size || offset + msg_len > buf.len() {
            break;
        }

        if rtm.rtm_flags & (libc::RTF_GATEWAY | libc::RTF_UP) == (libc::RTF_GATEWAY | libc::RTF_UP)
        {
            let msg = &buf[offset..offset + msg_len];
            if let Some(gw) = rt_msg_gateway(msg, &rtm) {
                if !gw.is_loopback() && !gw.is_unspecified() {
                    debug!("detected default gateway via sysctl: {gw}");
                    return Some(gw);
                }
            }
        }
        offset += msg_len;
    }

    warn!("could not detect default gateway from routing table");
    None
}

/// Extract the RTA_GATEWAY sockaddr from a single rt_msghdr message.
fn rt_msg_gateway(msg: &[u8], rtm: &libc::rt_msghdr) -> Option<IpAddr> {
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
    let sa_buf = msg.get(hdr_size..)?;

    // Walk sockaddrs in RTA bit order (bit 0 = RTA_DST, bit 1 = RTA_GATEWAY, …).
    // Each sockaddr is padded to the next sizeof(long) boundary (8 bytes on Darwin).
    let mut pos = 0usize;
    for bit in 0..32i32 {
        let rta = 1 << bit;
        if rtm.rtm_addrs & rta == 0 {
            continue;
        }
        if pos >= sa_buf.len() {
            break;
        }
        let sa_len = sa_buf[pos] as usize;
        let actual = if sa_len == 0 {
            std::mem::size_of::<libc::sockaddr>()
        } else {
            sa_len
        };
        let rounded = rt_roundup(actual);

        if rta == libc::RTA_GATEWAY {
            return rt_parse_sockaddr(sa_buf.get(pos..pos + actual)?);
        }
        pos += rounded;
    }
    None
}

/// BSD RT_ROUNDUP: align to sizeof(long) (8 bytes on 64-bit Darwin).
fn rt_roundup(n: usize) -> usize {
    const ALIGN: usize = std::mem::size_of::<libc::c_long>();
    if n == 0 {
        ALIGN
    } else {
        (n + ALIGN - 1) & !(ALIGN - 1)
    }
}

/// Parse an IpAddr from a raw sockaddr slice (AF_INET or AF_INET6).
fn rt_parse_sockaddr(buf: &[u8]) -> Option<IpAddr> {
    if buf.len() < 2 {
        return None;
    }
    match buf[1] as libc::c_int {
        libc::AF_INET => {
            if buf.len() < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // SAFETY: bounds checked above.
            let sin: libc::sockaddr_in =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::sockaddr_in) };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(
                sin.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            if buf.len() < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let sin6: libc::sockaddr_in6 =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Detect ALL local IPs (IPv4 + IPv6) and subnet broadcast addresses.
/// Broadcast is computed from ifa_netmask alongside each address — same
/// getifaddrs() call, zero extra syscalls. Returns a HashSet for O(1)
/// lookup in the block guard.
pub fn detect_own_ips() -> HashSet<IpAddr> {
    use std::ffi::CStr;

    let mut ifa_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
    let ret = unsafe { libc::getifaddrs(&mut ifa_ptr) };
    if ret != 0 {
        return HashSet::new();
    }

    let mut ips = HashSet::new();
    let mut ptr = ifa_ptr;
    while !ptr.is_null() {
        let ifa = unsafe { &*ptr };
        if ifa.ifa_flags & libc::IFF_LOOPBACK as u32 != 0 {
            ptr = ifa.ifa_next;
            continue;
        }
        if let Some(ip) = sockaddr_to_ip(ifa.ifa_addr) {
            if !ip.is_unspecified() {
                let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
                debug!("own IP detected: {} on {}", ip, name.to_string_lossy());
                ips.insert(ip);
                // Compute subnet broadcast: ip | !mask.
                if let Some(bcast) = compute_broadcast(ip, ifa.ifa_netmask) {
                    debug!("subnet broadcast: {} on {}", bcast, name.to_string_lossy());
                    ips.insert(bcast);
                }
            }
        }
        ptr = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(ifa_ptr) };
    ips
}

/// Compute subnet broadcast address: ip | !mask.
/// Handles both IPv4 and IPv6. Returns None on parse failure.
fn compute_broadcast(ip: IpAddr, netmask: *const libc::sockaddr) -> Option<IpAddr> {
    let mask_ip = sockaddr_to_ip(netmask)?;
    match (ip, mask_ip) {
        (IpAddr::V4(addr), IpAddr::V4(mask)) => {
            let bcast = u32::from_be_bytes(addr.octets()) | !u32::from_be_bytes(mask.octets());
            Some(IpAddr::V4(std::net::Ipv4Addr::from(bcast)))
        }
        (IpAddr::V6(addr), IpAddr::V6(mask)) => {
            let addr_bits = u128::from_be_bytes(addr.octets());
            let mask_bits = u128::from_be_bytes(mask.octets());
            let bcast = addr_bits | !mask_bits;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bcast.to_be_bytes())))
        }
        _ => None,
    }
}

/// Convert a sockaddr to an IpAddr (IPv4 or IPv6). Returns None for AF_UNIX etc.
fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    if addr.is_null() {
        return None;
    }
    let sa = unsafe { &*addr };
    match sa.sa_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(addr as *const libc::sockaddr_in) };
            let octets = sin.sin_addr.s_addr.to_ne_bytes();
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
            let octets = sin6.sin6_addr.s6_addr;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

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
        // P1: Lock-free snapshot via arc_swap — no mutex contention on hot path.
        // R10: If local_ip is unknown, skip all expired flow processing —
        // direction resolution requires a known local IP.
        let local_ip = match **self.caches.local_ip.load() {
            Some(ip) => ip,
            None => {
                warn!(
                    "local_ip unknown — skipping expired flow processing ({} flows skipped)",
                    expired.len()
                );
                return;
            }
        };

        for &flow_id in expired {
            if let Some(flow_ref) = self.tracker.get(flow_id) {
                let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                let common_flow = std::sync::Arc::new(common_flow);
                let (findings, cb_transitions) = detectors::run_detectors(
                    &self.detectors,
                    std::sync::Arc::clone(&common_flow),
                    self.config.detector_timeout,
                    &mut self.circuit_breaker,
                    &self.config.cb_config,
                );
                self.emit_cb_transitions(cb_transitions);
                let features = synapse_common::FlowFeatures::from_flow(&common_flow);
                let (verdict, score) = self.decision_engine.evaluate(&features, &findings);
                self.handle_verdict(flow_id, &common_flow, &findings, score, verdict, local_ip);
            }
        }
    }

    /// Re-run detectors on active flows due for periodic re-evaluation.
    /// Verbatim extraction from main.rs lines 528-602.
    pub fn process_re_evaluate_flows(&mut self, re_evaluate: &[u64]) {
        // Temporarily take local_ip to avoid borrow conflicts.
        // R9: Recover from mutex poison — keep last-known value rather than aborting.
        // P1: Lock-free snapshot via arc_swap.
        // R10: If local_ip is unknown, skip all re-evaluation —
        // direction resolution requires a known local IP.
        let local_ip = match **self.caches.local_ip.load() {
            Some(ip) => ip,
            None => {
                warn!(
                    "local_ip unknown — skipping re-evaluation ({} flows skipped)",
                    re_evaluate.len()
                );
                return;
            }
        };

        for &flow_id in re_evaluate {
            if let Some(flow_ref) = self.tracker.get(flow_id) {
                let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                let common_flow = std::sync::Arc::new(common_flow);
                let (findings, cb_transitions) = detectors::run_detectors(
                    &self.detectors,
                    std::sync::Arc::clone(&common_flow),
                    self.config.detector_timeout,
                    &mut self.circuit_breaker,
                    &self.config.cb_config,
                );
                self.emit_cb_transitions(cb_transitions);
                let features = synapse_common::FlowFeatures::from_flow(&common_flow);
                let (verdict, score) = self.decision_engine.evaluate(&features, &findings);
                self.handle_verdict(flow_id, &common_flow, &findings, score, verdict, local_ip);
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
        local_ip: IpAddr,
    ) {
        let a_ip = flow.a_ip;
        let b_ip = flow.b_ip;

        match verdict {
            synapse_common::Verdict::Allow => {
                info!("[ALLOW] flow={}", flow_id);
            }
            synapse_common::Verdict::Alert { ref reason } => {
                let remote = determine_remote_ip(a_ip, b_ip, local_ip);
                info!("[ALERT] flow={} remote={} {}", flow_id, remote, reason);
                if let Some(ref tx) = self.storage_tx {
                    let _ = tx.send(StorageEvent::VerdictDecided {
                        flow: flow.clone(),
                        verdict: "Alert".to_string(),
                        reason: reason.clone(),
                        composite_score,
                        ttl_ms: None,
                        findings: findings.to_vec(),
                    });
                }
            }
            synapse_common::Verdict::Block { ttl, ref reason } => {
                let remote = determine_remote_ip(a_ip, b_ip, local_ip);
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
                                flow: flow.clone(),
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

                let (local_port, pid) = {
                    // P1: Lock-free snapshot via arc_swap — no mutex on hot path.
                    let cache = self.caches.port_pid.load();
                    let lookup = |port: u16, proto: u8| -> Option<(u16, u32)> {
                        let key = (port, proto);
                        cache.get(&key).map(|&pid| (port, pid))
                    };
                    // P1 + R10: Lock-free snapshot. If local_ip unknown,
                    // skip direction resolution rather than misclassifying.
                    let current_local_ip = match **self.caches.local_ip.load() {
                        Some(ip) => ip,
                        None => {
                            debug!("local_ip unknown — skipping packet (direction unknown)");
                            continue;
                        }
                    };
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
                    // Re-compute local IP for direction resolution (current_local_ip
                    // is scoped inside the pid lookup block above).
                    let cf_local_ip = match **self.caches.local_ip.load() {
                        Some(ip) => ip,
                        None => {
                            debug!("cross-flow: local_ip unknown — skipping record");
                            continue;
                        }
                    };
                    let remote_ip = if info_pkt.src_ip == cf_local_ip {
                        info_pkt.dst_ip
                    } else {
                        info_pkt.src_ip
                    };
                    if let Ok(mut state) = self.cross_flow_state.lock() {
                        state.record_connection(remote_ip, info_pkt.protocol, info_pkt.dst_port);
                    }

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
        #[derive(Default)]
        struct FlowEnrichment {
            dns_name: Option<String>,
            process_path: Option<String>,
            process_start_time: Option<f64>,
            country_code: Option<String>,
            asn: Option<u32>,
            reputation_score: Option<f32>,
        }

        let mut batch: HashMap<u64, FlowEnrichment> = HashMap::new();
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
            self.tracker.attach_enrichment(
                flow_id,
                e.dns_name,
                e.process_path,
                e.process_start_time,
                e.country_code,
                e.asn,
                e.reputation_score,
            );
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
        assert_eq!(hdr.next_offset(), Some(120));
    }

    #[test]
    fn test_bpf_hdr_next_offset_word_aligned() {
        let mut buf = [0u8; 20];
        buf[8..12].copy_from_slice(&98u32.to_ne_bytes()); // caplen=98
        buf[16..18].copy_from_slice(&24u16.to_ne_bytes()); // hdrlen=24
                                                           // 24 + 98 = 122 → wordalign(122) = 124
        let hdr = BpfHdr::from_bytes(&buf).unwrap();
        assert_eq!(hdr.next_offset(), Some(124));
    }

    #[test]
    fn test_bpf_hdr_hdrlen_too_large_rejected() {
        let mut buf = [0u8; 20];
        buf[8..12].copy_from_slice(&100u32.to_ne_bytes()); // caplen
        buf[16..18].copy_from_slice(&200u16.to_ne_bytes()); // hdrlen=200 > 128
        assert!(
            BpfHdr::from_bytes(&buf).is_none(),
            "bh_hdrlen > 128 must be rejected"
        );
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

    #[test]
    fn test_parse_ipv6_payload_length() {
        // 14 eth + 40 ipv6 header + 6 minimal TCP header = 60 bytes total.
        // IPv6 payload_length (bytes 4-5 of IPv6 header = frame[18..20]) = 6.
        let mut frame = vec![0u8; 60];
        frame[12] = 0x86;
        frame[13] = 0xDD; // EtherType = IPv6
        frame[14] = 0x60; // version=6
        frame[20] = 0x06; // Next header = TCP
                          // payload_length = 6 (TCP header+data after the 40-byte IPv6 header)
        frame[18] = 0x00;
        frame[19] = 0x06;

        let pkt = parse_ip_frame(&frame).unwrap();
        assert_eq!(
            pkt.length, 6,
            "IPv6 payload_length must be parsed, not zero"
        );
    }

    #[test]
    fn test_parse_ipv6_payload_length_zero_fallback() {
        // When payload_length is 0 (jumbo), should fall back to frame length minus Ethernet header.
        let mut frame = vec![0u8; 120];
        frame[12] = 0x86;
        frame[13] = 0xDD; // EtherType = IPv6
        frame[14] = 0x60; // version=6
        frame[20] = 0x06; // Next header = TCP
                          // payload_length stays 0x0000 (jumbo case)

        let pkt = parse_ip_frame(&frame).unwrap();
        assert_eq!(
            pkt.length, 106,
            "Zero payload_length should fall back to frame_len - 14"
        );
    }

    #[test]
    fn test_detect_default_gateway_returns_valid_ip() {
        let gw = detect_default_gateway();
        // On any connected Mac, we should get a valid gateway IP.
        assert!(
            gw.is_some(),
            "gateway detection should succeed on a connected host"
        );
        let ip = gw.unwrap();
        // Gateway must not be unspecified or loopback.
        assert!(!ip.is_unspecified(), "gateway must not be 0.0.0.0");
        assert!(!ip.is_loopback(), "gateway must not be loopback");
    }

    #[test]
    fn test_detect_own_ips_includes_all_local_addresses() {
        let ips = detect_own_ips();
        // Must have at least the primary IPv4 address.
        let has_ipv4 = ips.iter().any(|ip| ip.is_ipv4());
        assert!(has_ipv4, "own IPs must include at least one IPv4 address");

        // Must contain a subnet broadcast (computed from ifa_netmask).
        // On any real interface, broadcast != address, so set size > 1.
        assert!(
            ips.len() >= 2,
            "own IPs must include at least one address + its broadcast, got {}",
            ips.len()
        );

        // Must not contain loopback or unspecified.
        for ip in &ips {
            assert!(!ip.is_loopback(), "own IPs must not contain loopback: {ip}");
            assert!(
                !ip.is_unspecified(),
                "own IPs must not contain unspecified: {ip}"
            );
        }
    }
}
