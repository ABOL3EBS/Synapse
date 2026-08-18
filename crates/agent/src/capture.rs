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
use synapse_common::{
    EnforcementCommand, EnrichmentKind, EnrichmentRequest, PacketInfo, ResolvedFlow,
};

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

/// Determine the remote (IP, port) from a raw packet using the detected local IP.
/// Used for CrossFlow recording: using info_pkt.dst_port alone is wrong for inbound
/// flows where dst_port is the local service port, not the remote port.
/// Mirrors determine_local_port() — same three-branch logic, opposite side returned.
pub fn determine_remote_endpoint(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    local_ip: IpAddr,
) -> (IpAddr, u16) {
    if src_ip == local_ip {
        (dst_ip, dst_port) // outbound: we are src, remote is dst
    } else if dst_ip == local_ip {
        (src_ip, src_port) // inbound: remote is src
    } else {
        (dst_ip, dst_port) // neither matches — outbound default
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
    if ret < 0 {
        warn!(
            "sysctl route size query failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    if needed == 0 {
        // sysctl succeeded but no RTF_GATEWAY routes exist in the kernel's IPv4
        // routing table. Common on VPN networks (e.g. Pritunl) that replace the
        // default route with /1 interface routes lacking the RTF_GATEWAY flag.
        // Fall back to NET_RT_DUMP which returns ALL routes regardless of flags,
        // then parse the default route's gateway from that buffer.
        debug!("no RTF_GATEWAY routes in routing table — falling back to RT_DUMP");
        return detect_gateway_via_rt_dump();
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

    rt_buf_find_gateway(&buf, true)
}

/// Fallback gateway detection using NET_RT_DUMP when NET_RT_FLAGS|RTF_GATEWAY
/// returns no entries. NET_RT_DUMP returns all routes regardless of flags, so
/// it finds the default route even on VPN networks where the routing table
/// lacks RTF_GATEWAY-flagged entries.
pub(crate) fn detect_gateway_via_rt_dump() -> Option<IpAddr> {
    const NET_RT_DUMP: libc::c_int = 1;
    let mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        NET_RT_DUMP,
        0,
    ];

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
            "NET_RT_DUMP size query failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }

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
            "NET_RT_DUMP fill failed: {}",
            std::io::Error::last_os_error()
        );
        return None;
    }
    buf.truncate(needed);

    // require_gateway_flag=false: NET_RT_DUMP returns ALL routes regardless of
    // flags. Routes lacking RTF_GATEWAY are still valid when that flag is absent
    // from the entire routing table (e.g. Pritunl /1 interface routes). Interface
    // routes use AF_LINK gateways which rt_msg_dst_and_gateway skips, so they are
    // excluded naturally — no additional filter needed.
    rt_buf_find_gateway(&buf, false)
}

/// Walk a routing table buffer and return the gateway for the default route.
///
/// `require_gateway_flag`:
///   - `true` — only consider routes with `RTF_GATEWAY | RTF_UP` set.
///     Used by the primary sysctl path (NET_RT_FLAGS|RTF_GATEWAY),
///     which already pre-filters to gateway routes.
///   - `false` — only require `RTF_UP`. Used by the RT_DUMP fallback path
///     when `needed == 0` means no RTF_GATEWAY routes exist in the
///     routing table (e.g. Pritunl VPN replaces the default with
///     interface routes). Routes with AF_LINK (non-IP) gateways are
///     skipped automatically by `rt_msg_dst_and_gateway`.
///
/// Prefer the entry whose RTA_DST is 0.0.0.0 (the true default). Fall back to
/// the first qualifying non-loopback, non-unspecified gateway if no 0.0.0.0
/// entry exists.
fn rt_buf_find_gateway(buf: &[u8], require_gateway_flag: bool) -> Option<IpAddr> {
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
    let mut offset = 0usize;
    let mut fallback: Option<IpAddr> = None;

    while offset + hdr_size <= buf.len() {
        // SAFETY: buf is kernel-provided, bounds-checked above.
        let rtm: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::rt_msghdr) };
        let msg_len = rtm.rtm_msglen as usize;
        if msg_len < hdr_size || offset + msg_len > buf.len() {
            break;
        }

        let required = if require_gateway_flag {
            libc::RTF_GATEWAY | libc::RTF_UP
        } else {
            libc::RTF_UP
        };
        if rtm.rtm_flags & required == required {
            let msg = &buf[offset..offset + msg_len];
            if let Some((dst, gw)) = rt_msg_dst_and_gateway(msg, &rtm) {
                if !gw.is_loopback() && !gw.is_unspecified() {
                    if dst.is_unspecified() {
                        let via = if require_gateway_flag {
                            "sysctl"
                        } else {
                            "RT_DUMP"
                        };
                        debug!("detected default gateway via {via}: {gw}");
                        return Some(gw);
                    }
                    if fallback.is_none() {
                        fallback = Some(gw);
                    }
                }
            }
        }
        offset += msg_len;
    }

    if let Some(gw) = fallback {
        let via = if require_gateway_flag {
            "sysctl"
        } else {
            "RT_DUMP"
        };
        debug!("detected default gateway via {via} (fallback): {gw}");
        return Some(gw);
    }
    warn!("could not detect default gateway from routing table");
    None
}

/// Extract RTA_DST and RTA_GATEWAY sockaddrs from a single rt_msghdr message.
/// Returns (dst, gateway). Either may be None if the sockaddr is absent or
/// of an unrecognised address family.
fn rt_msg_dst_and_gateway(msg: &[u8], rtm: &libc::rt_msghdr) -> Option<(IpAddr, IpAddr)> {
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
    let sa_buf = msg.get(hdr_size..)?;

    // Walk sockaddrs in RTA bit order (bit 0 = RTA_DST, bit 1 = RTA_GATEWAY, …).
    // Each sockaddr is padded to the next sizeof(long) boundary (8 bytes on Darwin).
    let mut pos = 0usize;
    let mut dst: Option<IpAddr> = None;
    let mut gw: Option<IpAddr> = None;

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

        if rta == libc::RTA_DST {
            dst = rt_parse_sockaddr(sa_buf.get(pos..pos + actual)?);
        } else if rta == libc::RTA_GATEWAY {
            gw = rt_parse_sockaddr(sa_buf.get(pos..pos + actual)?);
        }

        if dst.is_some() && gw.is_some() {
            break;
        }
        pos += rounded;
    }

    match (dst, gw) {
        (Some(d), Some(g)) => Some((d, g)),
        _ => None,
    }
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

/// Detect gateway IPs reachable via VPN tunnel interfaces (utun*, ppp*, tun*).
///
/// On Pritunl/OpenVPN, the physical router keeps the actual `default` routing
/// entry (e.g. 192.168.0.1 via en0). The VPN server endpoint only appears as
/// the RTA_GATEWAY field in /1-split or subnet routes via the tunnel interface:
///
///   0/1      192.168.10.1  UGScg  utun6
///   128.0/1  192.168.10.1  UGSc   utun6
///
/// This function reads RTA_GATEWAY from the routing table — NOT ifa_dstaddr
/// from getifaddrs(). On Pritunl/OpenVPN, ifa_dstaddr for a utun interface is
/// the machine's own tunnel IP (self-loop, e.g. 192.168.10.43 → 192.168.10.43),
/// not the VPN server. Using ifa_dstaddr was confirmed wrong against a live
/// routing table before this function was written (incident #5, 2026-08-09).
///
/// `own_ips` filters self-loop artifacts: utun subnet routes list the machine's
/// own tunnel IP as their gateway; filtering here keeps the returned set clean.
pub fn detect_vpn_gateway_peers(own_ips: &HashSet<IpAddr>) -> HashSet<IpAddr> {
    use std::ffi::CStr;

    const IF_NAMESIZE: usize = 16; // IFNAMSIZ on macOS/BSD

    const NET_RT_DUMP: libc::c_int = 1;
    let mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        NET_RT_DUMP,
        0,
    ];

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
        return HashSet::new();
    }

    let mut buf = vec![0u8; needed];
    let mut filled = needed;
    let ret = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            6,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut filled,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret < 0 {
        return HashSet::new();
    }
    buf.truncate(filled);

    collect_vpn_peers_from_buf(&buf, own_ips, |idx| {
        let mut name_buf = [0i8; IF_NAMESIZE];
        let ptr = unsafe { libc::if_indextoname(idx as libc::c_uint, name_buf.as_mut_ptr()) };
        if ptr.is_null() {
            return None;
        }
        Some(
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    })
}

/// Walk a routing-table buffer and collect VPN gateway IPs.
///
/// Extracted from `detect_vpn_gateway_peers` so the test suite can inject a
/// synthetic buffer and interface-name resolver without touching the sysctl layer.
///
/// For each RTF_UP route whose interface name (resolved by `iface_name_fn`)
/// matches a tunnel prefix (utun*/ppp*/tun*), the RTA_GATEWAY IP is extracted.
/// IPs present in `own_ips` are filtered before returning — this removes
/// self-loop gateway artifacts (the machine's own tunnel IP appearing as the
/// gateway of subnet routes) without requiring a separate getifaddrs() call.
fn collect_vpn_peers_from_buf(
    buf: &[u8],
    own_ips: &HashSet<IpAddr>,
    iface_name_fn: impl Fn(u32) -> Option<String>,
) -> HashSet<IpAddr> {
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
    let mut offset = 0usize;
    let mut peers: HashSet<IpAddr> = HashSet::new();

    while offset + hdr_size <= buf.len() {
        // SAFETY: buf is bounds-checked; read_unaligned handles unaligned access.
        let rtm: libc::rt_msghdr =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::rt_msghdr) };
        let msg_len = rtm.rtm_msglen as usize;
        if msg_len < hdr_size || offset + msg_len > buf.len() {
            break;
        }

        if rtm.rtm_flags & libc::RTF_UP != 0 {
            if let Some(name) = iface_name_fn(rtm.rtm_index as u32) {
                if is_tunnel_iface(&name) {
                    let msg = &buf[offset..offset + msg_len];
                    // rt_msg_dst_and_gateway reads RTA_GATEWAY from the routing table
                    // message — the gateway IP field, not the interface's own address.
                    // On Pritunl/OpenVPN, this yields 192.168.10.1 (VPN server), not
                    // 192.168.10.43 (the machine's own tunnel IP in ifa_dstaddr).
                    if let Some((_, gw)) = rt_msg_dst_and_gateway(msg, &rtm) {
                        if !gw.is_loopback() && !gw.is_unspecified() && !own_ips.contains(&gw) {
                            debug!("VPN peer gateway: {gw} via {name}");
                            peers.insert(gw);
                        }
                    }
                }
            }
        }

        offset += msg_len;
    }

    peers
}

/// Returns true for kernel tunnel interface name prefixes on macOS.
fn is_tunnel_iface(name: &str) -> bool {
    name.starts_with("utun") || name.starts_with("ppp") || name.starts_with("tun")
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

    // determine_remote_endpoint tests — these exercise the bug that was latent in
    // record_connection's old dst_port argument: inbound flows have dst_port=local
    // service port, NOT the remote's port. The old code would have record_connection
    // receiving 53 for an inbound-to-local:53 connection, incorrectly counting it
    // as "we sent a DNS query."

    #[test]
    fn test_remote_endpoint_outbound() {
        // Outbound DNS query: local:ephemeral → remote:53
        // remote_port must resolve to 53 (the remote DNS server port).
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let (r_ip, r_port) = determine_remote_endpoint(local, 55000, remote, 53, local);
        assert_eq!(r_ip, remote);
        assert_eq!(
            r_port, 53,
            "outbound DNS: remote_port must be 53, not the local ephemeral 55000"
        );
    }

    #[test]
    fn test_remote_endpoint_inbound_dns() {
        // Inbound connection to local DNS server: remote:random_port → local:53.
        // remote_port must resolve to random_port (the REMOTE side's port), NOT 53.
        // Before the fix, record_connection received info_pkt.dst_port = 53 here —
        // incorrectly counting an inbound connection as "we sent a DNS query."
        let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let remote = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let remote_ephemeral = 47382_u16;
        let (r_ip, r_port) = determine_remote_endpoint(remote, remote_ephemeral, local, 53, local);
        assert_eq!(r_ip, remote);
        assert_eq!(
            r_port, remote_ephemeral,
            "inbound to local:53: remote_port must be the remote's ephemeral port ({remote_ephemeral}), \
             NOT the local service port 53 — that was the pre-fix bug"
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

    // Build a minimal rt_msghdr + two sockaddr_in entries (dst, gateway) into a
    // buffer that rt_buf_find_gateway can parse. Both addresses are AF_INET.
    fn make_route_entry(
        flags: libc::c_int,
        dst_addr: std::net::Ipv4Addr,
        gw_addr: std::net::Ipv4Addr,
    ) -> Vec<u8> {
        use std::mem::size_of;

        let hdr_size = size_of::<libc::rt_msghdr>();
        let sin_size = size_of::<libc::sockaddr_in>();
        let rounded_sin = rt_roundup(sin_size); // 16 on Darwin
        let total = hdr_size + rounded_sin * 2;

        let mut buf = vec![0u8; total];

        // Write the rt_msghdr.
        let rtm = libc::rt_msghdr {
            rtm_msglen: total as u16,
            rtm_version: libc::RTM_VERSION as u8,
            rtm_type: libc::RTM_GET as u8,
            rtm_index: 0,
            rtm_flags: flags,
            rtm_addrs: libc::RTA_DST | libc::RTA_GATEWAY, // bits 0 and 1
            rtm_pid: 0,
            rtm_seq: 0,
            rtm_errno: 0,
            rtm_use: 0,
            rtm_inits: 0,
            rtm_rmx: unsafe { std::mem::zeroed() },
        };
        unsafe {
            std::ptr::write_unaligned(buf.as_mut_ptr() as *mut libc::rt_msghdr, rtm);
        }

        // Write dst sockaddr_in at hdr_size.
        let dst_sin = libc::sockaddr_in {
            sin_len: sin_size as u8,
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dst_addr.octets()),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            std::ptr::write_unaligned(
                buf.as_mut_ptr().add(hdr_size) as *mut libc::sockaddr_in,
                dst_sin,
            );
        }

        // Write gateway sockaddr_in at hdr_size + rounded_sin.
        let gw_sin = libc::sockaddr_in {
            sin_len: sin_size as u8,
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(gw_addr.octets()),
            },
            sin_zero: [0; 8],
        };
        unsafe {
            std::ptr::write_unaligned(
                buf.as_mut_ptr().add(hdr_size + rounded_sin) as *mut libc::sockaddr_in,
                gw_sin,
            );
        }

        buf
    }

    #[test]
    fn test_rt_buf_find_gateway_prefers_default_route_over_vpn_route() {
        // Simulate a routing table where a VPN-specific gateway route (dst=10.0.0.0)
        // appears BEFORE the true default route (dst=0.0.0.0) — the scenario that
        // caused the 172.18.22.1 false-positive. The fix must return the 0.0.0.0
        // entry's gateway, not the VPN entry's gateway.
        let vpn_gw = std::net::Ipv4Addr::new(10, 8, 0, 1);
        let lan_gw = std::net::Ipv4Addr::new(172, 18, 22, 1);
        let flags = libc::RTF_GATEWAY | libc::RTF_UP;

        let mut buf = Vec::new();
        // VPN route comes first: dst=10.0.0.0, gw=10.8.0.1
        buf.extend_from_slice(&make_route_entry(
            flags,
            std::net::Ipv4Addr::new(10, 0, 0, 0),
            vpn_gw,
        ));
        // Default route comes second: dst=0.0.0.0, gw=172.18.22.1
        buf.extend_from_slice(&make_route_entry(
            flags,
            std::net::Ipv4Addr::UNSPECIFIED,
            lan_gw,
        ));

        let result = rt_buf_find_gateway(&buf, true);
        assert_eq!(
            result,
            Some(IpAddr::V4(lan_gw)),
            "must return the 0.0.0.0 default route's gateway, not the VPN gateway"
        );
    }

    #[test]
    fn test_rt_buf_find_gateway_fallback_when_no_default_route() {
        // If no entry has dst=0.0.0.0, fall back to the first RTF_GATEWAY|RTF_UP entry.
        let only_gw = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let flags = libc::RTF_GATEWAY | libc::RTF_UP;
        let buf = make_route_entry(flags, std::net::Ipv4Addr::new(8, 8, 8, 0), only_gw);

        let result = rt_buf_find_gateway(&buf, true);
        assert_eq!(
            result,
            Some(IpAddr::V4(only_gw)),
            "fallback must return the only RTF_GATEWAY|RTF_UP entry when no 0.0.0.0 route exists"
        );
    }

    #[test]
    fn test_rt_buf_find_gateway_no_rtf_gateway_flag_still_finds_default_route() {
        // Simulate the Aug 6 2026 Pritunl VPN failure: the routing table has a
        // default route entry (dst=0.0.0.0 → gateway=172.18.22.1) but WITHOUT
        // RTF_GATEWAY set. The NET_RT_FLAGS|RTF_GATEWAY sysctl would return
        // needed == 0, so this buffer comes from the NET_RT_DUMP fallback path
        // which only requires RTF_UP.
        //
        // Verifies that rt_buf_find_gateway(&buf, false) finds the gateway even
        // when RTF_GATEWAY is absent — which is the specific condition that caused
        // the 1h45m block in incident #4.
        let lan_gw = std::net::Ipv4Addr::new(172, 18, 22, 1);
        // RTF_UP only — no RTF_GATEWAY — models VPN-modified routing table
        let flags = libc::RTF_UP;
        let buf = make_route_entry(flags, std::net::Ipv4Addr::UNSPECIFIED, lan_gw);

        let result = rt_buf_find_gateway(&buf, false);
        assert_eq!(
            result,
            Some(IpAddr::V4(lan_gw)),
            "RT_DUMP fallback must find gateway even when RTF_GATEWAY flag is absent"
        );

        // Confirm that the strict path (require_gateway_flag=true) does NOT find it,
        // which is exactly why the primary detection returns None on this routing table.
        let strict_result = rt_buf_find_gateway(&buf, true);
        assert_eq!(
            strict_result, None,
            "primary path must NOT find a route without RTF_GATEWAY (proves why detection failed)"
        );
    }

    #[test]
    fn test_detect_gateway_via_rt_dump_returns_valid_ip_on_connected_host() {
        // Live test: call detect_gateway_via_rt_dump() against the actual routing
        // table. On any machine with a working network connection this must succeed,
        // regardless of whether the primary RTF_GATEWAY sysctl would also succeed.
        let gw = detect_gateway_via_rt_dump();
        assert!(
            gw.is_some(),
            "RT_DUMP fallback must find a gateway on any connected host"
        );
        let ip = gw.unwrap();
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

    // ---------------------------------------------------------------------------
    // VPN peer detection tests
    // ---------------------------------------------------------------------------

    /// Build a minimal sockaddr_in byte buffer for a given IPv4 address.
    /// Layout: [sin_len(1), sin_family(1), sin_port(2), sin_addr(4), sin_zero(8)]
    /// sin_addr bytes are in network byte order (ip.octets() order).
    fn make_sockaddr_in_bytes(ip: std::net::Ipv4Addr) -> Vec<u8> {
        let mut buf = vec![0u8; std::mem::size_of::<libc::sockaddr_in>()];
        buf[0] = buf.len() as u8; // sin_len
        buf[1] = libc::AF_INET as u8; // sin_family
        buf[4..8].copy_from_slice(&ip.octets()); // sin_addr, network byte order
        buf
    }

    /// rt_roundup for 64-bit Darwin: align to 8 bytes (sizeof(long)).
    fn rt_roundup_test(n: usize) -> usize {
        const ALIGN: usize = 8;
        if n == 0 {
            ALIGN
        } else {
            (n + ALIGN - 1) & !(ALIGN - 1)
        }
    }

    /// Build a single synthetic rt_msghdr record with IPv4 DST and GATEWAY sockaddrs.
    fn build_rt_record(
        rtm_index: u16,
        rtm_flags: libc::c_int,
        dst_ip: std::net::Ipv4Addr,
        gw_ip: std::net::Ipv4Addr,
    ) -> Vec<u8> {
        let dst_sa = make_sockaddr_in_bytes(dst_ip);
        let gw_sa = make_sockaddr_in_bytes(gw_ip);
        let dst_rounded = rt_roundup_test(dst_sa.len());
        let gw_rounded = rt_roundup_test(gw_sa.len());

        let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
        let total = hdr_size + dst_rounded + gw_rounded;

        let mut buf = vec![0u8; total];

        let mut rtm: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        rtm.rtm_msglen = total as libc::c_ushort;
        rtm.rtm_version = 5; // RTM_VERSION on macOS
        rtm.rtm_type = 4; // RTM_GET
        rtm.rtm_index = rtm_index as libc::c_ushort;
        rtm.rtm_flags = rtm_flags;
        rtm.rtm_addrs = (libc::RTA_DST | libc::RTA_GATEWAY) as libc::c_int;
        unsafe { std::ptr::write_unaligned(buf.as_mut_ptr() as *mut libc::rt_msghdr, rtm) };

        buf[hdr_size..hdr_size + dst_sa.len()].copy_from_slice(&dst_sa);
        let gw_pos = hdr_size + dst_rounded;
        buf[gw_pos..gw_pos + gw_sa.len()].copy_from_slice(&gw_sa);

        buf
    }

    /// Confirm that collect_vpn_peers_from_buf:
    ///   - returns the real VPN server gateway (192.168.10.1) from both /1 split routes
    ///   - deduplicates those two routes to a single set entry
    ///   - does NOT return the machine's own tunnel IP (192.168.10.43) that appears
    ///     as the gateway of a self-referential subnet/host route
    ///
    /// This encodes the exact distinction that broke Option A (ifa_dstaddr extraction):
    /// on Pritunl/OpenVPN, ifa_dstaddr is the machine's own IP (self-loop), not the
    /// VPN server. RTA_GATEWAY from the routing table is the correct field.
    #[test]
    fn test_collect_vpn_peers_self_loop_excluded_real_gateway_included() {
        let utun6_idx: u16 = 42; // arbitrary synthetic interface index
        let gw_ip = std::net::Ipv4Addr::new(192, 168, 10, 1);
        let own_tunnel_ip = std::net::Ipv4Addr::new(192, 168, 10, 43);

        // own_ips represents the machine's own tunnel address, as detect_own_ips() returns.
        let own_ips: HashSet<IpAddr> = [IpAddr::V4(own_tunnel_ip)].into_iter().collect();

        let mut buf = Vec::new();
        // Route 1: 0/1 via 192.168.10.1 via utun6 (Pritunl split-half #1).
        buf.extend(build_rt_record(
            utun6_idx,
            libc::RTF_UP,
            std::net::Ipv4Addr::new(0, 0, 0, 0),
            gw_ip,
        ));
        // Route 2: 128.0/1 via 192.168.10.1 via utun6 (split-half #2 — same gateway).
        buf.extend(build_rt_record(
            utun6_idx,
            libc::RTF_UP,
            std::net::Ipv4Addr::new(128, 0, 0, 0),
            gw_ip,
        ));
        // Route 3: 192.168.10.43 → 192.168.10.43 (self-referential host route — the
        // utun interface's own inet address appearing as its own gateway). This is the
        // exact pattern that made Option A (ifa_dstaddr) wrong: we must NOT pick up
        // 192.168.10.43 as a VPN peer.
        buf.extend(build_rt_record(
            utun6_idx,
            libc::RTF_UP,
            own_tunnel_ip,
            own_tunnel_ip,
        ));

        let peers = collect_vpn_peers_from_buf(&buf, &own_ips, |idx| {
            if idx == utun6_idx as u32 {
                Some("utun6".to_string())
            } else {
                None
            }
        });

        assert!(
            peers.contains(&IpAddr::V4(gw_ip)),
            "VPN server gateway 192.168.10.1 must be in vpn_peers"
        );
        assert!(
            !peers.contains(&IpAddr::V4(own_tunnel_ip)),
            "Own tunnel IP 192.168.10.43 must NOT be in vpn_peers — it appears as \
             the gateway in self-referential routes but is the machine's own address. \
             This is the Option A failure mode."
        );
        assert_eq!(
            peers.len(),
            1,
            "Both /1 split routes share gateway 192.168.10.1 — \
             set insert must deduplicate to exactly 1 entry, got: {:?}",
            peers
        );
    }

    /// Live-system smoke test: vpn_peers must never contain loopback, unspecified,
    /// or own IPs regardless of whether VPN is connected.
    #[test]
    fn test_detect_vpn_gateway_peers_no_loopback_unspecified_or_own_ip() {
        let own = detect_own_ips();
        let peers = detect_vpn_gateway_peers(&own);
        for ip in &peers {
            assert!(
                !ip.is_loopback(),
                "loopback must not appear in vpn_peers: {ip}"
            );
            assert!(
                !ip.is_unspecified(),
                "unspecified must not appear in vpn_peers: {ip}"
            );
            assert!(
                !own.contains(ip),
                "own IP must not appear in vpn_peers after filtering: {ip}"
            );
        }
    }

    /// Verify that handle_verdict() with resolved=None skips enforcement entirely.
    ///
    /// The packet loop guards against resolved=None in production (it skips
    /// packets when local_ip is unknown, so set_resolved is always called with
    /// a real IP). This test exercises handle_verdict() in isolation so that
    /// any future code path that bypasses the packet-loop invariant cannot
    /// silently enforce against a wrong target. Three properties verified:
    ///
    /// 1. No enforcement command is sent (socket read end gets no bytes).
    /// 2. No panic — the function returns cleanly.
    /// 3. (Implicitly) No storage event fires — storage_tx is None, and the
    ///    function returns before the storage branches.
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
