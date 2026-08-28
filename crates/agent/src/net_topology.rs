// crates/agent/src/net_topology.rs
//
// OS network-topology introspection: local IP, default gateway, own IPs
// (+ subnet broadcasts), and VPN tunnel gateway peers. Raw syscall wrappers
// (getifaddrs, sysctl routing-table dumps) — zero CaptureEngine coupling
// (verified: no `self` in this file). Called only from main.rs, at startup
// and from the periodic own-ips/gateway refresh thread; never from
// CaptureEngine's own methods.
//
// CLAUDE.md rules #15/#16: this is the incident-history code. Rule #15 —
// a frozen (non-live-refreshed) exclusion set built from these functions'
// output caused CrossFlow to alert on the default gateway after a network
// change. Rule #16 — detect_default_gateway() silently returned None on a
// Pritunl VPN network (routing table had no RTF_GATEWAY-flagged routes),
// leaving the gateway unexcluded for 1h45m until a real block fired; fixed
// via the RT_DUMP fallback (detect_gateway_via_rt_dump) plus a
// last-known-gateway cache in the refresh thread (see main.rs). Any future
// change to gateway/VPN detection should start here, and any regression in
// this area should be treated as a candidate repeat of incidents #4/#5.

use std::collections::HashSet;
use std::net::IpAddr;

use log::{debug, warn};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
