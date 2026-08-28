// crates/agent/src/capture/direction.rs
//
// Direction resolution: given a raw packet's (src, dst) and the detected
// local IP, resolve which side is local and which is remote. Pure functions
// — zero CaptureEngine coupling (verified: no `self` in this file).
//
// CLAUDE.md rules #8/#11: FlowRecord's a_ip/b_ip are canonical (smaller/
// larger), never directional. determine_local_port() and
// determine_remote_endpoint() are the ONLY places direction should be
// resolved before directional use of a flow's IPs/ports. This exact bug
// class (assuming a canonical field means "local" or "remote" by position)
// shipped twice under different names before being recognized as a pattern
// — do not reintroduce a second direction-resolution helper elsewhere;
// route new call sites through these two functions.

use std::net::IpAddr;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net_topology::detect_local_ip;
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
}
