// crates/agent/src/capture/parse.rs
//
// BPF frame header parsing + IPv4/IPv6 packet parsing. Pure functions —
// zero CaptureEngine coupling (verified: no `self` in this file). Extracted
// from capture.rs verbatim, no behavior change.

use std::net::IpAddr;

use synapse_common::PacketInfo;

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
    pub(crate) bh_caplen: u32,
    bh_datalen: u32,
    pub(crate) bh_hdrlen: u16,
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
