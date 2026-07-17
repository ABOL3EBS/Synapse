// crates/platform-macos/src/agent/main.rs
//
// synapse-agent — the unprivileged processing engine.
//
// Milestone 1: opens its own pcap capture (both agent and helper run as root).
// The privilege separation architecture is validated by code structure:
// the helper is the ONLY process that calls pfctl, and the enforcement
// protocol only accepts typed values — never strings.
//
// Milestone 2: replace pcap::from_device with SCM_RIGHTS fd passing from helper.

use std::collections::HashSet;
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::Duration;

use log::{error, info, warn};
use synapse_common::{EnforcementCommand, PacketInfo};

const IPC_SOCKET_PATH: &str = "/tmp/synapse-helper.sock";
const TEST_TARGET_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
const BLOCK_TTL: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Length-prefixed bincode messages
// ---------------------------------------------------------------------------

fn send_message<S: serde::Serialize>(stream: &mut std::os::unix::net::UnixStream, msg: &S) -> io::Result<()> {
    let payload = bincode::serialize(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {e}")))?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// IP Frame Parser
// ---------------------------------------------------------------------------

fn parse_ip_frame(frame: &[u8]) -> Option<PacketInfo> {
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
        frame[ip + 12], frame[ip + 13], frame[ip + 14], frame[ip + 15],
    ));
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        frame[ip + 16], frame[ip + 17], frame[ip + 18], frame[ip + 19],
    ));
    let total_len = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]);

    let (sp, dp) = match protocol {
        6 | 17 => {
            let t = ip + hdr_len;
            (u16::from_be_bytes([frame[t], frame[t + 1]]),
             u16::from_be_bytes([frame[t + 2], frame[t + 3]]))
        }
        _ => (0, 0),
    };

    Some(PacketInfo { src_ip, dst_ip, src_port: sp, dst_port: dp, protocol, length: total_len })
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
            (u16::from_be_bytes([frame[t], frame[t + 1]]),
             u16::from_be_bytes([frame[t + 2], frame[t + 3]]))
        }
        _ => (0, 0),
    };
    Some(PacketInfo { src_ip, dst_ip, src_port: sp, dst_port: dp, protocol: nh, length: 0 })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    env_logger::init();
    let euid = unsafe { libc::geteuid() };
    info!("synapse-agent starting (pid={}, euid={})", std::process::id(), euid);
    if euid == 0 {
        warn!("agent running as root — expected during milestone 1 testing");
    }

    // 1. Connect to helper for enforcement commands.
    let mut stream = std::os::unix::net::UnixStream::connect(IPC_SOCKET_PATH)?;
    info!("connected to helper");

    // 2. Open capture via pcap (milestone 1: own device; milestone 2: receive fd via SCM_RIGHTS).
    let interface = std::env::var("SYNAPSE_IFACE").unwrap_or_else(|_| "en0".to_string());
    let mut cap = pcap::Capture::from_device(interface.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("pcap: {e}")))?
        .buffer_size(1024 * 1024)
        .immediate_mode(true)
        .open()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("pcap open: {e}")))?;
    cap.filter("ip", true)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("pcap filter: {e}")))?;

    info!("capture started on {interface} — watching for {TEST_TARGET_IP}");

    // 3. Capture loop.
    let mut pkt_count: u64 = 0;
    let mut blocked: HashSet<IpAddr> = HashSet::new();

    loop {
        let pkt = match cap.next_packet() {
            Ok(p) => p,
            Err(e) => {
                // pcap returns error when the interface goes down or capture is stopped.
                error!("pcap error: {e}");
                break;
            }
        };

        pkt_count += 1;
        let data = pkt.data;

        let info_pkt = match parse_ip_frame(data) {
            Some(p) => p,
            None => continue,
        };

        let hit = info_pkt.src_ip == TEST_TARGET_IP || info_pkt.dst_ip == TEST_TARGET_IP;

        if pkt_count % 10 == 0 || hit {
            info!(
                "pkt#{pkt_count}: {}:{} → {}:{} (proto={}){}",
                info_pkt.src_ip, info_pkt.src_port,
                info_pkt.dst_ip, info_pkt.dst_port,
                info_pkt.protocol,
                if hit { " *** TARGET ***" } else { "" }
            );
        }

        if hit && !blocked.contains(&TEST_TARGET_IP) {
            let cmd = EnforcementCommand::Block { ip: TEST_TARGET_IP, ttl: BLOCK_TTL };
            info!("sending: {cmd:?}");
            if let Err(e) = send_message(&mut stream, &cmd) {
                error!("send failed: {e}");
                break;
            }
            blocked.insert(TEST_TARGET_IP);
        }
    }

    info!("agent shutting down — {pkt_count} packets, {} blocked", blocked.len());
    Ok(())
}
