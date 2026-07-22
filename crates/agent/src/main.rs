// crates/agent/src/main.rs
//
// synapse-agent — the unprivileged processing engine.
//
// Milestone 1: receives BPF fd from helper via SCM_RIGHTS and reads packets
// directly from the fd using raw BPF reads. The agent never opens /dev/bpf*
// itself — privilege separation is enforced structurally.

mod enrichment;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use log::{error, info, warn};
use synapse_common::{
    EnforcementCommand, EnrichmentKind, EnrichmentRequest, IpcMessage, PacketInfo,
};
use synapse_platform_macos::protocol;

const IPC_SOCKET_PATH: &str = "/tmp/synapse-helper.sock";
const TEST_TARGET_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
const BLOCK_TTL: Duration = Duration::from_secs(300);

/// BPF word alignment — packets are padded to this boundary between entries.
/// On macOS/BSD this is 4 (sizeof(long) on 32-bit, traditional BPF alignment).
const BPF_WORDALIGN: usize = 4;

/// Align a BPF offset up to the next word boundary.
fn bpf_wordalign(offset: usize) -> usize {
    (offset + BPF_WORDALIGN - 1) & !(BPF_WORDALIGN - 1)
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BpfHdr {
    tv_sec: i32,  // timeval32.tv_sec
    tv_usec: i32, // timeval32.tv_usec
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
}

impl BpfHdr {
    const SIZE: usize = std::mem::size_of::<Self>(); // 20

    /// Parse a BPF header from the beginning of a buffer.
    fn from_bytes(buf: &[u8]) -> Option<Self> {
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

    /// Offset to next packet in the buffer: header + captured data, word-aligned.
    fn next_offset(&self) -> usize {
        bpf_wordalign(self.bh_hdrlen as usize + self.bh_caplen as usize)
    }
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
// Main
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    env_logger::init();
    let euid = unsafe { libc::geteuid() };
    info!(
        "synapse-agent starting (pid={}, euid={})",
        std::process::id(),
        euid
    );
    if euid == 0 {
        warn!("agent running as root — expected during milestone 1 testing");
    }

    // 1. Connect to helper.
    let stream = UnixStream::connect(IPC_SOCKET_PATH)?;
    info!("connected to helper");

    // 2. Receive BPF fd from helper via SCM_RIGHTS.
    //    The helper has already configured: buffer, filter, immediate mode.
    let bpf_fd: RawFd = protocol::recv_fd(&stream)?;
    info!("received fd from helper: fd={bpf_fd}");

    // 3. Split stream for concurrent read/write.
    //    write_half: sends EnforcementCommand to helper (main thread).
    //    read_half: receives IpcMessage::PortPidCache from helper (reader thread).
    //    try_clone() duplicates the underlying fd so each half has independent
    //    file-descriptor state — concurrent read/write cannot corrupt framing.
    // Only one thread may write on this half. If a future feature needs to write
    // from elsewhere (e.g. sending acks/receipts back), route it through this
    // same thread/channel — do not spawn a second writer on this stream half,
    // or the length-prefix framing race this design was built to avoid comes back.
    let mut write_half = stream.try_clone()?;
    let read_half = stream;

    // 4. Shared port→PID cache — updated by reader thread, read by main loop.
    let port_pid_cache: Arc<Mutex<HashMap<(u16, u8), u32>>> = Arc::new(Mutex::new(HashMap::new()));

    // 5. Spawn IPC reader thread: receives cache pushes from helper.
    {
        let cache = port_pid_cache.clone();
        thread::Builder::new()
            .name("ipc-reader".to_string())
            .spawn(move || {
                let mut reader = read_half;
                loop {
                    match protocol::recv_message::<IpcMessage>(&mut reader) {
                        Ok(IpcMessage::PortPidCache(snapshot)) => {
                            let mut cache = match cache.lock() {
                                Ok(g) => g,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            let was_empty = cache.is_empty();
                            *cache = snapshot.entries;
                            info!(
                                "port→PID cache updated: {} entries ({} PIDs, {} fds, {:?})",
                                cache.len(),
                                snapshot.pid_count,
                                snapshot.fd_count,
                                snapshot.elapsed,
                            );
                            if was_empty && !cache.is_empty() {
                                let mut keys: Vec<_> = cache.keys().collect();
                                keys.sort();
                                info!("cache keys (first 20): {:?}", &keys[..keys.len().min(20)]);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            info!("helper disconnected (reader thread)");
                            break;
                        }
                        Err(e) => {
                            error!("IPC reader error: {e}");
                            break;
                        }
                    }
                }
            })
            .expect("failed to spawn IPC reader thread");
    }

    // 6. Query the ACTUAL buffer length the helper configured.
    //    bpf(4): "A read call will result in EINVAL if it is passed a buffer
    //    that is not this size."
    let mut buf_len: u32 = 0;
    let ret = unsafe { libc::ioctl(bpf_fd, libc::BIOCGBLEN, &mut buf_len) };
    if ret < 0 || buf_len == 0 {
        let err = io::Error::last_os_error();
        error!("BIOCGBLEN failed: ret={ret}, buf_len={buf_len}, err={err}");
        return Err(err);
    }
    let buf_len = buf_len as usize;
    info!("BPF buffer length from kernel: {buf_len} bytes");

    info!("capture started — watching for {TEST_TARGET_IP}");

    // 4. Allocate read buffer of EXACTLY the kernel-reported size.
    let mut read_buf = vec![0u8; buf_len];

    // 5. Capture loop — one read() can return multiple packets.
    let mut pkt_count: u64 = 0;
    let mut blocked: HashSet<IpAddr> = HashSet::new();
    let mut next_flow_id: u64 = 1;

    // Start enrichment worker pool (async side-channel, never blocks hot path).
    let enrich_pool = enrichment::EnrichmentPool::new();

    loop {
        let n = unsafe {
            libc::read(
                bpf_fd,
                read_buf.as_mut_ptr() as *mut libc::c_void,
                read_buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            error!("BPF read error: {err}");
            break;
        }
        if n == 0 {
            info!("BPF fd closed (helper exited?)");
            break;
        }
        let n = n as usize;

        // Parse BPF packets from the read buffer.
        let mut offset = 0usize;
        while offset + BpfHdr::SIZE <= n {
            let hdr = match BpfHdr::from_bytes(&read_buf[offset..]) {
                Some(h) => h,
                None => break,
            };

            let data_start = offset + hdr.bh_hdrlen as usize;
            let data_end = data_start + hdr.bh_caplen as usize;
            if data_end > n {
                warn!("truncated packet at offset {offset}");
                break;
            }

            pkt_count += 1;
            let frame = &read_buf[data_start..data_end];

            if let Some(info_pkt) = parse_ip_frame(frame) {
                let hit = info_pkt.src_ip == TEST_TARGET_IP || info_pkt.dst_ip == TEST_TARGET_IP;

                if pkt_count.is_multiple_of(10) || hit {
                    info!(
                        "pkt#{pkt_count}: {}:{} → {}:{} (proto={}){}",
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        info_pkt.protocol,
                        if hit { " *** TARGET ***" } else { "" }
                    );
                }

                // Dispatch enrichment for the first packet of each new destination.
                // v1: simple — assign a flow ID per unique dst_ip. The real flow
                // tracker (§6) will replace this with proper session windows.
                if !blocked.contains(&info_pkt.dst_ip) {
                    let flow_id = next_flow_id;
                    next_flow_id += 1;

                    // Look up local PID from the port→PID cache.
                    // Try src_port first (outbound traffic), then dst_port (inbound).
                    let pid = port_pid_cache.lock().ok().and_then(|cache| {
                        let key_src = (info_pkt.src_port, info_pkt.protocol);
                        let key_dst = (info_pkt.dst_port, info_pkt.protocol);
                        if cache.is_empty() {
                            info!("PID lookup: cache empty (0 entries)");
                        }
                        cache.get(&key_src).or_else(|| cache.get(&key_dst)).copied()
                    });
                    if pkt_count <= 50 || pkt_count.is_multiple_of(200) {
                        info!(
                            "PID lookup: src=({},{}) dst=({},{}) → {:?} (cache size={})",
                            info_pkt.src_port,
                            info_pkt.protocol,
                            info_pkt.dst_port,
                            info_pkt.protocol,
                            pid,
                            port_pid_cache.lock().map(|c| c.len()).unwrap_or(0),
                        );
                    }

                    let request = EnrichmentRequest {
                        flow_id,
                        src_ip: info_pkt.src_ip,
                        dst_ip: info_pkt.dst_ip,
                        src_port: info_pkt.src_port,
                        dst_port: info_pkt.dst_port,
                        protocol: info_pkt.protocol,
                        pid,
                        kinds: vec![
                            EnrichmentKind::DnsReverse,
                            EnrichmentKind::ProcessAttribution,
                            EnrichmentKind::GeoIp,
                            EnrichmentKind::Reputation,
                        ],
                    };

                    if let Err(e) = enrich_pool.dispatch(request) {
                        warn!("enrichment dispatch failed: {e}");
                    }
                }

                if hit && !blocked.contains(&TEST_TARGET_IP) {
                    let cmd = EnforcementCommand::Block {
                        ip: TEST_TARGET_IP,
                        ttl: BLOCK_TTL,
                    };
                    info!("sending: {cmd:?}");
                    if let Err(e) = protocol::send_message(&mut write_half, &cmd) {
                        error!("send failed: {e}");
                        break;
                    }
                    blocked.insert(TEST_TARGET_IP);
                }
            }

            offset += hdr.next_offset();
        }

        // Collect enrichment results (non-blocking). Results attach to the
        // flow record whenever they complete — never gate the hot path.
        for result in enrich_pool.drain_results() {
            if result.success {
                match result.kind {
                    synapse_common::EnrichmentKind::DnsReverse => {
                        info!(
                            "enrich: dns → {}",
                            result.dns_name.as_deref().unwrap_or("?"),
                        );
                    }
                    synapse_common::EnrichmentKind::ProcessAttribution => {
                        info!(
                            "enrich: process → {} (start={:?})",
                            result.process_path.as_deref().unwrap_or("?"),
                            result.process_start_time,
                        );
                    }
                    _ => {}
                }
            }
        }
    }

    info!(
        "agent shutting down — {pkt_count} packets, {} blocked",
        blocked.len()
    );
    Ok(())
}
