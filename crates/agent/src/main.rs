// crates/agent/src/main.rs
//
// synapse-agent — the unprivileged processing engine.
//
// Milestone 1: receives BPF fd from helper via SCM_RIGHTS and reads packets
// directly from the fd using raw BPF reads. The agent never opens /dev/bpf*
// itself — privilege separation is enforced structurally.
//
// Flow tracker (§4 step 3): in-memory session window with ~100ms ticks.
// poll() with timeout ensures tick() fires even on quiet networks.

mod decision;
mod detectors;
mod enrichment;
mod flow;

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use log::{debug, error, info, warn};
use synapse_common::{
    EnforcementCommand, EnrichmentKind, EnrichmentRequest, IpcMessage, PacketInfo, IPC_SOCKET_PATH,
};
use synapse_platform_macos::protocol;

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

/// Determine which port is local based on which IP matches the detected local IP.
/// Returns (local_port, remote_port).
fn determine_local_port(
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

/// Detect the local IP address from the network interface.
/// Uses getifaddrs() to find IPv4 addresses on non-loopback interfaces.
/// Returns the first non-loopback IPv4 address found.
fn detect_local_ip() -> Option<IpAddr> {
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

    // Detect local IP from network interface — used for port→PID direction.
    // Shared with a background refresh thread (handles DHCP/VPN changes).
    let local_ip_cache: Arc<Mutex<Option<IpAddr>>> =
        Arc::new(Mutex::new(detect_local_ip().inspect(|&ip| {
            info!("local IP detected: {ip}");
        })));
    {
        let cache = local_ip_cache.clone();
        std::thread::Builder::new()
            .name("local-ip-refresh".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let new_ip = detect_local_ip();
                if let Ok(mut guard) = cache.lock() {
                    if *guard != new_ip {
                        match new_ip {
                            Some(ip) => info!("local IP changed: {:?} → {}", *guard, ip),
                            None => warn!("local IP lost (interface down?)"),
                        }
                        *guard = new_ip;
                    }
                }
            })
            .expect("failed to spawn local-ip-refresh thread");
    }

    info!("capture started — watching for packets on BPF fd");

    // Allocate read buffer of EXACTLY the kernel-reported size.
    let mut read_buf = vec![0u8; buf_len];

    // Flow tracker — session window with ~100ms ticks.
    let mut tracker = flow::FlowTracker::new();

    // Start enrichment worker pool (async side-channel, never blocks hot path).
    let enrich_pool = enrichment::EnrichmentPool::new();

    // Register detectors — each wrapped in Arc for timeout enforcement.
    let detectors: Vec<Arc<dyn synapse_common::Detector>> =
        vec![Arc::new(detectors::RuleDetector::new())];
    let detector_timeout = std::time::Duration::from_millis(100); // 100ms budget per detector
    info!(
        "registered {} detector(s) with {}ms timeout",
        detectors.len(),
        detector_timeout.as_millis()
    );

    // Decision engine — weighted scoring, threshold comparison, TTL from severity.
    let decision_engine = decision::DecisionEngine::new(synapse_common::DecisionConfig::default());
    info!("decision engine initialized");

    // Enforcement cooldown — keyed by destination IP. Prevents sending a fresh
    // EnforcementCommand::Block on every re-evaluation tick (~1s) for the same IP.
    // Value is the Instant when the cooldown expires (sent_at + ttl).
    // Expired entries are lazily cleaned during tick processing.
    let mut block_cooldown: HashMap<IpAddr, Instant> = HashMap::new();

    // Per-detector circuit breaker — tracks consecutive failures (Errored or
    // TimedOut). After 5 consecutive failures, the circuit opens (detector
    // skipped for 30s cooldown), then probes via HalfOpen. Counter resets
    // on any Completed finding.
    let mut circuit_breaker: HashMap<synapse_common::DetectorId, detectors::CircuitState> =
        HashMap::new();

    // Capture loop — uses poll() with 100ms timeout so tick() fires even
    // on quiet networks. A blocking read() would pin memory forever.
    let mut pkt_count: u64 = 0;
    loop {
        // poll() with 100ms timeout. tick() fires on every iteration
        // regardless of whether packets arrived.
        let mut pollfd = libc::pollfd {
            fd: bpf_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pollfd, 1, 100) };

        if poll_ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            error!("poll error: {err}");
            break;
        }

        // Always tick on every iteration — even on timeout.
        // Expires stale flows and reclaims memory.
        // Returns (expired, due_for_re_evaluate).
        let (expired, re_evaluate) = tracker.tick();
        if !expired.is_empty() || !re_evaluate.is_empty() {
            info!(
                "tick: expired {} flows, re-evaluate {} flows ({} remaining)",
                expired.len(),
                re_evaluate.len(),
                tracker.len()
            );

            // Lazy cleanup of expired cooldown entries.
            let now = Instant::now();
            block_cooldown.retain(|_ip, expires_at| {
                if now >= *expires_at {
                    debug!("cooldown expired for {_ip}");
                    false
                } else {
                    true
                }
            });

            // Run detectors + decision engine on expired flows.
            for &flow_id in &expired {
                if let Some(flow_ref) = tracker.get(flow_id) {
                    let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                    let findings = detectors::run_detectors(
                        &detectors,
                        &common_flow,
                        detector_timeout,
                        &mut circuit_breaker,
                    );
                    let features = synapse_common::FlowFeatures::from_flow(
                        &common_flow,
                        flow_ref.first_seen.elapsed(),
                    );
                    let verdict = decision_engine.evaluate(&features, &findings);
                    match verdict {
                        synapse_common::Verdict::Allow => {}
                        synapse_common::Verdict::Alert { ref reason } => {
                            info!(
                                "ALERT flow={} dst={} {}",
                                flow_id, common_flow.dst_ip, reason
                            );
                        }
                        synapse_common::Verdict::Block { ttl, ref reason } => {
                            let dst_ip = common_flow.dst_ip;
                            let dominated = block_cooldown
                                .get(&dst_ip)
                                .is_some_and(|&expires| Instant::now() < expires);
                            if dominated {
                                debug!("BLOCK skip flow={} {dst_ip} (cooldown active)", flow_id,);
                            } else {
                                info!("BLOCK flow={} dst={dst_ip} ttl={ttl:?} {reason}", flow_id,);
                                let cmd = EnforcementCommand::Block { ip: dst_ip, ttl };
                                if let Err(e) = protocol::send_message(&mut write_half, &cmd) {
                                    error!(
                                        "enforcement send failed for {dst_ip}: {e} — continuing"
                                    );
                                } else {
                                    info!("enforcement command sent: Block {dst_ip} ttl={ttl:?}");
                                    block_cooldown.insert(dst_ip, Instant::now() + ttl);
                                }
                            }
                        }
                    }
                }
            }
            // Re-run detectors on active flows due for periodic re-evaluation.
            // These flows stay in the tracker — mark_evaluated() bumps their
            // last_evaluated timestamp so they're not re-evaluated every tick.
            for &flow_id in &re_evaluate {
                if let Some(flow_ref) = tracker.get(flow_id) {
                    let common_flow: synapse_common::FlowRecord = flow_ref.clone().into();
                    let findings = detectors::run_detectors(
                        &detectors,
                        &common_flow,
                        detector_timeout,
                        &mut circuit_breaker,
                    );
                    let features = synapse_common::FlowFeatures::from_flow(
                        &common_flow,
                        flow_ref.first_seen.elapsed(),
                    );
                    let verdict = decision_engine.evaluate(&features, &findings);
                    match verdict {
                        synapse_common::Verdict::Allow => {}
                        synapse_common::Verdict::Alert { ref reason } => {
                            info!(
                                "RE-ALERT flow={} dst={} {}",
                                flow_id, common_flow.dst_ip, reason
                            );
                        }
                        synapse_common::Verdict::Block { ttl, ref reason } => {
                            let dst_ip = common_flow.dst_ip;
                            let dominated = block_cooldown
                                .get(&dst_ip)
                                .is_some_and(|&expires| Instant::now() < expires);
                            if dominated {
                                debug!("BLOCK skip flow={} {dst_ip} (cooldown active)", flow_id,);
                            } else {
                                info!(
                                    "RE-BLOCK flow={} dst={dst_ip} ttl={ttl:?} {reason}",
                                    flow_id,
                                );
                                let cmd = EnforcementCommand::Block { ip: dst_ip, ttl };
                                if let Err(e) = protocol::send_message(&mut write_half, &cmd) {
                                    error!(
                                        "enforcement send failed for {dst_ip}: {e} — continuing"
                                    );
                                } else {
                                    info!("enforcement command sent: Block {dst_ip} ttl={ttl:?}");
                                    block_cooldown.insert(dst_ip, Instant::now() + ttl);
                                }
                            }
                        }
                    }
                    tracker.mark_evaluated(flow_id);
                }
            }
        }

        if poll_ret == 0 {
            // Timeout — no packets. tick() already ran above.
            continue;
        }

        // Data available — read packets.
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
                if pkt_count.is_multiple_of(10) {
                    info!(
                        "pkt#{pkt_count}: {}:{} → {}:{} (proto={})",
                        info_pkt.src_ip,
                        info_pkt.src_port,
                        info_pkt.dst_ip,
                        info_pkt.dst_port,
                        info_pkt.protocol,
                    );
                }

                // Resolve local_port and PID from the port→PID cache.
                // local_port is determined by comparing packet IPs to the
                // detected local IP — NOT by IP-magnitude comparison (that's
                // canonicalization, which discards direction).
                let (local_port, pid) = {
                    let cache_guard = port_pid_cache.lock().ok();
                    let cache = cache_guard.as_ref();
                    let lookup = |port: u16, proto: u8| -> Option<(u16, u32)> {
                        cache.and_then(|c| {
                            let key = (port, proto);
                            c.get(&key).map(|&pid| (port, pid))
                        })
                    };
                    // Determine which port is local based on which IP matches.
                    // Read local_ip from the periodically-refreshed cache.
                    let current_local_ip = local_ip_cache
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

                // Feed packet to the flow tracker.
                let update = tracker.update(
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
                    // New flow — dispatch enrichment.
                    // KNOWN v1 INEFFICIENCY: DNS/GeoIP/Reputation are per-destination-IP
                    // but we dispatch per-flow. This means redundant lookups for flows
                    // to the same IP. Fix: global HashMap<IpAddr, EnrichmentState> cache.
                    // Only process attribution is genuinely flow-specific.
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

                    if let Err(e) = enrich_pool.dispatch(request) {
                        warn!("enrichment dispatch failed: {e}");
                    }
                }
            }

            offset += hdr.next_offset();
        }

        // Collect enrichment results (non-blocking). Attach to the flow
        // record whenever they complete — never gate the hot path.
        for result in enrich_pool.drain_results() {
            if result.success {
                match result.kind {
                    synapse_common::EnrichmentKind::DnsReverse => {
                        info!(
                            "enrich: dns → {}",
                            result.dns_name.as_deref().unwrap_or("?"),
                        );
                        // Attach to the flow that requested this enrichment.
                        // result.flow_id was set by the enrichment worker.
                        tracker.attach_enrichment(
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
                        tracker.attach_enrichment(
                            result.flow_id,
                            None,
                            result.process_path,
                            result.process_start_time,
                            None,
                            None,
                        );
                    }
                    synapse_common::EnrichmentKind::GeoIp => {
                        tracker.attach_enrichment(
                            result.flow_id,
                            None,
                            None,
                            None,
                            result.country_code,
                            None,
                        );
                    }
                    synapse_common::EnrichmentKind::Reputation => {
                        tracker.attach_enrichment(
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

    info!(
        "agent shutting down — {pkt_count} packets, {} flows tracked",
        tracker.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Test the real determine_local_port() with an inbound packet.
    /// This is the test that should have existed from the start — it exercises
    /// the actual production code path, not a hardcoded local_port bypass.
    ///
    /// Scenario: inbound packet from 8.8.8.8:443 → local_ip:50000
    /// Before fix: src_port (443) was tried first — wrong, it's remote.
    /// After fix: is_local(dst_ip) detects it's local, selects dst_port (50000).
    #[test]
    fn test_determine_local_port_inbound_real_code_path() {
        // Get the real local IP from the system — this is the same function
        // the production code calls at startup.
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        // Inbound packet: remote 8.8.8.8:443 → local (local_ip):50000
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
    /// Outbound: local_ip:50000 → 8.8.8.8:443
    /// src_ip matches local_ip → src_port (50000) is local.
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
    /// Both IPs are external — fallback returns src_port as local.
    #[test]
    fn test_determine_local_port_neither_matches_fallback() {
        let local_ip = detect_local_ip()
            .expect("detect_local_ip() failed — cannot run this test without a network interface");

        // Both IPs are external — neither matches.
        let (local_port, remote_port) = determine_local_port(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
            local_ip,
        );

        // Fallback: src_port as local.
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
}
