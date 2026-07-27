// crates/agent/src/main.rs
//
// synapse-agent — the unprivileged processing engine.
//
// Milestone 1: receives BPF fd from helper via SCM_RIGHTS and reads packets
// directly from the fd using raw BPF reads. The agent never opens /dev/bpf*
// itself — privilege separation is enforced structurally.
//
// Capture loop extracted to capture.rs — this file orchestrates startup and
// delegates to CaptureEngine.

mod capture;
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

use log::{error, info, warn};
use synapse_common::{IpcMessage, IPC_SOCKET_PATH};
use synapse_platform_macos::protocol;

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
    let bpf_fd: RawFd = protocol::recv_fd(&stream)?;
    info!("received fd from helper: fd={bpf_fd}");

    // 3. Split stream for concurrent read/write.
    let write_half = stream.try_clone()?;
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
    let local_ip_cache: Arc<Mutex<Option<IpAddr>>> =
        Arc::new(Mutex::new(capture::detect_local_ip().inspect(|&ip| {
            info!("local IP detected: {ip}");
        })));
    {
        let cache = local_ip_cache.clone();
        std::thread::Builder::new()
            .name("local-ip-refresh".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let new_ip = capture::detect_local_ip();
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

    // Build capture engine — all state lives here.
    let read_buf = vec![0u8; buf_len];
    let tracker = flow::FlowTracker::new();
    let enrich_pool = enrichment::EnrichmentPool::new();
    let detectors: Vec<Arc<dyn synapse_common::Detector>> = vec![
        Arc::new(detectors::dns_analyzer::DnsAnalyzer::new()),
        Arc::new(detectors::process_correlator::ProcessCorrelator),
        Arc::new(detectors::flow_behavior::FlowBehavior),
        Arc::new(detectors::ip_reputation::IpReputation::new()),
        Arc::new(detectors::dns_tunnel::DnsTunnelDetector),
    ];
    let detector_timeout = std::time::Duration::from_millis(100);
    info!(
        "registered {} detector(s) with {}ms timeout",
        detectors.len(),
        detector_timeout.as_millis()
    );
    let decision_engine = decision::DecisionEngine::new(synapse_common::DecisionConfig::default());
    info!("decision engine initialized");

    let mut engine = capture::CaptureEngine::new(
        bpf_fd,
        read_buf,
        local_ip_cache,
        port_pid_cache,
        enrich_pool,
        tracker,
        decision_engine,
        detectors,
        detector_timeout,
        write_half,
    );

    info!("capture started — watching for packets on BPF fd");

    // Capture loop — poll() with 100ms timeout so tick() fires even on quiet networks.
    loop {
        match engine.run_tick() {
            Ok(true) => {
                // Data available — read and process packets.
                if !engine.read_and_process_packets()? {
                    break; // BPF fd closed.
                }
            }
            Ok(false) => {
                // Timeout — tick() already ran inside run_tick.
            }
            Err(e) => {
                error!("tick error: {e}");
                break;
            }
        }
        engine.collect_enrichment_results();
    }

    info!(
        "agent shutting down — {} packets, {} flows tracked",
        engine.pkt_count(),
        engine.flows_tracked()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::capture::*;

    #[test]
    fn test_bpf_wordalign() {
        assert_eq!(BPF_WORDALIGN, 4);
        assert_eq!(bpf_wordalign(0), 0);
        assert_eq!(bpf_wordalign(1), 4);
        assert_eq!(bpf_wordalign(4), 4);
        assert_eq!(bpf_wordalign(5), 8);
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
    fn test_parse_ip_frame_too_short() {
        assert!(parse_ip_frame(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_parse_ipv4_minimal() {
        let mut frame = vec![0u8; 54];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 6;
        frame[16] = 0x00;
        frame[17] = 0x36;

        let pkt = parse_ip_frame(&frame).unwrap();
        assert_eq!(pkt.protocol, 6);
        assert_eq!(pkt.length, 54);
    }

    #[test]
    fn test_parse_ipv4_with_ports() {
        let mut frame = vec![0u8; 54];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 6;
        frame[16] = 0x00;
        frame[17] = 34;
        frame[34] = 0x1F;
        frame[35] = 0x40;
        frame[36] = 0x01;
        frame[37] = 0xBB;

        let pkt = parse_ip_frame(&frame).unwrap();
        assert_eq!(pkt.src_port, 8000);
        assert_eq!(pkt.dst_port, 443);
    }

    #[test]
    fn test_parse_ipv6_minimal() {
        let mut frame = vec![0u8; 60];
        frame[12] = 0x86;
        frame[13] = 0xDD;
        frame[20] = 0x06;

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
