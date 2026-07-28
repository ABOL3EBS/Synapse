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
mod config;
mod decision;
mod detectors;
mod enrichment;
mod flow;

use std::collections::{HashMap, HashSet};
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

    // Load configuration (TOML, or defaults).
    let cfg = config::AgentConfig::load();
    info!("configuration loaded (paths: {})", cfg.summary());

    // Detect local IP from network interface — used for port→PID direction.
    let local_ip_cache: Arc<Mutex<Option<IpAddr>>> =
        Arc::new(Mutex::new(capture::detect_local_ip().inspect(|&ip| {
            info!("local IP detected: {ip}");
        })));

    // Detect default gateway — protected from blocking in handle_verdict.
    let gateway_ip = capture::detect_default_gateway();
    match gateway_ip {
        Some(gw) => info!("default gateway detected: {gw}"),
        None => warn!("could not detect default gateway — gateway guard disabled"),
    }

    // Detect ALL own IPs (v4+v6) — never block our own addresses.
    let own_ips: Arc<Mutex<HashSet<IpAddr>>> = Arc::new(Mutex::new(capture::detect_own_ips()));
    {
        let cache = own_ips.clone();
        let refresh_secs = cfg.local_ip_refresh_secs();
        std::thread::Builder::new()
            .name("own-ips-refresh".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(refresh_secs));
                let new_ips = capture::detect_own_ips();
                if let Ok(mut guard) = cache.lock() {
                    if *guard != new_ips {
                        info!("own IPs refreshed: {} addresses", new_ips.len());
                        *guard = new_ips;
                    }
                }
            })
            .expect("failed to spawn own-ips-refresh thread");
    }
    {
        let cache = local_ip_cache.clone();
        let refresh_secs = cfg.local_ip_refresh_secs();
        std::thread::Builder::new()
            .name("local-ip-refresh".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(refresh_secs));
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
    let tracker = flow::FlowTracker::new(cfg.flow_config());

    // Load GeoIP database (optional — graceful degradation if missing).
    let geoip_db = match cfg.geoip_db_path() {
        Some(geoip_path) => match enrichment::GeoIpDb::open(&geoip_path) {
            Ok(db) => {
                info!("loaded GeoIP database: {}", geoip_path.display());
                Some(db)
            }
            Err(e) => {
                info!(
                    "GeoIP database not found ({e}). \
                     GeoIP enrichment disabled."
                );
                None
            }
        },
        None => {
            info!("no GeoIP database path configured — GeoIP enrichment disabled");
            None
        }
    };

    // Load reputation feeds (optional — graceful degradation if missing).
    let feeds_dir = cfg.feeds_dir();
    let reputation = {
        let store = enrichment::ReputationStore::load_from_dir(&feeds_dir);
        if store.is_empty() {
            info!(
                "no reputation feeds found at {}. \
                 Reputation enrichment will return no data.",
                feeds_dir.display()
            );
            None
        } else {
            Some(std::sync::Arc::new(store))
        }
    };

    let enrich_pool =
        enrichment::EnrichmentPool::new(geoip_db, reputation, cfg.enrichment.worker_count);
    let detectors: Vec<Arc<dyn synapse_common::Detector>> = vec![
        Arc::new(detectors::dns_analyzer::DnsAnalyzer::new()),
        Arc::new(detectors::process_correlator::ProcessCorrelator),
        Arc::new(detectors::flow_behavior::FlowBehavior),
        Arc::new(detectors::ip_reputation::IpReputation::new()),
        Arc::new(detectors::dns_tunnel::DnsTunnelDetector),
    ];
    let detector_timeout = cfg.detector_timeout();
    let cb_config = cfg.circuit_breaker_config();
    info!(
        "registered {} detector(s) with {}ms timeout, circuit breaker (failures={}, cooldown={}s)",
        detectors.len(),
        detector_timeout.as_millis(),
        cb_config.max_failures,
        cb_config.cooldown.as_secs(),
    );
    let decision_engine = decision::DecisionEngine::new(cfg.decision_config());
    info!("decision engine initialized");

    let mut engine = capture::CaptureEngine::new(
        bpf_fd,
        read_buf,
        local_ip_cache,
        own_ips,
        port_pid_cache,
        enrich_pool,
        tracker,
        decision_engine,
        detectors,
        detector_timeout,
        write_half,
        cb_config,
        cfg.poll_timeout_ms(),
        gateway_ip,
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
