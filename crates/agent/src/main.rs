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
mod storage;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use arc_swap::ArcSwap;
use log::{error, info, warn};
use synapse_common::{IpcMessage, IPC_SOCKET_PATH};
use synapse_platform_macos::protocol;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn agent_pid_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home)
        .join(".synapse")
        .join("agent.pid")
}

fn main() -> io::Result<()> {
    synapse_common::log_format::init_logging();
    let euid = unsafe { libc::geteuid() };
    info!(
        "synapse-agent starting (pid={}, euid={})",
        std::process::id(),
        euid
    );
    if euid == 0 {
        warn!("agent running as root — expected during milestone 1 testing");
    }

    // Write PID file so the dashboard can check liveness via kill(pid, 0).
    // Same pattern as the helper's HELPER_PID_FILE — process-independent,
    // correct regardless of whether any verdicts have been written recently.
    {
        let pid_path = agent_pid_path();
        if let Some(dir) = pid_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(&pid_path, format!("{}\n", std::process::id())) {
            warn!("could not write agent PID file {}: {e}", pid_path.display());
        }
    }

    // Signal handler — clean shutdown on SIGINT/SIGTERM.
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::Release);
        })
        .map_err(|e| io::Error::other(format!("signal handler: {e}")))?;
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
    //    P1: ArcSwap for lock-free reads on the hot path.
    let port_pid_cache: Arc<ArcSwap<HashMap<(u16, u8), u32>>> =
        Arc::new(ArcSwap::from_pointee(HashMap::new()));

    // 5. Spawn IPC reader thread: receives cache pushes from helper.
    {
        let cache = port_pid_cache.clone();
        thread::Builder::new()
            .name("ipc-reader".to_string())
            .spawn(move || {
                let mut reader = read_half;
                let mut recv_buf = Vec::with_capacity(64 * 1024);
                loop {
                    match protocol::recv_message_into::<IpcMessage>(&mut reader, &mut recv_buf) {
                        Ok(IpcMessage::PortPidCache(snapshot)) => {
                            let was_empty = cache.load().is_empty();
                            let new_entries = Arc::new(snapshot.entries);
                            let len = new_entries.len();
                            cache.store(new_entries);
                            info!(
                                "port→PID cache updated: {} entries ({} PIDs, {} fds, {:?})",
                                len, snapshot.pid_count, snapshot.fd_count, snapshot.elapsed,
                            );
                            if was_empty && len > 0 {
                                let snapshot = cache.load();
                                let mut keys: Vec<_> = snapshot.keys().collect();
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
            .map_err(|e| io::Error::other(format!("spawn ipc-reader: {e}")))?;
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
    //    P1: ArcSwap for lock-free reads on the hot path.
    let local_ip_cache: Arc<ArcSwap<Option<IpAddr>>> = Arc::new(ArcSwap::from_pointee(
        capture::detect_local_ip().inspect(|&ip| {
            info!("local IP detected: {ip}");
        }),
    ));

    // Detect default gateway — protected from blocking in handle_verdict.
    let gateway_ip = capture::detect_default_gateway();
    match gateway_ip {
        Some(gw) => info!("default gateway detected: {gw}"),
        None => warn!("could not detect default gateway — gateway guard disabled"),
    }

    // Detect ALL own IPs (v4+v6) — never block our own addresses.
    //    P1: ArcSwap for lock-free reads in should_skip_block.
    let own_ips: Arc<ArcSwap<HashSet<IpAddr>>> =
        Arc::new(ArcSwap::from_pointee(capture::detect_own_ips()));

    // CrossFlow exclusion set: own_ips + gateway + known high-volume API endpoints.
    // Kept separate from own_ips because the semantics differ: own_ips is used
    // for enforcement (never block our own address); cf_excluded is used only by
    // CrossFlow to skip per-destination counting. The gateway and API endpoints
    // are excluded from CrossFlow counting but must NOT be exempt from enforcement
    // (a compromised router or CDN IP is still in-scope for blocking).
    //
    // Excluded API endpoints are scoped to the SPECIFIC IP only — NOT the full
    // ASN or CIDR. The Claude desktop app sustains ~156 connections/60s to
    // 160.79.104.10 (Anthropic API / api.anthropic.com), enough to trigger
    // CrossFlow's pid_diversity threshold on normal API usage. If Anthropic
    // changes the IP, update this list. Exclusion applies to CrossFlow only —
    // all other detectors (reputation, flow_behavior, dns_analyzer) still
    // evaluate flows to this IP normally.
    const CROSSFLOW_EXCLUDED_API_IPS: &[&str] = &[
        "160.79.104.10", // Anthropic API (api.anthropic.com) — Claude desktop false positive
    ];
    fn build_cf_excluded(own: &HashSet<IpAddr>, gateway: Option<IpAddr>) -> HashSet<IpAddr> {
        let mut set = own.clone();
        if let Some(gw) = gateway {
            set.insert(gw);
        }
        for &ip_str in CROSSFLOW_EXCLUDED_API_IPS {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                set.insert(ip);
            }
        }
        set
    }
    let cf_excluded: Arc<ArcSwap<HashSet<IpAddr>>> = Arc::new(ArcSwap::from_pointee(
        build_cf_excluded(&own_ips.load(), gateway_ip),
    ));
    info!(
        "CrossFlow exclusion set: {} addresses (own_ips + gateway + api endpoints)",
        cf_excluded.load().len()
    );

    {
        let own_ips_cache = own_ips.clone();
        let cf_excluded_cache = cf_excluded.clone();
        let refresh_secs = cfg.local_ip_refresh_secs();
        // Seed last_known_gw from startup detection so the refresh thread
        // never silently drops the gateway when detection transiently fails
        // (e.g. VPN reconnect causes needed == 0 for one or two ticks).
        let mut last_known_gw: Option<IpAddr> = gateway_ip;
        // Count consecutive ticks where detection returned None and we fell back.
        // Surfaced as warn! so persistent detection failures (not just transient ones)
        // remain visible — the Aug 6 incident was silent for 1h45m before triggering.
        let mut consecutive_detect_failures: u32 = 0;
        std::thread::Builder::new()
            .name("own-ips-refresh".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(refresh_secs));
                let new_own = capture::detect_own_ips();
                // Rebuild CrossFlow exclusion set every tick: gateway may have
                // changed (network switch) even when own IPs are unchanged.
                let new_gw = capture::detect_default_gateway();
                if new_gw.is_some() {
                    if consecutive_detect_failures > 0 {
                        info!(
                            "own-ips-refresh: gateway detection recovered after \
                             {} consecutive failures — new gateway: {:?}",
                            consecutive_detect_failures, new_gw
                        );
                    }
                    last_known_gw = new_gw;
                    consecutive_detect_failures = 0;
                } else if last_known_gw.is_some() {
                    // Detection failed — preserve last successful value.
                    // This prevents the gateway from dropping out of cf_excluded
                    // during transient failures (VPN reconnect, split routing).
                    consecutive_detect_failures += 1;
                    // Warn at 1 minute, then every 5 minutes — keeps persistent
                    // detection failures visible without log spam.
                    let warn_ticks = 60u64 / refresh_secs.max(1);
                    let warn_period = 5 * 60u64 / refresh_secs.max(1);
                    let n = consecutive_detect_failures as u64;
                    if n == warn_ticks
                        || (n > warn_ticks && (n - warn_ticks).is_multiple_of(warn_period))
                    {
                        warn!(
                            "own-ips-refresh: gateway detection has failed {} consecutive \
                             ticks (~{}s) — running on last known gateway {:?}. \
                             Detection may be persistently broken on this network \
                             (e.g. VPN routing table has no RTF_GATEWAY routes).",
                            consecutive_detect_failures,
                            consecutive_detect_failures as u64 * refresh_secs,
                            last_known_gw
                        );
                    } else {
                        log::debug!(
                            "own-ips-refresh: gateway detection returned None — \
                             preserving last known: {:?} (consecutive failures: {})",
                            last_known_gw,
                            consecutive_detect_failures
                        );
                    }
                }
                let effective_gw = new_gw.or(last_known_gw);
                let new_cf = build_cf_excluded(&new_own, effective_gw);
                let current = own_ips_cache.load();
                if **current != new_own {
                    info!("own IPs refreshed: {} addresses", new_own.len());
                    drop(current);
                    own_ips_cache.store(Arc::new(new_own));
                }
                cf_excluded_cache.store(Arc::new(new_cf));
                log::debug!(
                    "own-ips-refresh tick: cf_excluded updated (effective_gateway={:?})",
                    effective_gw
                );
            })
            .map_err(|e| io::Error::other(format!("spawn own-ips-refresh: {e}")))?;
    }
    {
        let cache = local_ip_cache.clone();
        let refresh_secs = cfg.local_ip_refresh_secs();
        std::thread::Builder::new()
            .name("local-ip-refresh".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(refresh_secs));
                let new_ip = capture::detect_local_ip();
                let current = cache.load();
                if **current != new_ip {
                    match new_ip {
                        Some(ip) => info!("local IP changed: {:?} → {}", **current, ip),
                        None => warn!("local IP lost (interface down?)"),
                    }
                    drop(current);
                    cache.store(Arc::new(new_ip));
                }
            })
            .map_err(|e| io::Error::other(format!("spawn local-ip-refresh: {e}")))?;
    }

    // Build capture engine — all state lives here.
    let read_buf = vec![0u8; buf_len];
    let tracker = flow::FlowTracker::new(cfg.flow_config());

    // Load GeoIP databases (optional — graceful degradation if missing).
    // City DB failure disables all GeoIP; ASN DB failure disables ASN only.
    let geoip_db = match cfg.geoip_db_path() {
        Some(city_path) => {
            match enrichment::GeoIpDb::open(&city_path, cfg.geoip_asn_db_path().as_deref()) {
                Ok(db) => Some(db),
                Err(e) => {
                    info!("GeoIP City database not found ({e}) — GeoIP enrichment disabled.");
                    None
                }
            }
        }
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

    // Initialize bounded detector worker pool (R1: no per-call thread spawning).
    synapse_common::init_detector_pool(8);
    info!("detector worker pool initialized (8 workers)");

    let cross_flow_state = Arc::new(std::sync::Mutex::new(
        detectors::cross_flow::CrossFlowState::new(
            detectors::cross_flow::CrossFlowConfig::default(),
            cf_excluded,
        ),
    ));

    let detectors: Vec<Arc<dyn synapse_common::Detector>> = vec![
        Arc::new(detectors::dns_analyzer::DnsAnalyzer::new()),
        Arc::new(detectors::process_correlator::ProcessCorrelator),
        Arc::new(detectors::flow_behavior::FlowBehavior),
        Arc::new(detectors::ip_reputation::IpReputation::new()),
        Arc::new(detectors::dns_tunnel::DnsTunnelDetector),
        Arc::new(detectors::cross_flow::CrossFlowDetector::new(
            cross_flow_state.clone(),
        )),
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

    // SQLite storage worker (enforcement_log only — graceful degradation).
    let storage_worker = storage::StorageWorker::start(cfg.storage_db_path());
    let storage_tx = storage_worker.as_ref().map(|w| w.event_tx());
    if storage_worker.is_some() {
        info!("storage worker initialized (enforcement_log)");
    }

    let cap_config = capture::CaptureConfig {
        poll_timeout_ms: cfg.poll_timeout_ms(),
        detector_timeout,
        cb_config,
        gateway_ip,
    };
    let net_caches = capture::NetworkCaches {
        local_ip: local_ip_cache,
        own_ips,
        port_pid: port_pid_cache,
    };
    let mut engine = capture::CaptureEngine::new(capture::CaptureInit {
        bpf_fd,
        buf: read_buf,
        write_half,
        caches: net_caches,
        config: cap_config,
        enrich_pool,
        tracker,
        decision_engine,
        detectors,
        cross_flow_state,
        storage_tx,
    });

    info!("capture started — watching for packets on BPF fd");

    // Capture loop — poll() with 100ms timeout so tick() fires even on quiet networks.
    while running.load(Ordering::Acquire) {
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

        // R3/R4: Exit cleanly if IPC channel is dead — lets launchd/systemd restart.
        if let Err(e) = engine.check_ipc_health() {
            error!("{e}");
            break;
        }
    }

    info!(
        "agent shutting down — {} packets, {} flows tracked",
        engine.pkt_count(),
        engine.flows_tracked()
    );
    drop(engine);
    if let Some(worker) = storage_worker {
        worker.shutdown();
    }
    let _ = std::fs::remove_file(agent_pid_path());
    Ok(())
}
