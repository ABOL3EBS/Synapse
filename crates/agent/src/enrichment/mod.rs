// crates/agent/src/enrichment/mod.rs
//
// Async enrichment worker pool — runs as a side-channel that never gates
// the hot path (§4). Dispatched on flow creation, results attach to the
// flow record whenever they complete.
//
// Justification >600 lines: enrichment/mod.rs implements 4 independent
// workers (DNS reverse, process attribution, GeoIP, reputation) plus the
// worker pool dispatch/result-collection machinery, ReputationStore with
// CIDR/blocklist/CSV parsing, and GeoIpDb wrapper. Each worker is a
// distinct I/O path with different error handling. Splitting would create
// artificial boundaries between tightly-coupled enrichment logic.

pub mod reputation_store;

use std::net::IpAddr;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use log::{debug, error, info};
use maxminddb::Reader;
use synapse_common::{EnrichmentKind, EnrichmentRequest, EnrichmentResult};

pub use reputation_store::ReputationStore;

/// Default timeout for a single enrichment lookup (e.g., DNS).
/// Currently unused — reserved for future per-lookup timeouts.
#[allow(dead_code)]
const LOOKUP_TIMEOUT_MS: u64 = 2000;

// ---------------------------------------------------------------------------
// GeoIP database wrapper
// ---------------------------------------------------------------------------

/// Thread-safe wrapper around a MaxMind GeoLite2-City database.
/// Loaded once at startup, shared across enrichment worker threads via Arc.
/// Provides country code and ASN lookups for public IPs.
pub struct GeoIpDb {
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIpDb {
    /// Open a MaxMind database file. Returns an error if the file doesn't
    /// exist or is corrupted — caller decides how to handle (typically log
    /// and continue without GeoIP).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let reader =
            Reader::open_readfile(path).map_err(|e| format!("failed to open {:?}: {}", path, e))?;

        let metadata = reader.metadata();
        info!(
            "geoip database loaded: {:?} (v{}, {:?})",
            path, metadata.database_type, metadata.build_epoch,
        );

        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Look up country code and ASN for an IP address.
    /// Returns (country_code, asn). Private/RFC1918 IPs return (None, None).
    /// If the IP is not found in the database, returns (None, None).
    pub fn lookup(&self, ip: IpAddr) -> (Option<String>, Option<u32>) {
        if !is_public_ip(ip) {
            return (None, None);
        }

        let result = match self.reader.lookup(ip) {
            Ok(r) => r,
            Err(e) => {
                debug!("geoip lookup failed for {}: {}", ip, e);
                return (None, None);
            }
        };

        // Try decoding as City record for country code.
        // GeoLite2-City includes country iso_code.
        let country_code = match result.decode::<maxminddb::geoip2::City>() {
            Ok(Some(city)) => city.country.iso_code.map(|s| s.to_string()),
            Ok(None) => None,
            Err(e) => {
                debug!("geoip city decode failed for {}: {}", ip, e);
                None
            }
        };

        // Try decoding as ASN (same database may include ASN data).
        let asn = match result.decode::<maxminddb::geoip2::Asn>() {
            Ok(Some(asn_data)) => asn_data.autonomous_system_number,
            Ok(None) => None,
            Err(_) => None, // City DB may not include ASN — silently skip
        };

        (country_code, asn)
    }

    /// Look up ASN separately from an ASN database (if available).
    /// GeoLite2-City doesn't include ASN — call this with a separate
    /// GeoLite2-ASN.mmdb reader if one is loaded.
    #[allow(dead_code)]
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        if !is_public_ip(ip) {
            return None;
        }

        match self.reader.lookup(ip) {
            Ok(result) => match result.decode::<maxminddb::geoip2::Asn>() {
                Ok(Some(asn_data)) => asn_data.autonomous_system_number,
                _ => None,
            },
            Err(_) => None,
        }
    }
}

/// Check if an IP is a public (non-RFC1918, non-loopback) address.
/// Used by GeoIpDb to skip private IPs and by enrichment workers.
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100
                    && v4.octets()[1] >= 64
                    && v4.octets()[1] <= 127) // 100.64.0.0/10 CGNAT
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)) // 169.254.0.0/16
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()),
    }
}

/// The enrichment worker pool. Owns the dispatch sender and result receiver.
/// Callers dispatch requests via `dispatch()` and collect results via `try_recv()`.
pub struct EnrichmentPool {
    /// Send enrichment requests to any available worker.
    tx: Sender<EnrichmentRequest>,
    /// Receive results from workers (non-blocking via try_recv).
    rx: Receiver<EnrichmentResult>,
}

impl EnrichmentPool {
    /// Create a new enrichment pool with `worker_count` background threads.
    /// Each thread pulls requests from a shared receiver and sends results
    /// back through per-thread result senders that all feed into one receiver.
    pub fn new(
        geoip_db: Option<GeoIpDb>,
        reputation: Option<Arc<ReputationStore>>,
        worker_count: usize,
    ) -> Self {
        let (req_tx, req_rx) = mpsc::channel::<EnrichmentRequest>();
        let (res_tx, res_rx) = mpsc::channel::<EnrichmentResult>();

        // Wrap request receiver in Arc<Mutex<>> so workers can share it.
        // Lock contention is minimal — workers hold the lock only while calling recv().
        let shared_rx = Arc::new(Mutex::new(req_rx));

        // Share GeoIP database across workers via Arc clone.
        let geoip = geoip_db.map(Arc::new);

        for worker_id in 0..worker_count {
            let req_rx = shared_rx.clone();
            let res_tx = res_tx.clone();
            let geoip = geoip.clone();
            let reputation = reputation.clone();

            thread::Builder::new()
                .name(format!("enrichment-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(worker_id, req_rx, res_tx, geoip, reputation);
                })
                .expect("failed to spawn enrichment worker thread");
        }

        // Drop our copy of res_tx so the receiver closes when all workers exit.
        drop(res_tx);

        info!("enrichment pool started: {worker_count} workers");

        Self {
            tx: req_tx,
            rx: res_rx,
        }
    }

    /// Dispatch an enrichment request to the worker pool.
    /// Returns immediately — does not block the hot path.
    /// Returns Err if the pool has shut down (all workers exited).
    pub fn dispatch(&self, request: EnrichmentRequest) -> Result<(), String> {
        self.tx
            .send(request)
            .map_err(|e| format!("enrichment pool shut down: {e}"))
    }

    /// Non-blocking receive of completed enrichment results.
    /// Returns None if no results are ready yet.
    #[allow(dead_code)]
    pub fn try_recv(&self) -> Option<EnrichmentResult> {
        self.rx.try_recv().ok()
    }

    /// Drain all available results (non-blocking). Returns a Vec of results
    /// that were ready at the time of the call.
    pub fn drain_results(&self) -> Vec<EnrichmentResult> {
        let mut results = Vec::new();
        while let Ok(r) = self.rx.try_recv() {
            results.push(r);
        }
        results
    }

    // -----------------------------------------------------------------------
    // Worker loop
    // -----------------------------------------------------------------------

    fn worker_loop(
        worker_id: usize,
        rx: Arc<Mutex<Receiver<EnrichmentRequest>>>,
        tx: Sender<EnrichmentResult>,
        geoip: Option<Arc<GeoIpDb>>,
        reputation: Option<Arc<ReputationStore>>,
    ) {
        debug!("enrichment worker {worker_id} started");

        loop {
            let request = {
                let rx = match rx.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        error!(
                            "worker {worker_id}: request receiver mutex poisoned, shutting down"
                        );
                        poisoned.into_inner()
                    }
                };
                match rx.recv() {
                    Ok(req) => req,
                    Err(_) => {
                        debug!("enrichment worker {worker_id} exiting (request channel closed)");
                        return;
                    }
                }
            };
            debug!(
                "worker {worker_id}: enriching flow {} ({}:{} → {}:{}, proto={})",
                request.flow_id,
                request.src_ip,
                request.src_port,
                request.dst_ip,
                request.dst_port,
                request.protocol
            );

            for kind in &request.kinds {
                let result =
                    Self::run_enrichment(*kind, &request, geoip.as_deref(), reputation.as_deref());
                if tx.send(result).is_err() {
                    error!("worker {worker_id}: result receiver dropped, shutting down");
                    return;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment dispatch
    // -----------------------------------------------------------------------

    fn run_enrichment(
        kind: EnrichmentKind,
        request: &EnrichmentRequest,
        geoip: Option<&GeoIpDb>,
        reputation: Option<&ReputationStore>,
    ) -> EnrichmentResult {
        match kind {
            EnrichmentKind::DnsReverse => Self::enrich_dns_reverse(request),
            EnrichmentKind::ProcessAttribution => Self::enrich_process_attribution(request),
            EnrichmentKind::GeoIp => Self::enrich_geoip(request, geoip),
            EnrichmentKind::Reputation => Self::enrich_reputation(request, reputation),
        }
    }

    // -----------------------------------------------------------------------
    // DNS reverse lookup
    // -----------------------------------------------------------------------

    fn enrich_dns_reverse(request: &EnrichmentRequest) -> EnrichmentResult {
        let target_ip = Self::pick_enrichable_ip(request.src_ip, request.dst_ip);

        match Self::reverse_dns_lookup(target_ip) {
            Ok(name) => {
                debug!("dns reverse: {target_ip} → {name}");
                EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::DnsReverse,
                    success: true,
                    dns_name: Some(name),
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: None,
                }
            }
            Err(e) => {
                debug!("dns reverse: {target_ip} failed: {e}");
                EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::DnsReverse,
                    success: false,
                    dns_name: None,
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: Some(e),
                }
            }
        }
    }

    /// Perform a reverse DNS lookup using std::net::ToSocketAddrs.
    /// This blocks the calling worker thread — acceptable because enrichment
    /// runs on background threads, not the hot path.
    fn reverse_dns_lookup(ip: IpAddr) -> Result<String, String> {
        // std::net doesn't have a direct reverse-DNS API.
        // On macOS, we use getnameinfo() which does PTR record resolution.
        Self::getnameinfo_lookup(ip)
    }

    /// Reverse DNS via libc getnameinfo(). Resolves an IP to a hostname
    /// using the system's DNS resolver (PTR record lookup).
    fn getnameinfo_lookup(ip: IpAddr) -> Result<String, String> {
        use std::ffi::CStr;
        use std::mem;

        let (addr, addrlen) = match ip {
            IpAddr::V4(v4) => {
                let mut sin: libc::sockaddr_in = unsafe { mem::zeroed() };
                sin.sin_family = libc::AF_INET as u8;
                sin.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                (
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            IpAddr::V6(v6) => {
                let mut sin6: libc::sockaddr_in6 = unsafe { mem::zeroed() };
                sin6.sin6_family = libc::AF_INET6 as u8;
                sin6.sin6_addr.s6_addr = v6.octets();
                (
                    &sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        };

        let mut buf = [0u8; 256];
        let flags = libc::NI_NAMEREQD | libc::NI_NOFQDN;

        let ret = unsafe {
            libc::getnameinfo(
                addr,
                addrlen,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len() as u32,
                std::ptr::null_mut(),
                0,
                flags,
            )
        };

        if ret != 0 {
            let gai_err = unsafe { CStr::from_ptr(libc::gai_strerror(ret)) };
            return Err(format!("getnameinfo failed: {}", gai_err.to_string_lossy()));
        }

        let name = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        let name = name.to_string_lossy().into_owned();

        if name.is_empty() {
            return Err("getnameinfo returned empty string".into());
        }

        Ok(name)
    }

    // -----------------------------------------------------------------------
    // Process attribution (libproc FFI)
    // -----------------------------------------------------------------------

    fn enrich_process_attribution(request: &EnrichmentRequest) -> EnrichmentResult {
        let pid = match request.pid {
            Some(p) => p,
            None => {
                return EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::ProcessAttribution,
                    success: false,
                    dns_name: None,
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: Some("no PID available for process attribution".into()),
                };
            }
        };

        match synapse_platform_macos::process_lookup::lookup_process(pid) {
            Ok(info) => {
                debug!("process attribution: pid={pid} → {}", info.path);
                EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::ProcessAttribution,
                    success: true,
                    dns_name: None,
                    process_path: Some(info.path),
                    process_start_time: Some(info.start_time),
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: None,
                }
            }
            Err(e) => {
                debug!("process attribution: pid={pid} failed: {e}");
                EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::ProcessAttribution,
                    success: false,
                    dns_name: None,
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: Some(e),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // GeoIP lookup
    // -----------------------------------------------------------------------

    fn enrich_geoip(request: &EnrichmentRequest, geoip: Option<&GeoIpDb>) -> EnrichmentResult {
        let target_ip = Self::pick_enrichable_ip(request.src_ip, request.dst_ip);

        let geoip_db = match geoip {
            Some(db) => db,
            None => {
                return EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::GeoIp,
                    success: false,
                    dns_name: None,
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: Some("geoip database not loaded".into()),
                };
            }
        };

        // Skip private/RFC1918 IPs — no meaningful geo data.
        if !is_public_ip(target_ip) {
            return EnrichmentResult {
                flow_id: request.flow_id,
                kind: EnrichmentKind::GeoIp,
                success: true,
                dns_name: None,
                process_path: None,
                process_start_time: None,
                country_code: None,
                asn: None,
                reputation_score: None,
                error: None,
            };
        }

        // Look up country + ASN via the GeoIpDb wrapper.
        let (country_code, asn) = geoip_db.lookup(target_ip);

        let success = country_code.is_some() || asn.is_some();
        if success {
            debug!(
                "geoip: {} → country={:?} asn={:?}",
                target_ip, country_code, asn
            );
        } else {
            debug!("geoip: {} → no data found", target_ip);
        }

        EnrichmentResult {
            flow_id: request.flow_id,
            kind: EnrichmentKind::GeoIp,
            success,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code,
            asn,
            reputation_score: None,
            error: None,
        }
    }

    // -----------------------------------------------------------------------
    // Reputation lookup
    // -----------------------------------------------------------------------

    fn enrich_reputation(
        request: &EnrichmentRequest,
        store: Option<&ReputationStore>,
    ) -> EnrichmentResult {
        let target_ip = Self::pick_enrichable_ip(request.src_ip, request.dst_ip);

        let store = match store {
            Some(s) => s,
            None => {
                return EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::Reputation,
                    success: false,
                    dns_name: None,
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: Some("reputation store not loaded".into()),
                };
            }
        };

        // Skip private/RFC1918 IPs — no meaningful reputation data.
        if !is_public_ip(target_ip) {
            return EnrichmentResult {
                flow_id: request.flow_id,
                kind: EnrichmentKind::Reputation,
                success: true,
                dns_name: None,
                process_path: None,
                process_start_time: None,
                country_code: None,
                asn: None,
                reputation_score: None,
                error: None,
            };
        }

        match store.lookup(target_ip) {
            Some(score) => {
                debug!("reputation: {} → {score:.2}", target_ip);
                EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::Reputation,
                    success: true,
                    dns_name: None,
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: Some(score),
                    error: None,
                }
            }
            None => {
                debug!("reputation: {} → unknown", target_ip);
                EnrichmentResult {
                    flow_id: request.flow_id,
                    kind: EnrichmentKind::Reputation,
                    success: true,
                    dns_name: None,
                    process_path: None,
                    process_start_time: None,
                    country_code: None,
                    asn: None,
                    reputation_score: None,
                    error: None,
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Pick which IP to enrich. Prefer the remote (non-local) IP.
    /// For v1, we enrich both — but this helper picks one for single-IP
    /// lookups like DNS or GeoIP.
    fn pick_enrichable_ip(src: IpAddr, dst: IpAddr) -> IpAddr {
        // Prefer non-RFC1918 IPs (more likely to have DNS/reputation data).
        if is_public_ip(dst) {
            dst
        } else {
            src
        }
    }
}

impl Drop for EnrichmentPool {
    fn drop(&mut self) {
        info!("enrichment pool shutting down");
        // Dropping the sender (self.tx) closes the channel, causing workers
        // to exit their recv() loop and terminate their threads.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrichment_pool_dispatch_and_collect() {
        let pool = EnrichmentPool::new(None, None, 4);

        // Dispatch a DNS reverse lookup for 8.8.8.8 (Google DNS — should resolve)
        let request = EnrichmentRequest {
            flow_id: 1,
            src_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            pid: Some(std::process::id()),
            kinds: vec![
                EnrichmentKind::DnsReverse,
                EnrichmentKind::ProcessAttribution,
            ],
        };

        pool.dispatch(request).expect("dispatch should succeed");

        // Poll for results — enrichment runs on background threads
        let mut dns_result = None;
        let mut process_result = None;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            for r in pool.drain_results() {
                match r.kind {
                    EnrichmentKind::DnsReverse => dns_result = Some(r),
                    EnrichmentKind::ProcessAttribution => process_result = Some(r),
                    _ => {}
                }
            }
            if dns_result.is_some() && process_result.is_some() {
                break;
            }
        }

        // DNS should resolve for 8.8.8.8
        let dns = dns_result.expect("DNS result should arrive");
        assert!(dns.success, "DNS lookup should succeed: {:?}", dns.error);
        let name = dns.dns_name.expect("DNS name should be present");
        assert!(!name.is_empty(), "DNS name should not be empty");
        println!("DNS reverse: 8.8.8.8 → {name}");

        // Process attribution should resolve our own PID
        let proc = process_result.expect("Process result should arrive");
        assert!(
            proc.success,
            "Process attribution should succeed: {:?}",
            proc.error
        );
        let path = proc.process_path.expect("Process path should be present");
        assert!(!path.is_empty(), "Process path should not be empty");
        assert!(
            proc.process_start_time.is_some(),
            "Start time should be present"
        );
        println!("Process: pid={} → {path}", std::process::id());
    }

    #[test]
    fn test_dns_reverse_localhost() {
        let result =
            EnrichmentPool::getnameinfo_lookup(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        // localhost may or may not resolve depending on /etc/hosts — just verify no panic
        println!("DNS reverse 127.0.0.1: {:?}", result);
    }

    #[test]
    fn test_is_public_ip() {
        assert!(!is_public_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_public_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(!is_public_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(is_public_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(is_public_ip(IpAddr::V4(std::net::Ipv4Addr::new(
            1, 1, 1, 1
        ))));
    }
}
