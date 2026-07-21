// crates/agent/src/enrichment/mod.rs
//
// Async enrichment worker pool — runs as a side-channel that never gates
// the hot path (§4). Dispatched on flow creation, results attach to the
// flow record whenever they complete.

use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use log::{debug, error, info};
use synapse_common::{EnrichmentKind, EnrichmentRequest, EnrichmentResult};

/// Number of worker threads in the enrichment pool.
/// v1: fixed at 4. Could become configurable later.
const WORKER_COUNT: usize = 4;

/// Default timeout for a single enrichment lookup (e.g., DNS).
/// Currently unused — reserved for future per-lookup timeouts.
#[allow(dead_code)]
const LOOKUP_TIMEOUT_MS: u64 = 2000;

/// The enrichment worker pool. Owns the dispatch sender and result receiver.
/// Callers dispatch requests via `dispatch()` and collect results via `try_recv()`.
pub struct EnrichmentPool {
    /// Send enrichment requests to any available worker.
    tx: Sender<EnrichmentRequest>,
    /// Receive results from workers (non-blocking via try_recv).
    rx: Receiver<EnrichmentResult>,
}

impl EnrichmentPool {
    /// Create a new enrichment pool with WORKER_COUNT background threads.
    /// Each thread pulls requests from a shared receiver and sends results
    /// back through per-thread result senders that all feed into one receiver.
    pub fn new() -> Self {
        let (req_tx, req_rx) = mpsc::channel::<EnrichmentRequest>();
        let (res_tx, res_rx) = mpsc::channel::<EnrichmentResult>();

        // Wrap request receiver in Arc<Mutex<>> so workers can share it.
        // Lock contention is minimal — workers hold the lock only while calling recv().
        let shared_rx = Arc::new(Mutex::new(req_rx));

        for worker_id in 0..WORKER_COUNT {
            let req_rx = shared_rx.clone();
            let res_tx = res_tx.clone();

            thread::Builder::new()
                .name(format!("enrichment-{worker_id}"))
                .spawn(move || {
                    Self::worker_loop(worker_id, req_rx, res_tx);
                })
                .expect("failed to spawn enrichment worker thread");
        }

        // Drop our copy of res_tx so the receiver closes when all workers exit.
        drop(res_tx);

        info!("enrichment pool started: {WORKER_COUNT} workers");

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
                let result = Self::run_enrichment(*kind, &request);
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

    fn run_enrichment(kind: EnrichmentKind, request: &EnrichmentRequest) -> EnrichmentResult {
        match kind {
            EnrichmentKind::DnsReverse => Self::enrich_dns_reverse(request),
            EnrichmentKind::ProcessAttribution => Self::enrich_process_attribution(request),
            EnrichmentKind::GeoIp => Self::enrich_geoip_stub(request),
            EnrichmentKind::Reputation => Self::enrich_reputation_stub(request),
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
    // GeoIP stub (v1)
    // -----------------------------------------------------------------------

    fn enrich_geoip_stub(request: &EnrichmentRequest) -> EnrichmentResult {
        let target_ip = Self::pick_enrichable_ip(request.src_ip, request.dst_ip);
        debug!("geoip stub: {target_ip} → unknown (v1 stub)");
        EnrichmentResult {
            kind: EnrichmentKind::GeoIp,
            success: false,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code: None,
            asn: None,
            reputation_score: None,
            error: Some("geoip not implemented in v1".into()),
        }
    }

    // -----------------------------------------------------------------------
    // Reputation stub (v1)
    // -----------------------------------------------------------------------

    fn enrich_reputation_stub(request: &EnrichmentRequest) -> EnrichmentResult {
        let target_ip = Self::pick_enrichable_ip(request.src_ip, request.dst_ip);
        debug!("reputation stub: {target_ip} → unknown (v1 stub)");
        EnrichmentResult {
            kind: EnrichmentKind::Reputation,
            success: false,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code: None,
            asn: None,
            reputation_score: None,
            error: Some("reputation lookup not implemented in v1".into()),
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
        if Self::is_public_ip(dst) {
            dst
        } else {
            src
        }
    }

    /// Check if an IP is a public (non-RFC1918, non-loopback) address.
    fn is_public_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                !(v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.octets()[0] == 100 && v4.octets()[1] >= 64 && v4.octets()[1] <= 127 // 100.64.0.0/10 CGNAT
                    || v4.octets()[0] == 169 && v4.octets()[1] == 254) // 169.254.0.0/16 link-local
            }
            IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()),
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
        let pool = EnrichmentPool::new();

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
        let result = EnrichmentPool::getnameinfo_lookup(
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        );
        // localhost may or may not resolve depending on /etc/hosts — just verify no panic
        println!("DNS reverse 127.0.0.1: {:?}", result);
    }

    #[test]
    fn test_is_public_ip() {
        assert!(!EnrichmentPool::is_public_ip(
            IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
        ));
        assert!(!EnrichmentPool::is_public_ip(
            IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))
        ));
        assert!(!EnrichmentPool::is_public_ip(
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
        ));
        assert!(EnrichmentPool::is_public_ip(
            IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
        ));
        assert!(EnrichmentPool::is_public_ip(
            IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))
        ));
    }
}
