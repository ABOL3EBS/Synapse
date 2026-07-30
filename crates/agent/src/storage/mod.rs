pub mod models;
pub mod reader;
mod schema;
mod spool;

use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crossbeam_channel::{Receiver, Sender};
use log::{error, info, warn};
use rusqlite::{params, Connection};
use synapse_common::{DetectorFinding, FlowRecord};

use spool::CriticalSpool;

// ---------------------------------------------------------------------------
// Public event types
// ---------------------------------------------------------------------------

/// Events produced by the capture pipeline and consumed by the storage worker.
/// All sends are non-blocking (unbounded channel) — the storage worker never
/// stalls the BPF capture loop.
///
/// Durability classes:
///   Critical  — enforcement lifecycle (written to durable spool before main DB)
///   Important — verdict decisions and circuit breaker transitions (main DB only)
#[derive(Debug)]
pub enum StorageEvent {
    /// Critical: a Block enforcement command was sent to the helper (or failed).
    /// Written to the crash-safe spool before the main DB so enforcement records
    /// survive an agent crash between the IPC send and the database commit.
    EnforcementRequested {
        ip: IpAddr,
        ttl_ms: u64,
        reason: String,
        top_detector: Option<String>,
        composite_score: f32,
        /// None = IPC send succeeded. Some(msg) = send failed with this error.
        send_error: Option<String>,
    },

    /// Important: an Alert or Block verdict was reached for a flow.
    /// Not emitted for Allow — benign traffic is not stored.
    VerdictDecided {
        flow: FlowRecord,
        verdict: String,
        reason: String,
        composite_score: f32,
        ttl_ms: Option<u64>,
        findings: Vec<DetectorFinding>,
    },

    /// Important: a detector's circuit breaker changed state.
    CircuitBreakerTransition {
        detector_id: String,
        from_state: String,
        to_state: String,
        consecutive_failures: u32,
    },
}

// ---------------------------------------------------------------------------
// StorageWorker
// ---------------------------------------------------------------------------

pub struct StorageWorker {
    event_tx: Sender<StorageEvent>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl StorageWorker {
    /// Open the database, apply schema, open the spool, spawn the writer thread.
    /// Returns None on any setup failure — storage is always optional.
    pub fn start(db_path: PathBuf) -> Option<Self> {
        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    warn!("storage: cannot create {}: {e} — disabled", parent.display());
                    return None;
                }
                // Restrict the data directory to the owner only.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) =
                        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    {
                        warn!("storage: chmod {}: {e}", parent.display());
                    }
                }
            }
        }

        // Open a temporary connection just to apply the schema, then drop it.
        // The worker thread opens its own connection after the thread starts.
        match Connection::open(&db_path) {
            Ok(conn) => {
                if let Err(e) = schema::apply_schema(&conn) {
                    warn!("storage: schema init: {e} — disabled");
                    return None;
                }
            }
            Err(e) => {
                warn!("storage: cannot open {}: {e} — disabled", db_path.display());
                return None;
            }
        }

        let spool_path = db_path.with_extension("spool");
        let db_path_str = db_path.to_string_lossy().to_string();
        let boot_id = generate_boot_id();

        let (tx, rx) = crossbeam_channel::unbounded::<StorageEvent>();
        let handle = std::thread::Builder::new()
            .name("storage-worker".into())
            .spawn(move || worker_loop(db_path_str, spool_path, boot_id, rx))
            .expect("storage worker thread spawn");

        info!("storage worker started: {}", db_path.display());
        Some(Self {
            event_tx: tx,
            join_handle: Some(handle),
        })
    }

    pub fn event_tx(&self) -> Sender<StorageEvent> {
        self.event_tx.clone()
    }

    /// Drop the sender (signals shutdown) and wait for the worker to flush.
    pub fn shutdown(self) {
        drop(self.event_tx);
        if let Some(handle) = self.join_handle {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Worker loop
// ---------------------------------------------------------------------------

fn worker_loop(db_path: String, spool_path: PathBuf, boot_id: u64, rx: Receiver<StorageEvent>) {
    let mut conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            error!("storage worker: open {db_path}: {e}");
            return;
        }
    };
    if let Err(e) = schema::harden(&mut conn) {
        warn!("storage worker: harden: {e}");
    }

    // Open the critical spool. Failure is degraded-mode (not fatal) — enforcement
    // records will still reach the main DB; they just won't survive a crash
    // between IPC send and DB commit. Warn loudly so operators notice.
    let mut spool: Option<CriticalSpool> = match CriticalSpool::open(&spool_path) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("storage: spool unavailable: {e} — critical events not crash-safe");
            None
        }
    };

    // On startup, replay any Critical events that were spooled but not yet
    // committed to the main DB (e.g. due to a crash).
    if let Some(ref mut sp) = spool {
        replay_spool(sp, &mut conn);
    }

    let mut seq: u64 = 0;
    let mut batch_count: u64 = 0;
    let mut pending: Vec<StorageEvent> = Vec::with_capacity(20);
    let mut pending_critical_ids: Vec<String> = Vec::new();

    let tick = crossbeam_channel::tick(std::time::Duration::from_millis(250));

    loop {
        crossbeam_channel::select! {
            recv(rx) -> msg => match msg {
                Ok(event) => {
                    // Critical events go to the spool first.
                    if let StorageEvent::EnforcementRequested { .. } = &event {
                        seq += 1;
                        let event_id = format!("{boot_id:016x}{seq:016x}");
                        let ts_ms = system_time_millis();
                        let payload = spool_payload_for(&event);
                        if let Some(ref mut sp) = spool {
                            if let Err(e) = sp.append(&event_id, ts_ms, "EnforcementRequested", &payload) {
                                warn!("storage: spool append: {e}");
                            }
                        }
                        pending_critical_ids.push(event_id);
                    }
                    pending.push(event);
                    if pending.len() >= 20 {
                        flush(&mut conn, &mut spool, &mut pending,
                              &mut pending_critical_ids, &mut batch_count);
                    }
                }
                Err(_) => {
                    // Channel closed — flush remaining and exit.
                    if !pending.is_empty() {
                        flush(&mut conn, &mut spool, &mut pending,
                              &mut pending_critical_ids, &mut batch_count);
                    }
                    info!("storage worker shut down");
                    return;
                }
            },
            recv(tick) -> _ => {
                if !pending.is_empty() {
                    flush(&mut conn, &mut spool, &mut pending,
                          &mut pending_critical_ids, &mut batch_count);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Flush: commit a batch to SQLite
// ---------------------------------------------------------------------------

fn flush(
    conn: &mut Connection,
    spool: &mut Option<CriticalSpool>,
    pending: &mut Vec<StorageEvent>,
    pending_critical_ids: &mut Vec<String>,
    batch_count: &mut u64,
) {
    let ts_ms = system_time_millis();

    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!("storage: begin tx: {e} — dropping {} event(s)", pending.len());
            pending.clear();
            pending_critical_ids.clear();
            return;
        }
    };

    for event in pending.drain(..) {
        match event {
            StorageEvent::EnforcementRequested {
                ip,
                ttl_ms,
                reason,
                top_detector,
                composite_score,
                send_error,
            } => {
                // Stable event_id is at the same index as pending_critical_ids.
                // We drain pending in order so the IDs match.
                let event_id = pending_critical_ids
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("{ts_ms}"));
                let (ip_blob, ip_text) = ip_to_parts(ip);
                let requested = if send_error.is_none() { 1i64 } else { 0i64 };
                if let Err(e) = tx.execute(
                    "INSERT OR IGNORE INTO enforcement_log
                     (event_id, ts_ms, action, ip_blob, ip_text, ttl_ms,
                      reason, detector, score, requested, confirmed, error)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,?11)",
                    params![
                        event_id,
                        ts_ms,
                        "Block",
                        &ip_blob[..],
                        ip_text,
                        ttl_ms as i64,
                        reason,
                        top_detector,
                        composite_score as f64,
                        requested,
                        send_error,
                    ],
                ) {
                    warn!("storage: enforcement insert: {e}");
                }
                if !pending_critical_ids.is_empty() {
                    pending_critical_ids.remove(0);
                }
            }

            StorageEvent::VerdictDecided {
                flow,
                verdict,
                reason,
                composite_score,
                ttl_ms,
                findings,
            } => {
                let (a_blob, a_text) = ip_to_parts(flow.a_ip);
                let (b_blob, b_text) = ip_to_parts(flow.b_ip);
                let flow_age_ms = flow.flow_age.as_millis() as i64;
                let verdict_id: i64 = match tx.query_row(
                    "INSERT INTO verdicts
                     (ts_ms, flow_id, a_ip_blob, b_ip_blob, a_ip_text, b_ip_text,
                      a_port, b_port, protocol, pid, process_path, process_start,
                      dns_name, country_code, asn, reputation_score,
                      verdict, reason, composite_score, ttl_ms, flow_age_ms,
                      pkt_count, byte_count)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,
                             ?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)
                     RETURNING id",
                    params![
                        ts_ms,
                        flow.flow_id as i64,
                        &a_blob[..],
                        &b_blob[..],
                        a_text,
                        b_text,
                        flow.a_port as i64,
                        flow.b_port as i64,
                        flow.protocol as i64,
                        flow.pid.map(|p| p as i64),
                        flow.process_path,
                        flow.process_start_time,
                        flow.dns_name,
                        flow.country_code,
                        flow.asn.map(|a| a as i64),
                        flow.reputation_score.map(|s| s as f64),
                        verdict,
                        reason,
                        composite_score as f64,
                        ttl_ms.map(|t| t as i64),
                        flow_age_ms,
                        flow.packet_count as i64,
                        flow.byte_count as i64,
                    ],
                    |r| r.get(0),
                ) {
                    Ok(id) => id,
                    Err(e) => {
                        warn!("storage: verdict insert: {e}");
                        continue;
                    }
                };

                for finding in &findings {
                    let ev_json = serde_json::to_string(&finding.evidence).ok();
                    if let Err(e) = tx.execute(
                        "INSERT INTO detector_findings
                         (verdict_id, detector_id, detector_version, score,
                          confidence, severity, status, latency_us, evidence_json)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                        params![
                            verdict_id,
                            format!("{:?}", finding.detector_id),
                            finding.detector_version,
                            finding.score as f64,
                            finding.confidence as f64,
                            format!("{:?}", finding.severity),
                            format!("{:?}", finding.status),
                            finding.latency_us as i64,
                            ev_json,
                        ],
                    ) {
                        warn!("storage: finding insert: {e}");
                    }
                }
            }

            StorageEvent::CircuitBreakerTransition {
                detector_id,
                from_state,
                to_state,
                consecutive_failures,
            } => {
                if let Err(e) = tx.execute(
                    "INSERT INTO circuit_breaker_events
                     (ts_ms, detector_id, from_state, to_state, consecutive_failures)
                     VALUES (?1,?2,?3,?4,?5)",
                    params![
                        ts_ms,
                        detector_id,
                        from_state,
                        to_state,
                        consecutive_failures as i64,
                    ],
                ) {
                    warn!("storage: cb_event insert: {e}");
                }
            }
        }
    }

    let commit_ok = tx.commit().is_ok();

    // After a successful commit, mark the Critical spool entries as done.
    if commit_ok {
        if let Some(ref mut sp) = spool {
            // All pending_critical_ids were consumed during the loop above;
            // the vec is now empty. Confirm any remaining stragglers (shouldn't
            // happen but guard defensively).
            if !pending_critical_ids.is_empty() {
                let ids: Vec<String> = pending_critical_ids.drain(..).collect();
                if let Err(e) = sp.confirm(&ids) {
                    warn!("storage: spool confirm: {e}");
                }
            }
        }
    } else {
        warn!("storage: commit failed — batch dropped");
        pending_critical_ids.clear();
    }

    *batch_count += 1;

    // Retention: prune old rows every 2000 batches (~500s at 250ms cadence).
    if *batch_count % 2000 == 0 {
        run_retention(conn);
        if let Some(ref mut sp) = spool {
            let cutoff = system_time_millis() - 7 * 24 * 60 * 60 * 1000;
            sp.prune_done(cutoff);
        }
    }
}

// ---------------------------------------------------------------------------
// Spool replay on startup
// ---------------------------------------------------------------------------

fn replay_spool(spool: &mut CriticalSpool, conn: &mut Connection) {
    let entries = spool.unconfirmed();
    if entries.is_empty() {
        return;
    }
    info!("storage: replaying {} unconfirmed spool entry(ies)", entries.len());
    let mut confirmed = Vec::new();
    for entry in entries {
        // Each payload was serialised by spool_payload_for() as JSON.
        // Re-insert into enforcement_log with INSERT OR IGNORE — idempotent.
        let ok = replay_enforcement(conn, &entry.event_id, entry.ts_ms, &entry.payload);
        if ok {
            confirmed.push(entry.event_id);
        }
    }
    let n = confirmed.len();
    if let Err(e) = spool.confirm(&confirmed) {
        warn!("storage: spool confirm after replay: {e}");
    } else {
        info!("storage: spool replay complete — {n} entry(ies) confirmed");
    }
}

fn replay_enforcement(conn: &mut Connection, event_id: &str, ts_ms: i64, payload: &str) -> bool {
    // Payload is JSON produced by spool_payload_for — parse the fields we need.
    let v: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(e) => {
            warn!("storage: replay parse {event_id}: {e}");
            return false;
        }
    };
    let ip_text = v["ip_text"].as_str().unwrap_or("unknown");
    let ip_blob_hex = v["ip_blob_hex"].as_str().unwrap_or("");
    let ip_blob: Vec<u8> = (0..ip_blob_hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&ip_blob_hex[i..i + 2], 16).ok())
        .collect();
    let ttl_ms = v["ttl_ms"].as_i64();
    let reason = v["reason"].as_str().unwrap_or("");
    let detector = v["detector"].as_str();
    let score = v["score"].as_f64();
    let send_error = v["send_error"].as_str();
    let requested = if send_error.is_none() { 1i64 } else { 0i64 };

    conn.execute(
        "INSERT OR IGNORE INTO enforcement_log
         (event_id, ts_ms, action, ip_blob, ip_text, ttl_ms,
          reason, detector, score, requested, confirmed, error)
         VALUES (?1,?2,'Block',?3,?4,?5,?6,?7,?8,?9,0,?10)",
        params![
            event_id,
            ts_ms,
            ip_blob,
            ip_text,
            ttl_ms,
            reason,
            detector,
            score,
            requested,
            send_error,
        ],
    )
    .is_ok()
}

// ---------------------------------------------------------------------------
// Retention
// ---------------------------------------------------------------------------

fn run_retention(conn: &mut Connection) {
    let now = system_time_millis();
    // enforcement_log: 90 days
    let enf_cutoff = now - 90 * 24 * 60 * 60 * 1000_i64;
    // verdicts + cascade to detector_findings: 7 days
    let verd_cutoff = now - 7 * 24 * 60 * 60 * 1000_i64;
    // circuit_breaker_events: 7 days
    let cb_cutoff = verd_cutoff;

    for (sql, cutoff, label) in [
        ("DELETE FROM enforcement_log WHERE ts_ms < ?1", enf_cutoff, "enforcement_log"),
        ("DELETE FROM verdicts WHERE ts_ms < ?1", verd_cutoff, "verdicts"),
        ("DELETE FROM circuit_breaker_events WHERE ts_ms < ?1", cb_cutoff, "circuit_breaker_events"),
    ] {
        match conn.execute(sql, params![cutoff]) {
            Ok(n) if n > 0 => info!("storage: retention pruned {n} rows from {label}"),
            Ok(_) => {}
            Err(e) => warn!("storage: retention {label}: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an IpAddr to canonical 16-byte blob (IPv4-mapped) and text string.
fn ip_to_parts(ip: IpAddr) -> ([u8; 16], String) {
    let blob = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    (blob, ip.to_string())
}

/// Decode a 16-byte blob back to IpAddr (used in spool replay).
#[allow(dead_code)]
fn blob_to_ip(blob: &[u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(*blob);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Serialise a Critical event to JSON for spool storage.
fn spool_payload_for(event: &StorageEvent) -> String {
    match event {
        StorageEvent::EnforcementRequested {
            ip,
            ttl_ms,
            reason,
            top_detector,
            composite_score,
            send_error,
        } => {
            let (blob, ip_text) = ip_to_parts(*ip);
            let blob_hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
            serde_json::json!({
                "ip_blob_hex": blob_hex,
                "ip_text":     ip_text,
                "ttl_ms":      ttl_ms,
                "reason":      reason,
                "detector":    top_detector,
                "score":       composite_score,
                "send_error":  send_error,
            })
            .to_string()
        }
        _ => "{}".to_string(),
    }
}

/// Generate a boot-scoped unique ID from startup time + PID.
/// Not cryptographically random — unique enough for event IDs within a host.
fn generate_boot_id() -> u64 {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    // Fibonacci hashing to spread bits.
    ts ^ pid.wrapping_mul(0x9e3779b97f4a7c15)
}

fn system_time_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_roundtrip_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let (blob, text) = ip_to_parts(ip);
        assert_eq!(text, "192.168.1.1");
        let recovered = blob_to_ip(&blob);
        assert_eq!(recovered, ip);
    }

    #[test]
    fn test_ip_roundtrip_v6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let (blob, _) = ip_to_parts(ip);
        let recovered = blob_to_ip(&blob);
        assert_eq!(recovered, ip);
    }

    #[test]
    fn test_spool_append_and_confirm() {
        let dir = std::env::temp_dir().join("synapse_spool_test");
        let _ = std::fs::remove_file(&dir);
        let mut spool = CriticalSpool::open(&dir).expect("open spool");
        spool.append("evt-1", 1000, "EnforcementRequested", "{}").unwrap();
        spool.append("evt-2", 2000, "EnforcementRequested", "{}").unwrap();
        let pending = spool.unconfirmed();
        assert_eq!(pending.len(), 2);
        spool.confirm(&["evt-1".to_string()]).unwrap();
        let pending = spool.unconfirmed();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, "evt-2");
        let _ = std::fs::remove_file(dir);
    }
}
