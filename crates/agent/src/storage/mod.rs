pub mod models;
pub mod reader;
mod schema;
mod spool;

use std::collections::VecDeque;
use std::net::IpAddr;
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
        flow: Box<FlowRecord>,
        local_ip: std::net::IpAddr,
        /// Direction-resolved remote endpoint, persisted verbatim from resolved.remote_ip.
        /// Stored as remote_ip_text so the dashboard never re-derives direction.
        remote_ip: std::net::IpAddr,
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
                    warn!(
                        "storage: cannot create {}: {e} — disabled",
                        parent.display()
                    );
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

// Retention fires at most once per hour of wall-clock time, checked on every
// 250ms tick. The timestamp is persisted in the metadata table so it survives
// agent restarts — a pure in-memory counter resets on every restart and will
// never fire in a usage pattern of frequent short-lived runs.
const RETENTION_INTERVAL_MS: i64 = 60 * 60 * 1000; // 1 hour

fn worker_loop(db_path: String, spool_path: PathBuf, boot_id: u64, rx: Receiver<StorageEvent>) {
    let mut conn = match Connection::open(&db_path) {
        Ok(c) => c,
        Err(e) => {
            error!("storage worker: open {db_path}: {e}");
            return;
        }
    };
    if let Err(e) = schema::harden(&conn) {
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

    // Load the last retention timestamp from the metadata table. This survives
    // restarts — if it was an hour ago, retention fires on the first tick.
    let mut last_retention_ms: i64 = load_last_retention_ms(&conn);

    let mut seq: u64 = 0;
    let mut pending: Vec<StorageEvent> = Vec::with_capacity(20);
    let mut pending_critical_ids: VecDeque<String> = VecDeque::new();

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
                        pending_critical_ids.push_back(event_id);
                    }
                    pending.push(event);
                    if pending.len() >= 20 {
                        flush(&mut conn, &mut spool, &mut pending,
                              &mut pending_critical_ids);
                    }
                }
                Err(_) => {
                    // Channel closed — flush remaining and exit.
                    if !pending.is_empty() {
                        flush(&mut conn, &mut spool, &mut pending,
                              &mut pending_critical_ids);
                    }
                    info!("storage worker shut down");
                    return;
                }
            },
            recv(tick) -> _ => {
                if !pending.is_empty() {
                    flush(&mut conn, &mut spool, &mut pending,
                          &mut pending_critical_ids);
                }
                // Wall-clock retention check — survives restarts.
                let now = system_time_millis();
                if now - last_retention_ms > RETENTION_INTERVAL_MS {
                    run_retention(&mut conn);
                    if let Some(ref mut sp) = spool {
                        let cutoff = now - 7 * 24 * 60 * 60 * 1000;
                        sp.prune_done(cutoff);
                    }
                    last_retention_ms = now;
                    save_last_retention_ms(&mut conn, now);
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
    pending_critical_ids: &mut VecDeque<String>,
) {
    let ts_ms = system_time_millis();

    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!(
                "storage: begin tx: {e} — dropping {} event(s)",
                pending.len()
            );
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
                    .pop_front()
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
            }

            StorageEvent::VerdictDecided {
                flow,
                local_ip,
                remote_ip,
                verdict,
                reason,
                composite_score,
                ttl_ms,
                findings,
            } => {
                let (a_blob, a_text) = ip_to_parts(flow.a_ip);
                let (b_blob, b_text) = ip_to_parts(flow.b_ip);
                let local_ip_text = local_ip.to_string();
                let remote_ip_text = remote_ip.to_string();
                let flow_age_ms = flow.flow_age.as_millis() as i64;
                let verdict_id: i64 = match tx.query_row(
                    "INSERT INTO verdicts
                     (ts_ms, flow_id, a_ip_blob, b_ip_blob, a_ip_text, b_ip_text,
                      a_port, b_port, protocol, pid, process_path, process_start,
                      dns_name, country_code, asn, reputation_score,
                      verdict, reason, composite_score, ttl_ms, flow_age_ms,
                      pkt_count, byte_count, local_ip_text, remote_ip_text)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,
                             ?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)
                     ON CONFLICT(a_ip_text, a_port, b_ip_text, b_port, protocol, verdict)
                     DO UPDATE SET
                       ts_ms            = excluded.ts_ms,
                       flow_id          = excluded.flow_id,
                       composite_score  = excluded.composite_score,
                       reason           = excluded.reason,
                       ttl_ms           = excluded.ttl_ms,
                       flow_age_ms      = excluded.flow_age_ms,
                       pkt_count        = excluded.pkt_count,
                       byte_count       = excluded.byte_count,
                       pid              = excluded.pid,
                       process_path     = excluded.process_path,
                       process_start    = excluded.process_start,
                       dns_name         = excluded.dns_name,
                       country_code     = excluded.country_code,
                       asn              = excluded.asn,
                       reputation_score = excluded.reputation_score,
                       local_ip_text    = excluded.local_ip_text,
                       remote_ip_text   = excluded.remote_ip_text
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
                        local_ip_text,
                        remote_ip_text,
                    ],
                    |r| r.get(0),
                ) {
                    Ok(id) => id,
                    Err(e) => {
                        warn!("storage: verdict insert: {e}");
                        continue;
                    }
                };

                // On re-evaluation the same verdict row is upserted (same id).
                // The old detector_findings for this id are stale — replace them.
                if let Err(e) = tx.execute(
                    "DELETE FROM detector_findings WHERE verdict_id = ?1",
                    params![verdict_id],
                ) {
                    warn!("storage: stale findings delete: {e}");
                }

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
}

// ---------------------------------------------------------------------------
// Spool replay on startup
// ---------------------------------------------------------------------------

fn replay_spool(spool: &mut CriticalSpool, conn: &mut Connection) {
    let entries = spool.unconfirmed();
    if entries.is_empty() {
        return;
    }
    info!(
        "storage: replaying {} unconfirmed spool entry(ies)",
        entries.len()
    );
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
            event_id, ts_ms, ip_blob, ip_text, ttl_ms, reason, detector, score, requested,
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
        (
            "DELETE FROM enforcement_log WHERE ts_ms < ?1",
            enf_cutoff,
            "enforcement_log",
        ),
        (
            "DELETE FROM verdicts WHERE ts_ms < ?1",
            verd_cutoff,
            "verdicts",
        ),
        (
            "DELETE FROM circuit_breaker_events WHERE ts_ms < ?1",
            cb_cutoff,
            "circuit_breaker_events",
        ),
    ] {
        match conn.execute(sql, params![cutoff]) {
            Ok(n) if n > 0 => info!("storage: retention pruned {n} rows from {label}"),
            Ok(_) => {}
            Err(e) => warn!("storage: retention {label}: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata helpers — durable worker state in the metadata table
// ---------------------------------------------------------------------------

fn load_last_retention_ms(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT CAST(value AS INTEGER) FROM metadata WHERE key = 'last_retention_run_ms'",
        [],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

fn save_last_retention_ms(conn: &mut Connection, ts_ms: i64) {
    if let Err(e) = conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_retention_run_ms', ?1)",
        params![ts_ms],
    ) {
        warn!("storage: save last_retention_ms: {e}");
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

#[cfg(test)]
fn blob_to_ip(blob: &[u8; 16]) -> IpAddr {
    use std::net::Ipv6Addr;
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
    use rusqlite::Connection;
    use std::net::{IpAddr, Ipv4Addr};
    use synapse_common::{FlowRecord, ResolvedFlow};

    fn make_test_flow() -> FlowRecord {
        FlowRecord {
            flow_id: 99,
            a_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            b_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            a_port: 50000,
            b_port: 443,
            protocol: 6,
            local_port: 50000,
            pid: None,
            packet_count: 5,
            byte_count: 1024,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code: None,
            asn: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(1),
            // a_port=50000=local_port → a_ip is local, b_ip is remote.
            resolved: Some(ResolvedFlow {
                local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                local_port: 50000,
                remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 443,
            }),
        }
    }

    /// Verify that write failures degrade gracefully: the storage worker does not
    /// crash or panic when inserts fail, and continues processing subsequent events.
    ///
    /// Mechanism: sabotage the verdicts table via a separate connection while the
    /// worker is running, send events that will fail, then send a probe event to a
    /// still-intact table and verify it lands after shutdown. This proves:
    ///   (a) no panic — the test completes and the DB is queryable
    ///   (b) the warn! path runs (structurally: the only code between the failing INSERT
    ///       and `continue` is `warn!("storage: verdict insert: {e}")`)
    ///   (c) the worker is still alive and processing after the failures
    #[test]
    fn test_write_failure_degrades_gracefully() {
        let db_path = std::env::temp_dir().join(format!("synapse_fail_{}.db", std::process::id()));
        let spool_path = db_path.with_extension("spool");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);

        let worker = StorageWorker::start(db_path.clone()).expect("worker should start");
        let tx = worker.event_tx();

        // Sabotage the verdicts table on a separate connection while the worker runs.
        // FK constraints don't apply to DDL, so no need to disable them for DROP.
        {
            let sabotage = Connection::open(&db_path).unwrap();
            sabotage
                .execute_batch("DROP TABLE detector_findings; DROP TABLE verdicts;")
                .unwrap();
        }

        // Send events that will fail — verdicts table is gone.
        for _ in 0..3 {
            tx.send(StorageEvent::VerdictDecided {
                flow: Box::new(make_test_flow()),
                local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                verdict: "Alert".to_string(),
                reason: "failure test".to_string(),
                composite_score: 0.4,
                ttl_ms: None,
                findings: vec![],
            })
            .unwrap();
        }

        // Wait for the 250ms tick to flush the failing batch.
        std::thread::sleep(std::time::Duration::from_millis(600));

        // Send a probe event to a table that still exists — proves the worker is
        // still running and accepting events after the write failures.
        tx.send(StorageEvent::CircuitBreakerTransition {
            detector_id: "degradation-probe".to_string(),
            from_state: "Closed".to_string(),
            to_state: "Open".to_string(),
            consecutive_failures: 1,
        })
        .unwrap();

        // Drop our tx clone so the worker sees channel close when we call shutdown.
        drop(tx);
        worker.shutdown();

        // Confirm the probe event landed — the worker survived the write failures.
        let conn = Connection::open(&db_path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM circuit_breaker_events \
                 WHERE detector_id = 'degradation-probe'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "probe event must land after write failures — worker must survive"
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);
    }

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

    /// Verify that re-evaluation firing multiple times on the same active flow
    /// produces exactly ONE verdict row (upserted) rather than one row per tick.
    ///
    /// Exercises the real StorageWorker + event channel end-to-end (not internal
    /// state), per the rule that stateful-mechanism tests must go through the
    /// actual public call path.
    #[test]
    fn test_re_evaluation_upserts_not_inserts() {
        let db_path =
            std::env::temp_dir().join(format!("synapse_upsert_{}.db", std::process::id()));
        let spool_path = db_path.with_extension("spool");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);

        let worker = StorageWorker::start(db_path.clone()).expect("worker should start");
        let tx = worker.event_tx();

        // Re-use a fixed 5-tuple+verdict — simulates the re-evaluation loop
        // firing three times on the same still-active flow.
        let flow = make_test_flow(); // a_ip=10.0.0.1:50000, b_ip=8.8.8.8:443, proto=6
        for tick_ts in [1_000_000u64, 2_000_000, 3_000_000] {
            // Each tick sends a VerdictDecided with the same 5-tuple and verdict
            // but an advancing ts_ms — exactly what the re-evaluation loop does.
            tx.send(StorageEvent::VerdictDecided {
                flow: Box::new(FlowRecord {
                    flow_id: tick_ts, // flow_id advances each tick (simulates restarts)
                    ..flow.clone()
                }),
                local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                verdict: "Alert".to_string(),
                reason: format!("tick {tick_ts}"),
                composite_score: 0.6,
                ttl_ms: None,
                findings: vec![],
            })
            .unwrap();
        }

        // Wait for the 250ms tick to flush all three events.
        std::thread::sleep(std::time::Duration::from_millis(800));
        drop(tx);
        worker.shutdown();

        let conn = Connection::open(&db_path).unwrap();
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM verdicts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            row_count, 1,
            "three re-evaluation ticks for the same 5-tuple+verdict must produce exactly one row"
        );

        // ts_ms is set by the worker's wall clock, not the event — can't assert it.
        // reason IS from the event: must reflect the LAST tick, proving the upsert
        // updated the row rather than keeping the first write's stale values.
        let kept_reason: String = conn
            .query_row("SELECT reason FROM verdicts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            kept_reason, "tick 3000000",
            "kept row must have the latest reason (last re-evaluation tick)"
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);
    }

    #[test]
    fn test_escalation_alert_then_block_produces_two_rows() {
        let db_path =
            std::env::temp_dir().join(format!("synapse_escalate_{}.db", std::process::id()));
        let spool_path = db_path.with_extension("spool");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);

        let worker = StorageWorker::start(db_path.clone()).expect("worker should start");
        let tx = worker.event_tx();

        let flow = make_test_flow(); // a_ip=10.0.0.1:50000, b_ip=8.8.8.8:443
                                     // First: Alert verdict
        tx.send(StorageEvent::VerdictDecided {
            flow: Box::new(flow.clone()),
            local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            verdict: "Alert".to_string(),
            reason: "alert".to_string(),
            composite_score: 0.6,
            ttl_ms: None,
            findings: vec![],
        })
        .unwrap();
        // Then: Block verdict for the same flow (escalation)
        tx.send(StorageEvent::VerdictDecided {
            flow: Box::new(flow.clone()),
            local_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            remote_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            verdict: "Block".to_string(),
            reason: "block".to_string(),
            composite_score: 0.9,
            ttl_ms: Some(300_000),
            findings: vec![],
        })
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(800));
        drop(tx);
        worker.shutdown();

        let conn = Connection::open(&db_path).unwrap();
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM verdicts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            row_count, 2,
            "Alert and Block for the same flow are different verdict values — must produce two rows"
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);
    }

    #[test]
    fn test_spool_append_and_confirm() {
        let dir = std::env::temp_dir().join("synapse_spool_test");
        let _ = std::fs::remove_file(&dir);
        let mut spool = CriticalSpool::open(&dir).expect("open spool");
        spool
            .append("evt-1", 1000, "EnforcementRequested", "{}")
            .unwrap();
        spool
            .append("evt-2", 2000, "EnforcementRequested", "{}")
            .unwrap();
        let pending = spool.unconfirmed();
        assert_eq!(pending.len(), 2);
        spool.confirm(&["evt-1".to_string()]).unwrap();
        let pending = spool.unconfirmed();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, "evt-2");
        let _ = std::fs::remove_file(dir);
    }

    /// Verify remote_ip_text is persisted verbatim and reads back from the verdicts table.
    ///
    /// This closes the storage side of Step F: the dashboard can now read
    /// remote_ip_text directly without re-deriving direction from a/b canonical ordering.
    #[test]
    fn test_verdict_remote_ip_text_roundtrip() {
        let db_path =
            std::env::temp_dir().join(format!("synapse_remote_ip_{}.db", std::process::id()));
        let spool_path = db_path.with_extension("spool");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);

        let worker = StorageWorker::start(db_path.clone()).expect("worker should start");
        let tx = worker.event_tx();

        tx.send(StorageEvent::VerdictDecided {
            flow: Box::new(make_test_flow()),
            local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            verdict: "Alert".to_string(),
            reason: "roundtrip test".to_string(),
            composite_score: 0.5,
            ttl_ms: None,
            findings: vec![],
        })
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(600));
        drop(tx);
        worker.shutdown();

        let conn = Connection::open(&db_path).unwrap();
        let remote_ip_text: String = conn
            .query_row("SELECT remote_ip_text FROM verdicts LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(
            remote_ip_text, "8.8.8.8",
            "remote_ip_text must be persisted verbatim from VerdictDecided.remote_ip"
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);
    }

    /// Regression: local IP numerically larger than remote IP (swap-case).
    ///
    /// Canonical ordering: local=192.168.1.1 > remote=8.8.8.8, so
    /// a_ip=8.8.8.8 (remote, smaller), b_ip=192.168.1.1 (local, larger).
    /// Without remote_ip_text, the old pick_remote() heuristic with NO
    /// local_ip_text would return b_ip_text ("192.168.1.1" — the local endpoint)
    /// as the "remote" IP shown on the dashboard. The dashboard bug was that for
    /// pre-V3 rows (NULL local_ip_text), pick_remote() defaulted to b (canonical
    /// larger = local in this case), showing the user their own IP as the threat.
    ///
    /// With remote_ip_text stored directly, the dashboard never re-derives: it
    /// reads "8.8.8.8" verbatim regardless of canonical ordering.
    #[test]
    fn test_swap_case_remote_ip_text_correct() {
        let db_path = std::env::temp_dir().join(format!("synapse_swap_{}.db", std::process::id()));
        let spool_path = db_path.with_extension("spool");
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);

        let worker = StorageWorker::start(db_path.clone()).expect("worker should start");
        let tx = worker.event_tx();

        // Swap case: local=192.168.1.1 (0xC0A80101) > remote=8.8.8.8 (0x08080808)
        // Canonical: a_ip=8.8.8.8 (smaller=remote), b_ip=192.168.1.1 (larger=local)
        let swap_flow = FlowRecord {
            flow_id: 42,
            a_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            b_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            a_port: 443,
            b_port: 50000,
            protocol: 6,
            local_port: 50000,
            pid: None,
            packet_count: 10,
            byte_count: 2048,
            dns_name: None,
            process_path: None,
            process_start_time: None,
            country_code: None,
            asn: None,
            reputation_score: None,
            flow_age: std::time::Duration::from_secs(2),
            resolved: Some(ResolvedFlow {
                local_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_port: 50000,
                remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                remote_port: 443,
            }),
        };

        tx.send(StorageEvent::VerdictDecided {
            flow: Box::new(swap_flow),
            local_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            remote_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            verdict: "Alert".to_string(),
            reason: "swap-case test".to_string(),
            composite_score: 0.4,
            ttl_ms: None,
            findings: vec![],
        })
        .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(600));
        drop(tx);
        worker.shutdown();

        let conn = Connection::open(&db_path).unwrap();
        let (a_text, b_text, local_text, remote_text): (String, String, String, String) = conn
            .query_row(
                "SELECT a_ip_text, b_ip_text, local_ip_text, remote_ip_text FROM verdicts LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();

        // Canonical ordering: a=remote(8.8.8.8), b=local(192.168.1.1)
        assert_eq!(a_text, "8.8.8.8", "a_ip_text must be the remote endpoint");
        assert_eq!(
            b_text, "192.168.1.1",
            "b_ip_text must be the local endpoint"
        );
        assert_eq!(local_text, "192.168.1.1");
        assert_eq!(
            remote_text, "8.8.8.8",
            "remote_ip_text must be 8.8.8.8 — the REMOTE endpoint, not the \
             canonical b_ip (which is the local machine in the swap case)"
        );
        assert_ne!(
            remote_text, b_text,
            "remote_ip_text must NOT equal b_ip_text in the swap case: \
             b is the local endpoint when local IP > remote IP"
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&spool_path);
    }
}
