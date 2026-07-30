// Intentionally unused until the Tauri UI IPC socket is implemented.
#![allow(dead_code)]

/// StorageReader — a separate read-only connection to the main database.
///
/// WAL mode (set on the writer connection) allows concurrent readers without
/// blocking writes. The reader is intended for the Tauri IPC layer; it never
/// touches the spool and never writes.
///
/// All methods return empty collections on query failure rather than
/// propagating errors — the UI should degrade gracefully if the DB is
/// temporarily locked or missing.
use std::path::Path;

use log::warn;
use rusqlite::{params, Connection, OpenFlags};

use super::models::*;

pub struct StorageReader {
    conn: Connection,
}

impl StorageReader {
    pub fn open(db_path: &Path) -> Result<Self, String> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("reader open: {e}"))?;
        conn.execute_batch(
            "PRAGMA journal_mode   = WAL;
             PRAGMA foreign_keys   = ON;
             PRAGMA query_only     = ON;",
        )
        .ok();
        Ok(Self { conn })
    }

    /// Most recent Alert/Block verdicts, newest first.
    pub fn recent_verdicts(&self, limit: usize) -> Vec<VerdictRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, ts_ms, flow_id, a_ip_text, b_ip_text, a_port, b_port,
                    pid, process_path, dns_name, country_code,
                    verdict, composite_score, flow_age_ms
             FROM verdicts ORDER BY ts_ms DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("reader verdicts: {e}");
                return vec![];
            }
        };
        stmt.query_map(params![limit as i64], |r| {
            Ok(VerdictRow {
                id: r.get(0)?,
                ts_ms: r.get(1)?,
                flow_id: r.get(2)?,
                a_ip_text: r.get(3)?,
                b_ip_text: r.get(4)?,
                a_port: r.get(5)?,
                b_port: r.get(6)?,
                pid: r.get(7)?,
                process_path: r.get(8)?,
                dns_name: r.get(9)?,
                country_code: r.get(10)?,
                verdict: r.get(11)?,
                composite_score: r.get(12)?,
                flow_age_ms: r.get(13)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// All detector findings for a specific verdict, sorted by score descending.
    pub fn verdict_findings(&self, verdict_id: i64) -> Vec<FindingRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT detector_id, detector_version, score, confidence,
                    severity, status, latency_us, evidence_json
             FROM detector_findings
             WHERE verdict_id = ?1
             ORDER BY score DESC",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("reader findings: {e}");
                return vec![];
            }
        };
        stmt.query_map(params![verdict_id], |r| {
            Ok(FindingRow {
                detector_id: r.get(0)?,
                detector_version: r.get(1)?,
                score: r.get(2)?,
                confidence: r.get(3)?,
                severity: r.get(4)?,
                status: r.get(5)?,
                latency_us: r.get(6)?,
                evidence_json: r.get(7)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Most recent enforcement actions, newest first.
    pub fn recent_enforcement(&self, limit: usize) -> Vec<EnforcementRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, ts_ms, action, ip_text, ttl_ms, reason,
                    detector, score, requested, confirmed, error
             FROM enforcement_log ORDER BY ts_ms DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("reader enforcement: {e}");
                return vec![];
            }
        };
        stmt.query_map(params![limit as i64], |r| {
            Ok(EnforcementRow {
                id: r.get(0)?,
                ts_ms: r.get(1)?,
                action: r.get(2)?,
                ip_text: r.get(3)?,
                ttl_ms: r.get(4)?,
                reason: r.get(5)?,
                detector: r.get(6)?,
                score: r.get(7)?,
                requested: r.get::<_, i64>(8)? != 0,
                confirmed: r.get::<_, i64>(9)? != 0,
                error: r.get(10)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Per-detector last known circuit breaker state and transition count.
    pub fn detector_health(&self) -> Vec<DetectorHealthRow> {
        let mut stmt = match self.conn.prepare(
            "SELECT e.detector_id,
                    (SELECT e2.to_state FROM circuit_breaker_events e2
                     WHERE e2.detector_id = e.detector_id
                     ORDER BY e2.ts_ms DESC LIMIT 1) AS last_state,
                    COUNT(*)    AS transition_count,
                    MAX(e.ts_ms) AS last_ts_ms
             FROM circuit_breaker_events e
             GROUP BY e.detector_id",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("reader health: {e}");
                return vec![];
            }
        };
        stmt.query_map([], |r| {
            Ok(DetectorHealthRow {
                detector_id: r.get(0)?,
                last_state: r.get(1)?,
                transition_count: r.get(2)?,
                last_ts_ms: r.get(3)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// KPI counts since `since_ms` (unix milliseconds).
    pub fn kpi_since(&self, since_ms: i64) -> KpiSummary {
        let q = |sql: &str| -> i64 {
            self.conn
                .query_row(sql, params![since_ms], |r| r.get(0))
                .unwrap_or(0)
        };
        KpiSummary {
            blocks_24h: q(
                "SELECT count(*) FROM verdicts \
                 WHERE verdict='Block' AND ts_ms >= ?1",
            ),
            alerts_24h: q(
                "SELECT count(*) FROM verdicts \
                 WHERE verdict='Alert' AND ts_ms >= ?1",
            ),
            unique_ips_blocked: q(
                "SELECT count(DISTINCT ip_text) FROM enforcement_log \
                 WHERE ts_ms >= ?1 AND confirmed = 0 AND error IS NULL",
            ),
            enforcement_failures: q(
                "SELECT count(*) FROM enforcement_log \
                 WHERE ts_ms >= ?1 AND error IS NOT NULL",
            ),
        }
    }
}
