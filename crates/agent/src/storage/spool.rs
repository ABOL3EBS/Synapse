/// Critical event spool — a separate SQLite file with synchronous=FULL.
///
/// Critical events (enforcement lifecycle) are written here BEFORE the main
/// database. If the agent crashes between the spool write and the main DB
/// commit, the spool entries survive and are replayed on next startup,
/// giving at-least-once delivery. The main DB uses INSERT OR IGNORE on the
/// stable event_id column so replay is idempotent.
///
/// Spool is intentionally simple: one table, no WAL, synchronous=FULL so
/// every append is fsync'd before returning. Confirmed entries are pruned
/// periodically to keep the file small.
use std::path::Path;

use log::warn;
use rusqlite::{params, Connection};

pub struct SpoolEntry {
    pub event_id: String,
    pub ts_ms: i64,
    #[allow(dead_code)] // stored for operator inspection; not read in code
    pub kind: String,
    pub payload: String,
}

pub struct CriticalSpool {
    conn: Connection,
}

impl CriticalSpool {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn =
            Connection::open(path).map_err(|e| format!("spool open {}: {e}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA synchronous  = FULL;
             PRAGMA foreign_keys = OFF;
             CREATE TABLE IF NOT EXISTS spool (
                 id       INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id TEXT    NOT NULL UNIQUE,
                 ts_ms    INTEGER NOT NULL,
                 kind     TEXT    NOT NULL,
                 payload  TEXT    NOT NULL,
                 done     INTEGER NOT NULL DEFAULT 0
             );",
        )
        .map_err(|e| format!("spool schema: {e}"))?;
        Ok(Self { conn })
    }

    /// Append a Critical event. Blocks until the OS has acknowledged the write
    /// (PRAGMA synchronous=FULL). Returns Err only if the spool itself is broken.
    pub fn append(
        &mut self,
        event_id: &str,
        ts_ms: i64,
        kind: &str,
        payload: &str,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO spool (event_id, ts_ms, kind, payload) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![event_id, ts_ms, kind, payload],
            )
            .map(|_| ())
            .map_err(|e| format!("spool append {event_id}: {e}"))
    }

    /// Return all entries not yet confirmed — these need to be replayed into
    /// the main DB on startup.
    pub fn unconfirmed(&self) -> Vec<SpoolEntry> {
        let mut stmt = match self.conn.prepare(
            "SELECT event_id, ts_ms, kind, payload \
             FROM spool WHERE done = 0 ORDER BY id",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("spool: query unconfirmed: {e}");
                return vec![];
            }
        };
        stmt.query_map([], |r| {
            Ok(SpoolEntry {
                event_id: r.get(0)?,
                ts_ms: r.get(1)?,
                kind: r.get(2)?,
                payload: r.get(3)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    /// Mark a batch of event IDs as confirmed (successfully committed to main DB).
    pub fn confirm(&mut self, event_ids: &[String]) -> Result<(), String> {
        if event_ids.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("spool confirm tx: {e}"))?;
        for id in event_ids {
            tx.execute("UPDATE spool SET done = 1 WHERE event_id = ?1", params![id])
                .map_err(|e| format!("spool confirm {id}: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("spool confirm commit: {e}"))
    }

    /// Delete confirmed entries older than `before_ts_ms`. Called periodically
    /// to keep the spool file from growing unbounded.
    pub fn prune_done(&mut self, before_ts_ms: i64) {
        if let Err(e) = self.conn.execute(
            "DELETE FROM spool WHERE done = 1 AND ts_ms < ?1",
            params![before_ts_ms],
        ) {
            warn!("spool: prune failed: {e}");
        }
    }
}
