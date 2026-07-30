use log::info;
use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 2;

/// Apply the schema to an open connection. Idempotent — safe to call on
/// every startup. Uses PRAGMA user_version for lightweight migration tracking.
pub fn apply_schema(conn: &Connection) -> Result<(), String> {
    harden(conn)?;

    let version: u32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|e| format!("read user_version: {e}"))?;

    if version == 0 {
        // Pre-v1 databases have an enforcement_log with a different column set
        // (timestamp/ip/success/message instead of event_id/ip_blob/ip_text/…).
        // Drop it so V1_DDL can recreate it with the correct schema.
        let old_schema: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('enforcement_log') \
                 WHERE name = 'event_id'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0)
            == 0;
        if old_schema {
            conn.execute_batch("DROP TABLE IF EXISTS enforcement_log;")
                .map_err(|e| format!("drop legacy enforcement_log: {e}"))?;
            info!("storage: dropped legacy enforcement_log (pre-v1 schema)");
        }

        conn.execute_batch(V1_DDL)
            .map_err(|e| format!("schema v1: {e}"))?;
        info!("storage: schema v1 applied");
    }

    if version < 2 {
        conn.execute_batch(V2_DDL)
            .map_err(|e| format!("schema v2: {e}"))?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|e| format!("set user_version: {e}"))?;
        info!("storage: schema v2 applied (metadata table)");
    }

    Ok(())
}

/// Security and performance PRAGMAs applied on every connection open.
pub fn harden(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "PRAGMA journal_mode    = WAL;
         PRAGMA foreign_keys    = ON;
         PRAGMA trusted_schema  = OFF;
         PRAGMA secure_delete   = ON;",
    )
    .map_err(|e| format!("harden: {e}"))
}

// ---------------------------------------------------------------------------
// V1 DDL
// ---------------------------------------------------------------------------

const V1_DDL: &str = "
-- Critical: enforcement lifecycle.
-- event_id is a stable identifier assigned by the storage worker so that
-- spool replay can use INSERT OR IGNORE for idempotent recovery.
-- ip_blob = 16-byte IPv4-mapped IPv6 (canonical binary form).
-- ip_text = human-readable (denormalised for quick queries and UI display).
-- requested = IPC send was attempted.
-- confirmed = helper acknowledged (currently always 0 — no ACK in protocol yet).
CREATE TABLE IF NOT EXISTS enforcement_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id  TEXT    NOT NULL UNIQUE,
    ts_ms     INTEGER NOT NULL,
    action    TEXT    NOT NULL,
    ip_blob   BLOB    NOT NULL,
    ip_text   TEXT    NOT NULL,
    ttl_ms    INTEGER,
    reason    TEXT    NOT NULL,
    detector  TEXT,
    score     REAL,
    requested INTEGER NOT NULL DEFAULT 1,
    confirmed INTEGER NOT NULL DEFAULT 0,
    error     TEXT
);
CREATE INDEX IF NOT EXISTS enf_ts ON enforcement_log(ts_ms DESC);
CREATE INDEX IF NOT EXISTS enf_ip ON enforcement_log(ip_text, ts_ms DESC);

-- Important: Alert/Block decisions (one row per verdict, Alert or Block only).
-- Both IPs stored as BLOB (canonical) + TEXT (queryable).
-- process_start is float seconds (libproc-provided) used alongside pid to
-- detect PID reuse — a new process with the same pid but different start time
-- is a different process.
CREATE TABLE IF NOT EXISTS verdicts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms            INTEGER NOT NULL,
    flow_id          INTEGER NOT NULL,
    a_ip_blob        BLOB    NOT NULL,
    b_ip_blob        BLOB    NOT NULL,
    a_ip_text        TEXT    NOT NULL,
    b_ip_text        TEXT    NOT NULL,
    a_port           INTEGER NOT NULL,
    b_port           INTEGER NOT NULL,
    protocol         INTEGER NOT NULL,
    pid              INTEGER,
    process_path     TEXT,
    process_start    REAL,
    dns_name         TEXT,
    country_code     TEXT,
    asn              INTEGER,
    reputation_score REAL,
    verdict          TEXT    NOT NULL,
    reason           TEXT    NOT NULL,
    composite_score  REAL    NOT NULL,
    ttl_ms           INTEGER,
    flow_age_ms      INTEGER NOT NULL,
    pkt_count        INTEGER NOT NULL DEFAULT 0,
    byte_count       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS v_ts   ON verdicts(ts_ms DESC);
CREATE INDEX IF NOT EXISTS v_ip   ON verdicts(a_ip_text, b_ip_text);
CREATE INDEX IF NOT EXISTS v_type ON verdicts(verdict, ts_ms DESC);

-- Important: one row per detector per verdict.
-- Cascade-deletes when the parent verdict is pruned by retention.
-- evidence_json: JSON array of {description, detail?} objects.
CREATE TABLE IF NOT EXISTS detector_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id       INTEGER NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
    detector_id      TEXT    NOT NULL,
    detector_version TEXT    NOT NULL,
    score            REAL    NOT NULL,
    confidence       REAL    NOT NULL,
    severity         TEXT    NOT NULL,
    status           TEXT    NOT NULL,
    latency_us       INTEGER NOT NULL,
    evidence_json    TEXT
);
CREATE INDEX IF NOT EXISTS df_verdict  ON detector_findings(verdict_id);
CREATE INDEX IF NOT EXISTS df_detector ON detector_findings(detector_id);

-- Important: circuit breaker state transitions.
-- Used by the health dashboard to show which detectors are degraded.
CREATE TABLE IF NOT EXISTS circuit_breaker_events (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms                INTEGER NOT NULL,
    detector_id          TEXT    NOT NULL,
    from_state           TEXT    NOT NULL,
    to_state             TEXT    NOT NULL,
    consecutive_failures INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cb_ts       ON circuit_breaker_events(ts_ms DESC);
CREATE INDEX IF NOT EXISTS cb_detector ON circuit_breaker_events(detector_id, ts_ms DESC);
";

// ---------------------------------------------------------------------------
// V2 DDL — metadata table for durable worker state
// ---------------------------------------------------------------------------

const V2_DDL: &str = "
-- Durable worker state: survives agent restarts.
-- Initial row inserted once; updated in-place by the storage worker.
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO metadata (key, value)
    VALUES ('last_retention_run_ms', '0');
";
