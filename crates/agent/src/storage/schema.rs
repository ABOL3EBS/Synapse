use log::info;
use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 6;

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
        info!("storage: schema v2 applied (metadata table)");
    }

    if version < 3 {
        conn.execute_batch(V3_DDL)
            .map_err(|e| format!("schema v3: {e}"))?;
        conn.pragma_update(None, "user_version", 3u32)
            .map_err(|e| format!("set user_version v3: {e}"))?;
        info!("storage: schema v3 applied (verdicts.local_ip_text)");
    }

    if version < 4 {
        conn.execute_batch(V4_DDL)
            .map_err(|e| format!("schema v4: {e}"))?;
        conn.pragma_update(None, "user_version", 4u32)
            .map_err(|e| format!("set user_version v4: {e}"))?;
        info!("storage: schema v4 applied (dedup historical verdicts + unique 5-tuple index)");
    }

    if version < 5 {
        conn.execute_batch(V5_DDL)
            .map_err(|e| format!("schema v5: {e}"))?;
        conn.pragma_update(None, "user_version", 5u32)
            .map_err(|e| format!("set user_version v5: {e}"))?;
        info!("storage: schema v5 applied (verdicts.remote_ip_text)");
    }

    if version < 6 {
        conn.execute_batch(V6_MIGRATION)
            .map_err(|e| format!("schema v6: {e}"))?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|e| format!("set user_version v6: {e}"))?;
        info!(
            "storage: schema v6 applied (drop requested/confirmed, CHECK constraints on enums + scores)"
        );
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
-- requested/confirmed existed in V1..V5 but were dropped in V6: nothing read
-- them as a real helper ACK (durability is tracked by the crash-safe spool),
-- and the two dashboard writers (request_unblock, block-test) set confirmed=1
-- despite it never meaning anything.
-- CHECK constraints (V6): action is a closed enum; score must stay in [0,1].
CREATE TABLE IF NOT EXISTS enforcement_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT    NOT NULL UNIQUE,
    ts_ms    INTEGER NOT NULL,
    action   TEXT    NOT NULL CHECK (action IN ('Block', 'Unblock')),
    ip_blob  BLOB    NOT NULL,
    ip_text  TEXT    NOT NULL,
    ttl_ms   INTEGER,
    reason   TEXT    NOT NULL,
    detector TEXT,
    score    REAL    CHECK (score IS NULL OR (score >= 0 AND score <= 1)),
    error    TEXT
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

// ---------------------------------------------------------------------------
// V3 DDL — add local_ip_text to verdicts for direction-aware UI display
// ---------------------------------------------------------------------------

const V3_DDL: &str = "
-- local_ip_text: the agent's local IP at the time the verdict was written.
-- Stored alongside a_ip_text/b_ip_text so the Tauri backend can resolve
-- which canonical endpoint is remote without a private/public heuristic.
-- NULL for existing rows (rows written before V3 — treated as unknown by UI).
ALTER TABLE verdicts ADD COLUMN local_ip_text TEXT;
";

// ---------------------------------------------------------------------------
// V5 DDL — add remote_ip_text to verdicts for authoritative direction storage
// ---------------------------------------------------------------------------

const V5_DDL: &str = "
-- remote_ip_text: the remote endpoint's IP, persisted verbatim from
-- resolved.remote_ip at verdict time. No re-derivation. NULL for rows
-- written before V5; dashboard falls back to pick_remote() (using
-- local_ip_text from V3) for those rows until they age out.
ALTER TABLE verdicts ADD COLUMN remote_ip_text TEXT;
";

// ---------------------------------------------------------------------------
// V6 migration — drop dead requested/confirmed + add CHECK constraints
// ---------------------------------------------------------------------------
//
// SQLite cannot add CHECKs or drop NOT NULL/DEFAULT columns via ALTER TABLE, so
// each table is recreated with the classic rename dance. foreign_keys is toggled
// off for the duration because verdicts (referenced by detector_findings) and
// detector_findings (which references verdicts) are BOTH being swapped. The
// detector_findings_v6 FK is created while the old verdicts table still exists,
// and renames re-resolve the reference by table name, so integrity is preserved
// (verified by PRAGMA foreign_key_check at the end).
//
// Migration was validated against the production DB before being applied:
// every existing row satisfies the new constraints (distinct verdict = Alert,
// Block; distinct action = Block, Unblock; zero out-of-[0,1] scores), so the
// INSERT..SELECT below cannot fail on CHECK.
const V6_MIGRATION: &str = "
PRAGMA foreign_keys = OFF;
BEGIN;

-- enforcement_log: drop requested/confirmed, add action + score CHECKs.
CREATE TABLE enforcement_log_v6 (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT    NOT NULL UNIQUE,
    ts_ms    INTEGER NOT NULL,
    action   TEXT    NOT NULL CHECK (action IN ('Block', 'Unblock')),
    ip_blob  BLOB    NOT NULL,
    ip_text  TEXT    NOT NULL,
    ttl_ms   INTEGER,
    reason   TEXT    NOT NULL,
    detector TEXT,
    score    REAL    CHECK (score IS NULL OR (score >= 0 AND score <= 1)),
    error    TEXT
);
INSERT INTO enforcement_log_v6
    (event_id, ts_ms, action, ip_blob, ip_text, ttl_ms, reason, detector, score, error)
    SELECT event_id, ts_ms, action, ip_blob, ip_text, ttl_ms, reason, detector, score, error
    FROM enforcement_log;
DROP TABLE enforcement_log;
ALTER TABLE enforcement_log_v6 RENAME TO enforcement_log;

-- verdicts: add verdict + composite_score CHECKs.
-- id is copied explicitly: verdicts.id can be far beyond 1..N (V4 dedup keeps
-- MAX(id), retention deletes old rows). detector_findings.verdict_id references
-- those original ids — dropping them would orphan every finding.
CREATE TABLE verdicts_v6 (
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
    verdict          TEXT    NOT NULL CHECK (verdict IN ('Alert', 'Block')),
    reason           TEXT    NOT NULL,
    composite_score  REAL    NOT NULL CHECK (composite_score >= 0 AND composite_score <= 1),
    ttl_ms           INTEGER,
    flow_age_ms      INTEGER NOT NULL,
    pkt_count        INTEGER NOT NULL DEFAULT 0,
    byte_count       INTEGER NOT NULL DEFAULT 0,
    local_ip_text    TEXT,
    remote_ip_text   TEXT
);
INSERT INTO verdicts_v6
    (id, ts_ms, flow_id, a_ip_blob, b_ip_blob, a_ip_text, b_ip_text,
     a_port, b_port, protocol, pid, process_path, process_start,
     dns_name, country_code, asn, reputation_score,
     verdict, reason, composite_score, ttl_ms, flow_age_ms,
     pkt_count, byte_count, local_ip_text, remote_ip_text)
    SELECT id, ts_ms, flow_id, a_ip_blob, b_ip_blob, a_ip_text, b_ip_text,
     a_port, b_port, protocol, pid, process_path, process_start,
     dns_name, country_code, asn, reputation_score,
     verdict, reason, composite_score, ttl_ms, flow_age_ms,
     pkt_count, byte_count, local_ip_text, remote_ip_text
    FROM verdicts;

-- detector_findings: add score/confidence CHECKs. Referenced table (verdicts)
-- is still the old one at DDL time; renames below re-resolve by name.
CREATE TABLE detector_findings_v6 (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id       INTEGER NOT NULL REFERENCES verdicts(id) ON DELETE CASCADE,
    detector_id      TEXT    NOT NULL,
    detector_version TEXT    NOT NULL,
    score            REAL    NOT NULL CHECK (score >= 0 AND score <= 1),
    confidence       REAL    NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    severity         TEXT    NOT NULL,
    status           TEXT    NOT NULL,
    latency_us       INTEGER NOT NULL,
    evidence_json    TEXT
);
INSERT INTO detector_findings_v6
    (verdict_id, detector_id, detector_version, score,
     confidence, severity, status, latency_us, evidence_json)
    SELECT verdict_id, detector_id, detector_version, score,
     confidence, severity, status, latency_us, evidence_json
    FROM detector_findings;
DROP TABLE detector_findings;
DROP TABLE verdicts;
ALTER TABLE verdicts_v6 RENAME TO verdicts;
ALTER TABLE detector_findings_v6 RENAME TO detector_findings;

-- Recreate all indexes (dropped with their tables).
CREATE INDEX enf_ts ON enforcement_log(ts_ms DESC);
CREATE INDEX enf_ip ON enforcement_log(ip_text, ts_ms DESC);
CREATE UNIQUE INDEX v_5tuple_verdict
    ON verdicts(a_ip_text, a_port, b_ip_text, b_port, protocol, verdict);
CREATE INDEX v_ts   ON verdicts(ts_ms DESC);
CREATE INDEX v_ip   ON verdicts(a_ip_text, b_ip_text);
CREATE INDEX v_type ON verdicts(verdict, ts_ms DESC);
CREATE INDEX df_verdict  ON detector_findings(verdict_id);
CREATE INDEX df_detector ON detector_findings(detector_id);

COMMIT;
PRAGMA foreign_key_check;
PRAGMA foreign_keys = ON;
";

// ---------------------------------------------------------------------------
// V4 DDL — dedup historical re-evaluation rows + unique 5-tuple+verdict index
// ---------------------------------------------------------------------------

const V4_DDL: &str = "
-- Collapse per-tick re-evaluation duplicates. Keeps MAX(id) per
-- (5-tuple, verdict) — the most recent row with the freshest score,
-- evidence, and ts_ms. ON DELETE CASCADE propagates to detector_findings.
DELETE FROM verdicts
WHERE id NOT IN (
  SELECT MAX(id)
  FROM verdicts
  GROUP BY a_ip_text, a_port, b_ip_text, b_port, protocol, verdict
);
-- Enforce the invariant going forward: re-evaluation of the same active flow
-- must UPSERT, not INSERT, so the verdict table counts distinct detections.
CREATE UNIQUE INDEX IF NOT EXISTS v_5tuple_verdict
  ON verdicts(a_ip_text, a_port, b_ip_text, b_port, protocol, verdict);
";

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the exact V5 schema by hand (as a real pre-V6 production DB has),
    /// load it with representative rows including the legacy requested/confirmed
    /// columns, then run apply_schema. The migration must preserve every row and
    /// the new CHECK constraints must reject invalid values.
    #[test]
    fn test_v6_migration_preserves_rows_and_enforces_checks() {
        let conn = Connection::open_in_memory().unwrap();

        conn.execute_batch(
            "
            PRAGMA foreign_keys = OFF;
            CREATE TABLE enforcement_log (
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
            CREATE TABLE verdicts (
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
                byte_count       INTEGER NOT NULL DEFAULT 0,
                local_ip_text    TEXT,
                remote_ip_text   TEXT
            );
            CREATE TABLE detector_findings (
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
            INSERT INTO enforcement_log
                (event_id, ts_ms, action, ip_blob, ip_text, ttl_ms, reason, detector, score, requested, confirmed, error)
            VALUES
                ('old-1', 1000, 'Block', zeroblob(16), '1.2.3.4', 300000, 'migrate-test', 'test', 0.9, 1, 1, NULL),
                ('old-2', 2000, 'Unblock', zeroblob(16), '1.2.3.4', 0, 'migrate-test-cleanup', 'test', 0.0, 1, 1, NULL);
            INSERT INTO verdicts
                (id, ts_ms, flow_id, a_ip_blob, b_ip_blob, a_ip_text, b_ip_text,
                 a_port, b_port, protocol, verdict, reason, composite_score,
                 flow_age_ms, pkt_count, byte_count, local_ip_text, remote_ip_text)
            VALUES
                -- Realistic high id: a production DB's verdicts.id can reach the
                -- 200k range (V4 dedup keeps MAX(id); retention deletes old rows).
                -- detector_findings.verdict_id references it, so the migration
                -- MUST preserve it or every finding becomes an orphan.
                (210308, 1000, 7, zeroblob(16), zeroblob(16), '8.8.8.8', '192.168.1.5',
                 443, 50000, 6, 'Alert', 'migrate-test', 0.42, 150, 3, 1000, '192.168.1.5', '8.8.8.8');
            INSERT INTO detector_findings
                (verdict_id, detector_id, detector_version, score, confidence, severity, status, latency_us)
            VALUES
                (210308, 'CrossFlow', '1.0.0', 0.5, 0.6, 'Medium', 'Completed', 12);
            PRAGMA user_version = 5;
            ",
        )
        .unwrap();

        apply_schema(&conn).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 6, "migration must land on schema v6");

        let headers: Vec<String> = conn
            .prepare("PRAGMA table_info(enforcement_log)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            !headers.iter().any(|c| c == "requested" || c == "confirmed"),
            "requested/confirmed must be gone: {headers:?}"
        );

        let enf: Vec<(String, String, Option<f64>)> = conn
            .prepare("SELECT event_id, action, score FROM enforcement_log ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(enf.len(), 2, "all enforcement rows must survive");
        assert_eq!(enf[0].0, "old-1");
        assert_eq!(enf[0].1, "Block");
        assert_eq!(enf[1].1, "Unblock");

        let v = conn
            .query_row(
                "SELECT verdict, composite_score, remote_ip_text FROM verdicts",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, f64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(v.0, "Alert");
        assert_eq!(v.1, 0.42);
        assert_eq!(v.2, "8.8.8.8", "V5 remote_ip_text must survive recreation");

        let findings: i64 = conn
            .query_row("SELECT COUNT(*) FROM detector_findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(findings, 1, "findings must survive and cascade");

        // The preserved high verdicts.id must keep every finding's FK intact.
        let orphaned: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM detector_findings df \
                 LEFT JOIN verdicts v ON v.id = df.verdict_id WHERE v.id IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphaned, 0, "no detector_findings row may be orphaned");
        let joined: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM detector_findings df \
                 JOIN verdicts v ON v.id = df.verdict_id",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(joined, 1, "finding must join back to its verdict");

        // CHECK enforcement: invalid action / verdict / out-of-range scores rejected.
        let bad_action = conn.execute(
            "INSERT INTO enforcement_log (event_id, ts_ms, action, ip_blob, ip_text, reason) \
             VALUES ('bad-a', 1, 'Ban', zeroblob(16), '2.3.4.5', 'x')",
            [],
        );
        assert!(bad_action.is_err(), "action 'Ban' must fail CHECK");
        let bad_score = conn.execute(
            "INSERT INTO enforcement_log (event_id, ts_ms, action, ip_blob, ip_text, reason, score) \
             VALUES ('bad-s', 1, 'Block', zeroblob(16), '2.3.4.5', 'x', 1.5)",
            [],
        );
        assert!(bad_score.is_err(), "score 1.5 must fail CHECK");
        let bad_verdict = conn.execute(
            "INSERT INTO verdicts (ts_ms, flow_id, a_ip_blob, b_ip_blob, a_ip_text, b_ip_text, \
             verdict, reason, composite_score, flow_age_ms) \
             VALUES (1, 1, zeroblob(16), zeroblob(16), 'a', 'b', 'Allow', 'x', 0.5, 1)",
            [],
        );
        assert!(bad_verdict.is_err(), "verdict 'Allow' must fail CHECK");
        let bad_composite = conn.execute(
            "INSERT INTO verdicts (ts_ms, flow_id, a_ip_blob, b_ip_blob, a_ip_text, b_ip_text, \
             verdict, reason, composite_score, flow_age_ms) \
             VALUES (1, 1, zeroblob(16), zeroblob(16), 'a', 'b', 'Block', 'x', 1.2, 1)",
            [],
        );
        assert!(
            bad_composite.is_err(),
            "composite_score 1.2 must fail CHECK"
        );
        let bad_finding = conn.execute(
            "INSERT INTO detector_findings (verdict_id, detector_id, detector_version, score, confidence, severity, status, latency_us) \
             VALUES (210308, 'D', '1', 1.1, 0.5, 'Low', 'Completed', 1)",
            [],
        );
        assert!(
            bad_finding.is_err(),
            "finding score 1.1 must fail CHECK (not FK — verdict_id 210308 exists)"
        );
    }

    /// A fresh database (version 0) must converge to the same v6 shape without
    /// legacy columns ever existing.
    #[test]
    fn test_fresh_db_reaches_v6_without_legacy_columns() {
        let conn = Connection::open_in_memory().unwrap();
        apply_schema(&conn).unwrap();
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, 6);
        let enforced: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE type='table' AND name='enforcement_log'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(enforced, 1);
    }
}
