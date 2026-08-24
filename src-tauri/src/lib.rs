// src-tauri/src/lib.rs
//
// Tauri v2 backend — read-only dashboard queries + settings commands.
// Graceful degradation: all commands return empty/default data when DB is absent.

mod settings;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// DB state — one read-only connection, shared via Tauri managed state
// ---------------------------------------------------------------------------

pub struct DbState(pub Mutex<Option<Connection>>);

pub(crate) fn db_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("SYNAPSE_DB_PATH") {
        return std::path::PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home)
        .join(".synapse")
        .join("synapse.db")
}

fn open_db() -> Option<Connection> {
    let path = db_path();
    if !path.exists() {
        return None;
    }
    Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .inspect(|conn| {
        let _ = conn.execute_batch(
            "PRAGMA journal_mode = WAL;\
             PRAGMA query_only   = ON;\
             PRAGMA busy_timeout = 5000;",
        );
    })
    .ok()
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Response types (mirrored in src/lib/db.ts)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtectionStatus {
    pub is_protected: bool,
    pub blocks_week: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivityItem {
    pub id: i64,
    pub ts_ms: i64,
    pub app_name: String,
    pub verdict: String,
    pub detector_ids: Vec<String>,
    pub a_ip_text: String,
    pub b_ip_text: String,
    pub remote_ip_text: String, // direction-resolved: the non-local endpoint
    pub country_code: Option<String>,
    pub dns_name: Option<String>,
    /// evidence_json from the highest-scoring detector finding; None if no findings.
    /// Used by the UI to produce sub-type-specific copy for detectors like CrossFlow.
    pub top_evidence: Option<String>,
    /// Composite threat score (0.0–1.0) produced by the decision engine.
    pub composite_score: Option<f64>,
}

// Resolve the remote endpoint using the stored local_ip_text.
// Mirrors determine_remote_ip() in capture.rs: if a == local → b is remote,
// if b == local → a is remote, otherwise fall back to b (canonical larger).
// local_ip is None for rows written before schema V3 — falls back to b.
fn pick_remote(a: &str, b: &str, local: Option<&str>) -> String {
    if let Some(local_ip) = local {
        if a == local_ip {
            return b.to_string();
        }
        if b == local_ip {
            return a.to_string();
        }
    }
    b.to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatStats {
    pub blocks_today: i64,
    pub blocks_week: i64,
    pub blocked_addresses: i64,
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_protection_status(state: tauri::State<DbState>) -> ProtectionStatus {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return ProtectionStatus {
            is_protected: false,
            blocks_week: 0,
        };
    };

    let now = now_ms();
    let week_ago = now - 7 * 24 * 60 * 60 * 1000;

    let blocks_week: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM verdicts WHERE verdict='Block' AND ts_ms >= ?1",
            rusqlite::params![week_ago],
            |r| r.get(0),
        )
        .unwrap_or(0);

    // "Protected" if the DB exists and is readable. The agent may be quiet on a
    // benign network — absence of recent verdicts does not mean protection is off.
    ProtectionStatus {
        is_protected: true,
        blocks_week,
    }
}

#[tauri::command]
fn get_activity_feed(limit: i64, state: tauri::State<DbState>) -> Vec<ActivityItem> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    // Fetch recent Alert/Block verdicts, newest first.
    // Allow verdicts are included (brief example: "Spotify connected... allowed.")
    // but the real feed only shows Block/Alert in normal operation.
    let mut stmt = match conn.prepare(
        "SELECT v.id, v.ts_ms, v.process_path, v.verdict,
                v.a_ip_text, v.b_ip_text, v.local_ip_text, v.country_code, v.dns_name,
                v.composite_score, v.remote_ip_text
         FROM verdicts v
         ORDER BY v.ts_ms DESC
         LIMIT ?1",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let mut items: Vec<ActivityItem> = stmt
        .query_map(rusqlite::params![limit], |r| {
            let process_path: Option<String> = r.get(2)?;
            let app_name = process_path
                .as_deref()
                .and_then(|p| std::path::Path::new(p).file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown app")
                .to_string();

            let a_ip_text: String = r.get(4)?;
            let b_ip_text: String = r.get(5)?;
            let local_ip_text: Option<String> = r.get(6)?;
            // Column 10: remote_ip_text (V5+). Non-NULL means direction was resolved
            // at write time — use it verbatim. NULL for pre-V5 rows: fall back to
            // pick_remote() which uses local_ip_text (V3+) to derive direction.
            let stored_remote: Option<String> = r.get(10)?;
            let remote_ip_text = stored_remote
                .unwrap_or_else(|| pick_remote(&a_ip_text, &b_ip_text, local_ip_text.as_deref()));
            Ok(ActivityItem {
                id: r.get(0)?,
                ts_ms: r.get(1)?,
                app_name,
                verdict: r.get(3)?,
                detector_ids: vec![], // filled below
                a_ip_text,
                b_ip_text,
                remote_ip_text,
                country_code: r.get(7)?,
                dns_name: r.get(8)?,
                top_evidence: None, // filled below
                composite_score: r.get(9)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();

    // Attach detector IDs + top evidence for each verdict (one bulk query, no N+1).
    // Rows arrive ORDER BY verdict_id, score DESC — first row per verdict is the
    // highest-scoring finding, so we capture its evidence_json as top_evidence.
    if !items.is_empty() {
        let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT verdict_id, detector_id, evidence_json FROM detector_findings \
             WHERE verdict_id IN ({placeholders}) ORDER BY verdict_id, score DESC"
        );
        if let Ok(mut fstmt) = conn.prepare(&sql) {
            let params: Vec<&dyn rusqlite::types::ToSql> = ids
                .iter()
                .map(|i| i as &dyn rusqlite::types::ToSql)
                .collect();
            if let Ok(rows) = fstmt.query_map(params.as_slice(), |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            }) {
                let mut det_map: std::collections::HashMap<i64, Vec<String>> =
                    std::collections::HashMap::new();
                let mut ev_map: std::collections::HashMap<i64, String> =
                    std::collections::HashMap::new();
                for (vid, det, ev) in rows.flatten() {
                    det_map.entry(vid).or_default().push(det);
                    // Only the first row per verdict_id (highest score) → top_evidence
                    if let std::collections::hash_map::Entry::Vacant(e) = ev_map.entry(vid) {
                        if let Some(json) = ev {
                            e.insert(json);
                        }
                    }
                }
                for item in &mut items {
                    if let Some(dids) = det_map.remove(&item.id) {
                        item.detector_ids = dids;
                    }
                    item.top_evidence = ev_map.remove(&item.id);
                }
            }
        }
    }

    items
}

#[tauri::command]
fn get_threat_stats(state: tauri::State<DbState>) -> ThreatStats {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return ThreatStats {
            blocks_today: 0,
            blocks_week: 0,
            blocked_addresses: 0,
        };
    };

    let now = now_ms();
    let today_ago = now - 24 * 60 * 60 * 1000;
    let week_ago = now - 7 * 24 * 60 * 60 * 1000;

    let q = |sql: &str, since: i64| -> i64 {
        conn.query_row(sql, rusqlite::params![since], |r| r.get(0))
            .unwrap_or(0)
    };

    ThreatStats {
        blocks_today: q(
            "SELECT COUNT(*) FROM verdicts WHERE verdict='Block' AND ts_ms >= ?1",
            today_ago,
        ),
        blocks_week: q(
            "SELECT COUNT(*) FROM verdicts WHERE verdict='Block' AND ts_ms >= ?1",
            week_ago,
        ),
        blocked_addresses: q(
            "SELECT COUNT(DISTINCT ip_text) FROM enforcement_log \
             WHERE requested=1 AND error IS NULL AND ts_ms >= ?1",
            week_ago,
        ),
    }
}

// ---------------------------------------------------------------------------
// Chart commands
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ChartPoint {
    pub hour: i64,
    pub count: i64,
}

#[tauri::command]
fn get_activity_chart(state: tauri::State<DbState>) -> Vec<ChartPoint> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    let now = now_ms();
    let since = now - 24 * 60 * 60 * 1000;
    let since_bucket = since / 3_600_000;

    let mut stmt = match conn.prepare(
        "SELECT CAST(ts_ms / 3600000 AS INTEGER) as bucket, COUNT(*) as cnt
         FROM verdicts WHERE ts_ms >= ?1
         GROUP BY bucket ORDER BY bucket",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let mut map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    if let Ok(rows) = stmt.query_map(rusqlite::params![since], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    }) {
        for row in rows.flatten() {
            map.insert(row.0, row.1);
        }
    }

    (0..24)
        .map(|i| ChartPoint {
            hour: i,
            count: *map.get(&(since_bucket + i)).unwrap_or(&0),
        })
        .collect()
}

// day_offset uses the same UTC-epoch-day bucket as get_weekly_blocks
// (0 = today, 6 = six days ago) — hour is the bucket's index within that
// day (0-23), not an offset from "now" like get_activity_chart's hour field.
#[tauri::command]
fn get_activity_chart_for_day(state: tauri::State<DbState>, day_offset: i64) -> Vec<ChartPoint> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    let day_ms: i64 = 24 * 60 * 60 * 1000;
    let today_bucket = now_ms() / day_ms;
    let day_bucket = today_bucket - day_offset;
    let day_start = day_bucket * day_ms;
    let day_end = day_start + day_ms;

    let mut stmt = match conn.prepare(
        "SELECT CAST(ts_ms / 3600000 AS INTEGER) as bucket, COUNT(*) as cnt
         FROM verdicts WHERE ts_ms >= ?1 AND ts_ms < ?2
         GROUP BY bucket ORDER BY bucket",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let hour_bucket_start = day_start / 3_600_000;
    let mut map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    if let Ok(rows) = stmt.query_map(rusqlite::params![day_start, day_end], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    }) {
        for row in rows.flatten() {
            map.insert(row.0, row.1);
        }
    }

    (0..24)
        .map(|i| ChartPoint {
            hour: i,
            count: *map.get(&(hour_bucket_start + i)).unwrap_or(&0),
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetectorStat {
    pub name: String,
    pub count: i64,     // findings with score > 0
    pub has_runs: bool, // true if detector ran at all (even with 0 findings)
}

#[tauri::command]
fn get_detector_breakdown(state: tauri::State<DbState>) -> Vec<DetectorStat> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    // Return all detectors that ran, with finding count (score > 0) per detector.
    // Detectors that ran but had zero signal appear with count=0, has_runs=true —
    // distinct from "never ran" (absent from table entirely).
    let mut stmt = match conn.prepare(
        "SELECT detector_id,
                COUNT(CASE WHEN score > 0 THEN 1 END) as findings,
                COUNT(*) as runs
         FROM detector_findings
         WHERE detector_id IS NOT NULL
         GROUP BY detector_id
         ORDER BY findings DESC",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    stmt.query_map([], |r| {
        Ok(DetectorStat {
            name: r.get(0)?,
            count: r.get(1)?,
            has_runs: r.get::<_, i64>(2)? > 0,
        })
    })
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopApp {
    pub app_name: String,
    pub blocks: i64,
    pub alerts: i64,
}

#[tauri::command]
fn get_top_apps(state: tauri::State<DbState>) -> Vec<TopApp> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    let week_ago = now_ms() - 7 * 24 * 60 * 60 * 1000;

    let mut stmt = match conn.prepare(
        "SELECT process_path,
                SUM(CASE WHEN verdict='Block' THEN 1 ELSE 0 END) as blocks,
                SUM(CASE WHEN verdict='Alert'  THEN 1 ELSE 0 END) as alerts
         FROM verdicts
         WHERE process_path IS NOT NULL AND process_path != ''
           AND ts_ms >= ?1
         GROUP BY process_path
         ORDER BY (blocks * 2 + alerts) DESC LIMIT 5",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    stmt.query_map(rusqlite::params![week_ago], |r| {
        let path: String = r.get(0)?;
        let app_name = std::path::Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();
        Ok(TopApp {
            app_name,
            blocks: r.get(1)?,
            alerts: r.get(2)?,
        })
    })
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Weekly blocks — 7-day bar strip

#[derive(Debug, Serialize, Deserialize)]
pub struct DayStat {
    /// 0 = today, 6 = six days ago (left-to-right order callers must reverse).
    pub day_offset: i64,
    pub count: i64,
}

#[tauri::command]
fn get_weekly_blocks(state: tauri::State<DbState>) -> Vec<DayStat> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    let now = now_ms();
    let day_ms: i64 = 24 * 60 * 60 * 1000;
    let today_bucket = now / day_ms;
    let since = now - 7 * day_ms;

    let mut stmt = match conn.prepare(
        "SELECT CAST(ts_ms / 86400000 AS INTEGER) as bucket, COUNT(*) as cnt
         FROM verdicts
         WHERE verdict = 'Block' AND ts_ms >= ?1
         GROUP BY bucket",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let mut map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    if let Ok(rows) = stmt.query_map(rusqlite::params![since], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    }) {
        for (bucket, cnt) in rows.flatten() {
            map.insert(bucket, cnt);
        }
    }

    // day_offset 6 = oldest, 0 = today — callers render left-to-right
    (0..7_i64)
        .rev()
        .map(|offset| DayStat {
            day_offset: offset,
            count: *map.get(&(today_bucket - offset)).unwrap_or(&0),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Threat countries (globe)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CountryStat {
    pub country_code: String,
    pub count: i64,
}

#[tauri::command]
fn get_threat_countries(state: tauri::State<DbState>) -> Vec<CountryStat> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    let mut stmt = match conn.prepare(
        "SELECT country_code, COUNT(*) as cnt
         FROM verdicts
         WHERE country_code IS NOT NULL
           AND verdict IN ('Block', 'Alert')
         GROUP BY country_code
         ORDER BY cnt DESC",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    stmt.query_map([], |r| {
        Ok(CountryStat {
            country_code: r.get(0)?,
            count: r.get(1)?,
        })
    })
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// App entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(DbState(Mutex::new(open_db())))
        .manage(settings::WriteDbState(
            Mutex::new(settings::open_write_db()),
        ))
        .invoke_handler(tauri::generate_handler![
            get_protection_status,
            get_activity_feed,
            get_threat_stats,
            get_activity_chart,
            get_activity_chart_for_day,
            get_detector_breakdown,
            get_top_apps,
            get_threat_countries,
            get_weekly_blocks,
            settings::get_active_blocks,
            settings::request_unblock,
            settings::get_agent_status,
            settings::get_config_values,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Synapse dashboard");
}
