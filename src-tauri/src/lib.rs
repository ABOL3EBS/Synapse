// src-tauri/src/lib.rs
//
// Tauri v2 backend — read-only access to ~/.synapse/synapse.db.
// Never writes, never touches the spool, never sends enforcement commands.
// Graceful degradation: all commands return empty/default data when DB is absent.

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// DB state — one read-only connection, shared via Tauri managed state
// ---------------------------------------------------------------------------

pub struct DbState(pub Mutex<Option<Connection>>);

fn db_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("SYNAPSE_DB_PATH") {
        return std::path::PathBuf::from(path);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".synapse").join("synapse.db")
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
    .map(|conn| {
        let _ = conn.execute_batch(
            "PRAGMA journal_mode = WAL;\
             PRAGMA query_only   = ON;",
        );
        conn
    })
    .ok()
}

fn now_ms() -> i64 {
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
    pub country_code: Option<String>,
    pub dns_name: Option<String>,
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
        return ProtectionStatus { is_protected: false, blocks_week: 0 };
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
                v.a_ip_text, v.b_ip_text, v.country_code, v.dns_name
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

            Ok(ActivityItem {
                id: r.get(0)?,
                ts_ms: r.get(1)?,
                app_name,
                verdict: r.get(3)?,
                detector_ids: vec![],   // filled below
                a_ip_text: r.get(4)?,
                b_ip_text: r.get(5)?,
                country_code: r.get(6)?,
                dns_name: r.get(7)?,
            })
        })
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();

    // Attach detector IDs for each verdict (separate query — avoids N+1 by
    // fetching all findings for the returned verdict IDs in one pass).
    if !items.is_empty() {
        let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT verdict_id, detector_id FROM detector_findings \
             WHERE verdict_id IN ({placeholders}) ORDER BY verdict_id, score DESC"
        );
        if let Ok(mut fstmt) = conn.prepare(&sql) {
            let params: Vec<&dyn rusqlite::types::ToSql> =
                ids.iter().map(|i| i as &dyn rusqlite::types::ToSql).collect();
            if let Ok(rows) = fstmt.query_map(params.as_slice(), |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            }) {
                // Build a map verdict_id → detector_ids
                let mut map: std::collections::HashMap<i64, Vec<String>> =
                    std::collections::HashMap::new();
                for row in rows.flatten() {
                    map.entry(row.0).or_default().push(row.1);
                }
                for item in &mut items {
                    if let Some(dids) = map.remove(&item.id) {
                        item.detector_ids = dids;
                    }
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
        return ThreatStats { blocks_today: 0, blocks_week: 0, blocked_addresses: 0 };
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
// App entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(DbState(Mutex::new(open_db())))
        .invoke_handler(tauri::generate_handler![
            get_protection_status,
            get_activity_feed,
            get_threat_stats,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Synapse dashboard");
}
