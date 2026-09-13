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

/// Local UTC offset in milliseconds, including DST. Computed once per process
/// lifetime (same as `detect_local_ip()` — the system timezone doesn't change
/// while a desktop app runs, and a 1-hour staleness across a DST boundary is
/// acceptable for a dashboard with 30-second refresh).
fn local_utc_offset_ms() -> i64 {
    use std::sync::OnceLock;
    static OFFSET: OnceLock<i64> = OnceLock::new();
    *OFFSET.get_or_init(|| {
        let now = std::time::SystemTime::now();
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let secs = now
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        unsafe { libc::localtime_r(&secs, &mut tm) };
        tm.tm_gmtoff as i64 * 1000
    })
}

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const HOUR_MS: i64 = 60 * 60 * 1000;

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
    /// Full process_path from the verdicts table; used by the frontend to
    /// resolve the real app icon via get_app_icon(). None for system/
    /// non-bundle processes.
    pub process_path: Option<String>,
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

/// Optional narrowing applied to the activity feed query. Both fields are
/// mutually usable but callers currently set at most one (detector-id filter
/// from Detection Breakdown, app-name filter from Flagged Apps).
struct ActivityFeedFilter {
    detector_id: Option<String>,
    app_name: Option<String>,
}

#[tauri::command]
fn get_activity_feed(limit: i64, state: tauri::State<DbState>) -> Vec<ActivityItem> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };
    query_activity_feed(conn, limit, None)
}

#[tauri::command]
fn get_activity_feed_filtered(
    limit: i64,
    detector_id: Option<String>,
    app_name: Option<String>,
    state: tauri::State<DbState>,
) -> Vec<ActivityItem> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };
    query_activity_feed(
        conn,
        limit,
        Some(&ActivityFeedFilter {
            detector_id,
            app_name,
        }),
    )
}

fn query_activity_feed(
    conn: &Connection,
    limit: i64,
    filter: Option<&ActivityFeedFilter>,
) -> Vec<ActivityItem> {
    // Fetch recent Alert/Block verdicts, newest first.
    // Allow verdicts are included (brief example: "Spotify connected... allowed.")
    // but the real feed only shows Block/Alert in normal operation.
    let mut sql = String::from(
        "SELECT v.id, v.ts_ms, v.process_path, v.verdict,
                v.a_ip_text, v.b_ip_text, v.local_ip_text, v.country_code, v.dns_name,
                v.composite_score, v.remote_ip_text
         FROM verdicts v",
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    if let Some(f) = filter {
        if let Some(detector_id) = &f.detector_id {
            sql.push_str(
                " WHERE v.id IN (SELECT verdict_id FROM detector_findings WHERE detector_id = ?)",
            );
            params.push(Box::new(detector_id.clone()));
        } else if let Some(app_name) = &f.app_name {
            sql.push_str(" WHERE v.process_path LIKE '%/' || ?");
            params.push(Box::new(app_name.clone()));
        }
    }
    sql.push_str(" ORDER BY v.ts_ms DESC LIMIT ?");
    params.push(Box::new(limit));

    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();

    let mut items: Vec<ActivityItem> = stmt
        .query_map(param_refs.as_slice(), |r| {
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
                process_path: process_path.clone(),
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
    let off = local_utc_offset_ms();
    let today_start = ((now + off) / DAY_MS) * DAY_MS - off;
    let week_ago = now - 7 * DAY_MS;

    let q = |sql: &str, since: i64| -> i64 {
        conn.query_row(sql, rusqlite::params![since], |r| r.get(0))
            .unwrap_or(0)
    };

    ThreatStats {
        blocks_today: q(
            "SELECT COUNT(*) FROM verdicts WHERE verdict='Block' AND ts_ms >= ?1",
            today_start,
        ),
        blocks_week: q(
            "SELECT COUNT(*) FROM verdicts WHERE verdict='Block' AND ts_ms >= ?1",
            week_ago,
        ),
        blocked_addresses: q(
            "SELECT COUNT(DISTINCT ip_text) FROM enforcement_log \
             WHERE error IS NULL AND ts_ms >= ?1",
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
    let since = now - 24 * HOUR_MS;
    let off = local_utc_offset_ms();

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

    // Map each of the 24 local hours ending now to its UTC epoch-hour bucket.
    // i=0 is the current local hour, i=23 is 23 local hours ago.
    (0..24)
        .map(|i| {
            let utc_bucket = ((now - i * HOUR_MS + off) / HOUR_MS) % 24;
            let local_hour = ((utc_bucket + off / HOUR_MS) % 24 + 24) % 24;
            ChartPoint {
                hour: local_hour,
                count: *map.get(&utc_bucket).unwrap_or(&0),
            }
        })
        .collect()
}

// day_offset uses the same local-day bucket as get_weekly_blocks
// (0 = today, 6 = six days ago) — hour is the local clock hour (0-23).
#[tauri::command]
fn get_activity_chart_for_day(state: tauri::State<DbState>, day_offset: i64) -> Vec<ChartPoint> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };

    let now = now_ms();
    let off = local_utc_offset_ms();
    let today_start = ((now + off) / DAY_MS) * DAY_MS - off;
    let day_start = today_start - day_offset * DAY_MS;
    let day_end = day_start + DAY_MS;

    let mut stmt = match conn.prepare(
        "SELECT CAST(ts_ms / 3600000 AS INTEGER) as bucket, COUNT(*) as cnt
         FROM verdicts WHERE ts_ms >= ?1 AND ts_ms < ?2
         GROUP BY bucket ORDER BY bucket",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let mut map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    if let Ok(rows) = stmt.query_map(rusqlite::params![day_start, day_end], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    }) {
        for row in rows.flatten() {
            map.insert(row.0, row.1);
        }
    }

    // Map each UTC epoch-hour bucket to local clock hour for display.
    (0..24)
        .map(|i| {
            let utc_bucket = (day_start / HOUR_MS) + i;
            let local_hour = ((utc_bucket + off / HOUR_MS) % 24 + 24) % 24;
            ChartPoint {
                hour: local_hour,
                count: *map.get(&utc_bucket).unwrap_or(&0),
            }
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
    /// Full process_path from the verdicts table; used by the frontend to
    /// resolve the real app icon via get_app_icon(). None for system/
    /// non-bundle processes.
    pub process_path: Option<String>,
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
            process_path: Some(path),
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
    let off = local_utc_offset_ms();
    let today_start = ((now + off) / DAY_MS) * DAY_MS - off;
    let since = today_start - 6 * DAY_MS;

    // Single query: all Block verdicts in the last 7 local days. Bucket by
    // local day in Rust so the boundary is local midnight, not UTC midnight.
    let mut stmt = match conn.prepare(
        "SELECT ts_ms FROM verdicts
         WHERE verdict = 'Block' AND ts_ms >= ?1",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };

    let mut counts = std::collections::HashMap::<i64, i64>::new();
    if let Ok(rows) = stmt.query_map(rusqlite::params![since], |r| r.get::<_, i64>(0)) {
        for ts in rows.flatten() {
            let day_offset = (today_start - ts) / DAY_MS;
            if (0..7).contains(&day_offset) {
                *counts.entry(day_offset).or_insert(0) += 1;
            }
        }
    }

    // day_offset 6 = oldest, 0 = today — callers render left-to-right
    (0..7_i64)
        .rev()
        .map(|offset| DayStat {
            day_offset: offset,
            count: counts.get(&offset).copied().unwrap_or(0),
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
// App icon resolution — NSWorkspace on macOS, cache keyed by resolved .app
// ---------------------------------------------------------------------------

/// base64-encoded PNG icon per resolved .app bundle. Caches both hits and
/// misses so repeated helper-process verdicts (Renderer/GPU/Plugin all
/// resolve to the same parent .app) trigger at most one NSWorkspace call.
pub struct IconCache(Mutex<std::collections::HashMap<String, Option<String>>>);

/// Walk `process_path` components upward and return the OUTERMOST ancestor
/// ending in `.app` — the actual application bundle. Helper bundles nested
/// under a framework (e.g. `Brave Browser Helper.app` inside
/// `Brave Browser.app/Contents/Frameworks/`) carry no icon resource of their
/// own, so NSWorkspace::icon(forFile:) returns a generic placeholder for them.
/// The outermost `.app` (e.g. `Brave Browser.app`) owns the real icon the
/// user recognizes.
fn find_parent_app_bundle(process_path: &str) -> Option<String> {
    use std::path::Path;
    let mut current: Option<&Path> = Path::new(process_path).parent();
    let mut outermost: Option<String> = None;
    let mut candidates: Vec<String> = Vec::new();
    while let Some(dir) = current {
        let is_app = dir
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"));
        if is_app {
            candidates.push(dir.to_string_lossy().into_owned());
            // Keep climbing — a later ancestor may be a broader app bundle.
            outermost = Some(dir.to_string_lossy().into_owned());
        }
        current = dir.parent();
    }
    if !candidates.is_empty() {
        eprintln!("[AppIcon] app candidates: {candidates:?}");
    }
    outermost
}

#[cfg(target_os = "macos")]
fn extract_icon_via_nsworkspace(app_path: &str) -> Option<String> {
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    use std::ffi::CString;

    // Rust &str is NOT null-terminated. stringWithUTF8String: requires a
    // null-terminated C string — passing a raw as_ptr() causes it to read
    // past the buffer into garbage, producing a garbage NSString and a nil
    // icon. CString guarantees the trailing \0.
    let c_path = CString::new(app_path).ok()?;

    unsafe {
        // NSWorkspace.sharedWorkspace.icon(forFile: app_path) → NSImage
        let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
        let path_ns: *mut Object = msg_send![
            class!(NSString),
            stringWithUTF8String: c_path.as_ptr()
        ];
        if path_ns.is_null() {
            eprintln!("[AppIcon] NSString: FAILED");
            return None;
        }
        let icon: *mut Object = msg_send![workspace, iconForFile: path_ns];
        if icon.is_null() {
            eprintln!("[AppIcon] NSWorkspace icon: FAILED for: {app_path}");
            return None;
        }
        eprintln!("[AppIcon] NSWorkspace icon: SUCCESS for: {app_path}");

        // NSImage → TIFF → NSBitmapImageRep → PNG data
        let tiff: *mut Object = msg_send![icon, TIFFRepresentation];
        if tiff.is_null() {
            eprintln!("[AppIcon] PNG conversion: FAILED (TIFFRepresentation nil)");
            return None;
        }
        let rep: *mut Object = msg_send![class!(NSBitmapImageRep), imageRepWithData: tiff];
        if rep.is_null() {
            eprintln!("[AppIcon] PNG conversion: FAILED (imageRepWithData nil)");
            return None;
        }
        let png_data: *mut Object = msg_send![
            rep,
            representationUsingType: 4 /* NSBitmapImageFileTypePNG */
            properties: std::ptr::null::<Object>()
        ];
        if png_data.is_null() {
            eprintln!("[AppIcon] PNG conversion: FAILED (representationUsingType nil)");
            return None;
        }
        eprintln!("[AppIcon] PNG conversion: SUCCESS");

        let bytes: *const u8 = msg_send![png_data, bytes];
        let len: usize = msg_send![png_data, length];
        eprintln!("[AppIcon] PNG bytes: {len}");
        if len == 0 || bytes.is_null() {
            eprintln!("[AppIcon] PNG bytes: empty/null");
            return None;
        }
        let slice = std::slice::from_raw_parts(bytes, len);
        Some(general_purpose::STANDARD.encode(slice))
    }
}

/// Resolve and return the real macOS app icon for the process that produced
/// a verdict. `process_path` is the full path from the `verdicts` table.
/// Returns base64-encoded PNG data, or `None` when the icon cannot be
/// resolved (system binaries, non-bundle paths, non-macOS targets).
#[tauri::command]
#[cfg(target_os = "macos")]
fn get_app_icon(process_path: String, state: tauri::State<IconCache>) -> Option<String> {
    eprintln!("[AppIcon] process: {process_path}");

    let Some(app_path) = find_parent_app_bundle(&process_path) else {
        eprintln!("[AppIcon] selected bundle: None (no .app ancestor)");
        return None;
    };
    eprintln!("[AppIcon] selected bundle: {app_path}");

    // Cache keyed by the resolved MAIN .app bundle, so every helper variant
    // of one app (Brave Renderer/GPU/Plugin) shares a single extraction.
    if let Some(cached) = state
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&app_path)
    {
        match cached {
            Some(s) => eprintln!("[AppIcon] cache hit: {app_path} → {}b", s.len()),
            None => eprintln!("[AppIcon] cache hit: {app_path} → None"),
        }
        return cached.clone();
    }

    let icon = extract_icon_via_nsworkspace(&app_path);
    match &icon {
        Some(s) => eprintln!("[AppIcon] result: {app_path} → {} base64 bytes", s.len()),
        None => eprintln!("[AppIcon] result: {app_path} → None"),
    };
    state
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(app_path, icon.clone());
    icon
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
fn get_app_icon(_process_path: String) -> Option<String> {
    None
}

// ---------------------------------------------------------------------------
// App entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(DbState(Mutex::new(open_db())))
        .manage(IconCache(Mutex::new(std::collections::HashMap::new())))
        .manage(settings::WriteDbState(
            Mutex::new(settings::open_write_db()),
        ))
        .invoke_handler(tauri::generate_handler![
            get_protection_status,
            get_activity_feed,
            get_activity_feed_filtered,
            get_threat_stats,
            get_activity_chart,
            get_activity_chart_for_day,
            get_detector_breakdown,
            get_top_apps,
            get_threat_countries,
            get_weekly_blocks,
            get_app_icon,
            settings::get_active_blocks,
            settings::request_unblock,
            settings::get_agent_status,
            settings::get_config_values,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Synapse dashboard");
}

#[cfg(test)]
mod tests {
    use super::find_parent_app_bundle;

    #[test]
    fn nested_helper_bundle_returns_outermost_app() {
        // Real DB path: an Electron helper nested inside the parent app,
        // the parent framework, and its own helper bundle. The helper bundle
        // carries no icon resource, so we walk to the OUTERMOST `.app` —
        // Brave Browser.app — which owns the real icon.
        let path = "/Applications/Brave Browser.app/Contents/Frameworks/\
                    Brave Browser Framework.framework/Versions/151.1.93.138/\
                    Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper";
        assert_eq!(
            find_parent_app_bundle(path),
            Some("/Applications/Brave Browser.app".to_string())
        );
    }

    #[test]
    fn top_level_binary_returns_its_bundle() {
        // WhatsApp spawns its executable directly inside the bundle.
        assert_eq!(
            find_parent_app_bundle("/Applications/WhatsApp.app/Contents/MacOS/WhatsApp"),
            Some("/Applications/WhatsApp.app".to_string())
        );
    }

    #[test]
    fn caseless_app_extension_matches() {
        // ".APP" (uppercase) must match too.
        assert_eq!(
            find_parent_app_bundle("/Applications/Foo.APP/MacOS/foo"),
            Some("/Applications/Foo.APP".to_string())
        );
    }

    #[test]
    fn no_app_ancestor_returns_none() {
        // System binaries (rapportd, replicatord) have no .app ancestor.
        assert_eq!(find_parent_app_bundle("/usr/libexec/rapportd"), None);
        assert_eq!(
            find_parent_app_bundle(
                "/System/Library/PrivateFrameworks/ReplicatorCore.framework/\
                 Support/replicatord"
            ),
            None
        );
    }

    #[test]
    fn bare_filename_returns_none() {
        assert_eq!(find_parent_app_bundle("Brave Browser Helper"), None);
    }
}
