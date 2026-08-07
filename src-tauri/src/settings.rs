// src-tauri/src/settings.rs
//
// Tauri commands for the Settings screen: active blocks, unblock requests,
// agent/helper liveness, and config display. Separated from lib.rs to keep
// the main backend file under 600 lines.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::{db_path, now_ms};

// ---------------------------------------------------------------------------
// Write-capable DB state (separate from the read-only DbState in lib.rs)
// request_unblock() is the only writer — it inserts Unblock records.
// ---------------------------------------------------------------------------

pub struct WriteDbState(pub Mutex<Option<Connection>>);

pub fn open_write_db() -> Option<Connection> {
    let path = db_path();
    if !path.exists() {
        return None;
    }
    Connection::open(&path)
        .inspect(|conn| {
            // WAL: allow concurrent agent reads/writes without SQLITE_BUSY.
            // busy_timeout: retry writes for up to 5s if the agent holds the
            // write lock momentarily — default is 0 (fail immediately).
            let _ = conn.execute_batch(
                "PRAGMA journal_mode = WAL;\
                 PRAGMA busy_timeout  = 5000;",
            );
        })
        .ok()
}

// ---------------------------------------------------------------------------
// Response types (mirrored in src/lib/db.ts)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveBlock {
    pub ip_text: String,
    pub remaining_ms: i64,
    pub reason: String,
}

/// Three-state result for an unblock request:
///   queued=true,  fast_path=true  → DB written + trigger file touched (~1 s)
///   queued=true,  fast_path=false → DB written, trigger failed (up to 60 s, surfaced in UI)
///   queued=false, fast_path=false → DB write failed (real error)
#[derive(Debug, Serialize, Deserialize)]
pub struct UnblockResult {
    pub queued: bool,
    pub fast_path: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentStatus {
    pub agent_ok: bool,
    pub helper_ok: bool,
    pub db_mtime_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigValues {
    pub block_threshold: f64,
    pub alert_threshold: f64,
    pub cf_exclusions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const HELPER_PID_FILE: &str = "/var/run/synapsed-helper.pid";

pub(crate) fn reconcile_trigger_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home)
        .join(".synapse")
        .join("reconcile-now")
}

fn config_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("SYNAPSE_CONFIG") {
        return std::path::PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home)
        .join(".synapse")
        .join("synapse.toml")
}

/// Write an Unblock record to enforcement_log.
/// Free function (no Tauri state) so it can be unit-tested directly.
pub(crate) fn write_unblock_to_db(
    conn: &Connection,
    ip_text: &str,
    now: i64,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO enforcement_log \
         (event_id, ts_ms, action, ip_blob, ip_text, ttl_ms, reason, requested, confirmed) \
         VALUES (?1, ?2, 'Unblock', zeroblob(16), ?3, 0, 'dashboard-requested', 1, 1)",
        rusqlite::params![format!("dashboard-{now}"), now, ip_text],
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Touch (create or truncate) the trigger file that wakes the helper's reconcile loop.
/// Free function for unit-testability.
pub(crate) fn touch_trigger_file(path: &std::path::Path) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map(|_| ())
        .map_err(|e| format!("trigger write failed: {e}"))
}

/// Pure state machine: combine DB result and trigger result into UnblockResult.
/// No I/O — extracted so the three-state logic can be unit-tested in isolation.
pub(crate) fn build_unblock_result(
    db_result: Result<(), String>,
    trigger_result: Result<(), String>,
) -> UnblockResult {
    match db_result {
        Err(e) => UnblockResult {
            queued: false,
            fast_path: false,
            message: format!("write failed: {e}"),
        },
        Ok(()) => match trigger_result {
            Ok(()) => UnblockResult {
                queued: true,
                fast_path: true,
                message: String::new(),
            },
            Err(e) => UnblockResult {
                queued: true,
                fast_path: false,
                message: e,
            },
        },
    }
}

/// Path to the agent's PID file — written by the agent at startup, deleted on
/// clean shutdown. Lives in ~/.synapse/ (user-writable, no root required).
fn agent_pid_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home)
        .join(".synapse")
        .join("agent.pid")
}

/// Check agent liveness via kill(pid, 0).
/// Agent runs as the same user as Tauri: ret==0 is the normal alive case.
/// If the agent is ever launched via sudo (e.g. accidental `sudo synapse-agent`),
/// kill(pid, 0) returns -1/EPERM — process exists but caller can't signal root.
/// ESRCH = no such process → dead.
fn check_agent_alive() -> bool {
    let Ok(content) = std::fs::read_to_string(agent_pid_path()) else {
        return false;
    };
    let Ok(pid) = content.trim().parse::<libc::pid_t>() else {
        return false;
    };
    let ret = unsafe { libc::kill(pid, 0) };
    if ret == 0 {
        return true;
    }
    let errno = unsafe { *libc::__error() };
    errno == libc::EPERM
}

/// Check helper liveness via kill(pid, 0).
/// Helper runs as root; EPERM = alive (can't signal root process as non-root),
/// ESRCH = dead. Reading /var/run/synapsed-helper.pid is world-readable.
fn check_helper_alive() -> bool {
    let Ok(content) = std::fs::read_to_string(HELPER_PID_FILE) else {
        return false;
    };
    let Ok(pid) = content.trim().parse::<libc::pid_t>() else {
        return false;
    };
    let ret = unsafe { libc::kill(pid, 0) };
    if ret == 0 {
        return true; // can signal → process is alive
    }
    // ret == -1: check errno.
    // EPERM = process exists but unprivileged caller can't signal root process → alive.
    // ESRCH = no such process → dead.
    let errno = unsafe { *libc::__error() };
    errno == libc::EPERM
}

// ---------------------------------------------------------------------------
// CrossFlow: hardcoded always-excluded IPs
// Mirror of CROSSFLOW_EXCLUDED_API_IPS in crates/agent/src/main.rs.
// The dashboard binary cannot import from the agent crate; replicate here for
// display. Keep in sync when the agent constant changes.
// own IPs and default gateway are also always excluded at runtime but are
// dynamic (network-dependent) and not knowable from the Tauri process.
// ---------------------------------------------------------------------------

const CF_ALWAYS_EXCLUDED: &[&str] = &[
    "160.79.104.10", // Anthropic API (api.anthropic.com) — Claude desktop false positive
];

// ---------------------------------------------------------------------------
// Internal TOML types (not serialized to frontend — only used in config read)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
struct TomlConfig {
    #[serde(default)]
    decision: TomlDecisionSection,
    #[serde(default)]
    cross_flow: TomlCrossFlowSection,
}

#[derive(serde::Deserialize)]
struct TomlDecisionSection {
    #[serde(default = "default_block_threshold")]
    block_threshold: f64,
    #[serde(default = "default_alert_threshold")]
    alert_threshold: f64,
}

fn default_block_threshold() -> f64 {
    0.7
}
fn default_alert_threshold() -> f64 {
    0.3
}

impl Default for TomlDecisionSection {
    fn default() -> Self {
        Self {
            block_threshold: default_block_threshold(),
            alert_threshold: default_alert_threshold(),
        }
    }
}

#[derive(serde::Deserialize, Default)]
struct TomlCrossFlowSection {
    #[serde(default)]
    excluded_ips: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_active_blocks(state: tauri::State<crate::DbState>) -> Vec<ActiveBlock> {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return vec![];
    };
    let now = now_ms();
    let mut stmt = match conn.prepare(
        "SELECT ip_text, ts_ms + ttl_ms - ?1 AS remaining_ms, reason
         FROM enforcement_log el
         WHERE el.action = 'Block'
           AND el.ts_ms + el.ttl_ms > ?1
           AND el.ts_ms = (
               SELECT MAX(ts_ms) FROM enforcement_log
               WHERE ip_text = el.ip_text AND action IN ('Block', 'Unblock')
           )",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    stmt.query_map(rusqlite::params![now], |r| {
        Ok(ActiveBlock {
            ip_text: r.get(0)?,
            remaining_ms: r.get(1)?,
            reason: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
        })
    })
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

#[tauri::command]
pub fn request_unblock(ip_text: String, state: tauri::State<WriteDbState>) -> UnblockResult {
    let guard = state.0.lock().unwrap_or_else(|e| e.into_inner());
    let Some(conn) = guard.as_ref() else {
        return UnblockResult {
            queued: false,
            fast_path: false,
            message: "database unavailable".to_string(),
        };
    };
    let db_result = write_unblock_to_db(conn, &ip_text, now_ms());
    let trigger_result = touch_trigger_file(&reconcile_trigger_path());
    build_unblock_result(db_result, trigger_result)
}

#[tauri::command]
pub fn get_agent_status() -> AgentStatus {
    // db_mtime_ms: kept for the stale-data banner — shows how old the displayed
    // data is even when the agent process is alive.
    let db_mtime_ms = std::fs::metadata(db_path())
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    AgentStatus {
        agent_ok: check_agent_alive(),
        helper_ok: check_helper_alive(),
        db_mtime_ms,
    }
}

#[tauri::command]
pub fn get_config_values() -> ConfigValues {
    // Always-excluded hardcoded IPs are prepended regardless of TOML config.
    // Own IPs and detected gateway are also always excluded at runtime but are
    // dynamic (network-dependent) and cannot be read from the Tauri process.
    let mut cf_exclusions: Vec<String> =
        CF_ALWAYS_EXCLUDED.iter().map(|s| s.to_string()).collect();

    if let Ok(text) = std::fs::read_to_string(config_path()) {
        let cfg: TomlConfig = toml::from_str(&text).unwrap_or_default();
        cf_exclusions.extend(cfg.cross_flow.excluded_ips);
        return ConfigValues {
            block_threshold: cfg.decision.block_threshold,
            alert_threshold: cfg.decision.alert_threshold,
            cf_exclusions,
        };
    }

    ConfigValues {
        block_threshold: 0.7,
        alert_threshold: 0.3,
        cf_exclusions,
    }
}

// ---------------------------------------------------------------------------
// Unit tests — UnblockResult state machine + I/O helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::OpenFlags;

    fn setup_enforcement_log(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE enforcement_log (
                id        INTEGER PRIMARY KEY,
                event_id  TEXT    NOT NULL UNIQUE,
                ts_ms     INTEGER NOT NULL,
                action    TEXT    NOT NULL,
                ip_blob   BLOB    NOT NULL,
                ip_text   TEXT    NOT NULL,
                ttl_ms    INTEGER,
                reason    TEXT    NOT NULL DEFAULT '',
                requested INTEGER NOT NULL DEFAULT 0,
                confirmed INTEGER NOT NULL DEFAULT 0,
                error     TEXT
             );",
        )
        .unwrap();
    }

    // --- Pure state machine (no I/O) ---

    #[test]
    fn test_unblock_result_db_and_trigger_success() {
        let r = build_unblock_result(Ok(()), Ok(()));
        assert!(r.queued, "queued=true when DB write succeeded");
        assert!(r.fast_path, "fast_path=true when trigger write succeeded");
        assert!(r.message.is_empty());
    }

    #[test]
    fn test_unblock_result_db_ok_trigger_fail() {
        let r = build_unblock_result(
            Ok(()),
            Err("trigger write failed: Permission denied (os error 13)".into()),
        );
        assert!(
            r.queued,
            "queued=true — Unblock record exists, will run at next periodic pass"
        );
        assert!(
            !r.fast_path,
            "fast_path=false — trigger write failed, ~60 s latency"
        );
        assert!(
            r.message.contains("trigger write failed"),
            "error must surface trigger failure so UI can warn user"
        );
    }

    #[test]
    fn test_unblock_result_db_fail() {
        let r = build_unblock_result(
            Err("UNIQUE constraint failed: enforcement_log.event_id".into()),
            Ok(()),
        );
        assert!(
            !r.queued,
            "queued=false — DB write failed, unblock not recorded"
        );
        assert!(!r.fast_path, "fast_path=false when queued=false");
        assert!(
            r.message.contains("write failed"),
            "error must surface DB failure"
        );
    }

    // --- write_unblock_to_db (real SQLite I/O) ---

    #[test]
    fn test_write_unblock_inserts_row() {
        let conn = Connection::open_in_memory().unwrap();
        setup_enforcement_log(&conn);
        let result = write_unblock_to_db(&conn, "1.2.3.4", 1_000_000);
        assert!(result.is_ok());
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM enforcement_log \
                 WHERE action='Unblock' AND ip_text='1.2.3.4'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "exactly one Unblock row must be inserted");
    }

    #[test]
    fn test_write_unblock_fails_on_readonly_conn() {
        let dir = std::env::temp_dir().join("synapse_lib_unblock_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_readonly.db");
        let _ = std::fs::remove_file(&path); // clear any stale file from prior run
        {
            let setup = Connection::open(&path).unwrap();
            setup_enforcement_log(&setup);
        }
        let ro = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        let result = write_unblock_to_db(&ro, "1.2.3.4", 1_000_000);
        assert!(result.is_err(), "write to read-only connection must fail");
    }

    // --- touch_trigger_file (real filesystem I/O) ---

    #[test]
    fn test_touch_trigger_file_creates_file() {
        let dir = std::env::temp_dir().join("synapse_trigger_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("reconcile-now");
        let _ = std::fs::remove_file(&path);
        let result = touch_trigger_file(&path);
        assert!(result.is_ok());
        assert!(path.exists(), "trigger file must be created");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_touch_trigger_file_bad_path_fails() {
        let bad = std::path::Path::new("/no/such/dir/reconcile-now");
        let result = touch_trigger_file(bad);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("trigger write failed"),
            "error message must include 'trigger write failed'"
        );
    }
}
