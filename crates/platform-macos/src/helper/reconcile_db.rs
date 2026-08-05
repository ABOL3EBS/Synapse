// helper/reconcile_db.rs
//
// Read-only access to the agent's enforcement_log to derive desired firewall
// state for reconcile(). The helper (root) opens the agent's SQLite DB
// read-only — no writes, no WAL checkpointing. This is the only place in the
// helper that touches the agent's persistent storage.
//
// Architecturally: this is a one-directional read of the agent's log for
// enforcement recovery, not detection or decision logic. It does not cross the
// privileged/unprivileged boundary in the dangerous direction (writing from
// helper into agent storage).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::warn;
use rusqlite::{Connection, OpenFlags};
use synapse_common::{DesiredFirewallState, ValidatedBlock};

/// Resolve the agent's DB path: prefer $SYNAPSE_DB_PATH env var, fall back to
/// $HOME/.synapse/synapse.db. The helper runs as root under sudo, but $HOME is
/// typically preserved by sudo's env passthrough — same logic the agent uses.
pub fn agent_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("SYNAPSE_DB_PATH") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".synapse").join("synapse.db")
}

/// Open the agent's DB read-only. Returns Err if the file doesn't exist yet
/// (agent hasn't run) — caller should treat this as "empty desired state."
pub fn open_read_only(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("reconcile: open {} read-only: {e}", path.display()))
}

/// Query enforcement_log for IPs that should currently be blocked:
///   - most recent action for the IP is 'Block' (not superseded by Unblock)
///   - TTL window has not expired
///
/// A later Unblock for the same IP has a higher ts_ms, so MAX(ts_ms) across
/// both Block and Unblock events will be the Unblock's timestamp — the outer
/// WHERE action='Block' then fails, correctly excluding the IP.
pub fn query_desired_state(conn: &Connection) -> Result<DesiredFirewallState, String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let mut stmt = conn
        .prepare(
            "SELECT ip_text, ts_ms + ttl_ms - ?1 AS remaining_ms
             FROM enforcement_log el
             WHERE el.action = 'Block'
               AND el.ts_ms + el.ttl_ms > ?1
               AND el.ts_ms = (
                   SELECT MAX(ts_ms)
                   FROM enforcement_log
                   WHERE ip_text = el.ip_text
                     AND action IN ('Block', 'Unblock')
               )",
        )
        .map_err(|e| format!("reconcile: prepare desired-state query: {e}"))?;

    let blocks: Vec<ValidatedBlock> = stmt
        .query_map([now_ms], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|e| format!("reconcile: query desired state: {e}"))?
        .filter_map(|r| match r {
            Ok((ip_text, remaining_ms)) => match ip_text.parse::<IpAddr>() {
                Ok(ip) => {
                    // Skip blocks with less than 30 s remaining. The ValidatedBlock
                    // minimum TTL is 30 s, and re-adding a block that is about to
                    // expire would extend its lifetime beyond the original decision.
                    // These blocks expire naturally from enforcement_log within 30 s,
                    // so the next reconcile pass will not include them in desired state.
                    if remaining_ms < 30_000 {
                        return None;
                    }
                    let remaining_secs = (remaining_ms / 1000).min(86400) as u64;
                    let ttl = std::time::Duration::from_secs(remaining_secs);
                    match ValidatedBlock::try_new(ip, ttl) {
                        Ok(b) => Some(b),
                        Err(e) => {
                            warn!("reconcile: skip {ip_text}: {e}");
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("reconcile: skip unparseable IP {ip_text:?}: {e}");
                    None
                }
            },
            Err(e) => {
                warn!("reconcile: row error: {e}");
                None
            }
        })
        .collect();

    Ok(DesiredFirewallState { blocks })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE enforcement_log (
                id       INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                ts_ms    INTEGER NOT NULL,
                action   TEXT NOT NULL,
                ip_blob  BLOB NOT NULL,
                ip_text  TEXT NOT NULL,
                ttl_ms   INTEGER,
                reason   TEXT NOT NULL DEFAULT ''
             );",
        )
        .unwrap();
        conn
    }

    fn insert(conn: &Connection, id: i64, ip: &str, action: &str, ts_ms: i64, ttl_ms: i64) {
        conn.execute(
            "INSERT INTO enforcement_log (id, event_id, ts_ms, action, ip_blob, ip_text, ttl_ms, reason)
             VALUES (?1, ?2, ?3, ?4, zeroblob(16), ?5, ?6, '')",
            rusqlite::params![id, format!("evt-{id}"), ts_ms, action, ip, ttl_ms],
        )
        .unwrap();
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[test]
    fn test_active_block_included() {
        let conn = setup_db();
        let now = now_ms();
        insert(&conn, 1, "1.2.3.4", "Block", now - 1000, 300_000);
        let state = query_desired_state(&conn).unwrap();
        assert_eq!(state.blocks.len(), 1);
        assert_eq!(state.blocks[0].ip(), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_expired_block_excluded() {
        let conn = setup_db();
        let now = now_ms();
        // ttl_ms=5000, issued 10s ago → already expired
        insert(&conn, 1, "1.2.3.4", "Block", now - 10_000, 5_000);
        let state = query_desired_state(&conn).unwrap();
        assert!(
            state.blocks.is_empty(),
            "expired block must not appear in desired state"
        );
    }

    #[test]
    fn test_unblock_supersedes_block() {
        let conn = setup_db();
        let now = now_ms();
        insert(&conn, 1, "1.2.3.4", "Block", now - 2000, 300_000);
        insert(&conn, 2, "1.2.3.4", "Unblock", now - 1000, 0);
        let state = query_desired_state(&conn).unwrap();
        assert!(
            state.blocks.is_empty(),
            "Unblock after Block must exclude IP from desired state"
        );
    }

    #[test]
    fn test_reblock_after_unblock_included() {
        let conn = setup_db();
        let now = now_ms();
        insert(&conn, 1, "1.2.3.4", "Block", now - 3000, 300_000);
        insert(&conn, 2, "1.2.3.4", "Unblock", now - 2000, 0);
        insert(&conn, 3, "1.2.3.4", "Block", now - 1000, 300_000);
        let state = query_desired_state(&conn).unwrap();
        assert_eq!(
            state.blocks.len(),
            1,
            "re-block after unblock must be included"
        );
    }

    #[test]
    fn test_multiple_ips_independent() {
        let conn = setup_db();
        let now = now_ms();
        insert(&conn, 1, "1.2.3.4", "Block", now - 1000, 300_000); // active
        insert(&conn, 2, "5.6.7.8", "Block", now - 10_000, 5_000); // expired
        insert(&conn, 3, "9.10.11.12", "Block", now - 2000, 300_000); // active
        insert(&conn, 4, "9.10.11.12", "Unblock", now - 1000, 0); // unblocked
        let state = query_desired_state(&conn).unwrap();
        assert_eq!(state.blocks.len(), 1);
        assert_eq!(state.blocks[0].ip(), "1.2.3.4".parse::<IpAddr>().unwrap());
    }
}
