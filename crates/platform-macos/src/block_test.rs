// block_test.rs — end-to-end enforcement test binary.
//
// Uses the same pfctl invocations as MacOsEnforcementBackend::block_ip() /
// unblock_ip() (verbatim Command::new("pfctl").args([...]), no shell).
// Also writes the enforcement_log record so the Active Blocks panel shows the IP.
//
// Requires root (pfctl needs it). Run: sudo ./target/debug/block-test [block|unblock]
//
// Safe test IP: 203.0.113.55 (RFC 5737 TEST-NET-3 — documentation only,
// cannot be a real host, routers drop it). TTL: 5 min (300 s).

use rusqlite::Connection;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use synapse_common::{PF_ANCHOR_NAME, PF_TABLE_NAME};

const TEST_IP: &str = "203.0.113.55";
const TTL_MS: i64 = 300_000; // 5 minutes

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn db_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("SYNAPSE_DB_PATH") {
        return std::path::PathBuf::from(p);
    }
    // Under sudo, $HOME is reset to /root. Use $SUDO_USER to find the real
    // user's home directory, falling back to $HOME only if not running via sudo.
    let home = if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() {
            format!("/Users/{sudo_user}")
        } else {
            std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
        }
    } else {
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())
    };
    std::path::PathBuf::from(home)
        .join(".synapse")
        .join("synapse.db")
}

fn ip_blob(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Exact mirror of MacOsEnforcementBackend::block_ip().
fn pfctl_block(ip: &str) -> Result<(), String> {
    let out = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-t", PF_TABLE_NAME, "-T", "add", ip])
        .output()
        .map_err(|e| format!("pfctl spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "pfctl -T add failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    println!("[ENFORCE] added {} to pf table '{}'", ip, PF_TABLE_NAME);
    Ok(())
}

/// Exact mirror of MacOsEnforcementBackend::unblock_ip().
fn pfctl_unblock(ip: &str) -> Result<(), String> {
    let out = std::process::Command::new("pfctl")
        .args([
            "-a",
            PF_ANCHOR_NAME,
            "-t",
            PF_TABLE_NAME,
            "-T",
            "delete",
            ip,
        ])
        .output()
        .map_err(|e| format!("pfctl spawn: {e}"))?;
    if !out.status.success() {
        eprintln!(
            "[WARN] pfctl -T delete returned non-zero: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    } else {
        println!("[ENFORCE] removed {} from pf table '{}'", ip, PF_TABLE_NAME);
    }
    Ok(())
}

fn write_block_record(conn: &Connection, ip: &str, ts_ms: i64) -> rusqlite::Result<()> {
    let parsed: IpAddr = ip.parse().expect("test IP must parse");
    let blob = ip_blob(parsed);
    let event_id = format!("block-test-{ts_ms}");
    conn.execute(
        "INSERT OR IGNORE INTO enforcement_log
         (event_id, ts_ms, action, ip_blob, ip_text, ttl_ms,
          reason, detector, score, error)
         VALUES (?1,?2,'Block',?3,?4,?5,'block-test-binary','block-test',1.0,NULL)",
        rusqlite::params![event_id, ts_ms, &blob[..], ip, TTL_MS],
    )?;
    println!(
        "[DB] enforcement_log Block row written (event_id={}, ttl={}ms)",
        event_id, TTL_MS
    );
    Ok(())
}

fn write_unblock_record(conn: &Connection, ip: &str, ts_ms: i64) -> rusqlite::Result<()> {
    let parsed: IpAddr = ip.parse().expect("test IP must parse");
    let blob = ip_blob(parsed);
    let event_id = format!("unblock-test-{ts_ms}");
    conn.execute(
        "INSERT OR IGNORE INTO enforcement_log
         (event_id, ts_ms, action, ip_blob, ip_text, ttl_ms,
          reason, detector, score, error)
         VALUES (?1,?2,'Unblock',?3,?4,0,'block-test-cleanup','block-test',0.0,NULL)",
        rusqlite::params![event_id, ts_ms, &blob[..], ip],
    )?;
    println!(
        "[DB] enforcement_log Unblock row written (event_id={})",
        event_id
    );
    Ok(())
}

fn pfctl_show() {
    let out = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-t", PF_TABLE_NAME, "-T", "show"])
        .output();
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            if stdout.trim().is_empty() && !stderr.trim().is_empty() {
                println!("[PFCTL] table empty or not initialised: {}", stderr.trim());
            } else {
                println!("[PFCTL] current table contents:\n{}", stdout);
            }
        }
        Err(e) => eprintln!("[PFCTL] show failed: {e}"),
    }
}

fn cmd_block() {
    let ts = now_ms();
    println!("=== block-test: BLOCK {} ===", TEST_IP);

    pfctl_block(TEST_IP).unwrap_or_else(|e| panic!("pfctl block failed: {e}"));

    let path = db_path();
    if !path.exists() {
        eprintln!(
            "[WARN] DB not found at {} — skipping enforcement_log write",
            path.display()
        );
        eprintln!("       Active Blocks panel won't show the IP without the DB record.");
    } else {
        let conn = Connection::open(&path).expect("open DB");
        conn.execute_batch("PRAGMA journal_mode = WAL;").ok();
        write_block_record(&conn, TEST_IP, ts).expect("DB write");
    }

    println!();
    println!("=== pf table after block ===");
    pfctl_show();

    println!();
    println!("=== Next steps ===");
    println!(
        "1. Open Settings screen — {} should appear in Active Blocks",
        TEST_IP
    );
    println!(
        "2. Click Unblock (or call request_unblock(\"{}\"))",
        TEST_IP
    );
    println!(
        "3. Run: sudo pfctl -a {} -t {} -T show",
        PF_ANCHOR_NAME, PF_TABLE_NAME
    );
    println!("   (should be empty within ~1s if fast-path triggered)");
    println!();
    println!(
        "To clean up manually: sudo pfctl -a {} -t {} -T delete {}",
        PF_ANCHOR_NAME, PF_TABLE_NAME, TEST_IP
    );
}

fn cmd_unblock() {
    let ts = now_ms();
    println!("=== block-test: UNBLOCK {} ===", TEST_IP);

    pfctl_unblock(TEST_IP).unwrap_or_else(|e| panic!("pfctl unblock failed: {e}"));

    let path = db_path();
    if path.exists() {
        let conn = Connection::open(&path).expect("open DB");
        conn.execute_batch("PRAGMA journal_mode = WAL;").ok();
        write_unblock_record(&conn, TEST_IP, ts).expect("DB write");
    }

    println!();
    println!("=== pf table after unblock ===");
    pfctl_show();
}

fn main() {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "block".to_string());
    match arg.as_str() {
        "block" => cmd_block(),
        "unblock" => cmd_unblock(),
        other => {
            eprintln!("Usage: block-test [block|unblock]  (got: {:?})", other);
            std::process::exit(1);
        }
    }
}
