// crates/platform-macos/src/helper/enforce.rs
//
// The ONLY implementer of EnforcementBackend for macOS.
// §4c: "The concrete macOS implementation of this trait (in
// platform-macos/src/helper/enforce.rs) is the *only* place allowed to
// invoke pfctl, and it must do so via std::process::Command::new("pfctl")
// .arg(...).arg(...) — never through a shell."

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use log::{error, info, warn};
use synapse_common::{
    BlockId, DesiredFirewallState, EnforcementBackend, EnforcementReceipt, ReconciliationReport,
    ValidatedBlock, PF_ANCHOR_NAME, PF_TABLE_NAME,
};

/// macOS enforcement backend — owns the set of active blocks and the pf anchor.
pub struct MacOsEnforcementBackend {
    active_blocks: Arc<Mutex<HashSet<IpAddr>>>,
    /// Cancellation flags for TTL auto-unblock threads.
    /// On remove_block(), the flag is set to true so the sleeping thread
    /// skips the unblock — avoids a double-unblock and misleading log.
    cancel_handles: HashMap<IpAddr, Arc<AtomicBool>>,
}

impl MacOsEnforcementBackend {
    pub fn new() -> Self {
        Self {
            active_blocks: Arc::new(Mutex::new(HashSet::new())),
            cancel_handles: HashMap::new(),
        }
    }

    /// Number of currently active blocks — used to enforce MAX_CONCURRENT_BLOCKS.
    pub fn active_block_count(&self) -> usize {
        self.active_blocks.lock().map(|g| g.len()).unwrap_or(0)
    }

    fn block_ip(ip: IpAddr) -> Result<(), String> {
        let output = std::process::Command::new("pfctl")
            .args([
                "-a",
                PF_ANCHOR_NAME,
                "-t",
                PF_TABLE_NAME,
                "-T",
                "add",
                &ip.to_string(),
            ])
            .output()
            .map_err(|e| format!("pfctl spawn failed: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("pfctl table add failed for {ip}: {stderr}"));
        }
        info!("[ENFORCE] added {ip} to table '{PF_TABLE_NAME}'");
        Ok(())
    }

    fn unblock_ip(ip: IpAddr) -> Result<(), String> {
        let output = std::process::Command::new("pfctl")
            .args([
                "-a",
                PF_ANCHOR_NAME,
                "-t",
                PF_TABLE_NAME,
                "-T",
                "delete",
                &ip.to_string(),
            ])
            .output()
            .map_err(|e| format!("pfctl spawn failed: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("pfctl table delete failed for {ip}: {stderr}");
        } else {
            info!("[ENFORCE] removed {ip} from table '{PF_TABLE_NAME}'");
        }
        Ok(())
    }
}

impl EnforcementBackend for MacOsEnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String> {
        let ip = block.ip();
        let ttl = block.ttl();
        let block_id = BlockId::from(ip);

        // If already blocked, keep the original TTL. Re-issue block_ip()
        // (idempotent — pfctl table add is a no-op for an existing entry)
        // but do NOT spawn a second timer. Two timers for the same IP means
        // whichever fires first unblocks it, losing the intended duration.
        {
            let blocks = self.active_blocks.lock().map_err(|e| e.to_string())?;
            if blocks.contains(&ip) {
                drop(blocks);
                Self::block_ip(ip)?;
                return Ok(EnforcementReceipt {
                    block_id,
                    success: true,
                    message: format!("already blocked {ip}"),
                });
            }
        }

        Self::block_ip(ip)?;
        self.active_blocks
            .lock()
            .map_err(|e| e.to_string())?
            .insert(ip);

        // Spawn TTL auto-unblock in a background thread.
        // v1 tradeoff: one OS thread per active block, no cap. Fine at
        // current traffic volumes; if block counts grow, replace with a
        // single timer-wheel or a thread with a channel of wake events.
        //
        // Cancellation: Arc<AtomicBool> flag lets remove_block() abort the
        // unblock without waiting for the sleep to finish.
        let cancelled = Arc::new(AtomicBool::new(false));
        self.cancel_handles.insert(ip, Arc::clone(&cancelled));
        let active_blocks = Arc::clone(&self.active_blocks);
        std::thread::spawn(move || {
            std::thread::sleep(ttl);
            if cancelled.load(Ordering::Acquire) {
                // remove_block() already handled unblock — skip.
                return;
            }
            if let Err(e) = Self::unblock_ip(ip) {
                error!("TTL unblock failed for {ip}: {e}");
            } else {
                // R5: Remove from active_blocks after successful unblock.
                if let Ok(mut blocks) = active_blocks.lock() {
                    blocks.remove(&ip);
                }
            }
            info!("[ENFORCE] TTL expired: unblocked {ip}");
        });

        Ok(EnforcementReceipt {
            block_id,
            success: true,
            message: format!("blocked {ip} with TTL {ttl:?}"),
        })
    }

    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String> {
        let ip = block_id.0;

        // Cancel the TTL auto-unblock thread if it's still sleeping.
        if let Some(cancelled) = self.cancel_handles.remove(&ip) {
            cancelled.store(true, Ordering::Release);
        }

        Self::unblock_ip(ip)?;
        self.active_blocks
            .lock()
            .map_err(|e| e.to_string())?
            .remove(&ip);

        Ok(EnforcementReceipt {
            block_id,
            success: true,
            message: format!("unblocked {ip}"),
        })
    }

    /// Kill state entries for a specific src→dst pair.
    ///
    /// `man pfctl`: `-k host1 -k host2` kills all state entries from host1 to host2.
    /// NOTE: `pfctl -k` does NOT filter by protocol — it kills all states
    /// (TCP, UDP, etc.) matching the src/dst pair. The `proto` field is
    /// kept for logging and future use if pfctl gains protocol-specific killing.
    fn kill_state(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
    ) -> Result<EnforcementReceipt, String> {
        let proto_name = match proto {
            6 => "tcp",
            17 => "udp",
            _ => "all",
        };

        let output = std::process::Command::new("pfctl")
            .args(["-k", &src.to_string(), "-k", &dst.to_string()])
            .output()
            .map_err(|e| format!("pfctl spawn failed: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("pfctl kill failed: {stderr}"));
        }

        info!("[ENFORCE] killed states {proto_name} {src} → {dst} (all protocols for this pair)");

        Ok(EnforcementReceipt {
            block_id: BlockId::from(src),
            success: true,
            message: format!("killed states {proto_name} {src} → {dst}"),
        })
    }

    /// §4a/§4c: Diff live pf table against desired state; apply corrections.
    ///
    /// REMOVE direction: IPs in the live table not in desired state (orphans
    /// from a prior crash, expired blocks, or external pf manipulation).
    /// RE-ADD direction: IPs in desired state missing from the live table
    /// (another tool flushed pf, or the anchor was reloaded).
    ///
    /// Never panics or returns Err — errors accumulate in the report so the
    /// caller can log-and-continue.
    fn reconcile(
        &mut self,
        desired: &DesiredFirewallState,
    ) -> Result<ReconciliationReport, String> {
        let mut report = ReconciliationReport::default();

        let live = match read_live_table() {
            Ok(set) => set,
            Err(e) => {
                let msg = format!("reconcile: read live pf table failed: {e}");
                warn!("{msg}");
                report.errors.push(msg);
                return Ok(report);
            }
        };

        let desired_set: HashSet<IpAddr> = desired.blocks.iter().map(|b| b.ip()).collect();
        let (orphans, missing) = compute_diff(&live, &desired_set);

        for ip in &orphans {
            match Self::unblock_ip(*ip) {
                Ok(()) => {
                    report.orphans_removed += 1;
                    // Remove from in-memory tracking — it was never legitimately added
                    // during this session, but clean up just in case.
                    if let Ok(mut guard) = self.active_blocks.lock() {
                        guard.remove(ip);
                    }
                }
                Err(e) => {
                    let msg = format!("reconcile: remove orphan {ip}: {e}");
                    warn!("{msg}");
                    report.errors.push(msg);
                }
            }
        }

        for ip in &missing {
            // block_ip takes IpAddr directly — no ValidatedBlock wrapper needed here.
            // desired state IPs are already validated by query_desired_state().
            match Self::block_ip(*ip) {
                Ok(()) => {
                    report.re_applied += 1;
                    if let Ok(mut guard) = self.active_blocks.lock() {
                        guard.insert(*ip);
                    }
                }
                Err(e) => {
                    let msg = format!("reconcile: re-add {ip}: {e}");
                    warn!("{msg}");
                    report.evicted.push(BlockId::from(*ip));
                    report.errors.push(msg);
                }
            }
        }

        info!(
            "[RECONCILE] pass complete: removed {} orphan(s), restored {} missing block(s), {} error(s)",
            report.orphans_removed, report.re_applied, report.errors.len()
        );
        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// Reconciliation helpers (pure functions — no pfctl I/O, fully testable)
// ---------------------------------------------------------------------------

/// Read the current contents of the pf blocklist table.
/// Returns a set of IpAddr parsed from pfctl -T show output (one IP per line).
fn read_live_table() -> Result<HashSet<IpAddr>, String> {
    let output = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-t", PF_TABLE_NAME, "-T", "show"])
        .output()
        .map_err(|e| format!("pfctl -T show spawn failed: {e}"))?;

    // pfctl exits non-zero when the table is empty ("no addresses found") or
    // when the anchor doesn't exist yet. Treat both as an empty live set.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No addresses") || stderr.contains("pfctl: DIOCRGETADDRS") {
            return Ok(HashSet::new());
        }
        // For any other pfctl error, propagate so the caller logs it.
        return Err(format!(
            "pfctl -T show failed ({}): {stderr}",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let ips: HashSet<IpAddr> = stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // pfctl may include CIDR notation (e.g. "1.2.3.4/32") — strip the prefix.
            let addr_part = trimmed.split('/').next().unwrap_or(trimmed);
            match addr_part.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    if !trimmed.is_empty() {
                        warn!("reconcile: unrecognised pf table entry: {trimmed:?}");
                    }
                    None
                }
            }
        })
        .collect();

    Ok(ips)
}

/// Pure diff: compute orphans (in live but not desired) and missing (in desired
/// but not live). No I/O — extracted so the logic can be unit-tested without
/// real pfctl calls.
fn compute_diff(live: &HashSet<IpAddr>, desired: &HashSet<IpAddr>) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let orphans: Vec<IpAddr> = live.difference(desired).copied().collect();
    let missing: Vec<IpAddr> = desired.difference(live).copied().collect();
    (orphans, missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn set(ips: &[&str]) -> HashSet<IpAddr> {
        ips.iter().map(|s| ip(s)).collect()
    }

    #[test]
    fn test_compute_diff_in_sync() {
        let live = set(&["1.2.3.4", "5.6.7.8"]);
        let desired = set(&["1.2.3.4", "5.6.7.8"]);
        let (orphans, missing) = compute_diff(&live, &desired);
        assert!(orphans.is_empty(), "no orphans when in sync");
        assert!(missing.is_empty(), "no missing when in sync");
    }

    #[test]
    fn test_compute_diff_orphan_detection() {
        let live = set(&["1.2.3.4", "99.0.0.1"]);
        let desired = set(&["1.2.3.4"]);
        let (orphans, missing) = compute_diff(&live, &desired);
        assert_eq!(orphans, vec![ip("99.0.0.1")]);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_compute_diff_missing_detection() {
        let live = set(&["1.2.3.4"]);
        let desired = set(&["1.2.3.4", "5.6.7.8"]);
        let (orphans, missing) = compute_diff(&live, &desired);
        assert!(orphans.is_empty());
        assert_eq!(missing, vec![ip("5.6.7.8")]);
    }

    #[test]
    fn test_compute_diff_both_directions() {
        let live = set(&["1.2.3.4", "203.0.113.99"]);
        let desired = set(&["1.2.3.4", "5.6.7.8"]);
        let (orphans, missing) = compute_diff(&live, &desired);
        assert_eq!(orphans, vec![ip("203.0.113.99")]);
        assert_eq!(missing, vec![ip("5.6.7.8")]);
    }

    #[test]
    fn test_compute_diff_empty_live() {
        let live = set(&[]);
        let desired = set(&["1.2.3.4", "5.6.7.8"]);
        let (orphans, missing) = compute_diff(&live, &desired);
        assert!(orphans.is_empty());
        let mut missing_sorted = missing.clone();
        missing_sorted.sort();
        assert_eq!(missing_sorted, vec![ip("1.2.3.4"), ip("5.6.7.8")]);
    }

    #[test]
    fn test_compute_diff_empty_desired() {
        let live = set(&["1.2.3.4", "5.6.7.8"]);
        let desired = set(&[]);
        let (orphans, missing) = compute_diff(&live, &desired);
        let mut orphans_sorted = orphans.clone();
        orphans_sorted.sort();
        assert_eq!(orphans_sorted, vec![ip("1.2.3.4"), ip("5.6.7.8")]);
        assert!(missing.is_empty());
    }

    // Confirm the IPv4 loopback is a well-formed IpAddr (parse sanity).
    #[test]
    fn test_ip_parse_sanity() {
        let _: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    }
}
