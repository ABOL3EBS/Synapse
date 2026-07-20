// crates/platform-macos/src/helper/enforce.rs
//
// The ONLY implementer of EnforcementBackend for macOS.
// §4c: "The concrete macOS implementation of this trait (in
// platform-macos/src/helper/enforce.rs) is the *only* place allowed to
// invoke pfctl, and it must do so via std::process::Command::new("pfctl")
// .arg(...).arg(...) — never through a shell."

use std::collections::HashSet;
use std::net::IpAddr;

use log::{error, info, warn};
use synapse_common::{
    BlockId, DesiredFirewallState, EnforcementBackend, EnforcementReceipt, ReconciliationReport,
    ValidatedBlock,
};

const PF_ANCHOR_NAME: &str = "com.synapse.ips";
const PF_TABLE_NAME: &str = "synapse_blocklist";

/// macOS enforcement backend — owns the set of active blocks and the pf anchor.
pub struct MacOsEnforcementBackend {
    active_blocks: HashSet<IpAddr>,
}

impl MacOsEnforcementBackend {
    pub fn new() -> Self {
        Self {
            active_blocks: HashSet::new(),
        }
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
        info!("pfctl: added {ip} to table '{PF_TABLE_NAME}'");
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
            info!("pfctl: removed {ip} from table '{PF_TABLE_NAME}'");
        }
        Ok(())
    }
}

impl EnforcementBackend for MacOsEnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String> {
        let block_id = BlockId::from(block.ip);

        // If already blocked, keep the original TTL. Re-issue block_ip()
        // (idempotent — pfctl table add is a no-op for an existing entry)
        // but do NOT spawn a second timer. Two timers for the same IP means
        // whichever fires first unblocks it, losing the intended duration.
        if self.active_blocks.contains(&block.ip) {
            Self::block_ip(block.ip)?;
            return Ok(EnforcementReceipt {
                block_id,
                success: true,
                message: format!("already blocked {ip}", ip = block.ip),
            });
        }

        Self::block_ip(block.ip)?;
        self.active_blocks.insert(block.ip);

        // Spawn TTL auto-unblock in a background thread.
        // v1 tradeoff: one OS thread per active block, no cap. Fine at
        // current traffic volumes; if block counts grow, replace with a
        // single timer-wheel or a thread with a channel of wake events.
        let ip = block.ip;
        let ttl = block.ttl;
        std::thread::spawn(move || {
            std::thread::sleep(ttl);
            if let Err(e) = Self::unblock_ip(ip) {
                error!("TTL unblock failed for {ip}: {e}");
            }
            info!("TTL expired: unblocked {ip}");
        });

        Ok(EnforcementReceipt {
            block_id,
            success: true,
            message: format!("blocked {ip} with TTL {ttl:?}", ip = block.ip),
        })
    }

    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String> {
        let ip = block_id.0;

        Self::unblock_ip(ip)?;
        self.active_blocks.remove(&ip);

        Ok(EnforcementReceipt {
            block_id,
            success: true,
            message: format!("unblocked {ip}"),
        })
    }

    /// §4a/§4c: STUB — real reconciliation is tracked separate work.
    /// Returns default (no re-applied, no evicted, no errors).
    fn reconcile(
        &mut self,
        _desired: &DesiredFirewallState,
    ) -> Result<ReconciliationReport, String> {
        Ok(ReconciliationReport::default())
    }
}
