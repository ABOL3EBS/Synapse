// crates/common/src/types.rs
//
// Shared data contracts for the enforcement backend.
// §4c: "ValidatedBlock, BlockId, DesiredFirewallState, ReconciliationReport,
// and EnforcementReceipt belong in crates/common/src/types.rs"

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Enforcement Backend Types (§4c)
// ---------------------------------------------------------------------------

/// A validated, safe-to-enforce block request.
/// Constructed only through a validation path the caller can't bypass —
/// "did you validate this?" is answered by the type system, not discipline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatedBlock {
    pub ip: IpAddr,
    pub ttl: Duration,
}

/// Unique identifier for an active block. Currently the IP itself;
/// can become a UUID or opaque handle if the backend needs deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockId(pub IpAddr);

impl From<IpAddr> for BlockId {
    fn from(ip: IpAddr) -> Self {
        Self(ip)
    }
}

/// The complete set of blocks the agent wants enforced at any point in time.
/// §4a reconcile() uses this as the source of truth for what *should* be in
/// the pf table, then diffs it against what *is* there.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesiredFirewallState {
    pub blocks: Vec<ValidatedBlock>,
}

/// Result of applying or removing a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementReceipt {
    pub block_id: BlockId,
    pub success: bool,
    pub message: String,
}

/// Result of a reconciliation pass (§4a/§4c).
/// Reports what had to be re-applied (anchor eviction recovery),
/// what was evicted that couldn't be recovered, and any errors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconciliationReport {
    /// Blocks that were re-applied after anchor eviction.
    pub re_applied: usize,
    /// Block IDs that were in DesiredFirewallState but could not be restored.
    pub evicted: Vec<BlockId>,
    /// Human-readable error strings for failures during reconciliation.
    pub errors: Vec<String>,
}
