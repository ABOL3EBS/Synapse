// crates/common/src/lib.rs
//
// Shared data contracts between synapsed-helper (root) and synapse-agent (unprivileged).
// Zero logic — just types. Both crates depend on this without pulling in engine internals.

pub mod log_format;
pub mod types;

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

pub use types::{
    BlockId, DecisionConfig, DesiredFirewallState, DetectorConfig, DetectorFinding, DetectorId,
    DetectorStatus, EnforcementReceipt, EnrichmentKind, EnrichmentRequest, EnrichmentResult,
    Evidence, FlowFeatures, FlowRecord, PortPidCache, ReconciliationReport, Severity,
    ValidatedBlock, Verdict,
};

// Re-export the Detector trait and run_detector_with_timeout function.
pub use types::{run_detector_with_timeout, Detector};

// ---------------------------------------------------------------------------
// Enforcement Protocol
// ---------------------------------------------------------------------------
// This enum is the *only* shape enforcement commands can take between agent → helper.
// Typed IpAddr/Duration only — never strings. The helper validates against this
// fixed protocol before applying anything to pfctl, making shell injection
// structurally unreachable.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnforcementCommand {
    /// Block traffic from/to this IP for the given TTL.
    Block { ip: IpAddr, ttl: Duration },
    /// Remove a previously applied block.
    Unblock { ip: IpAddr },
    /// Kill active state table entries matching this 5-tuple.
    KillState {
        src: IpAddr,
        dst: IpAddr,
        proto: u8, // IPPROTO_TCP=6, IPPROTO_UDP=17
    },
}

// ---------------------------------------------------------------------------
// IPC Message Envelope (helper → agent)
// ---------------------------------------------------------------------------
// Wraps messages from helper to agent into a single enum so send_message /
// recv_message can distinguish message types without ad-hoc tagging.
// Agent → helper direction remains plain EnforcementCommand (no wrapping).

/// Messages the helper sends to the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Port→PID cache snapshot from the helper's fd-scan thread.
    PortPidCache(PortPidCache),
}

// ---------------------------------------------------------------------------
// Packet Metadata (basic, for first milestone)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub length: u16,
}

// ---------------------------------------------------------------------------
// Protocol Constants
// ---------------------------------------------------------------------------

/// Magic bytes preceding every IPC message. Provides basic framing validation.
pub const IPC_MAGIC: [u8; 4] = *b"SYNP";

/// Current IPC protocol version. Bump on breaking changes.
pub const IPC_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// pf Anchor Constants (shared between helper and enforcement backend)
// ---------------------------------------------------------------------------

/// pf anchor name — must match in helper/main.rs ensure_anchor() and enforce.rs.
pub const PF_ANCHOR_NAME: &str = "com.synapse.ips";

/// pf table name inside the anchor — dynamic IP blocklist.
pub const PF_TABLE_NAME: &str = "synapse_blocklist";

/// Unix domain socket path for helper ↔ agent IPC.
pub const IPC_SOCKET_PATH: &str = "/tmp/synapse-helper.sock";

// ---------------------------------------------------------------------------
// Enforcement Backend Trait (§4c)
// ---------------------------------------------------------------------------
// The only safe execution guarantee isn't just typed data — it's that the
// implementation uses argv-based process execution, never a shell.
// ValidatedBlock/BlockId are constructed only through a validation path
// the caller can't bypass.

pub trait EnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
    fn kill_state(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
    ) -> Result<EnforcementReceipt, String>;
    fn reconcile(&mut self, desired: &DesiredFirewallState)
        -> Result<ReconciliationReport, String>;
}
