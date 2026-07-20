# synapse-common

Shared data contracts between `synapsed-helper` (root) and `synapse-agent` (unprivileged). **Zero logic — just types.** Both crates depend on this without pulling in engine internals.

## File map

| File | Lines | What it contains |
|---|---|---|
| `src/lib.rs` | 75 | `EnforcementCommand` enum, `PacketInfo` struct, `EnforcementBackend` trait, protocol constants, re-exports from `types.rs` |
| `src/types.rs` | 62 | `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport` |
| `Cargo.toml` | 8 | Package definition + dependencies |

## Dependencies

- `serde` 1.x (with `derive` feature) — serialization for IPC (bincode) and storage
- `bincode` 1.x — binary serialization format for IPC messages

## Types

### `EnforcementCommand` (lib.rs:24-36)
Enum — the **only** shape enforcement commands can take between agent → helper. Typed `IpAddr`/`Duration` only, never strings.

```rust
pub enum EnforcementCommand {
    Block { ip: IpAddr, ttl: Duration },
    Unblock { ip: IpAddr },
    KillState { src: IpAddr, dst: IpAddr, proto: u8 },
}
```

### `PacketInfo` (lib.rs:42-50)
Basic packet metadata extracted from raw frames.

```rust
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub length: u16,
}
```

### `ValidatedBlock` (types.rs:18-22)
A validated, safe-to-enforce block request. Constructed only through a validation path the caller can't bypass.

```rust
pub struct ValidatedBlock {
    pub ip: IpAddr,
    pub ttl: Duration,
}
```

### `BlockId` (types.rs:26-33)
Unique identifier for an active block. Currently wraps an `IpAddr`.

```rust
pub struct BlockId(pub IpAddr);
impl From<IpAddr> for BlockId { ... }
```

### `DesiredFirewallState` (types.rs:38-41)
The complete set of blocks the agent wants enforced. Used as source of truth for reconciliation (§4a).

```rust
pub struct DesiredFirewallState {
    pub blocks: Vec<ValidatedBlock>,
}
```

### `EnforcementReceipt` (types.rs:44-49)
Result of applying or removing a block.

```rust
pub struct EnforcementReceipt {
    pub block_id: BlockId,
    pub success: bool,
    pub message: String,
}
```

### `ReconciliationReport` (types.rs:54-62)
Result of a reconciliation pass (§4a/§4c). Currently only used as a stub default.

```rust
pub struct ReconciliationReport {
    pub re_applied: usize,
    pub evicted: Vec<BlockId>,
    pub errors: Vec<String>,
}
```

## Trait

### `EnforcementBackend` (lib.rs:70-75)
The enforcement contract. Only implementer: `MacOsEnforcementBackend` in `platform-macos/src/helper/enforce.rs`.

```rust
pub trait EnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
    fn reconcile(&mut self, desired: &DesiredFirewallState)
        -> Result<ReconciliationReport, String>;
}
```

## Constants

| Name | Value | Purpose |
|---|---|---|
| `IPC_MAGIC` | `[89, 89, 78, 80]` (`SYNP`) | Magic bytes preceding every IPC message |
| `IPC_VERSION` | `1` | IPC protocol version, bump on breaking changes |
