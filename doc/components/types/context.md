# Types — Shared Data Contracts + EnforcementBackend Trait

Zero-logic crate. Everything here is types, traits, and constants — no implementation.

## Code location

- `crates/common/src/lib.rs` (81 lines) — `EnforcementCommand`, `PacketInfo`, `EnforcementBackend` trait, IPC constants
- `crates/common/src/types.rs` (62 lines) — `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `EnforcementReceipt`, `ReconciliationReport`

## EnforcementCommand (wire format)

```rust
pub enum EnforcementCommand {
    Block { ip: IpAddr, ttl: Duration },
    Unblock { ip: IpAddr },
    KillState { src: IpAddr, dst: IpAddr, proto: u8 },
}
```

Sent from agent → helper via bincode IPC. All typed fields — no strings.

## PacketInfo (parsed packet metadata)

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

Populated by agent's IPv4/IPv6 parsers from raw BPF frames.

## EnforcementBackend trait

```rust
pub trait EnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
    fn kill_state(&mut self, src: IpAddr, dst: IpAddr, proto: u8) -> Result<EnforcementReceipt, String>;
    fn reconcile(&mut self, desired: &DesiredFirewallState) -> Result<ReconciliationReport, String>;
}
```

Enforces typed data + argv execution guarantees. Only implementer: `MacOsEnforcementBackend` in `platform-macos/src/helper/enforce.rs`.

## Shared types (types.rs)

| Type | Purpose |
|---|---|
| `ValidatedBlock { ip: IpAddr, ttl: Duration }` | Validated, safe-to-enforce block request |
| `BlockId(IpAddr)` | Unique handle for active blocks (newtype, Hash + Eq) |
| `DesiredFirewallState { blocks: Vec<ValidatedBlock> }` | Complete set of blocks agent wants enforced |
| `EnforcementReceipt { block_id, success, message }` | Return type for apply/remove/kill |
| `ReconciliationReport { re_applied, evicted, errors }` | Return type for reconcile (currently stub) |

## IPC constants

- `IPC_MAGIC: [u8; 4] = *b"SYNP"` — framing magic
- `IPC_VERSION: u8 = 1` — protocol version

## Dependencies

`serde` 1.x (derive), `bincode` 1.x — nothing else. This crate must stay zero-logic.
