# synapse-common — context

Zero-logic crate. Shared types and traits between helper (root) and agent (unprivileged).

## Files

| File | Contains |
|---|---|
| `src/lib.rs` | `EnforcementCommand` enum, `PacketInfo` struct, `EnforcementBackend` trait, `IPC_MAGIC`/`IPC_VERSION` constants, re-exports from `types.rs` |
| `src/types.rs` | `ValidatedBlock{ip: IpAddr, ttl: Duration}`, `BlockId(IpAddr)`, `DesiredFirewallState{blocks: Vec<ValidatedBlock>}`, `EnforcementReceipt{block_id, success, message}`, `ReconciliationReport{re_applied, evicted, errors}` |

## Dependencies

`serde` 1.x (derive), `bincode` 1.x

## EnforcementBackend trait (§4c)

```rust
fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
fn reconcile(&mut self, desired: &DesiredFirewallState) -> Result<ReconciliationReport, String>;
```

Only implementer: `MacOsEnforcementBackend` in `platform-macos/src/helper/enforce.rs`.
