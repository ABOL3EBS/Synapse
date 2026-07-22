# synapse-common — context

Zero-logic crate. Shared types and traits between helper (root) and agent (unprivileged).

## Files

| File | Contains |
|---|---|
| `src/lib.rs` | `EnforcementCommand` enum, `PacketInfo` struct, `EnforcementBackend` trait, `IPC_MAGIC`/`IPC_VERSION` constants, re-exports from `types.rs` |
| `src/types.rs` | All shared types (see below) |

## Types (`src/types.rs`)

| Type | Purpose |
|---|---|
| `ValidatedBlock{ip, ttl}` | Validated block command with TTL |
| `BlockId(IpAddr)` | Unique block identifier |
| `DesiredFirewallState{blocks}` | Set of desired blocks for reconciliation |
| `EnforcementReceipt{block_id, success, message}` | Result of enforcement action |
| `ReconciliationReport{re_applied, evicted, errors}` | Result of reconcile() |
| `PortPidCache{entries, pid_count, fd_count, socket_count, probe_ok, elapsed}` | Helper→agent port→PID mapping |
| `PortPidEntry{port, proto, pid}` | Single cache entry (for serialization) |
| `IpcMessage` enum | `PortPidCache(PortPidCache)` — all IPC messages |
| `EnrichmentRequest{flow_id, src/dst_ip, src/dst_port, protocol, pid, kinds}` | Agent→enrichment worker request |
| `EnrichmentResult{flow_id, kind, success, dns_name, process_path, ...}` | Enrichment worker→agent result |
| `EnrichmentKind` enum | `DnsReverse`, `ProcessAttribution`, `GeoIp`, `Reputation` |

## EnforcementBackend trait (§4c)

```rust
fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
fn kill_state(&mut self, src: IpAddr, dst: IpAddr, proto: u8) -> Result<EnforcementReceipt, String>;
fn reconcile(&mut self, desired: &DesiredFirewallState) -> Result<ReconciliationReport, String>;
```

Only implementer: `MacOsEnforcementBackend` in `platform-macos/src/helper/enforce.rs`.

## Dependencies

`serde` 1.x (derive), `bincode` 1.x
