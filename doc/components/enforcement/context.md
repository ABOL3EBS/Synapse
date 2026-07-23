# Enforcement — pf Anchor Management + pfctl Execution

Only code that calls `pfctl`. All via `Command::new("pfctl").args([...])` — never shell.

## Code location

- `crates/platform-macos/src/helper/enforce.rs` (196 lines) — `MacOsEnforcementBackend`
- `crates/platform-macos/src/helper/main.rs` (482 lines) — `ensure_anchor()`, reconnect loop

## EnforcementBackend trait (common/src/lib.rs)

```rust
pub trait EnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt, String>;
    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt, String>;
    fn kill_state(&mut self, src: IpAddr, dst: IpAddr, proto: u8) -> Result<EnforcementReceipt, String>;
    fn reconcile(&mut self, desired: &DesiredFirewallState) -> Result<ReconciliationReport, String>;
}
```

Only implementer: `MacOsEnforcementBackend` in `enforce.rs`.

## Methods

| Method | pfctl command | Notes |
|---|---|---|
| `apply_block()` | `pfctl -a com.synapse.ips -t synapse_blocklist -T add <ip>` | Idempotent — dedup in HashSet, keeps original TTL |
| `remove_block()` | `pfctl -a com.synapse.ips -t synapse_blocklist -T delete <ip>` | Removes from active_blocks |
| `kill_state()` | `pfctl -k <src> -k <dst>` | Kills all states for src→dst pair (no protocol filter) |
| `reconcile()` | Stub | Returns `ReconciliationReport::default()` |

## apply_block() dedup logic

If IP already in `active_blocks`: re-issue `block_ip()` (idempotent), do NOT spawn a second timer. Two timers = whichever fires first unblocks it, losing the intended duration.

## kill_state() notes

`pfctl -k` does NOT filter by protocol — kills all states (TCP, UDP, etc.) for the src/dst pair. The `proto` field is kept for logging and future use.

## Anchor lifecycle (ensure_anchor)

```
1. pfctl -a com.synapse.ips -F all        (flush stale rules)
2. pfctl -a com.synapse.ips -f -           (load rules via stdin)
   table <synapse_blocklist> persist
   block out quick to <synapse_blocklist>
   block in quick from <synapse_blocklist>
3. Check /etc/pf.conf for anchor line      (idempotent)
   Append: anchor "com.synapse.ips" all    (if missing)
4. pfctl -f /etc/pf.conf                   (reload main ruleset)
5. pfctl -e                                (enable pf, reference counted)
```

## Anchor rules (current — after bug fix)

```
table <synapse_blocklist> persist          dynamic IP list
block out quick to <synapse_blocklist>     outbound TO blocked IPs blocked
block in quick from <synapse_blocklist>    inbound FROM blocked IPs blocked
```

Both directions blocked. `block in` still needed independently — stops remote hosts from initiating contact, separate attack vector from outbound C2/exfil.

## Gotchas

- Anchor must be in `/etc/pf.conf` as `anchor "com.synapse.ips" all` or pf never evaluates it
- `pfctl -e` is reference counted — safe to call multiple times
- Flush before reload (`-F all` before `-f -`) clears stale rules from previous runs
- `apply_block()` TTL auto-unblock spawns one OS thread per block — no cap in v1
- Anchor rule text is static (changes only via code deploy + helper restart). Table contents are dynamic via `block_ip()`/`unblock_ip()`.
- Helper is a persistent daemon with accept→enforce→accept loop. Agent crashes do not kill the helper. Per-connection cache-push thread is cancelled via `Arc<AtomicBool>` on disconnect.
