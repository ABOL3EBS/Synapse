# Synapse IPS — Code Audit

**Mode:** Linus Torvalds, Linux 2007. No sugarcoating. No "great progress." Just code.

---

## Verdict: Architecturally sound, operationally immature. The bones are good. The plumbing has real leaks. Several things that look finished aren't.

---

## 1. Things that are genuinely good

**The privilege separation model is correct and stays correct.** Root opens BPF, hands fd via SCM_RIGHTS, drops its copy. Agent never touches `/dev/bpf*`. Enforcement flows through a single trait with a single implementor that shells out to `pfctl` via argv, never a shell. This is the one thing that *must* be right in an IPS, and it is.

**Typed IPC is the right call.** `IpAddr`, `Duration`, `u8` — no string interpolation at the enforcement boundary. Shell injection is structurally impossible. This isn't clever, it's correct. The fact that you got Bug #1 (pass out vs block out) in Milestone 1 proves the point: typed data prevents injection, but it doesn't prevent logic bugs. You still need to test the actual blocking behavior, which you didn't do with a real IP until someone caught it.

**FlowKey canonicalization is correct.** Direction-agnostic keys with `(ip, port)` as bound pairs. Forward and response produce the same key. The `local_port` stored separately is the right design — canonicalization discards direction, but PID attribution needs it. The tests prove it.

**The detector timeout mechanism works.** `run_detector_with_timeout()` spawns a thread, uses `recv_timeout()`, returns `TimedOut` without waiting. The 500ms sleeper with 50ms budget test proves it. This is the right pattern for pluggable detectors that could be untrusted or buggy.

**Decision engine scoring is correct for v1.** Weighted: `score × confidence × status_weight`. TimedOut at 0.1x, Errored at 0.0x. TTL from most severe Completed finding, clamped. Simple, testable, and the 11 unit tests cover the edge cases.

---

## 2. Things that are broken or will bite you

### 2a. The TTL auto-unblock thread is a time bomb

`enforce.rs:105` — every `apply_block()` spawns an OS thread that sleeps for the TTL duration, then calls `unblock_ip()`. No cap. No tracking. No cancellation.

The problem: if you call `apply_block()` twice for the same IP (which the idempotent check catches), you only spawn one timer. But if the IP is unblocked via `remove_block()` and then re-blocked, the *old* timer is still sleeping. When it fires, it unblocks the IP prematurely.

```rust
// enforce.rs:87-94 — the dedup check
if self.active_blocks.contains(&block.ip) {
    Self::block_ip(block.ip)?;
    return Ok(...);
}
```

This dedup is correct for the happy path. But `remove_block()` removes from `active_blocks` without cancelling the timer thread. The next `apply_block()` creates a new timer — but the old one is still sleeping in the background. When it fires, it calls `unblock_ip()` on an IP that's now blocked again.

**Impact:** Blocks can silently expire early. An attacker who triggers remove-then-add wins.

**Fix:** Each `apply_block()` must return a cancellation handle (e.g. an `Arc<AtomicBool>` that the timer thread checks before calling `unblock_ip()`). Or use a single timer-wheel thread with a channel, as the code comment already suggests.

### 2b. The capture loop is a single-threaded bottleneck with a lock on every packet

`main.rs:567-591` — on every single packet, you:
1. Lock `port_pid_cache` (Arc<Mutex<...>>)
2. Lock `local_ip_cache` (Arc<Mutex<Option<IpAddr>>>)
3. Call `determine_local_port()`
4. Call `tracker.update()` (mutable borrow on FlowTracker)
5. For new flows, call `enrich_pool.dispatch()` (sends to channel)
6. At end of iteration, call `enrich_pool.drain_results()` and `tracker.attach_enrichment()` (mutable borrow again)

At 10k pkt/s, this is fine. At 100k pkt/s (a burst of DNS amplification traffic), the Mutex contention on `port_pid_cache` becomes measurable. The `drain_results()` at the end of the loop is O(n) where n is pending results — if enrichment is slow and results pile up, this grows unbounded per iteration.

This is acceptable for v1 but will need to be an MPSC channel or a lock-free structure before any real throughput claim.

### 2c. `run_detector_with_timeout` leaks threads on timeout

`types.rs:408-415` — when a detector times out, the spawned thread keeps running. Its result is dropped. If the detector is doing I/O (DNS lookup, file read), that thread lives until the I/O completes or the process exits.

At one detector per flow per evaluation, with 1s re-evaluation interval and 100k flows, you could have 100k leaked threads in a worst case. In practice the RuleDetector is instant, so this doesn't trigger. But the architecture claims ONNX model inference is coming — a model that takes 500ms to run would create 500ms zombie threads on every 1s tick.

**Fix:** `catch_unwind` around `evaluate()` (you already know this), plus a mechanism to actually *kill* the detector thread on timeout — or at minimum, track leaked thread count and alert.

### 2d. Eviction in FlowTracker is O(n)

`flow/mod.rs:292` — `evict_oldest()` iterates the entire HashMap to find the flow with minimum `first_seen`. At MAX_FLOWS=100,000, that's 100k comparisons on every eviction. Under sustained overflow (attacker sending unique 5-tuples faster than 5s expiry reclaims them), this becomes a hot path.

**Fix:** Use a `BTreeMap<Instant, u64>` or a min-heap for eviction candidates. O(log n) instead of O(n).

### 2e. Re-evaluation iterates the entire HashMap

`flow/mod.rs:268` — `tick()` iterates all flows to find those where `now - last_evaluated >= 1s`. At 100k flows, that's 100k comparisons every 100ms (the poll timeout). You cap the *output* at `MAX_RE_EVAL_PER_TICK=100`, but you still iterate everything to find them.

**Fix:** A timing wheel or a `VecDeque<(Instant, u64)>` sorted by `last_evaluated`. O(1) amortized per tick.

---

## 3. Design smells

### 3a. `EnrichmentResult` is a god struct

Every enrichment kind shares the same struct with 10 fields. DNS fills `dns_name`, process fills `process_path`, GeoIP fills `country_code`, reputation fills `reputation_score`. Everything else is `None`. This is a C-style "bag of everything" — the opposite of what you'd do in Rust.

```rust
pub struct EnrichmentResult {
    pub flow_id: u64,
    pub kind: EnrichmentKind,
    pub success: bool,
    pub dns_name: Option<String>,       // only DnsReverse
    pub process_path: Option<String>,    // only ProcessAttribution
    pub process_start_time: Option<f64>, // only ProcessAttribution
    pub country_code: Option<String>,    // only GeoIp
    pub asn: Option<u32>,                // only GeoIp
    pub reputation_score: Option<f32>,   // only Reputation
    pub error: Option<String>,
}
```

A tagged union or separate result types per kind would be more idiomatic and prevent accidentally reading `country_code` from a DNS result. But this is cosmetic for v1 — the real cost is serialization overhead (bincode serializes all None fields).

### 3b. `FlowRecord` exists in two places with different fields

`common::types::FlowRecord` (passed to detectors) has `country_code`, `pid`, `local_port`. `flow::FlowRecord` (internal to the tracker) has `first_seen`, `last_seen`, `last_evaluated`, `process_start_time`. The agent manually converts between them at `main.rs:425-440` and `main.rs:465-480` — the exact same 15-line struct literal copy-pasted twice.

This is the kind of thing that silently drifts apart when someone adds a field to one and forgets the other. A `From` impl or a single type would be better.

### 3c. The `report.md` file counts are stale

`report.md:199-208` says `common/src/types.rs` is 150 lines. It's actually 438. Says `agent/src/main.rs` is 772 lines. It's 819. Says `agent/src/flow/mod.rs` is 574 lines. It's 898. The report hasn't been updated since it was written — it's documentation that lies about the codebase it documents.

### 3d. Magic constants without names

`helper/main.rs:31-33`:
```rust
const PF_ANCHOR_NAME: &str = "com.synapse.ips";
const PF_TABLE_NAME: &str = "synapse_blocklist";
const IPC_SOCKET_PATH: &str = "/tmp/synapse-helper.sock";
```

`enforce.rs:18-19` duplicates the same constants:
```rust
const PF_ANCHOR_NAME: &str = "com.synapse.ips";
const PF_TABLE_NAME: &str = "synapse_blocklist";
```

These should live in `common` and be imported, not duplicated. If someone changes the anchor name in one file and not the other, the helper and enforcement backend disagree silently.

### 3e. The `TEST_TARGET_IP` hardcoded block is a test artifact that's still in production code

`main.rs:33-34`:
```rust
const TEST_TARGET_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
const BLOCK_TTL: Duration = Duration::from_secs(300);
```

And `main.rs:638-649` — if a packet matches `TEST_TARGET_IP`, send a Block command. This is milestone 1 testing code that will never be removed unless someone explicitly removes it. It's not behind a feature flag or a config check. It's just... there.

---

## 4. Security considerations

### 4a. The IPC socket at `/tmp/synapse-helper.sock` with mode 0666

`helper/main.rs:303` — `chmod 0666` so the unprivileged agent can connect. Any local process can connect to this socket and send `EnforcementCommand::Block { ip: ..., ttl: ... }` or `KillState` commands. The socket is authenticated by nothing — not credentials, not a shared secret, not a PID check.

On a single-user Mac this is probably fine. On a multi-user system or if the machine is compromised, any process can manipulate the firewall.

**Mitigation for v1:** Use `SCM_CREDENTIALS` (Linux-only, doesn't exist on macOS) or check the connecting process's UID. macOS doesn't have `SO_PEERCRED`. The pragmatic fix: `fchmod(0600)` instead of `0666`, and have the agent connect before the chmod, or use a pre-created socket with restricted permissions.

### 4b. `bincode` deserialization without size limits on the receiving side

`protocol.rs:101-102` — `recv_message` reads a `u32` length, checks it's under 1MB, then allocates and reads that many bytes. The 1MB cap is good. But `bincode::deserialize` on the payload has no capacity limits — a crafted payload could create deeply nested types that consume stack on deserialization. In practice this isn't exploitable because the types are flat enums/structs, but it's worth noting.

### 4c. No IPC_MAGIC validation on receive

`protocol.rs:98-111` — `recv_message` reads length + payload and deserializes. It never checks the `SYNP` magic bytes. The constants are defined in `common/src/lib.rs:77` but never used. If a stray connection hits the socket, `bincode::deserialize` will either succeed (wrong data, wrong type) or return an error — but the error is generic, not "wrong magic."

---

## 5. Things the documentation claims that aren't true

- `doc/STATUS.md` says "Total: 4,838 lines across 11 files." The actual count is ~4,838 across 12 source files (I counted `flow/mod.rs`, `detectors/mod.rs`, `decision/mod.rs` as separate files — the STATUS.md doesn't list detectors or decision modules in the table).

- `doc/report.md` file inventory (line 199-208) has wrong line counts for 3 files as noted above.

- `opencode.md` says "47 tests pass" — this is currently correct (41 agent + 6 platform-macos), but the file says `doc/report.md` has "full architecture, bug history, struct layouts, and testing methodology" — the testing methodology section is a table of "verified" results, not an actual methodology description.

---

## 6. What you should fix before calling this anything other than a prototype

| Priority | Issue | Effort |
|---|---|---|
| **P0** | TTL timer race (remove-then-add loses the old timer) | Medium — needs cancellation handle |
| **P0** | Socket 0666 permissions (any local process can manipulate firewall) | Small — fchmod to 0600 or pre-authenticate |
| **P1** | `run_detector_with_timeout` thread leaks (no `catch_unwind`) | Small |
| **P1** | Deduplicate PF_ANCHOR_NAME / PF_TABLE_NAME constants | Trivial |
| **P1** | Remove TEST_TARGET_IP test code from production path | Trivial |
| **P2** | Eviction O(n) → O(log n) with min-heap | Medium |
| **P2** | Re-evaluation iteration O(n) → timing wheel | Medium |
| **P2** | Duplicate FlowRecord struct / copy-paste conversion | Small |
| **P3** | EnrichmentResult god struct → tagged union | Small |
| **P3** | Update stale line counts in report.md | Trivial |

---

## 7. Bottom line

The architecture is right. Privilege separation, typed IPC, pluggable detectors, async enrichment — these are the correct abstractions. The code is clean, well-organized, and the test suite covers the real code paths (not just happy-path mocks).

But this is a 4-day-old prototype that's being documented like it's a finished product. The `doc/` directory has more words than the `src/` directory. The `STATUS.md` reads like a press release. The `report.md` has stale line counts that nobody updated.

The TTL timer race is a real bug that will cause blocks to silently expire early. The socket permissions are a real security hole. The thread leaks are a real resource exhaustion vector. These aren't "known shortcomings" — they're bugs.

Ship the fixes for P0 and P1. Then go build something that isn't a demo.
