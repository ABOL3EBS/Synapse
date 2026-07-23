# Synapse IPS — Code Audit v2 (Post-Fix Re-Audit)

**Mode:** Linus Torvalds, Linux 2007. Same rules. No carryover credit.

**Date:** 2026-07-25
**Baseline:** 47 tests pass. 4,903 lines across 11 files. clippy clean. fmt clean.

---

## Verdict: Fixes landed cleanly. Architecture still holds. Three issues remain from v1, one was incorrectly claimed fixed.

**Score: 7 / 10**

Up from v1 (which I'd have scored 5/10 — architecturally sound but operationally broken in several places). The fixes are real, not cosmetic. But the score doesn't go higher because one P1 fix from v1 was incorrectly claimed as done, and the remaining issues are genuine security and correctness gaps, not just polish.

---

## 1. What was fixed (9 items — all verified)

### Fix 1: Constant deduplication — clean

`common/src/lib.rs:87-93` now owns `PF_ANCHOR_NAME`, `PF_TABLE_NAME`, `IPC_SOCKET_PATH`. Both `helper/main.rs` and `enforce.rs` import from `synapse_common`. Grep confirms zero inline duplicates. Single source of truth, zero risk of silent drift.

### Fix 2: Dead code removal — clean

`TEST_TARGET_IP`, `BLOCK_TTL`, `blocked: HashSet`, the `EnforcementCommand` import, and the entire hit-detection block are gone from `agent/main.rs`. Grep confirms zero references. The agent is now a clean packet-processing engine with no test artifacts in the production path.

### Fix 3: Stale documentation — clean

`STATUS.md` and `report.md` line counts now match `wc -l` for all 11 files. Total corrected from 4,816 to 4,903. Dates updated. Both file inventory tables in `report.md` corrected. Test count updated from 33 to 47.

### Fix 4: `catch_unwind` in `run_detector_with_timeout()` — partially fixed

`types.rs:414-428` wraps `evaluate()` in `catch_unwind(AssertUnwindSafe(...))`. Panic payloads downcast to `&str`/`String` and sent as `DetectorFinding::errored()`. The `version_clone` variable avoids a move-after-use. Correct panic safety implementation.

**But:** the thread leak on timeout is NOT fixed. The original audit explicitly identified two problems: (1) no `catch_unwind`, and (2) threads leak on timeout. Only (1) was addressed. See section 2a.

### Fix 5: Socket permissions 0666 to 0660 — clean

`helper/main.rs:299` uses `set_permissions(..., from_mode(0o660))`. Comment updated to explain group-rw only. Reduces attack surface from "any local process" to "any process in the socket's group (wheel)." On single-user Mac, effectively agent-only. On multi-user system, real improvement. See section 2b for remaining auth gap.

### Fix 6: TTL cancellation via AtomicBool — correct, but race window remains

`enforce.rs:26,112-124` stores `cancel_handles: HashMap<IpAddr, Arc<AtomicBool>>`. `apply_block()` stores the flag, TTL thread checks `cancelled.load(Ordering::Relaxed)` after sleep. `remove_block()` sets the flag before calling `unblock_ip()`.

The dedup check at `enforce.rs:91` prevents two timers for the same IP, eliminating the most common race scenario. The `Relaxed` ordering is correct for this single-writer pattern. But see section 2c for the remaining remove-then-add race.

### Fix 7: `From<flow::FlowRecord>` impl — clean

`flow/mod.rs:159-177` implements `From<FlowRecord> for synapse_common::FlowRecord`. Both conversion sites in `main.rs:415,440` use `.clone().into()`. The clone is necessary because `flow_ref` is borrowed for `first_seen.elapsed()` before the owned conversion. Eliminates the 15-line struct literal copy-paste that could silently drift.

### Fix 8: O(log n) eviction via BinaryHeap — clean

`flow/mod.rs:193,331-349` uses `BinaryHeap<Reverse<(Instant, u64)>>` for eviction candidates. `evict_oldest()` pops with lazy deletion of stale entries (flows already removed by tick expiry). O(log n) amortized. Stale entries accumulate in the heap until eviction — worst case 2x MAX_FLOWS entries before cleanup. Acceptable for v1.

### Fix 9: Batched re-evaluation scan — clean

`flow/mod.rs:299-313` uses `tick_count` incremented every tick, scan runs every 10th tick (~1s at 100ms poll timeout). Bounds per-tick cost to O(expiry) only. The scan still iterates the HashMap (non-deterministic), but only once per second instead of ten times per second. MAX_RE_EVAL_PER_TICK=100 caps the output. Starvation risk reduced, not eliminated — a flow with a very high ID could still wait longer than 1s.

---

## 2. What is still broken or will bite you

### 2a. Thread leak on timeout — incorrectly claimed fixed

The original audit identified two problems in `run_detector_with_timeout`:
1. No `catch_unwind` — fixed
2. Threads leak on timeout — NOT fixed

`types.rs:444-448`:
```rust
Err(mpsc::RecvTimeoutError::Timeout) => {
    let latency_us = start.elapsed().as_micros() as u64;
    DetectorFinding::timed_out(id, &version, latency_us)
}
```

When a detector times out, the spawned thread keeps running. Its result is dropped (the receiver is dropped, so `tx.send(finding)` at line 432 fails silently). The thread lives until the detector function returns or the process exits.

At one detector per flow per evaluation, with 1s re-evaluation interval and 100k flows, worst case is 100k zombie threads. In practice, `RuleDetector::evaluate()` is instant (<1 microsecond), so this never triggers with the current detector.

But the architecture claims ONNX model inference is coming. A model that takes 500ms would create 500ms zombie threads on every 1s tick. At 1000 active flows, that is 1000 zombie threads per second.

**Fix options:**
- `thread::JoinHandle` + kill: unreliable on macOS (no `pthread_cancel`)
- Accept the leak + add a counter for leaked thread count, log warning at threshold
- Reduce re-evaluation interval for slow detectors (configurable per-detector budget)
- Best v1 fix: add `leaked_thread_count: AtomicU64` to a global, increment on timeout, alert if count grows monotonically

### 2b. IPC socket has no authentication

`helper/main.rs:299` sets 0660. Any process in the wheel group can connect and send `EnforcementCommand::Block`, `Unblock`, or `KillState` commands. No credentials check, no shared secret, no PID verification.

macOS does not have `SO_PEERCRED` (Linux-only). `SCM_CREDENTIALS` does not exist on macOS.

On a single-user Mac, this is fine — the agent and helper run as the same user. On a multi-user system, any wheel-group process can manipulate the firewall.

**Mitigation for v1:** The socket path is predictable (`/tmp/synapse-helper.sock`), permissions are 0660. An attacker needs local wheel-group access. This is an acceptable threat model for a single-user desktop IPS. Document it.

**v2 fix:** Use a per-session shared secret (random bytes generated at helper startup, passed to agent via an environment variable or a file with restricted permissions). Agent sends the secret as the first message after connecting. Helper validates before accepting any commands.

### 2c. TTL timer race — remove-then-add still possible

The dedup check at `enforce.rs:91` prevents two timers for the same IP. But consider this sequence:

```
T=0:   apply_block(X, ttl=30s) — timer A spawned, sleeping, cancel_handle_A stored
T=10:  remove_block(X) — sets cancel_handle_A to true, unblocks X, removes from active_blocks
T=11:  apply_block(X, ttl=30s) — NEW timer B spawned, cancel_handle_B stored
T=30:  timer A wakes up — checks cancel_handle_A — it IS true (set at T=10) — skips unblock. Correct!
```

Wait — actually this is fine. `remove_block` at T=10 sets the flag on the OLD handle (cancel_handle_A). Timer A checks cancel_handle_A at T=30 and sees true. No race.

The actual problematic scenario requires the old handle to be replaced before remove_block runs:

```
T=0:   apply_block(X, ttl=30s) — timer A spawned, cancel_handle_A stored
T=10:  remove_block(X) — removes cancel_handle_A from HashMap, sets it to true, unblocks X
T=10:  (timer A is still sleeping with a clone of cancel_handle_A)
T=11:  apply_block(X, ttl=30s) — NEW cancel_handle_B stored, timer B spawned
T=30:  timer A wakes up — its cancel_handle_A WAS set to true at T=10 — skips unblock. Correct!
```

This is actually safe because `Arc::clone` at line 113 gives the timer its own reference to the same `AtomicBool`. `remove_block` sets the original to true via `self.cancel_handles.remove(&ip)`. The timer's clone sees the same `true`.

**Re-analysis: the TTL race is actually fixed.** The `Arc<AtomicBool>` shared between `remove_block` and the timer thread is the correct mechanism. The `cancel_handles` HashMap is just a registry — the real synchronization happens through the `Arc`.

I was wrong in the initial analysis. Let me re-verify:

1. `apply_block` creates `Arc::new(AtomicBool::new(false))`, stores clone in `cancel_handles`, moves another clone to the timer thread.
2. `remove_block` calls `self.cancel_handles.remove(&ip)` which returns the Arc, then sets it to `true`.
3. The timer thread holds its own Arc clone. When it wakes and calls `cancelled.load()`, it sees `true` because both Arcs point to the same `AtomicBool`.

This is correct. The race I described in v1 is actually fixed. The only remaining concern is if `remove_block` is called *after* the timer thread has already started executing `unblock_ip()` — but that is a benign race (double-unblock is harmless for pfctl table delete).

**Updated assessment: TTL race is FIXED.** My initial re-audit incorrectly carried over the v1 concern without re-verifying the Arc sharing semantics.

---

## 3. Design smells (carried from v1, not fixed)

### 3a. `EnrichmentResult` is a god struct

Every enrichment kind shares the same 10-field struct. DNS fills `dns_name`, process fills `process_path`, GeoIP fills `country_code`. Everything else is `None`. A tagged union or separate types per kind would be more idiomatic. Cosmetic for v1 — the real cost is bincode serializing all None fields, which is negligible.

### 3b. No IPC magic validation on receive

`protocol.rs:98-112` reads length + payload and deserializes. It never checks the `SYNP` magic bytes defined in `common/src/lib.rs:77`. A stray connection would produce a bincode deserialization error, not "wrong magic." Low risk — the socket has restricted permissions, and bincode errors are loud. Missed defense-in-depth layer.

### 3c. `bincode` deserialization without capacity limits

`protocol.rs:110` — `bincode::deserialize` has no capacity limits. The 1MB buffer cap prevents memory exhaustion from the length prefix, but a crafted payload could create deeply nested types that consume stack during deserialization. Types are flat enums/structs — not exploitable in practice.

### 3d. No circuit breaker for failing detectors

`detectors/mod.rs:144-164` retries all detectors every interval regardless of failure history. A consistently-errored or consistently-timed-out detector wastes thread budget. Fix: per-detector `consecutive_failures` counter, skip after 5 failures.

### 3e. Decision engine has no uncertainty/findings_summary

`Verdict::Block` and `Verdict::Alert` have `reason: String` but no `uncertainty: f32` field and no per-finding evidence summary. For the dashboard audit trail, you need to know not just "blocked" but "how confident was the system." v2 requirement.

### 3f. All config is hardcoded

Block/alert thresholds, TTLs, detector budgets are constants in `DecisionConfig`. No TOML/YAML config file. Tuning requires recompilation. Fine for a prototype.

---

## 4. What the code does well (carried from v1, still true)

- **Privilege separation is correct.** Root opens BPF, hands fd, drops copy. Agent never touches `/dev/bpf*`. Enforcement flows through one trait with one implementor. This is the one thing that must be right, and it is.

- **Typed IPC is the right call.** `IpAddr`, `Duration`, `u8` — no string interpolation at the enforcement boundary. Shell injection is structurally impossible.

- **FlowKey canonicalization is correct.** Direction-agnostic, `(ip, port)` as bound pairs. Tests prove it.

- **Decision engine scoring is correct for v1.** Weighted, clamped, testable. 11 unit tests cover edge cases.

- **The detector timeout mechanism works.** `recv_timeout()` returns `TimedOut` without waiting. The 500ms sleeper with 50ms budget test proves it. `catch_unwind` handles panics. Only gap is the zombie thread.

- **The enrichment pipeline never blocks the hot path.** Dispatched on flow creation, results attached non-blocking. Correct architecture for an IPS — parsing and detection must never wait for DNS.

- **Test coverage is real.** 47 tests, not happy-path mocks. Flow tracker tests prove canonicalization, eviction, tick cadence, and re-evaluation bounds. Detector tests prove timeout and panic safety. Decision tests prove scoring thresholds.

---

## 5. Updated priority table

| Priority | Issue | Effort | Status |
|---|---|---|---|
| ~~P0~~ | ~~TTL timer race~~ | ~~Medium~~ | FIXED — Arc shared AtomicBool correctly eliminates the race |
| ~~P0~~ | ~~Socket 0666 permissions~~ | ~~Small~~ | Fixed — 0660 |
| ~~P1~~ | ~~catch_unwind in detector timeout~~ | ~~Small~~ | Fixed |
| ~~P1~~ | ~~Deduplicate PF_ANCHOR_NAME~~ | ~~Trivial~~ | Fixed |
| ~~P1~~ | ~~Remove TEST_TARGET_IP~~ | ~~Trivial~~ | Fixed |
| ~~P2~~ | ~~Eviction O(n) to O(log n)~~ | ~~Medium~~ | Fixed via BinaryHeap |
| ~~P2~~ | ~~Re-evaluation O(n) to batched~~ | ~~Medium~~ | Fixed via tick_count |
| ~~P2~~ | ~~Duplicate FlowRecord conversion~~ | ~~Small~~ | Fixed via From impl |
| ~~P3~~ | ~~Update stale line counts~~ | ~~Trivial~~ | Fixed |
| **P1** | Thread leak on timeout (zombie threads) | Medium | NOT FIXED — catch_unwind handles panic, not timeout |
| **P1** | IPC socket has no authentication | Medium | NOT FIXED — 0660 helps but no credentials |
| **P2** | `drain_results()` unbounded | Small | Bounded in practice, not in code |
| **P3** | No IPC magic validation on receive | Trivial | Defined but unused |
| **P3** | No circuit breaker for failing detectors | Small | Known limitation |
| **P3** | EnrichmentResult god struct | Small | Cosmetic for v1 |
| **P3** | All config is hardcoded | Small | Fine for prototype |

---

## 6. Bottom line

The 9 fixes are real. The architecture is still correct. The code is clean, well-organized, and the test suite covers the real code paths.

What changed from v1:
- The P0 security issue (socket permissions) is addressed.
- The P0 correctness issue (TTL race) is fully fixed — my initial re-audit incorrectly carried over the v1 concern.
- The P1 panic safety issue is fixed.
- The P1 dead code and constant duplication are cleaned up.
- The P2 performance issues (eviction, re-evaluation) are resolved.
- Documentation is accurate.

What did not change:
- The thread leak on timeout was incorrectly claimed fixed. `catch_unwind` handles panics, not timeouts. The zombie thread problem is still real — it just does not trigger with the current instant-evaluating `RuleDetector`.
- The IPC socket still has no authentication beyond Unix permissions.

**Score: 7/10** — Good prototype, honest about its limitations, but not production-ready. The thread leak and socket authentication are the two issues that must be fixed before any real deployment. Everything else is v2 polish.

Ship the thread leak fix and the socket auth. Then go build something that is not a demo.
