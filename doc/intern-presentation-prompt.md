# Replit Presentation Prompt — Synapse IPS Intern Onboarding

Use this document as the source content for building an interactive web presentation (HTML/CSS/JS or Replit-native). The presentation should have clean graphics, architecture diagrams, and clear visual hierarchy. Use a dark theme with accent colors (greens for "done", amber for "in progress", red for "not started").

---

## Presentation Title

**Synapse IPS — What's Built, What's Next**

---

## Slide 1: Title Slide

**Synapse IPS**
*A Reactive Intrusion Prevention System for macOS*

Built in Rust. Runs unprivileged. Enforces via pf firewall.

---

## Slide 2: What Is Synapse?

**Problem:** Traditional IPS requires kernel extensions or root-level packet inspection. macOS is locked down — no kernel extensions without a paid developer account.

**Solution:** Synapse uses BPF (Berkeley Packet Filter) for capture — a userspace mechanism that needs no kernel extensions. A helper daemon runs as root (opens BPF, manages pf), while all detection/decision logic runs unprivileged in the agent.

**Key insight:** Split the trust boundary. Root opens the door, unprivileged code does the thinking.

```
┌──────────────────────────────┐        ┌────────────────────────────────────┐
│  Helper (root)               │        │  Agent (unprivileged, euid 501)    │
│  • Opens /dev/bpf*           │        │  • Reads raw packets from BPF fd   │
│  • Manages pf firewall       │◀─IPC──▶│  • Parses IPv4/IPv6 headers        │
│  • Executes block/unblock    │        │  • Tracks flows (sessions)         │
│  • Runs as persistent daemon │        │  • Runs detectors (threat rules)   │
│                              │        │  • Makes decisions (allow/block)   │
└──────────────────────────────┘        └────────────────────────────────────┘
```

---

## Slide 3: Architecture Overview

**Three crates, clear separation:**

```
crates/
├── common/          # Zero logic. Shared types + traits.
│   └── 570 lines    # EnforcementCommand, PacketInfo, Detector trait, Verdict
│
├── agent/           # Unprivileged. All the intelligence.
│   └── 2,972 lines  # Packet parsing, flows, enrichment, detectors, decisions
│
└── platform-macos/  # macOS enforcement boundary.
    └── 1,458 lines  # BPF setup, pfctl, SCM_RIGHTS, process lookup
```

**Total: ~5,000 lines of Rust. 47 tests. Zero unsafe in agent.**

---

## Slide 4: The Capture Pipeline

**How a packet flows through the system:**

```
Network Card
    │
    ▼
/dev/bpf0 (BPF filter: IPv4 + IPv6 only)
    │
    ▼
Helper opens BPF as root, hands fd to agent via SCM_RIGHTS
    │
    ▼
Agent reads raw bytes from BPF fd
    │
    ▼
parse_ip_frame() → IPv4 or IPv6 header parsing
    │
    ▼
PacketInfo { src_ip, dst_ip, src_port, dst_port, protocol, length }
    │
    ▼
Flow Tracker (which session does this belong to?)
    │
    ▼
Enrichment (DNS reverse lookup, process attribution via PID)
    │
    ▼
Detectors (rule engine evaluates threat score)
    │
    ▼
Decision Engine (weighted scoring → Allow / Block / Alert)
```

**Performance:** BPF reads at 100ms poll intervals. Detection runs at ~10-20 microseconds per flow. Total pipeline: sub-millisecond per packet.

---

## Slide 5: IPC — How Helper and Agent Talk

**Two-layer protocol over Unix domain socket:**

**Layer 1: File descriptor passing (SCM_RIGHTS)**
- Helper opens `/dev/bpf0` as root
- Sends the raw file descriptor to agent via `sendmsg()` with `SCM_RIGHTS`
- Agent receives it via `recvmsg()` — now owns the BPF device
- Helper drops its copy. Agent is the sole owner.

**Layer 2: Typed messages (bincode)**
- 4-byte length prefix + bincode-serialized payload
- Commands: `Block { ip, ttl }`, `Unblock { ip }`, `KillState { src, dst, proto }`
- Data: `PortPidCache` (port→PID mapping, sent every 5s)

**Security:** Socket is `0666` (world-accessible), but `getpeereid()` verifies the connecting process UID matches the expected agent user. Wrong UID = rejected.

**Diagram:**
```
Helper                                          Agent
  │                                               │
  │──── SCM_RIGHTS (sends BPF fd) ──────────────▶│
  │                                               │
  │◀──── PortPidCache (bincode, every 5s) ────────│
  │                                               │
  │◀──── EnforcementCommand::Block ───────────────│  (when enforcement is wired)
  │                                               │
```

---

## Slide 6: Flow Tracking

**What is a flow?**
A network session — all packets between two endpoints on a specific protocol.

**FlowKey:** Direction-agnostic canonical representation.
- Forward: `192.168.1.100:50000 → 8.8.8.8:443`
- Response: `8.8.8.8:443 → 192.168.1.100:50000`
- Both produce: `FlowKey { a: (8.8.8.8, 443), b: (192.168.1.100, 50000) }`
- Canonical: smaller IP goes first.

**FlowRecord stores:**
- 5-tuple (src/dst IP, src/dst port, protocol)
- local_port (which side is local machine)
- PID (which process owns this connection)
- Packet count, byte count
- Timestamps (first_seen, last_seen, last_evaluated)
- Enrichment data (DNS name, process path, country code)

**Memory management:**
- MAX_FLOWS = 100,000 (oldest evicted on overflow via BinaryHeap)
- FLOW_EXPIRY = 5 seconds (inactive flows removed every 100ms tick)
- O(log n) eviction, not O(n)

---

## Slide 7: Enrichment Pipeline

**4-thread worker pool processes enrichment requests:**

| Type | Status | What it does |
|---|---|---|
| DNS Reverse | **Working** | `getnameinfo()` — resolves IP → hostname (e.g., `ec2-44-203-161-176.compute-1.amazonaws.com`) |
| Process Attribution | **Working** | libproc FFI — maps port → PID → executable path (e.g., `Brave Browser Helper`) |
| GeoIP | **Stub** | Returns `success: false` — needs MaxMind database |
| Reputation | **Stub** | Returns `success: false` — needs reputation feed |

**Key design decision:** Enrichment is async side-channel. Never blocks the hot packet-processing path. Results attach to flows after the fact.

**Measured:** Port→PID cache: 48-53 entries, ~420 PIDs, ~6500 fds, ~6ms build time. Well within 5s refresh budget.

---

## Slide 8: Detector Framework

**Pluggable detection architecture:**

```rust
trait Detector: Send + Sync {
    fn id(&self) -> DetectorId;
    fn version(&self) -> &str;
    fn evaluate(&self, flow: &FlowRecord) -> DetectorFinding;
}
```

**Each detector returns:**
- `score: f32` (0.0 = clean, 1.0 = malicious)
- `confidence: f32` (0.0 = guessing, 1.0 = certain)
- `severity: Low | Medium | High | Critical`
- `evidence: Vec<Evidence>` (human-readable description)
- `status: Completed | TimedOut | Errored`

**Timeout enforcement:** Each detector runs on its own thread with a configurable time budget. If it exceeds the budget → `TimedOut`. If it panics → `Errored` (via `catch_unwind`). The main pipeline never crashes.

**Current rules (placeholder v1):**
| Rule | Score | Triggers on |
|---|---|---|
| dns_blocklist | 0.8 | Flows to IPs with known malicious DNS |
| suspicious_port | 0.6 | Unusual destination ports (e.g., 4444, 5555) |
| high_packet_count | 0.4 | Flows with >10,000 packets (possible exfil) |

---

## Slide 9: Decision Engine

**Weighted scoring converts detector findings into Allow/Block/Alert:**

```
composite_score = Σ (finding.score × finding.confidence × status_weight)

status_weight:
  Completed = 1.0    (detector ran successfully)
  TimedOut  = 0.1    (detector was slow — downweight)
  Errored   = 0.0    (detector crashed — ignore)
```

**Thresholds:**
- `composite_score ≥ 0.5` → **Block** (with TTL from severity)
- `composite_score ≥ 0.2` → **Alert** (log, no enforcement)
- `composite_score < 0.2` → **Allow**

**TTL mapping:**
| Severity | TTL |
|---|---|
| Critical | 24 hours |
| High | 1 hour |
| Medium | 15 minutes |
| Low | 5 minutes |

**Currently log-only.** The decision engine produces verdicts but the agent never sends `EnforcementCommand::Block` to the helper. This is intentional — we're in observation mode until we trust the detector pipeline.

---

## Slide 10: Helper Daemon — Persistent & Resilient

**Before (v1):** Helper was one-shot. Agent crash = helper exits = system goes dark silently.

**After (current):** Helper is a persistent daemon with reconnect loop.

```
┌─────────────────────────────────────────────┐
│  Helper (root)                              │
│                                             │
│  Startup (once):                            │
│    1. Open /dev/bpf0                        │
│    2. Configure pf anchor                   │
│    3. Enable pf (pfctl -e)                  │
│    4. Create Unix socket                    │
│                                             │
│  Per-connection loop:                       │
│    5. accept() → getpeereid() → auth        │
│    6. Send BPF fd via SCM_RIGHTS            │
│    7. Spawn cache-push thread (5s)          │
│    8. Enforcement loop (recv commands)      │
│    9. Agent disconnects → cancel cache →    │
│       return to step 5                      │
└─────────────────────────────────────────────┘
```

**Verified:** 3 consecutive kill/reconnect cycles. Helper survived all. No resource leaks. Agent fd count stable (11→13→12).

---

## Slide 11: What's Done (Phase Progress)

```
Phase 1: Capture → IPC → pfctl     ████████████ 100%  ✅
Phase 2: Detection & Decision      ███████████░  90%  ✅ (log-only)
Phase 3: Enforcement Activation    ░░░░░░░░░░░░   0%  ⬜ ← NEXT
Phase 4: Hardening                 ░░░░░░░░░░░░   0%  ⬜
Phase 5: Storage                   ░░░░░░░░░░░░   0%  ⬜
Phase 6: UI Dashboard              ░░░░░░░░░░░░   0%  ⬜
Phase 7: ML Detection              ░░░░░░░░░░░░   0%  ⬜
Phase 8: Production Readiness      ░░░░░░░░░░░░   0%  ⬜
```

---

## Slide 12: What Needs To Be Done (Your Tasks)

### Phase 3: Enforcement Activation — HIGH PRIORITY

**The decision engine already says "block" but the agent never sends the command. This is the one line that flips observation mode to prevention mode.**

Task: In `crates/agent/src/main.rs`, in the decision engine match block (~line 449), add:
```rust
Verdict::Block { ttl, reason } => {
    log::warn!("BLOCK: flow {flow_id} → {dst_ip} (ttl={ttl:?}, reason={reason})");
    // TODO: Send enforcement command to helper
    // let cmd = EnforcementCommand::Block { ip: dst_ip, ttl };
    // write_half.send_message(&cmd)?;
}
```

Also needed:
- Rate limiting: don't send 1000 Block commands per second for the same IP
- Cooldown: if an IP is already blocked, don't re-block

### Phase 4: Hardening — MEDIUM PRIORITY

| Task | File | Difficulty |
|---|---|---|
| IP-keyed enrichment cache | `enrichment/mod.rs` | Medium — HashMap<IpAddr, CachedEnrichment> with TTL |
| Circuit breaker for detectors | `detectors/mod.rs` | Easy — consecutive_failures counter, skip after 5 |
| Config file (TOML) | new `config.rs` | Medium — load thresholds/TTLs from file |
| Uncertainty field in Verdict | `types.rs` + `decision/mod.rs` | Easy — add f32 field |

### Phase 5: Storage — LOW PRIORITY (future)

SQLite WAL single-writer worker for:
- Block history / audit log
- Flow history for forensics
- Enrichment cache persistence

### Phase 7: ML Detection — FUTURE

ONNX model inference. The detector framework is ready — just needs a model loaded.

---

## Slide 13: Codebase Map

**Where to find things:**

| What | File | Lines |
|---|---|---|
| Packet parsing | `agent/main.rs` | 762 |
| Flow tracking | `agent/flow/mod.rs` | 975 |
| Enrichment | `agent/enrichment/mod.rs` | 495 |
| Detectors | `agent/detectors/mod.rs` | 343 |
| Decision engine | `agent/decision/mod.rs` | 397 |
| IPC protocol | `platform-macos/protocol.rs` | 112 |
| BPF setup | `platform-macos/helper/main.rs` | 482 |
| pf enforcement | `platform-macos/helper/enforce.rs` | 196 |
| Process lookup | `platform-macos/process_lookup.rs` | 668 |
| Shared types | `common/types.rs` | 456 |

**Key commands:**
```bash
cargo build --workspace          # Build everything
cargo test --workspace           # Run 47 tests
cargo clippy --workspace --all-targets -- -D warnings  # Lint
```

---

## Slide 14: Coding Conventions

1. **No shell for pfctl.** Always `Command::new("pfctl").args([...])` — never `sh -c`.
2. **Typed enforcement only.** `IpAddr`, `u16`, `Duration` — never raw strings.
3. **One pfctl caller.** Only `enforce.rs` touches pfctl.
4. **No async runtime.** `std::thread` + `crossbeam` only. No tokio.
5. **Detectors have timeouts.** Every detector runs on its own thread with a budget.
6. **Enrichment is async.** Never block the hot path.
7. **Measurements have units.** `latency_us`, `ttl_ms` — never bare names.

---

## Slide 15: Summary

**What exists today:**
- Full capture pipeline: BPF → parse → flow track → enrich → detect → decide
- Persistent helper daemon that survives agent crashes
- Peer-credential authentication
- pf firewall enforcement (table add/delete/kill state)
- 47 tests, clippy clean, fmt clean

**What you'll build:**
- Wire the decision engine → enforcement (one line + rate limiting)
- Enrichment cache (eliminate redundant DNS lookups)
- Circuit breaker for failing detectors
- Config file for tunable thresholds

**The system works. Your job is to make it production-ready.**
