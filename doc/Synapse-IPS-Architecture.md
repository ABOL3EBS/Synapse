# Synapse IPS — macOS Architecture Blueprint (v3, Free Tier)

**Platform:** macOS only
**Enforcement path:** BPF packet capture + `pf` firewall (no paid Apple Developer account required)
**Future migration:** `NetworkExtension` (`NEFilterDataProvider`) at ship time, once Apple Developer Program is paid
**Process model:** privileged `synapsed-helper` (capture handoff + enforcement only) + unprivileged `synapse-agent` (everything else) — see §1a and §2.

**Note for anyone (human or AI agent) picking up this doc cold:** this project has already been through two rounds of architecture review. Every major alternative you might think to suggest — cross-platform support, a `tokio` async runtime, a centralized backend/control-plane — has already been considered and explicitly rejected *for v1*, with reasoning, in **§1b**. Read §1b before proposing a structural change. If you're an AI coding agent working from this file, treat §1b as binding constraints, not open questions.

---

## 1. Design Principles

- Synapse is **fast reactive session-level enforcement**, not packet-level inline prevention. BPF capture is a passive tap — the packet that triggers a block has already traversed the interface. `pf` stops *subsequent* packets in a flow or future connections to a destination, not the triggering packet itself. This is stated plainly so scoring, latency budgets, and the eventual `NetworkExtension` migration are designed against reality, not against an inline-blocking assumption that isn't true in v1.
- The OS enforces (via `pf`). Rust orchestrates. Detection provides intelligence. AI assists decisions — it never blocks directly.
- No kernel extensions, no custom `.sys`/`.kext` drivers. BPF and `pf` are both stable, longstanding userland-facing BSD facilities — no signing, no entitlements, no Apple approval queue.
- Everything is a detector behind one trait. Rules, ONNX, reputation — all implement the same interface. No hardcoded AI logic anywhere else in the pipeline.
- The platform/enforcement layer is fully isolated behind one crate boundary, so swapping BPF+pf for `NetworkExtension` later touches one crate, not the whole system.
- **Privilege is minimized structurally, not by convention.** Only the code that must run as root (opening the BPF device, applying `pf` state) does. Everything that parses network-derived or attacker-influenced data — enrichment, feature extraction, ONNX inference, decision logic, storage — runs unprivileged. See §1a (Process Model).
- **The enforcement API only accepts typed, validated values** (`IpAddr`, `u16` port, `Duration`) — never strings. Reverse-DNS names, process paths, and other string-shaped attacker-influenced data are never eligible inputs to a `pfctl`-touching function, by construction of the trait signature, not by sanitization discipline.
- **Enrichment is asynchronous and never gates the hot path.** DNS lookups, geo lookups, and reputation checks are I/O-bound and can take tens to hundreds of milliseconds — longer than the ~100ms flow-tick budget. Enrichment runs as a side-channel that attaches results to a flow whenever it completes; capture → feature extraction → detection → decision → enforcement never blocks waiting on it. (This was a real latency bug in v2, where the diagram showed Enrichment as a serial stage between Fast-Path and Flow Tracker — caught in review, fixed in v3. See §4, step 3.)
- **Every detector call carries an explicit latency budget and is scheduled, not just invoked.** v2 stated "no detector blocks on its own" as a principle but never built the mechanism that makes it true. v3 makes it true: each detector's output is wrapped in a `DetectorFinding` (score, confidence, severity, evidence, `latency_us`, `status`) so a slow or hung ONNX inference or reputation lookup can be timed out and marked `TimedOut`/`Errored` instead of stalling the decision engine. See §4b.
- **Enforcement is a trait (`EnforcementBackend`), not just a wire protocol.** Typed values (`IpAddr`, `Duration`) at the IPC boundary stop malformed data from reaching `pfctl`, but they don't by themselves guarantee the *invocation* is safe — that also requires argv-based process execution (never `sh -c` string interpolation). `EnforcementBackend` makes both guarantees part of one interface, and folds `pf` reconciliation (§4a) into the same contract as `apply_block`/`remove_block`, so every future backend (should one ever be built) has to implement recovery-from-eviction, not just the happy path. See §4c.
- Single writer to SQLite. Many producers, one owner.

---

## 1a. Threat Model

Stated explicitly because every feature and scoring decision downstream depends on it.

**In scope (v1):**
- **Primary adversary:** malware or an implant already executing on the protected Mac, performing C2 beaconing, data exfiltration, or lateral movement over the network.
- **Secondary adversary:** a hostile peer on the local network (e.g., malicious LAN host probing or attacking the protected machine).

**Explicitly out of scope for v1** (deferred, not forgotten — see architecture doc changelog):
- An adversary capable of disabling or evading Synapse itself (anti-tamper / self-defense is a v2+ concern, once core detection is proven).
- Kernel-level rootkits that hide network activity from userland entirely (BPF/pcap can't see what the kernel doesn't show it — this is the accepted limitation of the no-kext, no-NE-entitlement v1 approach).
- Physical access attacks.
- Adversarial evasion of the locally-shipped ONNX model (model/weight protection is a v2+ hardening pass, not a v1 blocker).

This scope is why the feature set below is behavioral/session-oriented (packet_frequency, byte_ratio, connection_duration) rather than built around evading a sophisticated adversary who is actively trying to defeat Synapse's own process.

---

## 1b. Reviewed & Rejected Alternatives (Read This Before Suggesting Structural Changes)

This project had an internal architecture review where several substantial changes were proposed. Some were adopted (see the Design Principles above and the Changelog). Others were considered and explicitly declined **for v1**. They're documented here — not because they're bad ideas in the abstract, but because a v1 architecture doc with no memory of "we already thought about this" invites the same debate every time someone new (including an AI coding agent) looks at the project. If you're about to suggest one of the following, read the reasoning first.

### Rejected: cross-platform support (Linux + Windows) right now

**Proposal:** build Linux (AF_XDP/eBPF + nftables) and Windows (Windows Filtering Platform) capture/enforcement alongside macOS from the start, since "it's doable."

**Why declined for v1:** The entire point of scoping this project to macOS-only was to prove one capture backend and one enforcement backend end-to-end — see §6, First Build Milestone — before multiplying complexity. Building three capture stacks (BPF/libpcap, AF_XDP/eBPF, WFP), three privilege models, and three CI/test matrices *before* that milestone is hit means building on a foundation that hasn't been proven once, let alone three times.

There's also a direct conflict with the stated free-tier rationale: **Windows kernel-mode WFP callout drivers require EV code signing / Microsoft driver attestation signing** — a paid, bureaucratic process, arguably worse friction than the Apple Developer Program cost this project is explicitly structured to avoid on macOS (see the top-of-doc note: "no paid Apple Developer account required"). Adding Windows now reintroduces, on a different platform, exactly the cost this doc was designed to defer. Similarly, AF_XDP on Linux needs `CAP_NET_ADMIN`/privileged setup — "cross-platform" does not mean "equally free" across platforms.

**When to revisit:** once the macOS agent/helper contract (protocol.rs, `EnforcementBackend`, the async pipeline) is proven and stable, a second platform becomes an argument for generalizing `platform-macos` into a real `platform` abstraction. Not before. (See the repo-structure principle below: "no platform abstraction pretending to be cross-platform before it needs to be.")

### Rejected: `tokio` / hybrid async runtime for the agent

**Proposal:** use `tokio` because it's "essential for asynchronous I/O," combined with `crossbeam` in a hybrid model.

**Why declined for v1:** The agent's hot path is a tight capture/process loop, not a web server — this was a deliberate v1 choice (see §3, Agent Engine row) to avoid async-runtime scheduling overhead in code that needs predictable, low-latency behavior. The actual source of the tokio requirement wasn't the agent/helper IPC (a `UnixListener` handling a couple of long-lived connections doesn't need an async runtime) — it was `Axum`, needed only for the control-plane backend proposal below. Remove that backend and the tokio requirement disappears with it. Running two concurrency models side by side (tokio's reactor + crossbeam's channels/threads) adds a second scheduler, a second set of primitives, and a larger binary, for no benefit in a project that has no async network service to run.

**When to revisit:** if/when a control-plane backend is actually built (see below), tokio is appropriate *there* — scoped to that service, not spread into the endpoint agent.

### Rejected: centralized control plane (Axum + PostgreSQL + ClickHouse + fleet management + WebSocket live monitoring)

**Proposal:** add a backend service for fleet management, policy distribution, authentication, and historical analytics.

**Why declined for v1:** This is a SaaS backend for a product that hasn't captured a single packet yet (see §6). It's the same mistake as the cross-platform proposal, one layer up the stack: solving distribution/fleet problems before the core detection loop is proven. Nothing here is wrong as a *future* feature — it's wrong as v1-planning material. The existing local-first design (SQLite, single machine, "endpoint remains fully functional even when disconnected") is the correct v1 posture and should not be diluted by designing around a backend that doesn't exist yet.

**When to revisit:** once there's a working single-machine agent with real users, "how do multiple machines get managed" becomes a real question with real constraints to design against — designing it speculatively now just produces guesses.

### Corrected misconception: "IPC is being postponed"

**Claim raised in review:** IPC should be built first, not postponed until later.

**Why this is actually already true, not a change:** §6 (First Build Milestone) already requires the agent/helper typed-command handoff — which *is* the IPC layer — as the very first thing to prove, before ML models or the dashboard UI. Nothing in this doc postpones IPC. If this reads as ambiguous, it's because "before ML, before UI" was meant to scope out *those two things specifically*, not IPC. No change needed here beyond this clarification — noted so it doesn't get re-litigated.

### Rejected: pre-emptively generalized repo structure

**Proposal:** a repo/crate layout with per-platform crates already stubbed out for Linux/Windows (`synapse-capture-linux`, `synapse-enforcement-windows`, etc.) ahead of those platforms existing.

**Why declined for v1:** this directly contradicts a principle already stated in this doc (§5, "Why this shape"): *"No platform abstraction pretending to be cross-platform before it needs to be — write it concretely for macOS now, generalize only if/when a second platform is real."* Pre-creating multi-platform crate scaffolding before a second platform is real is exactly the premature abstraction that principle warns against — it adds directories and naming surface that will (best case) sit empty and (worst case) shape decisions around imagined future needs instead of the one platform that actually exists.

---

## 2. Architecture Diagram

```
                    [ NETWORK INTERFACE (en0 / en1) ]
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │   BPF Device (/dev/bpf*)        │   passive capture, root required
                  │   via libpcap                    │
                  └───────────────┬───────────────┘
                                  │ raw fd
                                  ▼
        ┌─────────────────────────────────────────────────────┐
        │   SYNAPSED-HELPER (Rust, root, launchd daemon)        │
        │   Minimal privileged surface — no packet parsing.      │
        │                                                       │
        │   1. Opens /dev/bpf*, hands fd to agent via            │
        │      SCM_RIGHTS (fd-passing over Unix socket)          │
        │   2. Exposes a typed enforcement protocol ONLY:        │
        │        Block{ip: IpAddr, ttl: Duration}                │
        │        Unblock{ip: IpAddr}                             │
        │        KillState{src, dst, proto}                      │
        │      No string inputs accepted — no shell string        │
        │      interpolation into pfctl is possible by            │
        │      construction.                                      │
        │   3. Owns the pf anchor: applies/removes table entries, │
        │      runs periodic reconciliation (see §4a) to detect   │
        │      and recover from anchor eviction by other tools.   │
        └────────────────────┬──────────────────────────────────┘
                             │ raw packets (fd) │ enforcement commands (typed, structured)
                             ▼                  ▲
        ┌─────────────────────────────────────────────────────┐
        │         SYNAPSE-AGENT (Rust, unprivileged)            │
        │  All parsing of network-derived / attacker-influenced │
        │  data happens here — nothing here can escalate.       │
        │                                                       │
        │  ┌─────────────────────────────┐                     │
        │  │  Capture Layer                │  parses raw frames  │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Fast-Path Rule Check         │──────► sends typed  │
        │  │  (incl. pre-seeded reputation  │        Block cmd    │
        │  │   feed for known-bad IPs)      │        to helper    │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐     ┌───────────────┐│
        │  │  Flow Tracker                  │◄───┤  Enrichment    ││
        │  │  (session window, ~100ms tick) │    │  (ASYNC side-  ││
        │  │                                 │    │  channel — NOT ││
        │  │  Attaches whatever enrichment   │    │  a serial gate)││
        │  │  has landed so far; does NOT    │    │  process attr, ││
        │  │  block waiting for it.          │    │  DNS, geo/rep  ││
        │  └──────────────┬────────────────┘    └───────────────┘│
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Feature Extraction            │  packet_frequency,   │
        │  │                                 │  byte_ratio, etc.    │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Detector Framework (trait)    │  each call wrapped   │
        │  │   ├─ Rule Engine               │  in a DetectorFinding │
        │  │   ├─ ONNX Model                │  with a latency       │
        │  │   ├─ Reputation Engine         │  budget — see §4b.    │
        │  │   └─ (future detectors)        │  Timed-out/errored    │
        │  │                                 │  detectors report a  │
        │  │                                 │  status, they don't   │
        │  │                                 │  stall the pipeline.  │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Decision Engine                │  weighted scoring:   │
        │  │  (AI score + rule hits −        │  merges all signals  │
        │  │   trust adjustments = verdict)  │  into final verdict  │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Policy / Mitigation Layer      │──────► typed Block/  │
        │  │                                 │        KillState cmd │
        │  │                                 │        sent to helper│
        │  │                                 │        (never a raw  │
        │  │                                 │        string)       │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Event Queue → Storage Worker  │──────► SQLite (WAL)  │
        │  └─────────────────────────────┘                     │
        └────────────────────┬──────────────────────────────────┘
                              │ IPC (Unix domain socket)
                              ▼
                  ┌───────────────────────────┐
                  │   TAURI + REACT DASHBOARD    │  UI never touches
                  │                               │  the engine directly
                  └───────────────────────────┘
```

---

## 3. Tech Stack by Layer

| Layer | Technology | Strategic Reason |
|---|---|---|
| **Process Model** | `synapsed-helper` (root, launchd) + `synapse-agent` (unprivileged) | Only BPF-open and `pf` enforcement run privileged. All parsing of network/attacker-influenced data runs unprivileged — a bug in enrichment, ONNX, or storage is not a root exploit. |
| **Packet Capture** | `pcap` crate (libpcap/BPF bindings), fd opened by helper, handed to agent via `SCM_RIGHTS` | Same primitive as `tcpdump`/Wireshark/old scapy version. No entitlement, no signing, just root — and root's involvement ends at the `open()` call. |
| **Enforcement** | `pf` via `pfctl`, invoked only by `synapsed-helper` behind an `EnforcementBackend` trait (typed values only — `IpAddr`/`Duration`, never strings — passed as argv, never shell-interpolated); direct ioctl planned as a latency optimization, not a security fix | Native macOS firewall since Leopard. Anchor tables for dynamic block/allow. No kernel driver, no NE entitlement. Typed values close the injection risk at the data layer; argv-based invocation (never `sh -c` string building) closes it at the execution layer — both are required, neither alone is sufficient. See §4c. |
| **Process Attribution** | `libproc` bindings / parsed `lsof`-equivalent syscalls | Maps a flow to a PID/executable path without Endpoint Security entitlement. |
| **Agent Engine** | Rust, `std::thread` + `crossbeam` | No `tokio`. This isn't a web server — treat it like an OS service. Avoids async runtime bloat for what is fundamentally a tight capture/process loop. A hybrid `tokio`+`crossbeam` runtime was proposed in review and declined for v1 — the actual driver of that proposal was a control-plane backend that doesn't exist yet. See §1b. |
| **Concurrency** | `crossbeam` channels, `rayon` (only if a detector needs data-parallel scoring) | Predictable, low-overhead, no reactor/executor overhead. |
| **Detection Scheduling** | Each detector call wrapped in a `DetectorFinding` (score, confidence, severity, evidence, `latency_us`, `status`) with an enforced timeout per detector | Makes the existing "no detector blocks on its own" principle actually true instead of aspirational — a hung ONNX inference or reputation lookup reports `TimedOut`/`Errored` and the decision engine proceeds with whatever findings it has. See §4b. |
| **Inference** | ONNX Runtime (Rust bindings, `ort` crate) | Compiles trained models to native C++ execution speed, runs inside the agent process — fully local, no cloud call. |
| **Model Training** | Python + PyTorch (offline, not runtime) | Training happens outside the agent. Only the exported `.onnx` artifact ships with the agent. |
| **Local Storage** | SQLite (WAL mode) | Single-file DB, single writer / many producers via an event queue, avoids write contention with the capture hot path. |
| **IPC (Agent ↔ UI)** | Unix domain socket (or named pipe abstraction if you want portability later) | UI never touches the engine directly — always mediated. |
| **Desktop Shell** | Tauri | Native footprint, avoids Electron bloat. |
| **UI** | React + Tailwind + shadcn/ui | Standard, fast to iterate, matches Tauri's web-view frontend model. |
| **Build** | Cargo workspace (3 crates) | Enough separation to avoid dependency hell, without micro-crate over-engineering. |

**Future migration (post-payment):** swap `platform-macos`'s capture/enforcement internals from `pcap`+`pfctl` to a Swift `NEFilterDataProvider` system extension bridged over XPC/Unix socket. Everything above the `platform-macos` boundary (common types, agent engine, detectors, decision engine, storage, UI) stays untouched — that's the entire point of the crate boundary.

---

## 4. Data Pipeline Summary

The hot path (packets in, verdict out) and enrichment run as two decoupled sequences that join at the Flow Tracker. This split exists because enrichment (DNS, geo, reputation lookups) is I/O-bound and can take longer than the ~100ms flow-tick budget — an earlier version of this doc drew enrichment as a serial stage before flow tracking, which would have meant the hot path stalls on a network call. That was caught in review and fixed here.

**Hot path:**
1. **Capture:** `synapsed-helper` opens the BPF device as root and hands the fd to `synapse-agent` via `SCM_RIGHTS`; the agent (unprivileged) reads raw packets from it via libpcap. Root's involvement ends here.
2. **Fast-Path:** Immediate match against known-bad rules/blocklists — including reputation-feed IPs **pre-seeded into the pf block table proactively**, before any traffic to them occurs — sends a typed `Block` command to the helper. This closes the first-packet exposure gap for *known* threats; it does not (and cannot, given a passive-tap architecture) prevent the triggering packet of a *novel* threat from being delivered. That gap is accepted and tracked, not hidden (see §1, first bullet).
3. **Flow Tracking:** Traffic aggregated into sessions over an in-memory window (~100ms ticks), attaching whatever enrichment context has landed by this point (see below) without blocking for it, and producing feature vectors (packet_frequency, byte_ratio, connection_duration, destination reputation, **detection latency / flow-age-at-decision**, etc.). Flow-age is tracked explicitly so the decision engine knows how much of a given flow had already been delivered before a verdict was reached.
4. **Detection:** Feature vectors run through every registered detector (rules, ONNX, reputation) independently. Each call is wrapped in a `DetectorFinding` with an enforced per-detector latency budget (see §4b) — no detector blocks the others or the decision engine, by construction, not just by intent.
5. **Decision:** Weighted scoring merges all detector findings into a single verdict, weighting down or ignoring findings with a `TimedOut`/`Errored` status rather than treating a missing result as a silent zero. Example: `AI score 85 + known-malware-domain +90 + unsigned-binary +30 − trusted-process −40 = 165 → BLOCK`. This is what prevents any single false positive (or missing detector result) from being fatal.
6. **Enforce:** The agent calls `EnforcementBackend::apply_block(...)` (or `remove_block`) — never a raw string — which `synapsed-helper` is the sole implementer of (see §4c). The trait, not just the wire format, is what guarantees typed-and-argv-safe execution.
7. **Log:** Every decision and its inputs flow through an event queue to a single SQLite storage worker (WAL mode) in the unprivileged agent — never a direct write from the hot path, and never touched by the privileged helper.

**Enrichment (separate, asynchronous sequence):**
- On flow creation, an enrichment request (process attribution via PID + process-start-time, reverse DNS, geo/reputation lookup) is dispatched to a background worker pool in the unprivileged agent.
- Results attach to the flow record whenever they complete — they do not gate feature extraction, detection, or decision-making.
- **Open policy question, intentionally not resolved by this doc:** what should a reputation-dependent detector do if enrichment hasn't landed by decision time? Two reasonable defaults exist — (a) treat the flow as unenriched/default-trust until context arrives, re-scoring on a later tick once it does, or (b) allow the decision engine a short, bounded wait (e.g., one flow-tick) before proceeding without it. This needs to be decided during implementation of the decision engine, not assumed.

---

## 4a. `pf` Coexistence (Detect-and-Recover, Not a Disclaimer)

`pf` is a single shared global resource — Synapse does not own it exclusively. Other tools (Little Snitch, Lulu, MDM-managed firewall profiles, the user's own `pf.conf`) can reload or flush `pf` state independently of Synapse.

- Synapse owns a **dedicated named anchor**, loaded via its own anchor file and referenced explicitly in `pf.conf` at a known priority.
- On startup, `synapsed-helper` runs `pfctl -s Anchors` to check whether its anchor is already present/owned, and logs a warning (not a silent failure) if another tool's anchor appears to conflict in ordering.
- `synapsed-helper` runs a **periodic reconciliation task**: it re-checks that Synapse's anchor rules are still present. If another tool's reload flushed or evicted them, it re-applies them and logs the eviction event (visible in the dashboard) rather than silently operating with no enforcement in place.
- This does not solve rule-ordering conflicts with a tool that legitimately needs to allow traffic Synapse would block (that's a real, unresolved product question — surfaced here rather than papered over) — but it guarantees Synapse's own state doesn't silently disappear without anyone noticing.

---

## 4b. Detector Execution & Latency Budgets

v2 stated "no detector blocks on its own" as a design principle but had no actual enforcement mechanism — a slow ONNX inference call or a hung reputation lookup could still stall the decision engine, because nothing timed it out or reported it as anything other than "still running." This section is the fix, contributed during architecture review.

Every detector call — Rule Engine, ONNX Model, Reputation Engine, and any future detector implementing the `Detector` trait — returns a `DetectorFinding`, not a raw score:

```rust
pub struct DetectorFinding {
    pub detector_id: DetectorId,
    pub detector_version: String,
    pub score: f32,
    pub confidence: f32,
    pub severity: Severity,
    pub evidence: Vec<Evidence>,
    pub latency_us: u64,
    pub status: DetectorStatus, // Completed | TimedOut | Errored
}
```

**Why each field earns its place:**
- `detector_id` / `detector_version` — lets the decision engine (and later, the dashboard/audit log) attribute a verdict to a specific detector implementation, which matters once detectors get tuned or retrained over time.
- `score` / `confidence` / `severity` — separates "how bad" from "how sure" from "how urgent," so the decision engine's weighting isn't collapsing three different signals into one number before it has to.
- `evidence` — the concrete basis for the score (e.g., which rule matched, which reputation list hit), needed for the dashboard to explain *why* a block happened, not just that it did.
- `latency_us` — makes detector cost visible and measurable, which is what actually lets someone notice "the ONNX detector is creeping past its budget" before it becomes a production stall.
- `status` — this is the field that makes "no detector blocks on its own" true. A detector that exceeds its budget is scheduled with a timeout; on expiry, it returns (or is force-marked) `TimedOut` rather than being awaited indefinitely. `Errored` covers exceptions/panics caught at the boundary. The decision engine treats a non-`Completed` finding as a known-missing signal (down-weighted or excluded), not a silent zero and not a hang.

Per-detector latency budgets (the timeout threshold each detector gets before being marked `TimedOut`) are a decision-engine configuration concern, not hardcoded per detector — this keeps tuning a budget a config change, not a code change.

---

## 4c. Enforcement Backend Trait

Typed values at the enforcement IPC boundary (`IpAddr`, `Duration`, structured enum variants instead of strings) close off command injection *at the data layer* — malformed or attacker-shaped strings simply have nowhere to go, because the wire format doesn't accept strings for anything security-relevant. But that's a necessary condition, not a sufficient one: if the code that turns a validated `Block{ip, ttl}` value into an actual `pfctl` invocation still builds a shell command by string concatenation (`format!("pfctl -t blocklist -T add {ip}")` piped to `sh -c`), the injection risk reopens at the *execution layer*, because whatever produced that string could, in principle, be adversarial-adjacent even if individually well-typed. This distinction — typed data vs. safe execution — is easy to blur and was underspecified in v2. It's why this doc now defines enforcement as a trait, not just a protocol:

```rust
pub trait EnforcementBackend {
    fn apply_block(&mut self, block: ValidatedBlock) -> Result<EnforcementReceipt>;
    fn remove_block(&mut self, block_id: BlockId) -> Result<EnforcementReceipt>;
    fn reconcile(&mut self, desired: &DesiredFirewallState)
        -> Result<ReconciliationReport>;
}
```

**Why a trait instead of a bare protocol:**
- `apply_block` / `remove_block` take pre-validated types (`ValidatedBlock`, `BlockId`) constructed only through a validation path the caller can't bypass — so "did you validate this?" is answered by the type system, not by code review discipline.
- The concrete macOS implementation of this trait (in `platform-macos/src/helper/enforce.rs`) is the *only* place allowed to invoke `pfctl`, and it must do so via `std::process::Command::new("pfctl").arg(...).arg(...)` (argv array) — never through a shell. This is the execution-layer guarantee that typed data alone doesn't provide.
- `reconcile()` folds §4a's "detect-and-recover from anchor eviction" behavior into the trait contract itself, rather than leaving it as an ad hoc background task bolted onto the helper. Every implementer of `EnforcementBackend` — today just the macOS one — has to have an answer for "what if our state got evicted," because the trait requires it.
- `ValidatedBlock`, `BlockId`, `DesiredFirewallState`, `ReconciliationReport`, and `EnforcementReceipt` belong in `crates/common/src/types.rs`, alongside the other shared data contracts, since both `agent` (the caller) and `platform-macos` (the implementer) need them without either depending on the other's internals.

---

## 5. Repository Structure

```
synapse/
├── Cargo.toml                    # Workspace configuration
│
├── crates/
│   ├── common/                   # Shared data contracts — no logic
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       └── types.rs          # NetworkEvent, FlowAggregate, Decision, Verdict,
│   │                             #   DetectorFinding/DetectorStatus (§4b), and
│   │                             #   ValidatedBlock/BlockId/DesiredFirewallState/
│   │                             #   ReconciliationReport/EnforcementReceipt (§4c) —
│   │                             #   shared by both agent (caller) and platform-macos
│   │                             #   (implementer) without either depending on the
│   │                             #   other's internals
│   │
│   ├── agent/                    # Core processing service — runs unprivileged
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           # Engine pipeline & worker threads
│   │       ├── enrichment/       # Async worker pool — process attribution (libproc),
│   │       │                     #   DNS, reputation lookups. Dispatched on flow
│   │       │                     #   creation, attaches to the flow whenever it
│   │       │                     #   completes; never awaited inline on the hot path.
│   │       ├── flow/             # In-memory session tracking window
│   │       ├── detectors/        # Detector trait + Rule / ONNX / Reputation impls,
│   │       │                     #   each wrapped with a per-detector timeout that
│   │       │                     #   produces a DetectorFinding (§4b)
│   │       ├── decision/         # Weighted scoring matrix, policy thresholds
│   │       └── storage/          # SQLite connection, event queue, single-writer worker
│   │
│   └── platform-macos/           # Native macOS integration — the enforcement boundary
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── protocol.rs       # Typed enforcement commands (IpAddr/Duration only,
│           │                     #   never strings) AND the EnforcementBackend trait
│           │                     #   (§4c) — shared contract between helper & agent
│           ├── helper/           # synapsed-helper: root, launchd daemon
│           │   ├── main.rs       # Opens BPF device, hands fd to agent via SCM_RIGHTS
│           │   ├── enforce.rs    # ONLY implementer of EnforcementBackend for macOS —
│           │   │                 #   ONLY caller of pfctl, always via argv (Command::arg),
│           │   │                 #   never via a shell/sh -c string
│           │   └── reconcile.rs  # EnforcementBackend::reconcile() impl — periodic
│           │                     #   anchor-eviction detection & recovery (§4a/§4c)
│           ├── capture.rs        # BPF/libpcap capture wrapper (runs in unprivileged agent
│           │                     #   once the fd is received)
│           └── process_lookup.rs # libproc-based PID + process-start-time resolution
│                                 #   (start-time captured alongside PID to avoid
│                                 #   PID-reuse/TOCTOU misattribution)
│
├── models/                       # Exported .onnx artifacts (trained offline in Python)
│
└── src-tauri/                    # UI presentation layer
    ├── Cargo.toml
    └── src/                      # Tauri IPC handlers → agent Unix socket
        └── ui/                   # React + Tailwind + shadcn frontend
```

**Why this shape:**
- `common` has zero logic — just types — so both `agent` and `src-tauri` can depend on it without pulling in engine internals.
- `platform-macos` is the *only* crate that knows about BPF, `pf`, or (later) `NetworkExtension`. `agent` only ever talks to it through a small trait/interface (e.g., `Capture`, `Enforcer`), so the eventual NE migration is contained.
- `platform-macos` itself splits along the **privilege boundary, not just the platform boundary**: `helper/` is the entire root-privileged surface (BPF open, fd handoff, pfctl, anchor reconciliation) and is deliberately kept as small and auditable as possible; `capture.rs` and `process_lookup.rs` run inside the unprivileged `agent` process once handed the fd. A memory-safety or logic bug in packet parsing, DNS parsing, or process attribution — all of which touch attacker-influenced data — is no longer a root-level bug.
- `protocol.rs` is the load-bearing file for this boundary: it defines both the *shape* enforcement commands can take (typed `IpAddr`/`Duration`/enum variants — a data-layer guarantee) and the `EnforcementBackend` trait that forces safe, argv-based execution on whoever implements it (an execution-layer guarantee). Neither guarantee alone is sufficient; see §4c for why both are required.
- No `platform` abstraction pretending to be cross-platform before it needs to be — write it concretely for macOS now, generalize only if/when a second platform is real.

---

## 6. First Build Milestone

Before ML, before UI: get a minimal pipeline that can **capture one flow via BPF (fd opened by `synapsed-helper`, handed to an unprivileged `synapse-agent` via `SCM_RIGHTS`), log it, and block one test IP by calling `EnforcementBackend::apply_block` on the agent side, which sends a typed command to the helper — the only process that calls `pfctl`, always via argv, never a shell** — end to end, on your own machine. This is a deliberately higher bar than "just get pfctl to block something as root" because it proves the actual v1 claim: that the privilege boundary, the typed-and-safely-invoked enforcement trait, and the IPC layer all hold up together, not just that enforcement works when everything runs as root in one process. IPC is not a later milestone — the typed command handoff between agent and helper *is* this milestone, not a prerequisite deferred past it (see §1b if this is unclear). Get this working before anything else gets built on top of it.

---

## Changelog

- **v2:** Added explicit threat model (§1a); split into privileged `synapsed-helper` / unprivileged `synapse-agent` processes (§1, §2, §5); replaced shell-out `pfctl` string paths with a typed-only enforcement protocol; reframed "instant pfctl block" as fast reactive enforcement with tracked detection latency, not inline prevention (§1, §4); added reputation-feed pre-seeding to the fast path (§4); added `pf` coexistence detect-and-recover behavior (§4a); added process start-time to PID attribution to avoid PID-reuse TOCTOU (§5). Deferred to v2+ and out of scope for this doc: anti-tamper/self-defense, ONNX model/weight integrity protection, event-queue backpressure tuning, IPC auth hardening beyond socket permissions, and flow-window size tuning — see §1a for why these are explicitly out of scope rather than omitted by oversight.
- **v3 (post internal architecture review):** Adopted three concrete fixes surfaced in review: (1) enrichment decoupled into an async side-channel that never gates the hot path (§4, fixes a real latency bug in the v2 diagram where enrichment sat as a serial stage); (2) per-detector latency budgets via a `DetectorFinding` struct with a `status` field, which actually enforces the "no detector blocks on its own" principle v2 only stated (§4b); (3) enforcement formalized as an `EnforcementBackend` trait rather than a bare wire protocol, making both the typed-data guarantee and the argv-safe-execution guarantee part of one contract, and folding `pf` reconciliation into `reconcile()` (§4c). Also added §1b, documenting three proposals considered and declined for v1 — cross-platform support now, a `tokio`/hybrid runtime, and a centralized control-plane backend — with reasoning, plus a correction of a misconception that IPC was being postponed (it wasn't; see §6). Nothing in §1a, §2's privilege split, or the free-tier/no-signing rationale changed in this revision.
