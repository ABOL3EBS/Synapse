# Synapse IPS — macOS Architecture Blueprint (v2, Free Tier)

**Platform:** macOS only
**Enforcement path:** BPF packet capture + `pf` firewall (no paid Apple Developer account required)
**Future migration:** `NetworkExtension` (`NEFilterDataProvider`) at ship time, once Apple Developer Program is paid
**Process model:** privileged `synapsed-helper` (capture handoff + enforcement only) + unprivileged `synapse-agent` (everything else) — see §1a and §2.

---

## 1. Design Principles

- Synapse is **fast reactive session-level enforcement**, not packet-level inline prevention. BPF capture is a passive tap — the packet that triggers a block has already traversed the interface. `pf` stops *subsequent* packets in a flow or future connections to a destination, not the triggering packet itself. This is stated plainly so scoring, latency budgets, and the eventual `NetworkExtension` migration are designed against reality, not against an inline-blocking assumption that isn't true in v1.
- The OS enforces (via `pf`). Rust orchestrates. Detection provides intelligence. AI assists decisions — it never blocks directly.
- No kernel extensions, no custom `.sys`/`.kext` drivers. BPF and `pf` are both stable, longstanding userland-facing BSD facilities — no signing, no entitlements, no Apple approval queue.
- Everything is a detector behind one trait. Rules, ONNX, reputation — all implement the same interface. No hardcoded AI logic anywhere else in the pipeline.
- The platform/enforcement layer is fully isolated behind one crate boundary, so swapping BPF+pf for `NetworkExtension` later touches one crate, not the whole system.
- **Privilege is minimized structurally, not by convention.** Only the code that must run as root (opening the BPF device, applying `pf` state) does. Everything that parses network-derived or attacker-influenced data — enrichment, feature extraction, ONNX inference, decision logic, storage — runs unprivileged. See §1a (Process Model).
- **The enforcement API only accepts typed, validated values** (`IpAddr`, `u16` port, `Duration`) — never strings. Reverse-DNS names, process paths, and other string-shaped attacker-influenced data are never eligible inputs to a `pfctl`-touching function, by construction of the trait signature, not by sanitization discipline.
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
        │  ┌─────────────────────────────┐                     │
        │  │  Enrichment                    │  process attribution │
        │  │  (proc via libproc, DNS,       │  (lsof/libproc),     │
        │  │   geo/reputation lookups)      │  reverse DNS, ASN    │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Flow Tracker                  │  in-memory session   │
        │  │  (session window, ~100ms tick) │  aggregation         │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Feature Extraction            │  packet_frequency,   │
        │  │                                 │  byte_ratio, etc.    │
        │  └──────────────┬────────────────┘                     │
        │                 ▼                                     │
        │  ┌─────────────────────────────┐                     │
        │  │  Detector Framework (trait)    │                     │
        │  │   ├─ Rule Engine               │                     │
        │  │   ├─ ONNX Model                │                     │
        │  │   ├─ Reputation Engine         │                     │
        │  │   └─ (future detectors)        │                     │
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
| **Enforcement** | `pf` via `pfctl`, invoked only by `synapsed-helper` through a typed command protocol (`IpAddr`/`Duration`, never strings); direct ioctl planned as a latency optimization, not a security fix | Native macOS firewall since Leopard. Anchor tables for dynamic block/allow. No kernel driver, no NE entitlement. Typed-only inputs make shell/command injection structurally unreachable regardless of how `pfctl` is invoked. |
| **Process Attribution** | `libproc` bindings / parsed `lsof`-equivalent syscalls | Maps a flow to a PID/executable path without Endpoint Security entitlement. |
| **Agent Engine** | Rust, `std::thread` + `crossbeam` | No `tokio`. This isn't a web server — treat it like an OS service. Avoids async runtime bloat for what is fundamentally a tight capture/process loop. |
| **Concurrency** | `crossbeam` channels, `rayon` (only if a detector needs data-parallel scoring) | Predictable, low-overhead, no reactor/executor overhead. |
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

1. **Capture:** `synapsed-helper` opens the BPF device as root and hands the fd to `synapse-agent` via `SCM_RIGHTS`; the agent (unprivileged) reads raw packets from it via libpcap. Root's involvement ends here.
2. **Fast-Path:** Immediate match against known-bad rules/blocklists — including reputation-feed IPs **pre-seeded into the pf block table proactively**, before any traffic to them occurs — sends a typed `Block` command to the helper. This closes the first-packet exposure gap for *known* threats; it does not (and cannot, given a passive-tap architecture) prevent the triggering packet of a *novel* threat from being delivered. That gap is accepted and tracked, not hidden (see §1, first bullet).
3. **Enrichment:** Unmatched traffic gets tagged with process (PID + process start-time, to avoid PID-reuse misattribution), DNS, and reputation context before it reaches the flow tracker. All of this — parsing DNS responses, reputation lookups, process attribution — happens in the unprivileged agent.
4. **Flow Tracking:** Traffic aggregated into sessions over an in-memory window (~100ms ticks), producing feature vectors (packet_frequency, byte_ratio, connection_duration, destination reputation, **detection latency / flow-age-at-decision**, etc.). Flow-age is tracked explicitly so the decision engine knows how much of a given flow had already been delivered before a verdict was reached.
5. **Detection:** Feature vectors run through every registered detector (rules, ONNX, reputation) independently — no detector blocks on its own.
6. **Decision:** Weighted scoring merges all detector outputs into a single verdict. Example: `AI score 85 + known-malware-domain +90 + unsigned-binary +30 − trusted-process −40 = 165 → BLOCK`. This is what prevents any single false positive from being fatal.
7. **Enforce:** The agent sends a typed command (`Block{ip, ttl}` or `KillState{src, dst, proto}`) — never a string — to `synapsed-helper`, which is the only process that touches `pfctl`. The helper validates the command against its fixed protocol before applying it.
8. **Log:** Every decision and its inputs flow through an event queue to a single SQLite storage worker (WAL mode) in the unprivileged agent — never a direct write from the hot path, and never touched by the privileged helper.

---

## 4a. `pf` Coexistence (Detect-and-Recover, Not a Disclaimer)

`pf` is a single shared global resource — Synapse does not own it exclusively. Other tools (Little Snitch, Lulu, MDM-managed firewall profiles, the user's own `pf.conf`) can reload or flush `pf` state independently of Synapse.

- Synapse owns a **dedicated named anchor**, loaded via its own anchor file and referenced explicitly in `pf.conf` at a known priority.
- On startup, `synapsed-helper` runs `pfctl -s Anchors` to check whether its anchor is already present/owned, and logs a warning (not a silent failure) if another tool's anchor appears to conflict in ordering.
- `synapsed-helper` runs a **periodic reconciliation task**: it re-checks that Synapse's anchor rules are still present. If another tool's reload flushed or evicted them, it re-applies them and logs the eviction event (visible in the dashboard) rather than silently operating with no enforcement in place.
- This does not solve rule-ordering conflicts with a tool that legitimately needs to allow traffic Synapse would block (that's a real, unresolved product question — surfaced here rather than papered over) — but it guarantees Synapse's own state doesn't silently disappear without anyone noticing.

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
│   │       └── types.rs          # NetworkEvent, FlowAggregate, Decision, Verdict structs
│   │
│   ├── agent/                    # Core processing service — runs unprivileged
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs           # Engine pipeline & worker threads
│   │       ├── enrichment/       # Process attribution (libproc), DNS, reputation lookups
│   │       ├── flow/             # In-memory session tracking window
│   │       ├── detectors/        # Detector trait + Rule / ONNX / Reputation impls
│   │       ├── decision/         # Weighted scoring matrix, policy thresholds
│   │       └── storage/          # SQLite connection, event queue, single-writer worker
│   │
│   └── platform-macos/           # Native macOS integration — the enforcement boundary
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── protocol.rs       # Typed enforcement commands (IpAddr/Duration only,
│           │                     #   never strings) — shared contract between helper & agent
│           ├── helper/           # synapsed-helper: root, launchd daemon
│           │   ├── main.rs       # Opens BPF device, hands fd to agent via SCM_RIGHTS
│           │   ├── enforce.rs    # pfctl anchor management, state kill — ONLY caller of pfctl
│           │   └── reconcile.rs  # Periodic anchor-eviction detection & recovery (§4a)
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
- `protocol.rs` is the load-bearing file for this boundary: it defines the *only* shape enforcement commands can take (typed `IpAddr`/`Duration`/enum variants), so "attacker-influenced string ends up in a shell command" is not a discipline problem, it's a type error.
- No `platform` abstraction pretending to be cross-platform before it needs to be — write it concretely for macOS now, generalize only if/when a second platform is real.

---

## 6. First Build Milestone

Before ML, before UI: get a minimal pipeline that can **capture one flow via BPF (fd opened by `synapsed-helper`, handed to an unprivileged `synapse-agent` via `SCM_RIGHTS`), log it, and block one test IP by sending a typed command back to the helper, which is the only process that calls `pfctl`** — end to end, on your own machine. This is a deliberately higher bar than "just get pfctl to block something as root" because it proves the actual v1 claim: that the privilege boundary and the typed enforcement protocol both hold up, not just that enforcement works when everything runs as root. Get this working before anything else gets built on top of it.

---

## Changelog

- **v2:** Added explicit threat model (§1a); split into privileged `synapsed-helper` / unprivileged `synapse-agent` processes (§1, §2, §5); replaced shell-out `pfctl` string paths with a typed-only enforcement protocol; reframed "instant pfctl block" as fast reactive enforcement with tracked detection latency, not inline prevention (§1, §4); added reputation-feed pre-seeding to the fast path (§4); added `pf` coexistence detect-and-recover behavior (§4a); added process start-time to PID attribution to avoid PID-reuse TOCTOU (§5). Deferred to v2+ and out of scope for this doc: anti-tamper/self-defense, ONNX model/weight integrity protection, event-queue backpressure tuning, IPC auth hardening beyond socket permissions, and flow-window size tuning — see §1a for why these are explicitly out of scope rather than omitted by oversight.
