 ███████╗██╗   ██╗███╗   ██╗ █████╗ ██████╗ ███████╗███████╗
 ██╔════╝╚██╗ ██╔╝████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████╗ ╚████╔╝ ██╔██╗ ██║███████║██████╔╝███████╗█████╗
 ╚════██║  ╚██╔╝  ██║╚██╗██║██╔══██║██╔═══╝ ╚════██║██╔══╝
 ███████║   ██║   ██║ ╚████║██║  ██║██║     ███████║███████╗
 ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝

                    I N T R U S I O N   P R E V E N T I O N

**Reactive session-level IPS for macOS. No cloud. No kernel extensions. No Apple Developer account.**

Synapse captures network traffic via BPF, detects threats through a pluggable detector framework (rules, ONNX models, reputation feeds), and enforces decisions through the native `pf` firewall. All inference runs locally — nothing leaves the machine.

The process model splits privileged work (BPF device open, `pf` state) into a minimal helper daemon running as root, while all untrusted parsing, detection, and decision logic runs unprivileged in the agent. A bug in enrichment, ML inference, or storage is not a root exploit.

## Architecture

```
┌─────────────────────────────────────┐     ┌────────────────────────────────────────┐
│  synapsed-helper (root, launchd)    │     │  synapse-agent (unprivileged, euid 501)│
│                                     │     │                                        │
│  Startup (once):                    │     │  Capture loop:                         │
│    Open /dev/bpf0                   │     │    BPF reads → parse IPv4/IPv6          │
│    Configure pf anchor              │     │    → flow tracking → enrichment          │
│    Enable pf (pfctl -e)             │     │    → detector scoring → decision engine  │
│                                     │     │    → verdict (log-only / enforcement)    │
│  Per-connection loop:               │     │                                        │
│    accept() → peer-credential auth  │◀─IPC─│  SCM_RIGHTS fd handoff (BPF)           │
│    Send BPF fd via SCM_RIGHTS       │     │  PortPidCache (every 5s)               │
│    Spawn cache-push thread (5s)     │     │  EnforcementCommand::Block/Unblock     │
│    Enforcement loop (recv cmds)     │     │  → block IPs in pf table               │
│    Agent disconnects → cancel →     │     │                                        │
│    return to accept (persistent)    │     │                                        │
└─────────────────────────────────────┘     └────────────────────────────────────────┘
```

## What's built

| Component | Status | Lines |
|---|---|---|
| BPF capture (raw ioctls, no pcap) | Done | — |
| SCM_RIGHTS fd-passing + bincode IPC | Done | 112 |
| Helper daemon (persistent, reconnect loop) | Done | 482 |
| Peer-credential auth (`getpeereid`) | Done | — |
| pf anchor (flush, reload, enable) | Done | — |
| Typed enforcement (Block/Unblock/KillState) | Done | 196 |
| `EnforcementBackend` trait | Done | — |
| Dedup + TTL auto-unblock (`AtomicBool`) | Done | — |
| KillState (real state termination) | Verified | — |
| Agent capture loop (BPF reads, IPv4+IPv6) | Done | 762 |
| Flow tracker (session window, eviction) | Done | 975 |
| Enrichment pool (DNS, process attribution) | Done | 495 |
| Detector framework (trait + timeout) | Done | 343 |
| Decision engine (weighted scoring) | Done | 397 |
| Shared types (common crate) | Done | 570 |
| Port→PID cache (libproc FFI) | Done | 668 |

**Total: ~5,385 lines across 11 files. 47 tests. clippy clean. fmt clean.**

### Verified end-to-end

Helper sends PortPidCache (48-53 entries, ~420 PIDs, ~6500 fds, ~6ms build). Agent receives cache, looks up src_port on each packet, resolves to PID + executable path. Live test: Brave Browser connection resolved to pid=743 → `Brave Browser Helper`.

3 consecutive agent kill/reconnect cycles verified — helper survives all, no resource leaks.

## Stack

- **Capture:** BPF raw ioctls (BIOCSBLEN → BIOCSETIF → BIOCIMMEDIATE → BIOCSETF)
- **Enforcement:** `pf` via `pfctl` — `Command::new("pfctl").args([...])`, never shell
- **IPC:** Unix domain socket, SCM_RIGHTS fd-passing, bincode serialization
- **Process lookup:** `libproc` FFI — port→PID cache via per-process fd scan
- **Runtime:** `std::thread` + `crossbeam` — no async runtime, no tokio
- **Platform:** macOS only (v1)

## Building

```bash
cargo build --workspace
```

Helper requires root:
```bash
sudo RUST_LOG=info cargo run --bin synapsed-helper
```

Agent runs unprivileged:
```bash
cargo run --bin synapse-agent
```

## Project structure

```
crates/
├── common/          Shared types + EnforcementBackend trait (zero logic)
│   └── src/
│       ├── lib.rs       EnforcementCommand, PacketInfo, IPC constants
│       └── types.rs     ValidatedBlock, Detector trait, Verdict, DecisionConfig
│
├── agent/           Unprivileged processing
│   └── src/
│       ├── main.rs          Capture loop, packet parsing, pipeline wiring
│       ├── detectors/       Detector trait + RuleDetector (timeout + catch_unwind)
│       ├── enrichment/      4-thread worker pool (DNS, process, geo/reputation stubs)
│       ├── flow/            In-memory session tracker (tick-based, O(log n) eviction)
│       └── decision/        Weighted scoring engine, Verdict, active-flow re-evaluation
│
└── platform-macos/  macOS enforcement boundary
    └── src/
        ├── helper/
        │   ├── main.rs      Root daemon — BPF open, reconnect loop, fd handoff
        │   └── enforce.rs   MacOsEnforcementBackend — only pfctl caller
        ├── protocol.rs      SCM_RIGHTS + bincode IPC
        └── process_lookup.rs  libproc FFI — port→PID cache

doc/
├── STATUS.md                      Ground-truth ledger (source of truth)
├── report.md                      Full architecture, bug history, testing methodology
├── Synapse-IPS-Architecture.md    Design blueprint + rejected alternatives
└── intern-presentation-prompt.md  Replit presentation content for onboarding
```

## Coding conventions

1. **No shell for pfctl.** Always `Command::new("pfctl").args([...])`.
2. **Typed enforcement only.** `IpAddr`, `u16`, `Duration` — never raw strings.
3. **One pfctl caller.** Only `enforce.rs` touches pfctl.
4. **No async runtime.** `std::thread` + `crossbeam` only.
5. **Detectors have timeouts.** Every detector runs on its own thread with a budget.
6. **Enrichment is async.** Never block the hot packet-processing path.
7. **Measurements have units.** `latency_us`, `ttl_ms` — never bare names.

## Threat model

**In scope (v1):** malware performing C2 beaconing, data exfiltration, or lateral movement over the network. Hostile peers on the local network.

**Out of scope (v1):** anti-tamper / self-defense, kernel rootkits, physical access attacks, adversarial model evasion.

See `doc/Synapse-IPS-Architecture.md` §1a for full threat model.

## License

TBD
