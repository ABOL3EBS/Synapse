# Synapse IPS

A macOS-native intrusion prevention system built in Rust. Synapse detects and blocks malicious network activity — C2 beaconing, data exfiltration, lateral movement — using behavioral analysis and locally-run ML models. No cloud calls. No kernel extensions. No Apple Developer account required.

## Why Synapse

- **Privilege separation by construction.** Only the code that must run as root (opening BPF, applying `pf` rules) does. All parsing, ML inference, and decision logic run unprivileged — a bug in detection is not a root exploit.
- **Typed enforcement protocol.** The enforcement API accepts `IpAddr`, `Duration`, never strings. Shell injection into `pfctl` is a type error, not a discipline problem.
- **Everything is a detector.** Rules, ONNX models, reputation feeds — all implement one trait. No hardcoded AI logic anywhere else in the pipeline.
- **No kext, no NE entitlement.** BPF capture + `pf` firewall are stable, longstanding BSD facilities. No signing, no Apple approval queue.
- **Fast reactive enforcement.** Not inline prevention — Synapse is a passive tap that blocks subsequent packets in a flow. Designed against reality, not against an assumption that isn't true in v1.

## Architecture

```
  synapsed-helper (root, launchd)          synapse-agent (unprivileged)
  ┌─────────────────────────────┐          ┌──────────────────────────┐
  │ Opens /dev/bpf*             │──fd───> │ Capture (libpcap)        │
  │ Hands fd via SCM_RIGHTS     │          │ Fast-Path Rule Check     │
  │ Applies pf anchor rules     │<─typed── │ Enrichment (proc, DNS)   │
  │ Periodic reconciliation     │ commands │ Flow Tracker             │
  └─────────────────────────────┘          │ Feature Extraction       │
                                           │ Detector Framework       │
                                           │ Decision Engine (scoring)│
                                           │ Event Queue → SQLite     │
                                           └──────────┬──────────────┘
                                                      │ Unix socket IPC
                                                      v
                                           ┌──────────────────────────┐
                                           │ Tauri + React Dashboard  │
                                           └──────────────────────────┘
```

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Rust (edition 2021) |
| Packet Capture | BPF via libpcap — fd opened by helper, passed to agent via `SCM_RIGHTS` |
| Enforcement | `pf` firewall — anchor tables, typed-only command protocol |
| Process Attribution | `libproc` — PID + start-time to avoid PID-reuse misattribution |
| Concurrency | `crossbeam` channels, `std::thread` — no async runtime |
| ML Inference | ONNX Runtime (`ort` crate) — fully local, no cloud |
| Storage | SQLite (WAL mode) — single writer, event queue |
| Desktop Shell | Tauri |
| UI | React + Tailwind + shadcn/ui |

## Project Structure

```
synapse/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── common/                 # Shared types — zero logic
│   ├── agent/                  # Core engine — runs unprivileged
│   │   └── src/
│   │       ├── detectors/      # Detector trait + impls (Rule, ONNX, Reputation)
│   │       ├── enrichment/     # Process attribution, DNS, reputation lookups
│   │       ├── flow/           # In-memory session tracking
│   │       ├── decision/       # Weighted scoring, policy thresholds
│   │       └── storage/        # SQLite, event queue
│   └── platform-macos/         # macOS enforcement boundary
│       └── src/
│           ├── protocol.rs     # Typed enforcement commands (IpAddr/Duration only)
│           └── helper/         # Root-privileged: BPF open, fd handoff, pfctl
├── models/                     # Exported .onnx artifacts (trained offline)
└── src-tauri/                  # Tauri + React dashboard
```

## First Milestone

Before ML, before UI: capture one flow via BPF (fd opened by `synapsed-helper`, handed to unprivileged `synapse-agent` via `SCM_RIGHTS`), log it, and block one test IP by sending a typed command back to the helper. End to end. This proves the privilege boundary and typed enforcement protocol both hold up.

## Threat Model (v1)

**In scope:**
- Malware/implants performing C2, exfiltration, or lateral movement
- Hostile peers on the local network

**Out of scope (v2+):**
- Adversaries that can disable Synapse itself (anti-tamper)
- Kernel rootkits hiding network activity from userland
- Physical access attacks

## License

TBD
