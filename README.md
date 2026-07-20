 ███████╗██╗   ██╗███╗   ██╗ █████╗ ██████╗ ███████╗███████╗
 ██╔════╝╚██╗ ██╔╝████╗  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
 ███████╗ ╚████╔╝ ██╔██╗ ██║███████║██████╔╝███████╗█████╗
 ╚════██║  ╚██╔╝  ██║╚██╗██║██╔══██║██╔═══╝ ╚════██║██╔══╝
 ███████║   ██║   ██║ ╚████║██║  ██║██║     ███████║███████╗
 ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝

                    I N T R U S I O N   P R E V E N T I O N

**Reactive session-level IPS for macOS. No cloud. No kernel extensions. No Apple Developer account.**

Synapse captures network traffic via BPF, detects threats through a pluggable detector framework (rules, ONNX models, reputation feeds), and enforces decisions through the native `pf` firewall. All inference runs locally — nothing leaves the machine.

The process model splits privileged work (BPF device open, `pf` state) into a minimal helper daemon, while all untrusted parsing, detection, and decision logic runs unprivileged. A bug in enrichment, ML inference, or storage is not a root exploit.

```
                    ┌─────────────────────────────────┐
                    │      NETWORK INTERFACE (en0)      │
                    └───────────────┬─────────────────┘
                                    │ raw packets
                                    ▼
                 ┌──────────────────────────────────────┐
                 │   synapsed-helper (root, launchd)     │
                 │   • Opens /dev/bpf*                   │
                 │   • SCM_RIGHTS fd handoff              │
                 │   • pf anchor: flush → load → enable   │
                 │   • Enforcement: apply / remove / kill  │
                 └──────────┬───────────┬───────────────┘
                   fd (BPF) │           │ typed commands
                            ▼           ▲
                 ┌──────────────────────────────────────┐
                 │   synapse-agent (unprivileged)        │
                 │   • BPF reads (raw ioctls)            │
                 │   • IPv4 + IPv6 parsing                │
                 │   • EnforcementBackend trait            │
                 │   • Detection pipeline (planned)        │
                 │   • SQLite storage (planned)            │
                 └──────────────────────────────────────┘
```

## What's built

| Component | Status |
|---|---|
| BPF capture (raw ioctls, no pcap) | Done |
| SCM_RIGHTS fd-passing | Done |
| pf anchor (flush, reload, enable) | Done |
| Typed enforcement (Block/Unblock/KillState) | Done |
| `EnforcementBackend` trait | Done |
| Dedup + TTL auto-unblock | Done |
| KillState (real state termination) | Verified |

## Stack

- **Capture:** BPF raw ioctls (BIOCSBLEN → BIOCSETIF → BIOCIMMEDIATE → BIOCSETF)
- **Enforcement:** `pf` via `pfctl` — argv execution, never shell
- **IPC:** Unix domain socket, SCM_RIGHTS fd-passing, bincode serialization
- **Runtime:** `std::thread` + `crossbeam` — no async runtime
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
│       ├── lib.rs       EnforcementCommand, PacketInfo, trait def
│       └── types.rs     ValidatedBlock, BlockId, EnforcementReceipt
│
├── agent/           Unprivileged processing (planned)
│   └── src/
│       ├── detectors/   Detector trait + impls
│       ├── enrichment/  DNS, geo, process attribution
│       ├── flow/        Session tracking
│       ├── decision/    Weighted scoring
│       └── storage/     SQLite single-writer
│
└── platform-macos/  macOS enforcement boundary
    └── src/
        ├── helper/      Root daemon — BPF, fd handoff, pfctl
        ├── agent/       Unprivileged — packet reads, IPC
        └── protocol.rs  SCM_RIGHTS + bincode IPC

doc/
├── STATUS.md                    What's built (source of truth)
└── Synapse-IPS-Architecture.md  Design blueprint + rejected alternatives
```

## Threat model

**In scope (v1):** malware performing C2 beaconing, data exfiltration, or lateral movement over the network. Hostile peers on the local network.

**Out of scope (v1):** anti-tamper / self-defense, kernel rootkits, physical access attacks, adversarial model evasion.

See `doc/Synapse-IPS-Architecture.md` §1a for full threat model.

## License

TBD
