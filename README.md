# Synapse IPS

macOS-native intrusion prevention system in Rust. Detects and blocks malicious network activity — C2 beaconing, data exfiltration, lateral movement — using behavioral analysis and locally-run ML models. No cloud. No kernel extensions. No Apple Developer account required.

## Architecture

```
  synapsed-helper (root)                 synapse-agent (unprivileged)
  ┌──────────────────────────┐          ┌───────────────────────────┐
  │ Opens /dev/bpf*          │──fd───▶ │ BPF reads (raw ioctls)    │
  │ SCM_RIGHTS fd handoff    │          │ IPv4 + IPv6 parsing       │
  │ pf anchor management     │◀─typed── │ EnforcementBackend trait  │
  │ EnforcementBackend impl  │ commands │ Detection pipeline (planned)│
  └──────────────────────────┘          │ SQLite storage (planned)  │
                                        └───────────────────────────┘
```

## What's built

Capture + fd passing + pf enforcement end-to-end on macOS. BPF device opened by helper, passed to unprivileged agent via SCM_RIGHTS. Agent reads packets, parses IPv4/IPv6, sends typed Block/Unblock commands back. pf table add/delete verified against real `pfctl`.

## Project structure

```
crates/
  common/            Shared types + EnforcementBackend trait (zero logic)
  platform-macos/    macOS enforcement boundary
    helper/          Root daemon — BPF, fd handoff, pfctl
    agent/           Unprivileged — packet reads, IPC
    protocol.rs      SCM_RIGHTS + bincode IPC
doc/
  STATUS.md          What's actually built (source of truth)
  Synapse-IPS-Architecture.md  Design blueprint + rejected alternatives
```

## Building

```bash
cargo build --workspace
```

Requires macOS with BPF support. Helper must run as root.

## License

TBD
