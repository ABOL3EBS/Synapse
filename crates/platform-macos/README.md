# synapse-platform-macos

Native macOS integration — the enforcement boundary. This is the **only** crate that knows about BPF, `pf`, or (later) `NetworkExtension`. Contains two binaries and one library module.

## Binary targets

| Binary | Source | Runs as | Purpose |
|---|---|---|---|
| `synapsed-helper` | `src/helper/main.rs` | root (launchd daemon) | Opens BPF device, hands fd to agent, enforces pf rules |
| `synapse-agent` | `src/agent/main.rs` | unprivileged | Receives BPF fd, reads/parses packets, runs detection loop |

## Library

| Module | Source | Purpose |
|---|---|---|
| `protocol` | `src/protocol.rs` | SCM_RIGHTS fd-passing + length-prefixed bincode IPC. Used by both binaries. |

## Dependencies

- `synapse-common` — shared types, `EnforcementBackend` trait
- `libc` 0.2 — raw BPF ioctls, `read()`, `SCM_RIGHTS` CMSG handling
- `serde` 1.x (with derive) — serialization
- `bincode` 1.x — binary IPC encoding
- `log` 0.4 + `env_logger` 0.11 — logging

## File map

### `src/helper/main.rs` (325 lines) — synapsed-helper

The root-privileged daemon. Responsibilities and *only* these:

```
main()
 ├── open_bpf_device(interface) → OwnedFd     [line 97]
 │    └── raw ioctls: BIOCSBLEN → BIOCSETIF → BIOCIMMEDIATE → BIOCSETF
 │
 ├── ensure_anchor()                            [line 189]
 │    └── pfctl -a com.synapse.ips -f - (load anchor rules)
 │    └── Creates synapse_blocklist table + pass/block rules
 │
 ├── IPC socket setup                           [line 248]
 │    └── UnixListener::bind("/tmp/synapse-helper.sock")
 │    └── chmod 0o666
 │
 ├── protocol::send_fd(stream, bpf_fd)         [line 261]
 │    └── SCM_RIGHTS: sends BPF fd to agent, drops own copy
 │
 └── enforcement loop                           [line 270]
      └── protocol::recv_message::<EnforcementCommand>()
      ├── Block → backend.apply_block(ValidatedBlock)
      ├── Unblock → backend.remove_block(BlockId)
      └── KillState → direct pfctl call (BROKEN — see below)
```

**Internal modules:**
- `mod enforce` (line 11) — `MacOsEnforcementBackend`, the only pfctl executor

**Constants:**
- `PF_ANCHOR_NAME = "com.synapse.ips"`
- `PF_TABLE_NAME = "synapse_blocklist"`
- `IPC_SOCKET_PATH = "/tmp/synapse-helper.sock"`

**BPF filter** (lines 58-89): 5-instruction program matching IPv4 (0x0800) OR IPv6 (0x86DD).

### `src/helper/enforce.rs` (141 lines) — MacOsEnforcementBackend

The **only** file that executes `pfctl`. All enforcement goes through this trait impl.

```
MacOsEnforcementBackend
 ├── new() → Self                              [line 27]
 ├── block_ip(IpAddr) → Result<(), String>     [line 33]
 │    └── pfctl -a com.synapse.ips -t synapse_blocklist -T add <ip>
 │
 ├── unblock_ip(IpAddr) → Result<(), String>   [line 55]
 │    └── pfctl -a com.synapse.ips -t synapse_blocklist -T delete <ip>
 │
 └── impl EnforcementBackend
      ├── apply_block(ValidatedBlock)           [line 80]
      │    ├── if already in active_blocks: re-issue block_ip (idempotent), no new thread
      │    ├── else: block_ip + spawn TTL thread (sleep → unblock)
      │    └── v1: one OS thread per active block, no cap
      │
      ├── remove_block(BlockId)                 [line 120]
      │    └── unblock_ip + remove from active_blocks
      │
      └── reconcile(DesiredFirewallState)       [line 135]
           └── STUB: returns Ok(ReconciliationReport::default())
```

### `src/agent/main.rs` (289 lines) — synapse-agent

The unprivileged processing engine. Never opens `/dev/bpf*` directly.

```
main()
 ├── protocol::recv_fd(stream) → RawFd         [line 186]
 │    └── receives BPF fd from helper via SCM_RIGHTS
 │
 ├── libc::ioctl(bpf_fd, BIOCGBLEN)            [line 193]
 │    └── queries kernel for exact buffer size
 │
 ├── allocate read_buf = vec![0u8; buf_len]     [line 205]
 │
 └── capture loop                              [line 211]
      ├── libc::read(bpf_fd, read_buf)          [line 212]
      ├── parse BpfHdr (20-byte timeval32)      [line 236]
      ├── parse_ip_frame(frame)                 [line 251]
      │    ├── parse_ipv4(frame) → PacketInfo   [line 82]
      │    └── parse_ipv6(frame) → PacketInfo   [line 128]
      ├── log every 10th packet + target hits
      └── if hit: protocol::send_message(Block { ip, ttl })
```

**Key types:**
- `BpfHdr` — 20-byte `#[repr(C)]` struct matching macOS `bpf_hdr` (timeval32 = 8 bytes, not 16)
- `BPF_WORDALIGN = 4` — alignment between packets in the read buffer
- `TEST_TARGET_IP = 192.168.1.100` — hardcoded test target (milestone 1)
- `BLOCK_TTL = 300s` — hardcoded block duration (milestone 1)

### `src/protocol.rs` (112 lines) — IPC primitives

Reusable across crates. Used by both `synapsed-helper` and `synapse-agent`.

```
send_fd(stream, fd)                             [line 17]
 └── SCM_RIGHTS fd-passing via CMSG (libc::sendmsg)

recv_fd(stream) → RawFd                         [line 44]
 └── SCM_RIGHTS fd-receiving via CMSG (libc::recvmsg)

send_message(stream, msg)                       [line 90]
 └── 4-byte big-endian length prefix + bincode payload

recv_message(stream) → D                        [line 98]
 └── reads length + payload, bincode::deserialize
 └── max 1MB payload limit
```

### `src/lib.rs` (11 lines) — crate root

Re-exports `pub mod protocol`. The `helper/` and `agent/` binary directories are NOT re-exported as library modules (names conflict with `pub mod` declarations).

## Known bugs

- **KillState pfctl syntax** (`helper/main.rs:292`): Uses `-k "proto from src to dst"` which is wrong. `pfctl -k` expects separate flags per host/network. Fix tracked as Step 3.
