# synapse-platform-macos — context

macOS enforcement boundary. Only crate that knows about BPF, pf, or (later) NetworkExtension.

## Binaries

| Binary | Source | Runs as |
|---|---|---|
| `synapsed-helper` | `src/helper/main.rs` (325 lines) | root |
| `synapse-agent` | `src/agent/main.rs` (289 lines) | unprivileged |

## Library

`src/lib.rs` re-exports `pub mod protocol`. Helper/agent are NOT re-exported (directory name conflicts with `pub mod`).

## helper/main.rs call tree

```
open_bpf_device(iface) → OwnedFd        line 97
  raw ioctls: BIOCSBLEN → BIOCSETIF → BIOCIMMEDIATE → BIOCSETF
ensure_anchor()                          line 189
  pfctl -a com.synapse.ips -f - (creates table + rules)
IPC socket setup                         line 248
  /tmp/synapse-helper.sock, chmod 0666
protocol::send_fd(stream, bpf_fd)        line 261
  SCM_RIGHTS, drops own copy
enforcement loop                         line 270
  Block → backend.apply_block(ValidatedBlock)
  Unblock → backend.remove_block(BlockId)
  KillState → direct pfctl (BROKEN — -k syntax wrong)
```

## helper/enforce.rs — MacOsEnforcementBackend (141 lines)

ONLY file that executes pfctl. All via `Command::new("pfctl").args([...])`.

- `block_ip(IpAddr)` — `pfctl -a com.synapse.ips -t synapse_blocklist -T add <ip>`
- `unblock_ip(IpAddr)` — `pfctl -T delete`
- `apply_block()` — idempotent (dedup if already blocked, keeps original TTL), spawns TTL thread
- `remove_block()` — unblock + remove from active_blocks
- `reconcile()` — STUB, returns default

## agent/main.rs call tree

```
protocol::recv_fd(stream) → RawFd       line 186
  receives BPF fd from helper
libc::ioctl(BIOCGBLEN)                  line 193
  queries kernel buffer size
capture loop                            line 211
  libc::read(bpf_fd, buf)
  BpfHdr::from_bytes() — 20-byte struct
  parse_ip_frame()
    parse_ipv4() → PacketInfo            line 82
    parse_ipv6() → PacketInfo            line 128
  every 10th pkt + target hit → log
  if hit: send_message(Block { ip, ttl })
```

## protocol.rs (112 lines)

- `send_fd(stream, fd)` / `recv_fd(stream)` — SCM_RIGHTS via CMSG
- `send_message(stream, msg)` / `recv_message(stream)` — 4-byte length prefix + bincode, max 1MB

## Constants

| Name | Value |
|---|---|
| `PF_ANCHOR_NAME` | `com.synapse.ips` |
| `PF_TABLE_NAME` | `synapse_blocklist` |
| `IPC_SOCKET_PATH` | `/tmp/synapse-helper.sock` |
| `BPF_WORDALIGN` | 4 |
| `TEST_TARGET_IP` | `192.168.1.100` (milestone 1) |
| `BLOCK_TTL` | 300s (milestone 1) |

## Dependencies

`synapse-common`, `libc` 0.2, `serde` 1.x, `bincode` 1.x, `log` 0.4, `env_logger` 0.11
