# IPC — SCM_RIGHTS fd-passing + bincode message framing

Two-layer protocol over Unix domain socket: fd-passing for the BPF device, length-prefixed bincode for typed commands.

## Code location

`crates/platform-macos/src/protocol.rs` (164 lines)

## fd-passing (SCM_RIGHTS)

- `send_fd(stream, fd)` — constructs `msghdr` with CMSG control buffer, calls `libc::sendmsg()`
- `recv_fd(stream)` — receives via `libc::recvmsg()`, iterates control messages for `SCM_RIGHTS`
- Helper sends BPF fd, drops its copy. Agent receives and owns it.

## Message framing

- 4-byte big-endian length prefix (`u32`)
- Bincode-serialized payload
- Max 1MB per message
- Magic bytes: `SYNP` (defined in `common/src/lib.rs`, not currently checked on receive)

## Wire format

```
[4 bytes: length][N bytes: bincode payload]
```

## Command types (common/src/lib.rs)

```rust
enum EnforcementCommand {
    Block { ip: IpAddr, ttl: Duration },
    Unblock { ip: IpAddr },
    KillState { src: IpAddr, dst: IpAddr, proto: u8 },
}
```

All fields typed — `IpAddr`, `Duration`, `u8`. Shell injection structurally impossible.

## Socket

- Path: `/tmp/synapse-helper.sock`
- Helper creates, `chmod 0666` so unprivileged agent can connect
- Helper removes on shutdown

## Gotchas

- `sendmsg`/`recvmsg` require the control buffer even for fd-passing — can't use plain `write`/`read`
- 1MB max message size prevents memory exhaustion from corrupted length fields
- Both helper and agent use the same `protocol.rs` — it's a shared library module via `pub mod protocol`
