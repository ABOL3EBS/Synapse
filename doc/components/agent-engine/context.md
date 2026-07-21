# Agent Engine — BPF Reads + IPv4/IPv6 Parsing

Unprivileged capture loop. Receives BPF fd from helper, reads raw packets, parses into `PacketInfo`, sends enforcement commands.

## Code location

`crates/agent/src/main.rs` (289 lines) — standalone binary crate

## Startup sequence

1. Connect to helper via Unix socket (`/tmp/synapse-helper.sock`)
2. Receive BPF fd via `protocol::recv_fd()` (SCM_RIGHTS)
3. Query kernel buffer size via `ioctl(BIOCGBLEN)` — mandatory, read() fails with EINVAL otherwise
4. Allocate read buffer of exactly that size
5. Enter capture loop

## BpfHdr struct (20 bytes)

```rust
#[repr(C)]
struct BpfHdr {
    tv_sec: i32,      // timeval32.tv_sec
    tv_usec: i32,     // timeval32.tv_usec
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
}
```

Next packet offset: `BPF_WORDALIGN(bh_hdrlen + bh_caplen)` — word-aligned to 4 bytes.

## IP frame parsers

- `parse_ip_frame(frame)` — reads EtherType at offset 12-13, dispatches to IPv4 (0x0800) or IPv6 (0x86DD)
- `parse_ipv4(frame)` — IP header, protocol, src/dst IPs, TCP/UDP ports
- `parse_ipv6(frame)` — 40-byte fixed header, next-header, src/dst IPs, TCP/UDP ports

Returns `Option<PacketInfo>` — malformed frames silently skipped.

## Capture loop

```
loop {
    libc::read(bpf_fd, buf)       // one read can return multiple packets
    for each BpfHdr in buffer:
        parse_ip_frame(frame)
        if hit target IP && not already blocked:
            send_message(Block { ip, ttl })
}
```

- `HashSet<IpAddr>` tracks which IPs have been sent a Block command (idempotent)
- Handles `EINTR` (signal interruption) gracefully
- Handles BPF fd closure (helper exit) by breaking

## Dependencies

`synapse-common` (EnforcementCommand, PacketInfo), `synapse-platform-macos` (protocol only), `libc`, `log`, `env_logger`

## Gotchas

- Agent never opens `/dev/bpf*` — receives pre-configured fd from helper
- Test target IP is hardcoded (192.168.1.100) — milestone 1 only
- Block TTL is hardcoded (300s) — milestone 1 only
- IPv6 `length` field is set to 0 — total-length is in jumbogram extension, not base header
