# Capture — BPF Device Setup

Opens `/dev/bpf*`, configures buffer/bind/filter via raw ioctls, hands fd to agent via SCM_RIGHTS.

## Code location

`crates/platform-macos/src/helper/main.rs` — `open_bpf_device()` (line 98)

## BPF setup — ioctl ordering (CRITICAL)

```
open(/dev/bpfN)
  → BIOCSBLEN (set buffer size, 1MB)     MUST be first
  → BIOCSETIF (bind to interface)         MUST come after BIOCSBLEN
  → BIOCIMMEDIATE (deliver immediately)   after BIOCSETIF
  → BIOCSETF (set filter program)         after BIOCSETIF
```

**bpf(4) man page:** "The buffer must be set before the file is attached to an interface with BIOCSETIF." BIOCSBLEN before BIOCSETIF is non-negotiable.

## SockFprog struct (C interop)

```rust
#[repr(C)]
struct SockFprog {
    len: u32,              // MUST be u32 — matches C's unsigned int bf_len
    filter: *const SockFilter,
}
```

If `len` is `u16`, kernel reads garbage in upper 2 bytes → `EINVAL`. This was a real bug (commit `0869168`).

## BPF filter

5-instruction program, passes IPv4 (0x0800) and IPv6 (0x86DD), drops everything else:

```
[0] LD [12]              load 2-byte EtherType
[1] JEQ 0x0800, jt=2     IPv4? → [4]
[2] JEQ 0x86DD, jt=1     IPv6? → [4]
[3] RET 0                 drop
[4] RET 65535             pass full packet
```

## BPF fd handoff

Helper opens BPF as root, hands fd to agent via `protocol::send_fd()`. Helper drops its copy after sending — agent solely owns the fd. Root's involvement ends here.

## Gotchas

- Trying `/dev/bpf0` through `/dev/bpf9` — first available wins
- `BIOCGBLEN` query on agent side is mandatory — `read()` fails with `EINVAL` if buffer size doesn't match kernel's value
- `OwnedFd` wrap after open — ensures kernel fd is closed on drop, no leak

## Verified

- BPF open + bind + filter on en0 ✅
- Agent receives fd via SCM_RIGHTS, BIOCGBLEN returns 1048576 ✅
