# synapse-platform-macos — context

macOS enforcement boundary. Only crate that knows about BPF, pf, or (later) NetworkExtension.

## Binaries

| Binary | Source | Runs as |
|---|---|---|
| `synapsed-helper` | `src/helper/main.rs` (347 lines) | root |

## Library

`src/lib.rs` re-exports `pub mod protocol` and `pub mod process_lookup`. Helper is NOT re-exported (directory name conflicts with `pub mod`).

## helper/main.rs call tree

```
open_bpf_device(iface) → OwnedFd        line 98
  raw ioctls: BIOCSBLEN → BIOCSETIF → BIOCIMMEDIATE → BIOCSETF
  SockFprog.len is u32 (matches C bf_len)
ensure_anchor()                          line 190
  1. pfctl -a com.synapse.ips -F all (flush stale rules)
  2. pfctl -a com.synapse.ips -f - (load table + block-out + block-in rules via stdin)
  3. Add "anchor com.synapse.ips all" to /etc/pf.conf if missing
  4. pfctl -f /etc/pf.conf (reload main ruleset)
pfctl -e                                line 280
  Enable pf (reference counted)
IPC socket setup                         line 290
  /tmp/synapse-helper.sock, chmod 0666
protocol::send_fd(stream, bpf_fd)        line 301
  SCM_RIGHTS, drops own copy
enforcement loop                         line 308
  Block → backend.apply_block(ValidatedBlock)
  Unblock → backend.remove_block(BlockId)
  KillState → backend.kill_state(src, dst, proto)
```

## helper/enforce.rs — MacOsEnforcementBackend (180 lines)

ONLY file that executes pfctl. All via `Command::new("pfctl").args([...])`.

- `block_ip(IpAddr)` — `pfctl -a com.synapse.ips -t synapse_blocklist -T add <ip>`
- `unblock_ip(IpAddr)` — `pfctl -T delete`
- `apply_block()` — idempotent (dedup if already blocked, keeps original TTL), spawns TTL thread
- `remove_block()` — unblock + remove from active_blocks
- `kill_state(src, dst, proto)` — `pfctl -k src -k dst` (kills all states for pair, proto logged only)
- `reconcile()` — STUB, returns default

## Dependencies

`synapse-common`, `libc` 0.2, `mach2` 0.4, `serde` 1.x, `bincode` 1.x, `log` 0.4, `env_logger` 0.11

## process_lookup.rs — libproc FFI (155 lines)

Resolves PID to executable path + process start time. Called from agent's enrichment pool (unprivileged — libproc reads procfs, no root needed).

- `lookup_process(pid) -> Result<ProcessInfo, String>`
- `proc_pidpath(pid)` — gets executable path via libproc's `proc_pidpath()`
- `proc_start_time(pid)` — gets start time via `proc_pidinfo(PROC_PIDTASKINFO)` + mach2 timebase conversion
- `ProcessInfo { path: String, start_time: f64 }` — start_time is epoch seconds
- Start-time captured alongside PID to prevent PID-reuse/TOCTOU misattribution
- Tests: `test_lookup_own_pid` (passes), `test_lookup_invalid_pid` (passes)
