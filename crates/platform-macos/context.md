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
cache-push thread                        line 315
  Sends PortPidCache to agent every 5s
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

`synapse-common`, `libc` 0.2, `mach2` 0.4, `serde` 1.x, `bincode` 1.x, `log` 0.4, `env_logger` 0.11, `libproc` 0.14

## process_lookup.rs — port→PID cache + process attribution (668 lines)

Uses `libproc` crate (v0.14, typed structs via bindgen) for all FFI. Runs unprivileged (reads procfs).

### Key functions

- `lookup_process(pid) -> Result<ProcessInfo, String>` — executable path + start time
- `build_port_pid_cache() -> PortPidCache` — full per-process fd scan
- `probe_socket(pid, fd) -> Option<(lport, fport, proto)>` — single socket probe

### Port reading strategy

`insi_lport` and `insi_fport` are stored as BE u16 in the first 2 bytes of a `c_int` field.
On little-endian ARM, reading as `c_int` (native-endian) gives a wrong value (e.g., port 60202 → c_int 10987).
**Must use raw byte reading** via `read_port_be(info, offset)` which reads 2 bytes at a fixed offset and applies `u16::from_be_bytes`.

- `OFF_LPORT = 268` (verified by test_probe_socket_lport against lsof ground truth)
- `OFF_FPORT = 264` (verified by test_probe_socket_fport against lsof ground truth)
- Offsets computed from: `psi` at 24 (SocketInfo), `soi_proto` at 264, `InSockInfo` starts at soi_proto, `insi_fport` at +0, `insi_lport` at +4.

### SocketFDInfo struct layout (from libproc bindgen)

```
SocketFDInfo (792 bytes total):
  [0..24)    prefix (includes ProcFDInfo at offset 8 + extra fields)
  [24..792)  psi: SocketInfo (768 bytes)
             VInfoStat (136 bytes) at start
             soi_proto (SocketInfoProto, 528 bytes) at offset 264 from start
               pri_in: InSockInfo at offset 264 (first union member)
                 insi_fport: c_int at offset 264
                 insi_lport: c_int at offset 268
```

### Tests (all pass)

- `test_lookup_own_pid` — resolves own executable path and start time
- `test_lookup_invalid_pid` — fails correctly for nonexistent PID
- `test_build_port_pid_cache` — 39-53 entries, ~500 PIDs, ~5000 fds, ~2ms
- `test_probe_socket_lport` — lport matches lsof ground truth exactly
- `test_probe_socket_fport` — fport matches lsof ground truth exactly
- `test_struct_sizes` — verifies struct sizes, offsets, read_port_be vs lsof
