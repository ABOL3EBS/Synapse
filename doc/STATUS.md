# Implementation Status — Synapse IPS

This is a factual ledger, not a design doc. It answers one question only: **what actually exists in the code right now, verified against real files** — not what the architecture blueprint describes as the target. If this file and `Synapse-IPS-Architecture.md` ever disagree about what's built, this file wins; the architecture doc describes where the project is going, not where it is.

**Last verified:** 2026-07-20, against commit `67b8d02` ("helper: raw BPF ioctls + IPv4+IPv6 filter; agent: raw BPF reads from received fd"), by direct file read and live traffic verification on en0.

Update this file whenever you verify a change by actually reading the file that changed — not from memory, not from a commit message, not from an agent's description of what it wrote.

---

## Built and confirmed working

- **`crates/common/`** — shared types: `EnforcementCommand` (`Block`/`Unblock`/`KillState` variants), `PacketInfo`, protocol constants. (~54 lines, `lib.rs`)
- **`crates/platform-macos/src/helper/main.rs`** (331 lines) — the privileged daemon:
  - Opens BPF device via **raw ioctls** (no pcap): `BIOCSBLEN` → `BIOCSETIF` → `BIOCIMMEDIATE` → `BIOCSETF`, in that exact order. The earlier pcap-based version called `BIOCSBLEN` after `BIOCSETIF`, which violates bpf(4) ("buffer must be set before the file is attached to an interface with BIOCSETIF"). Fixed by switching to raw ioctls with correct ordering.
  - BPF filter: 5-instruction program matching both IPv4 (EtherType `0x0800`) and IPv6 (EtherType `0x86DD`), dropping other traffic. The earlier filter (`BPF_IP_FILTER`) had only 4 instructions matching IPv4 only; renamed to `BPF_IPV4_IPV6_FILTER` with a comment documenting both EtherTypes.
  - Sends BPF fd to agent via `SCM_RIGHTS` (using shared `protocol.rs`), drops own copy — agent now solely holds the fd.
  - Initializes the `pf` anchor and `synapse_blocklist` table
  - Listens for typed `EnforcementCommand`s over the agent↔helper channel
  - `block_ip()` (line ~190): `Command::new("pfctl").args([...])` — seven individual args, IP goes through `IpAddr::to_string()`. **Confirmed correct: argv-based, no shell, no injection risk.**
  - `unblock_ip()` (line ~206): same pattern as `block_ip()`. **Confirmed correct.**
- **`crates/platform-macos/src/agent/main.rs`** (247 lines) — the unprivileged side:
  - Receives BPF fd from helper via `SCM_RIGHTS` (does **not** open `/dev/bpf*` itself — privilege separation enforced structurally)
  - Queries `BIOCGBLEN` for exact kernel buffer size, allocates matching read buffer
  - Reads packets via raw `libc::read()` on the received fd (no pcap dependency in the agent)
  - Parses `bpf_hdr` headers (20-byte macOS `timeval32` layout) with proper `BPF_WORDALIGN` (4-byte alignment)
  - Parses both IPv4 and IPv6 frames from raw Ethernet: `parse_ipv4()` and `parse_ipv6()` — both confirmed working against live traffic
  - Sends a `Block` command for a hardcoded test target (`192.168.1.100`)
- **`crates/platform-macos/src/protocol.rs`** (95 lines) — reusable functions: `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (length-prefixed bincode). **Confirmed exercised** by the running M1 path — helper sends fd via `send_fd`, agent receives via `recv_fd`; agent sends `EnforcementCommand` via `send_message`, helper receives via `recv_message`.

### What was verified against real traffic (2026-07-20, commit `67b8d02`)

Live capture on `en0` with a long-running agent process (not synthetic single-packet tests):

- **IPv4 ICMP** (proto=1): echo request/reply pairs to `8.8.8.8` — `172.18.22.208:0 → 8.8.8.8:0 (proto=1)` and reply `8.8.8.8:0 → 172.18.22.208:0 (proto=1)`, multiple pairs over ~30 seconds of continuous ping. Ports correctly show as `0` (ICMP has no ports).
- **IPv4 TCP** (proto=6): HTTPS connections to various IPs (`104.17.91.187:443`, `52.108.8.12:443`, `18.210.236.250:443`, etc.)
- **IPv4 UDP** (proto=17): mDNS (`172.18.22.158:5353 → 224.0.0.251:5353`), DNS queries, QUIC traffic
- **IPv6 UDP** (proto=17): mDNS (`fe80::...:5353 → ff02::fb:5353`)
- **IPv6 ICMPv6** (proto=58): neighbor solicitation/advertisement (`fe80::... → ff02::1:ff...`, `fe80::... → fe80::...`)

## Built but broken — do not treat as working

- **`helper/main.rs`, KillState branch (~line 179–194):** `.args(["-k", &format!("{proto_str} from {src} to {dst}")])`. This is a **real functional bug**, not just a style issue. Real `pfctl -k` syntax takes a host/network per flag — kill both src and dst with **two separate `-k` flags**: `pfctl -k <src> -k <dst>` (see `man pfctl` — verified against FreeBSD/OpenBSD/macOS man pages directly, not inferred). A single formatted "proto from X to Y" sentence passed to one `-k` is not valid syntax as written. This will very likely either error or silently kill zero states (`killed 0 states` is the typical real-world symptom of this exact mistake). **No shell-injection risk** — this is a syntax/functionality bug, not a security bug. Needs fixing before the kill-state enforcement path can be trusted at all.

## Not built at all

- `EnforcementBackend` trait (architecture §4c) — spec only, no implementation. `block_ip()`/`unblock_ip()` are called directly, not through a trait.
- Reconciliation logic (§4a/§4c `reconcile()`)
- `crossbeam`-based agent engine / worker threads
- `crates/agent/` subdirectories (`detectors/`, `enrichment/`, `flow/`, `decision/`, `storage/`) — directories exist, all empty, no code
- SQLite storage layer
- Tauri app shell / any UI code (`src-tauri/src/ui/` is an empty directory; no `Cargo.toml` for the Tauri app yet)
- ONNX models / any detector implementations
- Windows or Linux platform code (intentionally — see architecture §1b)

---

## Why this file exists

On 2026-07-18, two separate OpenCode sessions gave confident, detailed, and **contradictory** descriptions of what enforcement code existed — one described a fully-wired pipeline with functions that didn't exist yet, the other claimed nothing existed when real milestone-1 code did. A third pass, after being told to read actual files, got the code inventory right but initially asserted an incorrect `pfctl -k` syntax as fact before it was checked against the real man page. The pattern: fluent, specific-sounding answers are not a reliable signal of correctness, especially about (a) what's actually built vs. what's designed, and (b) exact CLI/API syntax of external tools. This file exists so "what's built" has one place to check that isn't dependent on an agent's summary of the architecture doc's tone. Keep it honest and current, or it's worse than not having it.
