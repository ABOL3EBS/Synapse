# Implementation Status — Synapse IPS

This is a factual ledger, not a design doc. It answers one question only: **what actually exists in the code right now, verified against real files** — not what the architecture blueprint describes as the target. If this file and `Synapse-IPS-Architecture.md` ever disagree about what's built, this file wins; the architecture doc describes where the project is going, not where it is.

**Last verified:** 2026-07-18, against commit `40104b4` ("milestone 1 — working packet capture → enforcement pipeline"), by direct file read (not by asking an AI agent to summarize — see the note at the bottom on why that distinction matters here).

Update this file whenever you verify a change by actually reading the file that changed — not from memory, not from a commit message, not from an agent's description of what it wrote.

---

## Built and confirmed working

- **`crates/common/`** — shared types: `EnforcementCommand` (`Block`/`Unblock`/`KillState` variants), `PacketInfo`, protocol constants. (~54 lines, `lib.rs`)
- **`crates/platform-macos/src/helper/main.rs`** (291 lines) — the privileged daemon:
  - Opens `pcap` BPF capture
  - Initializes the `pf` anchor and `synapse_blocklist` table
  - Listens for typed `EnforcementCommand`s over the agent↔helper channel
  - `block_ip()` (line ~128): `Command::new("pfctl").args([...])` — seven individual args, IP goes through `IpAddr::to_string()`. **Confirmed correct: argv-based, no shell, no injection risk.**
  - `unblock_ip()` (line ~144): same pattern as `block_ip()`. **Confirmed correct.**
- **`crates/platform-macos/src/agent/main.rs`** (186 lines) — the unprivileged side:
  - Connects to the helper
  - Opens its **own** `pcap` capture directly (does *not* receive the fd from the helper yet — see "Not built" below)
  - Runs the capture loop, parses IPv4/IPv6 frames
  - Sends a `Block` command for a hardcoded test target (`192.168.1.100`)
- **`crates/platform-macos/src/protocol.rs`** (95 lines) — reusable functions: `send_fd`/`recv_fd` (SCM_RIGHTS), `send_message`/`recv_message` (length-prefixed bincode). **These functions exist but are not currently exercised by the running M1 path** — the agent opens its own capture rather than receiving a handed-off fd. Don't assume fd-passing is live just because the function exists.

## Built but broken — do not treat as working

- **`helper/main.rs`, KillState branch (~line 179–194):** `.args(["-k", &format!("{proto_str} from {src} to {dst}")])`. This is a **real functional bug**, not just a style issue. Real `pfctl -k` syntax takes a host/network per flag — kill both src and dst with **two separate `-k` flags**: `pfctl -k <src> -k <dst>` (see `man pfctl` — verified against FreeBSD/OpenBSD/macOS man pages directly, not inferred). A single formatted "proto from X to Y" sentence passed to one `-k` is not valid syntax as written. This will very likely either error or silently kill zero states (`killed 0 states` is the typical real-world symptom of this exact mistake). **No shell-injection risk** — this is a syntax/functionality bug, not a security bug. Needs fixing before the kill-state enforcement path can be trusted at all.

## Not built at all

- `EnforcementBackend` trait (architecture §4c) — spec only, no implementation. `block_ip()`/`unblock_ip()` are called directly, not through a trait.
- Fd-passing actually wired end-to-end (agent opening its own capture instead of receiving the helper's fd — planned as "M2" per a comment in `agent/main.rs`)
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
