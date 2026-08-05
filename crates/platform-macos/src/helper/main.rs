// crates/platform-macos/src/helper/main.rs
//
// synapsed-helper — the root-privileged daemon.
//
// Responsibilities (and *only* these):
//   1. Open BPF device, bind to network interface.
//   2. Pass the BPF fd to synapse-agent via SCM_RIGHTS over a Unix socket.
//   3. Listen for typed EnforcementCommand messages from the agent.
//   4. Execute pfctl commands in a dedicated anchor to block/unblock IPs.

mod enforce;
mod reconcile_db;

use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use log::{error, info, warn};
use synapse_common::{
    BlockId, EnforcementBackend, EnforcementCommand, IpcMessage, ValidatedBlock, IPC_SOCKET_PATH,
    MAX_CONCURRENT_BLOCKS, PF_ANCHOR_NAME, PF_TABLE_NAME,
};
use synapse_platform_macos::protocol;

use enforce::MacOsEnforcementBackend;

const HELPER_PID_FILE: &str = "/var/run/synapsed-helper.pid";

/// Path to the trigger file that signals the helper to run a reconcile pass
/// without waiting for the next 60-second periodic interval.
/// Written by the dashboard's request_unblock command; deleted by the helper
/// before running the reconcile so it is not re-triggered on the next cycle.
fn trigger_file_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    std::path::PathBuf::from(home)
        .join(".synapse")
        .join("reconcile-now")
}

// ---------------------------------------------------------------------------
// Peer credential authentication
// ---------------------------------------------------------------------------

/// Get the effective UID of the peer connected on a Unix domain socket.
/// Uses getpeereid() — available on macOS/BSD, not Linux.
/// Returns None if the call fails (non-Unix socket, kernel limitation).
fn get_peer_uid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    extern "C" {
        fn getpeereid(
            fd: std::os::raw::c_int,
            euid: *mut libc::uid_t,
            egid: *mut libc::gid_t,
        ) -> std::os::raw::c_int;
    }
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let ret = unsafe { getpeereid(fd, &mut uid, &mut gid) };
    if ret == 0 {
        Some(uid)
    } else {
        None
    }
}

/// Determine the expected UID for the agent process.
///
/// Priority:
///   1. SYNAPSE_AGENT_UID — set by launchd via plist EnvironmentVariables.
///      This is the production path: the plist declares which user runs the agent.
///   2. SUDO_UID — set by sudo during dev/testing (`sudo cargo run --bin synapsed-helper`).
///   3. Fallback: current process UID (root) — only accepts connections from root.
fn expected_agent_uid() -> u32 {
    // Production path: launchd plist sets SYNAPSE_AGENT_UID.
    if let Ok(uid_str) = std::env::var("SYNAPSE_AGENT_UID") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            return uid;
        }
    }
    // Dev/testing path: sudo sets SUDO_UID.
    if let Ok(uid_str) = std::env::var("SUDO_UID") {
        if let Ok(uid) = uid_str.parse::<u32>() {
            return uid;
        }
    }
    // Fallback: only accept root — safe default when no env var is set.
    unsafe { libc::getuid() }
}

/// Check whether an IP is unsafe to block/kill at the enforcement boundary.
/// Defense-in-depth: rejects loopback, multicast, broadcast, link-local,
/// and unspecified addresses even if the agent's guard was bypassed.
fn is_unsafe_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
        }
    }
}

// ---------------------------------------------------------------------------
// BPF filter for IP traffic (both IPv4 and IPv6)
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u32,
    filter: *const SockFilter,
}

/// BPF program: pass if EtherType is IPv4 (0x0800) OR IPv6 (0x86DD), else drop.
///
/// [0] LD [12]                    — load 2-byte EtherType from Ethernet header
/// [1] JEQ 0x0800, jt=2, jf=0    — IPv4? → jump to [4] (RET 65535 = pass)
/// [2] JEQ 0x86DD, jt=1, jf=0    — IPv6? → jump to [4] (RET 65535 = pass)
/// [3] RET 0                      — neither → drop
/// [4] RET 65535                  — pass full packet
const BPF_IPV4_IPV6_FILTER: &[SockFilter] = &[
    SockFilter {
        code: 0x28,
        jt: 0,
        jf: 0,
        k: 12,
    }, // LD [12]
    SockFilter {
        code: 0x15,
        jt: 2,
        jf: 0,
        k: 0x0800,
    }, // JEQ 0x0800 → [4]
    SockFilter {
        code: 0x15,
        jt: 1,
        jf: 0,
        k: 0x86DD,
    }, // JEQ 0x86DD → [4]
    SockFilter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0,
    }, // RET 0 (drop)
    SockFilter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 65535,
    }, // RET 65535 (pass)
];

// ---------------------------------------------------------------------------
// BPF device setup (raw, no pcap)
// ---------------------------------------------------------------------------

/// Open /dev/bpfN and configure it for the given interface.
/// Returns the BPF file descriptor ready for packet capture.
fn open_bpf_device(interface: &str) -> io::Result<std::os::unix::io::OwnedFd> {
    // Try /dev/bpf0 through /dev/bpf9.
    let mut last_err = None;
    for i in 0..10 {
        let path = format!("/dev/bpf{i}");
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(f) => {
                info!("opened {path}");
                let fd = std::os::fd::IntoRawFd::into_raw_fd(f);

                // Step 1: BIOCSBLEN — set buffer size FIRST, before BIOCSETIF.
                // "The buffer must be set before the file is attached to an
                //  interface with BIOCSETIF." — bpf(4) man page.
                let mut buf_len: u32 = 1024 * 1024;
                let ret = unsafe { libc::ioctl(fd, libc::BIOCSBLEN, &mut buf_len) };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    warn!("BIOCSBLEN failed on {path}: {err}");
                    unsafe { libc::close(fd) };
                    last_err = Some(err);
                    continue;
                }
                info!("BPF buffer: {buf_len} bytes");

                // Step 2: BIOCSETIF — bind to interface (must come after BIOCSBLEN).
                let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
                let ifname = CString::new(interface)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let name_bytes = ifname.to_bytes_with_nul();
                let copy_len = name_bytes.len().min(libc::IFNAMSIZ);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        name_bytes.as_ptr(),
                        ifr.ifr_name.as_mut_ptr() as *mut u8,
                        copy_len,
                    );
                }
                let ret = unsafe { libc::ioctl(fd, libc::BIOCSETIF, &mut ifr) };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    warn!("BIOCSETIF failed on {path}: {err}");
                    unsafe { libc::close(fd) };
                    last_err = Some(err);
                    continue;
                }
                info!("bound to interface: {interface}");

                // Step 3: BIOCIMMEDIATE — deliver packets as soon as they arrive
                // (must come after BIOCSETIF).
                let mut immediate: i32 = 1;
                let ret = unsafe { libc::ioctl(fd, libc::BIOCIMMEDIATE, &mut immediate) };
                if ret < 0 {
                    warn!("BIOCIMMEDIATE failed: {}", io::Error::last_os_error());
                }

                // Step 4: BIOCSETF — set BPF filter (must come after BIOCSETIF).
                let prog = SockFprog {
                    len: BPF_IPV4_IPV6_FILTER.len() as u32,
                    filter: BPF_IPV4_IPV6_FILTER.as_ptr(),
                };
                let ret = unsafe { libc::ioctl(fd, libc::BIOCSETF, &prog) };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    warn!("BIOCSETF failed: {err}");
                    unsafe { libc::close(fd) };
                    last_err = Some(err);
                    continue;
                }
                info!("BPF filter set (IPv4 + IPv6)");

                // Wrap in OwnedFd so it's properly closed on drop.
                let owned = unsafe { std::os::unix::io::OwnedFd::from_raw_fd(fd) };
                return Ok(owned);
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no /dev/bpf* device found")))
}

// ---------------------------------------------------------------------------
// pfctl — Anchor and Table Management
// ---------------------------------------------------------------------------

/// Acquire an advisory file lock to serialize concurrent helpers during
/// `ensure_anchor()`. The lock is auto-released when the returned `OwnedFd`
/// is dropped.
fn acquire_pf_lock() -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, IntoRawFd};
    let lock_path = "/var/run/synapse-helper.lock";
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .map_err(|e| io::Error::other(format!("open pf lock: {e}")))?;
    let fd = file.into_raw_fd();
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(io::Error::other(format!("flock failed: {err}")));
    }
    // Safety: we own the fd and it is valid.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

fn ensure_anchor() -> io::Result<()> {
    // Serialize concurrent helpers — prevents TOCTOU on /etc/pf.conf.
    let _lock = acquire_pf_lock()?;

    // 1. Flush the anchor to clear stale rules from previous runs or manual testing.
    let flush = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-F", "all"])
        .output();
    if let Ok(o) = flush {
        if !o.status.success() {
            // Anchor may not exist yet — that's fine, the next step creates it.
            info!(
                "anchor flush (first run or already clean): {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
    }

    // 2. Load rules into the anchor.
    // Rules:
    //   block out quick to <table>  — prevent outbound to blocked IPs
    //     (C2 beaconing, data exfiltration, lateral movement)
    //   block in quick from <table> — prevent inbound from blocked IPs
    //     (separate attack direction: remote host initiating contact toward
    //      this machine, independent of whether we also block outbound to it)
    let anchor_rules = format!(
        "table <{PF_TABLE_NAME}> persist\n\
         block out quick to <{PF_TABLE_NAME}>\n\
         block in quick from <{PF_TABLE_NAME}>\n"
    );
    let mut child = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(anchor_rules.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "pfctl anchor rules load failed: {stderr}"
        )));
    }
    info!("pf anchor '{PF_ANCHOR_NAME}' with table '{PF_TABLE_NAME}' ready");

    // 3. Ensure the anchor is referenced from the main ruleset.
    //    Without this, pf never evaluates the anchor rules — no states
    //    created, no blocks enforced. See /etc/pf.conf.
    let pf_conf = fs::read_to_string("/etc/pf.conf")
        .map_err(|e| io::Error::other(format!("failed to read /etc/pf.conf: {e}")))?;

    let anchor_line = format!("anchor \"{PF_ANCHOR_NAME}\" all");
    if !pf_conf.lines().any(|l| l.trim() == anchor_line) {
        info!("adding anchor '{PF_ANCHOR_NAME}' to /etc/pf.conf");
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open("/etc/pf.conf")
            .map_err(|e| io::Error::other(format!("failed to open /etc/pf.conf: {e}")))?;
        writeln!(f, "\n{anchor_line}\n")?;
    }

    // 4. Reload main ruleset so the anchor is always active (even on restart).
    let reload = std::process::Command::new("pfctl")
        .args(["-f", "/etc/pf.conf"])
        .output()?;
    if !reload.status.success() {
        let stderr = String::from_utf8_lossy(&reload.stderr);
        warn!("pfctl main ruleset reload warning: {stderr}");
    } else {
        info!("main ruleset reloaded — anchor '{PF_ANCHOR_NAME}' active");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    synapse_common::log_format::init_logging();
    if let Err(e) = run() {
        log::error!("helper exited with fatal error: {e:?} ({e})");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        error!("synapsed-helper must run as root (euid={euid})");
        std::process::exit(1);
    }
    info!("synapsed-helper starting (pid={})", std::process::id());

    // Write PID file so the dashboard can check liveness via kill(pid, 0).
    // Non-fatal: if /var/run/ is inaccessible, log and continue — the dashboard
    // will report "helper offline" but enforcement is unaffected.
    if let Err(e) = std::fs::write(HELPER_PID_FILE, format!("{}\n", std::process::id())) {
        warn!("could not write PID file {HELPER_PID_FILE}: {e}");
    } else {
        info!("PID file written: {HELPER_PID_FILE}");
    }

    // 1. Open and configure BPF device (raw, no pcap).
    //    The fd is opened once and kept alive for the lifetime of the helper so
    //    it can be handed to each new agent connection via SCM_RIGHTS.
    let interface = std::env::var("SYNAPSE_IFACE").unwrap_or_else(|_| "en0".to_string());
    info!("opening BPF on interface: {interface}");

    let bpf_fd = open_bpf_device(&interface)?;
    let bpf_raw_fd = bpf_fd.as_raw_fd();
    info!("BPF device configured and ready");

    // 2. Initialise pf anchor (idempotent — safe across reconnection cycles).
    ensure_anchor()?;

    // 2b. Startup reconcile: sync the live pf table with the agent's DB before
    //     accepting any connections. Recovers from: prior crash left orphan blocks,
    //     or someone flushed pf while the helper was down.
    //     Non-fatal: if the DB doesn't exist yet (agent hasn't run), skip silently.
    {
        let mut startup_backend = enforce::MacOsEnforcementBackend::new();
        let db_path = reconcile_db::agent_db_path();
        match reconcile_db::open_read_only(&db_path) {
            Ok(conn) => match reconcile_db::query_desired_state(&conn) {
                Ok(desired) => {
                    use synapse_common::EnforcementBackend;
                    match startup_backend.reconcile(&desired) {
                        Ok(report) => info!(
                            "[RECONCILE] startup pass: removed {} orphan(s), restored {} block(s), {} error(s)",
                            report.orphans_removed, report.re_applied, report.errors.len()
                        ),
                        Err(e) => warn!("[RECONCILE] startup reconcile failed: {e}"),
                    }
                }
                Err(e) => warn!("[RECONCILE] startup: could not query desired state: {e}"),
            },
            Err(e) => info!("[RECONCILE] startup: DB not available ({e}) — skipping"),
        }
    }

    // 3. Enable pf (reference counted — safe to call multiple times).
    let enable = std::process::Command::new("pfctl").args(["-e"]).output()?;
    if !enable.status.success() {
        let stderr = String::from_utf8_lossy(&enable.stderr);
        warn!("pfctl -e warning: {stderr}");
    } else {
        info!("pf enabled");
    }

    // 4. Create IPC socket.
    //    Bind-first pattern: avoid TOCTOU from preemptive remove_file.
    //    If bind fails with EADDRINUSE (stale socket from previous crash),
    //    remove the stale socket and retry once.
    let listener = match std::os::unix::net::UnixListener::bind(IPC_SOCKET_PATH) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            info!("stale socket detected — removing and rebinding");
            std::fs::remove_file(IPC_SOCKET_PATH)
                .map_err(|e| io::Error::other(format!("failed to remove stale socket: {e}")))?;
            std::os::unix::net::UnixListener::bind(IPC_SOCKET_PATH)?
        }
        Err(e) => return Err(e),
    };
    // 0666 — world-accessible so the non-root agent can connect.
    // Real access control is peer-credential authentication via getpeereid()
    // — see S1 fix below which rejects unauthenticated connections.
    std::fs::set_permissions(IPC_SOCKET_PATH, std::fs::Permissions::from_mode(0o666))?;
    info!("listening on {IPC_SOCKET_PATH} (mode 0666, peer-credential auth active)");

    // Signal handler — clean shutdown on SIGINT/SIGTERM.
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::Release);
        })
        .map_err(|e| io::Error::other(format!("signal handler: {e}")))?;
    }

    // Non-blocking accept so we can check the RUNNING flag periodically.
    listener.set_nonblocking(true)?;

    // Resolve expected agent UID once — does not change across connections.
    let expected_uid = expected_agent_uid();

    // Enforcement backend created once — persists across connections, holding
    // active_blocks and TTL cancellation handles so unblock-timers fire
    // correctly even if the agent crashes and reconnects.
    let mut backend = MacOsEnforcementBackend::new();

    // 5a. Periodic reconcile thread: re-sync live pf table vs DB every 60 s.
    //     Detects and corrects external tampering (manual pfctl flush, another tool
    //     modifying the anchor) without waiting for an agent-initiated enforcement
    //     command. 60 s is appropriate — pfctl subprocess cost makes 5 s too noisy.
    {
        let reconcile_running = Arc::clone(&running);
        thread::Builder::new()
            .name("reconcile-periodic".to_string())
            .spawn(move || {
                use synapse_common::EnforcementBackend;
                let mut periodic_backend = enforce::MacOsEnforcementBackend::new();
                while reconcile_running.load(Ordering::Acquire) {
                    // Poll 1 s/tick. Exits early when the dashboard writes the trigger
                    // file (unblock request), otherwise waits up to 60 ticks (60 s).
                    let trigger = trigger_file_path();
                    let mut ticks = 0u32;
                    let triggered = 'wait: loop {
                        if !reconcile_running.load(Ordering::Acquire) {
                            break 'wait false;
                        }
                        if trigger.exists() {
                            let _ = std::fs::remove_file(&trigger);
                            break 'wait true;
                        }
                        thread::sleep(Duration::from_secs(1));
                        ticks += 1;
                        if ticks >= 60 {
                            break 'wait false;
                        }
                    };
                    if !reconcile_running.load(Ordering::Acquire) {
                        break;
                    }
                    let source = if triggered { "triggered" } else { "periodic" };
                    let db_path = reconcile_db::agent_db_path();
                    match reconcile_db::open_read_only(&db_path) {
                        Ok(conn) => match reconcile_db::query_desired_state(&conn) {
                            Ok(desired) => match periodic_backend.reconcile(&desired) {
                                Ok(report) => info!(
                                    "[RECONCILE] {source} pass: removed {} orphan(s), restored {} block(s), {} error(s)",
                                    report.orphans_removed, report.re_applied, report.errors.len()
                                ),
                                Err(e) => warn!("[RECONCILE] {source} reconcile failed: {e}"),
                            },
                            Err(e) => warn!("[RECONCILE] {source}: could not query desired state: {e}"),
                        },
                        Err(e) => log::debug!("[RECONCILE] {source}: DB not available ({e})"),
                    }
                }
            })
            .map_err(|e| io::Error::other(format!("spawn reconcile-periodic: {e}")))?;
    }

    // 5. Accept loop — wait for an agent, run the enforcement loop, and return
    //    here when the agent disconnects so the next connection can be accepted.
    //    Everything inside is per-connection state that must not leak across loops.
    info!("waiting for synapse-agent to connect...");
    while running.load(Ordering::Acquire) {
        // --- Accept and authenticate -----------------------------------------
        let (stream, _addr) = match listener.accept() {
            Ok(pair) => {
                // Reset to blocking mode — macOS inherits O_NONBLOCK from the
                // listening socket; the enforcement loop needs blocking reads.
                pair.0
                    .set_nonblocking(false)
                    .map_err(|e| io::Error::other(format!("set stream blocking: {e}")))?;
                pair
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e),
        };
        info!("incoming connection");

        match get_peer_uid(&stream) {
            Some(peer_uid) if peer_uid == expected_uid => {
                info!("synapse-agent connected (peer uid={peer_uid}, authenticated)");
            }
            Some(peer_uid) => {
                warn!(
                    "rejecting connection: peer uid={peer_uid}, expected uid={expected_uid} \
                     (wrong user)"
                );
                // Drop the stream — closes the connection — then loop to accept()
                // the next one. Returning an error would kill the helper entirely.
                continue;
            }
            None => {
                warn!(
                    "rejecting connection: could not verify peer credentials \
                     (getpeereid failed) — refusing unauthenticated access to root daemon"
                );
                continue;
            }
        }

        // --- Handoff BPF fd -------------------------------------------------
        if let Err(e) = protocol::send_fd(&stream, bpf_raw_fd) {
            warn!("fd handoff failed: {e} — rejecting connection");
            continue;
        }
        // bpf_fd (OwnedFd) is NOT dropped here — kept alive so we can re-send
        // it to the next agent if the current one disconnects.  The agent's
        // received copy (via SCM_RIGHTS) is independent once the kernel dup's it.

        // --- Stream split ----------------------------------------------------
        let mut read_half = match stream.try_clone() {
            Ok(s) => s,
            Err(e) => {
                warn!("stream clone failed: {e} — rejecting connection");
                continue;
            }
        };
        let write_half = stream;

        // --- Cache-push thread (per-connection) ------------------------------
        // Cancelled via AtomicBool when the agent disconnects so we don't block
        // for 5 seconds on join() before returning to accept().
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_flag = cancel.clone();
        let cache_handle = thread::Builder::new()
            .name("port-pid-cache".to_string())
            .spawn(move || {
                let mut writer = write_half;
                loop {
                    if cancel_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let cache = synapse_platform_macos::process_lookup::build_port_pid_cache();
                    let msg = IpcMessage::PortPidCache(cache);
                    if let Err(e) = protocol::send_message(&mut writer, &msg) {
                        error!("cache-push: send failed: {e}");
                        break;
                    }
                    // Sleep in 1 s increments so cancellation is noticed within 1 s
                    // instead of blocking for the full 5 s interval.
                    for _ in 0..5 {
                        if cancel_flag.load(Ordering::Acquire) {
                            break;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .map_err(|e| io::Error::other(format!("spawn cache-push: {e}")))?;

        // --- Enforcement loop (read half — blocks until agent disconnects) ----
        info!("enforcement loop active");
        let mut recv_buf = Vec::with_capacity(64 * 1024);
        loop {
            match protocol::recv_message_into::<EnforcementCommand>(&mut read_half, &mut recv_buf) {
                Ok(cmd) => {
                    info!("[ENFORCE] received command: {cmd:?}");
                    let result = match &cmd {
                        EnforcementCommand::Block { ip, ttl } => {
                            // S3: Enforce concurrent block limit before validation.
                            if backend.active_block_count() >= MAX_CONCURRENT_BLOCKS {
                                Err(format!(
                                    "block rejected: at capacity ({}/{MAX_CONCURRENT_BLOCKS})",
                                    backend.active_block_count(),
                                ))
                            } else {
                                // S4: Validate IP and TTL via try_new — rejects
                                // loopback, multicast, broadcast, link-local,
                                // unspecified, and out-of-range TTLs.
                                match ValidatedBlock::try_new(*ip, *ttl) {
                                    Ok(block) => backend.apply_block(block).map(|r| r.message),
                                    Err(e) => Err(format!("block rejected for {ip}: {e}")),
                                }
                            }
                        }
                        EnforcementCommand::Unblock { ip } => {
                            let block_id = BlockId::from(*ip);
                            backend.remove_block(block_id).map(|r| r.message)
                        }
                        EnforcementCommand::KillState { src, dst, proto } => {
                            // S3: Defense-in-depth — reject dangerous IP pairs
                            // even if the agent's guard was bypassed.
                            if is_unsafe_ip(*src) || is_unsafe_ip(*dst) {
                                Err(format!(
                                    "kill_state rejected: unsafe IP in pair {src} → {dst}"
                                ))
                            } else {
                                backend.kill_state(*src, *dst, *proto).map(|r| r.message)
                            }
                        }
                    };
                    if let Err(e) = result {
                        error!("enforcement failed for {cmd:?}: {e}");
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    info!("agent disconnected (clean EOF)");
                    break;
                }
                Err(e) => {
                    error!("IPC error: {e}");
                    break;
                }
            }
        }

        // --- Per-connection teardown ------------------------------------------
        // Signal cache-push thread to stop. It will observe the flag on its next
        // iteration (within 1 s) and exit; the write will also fail once the
        // stream is dropped.
        cancel.store(true, Ordering::Release);
        // read_half is dropped here — closes the fd. write_half (moved into the
        // cache thread) is dropped when the thread exits, which happens promptly
        // because the write will fail after the fd closes.
        drop(read_half);
        let _ = cache_handle.join();
        if !running.load(Ordering::Acquire) {
            info!("signal received — shutting down...");
            break;
        }
        info!("connection torn down, awaiting next agent...");
    }

    // --- Clean shutdown -------------------------------------------------------
    // Flush the pf block table so a restarted helper starts clean.
    let flush = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-t", PF_TABLE_NAME, "-T", "flush"])
        .output();
    if let Ok(o) = flush {
        if o.status.success() {
            info!("pf table flushed on shutdown");
        }
    }
    let _ = std::fs::remove_file(IPC_SOCKET_PATH);
    let _ = std::fs::remove_file(HELPER_PID_FILE);
    info!("helper shut down cleanly");
    Ok(())
}
