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
    PF_ANCHOR_NAME, PF_TABLE_NAME,
};
use synapse_platform_macos::protocol;

use enforce::MacOsEnforcementBackend;

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

fn ensure_anchor() -> io::Result<()> {
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

fn main() -> io::Result<()> {
    env_logger::init();

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        error!("synapsed-helper must run as root (euid={euid})");
        std::process::exit(1);
    }
    info!("synapsed-helper starting (pid={})", std::process::id());

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

    // 3. Enable pf (reference counted — safe to call multiple times).
    let enable = std::process::Command::new("pfctl").args(["-e"]).output()?;
    if !enable.status.success() {
        let stderr = String::from_utf8_lossy(&enable.stderr);
        warn!("pfctl -e warning: {stderr}");
    } else {
        info!("pf enabled");
    }

    // 4. Create IPC socket.
    let _ = std::fs::remove_file(IPC_SOCKET_PATH);
    let listener = std::os::unix::net::UnixListener::bind(IPC_SOCKET_PATH)?;
    // 0666 — world-accessible so the agent can physically connect.
    // Real access control is peer-credential authentication via getpeereid().
    std::fs::set_permissions(IPC_SOCKET_PATH, std::fs::Permissions::from_mode(0o666))?;
    info!("listening on {IPC_SOCKET_PATH} (mode 0666, peer-credential auth active)");

    // Resolve expected agent UID once — does not change across connections.
    let expected_uid = expected_agent_uid();

    // Enforcement backend created once — persists across connections, holding
    // active_blocks and TTL cancellation handles so unblock-timers fire
    // correctly even if the agent crashes and reconnects.
    let mut backend = MacOsEnforcementBackend::new();

    // 5. Accept loop — wait for an agent, run the enforcement loop, and return
    //    here when the agent disconnects so the next connection can be accepted.
    //    Everything inside is per-connection state that must not leak across loops.
    info!("waiting for synapse-agent to connect...");
    loop {
        // --- Accept and authenticate -----------------------------------------
        let (stream, _addr) = listener.accept()?;
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
                    "could not verify peer credentials (getpeereid failed) — \
                     allowing connection for backward compatibility"
                );
                info!("synapse-agent connected (unauthenticated)");
            }
        }

        // --- Handoff BPF fd -------------------------------------------------
        protocol::send_fd(&stream, bpf_raw_fd)?;
        // bpf_fd (OwnedFd) is NOT dropped here — kept alive so we can re-send
        // it to the next agent if the current one disconnects.  The agent's
        // received copy (via SCM_RIGHTS) is independent once the kernel dup's it.

        // --- Stream split ----------------------------------------------------
        let mut read_half = stream.try_clone()?;
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
                    if cancel_flag.load(Ordering::Relaxed) {
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
                        if cancel_flag.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            })
            .expect("failed to spawn cache-push thread");

        // --- Enforcement loop (read half — blocks until agent disconnects) ----
        info!("enforcement loop active");
        loop {
            match protocol::recv_message::<EnforcementCommand>(&mut read_half) {
                Ok(cmd) => {
                    info!("received command: {cmd:?}");
                    let result = match &cmd {
                        EnforcementCommand::Block { ip, ttl } => {
                            let block = ValidatedBlock { ip: *ip, ttl: *ttl };
                            backend.apply_block(block).map(|r| r.message)
                        }
                        EnforcementCommand::Unblock { ip } => {
                            let block_id = BlockId::from(*ip);
                            backend.remove_block(block_id).map(|r| r.message)
                        }
                        EnforcementCommand::KillState { src, dst, proto } => {
                            backend.kill_state(*src, *dst, *proto).map(|r| r.message)
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
        cancel.store(true, Ordering::Relaxed);
        // read_half is dropped here — closes the fd. write_half (moved into the
        // cache thread) is dropped when the thread exits, which happens promptly
        // because the write will fail after the fd closes.
        drop(read_half);
        let _ = cache_handle.join();
        info!("connection torn down, awaiting next agent...");
    }
}
