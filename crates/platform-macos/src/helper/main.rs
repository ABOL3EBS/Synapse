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
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;

use log::{error, info, warn};
use synapse_common::{BlockId, EnforcementBackend, EnforcementCommand, ValidatedBlock};
use synapse_platform_macos::protocol;

use enforce::MacOsEnforcementBackend;

// ---------------------------------------------------------------------------
// pf Constants
// ---------------------------------------------------------------------------

const PF_ANCHOR_NAME: &str = "com.synapse.ips";
const PF_TABLE_NAME: &str = "synapse_blocklist";
const IPC_SOCKET_PATH: &str = "/tmp/synapse-helper.sock";

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
    len: u16,
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
                    len: BPF_IPV4_IPV6_FILTER.len() as u16,
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
    let status = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-f", "-"])
        .stdin(std::process::Stdio::null())
        .output()?;

    if !status.status.success() {
        let stderr = String::from_utf8_lossy(&status.stderr);
        return Err(io::Error::other(format!(
            "pfctl anchor init failed: {stderr}"
        )));
    }

    let anchor_rules = format!(
        "table <{PF_TABLE_NAME}> persist\n\
         pass out quick to <{PF_TABLE_NAME}>\n\
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
        warn!("pfctl table setup warning: {stderr}");
    } else {
        info!("pf anchor '{PF_ANCHOR_NAME}' with table '{PF_TABLE_NAME}' ready");
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
    let interface = std::env::var("SYNAPSE_IFACE").unwrap_or_else(|_| "en0".to_string());
    info!("opening BPF on interface: {interface}");

    let bpf_fd = open_bpf_device(&interface)?;
    info!("BPF device configured and ready");

    // 2. Initialise pf anchor.
    ensure_anchor()?;

    // 3. Create IPC socket and wait for agent.
    let _ = std::fs::remove_file(IPC_SOCKET_PATH);
    let listener = std::os::unix::net::UnixListener::bind(IPC_SOCKET_PATH)?;
    // chmod so unprivileged agent can connect.
    std::fs::set_permissions(IPC_SOCKET_PATH, std::fs::Permissions::from_mode(0o666))?;
    info!("listening on {IPC_SOCKET_PATH} (mode 0666)");

    info!("waiting for synapse-agent to connect...");
    let (mut stream, _addr) = listener.accept()?;
    info!("synapse-agent connected");

    // 4. Send BPF fd via SCM_RIGHTS.
    let raw_fd = bpf_fd.as_raw_fd();
    protocol::send_fd(&stream, raw_fd)?;
    // Drop OwnedFd — closes helper's copy. Agent now solely holds the fd.
    drop(bpf_fd);
    info!("sent BPF fd to agent via SCM_RIGHTS (helper copy closed)");

    // 5. Enforcement loop.
    info!("entering enforcement loop...");
    let mut backend = MacOsEnforcementBackend::new();

    loop {
        match protocol::recv_message::<EnforcementCommand>(&mut stream) {
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
                    // KillState: kept as direct pfctl call for now — broken syntax,
                    // will be fixed in Step 3.
                    EnforcementCommand::KillState { src, dst, proto } => {
                        let proto_str = match proto {
                            6 => "tcp",
                            17 => "udp",
                            _ => "all",
                        };
                        let output = std::process::Command::new("pfctl")
                            .args(["-k", &format!("{proto_str} from {src} to {dst}")])
                            .output();
                        match output {
                            Ok(o) if o.status.success() => {
                                info!("pfctl: killed state {proto_str} {src} → {dst}");
                                Ok("state killed".to_string())
                            }
                            Ok(o) => Err(format!(
                                "pfctl kill failed: {}",
                                String::from_utf8_lossy(&o.stderr)
                            )),
                            Err(e) => Err(format!("pfctl spawn failed: {e}")),
                        }
                    }
                };
                if let Err(e) = result {
                    error!("enforcement failed for {cmd:?}: {e}");
                }
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                info!("agent disconnected");
                break;
            }
            Err(e) => {
                error!("IPC error: {e}");
                break;
            }
        }
    }

    info!("synapsed-helper shutting down");
    let _ = std::fs::remove_file(IPC_SOCKET_PATH);
    Ok(())
}
