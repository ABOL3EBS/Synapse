// crates/platform-macos/src/helper/main.rs
//
// synapsed-helper — the root-privileged daemon.
//
// Responsibilities (and *only* these):
//   1. Open BPF device via pcap, bind to network interface.
//   2. Pass the BPF fd to synapse-agent via SCM_RIGHTS over a Unix socket.
//   3. Listen for typed EnforcementCommand messages from the agent.
//   4. Execute pfctl commands in a dedicated anchor to block/unblock IPs.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

use log::{error, info, warn};
use synapse_common::EnforcementCommand;

// ---------------------------------------------------------------------------
// pf Constants
// ---------------------------------------------------------------------------

const PF_ANCHOR_NAME: &str = "com.synapse.ips";
const PF_TABLE_NAME: &str = "synapse_blocklist";
const IPC_SOCKET_PATH: &str = "/tmp/synapse-helper.sock";

// ---------------------------------------------------------------------------
// SCM_RIGHTS — fd passing via raw libc
// ---------------------------------------------------------------------------

/// Send a file descriptor over a Unix domain socket using SCM_RIGHTS.
fn send_fd(stream: &UnixStream, fd_to_send: RawFd) -> io::Result<()> {
    let stream_fd: RawFd = std::os::fd::AsRawFd::as_raw_fd(stream);

    let cmsg_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };
    let mut cmsg_buf = vec![0u8; cmsg_len as usize];

    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_len;

    let cmsg = unsafe { &mut *(libc::CMSG_FIRSTHDR(&msg) as *mut libc::cmsghdr) };
    cmsg.cmsg_level = libc::SOL_SOCKET;
    cmsg.cmsg_type = libc::SCM_RIGHTS;
    cmsg.cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) };

    let data_ptr = unsafe { libc::CMSG_DATA(cmsg) } as *mut libc::c_int;
    unsafe { *data_ptr = fd_to_send };

    let ret = unsafe { libc::sendmsg(stream_fd, &msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a length-prefixed bincode message from the stream.
fn recv_message<D: for<'de> serde::Deserialize<'de>>(stream: &mut UnixStream) -> io::Result<D> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes"),
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;

    bincode::deserialize(&payload).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("bincode deserialize: {e}"))
    })
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("pfctl anchor init failed: {stderr}"),
        ));
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

fn block_ip(ip: IpAddr) -> io::Result<()> {
    let output = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-t", PF_TABLE_NAME, "-T", "add", &ip.to_string()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("pfctl table add failed for {ip}: {stderr}"),
        ));
    }
    info!("pfctl: added {ip} to table '{PF_TABLE_NAME}'");
    Ok(())
}

fn unblock_ip(ip: IpAddr) -> io::Result<()> {
    let output = std::process::Command::new("pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-t", PF_TABLE_NAME, "-T", "delete", &ip.to_string()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("pfctl table delete failed for {ip}: {stderr}");
    } else {
        info!("pfctl: removed {ip} from table '{PF_TABLE_NAME}'");
    }
    Ok(())
}

fn enforce(command: &EnforcementCommand, active_blocks: &mut HashSet<IpAddr>) -> io::Result<()> {
    match command {
        EnforcementCommand::Block { ip, ttl } => {
            block_ip(*ip)?;
            active_blocks.insert(*ip);
            let ip = *ip;
            let ttl = *ttl;
            std::thread::spawn(move || {
                std::thread::sleep(ttl);
                if let Err(e) = unblock_ip(ip) {
                    error!("TTL unblock failed for {ip}: {e}");
                }
                info!("TTL expired: unblocked {ip}");
            });
            Ok(())
        }
        EnforcementCommand::Unblock { ip } => {
            unblock_ip(*ip)?;
            active_blocks.remove(ip);
            Ok(())
        }
        EnforcementCommand::KillState { src, dst, proto } => {
            let proto_str = match proto {
                6 => "tcp",
                17 => "udp",
                _ => "all",
            };
            let output = std::process::Command::new("pfctl")
                .args(["-k", &format!("{proto_str} from {src} to {dst}")])
                .output()?;
            if !output.status.success() {
                warn!("pfctl kill state failed: {}", String::from_utf8_lossy(&output.stderr));
            } else {
                info!("pfctl: killed state {proto_str} {src} → {dst}");
            }
            Ok(())
        }
    }
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

    // 1. Open capture device via pcap — handles all BPF ioctl quirks.
    let interface = std::env::var("SYNAPSE_IFACE").unwrap_or_else(|_| "en0".to_string());
    info!("opening capture on interface: {interface}");

    // Configure before opening (Capture<Inactive> builder methods).
    let mut cap = pcap::Capture::from_device(interface.as_str())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("pcap: {e}")))?
        .buffer_size(1024 * 1024)
        .immediate_mode(true)
        .open()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("pcap open: {e}")))?;

    // Set BPF filter: IP traffic only.
    cap.filter("ip", true)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("pcap filter: {e}")))?;

    info!("capture configured: buffer=1MiB, immediate=true, filter=ip");

    // Get the raw BPF file descriptor from pcap and dup it before dropping.
    use std::os::fd::AsRawFd;
    let bpf_fd = cap.as_raw_fd();
    let bpf_fd_owned = unsafe { libc::dup(bpf_fd) };
    if bpf_fd_owned < 0 {
        return Err(io::Error::last_os_error());
    }
    drop(cap);
    let bpf_fd = bpf_fd_owned;
    info!("BPF fd ready: {bpf_fd}");

    // 2. Initialise pf anchor.
    ensure_anchor()?;

    // 3. Create IPC socket and wait for agent.
    let _ = std::fs::remove_file(IPC_SOCKET_PATH);
    let listener = std::os::unix::net::UnixListener::bind(IPC_SOCKET_PATH)?;
    // chmod so unprivileged agent can connect.
    std::fs::set_permissions(
        IPC_SOCKET_PATH,
        std::fs::Permissions::from_mode(0o666),
    )?;
    info!("listening on {IPC_SOCKET_PATH} (mode 0666)");

    info!("waiting for synapse-agent to connect...");
    let (mut stream, _addr) = listener.accept()?;
    info!("synapse-agent connected");

    // 4. Send BPF fd via SCM_RIGHTS.
    // The kernel dups the fd into the receiver's table; our copy stays open.
    // Close our copy so only the agent holds it (privilege separation).
    send_fd(&stream, bpf_fd)?;
    unsafe { libc::close(bpf_fd) };
    info!("sent BPF fd to agent via SCM_RIGHTS (helper copy closed)");

    // 5. Enforcement loop.
    info!("entering enforcement loop...");
    let mut active_blocks: HashSet<IpAddr> = HashSet::new();

    loop {
        match recv_message::<EnforcementCommand>(&mut stream) {
            Ok(cmd) => {
                info!("received command: {cmd:?}");
                if let Err(e) = enforce(&cmd, &mut active_blocks) {
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
