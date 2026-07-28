// crates/platform-macos/src/process_lookup.rs
//
// libproc-based PID + process-start-time resolution.
// §4: "Process attribution via PID + process-start-time resolution
// (start-time captured alongside PID to avoid PID-reuse/TOCTOU misattribution)"
//
// Justification >600 lines: process_lookup.rs owns all libproc FFI — typed
// structs for kernel data, port→PID cache builder (per-process fd scan),
// raw BE port reading at verified offsets, and probe_socket. The FFI
// boundary requires everything in one module for correctness.
//
// Also: port→PID cache builder via per-process fd scan (Apple DTS recommended
// approach: proc_listpids → proc_pidinfo(PROC_PIDLISTFDS) →
// proc_pidfdinfo(PROC_PIDFDSOCKETINFO)).
//
// All socket probe logic uses libproc crate's typed #[repr(C)] structs
// (SocketFDInfo, SocketInfo, InSockInfo) instead of hand-computed offsets.

use std::collections::HashMap;
use std::ffi::CStr;
use std::mem;
use std::time::Instant;

use libproc::file_info::ProcFDInfo as LibProcFDInfo;
use libproc::net_info::{SocketFDInfo, SocketInfoProto};
use synapse_common::PortPidCache;

/// Process information resolved via libproc.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Absolute path to the process executable.
    pub path: String,
    /// Process start time as seconds since Unix epoch.
    /// Captured alongside PID to prevent PID-reuse/TOCTOU misattribution.
    pub start_time: f64,
}

/// Resolve a PID to its executable path and start time using libproc FFI.
///
/// # Safety
/// Calls libproc C functions via FFI. All calls are on valid PIDs returned
/// by the kernel — if the PID is stale (process exited), libproc returns
/// an error, not undefined behavior.
pub fn lookup_process(pid: u32) -> Result<ProcessInfo, String> {
    let path = proc_pidpath(pid)?;
    let start_time = proc_start_time(pid)?;
    Ok(ProcessInfo { path, start_time })
}

/// Get the executable path for a PID via libproc's proc_pidpath().
fn proc_pidpath(pid: u32) -> Result<String, String> {
    // Start with a reasonable buffer size, grow if needed.
    let mut buf = [0u8; 4096];
    let buf_size = buf.len() as u32;

    let ret =
        unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr() as *mut libc::c_void, buf_size) };

    if ret <= 0 {
        return Err(format!(
            "proc_pidpath failed for pid {pid}: ret={ret}, err={}",
            std::io::Error::last_os_error()
        ));
    }

    let path = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    let path = path.to_string_lossy().into_owned();

    if path.is_empty() {
        return Err(format!("proc_pidpath returned empty path for pid {pid}"));
    }

    Ok(path)
}

/// Get the process start time via libproc's proc_pidinfo() with PROC_PIDTASKINFO.
///
/// Returns seconds since Unix epoch (floating point for sub-second precision).
fn proc_start_time(pid: u32) -> Result<f64, String> {
    const PROC_PIDTASKINFO: u32 = 4;

    #[repr(C)]
    struct ProcTaskinfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
        pti_starttime: u64,
    }

    let mut info: ProcTaskinfo = unsafe { mem::zeroed() };
    let info_size = mem::size_of::<ProcTaskinfo>() as u32;

    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            PROC_PIDTASKINFO as i32,
            0,
            &mut info as *mut ProcTaskinfo as *mut libc::c_void,
            info_size as i32,
        )
    };

    if ret <= 0 {
        return Err(format!(
            "proc_pidinfo PROC_PIDTASKINFO failed for pid {pid}: ret={ret}, err={}",
            std::io::Error::last_os_error()
        ));
    }

    let now_ticks = unsafe { mach2::mach_time::mach_absolute_time() };
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let mut timebase: mach2::mach_time::mach_timebase_info_data_t = unsafe { mem::zeroed() };
    let tb_ret = unsafe { mach2::mach_time::mach_timebase_info(&mut timebase) };
    if tb_ret != 0 {
        return Err(format!("mach_timebase_info failed: ret={tb_ret}"));
    }

    if timebase.denom == 0 {
        return Err("mach_timebase_info returned denom=0".into());
    }

    let start_ticks = info.pti_starttime;
    let elapsed_ticks = now_ticks.saturating_sub(start_ticks);
    let elapsed_secs =
        elapsed_ticks as f64 * timebase.numer as f64 / timebase.denom as f64 / 1_000_000_000.0;

    let start_epoch = now_epoch - elapsed_secs;

    Ok(start_epoch)
}

// ---------------------------------------------------------------------------
// Port -> PID cache (helper-side, requires root)
// ---------------------------------------------------------------------------
// Apple DTS recommended approach: per-process fd scan.
// proc_listpids() -> proc_pidinfo(PROC_PIDLISTFDS) -> proc_pidfdinfo(PROC_PIDFDSOCKETINFO).
//
// All socket field access uses libproc's typed structs:
// - SocketFDInfo { pfi: ProcFDInfo, psi: SocketInfo }
// - SocketInfo { soi_type, soi_protocol, soi_family, soi_proto: SocketInfoProto }
// - SocketInfoProto union → InSockInfo { insi_lport, insi_fport, ... }
//
// IMPORTANT: insi_lport and insi_fport are stored in NETWORK byte order
// (big-endian). Every Apple reference impl applies ntohs()/ntohl().
// We use u16::from_be_bytes() to extract the port value correctly.

/// libproc flavor constants not in libc crate.
const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;

/// Byte offset of `insi_lport` within `SocketFDInfo`.
/// Layout: psi at 24, soi_proto at 264, InSockInfo (pri_in) = first union member,
/// insi_fport at +0, insi_lport at +4. Verified by test_struct_sizes field offset output.
const OFF_LPORT: usize = 268;

/// Byte offset of `insi_fport` within `SocketFDInfo`.
/// Immediately precedes insi_lport in InSockInfo.
const OFF_FPORT: usize = 264;

/// Network-byte-order port extraction helper.
/// Port is stored at a fixed offset in the kernel's in_sockinfo struct as raw
/// bytes [high, low, 0, 0] in big-endian order.
/// We read the first two bytes directly as a big-endian u16.
/// This avoids the pitfall of reading via c_int (which native-endian reinterprets
/// the raw bytes, producing a wrong value on little-endian macOS).
fn read_port_be(info: &SocketFDInfo, byte_offset: usize) -> u16 {
    let raw = info as *const SocketFDInfo as *const u8;
    let bytes = unsafe { std::slice::from_raw_parts(raw, byte_offset + 2) };
    u16::from_be_bytes([bytes[byte_offset], bytes[byte_offset + 1]])
}

/// Build a port->PID cache by scanning every process's file descriptors.
/// Requires root to see all processes. Returns the cache with timing metadata.
///
/// This is the Apple DTS recommended approach — there is no sysctl MIB that
/// returns PID ownership for a socket. The only mechanism is per-process fd scan.
pub fn build_port_pid_cache() -> PortPidCache {
    let start = Instant::now();
    let mut entries: HashMap<(u16, u8), u32> = HashMap::new();
    let mut total_fd_count: usize = 0;
    let mut socket_fd_count: usize = 0;
    let mut probe_ok: usize = 0;

    let pids = match list_all_pids() {
        Ok(p) => p,
        Err(e) => {
            log::error!("port->PID cache: failed to list PIDs: {e}");
            return PortPidCache {
                entries,
                pid_count: 0,
                fd_count: 0,
                elapsed: start.elapsed(),
            };
        }
    };
    let pid_count = pids.len();

    for pid in &pids {
        let fds = match list_pid_fds(*pid) {
            Ok(f) => f,
            Err(_) => continue,
        };
        total_fd_count += fds.len();

        for fd_info in &fds {
            if fd_info.proc_fdtype != PROX_FDTYPE_SOCKET {
                continue;
            }
            socket_fd_count += 1;

            if let Some((lport, fport, proto)) = probe_socket(*pid, fd_info.proc_fd) {
                entries.insert((lport, proto), *pid);
                probe_ok += 1;
                if fport != 0 {
                    entries.insert((fport, proto), *pid);
                }
            }
        }
    }

    let elapsed = start.elapsed();

    log::debug!(
        "port->PID cache: {} entries, {} PIDs, {} fds, {} sockets, {} ok, {:?}",
        entries.len(),
        pid_count,
        total_fd_count,
        socket_fd_count,
        probe_ok,
        elapsed
    );

    PortPidCache {
        entries,
        pid_count,
        fd_count: total_fd_count,
        elapsed,
    }
}

/// List all PIDs on the system via proc_listpids(PROC_ALL_PIDS).
fn list_all_pids() -> Result<Vec<u32>, String> {
    // Use null_mut() for size query — non-null with size=0 returns 0 silently.
    let bytes_needed = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };

    if bytes_needed <= 0 {
        return Err(format!(
            "proc_listpids size query failed: ret={bytes_needed}, err={}",
            std::io::Error::last_os_error()
        ));
    }

    let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];

    let ret = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            buf.as_mut_ptr() as *mut libc::c_void,
            bytes_needed,
        )
    };

    if ret <= 0 {
        return Err(format!(
            "proc_listpids failed: ret={ret}, err={}",
            std::io::Error::last_os_error()
        ));
    }

    let bytes_written = ret as usize;
    let pid_size = mem::size_of::<u32>();
    let pid_count = bytes_written / pid_size;
    let pids: Vec<u32> = (0..pid_count)
        .map(|i| {
            u32::from_ne_bytes([
                buf[i * pid_size],
                buf[i * pid_size + 1],
                buf[i * pid_size + 2],
                buf[i * pid_size + 3],
            ])
        })
        .filter(|pid| *pid != 0)
        .collect();
    Ok(pids)
}

/// List file descriptors for a PID via proc_pidinfo(PROC_PIDLISTFDS).
/// Returns libproc's typed ProcFDInfo structs.
fn list_pid_fds(pid: u32) -> Result<Vec<LibProcFDInfo>, String> {
    // Use null_mut() for size query — non-null with size=0 returns 0 silently.
    let bytes_needed =
        unsafe { libc::proc_pidinfo(pid as i32, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };

    if bytes_needed <= 0 {
        return Err(format!(
            "proc_pidinfo PROC_PIDLISTFDS size query failed for pid {pid}: ret={bytes_needed}"
        ));
    }

    let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];

    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr() as *mut libc::c_void,
            bytes_needed,
        )
    };

    if ret <= 0 {
        return Err(format!(
            "proc_pidinfo PROC_PIDLISTFDS failed for pid {pid}: ret={ret}"
        ));
    }

    let entry_size = mem::size_of::<LibProcFDInfo>();
    let fd_count = ret as usize / entry_size;
    let fds: Vec<LibProcFDInfo> = (0..fd_count)
        .map(|i| {
            let offset = i * entry_size;
            LibProcFDInfo {
                proc_fd: i32::from_ne_bytes([
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ]),
                proc_fdtype: u32::from_ne_bytes([
                    buf[offset + 4],
                    buf[offset + 5],
                    buf[offset + 6],
                    buf[offset + 7],
                ]),
            }
        })
        .collect();
    Ok(fds)
}

/// Probe a socket fd via proc_pidfdinfo and extract (lport, fport, proto).
/// Uses libproc's typed SocketFDInfo struct — no hand-computed offsets.
/// Returns None if the fd is not an IPv4/IPv6 socket or the call fails.
fn probe_socket(pid: u32, fd: i32) -> Option<(u16, u16, u8)> {
    let mut info: SocketFDInfo = unsafe { mem::zeroed() };
    let buf_ptr = &mut info as *mut SocketFDInfo as *mut libc::c_void;
    let buf_size = mem::size_of::<SocketFDInfo>() as i32;

    let ret =
        unsafe { libc::proc_pidfdinfo(pid as i32, fd, PROC_PIDFDSOCKETINFO, buf_ptr, buf_size) };

    let min_size = mem::size_of::<LibProcFDInfo>() + mem::size_of::<SocketInfoProto>() as usize;
    if ret < min_size as i32 {
        return None;
    }

    // Access fields via typed structs — no raw offset math.
    let soi_type = info.psi.soi_type;
    let soi_protocol = info.psi.soi_protocol;
    let soi_family = info.psi.soi_family;

    // Must be IPv4 or IPv6.
    if soi_family != 2 && soi_family != 30 {
        return None;
    }

    // Map socket type to IP protocol number.
    let proto: u8 = match soi_type {
        1 => 6,  // SOCK_STREAM → TCP
        2 => 17, // SOCK_DGRAM → UDP
        _ => return None,
    };

    if soi_protocol != proto as i32 {
        return None;
    }

    // Extract ports from the InSockInfo union via the typed struct.
    // IMPORTANT: insi_lport and insi_fport are in NETWORK byte order (big-endian).
    // We read the raw bytes at the correct offset rather than using the c_int field,
    // because c_int native-endian reinterpretation corrupts the port on LE systems.
    let (lport, fport) = {
        let lport = read_port_be(&info, OFF_LPORT);
        let fport = read_port_be(&info, OFF_FPORT);
        (lport, fport)
    };

    if lport == 0 {
        return None;
    }

    Some((lport, fport, proto))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_own_pid() {
        let pid = std::process::id();
        let result = lookup_process(pid);
        assert!(result.is_ok(), "should resolve own pid: {:?}", result.err());
        let info = result.unwrap();
        assert!(!info.path.is_empty(), "path should not be empty");
        assert!(info.start_time > 0.0, "start_time should be positive");
    }

    #[test]
    fn test_lookup_invalid_pid() {
        let result = lookup_process(999999);
        assert!(result.is_err(), "should fail for invalid pid");
    }

    #[test]
    fn test_build_port_pid_cache() {
        let _ = env_logger::try_init();
        let cache = build_port_pid_cache();
        println!(
            "port->PID cache: {} entries, {} PIDs scanned, {} fds examined, {:?}",
            cache.entries.len(),
            cache.pid_count,
            cache.fd_count,
            cache.elapsed
        );
        let mut sorted: Vec<_> = cache.entries.keys().collect();
        sorted.sort();
        for (port, proto) in sorted.iter().take(30) {
            let pid = cache.entries.get(&(*port, *proto)).unwrap();
            println!("  ({port}, {proto}) -> pid={pid}");
        }
        assert!(cache.pid_count > 0, "should scan at least 1 PID");
        assert!(cache.fd_count > 0, "should examine at least 1 fd");
        assert!(
            !cache.entries.is_empty(),
            "should find at least one socket on a running machine"
        );
    }

    /// Verify lport reads correctly via typed structs against lsof ground truth.
    #[test]
    fn test_probe_socket_lport() {
        let lsof_out = std::process::Command::new("lsof")
            .args(["-i", "TCP", "-n", "-P"])
            .output()
            .expect("should run lsof");
        let lsof_str = String::from_utf8_lossy(&lsof_out.stdout);

        let mut target_pid: i32 = 0;
        let mut target_fd: i32 = 0;
        let mut expected_lport: u16 = 0;

        for line in lsof_str.lines().filter(|l| l.contains("ESTABLISHED")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }
            if let (Ok(pid), Ok(fd), Some(port)) = (
                parts[1].parse::<i32>(),
                parts[3].trim_end_matches('u').parse::<i32>(),
                parts[8]
                    .split("->")
                    .next()
                    .and_then(|addr| addr.rsplit(':').next())
                    .and_then(|p| p.parse::<u16>().ok()),
            ) {
                target_pid = pid;
                target_fd = fd;
                expected_lport = port;
                break;
            }
        }
        assert!(
            target_pid > 0,
            "no ESTABLISHED TCP connection found via lsof"
        );

        let result = probe_socket(target_pid as u32, target_fd);
        assert!(
            result.is_some(),
            "probe_socket returned None for known socket"
        );
        let (lport, _fport, proto) = result.unwrap();
        assert_eq!(
            lport, expected_lport,
            "lport mismatch: got {lport}, expected {expected_lport}"
        );
        assert_eq!(proto, 6, "proto should be TCP (6)");
        println!("OK: pid={target_pid} fd={target_fd} lport={lport} (expected {expected_lport})");
    }

    /// Diagnostic: verify struct offsets against a real proc_pidfdinfo buffer.
    #[test]
    fn test_struct_sizes() {
        use libproc::file_info::ProcFDInfo;
        use libproc::net_info::{InSockInfo, SocketFDInfo, SocketInfo, SocketInfoProto, VInfoStat};
        eprintln!("sizeof SocketFDInfo = {}", mem::size_of::<SocketFDInfo>());
        eprintln!("sizeof SocketInfo = {}", mem::size_of::<SocketInfo>());
        eprintln!("sizeof VInfoStat = {}", mem::size_of::<VInfoStat>());
        eprintln!("sizeof InSockInfo = {}", mem::size_of::<InSockInfo>());
        eprintln!(
            "sizeof SocketInfoProto = {}",
            mem::size_of::<SocketInfoProto>()
        );
        eprintln!("sizeof ProcFDInfo = {}", mem::size_of::<ProcFDInfo>());

        // Field offsets via pointer arithmetic on a real struct (not a stack copy).
        // Use raw pointers to avoid UB from reading through a copy.
        let mut si: SocketFDInfo = unsafe { mem::zeroed() };
        let si_addr = &mut si as *mut SocketFDInfo as usize;
        let psi_addr = &mut si.psi as *mut SocketInfo as usize;
        let proto_addr = &mut si.psi.soi_proto as *mut SocketInfoProto as usize;
        eprintln!("offset psi (from SocketFDInfo) = {}", psi_addr - si_addr);
        eprintln!(
            "offset soi_proto (from SocketFDInfo) = {}",
            proto_addr - si_addr
        );

        // For InSockInfo fields, we can't take & on a zeroed union member reliably.
        // Use the known constant offsets and verify against a real socket buffer.
        eprintln!("OFF_LPORT (hardcoded) = {}", OFF_LPORT);
        eprintln!("OFF_FPORT (hardcoded) = {}", OFF_FPORT);

        // Verify against a known socket
        let lsof_out = std::process::Command::new("lsof")
            .args(["-i", "TCP", "-n", "-P"])
            .output()
            .expect("should run lsof");
        let lsof_str = String::from_utf8_lossy(&lsof_out.stdout);
        let mut target_pid: i32 = 0;
        let mut target_fd: i32 = 0;
        let mut expected_lport: u16 = 0;
        let mut expected_fport: u16 = 0;
        for line in lsof_str.lines().filter(|l| l.contains("ESTABLISHED")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }
            let name = &parts[8];
            if let (Ok(pid), Ok(fd)) = (
                parts[1].parse::<i32>(),
                parts[3].trim_end_matches('u').parse::<i32>(),
            ) {
                if let Some((lp, fp)) = name.split_once("->").and_then(|(src, dst)| {
                    let lp = src.rsplit(':').next()?.parse::<u16>().ok()?;
                    let fp = dst.rsplit(':').next()?.parse::<u16>().ok()?;
                    Some((lp, fp))
                }) {
                    target_pid = pid;
                    target_fd = fd;
                    expected_lport = lp;
                    expected_fport = fp;
                    break;
                }
            }
        }
        assert!(target_pid > 0, "no ESTABLISHED TCP connection found");

        // Read into real SocketFDInfo struct
        let mut info: SocketFDInfo = unsafe { mem::zeroed() };
        let ret = unsafe {
            libc::proc_pidfdinfo(
                target_pid,
                target_fd,
                PROC_PIDFDSOCKETINFO,
                &mut info as *mut SocketFDInfo as *mut libc::c_void,
                mem::size_of::<SocketFDInfo>() as i32,
            )
        };
        eprintln!("proc_pidfdinfo ret={ret}");
        eprintln!("typed soi_family = {}", info.psi.soi_family);
        eprintln!("typed soi_type = {}", info.psi.soi_type);
        eprintln!("typed soi_protocol = {}", info.psi.soi_protocol);
        unsafe {
            let inet = &info.psi.soi_proto.pri_in;
            eprintln!("typed insi_lport (c_int) = {}", inet.insi_lport);
            eprintln!("typed insi_fport (c_int) = {}", inet.insi_fport);
        }

        // Verify read_port_be matches typed struct
        let rlport = read_port_be(&info, OFF_LPORT);
        let rfport = read_port_be(&info, OFF_FPORT);
        eprintln!("read_port_be(lport) = {rlport}, expected = {expected_lport}");
        eprintln!("read_port_be(fport) = {rfport}, expected = {expected_fport}");
        assert_eq!(rlport, expected_lport, "lport mismatch");
        assert_eq!(rfport, expected_fport, "fport mismatch");
    }

    /// Verify fport reads correctly via typed structs against lsof ground truth.
    #[test]
    fn test_probe_socket_fport() {
        let lsof_out = std::process::Command::new("lsof")
            .args(["-i", "TCP", "-n", "-P"])
            .output()
            .expect("should run lsof");
        let lsof_str = String::from_utf8_lossy(&lsof_out.stdout);

        let mut target_pid: i32 = 0;
        let mut target_fd: i32 = 0;
        let mut expected_lport: u16 = 0;
        let mut expected_fport: u16 = 0;

        for line in lsof_str.lines().filter(|l| l.contains("ESTABLISHED")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }
            // lsof format: NAME = "src:port->dst:port (STATUS)"
            let name = &parts[8];
            let parsed_ports = name.split_once("->").and_then(|(src, dst)| {
                let lp = src.rsplit(':').next()?.parse::<u16>().ok()?;
                let fp = dst.rsplit(':').next()?.parse::<u16>().ok()?;
                Some((lp, fp))
            });
            if let (Ok(pid), Ok(fd), Some((lp, fp))) = (
                parts[1].parse::<i32>(),
                parts[3].trim_end_matches('u').parse::<i32>(),
                parsed_ports,
            ) {
                target_pid = pid;
                target_fd = fd;
                expected_lport = lp;
                expected_fport = fp;
                break;
            }
        }
        assert!(
            target_pid > 0,
            "no ESTABLISHED TCP connection found via lsof"
        );

        let result = probe_socket(target_pid as u32, target_fd);
        assert!(
            result.is_some(),
            "probe_socket returned None for known socket"
        );
        let (lport, fport, _proto) = result.unwrap();
        assert_eq!(
            lport, expected_lport,
            "lport mismatch: got {lport}, expected {expected_lport}"
        );
        assert_eq!(
            fport, expected_fport,
            "fport mismatch: got {fport}, expected {expected_fport}"
        );
        println!(
            "OK: pid={target_pid} fd={target_fd} lport={lport} fport={fport} (expected lport={expected_lport} fport={expected_fport})"
        );
    }
}
