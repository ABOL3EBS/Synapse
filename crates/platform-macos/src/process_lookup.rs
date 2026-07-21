// crates/platform-macos/src/process_lookup.rs
//
// libproc-based PID + process-start-time resolution.
// §4: "Process attribution via PID + process-start-time resolution
// (start-time captured alongside PID to avoid PID-reuse/TOCTOU misattribution)"
//
// Runs unprivileged — libproc reads from the proc filesystem, no root required.
// macOS only — this module is platform-specific by design.

use std::ffi::CStr;
use std::mem;

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
    // From <libproc.h>:
    //   int proc_pidinfo(int pid, uint32_t flavor, uint64_t arg, void *buffer, uint32_t buffersize);
    // PROC_PIDTASKINFO = 4
    // Returns a struct proc_taskinfo with pti_starttime (mach absolute time).
    //
    // We need to convert mach absolute time to epoch seconds.
    // Use mach_timebase_info + mach_absolute_time conversion, then add
    // the boot time to get epoch.

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
        pti_starttime: u64, // mach absolute time of process start
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

    // Convert mach absolute time to epoch seconds.
    // mach_absolute_time() returns ticks since boot.
    // info.pti_starttime is the mach_absolute_time at process start.
    // We need: boot_time + (now_ticks - start_ticks) * timebase = now_epoch
    // So: boot_time = now_epoch - (now_ticks - start_ticks) * timebase
    // And: start_epoch = now_epoch - (now_ticks - start_ticks) * timebase + (now_ticks - start_ticks) * timebase
    //                  = now_epoch - (now_ticks - start_ticks) * timebase + (now_ticks - start_ticks) * timebase
    // Actually simpler: start_epoch = boot_time + start_ticks * timebase_numer / timebase_denom

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

    // Ticks since boot at process start
    let start_ticks = info.pti_starttime;
    // Ticks elapsed since process start
    let elapsed_ticks = now_ticks.saturating_sub(start_ticks);
    // Convert ticks to seconds
    let elapsed_secs =
        elapsed_ticks as f64 * timebase.numer as f64 / timebase.denom as f64 / 1_000_000_000.0;

    let start_epoch = now_epoch - elapsed_secs;

    Ok(start_epoch)
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
}
