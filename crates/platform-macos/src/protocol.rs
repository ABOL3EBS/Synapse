// crates/platform-macos/src/protocol.rs
//
// Reusable SCM_RIGHTS fd-passing and length-prefixed bincode message protocol.
// Same implementation as the binaries — this module exists so other crates
// (e.g. the Tauri UI layer) can use the IPC primitives without reimplementing.

use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SCM_RIGHTS — fd passing
// ---------------------------------------------------------------------------

pub fn send_fd(stream: &UnixStream, fd_to_send: RawFd) -> io::Result<()> {
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
    let cmsg = unsafe { &mut *libc::CMSG_FIRSTHDR(&msg) };
    cmsg.cmsg_level = libc::SOL_SOCKET;
    cmsg.cmsg_type = libc::SCM_RIGHTS;
    cmsg.cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) };
    let data = unsafe { libc::CMSG_DATA(cmsg) } as *mut libc::c_int;
    unsafe { *data = fd_to_send };
    let ret = unsafe { libc::sendmsg(stream_fd, &msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn recv_fd(stream: &UnixStream) -> io::Result<RawFd> {
    let stream_fd: RawFd = std::os::fd::AsRawFd::as_raw_fd(stream);
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let cmsg_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };
    let mut cmsg_buf = vec![0u8; cmsg_len as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_len;
    let ret = unsafe { libc::recvmsg(stream_fd, &mut msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    if ret == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "sender closed",
        ));
    }
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let hdr = unsafe { &*cmsg };
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            let data = unsafe { libc::CMSG_DATA(cmsg) } as *const RawFd;
            let fd = unsafe { *data };
            if fd >= 0 {
                return Ok(fd);
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no SCM_RIGHTS fd received",
    ))
}

// ---------------------------------------------------------------------------
// Length-prefixed bincode messages
// ---------------------------------------------------------------------------

pub fn send_message<S: Serialize>(stream: &mut UnixStream, msg: &S) -> io::Result<()> {
    let payload = bincode::serialize(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serialize: {e}")))?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()
}

pub fn recv_message<D: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> io::Result<D> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max 1MB)"),
        ));
    }
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty message payload",
        ));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    bincode::deserialize(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("deserialize: {e}")))
}
