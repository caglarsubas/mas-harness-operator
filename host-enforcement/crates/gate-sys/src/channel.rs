//! The channel substrate's raw calls (HE-003A DESIGN §2-§3), Linux only: the third module of the workspace allowed to
//! hold `unsafe` code (with `openat.rs` and `seal.rs`), each call in its own block with its own `// SAFETY:` argument
//! behind a safe function. The foreign symbols are exactly `socket`, `bind`, `listen`, `setsockopt`, `getsockopt`,
//! `recvmsg`, `sendmsg`, `epoll_create1`, `epoll_ctl`, `epoll_pwait`, `ppoll` and `syscall`; `tools/gate.py` checks
//! that this file declares exactly them.
//!
//! - [`SockCreate`]: the thread's socket-creation context in the proc filesystem (`attr/sockcreate` of the thread's own
//!   directory), set with its trailing NUL and cleared by one zero-length write, as libselinux does; the guard clears
//!   on drop, and [`SockCreate::clear`] reports a failed clear.
//! - [`listen_seqpacket`]: an AF_UNIX SOCK_SEQPACKET listener created inside the guard, with SO_PASSCRED and SO_PASSSEC
//!   set on it (accepted sockets inherit both), bound to an absolute path and listening with a backlog of one.
//! - [`accept`]: `accept4` issued through `syscall` (musl's `accept4` wrapper falls back to `accept` on EINVAL or
//!   ENOSYS, a call the EFFECT_GATE program kills).
//! - [`peer`]: SO_PEERCRED, SO_PEERSEC (the returned length kept exactly) and SO_PEERPIDFD.
//! - [`ProcDir`]: the peer's directory in the proc filesystem, opened by number and kept, and its three identity reads
//!   (`stat`, `cgroup`, `attr/current`), parsed by `peer_wire`.
//! - [`PidFd::exited`]: a zero-timeout `ppoll` on the pidfd.
//! - [`recv`] and [`send`]: one `recvmsg` or `sendmsg`, never waiting.
//! - [`Poller`]: `epoll_create1`, `epoll_ctl` and `epoll_pwait` (aarch64 has no `epoll_wait` system call).
//!
//! Every descriptor is an `OwnedFd` inside an opaque type (`Listener`, `Conn`, `PidFd`, `Poller`), closed by drop; no
//! type here derives `Debug`, and the manual impls print the type name only. Every `repr(C)` struct has compile-time
//! size, alignment and offset asserts, which both musl release builds check.
//!
//! Constants (per target, with their evidence; the pinned musl 1.2.5 `libc.a`, sha256 `e699c64b…` for x86_64 and
//! `b03473b6…` for aarch64, where its code shows the value, otherwise the kernel UAPI header named, for T04):
//! `accept4` is 288 / 242 (`accept4.lo` passes it to `__syscall_cp`); `AF_UNIX` 1 (`syslog.lo` calls `socket(1,
//! 0x80002, 0)`); `SOCK_CLOEXEC` 0x80000 and `SOCK_NONBLOCK` 0x800 (`socket.lo` and `accept4.lo` test exactly these
//! bits before their `fcntl` fallbacks); `MSG_NOSIGNAL` 0x4000 (`res_msend.lo` passes it to `sendto` and `sendmsg`);
//! `MSG_DONTWAIT` 0x40 (`netlink.lo` passes it to `recv`); `POLLNVAL` 0x20 (`__libc_start_main.lo` tests bit 5 of
//! `revents`, at offset 6 of `struct pollfd`). From the kernel UAPI: `SOCK_SEQPACKET` 5 (`linux/net.h`); `SOL_SOCKET`
//! 1, `SO_PASSCRED` 16, `SO_PEERCRED` 17, `SO_PEERSEC` 31, `SO_PASSSEC` 34 and `SO_PEERPIDFD` 77 (the generic
//! `socket.h`, which both architectures use; SO_PEERPIDFD needs Linux 6.5); `SCM_RIGHTS` 1, `SCM_CREDENTIALS` 2,
//! `SCM_SECURITY` 3, `MSG_CTRUNC` 0x8, `MSG_TRUNC` 0x20 and `MSG_CMSG_CLOEXEC` 0x40000000 (`linux/socket.h`);
//! `EPOLL_CLOEXEC` 0x80000 (`linux/eventpoll.h`, defined as `O_CLOEXEC`), `EPOLL_CTL_ADD` 1, `EPOLL_CTL_DEL` 2,
//! `EPOLL_CTL_MOD` 3, `EPOLLIN` 0x1, `EPOLLOUT` 0x4, `EPOLLERR` 0x8, `EPOLLHUP` 0x10 (`linux/eventpoll.h`); `POLLIN`
//! 0x1 and `POLLERR` 0x8 (the generic `poll.h`). The layouts follow musl's headers for the two 64-bit little-endian
//! targets: `struct msghdr` is 56 bytes with 32-bit `msg_iovlen` and `msg_controllen` followed by padding that
//! `recvmsg.lo` and `sendmsg.lo` zero (offsets 28 and 44), and `struct epoll_event` is packed (12 bytes) on x86_64
//! only, as the kernel and musl define it.
#![allow(unsafe_code)]

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_short;
use std::ffi::c_uint;
use std::ffi::c_ulong;
use std::ffi::c_void;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::mem::offset_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use crate::openat::Dir;
use crate::openat::FileMode;
use crate::peer_wire;
use crate::peer_wire::ProcIdentity;
use crate::peer_wire::CREDENTIALS_BYTES;
use crate::peer_wire::FRAME_BUFFER_BYTES;
use crate::peer_wire::LABEL_LIMIT;

#[cfg(target_arch = "x86_64")]
mod consts {
    use std::ffi::c_int;
    use std::ffi::c_long;
    use std::ffi::c_short;

    pub const SYS_ACCEPT4: c_long = 288;
    pub const AF_UNIX: c_int = 1;
    pub const SOCK_SEQPACKET: c_int = 5;
    pub const SOCK_NONBLOCK: c_int = 0o4000;
    pub const SOCK_CLOEXEC: c_int = 0o2000000;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_PASSCRED: c_int = 16;
    pub const SO_PEERCRED: c_int = 17;
    pub const SO_PEERSEC: c_int = 31;
    pub const SO_PASSSEC: c_int = 34;
    pub const SO_PEERPIDFD: c_int = 77;
    pub const SCM_RIGHTS: c_int = 1;
    pub const SCM_CREDENTIALS: c_int = 2;
    pub const SCM_SECURITY: c_int = 3;
    pub const MSG_CTRUNC: c_int = 0x8;
    pub const MSG_TRUNC: c_int = 0x20;
    pub const MSG_DONTWAIT: c_int = 0x40;
    pub const MSG_NOSIGNAL: c_int = 0x4000;
    pub const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
    pub const EPOLL_CLOEXEC: c_int = 0o2000000;
    pub const EPOLL_CTL_ADD: c_int = 1;
    pub const EPOLL_CTL_DEL: c_int = 2;
    pub const EPOLL_CTL_MOD: c_int = 3;
    pub const EPOLLIN: u32 = 0x001;
    pub const EPOLLOUT: u32 = 0x004;
    pub const EPOLLERR: u32 = 0x008;
    pub const EPOLLHUP: u32 = 0x010;
    pub const POLLIN: c_short = 0x001;
    pub const POLLERR: c_short = 0x008;
    pub const POLLNVAL: c_short = 0x020;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    use std::ffi::c_int;
    use std::ffi::c_long;
    use std::ffi::c_short;

    pub const SYS_ACCEPT4: c_long = 242;
    pub const AF_UNIX: c_int = 1;
    pub const SOCK_SEQPACKET: c_int = 5;
    pub const SOCK_NONBLOCK: c_int = 0o4000;
    pub const SOCK_CLOEXEC: c_int = 0o2000000;
    pub const SOL_SOCKET: c_int = 1;
    pub const SO_PASSCRED: c_int = 16;
    pub const SO_PEERCRED: c_int = 17;
    pub const SO_PEERSEC: c_int = 31;
    pub const SO_PASSSEC: c_int = 34;
    pub const SO_PEERPIDFD: c_int = 77;
    pub const SCM_RIGHTS: c_int = 1;
    pub const SCM_CREDENTIALS: c_int = 2;
    pub const SCM_SECURITY: c_int = 3;
    pub const MSG_CTRUNC: c_int = 0x8;
    pub const MSG_TRUNC: c_int = 0x20;
    pub const MSG_DONTWAIT: c_int = 0x40;
    pub const MSG_NOSIGNAL: c_int = 0x4000;
    pub const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
    pub const EPOLL_CLOEXEC: c_int = 0o2000000;
    pub const EPOLL_CTL_ADD: c_int = 1;
    pub const EPOLL_CTL_DEL: c_int = 2;
    pub const EPOLL_CTL_MOD: c_int = 3;
    pub const EPOLLIN: u32 = 0x001;
    pub const EPOLLOUT: u32 = 0x004;
    pub const EPOLLERR: u32 = 0x008;
    pub const EPOLLHUP: u32 = 0x010;
    pub const POLLIN: c_short = 0x001;
    pub const POLLERR: c_short = 0x008;
    pub const POLLNVAL: c_short = 0x020;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("gate-sys pins the channel constants for x86_64 and aarch64 only");

use consts::*;

// The control-message constants the portable parser uses are the same numbers.
const _: () = assert!(SOL_SOCKET == peer_wire::SOL_SOCKET && SCM_RIGHTS == peer_wire::SCM_RIGHTS);
const _: () = assert!(SCM_CREDENTIALS == peer_wire::SCM_CREDENTIALS && SCM_SECURITY == peer_wire::SCM_SECURITY);
const _: () = assert!(SOCK_NONBLOCK == 0x800 && SOCK_CLOEXEC == 0x80000 && EPOLL_CLOEXEC == SOCK_CLOEXEC);
const _: () = assert!(POLLIN as u32 == EPOLLIN && POLLERR as u32 == EPOLLERR && POLLNVAL == 0x20);

/// `struct sockaddr_un`: the family and a 108-byte path.
#[repr(C)]
struct SockaddrUn {
    family: u16,
    path: [u8; 108],
}

/// `struct ucred`.
#[repr(C)]
struct Ucred {
    pid: c_int,
    uid: c_uint,
    gid: c_uint,
}

/// `struct iovec`.
#[repr(C)]
struct Iovec {
    base: *mut c_void,
    length: usize,
}

/// musl's `struct msghdr` on a 64-bit little-endian target: the 32-bit `msg_iovlen` and `msg_controllen` are each
/// followed by padding, which musl's `recvmsg` and `sendmsg` zero in their own copy before the call.
#[repr(C)]
struct MsgHdr {
    name: *mut c_void,
    name_length: c_uint,
    iov: *mut Iovec,
    iov_length: c_int,
    pad1: c_int,
    control: *mut c_void,
    control_length: c_uint,
    pad2: c_int,
    flags: c_int,
}

/// `struct epoll_event`: packed on x86_64 (the kernel's `EPOLL_PACKED`, musl's `__packed__`), natural elsewhere.
#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
#[derive(Copy, Clone)]
struct EpollEvent {
    events: u32,
    data: u64,
}

/// `struct pollfd`.
#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

/// `struct timespec` (64-bit `time_t` and `long`).
#[repr(C)]
struct Timespec {
    seconds: c_long,
    nanoseconds: c_long,
}

const _: () = assert!(size_of::<SockaddrUn>() == 110 && align_of::<SockaddrUn>() == 2);
const _: () = assert!(offset_of!(SockaddrUn, family) == 0 && offset_of!(SockaddrUn, path) == 2);
const _: () = assert!(size_of::<Ucred>() == CREDENTIALS_BYTES && align_of::<Ucred>() == 4);
const _: () = assert!(offset_of!(Ucred, pid) == 0 && offset_of!(Ucred, uid) == 4 && offset_of!(Ucred, gid) == 8);
const _: () = assert!(size_of::<Iovec>() == 16 && align_of::<Iovec>() == 8);
const _: () = assert!(offset_of!(Iovec, base) == 0 && offset_of!(Iovec, length) == 8);
const _: () = assert!(size_of::<MsgHdr>() == 56 && align_of::<MsgHdr>() == 8);
const _: () = assert!(
    offset_of!(MsgHdr, name) == 0
        && offset_of!(MsgHdr, name_length) == 8
        && offset_of!(MsgHdr, iov) == 16
        && offset_of!(MsgHdr, iov_length) == 24
        && offset_of!(MsgHdr, pad1) == 28
        && offset_of!(MsgHdr, control) == 32
        && offset_of!(MsgHdr, control_length) == 40
        && offset_of!(MsgHdr, pad2) == 44
        && offset_of!(MsgHdr, flags) == 48
);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<EpollEvent>() == 12 && align_of::<EpollEvent>() == 1);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(size_of::<EpollEvent>() == 16 && align_of::<EpollEvent>() == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(offset_of!(EpollEvent, events) == 0 && offset_of!(EpollEvent, data) == 4);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(offset_of!(EpollEvent, events) == 0 && offset_of!(EpollEvent, data) == 8);
const _: () = assert!(size_of::<PollFd>() == 8 && align_of::<PollFd>() == 4);
const _: () = assert!(offset_of!(PollFd, fd) == 0 && offset_of!(PollFd, events) == 4 && offset_of!(PollFd, revents) == 6);
const _: () = assert!(size_of::<Timespec>() == 16 && align_of::<Timespec>() == 8);
const _: () = assert!(offset_of!(Timespec, seconds) == 0 && offset_of!(Timespec, nanoseconds) == 8);
const _: () = assert!(size_of::<c_long>() == 8 && size_of::<c_ulong>() == 8 && size_of::<c_int>() == 4);

unsafe extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn bind(fd: c_int, address: *const SockaddrUn, length: c_uint) -> c_int;
    fn listen(fd: c_int, backlog: c_int) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, length: c_uint) -> c_int;
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, length: *mut c_uint) -> c_int;
    fn recvmsg(fd: c_int, message: *mut MsgHdr, flags: c_int) -> c_long;
    fn sendmsg(fd: c_int, message: *const MsgHdr, flags: c_int) -> c_long;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epoll: c_int, operation: c_int, fd: c_int, event: *mut EpollEvent) -> c_int;
    fn epoll_pwait(epoll: c_int, events: *mut EpollEvent, capacity: c_int, timeout: c_int, mask: *const c_void) -> c_int;
    fn ppoll(fds: *mut PollFd, count: c_ulong, timeout: *const Timespec, mask: *const c_void) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
}

/// The most events one `epoll_pwait` returns.
pub const WAIT_EVENTS: usize = 64;

/// The longest socket path (`sun_path` holds 108 bytes, the last a NUL).
const MAX_SOCKET_PATH: usize = 107;

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// musl's convention for these wrappers: -1 and `errno` on failure.
fn checked(value: c_int) -> io::Result<c_int> {
    if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
}

/// A descriptor a call just returned, owned from here on (closed on every later path).
fn adopt(descriptor: c_int) -> OwnedFd {
    // SAFETY: callers pass only a descriptor a successful call returned to this process a moment ago, which is open
    // and owned by nothing else.
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

/// The result of a call that returns a new descriptor.
fn owned(value: c_int) -> io::Result<OwnedFd> {
    checked(value).map(adopt)
}

/// A listening socket.
pub struct Listener {
    fd: OwnedFd,
}

/// One accepted connection.
pub struct Conn {
    fd: OwnedFd,
}

/// A pidfd for the process a connection's peer was at `connect`.
pub struct PidFd {
    fd: OwnedFd,
}

/// An epoll instance.
pub struct Poller {
    fd: OwnedFd,
}

/// A peer process's directory in the proc filesystem, kept open: after that process is reaped, reads through it fail
/// and never reach a process that reused the number.
pub struct ProcDir {
    dir: Dir,
}

impl fmt::Debug for Listener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Listener")
    }
}

impl fmt::Debug for Conn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Conn")
    }
}

impl fmt::Debug for PidFd {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PidFd")
    }
}

impl fmt::Debug for Poller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Poller")
    }
}

impl fmt::Debug for ProcDir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProcDir")
    }
}

// ------------------------------------------------------------------------------------------ the sockcreate guard

/// One `write` call of `bytes` on the attribute file.
fn write_attribute(file: &File, bytes: &[u8]) -> io::Result<usize> {
    let mut handle = file;
    handle.write(bytes)
}

/// The clear: exactly one `write` call of length 0 (`write_all` of nothing would make no call).
fn write_empty(file: &File) -> io::Result<()> {
    match write_attribute(file, &[])? {
        0 => Ok(()),
        _ => Err(invalid("the sockcreate clear reported bytes written")),
    }
}

/// The calling thread's socket-creation context, set: sockets this thread creates while it is set get the context.
/// Dropping the guard clears it; [`SockCreate::clear`] clears it and reports a failure.
pub struct SockCreate {
    file: Option<File>,
}

impl fmt::Debug for SockCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SockCreate")
    }
}

impl SockCreate {
    /// Writes `context` (1 to 4095 bytes without NUL) with a trailing NUL, in one `write` call, to the thread's
    /// `sockcreate` attribute (opened `O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY` through [`Dir::file`]). The
    /// guard exists before the write, so the context is cleared on every path after it.
    pub fn set(context: &[u8]) -> io::Result<SockCreate> {
        if context.is_empty() || context.len() >= LABEL_LIMIT || context.contains(&0) {
            return Err(refusal("a socket context must be 1 to 4095 bytes without NUL"));
        }
        let directory = Dir::at("/proc/thread-self/attr")?;
        let Some((file, _)) = directory.file("sockcreate", FileMode::Existing)? else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "the thread has no sockcreate attribute"));
        };
        let guard = SockCreate { file: Some(file) };
        let mut full = Vec::with_capacity(context.len().saturating_add(1));
        full.extend_from_slice(context);
        full.push(0);
        let written = match guard.file.as_ref() {
            Some(file) => write_attribute(file, &full)?,
            None => 0,
        };
        if written != full.len() {
            return Err(invalid("the socket context was not written whole"));
        }
        Ok(guard)
    }

    /// Clears the context (one zero-length `write`) and reports the result; on failure the drop that follows tries
    /// once more.
    pub fn clear(mut self) -> io::Result<()> {
        let result = self.file.as_ref().map_or(Ok(()), write_empty);
        if result.is_ok() {
            self.file = None;
        }
        result
    }
}

impl Drop for SockCreate {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _cleared_or_reported_by_clear = write_empty(&file);
        }
    }
}

// ------------------------------------------------------------------------------------------ listener and accept

/// The step of [`listen_seqpacket`] that failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ListenStep {
    Address,
    SockCreate,
    Socket,
    SockCreateClear,
    PassCred,
    PassSec,
    Bind,
    Listen,
}

/// A failed [`listen_seqpacket`]: the step and the OS's error.
#[derive(Debug)]
pub struct ListenError {
    pub step: ListenStep,
    pub error: io::Error,
}

fn at(step: ListenStep) -> impl FnOnce(io::Error) -> ListenError {
    move |error| ListenError { step, error }
}

/// `sockaddr_un` for an absolute path of at most 107 bytes without NUL, and the length to pass (the family, the path
/// and its NUL).
fn socket_address(path: &str) -> io::Result<(SockaddrUn, c_uint)> {
    let bytes = path.as_bytes();
    if !path.starts_with('/') || bytes.len() > MAX_SOCKET_PATH || bytes.contains(&0) {
        return Err(refusal("a socket path must be absolute, at most 107 bytes and without NUL"));
    }
    let mut address = SockaddrUn { family: AF_UNIX as u16, path: [0; 108] };
    for (slot, byte) in address.path.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    let length = offset_of!(SockaddrUn, path).saturating_add(bytes.len()).saturating_add(1);
    let length = c_uint::try_from(length).map_err(|_| refusal("a socket address length"))?;
    Ok((address, length))
}

/// `setsockopt(fd, SOL_SOCKET, name, &1, 4)`.
fn enable(fd: &OwnedFd, name: c_int) -> io::Result<()> {
    let value: c_int = 1;
    // SAFETY: `value` is a live `int` that setsockopt reads (the length passed is its size) and does not write.
    checked(unsafe {
        setsockopt(fd.as_raw_fd(), SOL_SOCKET, name, (&value as *const c_int).cast(), size_of::<c_int>() as c_uint)
    })
    .map(|_| ())
}

/// An AF_UNIX SOCK_SEQPACKET listener at `path`, created with the socket context `context`: the socket is made
/// non-blocking and close-on-exec inside the sockcreate guard, the guard is cleared (a failed clear fails the
/// listener), SO_PASSCRED and SO_PASSSEC are set, and the socket binds and listens with a backlog of one. A path that
/// exists fails `bind` (EADDRINUSE): the gate cannot unlink, and HE-008 gives every start empty runtime directories.
pub fn listen_seqpacket(path: &str, context: &[u8]) -> Result<Listener, ListenError> {
    let (address, length) = socket_address(path).map_err(at(ListenStep::Address))?;
    let guard = SockCreate::set(context).map_err(at(ListenStep::SockCreate))?;
    // SAFETY: socket takes three integers and reads or writes no memory.
    let created = owned(unsafe { socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) });
    guard.clear().map_err(at(ListenStep::SockCreateClear))?;
    let fd = created.map_err(at(ListenStep::Socket))?;
    enable(&fd, SO_PASSCRED).map_err(at(ListenStep::PassCred))?;
    enable(&fd, SO_PASSSEC).map_err(at(ListenStep::PassSec))?;
    // SAFETY: `address` is a live `sockaddr_un` that bind reads and does not write; `length` is at most its size.
    checked(unsafe { bind(fd.as_raw_fd(), &address, length) }).map_err(at(ListenStep::Bind))?;
    // SAFETY: listen takes two integers and reads or writes no memory.
    checked(unsafe { listen(fd.as_raw_fd(), 1) }).map_err(at(ListenStep::Listen))?;
    Ok(Listener { fd })
}

/// One `accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC)` through `syscall`: a connection, or `None` when none is
/// queued (EAGAIN) or the queued one died (ECONNABORTED). EINTR retries; any other error is returned.
pub fn accept(listener: &Listener) -> io::Result<Option<Conn>> {
    let zero: c_long = 0;
    loop {
        // SAFETY: the two null address arguments ask the kernel for no peer address, so nothing is read or written
        // through a pointer; musl's syscall reads six further `long` arguments, which are all passed.
        let value = unsafe {
            syscall(SYS_ACCEPT4, c_long::from(listener.fd.as_raw_fd()), zero, zero,
                    c_long::from(SOCK_NONBLOCK | SOCK_CLOEXEC), zero, zero)
        };
        if value >= 0 {
            let descriptor = c_int::try_from(value).map_err(|_| invalid("accept4 returned a descriptor past int"))?;
            return Ok(Some(Conn { fd: adopt(descriptor) }));
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => continue,
            io::ErrorKind::WouldBlock | io::ErrorKind::ConnectionAborted => return Ok(None),
            _ => return Err(error),
        }
    }
}

// ------------------------------------------------------------------------------------------ peer identity

/// What the kernel recorded about a connection's peer at `connect`.
pub struct PeerCreds {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    /// SO_PEERSEC's bytes, exactly the returned length (the NUL included).
    pub label: Vec<u8>,
    pub pidfd: PidFd,
}

/// SO_PEERCRED, SO_PEERSEC (into a 4096-byte buffer; ERANGE fails) and SO_PEERPIDFD (Linux 6.5 or later: a pidfd for
/// the struct pid recorded at `connect`). A reaped peer fails the pidfd read (an identity failure).
pub fn peer(conn: &Conn) -> io::Result<PeerCreds> {
    let fd = conn.fd.as_raw_fd();
    let mut credentials = Ucred { pid: 0, uid: c_uint::MAX, gid: c_uint::MAX };
    let mut length = size_of::<Ucred>() as c_uint;
    // SAFETY: `credentials` is a live `struct ucred` and `length` its size; getsockopt writes at most `length` bytes
    // into it and the written length into `length`.
    checked(unsafe { getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (&mut credentials as *mut Ucred).cast(), &mut length) })?;
    if length as usize != CREDENTIALS_BYTES {
        return Err(invalid("SO_PEERCRED returned another length"));
    }
    let mut label = vec![0u8; LABEL_LIMIT];
    let mut label_length = LABEL_LIMIT as c_uint;
    // SAFETY: `label` holds `label_length` live, writable bytes; getsockopt writes at most that many and the written
    // length into `label_length` (a longer label fails with ERANGE).
    checked(unsafe { getsockopt(fd, SOL_SOCKET, SO_PEERSEC, label.as_mut_ptr().cast(), &mut label_length) })?;
    let label_length = label_length as usize;
    if label_length == 0 || label_length > LABEL_LIMIT {
        return Err(invalid("SO_PEERSEC returned no label or an over-long one"));
    }
    label.truncate(label_length);
    let mut descriptor: c_int = -1;
    let mut descriptor_length = size_of::<c_int>() as c_uint;
    // SAFETY: `descriptor` is a live `int` and `descriptor_length` its size; getsockopt writes the new pidfd's number
    // into it and the written length into `descriptor_length`.
    checked(unsafe {
        getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, (&mut descriptor as *mut c_int).cast(), &mut descriptor_length)
    })?;
    if descriptor < 0 {
        return Err(invalid("SO_PEERPIDFD returned no descriptor"));
    }
    let pidfd = PidFd { fd: adopt(descriptor) };
    if descriptor_length as usize != size_of::<c_int>() {
        return Err(invalid("SO_PEERPIDFD returned another length"));
    }
    Ok(PeerCreds { pid: credentials.pid, uid: credentials.uid, gid: credentials.gid, label, pidfd })
}

/// One identity file read whole: at most 4096 bytes, more is refused.
fn whole(file: File) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(LABEL_LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LABEL_LIMIT {
        return Err(invalid("an identity file is longer than 4096 bytes"));
    }
    Ok(bytes)
}

impl ProcDir {
    /// Opens the directory of process `pid` (a positive number) in the proc filesystem.
    pub fn open(pid: i32) -> io::Result<ProcDir> {
        if pid <= 0 {
            return Err(refusal("a process number must be positive"));
        }
        let dir = Dir::at(&format!("/proc/{}", pid))?;
        Ok(ProcDir { dir })
    }

    /// The start time (`stat` field 22), the whole `cgroup` file and the whole `attr/current` (through
    /// [`Dir::sub`]), each opened with [`Dir::file_ro`] and read whole.
    pub fn read(&self) -> io::Result<ProcIdentity> {
        let stat = whole(self.dir.file_ro("stat")?)?;
        let cgroup = whole(self.dir.file_ro("cgroup")?)?;
        let label = whole(self.dir.sub("attr")?.file_ro("current")?)?;
        ProcIdentity::from_files(&stat, cgroup, label).ok_or_else(|| invalid("an identity file of another shape"))
    }
}

impl PidFd {
    /// Whether the process has exited (zombie or reaped): a zero-timeout `ppoll` for POLLIN. EINTR retries; any other
    /// error, and POLLERR, POLLNVAL or any other returned event, counts as exited.
    pub fn exited(&self) -> bool {
        let zero = Timespec { seconds: 0, nanoseconds: 0 };
        loop {
            let mut entry = PollFd { fd: self.fd.as_raw_fd(), events: POLLIN, revents: 0 };
            // SAFETY: `entry` is one live `struct pollfd` (the count passed is 1), `zero` a live timespec that ppoll
            // reads, and the signal mask is null; ppoll writes only `entry.revents`.
            let value = unsafe { ppoll(&mut entry, 1, &zero, std::ptr::null()) };
            if value < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return true;
            }
            // A positive return means `revents` is not zero: POLLIN (the exit), POLLERR, POLLNVAL or another event,
            // every one of them counted as exited.
            return value > 0;
        }
    }
}

// ------------------------------------------------------------------------------------------ datagrams

/// One `recvmsg`'s result.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Recv {
    /// EAGAIN: nothing queued.
    WouldBlock,
    /// End of file: a return of 0 with no control data and no flags.
    Eof,
    /// Any other error (ECONNRESET among them), as its errno (-1 when the OS gave none).
    Error(i32),
    /// One datagram: its length in the buffer (MSG_TRUNC when it was longer) and its control bytes' length
    /// (MSG_CTRUNC when they did not fit). A zero-length datagram carries control data, so it is a datagram.
    Datagram { length: usize, truncated: bool, control_length: usize, control_truncated: bool },
}

/// One `recvmsg(fd, msg, MSG_DONTWAIT|MSG_CMSG_CLOEXEC)` into `buffer` with `control` as the control buffer. EINTR
/// retries.
pub fn recv(conn: &Conn, buffer: &mut [u8; FRAME_BUFFER_BYTES], control: &mut [u8]) -> Recv {
    let Ok(control_capacity) = c_uint::try_from(control.len()) else {
        return Recv::Error(-1);
    };
    loop {
        let mut vector = Iovec { base: buffer.as_mut_ptr().cast(), length: buffer.len() };
        let control_pointer = if control.is_empty() { std::ptr::null_mut() } else { control.as_mut_ptr().cast() };
        let mut message = MsgHdr {
            name: std::ptr::null_mut(),
            name_length: 0,
            iov: &mut vector,
            iov_length: 1,
            pad1: 0,
            control: control_pointer,
            control_length: control_capacity,
            pad2: 0,
            flags: 0,
        };
        // SAFETY: `message` is a live musl `struct msghdr` with no name, one live iovec addressing `buffer` (its whole
        // length) and a control pointer that is null or addresses `control` (its whole length); recvmsg writes at
        // most those lengths through them and its results into `message`, all of which outlive the call.
        let value = unsafe { recvmsg(conn.fd.as_raw_fd(), &mut message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC) };
        if value < 0 {
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Recv::WouldBlock,
                _ => return Recv::Error(error.raw_os_error().unwrap_or(-1)),
            }
        }
        let length = usize::try_from(value).unwrap_or(0).min(buffer.len());
        let control_length = (message.control_length as usize).min(control.len());
        if length == 0 && control_length == 0 && message.flags == 0 {
            return Recv::Eof;
        }
        return Recv::Datagram {
            length,
            truncated: message.flags & MSG_TRUNC != 0,
            control_length,
            control_truncated: message.flags & MSG_CTRUNC != 0,
        };
    }
}

/// One `sendmsg(fd, msg, MSG_DONTWAIT|MSG_NOSIGNAL)` of `bytes` as one datagram (SOCK_SEQPACKET sends it whole or
/// not at all). EINTR retries; any other failure, EAGAIN and EPIPE among them, is returned and never retried.
pub fn send(conn: &Conn, bytes: &[u8]) -> io::Result<()> {
    loop {
        let mut vector = Iovec { base: bytes.as_ptr().cast_mut().cast(), length: bytes.len() };
        let message = MsgHdr {
            name: std::ptr::null_mut(),
            name_length: 0,
            iov: &mut vector,
            iov_length: 1,
            pad1: 0,
            control: std::ptr::null_mut(),
            control_length: 0,
            pad2: 0,
            flags: 0,
        };
        // SAFETY: `message` is a live musl `struct msghdr` with no name, no control data and one live iovec
        // addressing `bytes` (its whole length); sendmsg only reads through them (musl copies the header first).
        let value = unsafe { sendmsg(conn.fd.as_raw_fd(), &message, MSG_DONTWAIT | MSG_NOSIGNAL) };
        if value < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if usize::try_from(value).ok() == Some(bytes.len()) {
            return Ok(());
        }
        return Err(io::Error::new(io::ErrorKind::WriteZero, "a datagram was not sent whole"));
    }
}

// ------------------------------------------------------------------------------------------ the poller

/// A descriptor the poller watches.
pub enum Watched<'a> {
    Listener(&'a Listener),
    Conn(&'a Conn),
    PidFd(&'a PidFd),
}

impl Watched<'_> {
    fn descriptor(&self) -> c_int {
        match self {
            Watched::Listener(listener) => listener.fd.as_raw_fd(),
            Watched::Conn(conn) => conn.fd.as_raw_fd(),
            Watched::PidFd(pidfd) => pidfd.fd.as_raw_fd(),
        }
    }
}

/// The events a watch asks for (error and hang-up are always reported).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Interest {
    pub readable: bool,
    pub writable: bool,
}

/// The events one wake reported for a token.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ready {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub hangup: bool,
}

fn interest_bits(interest: Interest) -> u32 {
    (if interest.readable { EPOLLIN } else { 0 }) | (if interest.writable { EPOLLOUT } else { 0 })
}

impl Poller {
    /// `epoll_create1(EPOLL_CLOEXEC)`.
    pub fn new() -> io::Result<Poller> {
        // SAFETY: epoll_create1 takes one integer and reads or writes no memory.
        owned(unsafe { epoll_create1(EPOLL_CLOEXEC) }).map(|fd| Poller { fd })
    }

    fn control(&self, operation: c_int, descriptor: c_int, token: u64, interest: Interest) -> io::Result<()> {
        let mut event = EpollEvent { events: interest_bits(interest), data: token };
        // SAFETY: `event` is a live `struct epoll_event` of the kernel's layout for this target, which epoll_ctl reads
        // (and ignores for EPOLL_CTL_DEL) and does not write.
        checked(unsafe { epoll_ctl(self.fd.as_raw_fd(), operation, descriptor, &mut event) }).map(|_| ())
    }

    /// Watches `watched` with `token` (EPOLL_CTL_ADD).
    pub fn add(&self, watched: Watched<'_>, token: u64, interest: Interest) -> io::Result<()> {
        self.control(EPOLL_CTL_ADD, watched.descriptor(), token, interest)
    }

    /// Changes the token or interest of a watched descriptor (EPOLL_CTL_MOD).
    pub fn modify(&self, watched: Watched<'_>, token: u64, interest: Interest) -> io::Result<()> {
        self.control(EPOLL_CTL_MOD, watched.descriptor(), token, interest)
    }

    /// Stops watching `watched` (EPOLL_CTL_DEL). Closing a descriptor no other descriptor shares also removes it.
    pub fn delete(&self, watched: Watched<'_>) -> io::Result<()> {
        self.control(EPOLL_CTL_DEL, watched.descriptor(), 0, Interest { readable: false, writable: false })
    }

    /// One `epoll_pwait` with a null signal mask and at most 64 events, `timeout_ms` -1 for none; `ready` is replaced
    /// by the reported tokens and events. EINTR is reported as an empty wake.
    pub fn wait(&self, timeout_ms: c_int, ready: &mut Vec<(u64, Ready)>) -> io::Result<()> {
        ready.clear();
        let mut events = [EpollEvent { events: 0, data: 0 }; WAIT_EVENTS];
        // SAFETY: `events` holds WAIT_EVENTS live, writable entries of the kernel's layout and the capacity passed is
        // that count; the signal mask is null. epoll_pwait writes at most that many entries.
        let value = unsafe {
            epoll_pwait(self.fd.as_raw_fd(), events.as_mut_ptr(), WAIT_EVENTS as c_int, timeout_ms, std::ptr::null())
        };
        if value < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(());
            }
            return Err(error);
        }
        let count = usize::try_from(value).unwrap_or(0).min(WAIT_EVENTS);
        for event in events.iter().take(count) {
            // Copied out by value: on x86_64 the struct is packed, so no reference to a field is taken.
            let event = *event;
            let (bits, token) = (event.events, event.data);
            ready.push((token, Ready {
                readable: bits & EPOLLIN != 0,
                writable: bits & EPOLLOUT != 0,
                error: bits & EPOLLERR != 0,
                hangup: bits & EPOLLHUP != 0,
            }));
        }
        Ok(())
    }
}
