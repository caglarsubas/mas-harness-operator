//! The I04 listener's raw calls (HE-003B DESIGN §3.1), Linux only: the fourth module of the workspace allowed to hold
//! `unsafe` code (with `openat.rs`, `seal.rs` and `channel.rs`), each call in its own block with its own `// SAFETY:`
//! argument behind a safe function. The foreign symbols are exactly `socket`, `setsockopt`, `bind`, `listen`, `recv`,
//! `send`, `shutdown` and `syscall`; `tools/gate.py` checks that this file declares exactly them.
//!
//! - [`listen_tcp`]: a TCP listener on a literal address (port 1024 or above): `socket(family,
//!   SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_TCP)`, SO_REUSEADDR (so a restarted gate binds while the crashed
//!   one's connections sit in TIME_WAIT), IPV6_V6ONLY for IPv6, `bind` with the exact address length, `listen`. No
//!   other TCP option (no TCP_NODELAY, keepalive, linger or TCP_FASTOPEN).
//! - [`accept_tcp`]: `accept4` issued through `syscall` (musl's `accept4` falls back to `accept`, which the EFFECT_GATE
//!   program kills), asking for no peer address.
//! - [`TcpConn::recv`], [`TcpConn::send`] and [`TcpConn::shutdown_write`]: one call each, never waiting.
//!
//! Every descriptor is an `OwnedFd` inside an opaque type (`TcpListener`, `TcpConn`), closed by drop; their manual
//! `Debug` prints the type name only, and the crate-private `descriptor` gives `channel.rs`'s poller the number.
//!
//! Constants and their evidence (the pinned musl 1.2.5 `libc.a`, sha256 `e699c64b…` for x86_64 and `b03473b6…` for
//! aarch64, where its code shows the value; otherwise the kernel UAPI header named; for T04): `accept4` 288 / 242
//! (`accept4.lo`); `AF_INET` 2 (`res_msend.lo` calls `socket(2, 0x80802, 0)` with a 16-byte address); `AF_INET6` 10
//! (`res_msend.lo` sets family 10 with a 28-byte address); `SOCK_STREAM` 1 (`res_msend.lo`'s TCP fallback calls
//! `socket(family, 0x80801, ..)`); `SOCK_NONBLOCK` 0x800 and `SOCK_CLOEXEC` 0x80000 (as `channel.rs`); `IPPROTO_TCP` 6
//! (`res_msend.lo` calls `setsockopt(fd, 6, 30, ..)`); `IPPROTO_IPV6` 41 and `IPV6_V6ONLY` 26 (`res_msend.lo` calls
//! `setsockopt(fd, 41, 26, ..)`); `MSG_DONTWAIT` 0x40 and `MSG_NOSIGNAL` 0x4000 (as `channel.rs`). musl's `recv` is
//! `recvfrom(fd, buf, len, flags, 0, 0)` (system call 45 / 207) and `send` is `sendto(.., 0, 0)` (44 / 206);
//! `shutdown` is 48 / 210. From the kernel UAPI: `SOL_SOCKET` 1 and `SO_REUSEADDR` 2 (the generic `socket.h`),
//! `SHUT_WR` 1 (`linux/net.h`), and the errno values below (the generic `errno.h`, which both architectures use).
#![allow(unsafe_code)]

use std::ffi::c_int;
use std::ffi::c_long;
use std::ffi::c_uint;
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::mem::offset_of;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;

use crate::inet::InetAddress;
use crate::inet::IpLiteral;

#[cfg(target_arch = "x86_64")]
const SYS_ACCEPT4: c_long = 288;
#[cfg(target_arch = "aarch64")]
const SYS_ACCEPT4: c_long = 242;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("gate-sys pins the TCP constants for x86_64 and aarch64 only");

const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;
const SOCK_STREAM: c_int = 1;
const SOCK_NONBLOCK: c_int = 0o4000;
const SOCK_CLOEXEC: c_int = 0o2000000;
const IPPROTO_TCP: c_int = 6;
const IPPROTO_IPV6: c_int = 41;
const IPV6_V6ONLY: c_int = 26;
const SOL_SOCKET: c_int = 1;
const SO_REUSEADDR: c_int = 2;
const MSG_DONTWAIT: c_int = 0x40;
const MSG_NOSIGNAL: c_int = 0x4000;
const SHUT_WR: c_int = 1;

/// The errno values the accept mapping names (the generic `errno.h`).
pub mod errno {
    pub const EINTR: i32 = 4;
    pub const EAGAIN: i32 = 11;
    pub const EINVAL: i32 = 22;
    pub const ENONET: i32 = 64;
    pub const EPROTO: i32 = 71;
    pub const ENOPROTOOPT: i32 = 92;
    pub const EOPNOTSUPP: i32 = 95;
    pub const ENETDOWN: i32 = 100;
    pub const ENETUNREACH: i32 = 101;
    pub const ECONNABORTED: i32 = 103;
    pub const EHOSTDOWN: i32 = 112;
    pub const EHOSTUNREACH: i32 = 113;
}

const _: () = assert!(SOCK_NONBLOCK == 0x800 && SOCK_CLOEXEC == 0x80000);

/// `struct sockaddr_in`: the port big-endian, the address's four octets in order.
#[repr(C)]
struct SockaddrIn {
    family: u16,
    port: u16,
    address: u32,
    zero: [u8; 8],
}

/// `struct sockaddr_in6`: the port big-endian, flow information and scope 0.
#[repr(C)]
struct SockaddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    address: [u8; 16],
    scope_id: u32,
}

const _: () = assert!(size_of::<SockaddrIn>() == 16 && align_of::<SockaddrIn>() == 4);
const _: () = assert!(
    offset_of!(SockaddrIn, family) == 0
        && offset_of!(SockaddrIn, port) == 2
        && offset_of!(SockaddrIn, address) == 4
        && offset_of!(SockaddrIn, zero) == 8
);
const _: () = assert!(size_of::<SockaddrIn6>() == 28 && align_of::<SockaddrIn6>() == 4);
const _: () = assert!(
    offset_of!(SockaddrIn6, family) == 0
        && offset_of!(SockaddrIn6, port) == 2
        && offset_of!(SockaddrIn6, flowinfo) == 4
        && offset_of!(SockaddrIn6, address) == 8
        && offset_of!(SockaddrIn6, scope_id) == 24
);
const _: () = assert!(size_of::<c_long>() == 8 && size_of::<c_int>() == 4 && size_of::<usize>() == 8);

#[allow(clashing_extern_declarations)]
unsafe extern "C" {
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, length: c_uint) -> c_int;
    fn bind(fd: c_int, address: *const c_void, length: c_uint) -> c_int;
    fn listen(fd: c_int, backlog: c_int) -> c_int;
    fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> c_long;
    fn send(fd: c_int, buffer: *const c_void, length: usize, flags: c_int) -> c_long;
    fn shutdown(fd: c_int, how: c_int) -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
}

/// musl's convention: -1 and `errno` on failure.
fn checked(value: c_int) -> io::Result<c_int> {
    if value < 0 { Err(io::Error::last_os_error()) } else { Ok(value) }
}

/// A descriptor a call just returned, owned from here on (closed on every later path).
fn adopt(descriptor: c_int) -> OwnedFd {
    // SAFETY: callers pass only a descriptor a successful call returned to this process a moment ago, which is open
    // and owned by nothing else.
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

/// The last call's errno (-1 when the OS gave none).
fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// The I04 listener.
pub struct TcpListener {
    fd: OwnedFd,
}

/// One accepted TCP connection.
pub struct TcpConn {
    fd: OwnedFd,
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TcpListener")
    }
}

impl fmt::Debug for TcpConn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TcpConn")
    }
}

impl TcpListener {
    /// The descriptor, for `channel.rs`'s poller only.
    pub(crate) fn descriptor(&self) -> c_int {
        self.fd.as_raw_fd()
    }
}

impl TcpConn {
    /// The descriptor, for `channel.rs`'s poller only.
    pub(crate) fn descriptor(&self) -> c_int {
        self.fd.as_raw_fd()
    }
}

// ------------------------------------------------------------------------------------------ listener

/// The step of [`listen_tcp`] that failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpStep {
    /// The port is below 1024 (refused before any call; owner decision Q-HE2S-9 (a)).
    Port,
    Socket,
    ReuseAddress,
    V6Only,
    Bind,
    Listen,
}

/// A failed [`listen_tcp`]: the step and the OS's error.
#[derive(Debug)]
pub struct TcpListenError {
    pub step: TcpStep,
    pub error: io::Error,
}

fn at(step: TcpStep) -> impl FnOnce(io::Error) -> TcpListenError {
    move |error| TcpListenError { step, error }
}

/// `setsockopt(fd, level, name, &1, 4)`.
fn enable(fd: &OwnedFd, level: c_int, name: c_int) -> io::Result<()> {
    let value: c_int = 1;
    // SAFETY: `value` is a live `int` that setsockopt reads (the length passed is its size) and does not write.
    let length = size_of::<c_int>() as c_uint;
    checked(unsafe { setsockopt(fd.as_raw_fd(), level, name, (&value as *const c_int).cast(), length) }).map(|_| ())
}

/// A TCP listener on `address` with a listen backlog of `backlog` (see the module documentation).
pub fn listen_tcp(address: &InetAddress, backlog: u16) -> Result<TcpListener, TcpListenError> {
    if address.port < 1024 {
        return Err(TcpListenError {
            step: TcpStep::Port,
            error: io::Error::new(io::ErrorKind::InvalidInput, "the I04 port must be 1024 or above"),
        });
    }
    let family = match address.ip {
        IpLiteral::V4(_) => AF_INET,
        IpLiteral::V6(_) => AF_INET6,
    };
    // SAFETY: socket takes three integers and reads or writes no memory; its new descriptor is adopted at once.
    let fd = checked(unsafe { socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP) })
        .map(adopt)
        .map_err(at(TcpStep::Socket))?;
    enable(&fd, SOL_SOCKET, SO_REUSEADDR).map_err(at(TcpStep::ReuseAddress))?;
    match address.ip {
        IpLiteral::V4(octets) => {
            let socket_address = SockaddrIn {
                family: AF_INET as u16,
                port: address.port.to_be(),
                address: u32::from_ne_bytes(octets),
                zero: [0; 8],
            };
            // SAFETY: `socket_address` is a live `sockaddr_in` that bind reads and does not write; the length passed is
            // exactly its size.
            checked(unsafe {
                bind(fd.as_raw_fd(), (&socket_address as *const SockaddrIn).cast(), size_of::<SockaddrIn>() as c_uint)
            })
            .map_err(at(TcpStep::Bind))?;
        }
        IpLiteral::V6(octets) => {
            enable(&fd, IPPROTO_IPV6, IPV6_V6ONLY).map_err(at(TcpStep::V6Only))?;
            let socket_address = SockaddrIn6 {
                family: AF_INET6 as u16,
                port: address.port.to_be(),
                flowinfo: 0,
                address: octets,
                scope_id: 0,
            };
            // SAFETY: `socket_address` is a live `sockaddr_in6` that bind reads and does not write; the length passed
            // is exactly its size.
            checked(unsafe {
                bind(fd.as_raw_fd(), (&socket_address as *const SockaddrIn6).cast(), size_of::<SockaddrIn6>() as c_uint)
            })
            .map_err(at(TcpStep::Bind))?;
        }
    }
    // SAFETY: listen takes two integers and reads or writes no memory.
    checked(unsafe { listen(fd.as_raw_fd(), c_int::from(backlog)) }).map_err(at(TcpStep::Listen))?;
    Ok(TcpListener { fd })
}

// ------------------------------------------------------------------------------------------ accept

/// One accept's result.
pub enum Accepted {
    Conn(TcpConn),
    /// EAGAIN: nothing queued.
    Empty,
    /// ECONNABORTED or a network error Linux reports on an accepted TCP connection (accept(2), "Error handling"):
    /// accept again.
    Skip,
    /// Any other error (EMFILE, ENFILE, ENOBUFS, ENOMEM, EBADF, ...), as its errno.
    Failed(i32),
}

/// Whether accept(2)'s "Error handling" names `errno` as a network error to retry after.
pub fn accept_retries(errno: i32) -> bool {
    matches!(
        errno,
        errno::ECONNABORTED
            | errno::ENETDOWN
            | errno::EPROTO
            | errno::ENOPROTOOPT
            | errno::EHOSTDOWN
            | errno::ENONET
            | errno::EHOSTUNREACH
            | errno::EOPNOTSUPP
            | errno::ENETUNREACH
    )
}

/// One `accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC)` through `syscall`; EINTR retries.
pub fn accept_tcp(listener: &TcpListener) -> Accepted {
    let zero: c_long = 0;
    loop {
        // SAFETY: the two null address arguments ask the kernel for no peer address, so nothing is read or written
        // through a pointer; musl's syscall reads six `long` arguments after the number, which are all passed.
        let value = unsafe {
            syscall(SYS_ACCEPT4, c_long::from(listener.fd.as_raw_fd()), zero, zero,
                    c_long::from(SOCK_NONBLOCK | SOCK_CLOEXEC), zero, zero)
        };
        if value >= 0 {
            return match c_int::try_from(value) {
                Ok(descriptor) => Accepted::Conn(TcpConn { fd: adopt(descriptor) }),
                Err(_) => Accepted::Failed(errno::EINVAL),
            };
        }
        let error = last_errno();
        match error {
            errno::EINTR => continue,
            errno::EAGAIN => return Accepted::Empty,
            error if accept_retries(error) => return Accepted::Skip,
            error => return Accepted::Failed(error),
        }
    }
}

// ------------------------------------------------------------------------------------------ transfers

/// One `recv` or `send`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Transfer {
    /// The bytes received (at least 1) or sent.
    Data(usize),
    /// EAGAIN.
    WouldBlock,
    /// A receive returned 0: the peer closed its side.
    Eof,
    /// Any other error, as its errno (EINVAL for an empty receive buffer, refused before the call).
    Failed(i32),
}

impl TcpConn {
    /// One `recv(fd, buffer, len, MSG_DONTWAIT)`. An empty buffer is refused before the call (a return of 0 must mean
    /// end of file); EINTR retries.
    pub fn recv(&self, buffer: &mut [u8]) -> Transfer {
        if buffer.is_empty() {
            return Transfer::Failed(errno::EINVAL);
        }
        loop {
            // SAFETY: the pointer and length come from one live `&mut [u8]`; recv writes at most that many bytes into
            // it, and the return value bounds what the caller reads back.
            let value = unsafe { recv(self.fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), MSG_DONTWAIT) };
            if value < 0 {
                match last_errno() {
                    errno::EINTR => continue,
                    errno::EAGAIN => return Transfer::WouldBlock,
                    error => return Transfer::Failed(error),
                }
            }
            return match usize::try_from(value) {
                Ok(0) => Transfer::Eof,
                Ok(count) => Transfer::Data(count.min(buffer.len())),
                Err(_) => Transfer::Failed(errno::EINVAL),
            };
        }
    }

    /// One `send(fd, bytes, len, MSG_DONTWAIT|MSG_NOSIGNAL)`: a partial count is normal on a stream; EINTR retries.
    pub fn send(&self, bytes: &[u8]) -> Transfer {
        loop {
            // SAFETY: the pointer and length come from one live `&[u8]`, which send only reads.
            let value =
                unsafe { send(self.fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), MSG_DONTWAIT | MSG_NOSIGNAL) };
            if value < 0 {
                match last_errno() {
                    errno::EINTR => continue,
                    errno::EAGAIN => return Transfer::WouldBlock,
                    error => return Transfer::Failed(error),
                }
            }
            return match usize::try_from(value) {
                Ok(count) => Transfer::Data(count.min(bytes.len())),
                Err(_) => Transfer::Failed(errno::EINVAL),
            };
        }
    }

    /// One `shutdown(fd, SHUT_WR)`: used only on the relay path, once rustls has nothing left to write.
    pub fn shutdown_write(&self) -> io::Result<()> {
        // SAFETY: shutdown takes two integers and reads or writes no memory.
        checked(unsafe { shutdown(self.fd.as_raw_fd(), SHUT_WR) }).map(|_| ())
    }
}
