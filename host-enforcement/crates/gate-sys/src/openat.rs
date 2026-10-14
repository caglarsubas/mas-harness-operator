//! `openat(2)` behind a safe API (HE-002C DESIGN §3): one of the three modules of the workspace where `unsafe` code may
//! appear (the others are the process seal's `seal.rs`, HE-002S, and the channel substrate's `channel.rs`, HE-003A),
//! and here only in two places, the call itself and the conversion of the descriptor it returns into a `File`.
//!
//! - [`Dir::at`] opens a store directory by absolute path (`openat(AT_FDCWD, path, O_RDONLY|O_DIRECTORY|O_CLOEXEC)`).
//! - [`Dir::file`] opens one store file inside it by name, read and write, never following a final symbolic link,
//!   never waiting and never taking a controlling terminal (`O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY`, HE-003A
//!   DESIGN §7, owner decision Q-HE3-4 (a)); [`FileMode::CreateOrExisting`] first tries an exclusive create with mode
//!   `0o600` and falls back to a plain open when the name exists. Whatever it opens must be a regular file (`fstat`): a
//!   FIFO, a device or a directory planted at a store name is refused. `O_NOCTTY` keeps the gate, a session leader
//!   under systemd, from acquiring a controlling terminal if a terminal node is planted at a store name; `O_NONBLOCK`
//!   keeps an open of a device node from waiting (a terminal waiting for carrier). Neither changes `pread`, `pwrite`,
//!   `fsync` or `flock` on a regular file.
//! - [`Dir::file_ro`] (HE-002S DESIGN §6) opens one existing file inside it by name, read-only and without waiting
//!   (`O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`), with the same name and regular-file checks: the seal's own status file
//!   and the signed configuration.
//! - [`Dir::sub`] (HE-003A DESIGN §7) opens one directory inside it by name, never following a symbolic link
//!   (`O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`), with the same name check: `attr` under a peer's process directory.
//! - [`Dir::sync`] and [`Dir::device`] are `fsync` and `fstat`'s `st_dev` on the directory.
//!
//! `Dir`'s `Debug` prints `Dir` and no descriptor: std's `Debug` of a `File` reads the descriptor's link in the proc
//! filesystem, a call the EFFECT_GATE program kills (HE-003A DESIGN §8).
//!
//! The flag values are pinned per target. The two Linux columns were checked against the pinned musl `libc.a` and
//! the macOS column (host tests only) against the 13.3 SDK's `fcntl.h` (design review round 1; `O_NONBLOCK`, HE-002S:
//! musl's `pipe2` sets 0o4000 with `F_SETFL` on both Linux targets, and the SDK's `sys/fcntl.h` defines 0x4;
//! `O_NOCTTY`, HE-003A: musl's `openpty.lo` opens the multiplexer with `O_RDWR|O_NOCTTY` = 0x102 on both Linux
//! targets, so 0o400, and the SDK's `sys/fcntl.h` defines 0x20000); any other target does not compile. Errors are the
//! OS's (`io::Error::last_os_error()`), except the name and type checks of this module, which are `InvalidInput`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uint;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod flags {
    use std::ffi::c_int;

    pub const AT_FDCWD: c_int = -100;
    pub const O_RDONLY: c_int = 0;
    pub const O_RDWR: c_int = 2;
    pub const O_CREAT: c_int = 0o100;
    pub const O_EXCL: c_int = 0o200;
    pub const O_DIRECTORY: c_int = 0o200000;
    pub const O_NOFOLLOW: c_int = 0o400000;
    pub const O_CLOEXEC: c_int = 0o2000000;
    pub const O_NONBLOCK: c_int = 0o4000;
    pub const O_NOCTTY: c_int = 0o400;
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod flags {
    use std::ffi::c_int;

    pub const AT_FDCWD: c_int = -100;
    pub const O_RDONLY: c_int = 0;
    pub const O_RDWR: c_int = 2;
    pub const O_CREAT: c_int = 0o100;
    pub const O_EXCL: c_int = 0o200;
    pub const O_DIRECTORY: c_int = 0o40000;
    pub const O_NOFOLLOW: c_int = 0o100000;
    pub const O_CLOEXEC: c_int = 0o2000000;
    pub const O_NONBLOCK: c_int = 0o4000;
    pub const O_NOCTTY: c_int = 0o400;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod flags {
    use std::ffi::c_int;

    pub const AT_FDCWD: c_int = -2;
    pub const O_RDONLY: c_int = 0;
    pub const O_RDWR: c_int = 2;
    pub const O_CREAT: c_int = 0x200;
    pub const O_EXCL: c_int = 0x800;
    pub const O_DIRECTORY: c_int = 0x100000;
    pub const O_NOFOLLOW: c_int = 0x100;
    pub const O_CLOEXEC: c_int = 0x1000000;
    pub const O_NONBLOCK: c_int = 0x4;
    pub const O_NOCTTY: c_int = 0x20000;
}

// HE-003A: the pinned musl `openpty.lo` opens the terminal multiplexer with `O_RDWR|O_NOCTTY`, the immediate 0x102 on
// both Linux targets.
#[cfg(target_os = "linux")]
const _: () = assert!(flags::O_RDWR | flags::O_NOCTTY == 0x102);

#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "aarch64")
)))]
compile_error!("gate-sys pins the openat flag values for linux x86_64, linux aarch64 and macOS aarch64 only");

/// The permission bits of a store file the gate creates: read and write for the owner only. Passed as `c_uint`, the
/// promoted type a variadic `mode_t` travels as (Darwin's `mode_t` is 16 bits, which a variadic call cannot carry).
const STORE_FILE_MODE: c_uint = 0o600;

/// The longest store file name (`NAME_MAX`).
const MAX_NAME_BYTES: usize = 255;

unsafe extern "C" {
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
}

/// How [`Dir::file`] opens a name.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FileMode {
    /// Only a file that is already there; a missing name is `Ok(None)`.
    Existing,
    /// Create the file exclusively, or open it when the name exists.
    CreateOrExisting,
}

/// An open store directory.
pub struct Dir {
    handle: File,
}

/// The type name only: no descriptor, and never std's `Debug` of the `File` (HE-003A DESIGN §7, §8).
impl fmt::Debug for Dir {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Dir")
    }
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// One `openat` call. The mode argument is passed only when the call may create; the descriptor becomes a `File`
/// right after the call, so it is closed on every path from then on.
fn call(dirfd: c_int, path: &CString, flags: c_int, create: bool) -> io::Result<File> {
    // SAFETY: `path` is NUL-terminated and outlives the call, and `openat` reads nothing else through pointers. The
    // variadic mode is read by the callee only when O_CREAT is set, and it is passed exactly then.
    let descriptor = unsafe {
        if create {
            openat(dirfd, path.as_ptr(), flags, STORE_FILE_MODE)
        } else {
            openat(dirfd, path.as_ptr(), flags)
        }
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `descriptor` was returned by the successful call above, is open, and nothing else owns it.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

/// A store name: 1 to 255 bytes, no `/`, no NUL, not `.` or `..`.
fn store_name(name: &str) -> io::Result<CString> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || name.contains('/') || name == "." || name == ".." {
        return Err(refusal("a store file name must be 1 to 255 bytes without '/' and not '.' or '..'"));
    }
    CString::new(name).map_err(|_| refusal("a store file name must not contain NUL"))
}

impl Dir {
    /// [`Dir::file`]'s flags: `O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY` (HE-003A DESIGN §7).
    pub const FILE_FLAGS: c_int =
        flags::O_RDWR | flags::O_CLOEXEC | flags::O_NOFOLLOW | flags::O_NONBLOCK | flags::O_NOCTTY;

    /// [`Dir::sub`]'s flags: `O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`.
    pub const SUB_FLAGS: c_int = flags::O_RDONLY | flags::O_DIRECTORY | flags::O_CLOEXEC | flags::O_NOFOLLOW;

    /// This target's `O_NOCTTY` and `O_NONBLOCK` (pinned by the host tests).
    pub const NOCTTY: c_int = flags::O_NOCTTY;
    pub const NONBLOCK: c_int = flags::O_NONBLOCK;

    /// Opens a directory by absolute path.
    pub fn at(absolute: &str) -> io::Result<Dir> {
        if !absolute.starts_with('/') {
            return Err(refusal("a store directory must be named by an absolute path"));
        }
        let path = CString::new(absolute).map_err(|_| refusal("a store directory path must not contain NUL"))?;
        let handle = call(flags::AT_FDCWD, &path, flags::O_RDONLY | flags::O_DIRECTORY | flags::O_CLOEXEC, false)?;
        Ok(Dir { handle })
    }

    /// Opens the store file `name` in this directory, read and write: `Some((file, created))`, or `None` for a
    /// missing name in [`FileMode::Existing`].
    pub fn file(&self, name: &str, mode: FileMode) -> io::Result<Option<(File, bool)>> {
        let name = store_name(name)?;
        let dirfd = self.handle.as_raw_fd();
        let plain = Dir::FILE_FLAGS;
        let (file, created) = match mode {
            FileMode::Existing => match call(dirfd, &name, plain, false) {
                Ok(file) => (file, false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            },
            FileMode::CreateOrExisting => match call(dirfd, &name, plain | flags::O_CREAT | flags::O_EXCL, true) {
                Ok(file) => (file, true),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (call(dirfd, &name, plain, false)?, false),
                Err(error) => return Err(error),
            },
        };
        if !file.metadata()?.file_type().is_file() {
            return Err(refusal("a store file name names something other than a regular file"));
        }
        Ok(Some((file, created)))
    }

    /// Opens the existing file `name` in this directory read-only, never following a final symbolic link and never
    /// waiting (`O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`), with [`Dir::file`]'s name check (before any call) and
    /// regular-file check (`fstat`, after the open). `O_NONBLOCK` has no effect on a regular file; a FIFO planted at the
    /// name opens at once instead of waiting for a writer, and the regular-file check refuses it (owner decision
    /// Q-HE2S-11 (a)). A missing name is the OS's `NotFound`.
    pub fn file_ro(&self, name: &str) -> io::Result<File> {
        let name = store_name(name)?;
        let read_only = flags::O_RDONLY | flags::O_CLOEXEC | flags::O_NOFOLLOW | flags::O_NONBLOCK;
        let file = call(self.handle.as_raw_fd(), &name, read_only, false)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(refusal("a file name names something other than a regular file"));
        }
        Ok(file)
    }

    /// Opens the directory `name` in this directory (`O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`), with
    /// [`Dir::file`]'s name check before any call: one component, never `.` or `..`, never a symbolic link.
    pub fn sub(&self, name: &str) -> io::Result<Dir> {
        let name = store_name(name)?;
        let handle = call(self.handle.as_raw_fd(), &name, Dir::SUB_FLAGS, false)?;
        Ok(Dir { handle })
    }

    /// Makes the directory's entries durable (`fsync` on the directory; `F_FULLFSYNC` on Darwin).
    pub fn sync(&self) -> io::Result<()> {
        self.handle.sync_all()
    }

    /// The device the directory is on (`st_dev`).
    pub fn device(&self) -> io::Result<u64> {
        Ok(self.handle.metadata()?.dev())
    }
}
