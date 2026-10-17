//! `openat(2)` behind a safe API (HE-002C DESIGN §3): one of the modules of the workspace where `unsafe` code may
//! appear (the others are the process seal's `seal.rs`, HE-002S, the channel substrate's `channel.rs`, HE-003A, and the
//! I04 listener's `tcp.rs`, HE-003B), and here only in three places: the `openat` call, the conversion of the
//! descriptor it returns into a `File`, and the `readlinkat` call of [`Dir::read_link`] (HE-003A2).
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
//! - [`Dir::read_link`] (HE-003A2 DESIGN §3, owner decision Q-A2-2 (a)) reads one symbolic link inside it by name,
//!   with the same name check, through musl's `readlinkat` wrapper on the directory's own descriptor (never `AT_FDCWD`,
//!   and the name is never absolute, so the descriptor is never ignored): the gate's read of its writer peer's `exe`
//!   link through the retained process directory. A full buffer, an empty result and any error are refused.
//! - [`KernelRoot`] (HE-003A3 DESIGN section 5, owner decisions Q-A3-5 and Q-A3-15 (a); Linux only) is the observation's
//!   root handle, a type of its own: [`KernelRoot::open_kernel_root`] opens a directory by absolute path with
//!   `O_PATH|O_DIRECTORY|O_CLOEXEC` (no `open` or `read` of the directory itself, which SELinux matrix v5 does not grant
//!   the gate), and its only method, [`KernelRoot::open_fixed`], opens one [`FixedPath`] relative to it, read-only,
//!   never following a final symbolic link (`O_RDONLY|O_CLOEXEC|O_NOFOLLOW`). A `FixedPath` is 1 to 4 components of
//!   `[A-Za-z0-9._-]+`, none `.` or `..`, built from a constant ([`FixedPath::from_constant`]) or as `<pid>/stat` for a
//!   process number of at least 1 ([`FixedPath::pid_stat`]); `tools/gate.py` pins the callers to effect-gate's
//!   `linux_os.rs` by exact call forms. [`read_bounded`] reads an opened file with plain `read` calls until one returns
//!   0, into a buffer one byte longer than its bound, so a longer file is refused without sizing anything from metadata
//!   (I05 v4 rule 5); `file_ro` is unchanged.
//!
//! `Dir`'s and `KernelRoot`'s `Debug` print their type names and no descriptor: std's `Debug` of a `File` reads the
//! descriptor's link in the proc filesystem, a call the EFFECT_GATE program kills (HE-003A DESIGN §8).
//!
//! The flag values are pinned per target. The two Linux columns were checked against the pinned musl `libc.a` and
//! the macOS column (host tests only) against the 13.3 SDK's `fcntl.h` (design review round 1; `O_NONBLOCK`, HE-002S:
//! musl's `pipe2` sets 0o4000 with `F_SETFL` on both Linux targets, and the SDK's `sys/fcntl.h` defines 0x4;
//! `O_NOCTTY`, HE-003A: musl's `openpty.lo` opens the multiplexer with `O_RDWR|O_NOCTTY` = 0x102 on both Linux
//! targets, so 0o400, and the SDK's `sys/fcntl.h` defines 0x20000); any other target does not compile. `O_PATH`
//! (HE-003A3, Linux only, D2-7): 0o10000000 on both Linux targets, the value of the vendored libc 0.2.190's musl
//! module (`src/unix/linux_like/linux/musl/mod.rs:522`, no architecture override), asserted at compile time; gate-sys
//! gains no dependency. Errors are the OS's (`io::Error::last_os_error()`), except the name and type checks of this
//! module, which are `InvalidInput`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uint;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
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
    pub const O_PATH: c_int = 0o10000000;
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
    pub const O_PATH: c_int = 0o10000000;
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

// HE-003A3 (D2-7): the vendored libc 0.2.190's musl `O_PATH`, the same on both Linux targets.
#[cfg(target_os = "linux")]
const _: () = assert!(flags::O_PATH == 0o10000000);

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

/// The most components a [`FixedPath`] holds (HE-003A3).
pub const MAX_FIXED_COMPONENTS: usize = 4;

unsafe extern "C" {
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn readlinkat(dirfd: c_int, path: *const c_char, buffer: *mut c_char, size: usize) -> isize;
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

    /// Reads the symbolic link `name` in this directory into `buffer` (HE-003A2 DESIGN §3): [`Dir::file`]'s name check
    /// before any call (one relative component, so the directory's descriptor is never ignored), then one
    /// `readlinkat` on this directory's own descriptor, which is non-negative by construction (never `AT_FDCWD`). The
    /// kernel writes no NUL and truncates a longer link without an error, so the count is refused when it fills the
    /// buffer; it is refused when it is 0, and an empty buffer is refused before the call. Any other result is the
    /// count of bytes the link's text holds in `buffer`. The comparison with an expected value is the caller's.
    pub fn read_link(&self, name: &str, buffer: &mut [u8]) -> io::Result<usize> {
        let name = store_name(name)?;
        if buffer.is_empty() {
            return Err(refusal("a link buffer must hold at least one byte"));
        }
        let size = buffer.len();
        // SAFETY: `name` is NUL-terminated and outlives the call; `buffer` is a live, writable slice of `size` bytes,
        // so `readlinkat` writes at most that many bytes into it and reads nothing else through pointers; the
        // descriptor is this directory's own and stays open while `self` lives.
        let count = unsafe { readlinkat(self.handle.as_raw_fd(), name.as_ptr(), buffer.as_mut_ptr().cast(), size) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        match usize::try_from(count) {
            Ok(0) => Err(refusal("a symbolic link read back empty")),
            Ok(count) if count < buffer.len() => Ok(count),
            _ => Err(refusal("a symbolic link filled its buffer and may be longer")),
        }
    }
}

// ------------------------------------------------------------------------------------------ the observation's reads

/// One component of a [`FixedPath`]: `[A-Za-z0-9._-]+`, not `.` or `..`.
fn fixed_component(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-')
}

/// A relative path a [`KernelRoot`] opens (HE-003A3 DESIGN section 5): 1 to 4 components of `[A-Za-z0-9._-]+`, none
/// empty, `.` or `..`, so it never leaves the root, never names a parent and is never absolute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedPath {
    path: CString,
}

impl FixedPath {
    /// A fixed path from a constant (the probe-worker leaf's member file); refused (`InvalidInput`) unless it is 1 to
    /// 4 components of the grammar.
    pub fn from_constant(path: &'static str) -> io::Result<FixedPath> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() > MAX_FIXED_COMPONENTS || !parts.iter().all(|part| fixed_component(part)) {
            return Err(refusal("a fixed path is 1 to 4 components of [A-Za-z0-9._-], none '.' or '..'"));
        }
        CString::new(path).map(|path| FixedPath { path }).map_err(|_| refusal("a fixed path must not contain NUL"))
    }

    /// `<pid>/stat` for a process number of at least 1; refused (`InvalidInput`) otherwise.
    pub fn pid_stat(pid: i32) -> io::Result<FixedPath> {
        if pid < 1 {
            return Err(refusal("a process number must be at least 1"));
        }
        CString::new(format!("{pid}/stat")).map(|path| FixedPath { path }).map_err(|_| refusal("a fixed path"))
    }

    /// The path's bytes (without the NUL).
    pub fn as_bytes(&self) -> &[u8] {
        self.path.as_bytes()
    }
}

/// Reads `file` with plain `read` calls until one returns 0 (EINTR retries), into a buffer of `limit + 1` bytes: the
/// bytes read, or `None` when the file holds more than `limit` bytes (HE-003A3, I05 v4 rule 5). Nothing is sized from
/// metadata; any other error is returned.
pub fn read_bounded(file: &File, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut buffer = vec![0u8; limit.saturating_add(1)];
    let mut filled = 0usize;
    let mut reader = file;
    loop {
        let Some(rest) = buffer.get_mut(filled..).filter(|rest| !rest.is_empty()) else { return Ok(None) };
        match reader.read(rest) {
            Ok(0) => break,
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    buffer.truncate(filled);
    Ok(Some(buffer))
}

/// The observation's root handle (HE-003A3 DESIGN section 5, Linux only): an `O_PATH` directory descriptor whose only
/// method is [`KernelRoot::open_fixed`]. The descriptor closes when the handle is dropped.
#[cfg(target_os = "linux")]
pub struct KernelRoot {
    handle: File,
}

/// The type name only: no descriptor, and never std's `Debug` of the `File`.
#[cfg(target_os = "linux")]
impl fmt::Debug for KernelRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KernelRoot")
    }
}

#[cfg(target_os = "linux")]
impl KernelRoot {
    /// [`KernelRoot::open_kernel_root`]'s flags: `O_PATH|O_DIRECTORY|O_CLOEXEC`.
    pub const ROOT_FLAGS: c_int = flags::O_PATH | flags::O_DIRECTORY | flags::O_CLOEXEC;

    /// [`KernelRoot::open_fixed`]'s flags: `O_RDONLY|O_CLOEXEC|O_NOFOLLOW`.
    pub const FIXED_FLAGS: c_int = flags::O_RDONLY | flags::O_CLOEXEC | flags::O_NOFOLLOW;

    /// Opens the directory at `absolute` as a root handle (`openat(AT_FDCWD, absolute, O_PATH|O_DIRECTORY|O_CLOEXEC)`).
    pub fn open_kernel_root(absolute: &str) -> io::Result<KernelRoot> {
        if !absolute.starts_with('/') {
            return Err(refusal("a kernel root must be named by an absolute path"));
        }
        let path = CString::new(absolute).map_err(|_| refusal("a kernel root path must not contain NUL"))?;
        let handle = call(flags::AT_FDCWD, &path, KernelRoot::ROOT_FLAGS, false)?;
        Ok(KernelRoot { handle })
    }

    /// Opens `path` relative to this root, read-only (`openat(root, path, O_RDONLY|O_CLOEXEC|O_NOFOLLOW)`); the
    /// descriptor is non-negative by construction and the path is never absolute, so the root is never ignored.
    pub fn open_fixed(&self, path: &FixedPath) -> io::Result<File> {
        call(self.handle.as_raw_fd(), &path.path, KernelRoot::FIXED_FLAGS, false)
    }
}
