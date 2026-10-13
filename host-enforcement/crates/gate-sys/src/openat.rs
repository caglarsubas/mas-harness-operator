//! `openat(2)` behind a safe API (HE-002C DESIGN §3): the only module of the workspace where `unsafe` code may
//! appear, and only in two places, the call itself and the conversion of the descriptor it returns into a `File`.
//!
//! - [`Dir::at`] opens a store directory by absolute path (`openat(AT_FDCWD, path, O_RDONLY|O_DIRECTORY|O_CLOEXEC)`).
//! - [`Dir::file`] opens one store file inside it by name, read and write, never following a final symbolic link
//!   (`O_RDWR|O_CLOEXEC|O_NOFOLLOW`); [`FileMode::CreateOrExisting`] first tries an exclusive create with mode `0o600`
//!   and falls back to a plain open when the name exists. Whatever it opens must be a regular file (`fstat`): a FIFO,
//!   a device or a directory planted at a store name is refused.
//! - [`Dir::sync`] and [`Dir::device`] are `fsync` and `fstat`'s `st_dev` on the directory.
//!
//! The flag values are pinned per target. The two Linux columns were checked against the pinned musl `libc.a` and
//! the macOS column (host tests only) against the 13.3 SDK's `fcntl.h` (design review round 1); any other target
//! does not compile. Errors are the OS's (`io::Error::last_os_error()`), except the name and type checks of this
//! module, which are `InvalidInput`.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_uint;
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
}

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
#[derive(Debug)]
pub struct Dir {
    handle: File,
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
        let plain = flags::O_RDWR | flags::O_CLOEXEC | flags::O_NOFOLLOW;
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

    /// Makes the directory's entries durable (`fsync` on the directory; `F_FULLFSYNC` on Darwin).
    pub fn sync(&self) -> io::Result<()> {
        self.handle.sync_all()
    }

    /// The device the directory is on (`st_dev`).
    pub fn device(&self) -> io::Result<u64> {
        Ok(self.handle.metadata()?.dev())
    }
}
