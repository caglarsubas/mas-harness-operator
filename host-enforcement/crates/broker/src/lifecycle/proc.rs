//! W3's reads of the frozen child's process directory (DESIGN-HE005 section 4.0 :422, H5E-6; the frozen seam note,
//! sections 1 and 3, with MON-SEAM-E2). The directory is opened through gate-sys's `Dir::at` with the one start-up
//! exception expression seam section 1 names for this file, held here exactly once; it is also the one formatting in
//! the broker's non-test sources (MON-SEAM-E2). `status`, `stat` and `cgroup` are read through `file_ro`, and
//! `attr/current` through `sub("attr")` then `file_ro("current")` (gate-sys's name check refuses a `/`, H5F-4). Each
//! read is bounded at 4 KiB. The child is frozen and unreaped, and its pidfd is held, so its number cannot be reused.

use std::io;

use gate_sys::openat::read_bounded;
use gate_sys::Dir;

use crate::lifecycle::ops::ProcFile;

/// The bound of one process-directory read.
const PROC_READ_LIMIT: usize = 4096;

/// One file of the process directory of `pid`, a positive process number (any other is refused before any call).
pub fn read(pid: i32, file: ProcFile) -> io::Result<Vec<u8>> {
    if pid <= 0 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let process = Dir::at(&format!("/proc/{}", pid))?;
    let opened = match file {
        ProcFile::Status => process.file_ro("status")?,
        ProcFile::Stat => process.file_ro("stat")?,
        ProcFile::Cgroup => process.file_ro("cgroup")?,
        ProcFile::AttrCurrent => process.sub("attr")?.file_ro("current")?,
    };
    read_bounded(&opened, PROC_READ_LIMIT)?.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
}
