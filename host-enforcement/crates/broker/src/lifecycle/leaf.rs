//! The probe-worker leaf (the frozen seam note, sections 1 and 3; Q-SEAM-1 (a), Q-SEAM-2 (a); HS53 section 4.2's
//! delegated leaf, W02 data). This file holds the leaf's one private root constant (a ROOT_CONSTANTS exception, seam
//! section 1), the one function that opens the leaf's two handles for `serve`, and, on Linux, the production `LeafOps`:
//! reads through gate-sys's `Dir` and `read_bounded`, writes through broker-sys's `LeafDir::write` alone.
//!
//! The two handles are opened back to back, in that order, from the one constant: gate-sys's `Dir` for the reads and
//! broker-sys's `LeafDir` for the writes and clone3 (Q-SEAM-2 (a); the residual is two opens of one fixed path, and
//! replacing a delegated leaf between them needs root, outside the threat model). `serve` owns both for the process's
//! life; the production `LeafOps` and `SpawnOps` borrow them. A failed open of either counts as `HoldRead` (SM-R2-2).
//! HE-006 creates the leaf, and T04 confirms it.

#[cfg(target_os = "linux")]
use std::io;

#[cfg(target_os = "linux")]
use broker_sys::{LeafDir, LeafWrite};
#[cfg(target_os = "linux")]
use gate_sys::openat::read_bounded;
#[cfg(target_os = "linux")]
use gate_sys::Dir;

#[cfg(target_os = "linux")]
use crate::lifecycle::ops::{LeafFile, LeafOps};

const LEAF_PATH: &str = "/sys/fs/cgroup/planeon.slice/planeon-capacity-broker.service/probe-worker";

/// The length of the cgroup filesystem's mount point at the head of `LEAF_PATH` (14 bytes): what follows it is the leaf
/// as a member's cgroup v2 line names it, read from the root cgroup namespace.
const MOUNT_BYTES: usize = 14;

/// The bound of one leaf read (seam section 3: 4 KiB).
#[cfg(target_os = "linux")]
const LEAF_READ_LIMIT: usize = 4096;

/// The leaf as a member's cgroup v2 line names it (`LEAF_PATH` past the mount point), which W3 compares with the frozen
/// child's `cgroup` line; empty, so never matched, if the constant were shorter than the mount point.
pub fn membership() -> &'static str {
    LEAF_PATH.get(MOUNT_BYTES..).unwrap_or_default()
}

/// The leaf's two handles, which `serve` owns for the process's life.
#[cfg(target_os = "linux")]
pub struct LeafHandles {
    dir: Dir,
    leaf: LeafDir,
}

/// The one opening function (seam sections 1 and 3, SM-R1-19, SM-R2-2): gate-sys's `Dir` and broker-sys's `LeafDir`,
/// back to back, in that order, from `LEAF_PATH`. `serve` calls it once, at its start.
#[cfg(target_os = "linux")]
pub fn open_leaf() -> io::Result<LeafHandles> {
    let dir = Dir::at(LEAF_PATH)?;
    let leaf = LeafDir::open(LEAF_PATH)?;
    Ok(LeafHandles { dir, leaf })
}

#[cfg(target_os = "linux")]
impl LeafHandles {
    /// The production `LeafOps`, borrowing both handles.
    pub fn leaf_ops(&self) -> LinuxLeaf<'_> {
        LinuxLeaf { dir: &self.dir, leaf: &self.leaf }
    }

    /// The leaf's directory, which the production `SpawnOps` borrows for clone3.
    pub fn leaf_dir(&self) -> &LeafDir {
        &self.leaf
    }
}

/// The production `LeafOps` (seam section 3).
#[cfg(target_os = "linux")]
pub struct LinuxLeaf<'a> {
    dir: &'a Dir,
    leaf: &'a LeafDir,
}

#[cfg(target_os = "linux")]
impl LeafOps for LinuxLeaf<'_> {
    fn read(&mut self, file: LeafFile) -> io::Result<Vec<u8>> {
        let name = match file {
            LeafFile::Type => "cgroup.type",
            LeafFile::Events => "cgroup.events",
            LeafFile::Procs => "cgroup.procs",
        };
        read_bounded(&self.dir.file_ro(name)?, LEAF_READ_LIMIT)?.ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
    }

    fn write(&mut self, what: LeafWrite) -> io::Result<()> {
        self.leaf.write(what)
    }
}
