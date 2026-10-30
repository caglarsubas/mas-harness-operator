//! The capacity broker's raw calls (HE-005C; DESIGN-HE005 revision 5 sections 3.2, 3.5 and 4.0; the frozen seam note
//! DESIGN-HE005.SEAM-C revision 4, `ad6d3a75`, MON-SEAM-FREEZE). A std-only crate that planeon-broker alone links, in
//! observer-sys's form: `raw` holds the one foreign item, `syscall`, the calls it issues by number, their constants and
//! layouts, one `// SAFETY:` argument per unsafe block, the clone3 span and the child path, generic over one raw-call
//! trait, and the safe API the broker's lifecycle drives. This file holds the seam note's plain types and re-exports
//! the rest.
//!
//! Written by hand by the Build-R10 session, in its main session, with no subagent (owner rulings of 2026-10-30,
//! "Hand-written raw module (Recommended)" and "Build-R10 session writes it (Recommended)").
//!
//! The crate root denies `unsafe_code`; `raw.rs` alone opts out. No function here chooses an outcome or retries a
//! failed call: every decision is the broker's (the seam note's section 2 rule).
#![deny(unsafe_code)]

mod raw;

pub use raw::ChannelEnd;
pub use raw::Child;
pub use raw::ChildPlan;
pub use raw::LeafDir;
pub use raw::Pidfd;
pub use raw::Script;

#[cfg(target_os = "linux")]
pub use raw::fd_table;
#[cfg(target_os = "linux")]
pub use raw::measure_verity;
#[cfg(target_os = "linux")]
pub use raw::reap;
#[cfg(target_os = "linux")]
pub use raw::seqpacket_pair;
#[cfg(target_os = "linux")]
pub use raw::sleep_monotonic;
#[cfg(target_os = "linux")]
pub use raw::spawn;

/// The leaf's three valid writes (seam note section 2, SM-R1-18): `Freeze` writes "1" and `Thaw` writes "0" to
/// cgroup.freeze, and `Kill` writes "1" to cgroup.kill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafWrite {
    Freeze,
    Thaw,
    Kill,
}

/// One source descriptor W3 compares, captured in the parent before clone3: its number, which the child inherits at
/// clone3, and its (dev, ino).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdIdentity {
    pub number: u32,
    pub dev: u64,
    pub ino: u64,
}

/// What W3 compares (seam note section 2, SM-R1-2): the child's fd 3-to-be and fd 4-to-be sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W3Expect {
    pub channel: FdIdentity,
    pub script: FdIdentity,
}

/// One entry of the frozen child's descriptor table: its number, and the (dev, ino) and mode of the descriptor's
/// target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdEntry {
    pub number: u32,
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
}

/// How a reaped worker ended: `si_code` CLD_EXITED, CLD_KILLED or CLD_DUMPED, with `si_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reaped {
    Exited(i32),
    Killed(i32),
    Dumped(i32),
}
