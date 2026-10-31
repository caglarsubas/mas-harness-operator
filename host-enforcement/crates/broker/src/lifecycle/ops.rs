//! The agent side's seam (the frozen seam note DESIGN-HE005.SEAM-C revision 4, section 3, exactly; MON-SEAM-E1). The
//! traits name broker-sys's opaque descriptors only through associated types: the production implementations
//! (`leaf.rs`, `spawn.rs`, `clock.rs`) set them to broker-sys's types, and a fake sets its own, so no fake constructs a
//! broker-sys descriptor (SM-R1-17). Statically dispatched in non-test code (no `dyn`, C3-1). Each trait has no other
//! item, no default body, and no other implementation outside the test blocks (SM-R2-13).

use std::io;

use broker_sys::{FdEntry, LeafWrite, Reaped, W3Expect};

/// The leaf's three readable control files: `cgroup.type`, `cgroup.events` and `cgroup.procs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafFile { Type, Events, Procs }
/// The frozen child's four process-directory files W3 reads: `status`, `stat`, `cgroup` and `attr/current`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcFile { Status, Stat, Cgroup, AttrCurrent }

pub trait LeafOps {
    /// A bounded read (4 KiB, gate-sys openat::read_bounded) through gate-sys Dir::at(LEAF_PATH) and file_ro.
    fn read(&mut self, file: LeafFile) -> io::Result<Vec<u8>>;
    /// The only leaf writes: broker_sys LeafDir::write.
    fn write(&mut self, what: LeafWrite) -> io::Result<()>;
}

pub trait SpawnOps {
    type Script;
    type ChannelEnd;
    type Plan;
    type Child;
    /// W5: gate-sys Dir::file_ro on workerScriptPath's directory and name, then broker_sys Script::from_file.
    fn open_script(&mut self) -> io::Result<Self::Script>;
    fn measure(&mut self, script: &Self::Script) -> io::Result<(u16, [u8; 32])>;          // broker_sys::measure_verity
    fn channel_pair(&mut self) -> io::Result<(Self::ChannelEnd, Self::ChannelEnd)>;       // (parent end, child end)
    fn plan(&mut self, worker_uid: u32, child_end: Self::ChannelEnd, script: Self::Script)
        -> io::Result<(Self::Plan, W3Expect)>;                                             // broker_sys ChildPlan::new
    fn spawn(&mut self, plan: Self::Plan) -> io::Result<Self::Child>;                      // broker_sys::spawn
    fn child_pid(&self, child: &Self::Child) -> i32;
    fn mask_restored(&self, child: &Self::Child) -> bool;
    /// W3, through the child's process directory, opened by gate-sys Dir::at with the one start-up exception
    /// expression (`proc.rs`), and file_ro; AttrCurrent through sub("attr").file_ro("current"). The child is frozen and
    /// unreaped, and its pidfd is held, so the number cannot be reused.
    fn proc_read(&mut self, child: &Self::Child, file: ProcFile) -> io::Result<Vec<u8>>;
    fn fd_table(&mut self, child: &Self::Child) -> io::Result<Vec<FdEntry>>;              // broker_sys::fd_table
    fn reap(&mut self, child: &Self::Child) -> io::Result<Option<Reaped>>;                 // broker_sys::reap (WNOHANG)
}

pub trait Clock {
    fn now_ms(&self) -> u64;                          // std::time::Instant, from one origin taken at serve's start
    fn sleep_ms(&self, ms: u32) -> io::Result<()>;    // broker_sys::sleep_monotonic
}
