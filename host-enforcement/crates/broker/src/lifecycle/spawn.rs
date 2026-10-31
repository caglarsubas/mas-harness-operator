//! The production `SpawnOps` (the frozen seam note, sections 2-4; DESIGN-HE005 sections 3.2 and 3.5; Linux only): W5's
//! script open and measure, the I03 socketpair, the child plan, clone3, W3's reads, the descriptor table and the reap,
//! each through broker-sys's safe API, gate-sys's `Dir` or `proc.rs`, and nothing else.
//!
//! The one file that embeds the two vendored WORKER programs (DESIGN-HE005 O1 and O7; `contracts/seccomp-v3/`, edge
//! record v11, REGISTERED_BEFORE_USE; delta C3's G-HE5C-9; the plan's G-HE5C-8): each is compiled in once, its length
//! pinned by its array type (187 and 172 instructions of 8 bytes), and both statics are named only in the child plan's
//! parent-side preparation, `ChildPlan::new`'s call in `plan` below, which runs after step 2, so the run's arm past
//! the gate's qualification is what keeps them linked. `RUNNING_ARCH` (seal.rs) selects the one installed. The child
//! path installs it at step 7 of section 3.5.

use std::io;

use broker_sys::{Child, ChildPlan, FdEntry, LeafDir, Reaped, Script, W3Expect};
use gate_sys::Dir;

use crate::lifecycle::ops::{ProcFile, SpawnOps};
use crate::lifecycle::proc;
use crate::seal::{Arch, RUNNING_ARCH};

static WORKER_X86_64: &[u8; 1496] = include_bytes!("../../../../contracts/seccomp-v3/WORKER.x86_64.bpf");
static WORKER_AARCH64: &[u8; 1376] = include_bytes!("../../../../contracts/seccomp-v3/WORKER.aarch64.bpf");

/// The production `SpawnOps`: it borrows serve's `LeafDir` (clone3's CLONE_INTO_CGROUP target) and the signed
/// `workerScriptPath`.
pub struct LinuxSpawn<'a> {
    leaf: &'a LeafDir,
    script: &'a str,
}

impl<'a> LinuxSpawn<'a> {
    pub fn new(leaf: &'a LeafDir, script: &'a str) -> LinuxSpawn<'a> {
        LinuxSpawn { leaf, script }
    }
}

impl SpawnOps for LinuxSpawn<'_> {
    type Script = Script;
    type ChannelEnd = broker_sys::ChannelEnd;
    type Plan = ChildPlan;
    type Child = Child;

    /// W5's open (section 3.2): gate-sys `Dir::at` on the script's directory and `file_ro` on its name (O_RDONLY, never
    /// O_PATH), then `Script::from_file`, which moves that one open file description to a number of 5 or more.
    fn open_script(&mut self) -> io::Result<Script> {
        let (directory, name) = self.script.rsplit_once('/').ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let directory = if directory.is_empty() { "/" } else { directory };
        Script::from_file(Dir::at(directory)?.file_ro(name)?)
    }

    fn measure(&mut self, script: &Script) -> io::Result<(u16, [u8; 32])> {
        broker_sys::measure_verity(script)
    }

    fn channel_pair(&mut self) -> io::Result<(broker_sys::ChannelEnd, broker_sys::ChannelEnd)> {
        broker_sys::seqpacket_pair()
    }

    fn plan(&mut self, worker_uid: u32, child_end: broker_sys::ChannelEnd, script: Script)
        -> io::Result<(ChildPlan, W3Expect)> {
        ChildPlan::new(
            worker_uid,
            match RUNNING_ARCH {
                Arch::X86_64 => WORKER_X86_64.as_slice(),
                Arch::Aarch64 => WORKER_AARCH64.as_slice(),
            },
            child_end,
            script,
        )
    }

    fn spawn(&mut self, plan: ChildPlan) -> io::Result<Child> {
        broker_sys::spawn(self.leaf, plan)
    }

    fn child_pid(&self, child: &Child) -> i32 {
        child.pid
    }

    fn mask_restored(&self, child: &Child) -> bool {
        child.mask_restored
    }

    fn proc_read(&mut self, child: &Child, file: ProcFile) -> io::Result<Vec<u8>> {
        proc::read(child.pid, file)
    }

    fn fd_table(&mut self, child: &Child) -> io::Result<Vec<FdEntry>> {
        broker_sys::fd_table(child.pid)
    }

    fn reap(&mut self, child: &Child) -> io::Result<Option<Reaped>> {
        broker_sys::reap(&child.pidfd)
    }
}
