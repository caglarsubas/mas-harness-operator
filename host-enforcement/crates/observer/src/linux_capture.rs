//! The Linux kernel view of the captures (HE-004D1 DESIGN-D1 sections 3, 4.5 and 17.3; owner decisions Q-HE4D1-4 and -5
//! (a); MODEL_DEFINED R124 and R132): `capture::KernelView` over observer-sys's safe API, after the seal. The only module
//! of crates/observer that names observer-sys (G-D1-6); it re-exports nothing, and no public item names an observer-sys
//! type.
//!
//! [`LinuxCapture::new`] takes `&Sealed`, so the roots (the proc root and the cgroup2 root, each checked by its
//! filesystem magic) exist only after the seal, as `LinuxWire::new` holds the sockets; `serve` calls it once (status 30
//! on failure). It is not inlined, so its symbol survives LTO for the binary's symbol rule (G-D1-14). An error's class
//! is read from its errno (ENOENT not found, ESRCH a vanished process, EPERM and EACCES refused) or from observer-sys's
//! own refusals (a bound or a malformed reply). The verity reply reaches the engine as algorithm 1 and size 32, which
//! observer-sys has already required. The wall clock is read in Unix milliseconds from the realtime clock.

use std::ffi::CString;
use std::io;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use observer_sys::kernel::{self, CgroupDir, CgroupFile, Opened, ProcDir, ProcFile, ProcLink, RelPath, Roots};

use crate::capture::{CgroupItem, Facts, KernelView, LinkItem, ProcItem, ProgramFacts, ReadError, Verity};
use crate::enrolled::SetupError;
use crate::seal::Sealed;

/// ENOENT, ESRCH, EPERM and EACCES on Linux.
const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EPERM: i32 = 1;
const EACCES: i32 = 13;

/// The longest link text a capture reads.
const LINK_BUFFER: usize = 4_096;

/// The captures' Linux kernel view: the two roots, opened after the seal.
pub struct LinuxCapture {
    roots: Roots,
}

impl LinuxCapture {
    /// Opens the roots after the seal (status 30 on failure); not inlined (G-D1-14).
    #[inline(never)]
    pub fn new(_sealed: &Sealed) -> Result<LinuxCapture, SetupError> {
        Roots::open().map(|roots| LinuxCapture { roots }).map_err(|_| SetupError::Roots("a capture root did not open"))
    }
}

fn class(error: io::Error) -> ReadError {
    match error.raw_os_error() {
        Some(ENOENT) => ReadError::NotFound,
        Some(ESRCH) => ReadError::Gone,
        Some(EPERM | EACCES) => ReadError::Denied,
        _ => match error.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => ReadError::Bound,
            _ => ReadError::Other,
        },
    }
}

fn proc_item(item: ProcItem) -> ProcFile {
    match item {
        ProcItem::Stat => ProcFile::Stat,
        ProcItem::Status => ProcFile::Status,
        ProcItem::Cgroup => ProcFile::Cgroup,
        ProcItem::AttrCurrent => ProcFile::AttrCurrent,
        ProcItem::Maps => ProcFile::Maps,
    }
}

fn link_item(item: LinkItem) -> ProcLink {
    match item {
        LinkItem::Exe => ProcLink::Exe,
        LinkItem::NsUser => ProcLink::NsUser,
        LinkItem::NsMnt => ProcLink::NsMnt,
        LinkItem::NsPid => ProcLink::NsPid,
        LinkItem::NsNet => ProcLink::NsNet,
    }
}

fn cgroup_item(item: CgroupItem) -> CgroupFile {
    match item {
        CgroupItem::Procs => CgroupFile::Procs,
        CgroupItem::Events => CgroupFile::Events,
        CgroupItem::Stat => CgroupFile::Stat,
        CgroupItem::MemoryMax => CgroupFile::MemoryMax,
        CgroupItem::PidsMax => CgroupFile::PidsMax,
        CgroupItem::PidsCurrent => CgroupFile::PidsCurrent,
        CgroupItem::CpuMax => CgroupFile::CpuMax,
    }
}

fn path_text(path: &str) -> Result<CString, ReadError> {
    CString::new(path).map_err(|_| ReadError::Bound)
}

impl KernelView for LinuxCapture {
    type Proc = ProcDir;
    type Cgroup = CgroupDir;
    type Held = Opened;

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_millis(&self) -> Option<u64> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
        u64::try_from(elapsed.as_millis()).ok()
    }

    fn observer_pid(&mut self) -> Result<i32, ReadError> {
        self.roots.own_pid().map_err(class)
    }

    fn processes(&mut self) -> Result<Vec<i32>, ReadError> {
        self.roots.processes().map_err(class)
    }

    fn process(&mut self, pid: i32) -> Result<ProcDir, ReadError> {
        self.roots.process(pid).map_err(class)
    }

    fn tasks(&mut self, process: &ProcDir, bound: usize) -> Result<Vec<i32>, ReadError> {
        process.tasks(bound).map_err(class)
    }

    fn task(&mut self, process: &ProcDir, tid: i32) -> Result<ProcDir, ReadError> {
        process.task(tid).map_err(class)
    }

    fn proc_read(&mut self, process: &ProcDir, item: ProcItem, limit: usize) -> Result<Vec<u8>, ReadError> {
        process.read(proc_item(item), limit).map_err(class)
    }

    fn proc_link(&mut self, process: &ProcDir, item: LinkItem) -> Result<String, ReadError> {
        let mut buffer = [0u8; LINK_BUFFER];
        let count = process.link_text(link_item(item), &mut buffer).map_err(class)?;
        let text = buffer.get(..count).ok_or(ReadError::Bound)?;
        String::from_utf8(text.to_vec()).map_err(|_| ReadError::Bound)
    }

    fn exe_identity(&mut self, process: &ProcDir) -> Result<(u64, u64), ReadError> {
        process.target_identity().map_err(class)
    }

    fn cgroup(&mut self, rel: &str) -> Result<CgroupDir, ReadError> {
        let rel = RelPath::new(rel).ok_or(ReadError::Bound)?;
        self.roots.cgroup(&rel).map_err(class)
    }

    fn cgroup_read(&mut self, cgroup: &CgroupDir, item: CgroupItem, limit: usize) -> Result<Vec<u8>, ReadError> {
        cgroup.read(cgroup_item(item), limit).map_err(class)
    }

    fn children(&mut self, cgroup: &CgroupDir) -> Result<Vec<String>, ReadError> {
        cgroup.children().map_err(class)
    }

    fn cgroup_inode(&mut self, cgroup: &CgroupDir) -> Result<u64, ReadError> {
        cgroup.inode().map_err(class)
    }

    fn prog_query(&mut self, cgroup: &CgroupDir, attach: &str, effective: bool) -> Result<(Vec<u32>, u32), ReadError> {
        let number = kernel::attach_type(attach).ok_or(ReadError::Other)?;
        cgroup.prog_query(number, effective).map_err(class)
    }

    fn attach_flags_name(&self, flags: u32) -> Option<&'static str> {
        kernel::attach_flags_name(flags)
    }

    fn program(&mut self, pin: &str) -> Result<ProgramFacts, ReadError> {
        let program = kernel::open_pinned(&path_text(pin)?).map_err(class)?;
        let info = program.info().map_err(class)?;
        Ok(ProgramFacts { id: info.id, kind: info.kind, xlated: info.xlated, map_ids: info.map_ids, ifindex: info.ifindex })
    }

    fn open_enrolled(&mut self, path: &str) -> Result<Opened, ReadError> {
        Opened::open(&path_text(path)?).map_err(class)
    }

    fn facts(&mut self, held: &Opened) -> Result<Facts, ReadError> {
        let facts = held.facts().map_err(class)?;
        Ok(Facts { device: facts.device, inode: facts.inode, uid: facts.uid, gid: facts.gid, nlink: facts.nlink, mode: facts.mode,
                   size: facts.size, ctime: facts.ctime, ctime_nsec: facts.ctime_nsec })
    }

    fn verity(&mut self, held: &Opened) -> Result<Verity, ReadError> {
        let digest = held.verity().map_err(class)?;
        Ok(Verity { algorithm: 1, size: 32, digest })
    }

    fn read_held(&mut self, held: &mut Opened, buffer: &mut [u8]) -> Result<usize, ReadError> {
        loop {
            match held.read(buffer) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(class(error)),
            }
        }
    }

    fn run_fs_type(&mut self, held: &Opened) -> Result<Option<&'static str>, ReadError> {
        held.fs_magic().map(kernel::run_fs_type).map_err(class)
    }
}
