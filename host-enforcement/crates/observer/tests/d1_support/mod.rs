//! Test support for HE-004D1 (DESIGN-D1 section 20): `FakeHost`, a `KernelView` built from a native-profile v5 positive,
//! with its processes, tasks, `status`, `stat`, `attr/current` and `cgroup` text, `exe` and namespace links, `maps`
//! lines (devices through the inverse of `makedev`), cgroup files and children, pins and program facts, query answers
//! (or a scripted error), enrolled files' facts, verity digests and bytes, the seal marker's bytes (the canonical seal
//! content), the process listing with labels, and the observer's own pid. Enrolled files are inodes, so a held
//! descriptor keeps reading the inode it opened when its path is replaced. Every access is logged, and scripted hooks
//! run after each access (a thaw, member and thread changes, exits, replaced files, slow reads). The clock is the
//! fake's own or the HE-004C rig's (`Clock`).
//!
//! The record the fake serves is derived from the positive (D1-9): every `files` and `backendFiles` row gets the sha256
//! of the fake's own bytes (backend rows shrink to small sizes), every program the sha256 of the fake's translated
//! instructions, and the seal marker the digest of the canonical seal content, so the captures the engine takes can
//! equal the positive's captures apart from those digests, the record's `qualificationDigest` and the timing fields.
//! HE-004D2 unit B1 (DESIGN-D2 section 4.4): the positives are native-profile v5's, whose records, profiles and endpoints
//! are v4's and whose captures carry no host, policy or boot field.
#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use i05_protocol::json::{self, Int, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::capture::{CaptureEngine, CgroupItem, Facts, KernelView, LinkItem, ProcItem, ProgramFacts, ReadError,
                                Verity};
use planeon_observer::capture_schema::CaptureSchema;
use planeon_observer::enrolled::{record_form, Enrolled, RecordBytes};
use planeon_observer::kernel_text;

pub const VECTORS: &str = include_str!("../../../../contracts/native-profile-v5/vectors.json");

pub fn vectors() -> Value {
    json::parse(VECTORS).expect("the vectors parse")
}

pub fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

pub fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key).as_array().unwrap_or_else(|| panic!("{key} is not a list"))
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).as_str().unwrap_or_else(|| panic!("{key} is not text"))
}

pub fn int(value: &Value, key: &str) -> i64 {
    field(value, key).as_int().and_then(Int::to_i64).unwrap_or_else(|| panic!("{key} is not an integer"))
}

pub fn uint(value: &Value, key: &str) -> u64 {
    field(value, key).as_int().and_then(Int::to_u64).unwrap_or_else(|| panic!("{key} is not a count"))
}

/// The member at a path of keys and indices, mutably.
pub fn member<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    path.iter().fold(value, |node, key| match node {
        Value::Object(object) => object.get_key_mut(&JStr::new(key)).unwrap_or_else(|| panic!("no member {key}")),
        Value::Array(items) => &mut items[key.parse::<usize>().expect("an index")],
        _ => panic!("not a container at {key}"),
    })
}

pub fn set(value: &mut Value, path: &[&str], new: Value) {
    *member(value, path) = new;
}

/// The value without its timing fields (CONSISTENCY_ONLY: `observedAt` and the three window instants).
pub fn untimed(value: &Value) -> Value {
    let mut value = value.clone();
    if let Value::Object(object) = &mut value {
        for key in ["observedAt", "inspectionStartedMs", "inspectionFinishedMs", "deadlineMs"] {
            object.remove(&JStr::new(key));
        }
    }
    value
}

// ------------------------------------------------------------------------------------------------ clocks

/// The fake's time.
pub trait Clock {
    fn now(&self) -> Instant;
    fn wall_millis(&self) -> Option<u64>;
    fn advance(&self, by: Duration);
}

/// A clock of the fake's own: a monotonic base and a wall reading in Unix milliseconds, stepped by the tests.
pub struct OwnClock {
    pub base: Instant,
    pub elapsed: Cell<Duration>,
    pub wall_base: Cell<u64>,
}

impl OwnClock {
    pub fn at(wall_ms: u64) -> OwnClock {
        OwnClock { base: Instant::now(), elapsed: Cell::new(Duration::ZERO), wall_base: Cell::new(wall_ms) }
    }
}

impl Clock for OwnClock {
    fn now(&self) -> Instant {
        self.base + self.elapsed.get()
    }

    fn wall_millis(&self) -> Option<u64> {
        Some(self.wall_base.get() + self.elapsed.get().as_millis() as u64)
    }

    fn advance(&self, by: Duration) {
        self.elapsed.set(self.elapsed.get() + by);
    }
}

// ------------------------------------------------------------------------------------------------ the fake state

/// One access of the fake, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    OwnPid,
    Processes,
    Process(i32),
    Tasks(i32),
    Task(i32, i32),
    ProcRead(i32, Option<i32>, ProcItem),
    ProcLink(i32, LinkItem),
    ExeIdentity(i32),
    Cgroup(String),
    CgroupRead(String, CgroupItem),
    Children(String),
    CgroupInode(String),
    Query(String, String, bool),
    Program(String),
    Open(String),
    Facts(String),
    Verity(String),
    Read(String, usize),
    FsType(String),
}

impl Access {
    /// Whether the access reads an enrolled file's content (a hashing read).
    pub fn is_hash_read(&self) -> bool {
        matches!(self, Access::Read(..))
    }
}

#[derive(Clone, Debug)]
pub struct FakeThread {
    pub start: u64,
    pub status: String,
    pub label: String,
}

#[derive(Clone, Debug)]
pub struct FakeProc {
    pub generation: u64,
    pub ppid: i32,
    pub start: u64,
    pub status: String,
    pub label: String,
    pub cgroup: String,
    pub maps: String,
    pub exe: String,
    pub identity: (u64, u64),
    pub namespaces: BTreeMap<&'static str, u64>,
    pub threads: BTreeMap<i32, FakeThread>,
    /// Reads of this process refused (EACCES).
    pub denied: bool,
}

#[derive(Clone, Debug)]
pub struct FakeCgroup {
    pub procs: Vec<i32>,
    pub populated: u64,
    pub frozen: u64,
    pub descendants: u64,
    pub memory_max: String,
    pub pids_max: String,
    pub pids_current: String,
    pub cpu_max: String,
    pub children: Vec<String>,
    pub inode: u64,
    pub queries: BTreeMap<(String, bool), Result<(Vec<u32>, u32), ReadError>>,
}

impl FakeCgroup {
    pub fn empty(inode: u64) -> FakeCgroup {
        FakeCgroup { procs: Vec::new(), populated: 0, frozen: 0, descendants: 0, memory_max: "268435456".into(),
                     pids_max: "16".into(), pids_current: "0".into(), cpu_max: "100000 100000".into(), children: Vec::new(), inode,
                     queries: BTreeMap::new() }
    }
}

#[derive(Clone, Debug)]
pub struct FakeFile {
    pub facts: Facts,
    pub verity: Verity,
    pub bytes: Vec<u8>,
    pub fs_type: Option<&'static str>,
}

/// A scripted hook: runs after each access, with the access and the state.
pub type Hook = Box<dyn FnMut(&Access, &mut HostState)>;

pub struct HostState {
    pub procs: BTreeMap<i32, FakeProc>,
    pub cgroups: BTreeMap<String, FakeCgroup>,
    pub pins: BTreeMap<String, ProgramFacts>,
    /// Enrolled files by inode, and each path's inode.
    pub inodes: BTreeMap<u64, FakeFile>,
    pub paths: BTreeMap<String, u64>,
    pub own_pid: i32,
    /// An error the process listing answers with, and synthetic listing entries past the fake's processes.
    pub listing_error: Option<ReadError>,
    pub extra_processes: usize,
    pub log: Vec<Access>,
    pub hooks: Vec<Hook>,
    /// Time each access takes (slow reads).
    pub delay: Option<Box<dyn FnMut(&Access) -> Duration>>,
    pub clock: Rc<dyn Clock>,
    pub next_generation: u64,
    /// Accesses that answer with an error (a scripted refusal).
    pub refuse: Vec<(Access, ReadError)>,
    /// The `frozen` value every `cgroup.events` answers with, computed at the read (a scripted freeze over time).
    pub frozen_when: Option<Box<dyn Fn() -> u64>>,
}

/// The fake kernel view; its state is shared with the test.
#[derive(Clone)]
pub struct FakeHost(pub Rc<RefCell<HostState>>);

/// A held process (or thread) directory: its pid, thread and the process generation it was opened on.
#[derive(Clone, Debug)]
pub struct HeldProc {
    pub pid: i32,
    pub tid: Option<i32>,
    pub generation: u64,
}

/// An opened enrolled file: its path, the inode it opened and its read offset.
#[derive(Clone, Debug)]
pub struct HeldFile {
    pub path: String,
    pub inode: u64,
    pub offset: usize,
}

impl FakeHost {
    pub fn state(&self) -> std::cell::RefMut<'_, HostState> {
        self.0.borrow_mut()
    }

    pub fn log(&self) -> Vec<Access> {
        self.0.borrow().log.clone()
    }

    pub fn clear_log(&self) {
        self.0.borrow_mut().log.clear();
    }

    pub fn hook(&self, hook: impl FnMut(&Access, &mut HostState) + 'static) {
        self.0.borrow_mut().hooks.push(Box::new(hook));
    }

    pub fn clock(&self) -> Rc<dyn Clock> {
        self.0.borrow().clock.clone()
    }

    /// Logs an access, lets it take its scripted time, and answers a scripted refusal.
    fn touch(&self, access: &Access) -> Result<(), ReadError> {
        let mut state = self.0.borrow_mut();
        state.log.push(access.clone());
        if let Some(mut delay) = state.delay.take() {
            let by = delay(access);
            state.delay = Some(delay);
            state.clock.advance(by);
        }
        match state.refuse.iter().find(|(refused, _)| refused == access) {
            Some((_, error)) => Err(*error),
            None => Ok(()),
        }
    }

    /// Runs the hooks after an access's answer is taken (a change scripted "right after" a read).
    fn after<T>(&self, access: &Access, answer: T) -> T {
        let mut state = self.0.borrow_mut();
        let mut hooks = std::mem::take(&mut state.hooks);
        for hook in hooks.iter_mut() {
            hook(access, &mut state);
        }
        hooks.append(&mut state.hooks);
        state.hooks = hooks;
        answer
    }

    /// Replaces the file at `path` with a new inode holding `bytes` (the old inode's ctime moves and its link count
    /// drops, as an unlink does); the new inode.
    pub fn replace(&self, path: &str, bytes: Vec<u8>) -> u64 {
        let mut state = self.0.borrow_mut();
        let old = *state.paths.get(path).expect("an enrolled path");
        let mut file = state.inodes.get(&old).expect("an inode").clone();
        if let Some(previous) = state.inodes.get_mut(&old) {
            previous.facts.ctime += 1;
            previous.facts.nlink = 0;
        }
        let inode = state.inodes.keys().max().copied().unwrap_or(0) + 1;
        file.facts.inode = inode;
        file.facts.size = bytes.len() as u64;
        file.bytes = bytes;
        state.inodes.insert(inode, file);
        state.paths.insert(path.to_string(), inode);
        inode
    }

    /// The inode at `path`, mutably.
    pub fn inode<R>(&self, path: &str, change: impl FnOnce(&mut FakeFile) -> R) -> R {
        let mut state = self.0.borrow_mut();
        let inode = *state.paths.get(path).expect("an enrolled path");
        change(state.inodes.get_mut(&inode).expect("an inode"))
    }

    fn proc_of(&self, held: &HeldProc) -> Result<FakeProc, ReadError> {
        let state = self.0.borrow();
        let process = state.procs.get(&held.pid).filter(|process| process.generation == held.generation).ok_or(ReadError::Gone)?;
        if process.denied {
            return Err(ReadError::Denied);
        }
        Ok(process.clone())
    }
}

impl KernelView for FakeHost {
    type Proc = HeldProc;
    type Cgroup = String;
    type Held = HeldFile;

    fn now(&self) -> Instant {
        self.0.borrow().clock.now()
    }

    fn wall_millis(&self) -> Option<u64> {
        self.0.borrow().clock.wall_millis()
    }

    fn observer_pid(&mut self) -> Result<i32, ReadError> {
        let access = Access::OwnPid;
        self.touch(&access)?;
        let answer = (|| -> Result<i32, ReadError> {
            Ok(self.0.borrow().own_pid)
        })();
        self.after(&access, answer)
    }

    fn processes(&mut self) -> Result<Vec<i32>, ReadError> {
        let access = Access::Processes;
        self.touch(&access)?;
        let answer = (|| -> Result<Vec<i32>, ReadError> {
            let state = self.0.borrow();
            if let Some(error) = state.listing_error {
                return Err(error);
            }
            let mut pids: Vec<i32> = state.procs.keys().copied().collect();
            pids.extend((0..state.extra_processes).map(|index| 1_000_000 + index as i32));
            if pids.len() > 65_536 {
                return Err(ReadError::Bound);
            }
            Ok(pids)
        })();
        self.after(&access, answer)
    }

    fn process(&mut self, pid: i32) -> Result<HeldProc, ReadError> {
        let access = Access::Process(pid);
        self.touch(&access)?;
        let answer = (|| -> Result<HeldProc, ReadError> {
            let state = self.0.borrow();
            let process = state.procs.get(&pid).ok_or(ReadError::NotFound)?;
            Ok(HeldProc { pid, tid: None, generation: process.generation })
        })();
        self.after(&access, answer)
    }

    fn tasks(&mut self, process: &HeldProc, bound: usize) -> Result<Vec<i32>, ReadError> {
        let access = Access::Tasks(process.pid);
        self.touch(&access)?;
        let answer = (|| -> Result<Vec<i32>, ReadError> {
            let found = self.proc_of(process)?;
            if found.threads.len() > bound {
                return Err(ReadError::Bound);
            }
            Ok(found.threads.keys().copied().collect())
        })();
        self.after(&access, answer)
    }

    fn task(&mut self, process: &HeldProc, tid: i32) -> Result<HeldProc, ReadError> {
        let access = Access::Task(process.pid, tid);
        self.touch(&access)?;
        let answer = (|| -> Result<HeldProc, ReadError> {
            let found = self.proc_of(process)?;
            found.threads.get(&tid).ok_or(ReadError::NotFound)?;
            Ok(HeldProc { pid: process.pid, tid: Some(tid), generation: process.generation })
        })();
        self.after(&access, answer)
    }

    fn proc_read(&mut self, process: &HeldProc, item: ProcItem, _limit: usize) -> Result<Vec<u8>, ReadError> {
        let access = Access::ProcRead(process.pid, process.tid, item);
        self.touch(&access)?;
        let answer = (|| -> Result<Vec<u8>, ReadError> {
            let found = self.proc_of(process)?;
            let (start, status, label) = match process.tid {
                None => (found.start, found.status.clone(), found.label.clone()),
                Some(tid) => {
                    let thread = found.threads.get(&tid).ok_or(ReadError::Gone)?;
                    (thread.start, thread.status.clone(), thread.label.clone())
                }
            };
            let id = process.tid.unwrap_or(process.pid);
            Ok(match item {
                ProcItem::Stat => stat_text(id, found.ppid, start).into_bytes(),
                ProcItem::Status => status.into_bytes(),
                ProcItem::Cgroup => found.cgroup.clone().into_bytes(),
                ProcItem::AttrCurrent => format!("{label}\0").into_bytes(),
                ProcItem::Maps => found.maps.clone().into_bytes(),
            })
        })();
        self.after(&access, answer)
    }

    fn proc_link(&mut self, process: &HeldProc, item: LinkItem) -> Result<String, ReadError> {
        let access = Access::ProcLink(process.pid, item);
        self.touch(&access)?;
        let answer = (|| -> Result<String, ReadError> {
            let found = self.proc_of(process)?;
            let namespace = |kind: &'static str| format!("{kind}:[{}]", found.namespaces.get(kind).copied().unwrap_or(0));
            Ok(match item {
                LinkItem::Exe => found.exe.clone(),
                LinkItem::NsUser => namespace("user"),
                LinkItem::NsMnt => namespace("mnt"),
                LinkItem::NsPid => namespace("pid"),
                LinkItem::NsNet => namespace("net"),
            })
        })();
        self.after(&access, answer)
    }

    fn exe_identity(&mut self, process: &HeldProc) -> Result<(u64, u64), ReadError> {
        let access = Access::ExeIdentity(process.pid);
        self.touch(&access)?;
        let answer = (|| -> Result<(u64, u64), ReadError> {
            Ok(self.proc_of(process)?.identity)
        })();
        self.after(&access, answer)
    }

    fn cgroup(&mut self, rel: &str) -> Result<String, ReadError> {
        let access = Access::Cgroup(rel.to_string());
        self.touch(&access)?;
        let answer = (|| -> Result<String, ReadError> {
            if !self.0.borrow().cgroups.contains_key(rel) {
                return Err(ReadError::NotFound);
            }
            Ok(rel.to_string())
        })();
        self.after(&access, answer)
    }

    fn cgroup_read(&mut self, cgroup: &String, item: CgroupItem, _limit: usize) -> Result<Vec<u8>, ReadError> {
        let access = Access::CgroupRead(cgroup.clone(), item);
        self.touch(&access)?;
        let answer = (|| -> Result<Vec<u8>, ReadError> {
            let state = self.0.borrow();
            let found = state.cgroups.get(cgroup).ok_or(ReadError::Gone)?;
            Ok(match item {
                CgroupItem::Procs => found.procs.iter().map(|pid| format!("{pid}\n")).collect::<String>(),
                CgroupItem::Events => {
                    let frozen = state.frozen_when.as_ref().map_or(found.frozen, |frozen| frozen());
                    format!("populated {}\nfrozen {}\n", found.populated, frozen)
                }
                CgroupItem::Stat => format!("nr_descendants {}\nnr_dying_descendants 0\n", found.descendants),
                CgroupItem::MemoryMax => format!("{}\n", found.memory_max),
                CgroupItem::PidsMax => format!("{}\n", found.pids_max),
                CgroupItem::PidsCurrent => format!("{}\n", found.pids_current),
                CgroupItem::CpuMax => format!("{}\n", found.cpu_max),
            }
            .into_bytes())
        })();
        self.after(&access, answer)
    }

    fn children(&mut self, cgroup: &String) -> Result<Vec<String>, ReadError> {
        let access = Access::Children(cgroup.clone());
        self.touch(&access)?;
        let answer = (|| -> Result<Vec<String>, ReadError> {
            let state = self.0.borrow();
            let found = state.cgroups.get(cgroup).ok_or(ReadError::Gone)?;
            if found.children.len() > 64 {
                return Err(ReadError::Bound);
            }
            Ok(found.children.clone())
        })();
        self.after(&access, answer)
    }

    fn cgroup_inode(&mut self, cgroup: &String) -> Result<u64, ReadError> {
        let access = Access::CgroupInode(cgroup.clone());
        self.touch(&access)?;
        let answer = (|| -> Result<u64, ReadError> {
            Ok(self.0.borrow().cgroups.get(cgroup).ok_or(ReadError::Gone)?.inode)
        })();
        self.after(&access, answer)
    }

    fn prog_query(&mut self, cgroup: &String, attach: &str, effective: bool) -> Result<(Vec<u32>, u32), ReadError> {
        let access = Access::Query(cgroup.clone(), attach.to_string(), effective);
        self.touch(&access)?;
        let answer = (|| -> Result<(Vec<u32>, u32), ReadError> {
            let state = self.0.borrow();
            let found = state.cgroups.get(cgroup).ok_or(ReadError::Gone)?;
            found.queries.get(&(attach.to_string(), effective)).cloned().unwrap_or(Ok((Vec::new(), 0)))
        })();
        self.after(&access, answer)
    }

    fn attach_flags_name(&self, flags: u32) -> Option<&'static str> {
        match flags {
            1 => Some("BPF_F_ALLOW_OVERRIDE"),
            2 => Some("BPF_F_ALLOW_MULTI"),
            _ => None,
        }
    }

    fn program(&mut self, pin: &str) -> Result<ProgramFacts, ReadError> {
        let access = Access::Program(pin.to_string());
        self.touch(&access)?;
        let answer = (|| -> Result<ProgramFacts, ReadError> {
            self.0.borrow().pins.get(pin).cloned().ok_or(ReadError::NotFound)
        })();
        self.after(&access, answer)
    }

    fn open_enrolled(&mut self, path: &str) -> Result<HeldFile, ReadError> {
        let access = Access::Open(path.to_string());
        self.touch(&access)?;
        let answer = (|| -> Result<HeldFile, ReadError> {
            let inode = *self.0.borrow().paths.get(path).ok_or(ReadError::NotFound)?;
            Ok(HeldFile { path: path.to_string(), inode, offset: 0 })
        })();
        self.after(&access, answer)
    }

    fn facts(&mut self, held: &HeldFile) -> Result<Facts, ReadError> {
        let access = Access::Facts(held.path.clone());
        self.touch(&access)?;
        let answer = (|| -> Result<Facts, ReadError> {
            Ok(self.0.borrow().inodes.get(&held.inode).ok_or(ReadError::Gone)?.facts)
        })();
        self.after(&access, answer)
    }

    fn verity(&mut self, held: &HeldFile) -> Result<Verity, ReadError> {
        let access = Access::Verity(held.path.clone());
        self.touch(&access)?;
        let answer = (|| -> Result<Verity, ReadError> {
            Ok(self.0.borrow().inodes.get(&held.inode).ok_or(ReadError::Gone)?.verity)
        })();
        self.after(&access, answer)
    }

    fn read_held(&mut self, held: &mut HeldFile, buffer: &mut [u8]) -> Result<usize, ReadError> {
        let count = {
            let state = self.0.borrow();
            let found = state.inodes.get(&held.inode).ok_or(ReadError::Gone)?;
            let rest = found.bytes.get(held.offset..).unwrap_or_default();
            let count = rest.len().min(buffer.len());
            buffer[..count].copy_from_slice(&rest[..count]);
            count
        };
        held.offset += count;
        let access = Access::Read(held.path.clone(), count);
        self.touch(&access)?;
        self.after(&access, Ok(count))
    }

    fn run_fs_type(&mut self, held: &HeldFile) -> Result<Option<&'static str>, ReadError> {
        let access = Access::FsType(held.path.clone());
        self.touch(&access)?;
        let answer = (|| -> Result<Option<&'static str>, ReadError> {
            Ok(self.0.borrow().inodes.get(&held.inode).ok_or(ReadError::Gone)?.fs_type)
        })();
        self.after(&access, answer)
    }
}

// ------------------------------------------------------------------------------------------------ kernel text

/// A `stat` line: `pid (comm) S ppid ...` with the start time as field 22.
pub fn stat_text(pid: i32, ppid: i32, start: u64) -> String {
    format!("{pid} (comm (x) y) S {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 {start} 100000 200 18446744073709551615\n")
}

/// A capability mask of names.
pub fn mask(names: &[Value]) -> u64 {
    names.iter().map(|name| {
        let name = name.as_str().expect("a capability name");
        let bit = kernel_text::CAPABILITY_NAMES.iter().position(|known| *known == name).expect("a known capability");
        1u64 << bit
    }).fold(0, |all, bit| all | bit)
}

/// A `status` text.
pub fn status_text(uid: u64, gid: u64, no_new_privs: u64, seccomp: u64, filters: u64, threads: u64, caps: [u64; 5]) -> String {
    format!("Name:\tcomm\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nThreads:\t{threads}\n\
             CapInh:\t{:016x}\nCapPrm:\t{:016x}\nCapEff:\t{:016x}\nCapBnd:\t{:016x}\nCapAmb:\t{:016x}\nNoNewPrivs:\t{no_new_privs}\n\
             Seccomp:\t{seccomp}\nSeccomp_filters:\t{filters}\n", caps[0], caps[1], caps[2], caps[3], caps[4])
}

/// A `maps` text of mappings, each `[path, offset, length, permissions, device, inode]`, with a `[vdso]` line.
pub fn maps_text(mappings: &[Value]) -> String {
    let mut out = String::new();
    let mut start = 0x5500_0000_0000u64;
    for mapping in mappings {
        let length = uint(mapping, "length");
        let (major, minor) = kernel_text::device_parts(uint(mapping, "device"));
        out.push_str(&format!("{start:x}-{:x} {} {:08x} {major:x}:{minor:x} {}                    {}\n", start + length,
                              text(mapping, "permissions"), uint(mapping, "offset"), uint(mapping, "inode"), text(mapping, "path")));
        start += length + 0x1000;
    }
    out.push_str("7ffc0000e000-7ffc00010000 r-xp 00000000 00:00 0                          [vdso]\n");
    out
}

/// The fake's translated program: four instructions, no call (mov r0, 0 three times; exit).
pub fn xlated() -> Vec<u8> {
    let mov = [0xb7u8, 0, 0, 0, 0, 0, 0, 0];
    let exit = [0x95u8, 0, 0, 0, 0, 0, 0, 0];
    [mov, mov, mov, exit].concat()
}

/// Deterministic bytes of one enrolled file.
pub fn content(path: &str, size: usize) -> Vec<u8> {
    let seed = sha256::digest(path.as_bytes());
    (0..size).map(|index| seed[index % 32] ^ (index / 32) as u8).collect()
}

fn value_of(text: &str) -> Value {
    Value::str(text)
}

// ------------------------------------------------------------------------------------------------ from a positive

/// A positive, its derived record and the captures the engine should take (apart from the timing fields).
pub struct Derived {
    pub record: Value,
    pub pin: String,
    /// The five role captures (ROLES order), the lifecycle capture and the backend captures (sorted by component).
    pub roles: Vec<Value>,
    pub lifecycle: Value,
    pub backends: Vec<Value>,
}

/// The positive's record with the fake's digests (see the module documentation), and the expected captures.
pub fn derive(positive: &Value) -> Derived {
    derive_scoped(positive, None)
}

/// [`derive`] with the record's window moved to (`validFrom`, `expiresAt`) when given.
pub fn derive_scoped(positive: &Value, window: Option<(&str, &str)>) -> Derived {
    let mut record = field(positive, "record").clone();
    if let Some((valid_from, expires_at)) = window {
        set(&mut record, &["scope", "validFrom"], value_of(valid_from));
        set(&mut record, &["scope", "expiresAt"], value_of(expires_at));
    }
    let xlated_digest = sha256::prefixed(&xlated());
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for index in 0..list(&record, "files").len() {
        let row = &list(&record, "files")[index];
        let (path, size) = (text(row, "path").to_string(), uint(row, "size") as usize);
        let digest = sha256::prefixed(&content(&path, size));
        set(&mut record, &["files", &index.to_string(), "sha256"], value_of(&digest));
        files.insert(path, digest);
    }
    let mut backend_files: BTreeMap<String, (String, u64)> = BTreeMap::new();
    for index in 0..list(&record, "backendFiles").len() {
        let path = text(&list(&record, "backendFiles")[index], "path").to_string();
        let size = 4_096 + index as u64;
        let digest = sha256::prefixed(&content(&path, size as usize));
        set(&mut record, &["backendFiles", &index.to_string(), "size"], Value::Int(Int::from_u64(size)));
        set(&mut record, &["backendFiles", &index.to_string(), "sha256"], value_of(&digest));
        backend_files.insert(path, (digest, size));
    }
    for role in ["SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE"] {
        for hook in ["INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT", "UDP4_SENDMSG", "UDP6_SENDMSG"] {
            set(&mut record, &["roles", role, "bpfPrograms", hook, "translatedSha256"], value_of(&xlated_digest));
        }
    }
    let seal = seal_content(&record);
    set(&mut record, &["hardening", "sealMarker", "digest"], value_of(&sha256::prefixed(&seal)));
    let pin = sha256::prefixed(&json::canonical(&record).expect("canonical"));
    let rebind = |capture: &Value| {
        let mut capture = untimed(capture);
        set(&mut capture, &["qualificationDigest"], value_of(&pin));
        capture
    };
    let mut roles = Vec::new();
    for capture in list(positive, "captures") {
        let mut capture = rebind(capture);
        for index in 0..list(&capture, "files").len() {
            let path = text(field(&list(&capture, "files")[index], "entry"), "path").to_string();
            let digest = files.get(&path).expect("a files row").clone();
            set(&mut capture, &["files", &index.to_string(), "entry", "sha256"], value_of(&digest));
            set(&mut capture, &["files", &index.to_string(), "contentDigest"], value_of(&digest));
        }
        for hook in ["INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT", "UDP4_SENDMSG", "UDP6_SENDMSG"] {
            set(&mut capture, &["bpfPrograms", hook, "program", "translatedSha256"], value_of(&xlated_digest));
        }
        roles.push(capture);
    }
    let order = ["SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE"];
    roles.sort_by_key(|capture| order.iter().position(|role| *role == text(capture, "role")));
    let mut lifecycle = rebind(field(positive, "lifecycle"));
    set(&mut lifecycle, &["sealMarker", "digest"], value_of(&sha256::prefixed(&seal)));
    let mut backends: Vec<Value> = list(positive, "backendCaptures").iter().map(|capture| {
        let mut capture = rebind(capture);
        let path = text(field(&capture, "executable"), "path").to_string();
        set(&mut capture, &["executable", "contentDigest"], value_of(&backend_files.get(&path).expect("a backend row").0));
        capture
    }).collect();
    backends.sort_by(|left, right| text(left, "component").cmp(text(right, "component")));
    Derived { record, pin, roles, lifecycle, backends }
}

/// The canonical seal content of a record (the model's `expected_seal_digest` input).
pub fn seal_content(record: &Value) -> Vec<u8> {
    let mut programs: Vec<(String, String, i64, String)> = Vec::new();
    for role in ["SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE"] {
        for hook in ["INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT", "UDP4_SENDMSG", "UDP6_SENDMSG"] {
            let program = field(field(field(field(record, "roles"), role), "bpfPrograms"), hook);
            programs.push((role.to_string(), hook.to_string(), int(program, "programId"), text(program, "translatedSha256").to_string()));
        }
    }
    programs.sort();
    let rows: Vec<Value> = programs.into_iter().map(|(role, hook, id, digest)| {
        Value::Array(vec![Value::str(&role), Value::str(&hook), Value::int(id), Value::str(&digest)])
    }).collect();
    let mut content = Object::new();
    content.insert(JStr::new("schemaVersion"), Value::str("planeon.internal.containment-seal/v1"));
    content.insert(JStr::new("bootId"), field(field(record, "host"), "bootId").clone());
    content.insert(JStr::new("policyDigest"), field(field(record, "selinux"), "policyDigest").clone());
    content.insert(JStr::new("containmentArtifactDigest"),
                   field(field(field(record, "lifecycleSubjects"), "HOST_CONTAINMENT"), "artifactDigest").clone());
    content.insert(JStr::new("programs"), Value::Array(rows));
    json::canonical(&Value::Object(content)).expect("canonical")
}

/// The enrolled record of a derived record (now: its `validFrom`).
pub fn enroll(record: &Value) -> Enrolled {
    let bytes = json::canonical(record).expect("canonical");
    let value = record_form(&bytes).expect("canonical form");
    let pin = sha256::prefixed(&bytes);
    let (_, record_schema) = CaptureSchema::embedded().expect("schema");
    let now = kernel_text::utc_seconds(text(field(record, "scope"), "validFrom"));
    Enrolled::new(RecordBytes { bytes, value, pin }, &record_schema, now).expect("the derived record enrolls")
}

fn octal(mode: &str) -> u32 {
    u32::from_str_radix(mode, 8).expect("an octal mode")
}

fn verity_of(text: &str) -> Verity {
    let hex = text.strip_prefix("sha256:").expect("a digest");
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
    }
    Verity { algorithm: 1, size: 32, digest }
}

/// A fixed ctime of every fake file.
pub const CTIME: i64 = 1_788_000_000;

/// The fake host serving a derived positive, with the clock at `validFrom` + 1 s (or the given clock).
pub fn host(positive: &Value, derived: &Derived, enrolled: &Enrolled, clock: Option<Rc<dyn Clock>>) -> FakeHost {
    let valid_from = enrolled.valid_from * 1_000;
    let clock: Rc<dyn Clock> = clock.unwrap_or_else(|| Rc::new(OwnClock::at(valid_from + 1_000)));
    let mut state = HostState {
        procs: BTreeMap::new(), cgroups: BTreeMap::new(), pins: BTreeMap::new(), inodes: BTreeMap::new(), paths: BTreeMap::new(),
        own_pid: 0, listing_error: None, extra_processes: 0, log: Vec::new(), hooks: Vec::new(), delay: None, clock,
        next_generation: 1, refuse: Vec::new(), frozen_when: None,
    };
    let record = &derived.record;
    // Enrolled files: the role files from the captures' observations, the backend executables, the seal marker.
    for capture in &derived.roles {
        for item in list(capture, "files") {
            let entry = field(item, "entry");
            let path = text(entry, "path").to_string();
            let size = uint(entry, "size");
            let facts = Facts { device: uint(item, "device"), inode: uint(item, "inode"), uid: uint(item, "uid") as u32,
                                gid: uint(item, "gid") as u32, nlink: uint(item, "nlink"), mode: octal(text(entry, "mode")),
                                size, ctime: CTIME, ctime_nsec: 0 };
            state.paths.insert(path.clone(), facts.inode);
            state.inodes.insert(facts.inode, FakeFile { facts, verity: verity_of(text(item, "measuredVerity")),
                                                        bytes: content(&path, size as usize), fs_type: None });
        }
    }
    for (index, row) in list(record, "backendFiles").iter().enumerate() {
        let path = text(row, "path").to_string();
        let size = uint(row, "size");
        let inode = 9_000 + index as u64;
        let facts = Facts { device: 77, inode, uid: 0, gid: 0, nlink: 1, mode: 0o555, size, ctime: CTIME, ctime_nsec: 0 };
        state.paths.insert(path.clone(), inode);
        state.inodes.insert(inode, FakeFile { facts, verity: verity_of(text(row, "verityDigest")), bytes: content(&path, size as usize),
                                              fs_type: None });
    }
    let marker = field(field(record, "hardening"), "sealMarker");
    let seal = seal_content(record);
    let marker_facts = Facts { device: 50, inode: 8_000, uid: uint(marker, "uid") as u32, gid: 0, nlink: 1,
                               mode: octal(text(marker, "mode")), size: seal.len() as u64, ctime: CTIME, ctime_nsec: 0 };
    state.paths.insert(text(marker, "path").to_string(), 8_000);
    state.inodes.insert(8_000, FakeFile { facts: marker_facts, verity: Verity { algorithm: 1, size: 32, digest: [0; 32] }, bytes: seal,
                                          fs_type: Some("tmpfs") });
    // The roles.
    for (index, capture) in derived.roles.iter().enumerate() {
        let target = &enrolled.roles[index];
        let rel = target.cgroup_rel.clone();
        let process = field(capture, "process");
        let cgroup = field(process, "cgroup");
        let mut fake = FakeCgroup::empty(uint(cgroup, "inode"));
        fake.populated = 1;
        fake.descendants = uint(capture, "descendantCount");
        fake.memory_max = uint(cgroup, "memoryMaxBytes").to_string();
        fake.pids_max = uint(cgroup, "pidsMax").to_string();
        fake.pids_current = uint(capture, "pidsCurrent").to_string();
        fake.cpu_max = format!("{} {}", uint(cgroup, "cpuQuotaMicros"), uint(cgroup, "cpuPeriodMicros"));
        fake.children = list(capture, "childCgroups").iter().map(|child| child.as_str().expect("a name").to_string()).collect();
        if target.role == "WORKER" {
            fake.frozen = uint(capture, "cgroupFrozenBefore");
        }
        for (hook, pin) in &target.pins {
            let observed = field(field(capture, "bpfPrograms"), hook);
            let program = field(observed, "program");
            let ids = |key: &str| list(observed, key).iter().map(|id| id.as_int().and_then(Int::to_u64).expect("an id") as u32).collect::<Vec<_>>();
            let attach = format!("BPF_CGROUP_{hook}");
            fake.queries.insert((attach.clone(), false), Ok((ids("localIds"), 2)));
            fake.queries.insert((attach, true), Ok((ids("effectiveIds"), 0)));
            state.pins.insert(pin.clone(), ProgramFacts { id: uint(program, "programId") as u32, kind: uint(program, "programType") as u32,
                                                          xlated: xlated(), map_ids: Vec::new(), ifindex: 0 });
        }
        for (name, ids) in field(capture, "effectiveCensus").as_object().expect("census").iter() {
            let ids: Vec<u32> = ids.as_array().expect("ids").iter().map(|id| id.as_int().and_then(Int::to_u64).expect("an id") as u32).collect();
            fake.queries.insert((name.as_str().expect("a name").to_string(), true), Ok((ids, 0)));
        }
        let members = list(capture, "cgroupMembers");
        fake.procs = members.iter().map(|member| int(member, "pid") as i32).collect();
        if target.role == "OBSERVER" {
            state.own_pid = int(&members[0], "pid") as i32;
            let generation = state.next_generation;
            state.next_generation += 1;
            state.procs.insert(state.own_pid, FakeProc {
                generation, ppid: 1, start: 4_242, status: status_text(0, 0, 1, 2, 1, 1, [0; 5]),
                label: text(field(field(record, "roles"), "OBSERVER"), "processLabel").to_string(), cgroup: format!("0::/{rel}\n"),
                maps: String::new(), exe: String::new(), identity: (0, 0), namespaces: BTreeMap::new(), threads: BTreeMap::new(),
                denied: false,
            });
        } else {
            let caps = [mask(list(process, "capInheritable")), mask(list(process, "capPermitted")), mask(list(process, "capEffective")),
                        mask(list(process, "capBounding")), mask(list(process, "capAmbient"))];
            let sets: BTreeMap<i64, &Value> = list(capture, "memberSetBefore").iter().map(|row| (int(row, "pid"), row)).collect();
            for member in members {
                let pid = int(member, "pid");
                let me = pid == int(process, "pid");
                let gid = uint(process, "gid");
                let status = status_text(uint(member, "uid"), gid, uint(member, "noNewPrivs"), uint(member, "seccompMode"),
                                         uint(member, "seccompFilters"), uint(member, "threadCount"), caps);
                let label = text(member, "processLabel").to_string();
                let threads = list(sets.get(&pid).expect("a member set row"), "threads").iter().map(|thread| {
                    (int(thread, "tid") as i32, FakeThread { start: uint(thread, "startTicks"), status: status.clone(), label: label.clone() })
                }).collect();
                let (exe, identity) = match member.get("exe") {
                    Some(exe) => (text(exe, "path").to_string(), (uint(exe, "device"), uint(exe, "inode"))),
                    None => ("/opt/planeon/bin/not-read".to_string(), (1, 1)),
                };
                let namespaces = if me { process.get("namespaceInodes").and_then(Value::as_object).map(|inodes| {
                    inodes.iter().map(|(kind, inode)| {
                        let kind: &'static str = match kind.as_str() { Some("user") => "user", Some("mnt") => "mnt", Some("pid") => "pid", _ => "net" };
                        (kind, inode.as_int().and_then(Int::to_u64).expect("an inode"))
                    }).collect()
                }).unwrap_or_default() } else { BTreeMap::new() };
                let maps = if me { capture.get("executableMaps").and_then(Value::as_array).map(maps_text).unwrap_or_default() } else { String::new() };
                let generation = state.next_generation;
                state.next_generation += 1;
                state.procs.insert(pid as i32, FakeProc {
                    generation, ppid: int(member, "ppid") as i32, start: uint(member, "startTicks"), status, label,
                    cgroup: format!("0::/{rel}\n"), maps, exe, identity, namespaces, threads, denied: false,
                });
            }
        }
        if target.role == "BROKER" {
            let parent = rel.rsplit_once('/').expect("a service").0.to_string();
            let mut service = FakeCgroup::empty(600);
            service.populated = 1;
            service.children = list(capture, "delegatedChildren").iter().map(|child| child.as_str().expect("a name").to_string()).collect();
            state.cgroups.insert(parent, service);
        }
        state.cgroups.insert(rel, fake);
    }
    // The lifecycle: the slice census, the containment cgroup and the slice root.
    let lifecycle = &derived.lifecycle;
    let census: Vec<(String, u64)> = list(lifecycle, "sliceCgroups").iter().map(|row| {
        let path = text(row, "path");
        let rel = path.splitn(5, '/').nth(4).expect("a cgroup path").to_string();
        (rel, uint(row, "populated"))
    }).collect();
    for (rel, populated) in &census {
        let children: Vec<String> = census.iter().filter_map(|(other, _)| {
            other.strip_prefix(rel.as_str()).and_then(|rest| rest.strip_prefix('/')).filter(|rest| !rest.contains('/')).map(str::to_string)
        }).collect();
        let entry = state.cgroups.entry(rel.clone()).or_insert_with(|| FakeCgroup::empty(700));
        entry.populated = *populated;
        if entry.children.is_empty() {
            entry.children = children;
        }
    }
    if let Some(slice) = state.cgroups.get_mut("planeon.slice") {
        slice.descendants = uint(lifecycle, "sliceDescendants");
    }
    if text(field(lifecycle, "cgroup"), "state") == "ABSENT" {
        state.cgroups.remove(&enrolled.containment_rel);
    }
    // The backends.
    for capture in &derived.backends {
        let process = field(capture, "process");
        let target = enrolled.backends.iter().find(|backend| backend.component == text(capture, "component")).expect("a component");
        let generation = state.next_generation;
        state.next_generation += 1;
        state.procs.insert(int(process, "pid") as i32, FakeProc {
            generation, ppid: 1, start: uint(process, "startTicks"), status: status_text(0, 0, 0, 0, 0, 1, [0; 5]),
            label: text(process, "processLabel").to_string(), cgroup: format!("0::/{}\n", target.cgroup_rel), maps: String::new(),
            exe: String::new(), identity: (0, 0), namespaces: BTreeMap::new(), threads: BTreeMap::new(), denied: false,
        });
    }
    let _ = positive;
    FakeHost(Rc::new(RefCell::new(state)))
}

/// A positive's engine over its fake host: (engine, host, derived).
pub fn fake_engine(index: usize, clock: Option<Rc<dyn Clock>>) -> (CaptureEngine<FakeHost>, FakeHost, Derived) {
    let vectors = vectors();
    let positive = &list(&vectors, "positive")[index];
    let derived = derive(positive);
    let enrolled = enroll(&derived.record);
    let host = host(positive, &derived, &enrolled, clock);
    let (schema, _) = CaptureSchema::embedded().expect("schema");
    (CaptureEngine::new(host.clone(), enrolled, schema), host, derived)
}

/// [`fake_engine`] over a positive changed by `patch` before the record is derived (PR review round 1, R1-3: a file
/// enrolled at another size).
pub fn fake_engine_with(index: usize, clock: Option<Rc<dyn Clock>>, patch: impl Fn(&mut Value))
                        -> (CaptureEngine<FakeHost>, FakeHost, Derived) {
    let vectors = vectors();
    let mut positive = list(&vectors, "positive")[index].clone();
    patch(&mut positive);
    let derived = derive(&positive);
    let enrolled = enroll(&derived.record);
    let host = host(&positive, &derived, &enrolled, clock);
    let (schema, _) = CaptureSchema::embedded().expect("schema");
    (CaptureEngine::new(host.clone(), enrolled, schema), host, derived)
}

/// Enrolls the WORKER's first file at `size` bytes (its `files` row and the captures' entries, from which the fake
/// serves that many bytes): its path.
pub fn with_worker_file_size(positive: &mut Value, size: u64) -> String {
    let path = list(field(field(field(positive, "record"), "roles"), "WORKER"), "filePaths")[0].as_str().expect("a path").to_string();
    let rows = list(field(positive, "record"), "files").len();
    let index = (0..rows).find(|index| text(&list(field(positive, "record"), "files")[*index], "path") == path).expect("a row");
    set(positive, &["record", "files", &index.to_string(), "size"], Value::Int(Int::from_u64(size)));
    for capture in 0..list(positive, "captures").len() {
        let files = list(&list(positive, "captures")[capture], "files").len();
        for item in 0..files {
            let entry = field(&list(&list(positive, "captures")[capture], "files")[item], "entry");
            if text(entry, "path") == path {
                set(positive, &["captures", &capture.to_string(), "files", &item.to_string(), "entry", "size"],
                    Value::Int(Int::from_u64(size)));
            }
        }
    }
    path
}

/// The value a taken slot holds.
pub fn taken(slot: &planeon_observer::capture::Slot) -> Value {
    match slot {
        planeon_observer::capture::Slot::Taken { canonical, .. } => {
            json::parse(std::str::from_utf8(canonical).expect("ASCII")).expect("canonical JSON")
        }
        other => panic!("not taken: {other:?}"),
    }
}

/// The reason of an unavailable slot.
pub fn reason(slot: &planeon_observer::capture::Slot) -> String {
    match slot {
        planeon_observer::capture::Slot::Unavailable(why) => why.clone(),
        other => panic!("not unavailable: {other:?}"),
    }
}

/// The paths where two values differ (a test's message).
pub fn diff(left: &Value, right: &Value) -> Vec<String> {
    fn walk(left: &Value, right: &Value, at: String, out: &mut Vec<String>) {
        match (left, right) {
            (Value::Object(a), Value::Object(b)) => {
                for (key, member) in a.iter() {
                    let name = key.as_str().unwrap_or("?");
                    match b.get_key(key) {
                        Some(other) => walk(member, other, format!("{at}.{name}"), out),
                        None => out.push(format!("{at}.{name} only left")),
                    }
                }
                for (key, _) in b.iter() {
                    if a.get_key(key).is_none() {
                        out.push(format!("{at}.{} only right", key.as_str().unwrap_or("?")));
                    }
                }
            }
            (Value::Array(a), Value::Array(b)) if a.len() == b.len() => {
                for (index, (x, y)) in a.iter().zip(b).enumerate() {
                    walk(x, y, format!("{at}[{index}]"), out);
                }
            }
            _ => {
                if !json::json_eq(left, right) {
                    let render = |value: &Value| String::from_utf8(json::canonical(value).unwrap_or_default()).unwrap_or_default();
                    out.push(format!("{at}: {} vs {}", render(left).chars().take(200).collect::<String>(),
                                     render(right).chars().take(200).collect::<String>()));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(left, right, "$".to_string(), &mut out);
    out
}
