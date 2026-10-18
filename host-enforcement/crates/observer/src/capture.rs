//! The portable capture engine (HE-004D1 DESIGN-D1 sections 8 to 14; owner decisions Q-HE4D1-1, -6, -7, -9 and -12,
//! all (a), and Q-HE4D1-D2 (a); MODEL_DEFINED R120 and R125-R129). Every kernel read goes through [`KernelView`], whose
//! Linux implementation is `linux_capture` over observer-sys and whose test implementation is a fake; this module
//! names neither. It reads, records what it read, and lets the ported checks decide (`capture_check`): it refuses early
//! only for read failures, R10's bounds, the 2 s window, the frozen bracket's start state and the record's window.
//!
//! **One set per cycle, in this order (WORKER-FIRST, D1's own rule, R126).** (1) The WORKER attempt, first of all: only
//! when every WORKER file's content digest is in the memo, only when it can start within 5 s of its cycle's scheduled
//! start (the scrape-to-set bound; later it is "cycle late"), and only while the broker holds the leaf frozen: the leaf's
//! `cgroup.events` must read `frozen 1` before (else the slot is NotFrozen and nothing else is read) and is read again
//! after. (2) The content fill: the WORKER's files first, then the other roles' and the backends' executables, within the
//! set's budget. (3) The other four role captures. (4) The host-wide process scan and the lifecycle capture. (5) The
//! backend captures. A set's budget ends at its cycle's scheduled start + 25 s; a capture not started by then is
//! "set budget". Before the record's `validFrom` every slot is Pending; from `expiresAt - 3 s` on every slot is Expired,
//! and each window first checks that it can end with a 1 s margin before then (D1-8).
//!
//! **The inspection window (section 9.2).** The wall clock `a` (Unix milliseconds) and the monotonic start; the role
//! cgroup held; the members before (`cgroup.procs`, each pid's directory held, its `stat`, its task listing and each
//! task's `stat`), the process reads through the held directories (`status`, `attr/current`, `cgroup`, each thread's
//! `status` and `attr/current`; OBSERVED roles `maps`, `exe` and the namespace links), the descriptor checks (each
//! enrolled file's open, facts, verity and memo digest; the cgroup's inode, limits, `pids.current`, children and
//! `cgroup.stat`; the broker's service directory; the seven hooks' pinned programs with their local and effective
//! queries and the 22-type census), OBSERVED roles' second `maps` (equal sets), the members after, and
//! `b = a + elapsed` (over 2,000 ms is "inspection window exceeded"). Each member's `cgroup` must name the role's cgroup
//! (D1-12). The observer's own capture holds cgroup facts only, and its one member must be its own pid (D1-12).
//!
//! **Files (section 14).** A per-epoch memo keyed by (path, device, inode, size, ctime) holds the SHA-256 of exactly
//! `size` bytes read through one no-follow read-only descriptor, then EOF, streamed in 64 KiB reads with i05-protocol's
//! `Sha256`. Before any byte is read, the fresh open's size must equal the record row's: a file of another size is marked
//! as differing and never read (its capture then refuses it), so the record's totals bound the hashing (S1; PR review
//! round 1, R1-3). A file the budget cuts keeps its one held descriptor, its partial hash and its byte count, bound to
//! its key; the next set checks the key with `fstat` and reads on (no seek), or restarts from byte 0 through a fresh open
//! if the key changed. Every window opens the path afresh, checks its facts against the memo's key (another key drops
//! the entry: the capture is unavailable and the entry is recomputed) and measures verity; the record's verity digest
//! binds the content the memo hashed, which keeps the memo sound across inode reuse (D1-9).
//!
//! **The declared host fields (Q-HE4D1-1 (a), R120).** `host`, `selinuxBefore`, `selinuxAfter`, `kernelPolicyDigest`,
//! `booleansObserved`, `hardeningObserved` and `bootEntryObserved` are copied from the record, never read; the view
//! carries [`DECLARED_HOST_FIELDS`] and [`HOST_FIELDS_OBSERVED`] = false. The model's equalities on them hold by
//! construction until HE-008 and T04 supply real reads, or a follow-up contract drops them.

use std::collections::BTreeMap;
use std::time::Duration;
use std::time::Instant;

use i05_protocol::json::{self, Int, JStr, Object, Value};
use i05_protocol::sha256::{self, Sha256};

use crate::capture_check::{self, Refusal, CENSUS_ATTACH_TYPES, ROLES};
use crate::capture_schema::CaptureSchema;
use crate::enrolled::{self, Enrolled, Row};
use crate::kernel_text;

/// A set's budget, counted from its cycle's scheduled start (R2-2).
pub const SET_BUDGET: Duration = Duration::from_secs(25);
/// The scrape-to-set bound: the WORKER window starts at most this long after its cycle's scheduled start (C4-2).
pub const SCRAPE_TO_SET: Duration = Duration::from_secs(5);
/// The inspection window's bound, and the margins of the expiry check (D1-8).
pub const WINDOW_MS: u64 = 2_000;
pub const WINDOW_MARGIN_MS: u64 = 1_000;
pub const EXPIRY_MARGIN_MS: u64 = 3_000;
/// The capture deadline's horizon.
pub const DEADLINE_MS: u64 = 900_000;
/// The host-wide scan's deadline.
pub const SCAN_DEADLINE: Duration = Duration::from_secs(5);
/// The read bounds (section 16).
pub const PROC_LIMIT: usize = 16 << 10;
pub const MAPS_LIMIT: usize = 1 << 20;
pub const CGROUP_LIMIT: usize = 16 << 10;
pub const PROCS_LIMIT: usize = 64 << 10;
pub const MARKER_LIMIT: usize = 4_096;
pub const HASH_CHUNK: usize = 64 << 10;
/// The census walk's bounds and a component's candidate bound.
pub const MAX_CENSUS: usize = 1_024;
pub const MAX_CENSUS_DEPTH: usize = 8;
pub const MAX_CANDIDATES: usize = 4_096;
/// The seven domains the lifecycle capture counts.
pub const DOMAINS: [&str; 7] = ["planeon_server_t", "planeon_observer_t", "planeon_broker_t", "planeon_worker_t",
                                "planeon_gate_t", "planeon_contain_t", "planeon_policy_writer_t"];
/// The declared host fields (R120), never observed by R10.
pub const DECLARED_HOST_FIELDS: [&str; 7] =
    ["host", "selinuxBefore", "selinuxAfter", "kernelPolicyDigest", "booleansObserved", "hardeningObserved", "bootEntryObserved"];
pub const HOST_FIELDS_OBSERVED: bool = false;

/// A process file of the closed read set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcItem {
    Stat,
    Status,
    Cgroup,
    AttrCurrent,
    Maps,
}

/// A process link of the closed read set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkItem {
    Exe,
    NsUser,
    NsMnt,
    NsPid,
    NsNet,
}

/// A cgroup file of the closed read set (no write target among them, NP-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupItem {
    Procs,
    Events,
    Stat,
    MemoryMax,
    PidsMax,
    PidsCurrent,
    CpuMax,
}

/// Why a read failed, by class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The name does not exist (ENOENT).
    NotFound,
    /// The process behind a held directory is gone (ESRCH).
    Gone,
    /// The read was refused (EACCES, EPERM).
    Denied,
    /// A listing or read over its bound, or a malformed reply.
    Bound,
    /// Any other error.
    Other,
}

impl ReadError {
    fn reason(self) -> &'static str {
        match self {
            ReadError::NotFound => "not found",
            ReadError::Gone => "member gone",
            ReadError::Denied => "read refused",
            ReadError::Bound => "a read over its bound",
            ReadError::Other => "read failed",
        }
    }
}

/// What `fstat` gives of an opened enrolled file; `mode` is `st_mode & 0o7777`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub mode: u32,
    pub size: u64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

/// What `BPF_OBJ_GET_INFO_BY_FD` reports of a pinned program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramFacts {
    pub id: u32,
    pub kind: u32,
    pub xlated: Vec<u8>,
    pub map_ids: Vec<u32>,
    pub ifindex: u32,
}

/// The verity measurement's reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verity {
    pub algorithm: u16,
    pub size: u16,
    pub digest: [u8; 32],
}

/// The kernel reads a capture makes (Linux: `linux_capture::LinuxCapture` over observer-sys; tests: a fake). Each
/// handle is held while a capture reads through it.
pub trait KernelView {
    /// A held process or thread directory.
    type Proc;
    /// A held cgroup directory.
    type Cgroup;
    /// An opened enrolled file or the seal marker.
    type Held;
    /// The monotonic clock.
    fn now(&self) -> Instant;
    /// The wall clock in Unix milliseconds, `None` before the epoch.
    fn wall_millis(&self) -> Option<u64>;
    /// The observer's own pid (the proc root's `self` link).
    fn observer_pid(&mut self) -> Result<i32, ReadError>;
    /// The numeric entries of a fresh listing of the proc root (over 65,536 refuses).
    fn processes(&mut self) -> Result<Vec<i32>, ReadError>;
    fn process(&mut self, pid: i32) -> Result<Self::Proc, ReadError>;
    /// The numeric entries of a fresh listing of the task directory (over `bound` refuses).
    fn tasks(&mut self, process: &Self::Proc, bound: usize) -> Result<Vec<i32>, ReadError>;
    fn task(&mut self, process: &Self::Proc, tid: i32) -> Result<Self::Proc, ReadError>;
    fn proc_read(&mut self, process: &Self::Proc, item: ProcItem, limit: usize) -> Result<Vec<u8>, ReadError>;
    fn proc_link(&mut self, process: &Self::Proc, item: LinkItem) -> Result<String, ReadError>;
    /// The running image's device and inode (`exe` followed).
    fn exe_identity(&mut self, process: &Self::Proc) -> Result<(u64, u64), ReadError>;
    /// A cgroup directory under the cgroup2 root.
    fn cgroup(&mut self, rel: &str) -> Result<Self::Cgroup, ReadError>;
    fn cgroup_read(&mut self, cgroup: &Self::Cgroup, item: CgroupItem, limit: usize) -> Result<Vec<u8>, ReadError>;
    /// The child cgroups of a fresh listing (over 64 refuses).
    fn children(&mut self, cgroup: &Self::Cgroup) -> Result<Vec<String>, ReadError>;
    fn cgroup_inode(&mut self, cgroup: &Self::Cgroup) -> Result<u64, ReadError>;
    /// One BPF program query of a named attach type: the ids and the attach flags word; any error is an error.
    fn prog_query(&mut self, cgroup: &Self::Cgroup, attach: &str, effective: bool) -> Result<(Vec<u32>, u32), ReadError>;
    /// The name of a local query's attach flags word, if it is exactly one named flag.
    fn attach_flags_name(&self, flags: u32) -> Option<&'static str>;
    /// The pinned program at an absolute path, opened read-only, and its facts.
    fn program(&mut self, pin: &str) -> Result<ProgramFacts, ReadError>;
    /// An enrolled file (or the seal marker) opened read-only by absolute path, a regular file.
    fn open_enrolled(&mut self, path: &str) -> Result<Self::Held, ReadError>;
    fn facts(&mut self, held: &Self::Held) -> Result<Facts, ReadError>;
    fn verity(&mut self, held: &Self::Held) -> Result<Verity, ReadError>;
    /// One plain read (the hashing loop's one primitive); 0 at the end.
    fn read_held(&mut self, held: &mut Self::Held, buffer: &mut [u8]) -> Result<usize, ReadError>;
    /// The run filesystem's type name of the held file (`tmpfs`, or `None` for any other magic).
    fn run_fs_type(&mut self, held: &Self::Held) -> Result<Option<&'static str>, ReadError>;
}

/// One slot of the capture view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    /// A capture the self-check accepted: its canonical bytes, their digest and its `observedAt`.
    Taken { canonical: Vec<u8>, digest: String, observed_at: String },
    /// The WORKER leaf was not frozen at the bracket's start.
    NotFrozen,
    /// Not taken this cycle, and why.
    Unavailable(String),
    /// Before the record's `validFrom`.
    Pending,
    /// From `expiresAt - 3 s` on.
    Expired,
}

/// The latest capture set, in memory only (Q-HE4-10 (a)), replaced wholesale by each set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureView {
    pub sequence: u64,
    pub record_digest: String,
    pub declared_host_fields: [&'static str; 7],
    /// The five roles, in the model's order.
    pub roles: [Slot; 5],
    pub lifecycle: Slot,
    /// The backend components, in sorted order.
    pub backends: Vec<(String, Slot)>,
    pub set_started_ms: u64,
}

impl CaptureView {
    /// The taken and the other slots of the view.
    pub fn counts(&self) -> (usize, usize) {
        let slots = self.roles.iter().chain([&self.lifecycle]).chain(self.backends.iter().map(|(_, slot)| slot));
        let (mut taken, mut other) = (0, 0);
        for slot in slots {
            if matches!(slot, Slot::Taken { .. }) { taken += 1 } else { other += 1 }
        }
        (taken, other)
    }

    fn every(&mut self, slot: &Slot) {
        for role in self.roles.iter_mut() {
            *role = slot.clone();
        }
        self.lifecycle = slot.clone();
        for (_, backend) in self.backends.iter_mut() {
            *backend = slot.clone();
        }
    }
}

/// What `Epoch::capture_view` reads: the latest view while the record's window is open, or Expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureViewState<'a> {
    Current(&'a CaptureView),
    Expired,
}

/// What the observation epoch drives (`Epoch::with_captures`).
pub trait CaptureCycle {
    /// One capture set for the cycle scheduled at `scheduled` (the previous cycle's actual start + 60 s).
    fn capture_set(&mut self, scheduled: Instant);
    /// Whether the engine's wall clock has reached `expiresAt - 3 s`.
    fn expired_now(&self) -> bool;
    /// When the engine's wall clock reaches `expiresAt - 3 s`, on its monotonic clock; `None` once it has.
    fn expiry_wake(&self) -> Option<Instant>;
    /// Every stored slot becomes Expired at once.
    fn expire(&mut self);
    /// The latest view.
    fn view(&self) -> &CaptureView;
}

/// A memo key: (device, inode, size, ctime) of one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
    device: u64,
    inode: u64,
    size: u64,
    ctime: i64,
    ctime_nsec: i64,
}

impl Key {
    fn of(facts: &Facts) -> Key {
        Key { device: facts.device, inode: facts.inode, size: facts.size, ctime: facts.ctime, ctime_nsec: facts.ctime_nsec }
    }
}

/// A memo entry: the digest of exactly `size` bytes, or a file that was shorter or longer than its size.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Done { key: Key, digest: String },
    Differs { key: Key },
}

/// The one file the budget cut, with its held descriptor and partial hash.
struct Partial<H> {
    path: String,
    held: H,
    key: Key,
    hasher: Sha256,
    count: u64,
}

/// The per-epoch content memo.
struct Memo<H> {
    entries: BTreeMap<String, Entry>,
    partial: Option<Partial<H>>,
}

/// How far a hash went this time.
enum Hashed {
    Done(String),
    Differs,
    Cut,
}

/// Why a capture stopped.
enum Halt {
    Unavailable(String),
    NotFrozen,
    Expired,
}

impl From<ReadError> for Halt {
    fn from(error: ReadError) -> Halt {
        Halt::Unavailable(error.reason().to_string())
    }
}

fn unavailable<T>(why: &str) -> Result<T, Halt> {
    Err(Halt::Unavailable(why.to_string()))
}

/// The record's values a capture copies (the declared host fields and the common binding).
struct Declared {
    host: Value,
    status: Value,
    policy_digest: Value,
    booleans: Value,
    hardening: Value,
    boot_entry: Value,
}

/// An integer value of a `u64`.
fn number(value: u64) -> Value {
    Value::Int(Int::from_u64(value))
}

fn signed(value: i64) -> Value {
    Value::int(value)
}

/// An object of the given members, in order.
fn object(members: Vec<(&str, Value)>) -> Value {
    let mut built = Object::new();
    for (key, member) in members {
        built.insert(JStr::new(key), member);
    }
    Value::Object(built)
}

fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().map(|text| Value::str(text)).collect())
}

fn ids(values: &[u32]) -> Value {
    Value::Array(values.iter().map(|id| number(u64::from(*id))).collect())
}

/// The capture engine over one kernel view.
pub struct CaptureEngine<K: KernelView> {
    kernel: K,
    enrolled: Enrolled,
    schema: CaptureSchema,
    declared: Declared,
    memo: Memo<K::Held>,
    view: CaptureView,
    buffer: Vec<u8>,
}

impl<K: KernelView> CaptureEngine<K> {
    /// The engine for one epoch: its view starts Pending.
    pub fn new(kernel: K, enrolled: Enrolled, schema: CaptureSchema) -> CaptureEngine<K> {
        let record = enrolled.record.value();
        let field = |path: &[&str]| path.iter().try_fold(record, |node, key| node.get(key)).cloned().unwrap_or(Value::Null);
        let mut hardening = field(&["hardening"]);
        if let Value::Object(members) = &mut hardening {
            if let Some(Value::Object(seal)) = members.get_key_mut(&JStr::new("sealMarker")) {
                seal.remove(&JStr::new("selinuxLabel"));
            }
        }
        let line = record
            .get("bootEntries")
            .and_then(|entries| entries.get("ENROLLED"))
            .and_then(|entry| entry.get("kernelCmdline"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let declared = Declared {
            host: field(&["host"]),
            status: field(&["selinux", "status"]),
            policy_digest: field(&["selinux", "policyDigest"]),
            booleans: field(&["selinux", "booleans"]),
            hardening,
            boot_entry: object(vec![("entryId", field(&["bootEntries", "ENROLLED", "entryId"])),
                                    ("cmdlineSha256", Value::str(&sha256::prefixed(line.as_bytes())))]),
        };
        let view = CaptureView {
            sequence: 0,
            record_digest: enrolled.record.digest().to_string(),
            declared_host_fields: DECLARED_HOST_FIELDS,
            roles: [Slot::Pending, Slot::Pending, Slot::Pending, Slot::Pending, Slot::Pending],
            lifecycle: Slot::Pending,
            backends: enrolled.backends.iter().map(|backend| (backend.component.clone(), Slot::Pending)).collect(),
            set_started_ms: 0,
        };
        CaptureEngine { kernel, enrolled, schema, declared, memo: Memo { entries: BTreeMap::new(), partial: None }, view,
                        buffer: vec![0u8; HASH_CHUNK] }
    }

    /// The kernel view (the tests read their fake's log through it).
    pub fn kernel(&self) -> &K {
        &self.kernel
    }

    /// The kernel view, mutably (the tests script their fake between sets).
    pub fn kernel_mut(&mut self) -> &mut K {
        &mut self.kernel
    }

    /// The enrolled record.
    pub fn enrolled(&self) -> &Enrolled {
        &self.enrolled
    }

    /// Whether every path has its memo answer: its content digest, or known to differ from its record row (a size other
    /// than the row's is never read, R1-3, and the window then refuses the file).
    pub fn digests_ready(&self, paths: &[String]) -> bool {
        paths.iter().all(|path| matches!(self.memo.entries.get(path), Some(Entry::Done { .. } | Entry::Differs { .. })))
    }

    /// Whether the memo holds a partial hash (a cut file's held descriptor).
    pub fn holds_partial(&self) -> bool {
        self.memo.partial.is_some()
    }

    /// The memo's complete digest of `path`, if any (a partial hash never yields one).
    pub fn content_digest(&self, path: &str) -> Option<&str> {
        match self.memo.entries.get(path) {
            Some(Entry::Done { digest, .. }) => Some(digest),
            _ => None,
        }
    }

    fn expires_ms(&self) -> u64 {
        self.enrolled.expires_at.saturating_mul(1_000).saturating_sub(EXPIRY_MARGIN_MS)
    }

    fn wall(&self) -> Option<u64> {
        self.kernel.wall_millis().filter(|wall| *wall / 1_000 <= kernel_text::MAX_UTC_SECONDS)
    }

    /// The content fill (section 14): the WORKER's files first, then the other roles' and the backends' executables,
    /// within the budget; a cut file keeps its held descriptor.
    fn fill(&mut self, budget_end: Instant) {
        let mut order: Vec<String> = Vec::new();
        let worker = self.enrolled.roles.iter().find(|role| role.role == "WORKER");
        let others = ["SERVER", "OBSERVER", "BROKER", "EFFECT_GATE"]
            .iter()
            .filter_map(|name| self.enrolled.roles.iter().find(|role| role.role == *name));
        for role in worker.into_iter().chain(others) {
            for path in &role.paths {
                if !order.contains(path) {
                    order.push(path.clone());
                }
            }
        }
        for backend in &self.enrolled.backends {
            if !order.contains(&backend.executable) {
                order.push(backend.executable.clone());
            }
        }
        for path in order {
            if self.memo.entries.contains_key(&path) {
                continue;
            }
            if self.kernel.now() >= budget_end {
                return;
            }
            let held = self.memo.partial.take();
            let resumed = match held {
                Some(partial) if partial.path == path => {
                    match self.kernel.facts(&partial.held) {
                        Ok(facts) if Key::of(&facts) == partial.key => Some(partial),
                        _ => None,
                    }
                }
                // Another file's partial hash: dropped (it restarts from byte 0 later), so at most one is held.
                _ => None,
            };
            let mut partial = match resumed {
                Some(partial) => partial,
                None => {
                    let Ok(held) = self.kernel.open_enrolled(&path) else { continue };
                    let Ok(facts) = self.kernel.facts(&held) else { continue };
                    // The record row's size bounds the read: another size is marked as differing, unread (R1-3).
                    let row_size = self.enrolled.rows.get(&path).or_else(|| self.enrolled.backend_rows.get(&path)).map(|row| row.size);
                    if row_size != Some(facts.size) {
                        self.memo.entries.insert(path, Entry::Differs { key: Key::of(&facts) });
                        continue;
                    }
                    Partial { path: path.clone(), held, key: Key::of(&facts), hasher: Sha256::new(), count: 0 }
                }
            };
            match hash_more(&mut self.kernel, &mut partial, &mut self.buffer, budget_end) {
                Ok(Hashed::Done(digest)) => {
                    self.memo.entries.insert(path, Entry::Done { key: partial.key, digest });
                }
                Ok(Hashed::Differs) => {
                    self.memo.entries.insert(path, Entry::Differs { key: partial.key });
                }
                Ok(Hashed::Cut) => {
                    self.memo.partial = Some(partial);
                    return;
                }
                Err(_) => {}
            }
        }
    }

    /// One P1 role capture (or its slot state).
    fn role(&mut self, index: usize, scheduled: Instant, budget_end: Instant) -> Result<Value, Halt> {
        let expires = self.expires_ms();
        let CaptureEngine { kernel, enrolled, memo, declared, .. } = self;
        let mut window = Window { kernel, enrolled, memo, declared, index, expires, started: None, start_ms: 0 };
        window.capture(scheduled, budget_end)
    }

    /// The canonical capture after the self-check, or its refusal.
    fn checked(&self, value: Value, family: Family) -> Slot {
        let record = &self.enrolled.record;
        let verdict = match family {
            Family::Role(role) => capture_check::check_capture(record, &value, role, &self.schema),
            Family::Lifecycle => capture_check::check_lifecycle_capture(record, &value, &self.schema),
            Family::Backend => capture_check::check_backend_capture(record, &value, &self.schema),
        };
        match verdict {
            Ok(()) => match json::canonical(&value) {
                Ok(canonical) => {
                    let observed_at = value.get("observedAt").and_then(Value::as_str).unwrap_or("").to_string();
                    Slot::Taken { digest: sha256::prefixed(&canonical), canonical, observed_at }
                }
                Err(_) => Slot::Unavailable("no canonical encoding".to_string()),
            },
            Err(Refusal::Model(text) | Refusal::Data(text)) => Slot::Unavailable(text.to_string()),
            Err(Refusal::Schema) => Slot::Unavailable("schema".to_string()),
            Err(Refusal::Missing) => Slot::Unavailable("missing member".to_string()),
        }
    }

    fn slot(&self, result: Result<Value, Halt>, family: Family) -> Slot {
        match result {
            Ok(value) => self.checked(value, family),
            Err(Halt::Unavailable(why)) => Slot::Unavailable(why),
            Err(Halt::NotFrozen) => Slot::NotFrozen,
            Err(Halt::Expired) => Slot::Expired,
        }
    }

    /// Whether a capture starting now can still end before the expiry wake (with the window and its margin).
    fn can_start(&self) -> bool {
        self.wall().is_some_and(|wall| wall.saturating_add(WINDOW_MS + WINDOW_MARGIN_MS) < self.expires_ms())
    }
}

/// Which check a value goes through.
#[derive(Clone, Copy)]
enum Family {
    Role(&'static str),
    Lifecycle,
    Backend,
}

/// Hashes on from where `partial` stands until the end, a size mismatch or the budget.
fn hash_more<K: KernelView>(kernel: &mut K, partial: &mut Partial<K::Held>, buffer: &mut [u8], budget_end: Instant)
                            -> Result<Hashed, ReadError> {
    loop {
        if kernel.now() >= budget_end {
            return Ok(Hashed::Cut);
        }
        let count = kernel.read_held(&mut partial.held, buffer)?;
        let read = u64::try_from(count).map_err(|_| ReadError::Bound)?;
        if read == 0 {
            if partial.count == partial.key.size {
                let digest = std::mem::take(&mut partial.hasher).finish();
                return Ok(Hashed::Done(format!("sha256:{}", sha256::hex(&digest))));
            }
            return Ok(Hashed::Differs);
        }
        let total = partial.count.checked_add(read).ok_or(ReadError::Bound)?;
        if total > partial.key.size {
            return Ok(Hashed::Differs);
        }
        partial.hasher.update(buffer.get(..count).ok_or(ReadError::Bound)?);
        partial.count = total;
    }
}

/// One P1 inspection window's state, borrowing the engine's parts.
struct Window<'a, K: KernelView> {
    kernel: &'a mut K,
    enrolled: &'a Enrolled,
    memo: &'a mut Memo<K::Held>,
    declared: &'a Declared,
    index: usize,
    expires: u64,
    started: Option<Instant>,
    start_ms: u64,
}

/// One member as read: its keys, status, label, threads and (OBSERVED) image.
struct Member {
    pid: i32,
    start: u64,
    ppid: i32,
    status: kernel_text::Status,
    label: String,
    uniform: bool,
    exe: Option<(String, u64, u64)>,
}

impl<K: KernelView> Window<'_, K> {
    /// The 2 s window, checked between reads.
    fn tick(&self) -> Result<(), Halt> {
        let Some(started) = self.started else { return Ok(()) };
        let elapsed = self.kernel.now().saturating_duration_since(started);
        if elapsed > Duration::from_millis(WINDOW_MS) {
            return unavailable("inspection window exceeded");
        }
        Ok(())
    }

    fn cgroup_text(&mut self, cgroup: &K::Cgroup, item: CgroupItem, limit: usize) -> Result<Vec<u8>, Halt> {
        let bytes = self.kernel.cgroup_read(cgroup, item, limit)?;
        self.tick()?;
        Ok(bytes)
    }

    fn proc_text(&mut self, process: &K::Proc, item: ProcItem, limit: usize) -> Result<Vec<u8>, Halt> {
        let bytes = self.kernel.proc_read(process, item, limit).map_err(member_error)?;
        self.tick()?;
        Ok(bytes)
    }

    /// The members as `cgroup.procs` lists them, each pid's directory held, with its `stat` and its threads' keys.
    fn member_set(&mut self, cgroup: &K::Cgroup, bound: usize) -> Result<Vec<(i32, u64, i32, K::Proc, Vec<(i32, u64)>)>, Halt> {
        let procs = self.cgroup_text(cgroup, CgroupItem::Procs, PROCS_LIMIT)?;
        let pids = kernel_text::procs(&procs).ok_or_else(|| Halt::Unavailable("cgroup.procs malformed".to_string()))?;
        if pids.len() > bound {
            return unavailable("members over pidsMax");
        }
        let mut members = Vec::with_capacity(pids.len());
        let mut tasks_total = 0usize;
        for pid in pids {
            let process = self.kernel.process(pid).map_err(member_error)?;
            let stat = kernel_text::stat(&self.proc_text(&process, ProcItem::Stat, PROC_LIMIT)?)
                .ok_or_else(|| Halt::Unavailable("stat malformed".to_string()))?;
            let tids = self.kernel.tasks(&process, bound).map_err(member_error)?;
            tasks_total = tasks_total.saturating_add(tids.len());
            if tasks_total > bound {
                return unavailable("tasks over pidsMax");
            }
            let mut threads = Vec::with_capacity(tids.len());
            for tid in tids {
                let thread = self.kernel.task(&process, tid).map_err(member_error)?;
                let thread_stat = kernel_text::stat(&self.proc_text(&thread, ProcItem::Stat, PROC_LIMIT)?)
                    .ok_or_else(|| Halt::Unavailable("thread stat malformed".to_string()))?;
                threads.push((tid, thread_stat.start_ticks));
            }
            members.push((pid, stat.start_ticks, stat.ppid, process, threads));
        }
        Ok(members)
    }

    /// The process reads of one member through its held directory (section 9.2 step 3).
    fn member(&mut self, held: &(i32, u64, i32, K::Proc, Vec<(i32, u64)>), rel: &str, observed: bool) -> Result<Member, Halt> {
        let (pid, start, ppid, process, threads) = held;
        let status = kernel_text::status(&self.proc_text(process, ProcItem::Status, PROC_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("status malformed".to_string()))?;
        let label = kernel_text::label(&self.proc_text(process, ProcItem::AttrCurrent, PROC_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("attr/current malformed".to_string()))?;
        let line = kernel_text::cgroup_line(&self.proc_text(process, ProcItem::Cgroup, PROC_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("cgroup malformed".to_string()))?;
        if line.strip_prefix('/') != Some(rel) {
            return unavailable("member outside the role cgroup");
        }
        let mut uniform = true;
        for (tid, _) in threads {
            let thread = self.kernel.task(process, *tid).map_err(member_error)?;
            let thread_status = kernel_text::status(&self.proc_text(&thread, ProcItem::Status, PROC_LIMIT)?);
            let thread_label = kernel_text::label(&self.proc_text(&thread, ProcItem::AttrCurrent, PROC_LIMIT)?);
            uniform = uniform && thread_status.as_ref() == Some(&status) && thread_label.as_deref() == Some(label.as_str());
        }
        let exe = if observed {
            let text = self.kernel.proc_link(process, LinkItem::Exe).map_err(member_error)?;
            self.tick()?;
            let path = kernel_text::exe_path(&text).ok_or_else(|| Halt::Unavailable("exe link deleted".to_string()))?;
            let (device, inode) = self.kernel.exe_identity(process).map_err(member_error)?;
            self.tick()?;
            Some((path, device, inode))
        } else {
            None
        };
        Ok(Member { pid: *pid, start: *start, ppid: *ppid, status, label, uniform, exe })
    }

    /// The executable mappings of `maps`.
    fn maps(&mut self, process: &K::Proc) -> Result<Vec<kernel_text::Mapping>, Halt> {
        kernel_text::maps(&self.proc_text(process, ProcItem::Maps, MAPS_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("maps malformed".to_string()))
    }

    /// One enrolled file's observation (section 14's window step): open, facts, verity and the memo's digest.
    fn measure(&mut self, row: &Row) -> Result<Value, Halt> {
        let held = self.kernel.open_enrolled(&row.path)?;
        let facts = self.kernel.facts(&held)?;
        let reply = self.kernel.verity(&held)?;
        self.tick()?;
        let measured = kernel_text::verity_text(reply.algorithm, reply.size, &reply.digest)
            .ok_or_else(|| Halt::Unavailable("verity other than SHA-256".to_string()))?;
        let digest = memo_digest(self.memo, &row.path, Key::of(&facts))?;
        if kernel_text::mode_text(facts.mode) != row.mode || facts.size != row.size {
            return unavailable("file differs from its record row");
        }
        Ok(object(vec![
            ("entry", row.entry.clone()),
            ("device", number(facts.device)),
            ("inode", number(facts.inode)),
            ("uid", number(u64::from(facts.uid))),
            ("gid", number(u64::from(facts.gid))),
            ("nlink", number(facts.nlink)),
            ("contentDigest", Value::str(&digest)),
            ("measuredVerity", Value::str(&measured)),
        ]))
    }

    /// The seven hooks' observed programs and the 22-type census of one cgroup.
    fn programs(&mut self, cgroup: &K::Cgroup, pins: &[(&'static str, String)]) -> Result<(Value, Value), Halt> {
        let mut programs = Object::new();
        for (hook, pin) in pins {
            let facts = self.kernel.program(pin)?;
            self.tick()?;
            let attach = format!("BPF_CGROUP_{hook}");
            let (local, flags) = self.kernel.prog_query(cgroup, &attach, false)?;
            let (effective, _) = self.kernel.prog_query(cgroup, &attach, true)?;
            self.tick()?;
            let flags = self.kernel.attach_flags_name(flags).ok_or_else(|| Halt::Unavailable("foreign attach flag".to_string()))?;
            let calls = kernel_text::call_count(&facts.xlated)
                .ok_or_else(|| Halt::Unavailable("a call the reading does not admit".to_string()))?;
            let length = u64::try_from(facts.xlated.len()).map_err(|_| Halt::Unavailable("program length".to_string()))?;
            let info = object(vec![
                ("programId", number(u64::from(facts.id))),
                ("programType", number(u64::from(facts.kind))),
                ("translatedSha256", Value::str(&sha256::prefixed(&facts.xlated))),
                ("instructionBytes", number(length)),
                ("mapIds", ids(&facts.map_ids)),
                ("ifindex", number(u64::from(facts.ifindex))),
                ("pinPath", Value::str(pin)),
                ("attachFlags", Value::str(flags)),
                ("helperCalls", number(calls)),
            ]);
            programs.insert(JStr::new(hook), object(vec![("program", info), ("pinPath", Value::str(pin)), ("localIds", ids(&local)),
                                                         ("effectiveIds", ids(&effective))]));
        }
        let mut census = Object::new();
        for name in CENSUS_ATTACH_TYPES {
            let (found, _) = self.kernel.prog_query(cgroup, name, true)?;
            self.tick()?;
            census.insert(JStr::new(name), ids(&found));
        }
        Ok((Value::Object(programs), Value::Object(census)))
    }

    /// The cgroup limits: (memoryMaxBytes, pidsMax, cpuQuotaMicros, cpuPeriodMicros).
    fn limits(&mut self, cgroup: &K::Cgroup) -> Result<(u64, u64, u64, u64), Halt> {
        let memory = kernel_text::limit(&self.cgroup_text(cgroup, CgroupItem::MemoryMax, CGROUP_LIMIT)?);
        let pids = kernel_text::limit(&self.cgroup_text(cgroup, CgroupItem::PidsMax, CGROUP_LIMIT)?);
        let cpu = kernel_text::cpu_max(&self.cgroup_text(cgroup, CgroupItem::CpuMax, CGROUP_LIMIT)?);
        match (memory, pids, cpu) {
            (Some(memory), Some(pids), Some((quota, period))) => Ok((memory, pids, quota, period)),
            _ => unavailable("a cgroup limit is not a number"),
        }
    }

    /// The common members of a role capture.
    fn common(&self, role: &str, a: u64, b: u64, d: u64) -> Result<Vec<(&'static str, Value)>, Halt> {
        let observed = kernel_text::utc_text(a / 1_000).ok_or_else(|| Halt::Unavailable("wall clock unusable".to_string()))?;
        Ok(vec![
            ("schemaVersion", Value::str(capture_check::V4_CAPTURE)),
            ("evidenceClass", Value::str("DATA_CHECK_ONLY")),
            ("capturer", Value::str("OBSERVER")),
            ("qualificationDigest", Value::str(self.enrolled.record.digest())),
            ("role", Value::str(role)),
            ("host", self.declared.host.clone()),
            ("selinuxBefore", self.declared.status.clone()),
            ("selinuxAfter", self.declared.status.clone()),
            ("kernelPolicyDigest", self.declared.policy_digest.clone()),
            ("observedAt", Value::str(&observed)),
            ("inspectionStartedMs", number(a)),
            ("inspectionFinishedMs", number(b)),
            ("deadlineMs", number(d)),
            ("booleansObserved", self.declared.booleans.clone()),
            ("hardeningObserved", self.declared.hardening.clone()),
            ("bootEntryObserved", self.declared.boot_entry.clone()),
        ])
    }

    /// The window (section 9.2) and the value it builds.
    fn capture(&mut self, scheduled: Instant, budget_end: Instant) -> Result<Value, Halt> {
        let enrolled: &Enrolled = self.enrolled;
        let target = enrolled.roles.get(self.index).ok_or_else(|| Halt::Unavailable("no such role".to_string()))?;
        let (role, class) = (target.role, target.class);
        let (rel, pids_max) = (target.cgroup_rel.clone(), target.pids_max);
        let bound = usize::try_from(pids_max).unwrap_or(usize::MAX);
        let (paths, pins) = (target.paths.clone(), target.pins.clone());
        let cgroup_path = target.cgroup_path.clone();
        if self.kernel.now() >= budget_end {
            return unavailable("set budget");
        }
        // Step 0: the expiry check (D1-8).
        let a = self.kernel.wall_millis().ok_or_else(|| Halt::Unavailable("wall clock unusable".to_string()))?;
        if a.saturating_add(WINDOW_MS + WINDOW_MARGIN_MS) >= self.expires {
            return Err(Halt::Expired);
        }
        if role == "WORKER" && self.kernel.now().saturating_duration_since(scheduled) > SCRAPE_TO_SET {
            return unavailable("cycle late");
        }
        // Step 1.
        self.started = Some(self.kernel.now());
        self.start_ms = a;
        let cgroup = self.kernel.cgroup(&rel)?;
        let own = class == "DECLARED_T04";
        let observed = class == "OBSERVED";
        let mut frozen_before = None;
        if role == "WORKER" {
            let events = kernel_text::events(&self.cgroup_text(&cgroup, CgroupItem::Events, CGROUP_LIMIT)?)
                .ok_or_else(|| Halt::Unavailable("cgroup.events malformed".to_string()))?;
            if events.1 != 1 {
                return Err(Halt::NotFrozen);
            }
            frozen_before = Some(events.1);
        }
        // Step 2: the members before (not for the observer's own capture).
        let mut members_before = Vec::new();
        let mut own_members = Vec::new();
        if own {
            let procs = self.cgroup_text(&cgroup, CgroupItem::Procs, PROCS_LIMIT)?;
            own_members = kernel_text::procs(&procs).ok_or_else(|| Halt::Unavailable("cgroup.procs malformed".to_string()))?;
            let me = self.kernel.observer_pid()?;
            if own_members.len() == 1 && own_members.first() != Some(&me) {
                return unavailable("observer leaf member is not the observer");
            }
        } else {
            members_before = self.member_set(&cgroup, bound)?;
        }
        // Step 3: the process reads.
        let mut members = Vec::with_capacity(members_before.len());
        for held in &members_before {
            members.push(self.member(held, &rel, observed)?);
        }
        let mut first_maps = None;
        let mut namespaces = None;
        let me_index = if own { None } else { inspected(role, &members) };
        if observed {
            let Some(index) = me_index else { return unavailable("no inspected process") };
            let held = members_before.get(index).ok_or_else(|| Halt::Unavailable("no inspected process".to_string()))?;
            first_maps = Some(self.maps(&held.3)?);
            let mut inodes = Object::new();
            for (key, link) in [("user", LinkItem::NsUser), ("mnt", LinkItem::NsMnt), ("pid", LinkItem::NsPid),
                                ("net", LinkItem::NsNet)] {
                let text = self.kernel.proc_link(&held.3, link).map_err(member_error)?;
                self.tick()?;
                let inode = kernel_text::namespace_inode(&text, key)
                    .ok_or_else(|| Halt::Unavailable("namespace link malformed".to_string()))?;
                inodes.insert(JStr::new(key), number(inode));
            }
            namespaces = Some(Value::Object(inodes));
        }
        // Step 4: the descriptor checks.
        let mut files = Vec::with_capacity(paths.len());
        for path in &paths {
            let row = enrolled.rows.get(path).ok_or_else(|| Halt::Unavailable("no record row".to_string()))?;
            files.push(self.measure(row)?);
        }
        let inode = self.kernel.cgroup_inode(&cgroup)?;
        let (memory, cgroup_pids_max, quota, period) = self.limits(&cgroup)?;
        let current = kernel_text::limit(&self.cgroup_text(&cgroup, CgroupItem::PidsCurrent, CGROUP_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("pids.current malformed".to_string()))?;
        let children = self.kernel.children(&cgroup)?;
        self.tick()?;
        let descendants = kernel_text::descendants(&self.cgroup_text(&cgroup, CgroupItem::Stat, CGROUP_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("cgroup.stat malformed".to_string()))?;
        let (delegated_children, delegated_members) = if role == "BROKER" {
            let parent = rel.rsplit_once('/').map(|(parent, _)| parent.to_string())
                .ok_or_else(|| Halt::Unavailable("no broker service".to_string()))?;
            let service = self.kernel.cgroup(&parent)?;
            let names = self.kernel.children(&service)?;
            self.tick()?;
            let service_set = self.member_set(&service, bound)?;
            let mut rows = Vec::with_capacity(service_set.len());
            for held in &service_set {
                let found = self.member(held, &parent, true)?;
                rows.push(member_row(&found, true));
            }
            (strings(&names), Value::Array(rows))
        } else {
            (Value::Null, Value::Null)
        };
        let (programs, census) = self.programs(&cgroup, &pins)?;
        // Step 5: OBSERVED roles read maps a second time; the executable mapping sets must be equal.
        if observed {
            let index = me_index.ok_or_else(|| Halt::Unavailable("no inspected process".to_string()))?;
            let held = members_before.get(index).ok_or_else(|| Halt::Unavailable("no inspected process".to_string()))?;
            let second = self.maps(&held.3)?;
            if first_maps.as_ref() != Some(&second) {
                return unavailable("executable maps changed during the inspection");
            }
        }
        // Step 6: the members after; WORKER, the bracket's end.
        let members_after = if own { Vec::new() } else { self.member_set(&cgroup, bound)? };
        let mut frozen_after = None;
        if role == "WORKER" {
            let events = kernel_text::events(&self.cgroup_text(&cgroup, CgroupItem::Events, CGROUP_LIMIT)?)
                .ok_or_else(|| Halt::Unavailable("cgroup.events malformed".to_string()))?;
            frozen_after = Some(events.1);
        }
        // Step 7: b and the window bound.
        let started = self.started.ok_or_else(|| Halt::Unavailable("no window".to_string()))?;
        let elapsed = u64::try_from(self.kernel.now().saturating_duration_since(started).as_millis()).unwrap_or(u64::MAX);
        if elapsed > WINDOW_MS {
            return unavailable("inspection window exceeded");
        }
        let b = a.saturating_add(elapsed);
        let d = enrolled.expires_at.saturating_mul(1_000).min(a.saturating_add(DEADLINE_MS));
        // The value.
        let mut value = self.common(role, a, b, d)?;
        let cgroup_value = |path: bool| {
            let mut members = Vec::new();
            if path {
                members.push(("path", Value::str(&cgroup_path)));
            }
            members.extend([("inode", number(inode)), ("memoryMaxBytes", number(memory)), ("pidsMax", number(cgroup_pids_max)),
                            ("cpuQuotaMicros", number(quota)), ("cpuPeriodMicros", number(period))]);
            object(members)
        };
        if own {
            value.push(("process", object(vec![("cgroup", cgroup_value(false))])));
            value.push(("cgroupMembers", Value::Array(own_members.iter().map(|pid| object(vec![("pid", signed(i64::from(*pid)))]))
                                                          .collect())));
        } else {
            let index = me_index.ok_or_else(|| Halt::Unavailable("no inspected process".to_string()))?;
            let me = members.get(index).ok_or_else(|| Halt::Unavailable("no inspected process".to_string()))?;
            let mut process = vec![
                ("pid", signed(i64::from(me.pid))),
                ("startTicks", number(me.start)),
                ("uid", number(me.status.uid)),
                ("gid", number(me.status.gid)),
                ("processLabel", Value::str(&me.label)),
                ("cgroup", cgroup_value(true)),
                ("seccompMode", number(me.status.seccomp_mode)),
                ("seccompFilters", number(me.status.seccomp_filters)),
                ("ppid", signed(i64::from(me.ppid))),
                ("threadCount", number(me.status.threads)),
                ("threadsUniform", Value::Bool(me.uniform)),
                ("noNewPrivs", number(me.status.no_new_privs)),
                ("capPermitted", strings(&kernel_text::capability_names(me.status.permitted))),
                ("capEffective", strings(&kernel_text::capability_names(me.status.effective))),
                ("capBounding", strings(&kernel_text::capability_names(me.status.bounding))),
                ("capAmbient", strings(&kernel_text::capability_names(me.status.ambient))),
                ("capInheritable", strings(&kernel_text::capability_names(me.status.inheritable))),
            ];
            if observed {
                if let Some((path, device, inode)) = &me.exe {
                    process.push(("exe", object(vec![("path", Value::str(path)), ("device", number(*device)),
                                                     ("inode", number(*inode))])));
                }
                if let Some(namespaces) = namespaces {
                    process.push(("namespaceInodes", namespaces));
                }
            }
            value.push(("process", object(process)));
            value.push(("cgroupMembers", Value::Array(members.iter().map(|member| member_row(member, observed)).collect())));
            value.push(("memberSetBefore", member_set_value(&members_before)));
            value.push(("memberSetAfter", member_set_value(&members_after)));
        }
        value.push(("files", Value::Array(files)));
        if let Some(maps) = first_maps {
            value.push(("executableMaps", Value::Array(maps.iter().map(|mapping| object(vec![
                ("path", Value::str(&mapping.path)),
                ("offset", number(mapping.offset)),
                ("length", number(mapping.length)),
                ("permissions", Value::str(&mapping.permissions)),
                ("device", number(mapping.device)),
                ("inode", number(mapping.inode)),
            ])).collect())));
        }
        value.push(("bpfPrograms", programs));
        if let (Some(before), Some(after)) = (frozen_before, frozen_after) {
            value.push(("cgroupFrozenBefore", number(before)));
            value.push(("cgroupFrozenAfter", number(after)));
        }
        value.push(("childCgroups", strings(&children)));
        value.push(("descendantCount", number(descendants)));
        value.push(("delegatedChildren", delegated_children));
        value.push(("delegatedServiceMembers", delegated_members));
        value.push(("pidsCurrent", number(current)));
        value.push(("effectiveCensus", census));
        Ok(object(value))
    }
}

/// A member read failing because its process exited is "member gone".
fn member_error(error: ReadError) -> Halt {
    match error {
        ReadError::Gone | ReadError::NotFound => Halt::Unavailable("member gone".to_string()),
        other => Halt::from(other),
    }
}

/// "me": a single-process role's one member (the earliest-started when there are several, which the self-check then
/// refuses); the WORKER's one member whose parent is not a member (none or several: unavailable).
fn inspected(role: &str, members: &[Member]) -> Option<usize> {
    if role == "WORKER" {
        let roots: Vec<usize> = members
            .iter()
            .enumerate()
            .filter(|(_, member)| !members.iter().any(|other| other.pid == member.ppid))
            .map(|(index, _)| index)
            .collect();
        return (roots.len() == 1).then(|| roots.first().copied()).flatten();
    }
    members.iter().enumerate().min_by_key(|(_, member)| (member.start, member.pid)).map(|(index, _)| index)
}

/// A `cgroupMembers` (or delegated service member) row.
fn member_row(member: &Member, with_exe: bool) -> Value {
    let mut row = vec![
        ("pid", signed(i64::from(member.pid))),
        ("startTicks", number(member.start)),
        ("ppid", signed(i64::from(member.ppid))),
        ("uid", number(member.status.uid)),
        ("processLabel", Value::str(&member.label)),
        ("noNewPrivs", number(member.status.no_new_privs)),
        ("seccompMode", number(member.status.seccomp_mode)),
        ("seccompFilters", number(member.status.seccomp_filters)),
        ("threadCount", number(member.status.threads)),
    ];
    if with_exe {
        if let Some((path, device, inode)) = &member.exe {
            row.push(("exe", object(vec![("path", Value::str(path)), ("device", number(*device)), ("inode", number(*inode))])));
        }
    }
    object(row)
}

/// A member set: `[{pid, startTicks, threads: [{tid, startTicks}]}]` in the order read.
fn member_set_value<P>(members: &[(i32, u64, i32, P, Vec<(i32, u64)>)]) -> Value {
    Value::Array(members.iter().map(|(pid, start, _, _, threads)| object(vec![
        ("pid", signed(i64::from(*pid))),
        ("startTicks", number(*start)),
        ("threads", Value::Array(threads.iter().map(|(tid, start)| object(vec![("tid", signed(i64::from(*tid))),
                                                                                ("startTicks", number(*start))]))
                                 .collect())),
    ])).collect())
}

/// The memo's digest for `path` at `key` (a window's check): another key drops the entry (and a partial of the path).
fn memo_digest<H>(memo: &mut Memo<H>, path: &str, key: Key) -> Result<String, Halt> {
    if memo.partial.as_ref().is_some_and(|partial| partial.path == path && partial.key != key) {
        memo.partial = None;
    }
    match memo.entries.get(path) {
        Some(Entry::Done { key: known, digest }) if *known == key => Ok(digest.clone()),
        Some(Entry::Differs { key: known }) if *known == key => unavailable("file differs from its record row"),
        Some(_) => {
            memo.entries.remove(path);
            unavailable("content digest stale")
        }
        None => unavailable("content digest pending"),
    }
}

/// The host-wide scan: the seven domains' counts and each backend component's candidates.
struct Scan {
    counts: BTreeMap<&'static str, u64>,
    candidates: BTreeMap<String, Vec<(u64, i32)>>,
    over: Vec<String>,
}

impl<K: KernelView> CaptureEngine<K> {
    /// The scan (section 11): a fresh listing; each process's label counted by its type; the backend candidates by
    /// label and cgroup. A refused or vanished process is not counted. A listing error or bound, or the 5 s deadline,
    /// makes the whole scan unavailable.
    fn scan(&mut self) -> Result<Scan, String> {
        let started = self.kernel.now();
        let pids = match self.kernel.processes() {
            Ok(pids) => pids,
            Err(ReadError::Bound) => return Err("process scan bound".to_string()),
            Err(_) => return Err("process scan failed".to_string()),
        };
        let mut counts: BTreeMap<&'static str, u64> = DOMAINS.iter().map(|domain| (*domain, 0)).collect();
        let mut candidates: BTreeMap<String, Vec<(u64, i32)>> = BTreeMap::new();
        let mut over = Vec::new();
        for pid in pids {
            if self.kernel.now().saturating_duration_since(started) > SCAN_DEADLINE {
                return Err("process scan bound".to_string());
            }
            let Ok(process) = self.kernel.process(pid) else { continue };
            let Ok(text) = self.kernel.proc_read(&process, ProcItem::AttrCurrent, PROC_LIMIT) else { continue };
            let Some(label) = kernel_text::label(&text) else { continue };
            if let Some(domain) = kernel_text::label_type(&label).and_then(|kind| DOMAINS.iter().find(|domain| **domain == kind)) {
                if let Some(count) = counts.get_mut(domain) {
                    *count = count.saturating_add(1);
                }
            }
            for backend in self.enrolled.backends.iter().filter(|backend| backend.process_label == label) {
                let Ok(line) = self.kernel.proc_read(&process, ProcItem::Cgroup, PROC_LIMIT) else { continue };
                let Some(path) = kernel_text::cgroup_line(&line) else { continue };
                if path.strip_prefix('/') != Some(backend.cgroup_rel.as_str()) {
                    continue;
                }
                let Ok(stat) = self.kernel.proc_read(&process, ProcItem::Stat, PROC_LIMIT) else { continue };
                let Some(stat) = kernel_text::stat(&stat) else { continue };
                let found = candidates.entry(backend.component.clone()).or_default();
                if found.len() >= MAX_CANDIDATES {
                    if !over.contains(&backend.component) {
                        over.push(backend.component.clone());
                    }
                    continue;
                }
                found.push((stat.start_ticks, pid));
            }
        }
        Ok(Scan { counts, candidates, over })
    }

    /// The lifecycle capture (section 11).
    fn lifecycle(&mut self, scan: &Result<Scan, String>) -> Result<Value, Halt> {
        let now_ms = self.kernel.wall_millis().ok_or_else(|| Halt::Unavailable("wall clock unusable".to_string()))?;
        if now_ms >= self.expires_ms() {
            return Err(Halt::Expired);
        }
        let observed = kernel_text::utc_text(now_ms / 1_000).ok_or_else(|| Halt::Unavailable("wall clock unusable".to_string()))?;
        let marker_path = self.enrolled.seal_marker.clone();
        let mut held = self.kernel.open_enrolled(&marker_path)?;
        let facts = self.kernel.facts(&held)?;
        let mut content = Vec::new();
        loop {
            let count = self.kernel.read_held(&mut held, &mut self.buffer)?;
            if count == 0 {
                break;
            }
            content.extend_from_slice(self.buffer.get(..count).unwrap_or_default());
            if content.len() > MARKER_LIMIT {
                return unavailable("seal marker over 4 KiB");
            }
        }
        let fs_type = self.kernel.run_fs_type(&held)?.ok_or_else(|| Halt::Unavailable("run filesystem not tmpfs".to_string()))?;
        let containment = match self.kernel.cgroup(&self.enrolled.containment_rel) {
            Err(ReadError::NotFound) => "ABSENT",
            Err(other) => return Err(Halt::from(other)),
            Ok(cgroup) => {
                let events = kernel_text::events(&self.kernel.cgroup_read(&cgroup, CgroupItem::Events, CGROUP_LIMIT)?)
                    .ok_or_else(|| Halt::Unavailable("cgroup.events malformed".to_string()))?;
                if events.0 == 0 { "EMPTY" } else { "POPULATED" }
            }
        };
        let slice = self.kernel.cgroup(enrolled::SLICE)?;
        let members = kernel_text::procs(&self.kernel.cgroup_read(&slice, CgroupItem::Procs, PROCS_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("cgroup.procs malformed".to_string()))?;
        if !members.is_empty() {
            return unavailable("process directly in the planeon slice");
        }
        let descendants = kernel_text::descendants(&self.kernel.cgroup_read(&slice, CgroupItem::Stat, CGROUP_LIMIT)?)
            .ok_or_else(|| Halt::Unavailable("cgroup.stat malformed".to_string()))?;
        let mut census: Vec<(String, u64)> = Vec::new();
        let mut queue = vec![(enrolled::SLICE.to_string(), 0usize)];
        while let Some((rel, depth)) = queue.pop() {
            if census.len() >= MAX_CENSUS {
                return unavailable("census over 1,024 entries");
            }
            let cgroup = self.kernel.cgroup(&rel)?;
            let events = kernel_text::events(&self.kernel.cgroup_read(&cgroup, CgroupItem::Events, CGROUP_LIMIT)?)
                .ok_or_else(|| Halt::Unavailable("cgroup.events malformed".to_string()))?;
            for child in self.kernel.children(&cgroup)? {
                if depth >= MAX_CENSUS_DEPTH {
                    return unavailable("census deeper than 8");
                }
                queue.insert(0, (format!("{rel}/{child}"), depth + 1));
            }
            census.push((rel, events.0));
        }
        census.sort();
        let scan = scan.as_ref().map_err(|why| Halt::Unavailable(why.clone()))?;
        let counts = object(DOMAINS.iter().map(|domain| (*domain, number(scan.counts.get(domain).copied().unwrap_or(0)))).collect());
        Ok(object(vec![
            ("schemaVersion", Value::str(capture_check::V4_LIFECYCLE)),
            ("evidenceClass", Value::str("DATA_CHECK_ONLY")),
            ("capturer", Value::str("OBSERVER")),
            ("qualificationDigest", Value::str(self.enrolled.record.digest())),
            ("subject", Value::str("HOST_CONTAINMENT")),
            ("host", self.declared.host.clone()),
            ("observedAt", Value::str(&observed)),
            ("sealMarker", object(vec![("path", Value::str(&marker_path)), ("digest", Value::str(&sha256::prefixed(&content))),
                                       ("uid", number(u64::from(facts.uid))), ("mode", Value::str(&kernel_text::mode_text(facts.mode)))])),
            ("runFsType", Value::str(fs_type)),
            ("cgroup", object(vec![("path", Value::str(&self.enrolled.containment_path)), ("state", Value::str(containment))])),
            ("sliceCgroups", Value::Array(census.iter().map(|(rel, populated)| {
                object(vec![("path", Value::str(&enrolled::cgroup_path(rel))), ("populated", number(*populated))])
            }).collect())),
            ("domainProcessCounts", counts),
            ("booleansObserved", self.declared.booleans.clone()),
            ("sliceMembers", Value::Array(Vec::new())),
            ("sliceDescendants", number(descendants)),
            ("bootEntryObserved", self.declared.boot_entry.clone()),
        ]))
    }

    /// One backend capture (section 12): the earliest candidate by (startTicks, pid), and the measured executable.
    fn backend(&mut self, index: usize, scan: &Result<Scan, String>) -> Result<Value, Halt> {
        let now_ms = self.kernel.wall_millis().ok_or_else(|| Halt::Unavailable("wall clock unusable".to_string()))?;
        if now_ms >= self.expires_ms() {
            return Err(Halt::Expired);
        }
        let observed = kernel_text::utc_text(now_ms / 1_000).ok_or_else(|| Halt::Unavailable("wall clock unusable".to_string()))?;
        let scan = scan.as_ref().map_err(|why| Halt::Unavailable(why.clone()))?;
        let target = self.enrolled.backends.get(index).ok_or_else(|| Halt::Unavailable("no such component".to_string()))?;
        if scan.over.contains(&target.component) {
            return unavailable("backend candidates over 4,096");
        }
        let Some(&(start, pid)) = scan.candidates.get(&target.component).and_then(|found| found.iter().min()) else {
            return unavailable("no candidate process");
        };
        let (component, label, cgroup_path, executable) =
            (target.component.clone(), target.process_label.clone(), target.cgroup_path.clone(), target.executable.clone());
        let row = self.enrolled.backend_rows.get(&executable).ok_or_else(|| Halt::Unavailable("no record row".to_string()))?;
        let held = self.kernel.open_enrolled(&executable)?;
        let facts = self.kernel.facts(&held)?;
        let reply = self.kernel.verity(&held)?;
        let measured = kernel_text::verity_text(reply.algorithm, reply.size, &reply.digest)
            .ok_or_else(|| Halt::Unavailable("verity other than SHA-256".to_string()))?;
        let digest = memo_digest(&mut self.memo, &executable, Key::of(&facts))?;
        if facts.size != row.size {
            return unavailable("file differs from its record row");
        }
        Ok(object(vec![
            ("schemaVersion", Value::str(capture_check::V4_BACKEND)),
            ("evidenceClass", Value::str("DATA_CHECK_ONLY")),
            ("capturer", Value::str("OBSERVER")),
            ("qualificationDigest", Value::str(self.enrolled.record.digest())),
            ("component", Value::str(&component)),
            ("host", self.declared.host.clone()),
            ("observedAt", Value::str(&observed)),
            ("process", object(vec![("pid", signed(i64::from(pid))), ("startTicks", number(start)), ("processLabel", Value::str(&label)),
                                    ("cgroupPath", Value::str(&cgroup_path))])),
            ("executable", object(vec![("path", Value::str(&executable)), ("contentDigest", Value::str(&digest)),
                                       ("measuredVerity", Value::str(&measured))])),
        ]))
    }
}

impl<K: KernelView> CaptureCycle for CaptureEngine<K> {
    fn capture_set(&mut self, scheduled: Instant) {
        let budget_end = scheduled.checked_add(SET_BUDGET).unwrap_or(scheduled);
        let mut view = self.view.clone();
        view.sequence = view.sequence.saturating_add(1);
        let Some(wall) = self.wall() else {
            view.every(&Slot::Unavailable("wall clock unusable".to_string()));
            self.view = view;
            return;
        };
        view.set_started_ms = wall;
        if wall < self.enrolled.valid_from.saturating_mul(1_000) {
            view.every(&Slot::Pending);
            self.view = view;
            return;
        }
        if wall >= self.expires_ms() {
            view.every(&Slot::Expired);
            self.view = view;
            return;
        }
        view.every(&Slot::Unavailable("set budget".to_string()));
        let index_of = |name: &str| ROLES.iter().position(|role| *role == name);
        let worker = index_of("WORKER").unwrap_or(3);
        let mut expired = false;
        // (1) WORKER-FIRST.
        let worker_paths = self.enrolled.roles.get(worker).map(|role| role.paths.clone()).unwrap_or_default();
        let worker_slot = if !self.digests_ready(&worker_paths) {
            Slot::Unavailable("content digest pending".to_string())
        } else if !self.can_start() {
            Slot::Expired
        } else {
            let result = self.role(worker, scheduled, budget_end);
            self.slot(result, Family::Role("WORKER"))
        };
        expired |= worker_slot == Slot::Expired;
        if let Some(slot) = view.roles.get_mut(worker) {
            *slot = worker_slot;
        }
        // (2) The content fill.
        if !expired {
            self.fill(budget_end);
        }
        // (3) The other four roles.
        for name in ["SERVER", "OBSERVER", "BROKER", "EFFECT_GATE"] {
            let Some(index) = index_of(name) else { continue };
            let slot = if expired || !self.can_start() {
                expired = true;
                Slot::Expired
            } else if self.kernel.now() >= budget_end {
                Slot::Unavailable("set budget".to_string())
            } else {
                let result = self.role(index, scheduled, budget_end);
                self.slot(result, Family::Role(ROLES.get(index).copied().unwrap_or("")))
            };
            expired |= slot == Slot::Expired;
            if let Some(stored) = view.roles.get_mut(index) {
                *stored = slot;
            }
        }
        // (4) The scan and the lifecycle capture.
        let scan = if expired || self.kernel.now() >= budget_end { Err("set budget".to_string()) } else { self.scan() };
        view.lifecycle = if expired {
            Slot::Expired
        } else if self.kernel.now() >= budget_end {
            Slot::Unavailable("set budget".to_string())
        } else {
            let result = self.lifecycle(&scan);
            self.slot(result, Family::Lifecycle)
        };
        expired |= view.lifecycle == Slot::Expired;
        // (5) The backend captures.
        for index in 0..self.enrolled.backends.len() {
            let slot = if expired {
                Slot::Expired
            } else if self.kernel.now() >= budget_end {
                Slot::Unavailable("set budget".to_string())
            } else {
                let result = self.backend(index, &scan);
                self.slot(result, Family::Backend)
            };
            expired |= slot == Slot::Expired;
            if let Some((_, stored)) = view.backends.get_mut(index) {
                *stored = slot;
            }
        }
        if expired {
            for role in view.roles.iter_mut() {
                if matches!(role, Slot::Unavailable(why) if why == "set budget") {
                    *role = Slot::Expired;
                }
            }
        }
        self.view = view;
    }

    fn expired_now(&self) -> bool {
        self.kernel.wall_millis().is_none_or(|wall| wall >= self.expires_ms())
    }

    fn expiry_wake(&self) -> Option<Instant> {
        let wall = self.kernel.wall_millis()?;
        let left = self.expires_ms().checked_sub(wall).filter(|left| *left > 0)?;
        self.kernel.now().checked_add(Duration::from_millis(left))
    }

    fn expire(&mut self) {
        self.view.every(&Slot::Expired);
    }

    fn view(&self) -> &CaptureView {
        &self.view
    }
}
