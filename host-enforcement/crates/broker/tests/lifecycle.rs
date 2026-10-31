//! HE-005C (the frozen seam note, sections 3, 4 and 6; delta C3 revision 2; DESIGN-HE005 sections 3.3-3.6): the
//! lifecycle over the seam's fakes and a fake clock, with no real sleep (the 70 s NP-9 hold passes on the fake clock).
//!
//! - Delta C3's three startup-run cases: `startup_run_stops_at_gate_qualification` (C's qualifier stand-in: nothing
//!   written, nothing spawned, `Unavailable` at step 2); a success qualifier fake with C's real `Binder` stand-in (W3
//!   reached, W6 with no thaw: the child killed, the leaf shown empty, `Unavailable`, C3-7); success fakes through W1-W6.
//! - Every W-step's failure path, HOLD at start and after a W6 that cannot show the leaf empty, and
//!   `w6_bound_expiry_ends_held_with_standing_hold` as seam section 6 states it.
//! - NP-9's bracket, its skip and its timing.

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;

use broker_sys::LeafWrite::{Freeze, Kill, Thaw};
use broker_sys::{FdEntry, FdIdentity, LeafWrite, Reaped, W3Expect};
use i05_protocol::json::Doc;
use planeon_broker::config::{BrokerConfig, FORMAT};
use planeon_broker::lifecycle::hold::{derive, Standing};
use planeon_broker::lifecycle::leaf::membership;
use planeon_broker::lifecycle::np9::{bracket, Bracket, Skip, NP9_HOLD_MS, NP9_RESERVE_MS};
use planeon_broker::lifecycle::ops::{Clock, LeafFile, LeafOps, ProcFile, SpawnOps};
use planeon_broker::lifecycle::outcome::{Outcome, Step};
use planeon_broker::lifecycle::run::startup;
use planeon_broker::lifecycle::seams::{BindAnswer, BindTicket, Binder, BinderStandIn, GateAnswer, GateQualifier, GateTicket,
                                       QualifierStandIn};
use planeon_broker::lifecycle::text::BROKER_LABEL;
use planeon_broker::lifecycle::w6::{sequence, W6End};
use planeon_broker::lifecycle::wait::FREEZE_WAIT_MS;

const PID: i32 = 4242;
const SCRIPT: u32 = 7;
const CHILD_END: u32 = 11;
const START_TICKS: u64 = 123_456;
const DIGEST: [u8; 32] = [0x5a; 32];
/// operationDeadlineSeconds (900) from the run's start at 0.
const DEADLINE_MS: u64 = 900_000;
/// W6_BOUND_MS (w6.rs).
const W6_BOUND: u64 = 10_000;
const CHAR_DEVICE: u32 = 0o020000;
const SOCKET: u32 = 0o140000;
const REGULAR: u32 = 0o100000;
const DIRECTORY: u32 = 0o040000;

/// The signed configuration the runs read: the verity digest is DIGEST's, the deadline 900 s.
fn config() -> BrokerConfig {
    let pin = |digit: char| Doc::str(&format!("sha256:{}", digit.to_string().repeat(64)));
    let document = Doc::object(vec![
        ("format", Doc::str(FORMAT)),
        ("workerUid", Doc::Int(10_001)),
        ("workerScriptPath", Doc::str("/usr/lib/planeon/worker/probe.py")),
        ("workerScriptVerityDigest", Doc::str(&format!("sha256:{}", "5a".repeat(32)))),
        ("workerInterpreterPath", Doc::str("/usr/bin/python3.12")),
        ("gateExecutablePath", Doc::str("/usr/lib/planeon/planeon-gate")),
        ("peerQualificationDigest", pin('e')),
        ("bracketPeriodSeconds", Doc::Int(600)),
        ("operationDeadlineSeconds", Doc::Int(900)),
        ("brokerManifestDigest", pin('1')),
        ("brokerExecutableDigest", pin('2')),
        ("workerManifestDigest", pin('3')),
        ("workerArtifactDigest", pin('4')),
    ]);
    BrokerConfig::parse(&document.canonical()).expect("the test configuration")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpawnFault {
    Open,
    Measure,
    Algorithm,
    Digest,
    Pair,
    Plan,
    Spawn,
    MaskNotRestored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcFault {
    Read,
    Cgroup,
    Uid,
    Gid,
    Groups,
    Label,
    StatShape,
    StatPid,
    Table,
    StdioSocket,
    StdioAbsent,
    ChannelSource,
    ScriptSource,
}

/// What the fakes share: the leaf and the child, the planted faults, and the record of writes and reads.
struct World {
    now: Rc<Cell<u64>>,
    frozen: bool,
    child_alive: bool,
    /// A process the kill never removes: the leaf shows populated.
    stuck: bool,
    leaf_type: &'static [u8],
    /// cgroup.procs lists a pid although cgroup.events reads populated 0.
    procs_listed: bool,
    /// The Freeze writes (by their order, from 0) that do not take effect.
    freeze_ignored: Vec<usize>,
    /// A Freeze write leaves a process in the leaf.
    stuck_on_freeze: bool,
    /// A Kill write removes nothing.
    kill_ignored: bool,
    read_fails: Vec<LeafFile>,
    /// The cgroup.events reads (by their order, from 1) that fail.
    events_fail: Vec<usize>,
    events_reads: usize,
    /// The writes (kind, order from 0) that fail, with no effect.
    write_fails: Vec<(LeafWrite, usize)>,
    write_counts: [usize; 3],
    /// The worker exits by itself at this time, unless the leaf holds it frozen.
    exit_at: Option<u64>,
    exited: Option<Reaped>,
    reaped: bool,
    reap_never: bool,
    spawned: usize,
    spawn_fault: Option<SpawnFault>,
    proc_fault: Option<ProcFault>,
    writes: Vec<(LeafWrite, u64)>,
    checks: Vec<u64>,
    reap_calls: Vec<u64>,
    measured: Option<u32>,
    planned: Option<(u32, u32, u32)>,
    qualified: usize,
}

impl World {
    fn new() -> World {
        World {
            now: Rc::new(Cell::new(0)),
            frozen: false,
            child_alive: false,
            stuck: false,
            leaf_type: b"domain\n",
            procs_listed: false,
            freeze_ignored: Vec::new(),
            stuck_on_freeze: false,
            kill_ignored: false,
            read_fails: Vec::new(),
            events_fail: Vec::new(),
            events_reads: 0,
            write_fails: Vec::new(),
            write_counts: [0; 3],
            exit_at: None,
            exited: None,
            reaped: false,
            reap_never: false,
            spawned: 0,
            spawn_fault: None,
            proc_fault: None,
            writes: Vec::new(),
            checks: Vec::new(),
            reap_calls: Vec::new(),
            measured: None,
            planned: None,
            qualified: 0,
        }
    }

    fn populated(&self) -> bool {
        self.child_alive || self.stuck
    }

    /// A worker whose exit time has come exits by itself, unless the leaf holds it frozen.
    fn settle(&mut self) {
        if self.child_alive && !self.frozen && self.exit_at.is_some_and(|at| self.now.get() >= at) {
            self.child_alive = false;
            self.exited = Some(Reaped::Exited(0));
        }
    }

    fn writes(&self) -> Vec<LeafWrite> {
        self.writes.iter().map(|(what, _)| *what).collect()
    }
}

type Shared = Rc<RefCell<World>>;

fn shared(build: impl FnOnce(&mut World)) -> Shared {
    let mut world = World::new();
    build(&mut world);
    Rc::new(RefCell::new(world))
}

fn failed() -> io::Error {
    io::Error::other("a planted failure")
}

fn kind(what: LeafWrite) -> usize {
    match what {
        LeafWrite::Freeze => 0,
        LeafWrite::Thaw => 1,
        LeafWrite::Kill => 2,
    }
}

struct FakeLeaf(Shared);

impl LeafOps for FakeLeaf {
    fn read(&mut self, file: LeafFile) -> io::Result<Vec<u8>> {
        let mut world = self.0.borrow_mut();
        world.settle();
        let now = world.now.get();
        world.checks.push(now);
        if world.read_fails.contains(&file) {
            return Err(failed());
        }
        match file {
            LeafFile::Type => Ok(world.leaf_type.to_vec()),
            LeafFile::Events => {
                world.events_reads += 1;
                if world.events_fail.contains(&world.events_reads) {
                    return Err(failed());
                }
                Ok(format!("populated {}\nfrozen {}\n", u8::from(world.populated()), u8::from(world.frozen)).into_bytes())
            }
            LeafFile::Procs => {
                Ok(if world.populated() || world.procs_listed { format!("{}\n", PID).into_bytes() } else { Vec::new() })
            }
        }
    }

    fn write(&mut self, what: LeafWrite) -> io::Result<()> {
        let mut world = self.0.borrow_mut();
        let now = world.now.get();
        world.writes.push((what, now));
        let nth = world.write_counts[kind(what)];
        world.write_counts[kind(what)] += 1;
        if world.write_fails.contains(&(what, nth)) {
            return Err(failed());
        }
        match what {
            LeafWrite::Freeze => {
                if !world.freeze_ignored.contains(&nth) {
                    world.frozen = true;
                }
                if world.stuck_on_freeze {
                    world.stuck = true;
                }
            }
            LeafWrite::Thaw => world.frozen = false,
            LeafWrite::Kill => {
                if world.child_alive && !world.kill_ignored {
                    world.child_alive = false;
                    world.exited = Some(Reaped::Killed(9));
                }
            }
        }
        Ok(())
    }
}

/// A `stat` line for `pid`, with START_TICKS as field 22.
fn stat_line(pid: i32) -> Vec<u8> {
    let mut fields = vec!["S".to_string()];
    fields.extend((4..=21).map(|field: u32| field.to_string()));
    fields.push(START_TICKS.to_string());
    fields.extend((23..=52).map(|field: u32| field.to_string()));
    format!("{} (planeon-broker) {}\n", pid, fields.join(" ")).into_bytes()
}

struct FakeSpawn(Shared);

impl FakeSpawn {
    fn fault(&self, fault: SpawnFault) -> bool {
        self.0.borrow().spawn_fault == Some(fault)
    }
}

impl SpawnOps for FakeSpawn {
    type Script = u32;
    type ChannelEnd = u32;
    type Plan = u32;
    type Child = i32;

    fn open_script(&mut self) -> io::Result<u32> {
        if self.fault(SpawnFault::Open) { Err(failed()) } else { Ok(SCRIPT) }
    }

    fn measure(&mut self, script: &u32) -> io::Result<(u16, [u8; 32])> {
        self.0.borrow_mut().measured = Some(*script);
        let fault = self.0.borrow().spawn_fault;
        match fault {
            Some(SpawnFault::Measure) => Err(failed()),
            Some(SpawnFault::Algorithm) => Ok((2, DIGEST)),
            Some(SpawnFault::Digest) => Ok((1, [0; 32])),
            _ => Ok((1, DIGEST)),
        }
    }

    fn channel_pair(&mut self) -> io::Result<(u32, u32)> {
        if self.fault(SpawnFault::Pair) { Err(failed()) } else { Ok((10, CHILD_END)) }
    }

    fn plan(&mut self, worker_uid: u32, child_end: u32, script: u32) -> io::Result<(u32, W3Expect)> {
        self.0.borrow_mut().planned = Some((worker_uid, child_end, script));
        if self.fault(SpawnFault::Plan) {
            return Err(failed());
        }
        Ok((99, W3Expect { channel: FdIdentity { number: 5, dev: 1, ino: 100 }, script: FdIdentity { number: 6, dev: 2, ino: 200 } }))
    }

    fn spawn(&mut self, plan: u32) -> io::Result<i32> {
        assert_eq!(plan, 99);
        if self.fault(SpawnFault::Spawn) {
            return Err(failed());
        }
        let mut world = self.0.borrow_mut();
        world.spawned += 1;
        world.child_alive = true;
        Ok(PID)
    }

    fn child_pid(&self, child: &i32) -> i32 {
        *child
    }

    fn mask_restored(&self, _child: &i32) -> bool {
        !self.fault(SpawnFault::MaskNotRestored)
    }

    fn proc_read(&mut self, _child: &i32, file: ProcFile) -> io::Result<Vec<u8>> {
        let fault = self.0.borrow().proc_fault;
        if fault == Some(ProcFault::Read) {
            return Err(failed());
        }
        let has = |planted: ProcFault| fault == Some(planted);
        Ok(match file {
            ProcFile::Cgroup if has(ProcFault::Cgroup) => b"0::/planeon.slice/elsewhere\n".to_vec(),
            ProcFile::Cgroup => format!("0::{}\n", membership()).into_bytes(),
            ProcFile::Status => {
                let uid = if has(ProcFault::Uid) { "0\t10001\t0\t0" } else { "0\t0\t0\t0" };
                let gid = if has(ProcFault::Gid) { "0\t0\t0\t10001" } else { "0\t0\t0\t0" };
                let groups = if has(ProcFault::Groups) { "10" } else { "" };
                format!("Name:\tplaneon-broker\nUid:\t{uid}\nGid:\t{gid}\nGroups:\t{groups}\nNSpid:\t{}\n", PID).into_bytes()
            }
            ProcFile::AttrCurrent if has(ProcFault::Label) => b"system_u:system_r:planeon_worker_t:s0\0".to_vec(),
            ProcFile::AttrCurrent => [BROKER_LABEL.as_bytes(), b"\0".as_slice()].concat(),
            ProcFile::Stat if has(ProcFault::StatShape) => b"4242 planeon-broker S\n".to_vec(),
            ProcFile::Stat => stat_line(if has(ProcFault::StatPid) { PID + 1 } else { PID }),
        })
    }

    fn fd_table(&mut self, _child: &i32) -> io::Result<Vec<FdEntry>> {
        let fault = self.0.borrow().proc_fault;
        if fault == Some(ProcFault::Table) {
            return Err(failed());
        }
        let entry = |number, dev, ino, mode| FdEntry { number, dev, ino, mode };
        let mut table = vec![entry(6, 2, 200, REGULAR), entry(0, 9, 1, CHAR_DEVICE), entry(5, 1, 100, SOCKET),
                             entry(2, 9, 1, CHAR_DEVICE), entry(1, 9, 1, CHAR_DEVICE), entry(8, 3, 300, DIRECTORY)];
        match fault {
            Some(ProcFault::StdioSocket) => table[4].mode = SOCKET,
            Some(ProcFault::StdioAbsent) => {
                table.remove(3);
            }
            Some(ProcFault::ChannelSource) => table[2].ino = 101,
            Some(ProcFault::ScriptSource) => table[0].dev = 3,
            _ => {}
        }
        Ok(table)
    }

    fn reap(&mut self, _child: &i32) -> io::Result<Option<Reaped>> {
        let mut world = self.0.borrow_mut();
        world.settle();
        let now = world.now.get();
        world.reap_calls.push(now);
        if world.reap_never || world.reaped {
            return Ok(None);
        }
        let exited = world.exited;
        if exited.is_some() {
            world.reaped = true;
        }
        Ok(exited)
    }
}

/// The fake clock: a sleep moves it by the time asked and `overshoot`; with `fail_sleep`, by about half and an error.
struct FakeClock {
    now: Rc<Cell<u64>>,
    overshoot: u64,
    fail_sleep: bool,
}

impl FakeClock {
    fn of(world: &Shared) -> FakeClock {
        FakeClock { now: world.borrow().now.clone(), overshoot: 0, fail_sleep: false }
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }

    fn sleep_ms(&self, ms: u32) -> io::Result<()> {
        if self.fail_sleep {
            self.now.set(self.now.get() + u64::from(ms) / 2 + 1);
            return Err(failed());
        }
        self.now.set(self.now.get() + u64::from(ms) + self.overshoot);
        Ok(())
    }
}

/// A qualifier fake that qualifies the gate, counting its calls.
struct Qualifies(Shared);

impl GateQualifier for Qualifies {
    fn qualify(&mut self) -> GateAnswer {
        self.0.borrow_mut().qualified += 1;
        GateAnswer::Qualified(GateTicket { generation: 7 })
    }
}

/// A binder fake that accepts the child it is given.
struct Binds;

impl Binder for Binds {
    fn bind(&mut self, gate: &GateTicket, pid: i32, start_ticks: u64) -> BindAnswer {
        assert_eq!((gate.generation, pid, start_ticks), (7, PID, START_TICKS));
        BindAnswer::Bound(BindTicket { pid, start_ticks })
    }
}

/// A binder fake that accepts another child.
struct BindsAnother;

impl Binder for BindsAnother {
    fn bind(&mut self, _gate: &GateTicket, pid: i32, start_ticks: u64) -> BindAnswer {
        BindAnswer::Bound(BindTicket { pid: pid + 1, start_ticks })
    }
}

fn run<Q: GateQualifier, B: Binder>(world: &Shared, clock: &FakeClock, qualifier: Q, binder: B, standing: &mut Standing<i32>)
    -> Outcome {
    startup(&mut FakeLeaf(world.clone()), &mut FakeSpawn(world.clone()), clock, qualifier, binder, &config(), standing)
}

/// A run with success fakes for both seams, from a fresh standing state.
fn succeed(world: &Shared) -> (Outcome, Standing<i32>) {
    let mut standing = Standing::new();
    let outcome = run(world, &FakeClock::of(world), Qualifies(world.clone()), Binds, &mut standing);
    (outcome, standing)
}

#[test]
fn startup_run_stops_at_gate_qualification() {
    let world = shared(|_| {});
    let mut standing = Standing::new();
    let outcome = run(&world, &FakeClock::of(&world), QualifierStandIn, BinderStandIn, &mut standing);
    assert_eq!(outcome, Outcome::Unavailable);
    let world = world.borrow();
    assert!(world.writes.is_empty() && world.checks.is_empty());
    assert_eq!((world.spawned, world.measured, world.planned), (0, None, None));
    assert_eq!(standing.held(), None);
}

#[test]
fn startup_run_with_the_binder_stand_in_ends_unavailable_through_w6_with_no_thaw() {
    let world = shared(|_| {});
    let mut standing = Standing::new();
    let outcome = run(&world, &FakeClock::of(&world), Qualifies(world.clone()), BinderStandIn, &mut standing);
    assert_eq!(outcome, Outcome::Unavailable);
    let world = world.borrow();
    // W1's freeze, then W6's freeze, kill and release: W4's thaw is never written (H5D-10).
    assert_eq!(world.writes(), [Freeze, Freeze, Kill, Thaw]);
    assert_eq!((world.spawned, world.exited, world.reaped), (1, Some(Reaped::Killed(9)), true));
    assert_eq!((standing.held(), standing.kept_children()), (None, 0));
}

#[test]
fn startup_run_with_success_fakes_brackets_once_and_ends_at_the_workers_end() {
    let world = shared(|world| world.exit_at = Some(100_000));
    let (outcome, standing) = succeed(&world);
    assert_eq!(outcome, Outcome::Ended(Reaped::Exited(0)));
    let world = world.borrow();
    // W1's freeze, W4's thaw, NP-9's freeze and thaw, then W6.
    assert_eq!(world.writes(), [Freeze, Thaw, Freeze, Thaw, Freeze, Kill, Thaw]);
    let times: Vec<u64> = world.writes.iter().map(|(_, at)| *at).collect();
    assert_eq!(times[..4], [0, 0, 0, NP9_HOLD_MS]);
    assert!(times[4] >= 100_000);
    // G-HE5C-4's agent half: the measured script is the one the plan takes, with the signed uid and the child end.
    assert_eq!((world.measured, world.planned), (Some(SCRIPT), Some((10_001, CHILD_END, SCRIPT))));
    assert_eq!((world.qualified, world.spawned, world.reaped), (1, 1, true));
    assert_eq!(standing.held(), None);
}

#[test]
fn the_operation_deadline_after_w4_ends_through_w6_with_the_worker_killed() {
    let world = shared(|_| {});
    let (outcome, standing) = succeed(&world);
    assert_eq!(outcome, Outcome::Ended(Reaped::Killed(9)));
    let world = world.borrow();
    assert_eq!(world.writes(), [Freeze, Thaw, Freeze, Thaw, Freeze, Kill, Thaw]);
    assert_eq!(world.writes[4].1, DEADLINE_MS);
    assert_eq!(standing.held(), None);
}

#[test]
fn hold_at_start_ends_the_run_at_step_one() {
    let cases: [(fn(&mut World), Step); 3] = [
        (|world: &mut World| world.stuck = true, Step::HoldPopulated),
        (|world: &mut World| world.frozen = true, Step::HoldFrozen),
        (|world: &mut World| world.read_fails = vec![LeafFile::Events], Step::HoldRead),
    ];
    for (build, step) in cases {
        let world = shared(build);
        assert_eq!(derive(&mut FakeLeaf(world.clone()), false), Some(step));
        let mut standing = Standing::new();
        standing.hold(step);
        let outcome = run(&world, &FakeClock::of(&world), Qualifies(world.clone()), Binds, &mut standing);
        assert_eq!(outcome, Outcome::CapacityHeld(step));
        let world = world.borrow();
        assert!(world.writes.is_empty(), "{step:?}");
        assert_eq!((world.qualified, world.spawned), (0, 0), "{step:?}");
    }
    // The standing flag over an empty, unfrozen leaf is HOLD too (SM-R3-1); with no flag, no HOLD.
    let world = shared(|_| {});
    assert_eq!(derive(&mut FakeLeaf(world.clone()), true), Some(Step::HoldStanding));
    assert_eq!(derive(&mut FakeLeaf(world.clone()), false), None);
    assert!(world.borrow().writes.is_empty());
}

#[test]
fn the_derivation_before_w1_holds_a_populated_leaf() {
    let world = shared(|world| world.stuck = true);
    let (outcome, standing) = succeed(&world);
    assert_eq!(outcome, Outcome::CapacityHeld(Step::HoldPopulated));
    let world = world.borrow();
    assert_eq!((world.measured, world.spawned, world.writes.len()), (Some(SCRIPT), 0, 0));
    assert_eq!(standing.held(), Some(Step::HoldPopulated));
}

#[test]
fn every_w5_failure_spawns_nothing_and_leaves_the_leaf_untouched() {
    for (fault, step) in [(SpawnFault::Open, Step::W5Open), (SpawnFault::Measure, Step::W5Measure),
                          (SpawnFault::Algorithm, Step::W5Compare), (SpawnFault::Digest, Step::W5Compare),
                          (SpawnFault::Pair, Step::Pair)] {
        let world = shared(|world| world.spawn_fault = Some(fault));
        let (outcome, standing) = succeed(&world);
        assert_eq!(outcome, Outcome::NotSpawned(step), "{fault:?}");
        let world = world.borrow();
        assert!(world.writes.is_empty() && world.checks.is_empty(), "{fault:?}");
        assert_eq!((world.spawned, standing.held()), (0, None), "{fault:?}");
    }
}

#[test]
fn every_w1_failure() {
    // Before the freeze: nothing written.
    let cases: [(fn(&mut World), Step); 3] = [
        (|world: &mut World| world.read_fails = vec![LeafFile::Type], Step::W1Read),
        (|world: &mut World| world.leaf_type = b"threaded\n", Step::W1NotEmpty),
        (|world: &mut World| world.procs_listed = true, Step::W1NotEmpty),
    ];
    for (build, step) in cases {
        let world = shared(build);
        let (outcome, standing) = succeed(&world);
        assert_eq!(outcome, Outcome::NotSpawned(step));
        assert!(world.borrow().writes.is_empty(), "{step:?}");
        assert_eq!(standing.held(), None);
    }
    // A failed freeze write: the failure path re-reads populated 0, then thaws the empty leaf.
    let world = shared(|world| world.write_fails = vec![(Freeze, 0)]);
    assert_eq!(succeed(&world).0, Outcome::NotSpawned(Step::W1Freeze));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw]);
    // frozen 1 not reached: the wait runs to its bound, never past it.
    let world = shared(|world| world.freeze_ignored = vec![0]);
    assert_eq!(succeed(&world).0, Outcome::NotSpawned(Step::W1NotFrozen));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw]);
    assert_eq!(world.borrow().now.get(), FREEZE_WAIT_MS);
    assert!(world.borrow().checks.iter().all(|at| *at <= FREEZE_WAIT_MS));
    // Every sleep failing: each counts as an early wake, and the wait still ends at its bound.
    let world = shared(|world| world.freeze_ignored = vec![0]);
    let clock = FakeClock { fail_sleep: true, ..FakeClock::of(&world) };
    let mut standing = Standing::new();
    assert_eq!(run(&world, &clock, Qualifies(world.clone()), Binds, &mut standing), Outcome::NotSpawned(Step::W1NotFrozen));
    assert!(world.borrow().checks.iter().all(|at| *at <= FREEZE_WAIT_MS));
    // A read failure in the wait (the third cgroup.events read), then an empty re-read: thawed.
    let world = shared(|world| world.events_fail = vec![3]);
    assert_eq!(succeed(&world).0, Outcome::NotSpawned(Step::W1Read));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw]);
    // The re-read not populated 0: no thaw, CapacityHeld, the standing HOLD.
    let world = shared(|world| {
        world.freeze_ignored = vec![0];
        world.stuck_on_freeze = true;
    });
    let (outcome, standing) = succeed(&world);
    assert_eq!(outcome, Outcome::CapacityHeld(Step::W1NotEmptyOnReread));
    assert_eq!(world.borrow().writes(), [Freeze]);
    assert_eq!(standing.held(), Some(Step::W1NotEmptyOnReread));
    // The re-read failing: the same.
    let world = shared(|world| world.events_fail = vec![3, 4]);
    let (outcome, standing) = succeed(&world);
    assert_eq!(outcome, Outcome::CapacityHeld(Step::W1NotEmptyOnReread));
    assert_eq!(world.borrow().writes(), [Freeze]);
    assert_eq!(standing.held(), Some(Step::W1NotEmptyOnReread));
    // The failure-thaw failing: CapacityHeld, the standing HOLD.
    let world = shared(|world| {
        world.freeze_ignored = vec![0];
        world.write_fails = vec![(Thaw, 0)];
    });
    let (outcome, standing) = succeed(&world);
    assert_eq!(outcome, Outcome::CapacityHeld(Step::W1FailThaw));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw]);
    assert_eq!(standing.held(), Some(Step::W1FailThaw));
}

#[test]
fn every_w2_failure_goes_through_w6() {
    for (fault, step, spawned) in [(SpawnFault::Plan, Step::W2Spawn, 0), (SpawnFault::Spawn, Step::W2Spawn, 0),
                                   (SpawnFault::MaskNotRestored, Step::W2MaskRestore, 1)] {
        let world = shared(|world| world.spawn_fault = Some(fault));
        let (outcome, standing) = succeed(&world);
        assert_eq!(outcome, Outcome::Cleaned(step), "{fault:?}");
        let world = world.borrow();
        assert_eq!(world.writes(), [Freeze, Freeze, Kill, Thaw], "{fault:?}");
        assert_eq!((world.spawned, world.reaped), (spawned, spawned == 1), "{fault:?}");
        assert_eq!(world.reap_calls.is_empty(), spawned == 0, "{fault:?}");
        assert_eq!(standing.held(), None);
    }
}

#[test]
fn every_w3_failure_goes_through_w6_with_no_thaw_before_it() {
    for (fault, step) in [(ProcFault::Read, Step::W3Read), (ProcFault::Cgroup, Step::W3Membership),
                          (ProcFault::Uid, Step::W3Credentials), (ProcFault::Gid, Step::W3Credentials),
                          (ProcFault::Groups, Step::W3Groups), (ProcFault::Label, Step::W3Label),
                          (ProcFault::StatShape, Step::W3Read), (ProcFault::StatPid, Step::W3Membership),
                          (ProcFault::Table, Step::W3Read), (ProcFault::StdioSocket, Step::W3Descriptors),
                          (ProcFault::StdioAbsent, Step::W3Descriptors), (ProcFault::ChannelSource, Step::W3Descriptors),
                          (ProcFault::ScriptSource, Step::W3Descriptors)] {
        let world = shared(|world| world.proc_fault = Some(fault));
        let (outcome, standing) = succeed(&world);
        assert_eq!(outcome, Outcome::Cleaned(step), "{fault:?}");
        let world = world.borrow();
        assert_eq!(world.writes(), [Freeze, Freeze, Kill, Thaw], "{fault:?}");
        assert_eq!((world.exited, world.reaped), (Some(Reaped::Killed(9)), true), "{fault:?}");
        assert_eq!(standing.held(), None);
    }
}

#[test]
fn a_bind_for_another_child_and_a_failed_w4_thaw_go_through_w6() {
    let world = shared(|_| {});
    let mut standing = Standing::new();
    let outcome = run(&world, &FakeClock::of(&world), Qualifies(world.clone()), BindsAnother, &mut standing);
    assert_eq!(outcome, Outcome::Cleaned(Step::Bind));
    assert_eq!(world.borrow().writes(), [Freeze, Freeze, Kill, Thaw]);
    // W4's thaw fails: the child may run, so W6 follows like any failure from step 5 on.
    let world = shared(|world| world.write_fails = vec![(Thaw, 0)]);
    assert_eq!(succeed(&world).0, Outcome::Cleaned(Step::W4Thaw));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw, Freeze, Kill, Thaw]);
}

#[test]
fn every_np9_failure_goes_through_w6_and_an_unreached_freeze_is_skipped() {
    // The bracket's freeze write (the second Freeze).
    let world = shared(|world| world.write_fails = vec![(Freeze, 1)]);
    assert_eq!(succeed(&world).0, Outcome::Cleaned(Step::Np9Freeze));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw, Freeze, Freeze, Kill, Thaw]);
    // Its cgroup.events read (the fourth: the derivation, W1's check, W1's wait, then the bracket's).
    let world = shared(|world| world.events_fail = vec![4]);
    assert_eq!(succeed(&world).0, Outcome::Cleaned(Step::Np9Events));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw, Freeze, Freeze, Kill, Thaw]);
    // Its thaw (the second Thaw; W4's is the first).
    let world = shared(|world| world.write_fails = vec![(Thaw, 1)]);
    assert_eq!(succeed(&world).0, Outcome::Cleaned(Step::Np9Thaw));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw, Freeze, Thaw, Freeze, Kill, Thaw]);
    // frozen 1 not reached in time: the bracket thaws only its own freeze, and the run goes on to the worker's end.
    let world = shared(|world| {
        world.freeze_ignored = vec![1];
        world.exit_at = Some(100_000);
    });
    assert_eq!(succeed(&world).0, Outcome::Ended(Reaped::Exited(0)));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw, Freeze, Thaw, Freeze, Kill, Thaw]);
}

#[test]
fn np9_bracket_holds_seventy_seconds_skips_when_late_and_never_thaws_past_the_deadline() {
    // Taken: the thaw lands NP9_HOLD_MS after the frozen read, on the fake clock.
    let world = shared(|_| {});
    let outcome = bracket(&mut FakeLeaf(world.clone()), &FakeClock::of(&world), DEADLINE_MS);
    assert_eq!(outcome, Bracket::Taken { frozen_ms: 0, thawed_ms: NP9_HOLD_MS });
    assert_eq!(world.borrow().writes(), [Freeze, Thaw]);
    // Exactly the hold and the reserve left: taken. One millisecond less: skipped, with nothing written or read.
    let world = shared(|_| {});
    let outcome = bracket(&mut FakeLeaf(world.clone()), &FakeClock::of(&world), NP9_HOLD_MS + NP9_RESERVE_MS);
    assert!(matches!(outcome, Bracket::Taken { .. }));
    let world = shared(|_| {});
    let outcome = bracket(&mut FakeLeaf(world.clone()), &FakeClock::of(&world), NP9_HOLD_MS + NP9_RESERVE_MS - 1);
    assert_eq!(outcome, Bracket::Skipped(Skip::Remaining));
    assert!(world.borrow().writes.is_empty() && world.borrow().checks.is_empty());
    // frozen 1 not reached within FREEZE_WAIT_MS: its own freeze thawed, at the wait's bound.
    let world = shared(|world| world.freeze_ignored = vec![0]);
    let outcome = bracket(&mut FakeLeaf(world.clone()), &FakeClock::of(&world), DEADLINE_MS);
    assert_eq!(outcome, Bracket::Skipped(Skip::NotFrozen));
    assert_eq!(world.borrow().writes(), [Freeze, Thaw]);
    assert_eq!(world.borrow().writes[1].1, FREEZE_WAIT_MS);
    // A cgroup.events read error in the wait: Np9Events, no thaw (W6 follows).
    let world = shared(|world| world.events_fail = vec![1]);
    let outcome = bracket(&mut FakeLeaf(world.clone()), &FakeClock::of(&world), DEADLINE_MS);
    assert_eq!(outcome, Bracket::Failed(Step::Np9Events));
    assert_eq!(world.borrow().writes(), [Freeze]);
    // The deadline reached inside the bracket: no thaw (O9), W6 follows.
    let world = shared(|_| {});
    let clock = FakeClock { overshoot: DEADLINE_MS, ..FakeClock::of(&world) };
    assert_eq!(bracket(&mut FakeLeaf(world.clone()), &clock, DEADLINE_MS), Bracket::Expired);
    assert_eq!(world.borrow().writes(), [Freeze]);
}

#[test]
fn w6_bound_expiry_ends_held_with_standing_hold() {
    // W6 is entered at operationDeadlineSeconds after W4 (the worker never ends by itself). The leaf never shows
    // empty (the kill takes nothing), and, separately, the reap never completes.
    let cases: [(fn(&mut World), Step, Step); 2] = [
        (|world: &mut World| world.kill_ignored = true, Step::W6NotEmpty, Step::HoldPopulated),
        (|world: &mut World| world.reap_never = true, Step::W6Reap, Step::HoldFrozen),
    ];
    for (build, end, next) in cases {
        let world = shared(build);
        let (outcome, mut standing) = succeed(&world);
        assert_eq!(outcome, Outcome::Held(end));
        {
            let world = world.borrow();
            // W1's freeze, W4's thaw, NP-9's bracket, then W6's freeze and kill at its entry, and no write after them.
            assert_eq!(world.writes(), [Freeze, Thaw, Freeze, Thaw, Freeze, Kill], "{end:?}");
            let entry = world.writes[4].1;
            assert_eq!(entry, DEADLINE_MS, "{end:?}");
            // The waits ran to W6's entry plus W6_BOUND_MS, with no check after it.
            let bound = entry + W6_BOUND;
            assert_eq!(world.now.get(), bound, "{end:?}");
            let last = world.checks.iter().chain(world.reap_calls.iter()).max().copied();
            assert_eq!(last, Some(bound), "{end:?}");
        }
        // The standing flag set and the child kept; the next derivation is HOLD.
        assert_eq!((standing.held(), standing.kept_children()), (Some(end), 1), "{end:?}");
        assert_eq!(derive(&mut FakeLeaf(world.clone()), standing.held().is_some()), Some(next), "{end:?}");
        // The next run gives CapacityHeld at step 1, and no leaf write follows.
        let writes = world.borrow().writes.len();
        let outcome = run(&world, &FakeClock::of(&world), Qualifies(world.clone()), Binds, &mut standing);
        assert_eq!(outcome, Outcome::CapacityHeld(end), "{end:?}");
        assert_eq!(world.borrow().writes.len(), writes, "{end:?}");
    }
}

#[test]
fn hold_after_a_w6_that_cannot_show_the_leaf_empty() {
    // A W3 failure goes to W6, whose kill takes nothing: Held, the standing HOLD, the child kept, then HOLD.
    let world = shared(|world| {
        world.proc_fault = Some(ProcFault::Label);
        world.kill_ignored = true;
    });
    let (outcome, mut standing) = succeed(&world);
    assert_eq!(outcome, Outcome::Held(Step::W6NotEmpty));
    assert_eq!(world.borrow().writes(), [Freeze, Freeze, Kill]);
    assert_eq!((standing.held(), standing.kept_children()), (Some(Step::W6NotEmpty), 1));
    assert_eq!(derive(&mut FakeLeaf(world.clone()), true), Some(Step::HoldPopulated));
    let outcome = run(&world, &FakeClock::of(&world), Qualifies(world.clone()), Binds, &mut standing);
    assert_eq!(outcome, Outcome::CapacityHeld(Step::W6NotEmpty));
    assert_eq!(world.borrow().writes(), [Freeze, Freeze, Kill]);
}

#[test]
fn w6_records_a_failed_write_goes_on_and_holds_a_failed_release() {
    // A failed freeze write is recorded, and the sequence goes on: the kill, the empty leaf, the reap, the release.
    let world = shared(|world| {
        world.child_alive = true;
        world.write_fails = vec![(Freeze, 0)];
    });
    let report = sequence(&mut FakeLeaf(world.clone()), &mut FakeSpawn(world.clone()), &FakeClock::of(&world), Some(&PID), None);
    assert_eq!((report.end, report.recorded, report.entry_ms),
               (W6End::Released(Some(Reaped::Killed(9))), Some(Step::W6Freeze), 0));
    assert_eq!(world.borrow().writes(), [Freeze, Kill, Thaw]);
    // A failed kill write is recorded; the leaf is never shown empty, so it is never released.
    let world = shared(|world| {
        world.child_alive = true;
        world.write_fails = vec![(Kill, 0)];
    });
    let report = sequence(&mut FakeLeaf(world.clone()), &mut FakeSpawn(world.clone()), &FakeClock::of(&world), Some(&PID), None);
    assert_eq!((report.end, report.recorded), (W6End::Held(Step::W6NotEmpty), Some(Step::W6Kill)));
    assert_eq!(world.borrow().writes(), [Freeze, Kill]);
    // A failed release: Held.
    let world = shared(|world| {
        world.child_alive = true;
        world.write_fails = vec![(Thaw, 0)];
    });
    let report = sequence(&mut FakeLeaf(world.clone()), &mut FakeSpawn(world.clone()), &FakeClock::of(&world), Some(&PID), None);
    assert_eq!(report.end, W6End::Held(Step::W6Release));
    assert_eq!(world.borrow().writes(), [Freeze, Kill, Thaw]);
    // No child (a failed plan or clone3, SM-R2-7): no reap, then the release.
    let world = shared(|_| {});
    let report = sequence(&mut FakeLeaf(world.clone()), &mut FakeSpawn(world.clone()), &FakeClock::of(&world), None, None);
    assert_eq!(report.end, W6End::Released(None));
    assert!(world.borrow().reap_calls.is_empty());
    assert_eq!(world.borrow().writes(), [Freeze, Kill, Thaw]);
    // A worker the run already reaped at its own end: no second reap.
    let world = shared(|_| {});
    let report = sequence(&mut FakeLeaf(world.clone()), &mut FakeSpawn(world.clone()), &FakeClock::of(&world), Some(&PID),
                          Some(Reaped::Exited(0)));
    assert_eq!(report.end, W6End::Released(Some(Reaped::Exited(0))));
    assert!(world.borrow().reap_calls.is_empty());
}
