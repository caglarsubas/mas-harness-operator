//! HE-004D1 DESIGN-D1 sections 10, 13.4, 14 and 16 (owner decisions Q-HE4D1-6, -7 and -D2 (a); MODEL_DEFINED R126,
//! R129, R131): the capture engine inside HE-004C's epoch, on HE-004C's `Rig` (unchanged) with `Epoch::with_captures` and
//! the fake host on the rig's clock. No set before the first cycle, one set per cycle right after the scrape;
//! WORKER-FIRST (the set's first access is the WORKER leaf's `cgroup.events`) and "cycle late" past the 5 s
//! scrape-to-set bound; the first set (WORKER pending, the fill's order); a WORKER file too large for one budget
//! (pending, no bracket read, a resumed hash) and a ctime change; no set when the scrape escalates; the view replaced
//! wholesale; NotFrozen; a 70 s freeze at every phase offset contains a WORKER window and a 30 s one between two attempts
//! does not; capture failures never exit; Pending before `validFrom`; the wake at `expiresAt - 3 s`; expiry inside a
//! snapshot phase (read-time Expired); the latch; the budget from the scheduled start (an on-time set, a set started
//! 12 s late, a blocked read that makes the next cycle late); the drain (a bookmark the apiserver sent during a long set
//! is credited before its deadline is judged, without it the same set is stale; at most 8 polls); and the epoch
//! unchanged without captures.
//!
//! The rig's scheduled actions run inside its wire's waits, so an apiserver write scheduled during a set reaches the
//! wire at the drain's first poll, after the set; the tests place such writes accordingly.

mod b1_rbac_support;
mod b1_support;
mod c_support;
mod d1_support;

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::{Duration, Instant};

use c_support::*;
use d1_support::{derive_scoped, enroll, host, list, vectors, with_worker_file_size, Access, Clock, FakeHost, CTIME};
use i05_protocol::json::Value;
use planeon_observer::capture::{CaptureCycle, CaptureEngine, CaptureView, CaptureViewState, CgroupItem, ReadError, Slot};
use planeon_observer::capture_schema::CaptureSchema;
use planeon_observer::inputs::Resource;
use planeon_observer::kernel_text;
use planeon_observer::observe::{Epoch, ObserverExit, Trace};

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// The rig's clock as the fake host's (the rig's wall shift, plus an optional step of the host's wall clock alone).
struct LabClock {
    lab: SharedLab,
    step: Option<(Duration, i64)>,
}

impl Clock for LabClock {
    fn now(&self) -> Instant {
        self.lab.borrow().now()
    }

    fn wall_millis(&self) -> Option<u64> {
        let lab = self.lab.borrow();
        if lab.wall_before_epoch {
            return None;
        }
        let step = self.step.filter(|(at, _)| lab.elapsed >= *at).map_or(0, |(_, by)| by);
        u64::try_from((wall_start() as i64 + lab.wall_shift + step) * 1_000 + lab.elapsed.as_millis() as i64).ok()
    }

    fn advance(&self, by: Duration) {
        self.lab.borrow_mut().elapsed += by;
    }
}

/// One set as the recorder saw it.
#[derive(Clone, Debug)]
struct SetRecord {
    started: Duration,
    ended: Duration,
    scheduled: Duration,
    log: (usize, usize),
    view: CaptureView,
}

#[derive(Default)]
struct Recording {
    sets: Vec<SetRecord>,
    expired_at: Vec<Duration>,
}

/// The capture engine with a recorder around it.
struct Recorder {
    inner: CaptureEngine<FakeHost>,
    host: FakeHost,
    lab: SharedLab,
    seen: Rc<RefCell<Recording>>,
}

impl Recorder {
    fn elapsed(&self) -> Duration {
        self.lab.borrow().elapsed
    }
}

impl CaptureCycle for Recorder {
    fn capture_set(&mut self, scheduled: Instant) {
        let started = self.elapsed();
        let from = self.host.log().len();
        self.inner.capture_set(scheduled);
        let base = self.lab.borrow().base;
        let record = SetRecord { started, ended: self.elapsed(), scheduled: scheduled.saturating_duration_since(base),
                                 log: (from, self.host.log().len()), view: self.inner.view().clone() };
        self.seen.borrow_mut().sets.push(record);
    }

    fn expired_now(&self) -> bool {
        self.inner.expired_now()
    }

    fn expiry_wake(&self) -> Option<Instant> {
        self.inner.expiry_wake()
    }

    fn expire(&mut self) {
        let at = self.elapsed();
        self.seen.borrow_mut().expired_at.push(at);
        self.inner.expire();
    }

    fn view(&self) -> &CaptureView {
        self.inner.view()
    }
}

/// A rig with a positive's captures on its clock.
struct Setup {
    rig: Rig,
    host: FakeHost,
    seen: Rc<RefCell<Recording>>,
    recorder: RefCell<Option<Recorder>>,
    /// Each role's cgroup (under the cgroup2 root); the WORKER leaf, its files, the fill's order and the backends'
    /// executables.
    rels: Vec<(&'static str, String)>,
    worker: String,
    worker_paths: Vec<String>,
    order: Vec<String>,
    backend_paths: Vec<String>,
}

/// The first positive's captures with the record's window from `valid_from` to `expires_at` seconds after the rig's
/// start, and the host's wall clock stepped by `step` (seconds) from a time on.
fn prepare_stepped(valid_from: u64, expires_at: u64, step: Option<(Duration, i64)>) -> Setup {
    prepare_full(valid_from, expires_at, step, |_| {})
}

/// [`prepare_stepped`] over the first positive changed by `patch` before the record is derived.
fn prepare_full(valid_from: u64, expires_at: u64, step: Option<(Duration, i64)>, patch: impl Fn(&mut Value)) -> Setup {
    let rig = Rig::new();
    let vectors = vectors();
    let mut positive = list(&vectors, "positive")[0].clone();
    patch(&mut positive);
    let positive = &positive;
    let text_at = |offset: u64| kernel_text::utc_text(wall_start() + offset).expect("UTC");
    let (from, until) = (text_at(valid_from), text_at(expires_at));
    let derived = derive_scoped(positive, Some((&from, &until)));
    let enrolled = enroll(&derived.record);
    let clock: Rc<dyn Clock> = Rc::new(LabClock { lab: rig.lab.clone(), step });
    let host = host(positive, &derived, &enrolled, Some(clock));
    let role = |name: &str| enrolled.roles.iter().find(|role| role.role == name).expect("a role");
    let rels: Vec<(&'static str, String)> = enrolled.roles.iter().map(|role| (role.role, role.cgroup_rel.clone())).collect();
    let worker = role("WORKER").cgroup_rel.clone();
    let worker_paths = role("WORKER").paths.clone();
    let mut order: Vec<String> = Vec::new();
    for name in ["WORKER", "SERVER", "OBSERVER", "BROKER", "EFFECT_GATE"] {
        for path in &role(name).paths {
            if !order.contains(path) {
                order.push(path.clone());
            }
        }
    }
    let backend_paths: Vec<String> = enrolled.backends.iter().map(|backend| backend.executable.clone()).collect();
    for path in &backend_paths {
        if !order.contains(path) {
            order.push(path.clone());
        }
    }
    let seen = Rc::new(RefCell::new(Recording::default()));
    let (schema, _) = CaptureSchema::embedded().expect("schema");
    let engine = CaptureEngine::new(host.clone(), enrolled, schema);
    let recorder = Recorder { inner: engine, host: host.clone(), lab: rig.lab.clone(), seen: seen.clone() };
    Setup { rig, host, seen, recorder: RefCell::new(Some(recorder)), rels, worker, worker_paths, order, backend_paths }
}

fn rel(setup: &Setup, name: &str) -> String {
    setup.rels.iter().find(|(role, _)| *role == name).map(|(_, rel)| rel.clone()).expect("a role")
}

fn prepare(valid_from: u64, expires_at: u64) -> Setup {
    prepare_stepped(valid_from, expires_at, None)
}

fn run(setup: &Setup) -> (ObserverExit, Epoch<FakeWire>) {
    let recorder = setup.recorder.borrow_mut().take().expect("a prepared recorder");
    let mut epoch = setup.rig.epoch().with_captures(Box::new(recorder));
    let exit = epoch.run();
    (exit, epoch)
}

fn sets(setup: &Setup) -> Vec<SetRecord> {
    setup.seen.borrow().sets.clone()
}

fn worker_slot(set: &SetRecord) -> &Slot {
    &set.view.roles[3]
}

fn reason(slot: &Slot) -> String {
    d1_support::reason(slot)
}

/// The accesses of one set.
fn accesses(setup: &Setup, set: &SetRecord) -> Vec<Access> {
    setup.host.log()[set.log.0..set.log.1].to_vec()
}

/// Whether the set's first access is the WORKER leaf's (its bracket's start).
fn leaf_first(setup: &Setup, set: &SetRecord) -> bool {
    matches!(accesses(setup, set).first(), Some(Access::Cgroup(rel)) if *rel == setup.worker)
}

// ------------------------------------------------------------------------------------------------ cadence

#[test]
fn one_set_per_cycle_right_after_the_scrape_worker_first() {
    let setup = prepare(0, 700);
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let sets = sets(&setup);
    assert_eq!(sets.iter().map(|set| set.started).collect::<Vec<_>>(), (1..=9).map(|k| secs(60 * k)).collect::<Vec<_>>());
    assert!(sets.iter().all(|set| set.scheduled == set.started), "each set right after its on-time scrape");
    // Each Captures entry follows the cycle's ADM-4 record; none before the first cycle.
    let trace = epoch.trace();
    let first_cycle = trace.iter().position(|(_, entry)| *entry == Trace::Cycle).expect("a cycle");
    let mut traced = 0;
    for (index, (_, entry)) in trace.iter().enumerate() {
        if let Trace::Captures { sequence, taken, not_taken } = entry {
            assert!(index > first_cycle && trace[index - 1].1 == Trace::Adm4, "a set right after the scrape");
            let view = &sets[traced].view;
            assert_eq!((*sequence, (*taken, *not_taken)), (view.sequence, view.counts()));
            traced += 1;
        }
    }
    assert_eq!(traced, sets.len());
    // The first set: the WORKER attempt pending with no read of the leaf; the fill's opens in order.
    let first = &sets[0];
    assert_eq!(reason(worker_slot(first)), "content digest pending");
    let log = accesses(&setup, first);
    let fill: Vec<String> = log.iter().take_while(|access| !matches!(access, Access::Cgroup(_)))
        .filter_map(|access| match access { Access::Open(path) => Some(path.clone()), _ => None }).collect();
    assert_eq!(fill, setup.order, "the WORKER's files first, then the other roles', then the backends'");
    assert_eq!(first.view.counts(), (13, 1));
    // Every later set: the WORKER leaf's cgroup.events is the first read, before any hashing read; every slot taken.
    for set in &sets[1..] {
        let log = accesses(&setup, set);
        assert_eq!(log[..2].to_vec(), vec![Access::Cgroup(setup.worker.clone()), Access::CgroupRead(setup.worker.clone(), CgroupItem::Events)]);
        assert!(matches!(worker_slot(set), Slot::Taken { .. }), "{:?}", worker_slot(set));
        assert_eq!(set.view.counts(), (14, 0));
    }
    // The view is replaced wholesale, one sequence per set.
    assert_eq!(sets.iter().map(|set| set.view.sequence).collect::<Vec<_>>(), (1..=9).collect::<Vec<_>>());
    assert!(sets.windows(2).all(|pair| pair[0].view.set_started_ms < pair[1].view.set_started_ms));
    assert!(sets.windows(2).all(|pair| pair[0].view.roles[0] != pair[1].view.roles[0]), "a new observedAt each set");
    match epoch.capture_view() {
        Some(CaptureViewState::Current(view)) => assert_eq!(*view, sets[8].view),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_worker_attempt_past_the_scrape_to_set_bound_is_cycle_late() {
    let setup = prepare(0, 700);
    // From the second cycle on, a slow progress read (2 s) and a slow scrape (4 s): the set starts 6 s late.
    setup.rig.hook(|req, api| {
        if req.at < secs(110) {
            return None;
        }
        if req.path == "/api/v1/namespaces" && req.param("limit") == Some("1") {
            return Some(Reply::Delay(secs(2), Box::new(json(200, &api.list_body(Resource::Namespaces, api.rv, Some(1))))));
        }
        (req.path == "/metrics").then(|| Reply::Delay(secs(4), Box::new(answer(200, "text/plain; version=0.0.4; charset=utf-8",
                                                                                api.exposition().as_bytes()))))
    });
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let sets = sets(&setup);
    assert_eq!(sets.len(), 9);
    for set in &sets[1..] {
        assert_eq!(set.started - set.scheduled, secs(6));
        assert_eq!(reason(worker_slot(set)), "cycle late");
        assert!(!leaf_first(&setup, set), "no read of the leaf");
        assert_eq!(set.view.counts(), (13, 1));
    }
}

#[test]
fn a_large_worker_file_stays_pending_and_a_ctime_change_makes_the_next_attempt_pending() {
    // The WORKER file enrolled at 200,000 bytes (its row and the fake's bytes agree, PR review round 1, R1-3).
    let setup = prepare_full(0, 700, None, |positive| {
        with_worker_file_size(positive, 200_000);
    });
    let path = setup.worker_paths[0].clone();
    assert_eq!(setup.host.inode(&path, |file| file.bytes.len()), 200_000);
    // Each 64 KiB read of the file takes 10 s: one set's budget hashes three of its four chunks.
    let slow = path.clone();
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        if matches!(access, Access::Read(read, _) if *read == slow) { secs(10) } else { Duration::ZERO }
    }));
    let (host, moved) = (setup.host.clone(), path.clone());
    setup.rig.at(secs(200), Action::Do(Box::new(move |_api: &mut Api| host.inode(&moved, |file| file.facts.ctime = CTIME + 9))));
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let sets = sets(&setup);
    // Sets 1 and 2: pending, no bracket read. Set 2 resumes the cut file on its one held descriptor (a facts check of
    // the held descriptor, then reads; no open).
    for set in &sets[..2] {
        assert_eq!(reason(worker_slot(set)), "content digest pending");
        assert!(!leaf_first(&setup, set));
    }
    let resumed: Vec<Access> = accesses(&setup, &sets[1]).into_iter()
        .filter(|access| matches!(access, Access::Open(named) | Access::Facts(named) | Access::Read(named, _) if *named == path))
        .take(2).collect();
    assert_eq!(resumed[0], Access::Facts(path.clone()));
    assert!(matches!(&resumed[1], Access::Read(named, _) if *named == path));
    // Set 3 (180 s): the digest is in the memo, so the bracket is read first and the WORKER capture is taken.
    assert!(leaf_first(&setup, &sets[2]));
    assert!(matches!(worker_slot(&sets[2]), Slot::Taken { .. }), "{:?}", worker_slot(&sets[2]));
    // The ctime moved at 200 s: set 4's window finds another key (stale; the entry is dropped, rehashed and cut again);
    // set 5 is pending again with no bracket read.
    assert!(leaf_first(&setup, &sets[3]));
    assert_eq!(reason(worker_slot(&sets[3])), "content digest stale");
    assert_eq!(reason(worker_slot(&sets[4])), "content digest pending");
    assert!(!leaf_first(&setup, &sets[4]));
}

#[test]
fn an_escalated_scrape_takes_no_set_and_a_thawed_leaf_is_not_frozen() {
    let setup = prepare(0, 700);
    let fired = Rc::new(Cell::new(false));
    let once = fired.clone();
    setup.rig.hook(move |req, _| {
        (req.path == "/metrics" && req.at >= secs(120) && !once.replace(true)).then(|| json(503, r#"{"kind": "Status"}"#))
    });
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert!(fired.get());
    assert_eq!(snapshots(epoch.trace()).len(), 2);
    let started: Vec<Duration> = sets(&setup).iter().map(|set| set.started).collect();
    assert!(started.contains(&secs(60)) && !started.contains(&secs(120)), "no set for the escalated cycle: {started:?}");
    // A thawed leaf: NotFrozen, and the window stops at the bracket's start.
    let setup = prepare(0, 700);
    setup.host.state().frozen_when = Some(Box::new(|| 0));
    let (exit, _) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired);
    for set in &sets(&setup)[1..] {
        assert_eq!(*worker_slot(set), Slot::NotFrozen);
        let log = accesses(&setup, set);
        assert_eq!(log[1], Access::CgroupRead(setup.worker.clone(), CgroupItem::Events));
        assert!(!matches!(&log[2], Access::Cgroup(rel) | Access::CgroupRead(rel, _) if *rel == setup.worker));
    }
}

/// Whether a run holding the leaf frozen during [start, end) seconds takes a WORKER capture.
fn freeze_takes_a_worker_capture(start: u64, end: u64) -> bool {
    let setup = prepare(0, 700);
    let lab = setup.rig.lab.clone();
    setup.host.state().frozen_when = Some(Box::new(move || {
        let at = lab.borrow().elapsed;
        u64::from(at >= secs(start) && at < secs(end))
    }));
    let (exit, _) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired);
    sets(&setup).iter().any(|set| matches!(worker_slot(set), Slot::Taken { .. }))
}

#[test]
fn a_70_s_freeze_at_every_phase_contains_a_worker_window() {
    for phase in (0..60).step_by(5) {
        let start = 110 + phase;
        assert!(freeze_takes_a_worker_capture(start, start + 70), "a 70 s freeze from {start} s");
    }
    assert!(!freeze_takes_a_worker_capture(125, 155), "a 30 s freeze between two attempts");
}

#[test]
fn capture_failures_never_exit() {
    let setup = prepare(0, 700);
    {
        let mut state = setup.host.state();
        state.listing_error = Some(ReadError::Other);
        for process in state.procs.values_mut() {
            process.denied = true;
        }
        state.paths.clear();
    }
    let (exit, epoch) = run(&setup);
    assert_eq!((exit, setup.rig.elapsed()), (ObserverExit::ConfigExpired, secs(600)), "{}", epoch.reason());
    assert_eq!(sets(&setup).len(), 9);
    assert!(sets(&setup).iter().all(|set| set.view.counts().0 == 0));
    // An exit is still reached as before: a changed restart marker at the cycle's scrape is 81, with no set for it.
    let setup = prepare(0, 700);
    setup.rig.at(secs(90), Action::Do(Box::new(|api: &mut Api| api.marker = "2.0e+09".to_string())));
    let (exit, _) = run(&setup);
    assert_eq!((exit, setup.rig.elapsed()), (ObserverExit::ApiserverRestart, secs(120)));
    assert_eq!(sets(&setup).len(), 1);
    // 92: an ERROR event after the first set.
    let setup = prepare(0, 700);
    setup.rig.at(secs(90), Action::Line(Resource::Roles, r#"{"type": "ERROR", "object": {"kind": "Status", "code": 500}}"#.to_string()));
    let (exit, _) = run(&setup);
    assert_eq!((exit, setup.rig.elapsed()), (ObserverExit::WatchGap, secs(90)));
    assert_eq!(sets(&setup).len(), 1);
}

// ------------------------------------------------------------------------------------------------ the record window

#[test]
fn slots_are_pending_before_valid_from() {
    let setup = prepare(150, 700);
    let (exit, _) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired);
    let sets = sets(&setup);
    for set in &sets[..2] {
        assert!(set.view.roles.iter().all(|slot| *slot == Slot::Pending) && set.view.lifecycle == Slot::Pending);
        assert!(set.view.backends.iter().all(|(_, slot)| *slot == Slot::Pending));
        assert!(accesses(&setup, set).is_empty(), "nothing read before validFrom");
    }
    assert!(matches!(sets[2].view.roles[0], Slot::Taken { .. }));
}

#[test]
fn the_wake_at_expires_at_minus_3_s_expires_every_slot_and_latches() {
    // From 451 s the host's wall clock reads 250 s earlier (before expiresAt - 3 s again): the latch holds.
    let setup = prepare_stepped(0, 400, Some((secs(451), -250)));
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let seen = setup.seen.borrow();
    assert_eq!(seen.expired_at, vec![secs(397)], "the wake at expiresAt - 3 s, with no set running");
    assert_eq!(seen.sets.iter().map(|set| set.started).collect::<Vec<_>>(), (1..=6).map(|k| secs(60 * k)).collect::<Vec<_>>());
    drop(seen);
    let wall = setup.host.clock().wall_millis().expect("a wall clock");
    assert!(wall < (wall_start() + 397) * 1_000, "the stepped clock is before the expiry again");
    assert_eq!(epoch.capture_view(), Some(CaptureViewState::Expired));
    assert!(!epoch.trace().iter().any(|(at, entry)| matches!(entry, Trace::Captures { .. }) && *at > secs(397)));
    assert_eq!(epoch.trace().iter().filter(|(_, entry)| *entry == Trace::Cycle).count(), 9, "the cycles go on");
}

#[test]
fn expiry_inside_a_snapshot_phase_is_read_as_expired_and_latched() {
    let setup = prepare(0, 400);
    // A change at 350 s re-snapshots; the snapshot's scrape answers 429 to its 120 s deadline (93), across the expiry.
    setup.rig.at(secs(350), Action::Change(Resource::Roles));
    setup.rig.hook(|req, _| (req.at >= secs(350) && req.path == "/metrics").then(|| json(429, r#"{"kind": "Status"}"#)));
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::Deadline, "{}", epoch.reason());
    assert_eq!(setup.rig.elapsed(), secs(470));
    // No wake ran in the snapshot phase: the stored slots are not Expired, but the view reads Expired.
    assert!(setup.seen.borrow().expired_at.is_empty());
    let last = sets(&setup).last().cloned().expect("a set");
    assert_eq!(last.started, secs(300));
    assert!(matches!(last.view.roles[0], Slot::Taken { .. }));
    assert_eq!(epoch.capture_view(), Some(CaptureViewState::Expired));
    // The first observation latched it: a wall clock stepped back does not revive the view.
    setup.rig.lab(|lab| lab.wall_shift = -300);
    assert!(setup.host.clock().wall_millis().expect("a wall clock") < (wall_start() + 397) * 1_000);
    assert_eq!(epoch.capture_view(), Some(CaptureViewState::Expired));
    // The wake latched it in a watch phase; a snapshot phase follows (a change at 420 s, its scrape answering 429 to
    // its deadline), during which the host's wall clock steps back 250 s: still Expired, and no set.
    let setup = prepare_stepped(0, 400, Some((secs(430), -250)));
    setup.rig.at(secs(420), Action::Change(Resource::Roles));
    setup.rig.hook(|req, _| (req.at >= secs(420) && req.path == "/metrics").then(|| json(429, r#"{"kind": "Status"}"#)));
    let (exit, epoch) = run(&setup);
    assert_eq!((exit, setup.rig.elapsed()), (ObserverExit::Deadline, secs(540)), "{}", epoch.reason());
    assert_eq!(setup.seen.borrow().expired_at, vec![secs(397)]);
    assert!(sets(&setup).iter().all(|set| set.started < secs(397)));
    assert!(setup.host.clock().wall_millis().expect("a wall clock") < (wall_start() + 397) * 1_000);
    assert_eq!(epoch.capture_view(), Some(CaptureViewState::Expired));
}

// ------------------------------------------------------------------------------------------------ the budget

#[test]
fn the_budget_runs_from_the_scheduled_start() {
    // An on-time set: a slow fill (5 s per backend read) runs into the budget; the later captures are "set budget".
    let setup = prepare(0, 700);
    let backends = setup.backend_paths.clone();
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        if matches!(access, Access::Read(path, _) if backends.contains(path)) { secs(5) } else { Duration::ZERO }
    }));
    let (exit, _) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired);
    let first = &sets(&setup)[0];
    assert_eq!((first.scheduled, first.ended), (secs(60), secs(85)), "{first:?}");
    assert_eq!(reason(&first.view.roles[0]), "set budget");
    assert_eq!(reason(&first.view.lifecycle), "set budget");
    // A set started 12 s late (a slow progress read) gets 13 s, and its WORKER attempt is "cycle late".
    let setup = prepare(0, 700);
    setup.rig.hook(|req, api| (req.at >= secs(110) && req.at < secs(130) && req.path == "/api/v1/namespaces"
                                && req.param("limit") == Some("1"))
        .then(|| Reply::Delay(secs(12), Box::new(json(200, &api.list_body(Resource::Namespaces, api.rv, Some(1)))))));
    let backends = setup.backend_paths.clone();
    let lab = setup.rig.lab.clone();
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        let now = lab.borrow().elapsed;
        let late_set = now >= secs(132) && now < secs(170);
        if late_set && matches!(access, Access::Open(path) if backends.contains(path)) { secs(4) } else { Duration::ZERO }
    }));
    let (exit, _) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired);
    let late = sets(&setup).into_iter().find(|set| set.scheduled == secs(120)).expect("the late set");
    assert_eq!(late.started, secs(132));
    assert_eq!(reason(worker_slot(&late)), "cycle late");
    assert!(late.ended >= secs(145) && late.ended <= secs(149), "{late:?}");
    assert!(late.view.backends.iter().any(|(_, slot)| *slot == Slot::Unavailable("set budget".to_string())));
    // A read blocked for 40 s delays the next cycle, whose WORKER attempt is then "cycle late"; no exit. In the set at
    // 180 s the SERVER's cgroup open takes 24.5 s, the OBSERVER's capture starts at 204.5 s (inside the budget), its
    // cgroup open takes 1 s and its next read blocks for 40 s, to 245.5 s: the cycle due at 240 s starts 5.5 s late.
    let setup = prepare(0, 700);
    let lab = setup.rig.lab.clone();
    let (server, observer) = (rel(&setup, "SERVER"), rel(&setup, "OBSERVER"));
    let stage = Cell::new(0u8);
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        if lab.borrow().elapsed < secs(180) {
            return Duration::ZERO;
        }
        match (stage.get(), access) {
            (0, Access::Cgroup(rel)) if *rel == server => stage.set(1),
            (1, Access::Cgroup(rel)) if *rel == observer => stage.set(2),
            (2, _) => stage.set(3),
            _ => return Duration::ZERO,
        }
        [Duration::ZERO, Duration::from_millis(24_500), secs(1), secs(40)][usize::from(stage.get())]
    }));
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let sets = sets(&setup);
    let blocked_set = &sets[2];
    assert_eq!(blocked_set.scheduled, secs(180));
    assert!(matches!(worker_slot(blocked_set), Slot::Taken { .. }));
    assert_eq!(reason(&blocked_set.view.roles[1]), "inspection window exceeded");
    assert_eq!(reason(&blocked_set.view.roles[2]), "set budget");
    assert_eq!(blocked_set.ended, Duration::from_millis(245_500));
    let next = &sets[3];
    assert_eq!((next.scheduled, next.started), (secs(240), Duration::from_millis(245_500)), "{next:?}");
    assert_eq!(reason(worker_slot(next)), "cycle late");
}

// ------------------------------------------------------------------------------------------------ the drain

/// A Roles stream stuck from 100 s (its bookmarks stay at its opening mark) and writes every 30 s, so F read at 120 s
/// (deadline 270 s) waits on it; the set at 240 s is held 35 s by its scan, past that deadline. With `unstick`, the
/// apiserver clears the stall at 255 s, during the set, and sends a bookmark at its revision.
fn long_set_over_a_deadline(unstick: bool) -> (ObserverExit, Epoch<FakeWire>, Setup) {
    let setup = prepare(0, 700);
    for k in 0..20 {
        setup.rig.at(secs(30 + 30 * k), Action::Bump(1));
    }
    setup.rig.at(secs(100), Action::Do(Box::new(|api: &mut Api| {
        api.stuck.insert(Resource::Roles);
    })));
    if unstick {
        setup.rig.at(secs(255), Action::Do(Box::new(|api: &mut Api| {
            api.stuck.clear();
            api.bookmarks();
        })));
    }
    let lab = setup.rig.lab.clone();
    let held = Rc::new(Cell::new(false));
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        let now = lab.borrow().elapsed;
        if *access == Access::Processes && now >= secs(240) && !held.replace(true) { secs(35) } else { Duration::ZERO }
    }));
    let (exit, epoch) = run(&setup);
    (exit, epoch, setup)
}

#[test]
fn a_bookmark_sent_during_a_long_set_is_credited_by_the_drain() {
    let (exit, epoch, setup) = long_set_over_a_deadline(true);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let long = sets(&setup).into_iter().find(|set| set.scheduled == secs(240)).expect("the long set");
    assert_eq!(long.ended, secs(275), "the set spans F(120)'s deadline");
    assert!(!epoch.trace().iter().any(|(_, entry)| matches!(entry, Trace::Stale(_))), "no Stale");
    let fresh_at_end: Vec<u64> = epoch.trace().iter()
        .filter_map(|(at, entry)| match entry { Trace::Fresh(mark) if *at == long.ended => Some(*mark), _ => None }).collect();
    assert!(!fresh_at_end.is_empty(), "fresh_as_of advances at the drain, before the deadline is judged");
    assert!(epoch.drains().iter().all(|polls| (1..=8).contains(polls)));
    assert_eq!(epoch.drains().len(), sets(&setup).len(), "one drain after each set's batch");
    // Without the bookmark the same set is stale.
    let (_, epoch, _) = long_set_over_a_deadline(false);
    assert!(epoch.trace().iter().any(|(at, entry)| matches!(entry, Trace::Stale(1)) && *at == secs(275)));
}

#[test]
fn the_drain_runs_after_the_batch_and_its_mark_is_cleared_when_the_watch_phase_ends() {
    // A poll batch whose first event is the cycle scrape's answer (it runs the set) and whose later event is an older
    // change on the Roles stream: the Roles stream ended at 59.5 s, its end check's scrape answered at 60.5 s, its reopen
    // was refused (503) and retried at 61.5 s, after the cycle scrape's link opened at 60.5 s (answered at 62.5 s with
    // the change). Newer Roles bytes are sent during the set (held 5 s). The batch's change is processed right after the
    // set and ends the watch phase before any drain poll; the mark is cleared, so the next phase drains only after its
    // own set.
    let setup = prepare(0, 700);
    setup.rig.at(Duration::from_millis(59_500), Action::EndStream(Resource::Roles));
    setup.rig.at(Duration::from_millis(62_500), Action::Change(Resource::Roles));
    setup.rig.at(secs(64), Action::Line(Resource::Roles, Api::bookmark(Resource::Roles, 2_000)));
    setup.rig.hook(|req, api| {
        let exposition = || answer(200, "text/plain; version=0.0.4; charset=utf-8", api.exposition().as_bytes());
        let at = req.at;
        if req.path == "/metrics" && at >= secs(59) && at < secs(60) {
            return Some(Reply::Delay(secs(1), Box::new(exposition())));
        }
        if req.path == "/metrics" && at >= secs(60) && at < secs(61) {
            return Some(Reply::Delay(secs(2), Box::new(exposition())));
        }
        (req.param("watch") == Some("true") && req.path.ends_with("/roles") && at >= secs(60) && at < secs(61))
            .then(|| json(503, r#"{"kind": "Status"}"#))
    });
    let lab = setup.rig.lab.clone();
    let held = Rc::new(Cell::new(false));
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        let now = lab.borrow().elapsed;
        if *access == Access::Processes && now < secs(70) && !held.replace(true) { secs(5) } else { Duration::ZERO }
    }));
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let first_run = sets(&setup);
    assert_eq!((first_run[0].scheduled, first_run[0].started, first_run[0].ended),
               (secs(60), Duration::from_millis(62_500), Duration::from_millis(67_500)));
    let trace = epoch.trace();
    let captures = trace.iter().position(|(_, entry)| matches!(entry, Trace::Captures { sequence: 1, .. })).expect("the set");
    assert_eq!(trace[captures + 1], (Duration::from_millis(67_500), Trace::Change(Resource::Roles)), "the batch's change next");
    assert!(traced(&trace[..captures], |entry| *entry == Trace::Reopened(Resource::Roles)));
    assert_eq!(snapshots(trace).len(), 2);
    assert_eq!(epoch.drains().len(), first_run.len() - 1, "no drain for the first set, none carried into the next phase");
    // A trigger from a drain poll: a change sent during the set at 180 s (held 5 s) is the drain's first poll's event;
    // the phase ends there, the mark is cleared, and the next phase drains only after its own set.
    let setup = prepare(0, 700);
    setup.rig.at(secs(182), Action::Change(Resource::Roles));
    let lab = setup.rig.lab.clone();
    let held = Rc::new(Cell::new(false));
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        let now = lab.borrow().elapsed;
        if *access == Access::Processes && now >= secs(180) && !held.replace(true) { secs(5) } else { Duration::ZERO }
    }));
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert!(traced(epoch.trace(), |entry| *entry == Trace::Change(Resource::Roles)));
    assert_eq!(snapshots(epoch.trace()).len(), 2);
    assert_eq!(epoch.drains().len(), sets(&setup).len());
    assert_eq!(epoch.drains()[2], 1, "the change ended the drain at its first poll");
}

#[test]
fn the_drain_stops_after_8_polls_and_the_loop_goes_on() {
    let setup = prepare(0, 700);
    // The set at 180 s is held 10 s by its scan; the apiserver queues 6,000 bookmark lines on the Roles stream at
    // 185 s. The client reads at most 64 KiB of a connection per poll, so every drain poll returns stream events.
    let lab = setup.rig.lab.clone();
    let held = Rc::new(Cell::new(false));
    setup.host.state().delay = Some(Box::new(move |access: &Access| {
        let now = lab.borrow().elapsed;
        if *access == Access::Processes && now >= secs(180) && !held.replace(true) { secs(10) } else { Duration::ZERO }
    }));
    setup.rig.at(secs(185), Action::Do(Box::new(|api: &mut Api| {
        let line = Api::chunk(&Api::bookmark(Resource::Roles, api.rv));
        let conns: Vec<u64> = api.streams.iter().filter(|stream| stream.resource == Resource::Roles).map(|stream| stream.conn).collect();
        for conn in conns {
            for _ in 0..6_000 {
                api.outbox.push((conn, line.clone(), false));
            }
        }
    })));
    let (exit, epoch) = run(&setup);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert_eq!(epoch.drains().len(), 9);
    assert_eq!(epoch.drains()[2], 8, "{:?}", epoch.drains());
    assert!(epoch.drains().iter().all(|polls| *polls <= 8));
}

#[test]
fn without_captures_the_epoch_is_unchanged() {
    let rig = Rig::new();
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired);
    assert!(!epoch.trace().iter().any(|(_, entry)| matches!(entry, Trace::Captures { .. })));
    assert!(epoch.drains().is_empty());
    assert_eq!(epoch.capture_view(), None);
}
