//! HE-004D1 DESIGN-D1 sections 9-14 and 20 (MODEL_DEFINED R125-R129): the capture engine on `FakeHost`. The round trip
//! (each positive's 14 captures, accepted by the self-check and equal to the positive's apart from the timing fields and
//! the derived digests); the classes (no OBSERVED read for LABEL_BOUND roles or the observer); the WORKER frozen
//! bracket; the 2 s window; the expiry check; members (an exit, a reused pid, another cgroup); the observer's own
//! member; files (a replaced inode, a size mismatch, special mode bits, a missing verity, the memo over two sets); the
//! resume of a cut hash on its held descriptor; hashing on the host (size - 1, size, size + 1); BPF (an overflowing
//! query, a 65,537-byte program, a foreign attach flag, a census query error); the listings' bounds; the lifecycle's
//! containment states and slice; the backends' candidates; and NP-3 over every access log (a closed read set, nothing
//! written).

mod d1_support;

use std::collections::BTreeSet;
use std::time::Duration;

use d1_support::{content, diff, fake_engine, fake_engine_with, field, reason, taken, text, untimed, with_worker_file_size, Access,
                 FakeHost, FakeProc, HostState, CTIME};
use i05_protocol::json;
use i05_protocol::sha256;
use planeon_observer::capture::{CaptureCycle, CaptureEngine, CgroupItem, KernelView, LinkItem, ProcItem, ReadError, Slot};

/// The index of each role in the view.
const SERVER: usize = 0;
const OBSERVER: usize = 1;
const BROKER: usize = 2;
const WORKER: usize = 3;
const GATE: usize = 4;

/// One set, scheduled now.
fn set(engine: &mut CaptureEngine<FakeHost>) {
    let now = engine.kernel().now();
    engine.capture_set(now);
}

/// A set one cycle (60 s) later.
fn next(engine: &mut CaptureEngine<FakeHost>, host: &FakeHost) {
    host.clock().advance(Duration::from_secs(60));
    set(engine);
}

fn rel(engine: &CaptureEngine<FakeHost>, index: usize) -> String {
    engine.enrolled().roles[index].cgroup_rel.clone()
}

fn paths(engine: &CaptureEngine<FakeHost>, index: usize) -> Vec<String> {
    engine.enrolled().roles[index].paths.clone()
}

/// NP-3 over an access log: every opened file is an enrolled file or the seal marker, every cgroup is a known one
/// (the roles', the broker service, the slice census, the containment cgroup); there is no write access at all, by
/// the closed `Access` set.
fn closed(engine: &CaptureEngine<FakeHost>, host: &FakeHost) {
    let enrolled = engine.enrolled();
    let state = host.state();
    let files: BTreeSet<&String> = enrolled.rows.keys().chain(enrolled.backend_rows.keys()).chain([&enrolled.seal_marker]).collect();
    let cgroups: BTreeSet<String> = state.cgroups.keys().cloned().chain([enrolled.containment_rel.clone()]).collect();
    for access in &state.log {
        match access {
            Access::Open(path) | Access::Facts(path) | Access::Verity(path) | Access::Read(path, _) | Access::FsType(path) => {
                assert!(files.contains(path), "an open outside the enrolled set: {path}");
            }
            Access::Cgroup(rel) | Access::CgroupRead(rel, _) | Access::Children(rel) | Access::CgroupInode(rel)
            | Access::Query(rel, _, _) => assert!(cgroups.contains(rel) || rel.starts_with("planeon.slice/"), "{rel}"),
            _ => {}
        }
    }
}

#[test]
fn the_round_trip_takes_the_positives_captures() {
    for index in 0..5 {
        let (mut engine, host, derived) = fake_engine(index, None);
        set(&mut engine);
        assert_eq!(reason(&engine.view().roles[WORKER]), "content digest pending", "positive {index}: the first set");
        next(&mut engine, &host);
        let view = engine.view().clone();
        for (slot, expected) in view.roles.iter().zip(&derived.roles) {
            let found = untimed(&taken(slot));
            assert!(json::json_eq(&found, expected), "positive {index} role {}: {:?}", text(expected, "role"), diff(&found, expected));
        }
        let found = untimed(&taken(&view.lifecycle));
        assert!(json::json_eq(&found, &derived.lifecycle), "positive {index} lifecycle: {:?}", diff(&found, &derived.lifecycle));
        assert_eq!(view.backends.len(), derived.backends.len());
        for ((component, slot), expected) in view.backends.iter().zip(&derived.backends) {
            assert_eq!(component, text(expected, "component"));
            let found = untimed(&taken(slot));
            assert!(json::json_eq(&found, expected), "positive {index} backend {component}: {:?}", diff(&found, expected));
        }
        assert_eq!(view.counts(), (14, 0));
        assert_eq!(view.record_digest, derived.pin);
        assert_eq!(view.declared_host_fields.len(), 7);
        closed(&engine, &host);
    }
}

#[test]
fn label_bound_roles_and_the_observer_read_no_observed_field() {
    let (mut engine, host, _) = fake_engine(0, None);
    set(&mut engine);
    next(&mut engine, &host);
    let view = engine.view().clone();
    assert!(matches!(view.roles[BROKER], Slot::Taken { .. }) && matches!(view.roles[WORKER], Slot::Taken { .. }));
    let state = host.state();
    let label_bound: BTreeSet<i32> = [BROKER, WORKER].iter()
        .flat_map(|index| state.cgroups.get(&engine.enrolled().roles[*index].cgroup_rel).map(|cgroup| cgroup.procs.clone()).unwrap_or_default())
        .collect();
    for access in &state.log {
        match access {
            Access::ProcLink(pid, _) | Access::ExeIdentity(pid) | Access::ProcRead(pid, _, ProcItem::Maps) => {
                assert!(!label_bound.contains(pid), "an OBSERVED read of a LABEL_BOUND member: {access:?}");
                assert_ne!(*pid, state.own_pid, "an OBSERVED read of the observer");
            }
            Access::ProcRead(pid, _, item) if *pid == state.own_pid => {
                assert_eq!(*item, ProcItem::AttrCurrent, "the observer's own process is read only by the scan");
            }
            Access::Tasks(pid) | Access::Task(pid, _) => assert_ne!(*pid, state.own_pid),
            _ => {}
        }
    }
    assert!(state.log.contains(&Access::OwnPid));
}

/// A positive's engine after its first set (the WORKER's digests in the memo) and its log cleared.
fn warmed(index: usize) -> (CaptureEngine<FakeHost>, FakeHost) {
    let (mut engine, host, _) = fake_engine(index, None);
    set(&mut engine);
    host.clear_log();
    (engine, host)
}

#[test]
fn the_frozen_bracket() {
    // Frozen throughout: taken.
    let (mut engine, host) = warmed(1);
    next(&mut engine, &host);
    assert!(matches!(engine.view().roles[WORKER], Slot::Taken { .. }));
    let worker = rel(&engine, WORKER);
    // Not frozen at the start: NotFrozen, and no member read at all.
    let (mut engine, host) = warmed(1);
    host.state().cgroups.get_mut(&worker).expect("the leaf").frozen = 0;
    next(&mut engine, &host);
    assert_eq!(engine.view().roles[WORKER], Slot::NotFrozen);
    let log = host.log();
    assert_eq!(log[..2].to_vec(), vec![Access::Cgroup(worker.clone()), Access::CgroupRead(worker.clone(), CgroupItem::Events)],
               "the set's first access is the WORKER leaf's cgroup.events");
    assert!(!log.iter().any(|access| matches!(access, Access::CgroupRead(rel, CgroupItem::Procs) if *rel == worker)));
    // A thaw between the two events reads: the pinned refusal.
    let (mut engine, host) = warmed(1);
    let leaf = worker.clone();
    host.hook(move |access, state: &mut HostState| {
        if *access == Access::CgroupRead(leaf.clone(), CgroupItem::Procs) {
            state.cgroups.get_mut(&leaf).expect("the leaf").frozen = 0;
        }
    });
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[WORKER]), "worker capture outside a frozen bracket");
    closed(&engine, &host);
}

/// Runs `change` once, right after the first access `trigger` of a set (inside the bracket).
fn once_after(host: &FakeHost, trigger: impl Fn(&Access) -> bool + 'static, change: impl FnOnce(&mut HostState) + 'static) {
    let mut change = Some(change);
    host.hook(move |access, state: &mut HostState| {
        if trigger(access) {
            if let Some(change) = change.take() {
                change(state);
            }
        }
    });
}

/// Right after the WORKER's first `cgroup.procs` read (the members before are being read).
fn after_members(host: &FakeHost, leaf: String, change: impl FnOnce(&mut HostState) + 'static) {
    once_after(host, move |access| *access == Access::CgroupRead(leaf.clone(), CgroupItem::Procs), change);
}

/// Right after the first `status` read of a process (the members before are read; the process reads have begun).
fn after_process_reads(host: &FakeHost, change: impl FnOnce(&mut HostState) + 'static) {
    once_after(host, |access| matches!(access, Access::ProcRead(_, None, ProcItem::Status)), change);
}

fn added_member(state: &mut HostState, leaf: &str) {
    let first = state.cgroups.get(leaf).expect("the leaf").procs[0];
    let mut process: FakeProc = state.procs.get(&first).expect("a member").clone();
    process.generation = 999;
    process.ppid = first;
    process.threads = [(7_777, d1_support::FakeThread { start: 9_999, status: process.status.clone(), label: process.label.clone() })]
        .into_iter()
        .collect();
    state.procs.insert(7_777, process);
    state.cgroups.get_mut(leaf).expect("the leaf").procs.push(7_777);
}

#[test]
fn member_and_thread_changes_inside_the_bracket_are_refused() {
    let (mut engine, host) = warmed(0);
    let leaf = rel(&engine, WORKER);
    let target = leaf.clone();
    after_members(&host, leaf.clone(), move |state| added_member(state, &target));
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[WORKER]), "member or thread set changed during the inspection");
    // A thread replaced inside the bracket (during the descriptor checks, after the process reads).
    let (mut engine, host) = warmed(0);
    let target = leaf.clone();
    let inode = leaf.clone();
    once_after(&host, move |access| *access == Access::CgroupInode(inode.clone()), move |state| {
        let pid = state.cgroups.get(&target).expect("the leaf").procs[0];
        let process = state.procs.get_mut(&pid).expect("a member");
        let (tid, thread) = process.threads.pop_first().expect("a thread");
        let mut replacement = thread.clone();
        replacement.start += 1;
        process.threads.insert(tid + 50, replacement);
    });
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[WORKER]), "member or thread set changed during the inspection");
    // A frozen member that exits mid-window, and a pid reused behind a held directory: "member gone".
    for reuse in [false, true] {
        let (mut engine, host) = warmed(0);
        let target = leaf.clone();
        after_process_reads(&host, move |state| {
            let pid = state.cgroups.get(&target).expect("the leaf").procs[0];
            if reuse {
                state.procs.get_mut(&pid).expect("a member").generation += 100;
            } else {
                state.procs.remove(&pid);
            }
        });
        next(&mut engine, &host);
        assert_eq!(reason(&engine.view().roles[WORKER]), "member gone", "reuse {reuse}");
        closed(&engine, &host);
    }
}

#[test]
fn a_member_in_another_cgroup_and_the_observers_own_member() {
    let (mut engine, host) = warmed(0);
    let server = rel(&engine, SERVER);
    {
        let mut state = host.state();
        let pid = state.cgroups.get(&server).expect("the server cgroup").procs[0];
        state.procs.get_mut(&pid).expect("a member").cgroup = "0::/planeon.slice/planeon-effect-gate.service\n".to_string();
    }
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[SERVER]), "member outside the role cgroup");
    // The observer's one member is its own pid: taken; another pid: unavailable.
    assert!(matches!(engine.view().roles[OBSERVER], Slot::Taken { .. }));
    host.state().own_pid += 1;
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[OBSERVER]), "observer leaf member is not the observer");
}

#[test]
fn a_window_over_2000_ms_is_unavailable_and_expiry_ends_the_set() {
    let (mut engine, host) = warmed(0);
    let gate = rel(&engine, GATE);
    let clock = host.clock();
    host.hook(move |access, _state: &mut HostState| {
        if *access == Access::CgroupInode(gate.clone()) {
            clock.advance(Duration::from_millis(2_001));
        }
    });
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "inspection window exceeded");
    // Near expiresAt: the window cannot end 1 s before the wake, so the WORKER slot and every later one are Expired.
    let (mut engine, host) = warmed(0);
    let expires = engine.enrolled().expires_at * 1_000;
    let wall = host.clock().wall_millis().expect("a wall clock");
    host.clock().advance(Duration::from_millis(expires - 3_000 - 2_500 - wall));
    set(&mut engine);
    let view = engine.view().clone();
    assert!(view.roles.iter().all(|slot| *slot == Slot::Expired), "{:?}", view.roles);
    assert_eq!(view.lifecycle, Slot::Expired);
    assert!(view.backends.iter().all(|(_, slot)| *slot == Slot::Expired));
    assert!(!engine.expired_now());
}

#[test]
fn files_replaced_resized_with_special_bits_or_without_verity_are_refused() {
    // A replaced inode: the window's fresh open finds another key; the entry is dropped and rehashed next set.
    let (mut engine, host) = warmed(0);
    let path = paths(&engine, SERVER)[0].clone();
    let size = engine.enrolled().rows.get(&path).expect("a row").size as usize;
    host.replace(&path, content(&path, size));
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[SERVER]), "content digest stale");
    host.clear_log();
    next(&mut engine, &host);
    assert!(matches!(engine.view().roles[SERVER], Slot::Taken { .. }));
    assert!(host.log().iter().any(|access| *access == Access::Read(path.clone(), size)), "rehashed from byte 0");
    // Special mode bits against a 0555 row, and 0755.
    for mode in [0o4555, 0o2555, 0o1555, 0o755] {
        let (mut engine, host) = warmed(0);
        let path = paths(&engine, GATE)[0].clone();
        host.inode(&path, |file| file.facts.mode = mode);
        next(&mut engine, &host);
        assert_eq!(reason(&engine.view().roles[GATE]), "file differs from its record row", "{mode:o}");
    }
    // The seal marker's 04444 against its 0444 row.
    let (mut engine, host) = warmed(0);
    let marker = engine.enrolled().seal_marker.clone();
    host.inode(&marker, |file| file.facts.mode = 0o4444);
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().lifecycle), "seal marker differs");
    // A size mismatch: the hashed file holds a byte more than its row.
    let (mut engine, host, _) = fake_engine(0, None);
    let path = paths(&engine, GATE)[0].clone();
    let size = engine.enrolled().rows.get(&path).expect("a row").size as usize;
    host.inode(&path, |file| {
        file.bytes = content(&path, size + 1);
        file.facts.size = (size + 1) as u64;
    });
    set(&mut engine);
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "file differs from its record row");
    // No verity: the read error makes the capture unavailable.
    let (mut engine, host) = warmed(0);
    let path = paths(&engine, GATE)[0].clone();
    host.state().refuse.push((Access::Verity(path), ReadError::Other));
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "read failed");
    closed(&engine, &host);
}

#[test]
fn hashing_on_the_host_needs_exactly_size_bytes() {
    for (extra, ok) in [(-1i64, false), (0, true), (1, false)] {
        let (mut engine, host, _) = fake_engine(0, None);
        let path = paths(&engine, GATE)[0].clone();
        let size = engine.enrolled().rows.get(&path).expect("a row").size as usize;
        host.inode(&path, |file| file.bytes = content(&path, (size as i64 + extra) as usize));
        set(&mut engine);
        assert_eq!(engine.content_digest(&path).is_some(), ok, "{extra}");
        if ok {
            assert_eq!(engine.content_digest(&path), Some(sha256::prefixed(&content(&path, size)).as_str()));
            assert!(matches!(engine.view().roles[GATE], Slot::Taken { .. }));
        } else {
            assert_eq!(reason(&engine.view().roles[GATE]), "file differs from its record row", "{extra}");
        }
    }
}

#[test]
fn the_memo_fills_over_two_sets_and_a_cut_file_resumes_on_its_held_descriptor() {
    // The WORKER file enrolled at 200,000 bytes (its row and the fake's bytes agree, R1-3).
    let big = 200_000usize;
    let (mut engine, host, _) = fake_engine_with(0, None, |positive| {
        with_worker_file_size(positive, big as u64);
    });
    let path = paths(&engine, WORKER)[0].clone();
    let slow = path.clone();
    host.state().delay = Some(Box::new(move |access: &Access| {
        if matches!(access, Access::Read(read, _) if *read == slow) { Duration::from_secs(10) } else { Duration::ZERO }
    }));
    set(&mut engine);
    assert!(engine.holds_partial(), "the budget cut the WORKER file");
    assert_eq!(engine.content_digest(&path), None, "a partial hash yields no digest");
    assert_eq!(reason(&engine.view().roles[WORKER]), "content digest pending");
    host.state().delay = None;
    next(&mut engine, &host);
    assert!(!engine.holds_partial());
    assert_eq!(engine.content_digest(&path), Some(sha256::prefixed(&content(&path, big)).as_str()), "equal to a one-pass digest");
    let log = host.log();
    assert_eq!(log.iter().filter(|access| **access == Access::Open(path.clone())).count(), 1, "one open, resumed");
    let total: usize = log.iter().filter_map(|access| match access { Access::Read(read, count) if *read == path => Some(*count), _ => None }).sum();
    assert_eq!(total, big);
    // The same path replaced, or its ctime changed, between the sets: the partial is dropped and restarts from 0.
    for replaced in [true, false] {
        let (mut engine, host, _) = fake_engine_with(0, None, |positive| {
            with_worker_file_size(positive, big as u64);
        });
        let slow = path.clone();
        host.state().delay = Some(Box::new(move |access: &Access| {
            if matches!(access, Access::Read(read, _) if *read == slow) { Duration::from_secs(10) } else { Duration::ZERO }
        }));
        set(&mut engine);
        assert!(engine.holds_partial());
        host.state().delay = None;
        if replaced {
            host.replace(&path, content(&path, big));
        } else {
            host.inode(&path, |file| file.facts.ctime = CTIME + 5);
        }
        host.clear_log();
        next(&mut engine, &host);
        let log = host.log();
        assert_eq!(log.iter().filter(|access| **access == Access::Open(path.clone())).count(), 1, "a fresh open");
        let total: usize = log.iter().filter_map(|access| match access { Access::Read(read, count) if *read == path => Some(*count), _ => None }).sum();
        assert_eq!(total, big, "read again from byte 0 ({replaced})");
        assert!(!engine.holds_partial());
    }
}

#[test]
fn a_file_larger_than_its_row_is_never_read() {
    // PR review round 1, R1-3: a role file, a WORKER file and a backend executable replaced by files one byte longer than
    // their rows. The fill reads none of their bytes (the access log), and each capture refuses the file.
    let (mut engine, host, _) = fake_engine(0, None);
    let gate = paths(&engine, GATE)[0].clone();
    let worker = paths(&engine, WORKER)[0].clone();
    let backend = engine.enrolled().backends[0].executable.clone();
    for path in [&gate, &worker, &backend] {
        let size = host.inode(path, |file| file.bytes.len());
        host.replace(path, content(path, size + 1));
    }
    host.clear_log();
    set(&mut engine);
    next(&mut engine, &host);
    let unread = |path: &String| !host.log().iter().any(|access| matches!(access, Access::Read(read, _) if read == path));
    assert!(unread(&gate) && unread(&worker) && unread(&backend), "no byte of a file larger than its row is read");
    assert_eq!(reason(&engine.view().roles[GATE]), "file differs from its record row");
    assert_eq!(reason(&engine.view().roles[WORKER]), "file differs from its record row");
    assert_eq!(reason(&engine.view().backends[0].1), "file differs from its record row");
    // A file of its row's size is read and hashed as before.
    let (mut engine, host, _) = fake_engine(0, None);
    set(&mut engine);
    assert!(host.log().iter().any(|access| matches!(access, Access::Read(read, _) if *read == gate)));
    closed(&engine, &host);
}

#[test]
fn bpf_errors_never_read_as_empty_lists() {
    let census_error = |engine: &CaptureEngine<FakeHost>, host: &FakeHost| {
        let rel = rel(engine, GATE);
        host.state().cgroups.get_mut(&rel).expect("the gate cgroup").queries
            .insert(("BPF_CGROUP_SYSCTL".to_string(), true), Err(ReadError::Other));
    };
    let (mut engine, host) = warmed(0);
    census_error(&engine, &host);
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "read failed", "EINVAL from one census query");
    // An overflowing local query (more ids than its capacity).
    let (mut engine, host) = warmed(0);
    let gate = rel(&engine, GATE);
    host.state().cgroups.get_mut(&gate).expect("the gate cgroup").queries
        .insert(("BPF_CGROUP_INET4_BIND".to_string(), false), Err(ReadError::Bound));
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "a read over its bound");
    // A foreign attach flag.
    let (mut engine, host) = warmed(0);
    host.state().cgroups.get_mut(&gate).expect("the gate cgroup").queries
        .insert(("BPF_CGROUP_INET4_BIND".to_string(), false), Ok((vec![1_040], 4)));
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "foreign attach flag");
    // A 65,537-byte program.
    let (mut engine, host) = warmed(0);
    let pin = engine.enrolled().roles[GATE].pins[0].1.clone();
    host.state().pins.get_mut(&pin).expect("a pin").xlated = vec![0u8; 65_537];
    next(&mut engine, &host);
    assert!(matches!(engine.view().roles[GATE], Slot::Unavailable(_)));
    closed(&engine, &host);
}

#[test]
fn listings_refuse_past_their_bounds_and_never_truncate() {
    // 65,536 entries are accepted (the backends still find their processes); 65,537 refuse the scan.
    let (mut engine, host) = warmed(0);
    let count = host.state().procs.len();
    host.state().extra_processes = 65_536 - count;
    next(&mut engine, &host);
    assert!(matches!(engine.view().lifecycle, Slot::Taken { .. }));
    assert!(engine.view().backends.iter().all(|(_, slot)| matches!(slot, Slot::Taken { .. })));
    let (mut engine, host) = warmed(0);
    host.state().extra_processes = 65_537 - count;
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().lifecycle), "process scan bound");
    assert!(engine.view().backends.iter().all(|(_, slot)| reason(slot) == "process scan bound"));
    assert_eq!(host.log().iter().filter(|access| **access == Access::Processes).count(), 1, "one fresh listing");
    // A listing error mid-way and a malformed record buffer.
    for (error, why) in [(ReadError::Other, "process scan failed"), (ReadError::Bound, "process scan bound")] {
        let (mut engine, host) = warmed(0);
        host.state().listing_error = Some(error);
        next(&mut engine, &host);
        assert_eq!(reason(&engine.view().lifecycle), why);
        assert!(engine.view().backends.iter().all(|(_, slot)| reason(slot) == why));
    }
    // A scan past its 5 s deadline.
    let (mut engine, host) = warmed(0);
    host.state().delay = Some(Box::new(|access: &Access| {
        if matches!(access, Access::Process(_)) { Duration::from_secs(1) } else { Duration::ZERO }
    }));
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().lifecycle), "process scan bound");
    // tasks() and children() over their bounds.
    let (mut engine, host) = warmed(0);
    let gate = rel(&engine, GATE);
    {
        let mut state = host.state();
        let pid = state.cgroups.get(&gate).expect("the gate cgroup").procs[0];
        let process = state.procs.get_mut(&pid).expect("a member");
        let thread = process.threads.values().next().expect("a thread").clone();
        for tid in 0..20 {
            process.threads.insert(50_000 + tid, thread.clone());
        }
    }
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "a read over its bound");
    let (mut engine, host) = warmed(0);
    host.state().cgroups.get_mut(&gate).expect("the gate cgroup").children = (0..65).map(|index| format!("c{index}")).collect();
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().roles[GATE]), "a read over its bound");
    // The census walk over 1,024 entries.
    let (mut engine, host) = warmed(0);
    {
        let mut state = host.state();
        for outer in 0..20 {
            let name = format!("planeon.slice/extra-{outer}");
            let mut cgroup = d1_support::FakeCgroup::empty(10_000 + outer);
            cgroup.children = (0..60).map(|inner| format!("leaf-{inner}")).collect();
            for inner in 0..60 {
                state.cgroups.insert(format!("{name}/leaf-{inner}"), d1_support::FakeCgroup::empty(20_000 + inner));
            }
            state.cgroups.insert(name, cgroup);
            state.cgroups.get_mut("planeon.slice").expect("the slice").children.push(format!("extra-{outer}"));
        }
    }
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().lifecycle), "census over 1,024 entries");
    closed(&engine, &host);
}

#[test]
fn the_lifecycle_states_and_a_populated_slice() {
    // EMPTY (the positives'): taken. ABSENT: the containment cgroup gone from the slice. POPULATED: refused.
    let (mut engine, host) = warmed(0);
    next(&mut engine, &host);
    assert_eq!(text(field(&taken(&engine.view().lifecycle), "cgroup"), "state"), "EMPTY");
    let containment = engine.enrolled().containment_rel.clone();
    {
        let mut state = host.state();
        state.cgroups.remove(&containment);
        let name = containment.rsplit_once('/').expect("a leaf").1.to_string();
        let slice = state.cgroups.get_mut("planeon.slice").expect("the slice");
        slice.children.retain(|child| *child != name);
        slice.descendants -= 1;
    }
    next(&mut engine, &host);
    assert_eq!(text(field(&taken(&engine.view().lifecycle), "cgroup"), "state"), "ABSENT");
    let (mut engine, host) = warmed(0);
    host.state().cgroups.get_mut(&containment).expect("the containment cgroup").populated = 1;
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().lifecycle), "containment subject still resident");
    let (mut engine, host) = warmed(0);
    host.state().cgroups.get_mut("planeon.slice").expect("the slice").procs = vec![4_321];
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().lifecycle), "process directly in the planeon slice");
    closed(&engine, &host);
}

#[test]
fn backends_take_the_earliest_candidate() {
    let (mut engine, host) = warmed(0);
    let label = engine.enrolled().backends[0].process_label.clone();
    let pid = host.state().procs.iter().find(|(_, process)| process.label == label).map(|(pid, _)| *pid).expect("a process");
    // Several candidates: the earliest start is taken.
    {
        let mut state = host.state();
        let mut earlier = state.procs.get(&pid).expect("a process").clone();
        earlier.start = 1;
        earlier.generation = 5_000;
        state.procs.insert(9_999, earlier);
    }
    next(&mut engine, &host);
    let capture = taken(&engine.view().backends[0].1);
    assert_eq!(field(field(&capture, "process"), "pid").as_int().and_then(|int| int.to_i64()), Some(9_999));
    // None.
    {
        let mut state = host.state();
        state.procs.remove(&pid);
        state.procs.remove(&9_999);
    }
    next(&mut engine, &host);
    assert_eq!(reason(&engine.view().backends[0].1), "no candidate process");
    closed(&engine, &host);
}

#[test]
fn every_access_is_a_read_of_the_closed_set() {
    let (mut engine, host, _) = fake_engine(1, None);
    set(&mut engine);
    next(&mut engine, &host);
    closed(&engine, &host);
    // The link reads are exactly the five link names and the cgroup reads the seven file names, by the closed enums.
    for access in host.log() {
        if let Access::ProcLink(_, link) = access {
            assert!([LinkItem::Exe, LinkItem::NsUser, LinkItem::NsMnt, LinkItem::NsPid, LinkItem::NsNet].contains(&link));
        }
    }
}
