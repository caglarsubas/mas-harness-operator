//! HE-004-I01B5 DESIGN-I01B5 rev 5 sections 3.1, 3.3 and 3.4 (Q-I01B5D-1, -2, -4 and -5, all (a); I5D-4..6, I5E-3,
//! I5E-10; MODEL_DEFINED's HE-004-I01B5 section): the epoch's request round and pushes, on HE-004C's `Rig` (unchanged)
//! with a recording I01 service (`c_support::PushRecorder`) that reports a pending receipt during scripted windows. A
//! round reads `requests::progress()` in the one probe slot and passes once its list answered before its 2 s deadline
//! and every stream is established in the phase with its mark at the list's; its `Passed` rides the next availability
//! push, once. A failed list, a mark error, a mark below F and the deadline each push `Failed` and never escalate; 401
//! and 403 exit 82; the latch holds rounds and `Passed` until the next snapshot's view; the spacing defers a second
//! round to 1 s after the first one's start; the round's mark never enters the progress rule but raises the highest
//! mark; each snapshot pushes one view, refused with the named text without a capture engine.

mod b1_rbac_support;
mod b1_support;
mod c_support;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use c_support::*;
use planeon_observer::client::{Availability, Passed, Round};
use planeon_observer::inputs::Resource;
use planeon_observer::observe::{Epoch, ObserverExit, Trace, NO_CAPTURE_ENGINE_TEXT, REQUEST_ROUND_DEADLINE,
                                REQUEST_ROUND_SPACING};
use planeon_observer::requests;

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// A healthy rig whose configuration expires `lifetime` seconds after the start.
fn healthy(lifetime: u64) -> Rig {
    let mut rig = Rig::new();
    rig.config = config_for(secs(lifetime));
    rig
}

/// Runs an epoch with the recording service and its pending windows.
fn run_with(rig: &Rig, windows: &[(Duration, Duration)]) -> (ObserverExit, Epoch<FakeWire>, Rc<RefCell<Pushed>>) {
    let (service, pushed) = PushRecorder::new(rig, windows);
    let mut epoch = rig.epoch().with_peer_service(Box::new(service));
    let exit = epoch.run();
    (exit, epoch, pushed)
}

/// The progress reads made at `from` or later and before `until` (no cycle reads one there).
fn reads(rig: &Rig, from: Duration, until: Duration) -> Vec<Duration> {
    rig.requests(requests::PROGRESS).iter().map(|req| req.at).filter(|at| from <= *at && *at < until).collect()
}

/// Whether a request is a progress read inside `from..until`.
fn in_window(req: &Req, from: Duration, until: Duration) -> bool {
    req.target == requests::PROGRESS && from <= req.at && req.at < until
}

fn passed(pushed: &Pushed) -> Vec<(Duration, Availability, Passed)> {
    pushed
        .availability
        .iter()
        .filter_map(|(at, availability)| match availability.round {
            Some(Round::Passed(passed)) => Some((*at, *availability, passed)),
            _ => None,
        })
        .collect()
}

fn failed(pushed: &Pushed) -> Vec<Duration> {
    pushed.availability.iter().filter(|(_, availability)| availability.round == Some(Round::Failed)).map(|(at, _)| *at).collect()
}

fn base(rig: &Rig) -> std::time::Instant {
    rig.lab.borrow().base
}

#[test]
fn the_constants() {
    assert_eq!(REQUEST_ROUND_SPACING, secs(1), "COALESCE's source");
    assert_eq!(REQUEST_ROUND_DEADLINE, secs(2), "EXCHANGE_DEADLINE_SECONDS");
    assert_eq!(NO_CAPTURE_ENGINE_TEXT, "no capture engine");
}

#[test]
fn a_round_passes_and_its_passed_rides_the_next_availability_push_once() {
    let rig = healthy(100);
    // The receipt stays pending for 1 s here (the recorder answers nothing), so one round runs.
    let (exit, epoch, pushed) = run_with(&rig, &[(secs(30), secs(31))]);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert_eq!(reads(&rig, secs(1), secs(60)), vec![secs(30)], "one round, at the receipt");
    let pushed = pushed.borrow();
    let passes = passed(&pushed);
    assert_eq!(passes.len(), 1, "{passes:?}");
    let (at, availability, round) = passes[0];
    assert_eq!(at, secs(30));
    assert_eq!(round.started, base(&rig) + secs(30), "the round's own start");
    assert_eq!(round.mark, 1000, "the list's mark");
    assert!(round.started <= round.stamp && round.stamp < round.started + REQUEST_ROUND_DEADLINE);
    assert_eq!((availability.phase, availability.established, availability.fresh), (1, true, true));
    assert!(failed(&pushed).is_empty());
    // The pushes after it carry no round.
    let later: Vec<&(Duration, Availability)> = pushed.availability.iter().filter(|(when, _)| *when > secs(30)).collect();
    assert!(!later.is_empty() && later.iter().all(|(_, availability)| availability.round.is_none()));
    // Without a capture engine each snapshot's view is refused with the named text (Q-I01B5D-4 (a)).
    let views: Vec<(u64, u64, Option<&str>)> = pushed.views.iter().map(|(_, phase, mark, refusal)| (*phase, *mark, *refusal)).collect();
    assert_eq!(views, vec![(1, 1000, Some(NO_CAPTURE_ENGINE_TEXT))]);
}

#[test]
fn a_round_waits_for_every_stream_to_reach_its_mark_within_its_deadline() {
    // The revision moves at 25 s, so the round's mark (1005) is past the streams' (1000) until the 40 s bookmarks.
    let rig = healthy(100);
    rig.at(secs(25), Action::Bump(5));
    let (exit, epoch, pushed) = run_with(&rig, &[(secs(39), secs(41))]);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let pushed = pushed.borrow();
    let passes = passed(&pushed);
    assert_eq!(passes.iter().map(|(at, _, round)| (*at, round.mark)).collect::<Vec<_>>(), vec![(secs(40), 1005)]);
    assert!(failed(&pushed).is_empty());
    // A round started at 35 s meets no bookmark before its deadline: Failed at 37 s, the latch then holding.
    let rig = healthy(100);
    rig.at(secs(25), Action::Bump(5));
    let (exit, _, pushed) = run_with(&rig, &[(secs(35), secs(37))]);
    assert_eq!(exit, ObserverExit::ConfigExpired);
    let pushed = pushed.borrow();
    assert!(passed(&pushed).is_empty());
    assert_eq!(failed(&pushed).first(), Some(&secs(37)));
}

#[test]
fn a_failed_list_a_mark_error_a_mark_below_f_and_the_deadline_push_failed_and_never_escalate() {
    let window = (secs(30), secs(32));
    let body = |version: &str| format!(r#"{{"kind": "NamespaceList", "apiVersion": "v1", "metadata": {{"resourceVersion": "{version}"}}, "items": []}}"#);
    let cases: Vec<(&str, Reply, Duration)> = vec![
        ("a failed list", json(500, r#"{"kind": "Status", "code": 500}"#), secs(30)),
        ("a mark error", json(200, &body("x1")), secs(30)),
        ("a mark below F", json(200, &body("999")), secs(30)),
        ("the deadline", Reply::Delay(secs(3), Box::new(json(200, &body("1000")))), secs(32)),
    ];
    for (name, reply, at) in cases {
        let rig = healthy(100);
        rig.hook(move |req, _| in_window(req, window.0, window.1).then(|| reply.clone()));
        let (exit, epoch, pushed) = run_with(&rig, &[window]);
        assert_eq!(exit, ObserverExit::ConfigExpired, "{name}: {}", epoch.reason());
        assert_eq!(snapshots(epoch.trace()).len(), 1, "{name}: no escalation, no new snapshot");
        assert!(!traced(epoch.trace(), |entry| matches!(entry, Trace::Stale(_))), "{name}");
        let pushed = pushed.borrow();
        assert!(passed(&pushed).is_empty(), "{name}");
        assert_eq!(failed(&pushed).first(), Some(&at), "{name}");
        assert_eq!(reads(&rig, secs(1), secs(60)), vec![secs(30)], "{name}: one round");
    }
}

#[test]
fn a_401_or_403_on_the_round_exits_82() {
    for status in [401u16, 403] {
        let rig = healthy(100);
        rig.hook(move |req, _| in_window(req, secs(30), secs(32)).then(|| json(status, r#"{"kind": "Status"}"#)));
        let (exit, epoch, pushed) = run_with(&rig, &[(secs(30), secs(32))]);
        assert_eq!(exit, ObserverExit::ReadRefused, "{status}: {}", epoch.reason());
        assert_eq!(epoch.reason(), "a request round's read was refused (401 or 403)");
        assert!(passed(&pushed.borrow()).is_empty(), "{status}");
    }
}

#[test]
fn the_latch_holds_rounds_and_passed_until_the_next_snapshot_s_view() {
    // The 30 s round fails (500); the 40 s receipt gets no round; a change at 50 s re-snapshots; the 70 s round passes.
    let rig = healthy(100);
    rig.hook(|req, _| in_window(req, secs(30), secs(32)).then(|| json(500, r#"{"kind": "Status"}"#)));
    rig.at(secs(50), Action::Change(Resource::Roles));
    let windows = [(secs(30), secs(32)), (secs(40), secs(42)), (secs(70), secs(71))];
    let (exit, epoch, pushed) = run_with(&rig, &windows);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert_eq!(reads(&rig, secs(1), secs(60)), vec![secs(30)], "no round while the latch holds");
    assert_eq!(reads(&rig, secs(61), secs(100)), vec![secs(70)]);
    let pushed = pushed.borrow();
    let failures = failed(&pushed);
    assert!(failures.iter().all(|at| *at >= secs(30) && *at <= secs(50)) && failures.contains(&secs(40)), "{failures:?}");
    let passes = passed(&pushed);
    assert_eq!(passes.iter().map(|(at, availability, _)| (*at, availability.phase)).collect::<Vec<_>>(), vec![(secs(70), 2)]);
    assert_eq!(pushed.views.iter().map(|(_, phase, _, _)| *phase).collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn the_spacing_defers_a_second_round_to_one_second_after_the_first_one_s_start() {
    let rig = healthy(100);
    let (exit, epoch, pushed) = run_with(&rig, &[(secs(30), secs(35))]);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    // The wake holds the spacing's end while the receipt stays pending, so each round starts on it.
    assert_eq!(reads(&rig, secs(1), secs(60)), (30..35).map(secs).collect::<Vec<_>>());
    assert_eq!(passed(&pushed.borrow()).len(), 5);
}

#[test]
fn the_round_s_mark_never_enters_the_progress_rule_and_raises_the_highest_mark() {
    // The round's list answers a mark far ahead of the streams: it cannot pass and fails at its deadline; the progress
    // rule never sees it (no staleness snapshot within the run, the cycles' F stay the cycle reads' marks).
    let ahead = r#"{"kind": "NamespaceList", "apiVersion": "v1", "metadata": {"resourceVersion": "2000"}, "items": []}"#;
    let rig = healthy(250);
    rig.hook(move |req, _| in_window(req, secs(30), secs(32)).then(|| json(200, ahead)));
    let (exit, epoch, pushed) = run_with(&rig, &[(secs(30), secs(32))]);
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert!(!traced(epoch.trace(), |entry| matches!(entry, Trace::Stale(_))));
    assert!(epoch.trace().iter().filter_map(|(_, entry)| match entry { Trace::Progress(mark) => Some(*mark), _ => None })
                .all(|mark| mark == 1000));
    assert_eq!(failed(&pushed.borrow()).first(), Some(&secs(32)));
    // I5E-10: the round's mark raised the highest mark, so a later snapshot whose R is below it exits 85.
    let rig = healthy(250);
    rig.hook(move |req, _| in_window(req, secs(30), secs(32)).then(|| json(200, ahead)));
    rig.at(secs(100), Action::Change(Resource::Roles));
    let (exit, epoch, _) = run_with(&rig, &[(secs(30), secs(32))]);
    assert_eq!(exit, ObserverExit::Consistency, "{}", epoch.reason());
    assert_eq!(epoch.reason(), "a new snapshot's R is below an earlier mark");
}
