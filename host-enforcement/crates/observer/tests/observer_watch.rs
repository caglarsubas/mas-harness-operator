//! HE-004C DESIGN-C sections 5.2 and 9 (Q-HE4C-1 (a), Q-HE4C-14 (a); D1-7, D1-13, D2-5, D3-2): watch lines and streams:
//! each event type, a kind mismatch, extra members, a line growing past 64 KiB (a change), a non-decimal bookmark (a
//! gap), bookmark resume points, the idle deadline, three failed reopens tolerated and the fourth 83, 410 or 504 on the
//! initial open restarting the snapshot, 410 on a reopen 92, and a bookmark below the stream's highest mark ignored.

mod b1_rbac_support;
mod b1_support;
mod c_support;

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use c_support::*;
use planeon_observer::inputs::Resource;
use planeon_observer::observe::{ObserverExit, Trace};
use planeon_observer::watch::{classify, decimal, Event, Lines, LongLine, LINE_LIMIT};

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

#[test]
fn each_event_type() {
    let event = |kind: &str, object: &str| format!(r#"{{"type": "{kind}", "object": {object}}}"#);
    let role = r#"{"kind": "Role", "metadata": {"name": "r", "resourceVersion": "12"}}"#;
    for kind in ["ADDED", "MODIFIED", "DELETED"] {
        assert_eq!(classify(event(kind, role).as_bytes(), "Role"), Event::Change, "{kind}");
    }
    assert_eq!(classify(event("BOOKMARK", role).as_bytes(), "Role"), Event::Bookmark(12));
    assert!(matches!(classify(event("ERROR", r#"{"kind": "Status", "code": 410}"#).as_bytes(), "Role"), Event::Gap(_)));
    assert!(matches!(classify(event("SYNC", role).as_bytes(), "Role"), Event::Gap(_)));
    // A kind mismatch, extra or missing members, a non-object, a non-string type, a non-decimal bookmark: gaps.
    assert!(matches!(classify(event("MODIFIED", role).as_bytes(), "ClusterRole"), Event::Gap(_)));
    assert!(matches!(classify(br#"{"type": "MODIFIED", "object": {"kind": "Role"}, "extra": 1}"#, "Role"), Event::Gap(_)));
    assert!(matches!(classify(br#"{"type": "MODIFIED"}"#, "Role"), Event::Gap(_)));
    assert!(matches!(classify(br#"{"type": "MODIFIED", "object": "Role"}"#, "Role"), Event::Gap(_)));
    assert!(matches!(classify(br#"{"type": 1, "object": {"kind": "Role"}}"#, "Role"), Event::Gap(_)));
    assert!(matches!(classify(br#"["MODIFIED"]"#, "Role"), Event::Gap(_)));
    assert!(matches!(classify(br#"{"type": "MODIFIED", "type": "ADDED", "object": {"kind": "Role"}}"#, "Role"), Event::Gap(_)));
    assert!(matches!(classify(b"\xff", "Role"), Event::Gap(_)));
    for version in ["\"\"", "\"12a\"", "12", "\"18446744073709551616\"", "\"-3\"", "null"] {
        let bookmark = format!(r#"{{"type": "BOOKMARK", "object": {{"kind": "Role", "metadata": {{"resourceVersion": {version}}}}}}}"#);
        assert!(matches!(classify(bookmark.as_bytes(), "Role"), Event::Gap(_)), "{version}");
    }
    // OR05's metadata-only streams carry PartialObjectMetadata.
    let partial = r#"{"kind": "PartialObjectMetadata", "metadata": {"resourceVersion": "9"}}"#;
    assert_eq!(classify(event("BOOKMARK", partial).as_bytes(), "PartialObjectMetadata"), Event::Bookmark(9));
    assert_eq!((decimal("0"), decimal("18446744073709551615"), decimal("00012")), (Some(0), Some(u64::MAX), Some(12)));
}

#[test]
fn lines_and_the_64_kib_bound() {
    let mut lines = Lines::new();
    let mut out = Vec::new();
    lines.push(b"one\ntw", &mut out).expect("bounded");
    lines.push(b"o\n\nthree", &mut out).expect("bounded");
    assert_eq!(out, vec![b"one".to_vec(), b"two".to_vec(), Vec::new()]);
    assert_eq!(lines.held(), 5);
    // A line of exactly 64 KiB (the LF excluded) passes; one that grows past it is a change at once.
    let mut lines = Lines::new();
    let mut out = Vec::new();
    let exact = vec![b'x'; LINE_LIMIT];
    lines.push(&exact, &mut out).expect("at the bound");
    lines.push(b"\n", &mut out).expect("ends");
    assert_eq!(out[0].len(), LINE_LIMIT);
    let mut lines = Lines::new();
    lines.push(&exact, &mut out).expect("at the bound");
    assert_eq!(lines.push(b"y", &mut out), Err(LongLine));
}

#[test]
fn a_line_growing_past_64_kib_is_a_change_and_re_snapshots() {
    let rig = Rig::new();
    let long = format!(r#"{{"type": "MODIFIED", "object": {{"kind": "Role", "data": "{}"}}}}"#, "x".repeat(70_000));
    rig.at(secs(100), Action::Line(Resource::Roles, long));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert_eq!(snapshots(epoch.trace()).len(), 2);
    assert!(traced(epoch.trace(), |entry| *entry == Trace::Change(Resource::Roles)));
}

#[test]
fn malformed_short_lines_are_gaps() {
    for line in [r#"{"type": "MODIFIED", "object": {"kind": "ClusterRole"}}"#,
                 r#"{"type": "BOOKMARK", "object": {"kind": "Role", "metadata": {"resourceVersion": "x"}}}"#,
                 r#"{"type": "ADDED", "object": {"kind": "Role"}, "x": 1}"#, "not json"] {
        let rig = Rig::new();
        rig.at(secs(100), Action::Line(Resource::Roles, line.to_string()));
        assert_eq!(rig.run().0, ObserverExit::WatchGap, "{line}");
    }
}

#[test]
fn a_stream_resumes_from_its_last_bookmark_and_a_lower_one_is_ignored() {
    let rig = Rig::new();
    rig.at(secs(30), Action::Bump(7));
    rig.at(secs(50), Action::Line(Resource::Roles, Api::bookmark(Resource::Roles, 1002)));
    rig.at(secs(100), Action::EndStream(Resource::Roles));
    rig.at(secs(130), Action::Bump(5));
    rig.at(secs(200), Action::EndStream(Resource::Roles));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let opens: Vec<Option<String>> = rig
        .requests("/apis/rbac.authorization.k8s.io/v1/roles")
        .into_iter()
        .filter(|req| req.param("watch") == Some("true"))
        .map(|req| req.param("resourceVersion").map(str::to_string))
        .collect();
    assert_eq!(opens, vec![Some("1000".to_string()), Some("1007".to_string()), Some("1012".to_string())]);
}

#[test]
fn a_silent_stream_ends_after_300_s_and_is_reopened() {
    let mut rig = Rig::new();
    rig.config = config_for(secs(850));
    rig.api(|api| {
        api.quiet.insert(Resource::Roles);
    });
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    let ends: Vec<Duration> = epoch.trace().iter().filter(|(_, entry)| *entry == Trace::StreamEnd(Resource::Roles)).map(|(at, _)| *at).collect();
    assert_eq!(ends, vec![secs(300), secs(600)]);
    assert!(traced(epoch.trace(), |entry| *entry == Trace::Reopened(Resource::Roles)));
}

fn failing_reopens(failures: u32, reply: Reply) -> (ObserverExit, String, Rig) {
    let rig = Rig::new();
    rig.at(secs(90), Action::EndStream(Resource::Roles));
    let count = Rc::new(Cell::new(0u32));
    let seen = count.clone();
    rig.hook(move |req, _| {
        if req.param("watch") == Some("true") && req.path.ends_with("/roles") && req.at >= secs(90) && seen.get() < failures {
            seen.set(seen.get() + 1);
            return Some(reply.clone());
        }
        None
    });
    let (exit, epoch) = rig.run();
    let reason = epoch.reason().to_string();
    (exit, reason, rig)
}

#[test]
fn three_failed_reopens_are_tolerated_and_the_fourth_is_83() {
    for reply in [json(503, "{}"), json(429, "{}"), json(504, "{}"), Reply::Reset] {
        let (exit, reason, rig) = failing_reopens(3, reply.clone());
        assert_eq!(exit, ObserverExit::ConfigExpired, "{reply:?}: {reason}");
        let opens: Vec<Duration> = rig.requests("/apis/rbac.authorization.k8s.io/v1/roles").into_iter()
            .filter(|req| req.param("watch") == Some("true")).map(|req| req.at).collect();
        assert_eq!(opens, vec![secs(0), secs(90), secs(91), secs(92), secs(93)], "1 s apart");
        let (exit, _, _) = failing_reopens(4, reply.clone());
        assert_eq!(exit, ObserverExit::Unreachable, "{reply:?}");
    }
    // 410 on a reopen is a gap; 401/403 is 82; 404 or another status is 84.
    assert_eq!(failing_reopens(1, json(410, "{}")).0, ObserverExit::WatchGap);
    assert_eq!(failing_reopens(1, json(403, "{}")).0, ObserverExit::ReadRefused);
    assert_eq!(failing_reopens(1, json(404, "{}")).0, ObserverExit::Answer);
    assert_eq!(failing_reopens(1, answer(200, "text/plain", b"x")).0, ObserverExit::Answer);
}

#[test]
fn a_410_or_504_on_the_initial_open_restarts_the_snapshot() {
    for code in [410u16, 504] {
        let rig = Rig::new();
        let fired = Rc::new(Cell::new(false));
        let seen = fired.clone();
        rig.hook(move |req, _| {
            if req.param("watch") == Some("true") && req.path.ends_with("/clusterroles") && !seen.get() {
                seen.set(true);
                return Some(json(code, "{}"));
            }
            None
        });
        let (exit, epoch) = rig.run();
        assert_eq!(exit, ObserverExit::ConfigExpired, "{code}: {}", epoch.reason());
        let taken = snapshots(epoch.trace());
        assert_eq!(taken.iter().map(|(at, sequence, _)| (*at, *sequence)).collect::<Vec<_>>(), vec![(secs(0), 1), (secs(1), 2)], "{code}");
    }
    // An initial open that keeps answering 504 restarts within the first snapshot's deadline, then 93.
    let rig = Rig::new();
    rig.hook(|req, _| (req.param("watch") == Some("true") && req.path.ends_with("/clusterroles")).then(|| json(504, "{}")));
    let (exit, epoch) = rig.run();
    assert_eq!((exit, rig.elapsed()), (ObserverExit::Deadline, secs(120)), "{}", epoch.reason());
    // 429 or 503 on the initial open count as failed opens.
    let rig = Rig::new();
    let fired = Rc::new(Cell::new(0u32));
    let seen = fired.clone();
    rig.hook(move |req, _| {
        if req.param("watch") == Some("true") && req.path.ends_with("/clusterroles") && seen.get() < 2 {
            seen.set(seen.get() + 1);
            return Some(json(503, "{}"));
        }
        None
    });
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert_eq!(snapshots(epoch.trace()).len(), 1);
}

#[test]
fn a_lower_bookmark_does_not_count_as_progress() {
    // The Roles stream gets no bookmark of its own but a lower one at 100 s; F (1010, read at 60 s) is never passed by it,
    // so the progress rule fails at 210 s and a fresh snapshot runs.
    let rig = Rig::new();
    rig.api(|api| {
        api.quiet.insert(Resource::Roles);
    });
    rig.at(secs(30), Action::Bump(10));
    rig.at(secs(100), Action::Line(Resource::Roles, Api::bookmark(Resource::Roles, 999)));
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert!(traced(epoch.trace(), |entry| *entry == Trace::Stale(1)));
    assert_eq!(snapshots(epoch.trace()).iter().map(|(at, _, _)| *at).collect::<Vec<_>>()[..2], [secs(0), secs(210)]);
}
