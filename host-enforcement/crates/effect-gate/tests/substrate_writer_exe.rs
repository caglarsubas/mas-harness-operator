//! HE-003A2 DESIGN §4 and §9: the writer executable check through the substrate's scripted `Os` (`FakePeer::exe_ok`).
//! At accept a mismatch closes the writer unfed (R32) and a later enrolled writer still gets a session; on every I07
//! frame a mismatch is a deviation (`WPeerChanged`, N12: fatal PEER_CHANGED, `WRITER_PEER_DEVIATION`, HELD); the check
//! comes after the label and uid comparison at accept and after the process directory's reads on every frame, and the
//! pidfd probe after it in both; I05 peers are never checked. The Linux read (`ProcDir::exe`) is T04's.

mod substrate_support;

use effect_gate::{ConnId, Listen};

use substrate_support::*;

fn position(trace: &[String], wanted: &str, after: usize) -> usize {
    trace.iter().skip(after).position(|line| line == wanted).map(|at| at + after)
        .unwrap_or_else(|| panic!("{wanted} after {after} in {trace:?}"))
}

const DEVIATION: &str = r#"["INVALIDATED","WRITER_PEER_DEVIATION","HELD"]"#;

#[test]
fn an_enrolled_writer_qualifies_and_the_exe_read_sits_between_the_comparison_and_the_probe() {
    let mut bench = Bench::fresh();
    let conn = bench.connect(Listen::I07, writer_peer());
    assert_eq!(bench.last_output(), r#"{"session":"CONNECTED"}"#);
    assert_eq!(bench.substrate.held(Listen::I07), Some(ConnId(conn)));
    // Qualification order (D1-8): credentials, the process directory, its read, the executable, then the pidfd.
    let trace = bench.trace();
    let peer = position(&trace, &format!("peer #{conn}"), 0);
    let open = position(&trace, &format!("open_proc #{conn} {WRITER_PID}"), peer);
    let read = position(&trace, &format!("read_proc #{conn}"), open);
    let exe = position(&trace, &format!("exe #{conn}"), read);
    position(&trace, &format!("exited #{conn}"), exe);
    assert_eq!(trace.iter().filter(|line| **line == format!("exe #{conn}")).count(), 1, "one read at accept");
}

#[test]
fn a_writer_with_another_executable_is_closed_unfed_and_a_later_enrolled_writer_gets_a_session() {
    let mut bench = Bench::fresh();
    let journal = bench.journal();
    let mut replaced = writer_peer();
    replaced.exe_ok = false;
    let first = bench.connect(Listen::I07, replaced);
    assert!(bench.closed(first));
    assert!(bench.outputs().is_empty(), "no WConnect was fed (R32)");
    assert_eq!(bench.journal(), journal, "nothing is journalled");
    assert!(!bench.gate().session_held() && bench.substrate.held(Listen::I07).is_none());
    // The probe never runs after a failed executable check.
    let trace = bench.trace();
    let exe = position(&trace, &format!("exe #{first}"), 0);
    assert!(!trace[exe..].contains(&format!("exited #{first}")), "{trace:?}");
    let second = bench.connect(Listen::I07, writer_peer());
    assert_eq!(bench.last_output(), r#"{"session":"CONNECTED"}"#);
    assert_eq!(bench.substrate.held(Listen::I07), Some(ConnId(second)));
}

#[test]
fn an_unqualified_writer_is_refused_before_its_executable_is_read() {
    // D1-8: the label and uid comparison comes first, so a peer that is not the writer domain causes no exe read.
    let mut impostor = writer_peer();
    impostor.identity.as_mut().expect("identity").label = broker_label();
    let mut other_uid = writer_peer();
    other_uid.credentials.as_mut().expect("credentials").uid = 1000;
    for (case, peer) in [("process label", impostor), ("uid", other_uid)] {
        let mut bench = Bench::fresh();
        let conn = bench.connect(Listen::I07, peer);
        assert!(bench.closed(conn), "{case}");
        assert!(!bench.trace().contains(&format!("exe #{conn}")), "{case}: {:?}", bench.trace());
    }
}

#[test]
fn a_changed_executable_on_any_frame_is_a_writer_deviation() {
    let mut bench = Bench::fresh();
    let conn = bench.open_writer();
    bench.writer_says(conn, "MAINTENANCE_STATUS", empty()).expect("a wake");
    assert_eq!(bench.sent(conn).len(), 2, "frames from the enrolled executable pass custody");
    // The holder execs another binary, or the binary is replaced (" (deleted)"): the next frame's read mismatches.
    bench.set_peer(conn, |peer| peer.exe_ok = false);
    bench.clear_trace();
    bench.writer_says(conn, "MAINTENANCE_STATUS", empty()).expect("a wake");
    assert_eq!(bench.last_output(), r#"{"fatal":"PEER_CHANGED","maintenance":"NONE","sessionEnd":"FATAL"}"#);
    let journal = bench.journal();
    assert!(journal.contains(&DEVIATION.to_string()));
    assert_eq!(journal.last().map(String::as_str), Some(r#"["WRITER_SESSION_ENDED","FATAL"]"#));
    assert!(bench.closed(conn) && !bench.gate().session_held());
    assert_eq!(bench.state(), "HELD");
    assert_eq!(bench.sent(conn).len(), 2, "the frame is not answered");
    // Custody order: the receive, the process directory's read, the executable, and no probe after a mismatch.
    let trace = bench.trace();
    let received = position(&trace, &format!("recv #{conn}"), 0);
    let read = position(&trace, &format!("read_proc #{conn}"), received);
    let exe = position(&trace, &format!("exe #{conn}"), read);
    assert!(!trace[exe..].contains(&format!("exited #{conn}")), "{trace:?}");
}

#[test]
fn every_writer_frame_reads_the_executable_before_the_probe() {
    let mut bench = Bench::fresh();
    let conn = bench.open_writer();
    for round in 0..3 {
        bench.clear_trace();
        bench.writer_says(conn, "MAINTENANCE_STATUS", empty()).expect("a wake");
        let trace = bench.trace();
        let received = position(&trace, &format!("recv #{conn}"), 0);
        let read = position(&trace, &format!("read_proc #{conn}"), received);
        let exe = position(&trace, &format!("exe #{conn}"), read);
        let probe = position(&trace, &format!("exited #{conn}"), exe);
        position(&trace, &format!("send #{conn}"), probe);
        assert_eq!(trace.iter().filter(|line| **line == format!("exe #{conn}")).count(), 1, "round {round}");
    }
}

#[test]
fn broker_peers_are_never_checked() {
    let mut bench = Bench::fresh();
    // A broker whose executable would not match qualifies and keeps its channel: the check is the writer's only.
    let mut broker = broker_peer();
    broker.exe_ok = false;
    let conn = bench.connect(Listen::I05, broker);
    assert_eq!(bench.substrate.held(Listen::I05), Some(ConnId(conn)));
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("the opening frame");
    bench.broker_says(conn, "GENERATION_STATUS", empty()).expect("a second frame");
    assert_eq!(bench.sent(conn).len(), 2);
    assert!(!bench.closed(conn));
    assert!(bench.trace().iter().all(|line| !line.starts_with("exe #")), "{:?}", bench.trace());
}
