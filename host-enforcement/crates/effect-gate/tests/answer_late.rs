//! HE-003A's model additions (DESIGN §5.1, §5.7, §8): the R10-defined `Event::AnswerLate` and
//! `PolicyEvent::WAnswerLate` (owner decision Q-HE3A-2 (b)), the read-only accessors the substrate reads, and the
//! manual `Debug` of `FileStores`. No existing event's answer changes; the vector replays show that.

mod substrate_support;

use effect_gate::{BoundRun, ChannelState, Event, FatalReason, FrameInput, PolicyEvent, PolicyGate, WriterFatal};
use i05_protocol::json::Value;

use substrate_support::{begin_payload, broker_frame, config, empty, kinds, new_gate, object, place, role_create, stores,
                        t01, writer_frame};

fn handle(gate: &mut PolicyGate, event: PolicyEvent) -> String {
    let output = gate.handle(event).unwrap_or_else(|error| panic!("refused: {error:?}"));
    String::from_utf8_lossy(&output.to_doc().canonical()).into_owned()
}

fn broker(gate: &mut PolicyGate, operation: &str, payload: Value) -> String {
    let bytes = broker_frame(gate, operation, payload);
    handle(gate, PolicyEvent::Base(Event::Frame(FrameInput::Bytes(bytes))))
}

fn writer(gate: &mut PolicyGate, operation: &str, payload: Value) -> String {
    let bytes = writer_frame(gate, operation, payload);
    handle(gate, PolicyEvent::WFrame(FrameInput::Bytes(bytes)))
}

fn records(gate: &PolicyGate) -> Vec<String> {
    let doc = effect_gate::journal::journal_doc(gate.gate().journal()).to_value();
    doc.as_array()
        .map(|items| {
            items.iter().map(|item| String::from_utf8_lossy(&i05_protocol::json::canonical(item).expect("record")).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_reasons_are_answer_late() {
    assert_eq!(FatalReason::AnswerLate.as_str(), "ANSWER_LATE");
    assert_eq!(WriterFatal::AnswerLate.as_str(), "ANSWER_LATE");
}

#[test]
fn answer_late_needs_an_open_channel() {
    let mut gate = new_gate();
    let before = gate.snapshot().canonical();
    assert!(gate.handle(PolicyEvent::Base(Event::AnswerLate)).is_err(), "UNOPENED");
    assert_eq!(gate.snapshot().canonical(), before, "an EventError changes nothing");
    broker(&mut gate, "GENERATION_STATUS", empty());
    gate.handle(PolicyEvent::Base(Event::ChannelLost)).expect("a channel loss");
    let before = gate.snapshot().canonical();
    assert!(gate.handle(PolicyEvent::Base(Event::AnswerLate)).is_err(), "CLOSED");
    assert_eq!(gate.snapshot().canonical(), before);
}

#[test]
fn answer_late_on_an_open_channel_is_fatal_and_held_and_denies_armed_actions() {
    let mut gate = new_gate();
    broker(&mut gate, "GENERATION_STATUS", empty());
    broker(&mut gate, "BIND_EXECUTION", t01("BIND_EXECUTION"));
    broker(&mut gate, "ARM_ACTION", t01("ARM_ACTION"));
    assert_eq!(handle(&mut gate, PolicyEvent::Base(Event::AnswerLate)), r#"{"fatal":"ANSWER_LATE"}"#);
    assert_eq!(gate.gate().state().as_str(), "HELD");
    assert_eq!(gate.channel_state(), ChannelState::Closed);
    let journal = records(&gate);
    assert_eq!(journal[journal.len() - 2..], [r#"["INVALIDATED","ANSWER_LATE","HELD"]"#.to_string(),
                                              r#"["DENIED",1]"#.to_string()]);
    // In an orderly state too: HELD, never the broker's orderly end.
    let mut gate = new_gate();
    broker(&mut gate, "GENERATION_STATUS", empty());
    broker(&mut gate, "CLOSE_GENERATION", object(vec![("reason", Value::str("NORMAL_DRAIN"))]));
    assert_eq!(gate.gate().state().as_str(), "CLOSED");
    assert_eq!(handle(&mut gate, PolicyEvent::Base(Event::AnswerLate)), r#"{"fatal":"ANSWER_LATE"}"#);
    assert_eq!(gate.gate().state().as_str(), "HELD");
}

#[test]
fn w_answer_late_ends_the_session_in_n12s_order() {
    let mut gate = new_gate();
    assert_eq!(handle(&mut gate, PolicyEvent::WAnswerLate), "{}", "without a session");
    handle(&mut gate, PolicyEvent::WConnect { challenge: String::new() });
    writer(&mut gate, "MAINTENANCE_STATUS", empty());
    writer(&mut gate, "WRITE_BEGIN", begin_payload());
    let before = records(&gate).len();
    assert_eq!(handle(&mut gate, PolicyEvent::WAnswerLate),
               r#"{"fatal":"ANSWER_LATE","maintenance":"ENDED","sessionEnd":"FATAL"}"#);
    assert_eq!(records(&gate)[before..], [
        r#"["INVALIDATED","ANSWER_LATE","HELD"]"#.to_string(),
        r#"["WRITER_SESSION_ENDED","FATAL"]"#.to_string(),
        r#"["MAINT_ENDED","SESSION_FATAL",0,[]]"#.to_string(),
    ]);
    assert_eq!(gate.gate().state().as_str(), "HELD");
    assert!(!gate.session_held());
    // A session that does not own the maintenance ends without MAINT_ENDED.
    let mut gate = new_gate();
    handle(&mut gate, PolicyEvent::WConnect { challenge: String::new() });
    let before = records(&gate).len();
    assert_eq!(handle(&mut gate, PolicyEvent::WAnswerLate),
               r#"{"fatal":"ANSWER_LATE","maintenance":"NONE","sessionEnd":"FATAL"}"#);
    assert_eq!(records(&gate)[before..], [r#"["INVALIDATED","ANSWER_LATE","HELD"]"#.to_string(),
                                          r#"["WRITER_SESSION_ENDED","FATAL"]"#.to_string()]);
}

#[test]
fn the_accessors_read_the_model() {
    let mut gate = new_gate();
    assert_eq!((gate.channel_state(), gate.bound_run(), gate.session_held(), gate.pending_write()),
               (ChannelState::Unopened, None, false, None));
    broker(&mut gate, "GENERATION_STATUS", empty());
    broker(&mut gate, "BIND_EXECUTION", t01("BIND_EXECUTION"));
    assert_eq!(gate.channel_state(), ChannelState::Open);
    assert_eq!(gate.bound_run(), Some(BoundRun { execution_id: "1".repeat(64), run_nonce: "run-one".to_string(),
                                                 expired: false }));
    handle(&mut gate, PolicyEvent::Base(Event::Expire));
    assert!(gate.bound_run().is_some_and(|run| run.expired));
    handle(&mut gate, PolicyEvent::Base(Event::Backlog { conn: "c1".to_string() }));
    assert!(!gate.connection_open("c1"), "a queued connection is not open");
    handle(&mut gate, PolicyEvent::Base(Event::Accept { conn: "c1".to_string() }));
    assert!(gate.connection_open("c1") && !gate.connection_open("c2"));
    handle(&mut gate, PolicyEvent::WConnect { challenge: String::new() });
    assert!(gate.session_held());
    writer(&mut gate, "MAINTENANCE_STATUS", empty());
    writer(&mut gate, "WRITE_BEGIN", begin_payload());
    assert_eq!(gate.pending_write(), None);
    assert_eq!(writer(&mut gate, "WRITE_OBJECT", role_create(1)), r#"{"forwarded":1}"#);
    assert_eq!(gate.pending_write(), Some(1));
}

#[test]
fn file_stores_debug_prints_the_generation_only() {
    let (journal, marker) = place("debug");
    let opened = stores(&journal, &marker);
    assert_eq!(format!("{opened:?}"), format!("FileStores {{ generation: {:?}, .. }}", substrate_support::GENERATION));
}

#[test]
fn after_a_restart_the_channel_is_closed_and_the_bound_run_comes_from_the_journal() {
    let (journal, marker) = place("restart");
    let (converted, kernel) = effect_gate::fake_kernel::convert_v3_config(&config()).expect("v4's conversion");
    let mut gate = PolicyGate::create(&converted, &kinds(), stores(&journal, &marker)).expect("a new generation")
        .with_observer(Box::new(effect_gate::KernelObserver::new(kernel)));
    broker(&mut gate, "GENERATION_STATUS", empty());
    broker(&mut gate, "BIND_EXECUTION", t01("BIND_EXECUTION"));
    drop(gate);
    let (gate, _) = PolicyGate::open(&converted, &kinds(), stores(&journal, &marker)).expect("the restart");
    assert_eq!(gate.channel_state(), ChannelState::Closed);
    assert_eq!(gate.bound_run(), Some(BoundRun { execution_id: "1".repeat(64), run_nonce: "run-one".to_string(),
                                                 expired: false }));
    assert!(!gate.session_held());
}

#[test]
fn a_restart_after_answer_late_is_held() {
    // The journal file's decoder knows ANSWER_LATE (R42), so the reopened journal holds the record as written, its
    // digest is the one before the restart, and the restart is HELD, the state it names.
    let (journal, marker) = place("answer-late");
    let (converted, kernel) = effect_gate::fake_kernel::convert_v3_config(&config()).expect("v4's conversion");
    let mut gate = PolicyGate::create(&converted, &kinds(), stores(&journal, &marker)).expect("a new generation")
        .with_observer(Box::new(effect_gate::KernelObserver::new(kernel)));
    broker(&mut gate, "GENERATION_STATUS", empty());
    handle(&mut gate, PolicyEvent::Base(Event::AnswerLate));
    let invalidated = records(&gate).len() - 1;
    let digest = gate.gate().journal_digest();
    drop(gate);
    let (gate, output) = PolicyGate::open(&converted, &kinds(), stores(&journal, &marker)).expect("the restart");
    assert!(String::from_utf8_lossy(&output.to_doc().canonical()).contains(r#""restartState":"HELD""#));
    assert_eq!(records(&gate)[invalidated], r#"["INVALIDATED","ANSWER_LATE","HELD"]"#);
    // HE-003A PR review round 1, R1-3 (f): the reopened journal, up to the restart's own RESTARTED record, has the
    // digest the journal had before the restart.
    assert!(records(&gate)[invalidated + 1].starts_with(r#"["RESTARTED","#), "{:?}", records(&gate));
    let reopened = effect_gate::journal::journal_doc(&gate.gate().journal()[..=invalidated]).canonical();
    assert_eq!(i05_protocol::sha256::prefixed(&reopened), digest);
    assert_eq!(gate.gate().state().as_str(), "HELD");
}
