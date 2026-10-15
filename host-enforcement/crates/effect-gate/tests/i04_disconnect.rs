//! HE-003B: the R10-defined `Event::Disconnect` (DESIGN §4.3, MODEL_DEFINED R44). It removes an I04 connection the
//! port ended before any request, with no counter change and no journal record; the closed-entry case is defensive;
//! an unknown connection or one with a request is an `EventError`; and a later ARM flush counts only the connections
//! it closed, never one already gone. HE-002's to HE-003A's test files are unchanged; every vector replay passes as
//! before (no vector feeds `Disconnect`).

mod substrate_support;

use std::collections::BTreeMap;

use effect_gate::{Event, EventError, Lifetimes, OutputKind, Owner, PolicyEvent, PolicyGate, PolicyOutputKind};
use i05_protocol::json::{self, Value};

use substrate_support::*;

fn base(event: Event) -> PolicyEvent {
    PolicyEvent::Base(event)
}

fn conn(name: &str) -> String {
    name.to_string()
}

fn feed(gate: &mut PolicyGate, event: Event) -> Result<OutputKind, EventError> {
    gate.handle(base(event)).map(|output| match output.kind {
        PolicyOutputKind::Base(output) => output.kind,
        other => panic!("a base output, not {other:?}"),
    })
}

fn snapshot(gate: &PolicyGate) -> Value {
    gate.gate().snapshot().to_value()
}

fn text(value: Option<&Value>) -> String {
    value.map(|value| String::from_utf8_lossy(&json::canonical(value).expect("canonical")).into_owned()).unwrap_or_default()
}

fn accepted(gate: &mut PolicyGate, name: &str) {
    assert_eq!(feed(gate, Event::Backlog { conn: conn(name) }), Ok(OutputKind::Nothing));
    assert!(matches!(feed(gate, Event::Accept { conn: conn(name) }), Ok(OutputKind::Stamp(_))));
    assert!(gate.connection_open(name));
}

#[test]
fn a_disconnect_removes_an_unfed_entry_and_records_nothing() {
    let mut gate = new_gate();
    accepted(&mut gate, "i04-1");
    let before = snapshot(&gate);
    let journal = gate.gate().journal().len();
    assert_eq!(feed(&mut gate, Event::Disconnect { conn: conn("i04-1") }), Ok(OutputKind::Nothing));
    let after = snapshot(&gate);
    assert!(!gate.connection_open("i04-1"));
    assert_eq!(text(after.get("connections")), "{}", "the entry is gone");
    assert_eq!(text(after.get("counters")), text(before.get("counters")), "no counter moves");
    assert_eq!(gate.gate().journal().len(), journal, "nothing is journalled");
    assert_eq!(text(after.get("state")), text(before.get("state")));
}

#[test]
fn an_unknown_connection_or_one_with_a_request_is_refused() {
    let mut gate = new_gate();
    assert_eq!(feed(&mut gate, Event::Disconnect { conn: conn("i04-9") }),
               Err(EventError("disconnect of an unaccepted connection")));
    // Queued but not accepted: still unknown to the connection map.
    assert_eq!(feed(&mut gate, Event::Backlog { conn: conn("i04-2") }), Ok(OutputKind::Nothing));
    assert_eq!(feed(&mut gate, Event::Disconnect { conn: conn("i04-2") }),
               Err(EventError("disconnect of an unaccepted connection")));
    accepted(&mut gate, "i04-3");
    let request = Event::Request { conn: conn("i04-3"), certificate_digest: String::new(), head: String::new(),
                                   body_digest: None };
    assert!(matches!(feed(&mut gate, request), Ok(OutputKind::Close(_))));
    let before = text(Some(&snapshot(&gate)));
    assert_eq!(feed(&mut gate, Event::Disconnect { conn: conn("i04-3") }), Err(EventError("disconnect after a request")));
    assert_eq!(text(Some(&snapshot(&gate))), before, "a refused event changes nothing");
}

#[test]
fn a_closed_entry_without_a_request_is_removed_too() {
    // The defensive branch: the port never feeds it (a connection the model closed gets no Disconnect), but the rule
    // accepts an entry with no request whether it is open or closed.
    let mut gate = new_gate();
    accepted(&mut gate, "i04-4");
    assert!(gate.handle(base(Event::GateRestart)).is_ok());
    assert!(!gate.connection_open("i04-4"));
    assert_eq!(text(snapshot(&gate).get("connections")), r#"{"i04-4":"CLOSED"}"#);
    assert_eq!(feed(&mut gate, Event::Disconnect { conn: conn("i04-4") }), Ok(OutputKind::Nothing));
    assert_eq!(text(snapshot(&gate).get("connections")), "{}");
}

#[test]
fn an_arm_flush_counts_only_the_connections_it_closed() {
    let lifetimes = Lifetimes::new(BTreeMap::from([("run-one".to_string(), 1_900_000_000 + 3600)]));
    let mut bench = Bench::new(new_gate(), lifetimes);
    let broker = bench.open_broker();
    bench.broker_says(broker, "BIND_EXECUTION", t01("BIND_EXECUTION")).expect("a wake");
    bench.lab.borrow_mut().i04.ready.push_back(vec![
        base(Event::Backlog { conn: conn("i04-1") }),
        base(Event::Accept { conn: conn("i04-1") }),
        base(Event::Backlog { conn: conn("i04-2") }),
        base(Event::Accept { conn: conn("i04-2") }),
        base(Event::Disconnect { conn: conn("i04-1") }),
    ]);
    bench.wake(vec![(Owner::I04.token(1).expect("a 56-bit value"), readable())]).expect("a wake");
    assert!(!bench.gate().connection_open("i04-1") && bench.gate().connection_open("i04-2"));
    bench.broker_says(broker, "ARM_ACTION", t01("ARM_ACTION")).expect("a wake");
    let after = snapshot(bench.gate());
    assert_eq!(text(after.get("connections")), r#"{"i04-2":"CLOSED"}"#);
    assert_eq!(text(after.get("counters").and_then(|counters| counters.get("flushClosures"))), "1");
    assert!(!bench.gate().connection_open("i04-1"));
}
