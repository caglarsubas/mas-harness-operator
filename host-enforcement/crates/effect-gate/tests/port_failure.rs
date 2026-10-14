//! HE-003B: the ports' `failure()` (DESIGN §4.2, Q-HE3B-13 (a), MODEL_DEFINED R56). A failure set in `apply` or in
//! `sync` stops the loop with `LoopExit::Port` before any further event (the port's next queued event and the other
//! port's later outputs); a failed port stops the loop before a wait; a drain that fails stops it before its events
//! and the I05 frame. HE-003A's fakes are reused unchanged (`substrate_support`), wrapped by `port_support`.

mod port_support;
mod substrate_support;

use effect_gate::substrate::{I05_CONN_TOKEN, I05_LISTENER_TOKEN};
use effect_gate::{ChannelState, Event, Lifetimes, Listen, LoopExit, Owner, PolicyEvent};

use port_support::{failing, FailingLoop, Trigger};
use substrate_support::*;

fn i04_token() -> u64 {
    Owner::I04.token(1).expect("a 56-bit value")
}

/// One scripted wake reporting `ready`.
fn wake(lab: &Shared, substrate: &mut FailingLoop, ready: Vec<(u64, effect_gate::Readiness)>) -> Result<(), LoopExit> {
    lab.borrow_mut().wakes.push_back(Wake { ready, ..Wake::default() });
    substrate.turn()
}

fn two_accepts() -> Vec<PolicyEvent> {
    vec![PolicyEvent::Base(Event::Backlog { conn: "i04-1".to_string() }),
         PolicyEvent::Base(Event::Accept { conn: "i04-1".to_string() })]
}

#[test]
fn a_failure_set_in_apply_stops_the_loop_before_the_next_event() {
    let (lab, substrate) = failing(new_gate(), Lifetimes::default(), Trigger::Apply(1));
    let mut substrate = substrate.expect("the substrate starts");
    lab.borrow_mut().i04.ready.push_back(two_accepts());
    let exit = wake(&lab, &mut substrate, vec![(i04_token(), readable())]);
    assert_eq!(exit, Err(LoopExit::Port(Owner::I04, "failed in apply")));
    // The Backlog was fed and answered; the Accept queued after it was not.
    assert!(!substrate.gate().connection_open("i04-1"));
    assert_eq!(lab.borrow().i04.outputs.len(), 1);
    assert_eq!(lab.borrow().upstream.outputs.len(), 1, "the other port saw the one output, and nothing later");
}

#[test]
fn a_failure_set_in_sync_stops_the_loop_too() {
    let (lab, substrate) = failing(new_gate(), Lifetimes::default(), Trigger::Sync(1));
    let mut substrate = substrate.expect("the substrate starts");
    lab.borrow_mut().i04.ready.push_back(two_accepts());
    let exit = wake(&lab, &mut substrate, vec![(i04_token(), readable())]);
    assert_eq!(exit, Err(LoopExit::Port(Owner::I04, "failed in sync")));
    assert!(!substrate.gate().connection_open("i04-1"));
    assert_eq!(lab.borrow().upstream.outputs.len(), 1);
}

#[test]
fn a_failed_port_never_sits_in_a_wait() {
    let (lab, substrate) = failing(new_gate(), Lifetimes::default(), Trigger::Start);
    let mut substrate = substrate.expect("the substrate starts");
    let exit = substrate.turn();
    assert_eq!(exit, Err(LoopExit::Port(Owner::I04, "failed from the start")));
    assert!(lab.borrow().waits.is_empty(), "no wait, with or without a deadline");
}

#[test]
fn a_drain_that_fails_stops_the_loop_before_the_frame() {
    let (lab, substrate) = failing(new_gate(), Lifetimes::default(), Trigger::Drain);
    let mut substrate = substrate.expect("the substrate starts");
    lab.borrow_mut().accepts.entry(Listen::I05).or_default().push_back(Ok(broker_peer()));
    wake(&lab, &mut substrate, vec![(I05_LISTENER_TOKEN, readable())]).expect("the accept wake");
    let conn = substrate.held(Listen::I05).expect("the broker connection is held").0;
    lab.borrow_mut().i04.backlog.push_back(two_accepts());
    let frame = broker_frame(substrate.gate(), "GENERATION_STATUS", empty());
    lab.borrow_mut().conns.get_mut(&conn).expect("a fake connection").inbox.push_back(datagram(frame, broker_control()));
    let exit = wake(&lab, &mut substrate, vec![(I05_CONN_TOKEN, readable())]);
    assert_eq!(exit, Err(LoopExit::Port(Owner::I04, "failed in the drain")));
    assert_eq!(substrate.gate().gate().channel_state(), ChannelState::Unopened, "the frame was never fed");
    assert!(lab.borrow().conns.get(&conn).is_some_and(|fake| fake.sent.is_empty()), "no answer was sent");
    assert!(!substrate.gate().connection_open("i04-1"), "the drained events were not fed either");
}
