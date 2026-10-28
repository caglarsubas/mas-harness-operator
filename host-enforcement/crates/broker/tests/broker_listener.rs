//! HE-005A (owner decision Q-HE5A-3 (a), MON-HE005A-PLAN2): `serve_unanswered` over a recording fake of the I02
//! listener's seam. The seam offers four operations and no read or write, and the fake records every call it receives,
//! so the recorded sequence is everything the loop did: it listens first, closes each accepted connection before its
//! next wait with nothing written to it and nothing read from it, keeps no connection open, and returns only on a
//! listener error, whose status is the listener's one status (24). The Linux implementation (`linux_listen.rs`) is
//! code review's and T04's.

use std::collections::{BTreeSet, VecDeque};

use planeon_broker::status;
use planeon_broker::{serve_unanswered, I02Listener, ListenerError};

/// One call the loop made on the seam, with the fake's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Listen(Result<(), ListenerError>),
    Wait(Result<(), ListenerError>),
    Accept(Result<Option<u64>, ListenerError>),
    Close(u64),
}

/// The fake: scripted answers, the calls received in order, and the connections accepted and not yet closed.
struct Fake {
    listen: Result<(), ListenerError>,
    waits: VecDeque<Result<(), ListenerError>>,
    accepts: VecDeque<Result<Option<u64>, ListenerError>>,
    calls: Vec<Call>,
    open: BTreeSet<u64>,
}

impl Fake {
    /// A fake whose listen answers `listen`, whose waits answer `waits` in turn and then fail, and whose accepts answer
    /// `accepts` in turn and then find nothing queued.
    fn new(listen: Result<(), ListenerError>, waits: &[Result<(), ListenerError>],
           accepts: &[Result<Option<u64>, ListenerError>]) -> Fake {
        Fake { listen, waits: waits.iter().copied().collect(), accepts: accepts.iter().copied().collect(),
               calls: Vec::new(), open: BTreeSet::new() }
    }
}

impl I02Listener for Fake {
    fn listen(&mut self) -> Result<(), ListenerError> {
        self.calls.push(Call::Listen(self.listen));
        self.listen
    }

    fn wait(&mut self) -> Result<(), ListenerError> {
        let answer = self.waits.pop_front().unwrap_or(Err(ListenerError::Wait));
        self.calls.push(Call::Wait(answer));
        answer
    }

    fn accept(&mut self) -> Result<Option<u64>, ListenerError> {
        let answer = self.accepts.pop_front().unwrap_or(Ok(None));
        if let Ok(Some(connection)) = answer {
            assert!(self.open.insert(connection), "connection {connection} accepted twice");
        }
        self.calls.push(Call::Accept(answer));
        answer
    }

    fn close(&mut self, connection: u64) {
        assert!(self.open.remove(&connection), "connection {connection} closed but not open");
        self.calls.push(Call::Close(connection));
    }
}

const OK: Result<(), ListenerError> = Ok(());

#[test]
fn every_accepted_connection_is_closed_with_nothing_written_or_read() {
    let mut fake = Fake::new(OK, &[OK, OK, OK, OK], &[Ok(Some(1)), Ok(None), Ok(Some(2)), Ok(Some(3))]);
    let error = serve_unanswered(&mut fake);
    assert_eq!(error, ListenerError::Wait, "the fifth wait fails and ends serving");
    assert_eq!(status::listener(&error), 24);
    assert_eq!(fake.calls, [
        Call::Listen(OK),
        Call::Wait(OK), Call::Accept(Ok(Some(1))), Call::Close(1),
        Call::Wait(OK), Call::Accept(Ok(None)),
        Call::Wait(OK), Call::Accept(Ok(Some(2))), Call::Close(2),
        Call::Wait(OK), Call::Accept(Ok(Some(3))), Call::Close(3),
        Call::Wait(Err(ListenerError::Wait)),
    ]);
    assert!(fake.open.is_empty(), "no connection is left open: {:?}", fake.open);
    // Each accepted connection is closed by the very next call, before any other wait or accept.
    for (index, call) in fake.calls.iter().enumerate() {
        if let Call::Accept(Ok(Some(connection))) = call {
            assert_eq!(fake.calls.get(index + 1), Some(&Call::Close(*connection)), "{call:?}");
        }
    }
}

#[test]
fn a_listen_failure_ends_serving_before_any_wait_or_accept() {
    let mut fake = Fake::new(Err(ListenerError::Listen), &[OK], &[Ok(Some(1))]);
    let error = serve_unanswered(&mut fake);
    assert_eq!(error, ListenerError::Listen);
    assert_eq!(status::listener(&error), 24);
    assert_eq!(fake.calls, [Call::Listen(Err(ListenerError::Listen))]);
    let mut fake = Fake::new(Err(ListenerError::Register), &[OK], &[Ok(Some(1))]);
    assert_eq!(serve_unanswered(&mut fake), ListenerError::Register);
    assert_eq!(fake.calls, [Call::Listen(Err(ListenerError::Register))]);
}

#[test]
fn an_accept_failure_ends_serving_with_nothing_open() {
    let mut fake = Fake::new(OK, &[OK, OK, OK], &[Ok(Some(7)), Err(ListenerError::Accept), Ok(Some(8))]);
    let error = serve_unanswered(&mut fake);
    assert_eq!(error, ListenerError::Accept);
    assert_eq!(status::listener(&error), 24);
    assert_eq!(fake.calls, [
        Call::Listen(OK),
        Call::Wait(OK), Call::Accept(Ok(Some(7))), Call::Close(7),
        Call::Wait(OK), Call::Accept(Err(ListenerError::Accept)),
    ]);
    assert!(fake.open.is_empty());
}

#[test]
fn a_wake_with_nothing_queued_only_waits_again() {
    let mut fake = Fake::new(OK, &[OK, OK, OK], &[Ok(None), Ok(None), Ok(None)]);
    assert_eq!(serve_unanswered(&mut fake), ListenerError::Wait);
    let closes = fake.calls.iter().filter(|call| matches!(call, Call::Close(_))).count();
    assert_eq!(closes, 0);
    assert_eq!(fake.calls.len(), 1 + 3 * 2 + 1, "listen, three wait-accept pairs, the failing wait");
}
