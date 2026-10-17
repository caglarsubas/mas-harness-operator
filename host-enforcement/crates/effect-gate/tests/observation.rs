//! HE-003A3 host tests (DESIGN section 9): the observation driver's every step and cause on the fake kernel (each
//! errno, marker, bound and malformed content the reads can return), the numeric edges, a fresh read at every call
//! and the pidfd closed on every path; the two parsers' grammar edges and overflows; the default `Unobserved` and the
//! log's bound and drop counter through a gate; and the IR5-1 vector: for each of the nine answers before the
//! observation, a BIND naming a worker that does not exist is answered by that refusal and the observer is not called.

mod observation_support;
mod support;

use std::cell::RefCell;
use std::rc::Rc;

use effect_gate::fake_kernel::FakeKernel;
use effect_gate::observation::{parse_leaf_procs, parse_stat_start, ENOENT, ESRCH, LEAF_PROCS_LIMIT, LOG_ENTRIES, STAT_LIMIT};
use effect_gate::{Cause, Event, Gate, KernelFail, KernelObserver, Observation, Step, Unobserved, WorkerObserver};
use i05_protocol::json::{self, Value};
use observation_support::*;
use support::*;

const LEAF: &str = "/planeon.slice/planeon-capacity-broker.service/probe-worker";

fn kernel(processes: &[(i64, i64, &str)]) -> FakeKernel {
    let rows: Vec<String> = processes
        .iter()
        .map(|(pid, start, cgroup)| format!(r#"{{"cgroup":"{cgroup}","pid":{pid},"startTicks":{start}}}"#))
        .collect();
    let table = json::parse(&format!(r#"{{"processes":[{}]}}"#, rows.join(","))).expect("a table");
    FakeKernel::from_table(Some(&table)).expect("a valid table")
}

fn standard() -> FakeKernel {
    kernel(&[(4100, 900001, LEAF), (4200, 900002, LEAF), (5100, 800001, "/planeon.slice/planeon-proxy-server.service")])
}

fn not(step: Step, cause: Cause) -> Observation {
    Observation::NotObserved { step, cause }
}

fn observe(kernel: &FakeKernel, pid: i64, start: i64) -> Observation {
    KernelObserver::new(kernel.clone()).observe(pid, start)
}

fn race(kernel: &FakeKernel, after: &str, event: &str) {
    let race = json::parse(&format!(r#"{{"type":"OBSERVATION_RACE_NEXT","after":"{after}","event":{event}}}"#)).expect("a race");
    assert_eq!(kernel.event(&race), Ok(true));
}

#[test]
fn a_live_leaf_member_with_its_start_time_is_observed() {
    let kernel = standard();
    assert_eq!(observe(&kernel, 4100, 900001), Observation::Observed);
    assert_eq!(observe(&kernel, 4200, 900002), Observation::Observed, "any member may be named");
    assert!(kernel.idle() && kernel.fault().is_none());
}

#[test]
fn step_one_every_failure_and_shape() {
    let kernel = standard();
    for fail in [KernelFail::Os(5), KernelFail::Os(ENOENT), KernelFail::Os(ESRCH), KernelFail::TooLong, KernelFail::NoErrno] {
        kernel.fail_next(Step::Membership, fail);
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::Membership, Cause::Unreadable), "{fail:?}");
    }
    for bytes in [b"4100".to_vec(), b"04100\n".to_vec(), b"+4100\n".to_vec(), b"\n".to_vec(), b"4100\n\n".to_vec(),
                  b"4100 \n".to_vec(), b"41a0\n".to_vec(), b"2147483648\n".to_vec(), b"4100\r\n".to_vec()] {
        kernel.reply_next(Step::Membership, bytes.clone());
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::Membership, Cause::Unreadable), "{bytes:?}");
    }
    // The driver re-checks the bound: a reads implementation that returns more is still unreadable.
    let mut long = b"4100\n".to_vec();
    long.resize(LEAF_PROCS_LIMIT + 1, b'\n');
    kernel.reply_next(Step::Membership, long);
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::Membership, Cause::Unreadable));
    assert_eq!(observe(&kernel, 5100, 800001), not(Step::Membership, Cause::NotListed), "a process outside the leaf");
    assert_eq!(observe(&kernel, 4300, 900003), not(Step::Membership, Cause::NotListed), "no such process");
    assert!(kernel.idle());
}

#[test]
fn step_one_numeric_edges() {
    let kernel = standard();
    // A `0` line (a task outside the reader's pid namespace) never matches, not even a BIND naming 0.
    kernel.reply_next(Step::Membership, b"0\n4100\n".to_vec());
    assert_eq!(observe(&kernel, 0, 900001), not(Step::Membership, Cause::NotListed));
    for pid in [-1, -4100, i64::from(i32::MAX) + 1, i64::MAX, i64::MIN, 4100 + (1 << 32)] {
        assert_eq!(observe(&kernel, pid, 900001), not(Step::Membership, Cause::NotListed), "{pid}");
    }
    // Duplicates and any order are accepted.
    kernel.reply_next(Step::Membership, b"4200\n4100\n4100\n".to_vec());
    assert_eq!(observe(&kernel, 4100, 900001), Observation::Observed);
}

#[test]
fn step_two_esrch_is_gone_and_any_other_failure_is_open_failed() {
    let kernel = standard();
    kernel.fail_next(Step::PidfdOpen, KernelFail::Os(ESRCH));
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::PidfdOpen, Cause::Gone));
    for fail in [KernelFail::Os(24), KernelFail::Os(22), KernelFail::Os(ENOENT), KernelFail::TooLong, KernelFail::NoErrno] {
        kernel.fail_next(Step::PidfdOpen, fail);
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::PidfdOpen, Cause::OpenFailed), "{fail:?}");
    }
    race(&kernel, "CGROUP_PROCS", r#"{"type":"KERNEL_EXIT","pid":4100}"#);
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::PidfdOpen, Cause::Gone), "the fake's own ESRCH");
}

#[test]
fn step_three_every_failure_shape_and_value() {
    let kernel = standard();
    for fail in [KernelFail::Os(ENOENT), KernelFail::Os(ESRCH)] {
        kernel.fail_next(Step::StartTime, fail);
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::StartTime, Cause::Gone), "{fail:?}");
    }
    for fail in [KernelFail::Os(13), KernelFail::Os(5), KernelFail::TooLong, KernelFail::NoErrno] {
        kernel.fail_next(Step::StartTime, fail);
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::StartTime, Cause::Unreadable), "{fail:?}");
    }
    let fields = "S 1 4100 4100 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0";
    for bytes in [format!("4100 (w) {fields} 900001"), format!("4100 (w) {fields} 900001\n\n"),
                  format!("4100 (w) {fields}  900001\n"), format!("4100 (w) {fields} x900001\n"),
                  format!("4100 w) {fields} 900001\n"), format!("4100 (w) S 1\n")] {
        kernel.reply_next(Step::StartTime, bytes.clone().into_bytes());
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::StartTime, Cause::Unreadable), "{bytes:?}");
    }
    let mut long = format!("4100 (w) {fields} 900001 ").into_bytes();
    long.resize(STAT_LIMIT, b'0');
    long.push(b'\n');
    kernel.reply_next(Step::StartTime, long);
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::StartTime, Cause::Unreadable), "past the 4096-byte bound");
    assert_eq!(observe(&kernel, 4100, 900002), not(Step::StartTime, Cause::StartDiffers));
    assert_eq!(observe(&kernel, 4100, -900001), not(Step::StartTime, Cause::StartDiffers), "a negative start");
    assert_eq!(observe(&kernel, 4100, i64::MIN), not(Step::StartTime, Cause::StartDiffers));
    race(&kernel, "PIDFD_OPEN", r#"{"type":"KERNEL_EXIT","pid":4100}"#);
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::StartTime, Cause::Gone), "the fake's own ENOENT");
}

#[test]
fn step_three_compares_at_full_width() {
    let big = kernel(&[(4100, i64::MAX, LEAF)]);
    assert_eq!(observe(&big, 4100, i64::MAX), Observation::Observed);
    assert_eq!(observe(&big, 4100, i64::MAX - 1), not(Step::StartTime, Cause::StartDiffers));
    let fields = "S 1 4100 4100 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0";
    big.reply_next(Step::StartTime, format!("4100 (w) {fields} {}\n", u64::MAX).into_bytes());
    assert_eq!(observe(&big, 4100, i64::MAX), not(Step::StartTime, Cause::StartDiffers), "u64::MAX is not an i64");
}

#[test]
fn step_four_reads_afresh() {
    let kernel = standard();
    for fail in [KernelFail::Os(5), KernelFail::TooLong, KernelFail::NoErrno] {
        kernel.fail_next(Step::Recheck, fail);
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::Recheck, Cause::Unreadable), "{fail:?}");
    }
    kernel.reply_next(Step::Recheck, b"x\n".to_vec());
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::Recheck, Cause::Unreadable));
    race(&kernel, "STAT", r#"{"type":"KERNEL_MOVE","pid":4100,"cgroup":"/planeon.slice"}"#);
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::Recheck, Cause::NotListed));
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::Membership, Cause::NotListed), "no earlier answer is kept");
}

#[test]
fn step_five_a_poll_error_and_an_exit() {
    let kernel = standard();
    for fail in [KernelFail::Os(12), KernelFail::Os(ESRCH), KernelFail::NoErrno] {
        kernel.fail_next(Step::Liveness, fail);
        assert_eq!(observe(&kernel, 4100, 900001), not(Step::Liveness, Cause::PollFailed), "{fail:?}");
    }
    race(&kernel, "CGROUP_RECHECK", r#"{"type":"KERNEL_EXIT","pid":4100}"#);
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::Liveness, Cause::Exited));
    // A reuse with the same start in the leaf between steps 2 and 5 is caught only by the held pidfd.
    let kernel = standard();
    race(&kernel, "PIDFD_OPEN", r#"{"type":"KERNEL_EXIT","pid":4100}"#);
    race(&kernel, "PIDFD_OPEN", &format!(r#"{{"type":"KERNEL_SPAWN","pid":4100,"startTicks":900001,"cgroup":"{LEAF}"}}"#));
    assert_eq!(observe(&kernel, 4100, 900001), not(Step::Liveness, Cause::Exited));
    assert_eq!(observe(&kernel, 4100, 900001), Observation::Observed, "the reused pid is now the held process");
}

#[test]
fn the_pidfd_closes_on_every_path() {
    // After an observation that stops at step 2, 3, 4 or 5 holding (or not holding) a pidfd, the next observation's
    // first read is step 1 again: the fake tells step 4 by a pidfd the driver still holds, so none is left held.
    for (step, fail) in [(Step::PidfdOpen, KernelFail::Os(24)), (Step::StartTime, KernelFail::Os(13)),
                         (Step::Recheck, KernelFail::Os(5)), (Step::Liveness, KernelFail::Os(12))] {
        let kernel = standard();
        let mut observer = KernelObserver::new(kernel.clone());
        kernel.fail_next(step, fail);
        assert!(matches!(observer.observe(4100, 900001), Observation::NotObserved { .. }));
        kernel.fail_next(Step::Membership, KernelFail::Os(5));
        assert_eq!(observer.observe(4100, 900001), not(Step::Membership, Cause::Unreadable), "after {step:?}");
        assert_eq!(observer.observe(4100, 900002), not(Step::StartTime, Cause::StartDiffers));
        kernel.fail_next(Step::Membership, KernelFail::Os(5));
        assert_eq!(observer.observe(4100, 900001), not(Step::Membership, Cause::Unreadable), "after a mismatch");
        assert!(kernel.idle());
    }
}

#[test]
fn the_member_file_parser() {
    assert_eq!(parse_leaf_procs(b""), Some(Vec::new()));
    assert_eq!(parse_leaf_procs(b"1\n"), Some(vec![1]));
    assert_eq!(parse_leaf_procs(b"0\n"), Some(vec![0]));
    assert_eq!(parse_leaf_procs(b"4200\n4100\n4200\n"), Some(vec![4200, 4100, 4200]));
    assert_eq!(parse_leaf_procs(b"2147483647\n"), Some(vec![i32::MAX]));
    for bad in [&b"2147483648\n"[..], &b"00\n"[..], &b"01\n"[..], &b"+1\n"[..], &b"-1\n"[..], &b" 1\n"[..],
                &b"1 \n"[..], &b"1"[..], &b"1\n\n"[..], &b"\n"[..], &b"\n1\n"[..], &b"1\r\n"[..], &b"1\t\n"[..],
                &b"0x10\n"[..], &b"\xd9\xa1\n"[..]] {
        assert_eq!(parse_leaf_procs(bad), None, "{bad:?}");
    }
    // 10922 lines of six bytes and one of four: exactly 65536 bytes, accepted; two more bytes are past the bound.
    let mut exact = b"40000\n".repeat(10922);
    exact.extend_from_slice(b"123\n");
    assert_eq!(exact.len(), LEAF_PROCS_LIMIT);
    assert_eq!(parse_leaf_procs(&exact).map(|tgids| tgids.len()), Some(10923));
    let mut over = exact.clone();
    over.extend_from_slice(b"1\n");
    assert_eq!(parse_leaf_procs(&over), None, "past 65536 bytes");
}

#[test]
fn the_stat_parser() {
    let fields = "S 1 4100 4100 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0";
    assert_eq!(parse_stat_start(format!("4100 (w) {fields} 900001\n").as_bytes()), Some(900001));
    assert_eq!(parse_stat_start(format!("4100 (w) {fields} 900001 5 6\n").as_bytes()), Some(900001));
    // The command name may hold spaces, parentheses and newlines: the fields start after the last `)`.
    assert_eq!(parse_stat_start(format!("4100 (a) b\n(c)) {fields} 77\n").as_bytes()), Some(77));
    assert_eq!(parse_stat_start(format!("4100 (w) {fields} {}\n", u64::MAX).as_bytes()), Some(u64::MAX));
    assert_eq!(parse_stat_start(format!("4100 (w) {fields} 007\n").as_bytes()), Some(7), "decimal digits");
    for bad in [format!("4100 (w) {fields} 900001"), format!("4100 (w) {fields} 900001\n\n"),
                format!("4100 (w) {fields} 900001 \n"), format!("4100 (w)  {fields} 900001\n"),
                format!("4100 (w){fields} 900001\n"), format!("4100 w) {fields} 900001\n"),
                format!("4100 (w {fields} 900001\n"), format!("4100 (w) {fields}\n"),
                format!("4100 (w) {fields} -1\n"), format!("4100 (w) {fields} +1\n"), format!("4100 (w) {fields} 1a\n"),
                format!("4100 (w) {fields} {}0\n", u64::MAX), format!("4100 (w) {fields} 9\n0\n"),
                format!("4100 (w) {fields}\t9\n"), String::new(), "\n".to_string()] {
        assert_eq!(parse_stat_start(bad.as_bytes()), None, "{bad:?}");
    }
    let mut long = format!("4100 (w) {fields} 900001 ").into_bytes();
    long.resize(STAT_LIMIT - 1, b'0');
    long.push(b'\n');
    assert_eq!(parse_stat_start(&long), Some(900001), "4096 bytes");
    long.insert(long.len() - 1, b'0');
    assert_eq!(parse_stat_start(&long), None, "4097 bytes");
}

/// The ACTIVE configuration of the v4 vectors' OBSERVING without its kernel table, and its fake kernel.
fn observing() -> (Value, FakeKernel) {
    let vectors = load(V4_VECTORS);
    let config = field(field(&vectors, "configs"), "OBSERVING").clone();
    let mut rest = config.as_object().expect("OBSERVING").clone();
    let table = rest.remove(&i05_protocol::json::JStr::new("kernel"));
    (config, FakeKernel::from_table(table.as_ref()).expect("the kernel table"))
}

/// A BIND frame event of run-one naming `pid` and `start`.
fn bind(pid: i64, start: i64) -> Value {
    let vectors = load(V4_VECTORS);
    let row = rows(&vectors, "transcripts").iter().find(|row| text(row, "id") == "O01").expect("O01");
    let event = rows(row, "events")[1].clone();
    let worker = format!(r#"[{{"op":"set","path":["payload","workerPid"],"value":{pid}}},{{"op":"set","path":["payload","workerStartTicks"],"value":{start}}}]"#);
    apply_mutations(event, Some(&json::parse(&worker).expect("operations")))
}

fn feed(gate: &mut Gate, config: &Value, event: &Value) -> Value {
    let built = broker_frame(config, gate.next_sequence(), gate.last_digest(), event);
    gate.handle(Event::Frame(effect_gate::FrameInput::Value(built))).expect("a frame").to_doc().to_value()
}

fn status_event() -> Value {
    json::parse(r#"{"type":"FRAME","operation":"GENERATION_STATUS","payload":{}}"#).expect("a status frame")
}

#[test]
fn a_gate_without_an_observer_refuses_every_bind() {
    let (config, _) = observing();
    let (typed, _) = split(&config).expect("OBSERVING");
    let mut gate = Gate::new(typed).expect("gate");
    feed(&mut gate, &config, &status_event());
    let before = gate.snapshot();
    assert!(json::json_eq(&feed(&mut gate, &config, &bind(4100, 900001)), &json::parse(NOT_OBSERVED).expect("refusal")));
    assert_eq!(gate.snapshot(), before, "nothing durable, the channel open");
    let log = gate.observation_log().entries();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].observation, not(Step::Membership, Cause::Unreadable));
    assert_eq!(Unobserved.observe(4100, 900001), not(Step::Membership, Cause::Unreadable));
}

#[test]
fn the_gates_log_keeps_64_counts_the_dropped_and_stays_out_of_the_snapshot() {
    let (config, kernel) = observing();
    let (typed, _) = split(&config).expect("OBSERVING");
    let mut gate = Gate::new(typed).expect("gate").with_observer(Box::new(KernelObserver::new(kernel)));
    feed(&mut gate, &config, &status_event());
    let before = gate.snapshot();
    let refusal = json::parse(NOT_OBSERVED).expect("refusal");
    for round in 0..(LOG_ENTRIES as i64 + 2) {
        assert!(json::json_eq(&feed(&mut gate, &config, &bind(5100, 800001 + round)), &refusal), "round {round}");
    }
    assert_eq!(gate.snapshot(), before);
    let log = gate.observation_log();
    let entries = log.entries();
    assert_eq!((entries.len(), log.dropped()), (LOG_ENTRIES, 2));
    assert_eq!((entries[0].start_ticks, entries[LOG_ENTRIES - 1].start_ticks), (800003, 800001 + LOG_ENTRIES as i64 + 1));
    assert!(entries.iter().all(|entry| entry.pid == 5100 && entry.observation == not(Step::Membership, Cause::NotListed)));
    // Then the named member binds: an observation answer is retryable.
    let output = feed(&mut gate, &config, &bind(4100, 900001));
    assert_eq!(text(field(&output, "response"), "result"), "OK");
    assert_eq!(gate.observation_log().dropped(), 3);
}

/// IR5-1 (DESIGN section 9, D1-9): each order row's v3 prefix with its last BIND naming a worker that does not exist
/// (pid 9999), on a counting observer over the fake kernel: the answer is the row's and the last BIND is never
/// observed. The nine answers: the frame-level class (OPENING_FRAME_REQUIRED), peer, state, outstanding actions,
/// replay, generation, binding, certificate and manifest reuse.
#[test]
fn ir5_1_no_observation_before_any_of_the_nine_refusals() {
    let vectors = load(V4_VECTORS);
    let configs = field(&vectors, "configs");
    let mut answers = Vec::new();
    for row in rows(&vectors, "orderTranscripts").iter().step_by(2) {
        let id = text(row, "id");
        let config = field(configs, text(row, "config"));
        let (typed, kernel) = split(config).expect("an order configuration");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let observer = Counting { inner: KernelObserver::new(kernel.clone()), calls: Rc::clone(&calls) };
        let mut gate = Gate::new(typed).expect("gate").with_observer(Box::new(observer));
        let events = rows(row, "events");
        let (last, earlier) = events.split_last().expect("events");
        for event in earlier {
            match text(event, "type") {
                "FRAME" => {
                    feed(&mut gate, config, event);
                }
                _ => {
                    if !kernel.event(event).expect("a kernel event") {
                        gate.handle(base_event(event, id)).expect("an event");
                    }
                }
            }
        }
        let before = calls.borrow().len();
        assert_eq!(text(last, "operation"), "BIND_EXECUTION", "{id}");
        let absent = apply_mutations(last.clone(), Some(&json::parse(
            r#"[{"op":"set","path":["payload","workerPid"],"value":9999},{"op":"set","path":["payload","workerStartTicks"],"value":1}]"#,
        ).expect("operations")));
        let answer = feed(&mut gate, config, &absent);
        let expected = rows(row, "outputs").last().expect("an output");
        assert!(json::json_eq(&answer, expected), "{id}: {} expected {}", show(&answer), show(expected));
        assert_eq!(calls.borrow().len(), before, "{id}: the observer was called for the refused BIND");
        assert!(calls.borrow().iter().all(|(pid, _)| *pid != 9999), "{id}");
        answers.push(text(row, "answer").to_string());
    }
    // The nine, in R10's own (alphabetical) order.
    answers.sort();
    assert_eq!(answers, ["ACTION_OUTSTANDING", "CERTIFICATE_MISMATCH", "EXECUTION_REPLAY", "FATAL:OPENING_FRAME_REQUIRED",
                         "FATAL:PEER_QUALIFICATION_MISMATCH", "GENERATION_MISMATCH", "MANIFEST_REUSED", "NOT_ACTIVE",
                         "UNKNOWN_BINDING"]);
}
