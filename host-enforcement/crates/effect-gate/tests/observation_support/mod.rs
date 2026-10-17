//! HE-003A3 test support (DESIGN section 9): the I05 v4 vector replay through effect-gate's observation driver and the
//! fake kernel, R10's own table from the vectors' step and cause labels to the driver's (test side only: the labels
//! are never effect-gate's text, IR5-1), and a counting observer for the IR5-1 vector (a test-only observer lives
//! here, never in a linked source).
#![allow(dead_code)]

use std::cell::RefCell;
use std::rc::Rc;

use effect_gate::fake_kernel::FakeKernel;
use effect_gate::{Cause, Config, Event, Gate, KernelObserver, Logged, Observation, Step, WorkerObserver};
use i05_protocol::json::{self, JStr, Object, Value};

use crate::support::*;

pub const V4_VECTORS: &str = include_str!("../../../../contracts/i05-v4/vectors.json");

/// The refusal a failed observation answers (the wire never says which step failed).
pub const NOT_OBSERVED: &str = r#"{"response":{"reason":"WORKER_NOT_OBSERVED","result":"REFUSED"}}"#;

/// R10's test-side table: the vectors' (failing step, result) labels as the driver's observation; `None` for a pair
/// the observation cannot give.
pub fn expected_observation(step: &Value, result: &str) -> Option<Observation> {
    let step = match step {
        Value::Null => None,
        other => Some(other.as_str()?),
    };
    let (step, cause) = match (step, result) {
        (None, "OBSERVED") => return Some(Observation::Observed),
        (Some("CGROUP_PROCS"), "CGROUP_PROCS_UNREADABLE") => (Step::Membership, Cause::Unreadable),
        (Some("CGROUP_PROCS"), "NOT_A_MEMBER") => (Step::Membership, Cause::NotListed),
        (Some("PIDFD_OPEN"), "PIDFD_OPEN_FAILED") => (Step::PidfdOpen, Cause::OpenFailed),
        (Some("PIDFD_OPEN"), "PROCESS_GONE") => (Step::PidfdOpen, Cause::Gone),
        (Some("STAT"), "STAT_UNREADABLE") => (Step::StartTime, Cause::Unreadable),
        (Some("STAT"), "PROCESS_GONE") => (Step::StartTime, Cause::Gone),
        (Some("STAT"), "START_MISMATCH") => (Step::StartTime, Cause::StartDiffers),
        (Some("CGROUP_RECHECK"), "CGROUP_RECHECK_UNREADABLE") => (Step::Recheck, Cause::Unreadable),
        (Some("CGROUP_RECHECK"), "NOT_IN_PROBE_WORKER_CGROUP") => (Step::Recheck, Cause::NotListed),
        (Some("PIDFD_ALIVE"), "PIDFD_POLL_FAILED") => (Step::Liveness, Cause::PollFailed),
        (Some("PIDFD_ALIVE"), "PIDFD_EXITED") => (Step::Liveness, Cause::Exited),
        _ => return None,
    };
    Some(Observation::NotObserved { step, cause })
}

/// A row's `observations` as log entries, through the table.
pub fn expected_log(row: &Value) -> Vec<Logged> {
    rows(row, "observations")
        .iter()
        .map(|entry| Logged {
            pid: field(entry, "workerPid").as_int().and_then(|pid| pid.to_i64()).expect("workerPid"),
            start_ticks: field(entry, "workerStartTicks").as_int().and_then(|start| start.to_i64()).expect("workerStartTicks"),
            observation: expected_observation(field(entry, "step"), text(entry, "result")).expect("a pair the table holds"),
        })
        .collect()
}

/// `dict(base, **override)`: a shallow, top-level replacement.
pub fn merged(base: &Value, members: &Value) -> Value {
    let mut object: Object = base.as_object().expect("a configuration object").clone();
    for (key, value) in members.as_object().expect("an override object").iter() {
        object.insert(key.clone(), value.clone());
    }
    Value::Object(object)
}

/// A v4 configuration split: its `kernel` member to the fake kernel's builder, the rest to `Config`, which answers
/// first (C01 before the kernel table, as the model orders them).
pub fn split(config: &Value) -> Result<(Config, FakeKernel), String> {
    let mut rest = config.as_object().expect("a configuration object").clone();
    let table = rest.remove(&JStr::new("kernel"));
    let config = Config::from_value(&Value::Object(rest)).map_err(|error| error.message().to_string())?;
    let kernel = FakeKernel::from_table(table.as_ref())?;
    Ok((config, kernel))
}

/// A replay of a v4 transcript with the gate's log and its fake kernel.
pub struct Observed {
    pub replay: Replay,
    pub log: Vec<Logged>,
    pub dropped: u64,
    pub kernel: FakeKernel,
    /// BINDs answered WORKER_NOT_OBSERVED, each with the snapshot unchanged (checked as it runs).
    pub refused: usize,
}

/// The output of a fake-kernel event (the model's `{}`).
pub fn empty() -> Value {
    Value::Object(Object::new())
}

/// Replays `events` on a fresh gate whose observer is the configuration's fake kernel: FRAME events as `support`
/// builds them, the fake kernel's model-only events on the shared kernel (output `{}`), any other through
/// `base_event`. A BIND answered WORKER_NOT_OBSERVED must leave the whole snapshot unchanged (I05 v4 rule 4).
pub fn replay_v4(config_value: &Value, events: &[Value], mode: Mode, context: &str) -> Observed {
    let (config, kernel) = split(config_value).unwrap_or_else(|error| panic!("{context}: configuration refused: {error}"));
    let mut gate = Gate::new(config).expect("gate").with_observer(Box::new(KernelObserver::new(kernel.clone())));
    let schema = i05_protocol::i05_v3_schema().expect("schema");
    let refusal = json::parse(NOT_OBSERVED).expect("the refusal parses");
    let mut replay = Replay { outputs: Vec::new(), snapshot: Value::Null, frames: 0, value_fallbacks: 0 };
    let mut refused = 0;
    for (index, event) in events.iter().enumerate() {
        let context = format!("{context} event {index}");
        if text(event, "type") == "FRAME" {
            let built = broker_frame(config_value, gate.next_sequence(), gate.last_digest(), event);
            assert_bytes_path_agrees(&built, &schema, &context);
            replay.frames += 1;
            let before = gate.snapshot();
            let output = gate.handle(Event::Frame(frame_input(built, mode, &mut replay.value_fallbacks)));
            let output = output.unwrap_or_else(|error| panic!("{context}: {error:?}")).to_doc().to_value();
            if json::json_eq(&output, &refusal) {
                assert_eq!(gate.snapshot(), before, "{context}: a refused observation changed the snapshot");
                refused += 1;
            }
            replay.outputs.push(output);
            continue;
        }
        match kernel.event(event) {
            Ok(true) => replay.outputs.push(empty()),
            Ok(false) => {
                let output = gate.handle(base_event(event, &context)).unwrap_or_else(|error| panic!("{context}: {error:?}"));
                replay.outputs.push(output.to_doc().to_value());
            }
            Err(error) => panic!("{context}: the fake kernel refused the event: {error}"),
        }
    }
    replay.snapshot = gate.snapshot().to_value();
    let log = gate.observation_log();
    Observed { replay, log: log.entries(), dropped: log.dropped(), kernel, refused }
}

/// The IR5-1 observer: delegates to `inner` and records every call.
pub struct Counting<O> {
    pub inner: O,
    pub calls: Rc<RefCell<Vec<(i64, i64)>>>,
}

impl<O: WorkerObserver> WorkerObserver for Counting<O> {
    fn observe(&mut self, pid: i64, start_ticks: i64) -> Observation {
        self.calls.borrow_mut().push((pid, start_ticks));
        self.inner.observe(pid, start_ticks)
    }
}
