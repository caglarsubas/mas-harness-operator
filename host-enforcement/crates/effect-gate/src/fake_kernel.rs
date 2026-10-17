//! The fake kernel and v4's conversion (HE-003A3 DESIGN sections 3 and 5; owner decision Q-A3-2 (a)): test support,
//! pure (no system call), public so effect-gate's and gate-tls's tests share one implementation. `tools/gate.py` keeps
//! this module's name and its two names out of every other linked source (only `lib.rs`'s `pub mod` and the strict
//! `#[cfg(test)] mod tests` blocks may name them), and this file defines no other type, alias, re-export or wrapper.
//!
//! - [`FakeKernel`] implements the observation's four kernel calls over the I05 v4 vectors' process table (pid, start
//!   ticks, cgroup path), rendering the probe-worker leaf's member file and each process's `stat` file as the kernel
//!   prints them, so every replay runs effect-gate's own steps and parsers. A clone shares the kernel: the replay keeps
//!   one to feed the model-only events while the gate's observer holds the other. Every process also gets a counter
//!   value of its own; after an exit, a new process under the same pid gets a new value, which the held pidfd tells
//!   apart (the poll reports the exit). An exit here is exit and reap at once, as the vectors' KERNEL_EXIT is.
//! - The vectors' model-only events reach it through [`FakeKernel::event`], never through the gate: KERNEL_SPAWN,
//!   KERNEL_EXIT and KERNEL_MOVE change the table at once; OBSERVATION_FAIL_NEXT fails the next call at its step (an
//!   errno: EIO for the member file, EMFILE for `pidfd_open`, EACCES for `stat`, ENOMEM for the poll);
//!   OBSERVATION_RACE_NEXT applies its kernel event right after the next successful call at its step (the member
//!   file's two reads are told apart by the pidfd: the second comes while the driver holds it). Their shapes are closed
//!   and their refusals carry the vectors' texts (C02-C09, M01-M09). [`FakeKernel::fail_next`] and
//!   [`FakeKernel::reply_next`] let host tests inject any failure or content.
//! - [`convert_v3_config`] is v4's conversion of a v3 (or I07 v3) configuration, read as specification from the pinned
//!   v4 model: the configuration without `observedWorkers`, and a fake kernel whose probe-worker leaf holds each listed
//!   (pid, start ticks) pair as a live process. A pid is a `pid_t` of at least 1 here (R10-defined; the model takes any
//!   positive integer).
//!
//! Every `RefCell` borrow is `try_borrow` or `try_borrow_mut`; a failed borrow fails the call closed.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use i05_protocol::json::{JStr, Object, Value};

use crate::observation::{KernelFail, KernelReads, PidState, Step, ENOENT, ESRCH};

/// The probe-worker leaf's path below the cgroup2 root, as the vectors' process table writes it.
const PROBE_WORKER_LEAF: &str = "/planeon.slice/planeon-capacity-broker.service/probe-worker";

/// The vectors' refusal texts (contract text, compared exactly by the C and M vectors).
const TABLE: &str = "a closed kernel process table";
const PROCESS: &str = "a closed kernel process";
const EVENT: &str = "a closed kernel event";
const EXIT: &str = "exit of an unknown process";
const MOVE: &str = "a move of an unknown process or to a malformed cgroup";
const STEP: &str = "unknown observation step";
const RACE: &str = "unknown observation race";

/// R10-defined: what the conversion refuses.
const NOT_V3: &str = "a v3 configuration holds observedWorkers as a list of [pid, startTicks] integer pairs";

/// The errnos of an injected failure (each step's own, none of them ENOENT or ESRCH).
const EIO: i32 = 5;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EMFILE: i32 = 24;

/// The vectors' kernel processes, model-only injections and the pidfd last handed out.
#[derive(Clone, Debug, Default)]
pub struct FakeKernel {
    /// pid -> (start ticks, cgroup path, serial).
    processes: Rc<RefCell<BTreeMap<i32, (i64, String, u64)>>>,
    /// The last serial given.
    serial: Rc<Cell<u64>>,
    /// Pending failures, each for the next call at its step.
    failures: Rc<RefCell<Vec<(Step, KernelFail)>>>,
    /// Pending replies, each the bytes the next read at its step returns instead of the rendering.
    replies: Rc<RefCell<Vec<(Step, Vec<u8>)>>>,
    /// Pending races, each a kernel event applied right after the next successful call at its step.
    races: Rc<RefCell<Vec<(Step, Value)>>>,
    /// The pidfd last handed out; a second holder means the driver is between its steps 2 and 5.
    held: Rc<RefCell<Option<Rc<(i32, u64)>>>>,
    /// The first race whose kernel event was refused when it applied (the model raises there).
    fault: Rc<RefCell<Option<String>>>,
}

/// The vectors' name of a step.
fn step_named(name: &str) -> Option<Step> {
    match name {
        "CGROUP_PROCS" => Some(Step::Membership),
        "PIDFD_OPEN" => Some(Step::PidfdOpen),
        "STAT" => Some(Step::StartTime),
        "CGROUP_RECHECK" => Some(Step::Recheck),
        "PIDFD_ALIVE" => Some(Step::Liveness),
        _ => None,
    }
}

/// An object holding exactly `members`.
fn closed(object: &Object, members: &[&str]) -> bool {
    object.len() == members.len() && members.iter().all(|member| object.get(member).is_some())
}

/// A kernel event's closed shape: its type and exactly that type's members.
fn kernel_shape(event: &Value) -> bool {
    let Some(object) = event.as_object() else { return false };
    match object.get("type").and_then(Value::as_str) {
        Some("KERNEL_SPAWN") => closed(object, &["type", "pid", "startTicks", "cgroup"]),
        Some("KERNEL_EXIT") => closed(object, &["type", "pid"]),
        Some("KERNEL_MOVE") => closed(object, &["type", "pid", "cgroup"]),
        _ => false,
    }
}

/// A pid the table can hold: a `pid_t` of at least 1.
fn pid_of(value: Option<&Value>) -> Option<i32> {
    value.and_then(Value::as_int).and_then(|pid| pid.to_i64()).and_then(|pid| i32::try_from(pid).ok()).filter(|pid| *pid >= 1)
}

/// A cgroup path below the root: text starting with `/`.
fn cgroup_of(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|path| path.starts_with('/'))
}

/// The errno an injected OBSERVATION_FAIL_NEXT gives at a step.
fn injected(step: Step) -> KernelFail {
    KernelFail::Os(match step {
        Step::Membership | Step::Recheck => EIO,
        Step::PidfdOpen => EMFILE,
        Step::StartTime => EACCES,
        Step::Liveness => ENOMEM,
    })
}

impl FakeKernel {
    /// A fake kernel from a v4 vector configuration's `kernel` member (`None` when the configuration has none):
    /// exactly `{"processes": [...]}`, each process exactly `{"pid", "startTicks", "cgroup"}` with a pid that is not
    /// live yet, a start time of at least 0 and an absolute cgroup path (C02-C09).
    pub fn from_table(table: Option<&Value>) -> Result<FakeKernel, String> {
        let processes = table
            .and_then(Value::as_object)
            .filter(|object| closed(object, &["processes"]))
            .and_then(|object| object.get("processes"))
            .and_then(Value::as_array);
        let Some(processes) = processes else { return Err(TABLE.to_string()) };
        let kernel = FakeKernel::default();
        for process in processes {
            let Some(members) = process.as_object().filter(|object| closed(object, &["pid", "startTicks", "cgroup"])) else {
                return Err(PROCESS.to_string());
            };
            kernel.spawn(members.get("pid"), members.get("startTicks"), members.get("cgroup"))?;
        }
        Ok(kernel)
    }

    /// One vector event: `Ok(true)` when it is one of the fake kernel's model-only events and was applied, `Ok(false)`
    /// for any other type (the gate's), and the vectors' refusal text for a malformed one (M01-M09).
    pub fn event(&self, event: &Value) -> Result<bool, String> {
        match event.get("type").and_then(Value::as_str) {
            Some("KERNEL_SPAWN" | "KERNEL_EXIT" | "KERNEL_MOVE") => self.kernel_event(event).map(|()| true),
            Some("OBSERVATION_FAIL_NEXT") => {
                let step = event
                    .as_object()
                    .filter(|object| closed(object, &["type", "step"]))
                    .and_then(|object| object.get("step"))
                    .and_then(Value::as_str)
                    .and_then(step_named);
                let Some(step) = step else { return Err(STEP.to_string()) };
                self.fail_next(step, injected(step));
                Ok(true)
            }
            Some("OBSERVATION_RACE_NEXT") => {
                let members = event.as_object().filter(|object| closed(object, &["type", "after", "event"]));
                let after = members
                    .and_then(|object| object.get("after"))
                    .and_then(Value::as_str)
                    .and_then(step_named)
                    .filter(|step| *step != Step::Liveness);
                let inner = members.and_then(|object| object.get("event")).filter(|inner| kernel_shape(inner));
                let (Some(step), Some(inner)) = (after, inner) else { return Err(RACE.to_string()) };
                let Ok(mut races) = self.races.try_borrow_mut() else { return Err(RACE.to_string()) };
                races.push((step, inner.clone()));
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Fails the next call at `step` with `fail`.
    pub fn fail_next(&self, step: Step, fail: KernelFail) {
        if let Ok(mut failures) = self.failures.try_borrow_mut() {
            failures.push((step, fail));
        }
    }

    /// Makes the next read at `step` (the member file's two reads or the `stat` read) return `bytes`.
    pub fn reply_next(&self, step: Step, bytes: Vec<u8>) {
        if let Ok(mut replies) = self.replies.try_borrow_mut() {
            replies.push((step, bytes));
        }
    }

    /// Whether every failure, reply and race was consumed.
    pub fn idle(&self) -> bool {
        let empty = |pending: Result<usize, ()>| pending == Ok(0);
        empty(self.failures.try_borrow().map(|failures| failures.len()).map_err(|_| ()))
            && empty(self.replies.try_borrow().map(|replies| replies.len()).map_err(|_| ()))
            && empty(self.races.try_borrow().map(|races| races.len()).map_err(|_| ()))
    }

    /// The first race whose kernel event was refused when it applied, with the refusal's text.
    pub fn fault(&self) -> Option<String> {
        self.fault.try_borrow().map_or_else(|_| Some(EVENT.to_string()), |fault| fault.clone())
    }

    /// A new live process (KERNEL_SPAWN, a table row, a converted pair).
    fn spawn(&self, pid: Option<&Value>, start: Option<&Value>, cgroup: Option<&Value>) -> Result<(), String> {
        let start = start.and_then(Value::as_int).and_then(|start| start.to_i64()).filter(|start| *start >= 0);
        let (Some(pid), Some(start), Some(cgroup)) = (pid_of(pid), start, cgroup_of(cgroup)) else {
            return Err(PROCESS.to_string());
        };
        let Ok(mut processes) = self.processes.try_borrow_mut() else { return Err(PROCESS.to_string()) };
        if processes.contains_key(&pid) {
            return Err(PROCESS.to_string());
        }
        let serial = self.serial.get().saturating_add(1);
        self.serial.set(serial);
        processes.insert(pid, (start, cgroup.to_string(), serial));
        Ok(())
    }

    /// KERNEL_SPAWN, KERNEL_EXIT or KERNEL_MOVE, applied at once.
    fn kernel_event(&self, event: &Value) -> Result<(), String> {
        if !kernel_shape(event) {
            return Err(EVENT.to_string());
        }
        match event.get("type").and_then(Value::as_str) {
            Some("KERNEL_SPAWN") => self.spawn(event.get("pid"), event.get("startTicks"), event.get("cgroup")),
            Some("KERNEL_EXIT") => {
                let Ok(mut processes) = self.processes.try_borrow_mut() else { return Err(EXIT.to_string()) };
                match pid_of(event.get("pid")).and_then(|pid| processes.remove(&pid)) {
                    Some(_) => Ok(()),
                    None => Err(EXIT.to_string()),
                }
            }
            _ => {
                let Ok(mut processes) = self.processes.try_borrow_mut() else { return Err(MOVE.to_string()) };
                let live = pid_of(event.get("pid")).and_then(|pid| processes.get_mut(&pid));
                match (live, cgroup_of(event.get("cgroup"))) {
                    (Some(process), Some(cgroup)) => {
                        process.1 = cgroup.to_string();
                        Ok(())
                    }
                    _ => Err(MOVE.to_string()),
                }
            }
        }
    }

    /// The first pending failure for `step`, removed; a failed borrow fails the call too.
    fn take_failure(&self, step: Step) -> Option<KernelFail> {
        let Ok(mut failures) = self.failures.try_borrow_mut() else { return Some(KernelFail::NoErrno) };
        let index = failures.iter().position(|(at, _)| *at == step)?;
        Some(failures.remove(index).1)
    }

    /// The first pending reply for `step`, removed.
    fn take_reply(&self, step: Step) -> Option<Vec<u8>> {
        let mut replies = self.replies.try_borrow_mut().ok()?;
        let index = replies.iter().position(|(at, _)| *at == step)?;
        Some(replies.remove(index).1)
    }

    /// Applies every pending race for `step`, in order; the first refused one is kept as the fault.
    fn after(&self, step: Step) {
        let pending: Vec<Value> = match self.races.try_borrow_mut() {
            Ok(mut races) => {
                let (now, later): (Vec<(Step, Value)>, Vec<(Step, Value)>) = races.drain(..).partition(|(at, _)| *at == step);
                *races = later;
                now.into_iter().map(|(_, event)| event).collect()
            }
            Err(_) => Vec::new(),
        };
        for event in &pending {
            if let Err(refusal) = self.kernel_event(event) {
                if let Ok(mut fault) = self.fault.try_borrow_mut() {
                    fault.get_or_insert(refusal);
                }
            }
        }
    }

    /// Whether the driver holds the pidfd last handed out (it is between its steps 2 and 5).
    fn holding(&self) -> bool {
        self.held.try_borrow().is_ok_and(|held| held.as_ref().is_some_and(|pidfd| Rc::strong_count(pidfd) > 1))
    }

    /// The leaf's member file: one line per member, by pid.
    fn leaf_bytes(&self) -> Result<Vec<u8>, KernelFail> {
        let processes = self.processes.try_borrow().map_err(|_| KernelFail::NoErrno)?;
        let mut bytes = Vec::new();
        for (pid, (_, cgroup, _)) in processes.iter() {
            if cgroup == PROBE_WORKER_LEAF {
                bytes.extend_from_slice(format!("{pid}\n").as_bytes());
            }
        }
        Ok(bytes)
    }

    /// A live process's `stat` file as the kernel prints it (the start time is field 22); ENOENT for another pid.
    fn stat_bytes(&self, pid: i32) -> Result<Vec<u8>, KernelFail> {
        let processes = self.processes.try_borrow().map_err(|_| KernelFail::NoErrno)?;
        let Some((start, _, _)) = processes.get(&pid) else { return Err(KernelFail::Os(ENOENT)) };
        Ok(format!("{pid} (probe-worker) S 1 {pid} {pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} 1024 5\n").into_bytes())
    }

    /// One read at `step`: a pending failure, else a pending reply or the rendering, then the step's races.
    fn read(&self, step: Step, render: impl FnOnce(&FakeKernel) -> Result<Vec<u8>, KernelFail>) -> Result<Vec<u8>, KernelFail> {
        if let Some(fail) = self.take_failure(step) {
            return Err(fail);
        }
        let bytes = match self.take_reply(step) {
            Some(bytes) => bytes,
            None => render(self)?,
        };
        self.after(step);
        Ok(bytes)
    }
}

impl KernelReads for FakeKernel {
    type Pidfd = Rc<(i32, u64)>;

    fn read_leaf_procs(&mut self) -> Result<Vec<u8>, KernelFail> {
        let step = if self.holding() { Step::Recheck } else { Step::Membership };
        self.read(step, FakeKernel::leaf_bytes)
    }

    fn pidfd_open(&mut self, pid: i32) -> Result<Rc<(i32, u64)>, KernelFail> {
        if let Some(fail) = self.take_failure(Step::PidfdOpen) {
            return Err(fail);
        }
        let serial = {
            let processes = self.processes.try_borrow().map_err(|_| KernelFail::NoErrno)?;
            match processes.get(&pid) {
                Some((_, _, serial)) => *serial,
                None => return Err(KernelFail::Os(ESRCH)),
            }
        };
        let pidfd = Rc::new((pid, serial));
        let Ok(mut held) = self.held.try_borrow_mut() else { return Err(KernelFail::NoErrno) };
        *held = Some(Rc::clone(&pidfd));
        drop(held);
        self.after(Step::PidfdOpen);
        Ok(pidfd)
    }

    fn read_stat(&mut self, pid: i32) -> Result<Vec<u8>, KernelFail> {
        self.read(Step::StartTime, |kernel| kernel.stat_bytes(pid))
    }

    fn poll_zero(&mut self, pidfd: &Rc<(i32, u64)>) -> Result<PidState, KernelFail> {
        if let Some(fail) = self.take_failure(Step::Liveness) {
            return Err(fail);
        }
        let processes = self.processes.try_borrow().map_err(|_| KernelFail::NoErrno)?;
        let (pid, serial) = **pidfd;
        Ok(match processes.get(&pid) {
            Some((_, _, live)) if *live == serial => PidState::Alive,
            _ => PidState::Exited,
        })
    }
}

/// v4's conversion of a v3 (or I07 v3) configuration (see the module documentation): the configuration without
/// `observedWorkers`, and a fake kernel whose probe-worker leaf holds each listed pair as a live process.
pub fn convert_v3_config(config: &Value) -> Result<(Value, FakeKernel), String> {
    let Some(root) = config.as_object() else { return Err(NOT_V3.to_string()) };
    let mut rest = root.clone();
    let workers = rest.remove(&JStr::new("observedWorkers"));
    let Some(pairs) = workers.as_ref().and_then(Value::as_array) else { return Err(NOT_V3.to_string()) };
    let kernel = FakeKernel::default();
    let leaf = Value::str(PROBE_WORKER_LEAF);
    for pair in pairs {
        let Some([pid, start]) = pair.as_array() else { return Err(NOT_V3.to_string()) };
        kernel.spawn(Some(pid), Some(start), Some(&leaf))?;
    }
    Ok((Value::Object(rest), kernel))
}
