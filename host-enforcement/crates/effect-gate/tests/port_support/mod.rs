//! A failing I04 port for HE-003B's port-failure tests (DESIGN §4.2, §9; MODEL_DEFINED R56): HE-003A's scripted I04
//! port (from `substrate_support`, unchanged) wrapped with a failure the test arms for the n-th `apply`, the n-th
//! `sync`, the drain, or from the start.
#![allow(dead_code)]

use std::time::Instant;

use effect_gate::{ExpectedPeers, GateView, I04Port, Lifetimes, LoopExit, PolicyEvent, PolicyGate, PolicyOutput, Port,
                  Readiness, Registry, Substrate};

use super::substrate_support::{lab, FakeI04, FakeOs, FakeUpstream, Shared};

/// When the port fails.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    Apply(usize),
    Sync(usize),
    Drain,
    Start,
}

/// HE-003A's scripted I04 port with a failure.
pub struct FailingI04 {
    inner: FakeI04,
    trigger: Trigger,
    applies: usize,
    syncs: usize,
    failed: Option<&'static str>,
}

impl Port for FailingI04 {
    fn register(&mut self, registry: &mut Registry<'_>) -> Result<(), LoopExit> {
        self.inner.register(registry)
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.inner.next_deadline()
    }

    fn due(&mut self, now: Instant) -> Vec<PolicyEvent> {
        self.inner.due(now)
    }

    fn ready(&mut self, value: u64, readiness: Readiness) -> Vec<PolicyEvent> {
        self.inner.ready(value, readiness)
    }

    fn apply(&mut self, output: &PolicyOutput) {
        self.inner.apply(output);
        self.applies += 1;
        if self.trigger == Trigger::Apply(self.applies) {
            self.failed = Some("failed in apply");
        }
    }

    fn sync(&mut self, view: &dyn GateView) {
        self.inner.sync(view);
        self.syncs += 1;
        if self.trigger == Trigger::Sync(self.syncs) {
            self.failed = Some("failed in sync");
        }
    }

    fn failure(&self) -> Option<&'static str> {
        self.failed
    }
}

impl I04Port for FailingI04 {
    fn drain_backlog(&mut self) -> Vec<PolicyEvent> {
        let events = self.inner.drain_backlog();
        if self.trigger == Trigger::Drain {
            self.failed = Some("failed in the drain");
        }
        events
    }
}

pub type FailingLoop = Substrate<FakeOs, FailingI04, FakeUpstream>;

/// A loop over `gate` with the failing port; the lab the fakes share.
pub fn failing(gate: PolicyGate, lifetimes: Lifetimes, trigger: Trigger) -> (Shared, Result<FailingLoop, LoopExit>) {
    let shared = lab();
    let port = FailingI04 {
        inner: FakeI04(shared.clone()),
        trigger,
        applies: 0,
        syncs: 0,
        failed: (trigger == Trigger::Start).then_some("failed from the start"),
    };
    let substrate = Substrate::new(gate, FakeOs(shared.clone()), port, FakeUpstream(shared.clone()),
                                   ExpectedPeers::r10(), lifetimes);
    (shared, substrate)
}
