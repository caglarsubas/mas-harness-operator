//! Drivers for the HE-002C file tests (DESIGN §11): store directories under cargo's `CARGO_TARGET_TMPDIR`, a test
//! device probe (the two directories share the build host's device, E15), and one gate, I05 or I07, in memory or on
//! file stores, stepped through vector events exactly as the `support` and `policy_support` replays step them (broker
//! and writer frames on the byte path).
#![allow(dead_code)]

use std::io;

use effect_gate::file_store::{index_generations, scan_journal};
use effect_gate::fake_kernel::convert_v3_config;
use effect_gate::{Config, Entry, Event, FaultHandle, FileStores, Gate, KernelObserver, OpenError, PolicyEvent, PolicyGate,
                  StoreDir};
use gate_sys::Dir;
use i05_protocol::json::{self, JStr, Value};

use crate::policy_support::{upstream_outcome, writer_frame};
use crate::support::{base_event, broker_frame, field, frame_input, show, text, Mode};

/// The test probe: the journal directory is device 1 and the marker directory device 2.
pub fn distinct_devices(which: StoreDir, _: &Dir) -> io::Result<u64> {
    Ok(match which {
        StoreDir::Journal => 1,
        StoreDir::Marker => 2,
    })
}

/// A journal and a marker directory for one case.
pub struct Place {
    pub root: String,
    pub journal: String,
    pub marker: String,
}

impl Place {
    /// Fresh, empty directories `<tmp>/he002c/<group>/<case>/{journal,marker}`.
    pub fn fresh(group: &str, case: &str) -> Place {
        let root = format!("{}/he002c/{group}/{case}", env!("CARGO_TARGET_TMPDIR"));
        let _ = std::fs::remove_dir_all(&root);
        let place = Place { journal: format!("{root}/journal"), marker: format!("{root}/marker"), root };
        std::fs::create_dir_all(&place.journal).expect("journal directory");
        std::fs::create_dir_all(&place.marker).expect("marker directory");
        place
    }

    pub fn open(&self, generation: &str, plan: Option<FaultHandle>) -> Result<FileStores, OpenError> {
        FileStores::open(&self.journal, &self.marker, generation, &distinct_devices, plan)
    }

    pub fn stores(&self, generation: &str, plan: Option<FaultHandle>) -> FileStores {
        self.open(generation, plan).unwrap_or_else(|error| panic!("stores for {generation} open: {error:?}"))
    }

    /// A fresh scan of the generation's journal file.
    pub fn scan(&self, generation: &str) -> Vec<Entry> {
        scan_journal(&self.journal, generation).unwrap_or_else(|error| panic!("scan of {generation}: {error}"))
    }

    pub fn index(&self) -> Vec<String> {
        index_generations(&self.journal).expect("the index reads")
    }

    pub fn file(&self, name: &str) -> String {
        format!("{}/{name}", self.journal)
    }

    pub fn marker_file(&self, name: &str) -> String {
        format!("{}/{name}", self.marker)
    }

    pub fn bytes(path: &str) -> Vec<u8> {
        std::fs::read(path).unwrap_or_default()
    }

    pub fn remove(self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The generation a configuration names.
pub fn generation_of(config: &Value) -> String {
    text(config, "generation").to_string()
}

/// An I07 configuration without its `policyWriter` member: the I05 gate's configuration.
pub fn without_writer(config: &Value) -> Value {
    let mut object = config.as_object().expect("configuration").clone();
    object.remove(&JStr::new("policyWriter"));
    Value::Object(object)
}

/// Which gate a transcript drives.
#[derive(Clone)]
pub enum Family {
    I05,
    I07 { kinds: Value },
}

/// One gate stepping through vector events.
pub enum Driven {
    I05 { gate: Gate, config: Value },
    I07 { gate: PolicyGate, config: Value, kinds: Value, challenge: Value },
}

impl Driven {
    pub fn memory(family: &Family, config: &Value) -> Driven {
        match family {
            Family::I05 => {
                let (converted, kernel) = convert_v3_config(config).expect("v4's conversion");
                let typed = Config::from_value(&converted).expect("configuration");
                let gate = Gate::new(typed).expect("gate").with_observer(Box::new(KernelObserver::new(kernel)));
                Driven::I05 { gate, config: config.clone() }
            }
            Family::I07 { kinds } => Driven::I07 {
                gate: {
                    let (converted, kernel) = convert_v3_config(config).expect("v4's conversion");
                    PolicyGate::new(&converted, kinds).expect("PolicyGate").with_observer(Box::new(KernelObserver::new(kernel)))
                },
                config: config.clone(),
                kinds: kinds.clone(),
                challenge: Value::Null,
            },
        }
    }

    /// A new generation on `stores` (`create`).
    pub fn create(family: &Family, config: &Value, stores: FileStores) -> Driven {
        match family {
            Family::I05 => {
                let (converted, kernel) = convert_v3_config(config).expect("v4's conversion");
                let typed = Config::from_value(&converted).expect("configuration");
                let gate = Gate::create(typed, stores).expect("Gate::create").with_observer(Box::new(KernelObserver::new(kernel)));
                Driven::I05 { gate, config: config.clone() }
            }
            Family::I07 { kinds } => Driven::I07 {
                gate: {
                    let (converted, kernel) = convert_v3_config(config).expect("v4's conversion");
                    PolicyGate::create(&converted, kinds, stores).expect("PolicyGate::create")
                        .with_observer(Box::new(KernelObserver::new(kernel)))
                },
                config: config.clone(),
                kinds: kinds.clone(),
                challenge: Value::Null,
            },
        }
    }

    /// The process restart on reopened stores (`open`), with its output; the writer challenge the replay rule last
    /// saw is carried over, as the replay path keeps it.
    pub fn open(family: &Family, config: &Value, stores: FileStores, challenge: Value) -> (Driven, Value) {
        match family {
            Family::I05 => {
                let (converted, kernel) = convert_v3_config(config).expect("v4's conversion");
                let typed = Config::from_value(&converted).expect("configuration");
                let (gate, output) = Gate::open(typed, stores).expect("Gate::open");
                let gate = gate.with_observer(Box::new(KernelObserver::new(kernel)));
                (Driven::I05 { gate, config: config.clone() }, output.to_doc().to_value())
            }
            Family::I07 { kinds } => {
                let (converted, kernel) = convert_v3_config(config).expect("v4's conversion");
                let (gate, output) = PolicyGate::open(&converted, kinds, stores).expect("PolicyGate::open");
                let gate = gate.with_observer(Box::new(KernelObserver::new(kernel)));
                let driven = Driven::I07 { gate, config: config.clone(), kinds: kinds.clone(), challenge };
                (driven, output.to_doc().to_value())
            }
        }
    }

    pub fn challenge(&self) -> Value {
        match self {
            Driven::I05 { .. } => Value::Null,
            Driven::I07 { challenge, .. } => challenge.clone(),
        }
    }

    /// One vector event; its output as a JSON value.
    pub fn step(&mut self, event: &Value, context: &str) -> Value {
        let mut fallbacks = 0usize;
        let output = match self {
            Driven::I05 { gate, config } => {
                let typed = match text(event, "type") {
                    "FRAME" => {
                        let built = broker_frame(config, gate.next_sequence(), gate.last_digest(), event);
                        Event::Frame(frame_input(built, Mode::Bytes, &mut fallbacks))
                    }
                    _ => base_event(event, context),
                };
                gate.handle(typed).unwrap_or_else(|error| panic!("{context}: {error:?}")).to_doc().to_value()
            }
            Driven::I07 { gate, config, challenge, .. } => {
                let typed = match text(event, "type") {
                    "FRAME" => {
                        let base = gate.gate();
                        let built = broker_frame(config, base.next_sequence(), base.last_digest(), event);
                        PolicyEvent::Base(Event::Frame(frame_input(built, Mode::Bytes, &mut fallbacks)))
                    }
                    "W_CONNECT" => {
                        *challenge = field(event, "challenge").clone();
                        PolicyEvent::WConnect { challenge: text(event, "challenge").to_string() }
                    }
                    "W_FRAME" => {
                        let built = writer_frame(challenge, gate.writer_next_sequence(), gate.writer_last_digest(), event);
                        PolicyEvent::WFrame(frame_input(built, Mode::Bytes, &mut fallbacks))
                    }
                    "W_UPSTREAM" => {
                        let write_id = field(event, "writeId").as_int().and_then(|id| id.to_u64()).expect("writeId");
                        PolicyEvent::WUpstream {
                            write_id: u16::try_from(write_id).expect("writeId"),
                            outcome: upstream_outcome(field(event, "upstream")),
                        }
                    }
                    "W_CHANNEL_LOST" => PolicyEvent::WChannelLost,
                    "W_PEER_CHANGED" => PolicyEvent::WPeerChanged,
                    _ => PolicyEvent::Base(base_event(event, context)),
                };
                gate.handle(typed).unwrap_or_else(|error| panic!("{context}: {error:?}")).to_doc().to_value()
            }
        };
        assert_eq!(fallbacks, 0, "{context}: every built frame has a canonical encoding");
        output
    }

    pub fn journal(&self) -> &[Entry] {
        match self {
            Driven::I05 { gate, .. } => gate.journal(),
            Driven::I07 { gate, .. } => gate.gate().journal(),
        }
    }

    pub fn journal_digest(&self) -> String {
        match self {
            Driven::I05 { gate, .. } => gate.journal_digest(),
            Driven::I07 { gate, .. } => gate.gate().journal_digest(),
        }
    }

    pub fn snapshot(&self) -> Value {
        match self {
            Driven::I05 { gate, .. } => gate.snapshot().to_value(),
            Driven::I07 { gate, .. } => gate.snapshot().to_value(),
        }
    }
}

/// A snapshot without the members a process restart does not keep (DESIGN §8: the I05 counters, the connection
/// table and the I07 write counters) and without `extra` members.
pub fn kept(snapshot: &Value, extra: &[&str]) -> Value {
    let mut object = snapshot.as_object().expect("snapshot").clone();
    for key in ["counters", "connections", "writeCounters"].iter().chain(extra) {
        object.remove(&JStr::new(key));
    }
    Value::Object(object)
}

pub fn same(left: &Value, right: &Value) -> bool {
    json::json_eq(left, right)
}

/// Asserts that two JSON values are equal, showing both when not.
pub fn assert_same(got: &Value, want: &Value, context: &str) {
    assert!(same(got, want), "{context}:\n got  {}\n want {}", show(got), show(want));
}

/// What a lockstep run returns for comparison with a vector row.
pub struct Lockstep {
    pub outputs: Vec<Value>,
    pub snapshot: Value,
    pub entries: usize,
}

/// Replays `events` on an in-memory gate and on a new generation's file stores in lockstep: after every event the
/// outputs are equal, the file gate's mirror equals the in-memory journal and a fresh scan of the journal file equals
/// it too; at the end the snapshots (marker included) and the journal digests are equal.
pub fn lockstep(family: &Family, config: &Value, events: &[Value], place: &Place, context: &str) -> Lockstep {
    let generation = generation_of(config);
    let mut memory = Driven::memory(family, config);
    let mut files = Driven::create(family, config, place.stores(&generation, Some(FaultHandle::default())));
    let mut outputs = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let context = format!("{context} event {index}");
        let want = memory.step(event, &context);
        let got = files.step(event, &context);
        assert_same(&got, &want, &context);
        assert_eq!(files.journal(), memory.journal(), "{context}: the mirror");
        assert_eq!(place.scan(&generation), memory.journal(), "{context}: a fresh scan");
        outputs.push(want);
    }
    assert_same(&files.snapshot(), &memory.snapshot(), &format!("{context}: final snapshot"));
    assert_eq!(files.journal_digest(), memory.journal_digest(), "{context}: journal digest");
    Lockstep { outputs, snapshot: memory.snapshot(), entries: memory.journal().len() }
}

/// A process-restart run's results beside the in-memory replay of the same events.
pub struct Restarted {
    pub replay_outputs: Vec<Value>,
    pub replay_journal: Vec<Entry>,
    pub replay_snapshot: Value,
    pub outputs: Vec<Value>,
    pub journal: Vec<Entry>,
    pub scan: Vec<Entry>,
    pub snapshot: Value,
}

/// Replays `events` in memory (the replay restart) and on file stores where the one GATE_RESTART becomes a process
/// restart: the gate is dropped, the stores are reopened with the same fault-plan handle, and `open` restarts.
pub fn process_restart(family: &Family, config: &Value, events: &[Value], place: &Place, context: &str) -> Restarted {
    let generation = generation_of(config);
    let at = events.iter().position(|event| text(event, "type") == "GATE_RESTART").expect("a GATE_RESTART event");
    let mut memory = Driven::memory(family, config);
    let replay_outputs: Vec<Value> =
        events.iter().enumerate().map(|(index, event)| memory.step(event, &format!("{context} replay {index}"))).collect();
    let plan = FaultHandle::default();
    let mut files = Driven::create(family, config, place.stores(&generation, Some(plan.clone())));
    let mut outputs = Vec::new();
    for (index, event) in events[..at].iter().enumerate() {
        outputs.push(files.step(event, &format!("{context} files {index}")));
    }
    let challenge = files.challenge();
    drop(files);
    let (mut files, restart) = Driven::open(family, config, place.stores(&generation, Some(plan)), challenge);
    outputs.push(restart);
    for (index, event) in events.iter().enumerate().skip(at + 1) {
        outputs.push(files.step(event, &format!("{context} files {index}")));
    }
    Restarted {
        replay_outputs,
        replay_journal: memory.journal().to_vec(),
        replay_snapshot: memory.snapshot(),
        outputs,
        journal: files.journal().to_vec(),
        scan: place.scan(&generation),
        snapshot: files.snapshot(),
    }
}
