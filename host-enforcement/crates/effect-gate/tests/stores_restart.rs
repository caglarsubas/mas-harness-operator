//! The process restart (HE-002C DESIGN §8 and §11): every transcript with a GATE_RESTART (I05 v3, S01-S06, the R10-local
//! I05 and I07 vectors, HE-002C's two, and the I07 v3 transcripts), as it is and extended by an EXPIRE and by a
//! DRAIN_REQUEST after the restart, runs on file stores where the restart is a process restart: the gate is dropped,
//! the stores are reopened with the same fault-plan handle (so pending injections carry over), and `open` restarts.
//! Outputs and the journal equal the replay restart's, the journal file's fresh scan equals the mirror, and the
//! snapshot equals it without the members a process restart does not keep (the counters, the connection table, the
//! write counters). The one stated exception (owner decision Q-HE2C-3 (a)): R10-L02 and R10-L02b extended by EXPIRE
//! journal one more EXPIRED record, because their EXPIRED write failed before the restart.

mod file_support;
mod policy_support;
mod support;

use effect_gate::file_store::scan_journal;
use effect_gate::{Config, Entry, Gate, OutputKind, PolicyGate, Record, State};
use file_support::*;
use i05_protocol::json::{JStr, Object, Value};
use policy_support::{I07_VECTORS, KINDS};
use support::{field, load, rows, show, text};

const I05_VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const SUPPLEMENT: &str = include_str!("../../../contracts/i05-v3-supplement/vectors.json");
const LOCAL: &str = include_str!("vectors-local.json");
const LOCAL_I07: &str = include_str!("vectors-local-i07.json");
const LOCAL_HE002C: &str = include_str!("vectors-local-i07-he002c.json");

/// The execution R10-L02 and R10-L02b bind.
const L02_EXECUTION: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn event(kind: &str) -> Value {
    let mut object = Object::new();
    object.insert(JStr::new("type"), Value::str(kind));
    Value::Object(object)
}

/// The transcripts with a GATE_RESTART among `rows`, with their configuration.
fn with_restart<'a>(rows: &'a [Value], configs: &'a Value) -> Vec<(&'a str, &'a Value, Vec<Value>)> {
    rows.iter()
        .filter(|row| support::rows(row, "events").iter().any(|event| text(event, "type") == "GATE_RESTART"))
        .map(|row| (text(row, "id"), field(configs, text(row, "config")), support::rows(row, "events").to_vec()))
        .collect()
}

/// Runs every case and its two extensions; returns the number of process restarts.
fn check(group: &str, family: &Family, cases: Vec<(&str, &Value, Vec<Value>)>) -> usize {
    let mut failures = Vec::new();
    let mut runs = 0;
    for (id, config, events) in cases {
        assert_eq!(events.iter().filter(|event| text(event, "type") == "GATE_RESTART").count(), 1, "{id}");
        for extension in [None, Some("EXPIRE"), Some("DRAIN_REQUEST")] {
            let mut events = events.clone();
            if let Some(kind) = extension {
                events.push(event(kind));
            }
            let case = format!("{id}{}", extension.map_or(String::new(), |kind| format!("+{kind}")));
            let place = Place::fresh(group, &case);
            let run = process_restart(family, config, &events, &place, &case);
            runs += 1;
            let mut problems = Vec::new();
            if run.outputs.len() != run.replay_outputs.len()
                || !run.outputs.iter().zip(&run.replay_outputs).all(|(got, want)| same(got, want))
            {
                let shown = |outputs: &[Value]| outputs.iter().map(show).collect::<Vec<_>>().join(", ");
                problems.push(format!("outputs\n  got  {}\n  want {}", shown(&run.outputs), shown(&run.replay_outputs)));
            }
            if run.scan != run.journal {
                problems.push("the journal file's scan differs from the mirror".to_string());
            }
            let exception = matches!(id, "R10-L02" | "R10-L02b") && extension == Some("EXPIRE");
            let mut expected_journal = run.replay_journal.clone();
            if exception {
                // Q-HE2C-3 (a): the replay path kept `expired` after the failed EXPIRED write and answers without a
                // record; the process path derives the expiry from durable records only and journals it again.
                expected_journal.push(Entry::Record(Record::Expired { execution_id: L02_EXECUTION.to_string() }));
            }
            if run.journal != expected_journal {
                problems.push(format!("journal\n  got  {:?}\n  want {:?}", run.journal, expected_journal));
            }
            let extra: &[&str] = if exception { &["journal"] } else { &[] };
            let (got, want) = (kept(&run.snapshot, extra), kept(&run.replay_snapshot, extra));
            if !same(&got, &want) {
                problems.push(format!("snapshot\n  got  {}\n  want {}", show(&got), show(&want)));
            }
            if problems.is_empty() {
                place.remove();
            } else {
                failures.push(format!("{case}: {}", problems.join("\n")));
            }
        }
    }
    assert!(failures.is_empty(), "{} process restarts differ:\n{}", failures.len(), failures.join("\n"));
    runs
}

#[test]
fn i05_process_restarts_match_the_replay_restart() {
    let vectors = load(I05_VECTORS);
    let configs = field(&vectors, "configs");
    let supplement = load(SUPPLEMENT);
    let local = load(LOCAL);
    let mut cases = with_restart(rows(&vectors, "transcripts"), configs);
    assert_eq!(cases.len(), 18);
    cases.extend(with_restart(rows(&supplement, "transcripts"), configs));
    cases.extend(with_restart(rows(&local, "transcripts"), configs));
    assert_eq!(cases.len(), 28);
    assert_eq!(check("restart-i05", &Family::I05, cases), 84);
}

#[test]
fn i07_process_restarts_match_the_replay_restart() {
    let vectors = load(I07_VECTORS);
    let configs = field(&vectors, "configs");
    let local = load(LOCAL_I07);
    let he002c = load(LOCAL_HE002C);
    let mut cases = with_restart(rows(&vectors, "transcripts"), configs);
    assert_eq!(cases.len(), 8);
    cases.extend(with_restart(rows(&local, "transcripts"), configs));
    cases.extend(with_restart(rows(&he002c, "transcripts"), configs));
    assert_eq!(cases.len(), 12);
    assert_eq!(check("restart-i07", &Family::I07 { kinds: load(KINDS) }, cases), 36);
}

/// The stated exception is real: without the extra EXPIRE, R10-L02's process restart journals exactly the replay's.
#[test]
fn the_q_he2c_3_divergence_needs_a_failed_expiry_and_a_later_expire() {
    let local = load(LOCAL);
    let vectors = load(I05_VECTORS);
    let row = rows(&local, "transcripts").iter().find(|row| text(row, "id") == "R10-L02").expect("R10-L02");
    let config = field(field(&vectors, "configs"), text(row, "config"));
    let mut events = rows(row, "events").to_vec();
    let place = Place::fresh("restart-divergence", "R10-L02");
    let run = process_restart(&Family::I05, config, &events, &place, "R10-L02");
    assert_eq!(run.journal, run.replay_journal);
    events.push(event("EXPIRE"));
    let place = Place::fresh("restart-divergence", "R10-L02+EXPIRE");
    let run = process_restart(&Family::I05, config, &events, &place, "R10-L02+EXPIRE");
    assert_eq!(show(run.outputs.last().expect("an output")), r#"{"denied":[]}"#);
    assert_eq!(run.journal.len(), run.replay_journal.len() + 1);
    assert_eq!(run.journal.last(), Some(&Entry::Record(Record::Expired { execution_id: L02_EXECUTION.to_string() })));
    assert_eq!(run.replay_journal.last(), Some(&Entry::Record(Record::Drained { state: State::Held })));
}

/// The first `count` events of an I07 v3 transcript.
fn prefix(id: &str, count: usize) -> Vec<Value> {
    let vectors = load(I07_VECTORS);
    let row = rows(&vectors, "transcripts").iter().find(|row| text(row, "id") == id).expect("transcript");
    rows(row, "events")[..count].to_vec()
}

/// Runs `events` on a new generation's PolicyGate, drops it, and returns the place for the reopening.
fn written(case: &str, events: &[Value]) -> (Place, Value, String) {
    let vectors = load(I07_VECTORS);
    let config = field(field(&vectors, "configs"), "ACTIVE").clone();
    let generation = generation_of(&config);
    let place = Place::fresh("restart-held", case);
    let family = Family::I07 { kinds: load(KINDS) };
    let mut gate = Driven::create(&family, &config, place.stores(&generation, None));
    for (index, event) in events.iter().enumerate() {
        gate.step(event, &format!("{case} event {index}"));
    }
    drop(gate);
    (place, config, generation)
}

/// T14 and T62 in the process form: an ambiguous write makes the process restart HELD, for PolicyGate and for the
/// I05 gate alone (which applies the same floor, DESIGN §8); a delivered write does not.
#[test]
fn an_ambiguous_write_restarts_held_across_processes() {
    let kinds = load(KINDS);
    let mut lost = prefix("T62", 4);
    let mut upstream = Object::new();
    upstream.insert(JStr::new("type"), Value::str("W_UPSTREAM"));
    upstream.insert(JStr::new("writeId"), Value::int(1));
    upstream.insert(JStr::new("upstream"), Value::str("LOST"));
    lost.push(Value::Object(upstream));
    let cases = [
        ("T14-outstanding", prefix("T14", 4), State::Held),
        ("T62-lost", lost, State::Held),
        ("T62-delivered", prefix("T62", 5), State::Closed),
    ];
    for (case, events, expected) in cases {
        let (place, config, generation) = written(case, &events);
        let (converted, kernel) = effect_gate::fake_kernel::convert_v3_config(&config).expect("v4's conversion");
        let (policy, output) =
            PolicyGate::open(&converted, &kinds, place.stores(&generation, None)).expect("PolicyGate::open");
        let policy = policy.with_observer(Box::new(effect_gate::KernelObserver::new(kernel)));
        assert_eq!(show(&output.to_doc().to_value()),
                   format!(r#"{{"maintenance":"ENDED","restartState":"{}"}}"#, expected.as_str()), "{case}");
        assert_eq!(policy.gate().journal().last(), Some(&Entry::Record(Record::Restarted { state: expected })), "{case}");
        assert_eq!(scan_journal(&place.journal, &generation).expect("scan"), policy.gate().journal(), "{case}");
        let ambiguous = expected == State::Held;
        let writes = show(field(&policy.snapshot().to_value(), "writes"));
        assert_eq!(writes.contains("IO_AMBIGUOUS"), ambiguous, "{case}: {writes}");
        drop(policy);
        let (converted, kernel) = effect_gate::fake_kernel::convert_v3_config(&without_writer(&config)).expect("v4's conversion");
        let config = Config::from_value(&converted).expect("configuration");
        let (gate, output) = Gate::open(config, place.stores(&generation, None)).expect("Gate::open");
        let gate = gate.with_observer(Box::new(effect_gate::KernelObserver::new(kernel)));
        assert_eq!(output.kind, OutputKind::RestartState(expected), "{case}: the I05 gate alone");
        assert_eq!(gate.state(), expected);
        drop(gate);
        place.remove();
    }
}
