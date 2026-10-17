//! The I05 v4 contract replay (HE-003A3 DESIGN section 9, owner decision Q-A3-8 (a)): the 20 observation transcripts
//! O01-O20 and the 18 order transcripts OB01-OB18, each through effect-gate's observation driver on the fake kernel,
//! on both frame paths, with every output, the final snapshot and the local log equal to the vectors (each log entry
//! compared as R10's (pid, start ticks, observation) through the test-side table), every injection consumed and every
//! refused observation leaving the snapshot unchanged; the 9 configuration refusals (C01 through `Config`, C02-C09
//! through the fake kernel's builder) and the 9 model-event refusals (M01-M09, the fake kernel) with their exact texts.

mod observation_support;
mod support;

use std::collections::BTreeSet;

use effect_gate::fake_kernel::convert_v3_config;
use effect_gate::{Event, Gate, KernelObserver, Observation};
use i05_protocol::json::{self, Value};
use i05_protocol::sha256;
use observation_support::*;
use support::*;

const V3_VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const V3_SUPPLEMENT: &str = include_str!("../../../contracts/i05-v3-supplement/vectors.json");
const V3_SCHEMA: &str = include_str!("../../../contracts/i05-v3/channel.schema.json");
const V3_MAPPING: &str = include_str!("../../../contracts/i05-v3/outcome-mapping.json");

fn hex(text: &str) -> String {
    sha256::hex(&sha256::digest(text.as_bytes()))
}

#[test]
fn the_header_pins_the_v3_inputs_r10_holds() {
    let vectors = load(V4_VECTORS);
    assert_eq!(text(&vectors, "schemaVersion"), "planeon.internal.effect-gate-model-vectors/v4");
    assert_eq!(text(&vectors, "modelVersion"), "planeon.internal.effect-gate-model/v4");
    assert_eq!(text(&vectors, "frameVersion"), "planeon.internal.effect-gate-frame/v3");
    assert_eq!(text(&vectors, "evidenceClass"), "DATA_CHECK_ONLY");
    let pins = field(&vectors, "v3");
    // Each pinned file by its key, its directory under harness-onion's architecture/ and its name there.
    for (key, directory, name, bytes) in [("vectors", "i05-gate-channel-v3", "vectors.json", V3_VECTORS),
                                          ("supplement", "i05-gate-channel-v3-supplement", "vectors.json", V3_SUPPLEMENT),
                                          ("outcomeMapping", "i05-gate-channel-v3", "outcome-mapping.json", V3_MAPPING),
                                          ("schema", "i05-gate-channel-v3", "channel.schema.json", V3_SCHEMA)] {
        assert_eq!(text(field(pins, key), "path"), format!("architecture/{directory}/{name}"));
        assert_eq!(text(field(pins, key), "sha256"), hex(bytes), "{key}: the pinned v3 file is ours");
    }
    // The three configurations: v3's, converted, with the kernel table beside them.
    let v3 = load(V3_VECTORS);
    let v3_configs = field(&v3, "configs");
    for (name, source) in [("OBSERVING", "ACTIVE"), ("OBSERVING_INSPECTING", "INSPECTING"), ("OBSERVING_LATER", "LATER")] {
        let mut ours = field(field(&vectors, "configs"), name).as_object().expect("a configuration").clone();
        ours.remove(&i05_protocol::json::JStr::new("kernel")).expect("a kernel table");
        let (converted, _) = convert_v3_config(field(v3_configs, source)).expect("v4's conversion");
        assert!(json::json_eq(&Value::Object(ours), &converted), "{name} is v3's {source} converted");
    }
}

/// One transcript row through the driver on both frame paths.
fn check_row(row: &Value, configs: &Value, failures: &mut Vec<String>) -> Observed {
    let id = text(row, "id");
    let config = field(configs, text(row, "config"));
    let expected = expected_log(row);
    let mut last = None;
    for mode in [Mode::Value, Mode::Bytes] {
        let run = replay_v4(config, rows(row, "events"), mode, id);
        if let Err(difference) = compare(&run.replay, row) {
            failures.push(format!("{id} ({mode:?}): {difference}"));
        }
        if run.log != expected {
            failures.push(format!("{id} ({mode:?}): log {:?} expected {:?}", run.log, expected));
        }
        if run.dropped != 0 || !run.kernel.idle() || run.kernel.fault().is_some() {
            failures.push(format!("{id} ({mode:?}): dropped {}, idle {}, fault {:?}", run.dropped, run.kernel.idle(),
                                  run.kernel.fault()));
        }
        if mode == Mode::Bytes {
            assert_eq!(run.replay.value_fallbacks, 0, "{id}: every built frame has a canonical encoding");
        }
        last = Some(run);
    }
    last.expect("a run")
}

#[test]
fn observation_transcripts_o01_to_o20() {
    let vectors = load(V4_VECTORS);
    let configs = field(&vectors, "configs");
    let transcripts = rows(&vectors, "transcripts");
    let ids: Vec<&str> = transcripts.iter().map(|row| text(row, "id")).collect();
    assert_eq!(ids, (1..=20).map(|n| format!("O{n:02}")).collect::<Vec<_>>());
    let mut failures = Vec::new();
    let mut outcomes = BTreeSet::new();
    let (mut refused, mut expected_refused) = (0, 0);
    let refusal = json::parse(NOT_OBSERVED).expect("the refusal parses");
    for row in transcripts {
        let run = check_row(row, configs, &mut failures);
        refused += run.refused;
        expected_refused += rows(row, "outputs").iter().filter(|output| json::json_eq(output, &refusal)).count();
        for entry in &run.log {
            outcomes.insert(format!("{:?}", entry.observation));
        }
    }
    assert!(failures.is_empty(), "{} differences:\n{}", failures.len(), failures.join("\n"));
    // Every (step, cause) pair the observation can give, and OBSERVED, occurs (the vectors' own coverage rule).
    assert_eq!(outcomes.len(), 12, "{outcomes:?}");
    assert_eq!((refused, expected_refused), (16, 16), "every refused observation left the snapshot unchanged");
}

#[test]
fn order_transcripts_ob01_to_ob18() {
    let vectors = load(V4_VECTORS);
    let configs = field(&vectors, "configs");
    let transcripts = rows(&vectors, "orderTranscripts");
    assert_eq!(transcripts.len(), 18);
    let mut failures = Vec::new();
    let mut answers = Vec::new();
    for (index, row) in transcripts.iter().enumerate() {
        assert_eq!(text(row, "id"), format!("OB{:02}", index + 1));
        assert_eq!(text(row, "worker"), ["OUTSIDER", "WRONG_START"][index % 2]);
        let run = check_row(row, configs, &mut failures);
        // Nothing is observed for the last BIND: the log holds only what earlier BINDs observed.
        assert!(run.log.iter().all(|entry| entry.observation == Observation::Observed), "{}", text(row, "id"));
        answers.push(text(row, "answer").to_string());
    }
    assert!(failures.is_empty(), "{} differences:\n{}", failures.len(), failures.join("\n"));
    let distinct: BTreeSet<&String> = answers.iter().collect();
    assert_eq!(distinct.len(), 9, "the nine answers before the observation, each pinned twice");
}

#[test]
fn configuration_refusals_c01_to_c09() {
    let vectors = load(V4_VECTORS);
    let observing = field(field(&vectors, "configs"), "OBSERVING");
    let refusals = rows(&vectors, "configRefusals");
    assert_eq!(refusals.len(), 9);
    for (index, row) in refusals.iter().enumerate() {
        let id = text(row, "id");
        assert_eq!(id, format!("C{:02}", index + 1));
        let refusal = split(&merged(observing, field(row, "override"))).err();
        assert_eq!(refusal.as_deref(), Some(text(row, "expect")), "configuration refusal {id}");
    }
    for name in ["OBSERVING", "OBSERVING_INSPECTING", "OBSERVING_LATER"] {
        assert!(split(field(field(&vectors, "configs"), name)).is_ok(), "{name} is accepted");
    }
}

#[test]
fn model_event_refusals_m01_to_m09() {
    let vectors = load(V4_VECTORS);
    let observing = field(field(&vectors, "configs"), "OBSERVING");
    let refusals = rows(&vectors, "eventRefusals");
    assert_eq!(refusals.len(), 9);
    for (index, row) in refusals.iter().enumerate() {
        let id = text(row, "id");
        assert_eq!(id, format!("M{:02}", index + 1));
        let (config, kernel) = split(observing).expect("OBSERVING");
        let mut gate = Gate::new(config).expect("gate").with_observer(Box::new(KernelObserver::new(kernel.clone())));
        let mut refusal = None;
        for event in rows(row, "events") {
            match kernel.event(event) {
                Ok(true) => {}
                Ok(false) => {
                    let event: Event = base_event(event, id);
                    gate.handle(event).expect("a gate event");
                }
                Err(text) => {
                    refusal = Some(text);
                    break;
                }
            }
        }
        assert_eq!(refusal.as_deref(), Some(text(row, "expect")), "model-event refusal {id}");
    }
}

/// The comparison is not vacuous: a changed log entry or output is reported.
#[test]
fn the_log_comparison_detects_differences() {
    let vectors = load(V4_VECTORS);
    let row = rows(&vectors, "transcripts").iter().find(|row| text(row, "id") == "O04").expect("O04");
    let run = replay_v4(field(field(&vectors, "configs"), "OBSERVING"), rows(row, "events"), Mode::Value, "O04");
    assert_eq!(run.log, expected_log(row));
    let mut other = run.log.clone();
    other[0].observation = Observation::Observed;
    assert_ne!(other, expected_log(row));
    assert!(expected_observation(&Value::str("STAT"), "NOT_A_MEMBER").is_none(), "a pair the observation cannot give");
}
