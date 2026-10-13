//! The I05 v3 contract replay: the 5 configuration refusals (the validator's `dict(ACTIVE, **override)` rule) and the
//! 120 transcripts, each with every output and the final snapshot equal to the vectors, once through the value path
//! (`check_frame`, the contract's replay form) and once with every built frame encoded canonically and decoded by
//! `decode_frame` (DESIGN §13 E12).

mod support;

use effect_gate::Config;
use i05_protocol::json::{Object, Value};
use support::*;

const VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");

fn run_all(mode: Mode) {
    let vectors = load(VECTORS);
    let configs = field(&vectors, "configs");
    let transcripts = rows(&vectors, "transcripts");
    assert_eq!(transcripts.len(), 120);
    let mut failures = Vec::new();
    let (mut frames, mut fallbacks) = (0, 0);
    for row in transcripts {
        let id = text(row, "id");
        let config = field(configs, text(row, "config"));
        let replay = replay(config, rows(row, "events"), mode, id);
        frames += replay.frames;
        fallbacks += replay.value_fallbacks;
        if let Err(difference) = compare(&replay, row) {
            failures.push(format!("{id}: {difference}"));
        }
    }
    assert!(failures.is_empty(), "{} of 120 transcripts differ:\n{}", failures.len(), failures.join("\n"));
    assert_eq!(frames, 503, "every FRAME event replayed");
    if mode == Mode::Bytes {
        assert_eq!(fallbacks, 0, "every built frame has a canonical encoding");
    }
}

#[test]
fn transcripts_through_check_frame() {
    run_all(Mode::Value);
}

#[test]
fn transcripts_through_decode_frame() {
    run_all(Mode::Bytes);
}

#[test]
fn configuration_refusals() {
    let vectors = load(VECTORS);
    let active = field(field(&vectors, "configs"), "ACTIVE").as_object().expect("ACTIVE");
    let refusals = rows(&vectors, "configRefusals");
    assert_eq!(refusals.len(), 5);
    for row in refusals {
        let id = text(row, "id");
        // dict(ACTIVE, **override): a shallow, top-level replacement.
        let mut merged: Object = active.clone();
        for (key, value) in field(row, "override").as_object().expect("override").iter() {
            merged.insert(key.clone(), value.clone());
        }
        let refusal = Config::from_value(&Value::Object(merged)).err().map(|error| error.message().to_string());
        assert_eq!(refusal.as_deref(), Some(text(row, "expect")), "configuration refusal {id}");
    }
    for name in ["ACTIVE", "INSPECTING", "LATER"] {
        assert!(Config::from_value(field(field(&vectors, "configs"), name)).is_ok(), "{name} is accepted");
    }
}

/// The comparison is not vacuous: a changed expected output or final journal is reported.
#[test]
fn comparison_detects_differences() {
    let vectors = load(VECTORS);
    let row = &rows(&vectors, "transcripts")[0];
    let config = field(field(&vectors, "configs"), text(row, "config"));
    let replay = replay(config, rows(row, "events"), Mode::Value, "T01");
    assert!(compare(&replay, row).is_ok());
    let mut changed = replay.outputs.clone();
    changed[1] = Value::Null;
    let altered = support::Replay { outputs: changed, snapshot: replay.snapshot.clone(), frames: 0, value_fallbacks: 0 };
    assert!(compare(&altered, row).is_err());
    let mut snapshot = replay.snapshot.as_object().expect("snapshot").clone();
    snapshot.insert(i05_protocol::json::JStr::new("journal"), Value::Array(Vec::new()));
    let altered = support::Replay { outputs: replay.outputs.clone(), snapshot: Value::Object(snapshot), frames: 0, value_fallbacks: 0 };
    assert!(compare(&altered, row).is_err());
}
