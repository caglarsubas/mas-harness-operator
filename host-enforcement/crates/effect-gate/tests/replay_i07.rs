//! The I07 v3 contract replay (HE-002B, obligation I07-4): the 79 kind checks, 7 render checks and 22 outcome checks
//! of `contracts/i07-v3/vectors.json`, and the 62 transcripts with every output and the final snapshot equal to the
//! vectors, once through the value path (`check_frame`) and once with every built broker and writer frame encoded
//! canonically and decoded by `decode_frame`. The 48 frame and 9 byte checks are HE-002's (`i05-protocol`).

mod policy_support;
mod support;

use effect_gate::{check_write, classify, render_write, write_outcome_is_final, PolicyKinds, WriteOperation, WriteRequest};
use i05_protocol::json::Value;
use policy_support::*;
use support::*;

/// The validator's fixed qualification namespace and apiserver authority for the kind and render checks (N5).
const NAMESPACE: &str = "planeon-qual";
const AUTHORITY: &str = "127.0.0.1:6443";

fn kinds() -> PolicyKinds {
    PolicyKinds::from_value(&load(KINDS)).expect("the contract table")
}

fn run_all(mode: Mode) {
    let vectors = load(I07_VECTORS);
    let kinds_value = load(KINDS);
    let configs = field(&vectors, "configs");
    let transcripts = rows(&vectors, "transcripts");
    assert_eq!(transcripts.len(), 62);
    let mut failures = Vec::new();
    let (mut frames, mut writer_frames, mut fallbacks) = (0, 0, 0);
    for row in transcripts {
        let id = text(row, "id");
        let config = field(configs, text(row, "config"));
        let replay = replay_i07(config, &kinds_value, rows(row, "events"), mode, id);
        frames += replay.replay.frames;
        writer_frames += replay.writer_frames;
        fallbacks += replay.replay.value_fallbacks;
        if let Err(difference) = compare(&replay.replay, row) {
            failures.push(format!("{id}: {difference}"));
        }
    }
    assert!(failures.is_empty(), "{} of 62 transcripts differ:\n{}", failures.len(), failures.join("\n"));
    assert_eq!((frames, writer_frames), (73, 195), "every FRAME and W_FRAME event replayed");
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
fn kind_checks() {
    let vectors = load(I07_VECTORS);
    let kinds = kinds();
    let checks = rows(&vectors, "kindChecks");
    assert_eq!(checks.len(), 79);
    for row in checks {
        let id = text(row, "id");
        let request = WriteRequest::from_payload(field(row, "payload")).unwrap_or_else(|| panic!("{id}: payload"));
        let got = check_write(&kinds, NAMESPACE, &request).err().map(|refusal| refusal.as_str());
        let want = match field(row, "expect") {
            Value::Null => None,
            other => other.as_str(),
        };
        assert_eq!(got, want, "I07 kind check {id}");
    }
}

#[test]
fn render_checks() {
    let vectors = load(I07_VECTORS);
    let kinds = kinds();
    let checks = rows(&vectors, "renderChecks");
    assert_eq!(checks.len(), 7);
    for row in checks {
        let id = text(row, "id");
        let request = WriteRequest::from_payload(field(row, "payload")).unwrap_or_else(|| panic!("{id}: payload"));
        let entry = classify(&kinds, &request.resource).unwrap_or_else(|refusal| panic!("{id}: {refusal:?}"));
        let rendered = render_write(entry, &request, NAMESPACE, AUTHORITY).unwrap_or_else(|| panic!("{id}: rendering"));
        assert_eq!(rendered.head, text(row, "head"), "I07 render check {id}: head");
        assert_eq!(rendered.body, text(row, "body").as_bytes(), "I07 render check {id}: body");
        assert_eq!(rendered.body_digest, text(row, "bodyDigest"), "I07 render check {id}: body digest");
    }
}

#[test]
fn outcome_checks() {
    let vectors = load(I07_VECTORS);
    let checks = rows(&vectors, "outcomeChecks");
    assert_eq!(checks.len(), 22);
    for (index, row) in checks.iter().enumerate() {
        let operation = WriteOperation::parse(text(row, "operation")).expect("operation");
        let status = field(row, "httpStatus").as_int().and_then(|status| status.to_i64()).expect("status");
        let want = field(row, "final").as_bool().expect("final");
        assert_eq!(write_outcome_is_final(operation, status), want, "I07 outcome check {index}");
    }
}

/// The comparison is not vacuous: a changed output or final journal is reported.
#[test]
fn comparison_detects_differences() {
    let vectors = load(I07_VECTORS);
    let row = &rows(&vectors, "transcripts")[0];
    let config = field(field(&vectors, "configs"), text(row, "config"));
    let replay = replay_i07(config, &load(KINDS), rows(row, "events"), Mode::Value, "T01").replay;
    assert!(compare(&replay, row).is_ok());
    let mut changed = replay.outputs.clone();
    changed[2] = Value::Null;
    let altered = Replay { outputs: changed, snapshot: replay.snapshot.clone(), frames: 0, value_fallbacks: 0 };
    assert!(compare(&altered, row).is_err());
    let mut snapshot = replay.snapshot.as_object().expect("snapshot").clone();
    snapshot.insert(i05_protocol::json::JStr::new("writes"), Value::Null);
    let altered = Replay { outputs: replay.outputs.clone(), snapshot: Value::Object(snapshot), frames: 0, value_fallbacks: 0 };
    assert!(compare(&altered, row).is_err());
}
