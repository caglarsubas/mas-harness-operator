//! HE-005B's I03 tests (the HE-005B plan's items 3 and 6; Q-HE5B-4 (a)): START built from each positive vector's
//! checked DISPATCH, valid under `$defs/workerStart` and the whole channel schema, canonical and within 16 KiB,
//! carrying exactly the closed execution, binding, case, request and generation identifiers; a malformed execution id refused by
//! the schema; and START never taken as an I02 frame. The registered vectors hold no START (only the broker's leg is
//! registered), so its members are checked against the DISPATCH and the schema.

use i05_protocol::json::{self, Value};
use i05_protocol::FrameError;
use planeon_broker::i02::{
    check_dispatch, decode_datagram, Breach, ConfiguredDigests, Dispatch, Peer, Schemas, Transcript, MAX_CONTROL_BYTES,
    MAX_DATAGRAM_BYTES,
};
use planeon_broker::i03::{start, START_FIELDS, START_OPERATION, START_VERSION};

const VECTORS: &str = include_str!("../../../contracts/broker-handoff-v1/vectors.json");

fn schemas() -> Schemas {
    Schemas::embedded().expect("the embedded channel schema loads")
}

fn positives() -> Vec<Value> {
    let vectors = json::parse(VECTORS).expect("the vectors parse");
    vectors.get("positive").and_then(Value::as_array).expect("positive vectors").to_vec()
}

fn member<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("member {key}"))
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    member(value, key).as_str().unwrap_or_else(|| panic!("text {key}"))
}

fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

fn dispatch(positive: &Value, schemas: &Schemas) -> Dispatch {
    let binding = member(positive, "binding");
    let configured = ConfiguredDigests {
        broker_manifest: text(binding, "brokerManifestDigest").to_string(),
        broker_executable: text(binding, "brokerExecutableDigest").to_string(),
        worker_manifest: text(binding, "workerManifestDigest").to_string(),
        worker_artifact: text(binding, "workerArtifactDigest").to_string(),
    };
    check_dispatch(&canonical(member(positive, "request")), &canonical(binding), &configured, schemas)
        .expect("the DISPATCH passes")
}

fn execution_id(positive: &Value) -> String {
    let frames = member(positive, "frames").as_array().expect("frames");
    text(frames.first().expect("a first frame"), "executionId").to_string()
}

#[test]
fn start_carries_exactly_the_closed_identifiers() {
    let schemas = schemas();
    assert_eq!(START_FIELDS, ["bindingDigest", "caseId", "requestDigest", "generation"]);
    for positive in positives() {
        let dispatch = dispatch(&positive, &schemas);
        let execution = execution_id(&positive);
        let raw = start(&dispatch, &execution, &schemas).expect("START");
        assert!(raw.len() <= MAX_CONTROL_BYTES, "START is at most 16 KiB");
        let value = decode_datagram(&raw, MAX_CONTROL_BYTES, schemas.worker_start()).expect("valid under workerStart");
        assert_eq!(canonical(&value), raw, "START is canonical");
        let keys: Vec<&str> = value.as_object().expect("an object").iter()
            .map(|(key, _)| key.as_str().expect("a key")).collect();
        assert_eq!(keys, ["bindingDigest", "caseId", "executionId", "generation", "operation", "requestDigest",
                          "schemaVersion"]);
        assert_eq!(text(&value, "schemaVersion"), START_VERSION);
        assert_eq!(text(&value, "operation"), START_OPERATION);
        assert_eq!(text(&value, "executionId"), execution);
        for name in START_FIELDS {
            assert_eq!(text(&value, name), text(member(&positive, "request"), name), "{name}");
        }
        // The whole channel schema admits it too (its fourth branch).
        assert!(decode_datagram(&raw, MAX_DATAGRAM_BYTES, schemas.channel()).is_ok());
    }
}

#[test]
fn a_malformed_execution_id_is_refused() {
    let schemas = schemas();
    let positive = positives().into_iter().next().expect("a positive vector");
    let dispatch = dispatch(&positive, &schemas);
    let upper: String = std::iter::repeat('C').take(64).collect();
    let short: String = std::iter::repeat('c').take(63).collect();
    for bad in [upper.as_str(), short.as_str(), "", "not-hex"] {
        assert_eq!(start(&dispatch, bad, &schemas), Err(FrameError::F00), "{bad}");
    }
}

#[test]
fn start_is_no_i02_frame() {
    let schemas = schemas();
    let positive = positives().into_iter().next().expect("a positive vector");
    let dispatch = dispatch(&positive, &schemas);
    let execution = execution_id(&positive);
    let raw = start(&dispatch, &execution, &schemas).expect("START");
    for from in [Peer::Broker, Peer::Server] {
        let mut transcript = Transcript::new(&dispatch, &execution).expect("a transcript");
        assert!(matches!(transcript.accept(&raw, from, &schemas), Err(Breach::NotFrame)));
    }
}
