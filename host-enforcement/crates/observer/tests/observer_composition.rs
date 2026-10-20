//! HE-004D2 DESIGN-D2 sections 8 and 15.1 (owner decisions Q-HE4D2-6 (a) and Q-HE4D2-7 (a); MODEL_DEFINED R143, R144):
//! the fixture composition of I06 v3's evidence positive (bound to native-profile v4 positive 0's record) with
//! native-profile v5 positive 0's captures (the same record), a record-digest mismatch, fixture tokens refused by the
//! production entry, and the production calls of both checks refused, so that no production token can be made today.
//! The branch the integration tests cannot reach (two production tokens) is `composition.rs`'s own unit test; the
//! tokens' missing `Clone` and `Default` is G-D2-8's (compile-fail tests are not available).

mod b1_support;
mod d2_support;

use d2_support::{field, list, parse, positive_records, I06_V3_VECTORS, V1_VECTORS, V2_VECTORS, V3_VECTORS, V5_VECTORS};
use i05_protocol::json::{self, Value};
use planeon_observer::capture_check::Refusal;
use planeon_observer::capture_schema::{CaptureSchema, RecordSchema};
use planeon_observer::composition::{compose_fixture, compose_production, CompositionRefusal};
use planeon_observer::contracts;
use planeon_observer::i06_evidence::{check_evidence, record_digest, EvidenceAccepted, EvidenceRefusal};
use planeon_observer::qualification::{check_qualification, Histories, PredecessorSchemas, QualificationAccepted,
                                      QualificationInput};

const V1_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v1/qualification.schema.json");
const V2_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v2/qualification.schema.json");
const V3_SCHEMA: &[u8] = include_bytes!("../../../contracts/native-profile-v3/qualification.schema.json");

struct Setup {
    positives: Vec<Value>,
    evidence: Value,
    inventory: Value,
    schema: CaptureSchema,
    record_schema: RecordSchema,
    predecessors: PredecessorSchemas,
}

fn setup() -> Setup {
    let (schema, record_schema) = CaptureSchema::embedded().expect("the embedded schemas");
    Setup {
        positives: list(&parse(V5_VECTORS), "positive").to_vec(),
        evidence: field(&parse(I06_V3_VECTORS), "evidencePositive").clone(),
        inventory: json::parse(std::str::from_utf8(contracts::WRITER_INVENTORY).expect("UTF-8")).expect("the inventory"),
        schema,
        record_schema,
        predecessors: PredecessorSchemas::from_bytes(V1_SCHEMA, V2_SCHEMA, V3_SCHEMA).expect("the predecessor schemas"),
    }
}

/// The evidence check of I06 v3's positive against v5 positive `number`'s record (equal to v4's).
fn evidence(setup: &Setup, number: usize, fixture: bool) -> Result<EvidenceAccepted, EvidenceRefusal> {
    let positive = &setup.positives[number];
    check_evidence(&setup.evidence, &setup.inventory, field(positive, "record"), field(positive, "profile"),
                   field(positive, "endpoints"), &setup.record_schema, fixture)
}

/// The qualification of v5 positive `number` with the v1-v3 positives' records as histories.
fn qualification(setup: &Setup, number: usize, fixture: bool) -> Result<QualificationAccepted, Refusal> {
    let positive = &setup.positives[number];
    let input = QualificationInput {
        record: field(positive, "record").clone(),
        profile: field(positive, "profile").clone(),
        endpoints: field(positive, "endpoints").clone(),
        captures: field(positive, "captures").clone(),
        lifecycle: field(positive, "lifecycle").clone(),
        backend_captures: field(positive, "backendCaptures").clone(),
        histories: Histories::new(Value::Array(positive_records(V1_VECTORS)), Value::Array(positive_records(V2_VECTORS)),
                                  Value::Array(positive_records(V3_VECTORS))),
        no_earlier_history: false,
    };
    check_qualification(&input, &setup.schema, &setup.record_schema, &setup.predecessors, fixture)
}

#[test]
fn the_fixture_composition_binds_one_record() {
    let setup = setup();
    let record = field(&setup.positives[0], "record");
    let (proof, qualified) = (evidence(&setup, 0, true).expect("the evidence"), qualification(&setup, 0, true).expect("qualified"));
    assert_eq!(proof.record_digest(), qualified.record_digest());
    let (valid_from, expires_at) = (qualified.valid_from(), qualified.expires_at());
    let composed = compose_fixture(proof, qualified).expect("composed");
    assert_eq!(Some(composed.record_digest().to_string()), record_digest(record));
    assert_eq!(Some(composed.evidence_digest().to_string()), record_digest(&setup.evidence));
    assert_eq!((composed.valid_from(), composed.expires_at()), (valid_from, expires_at));
    assert!(valid_from < expires_at);
}

#[test]
fn tokens_of_two_records_do_not_compose() {
    let setup = setup();
    assert_ne!(record_digest(field(&setup.positives[0], "record")), record_digest(field(&setup.positives[1], "record")));
    let proof = evidence(&setup, 0, true).expect("the evidence");
    let other = qualification(&setup, 1, true).expect("positive 1 qualifies");
    assert_eq!(compose_fixture(proof, other), Err(CompositionRefusal::RecordMismatch));
}

#[test]
fn the_production_entry_refuses_fixture_tokens() {
    let setup = setup();
    let (proof, qualified) = (evidence(&setup, 0, true).expect("the evidence"), qualification(&setup, 0, true).expect("qualified"));
    assert_eq!(compose_production(&proof, &qualified), Err(CompositionRefusal::FixtureTokenInProduction));
    // The tokens are only borrowed there: they still compose as fixtures afterwards.
    assert!(compose_fixture(proof, qualified).is_ok());
}

#[test]
fn no_production_token_can_be_made_today() {
    let setup = setup();
    for number in 0..setup.positives.len() {
        assert_eq!(qualification(&setup, number, false).map(|_| ()), Err(Refusal::Model("test-only implementation profile")),
                   "positive {number}");
    }
    let refused = evidence(&setup, 0, false).map(|_| ()).expect_err("production evidence refused");
    assert!(refused.text().is_some(), "{refused:?}");
    // The record's backend profile is the test-only one, which the native-profile v4 schema alone admits.
    let backend = field(field(&setup.positives[0], "record"), "backendProfile");
    assert_eq!(field(backend, "testOnly").as_bool(), Some(true));
}
