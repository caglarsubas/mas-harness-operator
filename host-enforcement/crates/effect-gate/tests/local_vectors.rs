//! The R10-local vectors (`vectors-local.json`, DESIGN §8; not contract data): R10-L01 (STORAGE_FAIL_AFTER replaced in
//! both directions, with each pair required to behave identically), R10-L02 (the injection queue order), R10-L03 (EXPIRE
//! after a restart journals EXPIRED), and the R10-B byte and agreement checks of DESIGN §5's consequences. Expected
//! values come from R10's own run; the independent review re-runs the pinned model on the same inputs.

mod support;

use i05_protocol::json::{self, Value};
use i05_protocol::{decode_frame, Datagram, Identity, Kind, OutcomeMapping, Verb};
use support::*;

const LOCAL: &str = include_str!("vectors-local.json");
const CONTRACT: &str = include_str!("../../../contracts/i05-v3/vectors.json");

fn expect(row: &Value) -> Option<String> {
    match field(row, "expect") {
        Value::Null => None,
        other => Some(other.as_str().expect("expect is text or null").to_string()),
    }
}

#[test]
fn local_transcripts() {
    let local = load(LOCAL);
    assert_eq!(text(&local, "evidenceClass"), "R10_LOCAL");
    let contract = load(CONTRACT);
    let configs = field(&contract, "configs");
    let transcripts = rows(&local, "transcripts");
    let ids: Vec<&str> = transcripts.iter().map(|row| text(row, "id")).collect();
    assert_eq!(ids, ["R10-L01a", "R10-L01b", "R10-L01c", "R10-L01d", "R10-L02", "R10-L02b", "R10-L03", "R10-L03b"]);
    for row in transcripts {
        let id = text(row, "id");
        for mode in [Mode::Value, Mode::Bytes] {
            let replay = replay(field(configs, text(row, "config")), rows(row, "events"), mode, id);
            if let Err(difference) = compare(&replay, row) {
                panic!("{id} ({mode:?}): {difference}");
            }
        }
    }
}

/// A second STORAGE_FAIL_AFTER replaces the first: each pair has the same outputs (the injection events aside) and the
/// same final snapshot.
#[test]
fn replaced_injection_behaves_as_the_second_alone() {
    let local = load(LOCAL);
    let transcripts = rows(&local, "transcripts");
    let find = |id: &str| transcripts.iter().find(|row| text(row, "id") == id).unwrap_or_else(|| panic!("{id}"));
    let pairs = rows(&local, "sameAs");
    assert_eq!(pairs.len(), 2);
    for pair in pairs {
        let pair = pair.as_array().expect("pair");
        let (left, right) = (find(pair[0].as_str().expect("id")), find(pair[1].as_str().expect("id")));
        let effective = |row: &Value| -> Vec<Value> {
            rows(row, "events")
                .iter()
                .zip(rows(row, "outputs"))
                .filter(|(event, _)| text(event, "type") != "STORAGE_FAIL_AFTER")
                .map(|(_, output)| output.clone())
                .collect()
        };
        let (a, b) = (effective(left), effective(right));
        assert_eq!(a.len(), b.len());
        assert!(a.iter().zip(&b).all(|(x, y)| json::json_eq(x, y)), "{} and {} differ", text(left, "id"), text(right, "id"));
        assert!(json::json_eq(field(left, "final"), field(right, "final")));
    }
}

#[test]
fn local_byte_checks() {
    let local = load(LOCAL);
    let schema = i05_protocol::i05_v3_schema().expect("schema");
    let checks = rows(&local, "byteFrames");
    assert_eq!(checks.len(), 30);
    for row in checks {
        let id = text(row, "id");
        let raw = i05_protocol::base64::decode_strict(text(row, "base64").as_bytes()).expect("base64");
        let got = decode_frame(Datagram::Bytes(&raw), &schema).err().map(|error| error.message().to_string());
        assert_eq!(got, expect(row), "{id}: {}", text(row, "intent"));
    }
}

#[test]
fn local_agreement_checks() {
    let local = load(LOCAL);
    let mapping = OutcomeMapping::i05_v3().expect("mapping");
    let checks = rows(&local, "agreement");
    assert_eq!(checks.len(), 15);
    for row in checks {
        let id = text(row, "id");
        let identity = field(row, "identity");
        let identity = Identity {
            api_version: text(identity, "apiVersion").to_string(),
            kind: Kind::parse(text(identity, "kind")).expect("kind"),
            namespace: text(identity, "namespace").to_string(),
            name: text(identity, "name").to_string(),
        };
        let verb = Verb::parse(text(row, "verb")).expect("verb");
        let got = mapping
            .check_agreement(verb, &identity, field(row, "outcome"), field(row, "resourceResult"))
            .map(|mismatch| mismatch.message().to_string());
        assert_eq!(got, expect(row), "{id}: {}", text(row, "intent"));
    }
}
