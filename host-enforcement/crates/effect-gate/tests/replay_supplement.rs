//! The I05 v3 supplementary vectors (harness-onion W03-AMEND `93d32e1`, owner decision Q-HE2-E (b)): six transcripts in
//! the v3 transcript format on the v3 ACTIVE configuration, named by reference to the v3 vector file. Each is replayed
//! on both the value and the byte path with every output and the final snapshot equal to the vectors; a row's
//! `equals` names a reference whose non-injection outputs and final snapshot it must reproduce (S01 = S02 and
//! S03 = S04: a second STORAGE_FAIL_AFTER replaces a pending first one, AF2-I05-1 / I05-4). S05 pins accumulation and
//! S06 the queue order.

mod support;

use i05_protocol::json::{self, Value};
use i05_protocol::sha256;
use support::*;

const SUPPLEMENT: &str = include_str!("../../../contracts/i05-v3-supplement/vectors.json");
const CONTRACT: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const INJECTIONS: [&str; 3] = ["STORAGE_FAIL_NEXT", "STORAGE_FAIL_AFTER", "MARKER_FAIL_NEXT"];

/// The configuration a supplementary row names, resolved through the supplement's reference into the v3 vector file.
fn resolve_config<'a>(supplement: &Value, contract: &'a Value, name: &str) -> &'a Value {
    let reference = field(field(supplement, "configs"), name);
    assert_eq!(text(reference, "vectorsPath"), text(field(supplement, "contract"), "path"), "{name} names the v3 file");
    let key: Vec<&str> = rows(reference, "key").iter().map(|part| part.as_str().expect("key part")).collect();
    assert_eq!(key, ["configs", name], "{name} is the v3 configuration of the same name");
    field(field(contract, "configs"), name)
}

/// The outputs of a replay's non-injection events.
fn non_injection(outputs: &[Value], events: &[Value]) -> Vec<Value> {
    assert_eq!(outputs.len(), events.len());
    outputs
        .iter()
        .zip(events)
        .filter(|(_, event)| !INJECTIONS.contains(&text(event, "type")))
        .map(|(output, _)| output.clone())
        .collect()
}

#[test]
fn supplement_header_binds_the_v3_contract() {
    let supplement = load(SUPPLEMENT);
    assert_eq!(text(&supplement, "schemaVersion"), "planeon.internal.effect-gate-supplement/v1");
    assert_eq!(text(&supplement, "evidenceClass"), "DATA_CHECK_ONLY");
    let contract = field(&supplement, "contract");
    assert_eq!(text(contract, "path"), "architecture/i05-gate-channel-v3/vectors.json");
    let digest = sha256::hex(&sha256::digest(CONTRACT.as_bytes()));
    assert_eq!(text(contract, "sha256"), digest, "the referenced v3 file is ours");
    let configs = field(&supplement, "configs").as_object().expect("configs");
    assert_eq!(configs.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), [Some("ACTIVE")]);
}

#[test]
fn supplementary_transcripts() {
    let supplement = load(SUPPLEMENT);
    let contract = load(CONTRACT);
    let transcripts = rows(&supplement, "transcripts");
    let ids: Vec<&str> = transcripts.iter().map(|row| text(row, "id")).collect();
    assert_eq!(ids, ["S01", "S02", "S03", "S04", "S05", "S06"]);
    let mut replays = Vec::new();
    for row in transcripts {
        let id = text(row, "id");
        let config = resolve_config(&supplement, &contract, text(row, "config"));
        for mode in [Mode::Bytes, Mode::Value] {
            let replay = replay(config, rows(row, "events"), mode, id);
            if let Err(difference) = compare(&replay, row) {
                panic!("{id} ({mode:?}): {difference}");
            }
            if mode == Mode::Value {
                replays.push(replay);
            } else {
                assert_eq!(replay.value_fallbacks, 0, "{id}: every built frame has a canonical encoding");
            }
        }
    }
    let mut pairs = Vec::new();
    for (index, row) in transcripts.iter().enumerate() {
        let Some(reference) = row.get("equals") else { continue };
        let reference = reference.as_str().expect("equals names a row");
        let other = ids.iter().position(|id| *id == reference).expect("equals names a supplementary row");
        let (mine, theirs) = (&replays[index], &replays[other]);
        let (my_events, their_events) = (rows(row, "events"), rows(&transcripts[other], "events"));
        let (got, want) = (non_injection(&mine.outputs, my_events), non_injection(&theirs.outputs, their_events));
        let id = ids[index];
        assert!(json::json_eq(&Value::Array(got), &Value::Array(want)), "{id}: non-injection outputs differ from {reference}");
        assert!(json::json_eq(&mine.snapshot, &theirs.snapshot), "{id}: final snapshot differs from {reference}");
        pairs.push((id, reference));
    }
    assert_eq!(pairs, [("S01", "S02"), ("S03", "S04")]);
    // The two references differ, so the pairs show the replacement in both directions.
    assert!(!json::json_eq(&replays[1].snapshot, &replays[3].snapshot), "S02 and S04 differ");
}
