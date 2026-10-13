//! The I07 R10-local vectors (`vectors-local-i07.json`, HE-002B DESIGN §8; not contract data): the transcripts and the
//! kind check that close the gaps of the coverage measure on the pinned I07 v3 model (its executed lines, and every
//! success and failure of each I07 record it writes), and R10-L03 in its I07 form. Their expected values were computed
//! by the pinned model (`scripts/i07_policy_write_v3.py` at `a2eab93`, sha256 `6cc7ea0d…`); every transcript is replayed
//! here on both frame paths and must reproduce them. HE-002's `vectors-local.json` is separate and unchanged.

mod policy_support;
mod support;

use effect_gate::{check_write, PolicyKinds, WriteRequest};
use i05_protocol::json::Value;
use policy_support::*;
use support::*;

const LOCAL: &str = include_str!("vectors-local-i07.json");

/// The configuration a local row names, resolved through the file's reference into the I07 v3 contract vectors.
fn resolve_config<'a>(local: &Value, contract: &'a Value, name: &str) -> &'a Value {
    let reference = field(field(local, "configs"), name);
    assert_eq!(text(reference, "vectorsPath"), "contracts/i07-v3/vectors.json");
    let key: Vec<&str> = rows(reference, "key").iter().map(|part| part.as_str().expect("key part")).collect();
    assert_eq!(key, ["configs", name], "{name} is the I07 v3 configuration of the same name");
    field(field(contract, "configs"), name)
}

#[test]
fn local_header_names_the_pinned_model() {
    let local = load(LOCAL);
    assert_eq!(text(&local, "evidenceClass"), "R10_LOCAL");
    let model = field(&local, "model");
    assert_eq!(text(model, "path"), "scripts/i07_policy_write_v3.py");
    assert_eq!(text(model, "commit"), "a2eab9365c8663cc1ae23a666e864b821f600fa6");
    assert_eq!(text(model, "sha256"), "6cc7ea0d3df0c7f2966184bb6d322189de3b49b5b02dfe2429911121973afe08");
    let configs = field(&local, "configs").as_object().expect("configs");
    assert_eq!(configs.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>(), [Some("ACTIVE")]);
}

#[test]
fn local_i07_transcripts() {
    let local = load(LOCAL);
    let contract = load(I07_VECTORS);
    let kinds = load(KINDS);
    let transcripts = rows(&local, "transcripts");
    let ids: Vec<&str> = transcripts.iter().map(|row| text(row, "id")).collect();
    assert_eq!(ids, [
        "R10-I07-L01", "R10-I07-L02", "R10-I07-L03", "R10-I07-L04", "R10-I07-L05", "R10-I07-L06", "R10-I07-L07",
        "R10-I07-L08", "R10-I07-L09", "R10-I07-L10", "R10-I07-L11", "R10-I07-L12", "R10-I07-L13", "R10-I07-L14",
        "R10-I07-L15", "R10-I07-L16", "R10-L03-I07",
    ]);
    let (mut frames, mut writer_frames, mut fallbacks) = ([0usize; 2], [0usize; 2], 0usize);
    for row in transcripts {
        let id = text(row, "id");
        let config = resolve_config(&local, &contract, text(row, "config"));
        for (slot, mode) in [Mode::Value, Mode::Bytes].into_iter().enumerate() {
            let replay = replay_i07(config, &kinds, rows(row, "events"), mode, id);
            if let Err(difference) = compare(&replay.replay, row) {
                panic!("{id} ({mode:?}): {difference}");
            }
            frames[slot] += replay.replay.frames;
            writer_frames[slot] += replay.writer_frames;
            if mode == Mode::Bytes {
                fallbacks += replay.replay.value_fallbacks;
            }
        }
    }
    assert_eq!(frames, [9, 9], "every FRAME event replayed on both paths");
    assert_eq!(writer_frames, [47, 47], "every W_FRAME event replayed on both paths");
    assert_eq!(fallbacks, 0, "every built frame has a canonical encoding");
}

/// R10-L03 in its I07 form: the status after the restart reports the journal digest the pinned model computes.
#[test]
fn r10_l03_reports_the_journal_digest_on_the_channel() {
    let local = load(LOCAL);
    let row = rows(&local, "transcripts").iter().find(|row| text(row, "id") == "R10-L03-I07").expect("R10-L03-I07");
    let outputs = rows(row, "outputs");
    let status = outputs.last().and_then(|output| output.get("response")).expect("a status response");
    assert_eq!(text(status, "journalDigest"), "sha256:d406a10ae219760668b3685e632fb8a20dac473d66179cd502705dc3ae3c0e1d");
    assert_eq!(text(status, "maintenance"), "ENDED");
    assert_eq!(text(status, "gateState"), "CLOSED");
    assert_eq!(text(field(row, "final"), "maintenanceReason"), "GENERATION_REBUILT");
}

#[test]
fn local_kind_checks() {
    let local = load(LOCAL);
    let kinds = PolicyKinds::from_value(&load(KINDS)).expect("the contract table");
    let checks = rows(&local, "kindChecks");
    assert_eq!(checks.len(), 1);
    for row in checks {
        let id = text(row, "id");
        let request = WriteRequest::from_payload(field(row, "payload")).unwrap_or_else(|| panic!("{id}: payload"));
        let got = check_write(&kinds, "planeon-qual", &request).err().map(|refusal| refusal.as_str());
        assert_eq!(got, field(row, "expect").as_str(), "{id}: {}", text(row, "intent"));
    }
}
