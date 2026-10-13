//! Both suites through file stores (HE-002C DESIGN §11): every I05 v3 transcript, S01-S06, the R10-local I05 and I07
//! vectors (HE-002C's two included) and every I07 v3 transcript, each on a new generation's file stores (`create`,
//! one store opening per transcript) in lockstep with the in-memory gate. After every event the outputs are equal and
//! both the mirror and a fresh scan of the journal file equal the in-memory journal; at the end the snapshots and the
//! journal digests are equal, and the outputs and final snapshot equal the vector's.

mod file_support;
mod policy_support;
mod support;

use file_support::*;
use i05_protocol::json::Value;
use policy_support::{I07_VECTORS, KINDS};
use support::{compare, field, load, rows, text, Replay};

const I05_VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");
const SUPPLEMENT: &str = include_str!("../../../contracts/i05-v3-supplement/vectors.json");
const LOCAL: &str = include_str!("vectors-local.json");
const LOCAL_I07: &str = include_str!("vectors-local-i07.json");
const LOCAL_HE002C: &str = include_str!("vectors-local-i07-he002c.json");

/// Runs rows through files; returns (transcripts, final journal entries).
fn through_files(group: &str, family: &Family, configs: &Value, rows: &[Value]) -> (usize, usize) {
    let mut failures = Vec::new();
    let mut entries = 0;
    for row in rows {
        let id = text(row, "id");
        let place = Place::fresh(group, id);
        let run = lockstep(family, field(configs, text(row, "config")), rows_of(row), &place, id);
        entries += run.entries;
        let replay = Replay { outputs: run.outputs, snapshot: run.snapshot, frames: 0, value_fallbacks: 0 };
        match compare(&replay, row) {
            Ok(()) => place.remove(),
            Err(difference) => failures.push(format!("{id}: {difference}")),
        }
    }
    assert!(failures.is_empty(), "{} of {} differ from their vectors:\n{}", failures.len(), rows.len(), failures.join("\n"));
    (rows.len(), entries)
}

fn rows_of(row: &Value) -> &[Value] {
    rows(row, "events")
}

fn i05_part(range: std::ops::Range<usize>, group: &str) -> (usize, usize) {
    let vectors = load(I05_VECTORS);
    let transcripts = rows(&vectors, "transcripts");
    assert_eq!(transcripts.len(), 120);
    through_files(group, &Family::I05, field(&vectors, "configs"), &transcripts[range])
}

fn i07_part(range: std::ops::Range<usize>, group: &str) -> (usize, usize) {
    let vectors = load(I07_VECTORS);
    let transcripts = rows(&vectors, "transcripts");
    assert_eq!(transcripts.len(), 62);
    through_files(group, &Family::I07 { kinds: load(KINDS) }, field(&vectors, "configs"), &transcripts[range])
}

#[test]
fn i05_transcripts_1_to_40_through_files() {
    assert_eq!(i05_part(0..40, "i05-a").0, 40);
}

#[test]
fn i05_transcripts_41_to_80_through_files() {
    assert_eq!(i05_part(40..80, "i05-b").0, 40);
}

#[test]
fn i05_transcripts_81_to_120_through_files() {
    assert_eq!(i05_part(80..120, "i05-c").0, 40);
}

#[test]
fn i07_transcripts_1_to_31_through_files() {
    assert_eq!(i07_part(0..31, "i07-a").0, 31);
}

#[test]
fn i07_transcripts_32_to_62_through_files() {
    assert_eq!(i07_part(31..62, "i07-b").0, 31);
}

#[test]
fn supplementary_and_local_transcripts_through_files() {
    let i05 = load(I05_VECTORS);
    let i05_configs = field(&i05, "configs");
    let supplement = load(SUPPLEMENT);
    assert_eq!(through_files("supplement", &Family::I05, i05_configs, rows(&supplement, "transcripts")), (6, 26));
    let local = load(LOCAL);
    assert_eq!(through_files("local", &Family::I05, i05_configs, rows(&local, "transcripts")), (8, 48));
    let i07 = load(I07_VECTORS);
    let family = Family::I07 { kinds: load(KINDS) };
    let local_i07 = load(LOCAL_I07);
    assert_eq!(through_files("local-i07", &family, field(&i07, "configs"), rows(&local_i07, "transcripts")), (17, 101));
    let he002c = load(LOCAL_HE002C);
    assert_eq!(through_files("local-he002c", &family, field(&i07, "configs"), rows(&he002c, "transcripts")), (2, 17));
}

/// The two R10-local I07 vectors of HE-002C, in memory on both frame paths (the file runs are above).
#[test]
fn he002c_local_i07_vectors_in_memory() {
    let local = load(LOCAL_HE002C);
    assert_eq!(text(&local, "evidenceClass"), "R10_LOCAL");
    let model = field(&local, "model");
    assert_eq!(text(model, "path"), "scripts/i07_policy_write_v3.py");
    assert_eq!(text(model, "commit"), "a2eab9365c8663cc1ae23a666e864b821f600fa6");
    assert_eq!(text(model, "sha256"), "6cc7ea0d3df0c7f2966184bb6d322189de3b49b5b02dfe2429911121973afe08");
    let reference = field(field(&local, "configs"), "ACTIVE");
    assert_eq!(text(reference, "vectorsPath"), "contracts/i07-v3/vectors.json");
    let contract = load(I07_VECTORS);
    let kinds = load(KINDS);
    let transcripts = rows(&local, "transcripts");
    let ids: Vec<&str> = transcripts.iter().map(|row| text(row, "id")).collect();
    assert_eq!(ids, ["R10-I07-C01", "R10-I07-C02"]);
    for row in transcripts {
        let id = text(row, "id");
        let config = field(field(&contract, "configs"), text(row, "config"));
        for mode in [support::Mode::Value, support::Mode::Bytes] {
            let replay = policy_support::replay_i07(config, &kinds, rows_of(row), mode, id);
            if let Err(difference) = compare(&replay.replay, row) {
                panic!("{id} ({mode:?}): {difference}");
            }
        }
    }
    // What each pins: the failed record is absent from the journal and the storage-failure path ran.
    let journal = |row: &Value| support::show(field(field(row, "final"), "journal"));
    assert!(!journal(&transcripts[0]).contains("WRITER_SESSION_ENDED"));
    assert!(journal(&transcripts[0]).contains(r#"["INVALIDATED","STORAGE_FAILURE","HELD"],["MAINT_ENDED","SESSION_FATAL",0,[]]"#));
    assert!(!journal(&transcripts[1]).contains("WRITE_TERMINAL"));
    let upstream = &rows(&transcripts[1], "outputs")[5];
    assert_eq!(support::show(field(upstream, "classification")), r#""IO_AMBIGUOUS""#);
    assert_eq!(support::show(field(field(upstream, "response"), "httpStatus")), "null");
}
