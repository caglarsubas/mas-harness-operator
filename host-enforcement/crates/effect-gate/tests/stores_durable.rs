//! The file stores with real files under `CARGO_TARGET_TMPDIR` (HE-002C DESIGN §5-§11): every append failure point
//! with its `Appended` value, mirror and scan (Q-HE2C-1's window asserted as such); the R10-defined rules R19-R30; the
//! marker's fail-closed forms; the cross-process bindings (owner decision Q-HE2C-2 (a)); and the opening shapes the
//! design reviews raised (C1, C2, D1, D2).

mod file_support;
mod policy_support;
mod support;

use std::fs;
use std::os::unix::fs::MetadataExt;

use effect_gate::file_store::{fstat_device, journal_name, marker_name, INDEX_NAME, MAX_FILE_BYTES};
use effect_gate::frame::{self, Scanned, COMMITTED, MAX_PAYLOAD_BYTES, PENDING};
use effect_gate::{Appended, Config, Entry, FaultHandle, FaultPlan, FilePoint, FileStores, Gate, GateError, OpenError,
                  OutputKind, PolicyGate, PolicyGateError, Record, State, StoreDir, StoreFile, Stores};
use file_support::*;
use i05_protocol::json::{JStr, Object, Value};
use support::{field, load, rows, show, text};

const I05_VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");

/// A generation name for the store-level cases.
const G: &str = "g-1";

fn doc_text(doc: &i05_protocol::json::Doc) -> String {
    String::from_utf8_lossy(&doc.canonical()).into_owned()
}

fn length(path: &str) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

fn exists(path: &str) -> bool {
    fs::exists(path).unwrap_or(true)
}

fn committed_frame(payload: &[u8]) -> Vec<u8> {
    frame::encode(payload, COMMITTED).expect("a frame")
}

// ------------------------------------------------------------------------------------------ append failure points

struct PointRun {
    appended: Appended,
    mirror: Vec<Entry>,
    scan: Vec<Entry>,
    /// The failed frame's status byte in the file, if the frame is whole there.
    status: Option<u8>,
    grew: bool,
}

/// Appends DRAIN_STARTED, then CONSUMED 1 with the plan changed by `arm`, then DENIED 2.
fn points(case: &str, arm: impl Fn(&mut FaultPlan)) -> PointRun {
    let place = Place::fresh("points", case);
    let plan = FaultHandle::default();
    let mut stores = place.stores(G, Some(plan.clone()));
    assert_eq!(stores.append(Record::DrainStarted), Appended::Durable);
    let path = place.file(&journal_name(G));
    let first = length(&path);
    plan.with(arm);
    let consumed = Record::Consumed { action_id: 1 };
    let size = frame::encode(&consumed.to_doc().canonical(), PENDING).map_or(0, |frame| frame.len());
    let appended = stores.append(consumed);
    let raw = Place::bytes(&path);
    let status = usize::try_from(first).ok().and_then(|first| raw.get(first + size - 2)).copied();
    let grew = length(&path) > first;
    assert_eq!(stores.append(Record::Denied { action_id: 2 }), Appended::Durable, "{case}: the next append");
    let run = PointRun { appended, mirror: stores.entries().to_vec(), scan: place.scan(G), status, grew };
    drop(stores);
    place.remove();
    run
}

#[test]
fn every_append_failure_point_has_its_outcome() {
    let drain = Entry::Record(Record::DrainStarted);
    let consumed = Entry::Record(Record::Consumed { action_id: 1 });
    let denied = Entry::Record(Record::Denied { action_id: 2 });
    let durable = vec![drain.clone(), consumed.clone(), denied.clone()];
    let clean = vec![drain.clone(), denied.clone()];
    let torn = vec![drain.clone(), Entry::Torn, denied.clone()];
    let run = points("none", |_| {});
    assert_eq!((run.appended, run.status), (Appended::Durable, Some(COMMITTED)));
    assert_eq!((&run.mirror, &run.scan), (&durable, &durable));
    // Nothing written: a clean failure, the mirror and the file without it.
    for (case, arm) in [("first-write", FilePoint::FirstWrite)] {
        let run = points(case, |plan| plan.arm(StoreFile::Journal, arm));
        assert_eq!((run.appended, run.grew), (Appended::Failed { torn: false }, false), "{case}");
        assert_eq!((&run.mirror, &run.scan), (&clean, &clean), "{case}");
    }
    // Bytes written and no commit byte: torn, the file holds a partial or pending frame.
    for (case, arm, status) in [
        ("partial-frame", FilePoint::PartialFrame, None),
        ("first-sync", FilePoint::FirstSync, Some(PENDING)),
        ("first-read-back", FilePoint::FirstReadBack, Some(PENDING)),
        ("commit-write", FilePoint::CommitWrite, Some(PENDING)),
    ] {
        let run = points(case, |plan| plan.arm(StoreFile::Journal, arm));
        assert_eq!((run.appended, run.status), (Appended::Failed { torn: true }, status), "{case}");
        assert_eq!((&run.mirror, &run.scan), (&torn, &torn), "{case}");
    }
    // The commit byte written, its sync or read-back failed: torn and revoked (R29).
    for (case, arm) in [("commit-sync", FilePoint::CommitSync), ("commit-read-back", FilePoint::CommitReadBack)] {
        let run = points(case, |plan| plan.arm(StoreFile::Journal, arm));
        assert_eq!((run.appended, run.status), (Appended::Failed { torn: true }, Some(frame::REVOKED)), "{case}");
        assert_eq!((&run.mirror, &run.scan), (&torn, &torn), "{case}");
    }
    // Q-HE2C-1's window: the revocation fails too. The mirror holds TORN, but a scan (a process restart) reads the
    // committed frame as a record.
    for (case, arm) in [("commit-sync-revoke", FilePoint::CommitSync), ("commit-read-back-revoke", FilePoint::CommitReadBack)] {
        let run = points(case, |plan| {
            plan.arm(StoreFile::Journal, arm);
            plan.arm(StoreFile::Journal, FilePoint::Revoke);
        });
        assert_eq!((run.appended, run.status), (Appended::Failed { torn: true }, Some(COMMITTED)), "{case}");
        assert_eq!(run.mirror, torn, "{case}: the mirror");
        assert_eq!(run.scan, durable, "{case}: the scan reads the window's record");
    }
    // The contract's injections on files: STORAGE_FAIL_NEXT clean is FirstWrite, torn is PartialFrame, and
    // STORAGE_FAIL_AFTER joins the queue.
    let run = points("fail-next-clean", |plan| plan.fail_next(false));
    assert_eq!((run.appended, run.grew, &run.scan), (Appended::Failed { torn: false }, false, &clean));
    let run = points("fail-next-torn", |plan| plan.fail_next(true));
    assert_eq!((run.appended, run.status, &run.scan), (Appended::Failed { torn: true }, None, &torn));
    let run = points("fail-after-zero", |plan| plan.fail_after(0));
    assert_eq!((run.appended, &run.mirror, &run.scan), (Appended::Failed { torn: false }, &clean, &clean));
}

#[test]
fn r20_payload_and_file_bounds_fail_clean() {
    let place = Place::fresh("bounds", "payload");
    let mut stores = place.stores(G, None);
    let large = Record::Expired { execution_id: "x".repeat(MAX_PAYLOAD_BYTES) };
    assert_eq!(stores.append(large), Appended::Failed { torn: false });
    assert_eq!(length(&place.file(&journal_name(G))), 0);
    assert!(stores.entries().is_empty());
    drop(stores);
    place.remove();
    // A journal file past 64 MiB (sparse): the scan stops with one TORN for the rest, every append fails clean, and
    // the process restart is HELD with the marker written.
    let config = field(field(&load(I05_VECTORS), "configs"), "ACTIVE").clone();
    let generation = generation_of(&config);
    let place = Place::fresh("bounds", "file");
    let big = fs::File::create(place.file(&journal_name(&generation))).expect("journal file");
    big.set_len(MAX_FILE_BYTES + 1).expect("a sparse file");
    drop(big);
    let mut stores = place.stores(&generation, None);
    assert!(!stores.journal_created());
    assert_eq!(stores.entries(), [Entry::Torn]);
    assert_eq!(stores.append(Record::DrainStarted), Appended::Failed { torn: false });
    drop(stores);
    let typed = typed(&config);
    let (gate, output) = Gate::open(typed, place.stores(&generation, None)).expect("Gate::open");
    assert_eq!(output.kind, OutputKind::RestartState(State::Held));
    assert_eq!(gate.journal(), [Entry::Torn]);
    assert_eq!(show(field(&gate.snapshot().to_value(), "failureMarker")), format!(r#"[["{generation}","STORAGE_FAILURE"]]"#));
    assert_eq!(length(&place.file(&journal_name(&generation))), MAX_FILE_BYTES + 1);
    drop(gate);
    place.remove();
}

#[test]
fn r21_a_payload_outside_the_record_tuples_is_torn() {
    let config = field(field(&load(I05_VECTORS), "configs"), "ACTIVE").clone();
    let generation = generation_of(&config);
    let place = Place::fresh("r21", "undecodable");
    let mut planted = committed_frame(br#"["NOPE"]"#);
    planted.extend(committed_frame(br#"[ "DRAIN_STARTED"]"#));
    planted.extend(committed_frame(&Record::DrainStarted.to_doc().canonical()));
    fs::write(place.file(&journal_name(&generation)), &planted).expect("journal file");
    let stores = place.stores(&generation, None);
    assert_eq!(stores.entries(), [Entry::Torn, Entry::Torn, Entry::Record(Record::DrainStarted)]);
    drop(stores);
    let typed = typed(&config);
    let (_, output) = Gate::open(typed, place.stores(&generation, None)).expect("Gate::open");
    assert_eq!(output.kind, OutputKind::RestartState(State::Held));
    place.remove();
}

// ------------------------------------------------------------------------------------------ opening rules

#[test]
fn r19_generation_names() {
    let place = Place::fresh("r19", "names");
    let long = "a".repeat(129);
    for name in ["", ".hidden", "-x", "_x", "a/b", "a b", "generations", "é", "a\0b", "a:b", long.as_str()] {
        assert!(matches!(place.open(name, None), Err(OpenError::Name)), "{name:?}");
    }
    assert!(!exists(&place.file(INDEX_NAME)), "a refused name creates nothing");
    let longest = format!("Z{}", "y".repeat(127));
    for name in ["a", "A.b_c-9", "generations.x", longest.as_str()] {
        let stores = place.stores(name, None);
        assert!(stores.journal_created() && stores.indexed_now(), "{name}");
    }
    assert_eq!(place.index(), ["a", "A.b_c-9", "generations.x", longest.as_str()]);
    place.remove();
}

#[test]
fn r24_equal_devices_refuse_before_anything_is_created() {
    let place = Place::fresh("r24", "devices");
    let same = |_: StoreDir, _: &gate_sys::Dir| Ok(7);
    assert!(matches!(FileStores::open(&place.journal, &place.marker, G, &same, None), Err(OpenError::SameDevice)));
    // The production probe: both directories are on the build host's one device here.
    assert!(matches!(FileStores::open(&place.journal, &place.marker, G, &fstat_device, None), Err(OpenError::SameDevice)));
    let journals = gate_sys::Dir::at(&place.journal).expect("directory");
    assert_eq!(fstat_device(StoreDir::Journal, &journals).expect("fstat"), fs::metadata(&place.journal).expect("metadata").dev());
    assert!(!exists(&place.file(INDEX_NAME)) && !exists(&place.file(&journal_name(G))));
    place.remove();
}

#[test]
fn r25_a_live_journal_has_one_writer() {
    let place = Place::fresh("r25", "single-writer");
    let live = place.stores(G, None);
    assert!(matches!(place.open(G, None), Err(OpenError::JournalLocked)));
    drop(live);
    let reopened = place.stores(G, None);
    assert!(!reopened.journal_created() && !reopened.indexed_now());
    drop(reopened);
    place.remove();
}

#[test]
fn r28_only_the_newest_generation_reopens() {
    let place = Place::fresh("r28", "newest");
    drop(place.stores("g-1", None));
    drop(place.stores("g-2", None));
    let index = Place::bytes(&place.file(INDEX_NAME));
    assert!(matches!(place.open("g-1", None), Err(OpenError::NotNewest)));
    assert_eq!(Place::bytes(&place.file(INDEX_NAME)), index);
    drop(place.stores("g-2", None));
    place.remove();
}

#[test]
fn r23_a_missing_earlier_journal_refuses_and_changes_nothing() {
    let place = Place::fresh("r23", "missing");
    drop(place.stores("g-1", None));
    fs::remove_file(place.file(&journal_name("g-1"))).expect("journal removed");
    let index = Place::bytes(&place.file(INDEX_NAME));
    assert!(matches!(place.open("g-2", None), Err(OpenError::MissingEarlierJournal(name)) if name == "g-1"));
    assert_eq!(Place::bytes(&place.file(INDEX_NAME)), index, "the index is unchanged");
    assert!(!exists(&place.file(&journal_name("g-2"))), "nothing was created");
    place.remove();
}

/// R23's stricter half (owner decision Q-HE2C-4 (a); HE-002C PR review round 1, R1-2): an index, or a committed
/// earlier generation's journal, that cannot be read whole (here past R20's 64 MiB, sparse) refuses the open, and the
/// refused open creates nothing and indexes nothing.
#[test]
fn r23_an_index_or_earlier_journal_past_the_bound_refuses_the_open() {
    let entries = |directory: &str| fs::read_dir(directory).map_or(usize::MAX, Iterator::count);
    let place = Place::fresh("r23", "index-bound");
    let index = fs::File::create(place.file(INDEX_NAME)).expect("index file");
    index.set_len(MAX_FILE_BYTES + 1).expect("a sparse file");
    drop(index);
    let refused = place.open(G, None);
    assert!(matches!(&refused, Err(OpenError::Io(error))
                     if error.to_string() == "the generation index could not be read whole"), "{refused:?}");
    assert_eq!(length(&place.file(INDEX_NAME)), MAX_FILE_BYTES + 1, "nothing was indexed");
    assert!(!exists(&place.file(&journal_name(G))), "no journal was created");
    assert_eq!((entries(&place.journal), entries(&place.marker)), (1, 0), "nothing else was created");
    place.remove();
    let place = Place::fresh("r23", "earlier-journal-bound");
    drop(place.stores("g-1", None));
    let earlier = fs::File::create(place.file(&journal_name("g-1"))).expect("journal file");
    earlier.set_len(MAX_FILE_BYTES + 1).expect("a sparse file");
    drop(earlier);
    let index = Place::bytes(&place.file(INDEX_NAME));
    let refused = place.open("g-2", None);
    assert!(matches!(&refused, Err(OpenError::Io(error))
                     if error.to_string() == "an earlier generation's journal could not be read whole"), "{refused:?}");
    assert_eq!(Place::bytes(&place.file(INDEX_NAME)), index, "the index is unchanged");
    assert_eq!(place.index(), ["g-1"]);
    assert!(!exists(&place.file(&journal_name("g-2"))), "no journal was created");
    assert_eq!((entries(&place.journal), entries(&place.marker)), (2, 0), "nothing else was created");
    place.remove();
}

/// R30 and D2: an open refused because an earlier generation is live leaves nothing behind, so the same new
/// generation is created once the earlier holder is gone.
#[test]
fn r30_a_live_earlier_generation_refuses_the_next() {
    let config = field(field(&load(I05_VECTORS), "configs"), "ACTIVE").clone();
    let place = Place::fresh("r30", "live");
    let live = place.stores("g-1", None);
    let index = Place::bytes(&place.file(INDEX_NAME));
    assert!(matches!(place.open("g-2", None), Err(OpenError::EarlierGenerationLive(name)) if name == "g-1"));
    assert_eq!(Place::bytes(&place.file(INDEX_NAME)), index, "the index is unchanged");
    assert!(!exists(&place.file(&journal_name("g-2"))));
    drop(live);
    let stores = place.stores("g-2", None);
    assert!(stores.journal_created() && stores.indexed_now());
    let config = typed(&with(&config, "generation", Value::str("g-2")));
    assert!(Gate::create(config, stores).is_ok(), "the same generation is created afresh");
    assert_eq!(place.index(), ["g-1", "g-2"]);
    place.remove();
}

/// R26 as far as files show it: the journal exists before the index entry (a failed index append leaves a journal
/// and no entry), and the marker file appears only at the first marker write.
#[test]
fn r26_files_appear_in_the_durability_order() {
    let place = Place::fresh("r26", "order");
    let plan = FaultHandle::default();
    plan.with(|plan| plan.arm(StoreFile::Index, FilePoint::FirstWrite));
    assert!(matches!(place.open(G, Some(plan)), Err(OpenError::IndexAppend)));
    assert!(exists(&place.file(INDEX_NAME)) && exists(&place.file(&journal_name(G))));
    assert!(place.index().is_empty());
    assert!(!exists(&place.marker_file(&marker_name(G))));
    let mut stores = place.stores("g-2", None);
    assert!(!exists(&place.marker_file(&marker_name("g-2"))));
    assert!(stores.write_marker("g-2", "STORAGE_FAILURE"));
    assert_eq!(frame::scan_bytes(&Place::bytes(&place.marker_file(&marker_name("g-2")))).len(), 1);
    drop(stores);
    place.remove();
}

/// R26's directory syncs do not depend on which opening created a file (HE-002C PR review round 1, R1-3): every
/// opening syncs the journal directory once the index is open, and again before it appends the generation's index
/// entry, also when an earlier opening created the journal and failed; the first marker write syncs the marker
/// directory, also when the marker file was already there.
#[test]
fn r26_reopenings_sync_the_directories() {
    let place = Place::fresh("r26", "reopen");
    let first = place.stores("g-1", None);
    assert!(first.journal_created() && first.indexed_now());
    assert_eq!(first.directory_syncs(), (2, 0), "the index opened, then the new journal before its index entry");
    drop(first);
    let reopened = place.stores("g-1", None);
    assert!(!reopened.journal_created() && !reopened.indexed_now());
    assert_eq!(reopened.directory_syncs(), (1, 0), "an existing index is synced too");
    drop(reopened);
    // An opening creates g-2's journal and fails at its index append; the next opening finds the journal, syncs its
    // directory again and only then appends the index entry.
    let plan = FaultHandle::default();
    plan.with(|plan| plan.arm(StoreFile::Index, FilePoint::FirstWrite));
    assert!(matches!(place.open("g-2", Some(plan)), Err(OpenError::IndexAppend)));
    assert_eq!(place.index(), ["g-1"]);
    fs::write(place.marker_file(&marker_name("g-2")), b"").expect("an empty marker file");
    let mut stores = place.stores("g-2", None);
    assert!(!stores.journal_created() && stores.indexed_now() && stores.marker_file_exists());
    assert_eq!(stores.directory_syncs(), (2, 0), "an existing unindexed journal is synced before its index entry");
    assert_eq!(place.index(), ["g-1", "g-2"]);
    assert!(stores.write_marker("g-2", "STORAGE_FAILURE"));
    assert_eq!(stores.directory_syncs(), (2, 1), "an existing marker file's directory is synced at the first write");
    assert!(stores.write_marker("g-2", "STORAGE_FAILURE"));
    assert_eq!(stores.directory_syncs(), (2, 1), "a present marker is not rewritten");
    drop(stores);
    let mut stores = place.stores("g-3", None);
    assert!(stores.write_marker("g-3", "STORAGE_FAILURE"));
    assert_eq!(stores.directory_syncs(), (2, 1), "a new marker file's directory is synced once");
    drop(stores);
    place.remove();
}

// ------------------------------------------------------------------------------------------ the marker

#[test]
fn r22_the_marker_is_written_once_and_fails_closed() {
    let place = Place::fresh("r22", "written");
    let plan = FaultHandle::default();
    let mut stores = place.stores(G, Some(plan.clone()));
    let path = place.marker_file(&marker_name(G));
    assert!(!stores.marker_present() && !stores.marker_file_exists());
    assert_eq!(doc_text(&stores.marker_doc()), "[]");
    plan.with(|plan| plan.marker_fail_next());
    assert!(!stores.write_marker(G, "STORAGE_FAILURE"), "MARKER_FAIL_NEXT");
    assert!(!exists(&path), "a clean marker failure touches no file");
    assert!(stores.write_marker(G, "STORAGE_FAILURE"));
    let written = length(&path);
    assert!(stores.write_marker(G, "STORAGE_FAILURE"), "a present marker is not rewritten");
    assert_eq!(length(&path), written);
    assert_eq!(doc_text(&stores.marker_doc()), r#"[["g-1","STORAGE_FAILURE"]]"#);
    drop(stores);
    let stores = place.stores(G, None);
    assert!(stores.marker_present() && stores.marker_file_exists());
    assert_eq!(doc_text(&stores.marker_doc()), r#"[["g-1","STORAGE_FAILURE"]]"#);
    drop(stores);
    place.remove();
    // A real torn or revoked marker write leaves bytes: present, in R22's fail-closed form (DESIGN §5.2).
    for (case, point) in [("torn", FilePoint::PartialFrame), ("revoked", FilePoint::CommitSync), ("pending", FilePoint::FirstSync)] {
        let place = Place::fresh("r22", case);
        let plan = FaultHandle::default();
        let mut stores = place.stores(G, Some(plan.clone()));
        plan.with(|plan| plan.arm(StoreFile::Marker, point));
        assert!(!stores.write_marker(G, "STORAGE_FAILURE"), "{case}");
        assert!(stores.marker_present(), "{case}");
        assert_eq!(doc_text(&stores.marker_doc()), r#"[["g-1","UNREADABLE"]]"#, "{case}");
        assert!(stores.write_marker(G, "STORAGE_FAILURE"), "{case}: present, so not rewritten");
        drop(stores);
        let stores = place.stores(G, None);
        assert_eq!(doc_text(&stores.marker_doc()), r#"[["g-1","UNREADABLE"]]"#, "{case} after reopening");
        drop(stores);
        place.remove();
    }
}

#[test]
fn r22_planted_marker_bytes_count_as_present() {
    let own = committed_frame(&frame::marker_payload(G, "STORAGE_FAILURE"));
    let cases: [(&str, Vec<u8>, &str); 6] = [
        ("garbage", b"not a frame".to_vec(), r#"[["g-1","UNREADABLE"]]"#),
        ("other-generation", committed_frame(&frame::marker_payload("g-0", "STORAGE_FAILURE")), r#"[["g-1","UNREADABLE"]]"#),
        ("other-reason", committed_frame(&frame::marker_payload(G, "EXPIRY")), r#"[["g-1","UNREADABLE"]]"#),
        ("two-markers", [own.clone(), own.clone()].concat(), r#"[["g-1","UNREADABLE"]]"#),
        ("own", own, r#"[["g-1","STORAGE_FAILURE"]]"#),
        ("empty", Vec::new(), "[]"),
    ];
    for (case, bytes, doc) in cases {
        let place = Place::fresh("r22-planted", case);
        fs::write(place.marker_file(&marker_name(G)), &bytes).expect("marker file");
        let stores = place.stores(G, None);
        assert!(stores.marker_file_exists(), "{case}");
        assert_eq!(stores.marker_present(), !bytes.is_empty(), "{case}");
        assert_eq!(doc_text(&stores.marker_doc()), doc, "{case}");
        drop(stores);
        place.remove();
    }
}

// ------------------------------------------------------------------------------------------ create and open

fn active() -> Value {
    field(field(&load(I05_VECTORS), "configs"), "ACTIVE").clone()
}

fn with(config: &Value, key: &str, member: Value) -> Value {
    let mut object = config.as_object().expect("an object").clone();
    object.insert(JStr::new(key), member);
    Value::Object(object)
}

fn typed(config: &Value) -> Config {
    Config::from_value(&effect_gate::fake_kernel::convert_v3_config(config).expect("v4's conversion").0).expect("configuration")
}

fn event(kind: &str) -> Value {
    with(&Value::Object(Object::new()), "type", Value::str(kind))
}

fn opening_status() -> Value {
    let vectors = load(I05_VECTORS);
    let row = &rows(&vectors, "transcripts")[0];
    rows(row, "events")[0].clone()
}

/// C2: an indexed empty journal is no proof of a fresh generation. A first record that failed cleanly left only the
/// marker, and an opened channel wrote nothing; both reopen to `open` only, which restarts HELD.
#[test]
fn create_refuses_an_indexed_empty_journal_that_was_used() {
    let config = active();
    let generation = generation_of(&config);
    // Two clean failures: CHANNEL_ENDED and the storage path's INVALIDATED; only the marker is written.
    let place = Place::fresh("c2", "marker-only");
    let mut gate = Driven::create(&Family::I05, &config, place.stores(&generation, Some(FaultHandle::default())));
    gate.step(&event("STORAGE_FAIL_NEXT"), "c2");
    gate.step(&event("STORAGE_FAIL_NEXT"), "c2");
    assert_eq!(show(&gate.step(&event("CHANNEL_LOST"), "c2")), r#"{"channelEnd":"UNUSED"}"#);
    assert!(gate.journal().is_empty());
    drop(gate);
    let stores = place.stores(&generation, None);
    assert!(stores.entries().is_empty() && stores.marker_file_exists() && !stores.journal_created() && !stores.indexed_now());
    assert_eq!(Gate::create(typed(&config), stores).err(), Some(GateError::NotFresh));
    let (_, output) = Gate::open(typed(&config), place.stores(&generation, None)).expect("Gate::open");
    assert_eq!(output.kind, OutputKind::RestartState(State::Held));
    place.remove();
    // The channel opened (GENERATION_STATUS writes no record).
    let place = Place::fresh("c2", "channel-opened");
    let mut gate = Driven::create(&Family::I05, &config, place.stores(&generation, None));
    assert!(show(&gate.step(&opening_status(), "c2")).contains(r#""result":"OK""#));
    assert!(gate.journal().is_empty());
    drop(gate);
    let stores = place.stores(&generation, None);
    assert!(stores.entries().is_empty() && !stores.marker_file_exists() && !stores.journal_created());
    assert_eq!(Gate::create(typed(&config), stores).err(), Some(GateError::NotFresh));
    let (_, output) = Gate::open(typed(&config), place.stores(&generation, None)).expect("Gate::open");
    assert_eq!(output.kind, OutputKind::RestartState(State::Held));
    place.remove();
    // A marker file planted for a brand-new generation also refuses create.
    let place = Place::fresh("c2", "planted-marker");
    fs::write(place.marker_file(&marker_name(&generation)), b"").expect("marker file");
    let stores = place.stores(&generation, None);
    assert!(stores.journal_created() && stores.indexed_now() && stores.marker_file_exists());
    assert_eq!(Gate::create(typed(&config), stores).err(), Some(GateError::NotFresh));
    place.remove();
}

/// C1 and D2: failed and crashed index appends fail their opens, leave TORN entries the index ignores, and later
/// generations open and are created normally. A generation whose open failed after its journal was created is
/// burned: it can only be restarted (HELD).
#[test]
fn failed_index_appends_fail_the_open_and_burn_only_their_generation() {
    let config = active();
    let place = Place::fresh("c1", "index");
    for (generation, point) in [("gen-1", FilePoint::FirstSync), ("gen-2", FilePoint::PartialFrame)] {
        let plan = FaultHandle::default();
        plan.with(|plan| plan.arm(StoreFile::Index, point));
        assert!(matches!(place.open(generation, Some(plan)), Err(OpenError::IndexAppend)), "{generation}");
        assert!(place.index().is_empty(), "{generation}");
    }
    assert_eq!(frame::scan_bytes(&Place::bytes(&place.file(INDEX_NAME))), [Scanned::Torn, Scanned::Torn]);
    for generation in ["gen-3", "gen-4"] {
        let stores = place.stores(generation, None);
        assert!(stores.journal_created() && stores.indexed_now(), "{generation}");
        let gate = Gate::create(typed(&with(&config, "generation", Value::str(generation))), stores);
        assert!(gate.is_ok(), "{generation} is created");
    }
    assert_eq!(place.index(), ["gen-3", "gen-4"]);
    let burned = typed(&with(&config, "generation", Value::str("gen-1")));
    let stores = place.stores("gen-1", None);
    assert!(!stores.journal_created() && stores.indexed_now());
    assert_eq!(Gate::create(burned.clone(), stores).err(), Some(GateError::NotFresh));
    let (_, output) = Gate::open(burned, place.stores("gen-1", None)).expect("Gate::open");
    assert_eq!(output.kind, OutputKind::RestartState(State::Held));
    place.remove();
    // An index append inside Q-HE2C-1's window fails the open, but its entry reads as committed: open only.
    let place = Place::fresh("c1", "window");
    let plan = FaultHandle::default();
    plan.with(|plan| {
        plan.arm(StoreFile::Index, FilePoint::CommitSync);
        plan.arm(StoreFile::Index, FilePoint::Revoke);
    });
    assert!(matches!(place.open("gen-1", Some(plan)), Err(OpenError::IndexAppend)));
    assert_eq!(place.index(), ["gen-1"]);
    let window = typed(&with(&config, "generation", Value::str("gen-1")));
    let stores = place.stores("gen-1", None);
    assert!(!stores.journal_created() && !stores.indexed_now());
    assert_eq!(Gate::create(window.clone(), stores).err(), Some(GateError::NotFresh));
    let (_, output) = Gate::open(window, place.stores("gen-1", None)).expect("Gate::open");
    assert_eq!(output.kind, OutputKind::RestartState(State::Held));
    place.remove();
}

/// D1: a committed index entry corrupted later is ignored, so the generation looks unindexed and is indexed again,
/// but its journal file exists, so `create` refuses and it opens only.
#[test]
fn create_refuses_a_generation_whose_index_entry_was_corrupted() {
    let config = active();
    let generation = generation_of(&config);
    let place = Place::fresh("d1", "corrupted");
    let mut gate = Driven::create(&Family::I05, &config, place.stores(&generation, None));
    gate.step(&opening_status(), "d1");
    gate.step(&rows(&rows(&load(I05_VECTORS), "transcripts")[0], "events")[1], "d1");
    assert_eq!(gate.journal().len(), 1, "the BIND");
    drop(gate);
    let path = place.file(INDEX_NAME);
    let mut index = Place::bytes(&path);
    index[frame::HEADER_BYTES + 4] ^= 0x01;
    fs::write(&path, &index).expect("corrupted index");
    assert!(place.index().is_empty());
    let stores = place.stores(&generation, None);
    assert!(stores.indexed_now() && !stores.journal_created());
    assert_eq!(Gate::create(typed(&config), stores).err(), Some(GateError::NotFresh));
    let (gate, output) = Gate::open(typed(&config), place.stores(&generation, None)).expect("Gate::open");
    assert_eq!(output.kind, OutputKind::RestartState(State::Held), "a bound execution with no closing record");
    assert_eq!(show(field(&gate.snapshot().to_value(), "boundExecutionId")), format!("\"{}\"", "1".repeat(64)));
    drop(gate);
    place.remove();
}

#[test]
fn stores_must_belong_to_the_configured_generation() {
    let config = active();
    let place = Place::fresh("generation", "mismatch");
    assert_eq!(Gate::create(typed(&config), place.stores("gen-x", None)).err(), Some(GateError::GenerationMismatch));
    assert_eq!(Gate::open(typed(&config), place.stores("gen-x", None)).err(), Some(GateError::GenerationMismatch));
    let i07 = load(policy_support::I07_VECTORS);
    let kinds = load(policy_support::KINDS);
    let (writer_config, _) =
        effect_gate::fake_kernel::convert_v3_config(field(field(&i07, "configs"), "ACTIVE")).expect("v4's conversion");
    assert!(matches!(PolicyGate::create(&writer_config, &kinds, place.stores("gen-x", None)),
                     Err(PolicyGateError::Gate(GateError::GenerationMismatch))));
    place.remove();
}

// ------------------------------------------------------------------------------------------ cross-process bindings

const ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SIX: &str = "6666666666666666666666666666666666666666666666666666666666666666";

fn empty_prior() -> Value {
    let mut prior = Object::new();
    for key in ["executionIds", "runNonces", "manifestDigests", "manifestIdentities"] {
        prior.insert(JStr::new(key), Value::Array(Vec::new()));
    }
    Value::Object(prior)
}

/// LATER (a second generation) with its configured priorBindings replaced and the given generation.
fn later(generation: &str, prior: Value) -> Value {
    let config = field(field(&load(I05_VECTORS), "configs"), "LATER").clone();
    with(&with(&config, "priorBindings", prior), "generation", Value::str(generation))
}

/// T95's three BIND events (run-three, run-four, run-five), for `generation`.
fn t95_binds(generation: &str) -> Vec<Value> {
    let vectors = load(I05_VECTORS);
    let row = rows(&vectors, "transcripts").iter().find(|row| text(row, "id") == "T95").expect("T95");
    rows(row, "events")[1..4]
        .iter()
        .map(|event| {
            let payload = with(field(event, "payload"), "dispatchGeneration", Value::str(generation));
            with(event, "payload", payload)
        })
        .collect()
}

fn rebind(event: &Value, execution_id: &str, run_nonce: Option<&str>) -> Value {
    let mut payload = with(field(event, "payload"), "executionId", Value::str(execution_id));
    if let Some(nonce) = run_nonce {
        payload = with(&payload, "runNonce", Value::str(nonce));
    }
    with(event, "payload", payload)
}

fn refused(reason: &str) -> String {
    format!(r#"{{"response":{{"reason":"{reason}","result":"REFUSED"}}}}"#)
}

/// Generation 1 binds execution 1111 (run-one, manifests 1-3) and its stores are dropped.
fn first_generation(place: &Place, plan: Option<FaultHandle>, torn: bool) -> Vec<Entry> {
    let config = active();
    let vectors = load(I05_VECTORS);
    let t01 = rows(&rows(&vectors, "transcripts")[0], "events").to_vec();
    let mut gate = Driven::create(&Family::I05, &config, place.stores(&generation_of(&config), plan));
    gate.step(&t01[0], "g1");
    if torn {
        let mut injection = event("STORAGE_FAIL_NEXT");
        injection = with(&injection, "torn", Value::Bool(true));
        gate.step(&injection, "g1");
        assert_eq!(show(&gate.step(&t01[1], "g1")), refused("STORAGE_FAILURE"));
    } else {
        assert!(show(&gate.step(&t01[1], "g1")).contains(r#""result":"OK""#));
    }
    gate.journal().to_vec()
}

/// A second generation, opened by a new process with an empty configured priorBindings, refuses every replay of
/// generation 1's execution and run nonce and every reuse of its manifests by digest or identity, from generation 1's
/// journal alone; the controls show each refusal needs that journal.
#[test]
fn earlier_journals_carry_the_bindings_across_processes() {
    let place = Place::fresh("cross", "bindings");
    first_generation(&place, None, false);
    let second = "b".repeat(64);
    let config = later(&second, empty_prior());
    let binds = t95_binds(&second);
    let mut gate = Driven::create(&Family::I05, &config, place.stores(&second, None));
    gate.step(&opening_status(), "g2");
    // (case, BIND, answer after generation 1, answer without it)
    let cases = [
        ("execution id", rebind(&binds[0], ONE, None), refused("EXECUTION_REPLAY"), None),
        ("run nonce", rebind(&binds[0], SIX, Some("run-one")), refused("EXECUTION_REPLAY"), Some(refused("UNKNOWN_BINDING"))),
        ("manifest digest", binds[0].clone(), refused("MANIFEST_REUSED"), None),
        ("manifest identity", binds[1].clone(), refused("MANIFEST_REUSED"), None),
    ];
    for (case, bind, expected, _) in &cases {
        assert_eq!(&show(&gate.step(bind, case)), expected, "{case}");
    }
    assert!(show(&gate.step(&binds[2], "run-five")).contains(r#""result":"OK""#));
    drop(gate);
    place.remove();
    for (case, bind, _, without) in cases {
        let place = Place::fresh("cross", &format!("control-{}", case.replace(' ', "-")));
        let mut gate = Driven::create(&Family::I05, &config, place.stores(&second, None));
        gate.step(&opening_status(), "control");
        let answer = show(&gate.step(&bind, case));
        match without {
            Some(expected) => assert_eq!(answer, expected, "control {case}"),
            None => assert!(answer.contains(r#""result":"OK""#), "control {case}: binds without generation 1: {answer}"),
        }
        drop(gate);
        place.remove();
    }
}

/// A BIND torn at write time was never granted and contributes nothing; a configured binding still refuses.
#[test]
fn a_torn_earlier_bind_contributes_nothing() {
    let place = Place::fresh("cross", "torn-bind");
    let journal = first_generation(&place, Some(FaultHandle::default()), true);
    assert_eq!(journal.first(), Some(&Entry::Torn));
    let second = "b".repeat(64);
    let mut configured = empty_prior();
    configured = with(&configured, "executionIds", Value::Array(vec![Value::str(ONE)]));
    let mut gate = Driven::create(&Family::I05, &later(&second, configured), place.stores(&second, None));
    gate.step(&opening_status(), "g2");
    assert_eq!(show(&gate.step(&rebind(&t95_binds(&second)[0], ONE, None), "g2")), refused("EXECUTION_REPLAY"));
    drop(gate);
    let third = "c".repeat(64);
    let mut gate = Driven::create(&Family::I05, &later(&third, empty_prior()), place.stores(&third, None));
    gate.step(&opening_status(), "g3");
    assert!(show(&gate.step(&rebind(&t95_binds(&third)[0], ONE, None), "g3")).contains(r#""result":"OK""#));
    drop(gate);
    assert_eq!(place.index(), ["a".repeat(64), second, third]);
    place.remove();
}
