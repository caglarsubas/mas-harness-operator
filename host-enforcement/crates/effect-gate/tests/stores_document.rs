//! HE-003D DESIGN sections 3.3 and 8 (owner decision Q-HE3D-13 (b)): the generation binding of the file stores.
//! `FileStores::open_bound` writes `<generation>.document` as exactly one committed frame
//! `["DOCUMENT", generation, digest]` before the generation's index entry, compares it on every later opening, reuses an
//! equal file an earlier failed opening left, and refuses a missing (indexed generation), torn, empty or different one
//! with `OpenError::Document`; the `StoreFile::Document` fault points fail each write and sync. Store directories under
//! cargo's `CARGO_TARGET_TMPDIR`; the test device probe reports two devices (E15).

use std::io;

use effect_gate::file_store::{document_name, index_generations, journal_name};
use effect_gate::frame;
use effect_gate::{FaultHandle, FilePoint, FileStores, OpenError, StoreDir, StoreFile};
use gate_sys::Dir;
use i05_protocol::json::Doc;

const G: &str = "gen-1";

fn digest(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn devices(which: StoreDir, _: &Dir) -> io::Result<u64> {
    Ok(match which {
        StoreDir::Journal => 1,
        StoreDir::Marker => 2,
    })
}

struct Place {
    root: String,
    journal: String,
    marker: String,
}

impl Place {
    fn fresh(case: &str) -> Place {
        let root = format!("{}/he003d/stores-document/{case}", env!("CARGO_TARGET_TMPDIR"));
        let _ = std::fs::remove_dir_all(&root);
        let place = Place { journal: format!("{root}/journal"), marker: format!("{root}/marker"), root };
        std::fs::create_dir_all(&place.journal).expect("journal directory");
        std::fs::create_dir_all(&place.marker).expect("marker directory");
        place
    }

    fn open(&self, generation: &str, document: &str, plan: Option<FaultHandle>) -> Result<FileStores, OpenError> {
        FileStores::open_bound(&self.journal, &self.marker, generation, document, &devices, plan)
    }

    fn path(&self, name: &str) -> String {
        format!("{}/{name}", self.journal)
    }

    fn document(&self, generation: &str) -> Vec<u8> {
        std::fs::read(self.path(&document_name(generation))).unwrap_or_default()
    }

    fn index(&self) -> Vec<String> {
        index_generations(&self.journal).expect("the index reads")
    }

    fn remove(self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The one committed frame a bound generation's document file holds.
fn expected_frame(generation: &str, digest: &str) -> Vec<u8> {
    let payload = Doc::Array(vec![Doc::str("DOCUMENT"), Doc::str(generation), Doc::str(digest)]).canonical();
    let mut bytes = frame::encode(&payload, frame::PENDING).expect("a frame");
    let status = bytes.len() - 2;
    bytes[status] = frame::COMMITTED;
    bytes
}

fn document_refused(result: Result<FileStores, OpenError>) -> bool {
    matches!(result, Err(OpenError::Document))
}

#[test]
fn a_new_generation_writes_its_document_before_its_index_entry() {
    let place = Place::fresh("new");
    let stores = place.open(G, &digest('a'), None).expect("a new generation opens");
    assert!(stores.journal_created() && stores.indexed_now());
    // R26's counts are unchanged: the document file is created before the journal, under the same directory sync.
    assert_eq!(stores.directory_syncs(), (2, 0));
    drop(stores);
    assert_eq!(place.document(G), expected_frame(G, &digest('a')));
    assert_eq!(place.index(), vec![G.to_string()]);
    // The index entry is appended last: when it fails, the document is already there, and the next opening reuses it.
    let plan = FaultHandle::default();
    plan.with(|plan| plan.arm(StoreFile::Index, FilePoint::FirstWrite));
    assert!(matches!(place.open("gen-2", &digest('b'), Some(plan)), Err(OpenError::IndexAppend)));
    assert_eq!(place.document("gen-2"), expected_frame("gen-2", &digest('b')));
    assert_eq!(place.index(), vec![G.to_string()]);
    let stores = place.open("gen-2", &digest('b'), None).expect("an equal leftover document is reused");
    assert!(stores.indexed_now() && !stores.journal_created());
    drop(stores);
    assert_eq!(place.index(), vec![G.to_string(), "gen-2".to_string()]);
    place.remove();
}

#[test]
fn a_reopening_compares_the_document() {
    let place = Place::fresh("reopen");
    drop(place.open(G, &digest('a'), None).expect("opens"));
    let stores = place.open(G, &digest('a'), None).expect("the same document reopens its generation");
    assert!(!stores.journal_created() && !stores.indexed_now());
    assert_eq!(stores.directory_syncs(), (1, 0));
    drop(stores);
    assert!(document_refused(place.open(G, &digest('b'), None)), "another document for the same generation");
    assert_eq!(place.document(G), expected_frame(G, &digest('a')), "a refused opening changes nothing");
    // HE-002C's unbound opening is unchanged and does not read the file.
    drop(FileStores::open(&place.journal, &place.marker, G, &devices, None).expect("the unbound opening"));
    place.remove();
}

#[test]
fn a_missing_torn_empty_or_extended_document_is_refused() {
    let place = Place::fresh("damaged");
    drop(place.open(G, &digest('a'), None).expect("opens"));
    let good = place.document(G);
    let path = place.path(&document_name(G));
    // Missing, for an indexed generation.
    std::fs::remove_file(&path).expect("remove");
    assert!(document_refused(place.open(G, &digest('a'), None)));
    // Empty, truncated, uncommitted, revoked, with a second frame, or with a frame of another generation.
    let pending = {
        let mut bytes = good.clone();
        let status = bytes.len() - 2;
        bytes[status] = frame::PENDING;
        bytes
    };
    let revoked = {
        let mut bytes = good.clone();
        let status = bytes.len() - 2;
        bytes[status] = frame::REVOKED;
        bytes
    };
    let mut twice = good.clone();
    twice.extend_from_slice(&good);
    for bytes in [Vec::new(), good[..good.len() / 2].to_vec(), pending, revoked, twice, expected_frame("gen-9", &digest('a')),
                  [good.clone(), b"x".to_vec()].concat()] {
        std::fs::write(&path, &bytes).expect("write");
        assert!(document_refused(place.open(G, &digest('a'), None)), "{} bytes", bytes.len());
    }
    std::fs::write(&path, &good).expect("restore");
    drop(place.open(G, &digest('a'), None).expect("the restored document passes"));
    place.remove();
}

#[test]
fn a_leftover_that_is_not_equal_is_refused_for_a_new_generation_too() {
    let place = Place::fresh("leftover");
    let path = place.path(&document_name(G));
    for bytes in [Vec::new(), expected_frame(G, &digest('b')), b"junk".to_vec()] {
        std::fs::write(&path, &bytes).expect("write");
        assert!(document_refused(place.open(G, &digest('a'), None)), "{} bytes", bytes.len());
        assert!(place.index().is_empty(), "nothing is indexed");
        assert!(std::fs::metadata(place.path(&journal_name(G))).is_err(), "no journal is created");
    }
    place.remove();
}

#[test]
fn the_document_fault_points_fail_the_opening_before_anything_else() {
    for point in [FilePoint::PartialFrame, FilePoint::FirstWrite, FilePoint::FirstSync, FilePoint::FirstReadBack,
                  FilePoint::CommitWrite, FilePoint::CommitSync, FilePoint::CommitReadBack] {
        let place = Place::fresh(&format!("fault-{point:?}"));
        let plan = FaultHandle::default();
        plan.with(|plan| plan.arm(StoreFile::Document, point));
        assert!(document_refused(place.open(G, &digest('a'), Some(plan))), "{point:?}");
        assert!(place.index().is_empty(), "{point:?}: no index entry");
        assert!(std::fs::metadata(place.path(&journal_name(G))).is_err(), "{point:?}: no journal");
        // A torn or empty document cannot be repaired after the seal: the generation stays refused (a new one is used).
        assert!(document_refused(place.open(G, &digest('a'), None)), "{point:?}: refused again");
        drop(place.open("gen-2", &digest('a'), None).expect("a new generation opens"));
        place.remove();
    }
}

#[test]
fn the_document_file_names_do_not_collide() {
    assert_eq!(document_name(G), "gen-1.document");
    assert_ne!(document_name("a.journal"), journal_name("a"));
    assert_ne!(document_name("a"), journal_name("a.document"));
    assert!(!document_name("x").contains('/'));
}
