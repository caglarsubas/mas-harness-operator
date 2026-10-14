//! The file-backed stores of one generation (HE-002C DESIGN §5-§8): its journal file `<generation>.journal` with the
//! in-process mirror, its failure marker `<generation>.marker` in a directory on another device, and the generation
//! index `generations` beside the journals. Files are opened only through `gate_sys::Dir` (`openat`); everything else
//! is std on the returned `File`: `pwrite64`, `pread64`, `fstat`, `fsync`, `flock` and `close`.
//!
//! An append is two-phase (owner decision Q-HE2C-1 (a)): the frame is written with status `P`, synced and read back;
//! then the status byte becomes `C`, synced and read back. A failure that left no bytes is clean; any other is torn,
//! and a frame whose `C` byte was written is revoked to `R` (R29). The mirror changes exactly as HE-002's in-memory
//! journal does, so `journalDigest` and every in-process rebuild are the model's; the file is scanned only when the
//! stores open (and by tests). Every I/O error and every scan outcome is a value (R27).

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use gate_sys::Dir;
use gate_sys::FileMode;
use i05_protocol::json::Doc;

use crate::config::PriorBindings;
use crate::frame::{self, Scanned, Scanner};
use crate::journal::{Entry, Record};
use crate::store::{Appended, FaultHandle, FilePoint, StoreFile, Stores};

/// R20: the largest store file.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The scan's read size.
const CHUNK_BYTES: usize = 64 * 1024;

/// The generation index's file name in the journal directory.
pub const INDEX_NAME: &str = "generations";

/// The one marker reason the gate writes.
const STORAGE_FAILURE: &str = "STORAGE_FAILURE";

/// R22's snapshot reason for marker bytes that are not one committed marker of this generation.
const UNREADABLE: &str = "UNREADABLE";

/// Which store directory a device probe is asked about.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StoreDir {
    Journal,
    Marker,
}

/// The production device probe (R24): `fstat`'s `st_dev` of the directory. Tests pass their own (E15).
pub fn fstat_device(_which: StoreDir, dir: &Dir) -> io::Result<u64> {
    dir.device()
}

/// R19: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, and not the index's name.
pub fn valid_generation(generation: &str) -> bool {
    let bytes = generation.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.len() <= 128
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && generation != INDEX_NAME
}

/// A generation's journal file name.
pub fn journal_name(generation: &str) -> String {
    format!("{generation}.journal")
}

/// A generation's marker file name.
pub fn marker_name(generation: &str) -> String {
    format!("{generation}.marker")
}

/// Why `FileStores::open` refused.
#[derive(Debug)]
pub enum OpenError {
    /// R19: the generation is not a valid store name.
    Name,
    /// R24: the journal and marker directories report the same device.
    SameDevice,
    /// R28: the generation is a committed index entry but not the last one.
    NotNewest,
    /// R23: a committed earlier generation has no journal file.
    MissingEarlierJournal(String),
    /// R30: an earlier generation's journal is locked by a live holder.
    EarlierGenerationLive(String),
    /// R25: this generation's journal is locked by another holder.
    JournalLocked,
    /// §7 step 7: the index append failed, so the open fails.
    IndexAppend,
    /// An I/O error, or an index or earlier journal that could not be read whole.
    Io(io::Error),
}

/// What the marker file holds.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MarkerState {
    /// No file, or an empty one.
    Absent,
    /// One committed marker of this generation, with its reason.
    Committed(String),
    /// Any other bytes (R22): present, fail closed.
    Unreadable,
}

/// The journal and marker files of one generation, opened by [`FileStores::open`].
pub struct FileStores {
    generation: String,
    marker_dir: Dir,
    journal: File,
    mirror: Vec<Entry>,
    marker: Option<File>,
    marker_synced: bool,
    marker_state: MarkerState,
    prior: PriorBindings,
    plan: Option<FaultHandle>,
    journal_created: bool,
    indexed_now: bool,
    journal_dir_syncs: u32,
    marker_dir_syncs: u32,
}

/// The type name and the generation only (HE-003A DESIGN §8): std's `Debug` of a `File` reads the descriptor's link in
/// the proc filesystem, a call the EFFECT_GATE program kills, so no `File` (and no `Dir`) is formatted.
impl fmt::Debug for FileStores {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FileStores").field("generation", &self.generation).finish_non_exhaustive()
    }
}

/// A whole-file scan: what it found, and whether every byte up to the file's length was read.
struct Scan {
    found: Vec<Scanned>,
    complete: bool,
}

/// Scans a store file in fixed chunks (R20: at most 64 MiB; the rest, or the rest after a read error, is one TORN).
fn scan_file(file: &File) -> Scan {
    let mut scanner = Scanner::default();
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return Scan { found: scanner.abort(), complete: false };
    };
    let limit = length.min(MAX_FILE_BYTES);
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let mut offset = 0u64;
    while offset < limit {
        let wanted = usize::try_from(limit.saturating_sub(offset)).map_or(CHUNK_BYTES, |left| left.min(CHUNK_BYTES));
        let Some(chunk) = buffer.get_mut(..wanted) else {
            return Scan { found: scanner.abort(), complete: false };
        };
        if file.read_exact_at(chunk, offset).is_err() {
            return Scan { found: scanner.abort(), complete: false };
        }
        scanner.feed(chunk);
        offset = offset.saturating_add(u64::try_from(wanted).unwrap_or(u64::MAX));
    }
    if length > limit {
        return Scan { found: scanner.abort(), complete: false };
    }
    Scan { found: scanner.finish(), complete: true }
}

fn injected() -> io::Error {
    io::Error::other("injected store failure")
}

/// Reads `expected.len()` bytes at `at` and compares them with `expected` (the kernel's view, not the medium's).
fn read_back(file: &File, expected: &[u8], at: u64) -> io::Result<()> {
    let mut read = vec![0u8; expected.len()];
    file.read_exact_at(&mut read, at)?;
    if read == expected { Ok(()) } else { Err(io::Error::other("the bytes read back differ from the bytes written")) }
}

/// The two phases; `commit_written` records that the `C` byte's write returned success.
fn two_phases(file: &File, frame: &[u8], end: u64, status_at: u64, points: &BTreeSet<FilePoint>,
              commit_written: &mut bool) -> io::Result<()> {
    let fail_at = |point: FilePoint| if points.contains(&point) { Err(injected()) } else { Ok(()) };
    fail_at(FilePoint::FirstWrite)?;
    if points.contains(&FilePoint::PartialFrame) {
        file.write_all_at(frame.get(..frame.len() / 2).unwrap_or_default(), end)?;
        return Err(injected());
    }
    file.write_all_at(frame, end)?;
    fail_at(FilePoint::FirstSync)?;
    file.sync_all()?;
    fail_at(FilePoint::FirstReadBack)?;
    read_back(file, frame, end)?;
    fail_at(FilePoint::CommitWrite)?;
    file.write_all_at(&[frame::COMMITTED], status_at)?;
    *commit_written = true;
    fail_at(FilePoint::CommitSync)?;
    file.sync_all()?;
    fail_at(FilePoint::CommitReadBack)?;
    read_back(file, &[frame::COMMITTED], status_at)
}

/// R29: rewrites a frame's status to `R`; `false` when the revocation itself failed (Q-HE2C-1's window).
fn revoke(file: &File, status_at: u64, points: &BTreeSet<FilePoint>) -> bool {
    !points.contains(&FilePoint::Revoke)
        && file.write_all_at(&[frame::REVOKED], status_at).is_ok()
        && file.sync_all().is_ok()
        && read_back(file, &[frame::REVOKED], status_at).is_ok()
}

/// One two-phase append of `payload` at the file's end (§5). A payload above 1 MiB or a file that would pass 64 MiB
/// fails clean (R20).
pub(crate) fn append_frame(file: &File, payload: &[u8], points: &BTreeSet<FilePoint>) -> Appended {
    let clean = Appended::Failed { torn: false };
    let Some(frame) = frame::encode(payload, frame::PENDING) else { return clean };
    let Ok(end) = file.metadata().map(|metadata| metadata.len()) else { return clean };
    let Ok(length) = u64::try_from(frame.len()) else { return clean };
    let Some(after) = end.checked_add(length).filter(|after| *after <= MAX_FILE_BYTES) else { return clean };
    let Some(status_at) = after.checked_sub(2) else { return clean };
    let mut commit_written = false;
    if two_phases(file, &frame, end, status_at, points, &mut commit_written).is_ok() {
        return Appended::Durable;
    }
    // Unchanged length: nothing reached the file. Grown, or the length unreadable: torn (fail closed).
    if file.metadata().is_ok_and(|metadata| metadata.len() == end) {
        return clean;
    }
    if commit_written {
        let _revoked = revoke(file, status_at, points);
    }
    Appended::Failed { torn: true }
}

/// Opens a name that must exist afterwards.
fn opened(dir: &Dir, name: &str, mode: FileMode) -> Result<(File, bool), OpenError> {
    match dir.file(name, mode) {
        Ok(Some(found)) => Ok(found),
        Ok(None) => Err(OpenError::Io(io::Error::from(io::ErrorKind::NotFound))),
        Err(error) => Err(OpenError::Io(error)),
    }
}

/// The index's committed generations, in order (R23: every TORN or undecodable entry is ignored). An index that
/// cannot be read whole refuses the open.
fn committed_generations(index: &File) -> Result<Vec<String>, OpenError> {
    let scan = scan_file(index);
    if !scan.complete {
        return Err(OpenError::Io(io::Error::other("the generation index could not be read whole")));
    }
    Ok(scan
        .found
        .into_iter()
        .filter_map(|item| match item {
            Scanned::Frame(payload) => frame::decode_generation(&payload).filter(|generation| valid_generation(generation)),
            Scanned::Torn => None,
        })
        .collect())
}

/// Adds every committed BIND record's execution, run nonce, manifest digests and identities.
fn add_bindings(prior: &mut PriorBindings, entries: &[Entry]) {
    for entry in entries {
        if let Entry::Record(Record::Bind { execution_id, run_nonce, manifest_digests, manifest_identities, .. }) = entry {
            prior.execution_ids.insert(execution_id.clone());
            prior.run_nonces.insert(run_nonce.clone());
            prior.manifest_digests.extend(manifest_digests.iter().cloned());
            prior.manifest_identities.extend(manifest_identities.iter().cloned());
        }
    }
}

/// What a marker file found at opening holds (R22).
fn marker_state(file: &File, generation: &str) -> MarkerState {
    match file.metadata() {
        Ok(metadata) if metadata.len() == 0 => return MarkerState::Absent,
        Ok(_) => {}
        Err(_) => return MarkerState::Unreadable,
    }
    let scan = scan_file(file);
    match scan.found.as_slice() {
        [Scanned::Frame(payload)] if scan.complete => match frame::decode_marker(payload) {
            Some((written, reason)) if written == generation && reason == STORAGE_FAILURE => MarkerState::Committed(reason),
            _ => MarkerState::Unreadable,
        },
        _ => MarkerState::Unreadable,
    }
}

impl FileStores {
    /// Opens (or begins) a generation's stores (§7). Every check runs before anything is appended, and the index
    /// entry, when the generation has none, is appended last; a failed index append fails the open. The whole
    /// opening holds the index file's exclusive lock, so concurrent openings queue.
    ///
    /// 1. R19 (the name) and R24 (`probe` must report different devices for the two directories);
    /// 2. the index, created if new, its directory synced (R26: every opening, since an earlier opening that created
    ///    the file may have failed at that sync), then locked; its committed entries (R23);
    /// 3. R28: a committed generation must be the last committed one;
    /// 4. every earlier committed generation: its journal must exist (R23) and not be locked by a live holder (R30);
    ///    its committed BIND records are the earlier bindings (owner decision Q-HE2C-2 (a): the gate unites them with
    ///    the configuration's);
    /// 5. the marker file, if any;
    /// 6. the journal, created if new (`journal_created`), its directory synced when this opening created it or will
    ///    append the generation's index entry (R26: also a journal an earlier, failed opening created), locked for the
    ///    stores' life (R25), and scanned into the mirror;
    /// 7. the index entry, if the generation has none (`indexed_now`).
    pub fn open(journal_dir: &str, marker_dir: &str, generation: &str,
                probe: &dyn Fn(StoreDir, &Dir) -> io::Result<u64>, plan: Option<FaultHandle>)
                -> Result<FileStores, OpenError> {
        if !valid_generation(generation) {
            return Err(OpenError::Name);
        }
        let journals = Dir::at(journal_dir).map_err(OpenError::Io)?;
        let markers = Dir::at(marker_dir).map_err(OpenError::Io)?;
        let journal_device = probe(StoreDir::Journal, &journals).map_err(OpenError::Io)?;
        if journal_device == probe(StoreDir::Marker, &markers).map_err(OpenError::Io)? {
            return Err(OpenError::SameDevice);
        }
        let (index, _) = opened(&journals, INDEX_NAME, FileMode::CreateOrExisting)?;
        journals.sync().map_err(OpenError::Io)?;
        let mut journal_dir_syncs = 1u32;
        index.lock().map_err(OpenError::Io)?;
        let committed = committed_generations(&index)?;
        let indexed = committed.iter().any(|entry| entry == generation);
        if indexed && committed.last().map(String::as_str) != Some(generation) {
            return Err(OpenError::NotNewest);
        }
        let mut prior = PriorBindings::default();
        let mut visited = BTreeSet::new();
        for earlier in committed.iter().filter(|entry| entry.as_str() != generation) {
            if !visited.insert(earlier.as_str()) {
                continue;
            }
            let Some((file, _)) = journals.file(&journal_name(earlier), FileMode::Existing).map_err(OpenError::Io)? else {
                return Err(OpenError::MissingEarlierJournal(earlier.clone()));
            };
            if file.try_lock().is_err() {
                return Err(OpenError::EarlierGenerationLive(earlier.clone()));
            }
            let scan = scan_file(&file);
            if !scan.complete {
                return Err(OpenError::Io(io::Error::other("an earlier generation's journal could not be read whole")));
            }
            add_bindings(&mut prior, &frame::journal_entries(scan.found));
            // Closing the descriptor releases its lock.
            drop(file);
        }
        let marker = markers.file(&marker_name(generation), FileMode::Existing).map_err(OpenError::Io)?.map(|(file, _)| file);
        let marker_state = marker.as_ref().map_or(MarkerState::Absent, |file| marker_state(file, generation));
        let (journal, journal_created) = opened(&journals, &journal_name(generation), FileMode::CreateOrExisting)?;
        if journal_created || !indexed {
            journals.sync().map_err(OpenError::Io)?;
            journal_dir_syncs = journal_dir_syncs.saturating_add(1);
        }
        if journal.try_lock().is_err() {
            return Err(OpenError::JournalLocked);
        }
        let mirror = frame::journal_entries(scan_file(&journal).found);
        let mut indexed_now = false;
        if !indexed {
            let points = plan.as_ref().map(|plan| plan.with(|plan| plan.take(StoreFile::Index))).unwrap_or_default();
            if append_frame(&index, &frame::generation_payload(generation), &points) != Appended::Durable {
                return Err(OpenError::IndexAppend);
            }
            indexed_now = true;
        }
        drop(index);
        Ok(FileStores {
            generation: generation.to_string(),
            marker_dir: markers,
            journal,
            mirror,
            // R26: the first marker write syncs the marker directory even when the file was already there.
            marker_synced: false,
            marker,
            marker_state,
            prior,
            plan,
            journal_created,
            indexed_now,
            journal_dir_syncs,
            marker_dir_syncs: 0,
        })
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// This opening created the journal file.
    pub fn journal_created(&self) -> bool {
        self.journal_created
    }

    /// This opening appended the generation's index entry.
    pub fn indexed_now(&self) -> bool {
        self.indexed_now
    }

    /// A marker file existed when the stores opened.
    pub fn marker_file_exists(&self) -> bool {
        self.marker.is_some()
    }

    /// The directory syncs run so far (R26), of the journal directory (during the opening) and of the marker
    /// directory (at the first marker write).
    pub fn directory_syncs(&self) -> (u32, u32) {
        (self.journal_dir_syncs, self.marker_dir_syncs)
    }

    /// The points a plan has armed, or the contract injection due, for the next journal append.
    fn journal_points(&self) -> BTreeSet<FilePoint> {
        let Some(plan) = &self.plan else { return BTreeSet::new() };
        plan.with(|plan| match plan.record_failure() {
            Some(true) => BTreeSet::from([FilePoint::PartialFrame]),
            Some(false) => BTreeSet::from([FilePoint::FirstWrite]),
            None => plan.take(StoreFile::Journal),
        })
    }
}

impl Stores for FileStores {
    fn append(&mut self, record: Record) -> Appended {
        let points = self.journal_points();
        let appended = append_frame(&self.journal, &record.to_doc().canonical(), &points);
        match appended {
            Appended::Durable => self.mirror.push(Entry::Record(record)),
            Appended::Failed { torn: true } => self.mirror.push(Entry::Torn),
            Appended::Failed { torn: false } => {}
        }
        appended
    }

    fn entries(&self) -> &[Entry] {
        &self.mirror
    }

    fn marker_present(&self) -> bool {
        self.marker_state != MarkerState::Absent
    }

    /// §6: created at the first write, then the marker directory synced (R26; also when the file already existed),
    /// then one two-phase frame. A failed write that left bytes makes the marker present in its fail-closed form (R22).
    fn write_marker(&mut self, generation: &str, reason: &'static str) -> bool {
        if self.marker_present() {
            return true;
        }
        let (refused, points) = match &self.plan {
            Some(plan) => plan.with(|plan| (plan.marker_failure(), plan.take(StoreFile::Marker))),
            None => (false, BTreeSet::new()),
        };
        if refused || points.contains(&FilePoint::MarkerWrite) {
            return false;
        }
        if self.marker.is_none() {
            match self.marker_dir.file(&marker_name(&self.generation), FileMode::CreateOrExisting) {
                Ok(Some((file, _))) => self.marker = Some(file),
                Ok(None) | Err(_) => return false,
            }
        }
        if !self.marker_synced {
            if self.marker_dir.sync().is_err() {
                return false;
            }
            self.marker_synced = true;
            self.marker_dir_syncs = self.marker_dir_syncs.saturating_add(1);
        }
        let Some(file) = &self.marker else { return false };
        let appended = append_frame(file, &frame::marker_payload(generation, reason), &points);
        self.marker_state = match appended {
            Appended::Durable => MarkerState::Committed(reason.to_string()),
            Appended::Failed { .. } => match file.metadata() {
                Ok(metadata) if metadata.len() == 0 => MarkerState::Absent,
                _ => MarkerState::Unreadable,
            },
        };
        appended == Appended::Durable
    }

    fn marker_doc(&self) -> Doc {
        let one = |reason: &str| Doc::Array(vec![Doc::Array(vec![Doc::str(&self.generation), Doc::str(reason)])]);
        match &self.marker_state {
            MarkerState::Absent => Doc::Array(Vec::new()),
            MarkerState::Committed(reason) => one(reason),
            MarkerState::Unreadable => one(UNREADABLE),
        }
    }

    fn fail_next(&mut self, torn: bool) {
        if let Some(plan) = &self.plan {
            plan.with(|plan| plan.fail_next(torn));
        }
    }

    fn fail_after(&mut self, after: u64) {
        if let Some(plan) = &self.plan {
            plan.with(|plan| plan.fail_after(after));
        }
    }

    fn marker_fail_next(&mut self) {
        if let Some(plan) = &self.plan {
            plan.with(|plan| plan.marker_fail_next());
        }
    }

    fn prior_bindings(&self) -> &PriorBindings {
        &self.prior
    }
}

/// A fresh scan of a generation's journal through a second descriptor, without its lock (tests and inspection).
pub fn scan_journal(journal_dir: &str, generation: &str) -> io::Result<Vec<Entry>> {
    if !valid_generation(generation) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let Some((file, _)) = Dir::at(journal_dir)?.file(&journal_name(generation), FileMode::Existing)? else {
        return Err(io::Error::from(io::ErrorKind::NotFound));
    };
    Ok(frame::journal_entries(scan_file(&file).found))
}

/// The generation index's committed entries, read without its lock (tests and inspection).
pub fn index_generations(journal_dir: &str) -> io::Result<Vec<String>> {
    let Some((file, _)) = Dir::at(journal_dir)?.file(INDEX_NAME, FileMode::Existing)? else {
        return Ok(Vec::new());
    };
    committed_generations(&file).map_err(|error| match error {
        OpenError::Io(error) => error,
        _ => io::Error::other("the generation index could not be read"),
    })
}
