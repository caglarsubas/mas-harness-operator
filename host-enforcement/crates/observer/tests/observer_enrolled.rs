//! HE-004D1 DESIGN-D1 sections 5.2 and 7 (owner decision Q-HE4D1-2 (a); MODEL_DEFINED R121, R123): the record file's
//! read by path and pin (26): sizes 0, 262,144 and 262,145, the pin, the EOF probe; its form (27): non-canonical bytes,
//! the node cap, ASCII, floats, depth and integer bounds; `Enrolled::new`: not v4, each data-bound refusal and the
//! `record` variant (27), each R10 read-path precondition (28), the window (29; a `validFrom` in the future accepted; an
//! unusable clock 97), and the positives' canonical digest equal to their captures' `qualificationDigest`. Files are
//! written under cargo's `CARGO_TARGET_TMPDIR`.

use std::io::{self, Read};

use i05_protocol::json::{self, Value};
use i05_protocol::sha256;
use i05_protocol::json::JStr;
use planeon_observer::capture_check::bounded;
use planeon_observer::capture_schema::{CaptureSchema, RecordSchema};
use planeon_observer::config::FileRef;
use planeon_observer::enrolled::{load_record, read_pinned, record_form, Enrolled, RecordBytes, SetupError, RECORD_LIMIT,
                                 RECORD_NODE_CAP};
use planeon_observer::kernel_text;
use planeon_observer::status;

const VECTORS: &str = include_str!("../../../contracts/native-profile-v4/vectors.json");

fn positive_record(index: usize) -> Value {
    let vectors = json::parse(VECTORS).expect("the vendored vectors parse");
    let positives = vectors.get("positive").and_then(Value::as_array).expect("positives");
    positives[index].get("record").expect("a record").clone()
}

fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

/// Writes `bytes` as `record.json` in a fresh directory for `case`; its reference with `pin` (default: the bytes').
fn place(case: &str, bytes: &[u8], pin: Option<&str>) -> FileRef {
    let dir = format!("{}/he004d1/enrolled/{case}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let path = format!("{dir}/record.json");
    std::fs::write(&path, bytes).expect("record");
    FileRef { path, sha256: pin.map_or_else(|| sha256::prefixed(bytes), str::to_string) }
}

fn read_refusal(result: Result<impl Sized, SetupError>) -> bool {
    matches!(result.err(), Some(SetupError::RecordRead(_)))
}

fn form_refusal(result: Result<impl Sized, SetupError>) -> bool {
    matches!(result.err(), Some(SetupError::RecordForm(_)))
}

#[test]
fn the_positive_record_reads_by_path_and_pin() {
    let record = positive_record(0);
    let bytes = canonical(&record);
    let reference = place("positive", &bytes, None);
    let loaded = load_record(&reference).expect("the positive record");
    assert_eq!(loaded.bytes, bytes);
    assert!(json::json_eq(&loaded.value, &record));
    assert_eq!(loaded.pin, sha256::prefixed(&bytes));
}

#[test]
fn sizes_zero_and_past_the_limit_refuse_and_the_limit_passes() {
    assert_eq!(RECORD_LIMIT, 262_144);
    assert!(read_refusal(load_record(&place("empty", b"", None))));
    // A canonical JSON string of exactly 262,144 bytes reads; one byte more is refused before it is read.
    let exact = format!("\"{}\"", "a".repeat(RECORD_LIMIT - 2));
    assert!(load_record(&place("exact", exact.as_bytes(), None)).is_ok());
    let over = format!("\"{}\"", "a".repeat(RECORD_LIMIT - 1));
    assert!(read_refusal(load_record(&place("over", over.as_bytes(), None))));
}

#[test]
fn the_pin_and_a_missing_file_refuse_with_26() {
    let bytes = canonical(&positive_record(0));
    let other = format!("sha256:{}", "0".repeat(64));
    assert!(read_refusal(load_record(&place("pin", &bytes, Some(&other)))));
    let mut reference = place("missing", &bytes, None);
    reference.path.push_str(".absent");
    assert!(read_refusal(load_record(&reference)));
    reference.path = format!("{}/he004d1/enrolled/no-such-directory/record.json", env!("CARGO_TARGET_TMPDIR"));
    assert!(read_refusal(load_record(&reference)));
}

/// A reader that yields its bytes in pieces, an interrupted read first.
struct Pieces {
    bytes: Vec<u8>,
    at: usize,
    interrupted: bool,
}

impl Read for Pieces {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let count = buffer.len().min(self.bytes.len() - self.at).min(7);
        buffer[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

#[test]
fn the_eof_probe_refuses_a_record_that_grew_or_shrank() {
    let bytes = canonical(&positive_record(0));
    let pin = sha256::prefixed(&bytes);
    let reader = |held: &[u8]| Pieces { bytes: held.to_vec(), at: 0, interrupted: false };
    assert_eq!(read_pinned(&mut reader(&bytes), bytes.len(), &pin).expect("exact"), bytes);
    let mut grown = bytes.clone();
    grown.push(b' ');
    assert!(read_refusal(read_pinned(&mut reader(&grown), bytes.len(), &pin)));
    assert!(read_refusal(read_pinned(&mut reader(&bytes[..bytes.len() - 1]), bytes.len(), &pin)));
    assert!(read_refusal(read_pinned(&mut reader(&bytes), 0, &pin)));
    assert!(read_refusal(read_pinned(&mut reader(&bytes), RECORD_LIMIT + 1, &pin)));
}

#[test]
fn the_form_refusals_are_27() {
    let bytes = canonical(&positive_record(0));
    let text = String::from_utf8(bytes.clone()).expect("ASCII");
    assert!(record_form(&bytes).is_ok());
    for (case, other) in [
        ("whitespace", text.replacen(':', ": ", 1)),
        ("key order", text.replacen("{\"", "{\"zzz\":1,\"", 1)),
        ("escape", text.replacen("unit-tenant", "unit-t\\u0065nant", 1)),
        ("float", text.replacen(":0,", ":0.0,", 1)),
        ("not JSON", text[..text.len() - 1].to_string()),
        ("duplicate", text.replacen("{\"", "{\"host\":1,\"", 1)),
        ("deep", format!("{}{}", "[".repeat(17), "]".repeat(17))),
        ("big", "9007199254740992".to_string()),
        ("small", "-9007199254740992".to_string()),
    ] {
        assert!(form_refusal(record_form(other.as_bytes())), "{case}");
    }
    assert!(record_form(b"-9007199254740991").is_ok());
    assert!(record_form(format!("{}{}", "[".repeat(16), "]".repeat(16)).as_bytes()).is_ok());
    assert!(form_refusal(record_form("\"caf\u{e9}\"".as_bytes())));
}

#[test]
fn the_node_cap_counts_structural_tokens() {
    assert_eq!(RECORD_NODE_CAP, 32_768);
    let at_cap = format!("[{}]", vec!["0"; RECORD_NODE_CAP].join(","));
    assert!(record_form(at_cap.as_bytes()).is_ok());
    let over = format!("[{}]", vec!["0"; RECORD_NODE_CAP + 1].join(","));
    assert!(form_refusal(record_form(over.as_bytes())));
    let reference = place("node-cap", over.as_bytes(), None);
    assert!(form_refusal(load_record(&reference)));
}

// ------------------------------------------------------------------------------------------------ Enrolled::new

fn record_schema() -> RecordSchema {
    CaptureSchema::embedded().expect("the embedded schema").1
}

/// The record bytes of a value, as `load_record` would return them (canonical, pinned).
fn bytes_of(value: &Value) -> RecordBytes {
    let bytes = canonical(value);
    let value = record_form(&bytes).expect("a canonical record");
    RecordBytes { pin: sha256::prefixed(&bytes), bytes, value }
}

/// The wall second of the positives' `validFrom` (2026-09-08T00:00:00Z).
fn valid_from() -> u64 {
    kernel_text::utc_seconds("2026-09-08T00:00:00Z").expect("UTC")
}

fn enroll(value: &Value, now: Option<u64>) -> Result<Enrolled, SetupError> {
    Enrolled::new(bytes_of(value), &record_schema(), now)
}

/// The member at a path of object keys and array indices.
fn member<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    path.iter().fold(value, |node, key| match node {
        Value::Object(object) => object.get_key_mut(&JStr::new(key)).unwrap_or_else(|| panic!("no member {key}")),
        Value::Array(items) => &mut items[key.parse::<usize>().expect("an index")],
        _ => panic!("not a container at {key}"),
    })
}

fn set(value: &mut Value, path: &[&str], new: Value) {
    *member(value, path) = new;
}

fn kind(result: Result<Enrolled, SetupError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(SetupError::RecordForm(_)) => "27",
        Err(SetupError::RecordTargets(_)) => "28",
        Err(SetupError::RecordWindow(_)) => "29",
        Err(SetupError::Clock) => "97",
        Err(_) => "other",
    }
}

#[test]
fn every_positive_enrolls_and_its_digest_is_its_captures_binding() {
    let vectors = json::parse(VECTORS).expect("vectors");
    let positives = vectors.get("positive").and_then(Value::as_array).expect("positives");
    assert_eq!(positives.len(), 5);
    for positive in positives {
        let record = positive.get("record").expect("record");
        let enrolled = enroll(record, Some(valid_from())).expect("a positive enrolls");
        assert_eq!(enrolled.record.digest(), sha256::prefixed(&canonical(record)));
        let captures = positive.get("captures").and_then(Value::as_array).expect("captures").iter()
            .chain([positive.get("lifecycle").expect("lifecycle")])
            .chain(positive.get("backendCaptures").and_then(Value::as_array).expect("backend captures").iter());
        for capture in captures {
            assert_eq!(capture.get("qualificationDigest").and_then(Value::as_str), Some(enrolled.record.digest()));
        }
        assert_eq!(enrolled.roles.len(), 5);
        assert_eq!(enrolled.roles[0].cgroup_rel, "planeon.slice/planeon-proxy-server.service");
        assert_eq!(enrolled.roles[1].class, "DECLARED_T04");
        assert_eq!(enrolled.containment_rel, "planeon.slice/planeon-host-containment.service");
        assert_eq!(enrolled.backends.len(), 8);
        assert!(enrolled.backends.windows(2).all(|pair| pair[0].component < pair[1].component));
        assert_eq!(enrolled.seal_marker, "/run/planeon/containment/sealed");
        assert_eq!((enrolled.valid_from, enrolled.expires_at), (valid_from(), valid_from() + 600));
        let entry = enrolled.rows.values().next().expect("a row").entry.clone();
        assert!(entry.get("selinuxLabel").is_none() && entry.get("sha256").is_some());
    }
}

#[test]
fn the_form_refusals_of_enrolled_new_are_27() {
    let record = positive_record(0);
    let mut other = record.clone();
    set(&mut other, &["schemaVersion"], Value::str("planeon.internal.native-qualification/v3"));
    assert_eq!(kind(enroll(&other, Some(valid_from()))), "27");
    let mut other = record.clone();
    set(&mut other, &["qualificationProfile"], Value::str("SELINUX_FSVERITY_CGROUP_BPF_V3"));
    assert_eq!(kind(enroll(&other, Some(valid_from()))), "27");
    let mut other = record.clone();
    set(&mut other, &["scope", "tenantId"], Value::str("unit\u{1}tenant"));
    assert_eq!(kind(enroll(&other, Some(valid_from()))), "27", "a control character (the data bound)");
    let mut other = record.clone();
    if let Value::Object(object) = &mut other {
        object.remove(&JStr::new("t04Proofs"));
    }
    assert_eq!(kind(enroll(&other, Some(valid_from()))), "27", "the record variant");
}

#[test]
fn the_data_bound_is_the_models() {
    assert_eq!(bounded(&positive_record(0)), Ok(()));
    let deep = json::parse(&format!("{}1{}", "[".repeat(16), "]".repeat(16))).expect("deep");
    assert_eq!(bounded(&deep), Ok(()), "a value at depth 16");
    let deeper = json::parse(&format!("{}1{}", "[".repeat(17), "]".repeat(17))).expect("deeper");
    assert!(bounded(&deeper).is_err(), "a value at depth 17");
    assert!(bounded(&json::parse("1.5").expect("float")).is_err());
    assert!(bounded(&json::parse("9007199254740992").expect("big")).is_err());
    assert!(bounded(&json::parse("-9007199254740991").expect("small")).is_ok());
    assert!(bounded(&Value::str("tab\there")).is_err());
    assert!(bounded(&json::parse("{\"k\\u0001\":1}").expect("key")).is_err(), "a key outside printable ASCII");
    assert!(bounded(&Value::str(&"a".repeat(262_144))).is_ok());
    assert!(bounded(&Value::str(&"a".repeat(262_145))).is_err(), "the budget");
    let list = json::parse(&format!("[{}]", vec!["1"; 262_143].join(","))).expect("list");
    assert!(bounded(&list).is_ok(), "262,144 nodes spend the budget exactly");
}

#[test]
fn each_read_path_precondition_is_28() {
    let record = positive_record(0);
    let now = Some(valid_from());
    // A files row's path outside the read grammar (the schema's pattern allows a double slash).
    let mut other = record.clone();
    set(&mut other, &["files", "0", "path"], Value::str("/opt/planeon//bin/harness-live-proxy-serve"));
    assert_eq!(kind(enroll(&other, now)), "28");
    // A role's filePaths entry that names no files row.
    let mut other = record.clone();
    set(&mut other, &["roles", "BROKER", "filePaths", "0"], Value::str("/opt/planeon/bin/not-enrolled"));
    assert_eq!(kind(enroll(&other, now)), "28");
    // A pin outside the pin root.
    let mut other = record.clone();
    set(&mut other, &["roles", "SERVER", "bpfPrograms", "INET4_BIND", "pinPath"], Value::str("/run/planeon/inet4-bind"));
    assert_eq!(kind(enroll(&other, now)), "28");
    // A backend cgroup that leaves the cgroup2 root's grammar, and one outside it.
    for path in ["/run/kubelet.service", "/opt/planeon/x"] {
        let mut other = record.clone();
        set(&mut other, &["backendComponents", "KUBELET", "cgroupPath"], Value::str(path));
        assert_eq!(kind(enroll(&other, now)), "28", "{path}");
    }
    // A backend executable that names no backendFiles row.
    let mut other = record.clone();
    set(&mut other, &["backendComponents", "KUBELET", "executable"], Value::str("/usr/bin/not-enrolled"));
    assert_eq!(kind(enroll(&other, now)), "28");
    // The planeon inventory's total over 512 MiB: nine rows of 64 MiB.
    let mut other = record.clone();
    let extra = member(&mut other, &["files", "0"]).clone();
    if let Value::Array(rows) = member(&mut other, &["files"]) {
        rows.push(extra);
    }
    set(&mut other, &["files", "8", "path"], Value::str("/opt/planeon/lib/extra.so"));
    for index in 0..9 {
        set(&mut other, &["files", &index.to_string(), "size"], Value::int(64 << 20));
    }
    assert_eq!(kind(enroll(&other, now)), "28");
}

#[test]
fn the_backend_inventory_total_is_4_gib() {
    // PR review round 1, R1-4: the backendFiles rows' total, at most 4 GiB (each row at most the schema's 1 GiB). Three
    // rows of 1 GiB and a fourth that brings the eight rows to exactly 4 GiB pass; one byte more is 28.
    let record = positive_record(0);
    let now = Some(valid_from());
    let mut other = record.clone();
    let rest: i64 = (4..8).map(|index| match member(&mut other, &["backendFiles", &index.to_string(), "size"]) {
        Value::Int(size) => size.to_i128().expect("an integer") as i64,
        _ => panic!("a size"),
    }).sum();
    for index in 0..3 {
        set(&mut other, &["backendFiles", &index.to_string(), "size"], Value::int(1 << 30));
    }
    set(&mut other, &["backendFiles", "3", "size"], Value::int((1 << 30) - rest));
    assert_eq!(kind(enroll(&other, now)), "ok");
    set(&mut other, &["backendFiles", "3", "size"], Value::int((1 << 30) - rest + 1));
    assert_eq!(kind(enroll(&other, now)), "28");
    // Five rows of 1 GiB.
    let mut other = record.clone();
    for index in 0..5 {
        set(&mut other, &["backendFiles", &index.to_string(), "size"], Value::int(1 << 30));
    }
    assert_eq!(kind(enroll(&other, now)), "28");
}

#[test]
fn the_window_is_29_and_a_future_valid_from_is_accepted() {
    let record = positive_record(0);
    let start = valid_from();
    assert_eq!(kind(enroll(&record, Some(start - 3_600))), "ok", "validFrom in the future");
    assert_eq!(kind(enroll(&record, Some(start + 599))), "ok");
    assert_eq!(kind(enroll(&record, Some(start + 600))), "29", "expiresAt reached at start");
    assert_eq!(kind(enroll(&record, None)), "97");
    let mut other = record.clone();
    set(&mut other, &["scope", "expiresAt"], Value::str("2026-09-08T00:00:00Z"));
    assert_eq!(kind(enroll(&other, Some(start - 1))), "29", "validFrom not before expiresAt");
    let mut other = record.clone();
    set(&mut other, &["scope", "expiresAt"], Value::str("2026-09-31T00:10:00Z"));
    assert_eq!(kind(enroll(&other, Some(start))), "29", "not canonical UTC");
    assert_eq!(status::CLOCK, 97);
}
