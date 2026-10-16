//! HE-003A2 DESIGN section 5 and section 9 (owner decision Q-A2-5 (a)): configuration format v2's `enrolledWriter`
//! member, on a valid v2 document (built here from the I07 v3 vectors' ACTIVE configuration, as HE-003D's tests build
//! theirs) and on one mutation per refusal: the member missing or extra, its object not closed, the executable relative,
//! with a `.` or `..` component, ending in `" (deleted)"`, longer than 255 bytes, holding a non-ASCII character, a NUL
//! or another control character (0x01-0x1f, 0x7f; in either spelling: PR review round 1, R1-5); and a v1 document
//! refused.

use effect_gate::gate_config::{is_normal_path, DELETED_SUFFIX, FORMAT, MAX_PATH_BYTES};
use effect_gate::{GateConfig, GateConfigError};
use i05_protocol::json::{self, JStr, Object, Value};

const I07_VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");
const ENROLLED: &str = "/opt/planeon/bin/harness-policy-write";

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(JStr::new(key), value);
    }
    Value::Object(object)
}

fn file(path: &str, fill: char) -> Value {
    object(vec![("path", Value::str(path)), ("sha256", Value::str(&format!("sha256:{}", fill.to_string().repeat(64))))])
}

fn identity(base: &str, leaf: char, key: char) -> Value {
    object(vec![("chain", Value::Array(vec![file(&format!("{base}.crt"), leaf), file(&format!("{base}-ca.crt"), 'c')])),
                ("key", file(&format!("{base}.key"), key))])
}

fn active_gate() -> Value {
    let vectors = json::parse(I07_VECTORS).expect("the I07 vectors parse");
    let mut gate = vectors.get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().expect("ACTIVE");
    let Value::Object(members) = &mut gate else { panic!("ACTIVE is an object") };
    members.insert(JStr::new("observedWorkers"), Value::Array(Vec::new()));
    gate
}

/// A valid v2 document with `executable` as the enrolled writer's path.
fn document_with(executable: Value) -> Value {
    object(vec![
        ("format", Value::str(FORMAT)),
        ("gate", active_gate()),
        ("lifetimes", object(vec![("run-one", Value::int(1_900_000_000)), ("run-two", Value::int(1_900_000_100))])),
        ("stores", object(vec![("journalDirectory", Value::str("/var/lib/planeon/effect-gate/journal")),
                               ("markerDirectory", Value::str("/var/lib/planeon-marker/effect-gate"))])),
        ("credentials", object(vec![
            ("i04Server", identity("/etc/planeon/effect-gate/i04-server", 'a', '1')),
            ("i04ClientCa", file("/etc/planeon/effect-gate/i04-client-ca.crt", 'd')),
            ("apiserverServingCa", file("/etc/planeon/effect-gate/apiserver-ca.crt", 'e')),
            ("effectIdentity", identity("/etc/planeon/effect-gate/effect", '6', '2')),
            ("writerIdentity", identity("/etc/planeon/effect-gate/writer", '8', '3')),
        ])),
        ("enrolledWriter", object(vec![("executable", executable)])),
    ])
}

fn document() -> Value {
    document_with(Value::str(ENROLLED))
}

fn parse(value: &Value) -> Result<GateConfig, GateConfigError> {
    GateConfig::parse(&json::canonical(value).expect("a canonical encoding"))
}

fn members(value: &mut Value) -> &mut Object {
    let Value::Object(members) = value else { panic!("an object") };
    members
}

fn refused_check(executable: &str, what: &str) {
    match parse(&document_with(Value::str(executable))) {
        Err(GateConfigError::Check(message)) => {
            assert!(message.contains("enrolledWriter.executable"), "{message:?}");
            assert!(message.contains(what), "{message:?} names {what:?}");
        }
        other => panic!("{executable:?}: expected a check refusal, got {other:?}"),
    }
}

#[test]
fn the_format_is_v2_and_the_enrolled_path_is_typed() {
    assert_eq!(FORMAT, "planeon.effect-gate-config/v2");
    assert_eq!(DELETED_SUFFIX, " (deleted)");
    let config = parse(&document()).expect("the valid v2 document passes");
    assert_eq!(config.writer_executable, ENROLLED.as_bytes());
    // JCS order: credentials < enrolledWriter < format, so the document still starts with the credentials.
    let text = String::from_utf8(json::canonical(&document()).expect("canonical")).expect("ASCII");
    assert!(text.starts_with("{\"credentials\":"));
    assert!(text.contains(&format!("}},\"enrolledWriter\":{{\"executable\":\"{ENROLLED}\"}},\"format\":\"{FORMAT}\"")));
}

#[test]
fn the_member_is_required_and_closed() {
    let mut missing = document();
    members(&mut missing).remove(&JStr::new("enrolledWriter")).expect("the member exists");
    assert!(matches!(parse(&missing), Err(GateConfigError::Schema(_))), "the member missing");
    let mut extra = document();
    members(&mut extra).insert(JStr::new("enrolledWriterTwo"), object(vec![("executable", Value::str(ENROLLED))]));
    assert!(matches!(parse(&extra), Err(GateConfigError::Schema(_))), "another top-level member");
    let cases = [
        ("an extra member", object(vec![("executable", Value::str(ENROLLED)), ("digest", Value::str("sha256:"))])),
        ("no executable", object(vec![("path", Value::str(ENROLLED))])),
        ("empty", object(Vec::new())),
        ("not an object", Value::str(ENROLLED)),
        ("a list", Value::Array(vec![Value::str(ENROLLED)])),
    ];
    for (case, value) in cases {
        let mut changed = document();
        members(&mut changed).insert(JStr::new("enrolledWriter"), value);
        assert!(matches!(parse(&changed), Err(GateConfigError::Schema(_))), "{case}");
    }
    // The executable must be text.
    assert!(matches!(parse(&document_with(Value::int(1))), Err(GateConfigError::Schema(_))));
    assert!(matches!(parse(&document_with(Value::Null)), Err(GateConfigError::Schema(_))));
}

#[test]
fn the_executable_is_an_absolute_normalised_path_of_at_most_255_bytes() {
    for path in ["opt/planeon/bin/harness-policy-write", "harness-policy-write", "", "/", "/opt/planeon/bin/",
                 "/opt/planeon/../bin/harness-policy-write", "/opt/./planeon/bin/harness-policy-write",
                 "/opt//planeon/bin/harness-policy-write", "/opt/planeon/bin/harness-policy-write\u{0}"] {
        refused_check(path, "absolute normalised ASCII path");
    }
    let longest = format!("/{}", "w".repeat(MAX_PATH_BYTES - 1));
    assert!(is_normal_path(&longest));
    assert_eq!(parse(&document_with(Value::str(&longest))).expect("255 bytes pass").writer_executable.len(), 255);
    refused_check(&format!("/{}", "w".repeat(MAX_PATH_BYTES)), "absolute normalised ASCII path");
}

#[test]
fn a_deleted_suffix_and_non_ascii_are_refused() {
    refused_check(&format!("{ENROLLED}{DELETED_SUFFIX}"), "(deleted)");
    refused_check("/opt/planeon/bin/x (deleted)", "(deleted)");
    // The suffix only: the words elsewhere in a path are a path like any other.
    let inside = parse(&document_with(Value::str("/opt/planeon (deleted)/bin/harness-policy-write"))).expect("passes");
    assert_eq!(inside.writer_executable, b"/opt/planeon (deleted)/bin/harness-policy-write");
    // A non-ASCII character is refused by the canonical subset (the canonical form writes it raw, which is not ASCII,
    // and an escaped one is not the canonical form); the decoded ASCII test is defence in depth (R1-5).
    let result = parse(&document_with(Value::str("/opt/planeon/bin/harness-policy-wr\u{ee}te")));
    assert!(matches!(result, Err(GateConfigError::Canonical(_))), "{result:?}");
    let raw = String::from_utf8(json::canonical(&document()).expect("canonical")).expect("ASCII")
        .replacen("harness-policy-write", "harness-policy-wr\\u00eete", 1);
    let result = GateConfig::parse(raw.as_bytes());
    assert!(matches!(result, Err(GateConfigError::Canonical(_))), "an escaped non-ASCII character: {result:?}");
}

#[test]
fn control_characters_are_refused_escaped_or_raw() {
    for control in ['\u{1}', '\t', '\n', '\r', '\u{1b}', '\u{1f}', '\u{7f}'] {
        let path = format!("/opt/planeon/bin/harness{control}policy-write");
        // As the canonical form writes it (0x01-0x1f escaped, 0x7f raw): the document is canonical and the path check
        // refuses it.
        refused_check(&path, "control character");
        // The other spelling (0x01-0x1f raw, 0x7f escaped) is not the canonical form (or not JSON): the canonical subset
        // refuses it.
        let written = json::canonical(&Value::str(&control.to_string())).expect("canonical");
        let written = String::from_utf8(written).expect("ASCII");
        let written = &written[1..written.len() - 1];
        let raw = control.to_string();
        let other = if written == raw { format!("\\u{:04x}", u32::from(control)) } else { raw };
        let text = json::canonical(&document_with(Value::str(&path))).expect("canonical");
        let text = String::from_utf8(text).expect("ASCII").replacen(written, &other, 1);
        let result = GateConfig::parse(text.as_bytes());
        assert!(matches!(result, Err(GateConfigError::Canonical(_))), "{control:?} as {other:?}: {result:?}");
    }
    // NUL is refused by the path rule itself.
    refused_check("/opt/planeon/bin/harness\u{0}policy-write", "absolute normalised ASCII path");
    // Printable ASCII, the space and the tilde included, passes.
    let printable = parse(&document_with(Value::str("/opt/planeon/bin/harness policy~write"))).expect("printable");
    assert_eq!(printable.writer_executable, b"/opt/planeon/bin/harness policy~write");
}

#[test]
fn a_v1_document_is_refused() {
    let mut v1 = document();
    members(&mut v1).insert(JStr::new("format"), Value::str("planeon.effect-gate-config/v1"));
    assert!(matches!(parse(&v1), Err(GateConfigError::Schema(_))), "the v1 format string");
    // A complete v1 document (no enrolledWriter, the v1 format) is refused too.
    members(&mut v1).remove(&JStr::new("enrolledWriter")).expect("the member exists");
    assert!(matches!(parse(&v1), Err(GateConfigError::Schema(_))), "a v1 document");
    let mut v3 = document();
    members(&mut v3).insert(JStr::new("format"), Value::str("planeon.effect-gate-config/v3"));
    assert!(matches!(parse(&v3), Err(GateConfigError::Schema(_))), "another version");
}
