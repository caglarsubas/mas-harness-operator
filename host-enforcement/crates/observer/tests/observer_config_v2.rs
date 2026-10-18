//! HE-004D1 DESIGN-D1 section 5.1 (owner decision Q-HE4D1-2 (a); D1-3): `planeon.observer-config/v2`, v1's eight members
//! plus `qualificationRecord`; its schema and checks (every refusal status 13); v1 refused by the v2 parse and v2 by
//! the v1 parse; the signature's domain unchanged; and the record's location, the configuration's own directory only.

use i05_protocol::json::Doc;
use planeon_observer::config::{is_record_path, ConfigError, ObserverConfig, FORMAT, FORMAT_V2};
use planeon_observer::signed_config::{self, PRODUCTION_DIR};
use planeon_observer::status;

const PIN: &str = "sha256:0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb";
const RECORD_PIN: &str = "sha256:7d39e7686a01f3e0a34fa473e940965f5aee88f6e9dabc418e99955a5e3a7723";
const RECORD: &str = "/etc/planeon/policy-observer/qualification-record.json";

fn entry(path: &str, pin: &str) -> Doc {
    Doc::object(vec![("path", Doc::str(path)), ("sha256", Doc::str(pin))])
}

/// A v2 document with the record member `record` (`None`: omitted), the format `format` and an optional extra member.
fn document(format: &str, record: Option<Doc>, extra: Option<(&'static str, Doc)>) -> Vec<u8> {
    let mut members = vec![
        ("format", Doc::str(format)),
        ("generation", Doc::str("gen-2026.10_18")),
        ("validity", Doc::object(vec![("notBefore", Doc::Int(1_780_000_000)), ("notAfter", Doc::Int(1_790_000_000))])),
        ("apiserverAuthority", Doc::str("127.0.0.1:6443")),
        ("qualificationNamespace", Doc::str("planeon-qualification")),
        ("credentials", Doc::object(vec![
            ("apiserverServingCa", entry("/etc/planeon/policy-observer/ca.crt", PIN)),
            ("observerIdentity", Doc::object(vec![("chain", Doc::Array(vec![entry("/etc/planeon/policy-observer/tls.crt", PIN)])),
                                                  ("key", entry("/etc/planeon/policy-observer/tls.key", PIN))])),
        ])),
        ("admission", Doc::object(vec![("pinnedManifestHash", Doc::str(PIN)), ("expectedPlugin", Doc::str("planeon-admission.v1"))])),
        ("enrollment", Doc::object(vec![("nonce", Doc::str("00112233445566778899aabbccddeeff"))])),
    ];
    if let Some(record) = record {
        members.push(("qualificationRecord", record));
    }
    if let Some(extra) = extra {
        members.push(extra);
    }
    Doc::object(members).canonical()
}

fn good() -> Vec<u8> {
    document(FORMAT_V2, Some(entry(RECORD, RECORD_PIN)), None)
}

fn refused(bytes: &[u8]) -> ConfigError {
    ObserverConfig::parse_with_record(bytes).expect_err(&format!("refused: {}", String::from_utf8_lossy(bytes)))
}

#[test]
fn a_good_v2_document_parses_with_its_record() {
    let (config, record) = ObserverConfig::parse_with_record(&good()).expect("a good v2 document");
    assert_eq!((record.path.as_str(), record.sha256.as_str()), (RECORD, RECORD_PIN));
    assert_eq!(config.generation, "gen-2026.10_18");
    assert_eq!(config.nonce, "00112233445566778899aabbccddeeff");
    assert_eq!(FORMAT_V2, "planeon.observer-config/v2");
}

#[test]
fn the_record_member_is_schema_checked() {
    assert!(matches!(refused(&document(FORMAT_V2, None, None)), ConfigError::Schema(_)));
    assert!(matches!(refused(&document(FORMAT_V2, Some(entry(RECORD, RECORD_PIN)), Some(("comment", Doc::str("x"))))),
                     ConfigError::Schema(_)));
    for record in [Doc::str(RECORD), Doc::object(vec![("path", Doc::str(RECORD))]),
                   Doc::object(vec![("path", Doc::str(RECORD)), ("sha256", Doc::str(RECORD_PIN)), ("size", Doc::Int(1))]),
                   Doc::object(vec![("path", Doc::Int(1)), ("sha256", Doc::str(RECORD_PIN))])] {
        assert!(matches!(refused(&document(FORMAT_V2, Some(record), None)), ConfigError::Schema(_)));
    }
    for (path, pin) in [("etc/planeon/policy-observer/r.json", RECORD_PIN), ("/etc/planeon/policy-observer/../r.json", RECORD_PIN),
                        (RECORD, "sha256:7D39"), (RECORD, PIN.trim_start_matches("sha256:"))] {
        assert!(matches!(refused(&document(FORMAT_V2, Some(entry(path, pin)), None)), ConfigError::Check(_)), "{path} {pin}");
    }
    // Every refusal of the parse is status 13 in serve.
    assert_eq!(status::CONFIG_CHECK, 13);
}

#[test]
fn v1_is_refused_by_the_v2_parse_and_v2_by_the_v1_parse() {
    // A v1 document (eight members) and a v1 format with the record member are both refused by the v2 parse.
    assert!(matches!(refused(&document(FORMAT, None, None)), ConfigError::Schema(_)));
    assert!(matches!(refused(&document(FORMAT, Some(entry(RECORD, RECORD_PIN)), None)), ConfigError::Schema(_)));
    assert!(ObserverConfig::parse(&document(FORMAT, None, None)).is_ok(), "the v1 parse stays a library function");
    // A v2 document is refused by the v1 parse, with or without the record member.
    assert!(matches!(ObserverConfig::parse(&good()), Err(ConfigError::Schema(_))));
    assert!(matches!(ObserverConfig::parse(&document(FORMAT_V2, None, None)), Err(ConfigError::Schema(_))));
    // The canonical subset still comes first.
    let text = String::from_utf8(good()).expect("ASCII");
    assert!(matches!(ObserverConfig::parse_with_record(text.replacen(':', ": ", 1).as_bytes()), Err(ConfigError::Canonical(_))));
}

#[test]
fn the_signature_domain_is_unchanged() {
    assert_eq!(FORMAT, "planeon.observer-config/v1");
    let payload = signed_config::payload(&good());
    assert!(payload.starts_with(b"planeon.observer-config/v1\0{\"admission\""));
    assert_eq!(PRODUCTION_DIR, "/etc/planeon/policy-observer");
}

#[test]
fn the_record_lives_in_the_configuration_directory_only() {
    assert!(is_record_path(RECORD));
    assert!(is_record_path("/etc/planeon/policy-observer/record-v4.2_a"));
    for path in ["/etc/planeon/other/qualification-record.json", "/etc/planeon/policy-observer/sub/qualification-record.json",
                 "/etc/planeon/policy-observer/config.json", "/etc/planeon/policy-observer/config.json.sig",
                 "/etc/planeon/policy-observer", "/etc/planeon/policy-observer/", "/etc/planeon/policy-observerX/r.json",
                 "/etc/planeon/policy-observer/r+.json", "/var/lib/planeon/qualification-record.json"] {
        assert!(!is_record_path(path), "{path}");
        let refusal = refused(&document(FORMAT_V2, Some(entry(path, RECORD_PIN)), None));
        assert!(matches!(refusal, ConfigError::Check(_) | ConfigError::Schema(_)), "{path}: {refusal:?}");
    }
    // A path the generic check accepts but the location rule refuses is a check refusal (13).
    for path in ["/etc/planeon/policy-observer/sub/qualification-record.json", "/etc/planeon/policy-observer/config.json",
                 "/etc/planeon/policy-observer/config.json.sig", "/etc/planeon/other/qualification-record.json"] {
        assert!(matches!(refused(&document(FORMAT_V2, Some(entry(path, RECORD_PIN)), None)), ConfigError::Check(_)), "{path}");
    }
}
