//! HE-005C (DESIGN-HE005 revision 5 section 3.1, O19; the HE-005C plan's Q-HE5C-1 (a)): the broker's configuration
//! `planeon.capacity-broker-config/v1`. A good document's members through the accessors; the canonical subset; every
//! schema refusal (each member missing, an unknown member, another format, each member of another JSON type); every
//! bound of section 3.1 at both of its edges. Each refusal is status 13.

use i05_protocol::json::Doc;
use planeon_broker::config::{digest_bytes, is_digest, is_normal_path, BrokerConfig, ConfigError, FORMAT, MAX_INTEGER,
                             MEMBERS, VERITY_SHA256};
use planeon_broker::status;

/// `sha256:` and 64 copies of one hex digit.
fn pin(digit: char) -> String {
    format!("sha256:{}", digit.to_string().repeat(64))
}

const VERITY: &str = "sha256:00112233445566778899aabbccddeeff0123456789abcdef0f1e2d3c4b5a6978";

/// The members of a good document, in section 3.1's order.
fn good() -> Vec<(&'static str, Doc)> {
    vec![("format", Doc::str(FORMAT)),
         ("workerUid", Doc::Int(10_001)),
         ("workerScriptPath", Doc::str("/usr/lib/planeon/worker/probe.py")),
         ("workerScriptVerityDigest", Doc::str(VERITY)),
         ("workerInterpreterPath", Doc::str("/usr/bin/python3.12")),
         ("gateExecutablePath", Doc::str("/usr/lib/planeon/planeon-gate")),
         ("peerQualificationDigest", Doc::str(&pin('e'))),
         ("bracketPeriodSeconds", Doc::Int(600)),
         ("operationDeadlineSeconds", Doc::Int(900)),
         ("brokerManifestDigest", Doc::str(&pin('1'))),
         ("brokerExecutableDigest", Doc::str(&pin('2'))),
         ("workerManifestDigest", Doc::str(&pin('3'))),
         ("workerArtifactDigest", Doc::str(&pin('4')))]
}

/// A good document with `name` set to `value`.
fn with(name: &str, value: Doc) -> Vec<(&'static str, Doc)> {
    good().into_iter().map(|(key, old)| (key, if key == name { value.clone() } else { old })).collect()
}

fn document(members: Vec<(&'static str, Doc)>) -> Vec<u8> {
    Doc::object(members).canonical()
}

fn parsed(members: Vec<(&'static str, Doc)>) -> BrokerConfig {
    let bytes = document(members);
    BrokerConfig::parse(&bytes).unwrap_or_else(|error| panic!("{error:?}: {}", String::from_utf8_lossy(&bytes)))
}

fn refused(members: Vec<(&'static str, Doc)>) -> ConfigError {
    let bytes = document(members);
    BrokerConfig::parse(&bytes).expect_err(&format!("refused: {}", String::from_utf8_lossy(&bytes)))
}

fn schema(members: Vec<(&'static str, Doc)>) {
    let error = refused(members);
    assert!(matches!(error, ConfigError::Schema(_)), "{error:?}");
}

fn check(members: Vec<(&'static str, Doc)>) {
    let error = refused(members);
    assert!(matches!(error, ConfigError::Check(_)), "{error:?}");
}

const LOCATIONS: [&str; 3] = ["workerScriptPath", "workerInterpreterPath", "gateExecutablePath"];
const DIGESTS: [&str; 6] = ["workerScriptVerityDigest", "peerQualificationDigest", "brokerManifestDigest",
                            "brokerExecutableDigest", "workerManifestDigest", "workerArtifactDigest"];
const INTEGERS: [&str; 3] = ["workerUid", "bracketPeriodSeconds", "operationDeadlineSeconds"];

#[test]
fn a_good_document_parses_with_every_member() {
    assert_eq!(FORMAT, "planeon.capacity-broker-config/v1");
    assert_eq!(MEMBERS.len(), 13);
    assert_eq!(good().iter().map(|(name, _)| *name).collect::<Vec<_>>(), MEMBERS.to_vec());
    let config = parsed(good());
    assert_eq!(config.worker_uid(), 10_001);
    assert_eq!(config.worker_script_path(), "/usr/lib/planeon/worker/probe.py");
    assert_eq!(config.worker_script_verity_digest(),
               &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23,
                 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78]);
    assert_eq!(VERITY_SHA256, 1);
    assert_eq!(config.worker_interpreter_path(), "/usr/bin/python3.12");
    assert_eq!(config.gate_executable_path(), "/usr/lib/planeon/planeon-gate");
    assert_eq!(config.peer_qualification_digest(), pin('e'));
    assert_eq!((config.bracket_period_seconds(), config.operation_deadline_seconds()), (600, 900));
    assert_eq!((config.broker_manifest_digest(), config.broker_executable_digest()), (pin('1').as_str(), pin('2').as_str()));
    assert_eq!((config.worker_manifest_digest(), config.worker_artifact_digest()), (pin('3').as_str(), pin('4').as_str()));
}

#[test]
fn the_canonical_subset_is_required() {
    let bytes = document(good());
    let text = String::from_utf8(bytes).expect("UTF-8");
    for (case, other) in [
        ("whitespace", text.replacen(':', ": ", 1)),
        ("key order", text.replacen('{', "{\"zzz\":1,", 1)),
        ("non-ASCII", text.replace("probe.py", "pr\u{f6}be.py")),
        ("escaped", text.replace("probe.py", "prob\\u0065.py")),
        ("float", text.replace("\"workerUid\":10001", "\"workerUid\":10001.0")),
        ("negative", text.replace("\"operationDeadlineSeconds\":900", "\"operationDeadlineSeconds\":-1")),
        ("too big", text.replace("\"workerUid\":10001", "\"workerUid\":9007199254740992")),
        ("duplicate", text.replacen('{', "{\"format\":1,", 1)),
        ("not JSON", text[..text.len() - 1].to_string()),
        ("deep", format!("{}{}", "[".repeat(17), "]".repeat(17))),
    ] {
        assert_ne!(other, text, "{case}: the case changed nothing");
        let result = BrokerConfig::parse(other.as_bytes());
        assert!(matches!(result, Err(ConfigError::Canonical(_))), "{case}: {result:?}");
    }
    assert!(matches!(BrokerConfig::parse(b"{\"format\":\"x\xff\"}"), Err(ConfigError::Canonical(_))));
    assert_eq!(status::CONFIG_CHECK, 13);
}

#[test]
fn every_schema_refusal() {
    for missing in MEMBERS {
        schema(good().into_iter().filter(|(name, _)| *name != missing).collect());
    }
    let mut extra = good();
    extra.push(("comment", Doc::str("x")));
    schema(extra);
    for format in ["planeon.capacity-broker-config/v2", "planeon.observer-config/v1", "planeon.effect-gate-config/v3"] {
        schema(with("format", Doc::str(format)));
    }
    for name in LOCATIONS.iter().chain(DIGESTS.iter()).chain(["format"].iter()) {
        for value in [Doc::Int(1), Doc::Null, Doc::Bool(true), Doc::Array(vec![]), Doc::object(vec![])] {
            schema(with(name, value));
        }
    }
    for name in INTEGERS {
        for value in [Doc::str("600"), Doc::Null, Doc::Bool(false), Doc::Array(vec![Doc::Int(600)]), Doc::object(vec![])] {
            schema(with(name, value));
        }
    }
    let root = Doc::Array(vec![]).canonical();
    assert!(matches!(BrokerConfig::parse(&root), Err(ConfigError::Schema(_))));
}

#[test]
fn every_bound_at_both_edges() {
    // workerUid: 10000..=2147483647 (HS53 :452).
    for uid in [0, 9_999, 2_147_483_648, MAX_INTEGER as i64] {
        check(with("workerUid", Doc::Int(uid)));
    }
    assert_eq!(parsed(with("workerUid", Doc::Int(10_000))).worker_uid(), 10_000);
    assert_eq!(parsed(with("workerUid", Doc::Int(2_147_483_647))).worker_uid(), 2_147_483_647);
    // bracketPeriodSeconds: 140..=3600 (H5E-15).
    for seconds in [0, 139, 3_601] {
        check(with("bracketPeriodSeconds", Doc::Int(seconds)));
    }
    assert_eq!(parsed(with("bracketPeriodSeconds", Doc::Int(140))).bracket_period_seconds(), 140);
    assert_eq!(parsed(with("bracketPeriodSeconds", Doc::Int(3_600))).bracket_period_seconds(), 3_600);
    // operationDeadlineSeconds: 1..=900 (O21).
    for seconds in [0, 901] {
        check(with("operationDeadlineSeconds", Doc::Int(seconds)));
    }
    assert_eq!(parsed(with("operationDeadlineSeconds", Doc::Int(1))).operation_deadline_seconds(), 1);
    // The three locations: absolute, normalised, at most 255 bytes.
    let longest = format!("/{}", "a".repeat(254));
    let too_long = format!("/{}", "a".repeat(255));
    for name in LOCATIONS {
        for bad in ["relative/x", "", "/", "/a/", "/a//b", "/a/./b", "/a/../b", "/.", "/..", "./a", too_long.as_str()] {
            check(with(name, Doc::str(bad)));
        }
        assert!(BrokerConfig::parse(&document(with(name, Doc::str(&longest)))).is_ok(), "{name}");
    }
    // The six digests: sha256: and 64 lowercase hex digits.
    let upper = format!("sha256:{}", "A".repeat(64));
    let short = format!("sha256:{}", "a".repeat(63));
    let long = format!("sha256:{}", "a".repeat(65));
    let other = format!("sha512:{}", "a".repeat(64));
    let bare = "a".repeat(64);
    let not_hex = format!("sha256:{}g", "a".repeat(63));
    let spaced = format!(" sha256:{}", "a".repeat(64));
    for name in DIGESTS {
        for bad in ["", "sha256:", upper.as_str(), short.as_str(), long.as_str(), other.as_str(), bare.as_str(),
                    not_hex.as_str(), spaced.as_str()] {
            check(with(name, Doc::str(bad)));
        }
        assert!(BrokerConfig::parse(&document(with(name, Doc::str(&pin('f'))))).is_ok(), "{name}");
    }
}

#[test]
fn the_text_forms() {
    assert!(is_normal_path("/a/b.c") && !is_normal_path("/a\0b") && !is_normal_path("a"));
    assert!(is_digest(VERITY) && !is_digest(&VERITY.to_uppercase()));
    assert_eq!(digest_bytes(&pin('f')), Some([0xff; 32]));
    assert_eq!(digest_bytes(&pin('0')), Some([0; 32]));
    assert_eq!(digest_bytes(&format!("sha256:{}", "F".repeat(64))), None);
    assert_eq!(digest_bytes("sha256:"), None);
    assert_eq!(digest_bytes(&format!("sha256:{}", "0".repeat(66))), None);
}
