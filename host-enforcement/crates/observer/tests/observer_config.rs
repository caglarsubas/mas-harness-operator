//! HE-004C DESIGN-C section 11 (Q-HE4C-3 (a), Q-HE4C-13 (a); D1-1): the observer's configuration `planeon.observer-
//! config/v1`: the canonical subset, every schema and check refusal (status 13), the authority (only `127.0.0.1` and
//! `::1`), and the lifetime after the parse (14; a clock before the epoch or past 9999 is 97; reaching `notAfter` while
//! running is 94).

use i05_protocol::json::Doc;
use planeon_observer::config::{check_lifetime, ConfigError, LifetimeError, ObserverConfig, FORMAT, MAX_INTEGER,
                               MAX_WALL_SECONDS};
use planeon_observer::status;

const PIN: &str = "sha256:0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb";

fn file(path: &str) -> Doc {
    Doc::object(vec![("path", Doc::str(path)), ("sha256", Doc::str(PIN))])
}

/// The members of a good document, each replaceable.
struct Fields {
    format: Doc,
    generation: Doc,
    validity: Doc,
    authority: Doc,
    namespace: Doc,
    credentials: Doc,
    admission: Doc,
    enrollment: Doc,
    extra: Option<(&'static str, Doc)>,
    missing: Option<&'static str>,
}

fn validity(not_before: i64, not_after: i64) -> Doc {
    Doc::object(vec![("notBefore", Doc::Int(not_before)), ("notAfter", Doc::Int(not_after))])
}

fn credentials(chain: Vec<Doc>) -> Doc {
    Doc::object(vec![("apiserverServingCa", file("/etc/planeon/policy-observer/ca.crt")),
                     ("observerIdentity", Doc::object(vec![("chain", Doc::Array(chain)),
                                                           ("key", file("/etc/planeon/policy-observer/tls.key"))]))])
}

fn admission(pinned: &str, plugin: &str) -> Doc {
    Doc::object(vec![("pinnedManifestHash", Doc::str(pinned)), ("expectedPlugin", Doc::str(plugin))])
}

fn good() -> Fields {
    Fields {
        format: Doc::str(FORMAT),
        generation: Doc::str("gen-2026.10_18"),
        validity: validity(1_780_000_000, 1_790_000_000),
        authority: Doc::str("127.0.0.1:6443"),
        namespace: Doc::str("planeon-qualification"),
        credentials: credentials(vec![file("/etc/planeon/policy-observer/tls.crt")]),
        admission: admission(PIN, "planeon-admission.v1"),
        enrollment: Doc::object(vec![("nonce", Doc::str("00112233445566778899aabbccddeeff"))]),
        extra: None,
        missing: None,
    }
}

fn document(fields: Fields) -> Vec<u8> {
    let mut members = vec![("format", fields.format), ("generation", fields.generation), ("validity", fields.validity),
                           ("apiserverAuthority", fields.authority), ("qualificationNamespace", fields.namespace),
                           ("credentials", fields.credentials), ("admission", fields.admission),
                           ("enrollment", fields.enrollment)];
    if let Some(missing) = fields.missing {
        members.retain(|(name, _)| *name != missing);
    }
    if let Some(extra) = fields.extra {
        members.push(extra);
    }
    Doc::object(members).canonical()
}

fn refused(fields: Fields) -> ConfigError {
    let bytes = document(fields);
    ObserverConfig::parse(&bytes).expect_err(&format!("refused: {}", String::from_utf8_lossy(&bytes)))
}

fn schema(fields: Fields) {
    assert!(matches!(refused(fields), ConfigError::Schema(_)));
}

fn check(fields: Fields) {
    assert!(matches!(refused(fields), ConfigError::Check(_)));
}

#[test]
fn a_good_document_parses() {
    let config = ObserverConfig::parse(&document(good())).expect("a good document");
    assert_eq!(config.generation, "gen-2026.10_18");
    assert_eq!((config.not_before, config.not_after), (1_780_000_000, 1_790_000_000));
    assert_eq!((config.authority.as_str(), config.address.port), ("127.0.0.1:6443", 6443));
    assert_eq!(config.namespace, "planeon-qualification");
    assert_eq!(config.credentials.chain.len(), 1);
    assert_eq!(config.credentials.serving_ca.path, "/etc/planeon/policy-observer/ca.crt");
    assert_eq!((config.pinned_manifest_hash.as_str(), config.expected_plugin.as_str()), (PIN, "planeon-admission.v1"));
    assert_eq!(config.nonce, "00112233445566778899aabbccddeeff");
    // The IPv6 loopback, four chain certificates, the largest integer.
    let fields = Fields { authority: Doc::str("[::1]:65535"),
                          credentials: credentials((0..4).map(|index| file(&format!("/etc/planeon/c{index}.crt"))).collect()),
                          validity: validity(1, MAX_INTEGER as i64), ..good() };
    let config = ObserverConfig::parse(&document(fields)).expect("a good document");
    assert_eq!((config.address.port, config.credentials.chain.len(), config.not_after), (65_535, 4, MAX_INTEGER));
}

#[test]
fn the_canonical_subset_is_required() {
    let bytes = document(good());
    let text = String::from_utf8(bytes.clone()).expect("UTF-8");
    for (case, other) in [
        ("whitespace", text.replacen(":", ": ", 1)),
        ("key order", text.replacen("{\"admission\"", "{\"zzz\":1,\"admission\"", 1)),
        ("non-ASCII", text.replace("planeon-qualification", "planeon-qualificati\u{f6}n")),
        ("escaped", text.replace("planeon-qualification", "planeon-qualific\\u0061tion")),
        ("float", text.replace("1780000000", "1780000000.0")),
        ("negative", text.replace("1780000000", "-1")),
        ("too big", text.replace("1790000000", "9007199254740992")),
        ("duplicate", text.replacen("{\"admission\"", "{\"admission\":1,\"admission\"", 1)),
        ("not JSON", text[..text.len() - 1].to_string()),
        ("deep", format!("{}{}", "[".repeat(17), "]".repeat(17))),
    ] {
        let result = ObserverConfig::parse(other.as_bytes());
        assert!(matches!(result, Err(ConfigError::Canonical(_))), "{case}: {result:?}");
    }
    assert!(matches!(ObserverConfig::parse(b"{\"format\":\"x\xff\"}"), Err(ConfigError::Canonical(_))));
    assert_eq!(status::CONFIG_CHECK, 13);
}

#[test]
fn every_schema_refusal() {
    for missing in ["format", "generation", "validity", "apiserverAuthority", "qualificationNamespace", "credentials", "admission",
                    "enrollment"] {
        schema(Fields { missing: Some(missing), ..good() });
    }
    schema(Fields { extra: Some(("comment", Doc::str("x"))), ..good() });
    schema(Fields { format: Doc::str("planeon.observer-config/v2"), ..good() });
    schema(Fields { format: Doc::str("planeon.effect-gate-config/v3"), ..good() });
    schema(Fields { generation: Doc::Int(7), ..good() });
    schema(Fields { validity: Doc::object(vec![("notBefore", Doc::Int(1))]), ..good() });
    schema(Fields { validity: Doc::object(vec![("notBefore", Doc::Int(1)), ("notAfter", Doc::Int(2)), ("x", Doc::Int(3))]), ..good() });
    schema(Fields { validity: Doc::object(vec![("notBefore", Doc::str("1")), ("notAfter", Doc::Int(2))]), ..good() });
    schema(Fields { authority: Doc::Null, ..good() });
    schema(Fields { namespace: Doc::Array(vec![]), ..good() });
    schema(Fields { credentials: Doc::object(vec![("apiserverServingCa", file("/a"))]), ..good() });
    schema(Fields { credentials: Doc::object(vec![("apiserverServingCa", Doc::object(vec![("path", Doc::str("/a"))])),
                                                  ("observerIdentity", Doc::object(vec![("chain", Doc::Array(vec![file("/b")])),
                                                                                        ("key", file("/c"))]))]),
                    ..good() });
    schema(Fields { credentials: Doc::object(vec![("apiserverServingCa", file("/a")),
                                                  ("observerIdentity", Doc::object(vec![("chain", file("/b")), ("key", file("/c"))]))]),
                    ..good() });
    schema(Fields { admission: Doc::object(vec![("pinnedManifestHash", Doc::str(PIN))]), ..good() });
    schema(Fields { enrollment: Doc::object(vec![("nonce", Doc::str("00112233445566778899aabbccddeeff")), ("generation", Doc::Int(1))]),
                    ..good() });
}

#[test]
fn every_check_refusal() {
    for generation in ["", "-leading", "has space", "generations", "g".repeat(129).as_str(), "caf\\u00e9"] {
        check(Fields { generation: Doc::str(generation), ..good() });
    }
    assert!(ObserverConfig::parse(&document(Fields { generation: Doc::str(&"g".repeat(128)), ..good() })).is_ok());
    for (not_before, not_after) in [(0, 10), (10, 10), (11, 10), (1, MAX_INTEGER as i64 + 1)] {
        let result = ObserverConfig::parse(&document(Fields { validity: validity(not_before, not_after), ..good() }));
        assert!(matches!(result, Err(ConfigError::Check(_)) | Err(ConfigError::Canonical(_))), "{not_before} {not_after}");
    }
    for namespace in ["", "Upper", "-lead", "trail-", "under_score", "n".repeat(64).as_str(), "default", "kube-system", "kube-public",
                      "kube-node-lease"] {
        check(Fields { namespace: Doc::str(namespace), ..good() });
    }
    assert!(ObserverConfig::parse(&document(Fields { namespace: Doc::str(&"n".repeat(63)), ..good() })).is_ok());
    for path in ["relative/tls.crt", "/etc/../tls.crt", "/etc/./tls.crt", "/etc//tls.crt", "/etc/tls/", "/", format!("/{}", "p".repeat(255)).as_str()] {
        check(Fields { credentials: credentials(vec![file(path)]), ..good() });
    }
    for pin in ["sha256:0A9B82FFA2D63BF48A8850574CDF3ECE02BF1913F33A72CBB96ED30A40F1F3BB", "sha256:0a9b", "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb"] {
        let entry = Doc::object(vec![("path", Doc::str("/etc/planeon/tls.crt")), ("sha256", Doc::str(pin))]);
        check(Fields { credentials: credentials(vec![entry]), ..good() });
        check(Fields { admission: admission(pin, "plugin"), ..good() });
    }
    check(Fields { credentials: credentials(vec![]), ..good() });
    check(Fields { credentials: credentials((0..5).map(|index| file(&format!("/etc/planeon/c{index}.crt"))).collect()), ..good() });
    for plugin in ["", "p".repeat(64).as_str(), "has space", "plugin/v1", "pl\\u00fcgin"] {
        check(Fields { admission: admission(PIN, plugin), ..good() });
    }
    for nonce in ["0011223344556677889900aabbccddee".get(..31).unwrap_or(""), "0".repeat(65).as_str(), "00112233445566778899AABBCCDDEEFF",
                  "00112233445566778899aabbccddeefg"] {
        check(Fields { enrollment: Doc::object(vec![("nonce", Doc::str(nonce))]), ..good() });
    }
    assert!(ObserverConfig::parse(&document(Fields { enrollment: Doc::object(vec![("nonce", Doc::str(&"f".repeat(64)))]), ..good() })).is_ok());
}

#[test]
fn the_authority_is_exactly_127_0_0_1_or_v6_loopback_with_a_port() {
    for authority in ["127.0.0.1:6443", "[::1]:6443", "127.0.0.1:1", "[0:0:0:0:0:0:0:1]:443"] {
        assert!(ObserverConfig::parse(&document(Fields { authority: Doc::str(authority), ..good() })).is_ok(), "{authority}");
    }
    for authority in ["127.0.0.2:6443", "127.1.0.1:6443", "[::ffff:127.0.0.1]:6443", "[::ffff:7f00:1]:6443", "localhost:6443",
                      "127.0.0.1", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:65536", "[::1]", "::1:6443", "10.0.0.1:6443",
                      "[::2]:6443", "0.0.0.0:6443", " 127.0.0.1:6443", "127.0.0.1:06443"] {
        check(Fields { authority: Doc::str(authority), ..good() });
    }
}

#[test]
fn the_lifetime_after_the_parse() {
    let config = ObserverConfig::parse(&document(good())).expect("a good document");
    assert_eq!(check_lifetime(&config, Some(config.not_before - 1)), Err(LifetimeError::Outside));
    assert_eq!(check_lifetime(&config, Some(config.not_before)), Ok(()));
    assert_eq!(check_lifetime(&config, Some(config.not_after - 1)), Ok(()));
    assert_eq!(check_lifetime(&config, Some(config.not_after)), Err(LifetimeError::Outside));
    assert_eq!(check_lifetime(&config, None), Err(LifetimeError::Clock));
    assert_eq!(status::lifetime(&LifetimeError::Outside), 14);
    assert_eq!(status::lifetime(&LifetimeError::Clock), 97);
    // Past 9999: an unusable clock (97), whatever the validity says.
    let late = ObserverConfig::parse(&document(Fields { validity: validity(1, MAX_INTEGER as i64), ..good() })).expect("good");
    assert_eq!(check_lifetime(&late, Some(MAX_WALL_SECONDS)), Ok(()));
    assert_eq!(check_lifetime(&late, Some(MAX_WALL_SECONDS + 1)), Err(LifetimeError::Clock));
    // While running, reaching notAfter is 94 (observe checks `expired`).
    assert!(!config.expired(config.not_after - 1));
    assert!(config.expired(config.not_after));
    assert_eq!(status::CONFIG_EXPIRED, 94);
}
