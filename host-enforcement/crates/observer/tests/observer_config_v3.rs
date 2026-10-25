//! HE-004-I01B2 (DESIGN-I01B2 rev 3 sections 3, 4 and 8; the monitor's Q-I01B2D-1 (a), Q-I01B2D-2 (a) and Q-I01B2D-3
//! (a); I2D-3, I2D-8, I2D-10, I2E-6; MODEL_DEFINED's HE-004-I01B2 section): configuration v3, the observer configuration
//! successor, and its load-time checks.
//!
//! - A v3 document (v2's nine members, `sealedAdmission` and `binding`) parses with its record reference, its sealed
//!   values and its binding; v1 and v2 documents refuse in `parse_v3` (status 13), and v3 refuses in the older parses.
//! - The binding the configuration keeps is the document's own member, byte for byte: read here from the document
//!   bytes by this test's own canonical parse, never through `ObserverConfig`, over three documents (PV's positive
//!   binding, S1's v2 binding, and PV's with two members no load-time check compares changed), so neither a constant
//!   nor a rebuilt subset passes (I2E-6). `I01Binding::from_config` over the kept member gives `sha256:` and the hex
//!   SHA-256 of the member's canonical encoding, and the member's `scope.runNonce` (I2D-3). An input-triggered
//!   substitution is R-TEXT's (the PR review reads `parse_v3`).
//! - Each load-time check refuses with its own text, in section 4's order, the namespaces first (I2D-8).
//! - The binding form is held to the vendored channel schema's `$defs.binding` (`CS`), whole: every object, the
//!   constant, every text's bounds and pattern, the projections' `oneOf`; each hand-written pattern agrees with CS's
//!   pattern text (through i05-protocol's ECMA-262 subset) at its boundaries; PV's and S1's bindings pass.
//! - The sealed values: the vendored admission v4 vectors' `sealed` is the positive, with R10-defined negatives for
//!   each clause (I2D-10).
//! - PV case 27 (Q-I01B2D-3 (a)): PV's own case and W3's derived case on S1's v2 triple (row 74, the derivation rule
//!   unchanged), each as a v3 document refused at the namespace check (status 13).

use std::collections::BTreeSet;

use i05_protocol::json::{self, Doc, JStr, Object, Value};
use i05_protocol::regex::Regex;
use i05_protocol::sha256;
use planeon_observer::config::{is_generation_v3, is_service_cidr, BindingForm, ConfigError, ObserverConfig, SealedValues,
                               TextBounds, TextPattern, BINDING_FORM, BINDING_FORM_REFUSAL, BINDING_NAMESPACES_REFUSAL,
                               BINDING_SUBJECT_REFUSAL, FORMAT, FORMAT_V2, FORMAT_V3, IP_FAMILIES, SEALED_CIDR_REFUSAL,
                               SEALED_FAMILY_REFUSAL, TEXT_PATTERNS};
use planeon_observer::i01_request::I01Binding;
use planeon_observer::signed_config;
use planeon_observer::status;

const PV: &str = include_str!("../../../contracts/i01-v1/vectors.json");
const CS: &str = include_str!("../../../contracts/i01-v1/channel.schema.json");
const DIGEST_VECTORS: &str = include_str!("../../../contracts/i01-digests-v2/vectors.json");
const ADMISSION_V4: &str = include_str!("../../../contracts/admission-v4/vectors.json");
const GENERATION: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const PIN: &str = "sha256:0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb";
const RECORD_PIN: &str = "sha256:7d39e7686a01f3e0a34fa473e940965f5aee88f6e9dabc418e99955a5e3a7723";
const RECORD: &str = "/etc/planeon/policy-observer/qualification-record.json";
/// PV's positive binding's qualification namespace, and S1's.
const PV_NAMESPACE: &str = "unit-namespace";
const S1_NAMESPACE: &str = "planeon-qual";
/// PV's negative 27.
const CASE_27: &str = "negative-27-binding-scope.namespace";

fn parse(text: &str) -> Value {
    json::parse(text).expect("the vendored JSON parses")
}

fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).unwrap_or_else(|| panic!("{name} is missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    member(value, name).as_str().unwrap_or_else(|| panic!("{name} is not text"))
}

fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

/// PV's positive binding document.
fn pv_binding() -> Value {
    member(member(&parse(PV), "positive"), "binding").clone()
}

/// S1's complete triple's binding (row 74's file).
fn s1_binding() -> Value {
    member(member(&parse(DIGEST_VECTORS), "complete"), "binding").clone()
}

/// A copy of `document` with `change` applied to the object holding the last step of `path` (object member names).
fn edited(document: &Value, path: &[&str], change: impl FnOnce(&mut Object, JStr)) -> Value {
    let mut copy = document.clone();
    let (last, parents) = path.split_last().expect("a non-empty path");
    let mut node = &mut copy;
    for step in parents {
        node = match node {
            Value::Object(object) => object.get_key_mut(&JStr::new(step)).expect("the path exists"),
            _ => panic!("the path names object members"),
        };
    }
    match node {
        Value::Object(object) => change(object, JStr::new(last)),
        _ => panic!("the path names object members"),
    }
    copy
}

/// `document` with the member at `path` replaced by `new` (it must exist).
fn with_value(document: &Value, path: &[&str], new: Value) -> Value {
    edited(document, path, |object, last| {
        assert!(object.contains_key(&last), "a change replaces an existing member");
        object.insert(last, new);
    })
}

fn entry(path: &str, pin: &str) -> Doc {
    Doc::object(vec![("path", Doc::str(path)), ("sha256", Doc::str(pin))])
}

/// The vendored admission v4 vectors' sealed values as configuration v3's `sealedAdmission` (their namespace is the
/// qualification namespace, not a member).
fn sealed_v4() -> Value {
    let sealed = admission_sealed();
    let mut object = Object::new();
    for name in ["ipFamily", "serviceCIDR", "defaultTolerationSeconds"] {
        object.insert(JStr::new(name), member(&sealed, name).clone());
    }
    Value::Object(object)
}

/// The vendored admission v4 vectors' `sealed` object.
fn admission_sealed() -> Value {
    member(&parse(ADMISSION_V4), "sealed").clone()
}

/// v2's members of a test document for the qualification namespace `namespace`, with `format`.
fn v2_members(format: &str, namespace: &str) -> Object {
    Doc::object(vec![
        ("format", Doc::str(format)),
        ("generation", Doc::str(GENERATION)),
        ("validity", Doc::object(vec![("notBefore", Doc::Int(1_780_000_000)), ("notAfter", Doc::Int(1_790_000_000))])),
        ("apiserverAuthority", Doc::str("127.0.0.1:6443")),
        ("qualificationNamespace", Doc::str(namespace)),
        ("credentials", Doc::object(vec![
            ("apiserverServingCa", entry("/etc/planeon/policy-observer/ca.crt", PIN)),
            ("observerIdentity", Doc::object(vec![("chain", Doc::Array(vec![entry("/etc/planeon/policy-observer/tls.crt", PIN)])),
                                                  ("key", entry("/etc/planeon/policy-observer/tls.key", PIN))])),
        ])),
        ("admission", Doc::object(vec![("pinnedManifestHash", Doc::str(PIN)), ("expectedPlugin", Doc::str("planeon-admission.v1"))])),
        ("enrollment", Doc::object(vec![("nonce", Doc::str("00112233445566778899aabbccddeeff"))])),
        ("qualificationRecord", entry(RECORD, RECORD_PIN)),
    ])
    .to_value()
    .as_object()
    .cloned()
    .expect("an object")
}

/// A v3 document's members: v2's, the vendored sealed values and `binding`.
fn v3_members(namespace: &str, binding: &Value) -> Object {
    let mut object = v2_members(FORMAT_V3, namespace);
    object.insert(JStr::new("sealedAdmission"), sealed_v4());
    object.insert(JStr::new("binding"), binding.clone());
    object
}

fn encoded(members: &Object) -> Vec<u8> {
    canonical(&Value::Object(members.clone()))
}

/// A v3 document for `namespace` and `binding`.
fn document(namespace: &str, binding: &Value) -> Vec<u8> {
    encoded(&v3_members(namespace, binding))
}

/// A v3 document with one root member replaced.
fn with_member(namespace: &str, binding: &Value, name: &str, value: Value) -> Vec<u8> {
    let mut members = v3_members(namespace, binding);
    members.insert(JStr::new(name), value);
    encoded(&members)
}

/// A v3 document with one `sealedAdmission` member replaced.
fn with_sealed(name: &str, value: Value) -> Vec<u8> {
    let sealed = with_value(&sealed_v4(), &[name], value);
    with_member(PV_NAMESPACE, &pv_binding(), "sealedAdmission", sealed)
}

fn refused(bytes: &[u8]) -> ConfigError {
    ObserverConfig::parse_v3(bytes).expect_err(&format!("refused: {}", String::from_utf8_lossy(bytes)))
}

fn check(text: &str) -> ConfigError {
    ConfigError::Check(text.to_string())
}

/// The binding form's refusal at `path` (member names below the binding).
fn form_refusal(path: &[&str]) -> ConfigError {
    let at = ["binding"].iter().chain(path.iter()).copied().collect::<Vec<_>>().join(".");
    check(&format!("{BINDING_FORM_REFUSAL} {at} is not of the channel schema's $defs.binding form"))
}

/// The binding member read from the document bytes by this test's own canonical parse (I2E-6).
fn document_member(bytes: &[u8]) -> Value {
    member(&parse(std::str::from_utf8(bytes).expect("ASCII")), "binding").clone()
}

#[test]
fn a_v3_document_parses_with_its_record_sealed_values_and_binding() {
    assert_eq!(FORMAT_V3, "planeon.observer-config/v3");
    let sealed = &admission_sealed();
    // The vendored sealed values belong to S1's qualification namespace.
    assert_eq!(text(sealed, "namespace"), S1_NAMESPACE);
    for (namespace, binding) in [(PV_NAMESPACE, pv_binding()), (S1_NAMESPACE, s1_binding())] {
        let bytes = document(namespace, &binding);
        let (config, record) = ObserverConfig::parse_v3(&bytes).expect("a good v3 document");
        assert_eq!((record.path.as_str(), record.sha256.as_str()), (RECORD, RECORD_PIN));
        assert_eq!((config.generation.as_str(), config.namespace.as_str()), (GENERATION, namespace));
        assert_eq!(config.sealed, Some(SealedValues { ip_family: text(sealed, "ipFamily").to_string(),
                                                      service_cidr: text(sealed, "serviceCIDR").to_string(),
                                                      default_toleration_seconds: 300 }));
        assert_eq!(member(sealed, "defaultTolerationSeconds").as_int().and_then(|int| int.to_u64()), Some(300));
        assert!(json::json_eq(config.binding(), &binding));
        // The signature's domain is unchanged: each document's own format is signed under v1's domain.
        assert!(signed_config::payload(&bytes).starts_with(b"planeon.observer-config/v1\0{\"admission\""));
    }
}

#[test]
fn v1_and_v2_documents_refuse_at_13_and_v3_refuses_in_the_older_parses() {
    let v1 = {
        let mut members = v2_members(FORMAT, PV_NAMESPACE);
        members.remove(&JStr::new("qualificationRecord"));
        encoded(&members)
    };
    let v2 = encoded(&v2_members(FORMAT_V2, PV_NAMESPACE));
    // The older documents parse in their own parses (the generation's 64 hex is a store name) and refuse in v3's.
    assert!(ObserverConfig::parse(&v1).is_ok() && ObserverConfig::parse_with_record(&v2).is_ok());
    for bytes in [&v1, &v2] {
        assert!(matches!(refused(bytes), ConfigError::Schema(_)));
    }
    // v3's eleven members under the v2 format, and a v3 document in the older parses.
    let mut members = v3_members(PV_NAMESPACE, &pv_binding());
    members.insert(JStr::new("format"), Value::str(FORMAT_V2));
    assert_eq!(refused(&encoded(&members)), ConfigError::Schema(format!("the document's format is not {FORMAT_V3}")));
    let good = document(PV_NAMESPACE, &pv_binding());
    assert!(matches!(ObserverConfig::parse(&good), Err(ConfigError::Schema(_))));
    assert!(matches!(ObserverConfig::parse_with_record(&good), Err(ConfigError::Schema(_))));
    // The root is closed: a missing sealedAdmission or binding, or an extra member, refuses; the canonical subset first.
    for name in ["sealedAdmission", "binding"] {
        let mut members = v3_members(PV_NAMESPACE, &pv_binding());
        members.remove(&JStr::new(name));
        assert!(matches!(refused(&encoded(&members)), ConfigError::Schema(_)), "{name}");
    }
    assert!(matches!(refused(&with_member(PV_NAMESPACE, &pv_binding(), "zz", Value::Null)), ConfigError::Schema(_)));
    let spaced = String::from_utf8(good).expect("ASCII").replacen(':', ": ", 1);
    assert!(matches!(refused(spaced.as_bytes()), ConfigError::Canonical(_)));
    // The record's reference keeps v2's rule.
    let outside = with_member(PV_NAMESPACE, &pv_binding(), "qualificationRecord",
                              entry("/etc/planeon/other/qualification-record.json", RECORD_PIN).to_value());
    assert!(matches!(refused(&outside), ConfigError::Check(_)));
    // Every refusal of the parse is status 13 in serve.
    assert_eq!(status::CONFIG_CHECK, 13);
}

#[test]
fn the_generation_is_64_lowercase_hex() {
    assert!(is_generation_v3(GENERATION));
    // Each is a valid store name (R19), so only v3's narrowing refuses it.
    let generations = [String::from("gen-2026.10_18"), GENERATION[..63].to_string(), format!("{GENERATION}0"),
                       GENERATION.to_uppercase(), GENERATION.replacen('0', "g", 1)];
    for generation in &generations {
        assert!(!is_generation_v3(generation), "{generation}");
        let bytes = with_member(PV_NAMESPACE, &pv_binding(), "generation", Value::str(generation));
        assert_eq!(refused(&bytes), check("generation is not 64 lowercase hex digits (configuration v3)"), "{generation}");
    }
    // A text outside the store-name form still refuses at v2's check.
    let bytes = with_member(PV_NAMESPACE, &pv_binding(), "generation", Value::str("generations"));
    assert_eq!(refused(&bytes), check("generation is not a valid store name (R19)"));
}

#[test]
fn the_binding_is_the_document_s_member_byte_for_byte() {
    // I2D-3 and I2E-6: three v3 documents whose binding members differ; the third differs from PV's only in two members
    // no load-time check compares.
    let pv = pv_binding();
    let changed = with_value(&with_value(&pv, &["enforcementPins", "rbacClosureDigest"],
                                         Value::str(&format!("sha256:{}", "2".repeat(64)))),
                             &["projections", "rbac", "uid"], Value::str("another-rbac-uid"));
    assert!(!json::json_eq(&changed, &pv));
    let cases = [(PV_NAMESPACE, pv.clone()), (S1_NAMESPACE, s1_binding()), (PV_NAMESPACE, changed)];
    let mut kept = Vec::new();
    for (namespace, binding) in &cases {
        let bytes = document(namespace, binding);
        let expected = document_member(&bytes);
        let (config, _) = ObserverConfig::parse_v3(&bytes).expect("a good v3 document");
        assert!(json::json_eq(config.binding(), &expected));
        assert_eq!(canonical(config.binding()), canonical(&expected));
        // The member's canonical form is in the document's bytes as written.
        let inline = [b"\"binding\":".as_slice(), &canonical(&expected)].concat();
        assert!(bytes.windows(inline.len()).any(|window| window == inline.as_slice()));
        // The one constructor over the kept member: the member's canonical digest and its scope.runNonce (I2D-3).
        let bound = I01Binding::from_config(config.binding()).expect("the kept member has a digest and a nonce");
        assert_eq!(bound.signed_digest(), format!("sha256:{}", sha256::hex(&sha256::digest(&canonical(&expected)))));
        assert_eq!(bound.signed_nonce(), text(member(&expected, "scope"), "runNonce"));
        kept.push(canonical(config.binding()));
    }
    // Three different members kept: no constant, and no subset rebuilt from what the checks compare.
    assert!(kept[0] != kept[1] && kept[0] != kept[2] && kept[1] != kept[2]);
    // The older parses leave the binding null and the sealed values absent.
    let v2 = encoded(&v2_members(FORMAT_V2, PV_NAMESPACE));
    let (config, _) = ObserverConfig::parse_with_record(&v2).expect("a good v2 document");
    assert!(config.binding().is_null() && config.sealed.is_none());
}

#[test]
fn each_load_time_check_refuses_at_13_with_its_own_text() {
    let pv = pv_binding();
    // The namespaces: the binding's two names, or the qualification namespace, differ.
    let namespaces = check(BINDING_NAMESPACES_REFUSAL);
    assert_eq!(refused(&document(PV_NAMESPACE, &with_value(&pv, &["namespace", "name"], Value::str("other")))), namespaces);
    assert_eq!(refused(&document(PV_NAMESPACE, &with_value(&pv, &["scope", "namespace"], Value::str("other")))), namespaces);
    assert_eq!(refused(&document("other-namespace", &pv)), namespaces);
    // The binding form against CS (each member is covered below): another constant, a pattern, a closed object.
    assert_eq!(refused(&document(PV_NAMESPACE, &with_value(&pv, &["schemaVersion"],
                                                          Value::str("planeon.internal.policy-observation-binding/v2")))),
               form_refusal(&["schemaVersion"]));
    assert_eq!(refused(&document(PV_NAMESPACE, &with_value(&pv, &["profileDigest"], Value::str("sha256:FC56")))),
               form_refusal(&["profileDigest"]));
    // The subject: CS's form, but another namespace segment, or none.
    for subject in ["system:serviceaccount:other-namespace:campaign", "system:serviceaccount:unit-namespace-x:campaign",
                    "system:serviceaccount:unit:campaign"] {
        let binding = with_value(&pv, &["scope", "serviceAccountSubject"], Value::str(subject));
        assert_eq!(refused(&document(PV_NAMESPACE, &binding)), check(BINDING_SUBJECT_REFUSAL), "{subject}");
    }
    // The sealed values' forms (each clause is covered below).
    assert_eq!(refused(&with_sealed("ipFamily", Value::str("IPv5"))), check(SEALED_FAMILY_REFUSAL));
    assert_eq!(refused(&with_sealed("serviceCIDR", Value::str("10.96.0.1/12"))), check(SEALED_CIDR_REFUSAL));
}

#[test]
fn the_load_time_checks_run_in_section_4_s_order() {
    // I2D-8: one document breaking all four checks refuses at the namespaces; mending each in turn moves the refusal to
    // the next check: the form, the subject, the sealed values; mending the last parses.
    let pv = pv_binding();
    let bad_namespace = with_value(&pv, &["namespace", "name"], Value::str("other"));
    let bad_form = |binding: &Value| with_value(binding, &["enforcementPins", "hostPreflightDigest"], Value::str("x"));
    let bad_subject = |binding: &Value| with_value(binding, &["scope", "serviceAccountSubject"],
                                                   Value::str("system:serviceaccount:other:campaign"));
    let bad_sealed = with_value(&sealed_v4(), &["ipFamily"], Value::str("IPv5"));
    let all = bad_form(&bad_subject(&bad_namespace));
    let steps = [(all, Some(bad_sealed.clone()), check(BINDING_NAMESPACES_REFUSAL)),
                 (bad_form(&bad_subject(&pv)), Some(bad_sealed.clone()), form_refusal(&["enforcementPins", "hostPreflightDigest"])),
                 (bad_subject(&pv), Some(bad_sealed.clone()), check(BINDING_SUBJECT_REFUSAL)),
                 (pv.clone(), Some(bad_sealed), check(SEALED_FAMILY_REFUSAL))];
    for (binding, sealed, expected) in steps {
        let bytes = with_member(PV_NAMESPACE, &binding, "sealedAdmission", sealed.expect("a sealed member"));
        assert_eq!(refused(&bytes), expected);
    }
    assert!(ObserverConfig::parse_v3(&document(PV_NAMESPACE, &pv)).is_ok());
}

/// Every form of `form`, depth first, with its path below the binding.
fn forms(form: BindingForm, path: Vec<&'static str>, out: &mut Vec<(Vec<&'static str>, BindingForm)>) {
    out.push((path.clone(), form));
    if let BindingForm::Object(members) = form {
        for (name, inner) in members {
            let mut next = path.clone();
            next.push(*name);
            forms(*inner, next, out);
        }
    }
}

/// One CS node held to the table's form; the keywords and patterns met are collected.
fn hold(node: &Value, form: BindingForm, path: &str, keywords: &mut BTreeSet<String>, patterns: &mut BTreeSet<String>) {
    let object = node.as_object().unwrap_or_else(|| panic!("{path}: a schema node is an object"));
    let mut keys: Vec<&str> = object.iter().map(|(name, _)| name.as_str().expect("a text keyword")).collect();
    keys.sort_unstable();
    keywords.extend(keys.iter().map(|key| key.to_string()));
    match form {
        BindingForm::Const(expected) => {
            assert_eq!(keys, ["const"], "{path}");
            assert_eq!(text(node, "const"), expected, "{path}");
        }
        BindingForm::Text(bounds) => hold_text(node, bounds, path, patterns),
        BindingForm::TextOrNull(bounds) => {
            assert_eq!(keys, ["oneOf"], "{path}");
            let options = member(node, "oneOf").as_array().expect("oneOf is an array");
            assert_eq!(options.len(), 2, "{path}");
            hold_text(&options[0], bounds, path, patterns);
            let null = options[1].as_object().expect("an object");
            assert_eq!((null.len(), text(&options[1], "type")), (1, "null"), "{path}");
            for option in options {
                let names = option.as_object().expect("an object").iter().map(|(name, _)| name.as_str().expect("text"));
                keywords.extend(names.map(str::to_string));
            }
        }
        BindingForm::Object(members) => {
            assert_eq!(keys, ["additionalProperties", "properties", "required", "type"], "{path}");
            assert_eq!(text(node, "type"), "object", "{path}");
            assert_eq!(member(node, "additionalProperties").as_bool(), Some(false), "{path}");
            let names: Vec<&str> = members.iter().map(|(name, _)| *name).collect();
            let required: Vec<&str> = member(node, "required").as_array().expect("required is an array").iter()
                                                              .map(|name| name.as_str().expect("text")).collect();
            assert_eq!(required, names, "{path}");
            let properties = member(node, "properties").as_object().expect("properties is an object");
            let named: Vec<&str> = properties.iter().map(|(name, _)| name.as_str().expect("text")).collect();
            assert_eq!(named, names, "{path}");
            for (name, inner) in members {
                hold(member(member(node, "properties"), name), *inner, &format!("{path}.{name}"), keywords, patterns);
            }
        }
    }
}

fn hold_text(node: &Value, bounds: TextBounds, path: &str, patterns: &mut BTreeSet<String>) {
    let mut keys: Vec<&str> = node.as_object().expect("an object").iter().map(|(name, _)| name.as_str().expect("text")).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["maxLength", "minLength", "pattern", "type"], "{path}");
    assert_eq!(text(node, "type"), "string", "{path}");
    let length = |name: &str| member(node, name).as_int().and_then(|int| int.to_u64()).expect("a length");
    assert_eq!((length("minLength"), length("maxLength")), (bounds.min as u64, bounds.max as u64), "{path}");
    assert_eq!(text(node, "pattern"), bounds.pattern.pattern_text(), "{path}");
    patterns.insert(text(node, "pattern").to_string());
}

#[test]
fn the_binding_form_is_the_channel_schema_s_binding_definition_whole() {
    // Q-I01B2D-1 (a) with the monitor's Q-D1: the check's whole table against CS's text.
    let schema = parse(CS);
    let definition = member(member(&schema, "$defs"), "binding");
    let (mut keywords, mut patterns) = (BTreeSet::new(), BTreeSet::new());
    hold(definition, BINDING_FORM, "binding", &mut keywords, &mut patterns);
    // Nine keyword names (two of them read together as one closed object: required and properties) and seven
    // distinct patterns, each a TextPattern once.
    let expected: BTreeSet<String> = ["additionalProperties", "const", "maxLength", "minLength", "oneOf", "pattern",
                                      "properties", "required", "type"].iter().map(|name| name.to_string()).collect();
    assert_eq!(keywords, expected);
    let texts: BTreeSet<String> = TEXT_PATTERNS.iter().map(|pattern| pattern.pattern_text().to_string()).collect();
    assert_eq!((patterns.len(), texts.len()), (7, 7));
    assert_eq!(patterns, texts);
    // PV's positive binding and S1's v2 binding pass the check (through parse_v3).
    for (namespace, binding) in [(PV_NAMESPACE, pv_binding()), (S1_NAMESPACE, s1_binding())] {
        assert!(ObserverConfig::parse_v3(&document(namespace, &binding)).is_ok(), "{namespace}");
    }
}

#[test]
fn every_member_of_the_form_refuses_a_value_outside_it() {
    let pv = pv_binding();
    let mut all = Vec::new();
    forms(BINDING_FORM, Vec::new(), &mut all);
    // 7 root members, 9 + 2 + 2 + 7 + 4 below them, 7 x 6 projection members.
    assert_eq!(all.len(), 1 + 7 + 9 + 2 + 2 + 7 + 4 + 7 * 6);
    // A value outside the form at a path the namespace check reads (or above one) refuses there first.
    let namespaced = |path: &[&str]| {
        !path.is_empty() && (["scope", "namespace"].starts_with(path) || ["namespace", "name"].starts_with(path))
    };
    for (path, form) in &all {
        let expected = |path: &[&str]| if namespaced(path) { check(BINDING_NAMESPACES_REFUSAL) } else { form_refusal(path) };
        match form {
            BindingForm::Object(members) => {
                // An extra member, and the last member missing.
                let mut extra_path = path.clone();
                extra_path.push("zz");
                let extra = edited(&pv, &extra_path, |object, last| object.insert(last, Value::Null));
                assert_eq!(refused(&document(PV_NAMESPACE, &extra)), form_refusal(path), "{path:?} extra");
                let (last, _) = members.last().expect("a member");
                let mut missing_path = path.clone();
                missing_path.push(*last);
                let missing = edited(&pv, &missing_path, |object, last| {
                    object.remove(&last).expect("present");
                });
                assert_eq!(refused(&document(PV_NAMESPACE, &missing)), form_refusal(path), "{path:?} missing");
                if !path.is_empty() {
                    let scalar = with_value(&pv, path, Value::int(1));
                    assert_eq!(refused(&document(PV_NAMESPACE, &scalar)), expected(path), "{path:?} scalar");
                }
            }
            BindingForm::Const(_) | BindingForm::Text(_) | BindingForm::TextOrNull(_) => {
                for wrong in [Value::int(1), Value::str(""), Value::Bool(true)] {
                    let binding = with_value(&pv, path, wrong.clone());
                    assert_eq!(refused(&document(PV_NAMESPACE, &binding)), expected(path), "{path:?} {wrong:?}");
                }
                let nulled = with_value(&pv, path, Value::Null);
                let nullable = matches!(form, BindingForm::TextOrNull(_));
                match ObserverConfig::parse_v3(&document(PV_NAMESPACE, &nulled)) {
                    Ok(_) => assert!(nullable, "{path:?}: null passes only a oneOf member"),
                    Err(error) => {
                        assert!(!nullable, "{path:?}");
                        assert_eq!(error, expected(path), "{path:?} null");
                    }
                }
            }
        }
    }
}

/// Each pattern's boundary inputs with the outcome CS's pattern text gives.
fn boundaries(pattern: TextPattern) -> Vec<(String, bool)> {
    let owned = |items: &[(&str, bool)]| items.iter().map(|(text, ok)| (text.to_string(), *ok)).collect::<Vec<_>>();
    let digest = |hex: String| format!("sha256:{hex}");
    match pattern {
        TextPattern::Digest => vec![(digest("0".repeat(64)), true), (digest("f".repeat(64)), true),
                                    (digest("0123456789abcdef".repeat(4)), true), (digest("0".repeat(63)), false),
                                    (digest("0".repeat(65)), false), (digest("F".repeat(64)), false),
                                    (digest("g".repeat(64)), false), (format!("SHA256:{}", "0".repeat(64)), false),
                                    (format!("sha512:{}", "0".repeat(64)), false), (format!("sha256{}", "0".repeat(64)), false),
                                    (format!("{}\n", digest("0".repeat(64))), false), (String::new(), false)],
        TextPattern::Label => {
            let mut cases = owned(&[("a", true), ("0", true), ("a.b-c", true), ("0-", true), ("a.", true), ("", false),
                                    ("-a", false), (".a", false), ("A", false), ("aA", false), ("a_b", false),
                                    ("a b", false), ("a:b", false), ("a\n", false), ("\u{e9}", false)]);
            cases.extend([("a".repeat(63), true), ("a".repeat(64), false), (format!("0{}", "-".repeat(62)), true)]);
            cases
        }
        TextPattern::Subject => owned(&[("system:serviceaccount:a:b", true), ("system:serviceaccount:unit-namespace:campaign", true),
                                        ("system:serviceaccount:a.b-c:d.e-f", true), ("system:serviceaccount:-:.", true),
                                        ("system:serviceaccount::b", false), ("system:serviceaccount:a:", false),
                                        ("system:serviceaccount:a", false), ("system:serviceaccount:a:b:c", false),
                                        ("system:serviceaccount:A:b", false), ("System:serviceaccount:a:b", false),
                                        ("system:serviceaccount:a_b:c", false), ("xsystem:serviceaccount:a:b", false),
                                        ("system:serviceaccount:a:b ", false)]),
        TextPattern::Instant => owned(&[("2026-09-08T00:10:00Z", true), ("0000-00-00T00:00:00Z", true),
                                        ("9999-99-99T99:99:99Z", true), ("2026-09-08T00:10:00", false),
                                        ("2026-09-08t00:10:00Z", false), ("2026-09-08T00:10:00z", false),
                                        ("2026-09-08 00:10:00Z", false), ("2026-9-08T00:10:00Z", false),
                                        ("2026-09-08T00:10:00.0Z", false), ("a026-09-08T00:10:00Z", false),
                                        ("2026-09-08T00:10:00ZZ", false), ("2026-09-08T00-10:00Z", false)]),
        TextPattern::Uid => {
            let mut cases = owned(&[("a", true), ("A-1", true), ("-", true), ("unit-namespace-uid", true), ("", false),
                                    ("a_b", false), ("a.b", false), ("a b", false), ("a/b", false)]);
            cases.extend([("a".repeat(128), true), ("a".repeat(129), false)]);
            cases
        }
        TextPattern::ApiVersion => owned(&[("v1", true), ("admissionregistration.k8s.io/v1", true), ("a", true),
                                           ("./-", true), ("A9", true), ("", false), ("a_b", false), ("a b", false),
                                           ("a:b", false), ("v1\n", false)]),
        TextPattern::Kind => owned(&[("Ab", true), ("a1", true), ("ValidatingAdmissionPolicy", true), ("aB9", true),
                                     ("A", false), ("1A", false), ("", false), ("A-b", false), ("A_b", false),
                                     ("A b", false)]),
    }
}

#[test]
fn each_hand_written_pattern_is_the_schema_s_at_its_boundaries() {
    // The monitor's Q-D1: each pattern written by hand agrees with CS's pattern text, compiled by i05-protocol's
    // ECMA-262 subset (`$` only at the end), on inputs at its boundaries; and each bound at its edges.
    for pattern in TEXT_PATTERNS {
        let regex = Regex::new(pattern.pattern_text()).expect("CS's pattern compiles");
        for (input, expected) in boundaries(pattern) {
            assert_eq!(pattern.matches(&input), expected, "{pattern:?} {input:?}");
            assert_eq!(regex.is_match(&JStr::new(&input)), expected, "{pattern:?} {input:?} (CS's text)");
        }
    }
    // The bounds the patterns leave open: 256 code points for the subject, 128 for apiVersion and kind.
    let subject = |length: usize| format!("system:serviceaccount:{}:b", "a".repeat(length - 24));
    let bounds = TextBounds { min: 1, max: 256, pattern: TextPattern::Subject };
    assert_eq!((subject(256).len(), subject(257).len()), (256, 257));
    assert!(TextPattern::Subject.matches(&subject(257)));
    assert!(bounds.admits(&subject(256)) && !bounds.admits(&subject(257)));
    for pattern in [TextPattern::ApiVersion, TextPattern::Kind] {
        let bounds = TextBounds { min: 1, max: 128, pattern };
        let long = |length: usize| format!("A{}", "a".repeat(length - 1));
        assert!(pattern.matches(&long(129)), "{pattern:?}");
        assert!(bounds.admits(&long(128)) && !bounds.admits(&long(129)), "{pattern:?}");
    }
    // And through the parse: a 257-character subject in the qualification namespace refuses at the form.
    let long = format!("system:serviceaccount:{PV_NAMESPACE}:{}", "a".repeat(257 - 22 - PV_NAMESPACE.len() - 1));
    assert_eq!(long.len(), 257);
    let binding = with_value(&pv_binding(), &["scope", "serviceAccountSubject"], Value::str(&long));
    assert_eq!(refused(&document(PV_NAMESPACE, &binding)), form_refusal(&["scope", "serviceAccountSubject"]));
}

#[test]
fn the_sealed_values_are_admission_v4_s_with_r10_negatives() {
    // I2D-10: the vendored admission v4 vectors' sealed values are the positive.
    let sealed = &admission_sealed();
    assert!(IP_FAMILIES.contains(&text(sealed, "ipFamily")));
    assert!(is_service_cidr(text(sealed, "ipFamily"), text(sealed, "serviceCIDR")));
    assert_eq!(IP_FAMILIES, ["IPv4", "IPv6"]);
    // ipFamily: exactly the two texts.
    for family in ["ipv4", "IPV4", "IPv4 ", "IPv5", "", "DualStack"] {
        assert_eq!(refused(&with_sealed("ipFamily", Value::str(family))), check(SEALED_FAMILY_REFUSAL), "{family}");
    }
    assert!(matches!(refused(&with_sealed("ipFamily", Value::int(4))), ConfigError::Schema(_)));
    // serviceCIDR: canonical text of the family, a prefix in range, every host bit zero.
    for (family, cidr) in [("IPv4", "10.96.0.0/12"), ("IPv4", "0.0.0.0/0"), ("IPv4", "10.96.0.1/32"), ("IPv4", "192.168.0.0/16"),
                           ("IPv6", "fd00::/8"), ("IPv6", "fd00:10:96::/112"), ("IPv6", "::/0"), ("IPv6", "2001:db8::/32"),
                           ("IPv6", "1:0:0:2::3/128"), ("IPv6", "1::1:0:0:1:1/128"), ("IPv6", "1:0:1:1:1:1:1:1/128")] {
        assert!(is_service_cidr(family, cidr), "{family} {cidr}");
    }
    for (family, cidr) in [("IPv4", "10.96.0.1/12"), ("IPv4", "010.96.0.0/12"), ("IPv4", "10.96.0.0/012"), ("IPv4", "10.96.0.0/33"),
                           ("IPv4", "10.96.0.0"), ("IPv4", "10.96.0.0/"), ("IPv4", "10.96.0/12"), ("IPv4", "256.0.0.0/8"),
                           ("IPv4", "10.96.0.0/12 "), ("IPv4", "fd00::/8"), ("IPv6", "10.96.0.0/12"), ("IPv6", "2001:DB8::/32"),
                           ("IPv6", "2001:0db8::/32"), ("IPv6", "2001:db8:0:0:0:0:0:0/32"), ("IPv6", "2001:db8::1/32"),
                           ("IPv6", "fd00::/129"), ("IPv6", "::ffff:10.0.0.0/104"), ("IPv6", "1::2:0:0:0:3/128"),
                           ("IPv6", "1:0:0:1::1:1/128"), ("IPv6", "1::1:1:1:1:1:1/128"), ("IPv6", "fd00::/+8"),
                           ("IPv5", "10.96.0.0/12")] {
        assert!(!is_service_cidr(family, cidr), "{family} {cidr}");
    }
    for cidr in ["10.96.0.1/12", "010.96.0.0/12", "fd00::/8", "10.96.0.0/33"] {
        assert_eq!(refused(&with_sealed("serviceCIDR", Value::str(cidr))), check(SEALED_CIDR_REFUSAL), "{cidr}");
    }
    let six = with_value(&with_value(&sealed_v4(), &["ipFamily"], Value::str("IPv6")), &["serviceCIDR"], Value::str("fd00:10:96::/112"));
    let (config, _) = ObserverConfig::parse_v3(&with_member(PV_NAMESPACE, &pv_binding(), "sealedAdmission", six))
        .expect("an IPv6 network");
    assert_eq!(config.sealed.map(|values| values.service_cidr), Some("fd00:10:96::/112".to_string()));
    // defaultTolerationSeconds: an integer in 0..2^53-1 (the canonical subset holds the range for every integer).
    for seconds in [0, 300, 9_007_199_254_740_991] {
        let (config, _) = ObserverConfig::parse_v3(&with_sealed("defaultTolerationSeconds", Value::int(seconds)))
            .expect("a toleration in range");
        assert_eq!(config.sealed.map(|values| values.default_toleration_seconds), Some(seconds as u64));
    }
    assert!(matches!(refused(&with_sealed("defaultTolerationSeconds", Value::str("300"))), ConfigError::Schema(_)));
    for seconds in [-1, 9_007_199_254_740_992] {
        assert!(matches!(refused(&with_sealed("defaultTolerationSeconds", Value::int(seconds))), ConfigError::Canonical(_)));
    }
    // sealedAdmission is closed.
    let extra = edited(&sealed_v4(), &["namespace"], |object, last| object.insert(last, Value::str(S1_NAMESPACE)));
    assert!(matches!(refused(&with_member(PV_NAMESPACE, &pv_binding(), "sealedAdmission", extra)), ConfigError::Schema(_)));
}

/// PV's negative 27: its path and value (document `binding`).
fn case_27() -> (Vec<String>, Value) {
    let vectors = parse(PV);
    let cases = member(&vectors, "negative").as_array().expect("the negatives are an array");
    let case = cases.iter().find(|case| text(case, "label") == CASE_27).expect("PV's negative 27");
    assert_eq!(text(case, "document"), "binding");
    let path = member(case, "path").as_array().expect("a path").iter().map(|step| step.as_str().expect("text").to_string());
    (path.collect(), member(case, "value").clone())
}

/// I2D-8 for one binding: the unmutated v3 document parses; the mutated one refuses with the namespace check's own
/// text; the namespace check runs first; the qualification namespace equals the binding's `namespace.name`, and the
/// subject's namespace segment matches.
fn replays_case_27(namespace: &str, binding: &Value) {
    let (path, value) = case_27();
    let path: Vec<&str> = path.iter().map(String::as_str).collect();
    assert_eq!(path, ["scope", "namespace"]);
    assert_eq!(text(member(binding, "namespace"), "name"), namespace);
    let subject = text(member(binding, "scope"), "serviceAccountSubject");
    assert_eq!(subject.strip_prefix("system:serviceaccount:").and_then(|rest| rest.split_once(':')).map(|(space, _)| space),
               Some(namespace));
    assert!(ObserverConfig::parse_v3(&document(namespace, binding)).is_ok(), "{namespace}: the unmutated document parses");
    // The derivation rule: the one change at the path, nothing recomputed.
    let mutated = with_value(binding, &path, value.clone());
    assert!(!json::json_eq(&mutated, binding));
    let held = binding.get("scope").and_then(|scope| scope.get("namespace")).expect("present").clone();
    assert!(json::json_eq(&with_value(&mutated, &path, held), binding), "one change only");
    assert_eq!(refused(&document(namespace, &mutated)), check(BINDING_NAMESPACES_REFUSAL), "{namespace}");
    // The namespace check first: with the form and the sealed values broken too, the refusal is still the namespaces';
    // without the mutation the same document refuses at the form.
    let broken = |binding: &Value| with_value(binding, &["enforcementPins", "hostPreflightDigest"], Value::str("x"));
    let sealed = with_value(&sealed_v4(), &["ipFamily"], Value::str("IPv5"));
    assert_eq!(refused(&with_member(namespace, &broken(&mutated), "sealedAdmission", sealed.clone())),
               check(BINDING_NAMESPACES_REFUSAL));
    assert_eq!(refused(&with_member(namespace, &broken(binding), "sealedAdmission", sealed)),
               form_refusal(&["enforcementPins", "hostPreflightDigest"]));
    // In serve, every refusal of the parse is status 13.
    assert_eq!(status::CONFIG_CHECK, 13);
}

#[test]
fn pv_s_case_27_refuses_at_the_namespace_check() {
    // Q-I01B2D-3 (a): PV's own case 27 (profile v1 is still the wire's profile).
    replays_case_27(PV_NAMESPACE, &pv_binding());
}

#[test]
fn w3_s_derived_case_27_on_s1_s_triple_refuses_at_the_namespace_check() {
    // Q-I01B2D-3 (a) and I01B4's carried obligation (R181): W3's derived case 27, PV's change on S1's v2 triple.
    replays_case_27(S1_NAMESPACE, &s1_binding());
}
