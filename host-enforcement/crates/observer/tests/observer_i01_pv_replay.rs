//! HE-004-I01A2, unit U7 of HE-004-I01a (DESIGN-I01A sections 7, 8 and 15; owner decisions Q-HE4I1-10 (a), Q-I01A-1
//! and Q-U7-1..3 (a); MODEL_DEFINED's HE-004-I01A2 section): the I01 wire's vectors (`PV`, edge record v9's row 68)
//! replayed against R10's request checks.
//!
//! - The vendored files are edge record v9's bytes (rows 67 and 68: each sha256 and size), and the vendored schema's
//!   request definition (`CS`, `$defs.request`) is the one `i01_request` implements: its seven members, the two
//!   constants, the three text forms and the `sequence` range.
//! - `PV`'s request cases, the positive's request and its five request negatives, run at unit level, so that each
//!   negative's own refusal is seen: framing and the schema (`frame`, `request_schema`), a fresh session's chain
//!   (`Chain::check`; the positive has no previous observation), and the binding gate (`binding_gate`) with a test
//!   binding. The test binding is built from the positive's binding document: the SHA-256 of i05-protocol's canonical
//!   encoding of that document, which must be the `bindingDigest` the positive's request names (the evidence that R10's
//!   canonical form is the one `PV` was written with), and the scope's `runNonce`.
//! - The test binding is a value of this test binary only. The I01 service passes no binding (`i01_service.rs`), so
//!   through `serve` every request closes at the gate and proves nothing.
//! - Negative 1 (another operation) refuses at the schema; negatives 2 and 3 (another `runNonce`, another
//!   `bindingDigest`) pass framing, the schema and the chain and refuse only at the gate; negatives 4 and 5
//!   (sequence 2, a previous digest other than zero) refuse at the chain. The positive passes every check.
//! - R10's own framing negatives (DESIGN-I01A section 15) were all built by HE-004-I01A: `observer_i01_request`
//!   (size, bytes, strict JSON, depth, floats, integers, decoded text, the non-canonical encodings, extra and missing
//!   members), `observer_i01_wait` (a datagram over 16,384 bytes cut short, other ancillary data, a passed
//!   descriptor) and `observer_i01_service` (each receive outcome closing the session). None is new here; the last
//!   test applies the framing rules to `PV`'s positive request in other encodings than its canonical one.
//!
//! Not replayed: `PV`'s 17 observation negatives and 5 binding negatives. Those cases also read the proxy profile,
//! `architecture/proxy-contract-inputs/vectors.json`, which no edge record registers (edge record v9's replay-scope
//! note), so replaying them in R10 needs a later record first; the observation side is I01b's.

use i05_protocol::json::{self, JStr, Value};
use i05_protocol::sha256;
use planeon_observer::i01_request::{binding_gate, check_request, frame, request_schema, Chain, I01Binding, I01Request,
                                    RequestRefusal, MAX_INTEGER, MEMBERS, OBSERVE_POLICY, REQUEST_SCHEMA, ZERO_DIGEST};

const PV: &str = include_str!("../../../contracts/i01-v1/vectors.json");
const CS: &str = include_str!("../../../contracts/i01-v1/channel.schema.json");
/// Edge record v9's rows 67 and 68: the schema's and the vectors' sha256 and size.
const CS_PIN: (&str, usize) = ("fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e", 41_771);
const PV_PIN: (&str, usize) = ("1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124", 14_486);
/// `PV`'s five request negatives, in file order.
const REQUEST_NEGATIVES: [&str; 5] = ["negative-1-request-operation", "negative-2-request-runNonce",
                                      "negative-3-request-bindingDigest", "negative-4-request-sequence",
                                      "negative-5-request-previousObservationDigest"];
/// The chain's refusal of a session's first request.
const FIRST: RequestRefusal = RequestRefusal::Chain("a session's first request is sequence 1 after the zero digest");

fn parse(text: &str) -> Value {
    json::parse(text).expect("the vendored JSON parses")
}

fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).unwrap_or_else(|| panic!("{name} is missing"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    member(value, name).as_str().unwrap_or_else(|| panic!("{name} is not text"))
}

fn integer(value: &Value, name: &str) -> u64 {
    member(value, name).as_int().and_then(|int| int.to_u64()).unwrap_or_else(|| panic!("{name} is not a count"))
}

fn texts<'a>(value: &'a Value, name: &str) -> Vec<&'a str> {
    let items = member(value, name).as_array().unwrap_or_else(|| panic!("{name} is not an array"));
    items.iter().map(|item| item.as_str().expect("a text item")).collect()
}

fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

fn vectors() -> Value {
    parse(PV)
}

fn positive(vectors: &Value) -> &Value {
    member(vectors, "positive")
}

/// A member of an object, by name, for writing.
fn member_mut<'a>(node: &'a mut Value, name: &JStr) -> &'a mut Value {
    match node {
        Value::Object(object) => object.get_key_mut(name).expect("the path's member exists"),
        _ => panic!("PV's paths name object members"),
    }
}

/// A copy of `document` with the member at `path` (object member names) replaced by `new`.
fn with_value(document: &Value, path: &[Value], new: &Value) -> Value {
    let name = |step: &Value| match step {
        Value::Str(name) => name.clone(),
        _ => panic!("PV's paths name object members"),
    };
    let mut copy = document.clone();
    let (last, parents) = path.split_last().expect("a non-empty path");
    let mut node = &mut copy;
    for step in parents {
        node = member_mut(node, &name(step));
    }
    match node {
        Value::Object(object) => {
            let last = name(last);
            assert!(object.contains_key(&last), "a negative replaces an existing member");
            object.insert(last, new.clone());
        }
        _ => panic!("PV's paths name object members"),
    }
    copy
}

/// The test binding: HE-008's binding as the gate compares it, built from `PV`'s positive binding document. A value of
/// this test binary only; nothing in the observer builds one.
#[cfg(test)]
fn test_binding(positive: &Value) -> I01Binding {
    let binding = member(positive, "binding");
    I01Binding { binding_digest: sha256::prefixed(&canonical(binding)),
                 run_nonce: text(member(binding, "scope"), "runNonce").to_string() }
}

/// `PV`'s request negatives, each with its request: the positive's with the negative's one change.
fn request_negatives(vectors: &Value) -> Vec<(String, Value)> {
    let request = member(positive(vectors), "request");
    let cases = member(vectors, "negative").as_array().expect("the negatives are an array");
    cases.iter()
         .filter(|case| text(case, "document") == "request")
         .map(|case| {
             let path = member(case, "path").as_array().expect("a path");
             (text(case, "label").to_string(), with_value(request, path, member(case, "value")))
         })
         .collect()
}

/// Each request negative's own refusal: the request rule it breaks.
fn expected(label: &str) -> RequestRefusal {
    match label {
        "negative-1-request-operation" => RequestRefusal::Schema("another operation"),
        "negative-2-request-runNonce" | "negative-3-request-bindingDigest" => RequestRefusal::Binding,
        "negative-4-request-sequence" | "negative-5-request-previousObservationDigest" => FIRST,
        other => panic!("{other} is not one of PV's request negatives"),
    }
}

#[test]
fn the_vendored_files_are_edge_v9_s_and_the_case_counts_hold() {
    assert_eq!((hex(CS.as_bytes()), CS.len()), (CS_PIN.0.to_string(), CS_PIN.1));
    assert_eq!((hex(PV.as_bytes()), PV.len()), (PV_PIN.0.to_string(), PV_PIN.1));
    let vectors = vectors();
    assert_eq!(text(&vectors, "evidenceClass"), "UNIT_VERIFICATION_ONLY");
    assert_eq!(member(&vectors, "nativeAcceptance").as_bool(), Some(false));
    let positive = positive(&vectors);
    for name in ["binding", "request", "observation"] {
        assert!(member(positive, name).as_object().is_some(), "{name}");
    }
    assert!(member(positive, "previous").is_null(), "the positive's request is a session's first");
    // 27 negatives: 5 on the request (replayed), 17 on the observation and 5 on the binding (not replayed).
    let cases = member(&vectors, "negative").as_array().expect("the negatives are an array");
    let count = |document: &str| cases.iter().filter(|case| text(case, "document") == document).count();
    assert_eq!((cases.len(), count("request"), count("observation"), count("binding")), (27, 5, 17, 5));
    // Each request negative changes one member of the request.
    let labels: Vec<&str> = cases.iter().filter(|case| text(case, "document") == "request")
                                 .map(|case| text(case, "label")).collect();
    assert_eq!(labels, REQUEST_NEGATIVES);
    for case in cases.iter().filter(|case| text(case, "document") == "request") {
        let path = texts(case, "path");
        assert!(path.len() == 1 && MEMBERS.contains(&path[0]), "{path:?}");
    }
}

#[test]
fn the_schema_s_request_definition_is_the_one_i01_request_implements() {
    let schema = parse(CS);
    let request = member(member(&schema, "$defs"), "request");
    assert_eq!(text(request, "type"), "object");
    assert_eq!(member(request, "additionalProperties").as_bool(), Some(false));
    let mut required = texts(request, "required");
    required.sort_unstable();
    assert_eq!(required, MEMBERS);
    let properties = member(request, "properties");
    let mut named: Vec<&str> = properties.as_object().expect("the properties are an object").iter()
                                         .map(|(name, _)| name.as_str().expect("a text name")).collect();
    named.sort_unstable();
    assert_eq!(named, MEMBERS);
    assert_eq!(text(member(properties, "schemaVersion"), "const"), REQUEST_SCHEMA);
    assert_eq!(text(member(properties, "operation"), "const"), OBSERVE_POLICY);
    // The text forms `i01_request` checks: a sha256 digest, a run nonce of 1 to 63 characters, 64 hexadecimal digits.
    for (name, pattern, longest) in [("bindingDigest", "^sha256:[0-9a-f]{64}$", 71),
                                     ("previousObservationDigest", "^sha256:[0-9a-f]{64}$", 71),
                                     ("runNonce", "^[a-z0-9][a-z0-9.-]{0,62}$", 63),
                                     ("challenge", "^[0-9a-f]{64}$", 64)] {
        let property = member(properties, name);
        assert_eq!((text(property, "type"), text(property, "pattern")), ("string", pattern), "{name}");
        assert_eq!((integer(property, "minLength"), integer(property, "maxLength")), (1, longest), "{name}");
    }
    let sequence = member(properties, "sequence");
    assert_eq!(text(sequence, "type"), "integer");
    assert_eq!((integer(sequence, "minimum"), integer(sequence, "maximum")), (1, MAX_INTEGER));
    assert_eq!(ZERO_DIGEST, format!("sha256:{}", "0".repeat(64)));
}

#[test]
fn pv_s_positive_request_passes_every_check_with_the_test_binding() {
    let vectors = vectors();
    let positive = positive(&vectors);
    let request = member(positive, "request");
    // The positive's request names the digest of the binding document's canonical encoding, and the scope's nonce.
    let bound = test_binding(positive);
    assert_eq!(bound.binding_digest, text(request, "bindingDigest"));
    assert_eq!(bound.run_nonce, text(request, "runNonce"));
    let bytes = canonical(request);
    let framed = frame(&bytes, false).expect("the positive's request frames");
    let checked = request_schema(&framed).expect("the positive's request has the schema's form");
    assert_eq!(checked, I01Request { binding_digest: text(request, "bindingDigest").to_string(),
                                     run_nonce: text(request, "runNonce").to_string(),
                                     challenge: text(request, "challenge").to_string(),
                                     sequence: integer(request, "sequence"),
                                     previous_digest: text(request, "previousObservationDigest").to_string() });
    assert_eq!((checked.sequence, checked.previous_digest.as_str()), (1, ZERO_DIGEST));
    assert_eq!(Chain::default().check(&checked), Ok(()));
    assert_eq!(binding_gate(&checked, Some(&bound)), Ok(()));
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), Some(&bound)), Ok(checked));
    // I01a's case: no binding exists, so even the positive closes at the gate.
    assert_eq!(check_request(&bytes, false, &mut Chain::default(), None), Err(RequestRefusal::Binding));
}

#[test]
fn each_request_negative_refuses_at_its_own_step() {
    let vectors = vectors();
    let bound = test_binding(positive(&vectors));
    let negatives = request_negatives(&vectors);
    assert_eq!(negatives.len(), REQUEST_NEGATIVES.len());
    for (label, request) in &negatives {
        let refusal = expected(label);
        let bytes = canonical(request);
        // Every request negative is well framed: it changes one member's value.
        let framed = frame(&bytes, false).unwrap_or_else(|error| panic!("{label} frames: {error:?}"));
        let schema = request_schema(&framed);
        match refusal {
            RequestRefusal::Schema(_) => assert_eq!(schema, Err(refusal), "{label}"),
            RequestRefusal::Chain(_) => {
                let checked = schema.unwrap_or_else(|error| panic!("{label} has the schema's form: {error:?}"));
                assert_eq!(Chain::default().check(&checked), Err(refusal), "{label}");
                // Its binding members are the positive's, so the gate alone would pass it.
                assert_eq!(binding_gate(&checked, Some(&bound)), Ok(()), "{label}");
            }
            RequestRefusal::Binding => {
                let checked = schema.unwrap_or_else(|error| panic!("{label} has the schema's form: {error:?}"));
                assert_eq!(Chain::default().check(&checked), Ok(()), "{label}");
                assert_eq!(binding_gate(&checked, Some(&bound)), Err(refusal), "{label}");
                // The changed member is the refusal's cause: a binding naming it would pass the request.
                let named = I01Binding { binding_digest: checked.binding_digest.clone(),
                                         run_nonce: checked.run_nonce.clone() };
                assert_ne!(named, bound, "{label}");
                assert_eq!(binding_gate(&checked, Some(&named)), Ok(()), "{label}");
            }
            other => panic!("{label}: no request negative refuses at {other:?}"),
        }
        // The whole check, in its order, with the test binding and without one (I01a's case): the same refusal.
        assert_eq!(check_request(&bytes, false, &mut Chain::default(), Some(&bound)), Err(refusal), "{label}");
        assert_eq!(check_request(&bytes, false, &mut Chain::default(), None), Err(refusal), "{label}");
    }
}

#[test]
fn the_positive_request_in_other_encodings_refuses_at_framing() {
    let vectors = vectors();
    let request = member(positive(&vectors), "request");
    let bound = test_binding(positive(&vectors));
    let encoded = String::from_utf8(canonical(request)).expect("UTF-8");
    // The members in the vectors file's order (schemaVersion first), compactly: not sorted, so not canonical.
    let object = request.as_object().expect("the request is an object");
    let in_order: Vec<String> = object.iter()
        .map(|(name, value)| format!("{}:{}", String::from_utf8(canonical(&Value::Str(name.clone()))).expect("UTF-8"),
                                     String::from_utf8(canonical(value)).expect("UTF-8")))
        .collect();
    let in_order = format!("{{{}}}", in_order.join(","));
    assert_ne!(in_order, encoded, "the file's order is not the sorted one");
    for form in [in_order.clone(), in_order.replace("\":", "\": "), encoded.replace(",\"", ", \""),
                 encoded.replace("\":", "\": "), format!(" {encoded}")] {
        assert_eq!(check_request(form.as_bytes(), false, &mut Chain::default(), Some(&bound)),
                   Err(RequestRefusal::Canonical), "{form}");
    }
    // A line end (the vectors file's own layout) is not printable ASCII.
    for form in [format!("{encoded}\n"), encoded.replacen(",\"", ",\n  \"", 1)] {
        assert_eq!(check_request(form.as_bytes(), false, &mut Chain::default(), Some(&bound)),
                   Err(RequestRefusal::Bytes), "{form}");
    }
    assert!(check_request(encoded.as_bytes(), false, &mut Chain::default(), Some(&bound)).is_ok());
}
