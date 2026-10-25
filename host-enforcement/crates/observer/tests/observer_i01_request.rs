//! HE-004-I01a DESIGN-I01A sections 7, 8 and 15 (MODEL_DEFINED's HE-004-I01a section): the I01 request checks. A
//! canonical first request passes framing, the schema and its session's chain, and the binding gate passes it only
//! with a test binding it names (no binding, I01a's case, refuses). R10's own framing negatives: an empty datagram, one
//! over 16,384 bytes and one cut short; depth 17; a non-printable or non-ASCII byte, a float, a duplicate key, an integer
//! out of range; the non-canonical encodings (unsorted keys, whitespace, a `\u` escape, a leading zero, `-0`); an extra
//! member and a missing one; each schema form; and the chain (sequence 1 after the zero digest first, and no later
//! request passing in I01a, which answers nothing). The PV replay is U7's. HE-004-I01B2 (DESIGN-I01B rev 3 section
//! 3.4, DESIGN-I01B2 section 8): the test binding is built only through `I01Binding::from_config`, over a test binding
//! document B whose digest and nonce the request names; B2 (B with one member changed) and another request nonce refuse.

use i05_protocol::json::{self, Value};
use i05_protocol::sha256;
use planeon_observer::i01_request::{binding_gate, check_request, frame, request_schema, Chain, I01Binding, I01Request,
                                    RequestRefusal, MAX_INTEGER, MEMBERS, REQUEST_DEPTH, REQUEST_LIMIT, ZERO_DIGEST};

const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const CHALLENGE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const NONCE: &str = "run-7.a";

/// A canonical request naming `digest` and `nonce`, with `sequence` and `previous`.
fn request_naming(digest: &str, nonce: &str, sequence: u64, previous: &str) -> String {
    format!("{{\"bindingDigest\":\"{digest}\",\"challenge\":\"{CHALLENGE}\",\"operation\":\"OBSERVE_POLICY\",\
             \"previousObservationDigest\":\"{previous}\",\"runNonce\":\"{nonce}\",\
             \"schemaVersion\":\"planeon.internal.policy-observation-request/v1\",\"sequence\":{sequence}}}")
}

/// A canonical request with `sequence` and `previous`, naming DIGEST and NONCE.
fn request(sequence: u64, previous: &str) -> String {
    request_naming(DIGEST, NONCE, sequence, previous)
}

/// A test binding document (the gate reads only its canonical digest and its `scope.runNonce`).
fn binding_document(nonce: &str, tenant: &str) -> Value {
    json::parse(&format!("{{\"schemaVersion\":\"planeon.internal.policy-observation-binding/v1\",\
                          \"scope\":{{\"runNonce\":\"{nonce}\",\"tenantId\":\"{tenant}\"}}}}"))
        .expect("a test binding document")
}

fn first() -> String {
    request(1, ZERO_DIGEST)
}

fn refused(bytes: &[u8]) -> RequestRefusal {
    check_request(bytes, false, &mut Chain::default(), None).expect_err("refused")
}

fn parsed(text: &str) -> I01Request {
    request_schema(&frame(text.as_bytes(), false).expect("framed")).expect("the schema")
}

#[test]
fn a_canonical_first_request_passes_every_check_but_the_absent_binding() {
    assert_eq!((REQUEST_LIMIT, REQUEST_DEPTH, MAX_INTEGER), (16_384, 16, 9_007_199_254_740_991));
    assert_eq!(MEMBERS.len(), 7);
    let bytes = first();
    let checked = parsed(&bytes);
    assert_eq!(checked, I01Request { binding_digest: DIGEST.to_string(), run_nonce: NONCE.to_string(),
                                     challenge: CHALLENGE.to_string(), sequence: 1, previous_digest: ZERO_DIGEST.to_string() });
    // I01a's case: no binding, so the gate closes every request that passes the other checks.
    assert_eq!(check_request(bytes.as_bytes(), false, &mut Chain::default(), None), Err(RequestRefusal::Binding));
    // The bound case (DESIGN-I01B rev 3 section 3.4): a binding only through from_config, over a test binding document
    // B; the request names B's digest d and nonce n, and the gate and the whole check pass it.
    let document = binding_document(NONCE, "unit-tenant");
    let bound = I01Binding::from_config(&document).expect("B has a digest and a nonce");
    let d = sha256::prefixed(&json::canonical(&document).expect("a canonical encoding"));
    assert_eq!((bound.signed_digest(), bound.signed_nonce()), (d.as_str(), NONCE));
    let named = request_naming(&d, NONCE, 1, ZERO_DIGEST);
    let checked = parsed(&named);
    assert_eq!(binding_gate(&checked, Some(&bound)), Ok(()));
    assert_eq!(check_request(named.as_bytes(), false, &mut Chain::default(), Some(&bound)), Ok(checked.clone()));
    // Another digest: B2, B with one member changed, refuses the request naming d.
    let other = I01Binding::from_config(&binding_document(NONCE, "other-tenant")).expect("B2 has a digest and a nonce");
    assert_ne!(other.signed_digest(), d);
    assert_eq!(binding_gate(&checked, Some(&other)), Err(RequestRefusal::Binding));
    assert_eq!(check_request(named.as_bytes(), false, &mut Chain::default(), Some(&other)), Err(RequestRefusal::Binding));
    // Another nonce: the request varies, not the binding; d with run-7.b refuses against B.
    let renonced = request_naming(&d, "run-7.b", 1, ZERO_DIGEST);
    assert_eq!(binding_gate(&parsed(&renonced), Some(&bound)), Err(RequestRefusal::Binding));
    assert_eq!(check_request(renonced.as_bytes(), false, &mut Chain::default(), Some(&bound)), Err(RequestRefusal::Binding));
    // No binding: unchanged.
    assert_eq!(binding_gate(&checked, None), Err(RequestRefusal::Binding));
    // from_config gives nothing without a scope.runNonce text.
    for text in ["{\"scope\":{}}", "{\"scope\":{\"runNonce\":7}}", "{}", "[]", "null"] {
        assert_eq!(I01Binding::from_config(&json::parse(text).expect("JSON")), None, "{text}");
    }
}

#[test]
fn r10_s_framing_negatives_refuse_before_the_schema() {
    let good = first();
    // Size: empty, over 16,384 bytes (gate-sys's buffer holds one byte more), cut short.
    assert_eq!(refused(b""), RequestRefusal::Size);
    let long = format!("{good}{}", " ".repeat(REQUEST_LIMIT + 1 - good.len()));
    assert_eq!(long.len(), REQUEST_LIMIT + 1);
    assert_eq!(refused(long.as_bytes()), RequestRefusal::Size);
    assert_eq!(check_request(good.as_bytes(), true, &mut Chain::default(), None), Err(RequestRefusal::Size));
    // A byte outside printable ASCII: a tab, a non-ASCII letter, a final newline.
    for bytes in [good.replacen(NONCE, "run-7\ta", 1).into_bytes(), good.replacen(NONCE, "run-7\u{e9}a", 1).into_bytes(),
                  format!("{good}\n").into_bytes()] {
        assert_eq!(refused(&bytes), RequestRefusal::Bytes, "{bytes:?}");
    }
    // Not one strict JSON value: a duplicate key, trailing data, a non-finite constant, a leading zero.
    for text in [good.replacen('{', "{\"bindingDigest\":\"x\",", 1), format!("{good}{good}"), good.replacen(":1}", ":NaN}", 1),
                 good.replacen(":1}", ":01}", 1)] {
        assert_eq!(refused(text.as_bytes()), RequestRefusal::Json, "{text}");
    }
    // Depth: the root at 0, so 16 nested arrays put a value at depth 17; 15 are allowed.
    let nested = |levels: usize| format!("{{\"x\":{}1{}}}", "[".repeat(levels), "]".repeat(levels));
    assert_eq!(frame(nested(16).as_bytes(), false).map(|_| ()), Err(RequestRefusal::Depth));
    assert!(frame(nested(15).as_bytes(), false).is_ok(), "a value at depth 16 is allowed");
    // A float; integers past 2^53 - 1 either way (2^53 - 1 itself frames).
    assert_eq!(refused(good.replacen(":1}", ":1.0}", 1).as_bytes()), RequestRefusal::Float);
    for number in ["9007199254740992", "-9007199254740992", "100000000000000000000000000000000000000000"] {
        assert_eq!(refused(format!("{{\"x\":{number}}}").as_bytes()), RequestRefusal::Integer, "{number}");
    }
    assert!(frame(b"{\"x\":9007199254740991}", false).is_ok());
    assert!(frame(b"{\"x\":-9007199254740991}", false).is_ok());
    // An escape carrying a control character, in a value and in a member name.
    assert_eq!(refused(good.replacen(NONCE, "run-7\\u0001a", 1).as_bytes()), RequestRefusal::Text);
    assert_eq!(refused(b"{\"\\u0007\":1}"), RequestRefusal::Text);
    // The non-canonical encodings: unsorted keys, whitespace, a `\u` escape of a printable letter, an escaped slash, a
    // leading zero inside a canonical-looking number is a JSON refusal above, and `-0`.
    let unsorted = good.replacen("{\"bindingDigest\"", "{\"sequence\":1,\"bindingDigest\"", 1).replacen(",\"sequence\":1}", "}", 1);
    for text in [unsorted, good.replacen(':', ": ", 1), good.replacen(',', ", ", 1), format!(" {good}"),
                 good.replacen(NONCE, "\\u0072un-7.a", 1), good.replacen("v1\"", "v1\\/\"", 1).replacen("/v1\\/", "\\/v1", 1),
                 good.replacen(":1}", ":-0}", 1)] {
        assert_eq!(refused(text.as_bytes()), RequestRefusal::Canonical, "{text}");
    }
}

#[test]
fn the_request_schema_holds_exactly_seven_members_of_their_forms() {
    let good = first();
    let schema = |text: String| match refused(text.as_bytes()) {
        RequestRefusal::Schema(_) => true,
        other => panic!("{text}: {other:?}"),
    };
    let without = |member: &str, value: &str| good.replacen(&format!(",\"{member}\":{value}"), "", 1)
        .replacen(&format!("\"{member}\":{value},"), "", 1);
    // A missing member (each one) and an extra one (sorted last, so the bytes stay canonical).
    for (member, value) in [("challenge", format!("\"{CHALLENGE}\"")), ("operation", "\"OBSERVE_POLICY\"".to_string()),
                            ("previousObservationDigest", format!("\"{ZERO_DIGEST}\"")), ("runNonce", format!("\"{NONCE}\"")),
                            ("schemaVersion", "\"planeon.internal.policy-observation-request/v1\"".to_string()),
                            ("sequence", "1".to_string())] {
        assert!(schema(without(member, &value)), "{member}");
    }
    assert!(schema(good.replacen(&format!("{{\"bindingDigest\":\"{DIGEST}\","), "{", 1)));
    assert!(schema(good.replacen(":1}", ":1,\"zz\":1}", 1)));
    assert!(schema("[1]".to_string()));
    // Each member's form.
    for (old, new) in [("\"sequence\":1}", "\"sequence\":0}"), ("\"sequence\":1}", "\"sequence\":\"1\"}"),
                       ("\"sequence\":1}", "\"sequence\":true}"), ("\"sequence\":1}", "\"sequence\":-1}"),
                       ("\"OBSERVE_POLICY\"", "\"OBSERVE\""), ("request/v1", "request/v2"),
                       ("sha256:1111", "sha256:A111"), ("sha256:1111", "sha256:111"), ("sha256:1111", "sha512:1111"),
                       (NONCE, "-run"), (NONCE, ".run"), (NONCE, "Run"), (NONCE, ""), (NONCE, "run_7"),
                       ("\"2222", "\"g222"), ("\"2222", "\"222"), ("\"sha256:0000", "\"sha256:000")] {
        assert!(schema(good.replacen(old, new, 1)), "{old} -> {new}");
    }
    assert!(schema(good.replacen(NONCE, &"r".repeat(64), 1)), "a 64-character nonce");
    assert_eq!(parsed(&good.replacen(NONCE, &"r".repeat(63), 1)).run_nonce.len(), 63);
    assert_eq!(parsed(&good.replacen(":1}", ":9007199254740991}", 1)).sequence, MAX_INTEGER);
}

#[test]
fn the_chain_starts_at_one_after_the_zero_digest_and_no_later_request_passes() {
    let mut chain = Chain::default();
    let first_step = RequestRefusal::Chain("a session's first request is sequence 1 after the zero digest");
    assert_eq!(chain.check(&parsed(&request(2, ZERO_DIGEST))), Err(first_step));
    assert_eq!(chain.check(&parsed(&request(1, DIGEST))), Err(first_step));
    assert_eq!(refused(request(2, ZERO_DIGEST).as_bytes()), first_step, "through the whole check");
    assert_eq!(chain.check(&parsed(&first())), Ok(()));
    // A later request: the next sequence, a fresh challenge, and the last answer's digest, which I01a never sends.
    let later = |sequence: u64, challenge: &str| I01Request { challenge: challenge.to_string(), sequence,
                                                               previous_digest: DIGEST.to_string(), ..parsed(&first()) };
    let fresh = "3333333333333333333333333333333333333333333333333333333333333333";
    assert_eq!(chain.check(&later(3, fresh)), Err(RequestRefusal::Chain("a request out of sequence")));
    assert_eq!(chain.check(&later(2, CHALLENGE)), Err(RequestRefusal::Chain("a challenge repeated")));
    assert_eq!(chain.check(&later(2, fresh)), Err(RequestRefusal::Chain("no observation was answered")));
}
