//! The I01 request checks (HE-004-I01a DESIGN-I01A sections 7 and 8; owner decision Q-I01A-3 (a); MODEL_DEFINED's
//! HE-004-I01a section): a pure logic module without child modules, under B1's logic rule with its own whitelist
//! (`tools/gate.py`). Every function is total; a refusal names the step that refused, and the I01 service closes the
//! session on any of them (none is a status).
//!
//! - Framing: one datagram of 1 to 16,384 bytes, not cut short (gate-sys's 16,385-byte buffer shows a longer one);
//!   every byte printable ASCII (0x20-0x7E); one strict JSON value (i05-protocol's parser refuses a duplicate key, a
//!   non-finite constant and trailing data); no node below depth 16, the root being at depth 0; no float; no integer
//!   past 2^53 - 1 in magnitude; every decoded string and member name printable ASCII, so no escape can carry a control
//!   character; and the bytes equal to the value's canonical encoding (sorted keys, compact separators, no other escape
//!   or number form). Under these rules that encoding is i05-protocol's and the I01 oracle's `json.dumps` form.
//! - The schema, `planeon.internal.policy-observation-request/v1`: exactly its seven members, each of its type and form
//!   (`sequence` an integer from 1 to 2^53 - 1).
//! - The chain, per session: a session's first request carries sequence 1 and the all-zero previous digest; a later one
//!   would carry the next sequence, a challenge other than its predecessor's and the digest of the last answer, and
//!   I01a answers nothing, so no later request passes.
//! - The binding gate: `bindingDigest` and `runNonce` must equal HE-008's binding. I01a has none (the observer's
//!   configuration holds no binding member), so the gate refuses every request; the tests drive it with a test binding.

use i05_protocol::json::{self, Object, Value};

/// The largest request datagram.
pub const REQUEST_LIMIT: usize = 16_384;
/// The deepest node allowed, the root being at depth 0.
pub const REQUEST_DEPTH: usize = 16;
/// The largest integer magnitude, 2^53 - 1.
pub const MAX_INTEGER: u64 = (1 << 53) - 1;
/// The request's schema version and operation (contract identifiers).
pub const REQUEST_SCHEMA: &str = "planeon.internal.policy-observation-request/v1";
pub const OBSERVE_POLICY: &str = "OBSERVE_POLICY";
/// The previous-observation digest of a session's first request.
pub const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
/// The request's members, in the canonical (sorted) order.
pub const MEMBERS: [&str; 7] =
    ["bindingDigest", "challenge", "operation", "previousObservationDigest", "runNonce", "schemaVersion", "sequence"];

/// Why a request was refused: the step that refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestRefusal {
    /// Empty, longer than 16,384 bytes, or cut short.
    Size,
    /// A byte outside printable ASCII.
    Bytes,
    /// Not one strict JSON value.
    Json,
    /// A node deeper than 16.
    Depth,
    /// A float.
    Float,
    /// An integer past 2^53 - 1 in magnitude.
    Integer,
    /// A decoded string or member name outside printable ASCII.
    Text,
    /// Bytes other than the value's canonical encoding.
    Canonical,
    /// The request schema, with R10's text.
    Schema(&'static str),
    /// The session's chain, with R10's text.
    Chain(&'static str),
    /// No binding, or one the request does not name.
    Binding,
}

/// A request that passed framing and the schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I01Request {
    pub binding_digest: String,
    pub run_nonce: String,
    pub challenge: String,
    pub sequence: u64,
    pub previous_digest: String,
}

/// HE-008's binding as the gate compares it (a test value in I01a: nothing builds one in the binary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I01Binding {
    pub binding_digest: String,
    pub run_nonce: String,
}

/// Whether every byte is printable ASCII.
fn printable(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
}

/// Depth, floats, integer magnitudes and decoded text, in one walk.
fn walk(value: &Value) -> Result<(), RequestRefusal> {
    let mut stack = vec![(value, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > REQUEST_DEPTH {
            return Err(RequestRefusal::Depth);
        }
        let deeper = depth.saturating_add(1);
        match node {
            Value::Float(_) => return Err(RequestRefusal::Float),
            Value::Int(int) => {
                if int.to_i128().is_none_or(|number| number.unsigned_abs() > u128::from(MAX_INTEGER)) {
                    return Err(RequestRefusal::Integer);
                }
            }
            Value::Str(text) => {
                if !printable(text.as_bytes()) {
                    return Err(RequestRefusal::Text);
                }
            }
            Value::Array(items) => stack.extend(items.iter().map(|item| (item, deeper))),
            Value::Object(object) => {
                for (name, member) in object.iter() {
                    if !printable(name.as_bytes()) {
                        return Err(RequestRefusal::Text);
                    }
                    stack.push((member, deeper));
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
    }
    Ok(())
}

/// The framing and canonical-form rules (see the module documentation); the value.
pub fn frame(bytes: &[u8], truncated: bool) -> Result<Value, RequestRefusal> {
    if truncated || bytes.is_empty() || bytes.len() > REQUEST_LIMIT {
        return Err(RequestRefusal::Size);
    }
    if !printable(bytes) {
        return Err(RequestRefusal::Bytes);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| RequestRefusal::Bytes)?;
    let value = json::parse(text).map_err(|_| RequestRefusal::Json)?;
    walk(&value)?;
    let encoded = json::canonical(&value).map_err(|_| RequestRefusal::Canonical)?;
    if encoded != bytes {
        return Err(RequestRefusal::Canonical);
    }
    Ok(value)
}

/// 64 lowercase hexadecimal digits.
fn hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `sha256:` and 64 lowercase hexadecimal digits.
fn digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(hex64)
}

/// A run nonce: 1 to 63 characters, the first a lowercase letter or a digit, the rest those, `.` or `-`.
fn run_nonce(text: &str) -> bool {
    let mut bytes = text.bytes();
    let first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    first && text.len() <= 63 && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-')
}

/// A text member of the request.
fn text_member<'a>(object: &'a Object, name: &str) -> Result<&'a str, RequestRefusal> {
    object.get(name).and_then(Value::as_str).ok_or(RequestRefusal::Schema("a request member is not text"))
}

/// The request schema: exactly the seven members, each of its type and form.
pub fn request_schema(value: &Value) -> Result<I01Request, RequestRefusal> {
    let schema = RequestRefusal::Schema;
    let object = value.as_object().ok_or(schema("a request is an object"))?;
    let named = object.iter().all(|(name, _)| name.as_str().is_some_and(|name| MEMBERS.contains(&name)));
    if object.len() != MEMBERS.len() || !named {
        return Err(schema("a request holds exactly its seven members"));
    }
    if text_member(object, "schemaVersion")? != REQUEST_SCHEMA {
        return Err(schema("another request schema version"));
    }
    if text_member(object, "operation")? != OBSERVE_POLICY {
        return Err(schema("another operation"));
    }
    let binding_digest = text_member(object, "bindingDigest")?;
    if !digest(binding_digest) {
        return Err(schema("bindingDigest is not a sha256 digest"));
    }
    let run = text_member(object, "runNonce")?;
    if !run_nonce(run) {
        return Err(schema("runNonce is not a run nonce"));
    }
    let challenge = text_member(object, "challenge")?;
    if !hex64(challenge) {
        return Err(schema("challenge is not 64 hexadecimal digits"));
    }
    let previous = text_member(object, "previousObservationDigest")?;
    if !digest(previous) {
        return Err(schema("previousObservationDigest is not a sha256 digest"));
    }
    let sequence = match object.get("sequence") {
        Some(Value::Int(int)) => int.to_u64().filter(|number| (1..=MAX_INTEGER).contains(number)),
        _ => return Err(schema("sequence is not an integer")),
    };
    let sequence = sequence.ok_or(schema("sequence is outside 1 to 2^53 - 1"))?;
    Ok(I01Request {
        binding_digest: binding_digest.to_string(),
        run_nonce: run.to_string(),
        challenge: challenge.to_string(),
        sequence,
        previous_digest: previous.to_string(),
    })
}

/// One session's request-side chain: the previous request's sequence and challenge.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Chain {
    last: Option<(u64, String)>,
}

impl Chain {
    /// A request against the session's chain; on success it becomes the previous one.
    pub fn check(&mut self, request: &I01Request) -> Result<(), RequestRefusal> {
        let chain = RequestRefusal::Chain;
        match &self.last {
            None => {
                if request.sequence != 1 || request.previous_digest != ZERO_DIGEST {
                    return Err(chain("a session's first request is sequence 1 after the zero digest"));
                }
            }
            Some((sequence, challenge)) => {
                if sequence.checked_add(1) != Some(request.sequence) {
                    return Err(chain("a request out of sequence"));
                }
                if request.challenge == *challenge {
                    return Err(chain("a challenge repeated"));
                }
                // The previous digest names the last answer, and I01a sends none.
                return Err(chain("no observation was answered"));
            }
        }
        self.last = Some((request.sequence, request.challenge.clone()));
        Ok(())
    }
}

/// The binding gate (DESIGN-I01A section 8): the request's `bindingDigest` and `runNonce` must equal the binding's;
/// without a binding every request is refused.
pub fn binding_gate(request: &I01Request, binding: Option<&I01Binding>) -> Result<(), RequestRefusal> {
    match binding {
        Some(bound) if bound.binding_digest == request.binding_digest && bound.run_nonce == request.run_nonce => Ok(()),
        _ => Err(RequestRefusal::Binding),
    }
}

/// The checks in their order: framing and the canonical form, the schema, the session's chain, then the binding gate.
pub fn check_request(bytes: &[u8], truncated: bool, chain: &mut Chain, binding: Option<&I01Binding>)
                     -> Result<I01Request, RequestRefusal> {
    let value = frame(bytes, truncated)?;
    let checked = request_schema(&value)?;
    chain.check(&checked)?;
    binding_gate(&checked, binding)?;
    Ok(checked)
}
