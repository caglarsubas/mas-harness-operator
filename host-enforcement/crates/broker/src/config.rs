//! The capacity broker's configuration `planeon.capacity-broker-config/v1` (HE-005C: DESIGN-HE005 revision 5 section
//! 3.1 and O19, moved to HE-005C by the scope notes; the HE-005C plan's Q-HE5C-1 (a)): the parse of a verified document,
//! with section 3.1's closed members and bounds. Portable and host-tested; `main` calls it between the seal's two
//! stages, after the signature check (`signed_config`), so an unsigned document is never parsed. R10-defined
//! (`crates/effect-gate/MODEL_DEFINED.md`, the HE-005C section); the canonical subset is R70's, written again here in
//! the observer's form, since the broker links neither effect-gate nor the observer.
//!
//! Order (status 13 for every refusal): the canonical subset (ASCII, strict JSON through i05-protocol's parser, depth at
//! most 16, no float, integers 0 to 2^53-1, byte-equal to i05-protocol's canonical encoding); then the closed schema
//! (exactly the thirteen members of [`MEMBERS`], each of its JSON type, and the format); then the bounds:
//! - `workerUid` in 10000..=2147483647 (HS53 :452's signed uid); the worker's gid is `workerUid` too (H5E-13);
//! - `workerScriptPath`, `workerInterpreterPath` and `gateExecutablePath`: absolute, normalised, at most 255 bytes;
//! - `workerScriptVerityDigest`: `sha256:` and 64 lowercase hex digits, the digest W5 compares with its measure of the
//!   opened script (hash algorithm 1, SHA-256);
//! - `peerQualificationDigest` (O18) and the four binding digests the broker accepts (`brokerManifestDigest`,
//!   `brokerExecutableDigest`, `workerManifestDigest`, `workerArtifactDigest`): `sha256:` and 64 lowercase hex digits;
//! - `bracketPeriodSeconds`, NP-9's signed period P, in 140..=3600 (section 3.6, H5E-15: two minimum brackets at least,
//!   60 observer cycles at most);
//! - `operationDeadlineSeconds` in 1..=900 (O21: the whole operation within 900 s).
//!
//! Nothing a DISPATCH carries selects any of these: each is compared, never chosen by a request (section 3.1). The
//! interpreter's location is a record binding only; nothing reads the worker's executable link (H5F-3). The checked
//! configuration's fields are private, read through its accessors, and [`BrokerConfig::parse`] is its one maker.

use i05_protocol::json::{self, Object, Value};

/// The document's format, and the signature's domain.
pub const FORMAT: &str = "planeon.capacity-broker-config/v1";
/// The deepest nesting of the canonical subset.
pub const MAX_DEPTH: usize = 16;
/// The largest integer of the canonical subset, 2^53 - 1.
pub const MAX_INTEGER: u64 = (1 << 53) - 1;
/// The longest absolute location.
pub const MAX_PATH_BYTES: usize = 255;
/// The worker's uid bounds (section 3.1; HS53 :452).
pub const WORKER_UID_FIRST: u32 = 10_000;
pub const WORKER_UID_LAST: u32 = 2_147_483_647;
/// NP-9's signed period P, in seconds (section 3.6, H5E-15).
pub const BRACKET_PERIOD_FIRST: u64 = 140;
pub const BRACKET_PERIOD_LAST: u64 = 3_600;
/// The operation's deadline, in seconds (O21).
pub const OPERATION_DEADLINE_FIRST: u64 = 1;
pub const OPERATION_DEADLINE_LAST: u64 = 900;
/// A digest's prefix: `sha256:`, then 64 lowercase hex digits.
pub const DIGEST_PREFIX: &str = "sha256:";
/// The verity hash algorithm the `sha256:` prefix of `workerScriptVerityDigest` names (algorithm 1, SHA-256).
pub const VERITY_SHA256: u16 = 1;

/// The root's members, exactly (section 3.1).
pub const MEMBERS: [&str; 13] = ["format", "workerUid", "workerScriptPath", "workerScriptVerityDigest",
                                 "workerInterpreterPath", "gateExecutablePath", "peerQualificationDigest",
                                 "bracketPeriodSeconds", "operationDeadlineSeconds", "brokerManifestDigest",
                                 "brokerExecutableDigest", "workerManifestDigest", "workerArtifactDigest"];

/// The checked configuration (section 3.1): every member is the signed document's, and nothing is defaulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerConfig {
    worker_uid: u32,
    worker_script_path: String,
    worker_script_verity_digest: [u8; 32],
    worker_interpreter_path: String,
    gate_executable_path: String,
    peer_qualification_digest: String,
    bracket_period_seconds: u64,
    operation_deadline_seconds: u64,
    broker_manifest_digest: String,
    broker_executable_digest: String,
    worker_manifest_digest: String,
    worker_artifact_digest: String,
}

/// Why a document is refused (every case is status 13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Outside the canonical subset.
    Canonical(&'static str),
    /// The closed schema: a member missing or unknown, a member of another JSON type, or another format.
    Schema(&'static str),
    /// A bound of section 3.1.
    Check(&'static str),
}

/// `sha256:` and 64 lowercase hex digits.
pub fn is_digest(text: &str) -> bool {
    text.strip_prefix(DIGEST_PREFIX).is_some_and(|hex| hex.len() == 64 && lower_hex(hex))
}

fn lower_hex(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One lowercase hex digit's value.
fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => byte.checked_sub(b'0'),
        b'a'..=b'f' => byte.checked_sub(b'a').and_then(|value| value.checked_add(10)),
        _ => None,
    }
}

/// A digest's 32 bytes, when `text` is `sha256:` and 64 lowercase hex digits.
pub fn digest_bytes(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix(DIGEST_PREFIX).filter(|hex| hex.len() == 64 && lower_hex(hex))?;
    let mut bytes = [0u8; 32];
    for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let (high, low) = match pair {
            [high, low] => (nibble(*high)?, nibble(*low)?),
            _ => return None,
        };
        *byte = high.checked_mul(16)?.checked_add(low)?;
    }
    Some(bytes)
}

/// An absolute, normalised location of at most 255 bytes: it starts with `/`, has no empty, `.` or `..` component, does
/// not end with `/` and holds no NUL.
pub fn is_normal_path(text: &str) -> bool {
    text.len() <= MAX_PATH_BYTES
        && !text.contains('\0')
        && text.strip_prefix('/').is_some_and(|rest| {
            !rest.is_empty() && rest.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
        })
}

/// The document as a JSON value, if it is in the canonical subset.
fn canonical_value(document: &[u8]) -> Result<Value, ConfigError> {
    if !document.is_ascii() {
        return Err(ConfigError::Canonical("the document holds a byte outside ASCII"));
    }
    let text = std::str::from_utf8(document).map_err(|_| ConfigError::Canonical("the document is not UTF-8"))?;
    let value = json::parse(text).map_err(|_| ConfigError::Canonical("the document is not strict JSON"))?;
    if json::depth(&value) > MAX_DEPTH {
        return Err(ConfigError::Canonical("the document nests deeper than 16"));
    }
    if json::contains_float(&value) {
        return Err(ConfigError::Canonical("the document holds a float"));
    }
    let mut stack = vec![&value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Int(int) if int.is_negative() || int.to_u64().is_none_or(|number| number > MAX_INTEGER) => {
                return Err(ConfigError::Canonical("an integer outside 0..=2^53-1"));
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(object) => stack.extend(object.iter().map(|(_, member)| member)),
            _ => {}
        }
    }
    let encoded = json::canonical(&value).map_err(|_| ConfigError::Canonical("the document has no canonical form"))?;
    if encoded != document {
        return Err(ConfigError::Canonical("the document is not its canonical encoding"));
    }
    Ok(value)
}

/// The root: an object holding exactly [`MEMBERS`] (the strict parser refuses a duplicate member).
fn closed(value: &Value) -> Result<&Object, ConfigError> {
    let Some(object) = value.as_object() else { return Err(ConfigError::Schema("the document is not an object")) };
    if object.len() != MEMBERS.len() || !MEMBERS.iter().all(|member| object.get(member).is_some()) {
        return Err(ConfigError::Schema("the document does not hold exactly the thirteen members of section 3.1"));
    }
    Ok(object)
}

/// A text member, or `refusal` (the schema).
fn text<'a>(object: &'a Object, key: &str, refusal: &'static str) -> Result<&'a str, ConfigError> {
    object.get(key).and_then(Value::as_str).ok_or(ConfigError::Schema(refusal))
}

/// An integer member, or `refusal` (the schema).
fn integer(object: &Object, key: &str, refusal: &'static str) -> Result<u64, ConfigError> {
    object.get(key).and_then(Value::as_int).and_then(|int| int.to_u64()).ok_or(ConfigError::Schema(refusal))
}

/// A text member holding an absolute, normalised location: `schema` if it is not text, `bound` if it is not such a
/// location.
fn location(object: &Object, key: &str, schema: &'static str, bound: &'static str) -> Result<String, ConfigError> {
    let value = text(object, key, schema)?;
    if !is_normal_path(value) {
        return Err(ConfigError::Check(bound));
    }
    Ok(value.to_string())
}

/// A text member holding a digest: `schema` if it is not text, `bound` if it is not `sha256:` and 64 lowercase hex.
fn digest(object: &Object, key: &str, schema: &'static str, bound: &'static str) -> Result<String, ConfigError> {
    let value = text(object, key, schema)?;
    if !is_digest(value) {
        return Err(ConfigError::Check(bound));
    }
    Ok(value.to_string())
}

/// An integer member inside `first..=last`: `schema` if it is not an integer, `bound` if it is outside.
fn bounded(object: &Object, key: &str, first: u64, last: u64, schema: &'static str, bound: &'static str)
    -> Result<u64, ConfigError> {
    let value = integer(object, key, schema)?;
    if !(first..=last).contains(&value) {
        return Err(ConfigError::Check(bound));
    }
    Ok(value)
}

impl BrokerConfig {
    /// Checks a verified document (see the module documentation) and returns the checked configuration; every refusal
    /// is status 13. The one maker of a [`BrokerConfig`].
    pub fn parse(document: &[u8]) -> Result<BrokerConfig, ConfigError> {
        let value = canonical_value(document)?;
        let root = closed(&value)?;
        if text(root, "format", "format is not text")? != FORMAT {
            return Err(ConfigError::Schema("the document's format is not planeon.capacity-broker-config/v1"));
        }
        let uid = bounded(root, "workerUid", u64::from(WORKER_UID_FIRST), u64::from(WORKER_UID_LAST),
                          "workerUid is not an integer", "workerUid is outside 10000..=2147483647")?;
        let Ok(worker_uid) = u32::try_from(uid) else {
            return Err(ConfigError::Check("workerUid is outside 10000..=2147483647"));
        };
        let worker_script_path = location(root, "workerScriptPath", "workerScriptPath is not text",
                                          "workerScriptPath is not an absolute normalised location of at most 255 bytes")?;
        let verity = text(root, "workerScriptVerityDigest", "workerScriptVerityDigest is not text")?;
        let Some(worker_script_verity_digest) = digest_bytes(verity) else {
            return Err(ConfigError::Check("workerScriptVerityDigest is not sha256: and 64 lowercase hex digits"));
        };
        let worker_interpreter_path =
            location(root, "workerInterpreterPath", "workerInterpreterPath is not text",
                     "workerInterpreterPath is not an absolute normalised location of at most 255 bytes")?;
        let gate_executable_path =
            location(root, "gateExecutablePath", "gateExecutablePath is not text",
                     "gateExecutablePath is not an absolute normalised location of at most 255 bytes")?;
        let peer_qualification_digest =
            digest(root, "peerQualificationDigest", "peerQualificationDigest is not text",
                   "peerQualificationDigest is not sha256: and 64 lowercase hex digits")?;
        let bracket_period_seconds =
            bounded(root, "bracketPeriodSeconds", BRACKET_PERIOD_FIRST, BRACKET_PERIOD_LAST,
                    "bracketPeriodSeconds is not an integer", "bracketPeriodSeconds is outside 140..=3600")?;
        let operation_deadline_seconds =
            bounded(root, "operationDeadlineSeconds", OPERATION_DEADLINE_FIRST, OPERATION_DEADLINE_LAST,
                    "operationDeadlineSeconds is not an integer", "operationDeadlineSeconds is outside 1..=900")?;
        let broker_manifest_digest =
            digest(root, "brokerManifestDigest", "brokerManifestDigest is not text",
                   "brokerManifestDigest is not sha256: and 64 lowercase hex digits")?;
        let broker_executable_digest =
            digest(root, "brokerExecutableDigest", "brokerExecutableDigest is not text",
                   "brokerExecutableDigest is not sha256: and 64 lowercase hex digits")?;
        let worker_manifest_digest =
            digest(root, "workerManifestDigest", "workerManifestDigest is not text",
                   "workerManifestDigest is not sha256: and 64 lowercase hex digits")?;
        let worker_artifact_digest =
            digest(root, "workerArtifactDigest", "workerArtifactDigest is not text",
                   "workerArtifactDigest is not sha256: and 64 lowercase hex digits")?;
        Ok(BrokerConfig {
            worker_uid,
            worker_script_path,
            worker_script_verity_digest,
            worker_interpreter_path,
            gate_executable_path,
            peer_qualification_digest,
            bracket_period_seconds,
            operation_deadline_seconds,
            broker_manifest_digest,
            broker_executable_digest,
            worker_manifest_digest,
            worker_artifact_digest,
        })
    }

    /// `workerUid`: the worker's uid, which is its gid too (H5E-13).
    pub fn worker_uid(&self) -> u32 {
        self.worker_uid
    }

    /// `workerScriptPath`: where W5 opens the worker script.
    pub fn worker_script_path(&self) -> &str {
        &self.worker_script_path
    }

    /// `workerScriptVerityDigest`'s 32 bytes, which W5 compares with the opened script's measure under
    /// [`VERITY_SHA256`].
    pub fn worker_script_verity_digest(&self) -> &[u8; 32] {
        &self.worker_script_verity_digest
    }

    /// `workerInterpreterPath`: a record binding only (H5F-3).
    pub fn worker_interpreter_path(&self) -> &str {
        &self.worker_interpreter_path
    }

    /// `gateExecutablePath` (O10).
    pub fn gate_executable_path(&self) -> &str {
        &self.gate_executable_path
    }

    /// `peerQualificationDigest` (O18).
    pub fn peer_qualification_digest(&self) -> &str {
        &self.peer_qualification_digest
    }

    /// `bracketPeriodSeconds`, NP-9's period P (section 3.6).
    pub fn bracket_period_seconds(&self) -> u64 {
        self.bracket_period_seconds
    }

    /// `operationDeadlineSeconds` (O21).
    pub fn operation_deadline_seconds(&self) -> u64 {
        self.operation_deadline_seconds
    }

    /// `brokerManifestDigest`, a binding digest the broker accepts.
    pub fn broker_manifest_digest(&self) -> &str {
        &self.broker_manifest_digest
    }

    /// `brokerExecutableDigest`, a binding digest the broker accepts.
    pub fn broker_executable_digest(&self) -> &str {
        &self.broker_executable_digest
    }

    /// `workerManifestDigest`, a binding digest the broker accepts.
    pub fn worker_manifest_digest(&self) -> &str {
        &self.worker_manifest_digest
    }

    /// `workerArtifactDigest`, a binding digest the broker accepts.
    pub fn worker_artifact_digest(&self) -> &str {
        &self.worker_artifact_digest
    }
}
