//! The observer's configuration `planeon.observer-config/v1` (HE-004C DESIGN-C section 11; owner decisions Q-HE4C-3
//! (a), Q-HE4C-4 (a), Q-HE4C-8 (a), Q-HE4C-13 (a)): the parse of a verified document and its lifetime check. Portable
//! and host-tested; it runs in `serve` after the signature check (`signed_config`), so an unsigned document is never
//! parsed. R10-defined (MODEL_DEFINED R107); the canonical subset and the file references are R70's rules, written
//! again here because the observer does not link effect-gate.
//!
//! Order (status 13 for every refusal): the canonical subset (ASCII, strict JSON through i05-protocol's parser, depth at
//! most 16, no float, integers 0 to 2^53-1, byte-equal to i05-protocol's canonical encoding), then the closed schema
//! (unknown members refused), then the checks: `generation` in R19's store-name form; `0 < notBefore < notAfter <=
//! 2^53-1`; `apiserverAuthority` a literal authority whose address is exactly `127.0.0.1` or `::1` (native-profile v4's
//! `i06-apiserver` values, stricter than the gate's loopback range); `qualificationNamespace` a DNS label outside B1's
//! system namespaces; every path absolute, normalised and at most 255 bytes, every pin `sha256:` and 64 lowercase hex;
//! one serving CA and an identity of 1 to 4 chain certificates and one key; `pinnedManifestHash` a pin;
//! `expectedPlugin` 1-63 characters of `[A-Za-z0-9._-]`; the enrollment nonce 32-64 lowercase hex.
//!
//! The lifetime (D1-1) is checked right after the parse, because its bounds come from the parsed document:
//! `notBefore <= now < notAfter` on the wall clock (status 14), and a wall clock before the epoch or past the year 9999
//! is status 97. While the observer runs, reaching `notAfter` exits 94 (`observe`).

use std::fmt;

use gate_sys::inet::{parse_authority, InetAddress, IpLiteral};
use i05_protocol::json::{self, Object, Value};

use crate::snapshot::SYSTEM_NAMESPACES;

/// The document's format, and the signature's domain.
pub const FORMAT: &str = "planeon.observer-config/v1";
/// The deepest nesting of the canonical subset.
pub const MAX_DEPTH: usize = 16;
/// The largest integer of the canonical subset, 2^53 - 1.
pub const MAX_INTEGER: u64 = (1 << 53) - 1;
/// The longest path.
pub const MAX_PATH_BYTES: usize = 255;
/// The most chain certificates of the identity.
pub const MAX_CHAIN_FILES: usize = 4;
/// The last second a canonical UTC time can name: 9999-12-31T23:59:59Z.
pub const MAX_WALL_SECONDS: u64 = 253_402_300_799;
/// R19's index name, which a generation may not take.
const INDEX_NAME: &str = "generations";

/// The root's members, exactly.
const MEMBERS: [&str; 8] = ["format", "generation", "validity", "apiserverAuthority", "qualificationNamespace", "credentials",
                            "admission", "enrollment"];

/// A file the configuration names: an absolute normalised path and its pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRef {
    pub path: String,
    pub sha256: String,
}

/// The credential files: the one apiserver serving CA and the `planeon:policy-observer` identity (1 to 4 chain
/// certificates, leaf first, and the PKCS#8 key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialFiles {
    pub serving_ca: FileRef,
    pub chain: Vec<FileRef>,
    pub key: FileRef,
}

/// The checked configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverConfig {
    /// R19's store-name form; kept for HE-004-I01's generation-equality rule (HS43).
    pub generation: String,
    pub not_before: u64,
    pub not_after: u64,
    /// The authority as written (the `Host` line) and its parsed address.
    pub authority: String,
    pub address: InetAddress,
    pub namespace: String,
    pub credentials: CredentialFiles,
    pub pinned_manifest_hash: String,
    pub expected_plugin: String,
    pub nonce: String,
}

/// Why a document is refused (every case is status 13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Outside the canonical subset.
    Canonical(&'static str),
    /// The closed schema.
    Schema(String),
    /// A check of section 11.
    Check(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Canonical(why) => write!(out, "configuration: {why}"),
            ConfigError::Schema(why) | ConfigError::Check(why) => write!(out, "configuration: {why}"),
        }
    }
}

/// Why the lifetime check refuses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LifetimeError {
    /// `now` is before `notBefore` or not before `notAfter` (status 14).
    Outside,
    /// The wall clock is before the epoch or past the year 9999 (status 97).
    Clock,
}

fn schema<T>(message: String) -> Result<T, ConfigError> {
    Err(ConfigError::Schema(message))
}

fn check<T>(message: String) -> Result<T, ConfigError> {
    Err(ConfigError::Check(message))
}

/// `sha256:` and 64 lowercase hex digits.
pub fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && lower_hex(hex))
}

fn lower_hex(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// An absolute, normalised path of at most 255 bytes: it starts with `/`, has no empty, `.` or `..` component, does
/// not end with `/` and holds no NUL.
pub fn is_normal_path(text: &str) -> bool {
    text.len() <= MAX_PATH_BYTES
        && !text.contains('\0')
        && text.strip_prefix('/').is_some_and(|rest| {
            !rest.is_empty() && rest.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
        })
}

/// R19's store-name form: a first character that is an ASCII letter or digit, at most 128 characters of
/// `[A-Za-z0-9._-]`, and not the index name.
pub fn is_generation(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.len() <= 128
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && text != INDEX_NAME
}

/// A DNS label: 1 to 63 characters of `[a-z0-9-]`, beginning and ending with a letter or digit.
pub fn is_dns_label(text: &str) -> bool {
    let bytes = text.as_bytes();
    let end = |byte: Option<&u8>| byte.is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    (1..=63).contains(&bytes.len())
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && end(bytes.first())
        && end(bytes.last())
}

/// `expectedPlugin`: 1 to 63 characters of `[A-Za-z0-9._-]`.
pub fn is_plugin(text: &str) -> bool {
    (1..=63).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The enrollment nonce: 32 to 64 lowercase hex digits.
pub fn is_nonce(text: &str) -> bool {
    (32..=64).contains(&text.len()) && lower_hex(text)
}

/// The apiserver address: exactly `127.0.0.1` or `::1` (Q-HE4C-13 (a)); IPv4-mapped and other loopback forms refuse.
pub fn is_apiserver_address(address: &InetAddress) -> bool {
    let mut v6_loopback = [0u8; 16];
    if let Some(last) = v6_loopback.last_mut() {
        *last = 1;
    }
    match address.ip {
        IpLiteral::V4(octets) => octets == [127, 0, 0, 1],
        IpLiteral::V6(octets) => octets == v6_loopback,
    }
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

/// An object holding exactly `members`.
fn closed<'a>(value: Option<&'a Value>, what: &str, members: &[&str]) -> Result<&'a Object, ConfigError> {
    let Some(object) = value.and_then(Value::as_object) else { return schema(format!("{what} is not an object")) };
    if object.len() != members.len() || !members.iter().all(|member| object.get(member).is_some()) {
        return schema(format!("{what} must hold exactly {}", members.join(", ")));
    }
    Ok(object)
}

fn text<'a>(object: &'a Object, key: &str, what: &str) -> Result<&'a str, ConfigError> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) => Ok(value),
        None => schema(format!("{what}.{key} is not text")),
    }
}

fn integer(object: &Object, key: &str, what: &str) -> Result<u64, ConfigError> {
    match object.get(key).and_then(Value::as_int).and_then(|int| int.to_u64()) {
        Some(value) => Ok(value),
        None => schema(format!("{what}.{key} is not an integer")),
    }
}

/// `{ "path", "sha256" }`.
fn file_ref(value: Option<&Value>, what: &str) -> Result<FileRef, ConfigError> {
    let object = closed(value, what, &["path", "sha256"])?;
    let path = text(object, "path", what)?;
    let digest = text(object, "sha256", what)?;
    if !is_normal_path(path) {
        return check(format!("{what}.path is not an absolute normalised path of at most 255 bytes"));
    }
    if !is_digest(digest) {
        return check(format!("{what}.sha256 is not sha256: and 64 lowercase hex digits"));
    }
    Ok(FileRef { path: path.to_string(), sha256: digest.to_string() })
}

/// `credentials`: `{ apiserverServingCa: <file>, observerIdentity: { chain: [<file> x 1-4], key: <file> } }`.
fn credentials(value: Option<&Value>) -> Result<CredentialFiles, ConfigError> {
    let what = "credentials";
    let object = closed(value, what, &["apiserverServingCa", "observerIdentity"])?;
    let serving_ca = file_ref(object.get("apiserverServingCa"), "credentials.apiserverServingCa")?;
    let identity = closed(object.get("observerIdentity"), "credentials.observerIdentity", &["chain", "key"])?;
    let Some(entries) = identity.get("chain").and_then(Value::as_array) else {
        return schema("credentials.observerIdentity.chain is not a list".to_string());
    };
    if entries.is_empty() || entries.len() > MAX_CHAIN_FILES {
        return check("credentials.observerIdentity.chain must hold 1 to 4 certificates".to_string());
    }
    let chain = entries
        .iter()
        .map(|entry| file_ref(Some(entry), "credentials.observerIdentity.chain"))
        .collect::<Result<Vec<_>, _>>()?;
    let key = file_ref(identity.get("key"), "credentials.observerIdentity.key")?;
    Ok(CredentialFiles { serving_ca, chain, key })
}

impl ObserverConfig {
    /// Checks a verified document (see the module documentation) and returns the typed configuration.
    pub fn parse(document: &[u8]) -> Result<ObserverConfig, ConfigError> {
        let value = canonical_value(document)?;
        let root = closed(Some(&value), "the document", &MEMBERS)?;
        if text(root, "format", "the document")? != FORMAT {
            return schema(format!("the document's format is not {FORMAT}"));
        }
        let generation = text(root, "generation", "the document")?;
        if !is_generation(generation) {
            return check("generation is not a valid store name (R19)".to_string());
        }
        let validity = closed(root.get("validity"), "validity", &["notBefore", "notAfter"])?;
        let not_before = integer(validity, "notBefore", "validity")?;
        let not_after = integer(validity, "notAfter", "validity")?;
        if not_before == 0 || not_before >= not_after || not_after > MAX_INTEGER {
            return check("validity is not 0 < notBefore < notAfter <= 2^53-1".to_string());
        }
        let authority = text(root, "apiserverAuthority", "the document")?;
        let Ok(address) = parse_authority(authority) else {
            return check("apiserverAuthority is not a literal authority with a port".to_string());
        };
        if !is_apiserver_address(&address) {
            return check("apiserverAuthority's address is not exactly 127.0.0.1 or ::1".to_string());
        }
        let namespace = text(root, "qualificationNamespace", "the document")?;
        if !is_dns_label(namespace) || SYSTEM_NAMESPACES.contains(&namespace) {
            return check("qualificationNamespace is not a DNS label outside the system namespaces".to_string());
        }
        let credentials = credentials(root.get("credentials"))?;
        let admission = closed(root.get("admission"), "admission", &["pinnedManifestHash", "expectedPlugin"])?;
        let pinned = text(admission, "pinnedManifestHash", "admission")?;
        if !is_digest(pinned) {
            return check("admission.pinnedManifestHash is not sha256: and 64 lowercase hex digits".to_string());
        }
        let plugin = text(admission, "expectedPlugin", "admission")?;
        if !is_plugin(plugin) {
            return check("admission.expectedPlugin is not 1 to 63 characters of [A-Za-z0-9._-]".to_string());
        }
        let enrollment = closed(root.get("enrollment"), "enrollment", &["nonce"])?;
        let nonce = text(enrollment, "nonce", "enrollment")?;
        if !is_nonce(nonce) {
            return check("enrollment.nonce is not 32 to 64 lowercase hex digits".to_string());
        }
        Ok(ObserverConfig {
            generation: generation.to_string(),
            not_before,
            not_after,
            authority: authority.to_string(),
            address,
            namespace: namespace.to_string(),
            credentials,
            pinned_manifest_hash: pinned.to_string(),
            expected_plugin: plugin.to_string(),
            nonce: nonce.to_string(),
        })
    }

    /// Whether `notAfter` is reached at the wall second `now` (status 94 while running).
    pub fn expired(&self, now: u64) -> bool {
        now >= self.not_after
    }
}

/// The lifetime check after the parse (D1-1): `now` is the wall clock in whole seconds since the epoch (`None` before
/// the epoch). A clock before the epoch or past the year 9999 is `Clock` (status 97); outside `[notBefore, notAfter)`
/// is `Outside` (status 14).
pub fn check_lifetime(config: &ObserverConfig, now: Option<u64>) -> Result<(), LifetimeError> {
    let Some(now) = now.filter(|now| *now <= MAX_WALL_SECONDS) else { return Err(LifetimeError::Clock) };
    if now < config.not_before || config.expired(now) {
        return Err(LifetimeError::Outside);
    }
    Ok(())
}
