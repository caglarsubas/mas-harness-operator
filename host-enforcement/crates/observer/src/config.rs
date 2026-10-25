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
//!
//! HE-004D1 (DESIGN-D1 section 5.1; owner decision Q-HE4D1-2 (a); MODEL_DEFINED R121) adds
//! `planeon.observer-config/v2`: v1's eight members with that format, plus `qualificationRecord: {path, sha256}`, parsed
//! by [`ObserverConfig::parse_with_record`] with v1's helpers and checks. The record's path must name one entry of the
//! configuration's own directory (`/etc/planeon/policy-observer`, typed `planeon_etc_t`), other than `config.json` and
//! `config.json.sig` (D1-3); anything else is status 13. [`ObserverConfig::parse`] and [`FORMAT`] are unchanged, so a v2
//! document is refused there, and `serve` called only the v2 parse (since HE-004-I01B2, only the v3 parse), so the
//! binary refuses every v1 document. The
//! signature's domain stays `planeon.observer-config/v1` (`signed_config::payload`): each document's own `format` member
//! is signed under it, so a signed v1 document never parses as v2.
//!
//! HE-004-I01B2 (DESIGN-I01B2 rev 3 sections 3 and 4; the monitor's Q-I01B2D-1 (a) and Q-I01B2D-2 (a); MODEL_DEFINED's
//! HE-004-I01B2 section) adds `planeon.observer-config/v3`, the observer configuration successor: v2's nine members
//! with that format, `generation` narrowed to 64 lowercase hex, plus `sealedAdmission` (`ipFamily`, `serviceCIDR`,
//! `defaultTolerationSeconds`) and `binding`, the release-listed binding document inline in its canonical form; eleven
//! members, closed. [`ObserverConfig::parse_v3`] is the only parse `serve` calls (v1 and v2 documents refuse, their
//! format differs), and after v2's checks it runs the load-time checks in this order, each refusing at status 13 with
//! its own text: the binding's namespaces equal `qualificationNamespace`, the binding's form against the channel
//! schema's `$defs.binding` ([`BINDING_FORM`], written from that text), its service-account subject in the
//! qualification namespace, and the sealed values' forms. Only then is the member bound, once, and kept in the private
//! field the accessor [`ObserverConfig::binding`] reads; `parse` and `parse_with_record` leave it `Value::Null` and
//! `sealed` `None`. The signature's domain stays `planeon.observer-config/v1`.

use std::fmt;

use gate_sys::inet::{parse_authority, parse_ipv4, parse_ipv6, InetAddress, IpLiteral};
use i05_protocol::json::{self, Object, Value};

use crate::signed_config::{DOCUMENT_NAME, PRODUCTION_DIR, SIGNATURE_NAME};
use crate::snapshot::SYSTEM_NAMESPACES;

/// The document's format, and the signature's domain.
pub const FORMAT: &str = "planeon.observer-config/v1";
/// The format of a document that names the qualification record (HE-004D1); its signature's domain stays [`FORMAT`].
pub const FORMAT_V2: &str = "planeon.observer-config/v2";
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
/// The v2 root's members, exactly: v1's and the qualification record.
const MEMBERS_V2: [&str; 9] = ["format", "generation", "validity", "apiserverAuthority", "qualificationNamespace",
                               "credentials", "admission", "enrollment", "qualificationRecord"];
/// The format of the observer configuration successor (HE-004-I01B2); its signature's domain stays [`FORMAT`].
pub const FORMAT_V3: &str = "planeon.observer-config/v3";
/// The v3 root's members, exactly: v2's, the sealed admission values and the binding document.
const MEMBERS_V3: [&str; 11] = ["format", "generation", "validity", "apiserverAuthority", "qualificationNamespace",
                                "credentials", "admission", "enrollment", "qualificationRecord", "sealedAdmission",
                                "binding"];
/// `sealedAdmission`'s members, exactly.
const SEALED_MEMBERS: [&str; 3] = ["ipFamily", "serviceCIDR", "defaultTolerationSeconds"];
/// The Kubernetes Service API's two `ipFamilies` values, the only `ipFamily` texts.
pub const IP_FAMILIES: [&str; 2] = ["IPv4", "IPv6"];
/// The load-time checks' own refusal texts (DESIGN-I01B2 section 4), so that a refusal names its check.
pub const BINDING_NAMESPACES_REFUSAL: &str =
    "binding namespaces: binding.scope.namespace, binding.namespace.name and qualificationNamespace are not one namespace";
pub const BINDING_SUBJECT_REFUSAL: &str =
    "binding subject: binding.scope.serviceAccountSubject is not system:serviceaccount:<qualificationNamespace>:<name>";
pub const SEALED_FAMILY_REFUSAL: &str = "sealed values: sealedAdmission.ipFamily is not IPv4 or IPv6";
pub const SEALED_CIDR_REFUSAL: &str =
    "sealed values: sealedAdmission.serviceCIDR is not a network of ipFamily in canonical text with every host bit zero";
pub const SEALED_SECONDS_REFUSAL: &str =
    "sealed values: sealedAdmission.defaultTolerationSeconds is not an integer in 0..2^53-1";
/// The prefix of the binding form's refusal, which names the member that refused.
pub const BINDING_FORM_REFUSAL: &str = "binding form:";

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

/// The checked configuration. HE-004-I01B2: i05-protocol's `Value` derives only `Clone` and `Debug`, so the derive is
/// exactly those two (I2D-2); no whole configuration is compared.
#[derive(Clone, Debug)]
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
    /// HE-004-I01B2: the binding document inline (v3's checked `binding` member), private, read only through the
    /// accessor; `Value::Null` from `parse` and `parse_with_record`.
    binding: Value,
    /// HE-004-I01B2 (Q-I01B2D-2 (a)): the sealed admission values, kept for HE-004-I01B3; `None` from `parse` and
    /// `parse_with_record`.
    pub sealed: Option<SealedValues>,
}

/// The sealed admission values of configuration v3 (`sealedAdmission`), in their checked forms: HE-008 computes them
/// with the v2 model at enrollment, and HE-004-I01B3's A2 render reads them. A forged value changes only the render's
/// hash, which must equal ADM-4's loaded hash and the binding's `enforcementPins.admissionFenceDigest`, so it fails
/// closed (MODEL_DEFINED's HE-004-I01B2 section). Never defaulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedValues {
    pub ip_family: String,
    pub service_cidr: String,
    pub default_toleration_seconds: u64,
}

/// The pattern of one text member of the channel schema's `$defs.binding` (CS, `contracts/i01-v1/channel.schema.json`),
/// written by hand from CS's pattern text ([`TextPattern::pattern_text`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextPattern {
    /// `^sha256:[0-9a-f]{64}$`
    Digest,
    /// `^[a-z0-9][a-z0-9.-]{0,62}$`
    Label,
    /// `^system:serviceaccount:[a-z0-9.-]+:[a-z0-9.-]+$`
    Subject,
    /// `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`
    Instant,
    /// `^[A-Za-z0-9-]{1,128}$`
    Uid,
    /// `^[A-Za-z0-9./-]+$`
    ApiVersion,
    /// `^[A-Za-z][A-Za-z0-9]+$`
    Kind,
}

/// The seven patterns, each once.
pub const TEXT_PATTERNS: [TextPattern; 7] = [TextPattern::Digest, TextPattern::Label, TextPattern::Subject,
                                             TextPattern::Instant, TextPattern::Uid, TextPattern::ApiVersion,
                                             TextPattern::Kind];

/// A text member: `type` string, `minLength` and `maxLength` (code points) and `pattern`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextBounds {
    pub min: usize,
    pub max: usize,
    pub pattern: TextPattern,
}

/// One member's form in CS's `$defs.binding`, as the load-time check reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingForm {
    /// `{"const": <text>}`.
    Const(&'static str),
    /// `{"type": "string", "minLength", "maxLength", "pattern"}`.
    Text(TextBounds),
    /// `{"oneOf": [<a text form>, {"type": "null"}]}`.
    TextOrNull(TextBounds),
    /// `{"type": "object", "additionalProperties": false, "required": <the names>, "properties": <the names>}`: a
    /// closed object, each member required.
    Object(&'static [(&'static str, BindingForm)]),
}

const DIGEST_TEXT: BindingForm = BindingForm::Text(TextBounds { min: 1, max: 71, pattern: TextPattern::Digest });
const LABEL_TEXT: BindingForm = BindingForm::Text(TextBounds { min: 1, max: 63, pattern: TextPattern::Label });
const UID_TEXT: BindingForm = BindingForm::Text(TextBounds { min: 1, max: 128, pattern: TextPattern::Uid });
const INSTANT_TEXT: BindingForm = BindingForm::Text(TextBounds { min: 1, max: 20, pattern: TextPattern::Instant });
const PROJECTION: BindingForm = BindingForm::Object(&[
    ("apiVersion", BindingForm::Text(TextBounds { min: 1, max: 128, pattern: TextPattern::ApiVersion })),
    ("kind", BindingForm::Text(TextBounds { min: 1, max: 128, pattern: TextPattern::Kind })),
    ("name", LABEL_TEXT),
    ("namespace", BindingForm::TextOrNull(TextBounds { min: 1, max: 63, pattern: TextPattern::Label })),
    ("uid", UID_TEXT),
    ("projectionDigest", DIGEST_TEXT),
]);

/// CS's `$defs.binding`, whole (Q-I01B2D-1 (a)): `observer_config_v3` holds this table to CS's text.
pub const BINDING_FORM: BindingForm = BindingForm::Object(&[
    ("schemaVersion", BindingForm::Const("planeon.internal.policy-observation-binding/v1")),
    ("profileDigest", DIGEST_TEXT),
    ("scope", BindingForm::Object(&[
        ("tenantId", LABEL_TEXT),
        ("environmentId", LABEL_TEXT),
        ("runNonce", LABEL_TEXT),
        ("capacityNonce", LABEL_TEXT),
        ("endpointId", LABEL_TEXT),
        ("namespace", LABEL_TEXT),
        ("serviceAccountSubject", BindingForm::Text(TextBounds { min: 1, max: 256, pattern: TextPattern::Subject })),
        ("validFrom", INSTANT_TEXT),
        ("expiresAt", INSTANT_TEXT),
    ])),
    ("observer", BindingForm::Object(&[("executableDigest", DIGEST_TEXT), ("manifestDigest", DIGEST_TEXT)])),
    ("namespace", BindingForm::Object(&[("name", LABEL_TEXT), ("uid", UID_TEXT)])),
    ("projections", BindingForm::Object(&[
        ("admissionPolicy", PROJECTION),
        ("resourceQuota", PROJECTION),
        ("limitRange", PROJECTION),
        ("serviceAccount", PROJECTION),
        ("rbac", PROJECTION),
        ("networkPolicy", PROJECTION),
        ("mutationBroker", PROJECTION),
    ])),
    ("enforcementPins", BindingForm::Object(&[
        ("admissionFenceDigest", DIGEST_TEXT),
        ("rbacClosureDigest", DIGEST_TEXT),
        ("networkEnforcementDigest", DIGEST_TEXT),
        ("hostPreflightDigest", DIGEST_TEXT),
    ])),
]);

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

/// A qualification record's path (D1-3): the configuration's own directory, then one name of `[A-Za-z0-9._-]`, neither
/// `.`, `..`, the configuration document nor its signature.
pub fn is_record_path(path: &str) -> bool {
    path.strip_prefix(PRODUCTION_DIR).and_then(|rest| rest.strip_prefix('/')).is_some_and(|name| {
        !name.is_empty()
            && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && name != "."
            && name != ".."
            && name != DOCUMENT_NAME
            && name != SIGNATURE_NAME
    })
}

/// The v3 generation (HE-004-I01B2): 64 lowercase hex digits, within R19's store-name form.
pub fn is_generation_v3(text: &str) -> bool {
    text.len() == 64 && lower_hex(text) && is_generation(text)
}

/// A byte of CS's class `[a-z0-9.-]`.
fn label_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
}

/// One segment of a service-account subject: `[a-z0-9.-]+`.
fn segment(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(label_byte)
}

impl TextPattern {
    /// CS's pattern text, exactly as `$defs.binding` writes it.
    pub fn pattern_text(self) -> &'static str {
        match self {
            TextPattern::Digest => "^sha256:[0-9a-f]{64}$",
            TextPattern::Label => "^[a-z0-9][a-z0-9.-]{0,62}$",
            TextPattern::Subject => "^system:serviceaccount:[a-z0-9.-]+:[a-z0-9.-]+$",
            TextPattern::Instant => "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
            TextPattern::Uid => "^[A-Za-z0-9-]{1,128}$",
            TextPattern::ApiVersion => "^[A-Za-z0-9./-]+$",
            TextPattern::Kind => "^[A-Za-z][A-Za-z0-9]+$",
        }
    }

    /// Whether the whole of `text` matches the pattern (the hand-written reading of [`TextPattern::pattern_text`]; `$`
    /// only at the end, as in ECMA-262).
    pub fn matches(self, text: &str) -> bool {
        let bytes = text.as_bytes();
        match self {
            TextPattern::Digest => is_digest(text),
            TextPattern::Label => {
                bytes.first().is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                    && bytes.len() <= 63
                    && bytes.iter().all(|byte| label_byte(*byte))
            }
            TextPattern::Subject => text
                .strip_prefix("system:serviceaccount:")
                .and_then(|rest| rest.split_once(':'))
                .is_some_and(|(space, name)| segment(space) && segment(name)),
            TextPattern::Instant => {
                bytes.len() == 20
                    && bytes.iter().enumerate().all(|(index, byte)| match index {
                        4 | 7 => *byte == b'-',
                        10 => *byte == b'T',
                        13 | 16 => *byte == b':',
                        19 => *byte == b'Z',
                        _ => byte.is_ascii_digit(),
                    })
            }
            TextPattern::Uid => {
                (1..=128).contains(&bytes.len()) && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            }
            TextPattern::ApiVersion => {
                !bytes.is_empty() && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'-'))
            }
            TextPattern::Kind => {
                bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.len() >= 2 && bytes.iter().all(u8::is_ascii_alphanumeric)
            }
        }
    }
}

impl TextBounds {
    /// Whether `text` holds `min` to `max` code points and matches the pattern.
    pub fn admits(self, text: &str) -> bool {
        (self.min..=self.max).contains(&text.chars().count()) && self.pattern.matches(text)
    }
}

/// The member at `path` (object member names) of an optional value.
fn member_at<'a>(value: Option<&'a Value>, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value?, |node, name| node.get(name))
}

/// The first load-time check (DESIGN-I01B2 section 4; it replays PV case 27): `binding.scope.namespace` and
/// `binding.namespace.name` both equal `qualificationNamespace` (a missing or non-text one refuses here too).
fn binding_namespaces(member: Option<&Value>, namespace: &str) -> Result<(), ConfigError> {
    let scoped = member_at(member, &["scope", "namespace"]).and_then(Value::as_str);
    let named = member_at(member, &["namespace", "name"]).and_then(Value::as_str);
    if scoped != Some(namespace) || named != Some(namespace) {
        return check(BINDING_NAMESPACES_REFUSAL.to_string());
    }
    Ok(())
}

/// The second load-time check (Q-I01B2D-1 (a)): the binding document against [`BINDING_FORM`], each object closed with
/// every member required, the one constant, each text's length bounds and pattern, and a projection's namespace a
/// label or null. The refusal names the member.
fn binding_form(member: Option<&Value>) -> Result<(), ConfigError> {
    let Some(document) = member else { return check(format!("{BINDING_FORM_REFUSAL} the binding member is missing")) };
    let mut stack = vec![(document, BINDING_FORM, "binding".to_string())];
    while let Some((value, form, path)) = stack.pop() {
        let held = match form {
            BindingForm::Const(expected) => value.as_str() == Some(expected),
            BindingForm::Text(bounds) => value.as_str().is_some_and(|text| bounds.admits(text)),
            BindingForm::TextOrNull(bounds) => value.is_null() || value.as_str().is_some_and(|text| bounds.admits(text)),
            BindingForm::Object(members) => match value.as_object() {
                Some(object)
                    if object.len() == members.len() && members.iter().all(|(name, _)| object.get(name).is_some()) =>
                {
                    for (name, inner) in members {
                        if let Some(child) = object.get(name) {
                            stack.push((child, *inner, format!("{path}.{name}")));
                        }
                    }
                    true
                }
                _ => false,
            },
        };
        if !held {
            return check(format!("{BINDING_FORM_REFUSAL} {path} is not of the channel schema's $defs.binding form"));
        }
    }
    Ok(())
}

/// The third load-time check: `binding.scope.serviceAccountSubject` is `system:serviceaccount:<qualificationNamespace>:
/// <name>`, the name as CS's pattern allows.
fn binding_subject(member: Option<&Value>, namespace: &str) -> Result<(), ConfigError> {
    let name = member_at(member, &["scope", "serviceAccountSubject"])
        .and_then(Value::as_str)
        .and_then(|subject| subject.strip_prefix("system:serviceaccount:"))
        .and_then(|rest| rest.strip_prefix(namespace))
        .and_then(|rest| rest.strip_prefix(':'));
    if !name.is_some_and(segment) {
        return check(BINDING_SUBJECT_REFUSAL.to_string());
    }
    Ok(())
}

/// The canonical text of an IPv6 address (RFC 5952): lowercase hex groups without leading zeros, the longest run of
/// two or more zero groups (the first if tied) written `::`, no dotted tail.
fn ipv6_text(octets: &[u8; 16]) -> String {
    let words: Vec<u16> = octets
        .chunks_exact(2)
        .map(|pair| match pair {
            [high, low] => u16::from_be_bytes([*high, *low]),
            _ => 0,
        })
        .collect();
    let (mut best, mut run) = ((0usize, 0usize), (0usize, 0usize));
    for (index, word) in words.iter().enumerate() {
        if *word == 0 {
            if run.1 == 0 {
                run.0 = index;
            }
            run.1 = run.1.saturating_add(1);
            if run.1 > best.1 {
                best = run;
            }
        } else {
            run.1 = 0;
        }
    }
    let hex = |part: &[u16]| part.iter().map(|word| format!("{word:x}")).collect::<Vec<_>>().join(":");
    if best.1 < 2 {
        return hex(&words);
    }
    let head = words.get(..best.0).unwrap_or_default();
    let tail = words.get(best.0.saturating_add(best.1)..).unwrap_or_default();
    format!("{}::{}", hex(head), hex(tail))
}

/// `serviceCIDR` (I2D-10): a network of `family` in canonical text, then `/` and a decimal prefix without a leading zero
/// (0..32 for IPv4, 0..128 for IPv6), every host bit zero. IPv4 is four decimal octets without leading zeros
/// (gate-sys's `parse_ipv4`); IPv6 is RFC 5952's lowercase compressed form (the text must equal [`ipv6_text`]).
pub fn is_service_cidr(family: &str, cidr: &str) -> bool {
    let Some((address, prefix)) = cidr.split_once('/') else { return false };
    if prefix.is_empty()
        || prefix.len() > 3
        || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return false;
    }
    let Ok(bits) = prefix.parse::<u32>() else { return false };
    match family {
        "IPv4" => parse_ipv4(address)
            .is_some_and(|octets| bits <= 32 && (u32::from_be_bytes(octets) & u32::MAX.checked_shr(bits).unwrap_or(0)) == 0),
        "IPv6" => parse_ipv6(address).is_some_and(|octets| {
            bits <= 128
                && ipv6_text(&octets) == address
                && (u128::from_be_bytes(octets) & u128::MAX.checked_shr(bits).unwrap_or(0)) == 0
        }),
        _ => false,
    }
}

/// The fourth load-time check (DESIGN-I01B2 section 4, I2D-10; R10-defined, since neither the v2 model nor admission v4
/// states a form): `sealedAdmission` closed; `ipFamily` exactly `IPv4` or `IPv6`; `serviceCIDR` a canonical network of
/// that family; `defaultTolerationSeconds` an integer in 0..2^53-1. It names nothing of the digest port (G-I01B-1).
fn sealed_values(value: Option<&Value>) -> Result<SealedValues, ConfigError> {
    let what = "sealedAdmission";
    let object = closed(value, what, &SEALED_MEMBERS)?;
    let family = text(object, "ipFamily", what)?;
    if !IP_FAMILIES.contains(&family) {
        return check(SEALED_FAMILY_REFUSAL.to_string());
    }
    let cidr = text(object, "serviceCIDR", what)?;
    if !is_service_cidr(family, cidr) {
        return check(SEALED_CIDR_REFUSAL.to_string());
    }
    let seconds = integer(object, "defaultTolerationSeconds", what)?;
    if seconds > MAX_INTEGER {
        return check(SEALED_SECONDS_REFUSAL.to_string());
    }
    Ok(SealedValues { ip_family: family.to_string(), service_cidr: cidr.to_string(), default_toleration_seconds: seconds })
}

impl ObserverConfig {
    /// Checks a verified document (see the module documentation) and returns the typed configuration.
    pub fn parse(document: &[u8]) -> Result<ObserverConfig, ConfigError> {
        let value = canonical_value(document)?;
        let root = closed(Some(&value), "the document", &MEMBERS)?;
        if text(root, "format", "the document")? != FORMAT {
            return schema(format!("the document's format is not {FORMAT}"));
        }
        ObserverConfig::members(root)
    }

    /// Checks a verified `planeon.observer-config/v2` document (HE-004D1, D1-3): v1's checks on its eight members,
    /// then the qualification record's reference, which must name an entry of the configuration's own directory. The
    /// typed configuration and the record's path and pin. Every refusal is status 13.
    pub fn parse_with_record(document: &[u8]) -> Result<(ObserverConfig, FileRef), ConfigError> {
        let value = canonical_value(document)?;
        let root = closed(Some(&value), "the document", &MEMBERS_V2)?;
        if text(root, "format", "the document")? != FORMAT_V2 {
            return schema(format!("the document's format is not {FORMAT_V2}"));
        }
        let config = ObserverConfig::members(root)?;
        let record = file_ref(root.get("qualificationRecord"), "qualificationRecord")?;
        if !is_record_path(&record.path) {
            return check("qualificationRecord.path is not an entry of the configuration's directory".to_string());
        }
        Ok((config, record))
    }

    /// Checks a verified `planeon.observer-config/v3` document (HE-004-I01B2; DESIGN-I01B2 sections 3 and 4): the root's
    /// eleven members and the format, v2's checks (`fn members`) with `generation` narrowed to 64 lowercase hex, and the
    /// record's reference as `parse_with_record` checks it; then the load-time checks in their order (the namespaces,
    /// the binding's form against CS, the subject, the sealed values' forms). Only after every check is the `binding`
    /// member bound, once, and assigned once (I2D-3). The typed configuration and the record's path and pin; every
    /// refusal is status 13. `serve` calls only this parse.
    pub fn parse_v3(document: &[u8]) -> Result<(ObserverConfig, FileRef), ConfigError> {
        let value = canonical_value(document)?;
        let root = closed(Some(&value), "the document", &MEMBERS_V3)?;
        if text(root, "format", "the document")? != FORMAT_V3 {
            return schema(format!("the document's format is not {FORMAT_V3}"));
        }
        let mut config = ObserverConfig::members(root)?;
        if !is_generation_v3(&config.generation) {
            return check("generation is not 64 lowercase hex digits (configuration v3)".to_string());
        }
        let record = file_ref(root.get("qualificationRecord"), "qualificationRecord")?;
        if !is_record_path(&record.path) {
            return check("qualificationRecord.path is not an entry of the configuration's directory".to_string());
        }
        binding_namespaces(root.get("binding"), &config.namespace)?;
        binding_form(root.get("binding"))?;
        binding_subject(root.get("binding"), &config.namespace)?;
        let sealed = sealed_values(root.get("sealedAdmission"))?;
        let binding = match root.get("binding") {
            Some(member) => member.clone(),
            None => return schema("the document holds no binding member".to_string()),
        };
        config.sealed = Some(sealed);
        config.binding = binding;
        Ok((config, record))
    }

    /// The checks of the members v1 and v2 share, in v1's order.
    fn members(root: &Object) -> Result<ObserverConfig, ConfigError> {
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
            binding: Value::Null,
            sealed: None,
        })
    }

    /// Whether `notAfter` is reached at the wall second `now` (status 94 while running).
    pub fn expired(&self, now: u64) -> bool {
        now >= self.not_after
    }

    /// The binding document inline (HE-004-I01B2, B2-11 (f)): v3's checked `binding` member as `parse_v3` kept it,
    /// `Value::Null` after `parse` and `parse_with_record`; the one argument of `serve`'s `I01Binding::from_config`.
    pub fn binding(&self) -> &Value {
        &self.binding
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
