//! The gate binary's signed configuration document (HE-003D DESIGN sections 3.2, 3.3 and 3.5; owner decision
//! Q-HE3D-1 (a), R10-defined): its canonical form, its closed schema and the checks that run on it before the seal's
//! second stage, returning a typed [`GateConfig`]. Portable and host-tested; it opens nothing and creates nothing.
//!
//! The bytes reach [`GateConfig::parse`] only after gate-tls's `signed_config` verified their Ed25519 signature, so an
//! unsigned document is never parsed. Order: the canonical subset (ASCII, strict JSON, depth at most 16, no float,
//! integers 0..=2^53-1, byte-equal to the canonical encoding), then the schema (closed objects, unknown members
//! refused), then the checks of DESIGN section 3.3. Every refusal is a value (the binary exits with status 13).

use std::collections::{BTreeMap, BTreeSet};

use i05_protocol::json::{self, Object, Value};
use i05_protocol::sha256;

use crate::file_store::valid_generation;
use crate::net::{InetAddress, IpLiteral};
use crate::policy_gate::{PolicyGate, PolicyGateError};
use crate::substrate::Lifetimes;

/// The configuration format; a binary accepts exactly this one, and gate-tls's domain prefix changes with it.
pub const FORMAT: &str = "planeon.effect-gate-config/v1";

/// The deepest nesting accepted (an empty object or array counts 1).
pub const MAX_DEPTH: usize = 16;

/// The largest integer accepted anywhere in the document, 2^53 - 1.
pub const MAX_INTEGER: u64 = (1 << 53) - 1;

/// R48: at most 32 manifests, each at most 16,384 bytes.
pub const MAX_MANIFESTS: usize = 32;
pub const MAX_MANIFEST_BYTES: u64 = 16_384;

/// The longest configured path.
pub const MAX_PATH_BYTES: usize = 255;

/// O5 (Q-HE2S-9 (a)): the lowest I04 port; the gate holds no capability after the seal.
pub const MIN_I04_PORT: u16 = 1024;

/// A certificate chain holds 1 to 4 files, leaf first.
pub const MAX_CHAIN_FILES: usize = 4;

const MEMBERS: [&str; 5] = ["format", "gate", "lifetimes", "stores", "credentials"];
const STORE_MEMBERS: [&str; 2] = ["journalDirectory", "markerDirectory"];
const CREDENTIAL_MEMBERS: [&str; 5] = ["i04Server", "i04ClientCa", "apiserverServingCa", "effectIdentity", "writerIdentity"];

/// One configured file: its absolute path and the pinned `sha256:` digest of its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRef {
    pub path: String,
    pub sha256: String,
}

/// A certificate chain (leaf first, one DER certificate per file) and its PKCS#8 DER key file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityFiles {
    pub chain: Vec<FileRef>,
    pub key: FileRef,
}

/// The credential and CA files of DESIGN section 3.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialFiles {
    pub i04_server: IdentityFiles,
    pub i04_client_ca: FileRef,
    pub apiserver_serving_ca: FileRef,
    pub effect_identity: IdentityFiles,
    pub writer_identity: IdentityFiles,
}

/// A checked configuration (DESIGN section 3.5).
#[derive(Clone, Debug)]
pub struct GateConfig {
    /// The `gate` member, unchanged, for `PolicyGate::create` or `PolicyGate::open`.
    pub gate: Value,
    /// The embedded I07 policy-kind table (DESIGN section 3.6), parsed.
    pub kinds: Value,
    /// `gate.generation` (R19's form).
    pub generation: String,
    /// The I04 endpoint (`gate.endpoint`), parsed.
    pub endpoint: InetAddress,
    pub lifetimes: Lifetimes,
    pub journal_directory: String,
    pub marker_directory: String,
    pub credentials: CredentialFiles,
    /// `sha256:` and the hex digest of the document's bytes (the generation binding, DESIGN section 3.3).
    pub document_digest: String,
}

/// Why a document was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateConfigError {
    /// Outside the canonical subset of DESIGN section 3.1.
    Canonical(&'static str),
    /// The closed schema of DESIGN section 3.2.
    Schema(String),
    /// A check of DESIGN section 3.3.
    Check(String),
    /// `PolicyGate::new`'s configuration checks (the I05 `Config` and R16).
    Gate(PolicyGateError),
    /// The embedded policy-kind table (never with the pinned bytes).
    Kinds,
}

fn schema<T>(message: String) -> Result<T, GateConfigError> {
    Err(GateConfigError::Schema(message))
}

fn check<T>(message: String) -> Result<T, GateConfigError> {
    Err(GateConfigError::Check(message))
}

/// The embedded policy-kind table as a JSON value.
pub fn policy_kinds() -> Result<Value, GateConfigError> {
    let text = std::str::from_utf8(i05_protocol::contracts::I07_V3_POLICY_KINDS).map_err(|_| GateConfigError::Kinds)?;
    json::parse(text).map_err(|_| GateConfigError::Kinds)
}

/// R47's digest form: `sha256:` and 64 lowercase hex digits.
pub fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

/// An absolute, normalised path of at most 255 bytes: it starts with `/`, has no empty, `.` or `..` component, does
/// not end with `/` and holds no NUL.
pub fn is_normal_path(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && !path.contains('\0')
        && path.strip_prefix('/').is_some_and(|rest| {
            !rest.is_empty() && rest.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
        })
}

/// The document as a JSON value, if it is in the canonical subset (DESIGN section 3.1).
fn canonical_value(document: &[u8]) -> Result<Value, GateConfigError> {
    if !document.is_ascii() {
        return Err(GateConfigError::Canonical("the document holds a byte outside ASCII"));
    }
    let text = std::str::from_utf8(document).map_err(|_| GateConfigError::Canonical("the document is not UTF-8"))?;
    let value = json::parse(text).map_err(|_| GateConfigError::Canonical("the document is not strict JSON"))?;
    if json::depth(&value) > MAX_DEPTH {
        return Err(GateConfigError::Canonical("the document nests deeper than 16"));
    }
    if json::contains_float(&value) {
        return Err(GateConfigError::Canonical("the document holds a float"));
    }
    let mut stack = vec![&value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Int(int) if int.is_negative() || int.to_u64().is_none_or(|number| number > MAX_INTEGER) => {
                return Err(GateConfigError::Canonical("an integer outside 0..=2^53-1"));
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(object) => stack.extend(object.iter().map(|(_, member)| member)),
            _ => {}
        }
    }
    let encoded = json::canonical(&value).map_err(|_| GateConfigError::Canonical("the document has no canonical form"))?;
    if encoded != document {
        return Err(GateConfigError::Canonical("the document is not its canonical encoding"));
    }
    Ok(value)
}

/// An object holding exactly `members`.
fn closed<'a>(value: Option<&'a Value>, what: &str, members: &[&str]) -> Result<&'a Object, GateConfigError> {
    let Some(object) = value.and_then(Value::as_object) else { return schema(format!("{what} is not an object")) };
    if object.len() != members.len() || !members.iter().all(|member| object.get(member).is_some()) {
        return schema(format!("{what} must hold exactly {}", members.join(", ")));
    }
    Ok(object)
}

fn text<'a>(object: &'a Object, key: &str, what: &str) -> Result<&'a str, GateConfigError> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) => Ok(value),
        None => schema(format!("{what}.{key} is not text")),
    }
}

/// `{ "path", "sha256" }`.
fn file_ref(value: Option<&Value>, what: &str) -> Result<FileRef, GateConfigError> {
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

/// `{ "chain": [<file>, ...], "key": <file> }`, 1 to 4 chain files.
fn identity(value: Option<&Value>, what: &str) -> Result<IdentityFiles, GateConfigError> {
    let object = closed(value, what, &["chain", "key"])?;
    let Some(files) = object.get("chain").and_then(Value::as_array) else {
        return schema(format!("{what}.chain is not a list"));
    };
    if files.is_empty() || files.len() > MAX_CHAIN_FILES {
        return check(format!("{what}.chain must hold 1 to 4 files"));
    }
    let chain = files.iter().map(|file| file_ref(Some(file), &format!("{what}.chain"))).collect::<Result<Vec<_>, _>>()?;
    Ok(IdentityFiles { chain, key: file_ref(object.get("key"), &format!("{what}.key"))? })
}

/// The I04 endpoint: a literal authority whose address is neither unspecified nor multicast (also in its IPv4-mapped
/// IPv6 form) and whose port is at least 1024 (O5).
fn endpoint(text: &str) -> Result<InetAddress, GateConfigError> {
    let Ok(address) = crate::parse_authority(text) else { return check("gate.endpoint is not a literal authority".to_string()) };
    let v4 = |octets: [u8; 4]| octets == [0, 0, 0, 0] || (224..=239).contains(&octets[0]);
    let refused = match address.ip {
        IpLiteral::V4(octets) => v4(octets),
        IpLiteral::V6(octets) => {
            let mapped = octets[..10].iter().all(|byte| *byte == 0) && octets[10] == 0xff && octets[11] == 0xff;
            octets == [0; 16] || octets[0] == 0xff || (mapped && v4([octets[12], octets[13], octets[14], octets[15]]))
        }
    };
    if refused {
        return check("gate.endpoint's address is unspecified or multicast".to_string());
    }
    if address.port < MIN_I04_PORT {
        return check("gate.endpoint's port is below 1024".to_string());
    }
    Ok(address)
}

impl GateConfig {
    /// Checks a verified document (see the module documentation) and returns the typed configuration.
    pub fn parse(document: &[u8]) -> Result<GateConfig, GateConfigError> {
        let value = canonical_value(document)?;
        let root = closed(Some(&value), "the document", &MEMBERS)?;
        if text(root, "format", "the document")? != FORMAT {
            return schema(format!("the document's format is not {FORMAT}"));
        }
        let Some(gate) = root.get("gate") else { return schema("the document has no gate".to_string()) };
        let kinds = policy_kinds()?;
        // `PolicyGate::new`'s configuration checks on an in-memory instance, dropped at once (DESIGN section 3.3).
        drop(PolicyGate::new(gate, &kinds).map_err(GateConfigError::Gate)?);
        let Some(members) = gate.as_object() else { return schema("gate is not an object".to_string()) };
        let generation = text(members, "generation", "gate")?;
        if !valid_generation(generation) {
            return check("gate.generation is not a valid store name (R19)".to_string());
        }
        let endpoint = endpoint(text(members, "endpoint", "gate")?)?;
        if !members.get("observedWorkers").and_then(Value::as_array).is_some_and(<[Value]>::is_empty) {
            return check("gate.observedWorkers must be empty (Q-HE3D-2 (a))".to_string());
        }
        let manifests = closed_entries(members.get("manifests"), "gate.manifests")?;
        if manifests.len() > MAX_MANIFESTS {
            return check("gate.manifests holds more than 32 manifests (R48)".to_string());
        }
        for (key, entry) in manifests.iter() {
            let key = key.as_str().unwrap_or_default();
            let digest = entry.get("digest").and_then(Value::as_str).unwrap_or_default();
            if !is_digest(key) || key != digest {
                return check("a gate.manifests key is not its entry's sha256 digest (R47)".to_string());
            }
            if entry.get("size").and_then(Value::as_int).and_then(json::Int::to_u64).is_none_or(|size| size > MAX_MANIFEST_BYTES) {
                return check("a gate.manifests size is above 16,384 bytes (R48)".to_string());
            }
        }
        let runs = closed_entries(members.get("runs"), "gate.runs")?;
        let mut certificates = BTreeSet::new();
        for (_, run) in runs.iter() {
            let digest = run.get("serverCertificateDigest").and_then(Value::as_str).unwrap_or_default();
            if !is_digest(digest) {
                return check("a serverCertificateDigest is not sha256: and 64 lowercase hex digits (R47)".to_string());
            }
            if !certificates.insert(digest) {
                return check("two runs carry the same serverCertificateDigest".to_string());
            }
        }
        let lifetimes = lifetimes(root.get("lifetimes"), runs)?;
        let stores = closed(root.get("stores"), "stores", &STORE_MEMBERS)?;
        let journal_directory = text(stores, "journalDirectory", "stores")?;
        let marker_directory = text(stores, "markerDirectory", "stores")?;
        if !is_normal_path(journal_directory) || !is_normal_path(marker_directory) {
            return check("a store directory is not an absolute normalised path of at most 255 bytes".to_string());
        }
        if journal_directory == marker_directory {
            return check("the journal and marker directories are the same".to_string());
        }
        let files = closed(root.get("credentials"), "credentials", &CREDENTIAL_MEMBERS)?;
        let credentials = CredentialFiles {
            i04_server: identity(files.get("i04Server"), "credentials.i04Server")?,
            i04_client_ca: file_ref(files.get("i04ClientCa"), "credentials.i04ClientCa")?,
            apiserver_serving_ca: file_ref(files.get("apiserverServingCa"), "credentials.apiserverServingCa")?,
            effect_identity: identity(files.get("effectIdentity"), "credentials.effectIdentity")?,
            writer_identity: identity(files.get("writerIdentity"), "credentials.writerIdentity")?,
        };
        let own = [&credentials.i04_server, &credentials.effect_identity, &credentials.writer_identity];
        if own.iter().filter_map(|files| files.chain.first()).any(|leaf| certificates.contains(leaf.sha256.as_str())) {
            return check("a serverCertificateDigest is the pin of one of the gate's own leaf certificates".to_string());
        }
        Ok(GateConfig {
            gate: gate.clone(),
            kinds,
            generation: generation.to_string(),
            endpoint,
            lifetimes,
            journal_directory: journal_directory.to_string(),
            marker_directory: marker_directory.to_string(),
            credentials,
            document_digest: sha256::prefixed(document),
        })
    }
}

/// `gate.manifests` or `gate.runs`: an object whose entries are objects (their members were checked by the I05
/// `Config` already).
fn closed_entries<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a Object, GateConfigError> {
    let Some(object) = value.and_then(Value::as_object) else { return schema(format!("{what} is not an object")) };
    if !object.iter().all(|(_, entry)| entry.as_object().is_some()) {
        return schema(format!("{what} holds an entry that is not an object"));
    }
    Ok(object)
}

/// `lifetimes`: exactly the run nonces of `gate.runs`, each an integer 1..=2^53-1 (seconds since the epoch).
fn lifetimes(value: Option<&Value>, runs: &Object) -> Result<Lifetimes, GateConfigError> {
    let Some(object) = value.and_then(Value::as_object) else { return schema("lifetimes is not an object".to_string()) };
    let nonces: BTreeSet<&str> = runs.iter().filter_map(|(nonce, _)| nonce.as_str()).collect();
    let mut ends = BTreeMap::new();
    for (nonce, end) in object.iter() {
        let Some(nonce) = nonce.as_str().filter(|nonce| nonces.contains(nonce)) else {
            return check("lifetimes names a run that gate.runs does not hold".to_string());
        };
        let end = end.as_int().and_then(json::Int::to_u64).filter(|end| (1..=MAX_INTEGER).contains(end));
        let Some(end) = end.and_then(|end| i64::try_from(end).ok()) else {
            return check("a lifetime end is not an integer 1..=2^53-1".to_string());
        };
        ends.insert(nonce.to_string(), end);
    }
    if ends.len() != nonces.len() {
        return check("a run of gate.runs has no lifetime".to_string());
    }
    Ok(Lifetimes::new(ends))
}
