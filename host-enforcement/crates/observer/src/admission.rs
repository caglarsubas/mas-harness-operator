//! ADM-4: the loaded static admission manifest hash, checked before a generation becomes ACTIVE (HE-004B1 DESIGN-B
//! section 4.5; D1-4, D1-16, D2-3; owner decisions Q-HE4-9 (a), Q-HE4B-8 (a), Q-HE4B-12 (a) "Fields as proposed").
//!
//! - `manifest_directory_hash` is the reference derivation of the apiserver loader's directory hash (for HE-008's
//!   enrollment and the tests; the observer itself compares two strings).
//! - `check_loaded_manifest` compares the hash the apiserver reports through its ALPHA metric (the samples the apiserver
//!   client parsed, HE-004C) with the pinned hash from the observer's signed configuration, and returns the pre-ACTIVE
//!   record `planeon.internal.observer-adm4/v1` (R10-defined), an in-memory value with a canonical encoding and its
//!   sha256, which HE-008 binds by digest. The record alone does not prevent replay: HE-008 checks its observation binding
//!   against the enrollment it signs and the window's freshness.

use std::fmt;

use i05_protocol::json::Doc;
use i05_protocol::sha256::{self, Sha256};

/// The only Kubernetes version whose ALPHA metric is accepted (owner decision Q-HE4-9 (a): a residual re-checked at every
/// upgrade; changed only by a reviewed packet).
pub const ACCEPTED_KUBERNETES_VERSION: &str = "v1.37.1";
/// The record's version (R10-defined).
pub const RECORD_VERSION: &str = "planeon.internal.observer-adm4/v1";
/// The apiserver metric that carries the loaded manifest hash (admission semantics v3 README).
pub const METRIC_NAME: &str = "apiserver_manifest_admission_config_controller_last_config_info";

/// Why a directory has no reference hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashError {
    /// Two entries with one name (a directory cannot hold them; a slice can).
    DuplicateName(String),
}

impl fmt::Display for HashError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::DuplicateName(name) => write!(out, "ADM-4: the manifest directory names {} twice", name),
        }
    }
}

/// Whether the loader reads an entry: its name ends, ignoring ASCII case, in `.yaml`, `.yml` or `.json`, and it holds
/// data. (No non-ASCII character lower-cases to one of those suffix letters, so ASCII case folding equals the model's
/// `str.lower()` here.)
fn read_by_loader(name: &str, content: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    !content.is_empty() && (lower.ends_with(".yaml") || lower.ends_with(".yml") || lower.ends_with(".json"))
}

/// The loader's directory hash over (name, content) entries: names in byte order (Python's code-point order), each read
/// entry's content followed by one NUL byte into SHA-256, `"sha256:" + lowercase hex`, or `""` when no entry is read.
pub fn manifest_directory_hash(entries: &[(&str, &[u8])]) -> Result<String, HashError> {
    let mut ordered: Vec<&(&str, &[u8])> = entries.iter().collect();
    ordered.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    for pair in ordered.windows(2) {
        if let [first, second] = pair {
            if first.0 == second.0 {
                return Err(HashError::DuplicateName(first.0.to_string()));
            }
        }
    }
    let mut hasher = Sha256::new();
    let mut any = false;
    for (name, content) in ordered {
        if read_by_loader(name, content) {
            hasher.update(content);
            hasher.update(&[0]);
            any = true;
        }
    }
    Ok(if any { format!("sha256:{}", sha256::hex(&hasher.finish())) } else { String::new() })
}

/// One sample of the metric for one apiserver, as the client parsed it: its `plugin`, `apiserver_id_hash` and `hash`
/// labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricSample {
    pub plugin: String,
    pub apiserver_id_hash: String,
    pub hash: String,
}

/// What ties a record to one observation: the generation's enrolled-record digest or a run nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingId {
    /// `sha256:` and 64 lowercase hex digits.
    RecordDigest(String),
    /// 32 to 64 lowercase hex digits.
    Nonce(String),
}

/// The observation binding: the identifier and the observation window, each end a canonical UTC time
/// `YYYY-MM-DDTHH:MM:SSZ`, the start before the end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationBinding {
    pub id: BindingId,
    pub window_start: String,
    pub window_end: String,
}

/// The caller's (HE-004C's) input to the comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adm4Input {
    /// The pinned directory hash, from the observer's signed configuration.
    pub pinned_hash: String,
    /// The `plugin` label value of the sample to compare (a caller input until HE-004C confirms the label's value).
    pub expected_plugin: String,
    /// Every sample of `METRIC_NAME` the client parsed.
    pub samples: Vec<MetricSample>,
    /// The apiserver's Kubernetes version.
    pub kubernetes_version: String,
    pub binding: ObservationBinding,
}

/// A malformed observation binding: refused before any record is made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adm4InputError {
    RecordDigest,
    Nonce,
    WindowStart,
    WindowEnd,
    WindowOrder,
}

impl fmt::Display for Adm4InputError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Adm4InputError::RecordDigest => "ADM-4: the binding's record digest is not sha256: and 64 lowercase hex digits",
            Adm4InputError::Nonce => "ADM-4: the binding's nonce is not 32 to 64 lowercase hex digits",
            Adm4InputError::WindowStart => "ADM-4: the window start is not a canonical UTC time",
            Adm4InputError::WindowEnd => "ADM-4: the window end is not a canonical UTC time",
            Adm4InputError::WindowOrder => "ADM-4: the window does not start before it ends",
        })
    }
}

/// The comparison's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Match,
    Mismatch,
    Unavailable,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Match => "MATCH",
            Verdict::Mismatch => "MISMATCH",
            Verdict::Unavailable => "UNAVAILABLE",
        }
    }
}

/// The pre-ACTIVE record `planeon.internal.observer-adm4/v1`. Made only by `check_loaded_manifest`; a malformed hash is
/// recorded as null, never copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adm4Record {
    plugin: String,
    apiserver_id_hash: Option<String>,
    kubernetes_version: String,
    binding: ObservationBinding,
    pinned_hash: Option<String>,
    loaded_hash: Option<String>,
    verdict: Verdict,
}

impl Adm4Record {
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    pub fn pinned_hash(&self) -> Option<&str> {
        self.pinned_hash.as_deref()
    }

    pub fn loaded_hash(&self) -> Option<&str> {
        self.loaded_hash.as_deref()
    }

    pub fn apiserver_id_hash(&self) -> Option<&str> {
        self.apiserver_id_hash.as_deref()
    }

    /// The record as a document: `{schemaVersion, metricName, plugin, apiserverIdHash, kubernetesVersion,
    /// observationBinding {recordDigest | nonce, windowStart, windowEnd}, pinnedHash, loadedHash, verdict}`.
    pub fn to_doc(&self) -> Doc {
        let id = match &self.binding.id {
            BindingId::RecordDigest(digest) => ("recordDigest", Doc::str(digest)),
            BindingId::Nonce(nonce) => ("nonce", Doc::str(nonce)),
        };
        Doc::object(vec![
            ("schemaVersion", Doc::str(RECORD_VERSION)),
            ("metricName", Doc::str(METRIC_NAME)),
            ("plugin", Doc::str(&self.plugin)),
            ("apiserverIdHash", Doc::opt_str(self.apiserver_id_hash.as_deref())),
            ("kubernetesVersion", Doc::str(&self.kubernetes_version)),
            ("observationBinding", Doc::object(vec![
                id,
                ("windowStart", Doc::str(&self.binding.window_start)),
                ("windowEnd", Doc::str(&self.binding.window_end)),
            ])),
            ("pinnedHash", Doc::opt_str(self.pinned_hash.as_deref())),
            ("loadedHash", Doc::opt_str(self.loaded_hash.as_deref())),
            ("verdict", Doc::str(self.verdict.as_str())),
        ])
    }

    /// The canonical encoding (i05-protocol's: sorted keys, no whitespace, UTF-8).
    pub fn canonical(&self) -> Vec<u8> {
        self.to_doc().canonical()
    }

    /// `"sha256:" + hex(sha256(canonical))`, the digest HE-008 binds.
    pub fn digest(&self) -> String {
        sha256::prefixed(&self.canonical())
    }
}

fn lower_hex(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `sha256:` and 64 lowercase hex digits.
fn well_formed_hash(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && lower_hex(hex))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// A canonical UTC time `YYYY-MM-DDTHH:MM:SSZ` naming a real instant (years 0001-9999, no leap second).
fn utc_time(text: &str) -> bool {
    let bytes = text.as_bytes();
    let shape = bytes.len() == 20
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        });
    if !shape {
        return false;
    }
    let number = |from: usize, to: usize| text.get(from..to).and_then(|digits| digits.parse::<u32>().ok());
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (number(0, 4), number(5, 7), number(8, 10), number(11, 13), number(14, 16), number(17, 19))
    else {
        return false;
    };
    year >= 1
        && (1..=12).contains(&month)
        && day >= 1
        && day <= days_in_month(year, month)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

fn check_binding(binding: &ObservationBinding) -> Result<(), Adm4InputError> {
    match &binding.id {
        BindingId::RecordDigest(digest) if !well_formed_hash(digest) => return Err(Adm4InputError::RecordDigest),
        BindingId::Nonce(nonce) if !((32..=64).contains(&nonce.len()) && lower_hex(nonce)) => {
            return Err(Adm4InputError::Nonce);
        }
        _ => {}
    }
    if !utc_time(&binding.window_start) {
        return Err(Adm4InputError::WindowStart);
    }
    if !utc_time(&binding.window_end) {
        return Err(Adm4InputError::WindowEnd);
    }
    // Canonical times of one fixed width compare in time order as text.
    if binding.window_start >= binding.window_end {
        return Err(Adm4InputError::WindowOrder);
    }
    Ok(())
}

/// The pre-ACTIVE comparison (DESIGN-B section 4.5, D2-3). After the binding is checked: `UNAVAILABLE` unless the
/// Kubernetes version is `ACCEPTED_KUBERNETES_VERSION`, for an empty expected plugin, for any sample of another plugin,
/// for zero or several samples of the expected plugin, and for a malformed or empty loaded or pinned hash (the model's
/// empty-equals-empty is refused); otherwise `MATCH` when the one sample's hash equals the pinned hash and `MISMATCH`
/// when it differs.
pub fn check_loaded_manifest(input: &Adm4Input) -> Result<Adm4Record, Adm4InputError> {
    check_binding(&input.binding)?;
    let plugin = input.expected_plugin.as_str();
    let mut expected = input.samples.iter().filter(|sample| sample.plugin == plugin);
    let single = match (expected.next(), expected.next()) {
        (Some(one), None) => Some(one),
        _ => None,
    };
    let foreign = input.samples.iter().any(|sample| sample.plugin != plugin);
    let loaded = single.map(|sample| sample.hash.as_str()).filter(|hash| well_formed_hash(hash));
    let pinned = Some(input.pinned_hash.as_str()).filter(|hash| well_formed_hash(hash));
    let apiserver = single.map(|sample| sample.apiserver_id_hash.as_str()).filter(|hash| well_formed_hash(hash));
    let accepted = input.kubernetes_version == ACCEPTED_KUBERNETES_VERSION && !plugin.is_empty() && !foreign;
    let verdict = match (accepted, loaded, pinned) {
        (true, Some(loaded), Some(pinned)) if loaded == pinned => Verdict::Match,
        (true, Some(_), Some(_)) => Verdict::Mismatch,
        _ => Verdict::Unavailable,
    };
    Ok(Adm4Record {
        plugin: input.expected_plugin.clone(),
        apiserver_id_hash: apiserver.map(str::to_string),
        kubernetes_version: input.kubernetes_version.clone(),
        binding: input.binding.clone(),
        pinned_hash: pinned.map(str::to_string),
        loaded_hash: loaded.map(str::to_string),
        verdict,
    })
}
