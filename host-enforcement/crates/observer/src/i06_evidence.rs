//! The R10 port of I06's distribution-evidence check (HE-004D2 DESIGN-D2 section 7; owner decision Q-HE4D2-9 (a);
//! MODEL_DEFINED R142): I06 v3's wrapper, which binds one evidence record by digest to one native-profile v4 record that
//! `record_check::check_record` accepts, around I06 v1's SC00-SC15 on the projection (the record without its W02a
//! reference, at I06 v1's version), and the acceptance token [`EvidenceAccepted`], minted only at the end of
//! [`check_evidence`]. A logic module: pure, no panic, std's ordered collections and i05-protocol's json and sha256 only.
//! Nothing outside the four HE-004D2 modules names it, so `serve` cannot reach it (G-D2-5).
//!
//! The order is I06 v3's (`i06_backend_profile_v3.py` lines 68-88), then I06 v1's (`i06_backend_profile.py` lines
//! 425-593). The fixture flag's type, the wrapper's first rule, is the boundary [`fixture_flag`]: the check itself takes a
//! `bool`. Refusals a vector pins are contract text and appear verbatim; the unpinned ones of eight words or more (the two
//! production-only rules, SC08's component-set and executable-path rules, and the fixture-identity rule) are R10's own
//! words, as are the shorter unpinned ones. Python's `is True`, `is False` and `is None` are exact JSON booleans and null;
//! `==` is i05-protocol's `py_eq`; a member Python would read and fail on is [`EvidenceRefusal::Missing`]. Two readings are
//! R10's (MODEL_DEFINED): SC02's loopback test does not treat an IPv4-mapped loopback as loopback, and `str.strip()` is
//! CPython 3.12's whitespace set, held here as R10's own copy.

use std::collections::BTreeSet;

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;

use crate::capture_check::Refusal;
use crate::capture_schema::RecordSchema;
use crate::record_check::{self, ip_text};

/// I06 v3's evidence version and the W02a record version it binds.
const EVIDENCE_VERSION: &str = "planeon.internal.i06-distribution-evidence/v2";
const W02A_VERSION: &str = "planeon.internal.native-qualification/v4";
/// I06 v1's evidence version, which the projection carries.
const V1_EVIDENCE_VERSION: &str = "planeon.internal.i06-distribution-evidence/v1";
/// The prefix of a W02a refusal reported by SC00 (contract text).
pub const W02A_PREFIX: &str = "SC00 W02a v4 refuses the backend record: ";
/// The evidence record's members (I06 v3) and the projection's (I06 v1).
const EVIDENCE_KEYS: [&str; 17] = ["schemaVersion", "w02aRecord", "implementationId", "testOnly", "kubernetesVersion",
                                   "distribution", "artifacts", "components", "datastore", "apiserver", "controllerManager",
                                   "kubelet", "versioning", "credentialsOnHost", "apiClients", "runtimeSocket",
                                   "sealedConfiguration"];
/// The backend profile members I06 v1 reads.
const PROFILE_KEYS: [&str; 3] = ["profile", "implementationId", "componentKeys"];
const KUBERNETES_VERSION: &str = "v1.37.1";
const BACKEND_PROFILE: &str = "SEALED_SINGLE_NODE_CONTROL_PLANE_V1";
const TEST_FIXTURES: [&str; 1] = ["unit-distribution"];
/// Upstream identifiers, in the model's order.
const COMPONENTS: [&str; 8] = ["APISERVER", "CONTAINER_RUNTIME", "CONTROLLER_MANAGER", "DATASTORE", "KUBELET",
                               "NETWORK_POLICY_AGENT", "SCHEDULER", "SERVICE_PROXY"];
const REQUIRED_COMPONENTS: [&str; 6] = ["APISERVER", "CONTAINER_RUNTIME", "CONTROLLER_MANAGER", "DATASTORE", "KUBELET", "SCHEDULER"];
const COMPONENT_TYPES: [(&str, &str); 8] = [
    ("APISERVER", "qualk8s_apiserver_t"), ("CONTAINER_RUNTIME", "qualk8s_runtime_t"),
    ("CONTROLLER_MANAGER", "qualk8s_controller_manager_t"), ("DATASTORE", "qualk8s_datastore_t"),
    ("KUBELET", "qualk8s_kubelet_t"), ("NETWORK_POLICY_AGENT", "qualk8s_netpol_t"), ("SCHEDULER", "qualk8s_scheduler_t"),
    ("SERVICE_PROXY", "qualk8s_proxy_t"),
];
const GATED_COMPONENTS: [&str; 5] = ["APISERVER", "CONTROLLER_MANAGER", "KUBELET", "SCHEDULER", "SERVICE_PROXY"];
const REQUIRED_ADMISSION: [&str; 9] = ["NamespaceLifecycle", "LimitRanger", "ServiceAccount", "ResourceQuota", "NodeRestriction",
                                       "ValidatingAdmissionPolicy", "PodSecurity", "CertificateApproval", "CertificateSigning"];
const FORBIDDEN_ADMISSION: [&str; 6] = ["MutatingAdmissionWebhook", "ValidatingAdmissionWebhook", "MutatingAdmissionPolicy",
                                        "ImagePolicyWebhook", "NamespaceAutoProvision", "AlwaysAdmit"];
const ALLOWED_ADMISSION: [&str; 27] = [
    "CertificateApproval", "CertificateSigning", "CertificateSubjectRestriction", "ClusterTrustBundleAttest",
    "DefaultIngressClass", "DefaultStorageClass", "DefaultTolerationSeconds", "LimitRanger", "NamespaceLifecycle",
    "NodeDeclaredFeatureValidator", "PersistentVolumeClaimResize", "PodGroupProtection", "PodResizeValidator",
    "PodSecurity", "PodTopologyLabels", "Priority", "ResourceQuota", "RuntimeClass", "ServiceAccount",
    "StorageObjectInUseProtection", "TaintNodesByCondition", "ValidatingAdmissionPolicy",
    "NodeRestriction", "AlwaysPullImages", "DenyServiceExternalIPs", "EventRateLimit",
    "OwnerReferencesPermissionEnforcement",
];
const LICENSES: [&str; 1] = ["Apache-2.0"];
const SEALED_SET: [&str; 13] = ["ADMISSION_CONFIG", "APISERVER_FLAGS", "AUTHORIZATION_CONFIG", "CNI_CONFIG", "COMPONENT_DEFINITIONS",
                                "CONTAINER_RUNTIME_CONFIG", "CONTROLLER_MANAGER_FLAGS", "DATASTORE_CONFIG", "ENCRYPTION_CONFIG",
                                "KUBECONFIGS", "KUBELET_CONFIG", "PKI_TRUST_BUNDLES", "SCHEDULER_FLAGS"];
const API_CLIENTS: [(&str, &str); 2] = [("SERVICE_PROXY", "system:kube-proxy"), ("NETWORK_POLICY_AGENT", "planeon:netpol-agent")];

/// Pinned refusal texts (contract text, verbatim), named where the code around them would otherwise follow the
/// model's token for token (HE-004D1's practice).
const OTHER_PROFILE: &str = "SC00 evidence bound to a different W02a backend profile";
const OTHER_RELEASE: &str = "SC14 Kubernetes release differs from the v1.37.1 baseline";
const OTHER_COMPONENTS: &str = "SC08 component set differs from the W02a implementation profile";
const EXTERNAL_AUTHENTICATORS: &str = "SC03 request-header and external authenticators must be off";
const SIGNING_KEY_READERS: &str = "SC03 service-account signing key readable only by the apiserver";
const NODE_THEN_RBAC: &str = "SC04 authorization must be exactly Node then RBAC from a sealed structured configuration file";
const LOCAL_SERVICES: &str = "SC09 only local APIServices and no CustomResourceDefinitions";
const STATIC_PODS: &str = "SC07 kubelet must have no static pod source (file or URL)";
const KUBELET_ACCESS: &str = "SC07 kubelet must have no anonymous or read-only access, and Webhook authorization";
const VERSION_DEFAULTS: &str = "SC15 emulated and minimum-compatibility versions keep their defaults and runtime-config is empty";
const OTHER_VERSION: &str = "SC00 evidence names a W02a record of another version";
/// Why the evidence check refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceRefusal {
    /// A rule's text.
    Rule(&'static str),
    /// A rule's text followed by the component it names.
    Component(&'static str, String),
    /// W02a v4's `check_record` refused the backend record: [`W02A_PREFIX`] and its refusal.
    W02a(Refusal),
    /// A member Python would read and fail on (`KeyError`, `TypeError` or `AttributeError`).
    Missing,
}

impl EvidenceRefusal {
    /// The refusal's text where it is a text: a rule, a rule and its component, or the prefix and a W02a rule (a W02a
    /// schema, data or missing-member refusal has none; the replay localises the schema one).
    pub fn text(&self) -> Option<String> {
        match self {
            EvidenceRefusal::Rule(rule) => Some(rule.to_string()),
            EvidenceRefusal::Component(rule, name) => Some(format!("{rule}{name}")),
            EvidenceRefusal::W02a(Refusal::Model(rule)) => Some(format!("{W02A_PREFIX}{rule}")),
            EvidenceRefusal::W02a(_) | EvidenceRefusal::Missing => None,
        }
    }
}

/// An evidence record that passed [`check_evidence`]: the digest of the W02a record it binds, the digest of the
/// evidence record, and whether it was accepted in an explicit fixture call. Only `check_evidence` makes one.
#[derive(Debug, PartialEq, Eq)]
pub struct EvidenceAccepted {
    record_digest: String,
    evidence_digest: String,
    fixture: bool,
}

impl EvidenceAccepted {
    /// `sha256:` and the hex of the bound W02a record's canonical encoding.
    pub fn record_digest(&self) -> &str {
        &self.record_digest
    }

    /// `sha256:` and the hex of the evidence record's canonical encoding.
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    /// Whether the evidence was accepted in an explicit fixture call.
    pub fn fixture(&self) -> bool {
        self.fixture
    }
}

// ------------------------------------------------------------------------------------------------ helpers

fn refuse_unless(condition: bool, rule: &'static str) -> Result<(), EvidenceRefusal> {
    if condition { Ok(()) } else { Err(EvidenceRefusal::Rule(rule)) }
}

fn refuse_unless_named(condition: bool, rule: &'static str, name: &str) -> Result<(), EvidenceRefusal> {
    if condition { Ok(()) } else { Err(EvidenceRefusal::Component(rule, name.to_string())) }
}

fn at<'a>(value: &'a Value, key: &str) -> Result<&'a Value, EvidenceRefusal> {
    value.as_object().and_then(|object| object.get(key)).ok_or(EvidenceRefusal::Missing)
}

/// I06 v1's `_keys`: an object whose member names are exactly `names`.
fn closed(rule: &'static str, value: &Value, names: &[&str]) -> Result<(), EvidenceRefusal> {
    let exact = value.as_object().is_some_and(|object| object.len() == names.len() && names.iter().all(|name| object.get(name).is_some()));
    refuse_unless(exact, rule)
}

fn is_true(value: &Value) -> bool {
    matches!(value, Value::Bool(true))
}

fn is_false(value: &Value) -> bool {
    matches!(value, Value::Bool(false))
}

/// `type(value) is int and value == 0`.
fn is_zero(value: &Value) -> bool {
    value.as_int().is_some_and(|number| number.to_i128() == Some(0))
}

fn is_text(value: &Value, wanted: &str) -> bool {
    value.as_str() == Some(wanted)
}

fn is_empty_list(value: &Value) -> bool {
    value.as_array().is_some_and(<[Value]>::is_empty)
}

fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(Object::is_empty)
}

/// A list equal to `wanted` under `==` (each member a text).
fn is_text_list(value: &Value, wanted: &[&str]) -> bool {
    value.as_array().is_some_and(|items| items.len() == wanted.len() && items.iter().zip(wanted).all(|(item, text)| is_text(item, text)))
}

/// A list of distinct texts: its members, or `None`.
fn distinct_texts(value: &Value) -> Option<Vec<&str>> {
    let texts: Vec<&str> = value.as_array()?.iter().map(Value::as_str).collect::<Option<Vec<_>>>()?;
    let unique: BTreeSet<&str> = texts.iter().copied().collect();
    (unique.len() == texts.len()).then_some(texts)
}

/// Python's `str.isspace` for one code point (CPython 3.12's whitespace).
pub fn whitespace(point: u32) -> bool {
    matches!(point, 0x09..=0x0D | 0x1C..=0x20 | 0x85 | 0xA0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000)
}

/// I06 v1's `_text`: a non-empty text equal to its `strip()`.
pub fn stripped_text(value: &Value) -> bool {
    let Value::Str(text) = value else { return false };
    let points: Vec<u32> = text.code_points().collect();
    match (points.first(), points.last()) {
        (Some(first), Some(last)) => !whitespace(*first) && !whitespace(*last),
        _ => false,
    }
}

/// I06 v1's `PATH` matcher, `(/[A-Za-z0-9_.+@-]+)+` over the whole text.
fn path_form(text: &str) -> bool {
    text.strip_prefix('/').is_some_and(|rest| {
        rest.split('/').all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.+@-".contains(&byte)))
    })
}

/// I06 v1's `_path`: the `PATH` form with no `.` or `..` segment.
pub fn canonical_path(value: &Value) -> bool {
    value.as_str().is_some_and(|text| path_form(text) && text.split('/').skip(1).all(|part| part != "." && part != ".."))
}

/// I06 v1's implementation identifier: a lower-case ASCII letter or digit, then up to 127 more of those, full stops and
/// hyphens.
pub fn implementation_form(text: &str) -> bool {
    let bytes = text.as_bytes();
    let lower_digit = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    bytes.first().is_some_and(lower_digit) && bytes.len() <= 128
        && bytes.iter().skip(1).all(|byte| lower_digit(byte) || *byte == b'.' || *byte == b'-')
}

/// I06 v1's `DIGEST`, `sha256:[0-9a-f]{64}` over the whole text.
pub fn digest_form(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

/// A Python set of a list's members: refused (`TypeError`) when one is a list or an object; otherwise the members, each
/// once under `==`.
fn hashed(value: &[Value]) -> Result<Vec<&Value>, EvidenceRefusal> {
    let mut members: Vec<&Value> = Vec::with_capacity(value.len());
    for item in value {
        if item.as_array().is_some() || item.as_object().is_some() {
            return Err(EvidenceRefusal::Missing);
        }
        if !members.iter().any(|seen| json::py_eq(seen, item)) {
            members.push(item);
        }
    }
    Ok(members)
}

/// `"sha256:"` and the hex of a value's canonical encoding (the W02a qualification digest form); `None` where the value
/// has no canonical encoding.
pub fn record_digest(record: &Value) -> Option<String> {
    json::canonical(record).ok().map(|encoded| sha256::prefixed(&encoded))
}

/// The wrapper's first rule: the vector or caller's fixture flag must be a boolean.
pub fn fixture_flag(value: &Value) -> Result<bool, EvidenceRefusal> {
    value.as_bool().ok_or(EvidenceRefusal::Rule("SC00 fixture flag must be a boolean"))
}

// ------------------------------------------------------------------------------------------------ I06 v1

/// I06 v1's `check_evidence` on the projection, bound to `backend` (`backendProfile` with its three members and the W02a
/// record's `backendComponents`).
fn check_v1(evidence: &Value, inventory: &Value, backend: &Value, production: bool) -> Result<(), EvidenceRefusal> {
    let projection_keys: Vec<&str> = EVIDENCE_KEYS.iter().copied().filter(|key| *key != "w02aRecord").collect();
    closed("SC00 closed evidence record", evidence, &projection_keys)?;
    refuse_unless(is_text(at(evidence, "schemaVersion")?, V1_EVIDENCE_VERSION), "SC00 evidence version")?;
    let implementation = at(evidence, "implementationId")?;
    refuse_unless(implementation.as_str().is_some_and(implementation_form), "SC00 implementation identifier outside the W02a pattern")?;
    let implementation = implementation.as_str().ok_or(EvidenceRefusal::Missing)?;
    closed("SC00 W02a backend", backend, &["backendProfile", "backendComponents"])?;
    let profile = at(backend, "backendProfile")?;
    closed("SC00 W02a backend profile", profile, &PROFILE_KEYS)?;
    refuse_unless(is_text(at(profile, "profile")?, BACKEND_PROFILE) && is_text(at(profile, "implementationId")?, implementation),
            OTHER_PROFILE)?;
    let test_only = at(evidence, "testOnly")?;
    refuse_unless(test_only.as_bool().is_some() && (!TEST_FIXTURES.contains(&implementation) || is_true(test_only)),
            "SC00 the fixture implementation must be test-only")?;
    let distribution = at(evidence, "distribution")?;
    closed("SC13 distribution identity", distribution, &["name", "version", "license"])?;
    let name = at(distribution, "name")?;
    refuse_unless(stripped_text(name) && stripped_text(at(distribution, "version")?), "SC13 distribution identity")?;
    if production {
        refuse_unless(is_false(test_only), "SC00 test-only evidence refused in production")?;
        let fixture_name = name.as_str().is_some_and(|text| TEST_FIXTURES.contains(&text));
        refuse_unless(!TEST_FIXTURES.contains(&implementation) && !fixture_name, "SC00 fixture identity refused in production")?;
    }
    refuse_unless(is_text(at(evidence, "kubernetesVersion")?, KUBERNETES_VERSION), OTHER_RELEASE)?;
    refuse_unless(at(distribution, "license")?.as_str().is_some_and(|license| LICENSES.contains(&license)), "SC13 license outside the allowed set")?;
    let artifacts = at(evidence, "artifacts")?;
    closed("SC13 artifact closure", artifacts, &["pinned", "offline", "runtimeDownloads", "autoUpdate"])?;
    refuse_unless(is_true(at(artifacts, "pinned")?) && is_true(at(artifacts, "offline")?) && is_false(at(artifacts, "runtimeDownloads")?)
                && is_false(at(artifacts, "autoUpdate")?),
            "SC13 artifacts must be pinned and offline, with no downloads or auto-update")?;

    // SC08: the components.
    let keys = distinct_texts(at(profile, "componentKeys")?)
        .filter(|keys| REQUIRED_COMPONENTS.iter().all(|name| keys.contains(name)) && keys.iter().all(|name| COMPONENTS.contains(name)));
    let keys = keys.ok_or(EvidenceRefusal::Rule("SC08 W02a component keys out of range"))?;
    let key_set: BTreeSet<&str> = keys.iter().copied().collect();
    let (components, rows) = (at(evidence, "components")?, at(backend, "backendComponents")?);
    let same_names = |value: &Value| {
        value.as_object().is_some_and(|object| {
            object.len() == key_set.len() && object.iter().all(|(name, _)| name.as_str().is_some_and(|name| key_set.contains(name)))
        })
    };
    refuse_unless(same_names(components) && same_names(rows), OTHER_COMPONENTS)?;
    for name in &key_set {
        let entry = at(components, name)?;
        closed("SC08 component entry", entry, &["separateProcess"])?;
        refuse_unless_named(is_true(at(entry, "separateProcess")?), "SC08 component not a separate process: ", name)?;
        let row = at(rows, name)?;
        let confined = COMPONENT_TYPES.iter().find(|(component, _)| component == name).map(|(_, kind)| format!("system_u:system_r:{kind}:s0"));
        let label = row.as_object().and_then(|object| object.get("processLabel")).and_then(Value::as_str);
        refuse_unless_named(confined.is_some_and(|confined| label == Some(confined.as_str())), "SC08 component outside its confined type: ", name)?;
        refuse_unless_named(row.get("executable").is_some_and(canonical_path), "SC08 component executable not a canonical path: ", name)?;
        refuse_unless_named(row.get("artifactDigest").and_then(Value::as_str).is_some_and(digest_form), "SC08 component artifact digest: ", name)?;
    }
    let mut executables: BTreeSet<&str> = BTreeSet::new();
    let mut artifacts_seen: BTreeSet<&str> = BTreeSet::new();
    for name in &keys {
        let row = at(rows, name)?;
        executables.insert(at(row, "executable")?.as_str().ok_or(EvidenceRefusal::Missing)?);
        artifacts_seen.insert(at(row, "artifactDigest")?.as_str().ok_or(EvidenceRefusal::Missing)?);
    }
    refuse_unless(executables.len() == keys.len() && artifacts_seen.len() == keys.len(),
            "SC08 components must use distinct executables with distinct content (one entry type per confined domain)")?;

    // SC01: the datastore.
    let store = at(evidence, "datastore")?;
    closed("SC01 datastore entry", store, &["clientListen", "peerListen", "members"])?;
    let listen = at(store, "clientListen")?.as_array().filter(|urls| !urls.is_empty());
    let unix_only = listen.is_some_and(|urls| {
        urls.iter().all(|url| url.as_str().is_some_and(|url| url.starts_with("unix:///") && url.get(7..).is_some_and(|path| canonical_path(&Value::str(path)))))
    });
    let one_member = at(store, "members")?.as_int().is_some_and(|members| members.to_i128() == Some(1));
    refuse_unless(unix_only && is_empty_list(at(store, "peerListen")?) && one_member,
            "SC01 datastore must listen on AF_UNIX only, with one member and no peers")?;

    // SC02-SC05, SC09 and SC12's two files: the apiserver.
    let api = at(evidence, "apiserver")?;
    closed("SC02 apiserver entry", api, &["bindAddress", "securePort", "authentication", "authorization", "admissionPlugins", "admissionManifestsDir",
                  "auditPolicyFile", "apiServices", "customResourceDefinitions", "serviceAccountTokens"])?;
    let loopback = at(api, "bindAddress")?.as_str().and_then(ip_text).is_some_and(|ip| ip.is_loopback());
    let port = at(api, "securePort")?.as_int().and_then(|port| port.to_i128());
    refuse_unless(loopback && port.is_some_and(|port| (1..=65535).contains(&port)), "SC02 apiserver must bind a loopback address")?;
    let authentication = at(api, "authentication")?;
    closed("SC03 authentication entry", authentication, &["anonymous", "staticTokenFile", "bootstrapTokens", "requestHeader", "externalAuthenticators", "configFile"])?;
    refuse_unless(is_false(at(authentication, "anonymous")?) && at(authentication, "staticTokenFile")?.is_null()
                && is_false(at(authentication, "bootstrapTokens")?),
            "SC03 anonymous, static-token and bootstrap-token authentication must be off")?;
    refuse_unless(is_false(at(authentication, "requestHeader")?) && is_empty_list(at(authentication, "externalAuthenticators")?),
            EXTERNAL_AUTHENTICATORS)?;
    let config_file = at(authentication, "configFile")?;
    refuse_unless(config_file.is_null() || canonical_path(config_file), "SC03 authentication configuration file")?;
    let tokens = at(api, "serviceAccountTokens")?;
    closed("SC03 service-account token entry", tokens, &["signingEndpoint", "signingKeyReaders", "verificationKeys", "verificationKeyIsSigningPublicKey", "issuers", "lookup"])?;
    refuse_unless(at(tokens, "signingEndpoint")?.is_null(), "SC03 no external service-account token signer")?;
    refuse_unless(is_text_list(at(tokens, "signingKeyReaders")?, &["APISERVER"]), SIGNING_KEY_READERS)?;
    let one_key = at(tokens, "verificationKeys")?.as_int().is_some_and(|keys| keys.to_i128() == Some(1));
    refuse_unless(one_key && is_true(at(tokens, "verificationKeyIsSigningPublicKey")?),
            "SC03 the only service-account verification key is the public half of the apiserver's signing key")?;
    let issuers = at(tokens, "issuers")?.as_array();
    refuse_unless(issuers.is_some_and(|issuers| issuers.len() == 1 && issuers.first().is_some_and(stripped_text)),
            "SC03 exactly one fixed service-account issuer")?;
    refuse_unless(is_true(at(tokens, "lookup")?), "SC03 service-account token lookup must stay on")?;
    let authorization = at(api, "authorization")?;
    closed("SC04 authorization entry", authorization, &["source", "authorizers"])?;
    refuse_unless(is_text(at(authorization, "source")?, "AUTHORIZATION_CONFIG_FILE") && is_text_list(at(authorization, "authorizers")?, &["Node", "RBAC"]),
            NODE_THEN_RBAC)?;
    let plugins = at(api, "admissionPlugins")?;
    closed("SC05 admission entry", plugins, &["enabled"])?;
    let enabled = distinct_texts(at(plugins, "enabled")?).ok_or(EvidenceRefusal::Rule("SC05 admission plugin list"))?;
    refuse_unless(REQUIRED_ADMISSION.iter().all(|name| enabled.contains(name)), "SC05 required admission plugin missing")?;
    refuse_unless(!enabled.iter().any(|name| FORBIDDEN_ADMISSION.contains(name)), "SC05 forbidden admission plugin enabled")?;
    refuse_unless(enabled.iter().all(|name| ALLOWED_ADMISSION.contains(name)), "SC05 admission plugin outside the allowed set")?;
    let manifests = at(api, "admissionManifestsDir")?;
    refuse_unless(manifests.is_null() || canonical_path(manifests), "SC12 admission manifests directory")?;
    let audit = at(api, "auditPolicyFile")?;
    refuse_unless(audit.is_null() || canonical_path(audit), "SC12 audit policy file")?;
    refuse_unless(is_text(at(api, "apiServices")?, "LOCAL_ONLY") && is_empty_list(at(api, "customResourceDefinitions")?),
            LOCAL_SERVICES)?;

    // SC06: the controller manager against the inventory's controllers.
    let manager = at(evidence, "controllerManager")?;
    closed("SC06 controller-manager entry", manager, &["useServiceAccountCredentials", "controllers", "clusterSigning", "serviceAccountPrivateKeyFile"])?;
    refuse_unless(is_true(at(manager, "useServiceAccountCredentials")?), "SC06 per-controller service-account credentials required")?;
    refuse_unless(at(manager, "clusterSigning")?.is_null() && at(manager, "serviceAccountPrivateKeyFile")?.is_null(),
            "SC06 controller-manager holds no signing key")?;
    let mut known: Vec<(&Value, &Value)> = Vec::new();
    for row in at(inventory, "controllers")?.as_array().ok_or(EvidenceRefusal::Missing)? {
        let controller = at(row, "name")?;
        if controller.as_array().is_some() || controller.as_object().is_some() {
            return Err(EvidenceRefusal::Missing);
        }
        match known.iter_mut().find(|(seen, _)| json::py_eq(seen, controller)) {
            Some(entry) => entry.1 = row,
            None => known.push((controller, row)),
        }
    }
    let running = distinct_texts(at(manager, "controllers")?)
        .filter(|running| running.iter().all(|name| known.iter().any(|(seen, _)| is_text(seen, name))));
    let running = running.ok_or(EvidenceRefusal::Rule("SC06 controller unknown to the v1.37 inventory"))?;
    let mut disabled = false;
    for name in &running {
        let row = known.iter().find(|(seen, _)| is_text(seen, name)).map(|(_, row)| *row).ok_or(EvidenceRefusal::Missing)?;
        disabled = disabled || is_text(at(row, "profile")?, "REQUIRED_DISABLED");
    }
    refuse_unless(!disabled, "SC06 required-disabled controller enabled")?;

    // SC07: the kubelet.
    let kubelet = at(evidence, "kubelet")?;
    closed("SC07 kubelet entry", kubelet, &["rotateCertificates", "serverTLSBootstrap", "staticPodPath", "staticPodURL", "staticPodURLHeader", "anonymousAuth",
                      "readOnlyPort", "authorizationMode"])?;
    refuse_unless(is_false(at(kubelet, "rotateCertificates")?) && is_false(at(kubelet, "serverTLSBootstrap")?),
            "SC07 kubelet certificate rotation and TLS bootstrap must be off")?;
    refuse_unless(at(kubelet, "staticPodPath")?.is_null() && at(kubelet, "staticPodURL")?.is_null() && is_empty_object(at(kubelet, "staticPodURLHeader")?),
            STATIC_PODS)?;
    refuse_unless(is_false(at(kubelet, "anonymousAuth")?) && is_zero(at(kubelet, "readOnlyPort")?) && is_text(at(kubelet, "authorizationMode")?, "Webhook"),
            KUBELET_ACCESS)?;

    // SC15: versioning and feature gates.
    let versioning = at(evidence, "versioning")?;
    closed("SC15 versioning entry", versioning, &["emulatedVersion", "minCompatibilityVersion", "runtimeConfig", "featureGates"])?;
    refuse_unless(at(versioning, "emulatedVersion")?.is_null() && at(versioning, "minCompatibilityVersion")?.is_null()
                && is_empty_object(at(versioning, "runtimeConfig")?),
            VERSION_DEFAULTS)?;
    let gated: BTreeSet<&str> = GATED_COMPONENTS.iter().copied().filter(|name| key_set.contains(name)).collect();
    let gates = at(versioning, "featureGates")?;
    let defaults = gates.as_object().is_some_and(|object| {
        object.len() == gated.len()
            && object.iter().all(|(name, member)| name.as_str().is_some_and(|name| gated.contains(name)) && is_empty_object(member))
    });
    refuse_unless(defaults, "SC15 feature gates must keep their v1.37 defaults in every component")?;

    // SC03's credential census, SC10, SC11 and SC12's sealed set.
    let credentials = at(evidence, "credentialsOnHost")?;
    closed("SC03 credential census", credentials, &["clusterAdminCredentials", "trustedCaPrivateKeys", "bootstrapTokens"])?;
    refuse_unless(credentials.as_object().is_some_and(|object| object.iter().all(|(_, count)| is_zero(count))),
            "SC03 no cluster-admin credential, trusted CA private key or bootstrap token on the host")?;
    let clients = at(evidence, "apiClients")?;
    closed("SC10 API clients", clients, &["automountedTokens", "identities"])?;
    let allowed: Vec<&str> = API_CLIENTS.iter().filter(|(name, _)| key_set.contains(name)).map(|(_, identity)| *identity).collect();
    let identities = distinct_texts(at(clients, "identities")?).filter(|identities| identities.iter().all(|identity| allowed.contains(identity)));
    refuse_unless(is_false(at(clients, "automountedTokens")?) && identities.is_some(), "SC10 API client outside the closure's component identities")?;
    let socket = at(evidence, "runtimeSocket")?;
    closed("SC11 runtime socket", socket, &["path", "allowedClientType"])?;
    refuse_unless(canonical_path(at(socket, "path")?) && is_text(at(socket, "allowedClientType")?, "qualk8s_kubelet_t"),
            "SC11 runtime socket reachable beyond the kubelet")?;
    let sealed = at(evidence, "sealedConfiguration")?;
    closed("SC12 sealed configuration", sealed, &["files", "autoApplyManifestDirs"])?;
    let mut expected: BTreeSet<&str> = SEALED_SET.iter().copied().collect();
    for (name, used) in [("ADMISSION_MANIFESTS", !manifests.is_null()), ("AUDIT_CONFIG", !audit.is_null()),
                         ("AUTHENTICATION_CONFIG", !config_file.is_null()),
                         ("NETWORK_POLICY_AGENT_CONFIG", key_set.contains("NETWORK_POLICY_AGENT")),
                         ("SERVICE_PROXY_CONFIG", key_set.contains("SERVICE_PROXY"))] {
        if used {
            expected.insert(name);
        }
    }
    let listed = at(sealed, "files")?;
    let exact = match listed.as_array() {
        None => false,
        Some(items) => {
            let members = hashed(items)?;
            members.len() == items.len() && members.len() == expected.len()
                && members.iter().all(|member| member.as_str().is_some_and(|name| expected.contains(name)))
        }
    };
    refuse_unless(exact, "SC12 sealed configuration must be exactly the profile's file set")?;
    let directories = at(sealed, "autoApplyManifestDirs")?.as_array().ok_or(EvidenceRefusal::Rule("SC12 auto-apply manifest directories"))?;
    for entry in directories {
        closed("SC12 auto-apply manifest directory entry", entry, &["path", "empty", "sealed"])?;
        refuse_unless(canonical_path(at(entry, "path")?) && is_true(at(entry, "empty")?) && is_true(at(entry, "sealed")?),
                "SC12 auto-apply manifest directories must be empty and sealed")?;
    }
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    for entry in directories {
        paths.insert(at(entry, "path")?.as_str().ok_or(EvidenceRefusal::Missing)?);
    }
    refuse_unless(paths.len() == directories.len(), "SC12 auto-apply manifest directories")
}

// ------------------------------------------------------------------------------------------------ check_evidence

/// I06 v3's `check_evidence` (see the module documentation for the order): the evidence record bound to the W02a v4
/// record `record` (with its profile and signed endpoints), checked under I06 v1's SC00-SC15 against the writer
/// `inventory`. A test-only backend qualifies only when `test_fixture` is set. On success only, the token.
pub fn check_evidence(evidence: &Value, inventory: &Value, record: &Value, profile: &Value, endpoints: &Value,
                      record_schema: &RecordSchema, test_fixture: bool) -> Result<EvidenceAccepted, EvidenceRefusal> {
    closed("SC00 closed evidence record", evidence, &EVIDENCE_KEYS)?;
    refuse_unless(is_text(at(evidence, "schemaVersion")?, EVIDENCE_VERSION), "SC00 evidence version")?;
    let reference = at(evidence, "w02aRecord")?;
    closed("SC00 closed W02a record reference", reference, &["schemaVersion", "qualificationDigest"])?;
    refuse_unless(is_text(at(reference, "schemaVersion")?, W02A_VERSION), OTHER_VERSION)?;
    let accepted = record_check::check_record(record, profile, endpoints, record_schema).map_err(EvidenceRefusal::W02a)?;
    let bound_digest = accepted.record().digest().to_string();
    refuse_unless(is_text(at(reference, "qualificationDigest")?, &bound_digest), "SC00 evidence names a different W02a record")?;
    let backend = at(record, "backendProfile")?;
    let backend_test_only = at(backend, "testOnly")?;
    let test_only = at(evidence, "testOnly")?;
    refuse_unless(test_only.as_bool().is_some() && backend_test_only.as_bool().is_some() && json::py_eq(test_only, backend_test_only),
            "SC00 evidence and its W02a backend disagree on test-only")?;
    refuse_unless(test_fixture || is_false(backend_test_only), "SC00 a test-only W02a backend qualifies only in an explicit fixture call")?;
    let mut projection = Object::new();
    for (name, member) in evidence.as_object().ok_or(EvidenceRefusal::Missing)?.iter() {
        if name.as_str() != Some("w02aRecord") {
            projection.insert(name.clone(), member.clone());
        }
    }
    projection.insert(JStr::new("schemaVersion"), Value::str(V1_EVIDENCE_VERSION));
    let mut bound_profile = Object::new();
    for key in PROFILE_KEYS {
        bound_profile.insert(JStr::new(key), at(backend, key)?.clone());
    }
    let mut bound = Object::new();
    bound.insert(JStr::new("backendProfile"), Value::Object(bound_profile));
    bound.insert(JStr::new("backendComponents"), at(record, "backendComponents")?.clone());
    check_v1(&Value::Object(projection), inventory, &Value::Object(bound), !test_fixture)?;
    let evidence_digest = record_digest(evidence).ok_or(EvidenceRefusal::Missing)?;
    Ok(EvidenceAccepted { record_digest: bound_digest, evidence_digest, fixture: test_fixture })
}
