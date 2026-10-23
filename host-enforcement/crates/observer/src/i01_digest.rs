//! The I01 digest contract's port (HE-004-I01B1; DESIGN-I01B rev 3 section 2 and DESIGN-I01B1 rev 2; owner decision
//! Q-HE4I1-2 and the monitor's Q-I01B-1..5 and Q-I01B-26): the seven projection documents and the four enforcement
//! digests of the I01 v1 answer, derived from one snapshot as `contracts/i01-digests-v1/README.md` states them
//! (DIGEST-CONTRACT, harness-onion `2043cc27`, edge record v10's row 71), with the pinned reference model
//! `scripts/policy_observation_digests.py` read as text where the README is silent. A pure logic module under the I01
//! logic whitelist (`tools/gate.py`, I01_LOGIC_PATHS): no system call beyond allocation, every function total, no
//! panic, and no caller in the binary (G-I01B-1).
//!
//! - Canonical bytes are i05-protocol's encoder, which equals the contract's `canonical`; a digest is `sha256:` and the
//!   lowercase hex SHA-256 of a document's canonical bytes. Every document passes the exactness rule ([`exactness`]):
//!   a float refuses first, then VPC's `_bounded` in its own walk order (depth at most 16, a budget of 262,144,
//!   integers within 2^53 - 1 in magnitude).
//! - The snapshot ([`DigestSnapshot`]) is B1's checked lists (`Inputs`), the read's resourceVersion, the
//!   configuration's values, ADM-4's loaded hash and the enrolled record; the binding is the signed binding. Both are
//!   i05 values, and the binding is read only for the one-object kinds' bound names and the profile's service-account
//!   subject.
//! - RBAC: B1's producer runs first, so its refusals come first, in its order; the contract's two documents are a
//!   second derivation over the same lists, which keeps the non-resource rules B1 drops. The closure digest exists only
//!   after the closure check and the role pin pass on B1's snapshot, as `observe.rs` runs them.
//! - The A2 render (admission v3's eight objects and the sealed directory's hash) is the caller's, handed in as a
//!   function: this module checks the sealed values before it, and the two hashes, the admission lists and the
//!   qualification Namespace after it.
//! - Not here: the capture gate at each answer, the comparison with the signed values, and the answer itself.
//!
//! Every refusal is one of the contract's pinned texts (`definitions.json` `refusalTexts`), written out below;
//! [`refusal_texts`] lists them all.

use std::collections::{BTreeMap, BTreeSet};

use i05_protocol::json::{self, Doc, JStr, Object, Value};
use i05_protocol::sha256;

use crate::inputs::{object_name, object_namespace, Inputs, Resource};
use crate::observer_rbac::{self, RbacLists};
use crate::rbac::{self, ProduceError, CLUSTER, SERVICE_ACCOUNT_PREFIX};
use crate::snapshot::Closure;

/// The contract's schema version and the RBAC closure document's (contract identifiers).
pub const SCHEMA_VERSION: &str = "planeon.internal.policy-observation-digests/v1";
pub const CLOSURE_VERSION: &str = "planeon.internal.policy-observation-rbac-closure/v1";
/// The exactness rule's bounds (VPC's `_bounded`): the deepest node, the root being at depth 0 and a member name one
/// deeper than its object; the size budget; the largest integer magnitude, 2^53 - 1.
pub const BOUND_DEPTH: usize = 16;
pub const BOUND_BUDGET: usize = 262_144;
pub const BOUND_INTEGER: u64 = (1 << 53) - 1;

/// The ServiceAccount annotation that changes enforcement (refused), and the kind's enforcement keys, which stand in
/// for a `spec` (I07 v3's `topLevelKeys`).
const MOUNTABLE_SECRETS: &str = "kubernetes.io/enforce-mountable-secrets";
const SERVICE_ACCOUNT_KEYS: [&str; 3] = ["automountServiceAccountToken", "imagePullSecrets", "secrets"];
/// The qualification Namespace's Pod Security labels.
const POD_SECURITY_PREFIX: &str = "pod-security.kubernetes.io/";
/// The configuration's three sealed admission values.
const SEALED_VALUES: [&str; 3] = ["ipFamily", "serviceCIDR", "defaultTolerationSeconds"];
/// The two admission kinds the A2 render holds.
const POLICY_KIND: &str = "ValidatingAdmissionPolicy";
const BINDING_KIND: &str = "ValidatingAdmissionPolicyBinding";
/// The v4 record's BROKER row: its 20 members, its cgroup's 7, and the document's 14 (the cgroup without its inode).
/// The row's and the document's members are listed in the order the canonical encoding gives them (code points); only
/// the sets count, as the row is checked closed and the document's members are encoded sorted.
const BROKER_MEMBERS: [&str; 20] = [
    "artifactDigest", "bpfPrograms", "capabilities", "cgroup", "executable", "executableLabel", "filePaths", "gid",
    "interpreterLabel", "interpreterPath", "listenEndpointIds", "namespaceInodes", "noNewPrivs", "outboundEndpointIds",
    "processLabel", "rlimitCore", "seccompDefaultAction", "seccompFilterDigest", "seccompMode", "uid",
];
const CGROUP_MEMBERS: [&str; 7] =
    ["path", "inode", "memoryMaxBytes", "pidsMax", "cpuQuotaMicros", "cpuPeriodMicros", "selinuxLabel"];
const CGROUP_INODE: &str = "inode";
const BROKER_DOCUMENT: [&str; 14] = [
    "artifactDigest", "capabilities", "cgroup", "executable", "executableLabel", "gid", "listenEndpointIds",
    "noNewPrivs", "outboundEndpointIds", "processLabel", "seccompDefaultAction", "seccompFilterDigest", "seccompMode",
    "uid",
];
/// The network policy agent's backend component, and the five members of it the network document holds.
const AGENT: &str = "NETWORK_POLICY_AGENT";
const AGENT_MEMBERS: [&str; 5] = ["executable", "executableLabel", "artifactDigest", "processLabel", "apiIdentities"];
/// The three synthetic projections' fixed names.
const ADMISSION_POLICY_NAME: &str = "admissionpolicy";
const RBAC_NAME: &str = "rbac";
const MUTATION_BROKER_NAME: &str = "mutationbroker";

/// The refusal texts that belong to one rule (README section 9), contract text.
pub const RENDERED_HASH_DIFFERS: &str = "admissionPolicy: rendered hash differs";
pub const UNKNOWN_ADMISSION_OBJECT: &str = "admissionPolicy: unknown admission object";
pub const NAMESPACE_NOT_LISTED: &str = "admissionPolicy: qualification namespace not listed";
pub const MOUNTABLE_SECRETS_ANNOTATION: &str = "serviceAccount: enforce-mountable-secrets annotation";
pub const SELECTOR_FORM: &str = "networkPolicy: selector form outside v1";
pub const AGGREGATED_ROLE: &str = "rbac: aggregated role reaches the namespace";
pub const ROLE_MISSING: &str = "rbac: role does not exist";
pub const LOOPBACK_NON_RESOURCE: &str = "rbac: loopback user bound to a non-resource rule";
pub const CLOSURE_NOT_PASSED: &str = "rbacClosureDigest: I06 closure check not passed";
pub const BROKER_ROW_INCOMPLETE: &str = "mutationBroker: broker row incomplete";
pub const NO_NETWORK_AGENT: &str = "networkEnforcementDigest: no network policy agent";
/// B1's malformed-object refusals (`rbac::ProduceError::Malformed`'s field) and the contract's text for each
/// (README section 4.5), in the order of the contract's `refusalTexts` (sorted by text).
pub const B1_MALFORMED: [(&str, &str); 14] = [
    ("metadata", "rbac: malformed metadata"),
    ("roleRef", "rbac: malformed roleRef"),
    ("roleRef apiGroup", "rbac: malformed roleRef apiGroup"),
    ("roleRef kind", "rbac: malformed roleRef kind"),
    ("roleRef name", "rbac: malformed roleRef name"),
    ("rule", "rbac: malformed rule"),
    ("rule (non-resource URLs beside resources)", "rbac: malformed rule (non-resource URLs beside resources)"),
    ("rule list", "rbac: malformed rule list"),
    ("rules", "rbac: malformed rules"),
    ("subject", "rbac: malformed subject"),
    ("subject kind", "rbac: malformed subject kind"),
    ("subject name", "rbac: malformed subject name"),
    ("subject namespace", "rbac: malformed subject namespace"),
    ("subjects", "rbac: malformed subjects"),
];

/// The contract's eleven keys: the seven projections and the four enforcement digests, in its order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DigestKey {
    AdmissionPolicy,
    ResourceQuota,
    LimitRange,
    ServiceAccount,
    Rbac,
    NetworkPolicy,
    MutationBroker,
    AdmissionFenceDigest,
    RbacClosureDigest,
    NetworkEnforcementDigest,
    HostPreflightDigest,
}

/// Why a value is not exact (README section 3.2): a float, an integer past 2^53 - 1 in magnitude, or any other fault of
/// VPC's `_bounded` (depth, budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inexact {
    Float,
    Integer,
    Bound,
}

impl DigestKey {
    /// The seven projections, in the contract's order.
    pub const POLICIES: [DigestKey; 7] = [
        DigestKey::AdmissionPolicy, DigestKey::ResourceQuota, DigestKey::LimitRange, DigestKey::ServiceAccount,
        DigestKey::Rbac, DigestKey::NetworkPolicy, DigestKey::MutationBroker,
    ];
    /// The four enforcement digests, in the contract's order.
    pub const DIGESTS: [DigestKey; 4] = [
        DigestKey::AdmissionFenceDigest, DigestKey::RbacClosureDigest, DigestKey::NetworkEnforcementDigest,
        DigestKey::HostPreflightDigest,
    ];
    /// The three values the capture gate holds at each answer.
    pub const GATED: [DigestKey; 3] =
        [DigestKey::MutationBroker, DigestKey::NetworkEnforcementDigest, DigestKey::HostPreflightDigest];

    /// The key as the contract writes it.
    pub fn name(self) -> &'static str {
        match self {
            DigestKey::AdmissionPolicy => "admissionPolicy",
            DigestKey::ResourceQuota => "resourceQuota",
            DigestKey::LimitRange => "limitRange",
            DigestKey::ServiceAccount => "serviceAccount",
            DigestKey::Rbac => "rbac",
            DigestKey::NetworkPolicy => "networkPolicy",
            DigestKey::MutationBroker => "mutationBroker",
            DigestKey::AdmissionFenceDigest => "admissionFenceDigest",
            DigestKey::RbacClosureDigest => "rbacClosureDigest",
            DigestKey::NetworkEnforcementDigest => "networkEnforcementDigest",
            DigestKey::HostPreflightDigest => "hostPreflightDigest",
        }
    }

    /// The key the contract writes as `name`, if any.
    pub fn of_name(name: &str) -> Option<DigestKey> {
        DigestKey::POLICIES.into_iter().chain(DigestKey::DIGESTS).find(|key| key.name() == name)
    }

    /// A projection's fixed `apiVersion` and `kind` (README section 4); the four digests have none.
    pub fn api_version_and_kind(self) -> Option<(&'static str, &'static str)> {
        match self {
            DigestKey::AdmissionPolicy => Some(("admissionregistration.k8s.io/v1", POLICY_KIND)),
            DigestKey::ResourceQuota => Some(("v1", "ResourceQuota")),
            DigestKey::LimitRange => Some(("v1", "LimitRange")),
            DigestKey::ServiceAccount => Some(("v1", "ServiceAccount")),
            DigestKey::Rbac => Some(("planeon.internal/v1", "EffectiveRbac")),
            DigestKey::NetworkPolicy => Some(("networking.k8s.io/v1", "NetworkPolicy")),
            DigestKey::MutationBroker => Some(("planeon.internal/v1", "MutationBroker")),
            DigestKey::AdmissionFenceDigest
            | DigestKey::RbacClosureDigest
            | DigestKey::NetworkEnforcementDigest
            | DigestKey::HostPreflightDigest => None,
        }
    }

    /// "<key>: malformed input" (README section 3.4).
    pub fn malformed(self) -> &'static str {
        match self {
            DigestKey::AdmissionPolicy => "admissionPolicy: malformed input",
            DigestKey::ResourceQuota => "resourceQuota: malformed input",
            DigestKey::LimitRange => "limitRange: malformed input",
            DigestKey::ServiceAccount => "serviceAccount: malformed input",
            DigestKey::Rbac => "rbac: malformed input",
            DigestKey::NetworkPolicy => "networkPolicy: malformed input",
            DigestKey::MutationBroker => "mutationBroker: malformed input",
            DigestKey::AdmissionFenceDigest => "admissionFenceDigest: malformed input",
            DigestKey::RbacClosureDigest => "rbacClosureDigest: malformed input",
            DigestKey::NetworkEnforcementDigest => "networkEnforcementDigest: malformed input",
            DigestKey::HostPreflightDigest => "hostPreflightDigest: malformed input",
        }
    }

    /// "<key>: float refused" (README section 3.2). The two RBAC documents hold only B1-checked strings and booleans,
    /// so the contract pins no such text for them (README section 9).
    pub fn float_refused(self) -> Option<&'static str> {
        match self {
            DigestKey::AdmissionPolicy => Some("admissionPolicy: float refused"),
            DigestKey::ResourceQuota => Some("resourceQuota: float refused"),
            DigestKey::LimitRange => Some("limitRange: float refused"),
            DigestKey::ServiceAccount => Some("serviceAccount: float refused"),
            DigestKey::NetworkPolicy => Some("networkPolicy: float refused"),
            DigestKey::MutationBroker => Some("mutationBroker: float refused"),
            DigestKey::AdmissionFenceDigest => Some("admissionFenceDigest: float refused"),
            DigestKey::NetworkEnforcementDigest => Some("networkEnforcementDigest: float refused"),
            DigestKey::HostPreflightDigest => Some("hostPreflightDigest: float refused"),
            DigestKey::Rbac | DigestKey::RbacClosureDigest => None,
        }
    }

    /// "<key>: integer out of range" (README section 3.2); none for the two RBAC documents, as for floats.
    pub fn integer_out_of_range(self) -> Option<&'static str> {
        match self {
            DigestKey::AdmissionPolicy => Some("admissionPolicy: integer out of range"),
            DigestKey::ResourceQuota => Some("resourceQuota: integer out of range"),
            DigestKey::LimitRange => Some("limitRange: integer out of range"),
            DigestKey::ServiceAccount => Some("serviceAccount: integer out of range"),
            DigestKey::NetworkPolicy => Some("networkPolicy: integer out of range"),
            DigestKey::MutationBroker => Some("mutationBroker: integer out of range"),
            DigestKey::AdmissionFenceDigest => Some("admissionFenceDigest: integer out of range"),
            DigestKey::NetworkEnforcementDigest => Some("networkEnforcementDigest: integer out of range"),
            DigestKey::HostPreflightDigest => Some("hostPreflightDigest: integer out of range"),
            DigestKey::Rbac | DigestKey::RbacClosureDigest => None,
        }
    }

    /// "<key>: document bound exceeded" (README section 3.2).
    pub fn bound_exceeded(self) -> &'static str {
        match self {
            DigestKey::AdmissionPolicy => "admissionPolicy: document bound exceeded",
            DigestKey::ResourceQuota => "resourceQuota: document bound exceeded",
            DigestKey::LimitRange => "limitRange: document bound exceeded",
            DigestKey::ServiceAccount => "serviceAccount: document bound exceeded",
            DigestKey::Rbac => "rbac: document bound exceeded",
            DigestKey::NetworkPolicy => "networkPolicy: document bound exceeded",
            DigestKey::MutationBroker => "mutationBroker: document bound exceeded",
            DigestKey::AdmissionFenceDigest => "admissionFenceDigest: document bound exceeded",
            DigestKey::RbacClosureDigest => "rbacClosureDigest: document bound exceeded",
            DigestKey::NetworkEnforcementDigest => "networkEnforcementDigest: document bound exceeded",
            DigestKey::HostPreflightDigest => "hostPreflightDigest: document bound exceeded",
        }
    }

    /// "<key>: differs from the signed value" (README section 3.5), for the comparison with the signed binding.
    pub fn differs(self) -> &'static str {
        match self {
            DigestKey::AdmissionPolicy => "admissionPolicy: differs from the signed value",
            DigestKey::ResourceQuota => "resourceQuota: differs from the signed value",
            DigestKey::LimitRange => "limitRange: differs from the signed value",
            DigestKey::ServiceAccount => "serviceAccount: differs from the signed value",
            DigestKey::Rbac => "rbac: differs from the signed value",
            DigestKey::NetworkPolicy => "networkPolicy: differs from the signed value",
            DigestKey::MutationBroker => "mutationBroker: differs from the signed value",
            DigestKey::AdmissionFenceDigest => "admissionFenceDigest: differs from the signed value",
            DigestKey::RbacClosureDigest => "rbacClosureDigest: differs from the signed value",
            DigestKey::NetworkEnforcementDigest => "networkEnforcementDigest: differs from the signed value",
            DigestKey::HostPreflightDigest => "hostPreflightDigest: differs from the signed value",
        }
    }

    /// "<key>: count is not one" and "<key>: name differs from the binding", for the four one-object kinds (README
    /// sections 4.2 and 4.3).
    pub fn one_object(self) -> Option<(&'static str, &'static str)> {
        match self {
            DigestKey::ResourceQuota => {
                Some(("resourceQuota: count is not one", "resourceQuota: name differs from the binding"))
            }
            DigestKey::LimitRange => {
                Some(("limitRange: count is not one", "limitRange: name differs from the binding"))
            }
            DigestKey::ServiceAccount => {
                Some(("serviceAccount: count is not one", "serviceAccount: name differs from the binding"))
            }
            DigestKey::NetworkPolicy => {
                Some(("networkPolicy: count is not one", "networkPolicy: name differs from the binding"))
            }
            _ => None,
        }
    }

    /// A gated value's own text when no completed capture set exists or a required slot is not taken (README section
    /// 3.3); the capture gate's.
    pub fn capture_not_passed(self) -> Option<&'static str> {
        match self {
            DigestKey::MutationBroker => Some("mutationBroker: broker capture not passed"),
            DigestKey::NetworkEnforcementDigest => Some("networkEnforcementDigest: agent capture not passed"),
            DigestKey::HostPreflightDigest => Some("hostPreflightDigest: capture set not passed"),
            _ => None,
        }
    }

    /// "<key>: capture set too old" for a gated value (README section 3.3); the capture gate's.
    pub fn capture_too_old(self) -> Option<&'static str> {
        match self {
            DigestKey::MutationBroker => Some("mutationBroker: capture set too old"),
            DigestKey::NetworkEnforcementDigest => Some("networkEnforcementDigest: capture set too old"),
            DigestKey::HostPreflightDigest => Some("hostPreflightDigest: capture set too old"),
            _ => None,
        }
    }

    /// The exactness rule's text for a fault. For the two RBAC keys, whose documents hold no number (so neither a float
    /// nor an integer can reach their rule), every fault is the bound text.
    pub fn inexact(self, fault: Inexact) -> &'static str {
        match fault {
            Inexact::Float => self.float_refused().unwrap_or(self.bound_exceeded()),
            Inexact::Integer => self.integer_out_of_range().unwrap_or(self.bound_exceeded()),
            Inexact::Bound => self.bound_exceeded(),
        }
    }
}

/// One snapshot as the contract reads it (README section 2), every value from one read: B1's checked lists, the read's
/// resourceVersion, the configuration's values (`qualificationNamespace`, `pinnedManifestHash` and `sealedAdmission`),
/// ADM-4's loaded hash and the enrolled native-qualification v4 record. A member is `None` when the snapshot lacks it,
/// which refuses as the key's malformed input wherever the contract reads it; the observer always holds all four.
#[derive(Clone, Copy, Debug)]
pub struct DigestSnapshot<'a> {
    pub inputs: &'a Inputs,
    pub resource_version: Option<&'a Value>,
    pub configuration: Option<&'a Value>,
    pub adm4_loaded_hash: Option<&'a Value>,
    pub record: Option<&'a Value>,
}

/// The four sealed admission values admission v3's A2 render reads (README section 4.1), each checked: the
/// qualification namespace, `ipFamily` and `serviceCIDR` as non-empty text, and `defaultTolerationSeconds` an exact
/// integer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedAdmission {
    pub namespace: String,
    pub ip_family: String,
    pub service_cidr: String,
    pub default_toleration_seconds: i64,
}

/// The A2 render of the sealed values: the eight rendered objects and the sealed directory's hash (`sha256:<hex>`).
#[derive(Clone, Debug)]
pub struct Rendered {
    pub objects: Vec<Value>,
    pub directory_hash: String,
}

/// A projection: its document; the identity that is compared with the signed binding's (its fixed `apiVersion` and
/// `kind`, the object's `name`, `namespace` and `uid`, and the `projectionDigest`); and the resourceVersion the read
/// observed.
#[derive(Clone, Debug)]
pub struct ProjectionValue {
    pub document: Value,
    pub identity: Value,
    pub resource_version: Value,
}

/// An enforcement digest; the RBAC closure digest and the network digest also keep the document they digest.
#[derive(Clone, Debug)]
pub struct EnforcementValue {
    pub document: Option<Value>,
    pub digest: String,
}

/// Every refusal text the contract pins, sorted: this module's, and the capture gate's per-key texts.
pub fn refusal_texts() -> Vec<&'static str> {
    let mut texts = vec![
        RENDERED_HASH_DIFFERS, UNKNOWN_ADMISSION_OBJECT, NAMESPACE_NOT_LISTED, MOUNTABLE_SECRETS_ANNOTATION,
        SELECTOR_FORM, AGGREGATED_ROLE, ROLE_MISSING, LOOPBACK_NON_RESOURCE, CLOSURE_NOT_PASSED, BROKER_ROW_INCOMPLETE,
        NO_NETWORK_AGENT,
    ];
    texts.extend(B1_MALFORMED.iter().map(|&(_, text)| text));
    for key in DigestKey::POLICIES.into_iter().chain(DigestKey::DIGESTS) {
        texts.extend([key.malformed(), key.bound_exceeded(), key.differs()]);
        texts.extend(key.float_refused());
        texts.extend(key.integer_out_of_range());
        if let Some((count, name)) = key.one_object() {
            texts.extend([count, name]);
        }
        texts.extend(key.capture_not_passed());
        texts.extend(key.capture_too_old());
    }
    texts.sort_unstable();
    texts.dedup();
    texts
}

// ------------------------------------------------------------------------------------------------ common rules

/// A walk step of the exactness rule: a member name, or a value, each with its depth.
#[derive(Clone, Copy)]
enum ExactStep<'a> {
    Name(&'a JStr, usize),
    Item(&'a Value, usize),
}

/// The exactness rule (README section 3.2; the model's `document_bound`). A float anywhere refuses first. Then VPC's
/// `_bounded` in its order (depth first, each member's name before its value, members in document order), stopping at
/// its first fault: a node deeper than [`BOUND_DEPTH`]; the budget spent (each node costs one, a string or a member
/// name its number of code points, and the rest must stay at or above zero); or an integer past [`BOUND_INTEGER`] in
/// magnitude, checked after the node's cost.
pub fn exactness(value: &Value) -> Result<(), Inexact> {
    if json::contains_float(value) {
        return Err(Inexact::Float);
    }
    let mut budget = BOUND_BUDGET;
    let mut stack = vec![ExactStep::Item(value, 0)];
    while let Some(step) = stack.pop() {
        let (cost, depth) = match step {
            ExactStep::Name(name, depth) => (name.len_code_points(), depth),
            ExactStep::Item(Value::Str(text), depth) => (text.len_code_points(), depth),
            ExactStep::Item(_, depth) => (1, depth),
        };
        if depth > BOUND_DEPTH {
            return Err(Inexact::Bound);
        }
        budget = budget.checked_sub(cost).ok_or(Inexact::Bound)?;
        let ExactStep::Item(item, _) = step else {
            continue;
        };
        let deeper = depth.saturating_add(1);
        match item {
            Value::Int(int) => {
                if int.to_i128().is_none_or(|number| number.unsigned_abs() > u128::from(BOUND_INTEGER)) {
                    return Err(Inexact::Integer);
                }
            }
            Value::Array(items) => stack.extend(items.iter().rev().map(|child| ExactStep::Item(child, deeper))),
            Value::Object(object) => {
                for (name, member) in object.iter().rev() {
                    stack.push(ExactStep::Item(member, deeper));
                    stack.push(ExactStep::Name(name, deeper));
                }
            }
            // `_bounded` refuses any other kind of value as a bound fault; a float was refused above.
            Value::Float(_) => return Err(Inexact::Bound),
            Value::Null | Value::Bool(_) | Value::Str(_) => {}
        }
    }
    Ok(())
}

/// The exactness rule with the key's text.
pub fn exact(key: DigestKey, value: &Value) -> Result<(), &'static str> {
    exactness(value).map_err(|fault| key.inexact(fault))
}

/// `sha256:` and the lowercase hex SHA-256 of the value's canonical bytes (the contract's `projection_digest`), or
/// `None` when the value has no canonical encoding (a lone surrogate).
pub fn projection_digest(document: &Value) -> Option<String> {
    json::canonical(document).ok().map(|bytes| sha256::prefixed(&bytes))
}

/// The uid of a synthetic projection (README section 3.1): 64 lowercase hex digits, the SHA-256 of the canonical
/// encoding of its fixed `{apiVersion, kind, name, namespace}`.
pub fn synthetic_uid(group_version: &str, kind_name: &str, fixed_name: &str, scope: Option<&str>) -> String {
    let identity = Doc::object(vec![
        ("apiVersion", Doc::str(group_version)),
        ("kind", Doc::str(kind_name)),
        ("name", Doc::str(fixed_name)),
        ("namespace", Doc::opt_str(scope)),
    ]);
    sha256::hex(&sha256::digest(&identity.canonical()))
}

/// The model's `_text`: a non-empty string.
fn nonempty(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| !text.is_empty())
}

/// The model's `_member`: an object's member, else the key's malformed input.
fn member<'a>(value: &'a Value, name: &str, key: DigestKey) -> Result<&'a Value, &'static str> {
    value.get(name).ok_or(key.malformed())
}

/// Whether an object holds exactly these member names.
fn closed(object: &Object, names: &[&str]) -> bool {
    object.len() == names.len() && names.iter().all(|name| object.get(name).is_some())
}

/// The model's `_namespace`: the configuration's qualification namespace, non-empty text.
fn qualification_namespace<'a>(snapshot: &DigestSnapshot<'a>, key: DigestKey) -> Result<&'a str, &'static str> {
    let configuration = snapshot.configuration.ok_or(key.malformed())?;
    nonempty(member(configuration, "qualificationNamespace", key)?).ok_or(key.malformed())
}

/// The model's `_list`: a checked list's items, else the key's malformed input.
fn listed<'a>(snapshot: &DigestSnapshot<'a>, resource: Resource, key: DigestKey)
              -> Result<&'a [Value], &'static str> {
    snapshot.inputs.items(resource).map_err(|_| key.malformed())
}

/// The model's `_in_namespace`: the qualification namespace and the kind's items in it; every item must carry a name
/// and a namespace.
fn in_namespace<'a>(snapshot: &DigestSnapshot<'a>, resource: Resource, key: DigestKey)
                    -> Result<(&'a str, Vec<&'a Value>), &'static str> {
    let space = qualification_namespace(snapshot, key)?;
    let items = listed(snapshot, resource, key)?;
    let mut found = Vec::new();
    for item in items {
        let (Some(_), Some(namespace)) = (object_name(item), object_namespace(item)) else {
            return Err(key.malformed());
        };
        if namespace == space {
            found.push(item);
        }
    }
    Ok((space, found))
}

/// The model's `_bound_name`: the binding's `projections.<key>.name`, which must be text.
fn bound_name(binding: &Value, key: DigestKey) -> Result<&JStr, &'static str> {
    let bound = binding.get("projections").and_then(|projections| projections.get(key.name()));
    match bound.and_then(|bound| bound.get("name")) {
        Some(Value::Str(name)) => Ok(name),
        _ => Err(key.malformed()),
    }
}

/// Whether an item's name is the binding's name.
fn named(item: &Value, bound: &JStr) -> bool {
    object_name(item).is_some_and(|name| name.as_bytes() == bound.as_bytes())
}

/// The projection form `{apiVersion, kind, metadata, spec}` with the key's fixed identity.
fn document(key: DigestKey, metadata: Object, spec: Value) -> Value {
    let (api_version, kind) = key.api_version_and_kind().unwrap_or(("", ""));
    let mut root = Object::new();
    root.insert(JStr::new("apiVersion"), Value::str(api_version));
    root.insert(JStr::new("kind"), Value::str(kind));
    root.insert(JStr::new("metadata"), Value::Object(metadata));
    root.insert(JStr::new("spec"), spec);
    Value::Object(root)
}

/// The model's `_real_document`: a live object's name, namespace and uid (non-empty text) with the given `spec`.
fn real_document(key: DigestKey, item: &Value, spec: Value) -> Result<Value, &'static str> {
    let meta = item.get("metadata").ok_or(key.malformed())?;
    let (Some(name), Some(namespace)) = (meta.get("name"), meta.get("namespace")) else {
        return Err(key.malformed());
    };
    let uid = meta.get("uid").filter(|uid| nonempty(uid).is_some()).ok_or(key.malformed())?;
    let mut metadata = Object::new();
    metadata.insert(JStr::new("name"), name.clone());
    metadata.insert(JStr::new("namespace"), namespace.clone());
    metadata.insert(JStr::new("uid"), uid.clone());
    Ok(document(key, metadata, spec))
}

/// The model's `_synthetic_document`: the fixed name, the namespace (`None`: cluster-scoped) and the synthetic uid.
fn synthetic_document(key: DigestKey, name: &str, namespace: Option<&str>, spec: Value) -> Value {
    let (api_version, kind) = key.api_version_and_kind().unwrap_or(("", ""));
    let mut metadata = Object::new();
    metadata.insert(JStr::new("name"), Value::str(name));
    metadata.insert(JStr::new("namespace"), namespace.map_or(Value::Null, Value::str));
    metadata.insert(JStr::new("uid"), Value::str(&synthetic_uid(api_version, kind, name, namespace)));
    document(key, metadata, spec)
}

/// The end of the model's `_projection`: the observed resourceVersion (non-empty text), the exactness rule over the
/// document, then the identity with the projection digest.
fn finish(key: DigestKey, document: Value, version: Option<&Value>) -> Result<ProjectionValue, &'static str> {
    let version = version.filter(|version| nonempty(version).is_some()).ok_or(key.malformed())?;
    exact(key, &document)?;
    let digest = projection_digest(&document).ok_or(key.malformed())?;
    let meta = document.get("metadata").ok_or(key.malformed())?;
    let mut identity = Object::new();
    for name in ["apiVersion", "kind"] {
        identity.insert(JStr::new(name), document.get(name).ok_or(key.malformed())?.clone());
    }
    for name in ["name", "namespace", "uid"] {
        identity.insert(JStr::new(name), meta.get(name).ok_or(key.malformed())?.clone());
    }
    identity.insert(JStr::new("projectionDigest"), Value::str(&digest));
    Ok(ProjectionValue { document, identity: Value::Object(identity), resource_version: version.clone() })
}

// ------------------------------------------------------------------------------------------------ the projections

/// One of the seven projections at the snapshot (the model's `projection`), or the first refusal. `render` is the A2
/// render, called only for `admissionPolicy` once its sealed values pass; `None` from it is malformed input. A digest
/// key is not a projection and refuses as its malformed input.
pub fn projection(key: DigestKey, snapshot: &DigestSnapshot<'_>, binding: &Value,
                  render: &dyn Fn(&SealedAdmission) -> Option<Rendered>) -> Result<ProjectionValue, &'static str> {
    match key {
        DigestKey::AdmissionPolicy => admission_policy(snapshot, render),
        DigestKey::ResourceQuota => one_object(key, Resource::ResourceQuotas, snapshot, binding),
        DigestKey::LimitRange => one_object(key, Resource::LimitRanges, snapshot, binding),
        DigestKey::NetworkPolicy => one_object(key, Resource::NetworkPolicies, snapshot, binding),
        DigestKey::ServiceAccount => service_account(snapshot, binding),
        DigestKey::Rbac => rbac_projection(snapshot),
        DigestKey::MutationBroker => mutation_broker(snapshot),
        DigestKey::AdmissionFenceDigest
        | DigestKey::RbacClosureDigest
        | DigestKey::NetworkEnforcementDigest
        | DigestKey::HostPreflightDigest => Err(key.malformed()),
    }
}

/// `resourceQuota`, `limitRange` and `networkPolicy` (README section 4.2): exactly one object of the kind in the
/// qualification namespace, named as the binding names it, with its served `spec` (selector-free for a NetworkPolicy).
fn one_object(key: DigestKey, resource: Resource, snapshot: &DigestSnapshot<'_>, binding: &Value)
              -> Result<ProjectionValue, &'static str> {
    let (count_differs, name_differs) = key.one_object().unwrap_or((key.malformed(), key.malformed()));
    let (_, found) = in_namespace(snapshot, resource, key)?;
    let item = match found.as_slice() {
        [item] => *item,
        _ => return Err(count_differs),
    };
    let bound = bound_name(binding, key)?;
    if !named(item, bound) {
        return Err(name_differs);
    }
    let spec = item.get("spec").filter(|spec| spec.as_object().is_some()).ok_or(key.malformed())?;
    if key == DigestKey::NetworkPolicy {
        selector_free(spec)?;
    }
    let document = real_document(key, item, spec.clone())?;
    finish(key, document, item.get("metadata").and_then(|meta| meta.get("resourceVersion")))
}

/// `serviceAccount` (README section 4.3): the profile's subject `system:serviceaccount:<namespace>:<name>` names
/// exactly one ServiceAccount in the qualification namespace, the binding names it too, it carries no
/// enforce-mountable-secrets annotation, and its `spec` is its three enforcement keys, each only when present.
fn service_account(snapshot: &DigestSnapshot<'_>, binding: &Value) -> Result<ProjectionValue, &'static str> {
    let key = DigestKey::ServiceAccount;
    let (count_differs, name_differs) = key.one_object().unwrap_or((key.malformed(), key.malformed()));
    let (space, found) = in_namespace(snapshot, Resource::ServiceAccounts, key)?;
    let subject = match binding.get("scope").and_then(|scope| scope.get("serviceAccountSubject")) {
        Some(Value::Str(subject)) => subject,
        _ => return Err(key.malformed()),
    };
    let prefix = format!("{}{}:", SERVICE_ACCOUNT_PREFIX, space);
    let wanted = subject.as_bytes().strip_prefix(prefix.as_bytes());
    let matches: Vec<&Value> = found
        .into_iter()
        .filter(|item| wanted.is_some_and(|name| object_name(item).is_some_and(|own| own.as_bytes() == name)))
        .collect();
    let item = match matches.as_slice() {
        [item] => *item,
        _ => return Err(count_differs),
    };
    let bound = bound_name(binding, key)?;
    if !named(item, bound) {
        return Err(name_differs);
    }
    match item.get("metadata").and_then(|meta| meta.get("annotations")) {
        None | Some(Value::Null) => {}
        Some(Value::Object(annotations)) => {
            if annotations.get(MOUNTABLE_SECRETS).is_some() {
                return Err(MOUNTABLE_SECRETS_ANNOTATION);
            }
        }
        Some(_) => return Err(key.malformed()),
    }
    let mut spec = Object::new();
    for name in SERVICE_ACCOUNT_KEYS {
        if let Some(value) = item.get(name) {
            spec.insert(JStr::new(name), value.clone());
        }
    }
    let document = real_document(key, item, Value::Object(spec))?;
    finish(key, document, item.get("metadata").and_then(|meta| meta.get("resourceVersion")))
}

/// A list member of a selector-free spec, as the model's `get(name, [])` reads it: absent is empty, anything but an
/// array refuses.
fn selector_list<'a>(holder: &'a Object, name: &str) -> Result<&'a [Value], &'static str> {
    match holder.get(name) {
        None => Ok(Default::default()),
        Some(Value::Array(items)) => Ok(items.as_slice()),
        Some(_) => Err(SELECTOR_FORM),
    }
}

/// Whether every member name of an object is one of `names`.
fn names_within(object: &Object, names: &[&str]) -> bool {
    object.iter().all(|(name, _)| names.iter().any(|allowed| name.as_bytes() == allowed.as_bytes()))
}

/// v1's selector-free NetworkPolicy (README section 4.4; the model's `_selector_free`): only the NetworkPolicy v1 API's
/// members, `podSelector` exactly `{}`, every peer an `ipBlock` alone, every `port` and `endPort` an integer (an entry
/// without them is admitted). Anything else refuses with the selector text.
fn selector_free(spec: &Value) -> Result<(), &'static str> {
    let Some(members) = spec.as_object() else {
        return Err(SELECTOR_FORM);
    };
    if !names_within(members, &["podSelector", "policyTypes", "ingress", "egress"]) {
        return Err(SELECTOR_FORM);
    }
    if !matches!(members.get("podSelector"), Some(Value::Object(selector)) if selector.is_empty()) {
        return Err(SELECTOR_FORM);
    }
    for (direction, peers_name) in [("ingress", "from"), ("egress", "to")] {
        for rule in selector_list(members, direction)? {
            let Some(rule) = rule.as_object() else {
                return Err(SELECTOR_FORM);
            };
            if !names_within(rule, &[peers_name, "ports"]) {
                return Err(SELECTOR_FORM);
            }
            let peers = selector_list(rule, peers_name)?;
            if !peers.iter().all(|peer| peer.as_object().is_some_and(|peer| closed(peer, &["ipBlock"]))) {
                return Err(SELECTOR_FORM);
            }
            for port in selector_list(rule, "ports")? {
                let Some(port) = port.as_object() else {
                    return Err(SELECTOR_FORM);
                };
                if !names_within(port, &["protocol", "port", "endPort"]) {
                    return Err(SELECTOR_FORM);
                }
                for name in ["port", "endPort"] {
                    if !matches!(port.get(name), None | Some(Value::Int(_))) {
                        return Err(SELECTOR_FORM);
                    }
                }
            }
        }
    }
    Ok(())
}

/// `mutationBroker` (README section 4.6): the qualification namespace, then the v4 record's BROKER row with exactly its
/// 20 members and its cgroup's 7; the document's `spec` is the row's 14 members, the cgroup without its inode. The
/// capture gate is the answer's.
fn mutation_broker(snapshot: &DigestSnapshot<'_>) -> Result<ProjectionValue, &'static str> {
    let key = DigestKey::MutationBroker;
    let space = qualification_namespace(snapshot, key)?;
    let record = snapshot.record.ok_or(key.malformed())?;
    let row = record.get("roles").and_then(|roles| roles.get("BROKER"));
    let complete = row.and_then(Value::as_object).is_some_and(|members| closed(members, &BROKER_MEMBERS))
        && row
            .and_then(|row| row.get("cgroup"))
            .and_then(Value::as_object)
            .is_some_and(|cgroup| closed(cgroup, &CGROUP_MEMBERS));
    let Some(row) = row.filter(|_| complete) else {
        return Err(BROKER_ROW_INCOMPLETE);
    };
    let mut spec = Object::new();
    for name in BROKER_DOCUMENT {
        let value = row.get(name).ok_or(key.malformed())?;
        match value.as_object().filter(|_| name == "cgroup") {
            Some(cgroup) => {
                let mut kept = Object::new();
                for (member, inner) in cgroup.iter() {
                    if member.as_bytes() != CGROUP_INODE.as_bytes() {
                        kept.insert(member.clone(), inner.clone());
                    }
                }
                spec.insert(JStr::new(name), Value::Object(kept));
            }
            None => spec.insert(JStr::new(name), value.clone()),
        }
    }
    let document = synthetic_document(key, MUTATION_BROKER_NAME, Some(space), Value::Object(spec));
    finish(key, document, snapshot.resource_version)
}

// ------------------------------------------------------------------------------------------------ RBAC

/// A role's rule as the contract keeps it: its five string lists (absent or null lists empty).
struct DigestRoleRule {
    api_groups: Vec<Value>,
    resources: Vec<Value>,
    verbs: Vec<Value>,
    resource_names: Vec<Value>,
    non_resource_urls: Vec<Value>,
}

/// One subject of the contract's RBAC documents (README section 4.5): B1's `exists`, every rule of every binding that
/// names it in binding and rule order (a non-resource rule as `{nonResourceURLs, verbs, scope}`), and whether a
/// ClusterRoleBinding or a RoleBinding in the qualification namespace names it (the `rbac` subject set).
struct DigestRbacEntry {
    exists: bool,
    rules: Vec<Value>,
    local: bool,
}

/// A string list member of a rule: absent or null is empty; anything but an array of text is `None`.
fn string_list(holder: &Object, name: &str) -> Option<Vec<Value>> {
    match holder.get(name) {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().all(|item| item.as_str().is_some()).then(|| items.clone()),
        Some(_) => None,
    }
}

/// The rules of a role, each with its five lists; a role whose `rules` is missing or null has none.
fn role_rules(role: &Value) -> Option<Vec<DigestRoleRule>> {
    let items: &[Value] = match role.get("rules") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => return None,
    };
    items
        .iter()
        .map(|item| {
            let members = item.as_object()?;
            Some(DigestRoleRule {
                api_groups: string_list(members, "apiGroups")?,
                resources: string_list(members, "resources")?,
                verbs: string_list(members, "verbs")?,
                resource_names: string_list(members, "resourceNames")?,
                non_resource_urls: string_list(members, "nonResourceURLs")?,
            })
        })
        .collect()
}

/// A rule at its binding's scope: `{nonResourceURLs, verbs, scope}` when it names non-resource URLs, else B1's shape
/// `{apiGroups, resources, verbs, resourceNames, scope}`.
fn shaped_rule(rule: &DigestRoleRule, scope: &str) -> Value {
    let mut members = Object::new();
    if rule.non_resource_urls.is_empty() {
        members.insert(JStr::new("apiGroups"), Value::Array(rule.api_groups.clone()));
        members.insert(JStr::new("resources"), Value::Array(rule.resources.clone()));
        members.insert(JStr::new("verbs"), Value::Array(rule.verbs.clone()));
        members.insert(JStr::new("resourceNames"), Value::Array(rule.resource_names.clone()));
    } else {
        members.insert(JStr::new("nonResourceURLs"), Value::Array(rule.non_resource_urls.clone()));
        members.insert(JStr::new("verbs"), Value::Array(rule.verbs.clone()));
    }
    members.insert(JStr::new("scope"), Value::str(scope));
    Value::Object(members)
}

/// A binding's subjects, each as its (kind, name) key, B1's (README section 4.5), and for a ServiceAccount its
/// (namespace, name): User and Group by name; a ServiceAccount as `system:serviceaccount:<namespace>:<name>`, a
/// RoleBinding's without a namespace (absent, null or empty) in the binding's.
fn binding_subjects(binding: &Value, namespace: Option<&str>)
                    -> Option<Vec<(String, String, Option<(String, String)>)>> {
    let items: &[Value] = match binding.get("subjects") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => return None,
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let name = item.get("name").and_then(nonempty)?;
        let kind = item.get("kind").and_then(Value::as_str)?;
        if kind == "User" || kind == "Group" {
            out.push((kind.to_string(), name.to_string(), None));
            continue;
        }
        if kind != "ServiceAccount" {
            return None;
        }
        let own = match item.get("namespace") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_str()?).filter(|space| !space.is_empty()),
        };
        let space = own.or(namespace)?;
        out.push((
            kind.to_string(),
            format!("{}{}:{}", SERVICE_ACCOUNT_PREFIX, space, name),
            Some((space.to_string(), name.to_string())),
        ));
    }
    Some(out)
}

/// The contract's second derivation over the RBAC lists B1's producer has accepted (the model's `_rbac`): every
/// subject of every binding, ClusterRoleBindings first by name, then RoleBindings by namespace and name, with all its
/// rules. `None` only for a shape B1 would have refused.
fn rbac_entries(inputs: &Inputs, space: &str) -> Option<BTreeMap<(String, String), DigestRbacEntry>> {
    let cluster_roles = inputs.items(Resource::ClusterRoles).ok()?;
    let cluster_bindings = inputs.items(Resource::ClusterRoleBindings).ok()?;
    let roles = inputs.items(Resource::Roles).ok()?;
    let role_bindings = inputs.items(Resource::RoleBindings).ok()?;
    let accounts = inputs.items(Resource::ServiceAccounts).ok()?;
    let mut cluster_rules: BTreeMap<&str, Vec<DigestRoleRule>> = BTreeMap::new();
    for role in cluster_roles {
        cluster_rules.insert(object_name(role)?, role_rules(role)?);
    }
    let mut namespaced_rules: BTreeMap<(&str, &str), Vec<DigestRoleRule>> = BTreeMap::new();
    for role in roles {
        namespaced_rules.insert((object_namespace(role)?, object_name(role)?), role_rules(role)?);
    }
    let mut existing: BTreeSet<(&str, &str)> = BTreeSet::new();
    for account in accounts {
        existing.insert((object_namespace(account)?, object_name(account)?));
    }
    let mut bindings: Vec<(Option<&str>, &str, &Value)> =
        Vec::with_capacity(cluster_bindings.len().saturating_add(role_bindings.len()));
    for value in cluster_bindings {
        bindings.push((None, object_name(value)?, value));
    }
    for value in role_bindings {
        bindings.push((Some(object_namespace(value)?), object_name(value)?, value));
    }
    bindings.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
    let mut entries: BTreeMap<(String, String), DigestRbacEntry> = BTreeMap::new();
    for (namespace, _, value) in bindings {
        let reference = value.get("roleRef")?;
        let role_name = reference.get("name").and_then(nonempty)?;
        let rules = match (reference.get("kind").and_then(Value::as_str)?, namespace) {
            ("Role", Some(namespace)) => namespaced_rules.get(&(namespace, role_name))?,
            _ => cluster_rules.get(role_name)?,
        };
        let scope = namespace.unwrap_or(CLUSTER);
        let local = namespace.is_none_or(|namespace| namespace == space);
        for (kind, name, account) in binding_subjects(value, namespace)? {
            let exists = match &account {
                Some((account_space, account_name)) => {
                    existing.contains(&(account_space.as_str(), account_name.as_str()))
                }
                None => true,
            };
            let entry =
                entries.entry((kind, name)).or_insert(DigestRbacEntry { exists, rules: Vec::new(), local: false });
            entry.local = entry.local || local;
            entry.rules.extend(rules.iter().map(|rule| shaped_rule(rule, scope)));
        }
    }
    Some(entries)
}

/// B1's refusal as the contract writes it (README section 4.5).
fn b1_refusal(error: &ProduceError) -> &'static str {
    match error {
        ProduceError::Input(_) => DigestKey::Rbac.malformed(),
        ProduceError::LoopbackNonResource { .. } => LOOPBACK_NON_RESOURCE,
        ProduceError::AggregatedRole { .. } => AGGREGATED_ROLE,
        ProduceError::DanglingRoleRef { .. } => ROLE_MISSING,
        ProduceError::Malformed { field, .. } => B1_MALFORMED
            .iter()
            .find(|&&(name, _)| name == *field)
            .map_or(DigestKey::Rbac.malformed(), |&(_, text)| text),
    }
}

/// B1's producer over the lists (its refusals first, in its order), then the contract's second derivation.
fn rbac_derivation(inputs: &Inputs, space: &str)
                   -> Result<(rbac::Produced, BTreeMap<(String, String), DigestRbacEntry>), &'static str> {
    let produced = rbac::produce_snapshot(inputs, space).map_err(|error| b1_refusal(&error))?;
    let entries = rbac_entries(inputs, space).ok_or(DigestKey::Rbac.malformed())?;
    Ok((produced, entries))
}

/// The contract's entry `{kind, name, exists, effectiveRules}`: the subject's rules, only those at the qualification
/// namespace or `CLUSTER` when `space` is given, deduplicated and sorted by their canonical bytes.
fn entry_value(subject: &(String, String), entry: &DigestRbacEntry, space: Option<&str>) -> Option<Value> {
    let mut unique: BTreeMap<Vec<u8>, &Value> = BTreeMap::new();
    for rule in &entry.rules {
        let scope = rule.get("scope").and_then(Value::as_str);
        let kept = match space {
            None => true,
            Some(space) => scope.is_some_and(|scope| scope == space || scope == CLUSTER),
        };
        if kept {
            unique.insert(json::canonical(rule).ok()?, rule);
        }
    }
    let mut members = Object::new();
    members.insert(JStr::new("kind"), Value::str(&subject.0));
    members.insert(JStr::new("name"), Value::str(&subject.1));
    members.insert(JStr::new("exists"), Value::Bool(entry.exists));
    members.insert(JStr::new("effectiveRules"), Value::Array(unique.into_values().cloned().collect()));
    Some(Value::Object(members))
}

/// `rbac` (README section 4.5): the qualification namespace, B1's refusals, then one entry per subject a RoleBinding
/// in the qualification namespace or any ClusterRoleBinding names, sorted by (kind, name), with its rules at the
/// qualification namespace or `CLUSTER`.
fn rbac_projection(snapshot: &DigestSnapshot<'_>) -> Result<ProjectionValue, &'static str> {
    let key = DigestKey::Rbac;
    let space = qualification_namespace(snapshot, key)?;
    let (_, entries) = rbac_derivation(snapshot.inputs, space)?;
    let subjects = entries
        .iter()
        .filter(|(_, entry)| entry.local)
        .map(|(subject, entry)| entry_value(subject, entry, Some(space)))
        .collect::<Option<Vec<Value>>>()
        .ok_or(key.malformed())?;
    let mut spec = Object::new();
    spec.insert(JStr::new("subjects"), Value::Array(subjects));
    let document = synthetic_document(key, RBAC_NAME, Some(space), Value::Object(spec));
    finish(key, document, snapshot.resource_version)
}

// ------------------------------------------------------------------------------------------------ admission

/// The first part of the model's `_rendered`: the qualification namespace, then `sealedAdmission` with exactly its
/// three members, exact (README section 3.2), `ipFamily` and `serviceCIDR` non-empty text and
/// `defaultTolerationSeconds` an integer. The caller renders these values.
pub fn sealed_admission(key: DigestKey, snapshot: &DigestSnapshot<'_>) -> Result<SealedAdmission, &'static str> {
    let configuration = snapshot.configuration.ok_or(key.malformed())?;
    let namespace = qualification_namespace(snapshot, key)?;
    let sealed = member(configuration, "sealedAdmission", key)?;
    if !sealed.as_object().is_some_and(|members| closed(members, &SEALED_VALUES)) {
        return Err(key.malformed());
    }
    exact(key, sealed)?;
    let (Some(ip_family), Some(service_cidr), Some(seconds)) = (
        sealed.get("ipFamily").and_then(nonempty),
        sealed.get("serviceCIDR").and_then(nonempty),
        sealed.get("defaultTolerationSeconds").and_then(Value::as_int).and_then(|int| int.to_i64()),
    ) else {
        return Err(key.malformed());
    };
    Ok(SealedAdmission {
        namespace: namespace.to_string(),
        ip_family: ip_family.to_string(),
        service_cidr: service_cidr.to_string(),
        default_toleration_seconds: seconds,
    })
}

/// The model's `_rendered`: the sealed values checked and rendered, then the directory hash equal to both the signed
/// `pinnedManifestHash` and ADM-4's loaded hash (README sections 4.1 and 5.1).
fn rendered(key: DigestKey, snapshot: &DigestSnapshot<'_>, render: &dyn Fn(&SealedAdmission) -> Option<Rendered>)
            -> Result<Rendered, &'static str> {
    let sealed = sealed_admission(key, snapshot)?;
    let rendered = render(&sealed).ok_or(key.malformed())?;
    let configuration = snapshot.configuration.ok_or(key.malformed())?;
    let pin = member(configuration, "pinnedManifestHash", key)?;
    let loaded = snapshot.adm4_loaded_hash.ok_or(key.malformed())?;
    let hash = rendered.directory_hash.as_bytes();
    let same = |value: &Value| matches!(value, Value::Str(text) if text.as_bytes() == hash);
    if !(same(pin) && same(loaded)) {
        return Err(RENDERED_HASH_DIFFERS);
    }
    Ok(rendered)
}

/// A rendered object's kind and name.
fn kind_and_name(object: &Value) -> Option<(&str, &str)> {
    let kind = object.get("kind").and_then(Value::as_str)?;
    let name = object.get("metadata").and_then(|meta| meta.get("name")).and_then(Value::as_str)?;
    Some((kind, name))
}

/// `admissionPolicy` (README section 4.1): the rendered objects, bound to the two hashes; every listed
/// ValidatingAdmissionPolicy and binding one of the rendered (kind, name) pairs; the qualification Namespace listed
/// exactly once; the document's `spec` the eight objects sorted by (kind, name) and the Namespace's Pod Security
/// labels.
fn admission_policy(snapshot: &DigestSnapshot<'_>, render: &dyn Fn(&SealedAdmission) -> Option<Rendered>)
                    -> Result<ProjectionValue, &'static str> {
    let key = DigestKey::AdmissionPolicy;
    let space = qualification_namespace(snapshot, key)?;
    let rendered = rendered(key, snapshot, render)?;
    let mut sealed_objects = Vec::with_capacity(rendered.objects.len());
    for object in &rendered.objects {
        sealed_objects.push((kind_and_name(object).ok_or(key.malformed())?, object));
    }
    for (resource, kind) in [(Resource::ValidatingAdmissionPolicies, POLICY_KIND),
                             (Resource::ValidatingAdmissionPolicyBindings, BINDING_KIND)] {
        for item in listed(snapshot, resource, key)? {
            let name = object_name(item).ok_or(key.malformed())?;
            if !sealed_objects.iter().any(|(pair, _)| *pair == (kind, name)) {
                return Err(UNKNOWN_ADMISSION_OBJECT);
            }
        }
    }
    let namespaces: Vec<&Value> =
        listed(snapshot, Resource::Namespaces, key)?.iter().filter(|item| object_name(item) == Some(space)).collect();
    let namespace = match namespaces.as_slice() {
        [namespace] => *namespace,
        _ => return Err(NAMESPACE_NOT_LISTED),
    };
    let mut labels = Object::new();
    match namespace.get("metadata").and_then(|meta| meta.get("labels")) {
        None | Some(Value::Null) => {}
        Some(Value::Object(members)) => {
            if !members.iter().all(|(_, value)| matches!(value, Value::Str(_))) {
                return Err(key.malformed());
            }
            for (label, value) in members.iter() {
                if label.as_bytes().starts_with(POD_SECURITY_PREFIX.as_bytes()) {
                    labels.insert(label.clone(), value.clone());
                }
            }
        }
        Some(_) => return Err(key.malformed()),
    }
    sealed_objects.sort_by(|left, right| left.0.cmp(&right.0));
    let sorted: Vec<Value> = sealed_objects.into_iter().map(|(_, object)| object.clone()).collect();
    let mut spec = Object::new();
    spec.insert(JStr::new("sealedObjects"), Value::Array(sorted));
    spec.insert(JStr::new("podSecurityLabels"), Value::Object(labels));
    let document = synthetic_document(key, ADMISSION_POLICY_NAME, None, Value::Object(spec));
    finish(key, document, snapshot.resource_version)
}

// ------------------------------------------------------------------------------------------------ the digests

/// One enforcement digest taken from the snapshot (the model's `enforcement`), or its first refusal; the RBAC closure
/// digest and the network digest also return the document they digest. `closure` is I06's embedded closure
/// (`Closure::embedded`) and `render` the A2 render, as for [`projection`]. The capture gates are the answer's. A
/// projection key is not a digest and refuses as its malformed input.
pub fn enforcement(key: DigestKey, snapshot: &DigestSnapshot<'_>, closure: &Closure,
                   render: &dyn Fn(&SealedAdmission) -> Option<Rendered>) -> Result<EnforcementValue, &'static str> {
    match key {
        DigestKey::AdmissionFenceDigest => {
            let rendered = rendered(key, snapshot, render)?;
            Ok(EnforcementValue { document: None, digest: rendered.directory_hash })
        }
        DigestKey::RbacClosureDigest => rbac_closure_digest(snapshot, closure),
        DigestKey::NetworkEnforcementDigest => network_enforcement_digest(snapshot),
        DigestKey::HostPreflightDigest => host_preflight_digest(snapshot),
        DigestKey::AdmissionPolicy
        | DigestKey::ResourceQuota
        | DigestKey::LimitRange
        | DigestKey::ServiceAccount
        | DigestKey::Rbac
        | DigestKey::NetworkPolicy
        | DigestKey::MutationBroker => Err(key.malformed()),
    }
}

/// The exactness rule over an enforcement document, then its digest.
fn with_document(key: DigestKey, document: Value) -> Result<EnforcementValue, &'static str> {
    exact(key, &document)?;
    let digest = projection_digest(&document).ok_or(key.malformed())?;
    Ok(EnforcementValue { document: Some(document), digest })
}

/// `rbacClosureDigest` (README section 5.2): the qualification namespace (its own malformed text), B1's refusals, then
/// I06's closure check and I06 v4's role pin on B1's snapshot and the read's ClusterRoles, ClusterRoleBindings and
/// RoleBindings (`Closure::check` and `observer_rbac::check_observer_snapshot`, as `observe.rs` runs them); the
/// document holds every subject of every binding with all its rules at every scope.
fn rbac_closure_digest(snapshot: &DigestSnapshot<'_>, closure: &Closure) -> Result<EnforcementValue, &'static str> {
    let key = DigestKey::RbacClosureDigest;
    let space = qualification_namespace(snapshot, key)?;
    let (produced, entries) = rbac_derivation(snapshot.inputs, space)?;
    if closure.check(&produced.snapshot, space).is_err() {
        return Err(CLOSURE_NOT_PASSED);
    }
    let lists = RbacLists {
        cluster_roles: listed(snapshot, Resource::ClusterRoles, key)?,
        cluster_role_bindings: listed(snapshot, Resource::ClusterRoleBindings, key)?,
        role_bindings: listed(snapshot, Resource::RoleBindings, key)?,
    };
    if observer_rbac::check_observer_snapshot(&produced.snapshot, lists).is_err() {
        return Err(CLOSURE_NOT_PASSED);
    }
    let subjects = entries
        .iter()
        .map(|(subject, entry)| entry_value(subject, entry, None))
        .collect::<Option<Vec<Value>>>()
        .ok_or(key.malformed())?;
    let mut document = Object::new();
    document.insert(JStr::new("schemaVersion"), Value::str(CLOSURE_VERSION));
    document.insert(JStr::new("subjects"), Value::Array(subjects));
    with_document(key, Value::Object(document))
}

/// The qualification namespace's NetworkPolicy documents for the network digest (the model's `_network_documents`):
/// exactly one in v1, selector-free and exact, each refusal with networkPolicy's text.
fn network_documents(snapshot: &DigestSnapshot<'_>) -> Result<Vec<Value>, &'static str> {
    let key = DigestKey::NetworkPolicy;
    let (count_differs, _) = key.one_object().unwrap_or((key.malformed(), key.malformed()));
    let (_, found) = in_namespace(snapshot, Resource::NetworkPolicies, key)?;
    if found.len() != 1 {
        return Err(count_differs);
    }
    let mut documents = Vec::with_capacity(found.len());
    for item in found {
        let spec = item.get("spec").filter(|spec| spec.as_object().is_some()).ok_or(key.malformed())?;
        selector_free(spec)?;
        let document = real_document(key, item, spec.clone())?;
        exact(key, &document)?;
        documents.push(document);
    }
    Ok(documents)
}

/// `networkEnforcementDigest` (README section 5.3): the NetworkPolicy documents sorted by their canonical bytes, and
/// the record's network policy agent, which `backendComponents` and `backendProfile.componentKeys` must both name.
fn network_enforcement_digest(snapshot: &DigestSnapshot<'_>) -> Result<EnforcementValue, &'static str> {
    let key = DigestKey::NetworkEnforcementDigest;
    let policies = network_documents(snapshot)?;
    let record = snapshot.record.ok_or(key.malformed())?;
    let components = record.get("backendComponents").and_then(Value::as_object);
    let component_keys =
        record.get("backendProfile").and_then(|profile| profile.get("componentKeys")).and_then(Value::as_array);
    let listed_agent = components.is_some_and(|components| components.get(AGENT).is_some())
        && component_keys.is_some_and(|names| names.iter().any(|name| name.as_str() == Some(AGENT)));
    if !listed_agent {
        return Err(NO_NETWORK_AGENT);
    }
    let agent = components
        .and_then(|components| components.get(AGENT))
        .and_then(Value::as_object)
        .filter(|agent| AGENT_MEMBERS.iter().all(|name| agent.get(name).is_some()))
        .ok_or(key.malformed())?;
    let mut sorted = Vec::with_capacity(policies.len());
    for policy in policies {
        sorted.push((json::canonical(&policy).map_err(|_| key.malformed())?, policy));
    }
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut agent_members = Object::new();
    for name in AGENT_MEMBERS {
        agent_members.insert(JStr::new(name), agent.get(name).ok_or(key.malformed())?.clone());
    }
    let mut document = Object::new();
    document.insert(JStr::new("networkPolicies"), Value::Array(sorted.into_iter().map(|(_, policy)| policy).collect()));
    document.insert(JStr::new("agent"), Value::Object(agent_members));
    with_document(key, Value::Object(document))
}

/// `hostPreflightDigest` (README section 5.4): `sha256:` and the SHA-256 of the enrolled record's canonical bytes, the
/// record an exact object.
fn host_preflight_digest(snapshot: &DigestSnapshot<'_>) -> Result<EnforcementValue, &'static str> {
    let key = DigestKey::HostPreflightDigest;
    let record = snapshot.record.filter(|record| record.as_object().is_some()).ok_or(key.malformed())?;
    exact(key, record)?;
    let digest = projection_digest(record).ok_or(key.malformed())?;
    Ok(EnforcementValue { document: None, digest })
}
