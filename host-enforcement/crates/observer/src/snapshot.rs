//! The RBAC snapshot check (HE-004B1 DESIGN-B section 4.3; I06-3; owner decision Q-HE4B-4 (a)): IC00-IC05 as I06 v1
//! states them and then I06 v2's IC03 for the loopback user, over the embedded, digest-pinned identity closure, writer
//! inventory and bootstrap RBAC (`crate::contracts`); no caller-supplied closure.
//!
//! The order of the checks is the pinned model's (`scripts/i06_backend_profile.py` `check_rbac_snapshot` and its v2
//! wrapper), because the vectors pin the first refusal; the code is written independently (the Q-HE2-R1 precedent,
//! disclosed in MODEL_DEFINED). Refusal texts that the I06 v2 vectors pin are contract text; the shorter unpinned ones
//! are R10's. The tables below are upstream Kubernetes identifiers transcribed as data; `tests/observer_snapshot.rs` pins
//! each table's canonical digest, computed from the model, and wires every row.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use i05_protocol::json::{self, Object, Value};

use crate::contracts;
use crate::rbac::{CLUSTER, LOOPBACK_USER, SERVICE_ACCOUNT_PREFIX, SNAPSHOT_VERSION};

const CORE: &str = "";
const RBAC: &str = "rbac.authorization.k8s.io";
const NETWORKING: &str = "networking.k8s.io";
const ADMISSION: &str = "admissionregistration.k8s.io";
const AGGREGATOR: &str = "apiregistration.k8s.io";
const EXTENSIONS: &str = "apiextensions.k8s.io";
const CERTIFICATES: &str = "certificates.k8s.io";
const FLOW_CONTROL: &str = "flowcontrol.apiserver.k8s.io";
const AUTHENTICATION: &str = "authentication.k8s.io";
const APPS_GROUP: &str = "apps";
const BATCH_GROUP: &str = "batch";
const KUBE_SYSTEM: &str = "kube-system";

/// Writes to these (group, resource) pairs change a policy fact (22 rows).
pub const POLICY_RESOURCES: [(&str, &str); 22] = [
    (CORE, "limitranges"), (CORE, "namespaces"), (CORE, "namespaces/finalize"), (CORE, "resourcequotas"),
    (CORE, "serviceaccounts"),
    (ADMISSION, "mutatingadmissionpolicies"), (ADMISSION, "mutatingadmissionpolicybindings"),
    (ADMISSION, "mutatingwebhookconfigurations"), (ADMISSION, "validatingadmissionpolicies"),
    (ADMISSION, "validatingadmissionpolicybindings"), (ADMISSION, "validatingwebhookconfigurations"),
    (EXTENSIONS, "customresourcedefinitions"),
    (AGGREGATOR, "apiservices"),
    (CERTIFICATES, "certificatesigningrequests/approval"), (CERTIFICATES, "certificatesigningrequests/status"),
    (FLOW_CONTROL, "flowschemas"), (FLOW_CONTROL, "prioritylevelconfigurations"),
    (NETWORKING, "networkpolicies"),
    (RBAC, "clusterrolebindings"), (RBAC, "clusterroles"), (RBAC, "rolebindings"), (RBAC, "roles"),
];

/// Status subresources whose writes are policy-relevant (7 rows).
pub const STATUS_RESOURCES: [(&str, &str); 7] = [
    (CORE, "namespaces/status"), (CORE, "resourcequotas/status"), (ADMISSION, "validatingadmissionpolicies/status"),
    (EXTENSIONS, "customresourcedefinitions/status"), (AGGREGATOR, "apiservices/status"),
    (FLOW_CONTROL, "flowschemas/status"), (FLOW_CONTROL, "prioritylevelconfigurations/status"),
];

/// The verbs the kubelet's API reaches through its proxy, log and checkpoint subresources (model order).
pub const KUBELET_VERBS: [&str; 5] = ["get", "create", "update", "patch", "delete"];

/// Verbs that take another identity's authority or widen one's own, per (group, resource) (20 rows; verbs in model
/// order). A verb `impersonate:<mode>` or `impersonate-on:<..>` counts as `impersonate`.
pub const SPECIAL_TARGETS: [(&str, &str, &[&str]); 20] = [
    (CORE, "groups", &["impersonate"]), (CORE, "nodes", &["proxy"]), (CORE, "nodes/checkpoint", &KUBELET_VERBS),
    (CORE, "nodes/log", &KUBELET_VERBS), (CORE, "nodes/proxy", &KUBELET_VERBS), (CORE, "pods/attach", &["create", "get"]),
    (CORE, "pods/exec", &["create", "get"]), (CORE, "serviceaccounts", &["impersonate"]),
    (CORE, "serviceaccounts/token", &["create"]), (CORE, "users", &["impersonate"]),
    (AUTHENTICATION, "admissionReviewAPIGroups", &["attest"]), (AUTHENTICATION, "groups", &["impersonate"]),
    (AUTHENTICATION, "nodes", &["impersonate"]), (AUTHENTICATION, "serviceaccounts", &["impersonate"]),
    (AUTHENTICATION, "uids", &["impersonate"]), (AUTHENTICATION, "userextras/*", &["impersonate"]),
    (AUTHENTICATION, "users", &["impersonate"]),
    (CERTIFICATES, "signers", &["approve", "sign", "attest"]),
    (RBAC, "clusterroles", &["escalate", "bind"]), (RBAC, "roles", &["escalate", "bind"]),
];

/// Pod-creating kinds: a write runs code as any service account of its namespace, so it counts at cluster scope and in
/// the protected namespaces (9 rows).
pub const WORKLOAD_RESOURCES: [(&str, &str); 9] = [
    (CORE, "pods"), (CORE, "pods/ephemeralcontainers"), (CORE, "replicationcontrollers"),
    (APPS_GROUP, "daemonsets"), (APPS_GROUP, "deployments"), (APPS_GROUP, "replicasets"), (APPS_GROUP, "statefulsets"),
    (BATCH_GROUP, "cronjobs"), (BATCH_GROUP, "jobs"),
];

/// The write verbs (model order).
pub const WRITE_VERBS: [&str; 5] = ["create", "update", "patch", "delete", "deletecollection"];
/// The workload verbs (model order).
pub const WORKLOAD_VERBS: [&str; 3] = ["create", "update", "patch"];
/// The namespaces where workload writes count as at cluster scope.
pub const PROTECTED_NAMESPACES: [&str; 1] = [KUBE_SYSTEM];
/// The namespaces the qualification namespace may not be (model order).
pub const SYSTEM_NAMESPACES: [&str; 4] = ["default", "kube-node-lease", "kube-public", KUBE_SYSTEM];

/// The closure's placeholder for the qualification namespace in an allowed grant's scope.
const QUALIFICATION_SCOPE: &str = "QUALIFICATION_NAMESPACE";
/// The writer inventory's controllers run in this namespace.
const CONTROLLER_NAMESPACE: &str = "kube-system";

const SNAPSHOT_KEYS: [&str; 2] = ["schemaVersion", "subjects"];
const SUBJECT_KEYS: [&str; 4] = ["kind", "name", "exists", "effectiveRules"];
const RULE_KEYS: [&str; 5] = ["apiGroups", "resources", "verbs", "resourceNames", "scope"];

/// A refusal of the snapshot check: the first broken rule, as text that starts with its code (IC00-IC05).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal(String);

impl Refusal {
    fn new(text: impl Into<String>) -> Refusal {
        Refusal(text.into())
    }

    pub fn text(&self) -> &str {
        &self.0
    }

    /// The rule's code, the text's first word (`IC00` .. `IC05`; `IC` for the embedded data's own refusals).
    pub fn code(&self) -> &str {
        self.0.split(' ').next().unwrap_or("")
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.0)
    }
}

/// One policy-relevant grant: (category, `group/resource`, verb, scope), ordered as the model sorts its tuples.
pub type Grant = (&'static str, String, String, String);

/// A rule as the snapshot carries it, its lists read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    groups: Vec<String>,
    resources: Vec<String>,
    verbs: Vec<String>,
    names: Vec<String>,
    scope: String,
}

/// One allowed grant of a closure entry (`ALL`, or one row; a scope of `QUALIFICATION_NAMESPACE` stands for the
/// qualification namespace) or of a dormant account's bootstrap baseline.
#[derive(Clone, Debug)]
enum Allowed {
    All,
    Row { category: String, resource: String, verb: String, scope: String },
}

#[derive(Clone, Debug)]
struct Entry {
    must_be_present: bool,
    names: Option<Vec<String>>,
    allowed: Vec<Allowed>,
}

/// The embedded closure, read once: its entries by (kind, name), the controller accounts of the writer inventory, and
/// each bootstrap subject's rules.
#[derive(Clone, Debug)]
pub struct Closure {
    entries: BTreeMap<(String, String), Entry>,
    accounts: BTreeSet<String>,
    bootstrap: BTreeMap<(String, String), Vec<Rule>>,
}

fn embedded(raw: &[u8], what: &str) -> Result<Value, Refusal> {
    let text = std::str::from_utf8(raw).map_err(|_| Refusal::new(format!("IC the embedded {} is not UTF-8", what)))?;
    json::parse(text).map_err(|_| Refusal::new(format!("IC the embedded {} is not JSON", what)))
}

fn closed(object: &Object, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.get(key).is_some())
}

fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    value?.as_array()?.iter().map(|item| item.as_str().map(str::to_string)).collect()
}

fn unreadable(what: &str) -> Refusal {
    Refusal::new(format!("IC the embedded {} does not have its pinned shape", what))
}

impl Closure {
    /// Reads the three embedded files (their bytes are pinned by `tools/gate.py` and the tests).
    pub fn embedded() -> Result<Closure, Refusal> {
        let closure = embedded(contracts::IDENTITY_CLOSURE, "identity closure")?;
        let inventory = embedded(contracts::WRITER_INVENTORY, "writer inventory")?;
        let bootstrap = embedded(contracts::BOOTSTRAP_RBAC, "bootstrap RBAC")?;
        let mut entries = BTreeMap::new();
        for identity in closure.get("identities").and_then(Value::as_array).ok_or_else(|| unreadable("identity closure"))? {
            let kind = identity.get("kind").and_then(Value::as_str).ok_or_else(|| unreadable("identity closure"))?;
            let name = identity.get("name").and_then(Value::as_str).ok_or_else(|| unreadable("identity closure"))?;
            let must_be_present =
                identity.get("mustBePresent").and_then(Value::as_bool).ok_or_else(|| unreadable("identity closure"))?;
            let names = match identity.get("resourceNames") {
                Some(Value::Null) => None,
                other => Some(string_list(other).ok_or_else(|| unreadable("identity closure"))?),
            };
            let mut allowed = Vec::new();
            for row in identity.get("allowedGrants").and_then(Value::as_array).ok_or_else(|| unreadable("identity closure"))? {
                let field = |key: &str| row.get(key).and_then(Value::as_str).map(str::to_string);
                let (Some(category), Some(resource), Some(verb), Some(scope)) =
                    (field("category"), field("resource"), field("verb"), field("scope"))
                else {
                    return Err(unreadable("identity closure"));
                };
                allowed.push(if category == "ALL" { Allowed::All } else { Allowed::Row { category, resource, verb, scope } });
            }
            entries.insert((kind.to_string(), name.to_string()), Entry { must_be_present, names, allowed });
        }
        let mut accounts = BTreeSet::new();
        for controller in inventory.get("controllers").and_then(Value::as_array).ok_or_else(|| unreadable("writer inventory"))? {
            match controller.get("serviceAccount") {
                Some(Value::Null) => {}
                Some(value) => match value.as_str() {
                    Some("") => {}
                    Some(account) => {
                        accounts.insert(format!("{}{}:{}", SERVICE_ACCOUNT_PREFIX, CONTROLLER_NAMESPACE, account));
                    }
                    None => return Err(unreadable("writer inventory")),
                },
                None => return Err(unreadable("writer inventory")),
            }
        }
        let mut subjects = BTreeMap::new();
        for subject in bootstrap.get("subjects").and_then(Value::as_array).ok_or_else(|| unreadable("bootstrap RBAC"))? {
            let kind = subject.get("kind").and_then(Value::as_str).ok_or_else(|| unreadable("bootstrap RBAC"))?;
            let name = subject.get("name").and_then(Value::as_str).ok_or_else(|| unreadable("bootstrap RBAC"))?;
            let mut rules = Vec::new();
            for rule in subject.get("rules").and_then(Value::as_array).ok_or_else(|| unreadable("bootstrap RBAC"))? {
                let (Some(groups), Some(resources), Some(verbs), Some(names), Some(scope)) = (
                    string_list(rule.get("apiGroups")),
                    string_list(rule.get("resources")),
                    string_list(rule.get("verbs")),
                    string_list(rule.get("resourceNames")),
                    rule.get("scope").and_then(Value::as_str),
                ) else {
                    return Err(unreadable("bootstrap RBAC"));
                };
                rules.push(Rule { groups, resources, verbs, names, scope: scope.to_string() });
            }
            if subjects.insert((kind.to_string(), name.to_string()), rules).is_some() {
                return Err(unreadable("bootstrap RBAC"));
            }
        }
        Ok(Closure { entries, accounts, bootstrap: subjects })
    }

    /// I06 v2's check: v1's, then the loopback user holds no rule at all.
    pub fn check(&self, snapshot: &Value, namespace: &str) -> Result<(), Refusal> {
        self.check_v1(snapshot, namespace)?;
        let subjects = snapshot.get("subjects").and_then(Value::as_array).unwrap_or(&[]);
        for subject in subjects {
            let loopback = subject.get("kind").and_then(Value::as_str) == Some("User")
                && subject.get("name").and_then(Value::as_str) == Some(LOOPBACK_USER);
            let holds = subject.get("effectiveRules").and_then(Value::as_array).is_some_and(|rules| !rules.is_empty());
            if loopback && holds {
                return Err(Refusal::new("IC03 the loopback user system:apiserver holds an RBAC rule"));
            }
        }
        Ok(())
    }

    /// I06 v1's check (IC00-IC05) in the model's order.
    pub fn check_v1(&self, snapshot: &Value, namespace: &str) -> Result<(), Refusal> {
        if !dns_label(namespace) || SYSTEM_NAMESPACES.contains(&namespace) {
            return Err(Refusal::new("IC00 qualification namespace must be a dedicated namespace"));
        }
        let Some(root) = snapshot.as_object().filter(|root| closed(root, &SNAPSHOT_KEYS)) else {
            return Err(Refusal::new("IC00 the snapshot is not the closed record"));
        };
        let versioned = root.get("schemaVersion").and_then(Value::as_str) == Some(SNAPSHOT_VERSION);
        let Some(subjects) = root.get("subjects").and_then(Value::as_array).filter(|_| versioned) else {
            return Err(Refusal::new("IC00 the snapshot's version or subject list"));
        };
        let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
        for subject in subjects {
            let Some(members) = subject.as_object().filter(|members| closed(members, &SUBJECT_KEYS)) else {
                return Err(Refusal::new("IC00 a subject is not the closed form"));
            };
            let kind = members.get("kind").and_then(Value::as_str).filter(|kind| ["User", "Group", "ServiceAccount"].contains(kind));
            let name = members.get("name").and_then(Value::as_str).filter(|name| stripped(name));
            let exists = members.get("exists").and_then(Value::as_bool);
            let listed = members.get("effectiveRules").and_then(Value::as_array);
            let (Some(kind), Some(name), Some(exists), Some(listed)) = (kind, name, exists, listed) else {
                return Err(Refusal::new("IC00 a subject's kind, name, exists or effectiveRules"));
            };
            if (kind == "ServiceAccount") != name.starts_with(SERVICE_ACCOUNT_PREFIX) {
                return Err(Refusal::new("IC00 service-account usernames must use kind ServiceAccount"));
            }
            if kind != "ServiceAccount" && !exists {
                return Err(Refusal::new("IC00 only service accounts can be absent"));
            }
            if !seen.insert((kind, name)) {
                return Err(Refusal::new("IC00 duplicate subject"));
            }
            let mut rules = Vec::with_capacity(listed.len());
            for value in listed {
                rules.push(read_rule(value).ok_or_else(|| Refusal::new("IC00 a rule is not the closed form"))?);
            }
            let mut held: BTreeSet<Grant> = BTreeSet::new();
            for rule in &rules {
                held.extend(grants(rule));
            }
            if held.is_empty() {
                continue;
            }
            let key = (kind.to_string(), name.to_string());
            let entry = self.entries.get(&key);
            if kind == "ServiceAccount" && !exists && self.accounts.contains(name) {
                let baseline: Vec<Allowed> = self
                    .bootstrap
                    .get(&key)
                    .map(|upstream| upstream.iter().flat_map(grants).map(row_of).collect())
                    .unwrap_or_default();
                let within = held.iter().all(|grant| {
                    allowed(grant, &baseline, namespace) && entry.is_none_or(|entry| allowed(grant, &entry.allowed, namespace))
                });
                if !within {
                    return Err(Refusal::new(format!(
                        "IC02 absent controller account with grants beyond its bootstrap role: {}",
                        name
                    )));
                }
                continue;
            }
            let Some(entry) = entry else {
                return Err(Refusal::new(format!(
                    "IC01 subject with policy-relevant grants outside the identity closure: {}",
                    name
                )));
            };
            if !exists {
                return Err(Refusal::new(format!("IC02 the closure identity is absent: {}", name)));
            }
            if let Some(grant) = held.iter().find(|grant| !allowed(grant, &entry.allowed, namespace)) {
                let (category, resource, verb, scope) = grant;
                return Err(Refusal::new(format!(
                    "IC03 grant beyond the closure entry: {} {} {} {} at {}",
                    name, category, verb, resource, scope
                )));
            }
            if let Some(names) = &entry.names {
                for rule in &rules {
                    let widening = grants(rule)
                        .iter()
                        .any(|(category, _, verb, _)| *category == "SPECIAL" && ["escalate", "bind", "*"].contains(&verb.as_str()));
                    if widening && (rule.names.is_empty() || !rule.names.iter().all(|role| names.contains(role))) {
                        return Err(Refusal::new(format!(
                            "IC04 escalate or bind beyond the named planeon roles: {}",
                            name
                        )));
                    }
                }
            }
        }
        for ((kind, name), entry) in &self.entries {
            if entry.must_be_present && !seen.contains(&(kind.as_str(), name.as_str())) {
                return Err(Refusal::new(format!("IC05 required closure identity absent from the snapshot: {}", name)));
            }
        }
        Ok(())
    }
}

/// The snapshot check over the embedded closure (DESIGN-B section 4.3): v1's IC00-IC05, then v2's IC03.
pub fn check_rbac_snapshot(snapshot: &Value, namespace: &str) -> Result<(), Refusal> {
    Closure::embedded()?.check(snapshot, namespace)
}

/// A DNS label: 1 to 63 of `[a-z0-9-]`, starting and ending with a letter or digit.
fn dns_label(text: &str) -> bool {
    let bytes = text.as_bytes();
    let edge = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && bytes.iter().all(|byte| edge(byte) || *byte == b'-')
}

/// Python's `str.isspace` for one code point (CPython 3.12's whitespace table).
fn python_space(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{20}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
                | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// A non-empty text equal to its Python `strip()`.
fn stripped(text: &str) -> bool {
    match (text.chars().next(), text.chars().next_back()) {
        (Some(first), Some(last)) => !python_space(first) && !python_space(last),
        _ => false,
    }
}

/// A snapshot rule: exactly its five keys, four lists of texts and a scope that is `CLUSTER` or a DNS label.
fn read_rule(value: &Value) -> Option<Rule> {
    let members = value.as_object().filter(|members| closed(members, &RULE_KEYS))?;
    let scope = members.get("scope")?.as_str().filter(|scope| *scope == CLUSTER || dns_label(scope))?;
    Some(Rule {
        groups: string_list(members.get("apiGroups"))?,
        resources: string_list(members.get("resources"))?,
        verbs: string_list(members.get("verbs"))?,
        names: string_list(members.get("resourceNames"))?,
        scope: scope.to_string(),
    })
}

/// Kubernetes resource matching: `*` matches everything, `*/sub` any `<resource>/sub`; a target ending in `/*` (one
/// user-extra key) is matched by any of its subresources.
fn covers(held: &str, target: &str) -> bool {
    if held == "*" || held == target {
        return true;
    }
    let (base, sub) = target.split_once('/').unwrap_or((target, ""));
    if sub == "*" {
        return held.strip_prefix(base).is_some_and(|rest| rest.starts_with('/'))
            || held.strip_prefix("*/").is_some_and(|rest| !rest.is_empty());
    }
    !sub.is_empty() && held.strip_prefix("*/") == Some(sub)
}

fn special_verbs(group: &str, resource: &str) -> Option<&'static [&'static str]> {
    SPECIAL_TARGETS.iter().find(|(g, r, _)| *g == group && *r == resource).map(|(_, _, verbs)| *verbs)
}

fn is_special(verb: &str, verbs: &[&str]) -> bool {
    verb == "*"
        || verbs.contains(&verb)
        || (verbs.contains(&"impersonate") && (verb.starts_with("impersonate:") || verb.starts_with("impersonate-on:")))
}

/// Every table (group, resource) pair, once.
fn table_pairs() -> BTreeSet<(&'static str, &'static str)> {
    POLICY_RESOURCES
        .iter()
        .chain(STATUS_RESOURCES.iter())
        .chain(WORKLOAD_RESOURCES.iter())
        .copied()
        .chain(SPECIAL_TARGETS.iter().map(|(group, resource, _)| (*group, *resource)))
        .collect()
}

/// The policy-relevant grants of one rule.
fn grants(rule: &Rule) -> BTreeSet<Grant> {
    let mut out = BTreeSet::new();
    for (group, resource) in table_pairs() {
        let group_held = rule.groups.iter().any(|held| held == "*" || held == group);
        if !group_held || !rule.resources.iter().any(|held| covers(held, resource)) {
            continue;
        }
        let key = format!("{}/{}", group, resource);
        let pair = (group, resource);
        let protected = rule.scope == CLUSTER || PROTECTED_NAMESPACES.contains(&rule.scope.as_str());
        for verb in &rule.verbs {
            let grant = |category: &'static str| (category, key.clone(), verb.clone(), rule.scope.clone());
            if special_verbs(group, resource).is_some_and(|verbs| is_special(verb, verbs)) {
                out.insert(grant("SPECIAL"));
            }
            if verb == "*" || WRITE_VERBS.contains(&verb.as_str()) {
                if POLICY_RESOURCES.contains(&pair) {
                    out.insert(grant("POLICY_WRITE"));
                } else if STATUS_RESOURCES.contains(&pair) {
                    out.insert(grant("STATUS_WRITE"));
                }
            }
            if WORKLOAD_RESOURCES.contains(&pair) && (verb == "*" || WORKLOAD_VERBS.contains(&verb.as_str())) && protected {
                out.insert(grant("WORKLOAD"));
            }
        }
    }
    out
}

fn row_of(grant: Grant) -> Allowed {
    let (category, resource, verb, scope) = grant;
    Allowed::Row { category: category.to_string(), resource, verb, scope }
}

/// Whether a grant is within the allowed rows (`ALL` allows everything; a row at `CLUSTER` covers every scope).
fn allowed(grant: &Grant, rows: &[Allowed], namespace: &str) -> bool {
    let (category, resource, verb, scope) = grant;
    rows.iter().any(|row| match row {
        Allowed::All => true,
        Allowed::Row { category: wanted_category, resource: wanted_resource, verb: wanted_verb, scope: wanted_scope } => {
            let at = if wanted_scope.as_str() == QUALIFICATION_SCOPE { namespace } else { wanted_scope.as_str() };
            wanted_category.as_str() == *category
                && wanted_resource.as_str() == resource.as_str()
                && wanted_verb.as_str() == verb.as_str()
                && (at == scope.as_str() || at == CLUSTER)
        }
    })
}

/// The policy-relevant grants of a snapshot rule value, for tests and the round trips (`None` for a value that is not a
/// closed rule).
pub fn rule_grants(value: &Value) -> Option<Vec<Grant>> {
    read_rule(value).map(|rule| grants(&rule).into_iter().collect())
}
