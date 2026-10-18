//! The effective-RBAC producer (HE-004B1 DESIGN-B section 4.2; owner decision Q-HE4B-3 (a) "Direct grants only"; D1-3,
//! D1-18). No harness-onion model computes effective RBAC, so this is R10-defined behaviour (MODEL_DEFINED, HE-004B1)
//! with R10-local vectors. It turns the five complete RBAC lists into the `planeon.internal.i06-rbac-snapshot/v1` value
//! that `snapshot::check_rbac_snapshot` judges, and refuses (never drops) what the snapshot shape could not carry or what
//! the I06 contracts forbid: a non-resource-URL rule bound directly to the loopback user (R1-7, I06-3), an aggregated
//! ClusterRole reaching the qualification namespace (OR03), a binding to a role that does not exist, and malformed
//! objects. Other subjects' non-resource-URL rules are dropped, as the bootstrap derivation drops them, and counted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use i05_protocol::json::{JStr, Object, Value};

use crate::inputs::{object_name, object_namespace, text, InputError, Inputs, Resource};

/// The snapshot's record version (`i06_backend_profile.py` `SNAPSHOT_VERSION`, contract text).
pub const SNAPSHOT_VERSION: &str = "planeon.internal.i06-rbac-snapshot/v1";
/// A ClusterRoleBinding's scope in a snapshot rule.
pub const CLUSTER: &str = "CLUSTER";
/// The apiserver's in-process loopback user.
pub const LOOPBACK_USER: &str = "system:apiserver";
/// The username prefix of a service account (`system:serviceaccount:<namespace>:<name>`).
pub const SERVICE_ACCOUNT_PREFIX: &str = "system:serviceaccount:";
const RBAC_GROUP: &str = "rbac.authorization.k8s.io";

/// The producer's result: the snapshot value and the number of (subject, rule) pairs whose non-resource-URL rule was
/// dropped (not part of the snapshot's shape).
#[derive(Clone, Debug)]
pub struct Produced {
    pub snapshot: Value,
    pub dropped_non_resource_rules: usize,
}

/// Why no snapshot is produced (each fails closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProduceError {
    /// The lists are incomplete or missing (`inputs`).
    Input(InputError),
    /// R1-7 (I06-3): a role holding a non-resource-URL rule is bound by a binding whose subjects directly name
    /// `{User, system:apiserver}`.
    LoopbackNonResource { binding: String, role: String },
    /// OR03: a ClusterRole with an `aggregationRule` key reaches the qualification namespace (bound there by a
    /// RoleBinding, or by any ClusterRoleBinding).
    AggregatedRole { binding: String, role: String },
    /// A binding's `roleRef` names a role that does not exist (a latent grant).
    DanglingRoleRef { binding: String, role: String },
    /// A malformed object: a field of the wrong shape, an unknown subject kind, a `roleRef` outside the RBAC group or
    /// kinds, a ClusterRoleBinding naming a Role, a ClusterRoleBinding's service account without a namespace, or a rule
    /// holding non-resource URLs beside resources.
    Malformed { object: String, field: &'static str },
}

impl From<InputError> for ProduceError {
    fn from(error: InputError) -> ProduceError {
        ProduceError::Input(error)
    }
}

impl fmt::Display for ProduceError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProduceError::Input(error) => write!(out, "{}", error),
            ProduceError::LoopbackNonResource { binding, role } => write!(
                out,
                "R1-7 {} binds User {} to {}, which holds a non-resource-URL rule: no snapshot is produced",
                binding, LOOPBACK_USER, role
            ),
            ProduceError::AggregatedRole { binding, role } => write!(
                out,
                "OR03 {} binds the aggregated ClusterRole {} where it reaches the qualification namespace",
                binding, role
            ),
            ProduceError::DanglingRoleRef { binding, role } => {
                write!(out, "producer: {} refers to the role {}, which does not exist", binding, role)
            }
            ProduceError::Malformed { object, field } => write!(out, "producer: {} has a malformed {}", object, field),
        }
    }
}

/// One RBAC rule of a role, its string lists read (absent or null lists are empty).
#[derive(Clone, Debug)]
struct Rule {
    api_groups: Vec<String>,
    resources: Vec<String>,
    verbs: Vec<String>,
    resource_names: Vec<String>,
    non_resource: bool,
}

/// A role's rules, and for a ClusterRole whether it has an `aggregationRule` key (any value, also empty selectors).
#[derive(Clone, Debug)]
struct RoleRules {
    rules: Vec<Rule>,
    aggregated: bool,
}

/// One subject entry while the snapshot is built.
struct Entry {
    exists: bool,
    rules: Vec<Value>,
}

fn malformed(object: &str, field: &'static str) -> ProduceError {
    ProduceError::Malformed { object: object.to_string(), field }
}

/// A list of strings; an absent or null member is the empty list.
fn strings(holder: &Object, key: &str, object: &str) -> Result<Vec<String>, ProduceError> {
    match holder.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| text(item).map(str::to_string).ok_or_else(|| malformed(object, "rule list")))
            .collect(),
        Some(_) => Err(malformed(object, "rule list")),
    }
}

/// A role's `rules` (absent or null: none). A rule holding non-resource URLs beside resources is malformed (refusal 4).
fn role_rules(role: &Value, object: &str) -> Result<RoleRules, ProduceError> {
    let aggregated = role.as_object().is_some_and(|members| members.get("aggregationRule").is_some());
    let items: &[Value] = match role.get("rules") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => return Err(malformed(object, "rules")),
    };
    let mut rules = Vec::with_capacity(items.len());
    for item in items {
        let Some(members) = item.as_object() else {
            return Err(malformed(object, "rule"));
        };
        let non_resource_urls = strings(members, "nonResourceURLs", object)?;
        let rule = Rule {
            api_groups: strings(members, "apiGroups", object)?,
            resources: strings(members, "resources", object)?,
            verbs: strings(members, "verbs", object)?,
            resource_names: strings(members, "resourceNames", object)?,
            non_resource: !non_resource_urls.is_empty(),
        };
        if rule.non_resource && !rule.resources.is_empty() {
            return Err(malformed(object, "rule (non-resource URLs beside resources)"));
        }
        rules.push(rule);
    }
    Ok(RoleRules { rules, aggregated })
}

fn string_array(items: &[String]) -> Value {
    Value::Array(items.iter().map(|item| Value::str(item)).collect())
}

/// A snapshot rule `{apiGroups, resources, verbs, resourceNames, scope}`.
fn snapshot_rule(rule: &Rule, scope: &str) -> Value {
    let mut members = Object::new();
    members.insert(JStr::new("apiGroups"), string_array(&rule.api_groups));
    members.insert(JStr::new("resources"), string_array(&rule.resources));
    members.insert(JStr::new("verbs"), string_array(&rule.verbs));
    members.insert(JStr::new("resourceNames"), string_array(&rule.resource_names));
    members.insert(JStr::new("scope"), Value::str(scope));
    Value::Object(members)
}

/// One binding, ready to resolve: its display name, its namespace (None for a ClusterRoleBinding) and its value.
struct Binding<'a> {
    label: String,
    namespace: Option<&'a str>,
    value: &'a Value,
}

/// A subject of a binding, resolved to its snapshot key.
struct Subject {
    kind: &'static str,
    name: String,
    service_account: Option<(String, String)>,
}

fn subjects(binding: &Binding<'_>) -> Result<Vec<Subject>, ProduceError> {
    let items: &[Value] = match binding.value.get("subjects") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => return Err(malformed(&binding.label, "subjects")),
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(members) = item.as_object() else {
            return Err(malformed(&binding.label, "subject"));
        };
        let Some(name) = members.get("name").and_then(text).filter(|name| !name.is_empty()) else {
            return Err(malformed(&binding.label, "subject name"));
        };
        let kind = match members.get("kind").and_then(text) {
            Some("User") => "User",
            Some("Group") => "Group",
            Some("ServiceAccount") => "ServiceAccount",
            _ => return Err(malformed(&binding.label, "subject kind")),
        };
        if kind != "ServiceAccount" {
            out.push(Subject { kind, name: name.to_string(), service_account: None });
            continue;
        }
        // The RBAC authorizer's rule: a RoleBinding's service account without a namespace is in the binding's namespace;
        // a ClusterRoleBinding's must name one.
        let namespace = match members.get("namespace") {
            None | Some(Value::Null) => None,
            Some(value) => match text(value) {
                Some("") => None,
                Some(space) => Some(space),
                None => return Err(malformed(&binding.label, "subject namespace")),
            },
        };
        let Some(namespace) = namespace.or(binding.namespace) else {
            return Err(malformed(&binding.label, "subject namespace"));
        };
        out.push(Subject {
            kind,
            name: format!("{}{}:{}", SERVICE_ACCOUNT_PREFIX, namespace, name),
            service_account: Some((namespace.to_string(), name.to_string())),
        });
    }
    Ok(out)
}

/// The `roleRef` of a binding: (kind, name), `Role` only in a RoleBinding.
fn role_ref<'a>(binding: &Binding<'a>) -> Result<(&'a str, &'a str), ProduceError> {
    let Some(members) = binding.value.get("roleRef").and_then(Value::as_object) else {
        return Err(malformed(&binding.label, "roleRef"));
    };
    if members.get("apiGroup").and_then(text) != Some(RBAC_GROUP) {
        return Err(malformed(&binding.label, "roleRef apiGroup"));
    }
    let kind = match members.get("kind").and_then(text) {
        Some("ClusterRole") => "ClusterRole",
        Some("Role") if binding.namespace.is_some() => "Role",
        _ => return Err(malformed(&binding.label, "roleRef kind")),
    };
    let Some(name) = members.get("name").and_then(text).filter(|name| !name.is_empty()) else {
        return Err(malformed(&binding.label, "roleRef name"));
    };
    Ok((kind, name))
}

/// Produces the effective-RBAC snapshot from the five complete RBAC lists (DESIGN-B section 4.2). `namespace` is the
/// qualification namespace (OR03's reach); the snapshot check judges it.
///
/// Order: the lists are fetched (ClusterRoles, ClusterRoleBindings, Roles, RoleBindings, ServiceAccounts); every
/// ClusterRole and then every Role is read; then the ClusterRoleBindings by name and the RoleBindings by namespace and
/// name, each checked in the order roleRef, subjects, role resolution, OR03, R1-7. The subjects come out sorted by (kind,
/// name), one entry per (kind, name) with the union of its bindings' rules in binding and then rule order (duplicates
/// kept).
pub fn produce_snapshot(inputs: &Inputs, namespace: &str) -> Result<Produced, ProduceError> {
    let cluster_roles = inputs.items(Resource::ClusterRoles)?;
    let cluster_bindings = inputs.items(Resource::ClusterRoleBindings)?;
    let roles = inputs.items(Resource::Roles)?;
    let role_bindings = inputs.items(Resource::RoleBindings)?;
    let accounts = inputs.items(Resource::ServiceAccounts)?;

    let mut cluster_role_rules: BTreeMap<&str, RoleRules> = BTreeMap::new();
    for role in cluster_roles {
        let Some(name) = object_name(role) else {
            return Err(malformed("a ClusterRole", "metadata"));
        };
        cluster_role_rules.insert(name, role_rules(role, &format!("ClusterRole/{}", name))?);
    }
    let mut role_rule_sets: BTreeMap<(&str, &str), RoleRules> = BTreeMap::new();
    for role in roles {
        let (Some(space), Some(name)) = (object_namespace(role), object_name(role)) else {
            return Err(malformed("a Role", "metadata"));
        };
        role_rule_sets.insert((space, name), role_rules(role, &format!("Role/{}/{}", space, name))?);
    }
    let mut existing: BTreeSet<(&str, &str)> = BTreeSet::new();
    for account in accounts {
        let (Some(space), Some(name)) = (object_namespace(account), object_name(account)) else {
            return Err(malformed("a ServiceAccount", "metadata"));
        };
        existing.insert((space, name));
    }

    let mut bindings: Vec<(Option<&str>, &str, &Value)> = Vec::with_capacity(cluster_bindings.len().saturating_add(role_bindings.len()));
    for value in cluster_bindings {
        let Some(name) = object_name(value) else {
            return Err(malformed("a ClusterRoleBinding", "metadata"));
        };
        bindings.push((None, name, value));
    }
    for value in role_bindings {
        let (Some(space), Some(name)) = (object_namespace(value), object_name(value)) else {
            return Err(malformed("a RoleBinding", "metadata"));
        };
        bindings.push((Some(space), name, value));
    }
    // ClusterRoleBindings (None) sort before RoleBindings, each by its namespace and name.
    bindings.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));

    let mut entries: BTreeMap<(&'static str, String), Entry> = BTreeMap::new();
    let mut dropped: usize = 0;
    for (space, name, value) in bindings {
        let binding = Binding {
            label: match space {
                None => format!("ClusterRoleBinding/{}", name),
                Some(space) => format!("RoleBinding/{}/{}", space, name),
            },
            namespace: space,
            value,
        };
        let (kind, role_name) = role_ref(&binding)?;
        let named = subjects(&binding)?;
        let (role_label, rules) = match (kind, space) {
            ("Role", Some(space)) => (format!("Role/{}/{}", space, role_name), role_rule_sets.get(&(space, role_name))),
            _ => (format!("ClusterRole/{}", role_name), cluster_role_rules.get(role_name)),
        };
        let Some(rules) = rules else {
            return Err(ProduceError::DanglingRoleRef { binding: binding.label, role: role_label });
        };
        if rules.aggregated && space.is_none_or(|space| space == namespace) {
            return Err(ProduceError::AggregatedRole { binding: binding.label, role: role_label });
        }
        let loopback = named.iter().any(|subject| subject.kind == "User" && subject.name == LOOPBACK_USER);
        if loopback && rules.rules.iter().any(|rule| rule.non_resource) {
            return Err(ProduceError::LoopbackNonResource { binding: binding.label, role: role_label });
        }
        let scope = space.unwrap_or(CLUSTER);
        for subject in named {
            let exists = match &subject.service_account {
                Some((space, name)) => existing.contains(&(space.as_str(), name.as_str())),
                None => true,
            };
            let entry = entries.entry((subject.kind, subject.name)).or_insert(Entry { exists, rules: Vec::new() });
            for rule in &rules.rules {
                if rule.non_resource {
                    dropped = dropped.saturating_add(1);
                } else {
                    entry.rules.push(snapshot_rule(rule, scope));
                }
            }
        }
    }

    let mut list = Vec::with_capacity(entries.len());
    for ((kind, name), entry) in entries {
        let mut members = Object::new();
        members.insert(JStr::new("kind"), Value::str(kind));
        members.insert(JStr::new("name"), Value::str(&name));
        members.insert(JStr::new("exists"), Value::Bool(entry.exists));
        members.insert(JStr::new("effectiveRules"), Value::Array(entry.rules));
        list.push(Value::Object(members));
    }
    let mut root = Object::new();
    root.insert(JStr::new("schemaVersion"), Value::str(SNAPSHOT_VERSION));
    root.insert(JStr::new("subjects"), Value::Array(list));
    Ok(Produced { snapshot: Value::Object(root), dropped_non_resource_rules: dropped })
}
