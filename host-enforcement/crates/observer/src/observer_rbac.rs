//! HE-004-I01a DESIGN-I01A section 10 (owner decisions Q-RBAC-4 and Q-HE4I1-9, both (a); MODEL_DEFINED's HE-004-I01a
//! section): the role pin. A snapshot is accepted only when I06 v4's RB rules hold on the read it came from, so the
//! account the observer runs as can read what HE-004C requests and no more. A pure logic module under B1's rule
//! (`tools/gate.py`, I01_LOGIC_PATHS): no system call beyond allocation, and every input gets an answer, never a panic.
//!
//! [`check_observer_snapshot`] is what v4 adds once `Closure::check` (I06 v3's IC00-IC05) has passed; `observe.rs`
//! calls it right after that check, with only the three list bindings between (G-I01-3). In order:
//! - RB05, on the produced snapshot: `User planeon:policy-observer` appears once, and its effective rules are the
//!   contract role's resource rules in the role's order, each at cluster scope and naming no resource;
//! - RB01-RB04, on the read's ClusterRoles and ClusterRoleBindings: one role and one binding carry the contract name;
//!   each holds only its contract members (the apiserver's own metadata fields aside); the role holds the eight rules
//!   and the binding the roleRef and the single User subject;
//! - RB06 and RB07, on every other binding (the ClusterRoleBindings first, then the RoleBindings) and every other
//!   ClusterRole with an aggregationRule: no binding names the observer user or points at the contract role, and no
//!   selector would pick up that role, whose metadata carries no labels.
//!
//! The rule data is compiled in below, and `tools/gate.py` holds it to `contracts/i06-v4/vectors.json`'s
//! `objectsPositive`. Where a vector pins a refusal, the text here is that vector's, byte for byte; R10 words the two
//! that no vector pins (a `rules` member that is no array, and a rule that is no object of text lists). Python's `==`
//! against a constant text is an exact text match, the model's `_same` against the constant data is exact JSON equality
//! (members as a map, lists in order), and `str.strip()` is CPython 3.12's whitespace set, R10's own copy. A name with a
//! lone surrogate, which no apiserver sends, shows as U+FFFD in a refusal.

use i05_protocol::json::{JStr, Object, Value};

use crate::rbac::CLUSTER;

/// The API version of the contract role and binding.
pub const RBAC_API_VERSION: &str = "rbac.authorization.k8s.io/v1";
/// The observer's user, the CN of its client certificate.
pub const OBSERVER_USER: &str = "planeon:policy-observer";
/// RB01: the contract ClusterRole's name.
pub const ROLE_NAME: &str = "planeon:policy-observer";
/// RB03: the contract ClusterRoleBinding's name.
pub const BINDING_NAME: &str = "planeon:policy-observer";
/// RB03: the binding's `roleRef`, member by member.
pub const ROLE_REF: [(&str, &str); 3] =
    [("apiGroup", "rbac.authorization.k8s.io"), ("kind", "ClusterRole"), ("name", "planeon:policy-observer")];
/// RB04: the binding's only subject, member by member.
pub const SUBJECT: [(&str, &str); 3] =
    [("apiGroup", "rbac.authorization.k8s.io"), ("kind", "User"), ("name", "planeon:policy-observer")];
/// RB01 and RB03: the metadata fields the apiserver writes on a stored object. Beside `name`, no other may appear.
pub const SERVER_METADATA: [&str; 5] = ["uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"];
/// RB01: the members the contract role may hold.
pub const ROLE_MEMBERS: [&str; 4] = ["apiVersion", "kind", "metadata", "rules"];
/// RB03: the members the contract binding may hold.
pub const BINDING_MEMBERS: [&str; 5] = ["apiVersion", "kind", "metadata", "roleRef", "subjects"];
/// RB02: a rule's five lists, in the order they are compared.
pub const RULE_KEYS: [&str; 5] = ["apiGroups", "resources", "nonResourceURLs", "verbs", "resourceNames"];

/// RB01's refusal for lists it cannot read (pinned by the vectors).
const CLOSED_LISTS: &str = "RB01 closed RBAC object lists";

/// One rule of the contract role: its five lists, an omitted one empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractRule {
    pub api_groups: &'static [&'static str],
    pub resources: &'static [&'static str],
    pub non_resource_urls: &'static [&'static str],
    pub verbs: &'static [&'static str],
    pub resource_names: &'static [&'static str],
}

impl ContractRule {
    /// The five lists under their JSON names, in RULE_KEYS' order.
    pub fn lists(&self) -> [(&'static str, &'static [&'static str]); 5] {
        [("apiGroups", self.api_groups), ("resources", self.resources), ("nonResourceURLs", self.non_resource_urls),
         ("verbs", self.verbs), ("resourceNames", self.resource_names)]
    }
}

/// RB02: the contract role's eight rules, in order. The first seven grant list and watch on the resources HE-004C
/// reads; the eighth grants get on its five fixed non-resource targets.
pub const OBSERVER_RULES: [ContractRule; 8] = [
    ContractRule { api_groups: &[""],
                   resources: &["limitranges", "namespaces", "resourcequotas", "serviceaccounts", "secrets"],
                   non_resource_urls: &[], verbs: &["list", "watch"], resource_names: &[] },
    ContractRule { api_groups: &["networking.k8s.io"], resources: &["networkpolicies"], non_resource_urls: &[],
                   verbs: &["list", "watch"], resource_names: &[] },
    ContractRule { api_groups: &["rbac.authorization.k8s.io"],
                   resources: &["roles", "rolebindings", "clusterroles", "clusterrolebindings"], non_resource_urls: &[],
                   verbs: &["list", "watch"], resource_names: &[] },
    ContractRule { api_groups: &["admissionregistration.k8s.io"],
                   resources: &["validatingwebhookconfigurations", "mutatingwebhookconfigurations",
                                "mutatingadmissionpolicies", "mutatingadmissionpolicybindings",
                                "validatingadmissionpolicies", "validatingadmissionpolicybindings"],
                   non_resource_urls: &[], verbs: &["list", "watch"], resource_names: &[] },
    ContractRule { api_groups: &["apiregistration.k8s.io"], resources: &["apiservices"], non_resource_urls: &[],
                   verbs: &["list", "watch"], resource_names: &[] },
    ContractRule { api_groups: &["apiextensions.k8s.io"], resources: &["customresourcedefinitions"], non_resource_urls: &[],
                   verbs: &["list", "watch"], resource_names: &[] },
    ContractRule { api_groups: &["certificates.k8s.io"], resources: &["certificatesigningrequests"], non_resource_urls: &[],
                   verbs: &["list", "watch"], resource_names: &[] },
    ContractRule { api_groups: &[], resources: &[],
                   non_resource_urls: &["/metrics", "/readyz/poststarthook/rbac/bootstrap-roles", "/version",
                                        "/apis/admissionregistration.k8s.io", "/apis/admissionregistration.k8s.io/*"],
                   verbs: &["get"], resource_names: &[] },
];

/// A refusal of the role pin: the first broken rule, as text that starts with its code (RB01-RB07).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolePinRefusal(String);

impl RolePinRefusal {
    pub fn text(&self) -> &str {
        &self.0
    }
}

fn refusal(text: impl Into<String>) -> RolePinRefusal {
    RolePinRefusal(text.into())
}

/// The three lists of one read that RB01-RB04, RB06 and RB07 judge, each a list answer's `items`.
#[derive(Clone, Copy, Debug)]
pub struct RbacLists<'a> {
    pub cluster_roles: &'a [Value],
    pub cluster_role_bindings: &'a [Value],
    pub role_bindings: &'a [Value],
}

// ------------------------------------------------------------------------------------------------ reading

/// CPython 3.12's `str.isspace` for one code point (R10's own copy of the table).
fn py_space(point: u32) -> bool {
    matches!(point, 0x09..=0x0D | 0x1C..=0x20 | 0x85 | 0xA0 | 0x1680 | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F
                    | 0x3000)
}

/// I06 v1's `_text`: a string that is not empty and has no white space at either end (as in Python, a lone surrogate
/// is a code point like any other).
fn plain_text(value: Option<&Value>) -> Option<&JStr> {
    let Some(Value::Str(text)) = value else { return None };
    let mut points = text.code_points();
    let first = points.next()?;
    let last = points.last().unwrap_or(first);
    (!py_space(first) && !py_space(last)).then_some(text)
}

/// Python's `value == text` for a constant text: a string holding exactly that text.
fn is(value: Option<&Value>, text: &str) -> bool {
    matches!(value, Some(Value::Str(found)) if found.as_bytes() == text.as_bytes())
}

/// A list of strings equal, in order, to `wanted`.
fn same_texts(items: &[Value], wanted: &[&str]) -> bool {
    items.len() == wanted.len() && items.iter().zip(wanted).all(|(item, text)| is(Some(item), text))
}

/// Exact JSON equality with an object of text members: the same names, each a string with the same text.
fn same_pairs(value: Option<&Value>, pairs: &[(&str, &str)]) -> bool {
    value
        .and_then(Value::as_object)
        .is_some_and(|object| object.len() == pairs.len() && pairs.iter().all(|(key, text)| is(object.get(key), text)))
}

/// A string's text for a refusal.
fn shown(text: &JStr) -> String {
    String::from_utf8_lossy(text.as_bytes()).into_owned()
}

/// The member names of `object` that `known` does not admit, in Python's sort order (code points).
fn outside<'a>(object: &'a Object, known: impl Fn(&[u8]) -> bool) -> Vec<&'a JStr> {
    let mut names: Vec<&JStr> = object.iter().map(|(name, _)| name).filter(|name| !known(name.as_bytes())).collect();
    names.sort();
    names
}

fn joined(names: &[&JStr]) -> String {
    names.iter().map(|name| shown(name)).collect::<Vec<String>>().join(",")
}

fn admitted(allowed: &[&str], name: &[u8]) -> bool {
    allowed.iter().any(|known| known.as_bytes() == name)
}

/// An item's `metadata.name` when it is a string.
fn name_of(item: &Value) -> Option<&JStr> {
    match item.get("metadata")?.get("name")? {
        Value::Str(name) => Some(name),
        _ => None,
    }
}

/// RB01's reading of a list: each item an object whose `metadata` is an object with a plain-text `name`.
fn readable(items: &[Value]) -> bool {
    items.iter().all(|item| item.get("metadata").is_some_and(|meta| meta.as_object().is_some() && plain_text(meta.get("name")).is_some()))
}

/// The items named `name`, with their places in the list.
fn with_name<'a>(items: &'a [Value], name: &str) -> Vec<(usize, &'a Value)> {
    items.iter().enumerate().filter(|(_, item)| name_of(item).is_some_and(|found| found.as_bytes() == name.as_bytes())).collect()
}

/// RB01 and RB03's shape check of the contract object found in `place`'s list: no member outside `members`, `kind`
/// and `apiVersion` the contract's when present, and no metadata beyond the name and the server's fields.
fn shape(item: &Value, kind: &str, members: &[&str], place: &str) -> Result<(), RolePinRefusal> {
    let Some(object) = item.as_object() else { return Err(refusal(CLOSED_LISTS)) };
    let unknown = outside(object, |name| admitted(members, name));
    if !unknown.is_empty() {
        return Err(refusal(format!("{place} holds an unknown member: {}", joined(&unknown))));
    }
    for (key, wanted) in [("kind", kind), ("apiVersion", RBAC_API_VERSION)] {
        if let Some(found) = object.get(key) {
            if !is(Some(found), wanted) {
                return Err(refusal(format!("{place}'s kind or apiVersion differs")));
            }
        }
    }
    let Some(metadata) = object.get("metadata").and_then(Value::as_object) else { return Err(refusal(CLOSED_LISTS)) };
    let extra = outside(metadata, |name| name == b"name" || admitted(&SERVER_METADATA, name));
    if !extra.is_empty() {
        return Err(refusal(format!("{place}'s metadata holds {}", joined(&extra))));
    }
    Ok(())
}

/// RB02's reading of the role's rule `number` (counted from 1): an object with no member outside RULE_KEYS, each list
/// absent, null (both read as empty) or an array of strings; its lists in RULE_KEYS' order.
fn rule_lists(rule: &Value, number: usize) -> Result<Vec<(&'static str, &[Value])>, RolePinRefusal> {
    let not_text_lists = || refusal(format!("RB02 the observer ClusterRole's rule {number} is not an object of text lists"));
    let Some(object) = rule.as_object() else { return Err(not_text_lists()) };
    let unknown = outside(object, |name| admitted(&RULE_KEYS, name));
    if !unknown.is_empty() {
        return Err(refusal(format!("RB02 the observer ClusterRole's rule {number} holds an unknown member: {}", joined(&unknown))));
    }
    let mut lists = Vec::with_capacity(RULE_KEYS.len());
    for key in RULE_KEYS {
        let items: &[Value] = match object.get(key) {
            None | Some(Value::Null) => &[],
            Some(Value::Array(items)) if items.iter().all(|item| matches!(item, Value::Str(_))) => items,
            Some(_) => return Err(not_text_lists()),
        };
        lists.push((key, items));
    }
    Ok(lists)
}

/// Where a binding sits, for RB06 and RB07's refusals: `Kind/name`, with a RoleBinding's string namespace between.
fn place_of(kind: &str, item: &Value) -> String {
    let name = name_of(item).map(shown).unwrap_or_default();
    match item.get("metadata").and_then(|meta| meta.get("namespace")) {
        Some(Value::Str(space)) if kind == "RoleBinding" => format!("{kind}/{}/{name}", shown(space)),
        _ => format!("{kind}/{name}"),
    }
}

/// RB07: whether an aggregationRule selector would pick up an object that carries no labels. That is so when it names
/// no label and each of its expressions is a `NotIn` or a `DoesNotExist` (the empty selector picks up everything).
/// `None`: a selector this cannot read, which refuses (fail closed).
fn selects_unlabeled(selector: &Value) -> Option<bool> {
    let members = selector.as_object()?;
    if !outside(members, |name| name == b"matchLabels" || name == b"matchExpressions").is_empty() {
        return None;
    }
    let no_labels = match members.get("matchLabels") {
        None | Some(Value::Null) => true,
        Some(Value::Object(labels)) => labels.is_empty(),
        Some(_) => return None,
    };
    let expressions: &[Value] = match members.get("matchExpressions") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => return None,
    };
    let mut absent_only = true;
    for expression in expressions {
        let fields = expression.as_object()?;
        plain_text(fields.get("key"))?;
        let Some(Value::Str(operator)) = fields.get("operator") else { return None };
        match operator.as_bytes() {
            b"NotIn" | b"DoesNotExist" => {}
            b"In" | b"Exists" => absent_only = false,
            _ => return None,
        }
    }
    Some(no_labels && absent_only)
}

// ------------------------------------------------------------------------------------------------ the checks

/// The three lists of a `{clusterRoles, clusterRoleBindings, roleBindings}` object (the vectors' form, and HE-008's
/// manifest): exactly those members, each an array. Anything else is RB01's closed-lists refusal. (`observe.rs` hands
/// over the read's lists directly.)
pub fn object_lists(objects: &Value) -> Result<RbacLists<'_>, RolePinRefusal> {
    fn list<'a>(members: &'a Object, key: &str) -> Result<&'a [Value], RolePinRefusal> {
        members.get(key).and_then(Value::as_array).ok_or_else(|| refusal(CLOSED_LISTS))
    }
    let Some(members) = objects.as_object().filter(|members| members.len() == 3) else { return Err(refusal(CLOSED_LISTS)) };
    Ok(RbacLists {
        cluster_roles: list(members, "clusterRoles")?,
        cluster_role_bindings: list(members, "clusterRoleBindings")?,
        role_bindings: list(members, "roleBindings")?,
    })
}

/// RB05 on a snapshot that `Closure::check` accepted: the observer user is present once, and its effective rules are
/// exactly the contract role's resource rules, in the role's order, each with no resource names at cluster scope (the
/// non-resource rule never reaches a snapshot).
pub fn check_effective_rules(snapshot: &Value) -> Result<(), RolePinRefusal> {
    let subjects = snapshot.get("subjects").and_then(Value::as_array).unwrap_or(&[]);
    let mut observers = subjects.iter().filter(|subject| is(subject.get("kind"), "User") && is(subject.get("name"), OBSERVER_USER));
    let (Some(observer), None) = (observers.next(), observers.next()) else {
        return Err(refusal("RB05 the observer is absent from the RBAC snapshot"));
    };
    let wanted: Vec<ContractRule> = OBSERVER_RULES.iter().copied().filter(|rule| !rule.resources.is_empty()).collect();
    let exact = observer.get("effectiveRules").and_then(Value::as_array).is_some_and(|rules| {
        rules.len() == wanted.len()
            && rules.iter().zip(&wanted).all(|(rule, contract)| {
                rule.as_object().is_some_and(|members| {
                    members.len() == 5
                        && members.get("apiGroups").and_then(Value::as_array).is_some_and(|items| same_texts(items, contract.api_groups))
                        && members.get("resources").and_then(Value::as_array).is_some_and(|items| same_texts(items, contract.resources))
                        && members.get("verbs").and_then(Value::as_array).is_some_and(|items| same_texts(items, contract.verbs))
                        && members.get("resourceNames").and_then(Value::as_array).is_some_and(<[Value]>::is_empty)
                        && is(members.get("scope"), CLUSTER)
                })
            })
    });
    if !exact {
        return Err(refusal("RB05 the observer's effective rules are not exactly the observer ClusterRole's resource rules"));
    }
    Ok(())
}

/// RB01-RB04, RB06 and RB07 over one read's lists, in the model's order.
pub fn check_observer_rbac(lists: RbacLists<'_>) -> Result<(), RolePinRefusal> {
    let RbacLists { cluster_roles, cluster_role_bindings, role_bindings } = lists;
    if ![cluster_roles, cluster_role_bindings, role_bindings].into_iter().all(readable) {
        return Err(refusal(CLOSED_LISTS));
    }
    // RB01: the one contract role, without aggregation, holding only its members.
    let roles = with_name(cluster_roles, ROLE_NAME);
    let &[(role_at, role)] = roles.as_slice() else {
        return Err(refusal("RB01 the observer ClusterRole is missing or repeated"));
    };
    if role.get("aggregationRule").is_some() {
        return Err(refusal("RB01 the observer ClusterRole has an aggregationRule"));
    }
    shape(role, "ClusterRole", &ROLE_MEMBERS, "RB01 the observer ClusterRole")?;
    // RB02: the eight rules, list by list.
    let rules: &[Value] = match role.get("rules") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => return Err(refusal("RB02 the observer ClusterRole's rules member is no array")),
    };
    if rules.len() != OBSERVER_RULES.len() {
        return Err(refusal(format!("RB02 the observer ClusterRole holds {} rules, the contract {}", rules.len(),
                                   OBSERVER_RULES.len())));
    }
    for (index, (rule, contract)) in rules.iter().zip(&OBSERVER_RULES).enumerate() {
        let number = index.saturating_add(1);
        for ((key, found), (_, wanted)) in rule_lists(rule, number)?.into_iter().zip(contract.lists()) {
            if !same_texts(found, wanted) {
                return Err(refusal(format!("RB02 the observer ClusterRole's rule {number} differs from the contract: {key}")));
            }
        }
    }
    // RB03 and RB04: the one contract binding, its members, its roleRef and its one subject.
    let bindings = with_name(cluster_role_bindings, BINDING_NAME);
    let &[(binding_at, binding)] = bindings.as_slice() else {
        return Err(refusal("RB03 the observer ClusterRoleBinding is missing or repeated"));
    };
    shape(binding, "ClusterRoleBinding", &BINDING_MEMBERS, "RB03 the observer ClusterRoleBinding")?;
    if !same_pairs(binding.get("roleRef"), &ROLE_REF) {
        return Err(refusal("RB03 the observer ClusterRoleBinding's roleRef is not the observer ClusterRole"));
    }
    let one_subject = binding.get("subjects").and_then(Value::as_array).is_some_and(|subjects| match subjects {
        [only] => same_pairs(Some(only), &SUBJECT),
        _ => false,
    });
    if !one_subject {
        return Err(refusal("RB04 the observer ClusterRoleBinding's subjects are not exactly User planeon:policy-observer"));
    }
    // RB06 and RB07: every other binding, the ClusterRoleBindings first.
    let others = cluster_role_bindings
        .iter()
        .enumerate()
        .filter(|(at, _)| *at != binding_at)
        .map(|(_, item)| ("ClusterRoleBinding", item))
        .chain(role_bindings.iter().map(|item| ("RoleBinding", item)));
    for (kind, item) in others {
        let place = place_of(kind, item);
        let subjects: &[Value] = match item.get("subjects") {
            None | Some(Value::Null) => &[],
            Some(Value::Array(items)) if items.iter().all(|subject| subject.as_object().is_some()) => items,
            Some(_) => return Err(refusal(format!("RB06 a binding's subjects are malformed: {place}"))),
        };
        if subjects.iter().any(|subject| is(subject.get("kind"), "User") && is(subject.get("name"), OBSERVER_USER)) {
            return Err(refusal(format!("RB06 a binding other than the contract's names the observer: {place}")));
        }
        let Some(reference) = item.get("roleRef").filter(|value| value.as_object().is_some()) else {
            return Err(refusal(format!("RB07 a binding's roleRef is malformed: {place}")));
        };
        if is(reference.get("kind"), "ClusterRole") && is(reference.get("name"), ROLE_NAME) {
            return Err(refusal(format!("RB07 a binding other than the contract's references the observer ClusterRole: {place}")));
        }
    }
    // RB07: no other ClusterRole aggregates the contract role.
    for (at, item) in cluster_roles.iter().enumerate() {
        if at == role_at {
            continue;
        }
        let Some(aggregation) = item.get("aggregationRule") else { continue };
        let place = format!("ClusterRole/{}", name_of(item).map(shown).unwrap_or_default());
        let unreadable = || refusal(format!("RB07 an aggregationRule selector is malformed: {place}"));
        let selectors: &[Value] = match aggregation {
            Value::Null => &[],
            Value::Object(members) => match members.get("clusterRoleSelectors") {
                None | Some(Value::Null) => &[],
                Some(Value::Array(items)) => items,
                Some(_) => return Err(unreadable()),
            },
            _ => return Err(unreadable()),
        };
        for selector in selectors {
            if selects_unlabeled(selector).ok_or_else(unreadable)? {
                return Err(refusal(format!("RB07 an aggregated ClusterRole selects the observer ClusterRole: {place}")));
            }
        }
    }
    Ok(())
}

/// I06 v4's `check_observer_snapshot` after `Closure::check`: RB05 on the produced snapshot, then RB01-RB04, RB06 and
/// RB07 on the lists it was produced from (the caller's obligation: snapshot and lists come from one read, at a
/// single resourceVersion).
pub fn check_observer_snapshot(snapshot: &Value, lists: RbacLists<'_>) -> Result<(), RolePinRefusal> {
    check_effective_rules(snapshot)?;
    check_observer_rbac(lists)
}
