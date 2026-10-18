//! HE-004B1 DESIGN-B section 8: round trips producer -> snapshot check. RBAC objects rebuilt from the I06 v2 positive
//! snapshot (one ClusterRole and one binding per subject and scope, the service-account list holding exactly the
//! accounts the positive marks present) reproduce it and are accepted; each IC refusal the producer's output can trigger
//! is then reached from RBAC objects.

mod b1_rbac_support;
mod b1_support;

use std::collections::BTreeMap;

use b1_rbac_support::*;
use b1_support::{field, parse, rows, text};
use i05_protocol::json::Value;
use planeon_observer::rbac::produce_snapshot;
use planeon_observer::snapshot::Closure;

const VECTORS: &str = include_str!("../../../contracts/i06-v2/vectors.json");

fn positive() -> Value {
    field(&parse(VECTORS), "snapshotPositive").clone()
}

fn subject_ref(kind: &str, name: &str) -> String {
    match kind {
        "User" => user(name),
        "Group" => group(name),
        _ => {
            let (namespace, account_name) = name.strip_prefix("system:serviceaccount:").expect("prefix").split_once(':').expect("split");
            account(Some(namespace), account_name)
        }
    }
}

fn role_rule(rule: &Value) -> String {
    format!(r#"{{"apiGroups": {}, "resources": {}, "verbs": {}, "resourceNames": {}}}"#, canonical(field(rule, "apiGroups")),
            canonical(field(rule, "resources")), canonical(field(rule, "verbs")), canonical(field(rule, "resourceNames")))
}

/// RBAC objects whose effective snapshot is `snapshot`.
fn rebuild(snapshot: &Value) -> Rbac {
    let mut rbac = Rbac::default();
    for (index, subject) in rows(snapshot, "subjects").iter().enumerate() {
        let (kind, name) = (text(subject, "kind"), text(subject, "name"));
        if kind == "ServiceAccount" && field(subject, "exists").as_bool() == Some(true) {
            let (namespace, account_name) = name["system:serviceaccount:".len()..].split_once(':').expect("split");
            rbac.accounts.push(service_account(namespace, account_name));
        }
        let mut by_scope: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for rule in rows(subject, "effectiveRules") {
            by_scope.entry(text(rule, "scope").to_string()).or_default().push(role_rule(rule));
        }
        if by_scope.is_empty() {
            by_scope.insert("CLUSTER".to_string(), Vec::new());
        }
        for (scope, rules) in by_scope {
            let role_name = format!("rt-{index}-{scope}");
            rbac.cluster_roles.push(cluster_role(&role_name, &rules));
            let binding = format!("rt-{index}");
            if scope == "CLUSTER" {
                rbac.cluster_bindings.push(cluster_binding(&binding, &role_name, &[subject_ref(kind, name)]));
            } else {
                rbac.role_bindings.push(role_binding(&scope, &binding, "ClusterRole", &role_name, &[subject_ref(kind, name)]));
            }
        }
    }
    rbac
}

/// (kind, name) -> (exists, sorted rule texts).
fn by_subject(snapshot: &Value) -> BTreeMap<(String, String), (bool, Vec<String>)> {
    snapshot_subjects(snapshot)
        .into_iter()
        .map(|(kind, name, exists, rules)| {
            let mut texts: Vec<String> = rules.iter().map(canonical).collect();
            texts.sort();
            ((kind, name), (exists, texts))
        })
        .collect()
}

fn checked(rbac: &Rbac, namespace: &str) -> Option<String> {
    let produced = produce_snapshot(&rbac.inputs(), QUALIFICATION).expect("a snapshot is produced");
    Closure::embedded().expect("closure").check(&produced.snapshot, namespace).err().map(|refusal| refusal.text().to_string())
}

#[test]
fn the_positive_round_trips_and_is_accepted() {
    let positive = positive();
    let rbac = rebuild(&positive);
    let produced = produce_snapshot(&rbac.inputs(), QUALIFICATION).expect("a snapshot is produced");
    assert_eq!(produced.dropped_non_resource_rules, 0);
    assert_eq!(by_subject(&produced.snapshot), by_subject(&positive), "the producer reproduces the positive");
    assert_eq!(rows(&produced.snapshot, "subjects").len(), 61);
    assert_eq!(Closure::embedded().expect("closure").check(&produced.snapshot, QUALIFICATION), Ok(()));
}

#[test]
fn each_reachable_ic_refusal_round_trips() {
    let base = rebuild(&positive());
    let ic01 = "IC01 subject with policy-relevant grants outside the identity closure: ";
    // IC00: the qualification namespace (judged by the check, not the producer).
    assert_eq!(checked(&base, "kube-system").as_deref(), Some("IC00 qualification namespace must be a dedicated namespace"));
    // IC00: a User named like a service account stays a User (S21's subject, from a binding).
    let mut named = base.clone();
    named.cluster_bindings.push(cluster_binding("as-user", "rt-0-CLUSTER", &[user("system:serviceaccount:kube-system:namespace-controller")]));
    assert_eq!(checked(&named, QUALIFICATION).as_deref(), Some("IC00 service-account usernames must use kind ServiceAccount"));
    // IC00: a subject name with surrounding whitespace, and a RoleBinding namespace that is not a DNS label (the rule's
    // scope): the producer copies both, the check refuses them (R10 texts, code IC00).
    let mut spaced = base.clone();
    spaced.cluster_bindings.push(cluster_binding("spaced", "rt-0-CLUSTER", &[user(" alice")]));
    assert!(checked(&spaced, QUALIFICATION).expect("refused").starts_with("IC00 "));
    let mut scoped = base.clone();
    scoped.cluster_roles.push(cluster_role("reader", &[rule(r#"[""]"#, r#"["pods"]"#, r#"["get"]"#)]));
    scoped.role_bindings.push(role_binding("Not_A_Label", "readers", "ClusterRole", "reader", &[user("planeon:effect-gate")]));
    assert!(checked(&scoped, QUALIFICATION).expect("refused").starts_with("IC00 "));
    // IC01: an outsider creating RoleBindings (S01), and a required-disabled controller account brought to life (S07).
    let mut outsider = base.clone();
    outsider.cluster_roles.push(cluster_role("binder", &[rule(r#"["rbac.authorization.k8s.io"]"#, r#"["rolebindings"]"#, r#"["create"]"#)]));
    outsider.role_bindings.push(role_binding(QUALIFICATION, "alice", "ClusterRole", "binder", &[user("alice")]));
    assert_eq!(checked(&outsider, QUALIFICATION), Some(format!("{ic01}alice")));
    let mut alive = base.clone();
    alive.accounts.push(service_account("kube-system", "clusterrole-aggregation-controller"));
    assert_eq!(checked(&alive, QUALIFICATION), Some(format!("{ic01}system:serviceaccount:kube-system:clusterrole-aggregation-controller")));
    // IC02: an absent controller account with grants beyond its bootstrap role (S28's shape).
    let mut dormant = base.clone();
    dormant.cluster_roles.push(cluster_role("everything", &[rule(r#"["*"]"#, r#"["*"]"#, r#"["*"]"#)]));
    dormant.cluster_bindings.push(cluster_binding("pre-positioned", "everything", &[account(Some("kube-system"), "certificate-controller")]));
    assert_eq!(checked(&dormant, QUALIFICATION).as_deref(),
               Some("IC02 absent controller account with grants beyond its bootstrap role: system:serviceaccount:kube-system:certificate-controller"));
    // IC03: the writer creating ClusterRoleBindings (S05).
    let mut writer = base.clone();
    writer.cluster_roles.push(cluster_role("crb-writer", &[rule(r#"["rbac.authorization.k8s.io"]"#, r#"["clusterrolebindings"]"#, r#"["create"]"#)]));
    writer.cluster_bindings.push(cluster_binding("writer-crb", "crb-writer", &[user("planeon:policy-writer")]));
    assert_eq!(checked(&writer, QUALIFICATION).as_deref(),
               Some("IC03 grant beyond the closure entry: planeon:policy-writer POLICY_WRITE create rbac.authorization.k8s.io/clusterrolebindings at CLUSTER"));
    // IC04: the writer's escalate and bind on every Role (S04's shape: no resourceNames).
    let mut every = base.clone();
    every.cluster_roles.push(cluster_role("escalator", &[rule(r#"["rbac.authorization.k8s.io"]"#, r#"["roles"]"#, r#"["bind", "escalate"]"#)]));
    every.role_bindings.push(role_binding(QUALIFICATION, "escalator", "ClusterRole", "escalator", &[user("planeon:policy-writer")]));
    assert_eq!(checked(&every, QUALIFICATION).as_deref(), Some("IC04 escalate or bind beyond the named planeon roles: planeon:policy-writer"));
    // IC05: no binding names the policy writer.
    let positive = positive();
    let writer_index = rows(&positive, "subjects").iter().position(|subject| text(subject, "name") == "planeon:policy-writer").expect("writer");
    let mut missing = base.clone();
    missing.cluster_bindings.retain(|binding| !binding.contains(&format!(r#""name": "rt-{writer_index}""#)));
    missing.role_bindings.retain(|binding| !binding.contains(&format!(r#""name": "rt-{writer_index}""#)));
    assert_eq!(checked(&missing, QUALIFICATION).as_deref(), Some("IC05 required closure identity absent from the snapshot: planeon:policy-writer"));
    // IC03 (v2): a resource rule bound directly to the loopback user (H02's shape); its non-resource rule refuses earlier,
    // in the producer (R1-7).
    let mut loopback = base.clone();
    loopback.cluster_roles.push(cluster_role("stats", &[rule(r#"[""]"#, r#"["nodes/stats"]"#, r#"["get"]"#)]));
    loopback.cluster_bindings.push(cluster_binding("loopback", "stats", &[user("system:apiserver")]));
    assert_eq!(checked(&loopback, QUALIFICATION).as_deref(), Some("IC03 the loopback user system:apiserver holds an RBAC rule"));
}
