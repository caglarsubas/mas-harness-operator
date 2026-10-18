//! HE-004B1 DESIGN-B section 4.2 (owner decision Q-HE4B-3 (a); D1-3, D1-18, D2-6) and section 8: the effective-RBAC
//! producer. R10-local vectors for every rule and refusal, the dropped non-resource count, and the model-derived
//! consistency test over `upstream-bootstrap-rbac-v1.37.1.json` (bindings rebuilt from each rule's `binding` field).

mod b1_rbac_support;
mod b1_support;

use std::collections::BTreeMap;

use b1_rbac_support::*;
use b1_support::{field, parse, rows, text};
use i05_protocol::json::Value;
use planeon_observer::inputs::{InputError, Inputs, Resource};
use planeon_observer::rbac::{produce_snapshot, ProduceError, Produced, SNAPSHOT_VERSION};

fn produce(rbac: &Rbac) -> Produced {
    produce_snapshot(&rbac.inputs(), QUALIFICATION).expect("a snapshot is produced")
}

fn refusal(rbac: &Rbac) -> ProduceError {
    produce_snapshot(&rbac.inputs(), QUALIFICATION).expect_err("no snapshot is produced")
}

fn rule_texts(rules: &[Value]) -> Vec<String> {
    rules.iter().map(canonical).collect()
}

fn base() -> Rbac {
    Rbac {
        cluster_roles: vec![
            cluster_role("cluster-admin", &[rule(r#"["*"]"#, r#"["*"]"#, r#"["*"]"#)]),
            cluster_role("view", &[rule(r#"[""]"#, r#"["pods", "configmaps"]"#, r#"["get", "list"]"#),
                                   rule(r#"["apps"]"#, r#"["deployments"]"#, r#"["get"]"#)]),
        ],
        cluster_bindings: vec![cluster_binding("cluster-admin", "cluster-admin", &[group("system:masters")])],
        roles: vec![role(QUALIFICATION, "editor", &[rule(r#"["rbac.authorization.k8s.io"]"#, r#"["roles"]"#, r#"["update"]"#)])],
        role_bindings: vec![
            role_binding(QUALIFICATION, "viewers", "ClusterRole", "view", &[user("alice")]),
            role_binding(QUALIFICATION, "editors", "Role", "editor", &[user("planeon:policy-writer")]),
        ],
        accounts: vec![service_account("kube-system", "default")],
    }
}

#[test]
fn the_snapshot_has_the_v1_shape_with_subjects_sorted_and_scoped() {
    let produced = produce(&base());
    assert_eq!(produced.dropped_non_resource_rules, 0);
    let snapshot = &produced.snapshot;
    assert_eq!(snapshot.as_object().expect("object").len(), 2);
    assert_eq!(text(snapshot, "schemaVersion"), SNAPSHOT_VERSION);
    let subjects = snapshot_subjects(snapshot);
    let keys: Vec<(&str, &str, bool)> = subjects.iter().map(|(kind, name, exists, _)| (kind.as_str(), name.as_str(), *exists)).collect();
    assert_eq!(keys, vec![("Group", "system:masters", true), ("User", "alice", true), ("User", "planeon:policy-writer", true)]);
    for subject in rows(snapshot, "subjects") {
        let mut members: Vec<&str> = subject.as_object().expect("object").iter().map(|(key, _)| key.as_str().expect("text")).collect();
        members.sort_unstable();
        assert_eq!(members, ["effectiveRules", "exists", "kind", "name"]);
    }
    assert_eq!(rule_texts(&subjects[0].3), vec![snapshot_rule(&["*"], &["*"], &["*"], &[], "CLUSTER")]);
    // A RoleBinding to a ClusterRole gives its rules at the binding's namespace; to a Role, the Role in that namespace.
    assert_eq!(rule_texts(&subjects[1].3), vec![
        snapshot_rule(&[""], &["pods", "configmaps"], &["get", "list"], &[], QUALIFICATION),
        snapshot_rule(&["apps"], &["deployments"], &["get"], &[], QUALIFICATION),
    ]);
    assert_eq!(rule_texts(&subjects[2].3), vec![snapshot_rule(&["rbac.authorization.k8s.io"], &["roles"], &["update"], &[], QUALIFICATION)]);
}

#[test]
fn one_entry_per_subject_with_the_union_of_its_bindings_in_binding_order() {
    let mut rbac = base();
    rbac.cluster_bindings.push(cluster_binding("viewers-everywhere", "view", &[user("alice"), user("alice")]));
    rbac.role_bindings.push(role_binding("other", "more", "ClusterRole", "view", &[user("alice")]));
    let subjects = snapshot_subjects(&produce(&rbac).snapshot);
    let alice: Vec<&(String, String, bool, Vec<Value>)> = subjects.iter().filter(|subject| subject.1 == "alice").collect();
    assert_eq!(alice.len(), 1, "one entry per (kind, name)");
    let cluster = snapshot_rule(&[""], &["pods", "configmaps"], &["get", "list"], &[], "CLUSTER");
    let cluster_apps = snapshot_rule(&["apps"], &["deployments"], &["get"], &[], "CLUSTER");
    let other = snapshot_rule(&[""], &["pods", "configmaps"], &["get", "list"], &[], "other");
    let other_apps = snapshot_rule(&["apps"], &["deployments"], &["get"], &[], "other");
    let mine = snapshot_rule(&[""], &["pods", "configmaps"], &["get", "list"], &[], QUALIFICATION);
    let mine_apps = snapshot_rule(&["apps"], &["deployments"], &["get"], &[], QUALIFICATION);
    // ClusterRoleBindings by name, then RoleBindings by namespace and name ("other" before "unit-namespace");
    // duplicates kept (the binding names alice twice).
    assert_eq!(rule_texts(&alice[0].3), vec![cluster.clone(), cluster_apps.clone(), cluster, cluster_apps, other, other_apps,
                                             mine, mine_apps]);
    // The same set in another list order gives the same snapshot.
    let mut shuffled = rbac.clone();
    shuffled.cluster_bindings.reverse();
    shuffled.role_bindings.reverse();
    shuffled.cluster_roles.reverse();
    assert_eq!(canonical(&produce(&shuffled).snapshot), canonical(&produce(&rbac).snapshot));
}

#[test]
fn service_accounts_exist_only_when_listed_and_default_to_the_role_binding_s_namespace() {
    let mut rbac = base();
    rbac.accounts.push(service_account("team", "builder"));
    rbac.role_bindings.push(role_binding("team", "builders", "ClusterRole", "view",
                                         &[account(None, "builder"), account(Some(""), "pusher"), account(Some("kube-system"), "default"),
                                           account(Some("kube-system"), "gone")]));
    let subjects = snapshot_subjects(&produce(&rbac).snapshot);
    let accounts: Vec<(&str, bool)> = subjects.iter().filter(|subject| subject.0 == "ServiceAccount")
        .map(|subject| (subject.1.as_str(), subject.2)).collect();
    assert_eq!(accounts, vec![("system:serviceaccount:kube-system:default", true), ("system:serviceaccount:kube-system:gone", false),
                              ("system:serviceaccount:team:builder", true), ("system:serviceaccount:team:pusher", false)]);
    // A ClusterRoleBinding's service account must name its namespace.
    let mut cluster = base();
    cluster.cluster_bindings.push(cluster_binding("bad", "view", &[account(None, "builder")]));
    assert_eq!(refusal(&cluster), ProduceError::Malformed { object: "ClusterRoleBinding/bad".into(), field: "subject namespace" });
    let mut empty = base();
    empty.cluster_bindings.push(cluster_binding("bad", "view", &[account(Some(""), "builder")]));
    assert!(matches!(refusal(&empty), ProduceError::Malformed { field: "subject namespace", .. }));
}

#[test]
fn groups_stay_groups_and_a_user_named_like_a_service_account_stays_a_user() {
    let mut rbac = base();
    rbac.cluster_bindings.push(cluster_binding("basic", "view", &[group("system:authenticated"),
                                                                   user("system:serviceaccount:kube-system:namespace-controller")]));
    let subjects = snapshot_subjects(&produce(&rbac).snapshot);
    assert!(subjects.iter().any(|subject| (subject.0.as_str(), subject.1.as_str()) == ("Group", "system:authenticated")));
    assert!(subjects.iter().any(|subject| (subject.0.as_str(), subject.1.as_str())
                                == ("User", "system:serviceaccount:kube-system:namespace-controller")));
    assert!(!subjects.iter().any(|subject| subject.0 == "ServiceAccount"), "no normalisation, no group expansion");
}

#[test]
fn r1_7_a_non_resource_rule_bound_directly_to_the_loopback_user_refuses() {
    let mut rbac = base();
    rbac.cluster_roles.push(cluster_role("discovery", &[non_resource(r#"["/api", "/healthz"]"#, r#"["get"]"#)]));
    rbac.cluster_bindings.push(cluster_binding("loopback", "discovery", &[group("system:masters"), user("system:apiserver")]));
    assert_eq!(refusal(&rbac), ProduceError::LoopbackNonResource { binding: "ClusterRoleBinding/loopback".into(),
                                                                   role: "ClusterRole/discovery".into() });
    let mut namespaced = base();
    namespaced.roles.push(role(QUALIFICATION, "mixed", &[rule(r#"[""]"#, r#"["pods"]"#, r#"["get"]"#),
                                                          non_resource(r#"["/metrics"]"#, r#"["get"]"#)]));
    namespaced.role_bindings.push(role_binding(QUALIFICATION, "loopback", "Role", "mixed", &[user("system:apiserver")]));
    assert!(matches!(refusal(&namespaced), ProduceError::LoopbackNonResource { .. }));
    // Group membership is not "reaching" (Q-HE4B-3 (a)): the loopback user is in system:masters and system:authenticated,
    // whose non-resource rules are dropped and counted.
    let mut groups = base();
    groups.cluster_roles.push(cluster_role("system:discovery", &[non_resource(r#"["/api"]"#, r#"["get"]"#)]));
    groups.cluster_bindings.push(cluster_binding("discovery", "system:discovery",
                                                 &[group("system:masters"), group("system:authenticated"), group("system:apiserver")]));
    assert_eq!(produce(&groups).dropped_non_resource_rules, 3);
    // A loopback binding of resource rules only is produced; the snapshot check refuses it (IC03 v2).
    let mut resources = base();
    resources.cluster_bindings.push(cluster_binding("loopback", "view", &[user("system:apiserver")]));
    let subjects = snapshot_subjects(&produce(&resources).snapshot);
    assert!(subjects.iter().any(|subject| subject.1 == "system:apiserver" && subject.3.len() == 2));
}

#[test]
fn non_resource_rules_of_other_subjects_are_dropped_and_counted_per_subject() {
    let mut rbac = base();
    rbac.cluster_roles.push(cluster_role("probe", &[non_resource(r#"["/livez"]"#, r#"["get"]"#),
                                                     rule(r#"[""]"#, r#"["nodes/metrics"]"#, r#"["get"]"#),
                                                     non_resource(r#"["/readyz", "/version"]"#, r#"["get"]"#)]));
    rbac.cluster_bindings.push(cluster_binding("probes", "probe", &[group("system:monitoring"), user("prober")]));
    rbac.role_bindings.push(role_binding("other", "probes", "ClusterRole", "probe", &[user("prober")]));
    let produced = produce(&rbac);
    assert_eq!(produced.dropped_non_resource_rules, 6, "2 rules x (2 subjects of one binding + 1 of another)");
    let subjects = snapshot_subjects(&produced.snapshot);
    let prober = subjects.iter().find(|subject| subject.1 == "prober").expect("prober");
    assert_eq!(rule_texts(&prober.3), vec![snapshot_rule(&[""], &["nodes/metrics"], &["get"], &[], "CLUSTER"),
                                           snapshot_rule(&[""], &["nodes/metrics"], &["get"], &[], "other")]);
    // A subject whose rules are all dropped is still listed, with no rule.
    let mut only = base();
    only.cluster_roles.push(cluster_role("public-info", &[non_resource(r#"["/version"]"#, r#"["get"]"#)]));
    only.cluster_bindings.push(cluster_binding("public-info", "public-info", &[group("system:unauthenticated")]));
    let produced = produce(&only);
    assert_eq!(produced.dropped_non_resource_rules, 1);
    let subjects = snapshot_subjects(&produced.snapshot);
    assert!(subjects.iter().any(|subject| subject.1 == "system:unauthenticated" && subject.3.is_empty()));
}

#[test]
fn or03_an_aggregated_cluster_role_reaching_the_qualification_namespace_refuses() {
    for aggregation in [r#"{"clusterRoleSelectors": [{"matchLabels": {"x": "true"}}]}"#, r#"{}"#, r#"{"clusterRoleSelectors": []}"#, "null"] {
        let mut rbac = base();
        rbac.cluster_roles.push(aggregated_role("admin", aggregation));
        rbac.cluster_bindings.push(cluster_binding("admins", "admin", &[user("bob")]));
        assert_eq!(refusal(&rbac), ProduceError::AggregatedRole { binding: "ClusterRoleBinding/admins".into(),
                                                                  role: "ClusterRole/admin".into() }, "{aggregation}");
        let mut here = base();
        here.cluster_roles.push(aggregated_role("admin", aggregation));
        here.role_bindings.push(role_binding(QUALIFICATION, "admins", "ClusterRole", "admin", &[user("bob")]));
        assert!(matches!(refusal(&here), ProduceError::AggregatedRole { .. }), "{aggregation}");
    }
    // Bound in another namespace only, or not bound at all (the stock admin, edit and view): no refusal.
    let mut elsewhere = base();
    elsewhere.cluster_roles.push(aggregated_role("admin", "{}"));
    elsewhere.cluster_roles.push(aggregated_role("edit", "{}"));
    elsewhere.role_bindings.push(role_binding("other", "admins", "ClusterRole", "admin", &[user("bob")]));
    produce(&elsewhere);
}

#[test]
fn a_binding_to_a_missing_role_refuses() {
    let mut cluster = base();
    cluster.cluster_bindings.push(cluster_binding("latent", "not-yet", &[user("bob")]));
    assert_eq!(refusal(&cluster), ProduceError::DanglingRoleRef { binding: "ClusterRoleBinding/latent".into(),
                                                                  role: "ClusterRole/not-yet".into() });
    let mut namespaced = base();
    namespaced.role_bindings.push(role_binding(QUALIFICATION, "latent", "Role", "not-yet", &[user("bob")]));
    assert!(matches!(refusal(&namespaced), ProduceError::DanglingRoleRef { .. }));
    // A Role resolves in its binding's namespace only.
    let mut other = base();
    other.role_bindings.push(role_binding("other", "editors", "Role", "editor", &[user("bob")]));
    assert_eq!(refusal(&other), ProduceError::DanglingRoleRef { binding: "RoleBinding/other/editors".into(),
                                                                role: "Role/other/editor".into() });
}

#[test]
fn malformed_objects_refuse() {
    let refs = [
        (r#""roleRef": {"apiGroup": "rbac.example.io", "kind": "ClusterRole", "name": "view"}"#, "roleRef apiGroup"),
        (r#""roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": "view"}"#, "roleRef kind"),
        (r#""roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "view"}"#, "roleRef kind"),
        (r#""roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": ""}"#, "roleRef name"),
        (r#""roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole"}"#, "roleRef name"),
        (r#""roleRef": "view""#, "roleRef"),
        (r#""other": 1"#, "roleRef"),
    ];
    for (reference, field_name) in refs {
        let mut rbac = base();
        rbac.cluster_bindings.push(format!(r#"{{"metadata": {{"name": "bad"}}, {reference}, "subjects": []}}"#));
        assert_eq!(refusal(&rbac), ProduceError::Malformed { object: "ClusterRoleBinding/bad".into(), field: field_name }, "{reference}");
    }
    let subjects = [(r#""subjects": {}"#, "subjects"), (r#""subjects": [1]"#, "subject"),
                    (r#""subjects": [{"kind": "Robot", "name": "r2"}]"#, "subject kind"),
                    (r#""subjects": [{"kind": "user", "name": "r2"}]"#, "subject kind"),
                    (r#""subjects": [{"kind": "User"}]"#, "subject name"),
                    (r#""subjects": [{"kind": "User", "name": ""}]"#, "subject name"),
                    (r#""subjects": [{"kind": "ServiceAccount", "name": "a", "namespace": 5}]"#, "subject namespace")];
    for (list, field_name) in subjects {
        let mut rbac = base();
        rbac.role_bindings.push(format!(r#"{{"metadata": {{"name": "bad", "namespace": "x"}}, "roleRef": {{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "view"}}, {list}}}"#));
        assert_eq!(refusal(&rbac), ProduceError::Malformed { object: "RoleBinding/x/bad".into(), field: field_name }, "{list}");
    }
    let roles = [(r#""rules": {}"#, "rules"), (r#""rules": [1]"#, "rule"), (r#""rules": [{"verbs": "get"}]"#, "rule list"),
                 (r#""rules": [{"verbs": [1]}]"#, "rule list"), (r#""rules": [{"apiGroups": [""], "resources": {}}]"#, "rule list"),
                 (r#""rules": [{"nonResourceURLs": ["/metrics"], "resources": ["pods"], "verbs": ["get"]}]"#,
                  "rule (non-resource URLs beside resources)")];
    for (rules, field_name) in roles {
        let mut rbac = base();
        rbac.cluster_roles.push(format!(r#"{{"metadata": {{"name": "odd"}}, {rules}}}"#));
        assert_eq!(refusal(&rbac), ProduceError::Malformed { object: "ClusterRole/odd".into(), field: field_name }, "{rules}");
    }
    // Empty non-resource URLs beside resources are a resource rule; absent and null lists are empty.
    let mut fine = base();
    fine.cluster_roles.push(format!(r#"{{"metadata": {{"name": "fine"}}, "rules": [{{"nonResourceURLs": [], "resources": ["pods"], "verbs": ["get"], "apiGroups": null}}]}}"#));
    fine.cluster_bindings.push(cluster_binding("fine", "fine", &[user("carol")]));
    let subjects = snapshot_subjects(&produce(&fine).snapshot);
    let carol = subjects.iter().find(|subject| subject.1 == "carol").expect("carol");
    assert_eq!(rule_texts(&carol.3), vec![snapshot_rule(&[], &["pods"], &["get"], &[], "CLUSTER")]);
    // A binding with no subjects grants nothing; a role with no rules key holds none.
    let mut empty = base();
    empty.cluster_roles.push(r#"{"metadata": {"name": "bare"}}"#.to_string());
    empty.cluster_bindings.push(r#"{"metadata": {"name": "bare"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "bare"}}"#.to_string());
    assert_eq!(snapshot_subjects(&produce(&empty).snapshot).len(), 3);
}

#[test]
fn the_refusal_order_is_the_binding_order_and_the_rule_order_within_one() {
    // A dangling ClusterRoleBinding comes before a malformed RoleBinding; within one binding the roleRef first.
    let mut rbac = base();
    rbac.cluster_bindings.push(cluster_binding("z-latent", "missing", &[user("bob")]));
    rbac.role_bindings.push(role_binding("a", "bad", "ClusterRole", "view", &[r#"{"kind": "Robot", "name": "r"}"#.to_string()]));
    assert!(matches!(refusal(&rbac), ProduceError::DanglingRoleRef { .. }));
    let mut within = base();
    within.cluster_bindings.push(r#"{"metadata": {"name": "both"}, "roleRef": {"apiGroup": "x", "kind": "ClusterRole", "name": "missing"}, "subjects": [1]}"#.to_string());
    assert_eq!(refusal(&within), ProduceError::Malformed { object: "ClusterRoleBinding/both".into(), field: "roleRef apiGroup" });
    let mut subjects_first = base();
    subjects_first.cluster_bindings.push(cluster_binding("both", "missing", &["1".to_string()]));
    assert!(matches!(refusal(&subjects_first), ProduceError::Malformed { field: "subject", .. }));
    // A malformed role refuses before any binding is read, bound or not.
    let mut role_first = base();
    role_first.cluster_roles.push(r#"{"metadata": {"name": "odd"}, "rules": 1}"#.to_string());
    role_first.cluster_bindings.push(cluster_binding("latent", "missing", &[user("bob")]));
    assert!(matches!(refusal(&role_first), ProduceError::Malformed { field: "rules", .. }));
    // OR03 before R1-7 within one binding.
    let mut aggregated = base();
    aggregated.cluster_roles.push(r#"{"metadata": {"name": "agg"}, "aggregationRule": {}, "rules": [{"nonResourceURLs": ["/x"], "verbs": ["get"]}]}"#.to_string());
    aggregated.cluster_bindings.push(cluster_binding("agg", "agg", &[user("system:apiserver")]));
    assert!(matches!(refusal(&aggregated), ProduceError::AggregatedRole { .. }));
}

#[test]
fn incomplete_lists_refuse_before_anything_is_produced() {
    let pairs: Vec<_> = base().pairs().into_iter().filter(|input| Resource::of_spec(&input.spec) != Some(Resource::ServiceAccounts)).collect();
    let inputs = Inputs::new(pairs).expect("checked");
    assert_eq!(produce_snapshot(&inputs, QUALIFICATION).expect_err("missing"),
               ProduceError::Input(InputError::Missing(Resource::ServiceAccounts)));
}

#[test]
fn the_refusal_texts() {
    assert_eq!(ProduceError::LoopbackNonResource { binding: "ClusterRoleBinding/x".into(), role: "ClusterRole/y".into() }.to_string(),
               "R1-7 ClusterRoleBinding/x binds User system:apiserver to ClusterRole/y, which holds a non-resource-URL rule: no snapshot is produced");
    assert_eq!(ProduceError::AggregatedRole { binding: "RoleBinding/n/x".into(), role: "ClusterRole/admin".into() }.to_string(),
               "OR03 RoleBinding/n/x binds the aggregated ClusterRole ClusterRole/admin where it reaches the qualification namespace");
}

/// DESIGN-B section 8 (D1-3, D2-6): the bindings rebuilt from the bootstrap file's per-rule `binding` field, one
/// ClusterRole per binding holding that binding's rules and a ServiceAccount list holding every service-account subject;
/// the producer reproduces every subject's rules as a multiset, and a subject with no rules matches absence.
#[test]
fn the_producer_reproduces_the_upstream_bootstrap_rbac() {
    let bootstrap = parse(std::str::from_utf8(planeon_observer::contracts::BOOTSTRAP_RBAC).expect("UTF-8"));
    // binding -> (its rules without the binding field, its subjects in file order)
    let mut bindings: BTreeMap<String, (Vec<Value>, Vec<(String, String)>)> = BTreeMap::new();
    let mut expected: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut accounts = Vec::new();
    for subject in rows(&bootstrap, "subjects") {
        let key = (text(subject, "kind").to_string(), text(subject, "name").to_string());
        let mut file_rules = Vec::new();
        let mut per_binding: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for rule in rows(subject, "rules") {
            let binding = text(rule, "binding").to_string();
            let mut bare = rule.clone();
            if let Value::Object(members) = &mut bare {
                members.remove(&"binding".into()).expect("binding");
            }
            let scope = text(rule, "scope");
            match binding.split('/').collect::<Vec<_>>().as_slice() {
                ["ClusterRoleBinding", _] => assert_eq!(scope, "CLUSTER"),
                ["RoleBinding", namespace, _] => assert_eq!(scope, *namespace),
                _ => panic!("binding {binding}"),
            }
            file_rules.push(canonical(&bare));
            per_binding.entry(binding).or_default().push(bare);
        }
        for (binding, rules) in per_binding {
            let slot = bindings.entry(binding.clone()).or_insert_with(|| (rules.clone(), Vec::new()));
            let mine: Vec<String> = rules.iter().map(canonical).collect();
            let theirs: Vec<String> = slot.0.iter().map(canonical).collect();
            assert_eq!(mine, theirs, "{binding}: one rule list per binding");
            slot.1.push(key.clone());
        }
        if key.0 == "ServiceAccount" {
            let rest = key.1.strip_prefix("system:serviceaccount:").expect("service-account name");
            let (namespace, name) = rest.split_once(':').expect("namespace and name");
            accounts.push(service_account(namespace, name));
        }
        if !file_rules.is_empty() {
            file_rules.sort();
            expected.insert(key, file_rules);
        }
    }
    assert_eq!(bindings.len(), 57, "50 ClusterRoleBindings and 7 RoleBindings");
    let mut rbac = Rbac { accounts, ..Rbac::default() };
    for (index, (binding, (rules, subjects))) in bindings.iter().enumerate() {
        let role_name = format!("bootstrap-{index}");
        let role_rules: Vec<String> = rules.iter().map(|rule| {
            format!(r#"{{"apiGroups": {}, "resources": {}, "verbs": {}, "resourceNames": {}}}"#,
                    canonical(field(rule, "apiGroups")), canonical(field(rule, "resources")), canonical(field(rule, "verbs")),
                    canonical(field(rule, "resourceNames")))
        }).collect();
        rbac.cluster_roles.push(cluster_role(&role_name, &role_rules));
        let named: Vec<String> = subjects.iter().map(|(kind, name)| match kind.as_str() {
            "User" => user(name),
            "Group" => group(name),
            _ => {
                let (namespace, account_name) = name["system:serviceaccount:".len()..].split_once(':').expect("split");
                account(Some(namespace), account_name)
            }
        }).collect();
        match binding.split('/').collect::<Vec<_>>().as_slice() {
            ["ClusterRoleBinding", name] => rbac.cluster_bindings.push(cluster_binding(name, &role_name, &named)),
            ["RoleBinding", namespace, name] => {
                rbac.role_bindings.push(role_binding(namespace, name, "ClusterRole", &role_name, &named))
            }
            _ => unreachable!(),
        }
    }
    let produced = produce_snapshot(&rbac.inputs(), QUALIFICATION).expect("the bootstrap RBAC produces a snapshot");
    assert_eq!(produced.dropped_non_resource_rules, 0);
    let mut got: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for (kind, name, exists, rules) in snapshot_subjects(&produced.snapshot) {
        assert!(exists, "{kind} {name}");
        let mut texts = rule_texts(&rules);
        texts.sort();
        got.insert((kind, name), texts);
    }
    assert_eq!(got.len(), expected.len());
    assert_eq!(got, expected);
    // Group system:unauthenticated has no rule in the file and is absent from the output.
    assert!(rows(&bootstrap, "subjects").iter().any(|subject| text(subject, "name") == "system:unauthenticated"
                                                     && rows(subject, "rules").is_empty()));
    assert!(!got.contains_key(&("Group".to_string(), "system:unauthenticated".to_string())));
}
