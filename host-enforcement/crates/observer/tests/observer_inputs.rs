//! HE-004B1 DESIGN-B section 4.1 (D1-1, D2-1, D2-4, D3-1) and section 8: the closed request specs, the pairing of each
//! list with the spec its fetcher states, every completeness refusal, and the NotServed marker for exactly the two
//! MutatingAdmissionPolicy kinds. R10-local vectors (no harness-onion vector covers the inputs).

mod b1_support;

use b1_support::{inputs, list_value, parse, served, unserved};
use i05_protocol::json::Value;
use planeon_observer::inputs::{InputError, Inputs, ListBody, ListInput, Listed, RequestScope, RequestSpec, Resource};

fn refused(pairs: Vec<ListInput>) -> InputError {
    Inputs::new(pairs).expect_err("the inputs are refused")
}

fn with_body(resource: Resource, body: Value) -> ListInput {
    ListInput { spec: resource.spec(), body: ListBody::Served(body) }
}

const SA: &str = r#"[{"metadata": {"name": "default", "namespace": "kube-system"}},
                     {"metadata": {"name": "namespace-controller", "namespace": "kube-system"}}]"#;

#[test]
fn the_closed_set_is_the_policy_kinds_plus_the_two_secret_lists() {
    assert_eq!(Resource::ALL.len(), 20);
    let mut specs: Vec<RequestSpec> = Resource::ALL.into_iter().map(Resource::spec).collect();
    for resource in Resource::ALL {
        assert_eq!(Resource::of_spec(&resource.spec()), Some(resource));
        let spec = resource.spec();
        assert_eq!(spec.label_selector, None, "no label selector ever");
        assert_eq!(spec.scope, if resource.namespaced() { RequestScope::AllNamespaces } else { RequestScope::Cluster });
    }
    specs.sort();
    specs.dedup();
    assert_eq!(specs.len(), 20, "each entry has its own spec");
    // The field selectors are OR05's two exact strings, on the two metadata-only Secret lists only.
    let selected: Vec<(Resource, String)> = Resource::ALL
        .into_iter()
        .filter_map(|resource| resource.spec().field_selector.map(|selector| (resource, selector)))
        .collect();
    assert_eq!(selected, vec![
        (Resource::ServiceAccountTokenSecrets, "type=kubernetes.io/service-account-token".to_string()),
        (Resource::BootstrapTokenSecrets, "type=bootstrap.kubernetes.io/token".to_string()),
    ]);
    for resource in [Resource::ServiceAccountTokenSecrets, Resource::BootstrapTokenSecrets] {
        assert_eq!(resource.list_kind(), ("PartialObjectMetadataList".to_string(), "meta.k8s.io/v1".to_string()));
        assert_eq!((resource.group(), resource.resource(), resource.namespaced()), ("", "secrets", true));
    }
    // The NotServed set is closed: the two MutatingAdmissionPolicy kinds (D3-1).
    let unservable: Vec<Resource> = Resource::ALL.into_iter().filter(|resource| resource.may_be_unserved()).collect();
    assert_eq!(unservable, vec![Resource::MutatingAdmissionPolicies, Resource::MutatingAdmissionPolicyBindings]);
}

#[test]
fn the_policy_entries_are_the_i07_v3_kind_table() {
    let table = parse(std::str::from_utf8(i05_protocol::contracts::I07_V3_POLICY_KINDS).expect("UTF-8"));
    let mut seen = Vec::new();
    for (section, writable) in [("writable", true), ("notWritable", false)] {
        for row in b1_support::rows(&table, section) {
            let group = b1_support::text(row, "group");
            let name = b1_support::text(row, "resource");
            let resource = Resource::of_policy_kind(group, name).unwrap_or_else(|| panic!("no entry for {group}/{name}"));
            assert_eq!(resource.kind(), b1_support::text(row, "kind"));
            let spec = resource.spec();
            if writable {
                assert_eq!(spec.version, b1_support::text(row, "version"), "{name}");
                let scope = b1_support::text(row, "scope");
                assert_eq!(resource.namespaced(), scope == "QUALIFICATION_NAMESPACE", "{name}: {scope}");
            } else {
                assert_eq!((spec.version.as_str(), resource.namespaced()), ("v1", false), "{name}");
            }
            let (kind, api_version) = resource.list_kind();
            assert_eq!(kind, format!("{}List", b1_support::text(row, "kind")));
            assert_eq!(api_version, if group.is_empty() { "v1".to_string() } else { format!("{group}/v1") });
            seen.push(resource);
        }
    }
    seen.sort();
    let mut policy: Vec<Resource> = Resource::ALL[..18].to_vec();
    policy.sort();
    assert_eq!(seen, policy, "the eighteen policy entries, each once");
    assert_eq!(Resource::of_policy_kind("", "secrets"), None);
}

#[test]
fn a_complete_set_of_lists_passes() {
    let checked = inputs(b1_support::all_empty_except(vec![served(Resource::ServiceAccounts, SA)]));
    assert_eq!(checked.items(Resource::ServiceAccounts).expect("served").len(), 2);
    assert!(matches!(checked.list(Resource::Roles), Ok(Listed::Items(items)) if items.is_empty()));
    // An absent continue token and an exactly empty one both pass; so does a list without metadata.
    let mut value = list_value(Resource::Roles, "[]");
    if let Value::Object(object) = &mut value {
        object.insert("metadata".into(), parse(r#"{"resourceVersion": "9", "continue": ""}"#));
    }
    inputs(vec![with_body(Resource::Roles, value)]);
    inputs(vec![with_body(Resource::Roles, parse(r#"{"kind": "RoleList", "apiVersion": "rbac.authorization.k8s.io/v1", "items": []}"#))]);
}

#[test]
fn a_pair_outside_the_closed_set_refuses() {
    // A namespace-scoped RoleBinding list (D2-1): its answer is a well-formed RoleBindingList, so only the stated
    // request shows that it hides the other namespaces' grants.
    let mut namespaced = Resource::RoleBindings.spec();
    namespaced.scope = RequestScope::Namespace("kube-system".to_string());
    let body = ListBody::Served(list_value(Resource::RoleBindings, "[]"));
    assert_eq!(refused(vec![ListInput { spec: namespaced.clone(), body: body.clone() }]),
               InputError::OutsideClosedSet(namespaced));
    // A selector-filtered ServiceAccount list (D2-1): it would hide an existing controller account.
    let mut labelled = Resource::ServiceAccounts.spec();
    labelled.label_selector = Some("app=planeon".to_string());
    let sa = ListBody::Served(list_value(Resource::ServiceAccounts, SA));
    assert_eq!(refused(vec![ListInput { spec: labelled.clone(), body: sa.clone() }]), InputError::OutsideClosedSet(labelled));
    let mut field = Resource::ServiceAccounts.spec();
    field.field_selector = Some("metadata.namespace=kube-system".to_string());
    assert!(matches!(refused(vec![ListInput { spec: field, body: sa.clone() }]), InputError::OutsideClosedSet(_)));
    // Another version, another group, another scope, and OR05's selector on another resource.
    for change in 0..4 {
        let mut spec = Resource::ClusterRoles.spec();
        match change {
            0 => spec.version = "v1beta1".to_string(),
            1 => spec.group = "rbac.example.io".to_string(),
            2 => spec.scope = RequestScope::AllNamespaces,
            _ => spec.field_selector = Some("type=kubernetes.io/service-account-token".to_string()),
        }
        let body = ListBody::Served(list_value(Resource::ClusterRoles, "[]"));
        assert!(matches!(refused(vec![ListInput { spec, body }]), InputError::OutsideClosedSet(_)), "change {change}");
    }
    // A Secret list with OR05's selector but cluster scope is outside too.
    let mut cluster = Resource::BootstrapTokenSecrets.spec();
    cluster.scope = RequestScope::Cluster;
    let body = ListBody::Served(list_value(Resource::BootstrapTokenSecrets, "[]"));
    assert!(matches!(refused(vec![ListInput { spec: cluster, body }]), InputError::OutsideClosedSet(_)));
}

#[test]
fn a_list_paired_with_another_spec_refuses() {
    // A RoleBindingList stated as the ServiceAccounts answer, and a full SecretList stated as OR05's metadata-only one.
    let body = ListBody::Served(list_value(Resource::RoleBindings, "[]"));
    assert_eq!(refused(vec![ListInput { spec: Resource::ServiceAccounts.spec(), body }]),
               InputError::ListKind(Resource::ServiceAccounts));
    let secrets = parse(r#"{"kind": "SecretList", "apiVersion": "v1", "items": []}"#);
    assert_eq!(refused(vec![with_body(Resource::ServiceAccountTokenSecrets, secrets)]),
               InputError::ListKind(Resource::ServiceAccountTokenSecrets));
    for (kind, api_version) in [("\"RoleList\"", "\"v1\""), ("\"RoleList\"", "null"), ("1", "\"rbac.authorization.k8s.io/v1\""),
                                ("\"Rolelist\"", "\"rbac.authorization.k8s.io/v1\"")] {
        let value = parse(&format!(r#"{{"kind": {kind}, "apiVersion": {api_version}, "items": []}}"#));
        assert_eq!(refused(vec![with_body(Resource::Roles, value)]), InputError::ListKind(Resource::Roles), "{kind} {api_version}");
    }
    assert_eq!(refused(vec![with_body(Resource::Roles, parse("[]"))]), InputError::NotAList(Resource::Roles));
}

#[test]
fn each_pair_once_and_a_missing_pair_refuses() {
    assert_eq!(refused(vec![served(Resource::Roles, "[]"), served(Resource::Roles, "[]")]),
               InputError::DuplicatePair(Resource::Roles));
    let checked = inputs(vec![served(Resource::Roles, "[]")]);
    assert_eq!(checked.list(Resource::RoleBindings).expect_err("missing"), InputError::Missing(Resource::RoleBindings));
    assert_eq!(checked.items(Resource::ClusterRoles).expect_err("missing"), InputError::Missing(Resource::ClusterRoles));
}

#[test]
fn a_paged_answer_refuses() {
    for metadata in [r#"{"continue": "eyJ2IjoibWV0YS5rOHMuaW8vdjEifQ"}"#, r#"{"continue": 1}"#, r#"{"continue": null}"#,
                     r#"{"continue": false}"#, r#"{"continue": ["x"]}"#, r#"{"remainingItemCount": 3}"#,
                     r#"{"remainingItemCount": 0}"#, r#"{"remainingItemCount": null, "continue": ""}"#, r#""rv""#, "[]"] {
        let value = parse(&format!(r#"{{"kind": "ServiceAccountList", "apiVersion": "v1", "metadata": {metadata}, "items": []}}"#));
        assert_eq!(refused(vec![with_body(Resource::ServiceAccounts, value)]), InputError::Paged(Resource::ServiceAccounts),
                   "{metadata}");
    }
}

#[test]
fn a_service_account_list_missing_an_existing_account_refuses_rather_than_marking_it_absent() {
    // The page that holds namespace-controller's account is not there: the list is visibly paged, and refused, so the
    // producer never sees the account as absent (D1-1's dormant-controller path).
    let first_page = parse(r#"{"kind": "ServiceAccountList", "apiVersion": "v1", "metadata": {"continue": "next"},
                               "items": [{"metadata": {"name": "default", "namespace": "kube-system"}}]}"#);
    assert_eq!(refused(vec![with_body(Resource::ServiceAccounts, first_page)]), InputError::Paged(Resource::ServiceAccounts));
    // Fetched for one namespace only: the stated request is outside the closed set.
    let mut spec = Resource::ServiceAccounts.spec();
    spec.scope = RequestScope::Namespace("kube-public".to_string());
    let body = ListBody::Served(list_value(Resource::ServiceAccounts, r#"[{"metadata": {"name": "default", "namespace": "kube-public"}}]"#));
    assert!(matches!(refused(vec![ListInput { spec, body }]), InputError::OutsideClosedSet(_)));
    // No pair at all: the producer's request for the list refuses (planeon_observer::rbac's tests carry it on).
    assert_eq!(inputs(vec![]).items(Resource::ServiceAccounts).expect_err("missing"), InputError::Missing(Resource::ServiceAccounts));
}

#[test]
fn the_items_must_be_an_array_of_named_objects() {
    for items in ["null", "{}", "\"x\"", "3"] {
        assert_eq!(refused(vec![served(Resource::Roles, items)]), InputError::Items(Resource::Roles), "{items}");
    }
    assert_eq!(refused(vec![with_body(Resource::Roles, parse(r#"{"kind": "RoleList", "apiVersion": "rbac.authorization.k8s.io/v1"}"#))]),
               InputError::Items(Resource::Roles));
    for item in ["1", "null", "[]", r#"{}"#, r#"{"metadata": null}"#, r#"{"metadata": []}"#, r#"{"metadata": {}}"#,
                 r#"{"metadata": {"name": ""}}"#, r#"{"metadata": {"name": 7}}"#, r#"{"metadata": {"name": "\ud800"}}"#] {
        assert_eq!(refused(vec![served(Resource::ClusterRoles, &format!("[{item}]"))]),
                   InputError::ItemShape(Resource::ClusterRoles, 0), "{item}");
    }
    assert_eq!(refused(vec![served(Resource::ClusterRoles, r#"[{"metadata": {"name": "a"}}, {"spec": {}}]"#)]),
               InputError::ItemShape(Resource::ClusterRoles, 1));
}

#[test]
fn an_item_must_fit_its_kind_s_scope() {
    // A namespaced kind's item without a namespace (absent, empty, not text), and a cluster-scoped kind's item with one.
    for metadata in [r#"{"name": "a"}"#, r#"{"name": "a", "namespace": ""}"#, r#"{"name": "a", "namespace": null}"#,
                     r#"{"name": "a", "namespace": 3}"#] {
        assert_eq!(refused(vec![served(Resource::RoleBindings, &format!(r#"[{{"metadata": {metadata}}}]"#))]),
                   InputError::ItemScope(Resource::RoleBindings, 0), "{metadata}");
    }
    for metadata in [r#"{"name": "a", "namespace": "default"}"#, r#"{"name": "a", "namespace": ""}"#,
                     r#"{"name": "a", "namespace": null}"#] {
        assert_eq!(refused(vec![served(Resource::ClusterRoleBindings, &format!(r#"[{{"metadata": {metadata}}}]"#))]),
                   InputError::ItemScope(Resource::ClusterRoleBindings, 0), "{metadata}");
    }
    let secret = r#"[{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": {"name": "t"}}]"#;
    assert_eq!(refused(vec![served(Resource::BootstrapTokenSecrets, secret)]), InputError::ItemScope(Resource::BootstrapTokenSecrets, 0));
}

#[test]
fn a_repeated_item_refuses() {
    assert_eq!(refused(vec![served(Resource::RoleBindings, r#"[{"metadata": {"name": "a", "namespace": "x"}},
                                                              {"metadata": {"name": "b", "namespace": "x"}},
                                                              {"metadata": {"name": "a", "namespace": "x"}}]"#)]),
               InputError::DuplicateItem(Resource::RoleBindings, 2));
    inputs(vec![served(Resource::RoleBindings, r#"[{"metadata": {"name": "a", "namespace": "x"}},
                                                  {"metadata": {"name": "a", "namespace": "y"}}]"#)]);
    assert_eq!(refused(vec![served(Resource::ClusterRoles, r#"[{"metadata": {"name": "view"}}, {"metadata": {"name": "view"}}]"#)]),
               InputError::DuplicateItem(Resource::ClusterRoles, 1));
}

#[test]
fn not_served_only_for_the_two_mutating_admission_policy_kinds() {
    let checked = inputs(vec![unserved(Resource::MutatingAdmissionPolicies), unserved(Resource::MutatingAdmissionPolicyBindings)]);
    assert!(matches!(checked.list(Resource::MutatingAdmissionPolicies), Ok(Listed::NotServed)));
    assert!(matches!(checked.list(Resource::MutatingAdmissionPolicyBindings), Ok(Listed::NotServed)));
    // A function that needs the list itself cannot take the marker.
    assert_eq!(checked.items(Resource::MutatingAdmissionPolicies).expect_err("not served"),
               InputError::NotServedRefused(Resource::MutatingAdmissionPolicies));
    // Outside the closed NotServed set (D3-1): an always-served kind, the other OR06 kinds, the RBAC and OR05 lists.
    for resource in Resource::ALL.into_iter().filter(|resource| !resource.may_be_unserved()) {
        assert_eq!(refused(vec![unserved(resource)]), InputError::NotServedRefused(resource), "{resource}");
    }
    // A marker and a list for one kind are two pairs.
    assert_eq!(refused(vec![unserved(Resource::MutatingAdmissionPolicies), served(Resource::MutatingAdmissionPolicies, "[]")]),
               InputError::DuplicatePair(Resource::MutatingAdmissionPolicies));
}

#[test]
fn the_refusals_name_the_list() {
    assert_eq!(InputError::Missing(Resource::ServiceAccounts).to_string(), "input: no list answers core/v1 serviceaccounts");
    assert_eq!(InputError::Paged(Resource::BootstrapTokenSecrets).to_string(),
               "input: the answer to core/v1 secrets (type=bootstrap.kubernetes.io/token) is paged or carries no complete list metadata");
    assert_eq!(InputError::NotServedRefused(Resource::ValidatingWebhookConfigurations).to_string(),
               "input: admissionregistration.k8s.io/v1 validatingwebhookconfigurations may not be attested as not served");
}
