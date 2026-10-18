//! HE-004B1 DESIGN-B section 4.4 (D1-5, D2-4, D3-1, D3-2) and section 8: OR02, OR05 and OR06 over the checked inputs,
//! including the NotServed marker OR02 and OR06 share and OR05's selector strings. R10-local vectors (I06 has none).

mod b1_support;

use b1_support::{all_empty_except, inputs, served, unserved};
use planeon_observer::inputs::{InputError, Inputs, ListBody, ListInput, Resource};
use planeon_observer::operational::{check_or02, check_or05, check_or06, policy_kinds, OperationalRefusal, OR05_LISTS, OR06_KINDS};

fn all_empty() -> Inputs {
    inputs(all_empty_except(vec![]))
}

fn object(resource: Resource, name: &str, extra: &str) -> String {
    let namespace = if resource.namespaced() { r#", "namespace": "unit-namespace""# } else { "" };
    format!(r#"[{{"metadata": {{"name": "{name}"{namespace}{extra}}}}}]"#)
}

#[test]
fn the_kind_set_is_the_i07_v3_table_in_table_order() {
    let kinds = policy_kinds().expect("the registered table");
    assert_eq!(kinds, vec![
        Resource::LimitRanges, Resource::Namespaces, Resource::ResourceQuotas, Resource::ServiceAccounts,
        Resource::NetworkPolicies, Resource::RoleBindings, Resource::Roles, Resource::ClusterRoles,
        Resource::ClusterRoleBindings, Resource::ValidatingWebhookConfigurations, Resource::MutatingWebhookConfigurations,
        Resource::MutatingAdmissionPolicies, Resource::MutatingAdmissionPolicyBindings, Resource::ApiServices,
        Resource::CustomResourceDefinitions, Resource::CertificateSigningRequests, Resource::ValidatingAdmissionPolicies,
        Resource::ValidatingAdmissionPolicyBindings,
    ]);
    assert_eq!(kinds.as_slice(), &Resource::ALL[..18]);
}

#[test]
fn every_rule_passes_on_complete_empty_lists() {
    let checked = all_empty();
    assert_eq!(check_or02(&checked), Ok(()));
    assert_eq!(check_or05(&checked), Ok(()));
    assert_eq!(check_or06(&checked), Ok(()));
}

#[test]
fn or02_refuses_a_non_empty_owner_reference_on_every_policy_kind() {
    for resource in policy_kinds().expect("table") {
        let owned = object(resource, "owned", r#", "ownerReferences": [{"apiVersion": "v1", "kind": "Namespace", "name": "x", "uid": "1"}]"#);
        let checked = inputs(all_empty_except(vec![served(resource, &owned)]));
        let expected = if resource.namespaced() { "unit-namespace/owned" } else { "owned" };
        assert_eq!(check_or02(&checked), Err(OperationalRefusal::OwnerReferences { resource, object: expected.to_string() }), "{resource}");
    }
    // Absent, null and empty pass; any other value refuses (a malformed list too).
    for extra in ["", r#", "ownerReferences": null"#, r#", "ownerReferences": []"#] {
        let checked = inputs(all_empty_except(vec![served(Resource::Roles, &object(Resource::Roles, "r", extra))]));
        assert_eq!(check_or02(&checked), Ok(()), "{extra}");
    }
    for extra in [r#", "ownerReferences": {}"#, r#", "ownerReferences": "x""#, r#", "ownerReferences": [null]"#] {
        let checked = inputs(all_empty_except(vec![served(Resource::Roles, &object(Resource::Roles, "r", extra))]));
        assert!(matches!(check_or02(&checked), Err(OperationalRefusal::OwnerReferences { .. })), "{extra}");
    }
    // Objects of other resources are outside OR02 (the Secret lists are not policy kinds).
    let secret = r#"[{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": {"name": "s", "namespace": "n", "ownerReferences": [{}]}}]"#;
    let checked = inputs(all_empty_except(vec![served(Resource::BootstrapTokenSecrets, secret)]));
    assert_eq!(check_or02(&checked), Ok(()));
}

#[test]
fn or02_needs_every_policy_kind_s_pair() {
    for missing in policy_kinds().expect("table") {
        let pairs: Vec<ListInput> = all_empty_except(vec![]).into_iter()
            .filter(|input| Resource::of_spec(&input.spec) != Some(missing)).collect();
        let checked = Inputs::new(pairs).expect("checked");
        assert_eq!(check_or02(&checked), Err(OperationalRefusal::Input(InputError::Missing(missing))), "{missing}");
    }
}

#[test]
fn or05_reads_two_metadata_only_lists_with_the_exact_selectors() {
    assert_eq!(OR05_LISTS.map(|resource| resource.spec().field_selector.expect("a selector")),
               ["type=kubernetes.io/service-account-token".to_string(), "type=bootstrap.kubernetes.io/token".to_string()]);
    for resource in OR05_LISTS {
        assert_eq!(resource.list_kind(), ("PartialObjectMetadataList".to_string(), "meta.k8s.io/v1".to_string()));
        let token = r#"[{"kind": "PartialObjectMetadata", "apiVersion": "meta.k8s.io/v1", "metadata": {"name": "default-token-x", "namespace": "kube-system"}}]"#;
        let checked = inputs(all_empty_except(vec![served(resource, token)]));
        assert_eq!(check_or05(&checked), Err(OperationalRefusal::TokenSecret { resource, object: "kube-system/default-token-x".to_string() }));
        // A missing list refuses, never an empty default.
        let pairs: Vec<ListInput> = all_empty_except(vec![]).into_iter()
            .filter(|input| Resource::of_spec(&input.spec) != Some(resource)).collect();
        assert_eq!(check_or05(&Inputs::new(pairs).expect("checked")), Err(OperationalRefusal::Input(InputError::Missing(resource))));
        // Full Secret objects (data included) are not the metadata-only answer.
        let full = ListInput { spec: resource.spec(),
                               body: ListBody::Served(b1_support::parse(r#"{"kind": "SecretList", "apiVersion": "v1", "items": []}"#)) };
        assert_eq!(Inputs::new(vec![full]).expect_err("refused"), InputError::ListKind(resource));
    }
}

#[test]
fn or06_needs_each_kind_empty_or_for_the_two_policy_kinds_not_served() {
    assert_eq!(OR06_KINDS, [Resource::ValidatingWebhookConfigurations, Resource::MutatingWebhookConfigurations,
                            Resource::MutatingAdmissionPolicies, Resource::MutatingAdmissionPolicyBindings]);
    for resource in OR06_KINDS {
        let checked = inputs(all_empty_except(vec![served(resource, &object(resource, "hook", ""))]));
        assert_eq!(check_or06(&checked), Err(OperationalRefusal::AdmissionObject { resource, object: "hook".to_string() }), "{resource}");
        let pairs: Vec<ListInput> = all_empty_except(vec![]).into_iter()
            .filter(|input| Resource::of_spec(&input.spec) != Some(resource)).collect();
        assert_eq!(check_or06(&Inputs::new(pairs).expect("checked")), Err(OperationalRefusal::Input(InputError::Missing(resource))));
    }
    let not_served = inputs(all_empty_except(vec![unserved(Resource::MutatingAdmissionPolicies),
                                                  unserved(Resource::MutatingAdmissionPolicyBindings)]));
    assert_eq!(check_or06(&not_served), Ok(()));
    // The two webhook kinds cannot be attested as not served (D3-1): the inputs refuse the marker.
    for resource in [Resource::ValidatingWebhookConfigurations, Resource::MutatingWebhookConfigurations] {
        assert_eq!(Inputs::new(all_empty_except(vec![unserved(resource)])).expect_err("refused"), InputError::NotServedRefused(resource));
    }
}

#[test]
fn or02_and_or06_read_the_same_not_served_input() {
    // Not served: both pass, OR02 finding no object of the kind.
    let both = inputs(all_empty_except(vec![unserved(Resource::MutatingAdmissionPolicies),
                                            unserved(Resource::MutatingAdmissionPolicyBindings)]));
    assert_eq!((check_or02(&both), check_or06(&both)), (Ok(()), Ok(())));
    // Served with an owned object: OR06 refuses the object and OR02 its owner reference, from the one pair.
    let owned = object(Resource::MutatingAdmissionPolicies, "p", r#", "ownerReferences": [{"name": "x"}]"#);
    let checked = inputs(all_empty_except(vec![served(Resource::MutatingAdmissionPolicies, &owned),
                                               unserved(Resource::MutatingAdmissionPolicyBindings)]));
    assert!(matches!(check_or06(&checked), Err(OperationalRefusal::AdmissionObject { resource: Resource::MutatingAdmissionPolicies, .. })));
    assert!(matches!(check_or02(&checked), Err(OperationalRefusal::OwnerReferences { resource: Resource::MutatingAdmissionPolicies, .. })));
    // A kind cannot be both served and not served: a second pair refuses.
    assert_eq!(Inputs::new(vec![unserved(Resource::MutatingAdmissionPolicies), served(Resource::MutatingAdmissionPolicies, "[]")])
                   .expect_err("refused"), InputError::DuplicatePair(Resource::MutatingAdmissionPolicies));
}

#[test]
fn each_refusal_names_its_rule() {
    let texts = [
        OperationalRefusal::OwnerReferences { resource: Resource::Roles, object: "n/r".to_string() }.to_string(),
        OperationalRefusal::TokenSecret { resource: Resource::BootstrapTokenSecrets, object: "kube-system/t".to_string() }.to_string(),
        OperationalRefusal::AdmissionObject { resource: Resource::MutatingWebhookConfigurations, object: "w".to_string() }.to_string(),
        OperationalRefusal::PolicyKinds("is not the registered file").to_string(),
    ];
    assert_eq!(texts, [
        "OR02 rbac.authorization.k8s.io/v1 roles object n/r carries ownerReferences",
        "OR05 core/v1 secrets (type=bootstrap.kubernetes.io/token) lists kube-system/t",
        "OR06 admissionregistration.k8s.io/v1 mutatingwebhookconfigurations object w exists",
        "OR02 the policy-kind table is not the registered file",
    ]);
}
