//! RBAC object builders for HE-004B1's producer tests: list inputs holding ClusterRoles, Roles, bindings and service
//! accounts in the apiserver's shape.
#![allow(dead_code)]

use i05_protocol::json::Value;
use planeon_observer::inputs::{Inputs, ListBody, ListInput, Resource};

use crate::b1_support::{list_value, parse};

pub const QUALIFICATION: &str = "unit-namespace";

pub fn rule(groups: &str, resources: &str, verbs: &str) -> String {
    format!(r#"{{"apiGroups": {groups}, "resources": {resources}, "verbs": {verbs}}}"#)
}

pub fn non_resource(urls: &str, verbs: &str) -> String {
    format!(r#"{{"nonResourceURLs": {urls}, "verbs": {verbs}}}"#)
}

pub fn cluster_role(name: &str, rules: &[String]) -> String {
    format!(r#"{{"metadata": {{"name": "{name}"}}, "rules": [{}]}}"#, rules.join(", "))
}

pub fn aggregated_role(name: &str, aggregation: &str) -> String {
    format!(r#"{{"metadata": {{"name": "{name}"}}, "aggregationRule": {aggregation}, "rules": []}}"#)
}

pub fn role(namespace: &str, name: &str, rules: &[String]) -> String {
    format!(r#"{{"metadata": {{"name": "{name}", "namespace": "{namespace}"}}, "rules": [{}]}}"#, rules.join(", "))
}

pub fn user(name: &str) -> String {
    format!(r#"{{"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "{name}"}}"#)
}

pub fn group(name: &str) -> String {
    format!(r#"{{"kind": "Group", "apiGroup": "rbac.authorization.k8s.io", "name": "{name}"}}"#)
}

pub fn account(namespace: Option<&str>, name: &str) -> String {
    match namespace {
        Some(namespace) => format!(r#"{{"kind": "ServiceAccount", "name": "{name}", "namespace": "{namespace}"}}"#),
        None => format!(r#"{{"kind": "ServiceAccount", "name": "{name}"}}"#),
    }
}

pub fn cluster_binding(name: &str, role: &str, subjects: &[String]) -> String {
    format!(r#"{{"metadata": {{"name": "{name}"}}, "roleRef": {{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "{role}"}}, "subjects": [{}]}}"#,
            subjects.join(", "))
}

pub fn role_binding(namespace: &str, name: &str, kind: &str, role: &str, subjects: &[String]) -> String {
    format!(r#"{{"metadata": {{"name": "{name}", "namespace": "{namespace}"}}, "roleRef": {{"apiGroup": "rbac.authorization.k8s.io", "kind": "{kind}", "name": "{role}"}}, "subjects": [{}]}}"#,
            subjects.join(", "))
}

pub fn service_account(namespace: &str, name: &str) -> String {
    format!(r#"{{"metadata": {{"name": "{name}", "namespace": "{namespace}"}}}}"#)
}

/// The five RBAC lists (each a JSON array text built from the items).
#[derive(Default, Clone)]
pub struct Rbac {
    pub cluster_roles: Vec<String>,
    pub cluster_bindings: Vec<String>,
    pub roles: Vec<String>,
    pub role_bindings: Vec<String>,
    pub accounts: Vec<String>,
}

impl Rbac {
    pub fn pairs(&self) -> Vec<ListInput> {
        let list = |resource: Resource, items: &[String]| ListInput {
            spec: resource.spec(),
            body: ListBody::Served(list_value(resource, &format!("[{}]", items.join(", ")))),
        };
        vec![list(Resource::ClusterRoles, &self.cluster_roles), list(Resource::ClusterRoleBindings, &self.cluster_bindings),
             list(Resource::Roles, &self.roles), list(Resource::RoleBindings, &self.role_bindings),
             list(Resource::ServiceAccounts, &self.accounts)]
    }

    pub fn inputs(&self) -> Inputs {
        Inputs::new(self.pairs()).expect("complete RBAC lists")
    }
}

/// The produced snapshot's subjects as (kind, name, exists, rules).
pub fn snapshot_subjects(snapshot: &Value) -> Vec<(String, String, bool, Vec<Value>)> {
    crate::b1_support::rows(snapshot, "subjects")
        .iter()
        .map(|subject| {
            (crate::b1_support::text(subject, "kind").to_string(), crate::b1_support::text(subject, "name").to_string(),
             crate::b1_support::field(subject, "exists").as_bool().expect("bool"),
             crate::b1_support::rows(subject, "effectiveRules").to_vec())
        })
        .collect()
}

/// A snapshot rule value as JSON text with sorted keys (for comparisons).
pub fn canonical(value: &Value) -> String {
    String::from_utf8(i05_protocol::json::canonical(value).expect("canonical")).expect("UTF-8")
}

pub fn snapshot_rule(groups: &[&str], resources: &[&str], verbs: &[&str], names: &[&str], scope: &str) -> String {
    let list = |items: &[&str]| format!("[{}]", items.iter().map(|item| format!("\"{item}\"")).collect::<Vec<_>>().join(","));
    canonical(&parse(&format!(r#"{{"apiGroups": {}, "resources": {}, "verbs": {}, "resourceNames": {}, "scope": "{scope}"}}"#,
                              list(groups), list(resources), list(verbs), list(names))))
}
