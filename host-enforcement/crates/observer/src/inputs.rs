//! The observer's list inputs and their completeness (HE-004B1 DESIGN-B section 4.1; D1-1, D2-1, D2-4, D3-1;
//! owner decision Q-HE4B-9 (a)).
//!
//! A Kubernetes list body does not say which request produced it, so a list fetched for one namespace or through a
//! selector looks like a complete one. The observer therefore owns a closed set of request specs, and every list input is
//! a pair: the spec its fetcher states it issued, and the list value (or, for the two MutatingAdmissionPolicy kinds only,
//! the marker that no version of the resource is served). `Inputs::new` refuses every pair a single pair can prove wrong;
//! watch continuity, one consistent resourceVersion across the lists and restart invalidation are the apiserver client's
//! (HE-004C). Pure logic: no input is defaulted to an empty list.

use std::collections::BTreeSet;
use std::fmt;

use i05_protocol::json::{JStr, Value};

/// A request's scope. Only `Cluster` and `AllNamespaces` are in the closed set; `Namespace` exists so that a fetcher's
/// statement of a namespace-scoped request can be refused.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RequestScope {
    Cluster,
    AllNamespaces,
    Namespace(String),
}

/// What a fetcher states it requested for one list: the resource, the scope and the selectors.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestSpec {
    pub group: String,
    pub version: String,
    pub resource: String,
    pub scope: RequestScope,
    pub label_selector: Option<String>,
    pub field_selector: Option<String>,
}

/// The closed set of requests the observer reads (DESIGN-B section 4.1): the eighteen I07 v3 policy kinds (OR02; the
/// RBAC producer's five lists and OR06's four kinds are among them) and OR05's two metadata-only Secret lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resource {
    LimitRanges,
    Namespaces,
    ResourceQuotas,
    ServiceAccounts,
    NetworkPolicies,
    RoleBindings,
    Roles,
    ClusterRoles,
    ClusterRoleBindings,
    ValidatingWebhookConfigurations,
    MutatingWebhookConfigurations,
    MutatingAdmissionPolicies,
    MutatingAdmissionPolicyBindings,
    ApiServices,
    CustomResourceDefinitions,
    CertificateSigningRequests,
    ValidatingAdmissionPolicies,
    ValidatingAdmissionPolicyBindings,
    ServiceAccountTokenSecrets,
    BootstrapTokenSecrets,
}

/// One closed-set entry: the request and the list kind its answer must carry.
struct Row {
    group: &'static str,
    version: &'static str,
    resource: &'static str,
    kind: &'static str,
    namespaced: bool,
    field_selector: Option<&'static str>,
    /// OR05's answers are metadata-only lists, whatever the resource's own kind.
    metadata_only: bool,
    /// DESIGN-B section 4.1 (D3-1): only the two MutatingAdmissionPolicy kinds may be attested as not served.
    may_be_unserved: bool,
}

const fn row(group: &'static str, version: &'static str, resource: &'static str, kind: &'static str, namespaced: bool) -> Row {
    Row { group, version, resource, kind, namespaced, field_selector: None, metadata_only: false, may_be_unserved: false }
}

/// The field selectors of OR05's two lists, exactly (DESIGN-B section 4.4).
pub const SERVICE_ACCOUNT_TOKEN_SELECTOR: &str = "type=kubernetes.io/service-account-token";
pub const BOOTSTRAP_TOKEN_SELECTOR: &str = "type=bootstrap.kubernetes.io/token";
/// The list kind and API version of a metadata-only list.
pub const METADATA_LIST_KIND: &str = "PartialObjectMetadataList";
pub const METADATA_LIST_API_VERSION: &str = "meta.k8s.io/v1";

impl Resource {
    /// Every closed-set entry, in table order.
    pub const ALL: [Resource; 20] = [
        Resource::LimitRanges, Resource::Namespaces, Resource::ResourceQuotas, Resource::ServiceAccounts,
        Resource::NetworkPolicies, Resource::RoleBindings, Resource::Roles, Resource::ClusterRoles,
        Resource::ClusterRoleBindings, Resource::ValidatingWebhookConfigurations, Resource::MutatingWebhookConfigurations,
        Resource::MutatingAdmissionPolicies, Resource::MutatingAdmissionPolicyBindings, Resource::ApiServices,
        Resource::CustomResourceDefinitions, Resource::CertificateSigningRequests, Resource::ValidatingAdmissionPolicies,
        Resource::ValidatingAdmissionPolicyBindings, Resource::ServiceAccountTokenSecrets, Resource::BootstrapTokenSecrets,
    ];

    fn row(self) -> Row {
        const RBAC: &str = "rbac.authorization.k8s.io";
        const ADMISSION: &str = "admissionregistration.k8s.io";
        match self {
            Resource::LimitRanges => row("", "v1", "limitranges", "LimitRange", true),
            Resource::Namespaces => row("", "v1", "namespaces", "Namespace", false),
            Resource::ResourceQuotas => row("", "v1", "resourcequotas", "ResourceQuota", true),
            Resource::ServiceAccounts => row("", "v1", "serviceaccounts", "ServiceAccount", true),
            Resource::NetworkPolicies => row("networking.k8s.io", "v1", "networkpolicies", "NetworkPolicy", true),
            Resource::RoleBindings => row(RBAC, "v1", "rolebindings", "RoleBinding", true),
            Resource::Roles => row(RBAC, "v1", "roles", "Role", true),
            Resource::ClusterRoles => row(RBAC, "v1", "clusterroles", "ClusterRole", false),
            Resource::ClusterRoleBindings => row(RBAC, "v1", "clusterrolebindings", "ClusterRoleBinding", false),
            Resource::ValidatingWebhookConfigurations => {
                row(ADMISSION, "v1", "validatingwebhookconfigurations", "ValidatingWebhookConfiguration", false)
            }
            Resource::MutatingWebhookConfigurations => {
                row(ADMISSION, "v1", "mutatingwebhookconfigurations", "MutatingWebhookConfiguration", false)
            }
            Resource::MutatingAdmissionPolicies => Row {
                may_be_unserved: true,
                ..row(ADMISSION, "v1", "mutatingadmissionpolicies", "MutatingAdmissionPolicy", false)
            },
            Resource::MutatingAdmissionPolicyBindings => Row {
                may_be_unserved: true,
                ..row(ADMISSION, "v1", "mutatingadmissionpolicybindings", "MutatingAdmissionPolicyBinding", false)
            },
            Resource::ApiServices => row("apiregistration.k8s.io", "v1", "apiservices", "APIService", false),
            Resource::CustomResourceDefinitions => {
                row("apiextensions.k8s.io", "v1", "customresourcedefinitions", "CustomResourceDefinition", false)
            }
            Resource::CertificateSigningRequests => {
                row("certificates.k8s.io", "v1", "certificatesigningrequests", "CertificateSigningRequest", false)
            }
            Resource::ValidatingAdmissionPolicies => {
                row(ADMISSION, "v1", "validatingadmissionpolicies", "ValidatingAdmissionPolicy", false)
            }
            Resource::ValidatingAdmissionPolicyBindings => {
                row(ADMISSION, "v1", "validatingadmissionpolicybindings", "ValidatingAdmissionPolicyBinding", false)
            }
            Resource::ServiceAccountTokenSecrets => Row {
                field_selector: Some(SERVICE_ACCOUNT_TOKEN_SELECTOR),
                metadata_only: true,
                ..row("", "v1", "secrets", "Secret", true)
            },
            Resource::BootstrapTokenSecrets => Row {
                field_selector: Some(BOOTSTRAP_TOKEN_SELECTOR),
                metadata_only: true,
                ..row("", "v1", "secrets", "Secret", true)
            },
        }
    }

    /// The request the apiserver client must issue for this entry, exactly (recorded in MODEL_DEFINED).
    pub fn spec(self) -> RequestSpec {
        let row = self.row();
        RequestSpec {
            group: row.group.to_string(),
            version: row.version.to_string(),
            resource: row.resource.to_string(),
            scope: if row.namespaced { RequestScope::AllNamespaces } else { RequestScope::Cluster },
            label_selector: None,
            field_selector: row.field_selector.map(str::to_string),
        }
    }

    /// The API group and resource name (the I07 v3 policy-kind table's `group` and `resource`).
    pub fn group(self) -> &'static str {
        self.row().group
    }

    pub fn resource(self) -> &'static str {
        self.row().resource
    }

    /// The object kind (for OR05's entries, `Secret`, whose answer is nevertheless a metadata-only list).
    pub fn kind(self) -> &'static str {
        self.row().kind
    }

    /// Whether the resource's objects live in namespaces (the request then spans all namespaces).
    pub fn namespaced(self) -> bool {
        self.row().namespaced
    }

    /// Whether the NotServed marker may stand for this entry's list.
    pub fn may_be_unserved(self) -> bool {
        self.row().may_be_unserved
    }

    /// The `kind` and `apiVersion` the answer must carry.
    pub fn list_kind(self) -> (String, String) {
        let row = self.row();
        if row.metadata_only {
            return (METADATA_LIST_KIND.to_string(), METADATA_LIST_API_VERSION.to_string());
        }
        let api_version = if row.group.is_empty() { row.version.to_string() } else { format!("{}/{}", row.group, row.version) };
        (format!("{}List", row.kind), api_version)
    }

    /// The closed-set entry a stated request names, if any.
    pub fn of_spec(spec: &RequestSpec) -> Option<Resource> {
        Resource::ALL.into_iter().find(|resource| resource.spec() == *spec)
    }

    /// The policy-kind entry for an I07 v3 table row's group and resource (OR02), if any.
    pub fn of_policy_kind(group: &str, resource: &str) -> Option<Resource> {
        Resource::ALL
            .into_iter()
            .find(|entry| !entry.row().metadata_only && entry.group() == group && entry.resource() == resource)
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let row = self.row();
        let group = if row.group.is_empty() { "core" } else { row.group };
        match row.field_selector {
            Some(selector) => write!(out, "{}/{} {} ({})", group, row.version, row.resource, selector),
            None => write!(out, "{}/{} {}", group, row.version, row.resource),
        }
    }
}

/// A list input's body: the list value as the apiserver returned it, or the attestation (by discovery over every served
/// version of the resource's group) that no version of the resource is served.
#[derive(Clone, Debug)]
pub enum ListBody {
    Served(Value),
    NotServed,
}

/// One input: the request its fetcher states it issued, and what came back.
#[derive(Clone, Debug)]
pub struct ListInput {
    pub spec: RequestSpec,
    pub body: ListBody,
}

/// Why the inputs are refused (each an R10-defined refusal; no default to an empty list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    /// A pair whose stated request is outside the closed set (another scope, a namespace, a selector, a version).
    OutsideClosedSet(RequestSpec),
    /// Two pairs for one closed-set entry.
    DuplicatePair(Resource),
    /// A NotServed marker for an entry outside the closed NotServed set.
    NotServedRefused(Resource),
    /// A list a function needs has no pair.
    Missing(Resource),
    /// The answer is not a JSON object.
    NotAList(Resource),
    /// The answer's `kind` or `apiVersion` is not the entry's list kind (a list paired with another spec).
    ListKind(Resource),
    /// `metadata` is not an object, or `metadata.continue` is present and not exactly `""`, or
    /// `metadata.remainingItemCount` is present: a paged or malformed answer.
    Paged(Resource),
    /// `items` is not an array.
    Items(Resource),
    /// An item that is not an object with an object `metadata` holding a non-empty `name`.
    ItemShape(Resource, usize),
    /// An item whose namespace does not fit the kind's scope (a namespaced kind's item without a non-empty
    /// `metadata.namespace`, a cluster-scoped kind's item with one).
    ItemScope(Resource, usize),
    /// A second item with the same namespace and name (name for cluster-scoped kinds).
    DuplicateItem(Resource, usize),
}

impl fmt::Display for InputError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::OutsideClosedSet(spec) => {
                write!(out, "input: the request {}/{} {} is outside the closed request specs", spec.group, spec.version,
                       spec.resource)
            }
            InputError::DuplicatePair(resource) => write!(out, "input: two lists answer {}", resource),
            InputError::NotServedRefused(resource) => {
                write!(out, "input: {} may not be attested as not served", resource)
            }
            InputError::Missing(resource) => write!(out, "input: no list answers {}", resource),
            InputError::NotAList(resource) => write!(out, "input: the answer to {} is not an object", resource),
            InputError::ListKind(resource) => write!(out, "input: the answer to {} is not its list kind", resource),
            InputError::Paged(resource) => {
                write!(out, "input: the answer to {} is paged or carries no complete list metadata", resource)
            }
            InputError::Items(resource) => write!(out, "input: the answer to {} has no items array", resource),
            InputError::ItemShape(resource, index) => {
                write!(out, "input: item {} of {} has no object metadata with a name", index, resource)
            }
            InputError::ItemScope(resource, index) => {
                write!(out, "input: item {} of {} does not fit the kind's scope", index, resource)
            }
            InputError::DuplicateItem(resource, index) => {
                write!(out, "input: item {} of {} repeats an earlier item", index, resource)
            }
        }
    }
}

/// A checked list: its items, or the NotServed attestation.
#[derive(Clone, Copy, Debug)]
pub enum Listed<'a> {
    Items(&'a [Value]),
    NotServed,
}

/// The checked inputs: at most one pair per closed-set entry, each complete as far as one pair can prove.
#[derive(Clone, Debug)]
pub struct Inputs {
    pairs: Vec<(Resource, ListBody)>,
}

impl Inputs {
    /// Checks every pair, in order (DESIGN-B section 4.1): the stated request in the closed set, one pair per entry, a
    /// NotServed marker only for the closed NotServed set, and each served answer complete.
    pub fn new(inputs: Vec<ListInput>) -> Result<Inputs, InputError> {
        let mut seen = BTreeSet::new();
        let mut pairs = Vec::with_capacity(inputs.len());
        for input in inputs {
            let Some(resource) = Resource::of_spec(&input.spec) else {
                return Err(InputError::OutsideClosedSet(input.spec));
            };
            if !seen.insert(resource) {
                return Err(InputError::DuplicatePair(resource));
            }
            match &input.body {
                ListBody::NotServed if !resource.may_be_unserved() => return Err(InputError::NotServedRefused(resource)),
                ListBody::NotServed => {}
                ListBody::Served(value) => check_list(resource, value)?,
            }
            pairs.push((resource, input.body));
        }
        Ok(Inputs { pairs })
    }

    /// The checked list for an entry a function needs; a missing pair refuses.
    pub fn list(&self, resource: Resource) -> Result<Listed<'_>, InputError> {
        let Some((_, body)) = self.pairs.iter().find(|(entry, _)| *entry == resource) else {
            return Err(InputError::Missing(resource));
        };
        match body {
            ListBody::NotServed => Ok(Listed::NotServed),
            ListBody::Served(value) => match value.get("items").and_then(Value::as_array) {
                Some(items) => Ok(Listed::Items(items)),
                None => Err(InputError::Items(resource)),
            },
        }
    }

    /// The items of an entry that must be served (the RBAC lists, OR05's lists): NotServed cannot stand for them.
    pub fn items(&self, resource: Resource) -> Result<&[Value], InputError> {
        match self.list(resource)? {
            Listed::Items(items) => Ok(items),
            Listed::NotServed => Err(InputError::NotServedRefused(resource)),
        }
    }
}

/// A string value without a lone surrogate (an apiserver's JSON is UTF-8, so a lone surrogate cannot come from one).
pub fn text(value: &Value) -> Option<&str> {
    value.as_str()
}

/// A string value as Python sees it (lone surrogates allowed).
pub fn jtext(value: &Value) -> Option<&JStr> {
    match value {
        Value::Str(string) => Some(string),
        _ => None,
    }
}

/// An item's `metadata.name` (present and non-empty in every checked list).
pub fn object_name(item: &Value) -> Option<&str> {
    item.get("metadata").and_then(|meta| meta.get("name")).and_then(text).filter(|name| !name.is_empty())
}

/// An item's `metadata.namespace` (present and non-empty for every item of a namespaced kind in a checked list).
pub fn object_namespace(item: &Value) -> Option<&str> {
    item.get("metadata").and_then(|meta| meta.get("namespace")).and_then(text).filter(|space| !space.is_empty())
}

/// One served answer (DESIGN-B section 4.1): an object of the entry's list kind, not paged, with an items array whose
/// items each carry an object `metadata` with a non-empty `name`, a namespace exactly when the kind is namespaced,
/// and no (namespace, name) twice.
fn check_list(resource: Resource, value: &Value) -> Result<(), InputError> {
    if value.as_object().is_none() {
        return Err(InputError::NotAList(resource));
    }
    let (kind, api_version) = resource.list_kind();
    if value.get("kind").and_then(text) != Some(kind.as_str())
        || value.get("apiVersion").and_then(text) != Some(api_version.as_str())
    {
        return Err(InputError::ListKind(resource));
    }
    if let Some(meta) = value.get("metadata") {
        let Some(members) = meta.as_object() else {
            return Err(InputError::Paged(resource));
        };
        if let Some(token) = members.get("continue") {
            if text(token) != Some("") {
                return Err(InputError::Paged(resource));
            }
        }
        if members.get("remainingItemCount").is_some() {
            return Err(InputError::Paged(resource));
        }
    }
    let Some(items) = value.get("items").and_then(Value::as_array) else {
        return Err(InputError::Items(resource));
    };
    let mut keys = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let meta = item.get("metadata").filter(|meta| meta.as_object().is_some());
        let Some(name) = object_name(item).filter(|_| meta.is_some()) else {
            return Err(InputError::ItemShape(resource, index));
        };
        let space = meta.and_then(|meta| meta.get("namespace"));
        let namespace = match (resource.namespaced(), space) {
            (true, Some(present)) => match text(present).filter(|space| !space.is_empty()) {
                Some(namespace) => Some(namespace),
                None => return Err(InputError::ItemScope(resource, index)),
            },
            (true, None) | (false, Some(_)) => return Err(InputError::ItemScope(resource, index)),
            (false, None) => None,
        };
        if !keys.insert((namespace, name)) {
            return Err(InputError::DuplicateItem(resource, index));
        }
    }
    Ok(())
}
