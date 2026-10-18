//! The observer-checked operational rules OR02, OR05 and OR06 (HE-004B1 DESIGN-B section 4.4; D1-5, D2-4, D3-1, D3-2).
//! I06 marks every OR row OPERATIONAL, with no model and no vector, so these predicates are R10-defined and tested by
//! R10-local vectors. Each reads the checked inputs (`crate::inputs`), never a default, and each refusal names its rule.
//!
//! - OR02: no object of an I07 v3 policy kind (writable and not writable) carries a non-empty `metadata.ownerReferences`;
//!   the kind set is read from i05-protocol's embedded `policy-kinds.json`, whose bytes are re-checked against the
//!   registered digest first.
//! - OR05: the two metadata-only Secret lists (field selectors for service-account tokens and bootstrap tokens) are
//!   empty. No Secret data or `type` is read.
//! - OR06: ValidatingWebhookConfiguration, MutatingWebhookConfiguration, MutatingAdmissionPolicy and
//!   MutatingAdmissionPolicyBinding are each a complete empty list or, for the last two only, attested as not served;
//!   OR02 reads the same pairs, so the two rules cannot disagree about a kind.

use std::fmt;

use i05_protocol::contracts::I07_V3_POLICY_KINDS;
use i05_protocol::json::{self, Value};
use i05_protocol::sha256;

use crate::contracts::I07_V3_POLICY_KINDS_SHA256;
use crate::inputs::{object_name, object_namespace, InputError, Inputs, Listed, Resource};

/// The four OR06 kinds, in the order the rule names them.
pub const OR06_KINDS: [Resource; 4] = [
    Resource::ValidatingWebhookConfigurations,
    Resource::MutatingWebhookConfigurations,
    Resource::MutatingAdmissionPolicies,
    Resource::MutatingAdmissionPolicyBindings,
];

/// OR05's two metadata-only Secret lists.
pub const OR05_LISTS: [Resource; 2] = [Resource::ServiceAccountTokenSecrets, Resource::BootstrapTokenSecrets];

/// Why an operational rule refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationalRefusal {
    /// The inputs are incomplete or a needed pair is missing.
    Input(InputError),
    /// The embedded policy-kind table is not the registered file, cannot be read, or names a kind outside the closed
    /// request specs.
    PolicyKinds(&'static str),
    /// OR02: a policy-kind object with a non-empty (or non-list) `metadata.ownerReferences`.
    OwnerReferences { resource: Resource, object: String },
    /// OR05: a service-account-token or bootstrap-token Secret exists.
    TokenSecret { resource: Resource, object: String },
    /// OR06: a webhook configuration or mutating admission policy object exists.
    AdmissionObject { resource: Resource, object: String },
}

impl From<InputError> for OperationalRefusal {
    fn from(error: InputError) -> OperationalRefusal {
        OperationalRefusal::Input(error)
    }
}

impl fmt::Display for OperationalRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperationalRefusal::Input(error) => write!(out, "{}", error),
            OperationalRefusal::PolicyKinds(why) => write!(out, "OR02 the policy-kind table {}", why),
            OperationalRefusal::OwnerReferences { resource, object } => {
                write!(out, "OR02 {} object {} carries ownerReferences", resource, object)
            }
            OperationalRefusal::TokenSecret { resource, object } => write!(out, "OR05 {} lists {}", resource, object),
            OperationalRefusal::AdmissionObject { resource, object } => {
                write!(out, "OR06 {} object {} exists", resource, object)
            }
        }
    }
}

/// `<namespace>/<name>` or `<name>`.
fn label(item: &Value) -> String {
    let name = object_name(item).unwrap_or("");
    match object_namespace(item) {
        Some(space) => format!("{}/{}", space, name),
        None => name.to_string(),
    }
}

/// The I07 v3 policy kinds (writable, then not writable, in table order), read from i05-protocol's embedded table after
/// its bytes are re-checked against the registered digest (D3-2).
pub fn policy_kinds() -> Result<Vec<Resource>, OperationalRefusal> {
    if sha256::hex(&sha256::digest(I07_V3_POLICY_KINDS)) != I07_V3_POLICY_KINDS_SHA256 {
        return Err(OperationalRefusal::PolicyKinds("is not the registered file"));
    }
    let table = std::str::from_utf8(I07_V3_POLICY_KINDS)
        .ok()
        .and_then(|text| json::parse(text).ok())
        .ok_or(OperationalRefusal::PolicyKinds("cannot be read"))?;
    let mut kinds = Vec::new();
    for section in ["writable", "notWritable"] {
        let rows = table.get(section).and_then(Value::as_array).ok_or(OperationalRefusal::PolicyKinds("cannot be read"))?;
        for row in rows {
            let group = row.get("group").and_then(Value::as_str);
            let resource = row.get("resource").and_then(Value::as_str);
            let (Some(group), Some(resource)) = (group, resource) else {
                return Err(OperationalRefusal::PolicyKinds("cannot be read"));
            };
            let Some(kind) = Resource::of_policy_kind(group, resource) else {
                return Err(OperationalRefusal::PolicyKinds("names a kind outside the closed request specs"));
            };
            kinds.push(kind);
        }
    }
    Ok(kinds)
}

/// OR02 over every policy kind's pair: no object carries a non-empty `metadata.ownerReferences` (absent, null and an
/// empty list pass; anything else refuses). A NotServed pair (only the two MutatingAdmissionPolicy kinds can have one)
/// holds no object.
pub fn check_or02(inputs: &Inputs) -> Result<(), OperationalRefusal> {
    for resource in policy_kinds()? {
        let Listed::Items(items) = inputs.list(resource)? else {
            continue;
        };
        for item in items {
            let references = item.get("metadata").and_then(|meta| meta.get("ownerReferences"));
            let empty = match references {
                None | Some(Value::Null) => true,
                Some(Value::Array(list)) => list.is_empty(),
                Some(_) => false,
            };
            if !empty {
                return Err(OperationalRefusal::OwnerReferences { resource, object: label(item) });
            }
        }
    }
    Ok(())
}

/// OR05: both metadata-only Secret lists are served and empty.
pub fn check_or05(inputs: &Inputs) -> Result<(), OperationalRefusal> {
    for resource in OR05_LISTS {
        if let Some(item) = inputs.items(resource)?.first() {
            return Err(OperationalRefusal::TokenSecret { resource, object: label(item) });
        }
    }
    Ok(())
}

/// OR06: each of the four kinds is a complete empty list or (MutatingAdmissionPolicy and its binding only) attested as
/// not served; a missing pair refuses.
pub fn check_or06(inputs: &Inputs) -> Result<(), OperationalRefusal> {
    for resource in OR06_KINDS {
        if let Listed::Items(items) = inputs.list(resource)? {
            if let Some(item) = items.first() {
                return Err(OperationalRefusal::AdmissionObject { resource, object: label(item) });
            }
        }
    }
    Ok(())
}
