//! The I07 closed policy-kind table (`contracts/i07-v3/policy-kinds.json`, `planeon.internal.i07-policy-kinds/v2`) and
//! the pure functions the PolicyGate applies with it (HE-002B): which table row a requested resource falls into, the
//! WRITE_OBJECT table checks, the one Kubernetes request a write may produce, that request's digest, and whether a
//! delivered status settles a write (I07 v1 Decisions 3-5, v2 R5, v3 W4). Nothing here holds state. Points the
//! READMEs leave open are listed as N-items in MODEL_DEFINED.md.

use i05_protocol::json::{self, Doc, Object, Value};
use i05_protocol::sha256;

/// The table version this module reads.
pub const KINDS_VERSION: &str = "planeon.internal.i07-policy-kinds/v2";

/// A WRITE_OBJECT operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WriteOperation {
    Create,
    Update,
    Delete,
}

impl WriteOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteOperation::Create => "CREATE",
            WriteOperation::Update => "UPDATE",
            WriteOperation::Delete => "DELETE",
        }
    }

    pub fn parse(text: &str) -> Option<WriteOperation> {
        match text {
            "CREATE" => Some(WriteOperation::Create),
            "UPDATE" => Some(WriteOperation::Update),
            "DELETE" => Some(WriteOperation::Delete),
            _ => None,
        }
    }

    /// The statuses that report the write as done (I07 v1 Decision 5): 201 for CREATE, 200 or 201 for UPDATE, 200 or
    /// 202 for DELETE.
    pub fn is_success(self, status: i64) -> bool {
        match self {
            WriteOperation::Create => status == 201,
            WriteOperation::Update => matches!(status, 200 | 201),
            WriteOperation::Delete => matches!(status, 200 | 202),
        }
    }
}

/// Where a writable kind may be written (I07 v3 W4: there is no cluster scope).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Objects inside the qualification namespace.
    QualificationNamespace,
    /// Only the qualification namespace's own Namespace object.
    QualificationNamespaceObject,
}

/// What the table says about a policy kind the writer may not touch.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Disposition {
    RebootMaintenanceOnly,
    MustStayAbsent,
    /// Admission policies and bindings: W02f keeps them out of the API altogether (ADMISSION_OBJECT_SEALED).
    SealedStaticManifest,
}

/// One writable row of the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WritableKind {
    pub group: String,
    pub version: String,
    pub resource: String,
    pub kind: String,
    pub scope: Scope,
    pub operations: Vec<WriteOperation>,
    /// The object members allowed besides apiVersion, kind and metadata.
    pub top_level_keys: Vec<String>,
}

impl WritableKind {
    /// `v1` for the core group, `<group>/<version>` otherwise.
    pub fn api_version(&self) -> String {
        if self.group.is_empty() { self.version.clone() } else { format!("{}/{}", self.group, self.version) }
    }
}

/// A row of the table matched by group and resource only (an effect kind or a non-writable policy kind).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupResource {
    pub group: String,
    pub resource: String,
}

/// A non-writable policy kind and its disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotWritableKind {
    pub group: String,
    pub resource: String,
    pub disposition: Disposition,
}

/// The parsed closed policy-kind table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyKinds {
    pub writable: Vec<WritableKind>,
    pub effect: Vec<GroupResource>,
    pub not_writable: Vec<NotWritableKind>,
}

/// A table that could not be read into the closed types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindsError(pub String);

fn kinds_error<T>(message: &str) -> Result<T, KindsError> {
    Err(KindsError(message.to_string()))
}

fn row_text(row: &Object, key: &str) -> Result<String, KindsError> {
    match row.get(key).and_then(Value::as_str) {
        Some(text) => Ok(text.to_string()),
        None => kinds_error(&format!("a table row's {key} is missing or not text")),
    }
}

fn row_list<'a>(row: &'a Object, key: &str) -> Result<Vec<&'a str>, KindsError> {
    let Some(items) = row.get(key).and_then(Value::as_array) else {
        return kinds_error(&format!("a table row's {key} is not a list"));
    };
    items.iter().map(|item| item.as_str().map_or_else(|| kinds_error(&format!("{key} holds a value that is not text")), Ok))
         .collect()
}

fn table_rows<'a>(root: &'a Object, key: &str) -> Result<Vec<&'a Object>, KindsError> {
    let Some(items) = root.get(key).and_then(Value::as_array) else {
        return kinds_error(&format!("the table's {key} is not a list"));
    };
    items.iter().map(|item| item.as_object().map_or_else(|| kinds_error(&format!("a {key} row is not an object")), Ok))
         .collect()
}

impl PolicyKinds {
    /// Reads the table. Members the gate does not use (the closure provenance, `unusedVerbs`, the RBAC side grants)
    /// are ignored; a wrong version, a missing or mistyped member, an unknown scope (including the retired CLUSTER
    /// scope), operation or disposition refuses the table.
    pub fn from_value(document: &Value) -> Result<PolicyKinds, KindsError> {
        let Some(root) = document.as_object() else { return kinds_error("the table is not an object") };
        if root.get("schemaVersion").and_then(Value::as_str) != Some(KINDS_VERSION) {
            return kinds_error("the table is not planeon.internal.i07-policy-kinds/v2");
        }
        let mut writable = Vec::new();
        for row in table_rows(root, "writable")? {
            let scope = match row_text(row, "scope")?.as_str() {
                "QUALIFICATION_NAMESPACE" => Scope::QualificationNamespace,
                "QUALIFICATION_NAMESPACE_OBJECT" => Scope::QualificationNamespaceObject,
                _ => return kinds_error("a writable row has a scope outside the closed set"),
            };
            let operations = row_list(row, "operations")?
                .into_iter()
                .map(|name| WriteOperation::parse(name).map_or_else(|| kinds_error("a writable row names an unknown operation"), Ok))
                .collect::<Result<Vec<_>, _>>()?;
            writable.push(WritableKind {
                group: row_text(row, "group")?,
                version: row_text(row, "version")?,
                resource: row_text(row, "resource")?,
                kind: row_text(row, "kind")?,
                scope,
                operations,
                top_level_keys: row_list(row, "topLevelKeys")?.into_iter().map(str::to_string).collect(),
            });
        }
        let mut effect = Vec::new();
        for row in table_rows(root, "effectKinds")? {
            effect.push(GroupResource { group: row_text(row, "group")?, resource: row_text(row, "resource")? });
        }
        let mut not_writable = Vec::new();
        for row in table_rows(root, "notWritable")? {
            let disposition = match row_text(row, "disposition")?.as_str() {
                "REBOOT_MAINTENANCE_ONLY" => Disposition::RebootMaintenanceOnly,
                "MUST_STAY_ABSENT" => Disposition::MustStayAbsent,
                "SEALED_STATIC_MANIFEST" => Disposition::SealedStaticManifest,
                _ => return kinds_error("a notWritable row has an unknown disposition"),
            };
            not_writable.push(NotWritableKind { group: row_text(row, "group")?, resource: row_text(row, "resource")?, disposition });
        }
        Ok(PolicyKinds { writable, effect, not_writable })
    }
}

/// Why a WRITE_OBJECT request is outside the table (the I07 refusal reasons the table decides).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WriteRefusal {
    EffectKind,
    PolicyKindNotWritable,
    AdmissionObjectSealed,
    KindOutsideTable,
    VerbNotAllowed,
    ScopeMismatch,
    PriorRule,
    ObjectRule,
}

impl WriteRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            WriteRefusal::EffectKind => "EFFECT_KIND",
            WriteRefusal::PolicyKindNotWritable => "POLICY_KIND_NOT_WRITABLE",
            WriteRefusal::AdmissionObjectSealed => "ADMISSION_OBJECT_SEALED",
            WriteRefusal::KindOutsideTable => "KIND_OUTSIDE_TABLE",
            WriteRefusal::VerbNotAllowed => "VERB_NOT_ALLOWED",
            WriteRefusal::ScopeMismatch => "SCOPE_MISMATCH",
            WriteRefusal::PriorRule => "PRIOR_RULE",
            WriteRefusal::ObjectRule => "OBJECT_RULE",
        }
    }
}

/// The requested resource: API group (empty for the core group), version and plural resource name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRef {
    pub group: String,
    pub version: String,
    pub resource: String,
}

/// The prior object an UPDATE or DELETE names: its uid and resourceVersion (sent as preconditions) and the observer
/// projection the writer acted on (journalled only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prior {
    pub uid: String,
    pub resource_version: String,
    pub projection_digest: String,
}

impl Prior {
    pub fn to_doc(&self) -> Doc {
        Doc::object(vec![
            ("projectionDigest", Doc::str(&self.projection_digest)),
            ("resourceVersion", Doc::str(&self.resource_version)),
            ("uid", Doc::str(&self.uid)),
        ])
    }
}

/// A WRITE_OBJECT request payload with typed members; the object itself stays a JSON value.
#[derive(Clone, Debug)]
pub struct WriteRequest {
    pub write_id: u16,
    pub operation: WriteOperation,
    pub resource: ResourceRef,
    pub namespace: Option<String>,
    pub name: String,
    pub object: Option<Value>,
    pub prior: Option<Prior>,
}

fn member_text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

impl WriteRequest {
    /// Types a WRITE_OBJECT payload. Every payload the I07 v3 schema accepts has this shape; anything else is `None`.
    pub fn from_payload(payload: &Value) -> Option<WriteRequest> {
        let resource = payload.get("resource")?;
        let prior = match payload.get("prior")? {
            Value::Null => None,
            prior => Some(Prior {
                uid: member_text(prior, "uid")?,
                resource_version: member_text(prior, "resourceVersion")?,
                projection_digest: member_text(prior, "projectionDigest")?,
            }),
        };
        Some(WriteRequest {
            write_id: payload.get("writeId")?.as_int()?.to_u64().and_then(|id| u16::try_from(id).ok())?,
            operation: WriteOperation::parse(payload.get("operation")?.as_str()?)?,
            resource: ResourceRef {
                group: member_text(resource, "group")?,
                version: member_text(resource, "version")?,
                resource: member_text(resource, "resource")?,
            },
            namespace: match payload.get("namespace")? {
                Value::Null => None,
                namespace => Some(namespace.as_str()?.to_string()),
            },
            name: member_text(payload, "name")?,
            object: match payload.get("object")? {
                Value::Null => None,
                object @ Value::Object(_) => Some(object.clone()),
                _ => return None,
            },
            prior,
        })
    }
}

/// The table row for a resource, or the refusal. A writable row needs group, version and resource to agree; effect
/// kinds and non-writable kinds are recognised by group and resource whatever the version, and the first matching
/// non-writable row's disposition picks between ADMISSION_OBJECT_SEALED and POLICY_KIND_NOT_WRITABLE (N1).
pub fn classify<'a>(kinds: &'a PolicyKinds, resource: &ResourceRef) -> Result<&'a WritableKind, WriteRefusal> {
    if let Some(row) = kinds.writable.iter().find(|row| {
        row.group == resource.group && row.version == resource.version && row.resource == resource.resource
    }) {
        return Ok(row);
    }
    let same = |group: &str, name: &str| group == resource.group && name == resource.resource;
    if kinds.effect.iter().any(|row| same(&row.group, &row.resource)) {
        return Err(WriteRefusal::EffectKind);
    }
    match kinds.not_writable.iter().find(|row| same(&row.group, &row.resource)) {
        Some(row) if row.disposition == Disposition::SealedStaticManifest => Err(WriteRefusal::AdmissionObjectSealed),
        Some(_) => Err(WriteRefusal::PolicyKindNotWritable),
        None => Err(WriteRefusal::KindOutsideTable),
    }
}

/// The metadata members a written object may carry.
const METADATA_MEMBERS: [&str; 6] = ["annotations", "labels", "name", "namespace", "resourceVersion", "uid"];

fn is_text(value: Option<&Value>, expected: &str) -> bool {
    value.and_then(Value::as_str) == Some(expected)
}

/// An object whose every member value is a string (labels and annotations).
fn is_string_map(value: &Value) -> bool {
    value.as_object().is_some_and(|map| map.iter().all(|(_, member)| matches!(member, Value::Str(_))))
}

/// The OBJECT_RULE checks on a CREATE or UPDATE object (N2).
fn object_fits(row: &WritableKind, namespace: &str, request: &WriteRequest, object: &Value) -> bool {
    let Some(members) = object.as_object() else { return false };
    let own = |name: &str| ["apiVersion", "kind", "metadata"].contains(&name) || row.top_level_keys.iter().any(|key| key == name);
    if !members.iter().all(|(key, _)| key.as_str().is_some_and(own)) {
        return false;
    }
    if !is_text(members.get("apiVersion"), &row.api_version()) || !is_text(members.get("kind"), &row.kind) {
        return false;
    }
    let Some(metadata) = members.get("metadata").and_then(Value::as_object) else { return false };
    if !metadata.iter().all(|(key, _)| key.as_str().is_some_and(|name| METADATA_MEMBERS.contains(&name))) {
        return false;
    }
    if !is_text(metadata.get("name"), &request.name) {
        return false;
    }
    let namespace_ok = match row.scope {
        Scope::QualificationNamespace => is_text(metadata.get("namespace"), namespace),
        // The Namespace object is cluster-scoped: its metadata carries no namespace member at all.
        Scope::QualificationNamespaceObject => metadata.get("namespace").is_none(),
    };
    if !namespace_ok {
        return false;
    }
    if ["labels", "annotations"].iter().any(|key| metadata.get(key).is_some_and(|map| !is_string_map(map))) {
        return false;
    }
    match (request.operation, &request.prior) {
        (WriteOperation::Create, _) => metadata.get("uid").is_none() && metadata.get("resourceVersion").is_none(),
        // An UPDATE repeats the prior object's identity in its own metadata.
        (_, Some(prior)) => {
            is_text(metadata.get("uid"), &prior.uid) && is_text(metadata.get("resourceVersion"), &prior.resource_version)
        }
        (_, None) => false,
    }
}

/// The table checks for one WRITE_OBJECT request, in the order of I07 v1 Decision 3 after the maintenance and write
/// ID checks: the kind, the operation, the scope, the prior rule and the object rule (N2). On success, the row the
/// write renders with.
pub fn check_write<'a>(kinds: &'a PolicyKinds, namespace: &str, request: &WriteRequest)
                       -> Result<&'a WritableKind, WriteRefusal> {
    let row = classify(kinds, &request.resource)?;
    if !row.operations.contains(&request.operation) {
        return Err(WriteRefusal::VerbNotAllowed);
    }
    let in_scope = match row.scope {
        Scope::QualificationNamespace => request.namespace.as_deref() == Some(namespace),
        Scope::QualificationNamespaceObject => request.namespace.is_none() && request.name == namespace,
    };
    if !in_scope {
        return Err(WriteRefusal::ScopeMismatch);
    }
    // CREATE expects no object to exist yet; UPDATE and DELETE name the one they replace or remove.
    if (request.operation == WriteOperation::Create) != request.prior.is_none() {
        return Err(WriteRefusal::PriorRule);
    }
    if (request.operation == WriteOperation::Delete) != request.object.is_none() {
        return Err(WriteRefusal::ObjectRule);
    }
    match &request.object {
        None => Ok(row),
        Some(object) if object_fits(row, namespace, request, object) => Ok(row),
        Some(_) => Err(WriteRefusal::ObjectRule),
    }
}

/// The request a write permits: the exact head bytes, the body and its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedWrite {
    pub head: String,
    pub body: Vec<u8>,
    pub body_digest: String,
}

/// Renders the one request a checked write permits (I07 v1 Decision 4, N3): POST of the canonical object to the
/// collection for CREATE, PUT of it to the item for UPDATE, DELETE of the item with canonical DeleteOptions holding the
/// prior uid and resourceVersion as preconditions; always `Host`, `Accept`, `Content-Type` and `Content-Length`.
/// `None` when the request lacks what its operation renders (a write `check_write` passed always has it) or the object
/// has no canonical encoding (impossible for a schema-valid object).
pub fn render_write(row: &WritableKind, request: &WriteRequest, namespace: &str, authority: &str) -> Option<RenderedWrite> {
    let root = if row.group.is_empty() { format!("/api/{}", row.version) } else { format!("/apis/{}/{}", row.group, row.version) };
    let collection = match row.scope {
        Scope::QualificationNamespace => format!("{root}/namespaces/{namespace}/{}", row.resource),
        Scope::QualificationNamespaceObject => format!("{root}/{}", row.resource),
    };
    let item = format!("{collection}/{}", request.name);
    let (method, target, body) = match request.operation {
        WriteOperation::Create => ("POST", collection, json::canonical(request.object.as_ref()?).ok()?),
        WriteOperation::Update => ("PUT", item, json::canonical(request.object.as_ref()?).ok()?),
        WriteOperation::Delete => {
            let prior = request.prior.as_ref()?;
            let options = Doc::object(vec![
                ("apiVersion", Doc::str("v1")),
                ("kind", Doc::str("DeleteOptions")),
                ("preconditions", Doc::object(vec![
                    ("resourceVersion", Doc::str(&prior.resource_version)),
                    ("uid", Doc::str(&prior.uid)),
                ])),
            ]);
            ("DELETE", item, options.canonical())
        }
    };
    let length = body.len();
    let head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {authority}\r\n\
         Accept: application/json\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n"
    );
    let body_digest = sha256::prefixed(&body);
    Some(RenderedWrite { head, body, body_digest })
}

/// The write's `requestDigest` (I07 v2 R5): the digest of the canonical `{"bodyDigest", "head"}` object.
pub fn request_digest(rendered: &RenderedWrite) -> String {
    let pair = Doc::object(vec![("bodyDigest", Doc::str(&rendered.body_digest)), ("head", Doc::str(&rendered.head))]);
    sha256::prefixed(&pair.canonical())
}

/// I07 v1 Decision 5: a delivered response settles a write when it is one of the operation's success statuses or a
/// rejection (a 4xx other than 408). Every other status leaves the outcome unknown (IO_AMBIGUOUS).
pub fn write_outcome_is_final(operation: WriteOperation, status: i64) -> bool {
    operation.is_success(status) || ((400..=499).contains(&status) && status != 408)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: &str = include_str!("../../../contracts/i07-v3/policy-kinds.json");

    fn kinds() -> PolicyKinds {
        let parsed = json::parse(KINDS).map_err(|error| format!("{error:?}")).and_then(|value| {
            PolicyKinds::from_value(&value).map_err(|error| error.0)
        });
        match parsed {
            Ok(kinds) => kinds,
            Err(error) => panic!("the contract table parses: {error}"),
        }
    }

    fn resource(group: &str, version: &str, name: &str) -> ResourceRef {
        ResourceRef { group: group.into(), version: version.into(), resource: name.into() }
    }

    #[test]
    fn the_contract_table_has_seven_writable_rows_and_no_cluster_scope() {
        let table = kinds();
        assert_eq!(table.writable.len(), 7);
        assert_eq!(table.effect.len(), 3);
        assert_eq!(table.not_writable.len(), 11);
        let namespace = table.writable.iter().find(|row| row.kind == "Namespace").map(|row| (row.scope, row.operations.clone()));
        assert_eq!(namespace, Some((Scope::QualificationNamespaceObject, vec![WriteOperation::Update])));
    }

    #[test]
    fn classification_by_version_and_by_group() {
        let table = kinds();
        assert!(classify(&table, &resource("rbac.authorization.k8s.io", "v1", "roles")).is_ok());
        assert_eq!(classify(&table, &resource("rbac.authorization.k8s.io", "v1beta1", "roles")).err(),
                   Some(WriteRefusal::KindOutsideTable));
        assert_eq!(classify(&table, &resource("", "v2", "pods")).err(), Some(WriteRefusal::EffectKind));
        assert_eq!(classify(&table, &resource("admissionregistration.k8s.io", "v1alpha1", "validatingadmissionpolicies")).err(),
                   Some(WriteRefusal::AdmissionObjectSealed));
        assert_eq!(classify(&table, &resource("admissionregistration.k8s.io", "v1", "mutatingadmissionpolicies")).err(),
                   Some(WriteRefusal::PolicyKindNotWritable));
    }

    #[test]
    fn a_table_with_a_cluster_scope_or_another_version_is_refused() {
        let cluster = KINDS.replacen("\"QUALIFICATION_NAMESPACE_OBJECT\"", "\"CLUSTER\"", 1);
        let refused = json::parse(&cluster).ok().map(|value| PolicyKinds::from_value(&value).is_err());
        assert_eq!(refused, Some(true));
        let other = KINDS.replacen("i07-policy-kinds/v2", "i07-policy-kinds/v1", 1);
        let refused = json::parse(&other).ok().map(|value| PolicyKinds::from_value(&value).is_err());
        assert_eq!(refused, Some(true));
    }

    #[test]
    fn finality_by_operation() {
        assert!(write_outcome_is_final(WriteOperation::Create, 201));
        assert!(!write_outcome_is_final(WriteOperation::Create, 200));
        assert!(write_outcome_is_final(WriteOperation::Update, 200) && write_outcome_is_final(WriteOperation::Update, 201));
        assert!(write_outcome_is_final(WriteOperation::Delete, 202) && write_outcome_is_final(WriteOperation::Delete, 404));
        assert!(!write_outcome_is_final(WriteOperation::Delete, 408) && !write_outcome_is_final(WriteOperation::Update, 204));
        assert!(!write_outcome_is_final(WriteOperation::Create, i64::MIN));
        assert!(!write_outcome_is_final(WriteOperation::Create, i64::MAX));
    }

    #[test]
    fn a_delete_without_a_prior_renders_nothing() {
        let table = kinds();
        let Some(row) = table.writable.first() else { panic!("a writable row") };
        let request = WriteRequest {
            write_id: 1,
            operation: WriteOperation::Delete,
            resource: resource(&row.group, &row.version, &row.resource),
            namespace: Some("planeon-qual".into()),
            name: "x".into(),
            object: None,
            prior: None,
        };
        assert_eq!(render_write(row, &request, "planeon-qual", "127.0.0.1:6443"), None);
        assert_eq!(check_write(&table, "planeon-qual", &request).err(), Some(WriteRefusal::PriorRule));
    }
}
