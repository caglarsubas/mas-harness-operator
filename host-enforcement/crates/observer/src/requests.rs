//! The observer's requests (HE-004C DESIGN-C sections 5.1, 6 and 9.5; MODEL_DEFINED R110 and R111) and the small
//! documents they answer.
//!
//! - Pairing by construction: [`list`] builds a target only from `Resource::spec()` (B1's closed set), so the list input
//!   it answers is paired with that same spec. Core `v1` is `/api/v1/<resource>`, a named group
//!   `/apis/<group>/<version>/<resource>`; OR05's two add their field selector, percent-encoded by RFC 3986 (unreserved
//!   characters kept), and ask for metadata-only answers. There is never a label selector, `limit` or `continue` on a
//!   closed-set list (B1 refuses paged answers).
//! - Parameters outside the pairing (transport-level "when", not "which objects"), after the field selector: none for
//!   the fresh list; `resourceVersion=<R>&resourceVersionMatch=Exact` for the other lists; `watch=true&
//!   allowWatchBookmarks=true&resourceVersion=<RV>` for a watch; `limit=1` for the per-spec progress probe (section 9.5,
//!   behind `observe::PER_SPEC_PROGRESS`), which is never paired or fed to B1.
//! - The fixed requests: discovery of `admissionregistration.k8s.io` and its versions, `/version`, the OR07 hook,
//!   `/metrics` and the progress read `GET /api/v1/namespaces?limit=1` (never paired or fed to B1).
//! - The documents: an `APIGroup`'s versions, an `APIResourceList`'s resource names (subresources do not count),
//!   `/version`'s `gitVersion`, a list's `metadata.resourceVersion`, the progress read's mark.

use i05_protocol::json::{self, Value};

use crate::http::{Request, ACCEPT_JSON, ACCEPT_METADATA_LIST, ACCEPT_METADATA_WATCH, ACCEPT_METRICS, ACCEPT_TEXT};
use crate::inputs::{RequestSpec, Resource, METADATA_LIST_KIND};
use crate::watch::decimal;

/// The group whose served versions discovery reads (departure 1, Q-HE4C-10 (a)).
pub const ADMISSION_GROUP: &str = "admissionregistration.k8s.io";
/// The version B1's MutatingAdmissionPolicy specs name.
pub const ADMISSION_VERSION: &str = "v1";
/// OR07's hook (I06 v3's OR07 row).
pub const READYZ: &str = "/readyz/poststarthook/rbac/bootstrap-roles";
/// The exposition.
pub const METRICS: &str = "/metrics";
/// The apiserver's version document.
pub const VERSION: &str = "/version";
/// The progress read (section 9.5).
pub const PROGRESS: &str = "/api/v1/namespaces?limit=1";
/// The kind of a metadata-only watch event's object.
pub const METADATA_KIND: &str = "PartialObjectMetadata";
/// The versions of one `APIGroup` document, at most (R10-defined).
pub const MAX_VERSIONS: usize = 16;

/// The request modes of a closed-set list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The snapshot's first served list: a fresh consistent read.
    Fresh,
    /// Every other list of a snapshot, read exactly at its resourceVersion `R`.
    Exact(String),
    /// A watch from a resourceVersion.
    Watch(String),
    /// The per-spec progress probe (`limit=1`).
    Probe,
}

/// Why a document is refused (status 84).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocError(pub &'static str);

/// Why a resourceVersion-bearing answer is refused: its shape (84) or its resourceVersion (85).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkError {
    Answer(&'static str),
    Consistency(&'static str),
}

/// RFC 3986 percent-encoding: unreserved characters kept, every other byte as `%XX` (upper-case hex).
pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The collection path of a spec: `/api/v1/<resource>` for the core group, `/apis/<group>/<version>/<resource>`
/// otherwise (a closed-set spec spans the cluster or all namespaces, so no namespace segment).
pub fn collection(spec: &RequestSpec) -> String {
    if spec.group.is_empty() {
        format!("/api/{}/{}", spec.version, spec.resource)
    } else {
        format!("/apis/{}/{}/{}", spec.group, spec.version, spec.resource)
    }
}

/// Whether a closed-set entry is answered with metadata-only lists (OR05's two).
pub fn metadata_only(resource: Resource) -> bool {
    resource.list_kind().0 == METADATA_LIST_KIND
}

/// The kind of a watch event's object for `resource`'s stream.
pub fn watch_kind(resource: Resource) -> &'static str {
    if metadata_only(resource) { METADATA_KIND } else { resource.kind() }
}

/// The request for `resource` in `mode`, built only from `resource.spec()`.
pub fn list(resource: Resource, mode: &Mode) -> Request {
    let spec = resource.spec();
    let mut query: Vec<String> = Vec::new();
    if let Some(selector) = &spec.field_selector {
        query.push(format!("fieldSelector={}", percent_encode(selector)));
    }
    match mode {
        Mode::Fresh => {}
        Mode::Exact(version) => {
            query.push(format!("resourceVersion={}", percent_encode(version)));
            query.push("resourceVersionMatch=Exact".to_string());
        }
        Mode::Watch(version) => {
            query.push("watch=true".to_string());
            query.push("allowWatchBookmarks=true".to_string());
            query.push(format!("resourceVersion={}", percent_encode(version)));
        }
        Mode::Probe => query.push("limit=1".to_string()),
    }
    let mut target = collection(&spec);
    if !query.is_empty() {
        target.push('?');
        target.push_str(&query.join("&"));
    }
    let accept = match (metadata_only(resource), mode) {
        (false, _) => ACCEPT_JSON,
        (true, Mode::Watch(_)) => ACCEPT_METADATA_WATCH,
        (true, _) => ACCEPT_METADATA_LIST,
    };
    Request { target, accept }
}

/// `GET /apis/admissionregistration.k8s.io`.
pub fn discovery_group() -> Request {
    Request { target: format!("/apis/{ADMISSION_GROUP}"), accept: ACCEPT_JSON }
}

/// `GET /apis/admissionregistration.k8s.io/<version>`.
pub fn discovery_version(version: &str) -> Request {
    Request { target: format!("/apis/{ADMISSION_GROUP}/{version}"), accept: ACCEPT_JSON }
}

pub fn version() -> Request {
    Request { target: VERSION.to_string(), accept: ACCEPT_JSON }
}

pub fn readyz() -> Request {
    Request { target: READYZ.to_string(), accept: ACCEPT_TEXT }
}

pub fn metrics() -> Request {
    Request { target: METRICS.to_string(), accept: ACCEPT_METRICS }
}

pub fn progress() -> Request {
    Request { target: PROGRESS.to_string(), accept: ACCEPT_JSON }
}

/// A JSON document through i05-protocol's strict parser (duplicate keys refused).
pub fn document(body: &[u8]) -> Result<Value, DocError> {
    let text = std::str::from_utf8(body).map_err(|_| DocError("a document is not UTF-8"))?;
    json::parse(text).map_err(|_| DocError("a document is not strict JSON"))
}

/// A version token: 1 to 63 characters of `[a-z0-9]`.
fn is_version(text: &str) -> bool {
    (1..=63).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// The `APIGroup` document's versions: `versions[].groupVersion` distinct and each `admissionregistration.k8s.io/<v>`;
/// the `<v>` values in document order.
pub fn group_versions(body: &[u8]) -> Result<Vec<String>, DocError> {
    let value = document(body)?;
    if value.get("kind").and_then(Value::as_str) != Some("APIGroup") {
        return Err(DocError("the group document is not an APIGroup"));
    }
    let Some(entries) = value.get("versions").and_then(Value::as_array) else {
        return Err(DocError("the APIGroup has no versions list"));
    };
    if entries.len() > MAX_VERSIONS {
        return Err(DocError("the APIGroup names more than 16 versions"));
    }
    let mut versions: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let group_version = entry.get("groupVersion").and_then(Value::as_str);
        let Some(version) = group_version.and_then(|text| text.strip_prefix(ADMISSION_GROUP)).and_then(|rest| rest.strip_prefix('/'))
        else {
            return Err(DocError("an APIGroup version is not admissionregistration.k8s.io/<v>"));
        };
        if !is_version(version) {
            return Err(DocError("an APIGroup version is not a version token"));
        }
        if versions.iter().any(|seen| seen == version) {
            return Err(DocError("an APIGroup names a version twice"));
        }
        versions.push(version.to_string());
    }
    Ok(versions)
}

/// The `APIResourceList` of `admissionregistration.k8s.io/<version>`: its `resources[].name` values (subresources such
/// as `<name>/status` included as written).
pub fn resource_names(body: &[u8], version: &str) -> Result<Vec<String>, DocError> {
    let value = document(body)?;
    if value.get("kind").and_then(Value::as_str) != Some("APIResourceList") {
        return Err(DocError("a version document is not an APIResourceList"));
    }
    let expected = format!("{ADMISSION_GROUP}/{version}");
    if value.get("groupVersion").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err(DocError("an APIResourceList names another groupVersion"));
    }
    let Some(entries) = value.get("resources").and_then(Value::as_array) else {
        return Err(DocError("an APIResourceList has no resources list"));
    };
    entries
        .iter()
        .map(|entry| {
            entry.get("name").and_then(Value::as_str).map(str::to_string).ok_or(DocError("a resource without a name"))
        })
        .collect()
}

/// `/version`'s `gitVersion`: a JSON text of 1 to 64 printable ASCII characters.
pub fn git_version(body: &[u8]) -> Result<String, DocError> {
    let value = document(body)?;
    let Some(text) = value.get("gitVersion").and_then(Value::as_str) else {
        return Err(DocError("the version document has no gitVersion text"));
    };
    if text.is_empty() || text.len() > 64 || !text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err(DocError("gitVersion is not 1 to 64 printable ASCII characters"));
    }
    Ok(text.to_string())
}

/// A list value's `metadata.resourceVersion`, if it is text.
pub fn list_resource_version(value: &Value) -> Option<&str> {
    value.get("metadata").and_then(|meta| meta.get("resourceVersion")).and_then(Value::as_str)
}

/// The mark of a resourceVersion-bearing list answer: an object of `kind` and `api_version` (else 84), whose
/// `metadata.resourceVersion` is decimal, 1-20 digits and at most 2^64-1 (else 85). `continue` and
/// `remainingItemCount` are ignored: the answer is never paired or fed to B1.
pub fn mark_of(body: &[u8], kind: &str, api_version: &str) -> Result<u64, MarkError> {
    let value = document(body).map_err(|error| MarkError::Answer(error.0))?;
    if value.as_object().is_none()
        || value.get("kind").and_then(Value::as_str) != Some(kind)
        || value.get("apiVersion").and_then(Value::as_str) != Some(api_version)
    {
        return Err(MarkError::Answer("a progress answer is not of its list kind"));
    }
    list_resource_version(&value)
        .and_then(decimal)
        .ok_or(MarkError::Consistency("a progress answer's resourceVersion is missing or not decimal"))
}

/// The progress read's mark `F`: a `NamespaceList` of `v1` (else 84) with a decimal resourceVersion (else 85).
pub fn progress_mark(body: &[u8]) -> Result<u64, MarkError> {
    mark_of(body, "NamespaceList", "v1")
}

/// A per-spec probe's mark: the spec's own list kind and API version.
pub fn probe_mark(body: &[u8], resource: Resource) -> Result<u64, MarkError> {
    let (kind, api_version) = resource.list_kind();
    mark_of(body, &kind, &api_version)
}
