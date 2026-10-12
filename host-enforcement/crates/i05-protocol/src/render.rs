//! The armed action's identity and its one permitted I04 request (I05 v1 Decision 4, unchanged in v3), and the action
//! template digest. The template layout `planeon.internal.effect-gate-template/v1` is model-defined (MODEL_DEFINED.md).

use crate::json::Doc;
use crate::sha256;

pub const TEMPLATE_VERSION: &str = "planeon.internal.effect-gate-template/v1";

/// An ARM_ACTION verb.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verb {
    Create,
    Get,
    Delete,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Verb::Create => "CREATE",
            Verb::Get => "GET",
            Verb::Delete => "DELETE",
        }
    }

    pub fn parse(text: &str) -> Option<Verb> {
        match text {
            "CREATE" => Some(Verb::Create),
            "GET" => Some(Verb::Get),
            "DELETE" => Some(Verb::Delete),
            _ => None,
        }
    }
}

/// A manifest kind the gate can render (the contract's plural table).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Pod,
    ConfigMap,
    Service,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Pod => "Pod",
            Kind::ConfigMap => "ConfigMap",
            Kind::Service => "Service",
        }
    }

    pub fn plural(self) -> &'static str {
        match self {
            Kind::Pod => "pods",
            Kind::ConfigMap => "configmaps",
            Kind::Service => "services",
        }
    }

    pub fn parse(text: &str) -> Option<Kind> {
        match text {
            "Pod" => Some(Kind::Pod),
            "ConfigMap" => Some(Kind::ConfigMap),
            "Service" => Some(Kind::Service),
            _ => None,
        }
    }
}

/// One manifest of the signed profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub api_version: String,
    pub kind: Kind,
    pub namespace: String,
    pub name: String,
    pub digest: String,
    /// The signed manifest's length in bytes (the CREATE body's Content-Length).
    pub size: u64,
}

impl Manifest {
    /// The object identity `kind/namespace/name`, the API server's uniqueness key.
    pub fn identity(&self) -> String {
        identity_of(self.kind, &self.namespace, &self.name)
    }
}

pub fn identity_of(kind: Kind, namespace: &str, name: &str) -> String {
    format!("{}/{}/{}", kind.as_str(), namespace, name)
}

/// What A1 compares for an armed action (M15): the rendered request head and the digest of the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedRequest {
    pub head: String,
    pub body_digest: Option<String>,
}

/// Canonical DeleteOptions for DELETE (M15): a UID precondition holding the recorded UID, or null when none is recorded.
pub fn delete_options(uid: Option<&str>) -> Vec<u8> {
    Doc::object(vec![
        ("apiVersion", Doc::str("v1")),
        ("kind", Doc::str("DeleteOptions")),
        ("preconditions", Doc::object(vec![("uid", Doc::opt_str(uid))])),
    ])
    .canonical()
}

pub fn render_request(verb: Verb, manifest: &Manifest, uid: Option<&str>, endpoint: &str) -> RenderedRequest {
    let base = format!("/api/v1/namespaces/{}/{}", manifest.namespace, manifest.kind.plural());
    let (method, target, body) = match verb {
        Verb::Create => ("POST", base, Some((manifest.digest.clone(), manifest.size))),
        Verb::Delete => {
            let options = delete_options(uid);
            ("DELETE", format!("{base}/{}", manifest.name), Some((sha256::prefixed(&options), options.len() as u64)))
        }
        Verb::Get => ("GET", format!("{base}/{}", manifest.name), None),
    };
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {endpoint}\r\nAccept: application/json\r\n");
    if let Some((_, length)) = &body {
        head.push_str(&format!("Content-Type: application/json\r\nContent-Length: {length}\r\n"));
    }
    head.push_str("\r\n");
    RenderedRequest { head, body_digest: body.map(|(digest, _)| digest) }
}

/// The ARM_ACTION request template digest: the canonical identity of one permitted action.
pub fn template_digest(verb: Verb, api_version: &str, kind: Kind, namespace: &str, name: &str, uid: Option<&str>,
                       manifest_digest: &str) -> String {
    let template = Doc::object(vec![
        ("schemaVersion", Doc::str(TEMPLATE_VERSION)),
        ("verb", Doc::str(verb.as_str())),
        ("apiVersion", Doc::str(api_version)),
        ("kind", Doc::str(kind.as_str())),
        ("namespace", Doc::str(namespace)),
        ("name", Doc::str(name)),
        ("uid", Doc::opt_str(uid)),
        ("manifestDigest", Doc::str(manifest_digest)),
    ]);
    sha256::prefixed(&template.canonical())
}

/// Decision 0: true when the response decides the outcome. GET: any status. CREATE: 201 or a 4xx except 408.
/// DELETE: 200, 202, 404 or a 4xx except 408. Every other mutation response leaves the outcome unknown.
pub fn outcome_is_final(verb: Verb, status: i64) -> bool {
    let rejected = (400..=499).contains(&status) && status != 408;
    match verb {
        Verb::Get => true,
        Verb::Create => rejected || status == 201,
        Verb::Delete => rejected || matches!(status, 200 | 202 | 404),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod() -> Manifest {
        Manifest { api_version: "v1".into(), kind: Kind::Pod, namespace: "planeon-qual".into(), name: "probe-pod".into(),
                   digest: format!("sha256:{}", "1".repeat(64)), size: 1234 }
    }

    #[test]
    fn renders_the_contract_requests() {
        let endpoint = "198.51.100.7:6443";
        let create = render_request(Verb::Create, &pod(), None, endpoint);
        assert_eq!(create.head, "POST /api/v1/namespaces/planeon-qual/pods HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                                 Accept: application/json\r\nContent-Type: application/json\r\nContent-Length: 1234\r\n\r\n");
        assert_eq!(create.body_digest, Some(pod().digest));
        let get = render_request(Verb::Get, &pod(), None, endpoint);
        assert_eq!(get.head, "GET /api/v1/namespaces/planeon-qual/pods/probe-pod HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                              Accept: application/json\r\n\r\n");
        assert_eq!(get.body_digest, None);
        let delete = render_request(Verb::Delete, &pod(), Some("11111111-aaaa-4bbb-8ccc-000000000001"), endpoint);
        assert!(delete.head.ends_with("Content-Length: 105\r\n\r\n"));
        assert_eq!(delete.body_digest.as_deref(),
                   Some("sha256:5d6108ae37bf0e01ce0c94ebeddd9d327604b40e6f40d7d87a920454f45914b1"));
        assert_eq!(delete_options(None), b"{\"apiVersion\":\"v1\",\"kind\":\"DeleteOptions\",\"preconditions\":{\"uid\":null}}");
    }

    #[test]
    fn template_digests_of_the_vectors() {
        let manifest = pod();
        let digest = |verb, uid| template_digest(verb, "v1", Kind::Pod, "planeon-qual", "probe-pod", uid, &manifest.digest);
        assert_eq!(digest(Verb::Create, None), "sha256:3a27a2635d71e1c068c2be15e3f027bec15470b7ec035fd421bb51179337f57c");
        assert_eq!(digest(Verb::Get, None), "sha256:815309fdb6f3da836521fc354b0fa853941e82501260e1e58117896a962780e0");
        assert_eq!(digest(Verb::Delete, Some("11111111-aaaa-4bbb-8ccc-000000000001")),
                   "sha256:f1e8a5ef962479a3889c694d36628ca36196f1abd9fd2670cf098419c24e06c0");
    }

    #[test]
    fn final_outcomes() {
        for status in [201, 400, 404, 409, 422, 499] {
            assert!(outcome_is_final(Verb::Create, status), "{status}");
        }
        for status in [200, 202, 408, 500, 504, 100, 302, 204] {
            assert!(!outcome_is_final(Verb::Create, status), "{status}");
        }
        for status in [200, 202, 404, 409] {
            assert!(outcome_is_final(Verb::Delete, status), "{status}");
        }
        for status in [201, 408, 503, 204] {
            assert!(!outcome_is_final(Verb::Delete, status), "{status}");
        }
        assert!(outcome_is_final(Verb::Get, 503) && outcome_is_final(Verb::Get, 408));
    }
}
