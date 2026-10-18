//! HE-004C DESIGN-C section 6 (R98's specs; departure 1, Q-HE4C-10 (a)): pairing by construction (every rendered target
//! parsed back gives `spec()` for all 20 entries in every mode); RFC 3986 percent-encoding; the parameters outside the
//! pairing; the discovery documents and their three outcomes (`v1`, none, another version only: B1's `Missing`); the
//! `/version` document; the progress read's target and its exclusion from the pairing; the marks of progress answers.

mod b1_rbac_support;
mod b1_support;
mod c_support;

use c_support::*;
use planeon_observer::inputs::{RequestScope, RequestSpec, Resource};
use planeon_observer::observe::ObserverExit;
use planeon_observer::requests::{self, git_version, group_versions, mark_of, percent_encode, progress_mark, resource_names,
                                 DocError, MarkError, Mode};

/// RFC 3986 percent-decoding.
fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            out.push(u8::from_str_radix(&text[at + 1..at + 3], 16).expect("hex"));
            at += 3;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    String::from_utf8(out).expect("UTF-8")
}

/// An independent reading of a rendered target: the spec it requests and its mode.
fn parse_target(target: &str) -> (RequestSpec, Mode) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let (group, version, resource) = match segments.as_slice() {
        ["api", version, resource] => (String::new(), version.to_string(), resource.to_string()),
        ["apis", group, version, resource] => (group.to_string(), version.to_string(), resource.to_string()),
        _ => panic!("not a collection path: {path}"),
    };
    let mut field_selector = None;
    let mut parameters: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').expect("key=value");
        if key == "fieldSelector" {
            assert!(parameters.is_empty(), "the field selector comes first");
            field_selector = Some(decode(value));
        } else {
            parameters.push((key.to_string(), value.to_string()));
        }
    }
    let keys: Vec<&str> = parameters.iter().map(|(key, _)| key.as_str()).collect();
    let mode = match keys.as_slice() {
        [] => Mode::Fresh,
        ["resourceVersion", "resourceVersionMatch"] if parameters[1].1 == "Exact" => Mode::Exact(parameters[0].1.clone()),
        ["watch", "allowWatchBookmarks", "resourceVersion"] if parameters[0].1 == "true" && parameters[1].1 == "true" => {
            Mode::Watch(parameters[2].1.clone())
        }
        ["limit"] if parameters[0].1 == "1" => Mode::Probe,
        _ => panic!("unexpected parameters {keys:?}"),
    };
    let namespaced = Resource::ALL.into_iter().find(|entry| entry.resource() == resource).expect("a resource").namespaced();
    let scope = if namespaced { RequestScope::AllNamespaces } else { RequestScope::Cluster };
    (RequestSpec { group, version, resource, scope, label_selector: None, field_selector }, mode)
}

#[test]
fn every_rendered_target_parses_back_to_its_spec_in_every_mode() {
    let modes = [Mode::Fresh, Mode::Exact("4711".to_string()), Mode::Watch("4711".to_string()), Mode::Probe];
    let mut seen = 0;
    for resource in Resource::ALL {
        for mode in &modes {
            let request = requests::list(resource, mode);
            let (spec, parsed) = parse_target(&request.target);
            assert_eq!(spec, resource.spec(), "{resource} {mode:?}: {}", request.target);
            assert_eq!(&parsed, mode, "{}", request.target);
            assert_eq!(Resource::of_spec(&spec), Some(resource));
            let metadata = matches!(resource, Resource::ServiceAccountTokenSecrets | Resource::BootstrapTokenSecrets);
            let accept = match (metadata, mode) {
                (false, _) => "application/json",
                (true, Mode::Watch(_)) => "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1",
                (true, _) => "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1",
            };
            assert_eq!(request.accept, accept, "{resource} {mode:?}");
            assert!(!request.target.contains("labelSelector") && !request.target.contains("continue"));
            seen += 1;
        }
    }
    assert_eq!(seen, 80);
    assert_eq!(requests::watch_kind(Resource::Roles), "Role");
    assert_eq!(requests::watch_kind(Resource::BootstrapTokenSecrets), "PartialObjectMetadata");
}

#[test]
fn percent_encoding_keeps_only_unreserved_characters() {
    assert_eq!(percent_encode("type=kubernetes.io/service-account-token"), "type%3Dkubernetes.io%2Fservice-account-token");
    assert_eq!(percent_encode("type=bootstrap.kubernetes.io/token"), "type%3Dbootstrap.kubernetes.io%2Ftoken");
    assert_eq!(percent_encode("AZaz09-._~"), "AZaz09-._~");
    assert_eq!(percent_encode(" !\"#$&'()*+,/:;=?@[]%"), "%20%21%22%23%24%26%27%28%29%2A%2B%2C%2F%3A%3B%3D%3F%40%5B%5D%25");
    assert_eq!(percent_encode("\u{e9}"), "%C3%A9");
    assert_eq!(decode(&percent_encode("a b/c=d")), "a b/c=d");
}

#[test]
fn the_progress_read_and_the_fixed_requests_are_outside_the_pairing() {
    assert_eq!(requests::progress().target, "/api/v1/namespaces?limit=1");
    let (spec, mode) = parse_target(&requests::progress().target);
    assert_eq!(mode, Mode::Probe);
    // The progress read names the Namespaces collection but carries `limit`, which no closed-set list issues: it is
    // never paired or fed to B1 (the pairing's targets carry no limit).
    assert_eq!(Resource::of_spec(&spec), Some(Resource::Namespaces));
    assert!(Resource::ALL.into_iter().all(|resource| !requests::list(resource, &Mode::Fresh).target.contains("limit=")));
    for request in [requests::readyz(), requests::metrics(), requests::version(), requests::discovery_group(),
                    requests::discovery_version("v1")] {
        assert!(Resource::ALL.into_iter().all(|resource| requests::list(resource, &Mode::Fresh).target != request.target));
    }
}

#[test]
fn the_discovery_documents() {
    let group = br#"{"kind": "APIGroup", "apiVersion": "v1", "name": "admissionregistration.k8s.io", "versions": [{"groupVersion": "admissionregistration.k8s.io/v1", "version": "v1"}, {"groupVersion": "admissionregistration.k8s.io/v1beta1", "version": "v1beta1"}]}"#;
    assert_eq!(group_versions(group), Ok(vec!["v1".to_string(), "v1beta1".to_string()]));
    for body in [br#"{"kind": "APIGroupList", "versions": []}"#.as_slice(),
                 br#"{"kind": "APIGroup", "versions": {}}"#,
                 br#"{"kind": "APIGroup", "versions": [{"groupVersion": "apps/v1"}]}"#,
                 br#"{"kind": "APIGroup", "versions": [{"groupVersion": "admissionregistration.k8s.io/v1"}, {"groupVersion": "admissionregistration.k8s.io/v1"}]}"#,
                 br#"{"kind": "APIGroup", "versions": [{"groupVersion": "admissionregistration.k8s.io/V1"}]}"#,
                 br#"{"kind": "APIGroup", "versions": [{"groupVersion": "admissionregistration.k8s.io/"}]}"#,
                 br#"{"kind": "APIGroup", "versions": [{"version": "v1"}]}"#,
                 br#"{"kind": "APIGroup", "kind": "APIGroup", "versions": []}"#,
                 b"not json"] {
        assert!(group_versions(body).is_err(), "{}", String::from_utf8_lossy(body));
    }
    let many: Vec<String> = (0..17).map(|index| format!(r#"{{"groupVersion": "admissionregistration.k8s.io/v{index}"}}"#)).collect();
    let body = format!(r#"{{"kind": "APIGroup", "versions": [{}]}}"#, many.join(", "));
    assert_eq!(group_versions(body.as_bytes()), Err(DocError("the APIGroup names more than 16 versions")));
    let list = br#"{"kind": "APIResourceList", "groupVersion": "admissionregistration.k8s.io/v1", "resources": [{"name": "mutatingadmissionpolicies"}, {"name": "mutatingadmissionpolicies/status"}]}"#;
    assert_eq!(resource_names(list, "v1"), Ok(vec!["mutatingadmissionpolicies".to_string(), "mutatingadmissionpolicies/status".to_string()]));
    assert!(resource_names(list, "v1beta1").is_err(), "another groupVersion");
    assert!(resource_names(br#"{"kind": "APIResourceList", "groupVersion": "admissionregistration.k8s.io/v1", "resources": [{"kind": "x"}]}"#, "v1").is_err());
    assert!(resource_names(br#"{"kind": "APIGroup", "groupVersion": "admissionregistration.k8s.io/v1", "resources": []}"#, "v1").is_err());
}

#[test]
fn discoverys_three_outcomes() {
    // v1 lists both kinds: 20 lists and 20 watches.
    let rig = Rig::new();
    assert_eq!(rig.run().0, ObserverExit::ConfigExpired);
    assert_eq!(rig.requests("/apis/admissionregistration.k8s.io/v1/mutatingadmissionpolic").len(), 2 * 2);
    // No version lists them (only the subresource names remain): NotServed, 18 lists and 18 watches, OR06 passes.
    let rig = Rig::new();
    rig.api(|api| {
        let names: Vec<String> = admission_v1_names()
            .into_iter()
            .map(|name| if name == "mutatingadmissionpolicies" { "mutatingadmissionpolicies/status".to_string() } else { name })
            .filter(|name| name != "mutatingadmissionpolicybindings")
            .collect();
        api.admission_versions = vec![("v1".to_string(), names), ("v1alpha1".to_string(), vec!["other".to_string()])];
    });
    let (exit, epoch) = rig.run();
    assert_eq!(exit, ObserverExit::ConfigExpired, "{}", epoch.reason());
    assert!(rig.requests("/apis/admissionregistration.k8s.io/v1/mutatingadmissionpolic").is_empty());
    let watches = rig.requests("/").into_iter().filter(|req| req.param("watch") == Some("true")).count();
    assert_eq!(watches, 18);
    // Only another version lists them: no pair, so B1's Missing refuses (86).
    let rig = Rig::new();
    rig.api(|api| {
        let v1: Vec<String> = admission_v1_names().into_iter().filter(|name| !name.starts_with("mutatingadmissionpolic")).collect();
        api.admission_versions = vec![("v1".to_string(), v1),
                                      ("v1beta1".to_string(), vec!["mutatingadmissionpolicybindings".to_string()])];
    });
    assert_eq!(rig.run().0, ObserverExit::Inputs);
    // A discovery answer outside its form is 84.
    let rig = Rig::new();
    rig.hook(|req, _| (req.path == "/apis/admissionregistration.k8s.io").then(|| json(200, r#"{"kind": "APIGroup"}"#)));
    assert_eq!(rig.run().0, ObserverExit::Answer);
}

#[test]
fn the_version_document_and_the_marks() {
    assert_eq!(git_version(br#"{"gitVersion": "v1.37.1", "major": "1"}"#), Ok("v1.37.1".to_string()));
    for body in [br#"{"gitVersion": ""}"#.as_slice(), br#"{"major": "1"}"#, br#"{"gitVersion": 137}"#] {
        assert!(git_version(body).is_err());
    }
    assert!(git_version(format!(r#"{{"gitVersion": "{}"}}"#, "v".repeat(65)).as_bytes()).is_err());
    assert!(git_version(br#"{"gitVersion": "v1.37.1\u0001"}"#).is_err());
    assert_eq!(git_version(format!(r#"{{"gitVersion": "{}"}}"#, "v".repeat(64)).as_bytes()).map(|text| text.len()), Ok(64));
    let list = |kind: &str, api_version: &str, version: &str| {
        format!(r#"{{"kind": "{kind}", "apiVersion": "{api_version}", "metadata": {{"resourceVersion": {version}, "continue": "x", "remainingItemCount": 3}}, "items": []}}"#)
    };
    assert_eq!(progress_mark(list("NamespaceList", "v1", "\"42\"").as_bytes()), Ok(42));
    assert_eq!(progress_mark(list("NamespaceList", "v1", "\"18446744073709551615\"").as_bytes()), Ok(u64::MAX));
    assert!(matches!(progress_mark(list("RoleList", "v1", "\"42\"").as_bytes()), Err(MarkError::Answer(_))));
    assert!(matches!(progress_mark(list("NamespaceList", "rbac.authorization.k8s.io/v1", "\"42\"").as_bytes()), Err(MarkError::Answer(_))));
    for version in ["42", "\"\"", "\"4.2\"", "\"-1\"", "\"18446744073709551616\"", "null"] {
        assert!(matches!(progress_mark(list("NamespaceList", "v1", version).as_bytes()), Err(MarkError::Consistency(_))), "{version}");
    }
    assert_eq!(mark_of(list("PartialObjectMetadataList", "meta.k8s.io/v1", "\"7\"").as_bytes(), "PartialObjectMetadataList",
                       "meta.k8s.io/v1"), Ok(7));
    assert_eq!(requests::probe_mark(list("RoleList", "rbac.authorization.k8s.io/v1", "\"9\"").as_bytes(), Resource::Roles), Ok(9));
}
