//! HE-003C: the identity fields of an upstream answer (DESIGN §4, D1-3, D2-2, Q-HE3C-6 (a), Q-HE3C-7 (a);
//! MODEL_DEFINED R65, R66), through the port with the scripted apiserver: read only where the model journals them
//! (I05 GET 200, CREATE 201, DELETE 200/202; I07 success statuses), in the one form per I05 kind (Pod and Service: the
//! deleted object; ConfigMap: a v1 Status whose details.kind is the resource plural) and either form for an I07
//! DELETE; every other status passes None so Decision 0's reconciliation runs; an unreadable identity is LOST; and
//! `write_response`'s R15 check (HE003-REQ-1).

mod tls_support;
mod upstream_support;

use effect_gate::{Event, PolicyEvent, UpstreamOutcome, UpstreamResponse};
use gate_tls::write_response;
use i05_protocol::{sha256, Kind, Verb};

use upstream_support::*;

const UID: &str = "11111111-aaaa-4bbb-8ccc-000000000001";

fn object(kind: &str, name: &str) -> Vec<u8> {
    format!(r#"{{"apiVersion": "v1", "kind": "{kind}", "metadata": {{"name": "{name}", "namespace": "planeon-qual", "uid": "{UID}", "resourceVersion": "42"}}, "spec": {{"ratio": 0.5}}}}"#)
        .into_bytes()
}

fn status(plural: &str, name: &str) -> Vec<u8> {
    format!(r#"{{"kind":"Status","apiVersion":"v1","metadata":{{}},"status":"Success","details":{{"name":"{name}","group":"","kind":"{plural}","uid":"{UID}"}}}}"#)
        .into_bytes()
}

/// The I05 outcome of one exchange: `Some((status, uid, resourceVersion))` for a response, `None` for LOST.
fn i05(verb: Verb, kind: Kind, name: &str, status_line: &str, body: &[u8]) -> Option<(i64, Option<String>, Option<String>)> {
    let mut rig = rig();
    let (_, events) = rig.i05_exchange(verb, kind, name, &http(status_line, body));
    match events.as_slice() {
        [PolicyEvent::Base(Event::UpstreamResponse { conn, response })] if conn == "i04-7" => {
            assert_eq!(response.body_digest, sha256::prefixed(body));
            Some((response.http_status, response.uid.clone(), response.resource_version.clone()))
        }
        [PolicyEvent::Base(Event::UpstreamLost { conn })] if conn == "i04-7" => None,
        other => panic!("one outcome, not {other:?}"),
    }
}

fn i07(payload: &str, status_line: &str, body: &[u8]) -> Option<(i64, Option<String>, Option<String>)> {
    let mut rig = rig();
    let (_, events) = rig.i07_exchange(payload, &http(status_line, body));
    match events.as_slice() {
        [PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Response(response) }] => {
            assert_eq!(response.body_digest, sha256::prefixed(body));
            Some((response.http_status, response.uid.clone(), response.resource_version.clone()))
        }
        [PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Lost }] => None,
        other => panic!("one outcome, not {other:?}"),
    }
}

fn read(status: i64) -> Option<(i64, Option<String>, Option<String>)> {
    Some((status, Some(UID.to_string()), Some("42".to_string())))
}

fn none(status: i64) -> Option<(i64, Option<String>, Option<String>)> {
    Some((status, None, None))
}

#[test]
fn i05_get_200_and_create_201_read_the_object() {
    assert_eq!(i05(Verb::Get, Kind::Pod, "probe-pod", "200 OK", &object("Pod", "probe-pod")), read(200));
    assert_eq!(i05(Verb::Create, Kind::Service, "probe-svc", "201 Created", &object("Service", "probe-svc")), read(201));
    // Whitespace and floats are allowed by the agreement-mode decoder.
    let spaced = b" {\n \"metadata\" : { \"uid\" : \"u-1\" , \"resourceVersion\" : \"9\" } , \"n\": 1.5e3 }\n";
    assert_eq!(i05(Verb::Get, Kind::ConfigMap, "probe-cm", "200 OK", spaced),
               Some((200, Some("u-1".into()), Some("9".into()))));
}

#[test]
fn i05_delete_reads_the_form_its_kind_names() {
    // Pod and Service: the deleted object.
    assert_eq!(i05(Verb::Delete, Kind::Pod, "probe-pod", "200 OK", &object("Pod", "probe-pod")), read(200));
    assert_eq!(i05(Verb::Delete, Kind::Service, "probe-svc", "202 Accepted", &object("Service", "probe-svc")), read(202));
    // ConfigMap: a v1 Status, details.kind the resource plural; no resourceVersion is observed.
    assert_eq!(i05(Verb::Delete, Kind::ConfigMap, "probe-cm", "200 OK", &status("configmaps", "probe-cm")),
               Some((200, Some(UID.to_string()), None)));
    // The other form, or a Status naming the Kind instead of the resource, or another name: LOST.
    assert_eq!(i05(Verb::Delete, Kind::Pod, "probe-pod", "200 OK", &status("pods", "probe-pod")), None);
    assert_eq!(i05(Verb::Delete, Kind::ConfigMap, "probe-cm", "200 OK", &object("ConfigMap", "probe-cm")), None);
    assert_eq!(i05(Verb::Delete, Kind::ConfigMap, "probe-cm", "200 OK", &status("ConfigMap", "probe-cm")), None);
    assert_eq!(i05(Verb::Delete, Kind::ConfigMap, "probe-cm", "200 OK", &status("configmaps", "other-cm")), None);
    let failure = String::from_utf8(status("configmaps", "probe-cm")).unwrap_or_default().replace("Success", "Failure");
    assert_eq!(i05(Verb::Delete, Kind::ConfigMap, "probe-cm", "200 OK", failure.as_bytes()), None);
    let v2 = String::from_utf8(status("configmaps", "probe-cm")).unwrap_or_default().replace("\"v1\"", "\"v2\"");
    assert_eq!(i05(Verb::Delete, Kind::ConfigMap, "probe-cm", "200 OK", v2.as_bytes()), None);
}

#[test]
fn statuses_the_model_does_not_journal_pass_none_and_are_relayed() {
    // A GET 2xx other than 200, a CREATE 200 (not final), a 404, a 409 and a 503: uid and resourceVersion None
    // whatever the body (even an unreadable one), so Decision 0's reconciliation path runs.
    assert_eq!(i05(Verb::Get, Kind::Pod, "probe-pod", "204 No Content", b""), none(204));
    assert_eq!(i05(Verb::Get, Kind::Pod, "probe-pod", "206 Partial Content", b"not json"), none(206));
    assert_eq!(i05(Verb::Create, Kind::Pod, "probe-pod", "200 OK", &object("Pod", "probe-pod")), none(200));
    assert_eq!(i05(Verb::Get, Kind::Pod, "probe-pod", "404 Not Found", b"{\"kind\":\"Status\"}"), none(404));
    assert_eq!(i05(Verb::Delete, Kind::ConfigMap, "probe-cm", "409 Conflict", b"{"), none(409));
    assert_eq!(i05(Verb::Create, Kind::Pod, "probe-pod", "503 Service Unavailable", b"\xff"), none(503));
}

#[test]
fn an_unreadable_identity_where_the_model_journals_it_is_lost() {
    let depth_17 = format!("{{\"metadata\":{{\"uid\":\"u\",\"resourceVersion\":\"1\"}},\"x\":{}1{}}}",
                           "[".repeat(16), "]".repeat(16));
    let depth_16 = format!("{{\"metadata\":{{\"uid\":\"u\",\"resourceVersion\":\"1\"}},\"x\":{}1{}}}",
                           "[".repeat(15), "]".repeat(15));
    assert_eq!(i05(Verb::Get, Kind::Pod, "probe-pod", "200 OK", depth_16.as_bytes()),
               Some((200, Some("u".into()), Some("1".into()))), "depth 16 is read");
    let long_uid = format!("{{\"metadata\":{{\"uid\":\"{}\",\"resourceVersion\":\"1\"}}}}", "u".repeat(129));
    let bodies: Vec<Vec<u8>> = vec![
        depth_17.into_bytes(),
        b"{\"metadata\":{\"uid\":\"u\",\"uid\":\"v\",\"resourceVersion\":\"1\"}}".to_vec(), // duplicate key
        b"{\"metadata\":{\"uid\":\"u\",\"resourceVersion\":\"1\"},\"x\":NaN}".to_vec(),
        b"{\"metadata\":{\"uid\":\"u\"}}".to_vec(),
        b"{\"metadata\":{\"resourceVersion\":\"1\"}}".to_vec(),
        b"{\"metadata\":{\"uid\":\"a_b\",\"resourceVersion\":\"1\"}}".to_vec(),
        b"{\"metadata\":{\"uid\":\"u\",\"resourceVersion\":\"4-2\"}}".to_vec(),
        b"{\"metadata\":{\"uid\":\"\",\"resourceVersion\":\"1\"}}".to_vec(),
        b"{\"metadata\":{\"uid\":7,\"resourceVersion\":\"1\"}}".to_vec(),
        long_uid.into_bytes(),
        b"[{\"metadata\":{\"uid\":\"u\",\"resourceVersion\":\"1\"}}]".to_vec(),
        b"{\"metadata\":{\"uid\":\"u\",\"resourceVersion\":\"1\"}} trailing".to_vec(),
        b"\xff{}".to_vec(),
        b"".to_vec(),
        // A Status where the object form is required.
        status("pods", "probe-pod"),
    ];
    for body in bodies {
        assert_eq!(i05(Verb::Create, Kind::Pod, "probe-pod", "201 Created", &body), None, "{}",
                   String::from_utf8_lossy(&body));
    }
}

#[test]
fn i07_successes_read_their_forms_and_a_delete_takes_either() {
    let role = |uid: &str, version: &str| {
        format!(r#"{{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{{"name":"planeon-role","uid":"{uid}","resourceVersion":"{version}"}}}}"#)
            .into_bytes()
    };
    let read_role = Some((201, Some("u-2".to_string()), Some("43".to_string())));
    assert_eq!(i07(ROLE_CREATE, "201 Created", &role("u-2", "43")), read_role);
    assert_eq!(i07(ROLE_UPDATE, "200 OK", &role("u-1", "44")), Some((200, Some("u-1".into()), Some("44".into()))));
    assert_eq!(i07(ROLE_DELETE, "200 OK", &role("u-1", "45")), Some((200, Some("u-1".into()), Some("45".into()))));
    // Q-HE3C-7 (a): a DELETE answered by a v1 Status: details.name the name, details.kind the plural (roles).
    assert_eq!(i07(ROLE_DELETE, "200 OK", &status("roles", "planeon-role")), Some((200, Some(UID.into()), None)));
    assert_eq!(i07(ROLE_DELETE, "202 Accepted", &status("roles", "planeon-role")), Some((202, Some(UID.into()), None)));
    assert_eq!(i07(ROLE_DELETE, "200 OK", &status("Role", "planeon-role")), None);
    assert_eq!(i07(ROLE_DELETE, "200 OK", &status("roles", "another-role")), None);
    // CREATE and UPDATE take the object form only.
    assert_eq!(i07(ROLE_CREATE, "201 Created", &status("roles", "planeon-role")), None);
    assert_eq!(i07(ROLE_CREATE, "201 Created", b"{}"), None);
    // Not a success: None, whatever the body; the model journals the status and digest (reconciliation or rejection).
    assert_eq!(i07(ROLE_CREATE, "200 OK", &role("u-2", "43")), none(200));
    assert_eq!(i07(ROLE_UPDATE, "409 Conflict", b"{\"kind\":\"Status\"}"), none(409));
    assert_eq!(i07(ROLE_DELETE, "404 Not Found", b"not json"), none(404));
    assert_eq!(i07(ROLE_CREATE, "500 Internal Server Error", b""), none(500));
}

#[test]
fn write_response_builds_the_event_or_lost_by_r15() {
    let body = b"{\"kind\":\"Role\"}";
    match write_response(3, 201, body, Some("a-".repeat(64)), Some("Z".repeat(64))) {
        PolicyEvent::WUpstream { write_id: 3, outcome: UpstreamOutcome::Response(UpstreamResponse { http_status,
                                                                                                    body_digest, uid,
                                                                                                    resource_version }) } => {
            assert_eq!(http_status, 201);
            assert_eq!(body_digest, sha256::prefixed(body));
            assert_eq!((uid.map(|uid| uid.len()), resource_version.map(|version| version.len())), (Some(128), Some(64)));
        }
        other => panic!("a response, not {other:?}"),
    }
    let lost = |event: PolicyEvent| matches!(event, PolicyEvent::WUpstream { write_id: 3, outcome: UpstreamOutcome::Lost });
    for (status, uid, version) in [(99u16, None, None), (600, None, None), (201, Some("a_b".to_string()), None),
                                   (201, Some("u".repeat(129)), None), (201, Some(String::new()), None),
                                   (201, None, Some("4-2".to_string())), (201, None, Some("1".repeat(65))),
                                   (201, Some("\n".to_string()), Some("1".to_string()))] {
        assert!(lost(write_response(3, status, body, uid.clone(), version.clone())), "{status} {uid:?} {version:?}");
    }
    // None passes: a non-success answer's empty identity.
    assert!(matches!(write_response(3, 409, b"", None, None),
                     PolicyEvent::WUpstream { write_id: 3, outcome: UpstreamOutcome::Response(_) }));
}
