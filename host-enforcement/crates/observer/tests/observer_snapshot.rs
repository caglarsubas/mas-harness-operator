//! HE-004B1 DESIGN-B section 4.3 (D1-11, D2-2) and section 8: the RBAC snapshot check. The I06 v2 replays (the positive,
//! B01-B05, S01-S35, H01-H03, and X05-X06 as v2 refusals) with every refusal compared exactly; the nine tables' canonical
//! digests, computed from the model at harness-onion `3cba1171` and pinned here; and a wiring test for every table row.

mod b1_support;

use b1_support::{apply, field, parse, rows, text};
use i05_protocol::json::{self, Value};
use i05_protocol::sha256;
use planeon_observer::snapshot::{
    check_rbac_snapshot, rule_grants, Closure, KUBELET_VERBS, POLICY_RESOURCES, PROTECTED_NAMESPACES, SPECIAL_TARGETS,
    STATUS_RESOURCES, SYSTEM_NAMESPACES, WORKLOAD_RESOURCES, WORKLOAD_VERBS, WRITE_VERBS,
};

const VECTORS: &str = include_str!("../../../contracts/i06-v2/vectors.json");

fn vectors() -> Value {
    parse(VECTORS)
}

fn closure() -> Closure {
    Closure::embedded().expect("the embedded closure reads")
}

fn result(closure: &Closure, snapshot: &Value, namespace: &str) -> Option<String> {
    closure.check(snapshot, namespace).err().map(|refusal| refusal.text().to_string())
}

// ------------------------------------------------------------------------------------------------ table digests

fn digest(value: &Value) -> String {
    sha256::hex(&sha256::digest(&json::canonical(value).expect("canonical")))
}

fn strings(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|item| Value::str(item)).collect())
}

fn pairs(table: &[(&str, &str)]) -> Value {
    let mut sorted: Vec<(&str, &str)> = table.to_vec();
    sorted.sort();
    Value::Array(sorted.iter().map(|(group, resource)| strings(&[group, resource])).collect())
}

#[test]
fn each_table_s_canonical_digest_is_the_model_s() {
    let special = {
        let mut rows: Vec<(&str, &str, &[&str])> = SPECIAL_TARGETS.to_vec();
        rows.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
        Value::Array(rows.iter().map(|(group, resource, verbs)| {
            Value::Array(vec![Value::str(group), Value::str(resource), strings(verbs)])
        }).collect())
    };
    let tables: [(&str, usize, Value, &str); 9] = [
        ("POLICY_RESOURCES", POLICY_RESOURCES.len(), pairs(&POLICY_RESOURCES),
         "00d07f879de9f363068964f72553af9c6dd7c6d2b9c59892f9b7fed50e0ca615"),
        ("STATUS_RESOURCES", STATUS_RESOURCES.len(), pairs(&STATUS_RESOURCES),
         "774412200dda10dfe387fe37eeacfefbb6378fbfdd9bcbf51c4538d4952f63ef"),
        ("WORKLOAD_RESOURCES", WORKLOAD_RESOURCES.len(), pairs(&WORKLOAD_RESOURCES),
         "26981eeafc03b4bd823957504050c1c1f6577eb070c04c409518691884af00b1"),
        ("SPECIAL_TARGETS", SPECIAL_TARGETS.len(), special,
         "ead65df5ae4b58af706ead40e09f36304892d177097a5fa6d195a8b76b665c61"),
        ("KUBELET_VERBS", KUBELET_VERBS.len(), strings(&KUBELET_VERBS),
         "b906f85c21084df3e9611d9dc9ef1804b5f705ae87ee8da097daff80045304e0"),
        ("WRITE_VERBS", WRITE_VERBS.len(), strings(&WRITE_VERBS),
         "f862c1c7b5df580fb4d75fa7d4db52492aa320ec57121dc2299b3bfa60ba5d40"),
        ("WORKLOAD_VERBS", WORKLOAD_VERBS.len(), strings(&WORKLOAD_VERBS),
         "a841aba1b1f7c36af2d83f38124235fbcad9fa6102d5202028f062933105b4ea"),
        ("PROTECTED_NAMESPACES", PROTECTED_NAMESPACES.len(), strings(&PROTECTED_NAMESPACES),
         "93e8c6f89776db2d11f5030e6382cebc7f1a66d60de14a92d8d5fcf48049e154"),
        ("SYSTEM_NAMESPACES", SYSTEM_NAMESPACES.len(), strings(&SYSTEM_NAMESPACES),
         "df490723ffb47942e284128c54487dddf2f2eeb9d369762c8750b18949376195"),
    ];
    let counts: Vec<(&str, usize)> = tables.iter().map(|(name, rows, _, _)| (*name, *rows)).collect();
    assert_eq!(counts, [("POLICY_RESOURCES", 22), ("STATUS_RESOURCES", 7), ("WORKLOAD_RESOURCES", 9), ("SPECIAL_TARGETS", 20),
                        ("KUBELET_VERBS", 5), ("WRITE_VERBS", 5), ("WORKLOAD_VERBS", 3), ("PROTECTED_NAMESPACES", 1),
                        ("SYSTEM_NAMESPACES", 4)]);
    for (name, _, value, expected) in tables {
        assert_eq!(digest(&value), expected, "{name}");
    }
}

// ------------------------------------------------------------------------------------------------ replays

#[test]
fn the_positive_is_accepted() {
    let vectors = vectors();
    let snapshot = field(&vectors, "snapshotPositive");
    let namespace = text(&vectors, "qualificationNamespace");
    assert_eq!(namespace, "unit-namespace");
    assert_eq!(rows(snapshot, "subjects").len(), 61);
    let closure = closure();
    assert_eq!(result(&closure, snapshot, namespace), None);
    assert_eq!(closure.check_v1(snapshot, namespace), Ok(()));
    assert_eq!(check_rbac_snapshot(snapshot, namespace), Ok(()), "the entry point over the embedded closure");
}

#[test]
fn the_accepted_variants_are_accepted() {
    let vectors = vectors();
    let snapshot = field(&vectors, "snapshotPositive");
    let namespace = text(&vectors, "qualificationNamespace");
    let closure = closure();
    let ids: Vec<&str> = rows(&vectors, "snapshotAccepted").iter().map(|row| text(row, "id")).collect();
    assert_eq!(ids, ["B01", "B02", "B03", "B04", "B05"]);
    for row in rows(&vectors, "snapshotAccepted") {
        let variant = apply(snapshot, rows(row, "ops"));
        let namespace = row.get("namespace").and_then(Value::as_str).unwrap_or(namespace);
        assert_eq!(result(&closure, &variant, namespace), None, "{}", text(row, "id"));
    }
}

#[test]
fn every_negative_is_refused_with_its_exact_text() {
    let vectors = vectors();
    let snapshot = field(&vectors, "snapshotPositive");
    let closure = closure();
    let negatives = rows(&vectors, "snapshotNegative");
    assert_eq!(negatives.len(), 38);
    let mut ids = Vec::new();
    for row in negatives {
        let id = text(row, "id");
        ids.push(id.to_string());
        let variant = apply(snapshot, rows(row, "ops"));
        assert_eq!(result(&closure, &variant, text(row, "namespace")).as_deref(), Some(text(row, "refusal")), "{id}");
    }
    let expected: Vec<String> = (1..=35).map(|n| format!("S{n:02}")).chain((1..=3).map(|n| format!("H{n:02}"))).collect();
    assert_eq!(ids, expected);
}

#[test]
fn x05_and_x06_are_v2_refusals_the_v1_check_accepts() {
    let vectors = vectors();
    let snapshot = field(&vectors, "snapshotPositive");
    let closure = closure();
    let mut replayed = Vec::new();
    for row in rows(&vectors, "crossVersion").iter().filter(|row| text(row, "subject") == "snapshot") {
        let variant = apply(snapshot, rows(row, "ops"));
        let namespace = text(row, "namespace");
        assert!(field(row, "v1Result").is_null());
        assert_eq!(closure.check_v1(&variant, namespace), Ok(()), "{}", text(row, "id"));
        assert_eq!(result(&closure, &variant, namespace).as_deref(), Some(text(row, "v2Result")), "{}", text(row, "id"));
        replayed.push(text(row, "id"));
    }
    assert_eq!(replayed, ["X05", "X06"]);
}

// ------------------------------------------------------------------------------------------------ per-row wiring

/// The positive with an outsider holding exactly one (group, resource, verb) at `scope`.
fn with_outsider(snapshot: &Value, group: &str, resource: &str, verb: &str, scope: &str) -> Value {
    let rule = format!(r#"{{"op": "append", "path": ["subjects"], "value": {{"kind": "User", "name": "outsider", "exists": true,
        "effectiveRules": [{{"apiGroups": ["{group}"], "resources": ["{resource}"], "verbs": ["{verb}"], "resourceNames": [],
        "scope": "{scope}"}}]}}}}"#);
    apply(snapshot, &[parse(&rule)])
}

const OUTSIDER: &str = "IC01 subject with policy-relevant grants outside the identity closure: outsider";

#[test]
fn every_table_row_is_wired_into_the_grant_classification() {
    let vectors = vectors();
    let snapshot = field(&vectors, "snapshotPositive");
    let closure = closure();
    let refused = |group: &str, resource: &str, verb: &str, scope: &str| {
        let variant = with_outsider(snapshot, group, resource, verb, scope);
        assert_eq!(result(&closure, &variant, "unit-namespace").as_deref(), Some(OUTSIDER), "{group}/{resource} {verb} at {scope}");
    };
    let accepted = |group: &str, resource: &str, verb: &str, scope: &str| {
        let variant = with_outsider(snapshot, group, resource, verb, scope);
        assert_eq!(result(&closure, &variant, "unit-namespace"), None, "{group}/{resource} {verb} at {scope}");
    };
    let mut checks = 0;
    // POLICY_RESOURCES and STATUS_RESOURCES with every WRITE_VERBS row (and `*`); a read is not policy-relevant.
    for (group, resource) in POLICY_RESOURCES.iter().chain(STATUS_RESOURCES.iter()) {
        for verb in WRITE_VERBS.iter().chain(["*"].iter()) {
            refused(group, resource, verb, "unit-namespace");
            checks += 1;
        }
        if SPECIAL_TARGETS.iter().all(|(g, r, _)| (g, r) != (group, resource)) {
            accepted(group, resource, "get", "CLUSTER");
            checks += 1;
        }
    }
    // SPECIAL_TARGETS with each of its verbs (KUBELET_VERBS through the three kubelet rows) and `*`; impersonate rows also
    // with a constrained mode.
    for (group, resource, verbs) in SPECIAL_TARGETS {
        for verb in verbs.iter().chain(["*"].iter()) {
            refused(group, resource, verb, "CLUSTER");
            checks += 1;
        }
        if verbs.contains(&"impersonate") {
            refused(group, resource, "impersonate:user-info", "CLUSTER");
            refused(group, resource, "impersonate-on:serviceaccount", "CLUSTER");
            checks += 2;
        }
    }
    for kubelet in ["nodes/proxy", "nodes/log", "nodes/checkpoint"] {
        for verb in KUBELET_VERBS {
            refused("", kubelet, verb, "CLUSTER");
            checks += 1;
        }
        accepted("", kubelet, "list", "CLUSTER");
    }
    // WORKLOAD_RESOURCES with every WORKLOAD_VERBS row, at cluster scope and in each PROTECTED_NAMESPACES row; not in the
    // qualification namespace, and not with another verb.
    for (group, resource) in WORKLOAD_RESOURCES {
        for verb in WORKLOAD_VERBS.iter().chain(["*"].iter()) {
            refused(group, resource, verb, "CLUSTER");
            for protected in PROTECTED_NAMESPACES {
                refused(group, resource, verb, protected);
            }
            accepted(group, resource, verb, "unit-namespace");
            checks += 3;
        }
        if SPECIAL_TARGETS.iter().all(|(g, r, _)| (*g, *r) != (group, resource)) {
            accepted(group, resource, "delete", "CLUSTER");
        }
    }
    assert!(checks > 250, "{checks}");
    // SYSTEM_NAMESPACES: none may be the qualification namespace.
    for namespace in SYSTEM_NAMESPACES {
        assert_eq!(result(&closure, snapshot, namespace).as_deref(),
                   Some("IC00 qualification namespace must be a dedicated namespace"), "{namespace}");
    }
}

#[test]
fn resource_matching_follows_the_upstream_wildcards() {
    let grants = |groups: &str, resources: &str, verbs: &str, scope: &str| {
        let rule = parse(&format!(r#"{{"apiGroups": {groups}, "resources": {resources}, "verbs": {verbs}, "resourceNames": [], "scope": "{scope}"}}"#));
        rule_grants(&rule).expect("a closed rule")
    };
    // `*/finalize` covers namespaces/finalize only; `*` covers every resource of the group.
    let finalize = grants(r#"[""]"#, r#"["*/finalize"]"#, r#"["update"]"#, "CLUSTER");
    assert_eq!(finalize, vec![("POLICY_WRITE", "/namespaces/finalize".to_string(), "update".to_string(), "CLUSTER".to_string())]);
    let everything = grants(r#"["authentication.k8s.io"]"#, r#"["*"]"#, r#"["impersonate:arbitrary"]"#, "CLUSTER");
    assert_eq!(everything.len(), 6, "users, groups, serviceaccounts, nodes, uids and userextras");
    // A user-extra key, and any subresource wildcard, cover userextras/*.
    for resource in ["userextras/scopes", "*/scopes", "userextras/*"] {
        let held = grants(r#"["authentication.k8s.io"]"#, &format!(r#"["{resource}"]"#), r#"["impersonate"]"#, "CLUSTER");
        assert_eq!(held, vec![("SPECIAL", "authentication.k8s.io/userextras/*".to_string(), "impersonate".to_string(),
                               "CLUSTER".to_string())], "{resource}");
    }
    assert!(grants(r#"["authentication.k8s.io"]"#, r#"["*/"]"#, r#"["impersonate"]"#, "CLUSTER").is_empty());
    assert!(grants(r#"["apps"]"#, r#"["deployments"]"#, r#"["create"]"#, "unit-namespace").is_empty());
    assert_eq!(rule_grants(&parse(r#"{"apiGroups": [], "resources": [], "verbs": [], "resourceNames": []}"#)), None);
}

#[test]
fn the_r10_texts_for_unpinned_refusals_keep_the_model_s_codes() {
    let vectors = vectors();
    let snapshot = field(&vectors, "snapshotPositive");
    let closure = closure();
    let code = |value: &Value, namespace: &str| closure.check(value, namespace).err().map(|refusal| refusal.code().to_string());
    assert_eq!(code(&parse("[]"), "unit-namespace").as_deref(), Some("IC00"));
    assert_eq!(code(&parse(r#"{"schemaVersion": "planeon.internal.i06-rbac-snapshot/v2", "subjects": []}"#), "unit-namespace").as_deref(),
               Some("IC00"));
    let bad = |op: &str| apply(snapshot, &[parse(op)]);
    for op in [r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": "x", "exists": true}}"#,
               r#"{"op": "append", "path": ["subjects"], "value": {"kind": "Robot", "name": "x", "exists": true, "effectiveRules": []}}"#,
               r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": " x", "exists": true, "effectiveRules": []}}"#,
               r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": "x　", "exists": true, "effectiveRules": []}}"#,
               r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": "x\ud800", "exists": true, "effectiveRules": []}}"#,
               r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": "x", "exists": 1, "effectiveRules": []}}"#,
               r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": "x", "exists": true, "effectiveRules": [{"apiGroups": [], "resources": [], "verbs": [], "resourceNames": [], "scope": "Bad"}]}}"#,
               r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": "x", "exists": true, "effectiveRules": [{"apiGroups": [1], "resources": [], "verbs": [], "resourceNames": [], "scope": "CLUSTER"}]}}"#] {
        assert_eq!(code(&bad(op), "unit-namespace").as_deref(), Some("IC00"), "{op}");
    }
    // A controller account marked absent takes the dormant path (as B04): within its bootstrap baseline it passes, beyond
    // it IC02 refuses with the pinned text.
    let absent = bad(r#"{"op": "set", "path": ["subjects", {"kind": "ServiceAccount", "name": "system:serviceaccount:kube-system:namespace-controller"}, "exists"], "value": false}"#);
    assert_eq!(closure.check(&absent, "unit-namespace"), Ok(()));
    let beyond = apply(&absent, &[parse(r#"{"op": "append", "path": ["subjects", {"kind": "ServiceAccount", "name": "system:serviceaccount:kube-system:namespace-controller"}, "effectiveRules"], "value": {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create"], "resourceNames": [], "scope": "CLUSTER"}}"#)]);
    assert_eq!(result(&closure, &beyond, "unit-namespace").as_deref(),
               Some("IC02 absent controller account with grants beyond its bootstrap role: system:serviceaccount:kube-system:namespace-controller"));
    // A name with interior whitespace is a text; one with surrounding whitespace is not.
    let inner = bad(r#"{"op": "append", "path": ["subjects"], "value": {"kind": "Group", "name": "a b", "exists": true, "effectiveRules": []}}"#);
    assert_eq!(closure.check(&inner, "unit-namespace"), Ok(()));
}
