//! HE-004-I01a DESIGN-I01A sections 10 and 15 (MODEL_DEFINED's HE-004-I01a section): the role pin. First the I06 v4
//! replay, 139 cases with every refusal compared byte for byte: 96 of the v4 vectors' own (6 accepted and 61 refused
//! object cases, 2 accepted and 14 refused snapshot cases, 6 cross-version and 7 composed) and the 43 snapshot cases of
//! I06 v3 (5 accepted, 38 refused), run on the v4 positive. A snapshot verdict is `Closure::check` (v3's IC00-IC05) and then RB05; an objects
//! verdict is `object_lists` and then RB01-RB04, RB06 and RB07; a composed case runs both in `observe.rs`'s order.
//! `documentNegative` (7) is RB00, HE-008's manifest check, and is not replayed. Then the frozen inputs are R10's
//! vendored files and the compiled constants are the positives' data; R10's own texts for the forms no vector pins; and
//! on the HE-004C rig, a read the role pin refuses ends the epoch with 87, before an operational rule's 88.

mod b1_rbac_support;
mod b1_support;
mod c_support;

use b1_rbac_support::aggregated_role;
use b1_support::{apply, field, parse, rows, text};
use c_support::Rig;
use i05_protocol::json::{self, Value};
use i05_protocol::sha256;
use planeon_observer::contracts;
use planeon_observer::inputs::Resource;
use planeon_observer::observe::ObserverExit;
use planeon_observer::observer_rbac::{check_effective_rules, check_observer_rbac, check_observer_snapshot, object_lists,
                                      BINDING_NAME, OBSERVER_RULES, OBSERVER_USER, ROLE_NAME, ROLE_REF, RULE_KEYS,
                                      SERVER_METADATA, SUBJECT};
use planeon_observer::snapshot::Closure;
use planeon_observer::status;

const V4_VECTORS: &str = include_str!("../../../contracts/i06-v4/vectors.json");
const V4_CRITERIA: &str = include_str!("../../../contracts/i06-v4/criteria.json");
const V3_VECTORS: &str = include_str!("../../../contracts/i06-v3/vectors.json");
const V3_CRITERIA: &[u8] = include_bytes!("../../../contracts/i06-v3/criteria.json");
const I07_V3_VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");

/// A verdict as the vectors write one: `None` for acceptance, otherwise the refusal's text.
type Verdict = Option<String>;

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

fn closure() -> Closure {
    Closure::embedded().expect("the embedded closure reads")
}

/// I06 v3's snapshot check alone.
fn v3_verdict(closure: &Closure, snapshot: &Value, namespace: &str) -> Verdict {
    closure.check(snapshot, namespace).err().map(|refusal| refusal.text().to_string())
}

/// I06 v4's snapshot check: v3's, then RB05.
fn v4_verdict(closure: &Closure, snapshot: &Value, namespace: &str) -> Verdict {
    v3_verdict(closure, snapshot, namespace)
        .or_else(|| check_effective_rules(snapshot).err().map(|refusal| refusal.text().to_string()))
}

/// The object rules alone, on the vectors' `{clusterRoles, clusterRoleBindings, roleBindings}` form.
fn objects_verdict(objects: &Value) -> Verdict {
    object_lists(objects).and_then(check_observer_rbac).err().map(|refusal| refusal.text().to_string())
}

/// The observer's acceptance as `observe.rs` runs it: the closure check, then the role pin on the snapshot and on the
/// lists it was produced from. (Here the lists come in the vectors' object form, read first; in `observe.rs` they are
/// the read's own lists, so that reading cannot refuse there. No composed case has an unreadable object form.)
fn observer_verdict(closure: &Closure, snapshot: &Value, objects: &Value, namespace: &str) -> Verdict {
    if let Some(refusal) = v3_verdict(closure, snapshot, namespace) {
        return Some(refusal);
    }
    object_lists(objects)
        .and_then(|lists| check_observer_snapshot(snapshot, lists))
        .err()
        .map(|refusal| refusal.text().to_string())
}

/// A row's expected verdict under `key` (absent or null: accepted).
fn expected(row: &Value, key: &str) -> Verdict {
    row.get(key).and_then(Value::as_str).map(str::to_string)
}

fn row_namespace<'a>(row: &'a Value, default: &'a str) -> &'a str {
    row.get("namespace").and_then(Value::as_str).unwrap_or(default)
}

/// The rows of `keys` in `vectors` by id.
fn case<'a>(vectors: &'a Value, keys: &[&str], id: &str) -> &'a Value {
    keys.iter()
        .flat_map(|key| rows(vectors, key).iter())
        .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
        .unwrap_or_else(|| panic!("no case {id}"))
}

/// A JSON array of texts.
fn texts(items: &[&str]) -> String {
    format!("[{}]", items.iter().map(|item| format!("\"{item}\"")).collect::<Vec<_>>().join(", "))
}

// ------------------------------------------------------------------------------------------------ the inputs

#[test]
fn the_frozen_inputs_are_r10_s_vendored_files_and_the_case_counts_hold() {
    let v4 = parse(V4_VECTORS);
    let v3 = parse(V3_VECTORS);
    assert_eq!((text(&v4, "evidenceClass"), text(&v4, "kubernetesBaseline")), ("DATA_CHECK_ONLY", "v1.37.1"));
    let inputs = field(&v4, "inputs");
    let pin = |key: &str| text(field(inputs, key), "sha256").to_string();
    assert_eq!(pin("v3Vectors"), hex(V3_VECTORS.as_bytes()));
    assert_eq!(pin("v3Criteria"), hex(V3_CRITERIA));
    assert_eq!(pin("criteria"), hex(V4_CRITERIA.as_bytes()));
    assert_eq!(pin("i07Vectors"), hex(I07_V3_VECTORS.as_bytes()));
    // The closure, inventory and bootstrap the vectors were computed over are the ones `Closure::embedded` reads.
    for (key, embedded, digest) in [("closure", contracts::IDENTITY_CLOSURE, contracts::IDENTITY_CLOSURE_SHA256),
                                    ("inventory", contracts::WRITER_INVENTORY, contracts::WRITER_INVENTORY_SHA256),
                                    ("bootstrap", contracts::BOOTSTRAP_RBAC, contracts::BOOTSTRAP_RBAC_SHA256)] {
        assert_eq!((pin(key), hex(embedded)), (digest.to_string(), digest.to_string()), "{key}");
    }
    // The case set, last section first: 96 of v4's own, the 43 of v3, and the seven RB00 cases, HE-008's.
    let counts: Vec<(&str, usize)> = ["composed", "crossVersion", "snapshotNegative", "snapshotAccepted", "objectsNegative",
                                      "objectsAccepted", "documentNegative"]
        .into_iter()
        .map(|key| (key, rows(&v4, key).len()))
        .collect();
    assert_eq!(counts, [("composed", 7), ("crossVersion", 6), ("snapshotNegative", 14), ("snapshotAccepted", 2),
                        ("objectsNegative", 61), ("objectsAccepted", 6), ("documentNegative", 7)]);
    let own: usize = counts[..6].iter().map(|(_, count)| count).sum();
    let carried = rows(&v3, "snapshotAccepted").len() + rows(&v3, "snapshotNegative").len();
    assert_eq!((own, carried, own + carried), (96, 43, 139));
    assert_eq!(b1_support::canonical_text(field(&v4, "v3SnapshotCases")), r#"{"accepted":5,"negative":38}"#);
    assert_eq!(text(&v4, "qualificationNamespace"), text(&v3, "qualificationNamespace"));
    // criteria.json is read for its ids: RB00-RB07 close the list, and each of RB01-RB07 has a refusal replayed here.
    let criteria = parse(V4_CRITERIA);
    let ids: Vec<&str> = rows(&criteria, "criteria").iter().map(|row| text(row, "id")).filter(|id| id.starts_with("RB")).collect();
    assert_eq!(ids, ["RB00", "RB01", "RB02", "RB03", "RB04", "RB05", "RB06", "RB07"]);
    let replayed: Vec<&str> = ["objectsNegative", "snapshotNegative"]
        .into_iter()
        .flat_map(|key| rows(&v4, key).iter().map(|row| text(row, "refusal")))
        .collect();
    for id in &ids[1..] {
        assert!(replayed.iter().any(|refusal| refusal.starts_with(&format!("{id} "))), "{id}");
    }
}

#[test]
fn the_compiled_constants_are_the_positives_data() {
    let v4 = parse(V4_VECTORS);
    let positive = field(&v4, "objectsPositive");
    // The role's eight rules, each list as the model reads it (absent or null: empty).
    let role = &rows(positive, "clusterRoles")[0];
    let rules = rows(role, "rules");
    assert_eq!(rules.len(), OBSERVER_RULES.len());
    for (number, (rule, contract)) in rules.iter().zip(&OBSERVER_RULES).enumerate() {
        let lists = contract.lists();
        assert_eq!(lists.map(|(key, _)| key), RULE_KEYS);
        for (key, wanted) in lists {
            let found = match rule.get(key) {
                None | Some(Value::Null) => String::from("[]"),
                Some(value) => b1_support::canonical_text(value),
            };
            assert_eq!(found, texts(wanted).replace(", ", ","), "rule {} {key}", number + 1);
        }
    }
    assert_eq!(text(field(role, "metadata"), "name"), ROLE_NAME);
    let binding = &rows(positive, "clusterRoleBindings")[0];
    assert_eq!(text(field(binding, "metadata"), "name"), BINDING_NAME);
    let pairs = |items: &[(&str, &str)]| {
        format!("{{{}}}", items.iter().map(|(key, value)| format!("\"{key}\":\"{value}\"")).collect::<Vec<_>>().join(","))
    };
    assert_eq!(b1_support::canonical_text(field(binding, "roleRef")), pairs(&ROLE_REF[..]));
    assert_eq!(b1_support::canonical_text(field(binding, "subjects")), format!("[{}]", pairs(&SUBJECT[..])));
    assert_eq!((ROLE_REF[2].1, SUBJECT[1].1, SUBJECT[2].1), (ROLE_NAME, "User", OBSERVER_USER));
    assert_eq!(SERVER_METADATA, ["uid", "resourceVersion", "generation", "creationTimestamp", "managedFields"]);
    // The v4 snapshot positive equals v3's after one change: the observer's entry holds the contract role's resource
    // rules, built here from the constants as RB05 reads them.
    let snapshot_rules: Vec<String> = OBSERVER_RULES
        .iter()
        .filter(|rule| !rule.resources.is_empty())
        .map(|rule| format!(r#"{{"apiGroups": {}, "resources": {}, "verbs": {}, "resourceNames": [], "scope": "CLUSTER"}}"#,
                            texts(rule.api_groups), texts(rule.resources), texts(rule.verbs)))
        .collect();
    assert_eq!(snapshot_rules.len(), 7);
    let replace = parse(&format!(r#"{{"op": "set", "path": ["subjects", {{"kind": "User", "name": "{OBSERVER_USER}"}}, "effectiveRules"], "value": [{}]}}"#,
                                 snapshot_rules.join(", ")));
    let rebuilt = apply(field(&parse(V3_VECTORS), "snapshotPositive"), &[replace]);
    assert!(json::json_eq(&rebuilt, field(&v4, "snapshotPositive")));
}

// ------------------------------------------------------------------------------------------------ the replay

#[test]
fn the_object_cases_are_judged_as_the_vectors_state() {
    let v4 = parse(V4_VECTORS);
    let i07 = parse(I07_V3_VECTORS);
    let positive = field(&v4, "objectsPositive");
    assert_eq!(objects_verdict(positive), None, "the positive (HE-008's manifest form) is accepted");
    let mut count = 0;
    for (key, accepted) in [("objectsAccepted", true), ("objectsNegative", false)] {
        for row in rows(&v4, key) {
            let id = text(row, "id");
            if let Some(from) = row.get("fromI07").and_then(Value::as_str) {
                // K22 and K23: the I07 writer's RoleBinding, byte for byte the object of I07 v3's own case.
                let kind_check = case(&i07, &["kindChecks"], from);
                let ops = rows(row, "ops");
                assert_eq!(ops.len(), 1, "{id}");
                assert_eq!(b1_support::canonical_text(field(&ops[0], "path")), r#"["roleBindings"]"#, "{id}");
                assert_eq!(text(&ops[0], "op"), "append", "{id}");
                assert!(json::json_eq(field(&ops[0], "value"), field(field(kind_check, "payload"), "object")), "{id}");
            }
            let wanted = expected(row, "refusal");
            assert_eq!(wanted.is_none(), accepted, "{id}");
            assert_eq!(objects_verdict(&apply(positive, rows(row, "ops"))), wanted, "{id}");
            count += 1;
        }
    }
    assert_eq!(count, 67);
}

#[test]
fn the_snapshot_cases_are_judged_by_v3_and_by_v4_as_the_vectors_state() {
    let v4 = parse(V4_VECTORS);
    let closure = closure();
    let snapshot = field(&v4, "snapshotPositive");
    let namespace = text(&v4, "qualificationNamespace");
    assert_eq!((v3_verdict(&closure, snapshot, namespace), v4_verdict(&closure, snapshot, namespace)), (None, None));
    let mut count = 0;
    for (key, accepted) in [("snapshotAccepted", true), ("snapshotNegative", false)] {
        for row in rows(&v4, key) {
            let id = text(row, "id");
            let variant = apply(snapshot, rows(row, "ops"));
            let space = row_namespace(row, namespace);
            let wanted = expected(row, "refusal");
            assert_eq!(wanted.is_none(), accepted, "{id}");
            assert_eq!(v3_verdict(&closure, &variant, space), expected(row, "v3Result"), "{id} under v3");
            assert_eq!(v4_verdict(&closure, &variant, space), wanted, "{id} under v4");
            count += 1;
        }
    }
    assert_eq!(count, 16);
}

#[test]
fn v3_s_snapshot_cases_keep_their_results_on_the_v4_positive() {
    let v4 = parse(V4_VECTORS);
    let v3 = parse(V3_VECTORS);
    let closure = closure();
    let snapshot = field(&v4, "snapshotPositive");
    let namespace = text(&v4, "qualificationNamespace");
    let mut count = 0;
    for (key, accepted) in [("snapshotAccepted", true), ("snapshotNegative", false)] {
        for row in rows(&v3, key) {
            let id = text(row, "id");
            let wanted = expected(row, "refusal");
            assert_eq!(wanted.is_none(), accepted, "{id}");
            let variant = apply(snapshot, rows(row, "ops"));
            assert_eq!(v4_verdict(&closure, &variant, row_namespace(row, namespace)), wanted, "v3 {id}");
            count += 1;
        }
    }
    assert_eq!(count, 43);
}

#[test]
fn the_cross_version_cases_hold_under_both_versions() {
    let v4 = parse(V4_VECTORS);
    let v3 = parse(V3_VECTORS);
    let closure = closure();
    let namespace = text(&v4, "qualificationNamespace");
    let mut count = 0;
    for row in rows(&v4, "crossVersion") {
        let id = text(row, "id");
        let base = match text(row, "base") {
            "v3" => field(&v3, "snapshotPositive"),
            "v4" => field(&v4, "snapshotPositive"),
            other => panic!("{id}: base {other}"),
        };
        let variant = apply(base, rows(row, "ops"));
        let space = row_namespace(row, namespace);
        assert_eq!(v3_verdict(&closure, &variant, space), expected(row, "v3Result"), "{id} under v3");
        assert_eq!(v4_verdict(&closure, &variant, space), expected(row, "v4Result"), "{id} under v4");
        count += 1;
    }
    assert_eq!(count, 6);
}

#[test]
fn the_composed_cases_are_judged_in_observe_rs_s_order() {
    let v4 = parse(V4_VECTORS);
    let closure = closure();
    let snapshot = field(&v4, "snapshotPositive");
    let objects = field(&v4, "objectsPositive");
    let namespace = text(&v4, "qualificationNamespace");
    assert_eq!(observer_verdict(&closure, snapshot, objects, namespace), None);
    let ops_of = |row: &Value, key: &str, sections: &[&str]| -> Vec<Value> {
        match row.get(key).and_then(Value::as_str) {
            Some(id) => rows(case(&v4, sections, id), "ops").to_vec(),
            None => Vec::new(),
        }
    };
    let mut count = 0;
    for row in rows(&v4, "composed") {
        let id = text(row, "id");
        let snapshot_ops = ops_of(row, "snapshotCase", &["snapshotAccepted", "snapshotNegative"]);
        let object_ops = ops_of(row, "objectsCase", &["objectsAccepted", "objectsNegative"]);
        let verdict = observer_verdict(&closure, &apply(snapshot, &snapshot_ops), &apply(objects, &object_ops), namespace);
        assert_eq!(verdict, expected(row, "refusal"), "{id}");
        count += 1;
    }
    assert_eq!(count, 7);
}

// ------------------------------------------------------------------------------------------------ R10's own cases

#[test]
fn r10_s_texts_for_the_forms_no_vector_pins_and_the_model_s_readings() {
    let v4 = parse(V4_VECTORS);
    let positive = field(&v4, "objectsPositive");
    let judged = |ops: &str| objects_verdict(&apply(positive, parse(ops).as_array().expect("ops")));
    let refused = |ops: &str, wanted: &str| assert_eq!(judged(ops).as_deref(), Some(wanted), "{ops}");
    // RB02's two forms no vector pins, in R10's words; a null rules member is no rules (the model's reading).
    refused(r#"[{"op": "set", "path": ["clusterRoles", 0, "rules"], "value": "all"}]"#,
            "RB02 the observer ClusterRole's rules member is no array");
    refused(r#"[{"op": "set", "path": ["clusterRoles", 0, "rules", 2, "verbs"], "value": ["list", 7]}]"#,
            "RB02 the observer ClusterRole's rule 3 is not an object of text lists");
    refused(r#"[{"op": "set", "path": ["clusterRoles", 0, "rules", 4], "value": "apiservices"}]"#,
            "RB02 the observer ClusterRole's rule 5 is not an object of text lists");
    refused(r#"[{"op": "set", "path": ["clusterRoles", 0, "rules"], "value": null}]"#,
            "RB02 the observer ClusterRole holds 0 rules, the contract 8");
    // Unknown members are listed sorted and joined; RB03's shape refusals follow RB01's form.
    refused(r#"[{"op": "set", "path": ["clusterRoles", 0, "zeta"], "value": 1}, {"op": "set", "path": ["clusterRoles", 0, "alpha"], "value": 1}]"#,
            "RB01 the observer ClusterRole holds an unknown member: alpha,zeta");
    refused(r#"[{"op": "set", "path": ["clusterRoleBindings", 0, "spec"], "value": {}}]"#,
            "RB03 the observer ClusterRoleBinding holds an unknown member: spec");
    refused(r#"[{"op": "set", "path": ["clusterRoleBindings", 0, "kind"], "value": "RoleBinding"}]"#,
            "RB03 the observer ClusterRoleBinding's kind or apiVersion differs");
    // A RoleBinding whose namespace is no string is placed without one; a selector key with white space is unreadable.
    refused(r#"[{"op": "append", "path": ["roleBindings"], "value": {"metadata": {"name": "odd", "namespace": 5}, "roleRef": {"kind": "ClusterRole", "name": "planeon:policy-observer"}}}]"#,
            "RB07 a binding other than the contract's references the observer ClusterRole: RoleBinding/odd");
    refused(r#"[{"op": "append", "path": ["clusterRoles"], "value": {"metadata": {"name": "spaced"}, "aggregationRule": {"clusterRoleSelectors": [{"matchExpressions": [{"key": " tier", "operator": "Exists"}]}]}}}]"#,
            "RB07 an aggregationRule selector is malformed: ClusterRole/spaced");
    // An item without a plain-text name, and object forms that are not the three lists.
    refused(r#"[{"op": "append", "path": ["roleBindings"], "value": {"metadata": {"name": "x "}}}]"#, "RB01 closed RBAC object lists");
    for objects in ["[]", r#"{"clusterRoles": [], "clusterRoleBindings": []}"#,
                    r#"{"clusterRoles": [], "clusterRoleBindings": [], "roleBindings": [], "roles": []}"#,
                    r#"{"clusterRoles": {}, "clusterRoleBindings": [], "roleBindings": []}"#] {
        assert_eq!(objects_verdict(&parse(objects)).as_deref(), Some("RB01 closed RBAC object lists"), "{objects}");
    }
    // Accepted: server metadata on both objects, an Exists or In selector beside empty labels, a Group named like the
    // observer, a binding to a Role named like the role.
    for ops in [r#"[{"op": "set", "path": ["clusterRoleBindings", 0, "metadata", "managedFields"], "value": []}, {"op": "set", "path": ["clusterRoles", 0, "metadata", "generation"], "value": 3}]"#,
                r#"[{"op": "append", "path": ["clusterRoles"], "value": {"metadata": {"name": "agg"}, "aggregationRule": {"clusterRoleSelectors": [{"matchLabels": {}, "matchExpressions": [{"key": "tier", "operator": "In", "values": ["a"]}]}]}}}]"#,
                r#"[{"op": "append", "path": ["clusterRoleBindings"], "value": {"metadata": {"name": "groups"}, "roleRef": {"kind": "ClusterRole", "name": "view"}, "subjects": [{"kind": "Group", "name": "planeon:policy-observer"}]}}]"#] {
        assert_eq!(judged(ops), None, "{ops}");
    }
    // RB05 alone: the observer twice, or a snapshot that is no object, is "absent".
    let snapshot = field(&v4, "snapshotPositive");
    let twice = apply(snapshot, &[parse(r#"{"op": "append", "path": ["subjects"], "value": {"kind": "User", "name": "planeon:policy-observer", "exists": true, "effectiveRules": []}}"#)]);
    for value in [&twice, &parse("[]")] {
        assert_eq!(check_effective_rules(value).map_err(|refusal| refusal.text().to_string()),
                   Err("RB05 the observer is absent from the RBAC snapshot".to_string()));
    }
    assert_eq!(check_effective_rules(snapshot), Ok(()));
}

// ------------------------------------------------------------------------------------------------ the epoch

#[test]
fn a_read_the_role_pin_refuses_ends_the_epoch_with_87() {
    // The rig's default read passes: the observer's grants are the contract role's alone.
    let rig = Rig::new();
    assert_eq!(rig.run().0, ObserverExit::ConfigExpired);
    // An unbound ClusterRole that aggregates everything: B1's producer and the closure check pass it, RB07 refuses.
    let rig = Rig::new();
    rig.api(|api| api.lists.get_mut(&Resource::ClusterRoles).expect("roles")
        .push(aggregated_role("aggregate-all", r#"{"clusterRoleSelectors": [{}]}"#)));
    let (exit, epoch) = rig.run();
    assert_eq!((exit, epoch.reason()), (ObserverExit::Rbac, "I06 v4's role pin refused"));
    assert_eq!(status::observation(&exit), 87);
    // A label on the contract role (RB01) beside a service-account token (OR05's 88): the role pin runs first.
    let rig = Rig::new();
    rig.api(|api| {
        let roles = api.lists.get_mut(&Resource::ClusterRoles).expect("roles");
        let role = roles.iter_mut().find(|role| role.starts_with(r#"{"metadata": {"name": "planeon:policy-observer"}"#)).expect("the role");
        *role = role.replacen(r#""name": "planeon:policy-observer"}"#, r#""name": "planeon:policy-observer", "labels": {"team": "x"}}"#, 1);
        api.lists.insert(Resource::ServiceAccountTokenSecrets,
                         vec![r#"{"metadata": {"name": "token", "namespace": "unit-namespace"}}"#.to_string()]);
    });
    let (exit, epoch) = rig.run();
    assert_eq!((exit, epoch.reason()), (ObserverExit::Rbac, "I06 v4's role pin refused"));
}
