//! HE-004-I01B1, the A2 render (DESIGN-I01B rev 3 section 2 and DESIGN-I01B1 rev 2; the monitor's Q-I01B-15 (a)),
//! moved to admission v4 by HE-004-I01B4 (DESIGN-I01B4 rev 2 section 4.2; Q-I01B4-2, Q-I01B4-11; I4D-9):
//! `i01_admission_render` held to admission v4's vectors and to the I01 digest contract v2's admission vectors. Every
//! assertion of I01B1's v3 replay is kept, with v4's values.
//!
//! - Admission v4 (`contracts/admission-v4/`, edge record v11's rows 77 and 78, pinned by `tools/gate.py`): the render
//!   of the vectors' sealed values is the vendored `admission-manifests/planeon-a2.json` byte for byte, its directory
//!   hash is H01's, H02's and the vectors' pinned `manifestDirectoryHash`, and its eight objects are the file's items;
//!   the sealed and pinned namespace is `planeon-qual`, the literal the digest replay's sixth complete check uses (the
//!   head layer's analogue); each of the eleven `objects` vectors (a changed or extra object, S01-S06d) differs from
//!   the render.
//! - The digest contract v2 (`contracts/i01-digests-v2/vectors.json`, row 74): every vector that pins
//!   `admissionFenceDigest`'s digest (2: P-UNIT, AF-01) is the render's directory hash for the vector's sealed values,
//!   and every vector that pins `admissionPolicy`'s document (3: P-UNIT, AP-09, AP-11) holds the render's objects,
//!   sorted by (kind, name), as its `sealedObjects`; the `unit` fixture's two hashes are the render at
//!   `unit-namespace`, and the `qual` fixture's the render at `planeon-qual`.
//! - The edit's extent: the v4 render differs from the held admission v3 file (edge record row 43) only in the Pod
//!   policy's validations, A2-POD-PULL-POLICY's two `'Always'` read `'Never'` and A2-POD-EMPTYDIR appended. This
//!   documents DESIGN-I01B4 section 2.1's extent against pinned data; it is not an independent check of the render.
//! - The render fits `i01_digest`'s render argument (`&dyn Fn(&SealedAdmission) -> Option<Rendered>`); the digest
//!   replay hands it in.

mod b1_support;

use b1_support::{apply, field, parse, rows, text};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::i01_admission_render::{self, MANIFEST_FILE};
use planeon_observer::i01_digest::{Rendered, SealedAdmission};

const ADMISSION_VECTORS: &[u8] = include_bytes!("../../../contracts/admission-v4/vectors.json");
const SEALED_FILE: &[u8] = include_bytes!("../../../contracts/admission-v4/admission-manifests/planeon-a2.json");
const DIGEST_VECTORS: &[u8] = include_bytes!("../../../contracts/i01-digests-v2/vectors.json");
/// The held admission v3 sealed file (edge record row 43), read only for the edit's extent.
const HELD_V3_SEALED_FILE: &[u8] = include_bytes!("../../../contracts/admission-v3/admission-manifests/planeon-a2.json");
/// The four vendored files' sha256 and sizes (edge record v11's rows 77, 78 and 74, and PROVENANCE's admission v3
/// line for the held file).
const PINS: [(&str, &[u8], &str, usize); 4] = [
    ("admission-v4/vectors.json", ADMISSION_VECTORS, "5706b1a8df5cabd978caa219400b40a9c4ef6cbdbca8ea2f7c6f69b69474301c",
     316_811),
    ("admission-v4/admission-manifests/planeon-a2.json", SEALED_FILE,
     "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32", 8_322),
    ("i01-digests-v2/vectors.json", DIGEST_VECTORS, "68eab4709431f73ce6f977aad7e5a087dccf9b5635c4ce04b8c08387bdce2594",
     602_663),
    ("admission-v3/admission-manifests/planeon-a2.json", HELD_V3_SEALED_FILE,
     "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741", 8_126),
];
/// Admission v4's eleven `objects` vectors, in file order.
const OBJECTS_VECTORS: [&str; 11] = ["S01", "S02", "S03", "S03b", "S03c", "S04", "S05", "S06", "S06b", "S06c", "S06d"];
/// The contract's vectors that pin the admission fence digest, and those that pin the admission policy's document.
const FENCE_VECTORS: [&str; 2] = ["P-UNIT", "AF-01"];
const DOCUMENT_VECTORS: [&str; 3] = ["P-UNIT", "AP-09", "AP-11"];
/// The sealed namespace: admission v4's `sealed.namespace` and the v2 model's `SEALED_NAMESPACE`
/// (harness-onion `scripts/policy_observation_digests_v2.py:63`), the literal of the digest replay's sixth complete
/// check.
const SEALED_NAMESPACE: &str = "planeon-qual";
/// Admission v4's directory hash (the pinned value, H01's and H02's), and the render's at `unit-namespace`.
const V4_HASH: &str = "sha256:9b1ddc1096ff0d35fb4cd5a9e5e6b4248fefc5b75b5a06f862c59d85e028ca60";
const UNIT_HASH: &str = "sha256:8004085f93b447942e2aeffd00856e7dc485a063445a40c3518c60d6bd3c503f";
/// The Pod policy, the row v4 changes, and the row v4 appends (its rule id, then its CEL expression, as admission v4's
/// model writes the row: harness-onion `scripts/admission_semantics_v4.py:463-466`).
const POD_POLICY: &str = "planeon-a2-pod.static.k8s.io";
const PULL_POLICY: &str = "A2-POD-PULL-POLICY";
const EMPTYDIR_RULE: &str = "A2-POD-EMPTYDIR";
const EMPTYDIR_EXPRESSION: &str = "!has(object.spec.volumes) || object.spec.volumes.all(v, !has(v.emptyDir) || \
                                   (has(v.emptyDir.sizeLimit) && !has(v.emptyDir.medium)))";

fn from_utf8(raw: &[u8]) -> &str {
    std::str::from_utf8(raw).expect("the vendored file is UTF-8")
}

fn hex(data: &[u8]) -> String {
    sha256::hex(&sha256::digest(data))
}

/// Four sealed values: the namespace and the three `sealedAdmission` members.
fn sealed(namespace: &str, values: &Value) -> SealedAdmission {
    let seconds = field(values, "defaultTolerationSeconds").as_int().and_then(|int| int.to_i64());
    SealedAdmission {
        namespace: namespace.to_string(),
        ip_family: text(values, "ipFamily").to_string(),
        service_cidr: text(values, "serviceCIDR").to_string(),
        default_toleration_seconds: seconds.expect("an integer"),
    }
}

/// A rendered object's (kind, name).
fn kind_and_name(object: &Value) -> (String, String) {
    (text(object, "kind").to_string(), text(field(object, "metadata"), "name").to_string())
}

/// An object's member names, sorted.
fn names(object: &Value) -> Vec<String> {
    let members = object.as_object().expect("an object");
    let mut names: Vec<String> =
        members.iter().map(|(name, _)| name.as_str().expect("a UTF-8 name").to_string()).collect();
    names.sort();
    names
}

/// A vector's inputs as the model builds them (the named snapshot fixture, binding and capture, then its operations).
fn combined(fixtures: &Value, row: &Value) -> Value {
    let mut members = Object::new();
    members.insert(JStr::new("snapshot"), field(field(fixtures, "snapshots"), text(row, "snapshot")).clone());
    members.insert(JStr::new("binding"), field(field(fixtures, "bindings"), text(row, "binding")).clone());
    members.insert(JStr::new("capture"), field(field(fixtures, "captures"), text(row, "capture")).clone());
    apply(&Value::Object(members), rows(row, "ops"))
}

#[test]
fn the_vendored_files_are_pinned() {
    for (name, bytes, digest, size) in PINS {
        assert_eq!((hex(bytes), bytes.len()), (digest.to_string(), size), "contracts/{name}");
    }
    // The render fits i01_digest's render argument.
    let render: &dyn Fn(&SealedAdmission) -> Option<Rendered> = &i01_admission_render::render;
    let vectors = parse(from_utf8(ADMISSION_VECTORS));
    assert!(render(&sealed(SEALED_NAMESPACE, field(&vectors, "sealed"))).is_some());
}

#[test]
fn the_render_of_admission_v4_s_sealed_values_is_the_vendored_manifest() {
    let vectors = parse(from_utf8(ADMISSION_VECTORS));
    let values = field(&vectors, "sealed");
    let pinned = field(&vectors, "pinned");
    assert_eq!(text(values, "namespace"), text(pinned, "namespace"));
    // The head layer's analogue: the sealed and pinned namespace is the literal the digest replay's sixth check uses.
    assert_eq!(text(values, "namespace"), SEALED_NAMESPACE);
    let sealed = sealed(text(values, "namespace"), values);
    assert_eq!((sealed.ip_family.as_str(), sealed.service_cidr.as_str(), sealed.default_toleration_seconds),
               ("IPv4", "10.96.0.0/12", 300));
    assert_eq!(MANIFEST_FILE, "planeon-a2.json");
    // The directory's one file, byte for byte.
    assert_eq!(i01_admission_render::manifest_file_bytes(&sealed), SEALED_FILE);
    // Its hash: the pinned value and H01's, whose one file is the vendored manifest, and H02's (that file beside a
    // README, which the loader does not hash).
    let rendered = i01_admission_render::render(&sealed).expect("a render");
    assert_eq!(rendered.directory_hash, text(pinned, "manifestDirectoryHash"));
    assert_eq!(rendered.directory_hash, V4_HASH);
    let hashes = rows(&vectors, "directoryHash");
    let h01 = hashes.first().expect("H01");
    assert_eq!(text(h01, "id"), "H01");
    assert_eq!(field(h01, "files").as_object().map(Object::len), Some(1));
    assert_eq!(text(field(h01, "files"), MANIFEST_FILE).as_bytes(), SEALED_FILE);
    assert_eq!(rendered.directory_hash, text(h01, "expect"));
    let h02 = hashes.get(1).expect("H02");
    assert_eq!(text(h02, "id"), "H02");
    assert_eq!(field(h02, "files").as_object().map(Object::len), Some(2));
    assert_eq!(text(field(h02, "files"), MANIFEST_FILE).as_bytes(), SEALED_FILE);
    assert_eq!(rendered.directory_hash, text(h02, "expect"));
    // The eight objects are the file's items, four policies and their four bindings.
    let file = parse(from_utf8(SEALED_FILE));
    let items = rows(&file, "items");
    assert_eq!(rendered.objects.len(), 8);
    assert!(json::json_eq(&Value::Array(rendered.objects.clone()), field(&file, "items")));
    let kinds: Vec<String> = items.iter().map(|item| kind_and_name(item).0).collect();
    assert_eq!(kinds.iter().filter(|kind| *kind == "ValidatingAdmissionPolicy").count(), 4);
    assert_eq!(kinds.iter().filter(|kind| *kind == "ValidatingAdmissionPolicyBinding").count(), 4);
    assert_eq!(i01_admission_render::a2_objects(&sealed).len(), 8);
    // Another sealed value renders other bytes and another hash.
    let mut other = sealed.clone();
    other.service_cidr = "10.97.0.0/16".to_string();
    let changed = i01_admission_render::render(&other).expect("a render");
    assert_ne!(changed.directory_hash, rendered.directory_hash);
    assert_ne!(i01_admission_render::manifest_file_bytes(&other), SEALED_FILE);
}

#[test]
fn each_admission_v4_objects_vector_differs_from_the_render() {
    let vectors = parse(from_utf8(ADMISSION_VECTORS));
    let values = field(&vectors, "sealed");
    let rendered = i01_admission_render::render(&sealed(text(values, "namespace"), values)).expect("a render");
    let rendered = Value::Array(rendered.objects);
    let mut ids = Vec::new();
    for row in rows(&vectors, "objects") {
        ids.push(text(row, "id").to_string());
        assert!(!json::json_eq(field(row, "objects"), &rendered), "{}", text(row, "id"));
    }
    assert_eq!(ids, OBJECTS_VECTORS);
}

#[test]
fn the_contract_s_admission_vectors_hold_the_render() {
    let vectors = parse(from_utf8(DIGEST_VECTORS));
    let fixtures = field(&vectors, "fixtures");
    let (mut fences, mut documents) = (Vec::new(), Vec::new());
    for row in rows(&vectors, "vectors") {
        let id = text(row, "id");
        let expect = field(row, "expect");
        let fence = expect.get("enforcement").and_then(|digests| digests.get("admissionFenceDigest"))
                          .and_then(|want| want.get("digest"));
        let document = expect.get("projections").and_then(|projections| projections.get("admissionPolicy"))
                             .and_then(|want| want.get("document"));
        if fence.is_none() && document.is_none() {
            continue;
        }
        let inputs = combined(fixtures, row);
        let configuration = field(field(&inputs, "snapshot"), "configuration");
        let sealed = sealed(text(configuration, "qualificationNamespace"), field(configuration, "sealedAdmission"));
        let rendered = i01_admission_render::render(&sealed).expect("a render");
        if let Some(want) = fence {
            assert_eq!(Some(rendered.directory_hash.as_str()), want.as_str(), "vector {id}");
            fences.push(id.to_string());
        }
        if let Some(want) = document {
            let mut objects = rendered.objects.clone();
            objects.sort_by_key(kind_and_name);
            assert!(json::json_eq(&Value::Array(objects), field(field(want, "spec"), "sealedObjects")), "vector {id}");
            documents.push(id.to_string());
        }
    }
    assert_eq!(fences, FENCE_VECTORS);
    assert_eq!(documents, DOCUMENT_VECTORS);
    // The unit fixture's configuration pins the render of its own sealed values, as ADM-4's loaded hash does; the qual
    // fixture's, at the sealed namespace, is admission v4's pinned hash.
    for (snapshot, namespace, want) in [("unit", "unit-namespace", UNIT_HASH), ("qual", SEALED_NAMESPACE, V4_HASH)] {
        let fixture = field(field(fixtures, "snapshots"), snapshot);
        let configuration = field(fixture, "configuration");
        assert_eq!(text(configuration, "qualificationNamespace"), namespace, "{snapshot}");
        let sealed = sealed(text(configuration, "qualificationNamespace"), field(configuration, "sealedAdmission"));
        let hash = i01_admission_render::render(&sealed).expect("a render").directory_hash;
        assert_eq!(hash, text(configuration, "pinnedManifestHash"), "{snapshot}");
        assert_eq!(hash, text(fixture, "adm4LoadedHash"), "{snapshot}");
        assert_eq!(hash, want, "{snapshot}");
    }
}

#[test]
fn the_v4_render_differs_from_the_held_v3_file_only_in_the_pod_rows() {
    let vectors = parse(from_utf8(ADMISSION_VECTORS));
    let values = field(&vectors, "sealed");
    let rendered = i01_admission_render::render(&sealed(text(values, "namespace"), values)).expect("a render");
    let held = parse(from_utf8(HELD_V3_SEALED_FILE));
    let items = rows(&held, "items");
    assert_eq!(rendered.objects.len(), items.len());
    let mut pod_policies = 0;
    for (new, old) in rendered.objects.iter().zip(items) {
        // The same eight items in the same order; every one but the Pod policy is equal.
        assert_eq!(kind_and_name(new), kind_and_name(old));
        if kind_and_name(old) != ("ValidatingAdmissionPolicy".to_string(), POD_POLICY.to_string()) {
            assert!(json::json_eq(new, old), "{:?}", kind_and_name(old));
            continue;
        }
        pod_policies += 1;
        // Every member of the Pod policy but spec.validations is equal.
        assert_eq!(names(new), names(old));
        for name in names(old).iter().filter(|name| *name != "spec") {
            assert!(json::json_eq(field(new, name), field(old, name)), "{name}");
        }
        let (new_spec, old_spec) = (field(new, "spec"), field(old, "spec"));
        assert_eq!(names(new_spec), names(old_spec));
        for name in names(old_spec).iter().filter(|name| *name != "validations") {
            assert!(json::json_eq(field(new_spec, name), field(old_spec, name)), "spec.{name}");
        }
        // The first nine rows are v3's, except that A2-POD-PULL-POLICY's two 'Always' read 'Never'.
        let (new_rows, old_rows) = (rows(new_spec, "validations"), rows(old_spec, "validations"));
        assert_eq!((old_rows.len(), new_rows.len()), (9, 10));
        for (index, (new_row, old_row)) in new_rows.iter().zip(old_rows).enumerate() {
            if text(old_row, "message") != PULL_POLICY {
                assert!(json::json_eq(new_row, old_row), "row {index}");
                continue;
            }
            assert_eq!(index, 8);
            assert_eq!(names(new_row), names(old_row));
            assert_eq!(text(old_row, "expression").matches("'Always'").count(), 2);
            assert_eq!(text(new_row, "expression"), text(old_row, "expression").replace("'Always'", "'Never'"));
            assert_eq!((text(new_row, "message"), text(new_row, "reason")), (PULL_POLICY, text(old_row, "reason")));
        }
        // The tenth row is A2-POD-EMPTYDIR.
        let last = new_rows.last().expect("the tenth row");
        assert_eq!(names(last), ["expression", "message", "reason"]);
        assert_eq!((text(last, "message"), text(last, "expression"), text(last, "reason")),
                   (EMPTYDIR_RULE, EMPTYDIR_EXPRESSION, "Forbidden"));
    }
    assert_eq!(pod_policies, 1);
}
