//! HE-004-I01B1, the A2 render (DESIGN-I01B rev 3 section 2 and DESIGN-I01B1 rev 2; the monitor's Q-I01B-15 (a)):
//! `i01_admission_render` held to admission v3's vectors and to the I01 digest contract's admission vectors.
//!
//! - Admission v3 (`contracts/admission-v3/`, pinned by `tools/gate.py`): the render of the vectors' sealed values is
//!   the vendored `admission-manifests/planeon-a2.json` byte for byte, its directory hash is H01's and the vectors'
//!   pinned `manifestDirectoryHash`, and its eight objects are the file's items; each of the nine `objects` vectors (a
//!   changed or extra object, S01-S06b) differs from the render.
//! - The digest contract (`contracts/i01-digests-v1/vectors.json`): every vector that pins `admissionFenceDigest`'s
//!   digest (2: P-UNIT, AF-01, the repository's manifest) is the render's directory hash for the vector's sealed
//!   values, and every vector that pins `admissionPolicy`'s document (3: P-UNIT, AP-09, AP-11) holds the render's
//!   objects, sorted by (kind, name), as its `sealedObjects`.
//! - The render fits `i01_digest`'s render argument (`&dyn Fn(&SealedAdmission) -> Option<Rendered>`); the digest
//!   replay hands it in.

mod b1_support;

use b1_support::{apply, field, parse, rows, text};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;
use planeon_observer::i01_admission_render::{self, MANIFEST_FILE};
use planeon_observer::i01_digest::{Rendered, SealedAdmission};

const ADMISSION_VECTORS: &[u8] = include_bytes!("../../../contracts/admission-v3/vectors.json");
const SEALED_FILE: &[u8] = include_bytes!("../../../contracts/admission-v3/admission-manifests/planeon-a2.json");
const DIGEST_VECTORS: &[u8] = include_bytes!("../../../contracts/i01-digests-v1/vectors.json");
/// The three vendored files' sha256 and sizes (PROVENANCE's admission v3 lines and edge record v10's row 70).
const PINS: [(&str, &[u8], &str, usize); 3] = [
    ("admission-v3/vectors.json", ADMISSION_VECTORS, "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
     249_833),
    ("admission-v3/admission-manifests/planeon-a2.json", SEALED_FILE,
     "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741", 8_126),
    ("i01-digests-v1/vectors.json", DIGEST_VECTORS, "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
     468_843),
];
/// Admission v3's nine `objects` vectors, in file order.
const OBJECTS_VECTORS: [&str; 9] = ["S01", "S02", "S03", "S03b", "S03c", "S04", "S05", "S06", "S06b"];
/// The contract's vectors that pin the admission fence digest, and those that pin the admission policy's document.
const FENCE_VECTORS: [&str; 2] = ["P-UNIT", "AF-01"];
const DOCUMENT_VECTORS: [&str; 3] = ["P-UNIT", "AP-09", "AP-11"];

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
    assert!(render(&sealed("planeon-qual", field(&vectors, "sealed"))).is_some());
}

#[test]
fn the_render_of_admission_v3_s_sealed_values_is_the_vendored_manifest() {
    let vectors = parse(from_utf8(ADMISSION_VECTORS));
    let values = field(&vectors, "sealed");
    let pinned = field(&vectors, "pinned");
    assert_eq!(text(values, "namespace"), text(pinned, "namespace"));
    let sealed = sealed(text(values, "namespace"), values);
    assert_eq!(MANIFEST_FILE, "planeon-a2.json");
    // The directory's one file, byte for byte.
    assert_eq!(i01_admission_render::manifest_file_bytes(&sealed), SEALED_FILE);
    // Its hash: the pinned value and H01's, whose one file is the vendored manifest.
    let rendered = i01_admission_render::render(&sealed).expect("a render");
    assert_eq!(rendered.directory_hash, text(pinned, "manifestDirectoryHash"));
    let h01 = rows(&vectors, "directoryHash").first().expect("H01");
    assert_eq!(text(h01, "id"), "H01");
    assert_eq!(field(h01, "files").as_object().map(Object::len), Some(1));
    assert_eq!(text(field(h01, "files"), MANIFEST_FILE).as_bytes(), SEALED_FILE);
    assert_eq!(rendered.directory_hash, text(h01, "expect"));
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
fn each_admission_v3_objects_vector_differs_from_the_render() {
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
    // The unit fixture's configuration pins the render of its own sealed values, as ADM-4's loaded hash does.
    let unit = field(field(fixtures, "snapshots"), "unit");
    let configuration = field(unit, "configuration");
    let sealed = sealed(text(configuration, "qualificationNamespace"), field(configuration, "sealedAdmission"));
    let hash = i01_admission_render::render(&sealed).expect("a render").directory_hash;
    assert_eq!(hash, text(configuration, "pinnedManifestHash"));
    assert_eq!(hash, text(unit, "adm4LoadedHash"));
}
