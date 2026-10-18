//! HE-004B1 DESIGN-B section 4.5 (D1-4, D1-16, D2-3; Q-HE4B-8 (a), Q-HE4B-12 (a)) and section 8: the reference directory
//! hash (H01-H04 and R10-local cases), the pre-ACTIVE comparison's verdicts (claims Q06 and Q07 through it), the
//! observation binding's checks, and the record's canonical bytes and digest.

mod b1_support;

use b1_support::{field, parse, rows, text};
use i05_protocol::json::Value;
use planeon_observer::admission::{
    check_loaded_manifest, manifest_directory_hash, Adm4Input, Adm4InputError, BindingId, HashError, MetricSample,
    ObservationBinding, Verdict, ACCEPTED_KUBERNETES_VERSION, METRIC_NAME, RECORD_VERSION,
};

const VECTORS: &str = include_str!("../../../contracts/admission-v3/vectors.json");
const SEALED: &[u8] = include_bytes!("../../../contracts/admission-v3/admission-manifests/planeon-a2.json");
const PINNED: &str = "sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189";
const PLUGIN: &str = "ValidatingAdmissionPolicy";
const APISERVER: &str = "sha256:abababababababababababababababababababababababababababababababab";

// ------------------------------------------------------------------------------------------------ the directory hash

#[test]
fn h01_to_h04_replay() {
    let vectors = parse(VECTORS);
    let mut ids = Vec::new();
    for row in rows(&vectors, "directoryHash") {
        let files: Vec<(String, Vec<u8>)> = field(row, "files").as_object().expect("files").iter()
            .map(|(name, content)| (name.as_str().expect("name").to_string(), content.as_str().expect("text").as_bytes().to_vec()))
            .collect();
        let entries: Vec<(&str, &[u8])> = files.iter().map(|(name, content)| (name.as_str(), content.as_slice())).collect();
        assert_eq!(manifest_directory_hash(&entries).expect("a hash"), text(row, "expect"), "{}", text(row, "id"));
        ids.push(text(row, "id").to_string());
    }
    assert_eq!(ids, ["H01", "H02", "H03", "H04"]);
    // H01's input is the vendored manifest: its bytes give the pinned hash, which is the vectors' pinned value.
    assert_eq!(manifest_directory_hash(&[("planeon-a2.json", SEALED)]).expect("a hash"), PINNED);
    assert_eq!(text(field(&vectors, "pinned"), "manifestDirectoryHash"), PINNED);
    let h01 = rows(&vectors, "directoryHash").first().expect("H01");
    assert_eq!(text(field(h01, "files"), "planeon-a2.json").as_bytes(), SEALED);
}

#[test]
fn the_r10_local_hash_cases() {
    let hash = |entries: &[(&str, &[u8])]| manifest_directory_hash(entries).expect("a hash");
    // An empty .yaml is skipped; README.txt is skipped; .JSON and .YmL are read, as their lower-case names.
    assert_eq!(hash(&[("planeon-a2.json", SEALED), ("empty.yaml", b"")]), PINNED);
    assert_eq!(hash(&[("planeon-a2.json", SEALED), ("README.txt", b"x")]), PINNED);
    assert_eq!(hash(&[("PLANEON-A2.JSON", SEALED)]), PINNED);
    assert_eq!(hash(&[("a.YmL", b"{}")]), hash(&[("a.yml", b"{}")]));
    for skipped in ["x.yaml.bak", "json", "x.jso", "x.yamll", ".json.txt"] {
        assert_eq!(hash(&[(skipped, b"{}")]), "", "{skipped}");
    }
    assert_eq!(hash(&[(".json", b"{}")]), hash(&[("z.json", b"{}")]), "a dot file with the suffix is read");
    // Byte order of the names, whatever the input order; contents chained with one NUL each.
    assert_eq!(hash(&[("z-extra.yaml", b"{}"), ("planeon-a2.json", SEALED)]),
               "sha256:0aa22ee6dd088e896b1e8a2b237f1a9ec4dc7ade5dc3159a64cf609589a9ef20");
    assert_ne!(hash(&[("a.json", b"1"), ("b.json", b"2")]), hash(&[("a.json", b"2"), ("b.json", b"1")]));
    assert_eq!(hash(&[("B.json", b"x"), ("a.json", b"y")]), hash(&[("a.json", b"y"), ("B.json", b"x")]));
    assert_ne!(hash(&[("a.json", b"xy")]), hash(&[("a.json", b"x"), ("b.json", b"y")]));
    // No entry read: "", and the comparison refuses the empty value (below).
    assert_eq!(hash(&[]), "");
    assert_eq!(hash(&[("empty.json", b"")]), "");
    // Duplicate names refuse.
    assert_eq!(manifest_directory_hash(&[("a.yaml", b"1"), ("b.yaml", b"2"), ("a.yaml", b"3")]),
               Err(HashError::DuplicateName("a.yaml".to_string())));
}

// ------------------------------------------------------------------------------------------------ the comparison

fn binding() -> ObservationBinding {
    ObservationBinding {
        id: BindingId::RecordDigest("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
        window_start: "2026-10-17T12:00:00Z".to_string(),
        window_end: "2026-10-17T12:05:00Z".to_string(),
    }
}

fn sample(plugin: &str, hash: &str) -> MetricSample {
    MetricSample { plugin: plugin.to_string(), apiserver_id_hash: APISERVER.to_string(), hash: hash.to_string() }
}

fn input(samples: Vec<MetricSample>) -> Adm4Input {
    Adm4Input {
        pinned_hash: PINNED.to_string(),
        expected_plugin: PLUGIN.to_string(),
        samples,
        kubernetes_version: "v1.37.1".to_string(),
        binding: binding(),
    }
}

fn verdict(input: &Adm4Input) -> Verdict {
    check_loaded_manifest(input).expect("a record").verdict()
}

const OTHER: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn one_sample_of_the_expected_plugin_matches_or_mismatches() {
    let matched = check_loaded_manifest(&input(vec![sample(PLUGIN, PINNED)])).expect("a record");
    assert_eq!((matched.verdict(), matched.loaded_hash(), matched.pinned_hash(), matched.apiserver_id_hash()),
               (Verdict::Match, Some(PINNED), Some(PINNED), Some(APISERVER)));
    let differs = check_loaded_manifest(&input(vec![sample(PLUGIN, OTHER)])).expect("a record");
    assert_eq!((differs.verdict(), differs.loaded_hash()), (Verdict::Mismatch, Some(OTHER)));
}

#[test]
fn zero_or_several_samples_or_another_plugin_is_unavailable() {
    let none = check_loaded_manifest(&input(vec![])).expect("a record");
    assert_eq!((none.verdict(), none.loaded_hash(), none.apiserver_id_hash()), (Verdict::Unavailable, None, None));
    let several = check_loaded_manifest(&input(vec![sample(PLUGIN, PINNED), sample(PLUGIN, PINNED)])).expect("a record");
    assert_eq!((several.verdict(), several.loaded_hash()), (Verdict::Unavailable, None));
    // Another plugin's sample makes the comparison unavailable, even beside one sample of the expected plugin (which is
    // still recorded) and even when its hash equals the pinned one.
    let beside = check_loaded_manifest(&input(vec![sample(PLUGIN, PINNED), sample("MutatingAdmissionPolicy", PINNED)])).expect("a record");
    assert_eq!((beside.verdict(), beside.loaded_hash()), (Verdict::Unavailable, Some(PINNED)));
    assert_eq!(verdict(&input(vec![sample("MutatingAdmissionPolicy", PINNED)])), Verdict::Unavailable);
    assert_eq!(verdict(&input(vec![sample("validatingadmissionpolicy", PINNED)])), Verdict::Unavailable);
    let mut empty_plugin = input(vec![sample("", PINNED)]);
    empty_plugin.expected_plugin = String::new();
    assert_eq!(verdict(&empty_plugin), Verdict::Unavailable);
}

#[test]
fn only_the_accepted_kubernetes_version() {
    assert_eq!(ACCEPTED_KUBERNETES_VERSION, "v1.37.1");
    for version in ["v1.37.2", "v1.38.0", "1.37.1", "v1.37.1+k3s1", "", "V1.37.1"] {
        let mut other = input(vec![sample(PLUGIN, PINNED)]);
        other.kubernetes_version = version.to_string();
        let record = check_loaded_manifest(&other).expect("a record");
        assert_eq!(record.verdict(), Verdict::Unavailable, "{version}");
        assert!(String::from_utf8(record.canonical()).expect("UTF-8").contains(&format!(r#""kubernetesVersion":"{version}""#)));
    }
}

#[test]
fn malformed_or_empty_hashes_are_unavailable_and_recorded_as_null() {
    for bad in ["", "sha256:", "SHA256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189",
                "sha256:5AA2CDEC0B8DC08C008B887E30B9954FFC46E7D779365F64DB1ADFD80656F189",
                "5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189",
                "sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f18",
                "sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f1890",
                "sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f18g", " sha256:5aa2"] {
        let loaded = check_loaded_manifest(&input(vec![sample(PLUGIN, bad)])).expect("a record");
        assert_eq!((loaded.verdict(), loaded.loaded_hash()), (Verdict::Unavailable, None), "loaded {bad:?}");
        let mut pinned = input(vec![sample(PLUGIN, PINNED)]);
        pinned.pinned_hash = bad.to_string();
        let record = check_loaded_manifest(&pinned).expect("a record");
        assert_eq!((record.verdict(), record.pinned_hash()), (Verdict::Unavailable, None), "pinned {bad:?}");
    }
    // The model's empty-equals-empty (no manifest loaded, none pinned) is refused.
    let mut both = input(vec![sample(PLUGIN, "")]);
    both.pinned_hash = String::new();
    assert_eq!(verdict(&both), Verdict::Unavailable);
    // A malformed apiserver id hash is recorded as null; it does not decide the verdict.
    let mut odd = sample(PLUGIN, PINNED);
    odd.apiserver_id_hash = "not-a-hash".to_string();
    let record = check_loaded_manifest(&input(vec![odd])).expect("a record");
    assert_eq!((record.verdict(), record.apiserver_id_hash()), (Verdict::Match, None));
}

#[test]
fn a_malformed_binding_is_refused_before_a_record_is_made() {
    let refused = |change: &dyn Fn(&mut ObservationBinding)| {
        let mut bad = input(vec![sample(PLUGIN, PINNED)]);
        change(&mut bad.binding);
        check_loaded_manifest(&bad).expect_err("refused")
    };
    for digest in ["", "sha256:0123", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                   "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"] {
        assert_eq!(refused(&|b| b.id = BindingId::RecordDigest(digest.to_string())), Adm4InputError::RecordDigest, "{digest}");
    }
    for nonce in ["0".repeat(31), "0".repeat(65), "A".repeat(32), "g".repeat(32), String::new(), format!("{} ", "0".repeat(32))] {
        assert_eq!(refused(&|b| b.id = BindingId::Nonce(nonce.clone())), Adm4InputError::Nonce, "{nonce:?}");
    }
    for nonce in ["0".repeat(32), "f".repeat(64), "0123456789abcdef".repeat(3)] {
        let mut ok = input(vec![sample(PLUGIN, PINNED)]);
        ok.binding.id = BindingId::Nonce(nonce.clone());
        assert!(check_loaded_manifest(&ok).is_ok(), "{nonce}");
    }
    for time in ["2026-10-17T12:00:00", "2026-10-17 12:00:00Z", "2026-10-17T12:00:00.5Z", "2026-10-17T12:00:00+00:00",
                 "2026-02-29T00:00:00Z", "2100-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-13-01T00:00:00Z",
                 "2026-00-10T00:00:00Z", "2026-10-00T00:00:00Z", "2026-10-17T24:00:00Z", "2026-10-17T23:60:00Z",
                 "2026-10-17T23:59:60Z", "0000-01-01T00:00:00Z", "2026-1-17T12:00:00Z", "+026-10-17T12:00:00Z",
                 "２026-10-17T12:00:00Z", "2026-10-17t12:00:00z"] {
        assert_eq!(refused(&|b| b.window_start = time.to_string()), Adm4InputError::WindowStart, "{time}");
        let mut late = binding();
        late.window_start = "0001-01-01T00:00:00Z".to_string();
        late.window_end = time.to_string();
        let mut bad = input(vec![]);
        bad.binding = late;
        assert_eq!(check_loaded_manifest(&bad).expect_err("refused"), Adm4InputError::WindowEnd, "{time}");
    }
    // Leap days that exist; the start strictly before the end.
    for (start, end) in [("2028-02-29T00:00:00Z", "2028-02-29T00:00:01Z"), ("2000-02-29T23:59:59Z", "2000-03-01T00:00:00Z")] {
        let mut ok = input(vec![]);
        ok.binding.window_start = start.to_string();
        ok.binding.window_end = end.to_string();
        assert!(check_loaded_manifest(&ok).is_ok(), "{start}");
    }
    assert_eq!(refused(&|b| b.window_end = b.window_start.clone()), Adm4InputError::WindowOrder);
    assert_eq!(refused(&|b| std::mem::swap(&mut b.window_start, &mut b.window_end)), Adm4InputError::WindowOrder);
}

#[test]
fn claims_q06_and_q07_replay_through_the_comparison() {
    let vectors = parse(VECTORS);
    let pinned = text(field(&vectors, "pinned"), "manifestDirectoryHash");
    let mut seen = Vec::new();
    for row in rows(&vectors, "claims").iter().filter(|row| ["Q06", "Q07"].contains(&text(row, "id"))) {
        let loaded = text(field(field(row, "claim"), "evidence"), "loadedManifestHash");
        let mut claim = input(vec![sample(PLUGIN, loaded)]);
        claim.pinned_hash = pinned.to_string();
        let got = verdict(&claim);
        match field(row, "expect") {
            Value::Null => assert_eq!(got, Verdict::Match, "Q06 is accepted"),
            refusal => {
                assert!(refusal.as_str().expect("text").starts_with("C21 "), "Q07 is C21");
                assert_eq!(got, Verdict::Mismatch);
            }
        }
        seen.push(text(row, "id").to_string());
    }
    assert_eq!(seen, ["Q06", "Q07"]);
}

// ------------------------------------------------------------------------------------------------ the record

#[test]
fn the_record_s_canonical_bytes_and_digest() {
    assert_eq!((RECORD_VERSION, METRIC_NAME), ("planeon.internal.observer-adm4/v1",
                                               "apiserver_manifest_admission_config_controller_last_config_info"));
    let matched = check_loaded_manifest(&input(vec![sample(PLUGIN, PINNED)])).expect("a record");
    assert_eq!(String::from_utf8(matched.canonical()).expect("UTF-8"), concat!(
        r#"{"apiserverIdHash":"sha256:abababababababababababababababababababababababababababababababab","#,
        r#""kubernetesVersion":"v1.37.1","#,
        r#""loadedHash":"sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189","#,
        r#""metricName":"apiserver_manifest_admission_config_controller_last_config_info","#,
        r#""observationBinding":{"recordDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","#,
        r#""windowEnd":"2026-10-17T12:05:00Z","windowStart":"2026-10-17T12:00:00Z"},"#,
        r#""pinnedHash":"sha256:5aa2cdec0b8dc08c008b887e30b9954ffc46e7d779365f64db1adfd80656f189","#,
        r#""plugin":"ValidatingAdmissionPolicy","schemaVersion":"planeon.internal.observer-adm4/v1","verdict":"MATCH"}"#));
    assert_eq!(matched.digest(), "sha256:f9927afa32f8d4be1b1f64944aef71591cb88ab09233f5c556622b70968d3fd7");
    // Nulls for the malformed and absent values, and the nonce form of the binding.
    let mut unavailable = input(vec![]);
    unavailable.pinned_hash = "SHA256:x".to_string();
    unavailable.binding.id = BindingId::Nonce("f".repeat(32));
    let record = check_loaded_manifest(&unavailable).expect("a record");
    assert_eq!(String::from_utf8(record.canonical()).expect("UTF-8"), concat!(
        r#"{"apiserverIdHash":null,"kubernetesVersion":"v1.37.1","loadedHash":null,"#,
        r#""metricName":"apiserver_manifest_admission_config_controller_last_config_info","#,
        r#""observationBinding":{"nonce":"ffffffffffffffffffffffffffffffff","windowEnd":"2026-10-17T12:05:00Z","#,
        r#""windowStart":"2026-10-17T12:00:00Z"},"pinnedHash":null,"plugin":"ValidatingAdmissionPolicy","#,
        r#""schemaVersion":"planeon.internal.observer-adm4/v1","verdict":"UNAVAILABLE"}"#));
    assert_eq!(record.digest(), "sha256:6cdd65b27ae41ddf051910bb907d094c25cd3c89caf7e03708406855157ae678");
    // The canonical bytes parse back to the document, with exactly the nine members.
    let parsed = parse(std::str::from_utf8(&matched.canonical()).expect("UTF-8"));
    assert_eq!(parsed.as_object().expect("object").len(), 9);
}

#[test]
fn records_differing_only_in_the_observation_binding_differ_in_digest() {
    let base = check_loaded_manifest(&input(vec![sample(PLUGIN, PINNED)])).expect("a record");
    let mut digests = vec![base.digest()];
    for change in 0..4 {
        let mut other = input(vec![sample(PLUGIN, PINNED)]);
        match change {
            0 => other.binding.id = BindingId::RecordDigest(format!("sha256:{}", "1".repeat(64))),
            1 => other.binding.id = BindingId::Nonce("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string()),
            2 => other.binding.window_start = "2026-10-17T12:00:01Z".to_string(),
            _ => other.binding.window_end = "2026-10-17T12:05:01Z".to_string(),
        }
        let record = check_loaded_manifest(&other).expect("a record");
        assert_eq!(record.verdict(), Verdict::Match);
        digests.push(record.digest());
    }
    let mut unique = digests.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), digests.len(), "{digests:?}");
}

#[test]
fn the_refusal_texts() {
    assert_eq!(Adm4InputError::WindowOrder.to_string(), "ADM-4: the window does not start before it ends");
    assert_eq!(HashError::DuplicateName("a.yaml".into()).to_string(), "ADM-4: the manifest directory names a.yaml twice");
    assert_eq!([Verdict::Match, Verdict::Mismatch, Verdict::Unavailable].map(Verdict::as_str), ["MATCH", "MISMATCH", "UNAVAILABLE"]);
}
