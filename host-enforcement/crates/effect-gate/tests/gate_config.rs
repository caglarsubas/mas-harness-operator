//! HE-003D DESIGN sections 3.1-3.3 and 8: the signed configuration document's canonical subset, closed schema and
//! checks (`GateConfig::parse`), on a valid document built from the I07 v3 vectors' ACTIVE configuration (with an
//! empty `observedWorkers`) and on one mutation per refusal.

use effect_gate::gate_config::{is_digest, is_normal_path, policy_kinds, FORMAT, MAX_INTEGER};
use effect_gate::net::IpLiteral;
use effect_gate::{GateConfig, GateConfigError, PolicyGate};
use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;

const I07_VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut object = Object::new();
    for (key, value) in members {
        object.insert(JStr::new(key), value);
    }
    Value::Object(object)
}

fn pin(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

fn file(path: &str, fill: char) -> Value {
    object(vec![("path", Value::str(path)), ("sha256", Value::str(&pin(fill)))])
}

fn identity(base: &str, leaf: char, key: char) -> Value {
    object(vec![("chain", Value::Array(vec![file(&format!("{base}.crt"), leaf), file(&format!("{base}-ca.crt"), 'c')])),
                ("key", file(&format!("{base}.key"), key))])
}

/// The ACTIVE configuration of the I07 v3 vectors, with no observed worker (Q-HE3D-2 (a)).
fn active_gate() -> Value {
    let vectors = json::parse(I07_VECTORS).expect("the I07 vectors parse");
    let mut gate = vectors.get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().expect("ACTIVE");
    remove(&mut gate, &["observedWorkers"]);
    gate
}

fn document() -> Value {
    object(vec![
        ("format", Value::str(FORMAT)),
        ("gate", active_gate()),
        ("lifetimes", object(vec![("run-one", Value::int(1_900_000_000)), ("run-two", Value::int(1_900_000_100))])),
        ("stores", object(vec![("journalDirectory", Value::str("/var/lib/planeon/effect-gate/journal")),
                               ("markerDirectory", Value::str("/var/lib/planeon-marker/effect-gate"))])),
        ("credentials", object(vec![
            ("i04Server", identity("/etc/planeon/effect-gate/i04-server", 'a', '1')),
            ("i04ClientCa", file("/etc/planeon/effect-gate/i04-client-ca.crt", 'd')),
            ("apiserverServingCa", file("/etc/planeon/effect-gate/apiserver-ca.crt", 'e')),
            ("effectIdentity", identity("/etc/planeon/effect-gate/effect", '6', '2')),
            ("writerIdentity", identity("/etc/planeon/effect-gate/writer", '8', '3')),
        ])),
        ("enrolledWriter", object(vec![("executable", Value::str("/opt/planeon/bin/harness-policy-write"))])),
    ])
}

fn node<'a>(value: &'a mut Value, path: &[&str]) -> &'a mut Value {
    let mut node = value;
    for key in path {
        let Value::Object(members) = node else { panic!("not an object before {key}") };
        node = members.get_key_mut(&JStr::new(key)).unwrap_or_else(|| panic!("no member {key}"));
    }
    node
}

fn set(value: &mut Value, path: &[&str], new: Value) {
    let (last, parents) = path.split_last().expect("a path");
    let Value::Object(members) = node(value, parents) else { panic!("not an object") };
    members.insert(JStr::new(last), new);
}

fn remove(value: &mut Value, path: &[&str]) {
    let (last, parents) = path.split_last().expect("a path");
    let Value::Object(members) = node(value, parents) else { panic!("not an object") };
    members.remove(&JStr::new(last)).expect("the member exists");
}

fn bytes(value: &Value) -> Vec<u8> {
    json::canonical(value).expect("a canonical encoding")
}

fn parse(value: &Value) -> Result<GateConfig, GateConfigError> {
    GateConfig::parse(&bytes(value))
}

fn mutated(change: impl FnOnce(&mut Value)) -> Result<GateConfig, GateConfigError> {
    let mut value = document();
    change(&mut value);
    parse(&value)
}

fn refused_check(change: impl FnOnce(&mut Value), what: &str) {
    match mutated(change) {
        Err(GateConfigError::Check(message)) => assert!(message.contains(what), "{message:?} names {what:?}"),
        other => panic!("{what}: expected a check refusal, got {other:?}"),
    }
}

fn refused_schema(change: impl FnOnce(&mut Value)) {
    assert!(matches!(mutated(change), Err(GateConfigError::Schema(_))));
}

fn refused_canonical(document: &[u8]) {
    assert!(matches!(GateConfig::parse(document), Err(GateConfigError::Canonical(_))), "{}",
            String::from_utf8_lossy(&document[..document.len().min(80)]));
}

#[test]
fn a_valid_document_is_typed() {
    let value = document();
    let config = parse(&value).expect("the valid document passes");
    assert_eq!(config.document_digest, sha256::prefixed(&bytes(&value)));
    assert_eq!(config.generation, "a".repeat(64));
    assert_eq!((config.endpoint.ip, config.endpoint.port), (IpLiteral::V4([198, 51, 100, 7]), 6443));
    assert_eq!(config.lifetimes.end("run-one"), Some(1_900_000_000));
    assert_eq!(config.lifetimes.end("run-two"), Some(1_900_000_100));
    assert_eq!(config.lifetimes.end("run-three"), None);
    assert_eq!(config.journal_directory, "/var/lib/planeon/effect-gate/journal");
    assert_eq!(config.marker_directory, "/var/lib/planeon-marker/effect-gate");
    let files = &config.credentials;
    assert_eq!(files.i04_server.chain.len(), 2);
    assert_eq!(files.i04_server.chain[0].path, "/etc/planeon/effect-gate/i04-server.crt");
    assert_eq!(files.i04_server.key.sha256, pin('1'));
    assert_eq!(files.i04_client_ca.sha256, pin('d'));
    assert_eq!(files.apiserver_serving_ca.path, "/etc/planeon/effect-gate/apiserver-ca.crt");
    assert_eq!(files.effect_identity.key.path, "/etc/planeon/effect-gate/effect.key");
    assert_eq!(files.writer_identity.chain[0].sha256, pin('8'));
}

#[test]
fn the_gate_member_round_trips_into_policy_gate() {
    let config = parse(&document()).expect("the valid document passes");
    assert_eq!(config.gate.get("generation").and_then(Value::as_str), Some("a".repeat(64).as_str()));
    let gate = PolicyGate::new(&config.gate, &config.kinds).expect("PolicyGate::new takes the gate member unchanged");
    assert_eq!(gate.apiserver_address().ip, IpLiteral::V4([127, 0, 0, 1]));
    assert_eq!(gate.apiserver_address().port, 6443);
    assert_eq!(gate.writer().qualification_namespace, "planeon-qual");
    assert!(policy_kinds().is_ok());
}

#[test]
fn the_i04_endpoint() {
    refused_check(|value| set(value, &["gate", "endpoint"], Value::str("198.51.100.7:1023")), "below 1024");
    refused_check(|value| set(value, &["gate", "endpoint"], Value::str("198.51.100.7:443")), "below 1024");
    for endpoint in ["0.0.0.0:6443", "[::]:6443", "224.0.0.1:6443", "239.255.255.255:6443", "[ff02::1]:6443",
                     "[::ffff:224.0.0.1]:6443", "[::ffff:0.0.0.0]:6443"] {
        refused_check(|value| set(value, &["gate", "endpoint"], Value::str(endpoint)), "unspecified or multicast");
    }
    refused_check(|value| set(value, &["gate", "endpoint"], Value::str("gate.local:6443")), "literal authority");
    for endpoint in ["198.51.100.7:1024", "[2001:db8::7]:65535", "127.0.0.1:6443"] {
        let config = mutated(|value| set(value, &["gate", "endpoint"], Value::str(endpoint))).expect(endpoint);
        assert!(config.endpoint.port >= 1024);
    }
}

#[test]
fn observed_workers_are_refused_with_v4s_text() {
    let pair = Value::Array(vec![Value::int(4100), Value::int(900001)]);
    for workers in [Value::Array(vec![pair]), Value::Array(Vec::new())] {
        match mutated(|value| set(value, &["gate", "observedWorkers"], workers)) {
            Err(GateConfigError::Gate(error)) => assert!(format!("{error:?}").contains(
                "v4 observes the kernel; a static observedWorkers list is refused (convert_v3_config)"), "{error:?}"),
            other => panic!("observedWorkers: expected the C01 refusal, got {other:?}"),
        }
    }
}

#[test]
fn every_run_has_exactly_one_lifetime() {
    refused_check(|value| remove(value, &["lifetimes", "run-two"]), "has no lifetime");
    refused_check(|value| set(value, &["lifetimes", "run-three"], Value::int(5)), "does not hold");
    refused_check(|value| set(value, &["lifetimes", "run-one"], Value::int(0)), "1..=2^53-1");
    refused_check(|value| set(value, &["lifetimes", "run-one"], Value::str("1900000000")), "1..=2^53-1");
    let config = mutated(|value| set(value, &["lifetimes", "run-one"], Value::int(MAX_INTEGER as i64))).expect("2^53-1");
    assert_eq!(config.lifetimes.end("run-one"), Some(MAX_INTEGER as i64));
    // 2^53 is outside the canonical subset itself.
    let mut value = document();
    set(&mut value, &["lifetimes", "run-one"], Value::int(1 << 53));
    refused_canonical(&bytes(&value));
}

/// `count` extra manifests no run lists, each a valid R47 key equal to its digest.
fn extra_manifests(value: &mut Value, count: usize) {
    for index in 0..count {
        let digest = format!("sha256:{index:064x}");
        let entry = object(vec![("apiVersion", Value::str("v1")), ("digest", Value::str(&digest)), ("kind", Value::str("Pod")),
                                ("name", Value::str(&format!("extra-{index}"))), ("namespace", Value::str("planeon-qual")),
                                ("size", Value::int(10))]);
        set(value, &["gate", "manifests", &digest], entry);
    }
}

#[test]
fn manifests_are_bounded_and_keyed_by_their_digest() {
    let key = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    refused_check(|value| set(value, &["gate", "manifests", key, "size"], Value::int(16_385)), "16,384");
    mutated(|value| set(value, &["gate", "manifests", key, "size"], Value::int(16_384))).expect("16,384 bytes pass");
    refused_check(|value| extra_manifests(value, 26), "more than 32");
    mutated(|value| extra_manifests(value, 25)).expect("32 manifests pass");
    let other = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    refused_check(|value| set(value, &["gate", "manifests", key, "digest"], Value::str(other)), "not its entry's sha256");
    refused_check(|value| {
        let unused = "sha256:0000000000000000000000000000000000000000000000000000000000000d01";
        let entry = node(value, &["gate", "manifests", unused]).clone();
        remove(value, &["gate", "manifests", unused]);
        set(value, &["gate", "manifests", "SHA256:0000000000000000000000000000000000000000000000000000000000000d01"], entry);
        remove(value, &["gate", "runs", "run-two"]);
        remove(value, &["lifetimes", "run-two"]);
    }, "not its entry's sha256");
}

#[test]
fn server_certificate_digests_are_r47_distinct_and_not_the_gates_own() {
    let field = |run: &'static str| ["gate", "runs", run, "serverCertificateDigest"];
    refused_check(|value| set(value, &field("run-two"), Value::str(&pin('4'))), "same serverCertificateDigest");
    refused_check(|value| set(value, &field("run-one"), Value::str("sha256:ABCD")), "R47");
    refused_check(|value| set(value, &field("run-one"), Value::str(&pin('A'))), "R47");
    for leaf in ['a', '6', '8'] {
        refused_check(|value| set(value, &field("run-one"), Value::str(&pin(leaf))), "own leaf");
    }
    // A pin of a key or a CA is not a leaf certificate's.
    mutated(|value| set(value, &field("run-one"), Value::str(&pin('c')))).expect("a chain's CA pin is not a leaf");
}

#[test]
fn exactly_one_ca_of_each_kind() {
    let two = |fill| Value::Array(vec![file("/etc/planeon/a.crt", fill), file("/etc/planeon/b.crt", fill)]);
    refused_schema(|value| set(value, &["credentials", "i04ClientCa"], two('d')));
    refused_schema(|value| set(value, &["credentials", "apiserverServingCa"], two('e')));
}

#[test]
fn chains_hold_one_to_four_files() {
    let chain = |count: usize| Value::Array((0..count).map(|index| file(&format!("/etc/c{index}.crt"), 'a')).collect());
    refused_check(|value| set(value, &["credentials", "i04Server", "chain"], chain(0)), "1 to 4");
    refused_check(|value| set(value, &["credentials", "effectIdentity", "chain"], chain(5)), "1 to 4");
    mutated(|value| set(value, &["credentials", "writerIdentity", "chain"], chain(4))).expect("four files pass");
}

#[test]
fn paths_are_absolute_and_normalised() {
    for path in ["etc/planeon/x.crt", "/etc/planeon/../x.crt", "/etc/./x.crt", "/etc//x.crt", "/etc/planeon/", "/",
                 "", "/etc/x\u{0}y"] {
        refused_check(|value| set(value, &["credentials", "i04ClientCa", "path"], Value::str(path)), "path");
        refused_check(|value| set(value, &["stores", "journalDirectory"], Value::str(path)), "store directory");
    }
    let long = format!("/{}", "x".repeat(255));
    refused_check(|value| set(value, &["credentials", "i04ClientCa", "path"], Value::str(&long)), "path");
    assert!(is_normal_path(&format!("/{}", "x".repeat(254))) && !is_normal_path(&long));
    refused_check(|value| set(value, &["stores", "markerDirectory"], Value::str("/var/lib/planeon/effect-gate/journal")),
                  "the same");
}

#[test]
fn digests_are_well_formed() {
    for digest in ["sha256:", "sha512:aaaa", "aaaa", &pin('g'), &format!("{}a", pin('a')), &pin('F')] {
        refused_check(|value| set(value, &["credentials", "i04Server", "key", "sha256"], Value::str(digest)), "sha256");
    }
    assert!(is_digest(&pin('0')) && is_digest(&pin('f')) && !is_digest(&pin('G')));
}

#[test]
fn the_generation_is_a_store_name() {
    for generation in ["generations", "-leading", "has/slash", ".dot", &"g".repeat(129)] {
        let result = mutated(|value| set(value, &["gate", "generation"], Value::str(generation)));
        assert!(matches!(result, Err(GateConfigError::Check(_)) | Err(GateConfigError::Gate(_))), "{generation}: {result:?}");
    }
}

#[test]
fn objects_are_closed() {
    refused_schema(|value| set(value, &["extra"], Value::int(1)));
    refused_schema(|value| remove(value, &["stores"]));
    refused_schema(|value| set(value, &["stores", "extra"], Value::str("/x")));
    refused_schema(|value| set(value, &["credentials", "extra"], file("/x", 'a')));
    refused_schema(|value| remove(value, &["credentials", "writerIdentity"]));
    refused_schema(|value| set(value, &["credentials", "i04ClientCa", "mode"], Value::int(256)));
    refused_schema(|value| set(value, &["credentials", "i04Server", "extra"], Value::int(1)));
    refused_schema(|value| set(value, &["format"], Value::str("planeon.effect-gate-config/v1")));
    // The gate member is the I05 Config with policyWriter: an unknown member there is the Config's refusal.
    assert!(matches!(mutated(|value| set(value, &["gate", "extra"], Value::int(1))), Err(GateConfigError::Gate(_))));
    assert!(matches!(mutated(|value| remove(value, &["gate", "policyWriter"])), Err(GateConfigError::Gate(_))));
    assert!(matches!(mutated(|value| set(value, &["gate", "policyWriter", "apiserverAuthority"],
                                         Value::str("10.0.0.1:6443"))), Err(GateConfigError::Gate(_))));
    assert!(matches!(mutated(|value| set(value, &["gate", "state"], Value::str("UNKNOWN"))), Err(GateConfigError::Gate(_))));
}

#[test]
fn the_canonical_subset() {
    let canonical = bytes(&document());
    let text = String::from_utf8(canonical.clone()).expect("ASCII");
    assert!(GateConfig::parse(&canonical).is_ok());
    // A trailing newline, a space, reordered keys, an escape JCS would not emit (`\u0041` for `A`).
    refused_canonical(format!("{text}\n").as_bytes());
    refused_canonical(text.replacen(':', ": ", 1).as_bytes());
    let format = format!("\"format\":\"{FORMAT}\",");
    assert!(text.contains(&format));
    refused_canonical(text.replacen(&format, "", 1).replacen('{', &format!("{{{format}"), 1).as_bytes());
    assert!(text.contains("\"state\":\"ACTIVE\""));
    refused_canonical(text.replacen("\"state\":\"ACTIVE\"", "\"state\":\"\\u0041CTIVE\"", 1).as_bytes());
    // A float, a negative integer, a non-ASCII key or string, a duplicate key, NaN, too deep, not JSON.
    refused_canonical(text.replacen("1900000000", "1900000000.0", 1).as_bytes());
    refused_canonical(text.replacen("1900000000", "1.9e9", 1).as_bytes());
    refused_canonical(text.replacen("1900000000", "-1900000000", 1).as_bytes());
    refused_canonical(text.replacen("\"journalDirectory\"", "\"journalDirectory\u{e9}\"", 1).as_bytes());
    refused_canonical(text.replacen("/var/lib/planeon/effect-gate/journal", "/var/lib/planeon/\u{e9}", 1).as_bytes());
    assert!(text.starts_with("{\"credentials\":"));
    refused_canonical(text.replacen("{\"credentials\"", "{\"credentials\":{},\"credentials\"", 1).as_bytes());
    refused_canonical(text.replacen("1900000000", "NaN", 1).as_bytes());
    let mut deep = Value::int(1);
    for _ in 0..16 {
        deep = Value::Array(vec![deep]);
    }
    let mut value = document();
    set(&mut value, &["stores", "deep"], deep);
    refused_canonical(&bytes(&value));
    refused_canonical(b"not json");
    refused_canonical(b"");
    // Escapes JCS emits are canonical: a control character as \u001f is allowed in a string (the schema refuses it
    // elsewhere).
    assert!(matches!(GateConfig::parse(text.replacen("\"state\":\"ACTIVE\"", "\"state\":\"A\\u001f\"", 1).as_bytes()),
                     Err(GateConfigError::Gate(_))));
}
