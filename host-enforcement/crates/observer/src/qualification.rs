//! The R10 ports of native-profile v4's migration check and native-profile v5's qualification check (HE-004D2
//! DESIGN-D2 section 6; owner decisions Q-HE4D2-1 (a), Q-HE4D2-2 (a) and Q-HE4D2-3 (a); MODEL_DEFINED R140, R141):
//! [`PredecessorSchemas`], the native-profile v1, v2 and v3 record validators built from their bytes after the model's
//! canonical pins; [`check_migration`], which a v4 enrollment must pass against the host's retained v1, v2 and v3
//! records ([`Histories`]); and [`check_qualification`], the one acceptance-shaped check: the record, a v5 capture of
//! each resident role, the v5 lifecycle capture and a v5 observation of each backend component, checked together with
//! the cross-capture rules and `check_migration` for one boot and validity window; on success only it mints the token
//! [`QualificationAccepted`]. A logic module: pure, no panic, std's ordered collections and i05-protocol's json, sha256
//! and schema only. Nothing outside the four HE-004D2 modules names it, so `serve` cannot reach it (G-D2-5).
//!
//! `check_migration`'s order is the model's (`native_qualification_v4.py` lines 709-737): the record's shape step, the
//! profile binding, the inputs' types, the attested-empty rule, the retained-records rule, then each predecessor in v1,
//! v2, v3 order (its version and validity, its boot, its nonces), the nonce reuse and the nonce scan of every string of
//! the profile and the record (keys included). The model checks the three schema pins inside the check; R10 checks them
//! once, when the validators are built, so the order differs only when a pin and an earlier rule fail together, which
//! no vector does (MODEL_DEFINED). The histories are a caller obligation (complete retained histories, or attested
//! empty; HE-008).
//!
//! `check_qualification`'s order is the model's (`native_qualification_v5.py` lines 243-298): the record, the test-only
//! rule, the role set, each role capture (D1's `check_capture`, under v5 since unit B1), the lifecycle capture, the
//! backend set and each backend capture, the cross-capture rules (one process once, one inode per observed path and one
//! path per inode, the worker's parent, the domain counts, the census against the role cgroups, the delegated broker
//! service's two leaves and the populated flags), then `check_migration`. Python's `KeyError`, `TypeError` and
//! `AttributeError` are [`Refusal::Missing`], as in D1 and `check_record`; a role or component name that is not text,
//! met by the sort among two or more captures, is `Missing` too. The retained-capture rule (`previous`) is not ported
//! (Q-HE4D2-8 (a)): the check never passes one.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::schema::Schema;
use i05_protocol::sha256;

use crate::capture_check::{self, Refusal, DELEGATED_CHILDREN, ROLES};
use crate::capture_schema::{rewrite_conditionals, CaptureSchema, RecordSchema};
use crate::kernel_text;
use crate::record_check;

/// The model's canonical pins of the three predecessor schemas (the sha256 of their canonical encodings).
const V1_PIN: &str = "8e184d60df63863bc627c1655887c32012490e3c7211f8f9a38baee67f64d4cf";
const V2_PIN: &str = "fd1657c9a9ea437df2d48f03c69a1de62013a47a9fc62ad7776db2fc7029c0c5";
const V3_PIN: &str = "1c7930351e58a12cdf8bf8ef0df1f971eddceb8d17268f73541425258e9657d2";
/// The predecessors' schema versions.
const V1_RECORD: &str = "planeon.internal.native-qualification/v1";
const V2_RECORD: &str = "planeon.internal.native-qualification/v2";
const V3_RECORD: &str = "planeon.internal.native-qualification/v3";
/// An R10 refusal: a predecessor schema whose pin holds but whose record variant does not load.
const NOT_LOADED: &str = "predecessor schema does not load";
/// The SELinux domain of each resident role (the model's `ROLE_DOMAINS`), in `ROLES` order.
const ROLE_DOMAINS: [(&str, &str); 5] = [("SERVER", "planeon_server_t"), ("OBSERVER", "planeon_observer_t"),
                                         ("BROKER", "planeon_broker_t"), ("WORKER", "planeon_worker_t"),
                                         ("EFFECT_GATE", "planeon_gate_t")];
/// The delegated broker service's unit, directly below the planeon slice.
const BROKER_UNIT: &str = "planeon-capacity-broker.service";
/// The qualification's refusals (each pinned by a qualification vector).
const TEST_ONLY: &str = "test-only implementation profile";
const ONE_PER_ROLE: &str = "one capture per resident role";
const ONE_PER_COMPONENT: &str = "one observation per backend component";
const PROCESS_TWICE: &str = "one process reported twice";
const INODE_TWICE: &str = "one inode reported for two files";
const PATH_TWICE: &str = "one file reported at two inodes";
const WORKER_PARENT: &str = "worker is not a child of the original broker";
const DOMAIN_COUNT: &str = "role-domain process outside its role cgroup";
const BELOW_ROLE: &str = "census lists a cgroup below a role cgroup";
const BROKER_CHILDREN: &str = "census children of the delegated broker service differ";
const UNPOPULATED: &str = "census reports a cgroup with captured processes as unpopulated";

/// The native-profile v1, v2 and v3 `record` validators.
pub struct PredecessorSchemas {
    v1: Schema,
    v2: Schema,
    v3: Schema,
}

impl PredecessorSchemas {
    /// Parses each schema, requires the sha256 of its canonical encoding to be the model's pin (refusing with the
    /// model's "unreviewed vN schema"), applies the closed conditional rewrite (none of the three holds `else`) and builds
    /// its `record` validator, in v1, v2, v3 order.
    pub fn from_bytes(v1: &[u8], v2: &[u8], v3: &[u8]) -> Result<PredecessorSchemas, Refusal> {
        let v1 = predecessor(v1, V1_PIN, "unreviewed v1 schema")?;
        let v2 = predecessor(v2, V2_PIN, "unreviewed v2 schema")?;
        let v3 = predecessor(v3, V3_PIN, "unreviewed v3 schema")?;
        Ok(PredecessorSchemas { v1, v2, v3 })
    }
}

fn predecessor(bytes: &[u8], pin: &str, unreviewed: &'static str) -> Result<Schema, Refusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::Model(unreviewed))?;
    let value = json::parse(text).map_err(|_| Refusal::Model(unreviewed))?;
    let encoded = json::canonical(&value).map_err(|_| Refusal::Model(unreviewed))?;
    if sha256::hex(&sha256::digest(&encoded)) != pin {
        return Err(Refusal::Model(unreviewed));
    }
    let (rewritten, _) = rewrite_conditionals(&value).map_err(|_| Refusal::Model(NOT_LOADED))?;
    let definitions = rewritten.get("$defs").ok_or(Refusal::Model(NOT_LOADED))?;
    let mut root = Object::new();
    root.insert(JStr::new("$ref"), Value::str("#/$defs/record"));
    root.insert(JStr::new("$defs"), definitions.clone());
    Schema::from_value(&Value::Object(root)).map_err(|_| Refusal::Model(NOT_LOADED))
}

/// The host's retained v1, v2 and v3 enrollment records, each a list of record values (a caller obligation).
pub struct Histories {
    v1: Value,
    v2: Value,
    v3: Value,
}

impl Histories {
    /// The three histories as given (each must be a list; [`check_migration`] refuses another value).
    pub fn new(v1: Value, v2: Value, v3: Value) -> Histories {
        Histories { v1, v2, v3 }
    }
}

fn refuse_unless(condition: bool, message: &'static str) -> Result<(), Refusal> {
    if condition { Ok(()) } else { Err(Refusal::Model(message)) }
}

fn at<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Refusal> {
    value.as_object().and_then(|object| object.get(key)).ok_or(Refusal::Missing)
}

/// The model's `check_migration` (see the module documentation for the order).
pub fn check_migration(histories: &Histories, record: &Value, profile: &Value, schemas: &PredecessorSchemas,
                       record_schema: &RecordSchema, no_earlier_history: bool) -> Result<(), Refusal> {
    record_check::shape(record, record_schema)?;
    let digest = json::canonical(profile).map(|encoded| sha256::prefixed(&encoded)).map_err(|_| Refusal::Missing)?;
    refuse_unless(json::py_eq(at(record, "profileDigest")?, &Value::str(&digest)), "profile substitution")?;
    let (Some(v1), Some(v2), Some(v3)) = (histories.v1.as_array(), histories.v2.as_array(), histories.v3.as_array()) else {
        return Err(Refusal::Model("migration inputs"));
    };
    if no_earlier_history {
        refuse_unless(v1.is_empty() && v2.is_empty() && v3.is_empty(), "attested empty history with earlier records")?;
    }
    refuse_unless(no_earlier_history || !v1.is_empty() || !v2.is_empty() || !v3.is_empty(), "retained earlier records required")?;
    let mut old_nonces: Vec<&Value> = Vec::new();
    for (records, version, schema, invalid) in [(v1, V1_RECORD, &schemas.v1, "predecessor is not a valid v1 record"),
                                                (v2, V2_RECORD, &schemas.v2, "predecessor is not a valid v2 record"),
                                                (v3, V3_RECORD, &schemas.v3, "predecessor is not a valid v3 record")] {
        for old in records {
            let valid = old.as_object().is_some() && old.get("schemaVersion").and_then(Value::as_str) == Some(version) && schema.is_valid(old);
            refuse_unless(valid, invalid)?;
            let rebooted = !json::py_eq(at(at(old, "host")?, "bootId")?, at(at(record, "host")?, "bootId")?);
            refuse_unless(rebooted, "v4 enrollment without a maintenance reboot")?;
            let scope = at(old, "scope")?;
            old_nonces.push(at(scope, "runNonce")?);
            old_nonces.push(at(scope, "capacityNonce")?);
        }
    }
    let scope = at(record, "scope")?;
    let fresh = [at(scope, "runNonce")?, at(scope, "capacityNonce")?];
    refuse_unless(!fresh.iter().any(|nonce| old_nonces.iter().any(|old| json::py_eq(old, nonce))), "nonce reused across versions")?;
    let carried = |value: &Value| {
        record_check::strings(value).into_iter().any(|text| old_nonces.iter().any(|old| matches!(old, Value::Str(nonce) if nonce == text)))
    };
    refuse_unless(!carried(profile) && !carried(record), "earlier nonce carried into v4 data")
}

/// The inputs of one qualification, as the model takes them: the v4 record, its profile and signed endpoints, the role
/// captures, the lifecycle capture and the backend captures (each as given), the retained histories and the
/// attested-empty flag. Test inputs only until W02-PROD and HE-008 source them (caller obligations 1 and 2).
pub struct QualificationInput {
    /// The native-profile v4 record.
    pub record: Value,
    /// The implementation profile the record binds.
    pub profile: Value,
    /// The signed endpoints.
    pub endpoints: Value,
    /// One v5 capture per resident role (a list).
    pub captures: Value,
    /// The v5 lifecycle capture.
    pub lifecycle: Value,
    /// One v5 observation per backend component (a list).
    pub backend_captures: Value,
    /// The host's retained v1, v2 and v3 records.
    pub histories: Histories,
    /// The attestation that the host never held an earlier record.
    pub no_earlier_history: bool,
}

/// A qualification [`check_qualification`] accepted: the canonical digest of the record it bound, the record's validity
/// window in Unix seconds, and whether it was accepted in an explicit fixture call. Only `check_qualification` makes
/// one; it is moved, never copied.
#[derive(Debug, PartialEq, Eq)]
pub struct QualificationAccepted {
    record_digest: String,
    valid_from: u64,
    expires_at: u64,
    fixture: bool,
}

impl QualificationAccepted {
    /// `sha256:` and the hex of the record's canonical encoding (the configuration's pin form).
    pub fn record_digest(&self) -> &str {
        &self.record_digest
    }

    /// The record's `validFrom`, in Unix seconds.
    pub fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// The record's `expiresAt`, in Unix seconds.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Whether the qualification was accepted in an explicit fixture call.
    pub fn fixture(&self) -> bool {
        self.fixture
    }
}

fn items(value: &Value) -> Result<&[Value], Refusal> {
    value.as_array().ok_or(Refusal::Missing)
}

fn text(value: &Value) -> Result<&str, Refusal> {
    value.as_str().ok_or(Refusal::Missing)
}

/// Python's truth value of a JSON value (`not value` is its negation).
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Int(_) | Value::Float(_) => !json::py_eq(value, &Value::int(0)),
        Value::Str(_) => value.as_str().is_some_and(|content| !content.is_empty()),
        Value::Array(members) => !members.is_empty(),
        Value::Object(members) => !members.is_empty(),
    }
}

/// The model's `sorted(c.get(key) for c in values) == sorted(expected)`: each value an object (Python's
/// `AttributeError` otherwise), each name text when two or more meet the sort (`TypeError` otherwise), the sorted names
/// equal to the sorted expected names.
fn same_names(values: &[Value], key: &str, expected: &[&str]) -> Result<bool, Refusal> {
    let mut names = Vec::new();
    for value in values {
        let member = value.as_object().ok_or(Refusal::Missing)?.get(key);
        match member.and_then(Value::as_str) {
            Some(name) => names.push(name),
            None if values.len() > 1 => return Err(Refusal::Missing),
            None => return Ok(false),
        }
    }
    names.sort_unstable();
    let mut wanted = expected.to_vec();
    wanted.sort_unstable();
    Ok(names == wanted)
}

/// The capture of a role (the model's `by_role`, the last of that role winning).
fn role_capture<'a>(captures: &'a [Value], role: &str) -> Result<&'a Value, Refusal> {
    captures.iter().rev().find(|capture| capture.get("role").and_then(Value::as_str) == Some(role)).ok_or(Refusal::Missing)
}

/// Python's tuple equality over two equal-length lists of values.
fn same_tuple(left: &[&Value], right: &[&Value]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(one, other)| json::py_eq(one, other))
}

/// The cross-capture rules (the model's lines 266-296), in its order.
fn cross_rules(record: &Value, captures: &[Value], lifecycle: &Value, backends: &[Value]) -> Result<(), Refusal> {
    // One process once: every role member but the observer's own (declared, T04-OBSERVER-IDENTITY) and every backend
    // process.
    let mut processes: Vec<[&Value; 2]> = Vec::new();
    for capture in captures {
        if text(at(capture, "role")?)? == "OBSERVER" {
            continue;
        }
        for member in items(at(capture, "cgroupMembers")?)? {
            processes.push([at(member, "pid")?, at(member, "startTicks")?]);
        }
    }
    for capture in backends {
        let process = at(capture, "process")?;
        processes.push([at(process, "pid")?, at(process, "startTicks")?]);
    }
    let distinct = processes.iter().enumerate()
        .all(|(index, one)| processes.iter().skip(index.saturating_add(1)).all(|other| !same_tuple(one, other)));
    refuse_unless(distinct, PROCESS_TWICE)?;
    // Across all five role captures, a (device, inode) pair names a single observed row and a path a single inode.
    let mut by_inode: Vec<([&Value; 2], [&Value; 3])> = Vec::new();
    let mut by_path: Vec<(&Value, [&Value; 2])> = Vec::new();
    for capture in captures {
        for row in items(at(capture, "files")?)? {
            let node = [at(row, "device")?, at(row, "inode")?];
            let seen = [at(at(row, "entry")?, "path")?, at(row, "contentDigest")?, at(row, "measuredVerity")?];
            match by_inode.iter().find(|(known, _)| same_tuple(known, &node)).map(|(_, first)| *first) {
                Some(first) => refuse_unless(same_tuple(&first, &seen), INODE_TWICE)?,
                None => by_inode.push((node, seen)),
            }
            match by_path.iter().find(|(known, _)| json::py_eq(known, seen[0])).map(|(_, first)| *first) {
                Some(first) => refuse_unless(same_tuple(&first, &node), PATH_TWICE)?,
                None => by_path.push((seen[0], node)),
            }
        }
    }
    let worker = at(role_capture(captures, "WORKER")?, "process")?;
    let broker = at(role_capture(captures, "BROKER")?, "process")?;
    refuse_unless(json::py_eq(at(worker, "ppid")?, at(broker, "pid")?), WORKER_PARENT)?;
    let counts = at(lifecycle, "domainProcessCounts")?;
    for (role, domain) in ROLE_DOMAINS {
        let members = items(at(role_capture(captures, role)?, "cgroupMembers")?)?.len();
        let members = i64::try_from(members).map_err(|_| Refusal::Missing)?;
        refuse_unless(json::py_eq(at(counts, domain)?, &Value::int(members)), DOMAIN_COUNT)?;
    }
    // The slice census against the role captures: no child of a role cgroup, the delegated broker service's two leaves,
    // and every enrolled cgroup holding a captured process populated.
    let mut census: BTreeMap<&str, &Value> = BTreeMap::new();
    for row in items(at(lifecycle, "sliceCgroups")?)? {
        census.insert(text(at(row, "path")?)?, at(row, "populated")?);
    }
    let roles = at(record, "roles")?;
    let mut role_cgroups: BTreeSet<String> = BTreeSet::new();
    for role in ROLES {
        role_cgroups.insert(text(at(at(at(roles, role)?, "cgroup")?, "path")?)?.to_string());
    }
    let below = census.keys().any(|path| role_cgroups.iter().any(|cgroup| path.starts_with(&format!("{cgroup}/"))));
    refuse_unless(!below, BELOW_ROLE)?;
    let slice = capture_check::slice();
    let service = format!("{slice}/{BROKER_UNIT}");
    let prefix = format!("{service}/");
    let mut children: Vec<&str> =
        census.keys().filter_map(|path| path.strip_prefix(prefix.as_str())).filter(|rest| !rest.contains('/')).collect();
    children.sort_unstable();
    refuse_unless(children == DELEGATED_CHILDREN, BROKER_CHILDREN)?;
    let one = Value::int(1);
    role_cgroups.insert(slice);
    role_cgroups.insert(service);
    for path in &role_cgroups {
        let populated = census.get(path.as_str()).ok_or(Refusal::Missing)?;
        refuse_unless(json::py_eq(populated, &one), UNPOPULATED)?;
    }
    Ok(())
}

/// The model's `check_qualification` (see the module documentation for the order). `test_fixture` admits a test-only
/// implementation profile and marks the token; on success only, the token.
pub fn check_qualification(input: &QualificationInput, schema: &CaptureSchema, record_schema: &RecordSchema,
                           predecessors: &PredecessorSchemas, test_fixture: bool) -> Result<QualificationAccepted, Refusal> {
    let checked = record_check::check_record(&input.record, &input.profile, &input.endpoints, record_schema)?.into_record();
    let record = checked.value();
    if !test_fixture {
        refuse_unless(!truthy(at(at(record, "backendProfile")?, "testOnly")?), TEST_ONLY)?;
    }
    let captures = input.captures.as_array().ok_or(Refusal::Model(ONE_PER_ROLE))?;
    refuse_unless(same_names(captures, "role", &ROLES)?, ONE_PER_ROLE)?;
    for capture in captures {
        capture_check::check_capture(&checked, capture, text(at(capture, "role")?)?, schema)?;
    }
    capture_check::check_lifecycle_capture(&checked, &input.lifecycle, schema)?;
    let backends = input.backend_captures.as_array().ok_or(Refusal::Model(ONE_PER_COMPONENT))?;
    let components = at(record, "backendComponents")?.as_object().ok_or(Refusal::Missing)?;
    let names: Vec<&str> = components.iter().map(|(name, _)| name.as_str()).collect::<Option<_>>().ok_or(Refusal::Missing)?;
    refuse_unless(same_names(backends, "component", &names)?, ONE_PER_COMPONENT)?;
    for capture in backends {
        capture_check::check_backend_capture(&checked, capture, schema)?;
    }
    cross_rules(record, captures, &input.lifecycle, backends)?;
    check_migration(&input.histories, &input.record, &input.profile, predecessors, record_schema, input.no_earlier_history)?;
    let scope = at(record, "scope")?;
    let valid_from = kernel_text::utc_seconds(text(at(scope, "validFrom")?)?).ok_or(Refusal::Missing)?;
    let expires_at = kernel_text::utc_seconds(text(at(scope, "expiresAt")?)?).ok_or(Refusal::Missing)?;
    Ok(QualificationAccepted { record_digest: checked.digest().to_string(), valid_from, expires_at, fixture: test_fixture })
}
