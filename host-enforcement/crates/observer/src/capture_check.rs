//! The R10 port of native-profile v4's three capture checks (HE-004D1 DESIGN-D1 section 15; owner decision Q-HE4D1-11
//! (a); MODEL_DEFINED R130): `check_capture`, `check_lifecycle_capture` and `check_backend_capture`, with `capture_class`,
//! the member-set rule, the boot entry, the window, the data bound and the shape step. A logic module: pure, no panic,
//! std's ordered collections and i05-protocol's json, sha256 and schema only. HE-004D2 reuses it for
//! `check_qualification`.
//!
//! The rule order is the model's (`native_qualification_v4.py` lines 510-706): the "not a v4 ..." type check, the
//! capture's data bound and canonical length, the schema step, then each rule in turn. The model's per-call shape step
//! of the record is discharged by [`CheckedRecord`], which only `Enrolled::new` makes, after the record's own shape
//! (the record is immutable for the epoch). Refusals pinned by a vector are contract text and appear verbatim; the
//! unpinned ones (all under eight words) are written independently. Equality is i05-protocol's `py_eq`; sorting follows
//! Python's tuple order over ASCII. A refusal is [`Refusal::Model`] (a rule), [`Refusal::Schema`] (the schema step),
//! [`Refusal::Data`] (the data bound) or [`Refusal::Missing`], where Python would raise `KeyError` or `TypeError` (not
//! reachable for a schema-valid capture over a record that passes `check_record`). Every function is total.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use i05_protocol::json::{self, Object, Value};
use i05_protocol::sha256;

use crate::capture_schema::CaptureSchema;
use crate::kernel_text;

/// The cgroup2 root, for the lifecycle rule's slice (G-D1-5).
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The schema versions of the three capture families and the record (upstream identifiers).
pub const V4_RECORD: (&str, &str) = ("planeon.internal.native-qualification/v4", "SELINUX_FSVERITY_CGROUP_BPF_V4");
pub const V4_CAPTURE: &str = "planeon.internal.native-qualification-capture/v4";
pub const V4_LIFECYCLE: &str = "planeon.internal.native-qualification-lifecycle/v4";
pub const V4_BACKEND: &str = "planeon.internal.native-qualification-backend/v4";
/// The resident roles, in the model's order.
pub const ROLES: [&str; 5] = ["SERVER", "OBSERVER", "BROKER", "WORKER", "EFFECT_GATE"];
/// The roles that run one process.
pub const SINGLE_PROCESS_ROLES: [&str; 4] = ["SERVER", "OBSERVER", "BROKER", "EFFECT_GATE"];
/// The containment hooks, in the model's order.
pub const HOOKS: [&str; 7] =
    ["INET_SOCK_CREATE", "INET4_BIND", "INET6_BIND", "INET4_CONNECT", "INET6_CONNECT", "UDP4_SENDMSG", "UDP6_SENDMSG"];
/// The 22 census attach types (cgroup BPF, Linux v6.12), each effective list read, in the model's order.
pub const CENSUS_ATTACH_TYPES: [&str; 22] = [
    "BPF_CGROUP_INET_INGRESS", "BPF_CGROUP_INET_EGRESS", "BPF_CGROUP_SOCK_OPS", "BPF_CGROUP_DEVICE",
    "BPF_CGROUP_UNIX_CONNECT", "BPF_CGROUP_INET4_POST_BIND", "BPF_CGROUP_INET6_POST_BIND", "BPF_CGROUP_UNIX_SENDMSG",
    "BPF_CGROUP_SYSCTL", "BPF_CGROUP_UDP4_RECVMSG", "BPF_CGROUP_UDP6_RECVMSG", "BPF_CGROUP_UNIX_RECVMSG",
    "BPF_CGROUP_GETSOCKOPT", "BPF_CGROUP_SETSOCKOPT", "BPF_CGROUP_INET4_GETPEERNAME", "BPF_CGROUP_INET6_GETPEERNAME",
    "BPF_CGROUP_UNIX_GETPEERNAME", "BPF_CGROUP_INET4_GETSOCKNAME", "BPF_CGROUP_INET6_GETSOCKNAME",
    "BPF_CGROUP_UNIX_GETSOCKNAME", "BPF_CGROUP_INET_SOCK_RELEASE", "BPF_LSM_CGROUP",
];
/// The roles whose capture is label-bound for every capability set.
pub const LABEL_BOUND_ROLES: [&str; 2] = ["BROKER", "WORKER"];
/// The delegated broker service's two leaves.
pub const DELEGATED_CHILDREN: [&str; 2] = ["broker", "probe-worker"];
/// The largest canonical encoding of a qualification value (the model's `MAX_BYTES`).
pub const MAX_BYTES: usize = 262_144;
/// The largest integer magnitude of the data bound, 2^53 - 1.
const MAX_MAGNITUDE: u128 = (1 << 53) - 1;

/// Pinned refusal texts (contract text, verbatim), named where the surrounding code would otherwise read like the
/// model's.
const MEMBERS_CHANGED: &str = "member or thread set changed during the inspection";
const OBSERVED_MISSING: &str = "OBSERVED field missing from the capture";
const THREADS_NOT_UNIFORM: &str = "per-thread state not uniform";
const CAPS_DIFFER: &str = "capability sets differ from the enrolled set";
const NOT_DESCENDED: &str = "worker member not descended from the inspected worker";
const TASKS_DIFFER: &str = "task count differs from pids.current or exceeds pids.max";
const FILTERS_DIFFER: &str = "Seccomp_filters count differs from the role's filters";
const OUTSIDE_BRACKET: &str = "worker capture outside a frozen bracket";
const NOT_PER_BOOT: &str = "seal marker not on a per-boot filesystem";
/// The `Seccomp_filters` count each role runs under: the worker keeps the broker's filter and adds its own.
pub fn seccomp_filters(role: &str) -> u64 {
    if role == "WORKER" { 2 } else { 1 }
}

/// Why a check refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A rule's text.
    Model(&'static str),
    /// The schema step.
    Schema,
    /// The data bound's text.
    Data(&'static str),
    /// A member Python would read and fail on (KeyError or TypeError).
    Missing,
}

/// A record whose shape was checked once (the v4 identity, the data bound, the canonical length and the `record`
/// variant); only `Enrolled::new` makes one. Its value and the digest of its canonical encoding.
pub struct CheckedRecord {
    value: Value,
    digest: String,
}

impl CheckedRecord {
    /// The record's value.
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// `sha256:` and the hex of the record's canonical encoding (the configuration's pin).
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// The constructor `Enrolled::new` calls after the record's shape step.
pub(crate) fn checked_record(value: Value, digest: String) -> CheckedRecord {
    CheckedRecord { value, digest }
}

/// One item of the data bound's walk: a value or a member name, at its depth.
enum Item<'a> {
    Node(&'a Value),
    Key(&'a json::JStr),
}

/// The model's data bound (`_bounded`): depth at most 16; only objects, arrays, strings, integers, booleans and null;
/// printable ASCII in every string and key; |integer| at most 2^53 - 1; a budget of 262,144 shared by the whole value
/// (a string spends its length, any other value 1). The first refusal in the model's walk order.
pub fn bounded(value: &Value) -> Result<(), &'static str> {
    let mut budget = i128::try_from(MAX_BYTES).map_err(|_| "size exceeded")?;
    let mut stack = vec![(Item::Node(value), 0usize)];
    while let Some((item, depth)) = stack.pop() {
        if depth > 16 {
            return Err("depth over 16");
        }
        let (spent, text) = match item {
            Item::Key(key) => (key.len_code_points(), Some(key)),
            Item::Node(Value::Str(text)) => (text.len_code_points(), Some(text)),
            Item::Node(Value::Float(_)) => return Err("a value outside the data types"),
            Item::Node(_) => (1, None),
        };
        budget = budget.saturating_sub(i128::try_from(spent).unwrap_or(i128::MAX));
        if budget < 0 {
            return Err("over the size budget");
        }
        if let Some(text) = text {
            if !text.as_bytes().iter().all(|byte| (0x20..=0x7e).contains(byte)) {
                return Err("text outside printable ASCII");
            }
            continue;
        }
        let deeper = depth.saturating_add(1);
        match item {
            Item::Node(Value::Int(int)) => {
                if int.to_i128().is_none_or(|number| number.unsigned_abs() > MAX_MAGNITUDE) {
                    return Err("integer over 2^53 - 1");
                }
            }
            Item::Node(Value::Array(items)) => {
                for member in items.iter().rev() {
                    stack.push((Item::Node(member), deeper));
                }
            }
            Item::Node(Value::Object(object)) => {
                for (key, member) in object.iter().rev() {
                    stack.push((Item::Node(member), deeper));
                    stack.push((Item::Key(key), deeper));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The evidence class of one role's capture: the observer's own is DECLARED_T04; the broker, the worker and a server
/// whose recorded capabilities hold CAP_NET_BIND_SERVICE are LABEL_BOUND; the others OBSERVED.
pub fn capture_class(record: &Value, role: &str) -> &'static str {
    if role == "OBSERVER" {
        return "DECLARED_T04";
    }
    let binds = record
        .get("roles")
        .and_then(|roles| roles.get(role))
        .and_then(|row| row.get("capabilities"))
        .and_then(Value::as_array)
        .is_some_and(|capabilities| capabilities.iter().any(|name| name.as_str() == Some("CAP_NET_BIND_SERVICE")));
    if LABEL_BOUND_ROLES.contains(&role) || binds { "LABEL_BOUND" } else { "OBSERVED" }
}

/// The slice of the planeon roles under the cgroup2 root.
pub fn slice() -> String {
    format!("{CGROUP_ROOT}/planeon.slice")
}

// ------------------------------------------------------------------------------------------------ helpers

fn require(condition: bool, text: &'static str) -> Result<(), Refusal> {
    if condition { Ok(()) } else { Err(Refusal::Model(text)) }
}

/// `value[key]` of an object (Python's `KeyError` or `TypeError` otherwise).
fn at<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Refusal> {
    value.as_object().and_then(|object| object.get(key)).ok_or(Refusal::Missing)
}

/// `key in value` of an object.
fn has(value: &Value, key: &str) -> bool {
    value.as_object().is_some_and(|object| object.get(key).is_some())
}

fn items(value: &Value) -> Result<&[Value], Refusal> {
    value.as_array().ok_or(Refusal::Missing)
}

fn text(value: &Value) -> Result<&str, Refusal> {
    value.as_str().ok_or(Refusal::Missing)
}

fn int(value: &Value) -> Result<i128, Refusal> {
    value.as_int().and_then(|int| int.to_i128()).ok_or(Refusal::Missing)
}

fn eq(left: &Value, right: &Value) -> bool {
    json::py_eq(left, right)
}

/// A string list's members (Python would hash or sort them).
fn strings(value: &Value) -> Result<Vec<String>, Refusal> {
    items(value)?.iter().map(|item| text(item).map(str::to_string)).collect()
}

/// `{key: value for key, value in object.items() if key not in dropped}`.
fn without(value: &Value, dropped: &[&str]) -> Result<Value, Refusal> {
    let object = value.as_object().ok_or(Refusal::Missing)?;
    let mut kept = Object::new();
    for (key, member) in object.iter() {
        if !key.as_str().is_some_and(|name| dropped.contains(&name)) {
            kept.insert(key.clone(), member.clone());
        }
    }
    Ok(Value::Object(kept))
}

/// An object of the given members, in order.
fn object(members: Vec<(&str, Value)>) -> Value {
    let mut built = Object::new();
    for (key, member) in members {
        built.insert(json::JStr::new(key), member);
    }
    Value::Object(built)
}

/// The shape step of a capture: the data bound, the canonical length, then the variant.
fn shape(capture: &Value, valid: bool) -> Result<(), Refusal> {
    bounded(capture).map_err(Refusal::Data)?;
    let encoded = json::canonical(capture).map_err(|_| Refusal::Data("no canonical encoding"))?;
    if encoded.len() > MAX_BYTES {
        return Err(Refusal::Data("canonical length over 262,144"));
    }
    if !valid {
        return Err(Refusal::Schema);
    }
    Ok(())
}

/// A canonical UTC time's seconds.
fn moment(value: &Value) -> Result<u64, Refusal> {
    kernel_text::utc_seconds(text(value)?).ok_or(Refusal::Model("a time that is not canonical UTC"))
}

/// `validFrom <= observedAt < expiresAt`.
fn within(record: &Value, observed: &Value, message: &'static str) -> Result<(), Refusal> {
    let now = moment(observed)?;
    let scope = at(record, "scope")?;
    let (start, end) = (moment(at(scope, "validFrom")?)?, moment(at(scope, "expiresAt")?)?);
    require(start <= now && now < end, message)
}

/// The boot entry observed is the enrolled one.
fn boot_entry(record: &Value, observed: &Value) -> Result<(), Refusal> {
    let enrolled = at(at(record, "bootEntries")?, "ENROLLED")?;
    let line = text(at(enrolled, "kernelCmdline")?)?;
    let expected = object(vec![("entryId", at(enrolled, "entryId")?.clone()),
                               ("cmdlineSha256", Value::str(&sha256::prefixed(line.as_bytes())))]);
    require(eq(observed, &expected), "observed on a boot entry other than the enrolled one")
}

/// The model's same-set test: no element repeated, and the two lists equal once sorted.
fn same_set(observed: &Value, enrolled: &Value) -> Result<bool, Refusal> {
    let (mut observed, mut enrolled) = (strings(observed)?, strings(enrolled)?);
    let unique = observed.iter().collect::<BTreeSet<_>>().len() == observed.len();
    observed.sort();
    enrolled.sort();
    Ok(unique && observed == enrolled)
}

/// A member's or thread's key (`pid` or `tid`, `startTicks`).
fn key_of(row: &Value, first: &str) -> Result<(i128, i128), Refusal> {
    Ok((int(at(row, first)?)?, int(at(row, "startTicks")?)?))
}

/// One member set keyed by (pid, startTicks), each with its sorted (tid, startTicks) list; a process or thread listed
/// twice refuses.
fn keyed(rows: &Value) -> Result<BTreeMap<(i128, i128), Vec<(i128, i128)>>, Refusal> {
    let rows = items(rows)?;
    let mut processes: Vec<((i128, i128), &[Value])> = Vec::with_capacity(rows.len());
    for row in rows {
        let key = key_of(row, "pid")?;
        let threads = items(at(row, "threads")?)?;
        match processes.iter_mut().find(|(seen, _)| *seen == key) {
            Some(entry) => entry.1 = threads,
            None => processes.push((key, threads)),
        }
    }
    let mut unique = processes.len() == rows.len();
    let mut keyed = BTreeMap::new();
    for (key, threads) in &processes {
        let pairs = threads.iter().map(|thread| key_of(thread, "tid")).collect::<Result<Vec<_>, _>>()?;
        let tids = pairs.iter().map(|pair| pair.0).collect::<BTreeSet<_>>();
        let distinct = pairs.iter().collect::<BTreeSet<_>>();
        unique = unique && distinct.len() == tids.len() && tids.len() == threads.len();
        let mut sorted = pairs;
        sorted.sort();
        keyed.insert(*key, sorted);
    }
    require(unique, "member set lists a process or thread twice")?;
    Ok(keyed)
}

/// The inspector obligation's member and thread sets (the model's `_member_sets`).
fn member_sets(capture: &Value, members: &[Value]) -> Result<(), Refusal> {
    let before = keyed(at(capture, "memberSetBefore")?)?;
    let after = keyed(at(capture, "memberSetAfter")?)?;
    require(before == after, MEMBERS_CHANGED)?;
    let mut reported: BTreeMap<(i128, i128), i128> = BTreeMap::new();
    for member in members {
        reported.insert(key_of(member, "pid")?, int(at(member, "threadCount")?)?);
    }
    let same_keys = before.keys().collect::<BTreeSet<_>>() == reported.keys().collect::<BTreeSet<_>>();
    let counts = before.iter().all(|(key, threads)| {
        reported.get(key).is_some_and(|count| i128::try_from(threads.len()).is_ok_and(|length| length == *count))
    });
    require(reported.len() == members.len() && same_keys && counts, "member set differs from the cgroup members")
}

/// An executable mapping's sort key: (path, offset, length, permissions, device, inode).
type MapKey = (String, i128, i128, String, i128, i128);

fn map_key(mapping: &Value) -> Result<MapKey, Refusal> {
    Ok((text(at(mapping, "path")?)?.to_string(), int(at(mapping, "offset")?)?, int(at(mapping, "length")?)?,
        text(at(mapping, "permissions")?)?.to_string(), int(at(mapping, "device")?)?, int(at(mapping, "inode")?)?))
}

// ------------------------------------------------------------------------------------------------ the three checks

/// The model's `check_capture` for one resident role (see the module documentation for the order).
pub fn check_capture(record: &CheckedRecord, capture: &Value, role: &str, schema: &CaptureSchema) -> Result<(), Refusal> {
    let record_value = record.value();
    require(capture.get("schemaVersion").and_then(Value::as_str) == Some(V4_CAPTURE) && capture.as_object().is_some(),
            "not a v4 capture")?;
    shape(capture, schema.capture_valid(capture))?;
    require(ROLES.contains(&role) && capture.get("role").and_then(Value::as_str) == Some(role)
                && capture.get("qualificationDigest").and_then(Value::as_str) == Some(record.digest()),
            "capture binding")?;
    require(eq(at(capture, "host")?, at(record_value, "host")?), "wrong boot/kernel")?;
    let selinux = at(record_value, "selinux")?;
    let status = at(selinux, "status")?;
    let even = int(at(status, "sequence")?)? % 2 == 0;
    require(even && eq(at(capture, "selinuxBefore")?, status) && eq(status, at(capture, "selinuxAfter")?)
                && eq(at(capture, "kernelPolicyDigest")?, at(selinux, "policyDigest")?),
            "active policy changed")?;
    let hardening = at(record_value, "hardening")?;
    let seal = without(at(hardening, "sealMarker")?, &["selinuxLabel"])?;
    let mut declared = hardening.as_object().cloned().ok_or(Refusal::Missing)?;
    declared.insert(json::JStr::new("sealMarker"), seal);
    require(eq(at(capture, "booleansObserved")?, at(selinux, "booleans")?)
                && eq(at(capture, "hardeningObserved")?, &Value::Object(declared)),
            "host lock state differs")?;
    boot_entry(record_value, at(capture, "bootEntryObserved")?)?;
    within(record_value, at(capture, "observedAt")?, "expired capture")?;
    let (a, b, d) = (int(at(capture, "inspectionStartedMs")?)?, int(at(capture, "inspectionFinishedMs")?)?,
                     int(at(capture, "deadlineMs")?)?);
    require(a <= b && b < d && b - a <= 2000 && d - a <= 900_000, "inspection deadline")?;
    let expected = at(at(record_value, "roles")?, role)?;
    let actual = at(capture, "process")?;
    let members = items(at(capture, "cgroupMembers")?)?;
    let route = capture_class(record_value, role);
    let own = route == "DECLARED_T04";
    if !own {
        let mut present = vec![has(actual, "exe"), has(actual, "namespaceInodes"), has(capture, "executableMaps")];
        present.extend(members.iter().map(|member| has(member, "exe")));
        if route == "OBSERVED" {
            require(present.iter().any(|flag| *flag), "LABEL_BOUND capture where OBSERVED is required")?;
            require(present.iter().all(|flag| *flag), OBSERVED_MISSING)?;
        } else {
            require(!present.iter().any(|flag| *flag), "field forbidden in a LABEL_BOUND capture")?;
        }
        let mut fields = vec!["uid", "gid", "processLabel", "seccompMode", "noNewPrivs"];
        if route == "OBSERVED" {
            fields.push("namespaceInodes");
        }
        for field in fields {
            require(eq(at(actual, field)?, at(expected, field)?), "process/kernel custody differs")?;
        }
    }
    let hidden: &[&str] = if own { &["selinuxLabel", "path"] } else { &["selinuxLabel"] };
    require(eq(at(actual, "cgroup")?, &without(at(expected, "cgroup")?, hidden)?), "process/kernel custody differs")?;
    require(own || matches!(at(actual, "threadsUniform")?, Value::Bool(true)), THREADS_NOT_UNIFORM)?;
    if role == "WORKER" {
        let bounding = strings(at(actual, "capBounding")?)?;
        let broker = strings(at(at(at(record_value, "roles")?, "BROKER")?, "capabilities")?)?;
        let empty = |key: &str| at(actual, key).and_then(items).map(<[Value]>::is_empty);
        let unique = bounding.iter().collect::<BTreeSet<_>>().len() == bounding.len();
        let within_broker = bounding.iter().all(|name| broker.contains(name));
        require(empty("capPermitted")? && empty("capEffective")? && empty("capAmbient")? && empty("capInheritable")?
                    && unique && within_broker,
                CAPS_DIFFER)?;
    } else if !own {
        let enrolled = at(expected, "capabilities")?;
        let empty = |key: &str| at(actual, key).and_then(items).map(<[Value]>::is_empty);
        require(same_set(at(actual, "capPermitted")?, enrolled)? && same_set(at(actual, "capEffective")?, enrolled)?
                    && same_set(at(actual, "capBounding")?, enrolled)? && empty("capAmbient")? && empty("capInheritable")?,
                CAPS_DIFFER)?;
    }
    let mut me = Object::new();
    // The member row's keys (an object compares without regard to order).
    for key in ["exe", "noNewPrivs", "pid", "ppid", "processLabel", "seccompFilters", "seccompMode", "startTicks",
                "threadCount", "uid"] {
        if let Some(member) = actual.as_object().and_then(|object| object.get(key)) {
            me.insert(json::JStr::new(key), member.clone());
        }
    }
    let me = Value::Object(me);
    let pids_max = int(at(at(expected, "cgroup")?, "pidsMax")?)?;
    if own {
        require(members.len() == 1, "unenrolled cgroup member")?;
    } else if SINGLE_PROCESS_ROLES.contains(&role) {
        require(members.len() == 1 && members.first().is_some_and(|member| eq(member, &me)), "unenrolled cgroup member")?;
    } else {
        let mut pids: BTreeMap<i128, &Value> = BTreeMap::new();
        for member in members {
            pids.insert(int(at(member, "pid")?)?, member);
        }
        let me_in = members.iter().any(|member| eq(member, &me));
        let size = i128::try_from(members.len()).unwrap_or(i128::MAX);
        let mut uniform = true;
        if me_in && pids.len() == members.len() && size <= pids_max {
            for member in members {
                uniform = uniform
                    && eq(at(member, "processLabel")?, at(expected, "processLabel")?)
                    && eq(at(member, "uid")?, at(expected, "uid")?)
                    && eq(at(member, "noNewPrivs")?, &Value::int(1))
                    && eq(at(member, "seccompMode")?, &Value::int(2));
                if !uniform {
                    break;
                }
            }
        }
        require(me_in && pids.len() == members.len() && size <= pids_max && uniform, "unenrolled cgroup member")?;
        let me_pid = int(at(&me, "pid")?)?;
        for member in members {
            let mut seen = BTreeSet::new();
            let mut cursor = member;
            while int(at(cursor, "pid")?)? != me_pid {
                let pid = int(at(cursor, "pid")?)?;
                let parent = int(at(cursor, "ppid")?)?;
                require(!seen.contains(&pid) && pids.contains_key(&parent),
                        NOT_DESCENDED)?;
                seen.insert(pid);
                cursor = pids.get(&parent).copied().ok_or(Refusal::Missing)?;
            }
        }
    }
    let current = int(at(capture, "pidsCurrent")?)?;
    let tasks = if own {
        current
    } else {
        members.iter().try_fold(0i128, |sum, member| Ok::<i128, Refusal>(sum.saturating_add(int(at(member, "threadCount")?)?)))?
    };
    require(current == tasks && tasks <= pids_max, TASKS_DIFFER)?;
    if !own {
        let filters = Value::int(i64::try_from(seccomp_filters(role)).unwrap_or(0));
        let mut agree = eq(at(actual, "seccompFilters")?, &filters);
        for member in members {
            agree = agree && eq(at(member, "seccompFilters")?, &filters);
        }
        require(agree, FILTERS_DIFFER)?;
        if role == "WORKER" {
            let one = Value::int(1);
            require(eq(at(capture, "cgroupFrozenBefore")?, &one) && eq(&one, at(capture, "cgroupFrozenAfter")?),
                    OUTSIDE_BRACKET)?;
        }
        member_sets(capture, members)?;
    }
    require(items(at(capture, "childCgroups")?)?.is_empty() && eq(at(capture, "descendantCount")?, &Value::int(0)),
            "role cgroup has descendants")?;
    let (children, service) = (at(capture, "delegatedChildren")?, at(capture, "delegatedServiceMembers")?);
    if role == "BROKER" {
        let sorted = children.as_array().map(|list| {
            let mut names: Vec<Option<&str>> = list.iter().map(Value::as_str).collect();
            names.sort();
            names
        });
        let wanted: Vec<Option<&str>> = DELEGATED_CHILDREN.iter().map(|name| Some(*name)).collect();
        require(sorted.is_some_and(|names| names == wanted) && service.as_array().is_some_and(<[Value]>::is_empty),
                "delegated broker subtree differs")?;
    } else {
        require(children.is_null() && service.is_null(), "delegated broker subtree differs")?;
    }
    let mut rows: BTreeMap<String, &Value> = BTreeMap::new();
    for row in items(at(record_value, "files")?)? {
        rows.insert(text(at(row, "path")?)?.to_string(), row);
    }
    let file_paths = items(at(expected, "filePaths")?)?;
    let mut observed: BTreeMap<String, &Value> = BTreeMap::new();
    for item in items(at(capture, "files")?)? {
        let path = text(at(at(item, "entry")?, "path")?)?;
        let entry = match rows.get(path) {
            Some(row) => Some(without(row, &["selinuxLabel"])?),
            None => None,
        };
        let mut good = !observed.contains_key(path) && file_paths.iter().any(|listed| listed.as_str() == Some(path));
        good = good && entry.as_ref().is_some_and(|entry| at(item, "entry").is_ok_and(|seen| eq(seen, entry)));
        if good {
            let row = rows.get(path).copied().ok_or(Refusal::Missing)?;
            good = eq(at(item, "contentDigest")?, at(row, "sha256")?) && eq(at(item, "measuredVerity")?, at(row, "verityDigest")?);
        }
        require(good, "file measurement differs")?;
        observed.insert(path.to_string(), item);
    }
    let enrolled_paths = strings(at(expected, "filePaths")?)?.into_iter().collect::<BTreeSet<_>>();
    require(observed.keys().cloned().collect::<BTreeSet<_>>() == enrolled_paths, "incomplete loaded-code closure")?;
    if route == "OBSERVED" {
        let interpreter = at(expected, "interpreterPath")?;
        let image = if interpreter.is_null() { text(at(expected, "executable")?)? } else { text(interpreter)? };
        let seen = observed.get(image).copied().ok_or(Refusal::Missing)?;
        let wanted = object(vec![("path", Value::str(image)), ("device", at(seen, "device")?.clone()),
                                 ("inode", at(seen, "inode")?.clone())]);
        let exe = at(actual, "exe")?;
        let mut same = eq(exe, &wanted);
        for member in members {
            same = same && eq(at(member, "exe")?, exe);
        }
        require(same, "running image is not the role's executable or interpreter")?;
        let mut mappings: Vec<MapKey> = Vec::new();
        for path in strings(at(expected, "filePaths")?)? {
            let row = rows.get(&path).copied().ok_or(Refusal::Missing)?;
            let seen = observed.get(&path).copied().ok_or(Refusal::Missing)?;
            for segment in items(at(row, "executableSegments")?)? {
                mappings.push((path.clone(), int(at(segment, "offset")?)?, int(at(segment, "length")?)?,
                               text(at(segment, "permissions")?)?.to_string(), int(at(seen, "device")?)?,
                               int(at(seen, "inode")?)?));
            }
        }
        let mut found = items(at(capture, "executableMaps")?)?.iter().map(map_key).collect::<Result<Vec<_>, _>>()?;
        found.sort();
        mappings.sort();
        require(found == mappings, "missing or injected executable map")?;
    }
    let programs = at(capture, "bpfPrograms")?;
    let pinned_programs = at(expected, "bpfPrograms")?;
    for hook in HOOKS {
        let (item, pinned) = (at(programs, hook)?, at(pinned_programs, hook)?);
        let local = at(item, "localIds")?;
        require(eq(at(item, "program")?, &without(pinned, &["pinLabel"])?) && eq(at(item, "pinPath")?, at(pinned, "pinPath")?)
                    && eq(local, &Value::Array(vec![at(pinned, "programId")?.clone()]))
                    && eq(at(item, "effectiveIds")?, local),
                "effective kernel filter differs")?;
    }
    let census = at(capture, "effectiveCensus")?;
    let mut clear = true;
    for name in CENSUS_ATTACH_TYPES {
        clear = clear && items(at(census, name)?)?.is_empty();
    }
    require(clear, "program effective on a role cgroup outside the containment hooks")
}

/// The model's `_path`: an absolute path without an empty, `.` or `..` component.
fn installed_path(path: &str) -> bool {
    path.strip_prefix('/').is_some_and(|rest| rest.split('/').all(|part| !part.is_empty() && part != "." && part != ".."))
}

/// The model's `check_lifecycle_capture` (the one-shot containment subject's absence, the planeon slice's census).
pub fn check_lifecycle_capture(record: &CheckedRecord, capture: &Value, schema: &CaptureSchema) -> Result<(), Refusal> {
    let record_value = record.value();
    require(capture.get("schemaVersion").and_then(Value::as_str) == Some(V4_LIFECYCLE) && capture.as_object().is_some(),
            "not a v4 lifecycle capture")?;
    shape(capture, schema.lifecycle_valid(capture))?;
    require(capture.get("qualificationDigest").and_then(Value::as_str) == Some(record.digest())
                && eq(at(capture, "host")?, at(record_value, "host")?),
            "lifecycle capture binding")?;
    within(record_value, at(capture, "observedAt")?, "expired lifecycle capture")?;
    let hardening = at(record_value, "hardening")?;
    require(eq(at(capture, "sealMarker")?, &without(at(hardening, "sealMarker")?, &["selinuxLabel"])?), "seal marker differs")?;
    require(eq(at(capture, "runFsType")?, at(hardening, "runFsType")?), NOT_PER_BOOT)?;
    let containment = text(at(at(at(record_value, "lifecycleSubjects")?, "HOST_CONTAINMENT")?, "cgroupPath")?)?;
    let cgroup = at(capture, "cgroup")?;
    let state = at(cgroup, "state")?;
    let absent_or_empty = state.as_str().is_some_and(|state| state == "ABSENT" || state == "EMPTY");
    let contained = at(at(capture, "domainProcessCounts")?, "planeon_contain_t")?;
    require(at(cgroup, "path")?.as_str() == Some(containment) && absent_or_empty && eq(contained, &Value::int(0)),
            "containment subject still resident")?;
    require(eq(at(capture, "booleansObserved")?, at(at(record_value, "selinux")?, "booleans")?), "host lock state differs")?;
    boot_entry(record_value, at(capture, "bootEntryObserved")?)?;
    require(items(at(capture, "sliceMembers")?)?.is_empty(), "process directly in the planeon slice")?;
    let rows = items(at(capture, "sliceCgroups")?)?;
    let mut order: Vec<String> = Vec::new();
    let mut census: BTreeMap<String, &Value> = BTreeMap::new();
    for row in rows {
        let path = text(at(row, "path")?)?.to_string();
        if census.insert(path.clone(), at(row, "populated")?).is_none() {
            order.push(path);
        }
    }
    for path in &order {
        require(installed_path(path), "canonical installed path")?;
    }
    let slice = slice();
    let in_slice = |path: &str| path == slice || path.strip_prefix(slice.as_str()).is_some_and(|rest| rest.starts_with('/'));
    require(census.len() == rows.len() && order.iter().all(|path| in_slice(path)), "planeon slice census malformed")?;
    require(order.iter().all(|path| *path == slice || path.rsplit_once('/').is_some_and(|(parent, _)| census.contains_key(parent))),
            "planeon slice census omits a parent cgroup")?;
    let mut enrolled: BTreeSet<String> = BTreeSet::new();
    let roles = at(record_value, "roles")?;
    for role in ROLES {
        enrolled.insert(text(at(at(at(roles, role)?, "cgroup")?, "path")?)?.to_string());
    }
    enrolled.insert(slice.clone());
    enrolled.insert(format!("{slice}/planeon-capacity-broker.service"));
    require(enrolled.iter().all(|path| census.contains_key(path)), "planeon slice census incomplete")?;
    let empty = state.as_str() == Some("EMPTY");
    let zero = Value::int(0);
    require(census.contains_key(containment) == empty && census.get(containment).is_none_or(|populated| eq(populated, &zero)),
            "containment subject still resident")?;
    require(order.iter().filter(|path| !enrolled.contains(*path))
                .all(|path| census.get(path).is_some_and(|populated| eq(populated, &zero))),
            "unenrolled populated cgroup in the planeon slice")?;
    let descendants = int(at(capture, "sliceDescendants")?)?;
    require(i128::try_from(census.len()).is_ok_and(|count| descendants == count - 1), "slice descendants differ from the census")
}

/// The model's `check_backend_capture` (ENTRY_BOUND: domain entry plus the measured file, not the running image).
pub fn check_backend_capture(record: &CheckedRecord, capture: &Value, schema: &CaptureSchema) -> Result<(), Refusal> {
    let record_value = record.value();
    require(capture.get("schemaVersion").and_then(Value::as_str) == Some(V4_BACKEND) && capture.as_object().is_some(),
            "not a v4 backend capture")?;
    shape(capture, schema.backend_valid(capture))?;
    require(capture.get("qualificationDigest").and_then(Value::as_str) == Some(record.digest())
                && eq(at(capture, "host")?, at(record_value, "host")?),
            "backend capture binding")?;
    within(record_value, at(capture, "observedAt")?, "expired backend capture")?;
    let component = at(capture, "component")?;
    let entry = component.as_str().and_then(|name| at(record_value, "backendComponents").ok()?.get(name));
    let Some(entry) = entry else { return Err(Refusal::Model("no recorded backend component")) };
    let executable = text(at(entry, "executable")?)?;
    let row = items(at(record_value, "backendFiles")?)?
        .iter()
        .rfind(|row| row.get("path").and_then(Value::as_str) == Some(executable))
        .ok_or(Refusal::Missing)?;
    let process = at(capture, "process")?;
    let wanted = object(vec![("path", Value::str(executable)), ("contentDigest", at(row, "sha256")?.clone()),
                             ("measuredVerity", at(row, "verityDigest")?.clone())]);
    require(eq(at(process, "processLabel")?, at(entry, "processLabel")?) && eq(at(process, "cgroupPath")?, at(entry, "cgroupPath")?)
                && eq(at(capture, "executable")?, &wanted),
            "backend observation differs")
}
