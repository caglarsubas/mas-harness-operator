//! The R10 port of native-profile v4's record check (HE-004D2 DESIGN-D2 section 5; owner decisions Q-HE4D2-1 (a) and
//! Q-HE4D2-5 (a); MODEL_DEFINED R139): [`check_record`] and [`RecordAccepted`], with the parts the model leaves to
//! Python written as R10's own code: the IP text ([`ip_text`], CPython 3.12's reading of the forms these contracts
//! admit), the closed kernel command-line grammar ([`kernel_parameter`], eleven hand-written whole-word matchers), the
//! code-ownership table, the seal digest and the string walk [`strings`] that `check_migration` scans. A logic module:
//! pure, no panic, std's ordered collections and i05-protocol's json and sha256 only. Nothing outside the four HE-004D2
//! modules names it, so `serve` cannot reach it (G-D2-5).
//!
//! The rule order is the model's (`native_qualification_v4.py` lines 266-479): the v4 identity, the shape step (the
//! data bound, the canonical length, then the `record` variant; the schema's canonical pin is checked once, when the
//! [`RecordSchema`] is built), the profile and scope bindings, the boot entries, the window, the resource labels, the
//! signed endpoints, the policy epoch, the two inventories, then each role, the executables and closures, the lifecycle
//! subjects, the seal marker, the entrypoint labels, the backend components and the in-set census. Refusals a vector
//! pins are contract text and appear verbatim; the unpinned ones are short. Where Python would raise `KeyError`,
//! `TypeError` or `AttributeError` (a profile or endpoint list of an unexpected type, or a member a schema-valid record
//! always holds), the refusal is [`Refusal::Missing`], D1's reading. Equality is i05-protocol's `py_eq`; sets and maps
//! are std's ordered collections, so no order depends on a hash.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::sha256;

use crate::capture_check::{self, checked_record, CheckedRecord, Refusal, HOOKS, MAX_BYTES, ROLES, V4_RECORD};
use crate::capture_schema::RecordSchema;
use crate::kernel_text;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PIN_ROOT: &str = "/sys/fs/bpf/planeon";
const INTERPRETER_TREE: &str = "/opt/planeon/python/";

/// The two one-shot lifecycle subjects, in the model's order.
const LIFECYCLE: [&str; 2] = ["HOST_CONTAINMENT", "POLICY_WRITER"];
/// The word a maintenance boot entry adds to the enrolled one.
const MAINTENANCE_UNIT: &str = "systemd.unit=planeon-maintenance.target";
/// The code inventories' size bounds (512 MiB and 4 GiB).
const PLANEON_CODE_BYTES: i128 = 536_870_912;
const BACKEND_CODE_BYTES: i128 = 4_294_967_296;
/// The seal marker's content version.
const SEAL_VERSION: &str = "planeon.internal.containment-seal/v1";
/// The backend components every record holds, and those that hold no API identity (upstream identifiers).
const REQUIRED_BACKEND: [&str; 6] = ["APISERVER", "DATASTORE", "CONTROLLER_MANAGER", "SCHEDULER", "KUBELET", "CONTAINER_RUNTIME"];
const NO_API_CLIENT: [&str; 2] = ["DATASTORE", "CONTAINER_RUNTIME"];
/// The roles whose closure is their executable alone.
const STATIC_ROLES: [&str; 2] = ["OBSERVER", "BROKER"];
/// The exec types of the v4 schema's eight backend-component constants, in the schema's order. The model reads them from
/// the schema; the schema is pinned by its canonical digest when the record validator is built, so R10 holds them as a
/// table, and `tests/observer_record_text.rs` asserts the table equal to the vendored schema's constants.
pub const BACKEND_EXEC_TYPES: [&str; 8] = [
    "qualk8s_apiserver_exec_t", "qualk8s_datastore_exec_t", "qualk8s_controller_manager_exec_t", "qualk8s_scheduler_exec_t",
    "qualk8s_kubelet_exec_t", "qualk8s_runtime_exec_t", "qualk8s_proxy_exec_t", "qualk8s_netpol_exec_t",
];
/// A signed endpoint row's five members.
const ENDPOINT_KEYS: [&str; 5] = ["endpointId", "kind", "addressFamily", "ipAddress", "port"];
/// The pinned refusal of a kernel command line outside the grammar (named once, used twice).
const ENROLLED_OUTSIDE: &str = "enrolled boot entry outside the closed kernel parameters";

/// Pinned refusal texts (contract text, verbatim), named where the code around them would otherwise follow the
/// model's token for token (HE-004D1's practice).
const UNIT_TWICE: &str = "maintenance boot entry names the maintenance target twice";
const BEYOND_UNIT: &str = "maintenance boot entry differs from the enrolled entry beyond the maintenance unit";
const BIND_CAPABILITY: &str = "CAP_NET_BIND_SERVICE only for a signed port below 1024";
const FOREIGN_EXECUTABLE: &str = "role closure lists another role's executable";
const STATIC_CLOSURE: &str = "static native role closure is its executable alone";
const ENTRY_LABEL: &str = "entrypoint file label differs from the role's entrypoint type";
const SHARED_BACKEND_EXECUTABLE: &str = "backend components share an executable";
const BACKEND_LABEL: &str = "backend executable label differs from the component's exec type";
/// A record that passed [`check_record`]: the checked record the capture checks take.
pub struct RecordAccepted {
    record: CheckedRecord,
}

impl RecordAccepted {
    /// The checked record (its value and the digest of its canonical encoding).
    pub fn record(&self) -> &CheckedRecord {
        &self.record
    }

    /// The checked record, by value.
    pub fn into_record(self) -> CheckedRecord {
        self.record
    }
}

// ------------------------------------------------------------------------------------------------ helpers

fn refuse_unless(condition: bool, message: &'static str) -> Result<(), Refusal> {
    if condition { Ok(()) } else { Err(Refusal::Model(message)) }
}

/// `value[key]` of an object (Python's `KeyError` or `TypeError` otherwise).
fn at<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Refusal> {
    value.as_object().and_then(|object| object.get(key)).ok_or(Refusal::Missing)
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

/// A list of strings (the record's path and identity lists).
fn texts(value: &Value) -> Result<Vec<String>, Refusal> {
    items(value)?.iter().map(|item| text(item).map(str::to_string)).collect()
}

/// An object of the given members, in order.
fn object(members: Vec<(&str, Value)>) -> Value {
    let mut built = Object::new();
    for (key, member) in members {
        built.insert(JStr::new(key), member);
    }
    Value::Object(built)
}

/// `"sha256:"` and the hex of a value's canonical encoding.
fn canonical_digest(value: &Value) -> Result<String, Refusal> {
    json::canonical(value).map(|encoded| sha256::prefixed(&encoded)).map_err(|_| Refusal::Missing)
}

/// The model's `_path`: an absolute path with no empty, `.` or `..` component.
fn canonical_path(path: &str) -> bool {
    path.strip_prefix('/').is_some_and(|rest| rest.split('/').all(|part| !part.is_empty() && part != "." && part != ".."))
}

/// The model's `_type`: the third colon-separated field of a label (SELinux grants by it).
fn context_type(label: &Value) -> Result<String, Refusal> {
    let parts: Vec<&str> = text(label)?.split(':').collect();
    refuse_unless(parts.len() >= 4 && parts.iter().take(3).all(|part| !part.is_empty()), "malformed SELinux context")?;
    parts.get(2).map(|part| part.to_string()).ok_or(Refusal::Missing)
}

/// A canonical UTC time's seconds.
fn moment(value: &Value) -> Result<u64, Refusal> {
    kernel_text::utc_seconds(text(value)?).ok_or(Refusal::Model("canonical UTC time"))
}

/// The rows Python's `for row in value` yields where each row is then indexed by a key: a list's members; an empty
/// object or text yields none; a non-empty one would index a text by a key (`TypeError`), and other values are not
/// iterable.
fn keyed_rows(value: &Value) -> Result<&[Value], Refusal> {
    match value {
        Value::Array(rows) => Ok(rows),
        Value::Object(object) if object.is_empty() => Ok(&[]),
        Value::Str(name) if name.as_bytes().is_empty() => Ok(&[]),
        _ => Err(Refusal::Missing),
    }
}

/// A key's lookup in a list of (key, row) pairs, as a Python dict reads it: by `==`; a list or object key cannot be
/// hashed (`TypeError`).
fn lookup<'a>(pairs: &[(&'a Value, &'a Value)], key: &Value) -> Result<Option<&'a Value>, Refusal> {
    if key.as_array().is_some() || key.as_object().is_some() {
        return Err(Refusal::Missing);
    }
    Ok(pairs.iter().find(|(name, _)| eq(name, key)).map(|(_, row)| *row))
}

fn role_directory(role: &str) -> Option<&'static str> {
    match role {
        "SERVER" => Some("proxy-server"),
        "OBSERVER" => Some("policy-observer"),
        "BROKER" => Some("capacity-broker"),
        "WORKER" => Some("probe-worker"),
        "EFFECT_GATE" => Some("effect-gate"),
        _ => None,
    }
}

fn hook_directory(hook: &str) -> String {
    hook.to_ascii_lowercase().replace('_', "-")
}

// ------------------------------------------------------------------------------------------------ IP text

/// An IP address as CPython 3.12's `ipaddress.ip_address` reads a text: IPv4 dotted decimal (four octets 0-255, no
/// leading zero) or IPv6 (hex groups, at most one `::`, an optional dotted IPv4 tail, an optional `%` zone, at most 45
/// characters before the zone). R10's own code: std's network module is refused in the observer's sources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpText {
    v6: bool,
    value: u128,
    zone: Option<String>,
}

/// The text's address, or `None` where CPython raises `ValueError`.
pub fn ip_text(address: &str) -> Option<IpText> {
    if let Some(value) = ipv4(address) {
        return Some(IpText { v6: false, value: u128::from(value), zone: None });
    }
    if address.contains('/') {
        return None;
    }
    let (body, zone) = match address.split_once('%') {
        None => (address, None),
        Some((body, zone)) => {
            if zone.is_empty() || zone.contains('%') {
                return None;
            }
            (body, Some(zone.to_string()))
        }
    };
    ipv6(body).map(|value| IpText { v6: true, value, zone })
}

/// Four decimal octets.
fn ipv4(address: &str) -> Option<u32> {
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut value: u32 = 0;
    for octet in octets {
        if octet.is_empty() || octet.len() > 3 || !octet.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if octet != "0" && octet.starts_with('0') {
            return None;
        }
        let number: u32 = octet.parse().ok()?;
        if number > 255 {
            return None;
        }
        value = value.checked_shl(8)? | number;
    }
    Some(value)
}

/// One hex group of one to four hex digits.
fn hextet(group: &str) -> Option<u128> {
    if group.is_empty() || group.len() > 4 || !group.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(group, 16).ok()
}

/// The IPv6 body (without its zone), following CPython's part counting.
fn ipv6(body: &str) -> Option<u128> {
    if body.is_empty() || body.len() > 45 {
        return None;
    }
    let mut parts: Vec<String> = body.splitn(10, ':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last()?.contains('.') {
        let tail = ipv4(&parts.pop()?)?;
        parts.push(format!("{:x}", (tail >> 16) & 0xFFFF));
        parts.push(format!("{:x}", tail & 0xFFFF));
    }
    if parts.len() > 9 {
        return None;
    }
    let last = parts.len().checked_sub(1)?;
    let mut skip = None;
    for index in 1..last {
        if parts.get(index)?.is_empty() {
            if skip.is_some() {
                return None;
            }
            skip = Some(index);
        }
    }
    let (high, low, skipped) = match skip {
        Some(index) => {
            let mut high = index;
            let mut low = last.checked_sub(index)?;
            if parts.first()?.is_empty() {
                high = high.checked_sub(1)?;
                if high != 0 {
                    return None;
                }
            }
            if parts.get(last)?.is_empty() {
                low = low.checked_sub(1)?;
                if low != 0 {
                    return None;
                }
            }
            let skipped = 8usize.checked_sub(high.checked_add(low)?).filter(|skipped| *skipped >= 1)?;
            (high, low, skipped)
        }
        None => {
            if parts.len() != 8 || parts.first()?.is_empty() || parts.get(last)?.is_empty() {
                return None;
            }
            (8, 0, 0)
        }
    };
    let mut value: u128 = 0;
    for group in parts.get(..high)? {
        value = (value.checked_shl(16).unwrap_or(0)) | hextet(group)?;
    }
    value = value.checked_shl(u32::try_from(skipped.checked_mul(16)?).ok()?).unwrap_or(0);
    for group in parts.get(parts.len().checked_sub(low)?..)? {
        value = (value.checked_shl(16).unwrap_or(0)) | hextet(group)?;
    }
    Some(value)
}

fn dotted(value: u32) -> String {
    format!("{}.{}.{}.{}", value >> 24, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)
}

/// RFC 5952's form as CPython writes it: lower-case groups, the longest run of two or more zero groups compressed (the
/// first on ties).
fn compressed(value: u128) -> String {
    let groups: Vec<String> = (0..8u32).rev().map(|place| format!("{:x}", (value >> (16 * place)) & 0xFFFF)).collect();
    let (mut best_start, mut best_length, mut start, mut length) = (0usize, 0usize, 0usize, 0usize);
    for (index, group) in groups.iter().enumerate() {
        if group == "0" {
            if length == 0 {
                start = index;
            }
            length = length.saturating_add(1);
            if length > best_length {
                best_length = length;
                best_start = start;
            }
        } else {
            length = 0;
        }
    }
    if best_length < 2 {
        return groups.join(":");
    }
    let head = groups.get(..best_start).unwrap_or(&[]).join(":");
    let tail = groups.get(best_start.saturating_add(best_length)..).unwrap_or(&[]).join(":");
    format!("{head}::{tail}")
}

impl IpText {
    /// Whether the address is IPv6.
    pub fn is_v6(&self) -> bool {
        self.v6
    }

    /// Whether the address carries a `%` zone.
    pub fn has_zone(&self) -> bool {
        self.zone.is_some()
    }

    /// The IPv4 address an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) holds.
    fn mapped(&self) -> Option<u32> {
        if self.v6 && (self.value >> 32) == 0xFFFF { u32::try_from(self.value & 0xFFFF_FFFF).ok() } else { None }
    }

    /// Whether the address is IPv4-mapped.
    pub fn is_ipv4_mapped(&self) -> bool {
        self.mapped().is_some()
    }

    /// The four octets of an IPv4 address, or of the address an IPv4-mapped one holds.
    fn v4_value(&self) -> Option<u32> {
        if self.v6 { self.mapped() } else { u32::try_from(self.value).ok() }
    }

    /// CPython's `str(ip)`: dotted decimal; RFC 5952 for IPv6, an IPv4-mapped address as `::ffff:a.b.c.d`; the zone
    /// after `%`.
    pub fn canonical(&self) -> String {
        let base = match (self.v6, self.mapped()) {
            (false, _) => dotted(u32::try_from(self.value).unwrap_or(0)),
            (true, Some(v4)) => format!("::ffff:{}", dotted(v4)),
            (true, None) => compressed(self.value),
        };
        match &self.zone {
            Some(zone) => format!("{base}%{zone}"),
            None => base,
        }
    }

    /// `0.0.0.0` or `::` (an IPv4-mapped address by its IPv4 half, as CPython 3.12 reads it).
    pub fn is_unspecified(&self) -> bool {
        match self.v4_value() {
            Some(v4) => v4 == 0,
            None => self.value == 0,
        }
    }

    /// `224.0.0.0/4` or `ff00::/8` (an IPv4-mapped address by its IPv4 half).
    pub fn is_multicast(&self) -> bool {
        match self.v4_value() {
            Some(v4) => (v4 >> 28) == 0xE,
            None => (self.value >> 120) == 0xFF,
        }
    }

    /// `127.0.0.0/8` or `::1`. An IPv4-mapped loopback is not loopback here: R10's stricter reading (MODEL_DEFINED), where
    /// CPython 3.12 reads it by its IPv4 half.
    pub fn is_loopback(&self) -> bool {
        if self.v6 { self.value == 1 } else { (self.value >> 24) == 127 }
    }
}

/// What `ipaddress.ip_address` makes of a JSON value: a text is read as above; an integer or boolean from 0 to 2^128 - 1
/// is an address whose text never equals the value (`None`); anything else is CPython's `ValueError` (an R10 refusal).
fn endpoint_address(value: &Value) -> Result<Option<IpText>, Refusal> {
    let unreadable = Refusal::Model("not an IP address");
    match value {
        Value::Str(_) => value.as_str().and_then(ip_text).map(Some).ok_or(unreadable),
        Value::Bool(_) => Ok(None),
        Value::Int(number) => {
            let below = !number.is_negative()
                && (number.digits() < 39
                    || (number.digits() == 39 && number.to_decimal().as_str() < "340282366920938463463374607431768211456"));
            if below { Ok(None) } else { Err(unreadable) }
        }
        _ => Err(unreadable),
    }
}

// ------------------------------------------------------------------------------------------------ kernel parameters

fn one_or_more(rest: &str, allowed: fn(u8) -> bool) -> bool {
    !rest.is_empty() && rest.bytes().all(allowed)
}

/// `initrd=`'s class: letters, digits and `_` `.` `/` `\` `+` `-`.
fn initrd_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"_./\\+-".contains(&byte)
}

/// `root=UUID=`, `root=PARTUUID=` and `root=LABEL=`'s class: letters, digits and `_` `.` `-`.
fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)
}

/// `root=/dev/`'s class: letters, digits and `_` `/` `.` `-`.
fn device_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"_/.-".contains(&byte)
}

/// Whether a boot-entry word is in the enrolled grammar: one of eleven whole-word matchers.
pub fn kernel_parameter(word: &str) -> bool {
    if let Some(rest) = word.strip_prefix("initrd=") {
        return one_or_more(rest, initrd_byte);
    }
    if let Some(rest) = word.strip_prefix("root=") {
        if let Some(device) = rest.strip_prefix("/dev/") {
            return one_or_more(device, device_byte);
        }
        let named = rest.strip_prefix("UUID=").or_else(|| rest.strip_prefix("PARTUUID=")).or_else(|| rest.strip_prefix("LABEL="));
        return named.is_some_and(|name| one_or_more(name, identifier_byte));
    }
    if let Some(level) = word.strip_prefix("loglevel=") {
        return level.len() == 1 && level.bytes().all(|byte| (b'0'..=b'7').contains(&byte));
    }
    ["ro", "rw", "security=selinux", "selinux=1", "enforcing=1", "lockdown=integrity", "quiet"].contains(&word)
}

// ------------------------------------------------------------------------------------------------ the string walk

/// One step of the walk: a value or a member name.
enum Walk<'a> {
    Node(&'a Value),
    Name(&'a JStr),
}

/// Every member name and every string value of `value`, in document order (the model's `_strings`); iterative, so a
/// deep value cannot exhaust the stack.
pub fn strings(value: &Value) -> Vec<&JStr> {
    let mut found = Vec::new();
    let mut pending = vec![Walk::Node(value)];
    while let Some(step) = pending.pop() {
        match step {
            Walk::Name(name) => found.push(name),
            Walk::Node(Value::Str(content)) => found.push(content),
            Walk::Node(Value::Array(members)) => pending.extend(members.iter().rev().map(Walk::Node)),
            Walk::Node(Value::Object(members)) => {
                for (name, member) in members.iter().rev() {
                    pending.push(Walk::Node(member));
                    pending.push(Walk::Name(name));
                }
            }
            Walk::Node(_) => {}
        }
    }
    found
}

// ------------------------------------------------------------------------------------------------ the shape step

/// The model's shape step of the record: the data bound, the canonical length, then the `record` variant. The digest of
/// the canonical encoding (the configuration's pin form). `check_migration` runs the same step.
pub(crate) fn shape(record: &Value, schema: &RecordSchema) -> Result<String, Refusal> {
    capture_check::bounded(record).map_err(Refusal::Data)?;
    let encoded = json::canonical(record).map_err(|_| Refusal::Data("no canonical encoding"))?;
    if encoded.len() > MAX_BYTES {
        return Err(Refusal::Data("canonical length over 262,144"));
    }
    if !schema.is_valid(record) {
        return Err(Refusal::Schema);
    }
    Ok(sha256::prefixed(&encoded))
}

// ------------------------------------------------------------------------------------------------ signed endpoints

/// The model's `_endpoint_rows`: one to sixteen closed rows, each a fixed canonical numeric address of the right family,
/// kind and port, no tuple twice. The rows by identifier, in order.
fn endpoint_rows(endpoints: &Value) -> Result<Vec<(&Value, &Value)>, Refusal> {
    let rows = endpoints.as_array().filter(|rows| (1..=16).contains(&rows.len()));
    let rows = rows.ok_or(Refusal::Model("bounded signed endpoints"))?;
    let mut by_id: Vec<(&Value, &Value)> = Vec::new();
    let mut tuples: BTreeSet<(String, i128)> = BTreeSet::new();
    for row in rows {
        let closed = row.as_object().is_some_and(|members| members.len() == 5 && ENDPOINT_KEYS.iter().all(|key| members.get(key).is_some()));
        let fresh = if closed { lookup(&by_id, at(row, "endpointId")?)?.is_none() } else { false };
        refuse_unless(closed && fresh, "unique closed endpoint tuples")?;
        let address = at(row, "ipAddress")?;
        let ip = endpoint_address(address)?;
        let ip = match ip {
            Some(ip) if address.as_str() == Some(ip.canonical().as_str()) && !ip.is_unspecified() && !ip.is_multicast()
                && !(ip.is_v6() && (ip.is_ipv4_mapped() || ip.has_zone())) => ip,
            _ => return Err(Refusal::Model("fixed canonical numeric endpoint")),
        };
        let family = if ip.is_v6() { "IPV6" } else { "IPV4" };
        let kind = at(row, "kind")?;
        let port = at(row, "port")?.as_int().and_then(|number| number.to_i128());
        let known_kind = ["CAMPAIGN_PROXY", "KUBERNETES_API_PROXY"].iter().any(|name| eq(kind, &Value::str(name)));
        refuse_unless(eq(at(row, "addressFamily")?, &Value::str(family)) && known_kind && port.is_some_and(|port| (1..=65535).contains(&port)),
                "endpoint family/type")?;
        let tuple = (text(address)?.to_string(), port.ok_or(Refusal::Missing)?);
        refuse_unless(!tuples.contains(&tuple), "duplicate signed endpoint tuple")?;
        tuples.insert(tuple);
        by_id.push((at(row, "endpointId")?, row));
    }
    Ok(by_id)
}

// ------------------------------------------------------------------------------------------------ code inventories

/// One code inventory by path: canonical paths, no path twice, content and verity digests distinct, every executable
/// segment inside the artifact's pages and listed once, the total size within `bound`.
fn inventory(rows: &[Value], bound: i128) -> Result<BTreeMap<String, &Value>, Refusal> {
    let mut found: BTreeMap<String, &Value> = BTreeMap::new();
    for row in rows {
        let path = at(row, "path")?;
        refuse_unless(path.as_str().is_some_and(canonical_path), "canonical installed path")?;
        let path = text(path)?;
        refuse_unless(!found.contains_key(path) && !eq(at(row, "sha256")?, at(row, "verityDigest")?), "duplicate file or conflated digest")?;
        found.insert(path.to_string(), row);
        let size = int(at(row, "size")?)?;
        let pages = size.checked_add(4095).map(|sum| sum.div_euclid(4096)).and_then(|count| count.checked_mul(4096));
        let pages = pages.ok_or(Refusal::Missing)?;
        let mut occupied: BTreeSet<(i128, i128, String)> = BTreeSet::new();
        for segment in items(at(row, "executableSegments")?)? {
            let (offset, length) = (int(at(segment, "offset")?)?, int(at(segment, "length")?)?);
            let key = (offset, length, text(at(segment, "permissions")?)?.to_string());
            let end = offset.checked_add(length).ok_or(Refusal::Missing)?;
            refuse_unless(!occupied.contains(&key) && end <= pages, "executable segment outside artifact")?;
            occupied.insert(key);
        }
    }
    let mut total: i128 = 0;
    for row in found.values() {
        total = total.saturating_add(int(at(row, "size")?)?);
    }
    refuse_unless(total <= bound, "code inventory bound")?;
    Ok(found)
}

/// Code ownership by path and by content and verity digest: one owner class per byte string (the roles together, each
/// lifecycle subject, the backend).
struct Owners {
    by_path: BTreeMap<String, String>,
    by_sha256: BTreeMap<String, String>,
    by_verity: BTreeMap<String, String>,
}

impl Owners {
    fn new() -> Owners {
        Owners { by_path: BTreeMap::new(), by_sha256: BTreeMap::new(), by_verity: BTreeMap::new() }
    }

    /// One subject's closure: custody of its artifact, its interpreter enrolled, its loaded image executable, and each
    /// path's three keys owned by `owner` alone.
    fn own(&mut self, listed: &Value, rows: &BTreeMap<String, &Value>, owner: &str, executable: &Value, artifact: &Value,
           interpreter: &Value) -> Result<(), Refusal> {
        let paths = texts(listed)?;
        let executable = text(executable)?;
        let custody = paths.iter().all(|path| rows.contains_key(path)) && paths.iter().any(|path| path == executable)
            && rows.get(executable).is_some_and(|row| row.get("sha256").is_some_and(|digest| eq(digest, artifact)));
        refuse_unless(custody, "artifact custody")?;
        let loaded = if interpreter.is_null() {
            executable
        } else {
            let enrolled = interpreter.as_str().filter(|name| paths.iter().any(|path| path == name));
            enrolled.ok_or(Refusal::Model("interpreter not enrolled"))?
        };
        let image = rows.get(loaded).ok_or(Refusal::Missing)?;
        let segments = at(image, "executableSegments")?.as_array().is_some_and(|list| !list.is_empty());
        refuse_unless(eq(at(image, "mode")?, &Value::str("0555")) && segments, "actual executable missing")?;
        for path in &paths {
            let row = rows.get(path).ok_or(Refusal::Missing)?;
            let keys = [path.clone(), text(at(row, "sha256")?)?.to_string(), text(at(row, "verityDigest")?)?.to_string()];
            for (index, key) in keys.into_iter().enumerate() {
                let table = match index {
                    0 => &mut self.by_path,
                    1 => &mut self.by_sha256,
                    _ => &mut self.by_verity,
                };
                let previous = table.entry(key).or_insert_with(|| owner.to_string());
                if previous.as_str() != owner {
                    let both_lifecycle = LIFECYCLE.contains(&previous.as_str()) && LIFECYCLE.contains(&owner);
                    refuse_unless(!both_lifecycle, "lifecycle subjects share code")?;
                    return Err(Refusal::Model("code shared across owner classes"));
                }
            }
        }
        Ok(())
    }
}

/// The digest the seal marker must hold, over the boot ID, the policy digest, the containment artifact's digest and
/// the sorted (role, hook, program ID, translated digest) rows.
fn seal_digest(record: &Value) -> Result<String, Refusal> {
    let roles = at(record, "roles")?;
    let mut programs: Vec<(&str, &str, Value, Value)> = Vec::with_capacity(ROLES.len().saturating_mul(HOOKS.len()));
    for role in ROLES {
        let assigned = at(at(roles, role)?, "bpfPrograms")?;
        for hook in HOOKS {
            let program = at(assigned, hook)?;
            programs.push((role, hook, at(program, "programId")?.clone(), at(program, "translatedSha256")?.clone()));
        }
    }
    programs.sort_by(|left, right| (left.0, left.1).cmp(&(right.0, right.1)));
    let rows = programs.into_iter().map(|(role, hook, id, digest)| Value::Array(vec![Value::str(role), Value::str(hook), id, digest]));
    let content = object(vec![
        ("schemaVersion", Value::str(SEAL_VERSION)),
        ("bootId", at(at(record, "host")?, "bootId")?.clone()),
        ("policyDigest", at(at(record, "selinux")?, "policyDigest")?.clone()),
        ("containmentArtifactDigest", at(at(at(record, "lifecycleSubjects")?, "HOST_CONTAINMENT")?, "artifactDigest")?.clone()),
        ("programs", Value::Array(rows.collect())),
    ]);
    canonical_digest(&content)
}

/// The sha256 and verity keys of one inventory row.
fn content_keys(row: &Value) -> Result<[(&'static str, String); 2], Refusal> {
    Ok([("sha256", text(at(row, "sha256")?)?.to_string()), ("verity", text(at(row, "verityDigest")?)?.to_string())])
}

// ------------------------------------------------------------------------------------------------ check_record

/// The model's `check_record` (see the module documentation for the order). On success, the checked record.
pub fn check_record(record: &Value, profile: &Value, endpoints: &Value, schema: &RecordSchema) -> Result<RecordAccepted, Refusal> {
    let is_v4 = record.as_object().is_some()
        && record.get("schemaVersion").and_then(Value::as_str) == Some(V4_RECORD.0)
        && record.get("qualificationProfile").and_then(Value::as_str) == Some(V4_RECORD.1);
    refuse_unless(is_v4, "not a v4 record")?;
    let digest = shape(record, schema)?;
    refuse_unless(eq(at(record, "profileDigest")?, &Value::str(&canonical_digest(profile)?)), "profile substitution")?;

    // The boot entries.
    let entries = at(record, "bootEntries")?;
    let (enrolled_entry, maintenance_entry) = (at(entries, "ENROLLED")?, at(entries, "MAINTENANCE")?);
    let enrolled_line = text(at(enrolled_entry, "kernelCmdline")?)?;
    let maintenance_line = text(at(maintenance_entry, "kernelCmdline")?)?;
    refuse_unless(!eq(at(enrolled_entry, "entryId")?, at(maintenance_entry, "entryId")?) && enrolled_line != maintenance_line,
            "enrolled and maintenance boot entries indistinguishable")?;
    let enrolled: Vec<&str> = enrolled_line.split(' ').collect();
    let maintenance: Vec<&str> = maintenance_line.split(' ').collect();
    refuse_unless(enrolled.iter().all(|word| kernel_parameter(word)), ENROLLED_OUTSIDE)?;
    refuse_unless(enrolled.contains(&"lockdown=integrity"), "enrolled boot entry without lockdown=integrity")?;
    refuse_unless(maintenance.iter().all(|word| kernel_parameter(word) || *word == MAINTENANCE_UNIT),
            "maintenance boot entry outside the closed kernel parameters")?;
    refuse_unless(maintenance.contains(&MAINTENANCE_UNIT), "maintenance boot entry does not select the maintenance target")?;
    refuse_unless(maintenance.iter().filter(|word| **word == MAINTENANCE_UNIT).count() == 1,
            UNIT_TWICE)?;
    let beyond: Vec<&str> = maintenance.iter().copied().filter(|word| *word != MAINTENANCE_UNIT).collect();
    refuse_unless(beyond == enrolled, BEYOND_UNIT)?;

    // The scope, the window and the resource labels.
    let binding = at(profile, "binding")?;
    let scope = at(record, "scope")?;
    let mut bound = Object::new();
    for (name, _) in scope.as_object().ok_or(Refusal::Missing)?.iter() {
        bound.insert(name.clone(), at(binding, name.as_str().ok_or(Refusal::Missing)?)?.clone());
    }
    refuse_unless(eq(scope, &Value::Object(bound)), "scope substitution")?;
    let (start, end) = (moment(at(scope, "validFrom")?)?, moment(at(scope, "expiresAt")?)?);
    refuse_unless(start < end && end.saturating_sub(start) <= 900, "canonical half-open window")?;
    let labels = object(vec![("planeon.ai/run-nonce", at(binding, "runNonce")?.clone()),
                             ("planeon.ai/tenant-id", at(binding, "tenantId")?.clone())]);
    let resources = at(profile, "resources")?;
    for row in keyed_rows(resources)? {
        refuse_unless(eq(at(at(at(row, "manifest")?, "metadata")?, "labels")?, &labels), "profile resource labels differ from the binding")?;
    }

    // The signed endpoints.
    let signed = endpoint_rows(endpoints)?;
    refuse_unless(eq(at(record, "endpointTuples")?, endpoints), "endpoint tuple substitution")?;
    let endpoint_id = at(binding, "endpointId")?;
    let proxy = lookup(&signed, endpoint_id)?;
    let api_id = at(binding, "apiEndpointId")?;
    let api = if api_id.is_null() { None } else { lookup(&signed, api_id)? };
    let with_resources = resources.as_array().is_some_and(|rows| !rows.is_empty());
    let kind_is = |row: Option<&Value>, kind: &str| row.and_then(|row| row.get("kind")).is_some_and(|found| eq(found, &Value::str(kind)));
    let api_kind = if with_resources { kind_is(api, "KUBERNETES_API_PROXY") } else { api_id.is_null() };
    refuse_unless(kind_is(proxy, "CAMPAIGN_PROXY") && api_kind, "profile endpoint kinds")?;
    let internal = items(at(record, "internalEndpoints")?)?.first().ok_or(Refusal::Missing)?;
    let internal_ip = ip_text(text(at(internal, "ipAddress")?)?).ok_or(Refusal::Model("not an IP address"))?;
    let internal_id = at(internal, "endpointId")?;
    let separate = signed.iter().all(|(_, row)| {
        !(row.get("ipAddress").is_some_and(|address| internal.get("ipAddress").is_some_and(|other| eq(address, other)))
            && row.get("port").is_some_and(|port| internal.get("port").is_some_and(|other| eq(port, other))))
    });
    let internal_family = if internal_ip.is_v6() { "IPV6" } else { "IPV4" };
    refuse_unless(internal_ip.is_loopback() && eq(at(internal, "addressFamily")?, &Value::str(internal_family))
                && lookup(&signed, internal_id)?.is_none() && separate,
            "loopback apiserver endpoint must stay internal")?;
    refuse_unless(int(at(at(at(record, "selinux")?, "status")?, "sequence")?)?.rem_euclid(2) == 0, "unstable policy epoch")?;

    // The two inventories and the roles.
    let planeon_rows = items(at(record, "files")?)?;
    let backend_list = items(at(record, "backendFiles")?)?;
    let planeon = inventory(planeon_rows, PLANEON_CODE_BYTES)?;
    let backend = inventory(backend_list, BACKEND_CODE_BYTES)?;
    refuse_unless(planeon.keys().all(|path| !backend.contains_key(path)), "planeon and backend inventories overlap")?;
    let mut owners = Owners::new();
    let roles = at(record, "roles")?;
    let empty = Value::Array(Vec::new());
    let api_list = if with_resources { Value::Array(vec![api_id.clone()]) } else { Value::Array(Vec::new()) };
    let internal_list = Value::Array(vec![internal_id.clone()]);
    let port_of = |row: Option<&Value>| row.and_then(|row| row.get("port")).ok_or(Refusal::Missing).and_then(int);
    let mut program_ids: BTreeSet<i128> = BTreeSet::new();
    let mut inodes: BTreeSet<i128> = BTreeSet::new();
    for role in ROLES {
        let row = at(roles, role)?;
        owners.own(at(row, "filePaths")?, &planeon, "role", at(row, "executable")?, at(row, "artifactDigest")?,
                   at(row, "interpreterPath")?)?;
        let inode = int(at(at(row, "cgroup")?, "inode")?)?;
        refuse_unless(!inodes.contains(&inode), "duplicate cgroup inode")?;
        inodes.insert(inode);
        let (listen, outbound) = (at(row, "listenEndpointIds")?, at(row, "outboundEndpointIds")?);
        let bound_ports: Vec<i128> = match role {
            "SERVER" => {
                refuse_unless(eq(listen, &Value::Array(vec![endpoint_id.clone()])) && eq(outbound, &api_list), "server endpoints differ")?;
                vec![port_of(proxy)?]
            }
            "EFFECT_GATE" => {
                refuse_unless(eq(listen, &api_list) && eq(outbound, &internal_list), "gate endpoints differ")?;
                if with_resources { vec![port_of(api)?] } else { Vec::new() }
            }
            "OBSERVER" => {
                refuse_unless(eq(listen, &empty) && eq(outbound, &internal_list), "observer endpoints differ")?;
                Vec::new()
            }
            "BROKER" => {
                refuse_unless(eq(listen, &empty) && eq(outbound, &empty), "broker network grant")?;
                Vec::new()
            }
            _ => {
                refuse_unless(eq(listen, &empty) && eq(outbound, &empty), "worker network grant")?;
                Vec::new()
            }
        };
        let capabilities = at(row, "capabilities")?;
        if role == "SERVER" {
            let binds = items(capabilities)?.iter().any(|name| eq(name, &Value::str("CAP_NET_BIND_SERVICE")));
            refuse_unless(binds == bound_ports.iter().any(|port| *port < 1024), BIND_CAPABILITY)?;
        }
        if role == "EFFECT_GATE" {
            refuse_unless(eq(capabilities, &empty) && bound_ports.iter().all(|port| *port >= 1024),
                    "EFFECT_GATE holds no capability and its signed I04 port is 1024 or above")?;
        }
        let programs = at(row, "bpfPrograms")?;
        let directory = role_directory(role).ok_or(Refusal::Missing)?;
        for hook in HOOKS {
            let program = at(programs, hook)?;
            let wanted = if hook == "INET_SOCK_CREATE" { 9 } else { 18 };
            refuse_unless(int(at(program, "programType")?)? == wanted && int(at(program, "instructionBytes")?)?.rem_euclid(8) == 0,
                    "wrong kernel program type/length")?;
            let pin = format!("{PIN_ROOT}/{directory}/{}", hook_directory(hook));
            refuse_unless(at(program, "pinPath")?.as_str() == Some(pin.as_str()), "program pin outside the sealed layout")?;
            let id = int(at(program, "programId")?)?;
            refuse_unless(!program_ids.contains(&id), "program shared between hooks or roles")?;
            program_ids.insert(id);
        }
    }

    // The executables, the interpreters and the native-only closures.
    let mut executables: BTreeMap<(&'static str, String), &str> = BTreeMap::new();
    for role in ROLES {
        let row = planeon.get(text(at(at(roles, role)?, "executable")?)?).ok_or(Refusal::Missing)?;
        for key in content_keys(row)? {
            refuse_unless(!executables.contains_key(&key), "role executables share content")?;
            executables.insert(key, role);
        }
    }
    let mut interpreters: BTreeSet<String> = BTreeSet::new();
    for role in ROLES {
        let path = at(at(roles, role)?, "interpreterPath")?;
        if !path.is_null() {
            interpreters.insert(text(path)?.to_string());
        }
    }
    let mut interpreter_content: BTreeSet<(&'static str, String)> = BTreeSet::new();
    for path in &interpreters {
        let row = planeon.get(path).ok_or(Refusal::Missing)?;
        let keys = content_keys(row)?;
        refuse_unless(keys.iter().all(|key| !executables.contains_key(key)), "role executable equal to an interpreter")?;
        interpreter_content.extend(keys);
    }
    let mut tree_content: BTreeSet<(&'static str, String)> = BTreeSet::new();
    for (path, row) in &planeon {
        if path.starts_with(INTERPRETER_TREE) {
            tree_content.extend(content_keys(row)?);
        }
    }
    let mut role_executables: Vec<&str> = Vec::with_capacity(ROLES.len());
    for role in ROLES {
        role_executables.push(text(at(at(roles, role)?, "executable")?)?);
    }
    for role in ROLES {
        let row = at(roles, role)?;
        let executable = text(at(row, "executable")?)?;
        let native_only = at(row, "interpreterPath")?.is_null();
        for path in texts(at(row, "filePaths")?)? {
            let keys = content_keys(planeon.get(&path).ok_or(Refusal::Missing)?)?;
            if path != executable {
                let foreign = keys.iter().any(|key| executables.get(key).is_some_and(|owner| *owner != role));
                refuse_unless(!foreign && role_executables.iter().all(|other| path != *other), FOREIGN_EXECUTABLE)?;
            }
            if native_only {
                refuse_unless(!interpreters.contains(&path) && !keys.iter().any(|key| interpreter_content.contains(key))
                            && !path.starts_with(INTERPRETER_TREE) && !keys.iter().any(|key| tree_content.contains(key)),
                        "native-only role closure lists an interpreter")?;
            }
        }
    }

    // The lifecycle subjects and the seal marker.
    let lifecycle = at(record, "lifecycleSubjects")?;
    for name in LIFECYCLE {
        let row = at(lifecycle, name)?;
        owners.own(at(row, "filePaths")?, &planeon, name, at(row, "executable")?, at(row, "artifactDigest")?, &Value::Null)?;
    }
    refuse_unless(owners.by_path.keys().eq(planeon.keys()), "unowned planeon code")?;
    let marker = at(at(at(record, "hardening")?, "sealMarker")?, "digest")?;
    refuse_unless(marker.as_str() == Some(seal_digest(record)?.as_str()), "seal marker does not bind this boot")?;

    // The closures and the entrypoint labels.
    for role in ROLES {
        let row = at(roles, role)?;
        let executable = at(row, "executable")?;
        let listed = at(row, "filePaths")?;
        if STATIC_ROLES.contains(&role) {
            refuse_unless(eq(listed, &Value::Array(vec![executable.clone()])), STATIC_CLOSURE)?;
        }
        if !at(row, "interpreterPath")?.is_null() {
            let mut typed = true;
            for path in texts(listed)? {
                let entry = planeon.get(&path).ok_or(Refusal::Missing)?;
                let loaded = at(entry, "executableSegments")?.as_array().is_some_and(|list| !list.is_empty());
                if executable.as_str() == Some(path.as_str()) || !loaded {
                    continue;
                }
                if context_type(at(entry, "selinuxLabel")?)? != context_type(at(row, "interpreterLabel")?)? {
                    typed = false;
                    break;
                }
            }
            refuse_unless(typed, "interpreter closure file outside the dedicated interpreter type")?;
        }
    }
    let mut named: Vec<(&str, &Value)> = Vec::with_capacity(ROLES.len().saturating_add(LIFECYCLE.len()));
    for role in ROLES {
        named.push((role, at(roles, role)?));
    }
    for name in LIFECYCLE {
        named.push((name, at(lifecycle, name)?));
    }
    let mut entry_labels: BTreeMap<String, &str> = BTreeMap::new();
    for (name, row) in &named {
        let first = *entry_labels.entry(context_type(at(row, "executableLabel")?)?).or_insert(*name);
        refuse_unless(first == *name, "two roles share an entrypoint label")?;
        let entry = planeon.get(text(at(row, "executable")?)?).ok_or(Refusal::Missing)?;
        refuse_unless(context_type(at(entry, "selinuxLabel")?)? == context_type(at(row, "executableLabel")?)?,
                ENTRY_LABEL)?;
    }

    // The backend components.
    let components = at(record, "backendComponents")?;
    let members = components.as_object().ok_or(Refusal::Missing)?;
    let mut names: Vec<String> = Vec::with_capacity(members.len());
    for (name, _) in members.iter() {
        names.push(name.as_str().ok_or(Refusal::Missing)?.to_string());
    }
    names.sort();
    let mut keys = texts(at(at(record, "backendProfile")?, "componentKeys")?)?;
    keys.sort();
    refuse_unless(names == keys && REQUIRED_BACKEND.iter().all(|name| members.get(name).is_some()),
            "backend components differ from the implementation profile")?;
    let mut planeon_labels: BTreeSet<String> = BTreeSet::new();
    for (_, row) in &named {
        planeon_labels.insert(text(at(row, "processLabel")?)?.to_string());
    }
    let (mut labels_seen, mut cgroups_seen, mut identities_seen) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let slice = capture_check::slice();
    for name in &names {
        let row = at(components, name)?;
        owners.own(at(row, "filePaths")?, &backend, "backend", at(row, "executable")?, at(row, "artifactDigest")?, &Value::Null)?;
        let label = text(at(row, "processLabel")?)?;
        let domain = label.split(':').nth(2).ok_or(Refusal::Missing)?;
        refuse_unless(!planeon_labels.contains(label) && !domain.starts_with("planeon_"), "backend component in a planeon domain")?;
        refuse_unless(!labels_seen.contains(label), "backend components share a domain")?;
        labels_seen.insert(label.to_string());
        let cgroup = at(row, "cgroupPath")?;
        refuse_unless(cgroup.as_str().is_some_and(canonical_path), "canonical installed path")?;
        let cgroup = text(cgroup)?;
        refuse_unless(cgroup.starts_with(&format!("{CGROUP_ROOT}/")), "backend cgroup outside cgroupfs")?;
        refuse_unless(cgroup != slice && !cgroup.starts_with(&format!("{slice}/")), "backend component inside the planeon slice")?;
        refuse_unless(!cgroups_seen.contains(cgroup), "backend components share a cgroup")?;
        let nested = cgroups_seen.iter().any(|seen: &String| cgroup.starts_with(&format!("{seen}/")) || seen.starts_with(&format!("{cgroup}/")));
        refuse_unless(!nested, "backend cgroup nested in another backend cgroup")?;
        let identities = texts(at(row, "apiIdentities")?)?;
        refuse_unless(identities.iter().filter(|identity| identity.starts_with("system:node:")).count() <= 1, "more than one node identity")?;
        cgroups_seen.insert(cgroup.to_string());
        if NO_API_CLIENT.contains(&name.as_str()) {
            refuse_unless(identities.is_empty(), "backend API identity")?;
        } else if name != "APISERVER" {
            refuse_unless(!identities.is_empty(), "backend API identity")?;
        }
        refuse_unless(!identities.iter().any(|identity| identities_seen.contains(identity)), "backend components share an API identity")?;
        identities_seen.extend(identities);
    }
    let unplaced: Vec<&String> = owners.by_path.keys().filter(|path| !planeon.contains_key(*path)).collect();
    refuse_unless(unplaced.into_iter().eq(backend.keys()), "unowned backend code")?;
    let mut component_executables: Vec<&str> = Vec::with_capacity(names.len());
    for name in &names {
        component_executables.push(text(at(at(components, name)?, "executable")?)?);
    }
    let distinct: BTreeSet<&str> = component_executables.iter().copied().collect();
    refuse_unless(distinct.len() == component_executables.len(), SHARED_BACKEND_EXECUTABLE)?;
    for name in &names {
        let row = at(components, name)?;
        let entry = backend.get(text(at(row, "executable")?)?).ok_or(Refusal::Missing)?;
        refuse_unless(context_type(at(entry, "selinuxLabel")?)? == context_type(at(row, "executableLabel")?)?,
                BACKEND_LABEL)?;
    }

    // The census inside the set: a subject's entrypoint or exec type may sit on that subject's executable alone, and
    // the interpreter type on nothing outside the interpreted closures.
    let mut subjects: Vec<&Value> = named.iter().map(|(_, row)| *row).collect();
    subjects.extend(members.iter().map(|(_, row)| row));
    let mut typed_entries: Vec<(String, String)> = Vec::with_capacity(subjects.len());
    for row in &subjects {
        typed_entries.push((context_type(at(row, "executableLabel")?)?, text(at(row, "executable")?)?.to_string()));
    }
    let mut entry_owner: BTreeMap<String, Option<String>> = BACKEND_EXEC_TYPES.iter().map(|kind| (kind.to_string(), None)).collect();
    for (kind, executable) in typed_entries {
        entry_owner.insert(kind, Some(executable));
    }
    let every_row: Vec<&Value> = planeon_rows.iter().chain(backend_list.iter()).collect();
    for row in &every_row {
        let path = text(at(row, "path")?)?;
        let held = match entry_owner.get(&context_type(at(row, "selinuxLabel")?)?) {
            None => true,
            Some(owner) => owner.as_deref() == Some(path),
        };
        refuse_unless(held, "entrypoint type labels a file other than its subject's executable")?;
    }
    let mut interpreted: BTreeSet<String> = BTreeSet::new();
    let mut elsewhere: BTreeSet<String> = BTreeSet::new();
    for role in ROLES {
        let row = at(roles, role)?;
        let target = if at(row, "interpreterPath")?.is_null() { &mut elsewhere } else { &mut interpreted };
        target.extend(texts(at(row, "filePaths")?)?);
    }
    for name in LIFECYCLE {
        elsewhere.extend(texts(at(at(lifecycle, name)?, "filePaths")?)?);
    }
    for (_, row) in members.iter() {
        elsewhere.extend(texts(at(row, "filePaths")?)?);
    }
    for row in &subjects {
        elsewhere.insert(text(at(row, "executable")?)?.to_string());
    }
    let mut interpreter_types: BTreeSet<String> = BTreeSet::new();
    for role in ROLES {
        let label = at(at(roles, role)?, "interpreterLabel")?;
        if !label.is_null() {
            interpreter_types.insert(context_type(label)?);
        }
    }
    for row in &every_row {
        let path = text(at(row, "path")?)?;
        refuse_unless(!interpreter_types.contains(&context_type(at(row, "selinuxLabel")?)?)
                    || (interpreted.contains(path) && !elsewhere.contains(path)),
                "interpreter type outside the interpreted closures")?;
    }
    Ok(RecordAccepted { record: checked_record(record.clone(), digest) })
}
