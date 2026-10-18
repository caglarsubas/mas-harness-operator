//! The enrolled qualification record (HE-004D1 DESIGN-D1 sections 5.2 and 7; owner decision Q-HE4D1-2 (a); MODEL_DEFINED
//! R121 and R123): its read by path and pin, its form, and the checked record the capture checks take. It runs in
//! `serve`, after the seal, once.
//!
//! [`load_record`] follows R73's reader: the named file is opened in its parent directory with gate-sys's read-only
//! `Dir` (`file_ro`: no-follow, non-blocking, a regular file), sized by `fstat` (1 to 262,144 bytes, the model's
//! `MAX_BYTES`), read into a buffer of size + 1 with `signed_config::fill` (the EOF probe) and pinned by its sha256 (status
//! 26). Then its form (status 27): ASCII, at most 32,768 structural tokens (HE-004C's node-count method), strict JSON
//! through i05-protocol, depth at most 16, no float, |integer| at most 2^53 - 1, and the bytes equal to i05-protocol's
//! canonical encoding of the value. So the configuration's pin is the sha256 of the record's canonical encoding, which
//! the model's capture binding requires of every capture's `qualificationDigest`.
//!
//! [`Enrolled::new`] (section 7) runs once, after the record is read: its form (27) is the v4 identity, the model's data
//! bound (`capture_check::bounded`), the canonical length and the `record` variant, which together are the model's
//! per-call shape step of the record (R10 runs it once: the record is immutable for the epoch, and the check functions
//! take the [`CheckedRecord`](crate::capture_check::CheckedRecord) only this constructor makes). Then R10's read-path
//! preconditions (28), which hold independently of HE-004D2's `check_record`: every cgroup path (the five roles,
//! `HOST_CONTAINMENT` and every backend component) is the cgroup2 root, `/` and a relative path of 1 to 16 components
//! of `[A-Za-z0-9_.+-]` (the roles' under its `planeon.slice`); every pin path is the pin root, `/` and such a path;
//! every enrolled path (`files`, `backendFiles`, the seal marker) is absolute and such a path after its `/`; each
//! `files` row is at most 64 MiB and each `backendFiles` row at most 1 GiB (the schema's maxima), with totals of at most
//! 512 MiB (`files`) and 4 GiB (`backendFiles`), so the per-epoch hashing is bounded; each role's `pidsMax` is at
//! most 4,096; every `filePaths` entry names a `files` row and every backend `executable` a `backendFiles` row. Then the
//! window (29): `validFrom` and `expiresAt` canonical UTC with `validFrom < expiresAt`, and `expiresAt` after the wall
//! clock at start (an enrollment already over is a setup fault; a `validFrom` in the future is not, and captures wait
//! for it). An unusable wall clock is 97, as for the configuration's lifetime.

use std::collections::BTreeMap;
use std::io::Read;

use gate_sys::Dir;
use i05_protocol::json::{self, Value};
use i05_protocol::sha256;

use crate::capture_check::{self, capture_class, checked_record, CheckedRecord, HOOKS, ROLES, V4_RECORD};
use crate::capture_schema::RecordSchema;
use crate::config::FileRef;
use crate::kernel_text;
use crate::observe::structural_tokens;
use crate::signed_config::fill;

/// The cgroup2 root and the pin root (G-D1-5: this module's two path literals).
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PIN_ROOT: &str = "/sys/fs/bpf/planeon";

/// The largest record (the model's `MAX_BYTES`).
pub const RECORD_LIMIT: usize = 262_144;
/// The record's structural-token cap (a value has at most this many nodes plus one).
pub const RECORD_NODE_CAP: usize = 32_768;
/// The deepest nesting of the record.
pub const RECORD_DEPTH: usize = 16;
/// The largest integer magnitude, 2^53 - 1.
pub const MAX_MAGNITUDE: u64 = (1 << 53) - 1;

/// Why the capture setup refused (statuses 25-30, `status::capture_setup`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupError {
    /// The embedded schema: its canonical pin, a conditional outside the closed form, or its load (25).
    Schema(&'static str),
    /// The record's open, size, read or pin (26).
    RecordRead(&'static str),
    /// The record's form: the canonical subset, the node cap, not a v4 record, the data bound or its variant (27).
    RecordForm(&'static str),
    /// R10's read-path preconditions (28).
    RecordTargets(&'static str),
    /// The validity window: not canonical UTC, not ordered, or already over at start (29).
    RecordWindow(&'static str),
    /// The capture roots: an open or its filesystem magic (30).
    Roots(&'static str),
    /// The wall clock is before the epoch at the window check (97, `status::lifetime`).
    Clock,
}

/// The record as read: its bytes, its parsed value and its pin (`sha256:` + the hex of the bytes).
pub struct RecordBytes {
    pub bytes: Vec<u8>,
    pub value: Value,
    pub pin: String,
}

/// Reads and pins the record file that `reference` names (status 26), then checks its form (27).
pub fn load_record(reference: &FileRef) -> Result<RecordBytes, SetupError> {
    let read = |why: &'static str| SetupError::RecordRead(why);
    let (parent, name) = reference.path.rsplit_once('/').ok_or(read("the record path has no directory"))?;
    let parent = if parent.is_empty() { "/" } else { parent };
    let directory = Dir::at(parent).map_err(|_| read("the record's directory does not open"))?;
    let mut opened = directory.file_ro(name).map_err(|_| read("the record does not open as a regular file"))?;
    let size = opened.metadata().map_err(|_| read("the record's size"))?.len();
    let size = usize::try_from(size).map_err(|_| read("the record's size"))?;
    let bytes = read_pinned(&mut opened, size, &reference.sha256)?;
    let value = record_form(&bytes)?;
    Ok(RecordBytes { pin: reference.sha256.clone(), bytes, value })
}

/// The record's bytes from `reader` (status 26): `size` from `fstat` must be 1 to 262,144; the bytes are read into a
/// buffer of size + 1 (the EOF probe: a record that grew or shrank is refused) and must hash to `pin`.
pub fn read_pinned(reader: &mut impl Read, size: usize, pin: &str) -> Result<Vec<u8>, SetupError> {
    let read = |why: &'static str| SetupError::RecordRead(why);
    if size == 0 || size > RECORD_LIMIT {
        return Err(read("the record is not 1 to 262,144 bytes"));
    }
    let mut buffer = vec![0u8; size.saturating_add(1)];
    let filled = fill(reader, &mut buffer).map_err(|_| read("the record's read failed"))?;
    if filled != size {
        return Err(read("the record grew or shrank while it was read"));
    }
    buffer.truncate(size);
    if sha256::prefixed(&buffer) != pin {
        return Err(read("the record's sha256 differs from its pin"));
    }
    Ok(buffer)
}

/// The record's form (status 27): see the module documentation.
pub fn record_form(bytes: &[u8]) -> Result<Value, SetupError> {
    let form = |why: &'static str| SetupError::RecordForm(why);
    if !bytes.is_ascii() {
        return Err(form("the record holds a byte outside ASCII"));
    }
    if structural_tokens(bytes) > RECORD_NODE_CAP {
        return Err(form("the record exceeds the node-count cap"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| form("the record is not UTF-8"))?;
    let value = json::parse(text).map_err(|_| form("the record is not strict JSON"))?;
    if json::depth(&value) > RECORD_DEPTH {
        return Err(form("the record nests deeper than 16"));
    }
    if json::contains_float(&value) {
        return Err(form("the record holds a float"));
    }
    let mut stack = vec![&value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Int(int) => {
                let magnitude = int.to_i128().map(i128::unsigned_abs);
                if magnitude.is_none_or(|magnitude| magnitude > u128::from(MAX_MAGNITUDE)) {
                    return Err(form("an integer beyond 2^53 - 1"));
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(object) => stack.extend(object.iter().map(|(_, member)| member)),
            _ => {}
        }
    }
    let encoded = json::canonical(&value).map_err(|_| form("the record has no canonical form"))?;
    if encoded != bytes {
        return Err(form("the record is not its canonical encoding"));
    }
    Ok(value)
}

/// The largest planeon and backend inventory rows (the schema's `file` and `backendFile` size maxima), and the totals
/// of the two inventories (the model's bounds).
pub const MAX_ENROLLED_BYTES: u64 = 64 << 20;
pub const MAX_BACKEND_BYTES: u64 = 1 << 30;
pub const MAX_PLANEON_CODE: u64 = 512 << 20;
pub const MAX_BACKEND_CODE: u64 = 4 << 30;
/// The largest `pidsMax` a role may record (the bound of a member listing).
pub const MAX_PIDS: u64 = 4_096;
/// The slice of the planeon roles, relative to the cgroup2 root.
pub const SLICE: &str = "planeon.slice";

/// One resident role's read targets.
pub struct RoleTarget {
    pub role: &'static str,
    /// `capture_check::capture_class`.
    pub class: &'static str,
    /// The cgroup's recorded path and its part under the cgroup2 root.
    pub cgroup_path: String,
    pub cgroup_rel: String,
    pub pids_max: u64,
    /// `filePaths`, in the record's order.
    pub paths: Vec<String>,
    /// Each hook's pin path, in the model's hook order.
    pub pins: Vec<(&'static str, String)>,
}

/// One inventory row: its path, size, mode, digests and the row without `selinuxLabel` (the capture's `entry`).
pub struct Row {
    pub path: String,
    pub size: u64,
    pub mode: String,
    pub sha256: String,
    pub verity: String,
    pub entry: Value,
}

/// One backend component's read targets.
pub struct BackendTarget {
    pub component: String,
    pub process_label: String,
    /// The cgroup's recorded path and its part under the cgroup2 root.
    pub cgroup_path: String,
    pub cgroup_rel: String,
    pub executable: String,
}

/// The checked record and its typed read targets.
pub struct Enrolled {
    pub record: CheckedRecord,
    /// The five roles, in the model's order.
    pub roles: Vec<RoleTarget>,
    /// `files` and `backendFiles` by path.
    pub rows: BTreeMap<String, Row>,
    pub backend_rows: BTreeMap<String, Row>,
    /// The backend components in sorted order.
    pub backends: Vec<BackendTarget>,
    /// `HOST_CONTAINMENT`'s cgroup path and its part under the cgroup2 root.
    pub containment_path: String,
    pub containment_rel: String,
    /// The seal marker's path.
    pub seal_marker: String,
    /// The window in seconds since the epoch.
    pub valid_from: u64,
    pub expires_at: u64,
}

/// A relative path of 1 to 16 components of `[A-Za-z0-9_.+-]`, none `.` or `..`, at most 4,096 bytes.
pub fn rel_path(text: &str) -> bool {
    let parts: Vec<&str> = text.split('/').collect();
    text.len() <= 4_096
        && parts.len() <= 16
        && parts.iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && part.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-'))
        })
}

/// The recorded form of a cgroup path relative to the cgroup2 root.
pub fn cgroup_path(rel: &str) -> String {
    format!("{CGROUP_ROOT}/{rel}")
}

/// The part of `path` under `root`, when it is `root`, `/` and a relative path.
fn under(path: &str, root: &str) -> Option<String> {
    path.strip_prefix(root)?.strip_prefix('/').filter(|rest| rel_path(rest)).map(str::to_string)
}

/// The value at a key path.
fn at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().try_fold(value, |node, key| node.get(key))
}

fn text_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    at(value, keys).and_then(Value::as_str)
}

fn number_at(value: &Value, keys: &[&str]) -> Option<u64> {
    at(value, keys).and_then(Value::as_int).and_then(|int| int.to_u64())
}

/// The inventory rows of `rows` by path, each path enrolled, each size within `largest` and the total within `total`.
fn inventory(rows: &[Value], largest: u64, total: u64) -> Result<BTreeMap<String, Row>, SetupError> {
    let targets = SetupError::RecordTargets;
    let mut found = BTreeMap::new();
    let mut sum = 0u64;
    for row in rows {
        let path = text_at(row, &["path"]).ok_or(SetupError::RecordForm("an inventory row without a path"))?;
        if !path.strip_prefix('/').is_some_and(rel_path) {
            return Err(targets("an enrolled path outside the read grammar"));
        }
        let size = number_at(row, &["size"]).ok_or(SetupError::RecordForm("an inventory row without a size"))?;
        if size > largest {
            return Err(targets("an enrolled file over its size bound"));
        }
        sum = sum.checked_add(size).ok_or(targets("an inventory total"))?;
        let entry = match row {
            Value::Object(object) => {
                let mut kept = json::Object::new();
                for (key, member) in object.iter() {
                    if key.as_str() != Some("selinuxLabel") {
                        kept.insert(key.clone(), member.clone());
                    }
                }
                Value::Object(kept)
            }
            _ => return Err(SetupError::RecordForm("an inventory row is not an object")),
        };
        let field = |key: &str| text_at(row, &[key]).map(str::to_string).ok_or(SetupError::RecordForm("an inventory row"));
        found.insert(path.to_string(), Row { path: path.to_string(), size, mode: field("mode")?, sha256: field("sha256")?,
                                             verity: field("verityDigest")?, entry });
    }
    if sum > total {
        return Err(targets("an inventory over its total bound"));
    }
    Ok(found)
}

impl Enrolled {
    /// The record's shape (27), R10's read-path preconditions (28) and its window (29) against the wall second `now`
    /// (`None` before the epoch: 97); see the module documentation.
    pub fn new(record: RecordBytes, schema: &RecordSchema, now: Option<u64>) -> Result<Enrolled, SetupError> {
        let (form, targets, window) = (SetupError::RecordForm, SetupError::RecordTargets, SetupError::RecordWindow);
        let value = record.value;
        let identity = (text_at(&value, &["schemaVersion"]), text_at(&value, &["qualificationProfile"]));
        if identity != (Some(V4_RECORD.0), Some(V4_RECORD.1)) {
            return Err(form("not a v4 record"));
        }
        capture_check::bounded(&value).map_err(form)?;
        if record.bytes.len() > capture_check::MAX_BYTES {
            return Err(form("the record's canonical length is over 262,144"));
        }
        if !schema.is_valid(&value) {
            return Err(form("the record variant refuses the record"));
        }
        let rows = inventory(at(&value, &["files"]).and_then(Value::as_array).unwrap_or_default(), MAX_ENROLLED_BYTES,
                             MAX_PLANEON_CODE)?;
        let backend_rows = inventory(at(&value, &["backendFiles"]).and_then(Value::as_array).unwrap_or_default(),
                                     MAX_BACKEND_BYTES, MAX_BACKEND_CODE)?;
        let mut roles = Vec::with_capacity(ROLES.len());
        for role in ROLES {
            let row = at(&value, &["roles", role]).ok_or(form("a role is missing"))?;
            let cgroup_path = text_at(row, &["cgroup", "path"]).ok_or(form("a role cgroup"))?.to_string();
            let cgroup_rel = under(&cgroup_path, CGROUP_ROOT)
                .filter(|rel| rel.strip_prefix(SLICE).is_some_and(|rest| rest.starts_with('/')))
                .ok_or(targets("a role cgroup outside the planeon slice"))?;
            let pids_max = number_at(row, &["cgroup", "pidsMax"]).ok_or(form("a role's pidsMax"))?;
            if pids_max > MAX_PIDS {
                return Err(targets("a role's pidsMax over 4,096"));
            }
            let mut paths = Vec::new();
            for path in at(row, &["filePaths"]).and_then(Value::as_array).unwrap_or_default() {
                let path = path.as_str().ok_or(form("a filePaths entry"))?;
                if !rows.contains_key(path) {
                    return Err(targets("a filePaths entry names no files row"));
                }
                paths.push(path.to_string());
            }
            let mut pins = Vec::with_capacity(HOOKS.len());
            for hook in HOOKS {
                let pin = text_at(row, &["bpfPrograms", hook, "pinPath"]).ok_or(form("a hook's pin"))?;
                if under(pin, PIN_ROOT).is_none() {
                    return Err(targets("a pin path outside the pin root"));
                }
                pins.push((hook, pin.to_string()));
            }
            roles.push(RoleTarget { role, class: capture_class(&value, role), cgroup_path, cgroup_rel, pids_max, paths, pins });
        }
        let containment_path =
            text_at(&value, &["lifecycleSubjects", "HOST_CONTAINMENT", "cgroupPath"]).ok_or(form("the containment cgroup"))?;
        let containment_rel = under(containment_path, CGROUP_ROOT).ok_or(targets("the containment cgroup's path"))?;
        let mut backends = Vec::new();
        if let Some(components) = at(&value, &["backendComponents"]).and_then(Value::as_object) {
            let mut sorted: Vec<(&str, &Value)> =
                components.iter().map(|(name, row)| (name.as_str().unwrap_or(""), row)).collect();
            sorted.sort_by(|left, right| left.0.cmp(right.0));
            for (component, row) in sorted {
                let cgroup_path = text_at(row, &["cgroupPath"]).ok_or(form("a backend cgroup"))?;
                let cgroup_rel = under(cgroup_path, CGROUP_ROOT).ok_or(targets("a backend cgroup's path"))?;
                let executable = text_at(row, &["executable"]).ok_or(form("a backend executable"))?;
                if !backend_rows.contains_key(executable) {
                    return Err(targets("a backend executable names no backendFiles row"));
                }
                backends.push(BackendTarget {
                    component: component.to_string(),
                    process_label: text_at(row, &["processLabel"]).ok_or(form("a backend label"))?.to_string(),
                    cgroup_path: cgroup_path.to_string(),
                    cgroup_rel,
                    executable: executable.to_string(),
                });
            }
        }
        let seal_marker = text_at(&value, &["hardening", "sealMarker", "path"]).ok_or(form("the seal marker"))?;
        if !seal_marker.strip_prefix('/').is_some_and(rel_path) {
            return Err(targets("the seal marker's path"));
        }
        let moment = |key: &str| text_at(&value, &["scope", key]).and_then(kernel_text::utc_seconds);
        let (Some(valid_from), Some(expires_at)) = (moment("validFrom"), moment("expiresAt")) else {
            return Err(window("the window is not canonical UTC"));
        };
        if valid_from >= expires_at {
            return Err(window("validFrom is not before expiresAt"));
        }
        let Some(now) = now else { return Err(SetupError::Clock) };
        if expires_at <= now {
            return Err(window("the enrollment is already over"));
        }
        let (containment_path, seal_marker) = (containment_path.to_string(), seal_marker.to_string());
        Ok(Enrolled {
            record: checked_record(value, record.pin),
            roles,
            rows,
            backend_rows,
            backends,
            containment_path,
            containment_rel,
            seal_marker,
            valid_from,
            expires_at,
        })
    }
}
