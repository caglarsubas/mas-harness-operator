//! The ACTION_OUTCOME to RESOURCE_RESULT agreement table (`outcome-mapping.json`) and `check_agreement`.
//!
//! The outcome and the resource result are taken as decoded values (the broker holds them as received), compared with
//! Python's `==`; a missing member reads as null. `objectBase64` is decoded in agreement mode (DESIGN §5): strict base64
//! (Python `b64decode(validate=True)`, ASCII text only), then UTF-8 and JSON that allows whitespace and floats but
//! refuses duplicate keys and NaN, an object at the top, depth at most 16.

use std::cmp::Ordering;

use crate::base64;
use crate::json::{self, Int, Object, Value};
use crate::render::{Kind, Verb};

pub const MAPPING_VERSION: &str = "planeon.internal.effect-gate-outcome-mapping/v2";

/// Why an outcome and a resource result disagree, in the contract's wording.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mismatch {
    M00,
    M01,
    M02,
    M03,
    M04,
    M05,
    M06,
    M07,
}

impl Mismatch {
    pub fn code(self) -> &'static str {
        match self {
            Mismatch::M00 => "M00",
            Mismatch::M01 => "M01",
            Mismatch::M02 => "M02",
            Mismatch::M03 => "M03",
            Mismatch::M04 => "M04",
            Mismatch::M05 => "M05",
            Mismatch::M06 => "M06",
            Mismatch::M07 => "M07",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Mismatch::M00 => "M00 no usable ACTION_OUTCOME",
            Mismatch::M01 => "M01 action identifiers differ",
            Mismatch::M02 => "M02 no mapping row for this outcome",
            Mismatch::M03 => "M03 resource result outside the mapped outcomes",
            Mismatch::M04 => "M04 object reported where the mapping requires none",
            Mismatch::M05 => "M05 reported object missing or not strictly decodable",
            Mismatch::M06 => "M06 reported object identity differs from the armed action",
            Mismatch::M07 => "M07 reported object UID or resourceVersion differs from the gate's observation",
        }
    }
}

/// The armed template's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub api_version: String,
    pub kind: Kind,
    pub namespace: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum StatusRule {
    Null,
    Exact(Int),
    Class(i64, i64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ObjectRule {
    IdentityMatch,
    DeleteBodyIfPresent,
    Any,
    Null,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BodyKind {
    Object,
    Status,
}

#[derive(Clone, Debug)]
struct Row {
    verb: Option<Verb>,
    classification: String,
    status: StatusRule,
    exclude: Vec<Value>,
    results: Vec<String>,
    object: ObjectRule,
}

/// The loaded table.
#[derive(Clone, Debug)]
pub struct OutcomeMapping {
    rows: Vec<Row>,
    pod: BodyKind,
    config_map: BodyKind,
    service: BodyKind,
}

/// Why a mapping document is outside the expected shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingError(pub String);

fn refuse<T>(message: &str) -> Result<T, MappingError> {
    Err(MappingError(message.to_string()))
}

fn strings(value: Option<&Value>, what: &str) -> Result<Vec<String>, MappingError> {
    let Some(items) = value.and_then(Value::as_array) else { return refuse(what) };
    items.iter().map(|item| item.as_str().map(str::to_string).map_or_else(|| refuse(what), Ok)).collect()
}

impl OutcomeMapping {
    pub fn from_json(raw: &[u8]) -> Result<OutcomeMapping, MappingError> {
        let text = std::str::from_utf8(raw).map_err(|_| MappingError("mapping is not UTF-8".into()))?;
        let document = json::parse(text).map_err(|_| MappingError("mapping is not JSON".into()))?;
        OutcomeMapping::from_value(&document)
    }

    pub fn from_value(document: &Value) -> Result<OutcomeMapping, MappingError> {
        if document.get("schemaVersion").and_then(Value::as_str) != Some(MAPPING_VERSION) {
            return refuse("not an outcome mapping v2");
        }
        let Some(rows) = document.get("rows").and_then(Value::as_array) else { return refuse("rows") };
        let mut parsed = Vec::new();
        for row in rows {
            let verb = match row.get("verb").and_then(Value::as_str) {
                Some("*") => None,
                Some(text) => Some(Verb::parse(text).map_or_else(|| refuse("row verb"), Ok)?),
                None => return refuse("row verb"),
            };
            let Some(classification) = row.get("classification").and_then(Value::as_str) else {
                return refuse("row classification");
            };
            let status = match row.get("httpStatus") {
                Some(Value::Null) => StatusRule::Null,
                Some(Value::Int(int)) => StatusRule::Exact(int.clone()),
                Some(Value::Str(text)) => match text.as_str() {
                    Some("4xx") => StatusRule::Class(400, 499),
                    Some("5xx") => StatusRule::Class(500, 599),
                    _ => return refuse("row status class"),
                },
                _ => return refuse("row status"),
            };
            let Some(exclude) = row.get("excludeStatus").and_then(Value::as_array) else { return refuse("row excludeStatus") };
            if !exclude.iter().all(|value| matches!(value, Value::Int(_))) {
                return refuse("row excludeStatus");
            }
            let object = match row.get("object").and_then(Value::as_str) {
                Some("IDENTITY_MATCH") => ObjectRule::IdentityMatch,
                Some("DELETE_BODY_IF_PRESENT") => ObjectRule::DeleteBodyIfPresent,
                Some("ANY") => ObjectRule::Any,
                Some("NULL") => ObjectRule::Null,
                _ => return refuse("row object rule"),
            };
            parsed.push(Row { verb, classification: classification.to_string(), status, exclude: exclude.to_vec(),
                              results: strings(row.get("resourceResults"), "row resourceResults")?, object });
        }
        let body = |kind: &str| -> Result<BodyKind, MappingError> {
            match document.get("deleteResponseBody").and_then(|table| table.get(kind)).and_then(Value::as_str) {
                Some("OBJECT") => Ok(BodyKind::Object),
                Some("STATUS") => Ok(BodyKind::Status),
                _ => refuse("deleteResponseBody must name every kind"),
            }
        };
        Ok(OutcomeMapping { rows: parsed, pod: body("Pod")?, config_map: body("ConfigMap")?, service: body("Service")? })
    }

    /// The table published with I05 v3.
    pub fn i05_v3() -> Result<OutcomeMapping, MappingError> {
        OutcomeMapping::from_json(crate::contracts::I05_V3_OUTCOME_MAPPING)
    }

    fn body_kind(&self, kind: Kind) -> BodyKind {
        match kind {
            Kind::Pod => self.pod,
            Kind::ConfigMap => self.config_map,
            Kind::Service => self.service,
        }
    }

    /// `None` when the outcome and the resource result agree, otherwise the first refusal.
    pub fn check_agreement(&self, verb: Verb, identity: &Identity, outcome: &Value, result: &Value) -> Option<Mismatch> {
        let ok = Value::str("OK");
        let Some(outcome) = outcome.as_object().filter(|object| member(object, "result").is_some_and(|v| json::py_eq(v, &ok)))
        else {
            return Some(Mismatch::M00);
        };
        let Some(result) = result.as_object() else { return Some(Mismatch::M01) };
        if !json::py_eq(read(result, "actionId"), read(outcome, "actionId")) {
            return Some(Mismatch::M01);
        }
        let status = read(outcome, "httpStatus");
        let classification = read(outcome, "classification");
        let candidates: Vec<&Row> = self
            .rows
            .iter()
            .filter(|row| row.verb.is_none_or(|row_verb| row_verb == verb))
            .filter(|row| json::py_eq(&Value::str(&row.classification), classification))
            .collect();
        let exact: Vec<&Row> = candidates.iter().copied().filter(|row| row_status(row, status, true)).collect();
        let matched = if exact.is_empty() {
            candidates.iter().copied().filter(|row| row_status(row, status, false)).collect()
        } else {
            exact
        };
        let row = match matched.as_slice() {
            [row] => *row,
            _ => return Some(Mismatch::M02),
        };
        let outcome_name = read(result, "outcome");
        if !row.results.iter().any(|name| json::py_eq(outcome_name, &Value::str(name))) {
            return Some(Mismatch::M03);
        }
        let data = read(result, "objectBase64");
        if row.object == ObjectRule::Null && !data.is_null() {
            return Some(Mismatch::M04);
        }
        let present = !data.is_null();
        if row.object == ObjectRule::DeleteBodyIfPresent && present && self.body_kind(identity.kind) == BodyKind::Status {
            // A completed deletion is answered with a v1 Status whose details.kind names the resource (M12); a server
            // that returns the object itself has not finished deleting it, and that body is refused here.
            let decoded = decode_object(data);
            let details = decoded.as_ref().and_then(|value| value.get("details")).and_then(Value::as_object);
            let (Some(value), Some(details)) = (decoded.as_ref(), details) else { return Some(Mismatch::M05) };
            let value = value.as_object().unwrap_or(&EMPTY);
            if !(eq_str(read(value, "kind"), "Status") && eq_str(read(value, "status"), "Success")) {
                return Some(Mismatch::M05);
            }
            if !(eq_str(read(details, "name"), &identity.name) && eq_str(read(details, "kind"), identity.kind.plural())) {
                return Some(Mismatch::M06);
            }
            if !json::py_eq(read(details, "uid"), read(outcome, "observedUid")) || !read(outcome, "observedResourceVersion").is_null() {
                return Some(Mismatch::M07);
            }
            return None;
        }
        if row.object == ObjectRule::IdentityMatch || (row.object == ObjectRule::DeleteBodyIfPresent && present) {
            let decoded = if present { decode_object(data) } else { None };
            let Some(value) = decoded.as_ref().and_then(Value::as_object) else { return Some(Mismatch::M05) };
            let metadata = member(value, "metadata").and_then(Value::as_object).unwrap_or(&EMPTY);
            if !(eq_str(read(value, "apiVersion"), &identity.api_version)
                && eq_str(read(value, "kind"), identity.kind.as_str())
                && eq_str(read(metadata, "namespace"), &identity.namespace)
                && eq_str(read(metadata, "name"), &identity.name))
            {
                return Some(Mismatch::M06);
            }
            if !json::py_eq(read(metadata, "uid"), read(outcome, "observedUid"))
                || !json::py_eq(read(metadata, "resourceVersion"), read(outcome, "observedResourceVersion"))
            {
                return Some(Mismatch::M07);
            }
        }
        None
    }
}

static EMPTY: Object = Object::const_empty();
static NULL: Value = Value::Null;

fn member<'a>(object: &'a Object, key: &str) -> Option<&'a Value> {
    object.get(key)
}

/// Python `object.get(key)`: a missing member reads as `None`.
fn read<'a>(object: &'a Object, key: &str) -> &'a Value {
    object.get(key).unwrap_or(&NULL)
}

fn eq_str(value: &Value, text: &str) -> bool {
    json::py_eq(value, &Value::str(text))
}

/// `low <= status <= high` and `status not in exclude`, for a numeric status (a boolean counts as 0 or 1, as in
/// Python). A non-numeric status matches no status-class row (R10-defined; the pinned model raises TypeError there).
fn in_class(status: &Value, low: i64, high: i64) -> bool {
    let above = |bound: i64| match status {
        Value::Int(int) => Some(int.cmp(&Int::from_i64(bound))),
        Value::Bool(flag) => Some(i64::from(*flag).cmp(&bound)),
        Value::Float(x) => Int::from_i64(bound).cmp_f64(*x).map(Ordering::reverse),
        _ => None,
    };
    matches!(above(low), Some(Ordering::Greater | Ordering::Equal)) && matches!(above(high), Some(Ordering::Less | Ordering::Equal))
}

fn row_status(row: &Row, status: &Value, exact: bool) -> bool {
    match (&row.status, status.is_null()) {
        (StatusRule::Null, true) => true,
        (StatusRule::Null, false) | (_, true) => false,
        (StatusRule::Exact(rule), false) => exact && json::py_eq(&Value::Int(rule.clone()), status),
        (StatusRule::Class(low, high), false) => {
            !exact && in_class(status, *low, *high) && !row.exclude.iter().any(|excluded| json::py_eq(excluded, status))
        }
    }
}

/// Agreement-mode decoding of `objectBase64`: the decoded object, or `None` when anything fails.
pub fn decode_object(data: &Value) -> Option<Value> {
    let Value::Str(text) = data else { return None };
    if !text.as_bytes().is_ascii() {
        return None;
    }
    let raw = base64::decode_strict(text.as_bytes())?;
    let value = json::parse(std::str::from_utf8(&raw).ok()?).ok()?;
    if !matches!(value, Value::Object(_)) || json::depth(&value) > crate::frame::MAX_DEPTH {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(text: &str) -> Value {
        json::parse(text).unwrap_or(Value::Null)
    }

    fn object_base64(text: &str) -> String {
        base64::encode(text.as_bytes())
    }

    #[test]
    fn agreement_mode_decoding() {
        let decoded = |text: &str| decode_object(&Value::str(&object_base64(text))).is_some();
        assert!(decoded("{ \"a\" : [1.5, 2e3] }"), "whitespace and floats are accepted");
        assert!(decoded("{\"a\":\"\\ud800\"}"), "a lone surrogate escape is accepted");
        assert!(!decoded("{\"a\":1,\"a\":2}") && !decoded("{\"a\":NaN}") && !decoded("[1]") && !decoded("1"));
        assert!(decoded(&format!("{}1{}", "{\"a\":".repeat(16), "}".repeat(16))));
        assert!(!decoded(&format!("{}1{}", "{\"a\":".repeat(17), "}".repeat(17))));
        assert!(!decoded(&format!("{{\"a\":{}}}", "1".repeat(4301))));
        assert!(decode_object(&Value::str("e30=")).is_some());
        assert!(decode_object(&Value::str("e31=")).is_some(), "non-zero trailing bits are accepted");
        assert!(decode_object(&Value::str("e30")).is_none() && decode_object(&Value::int(1)).is_none());
        assert!(decode_object(&value("\"e30=\u{e9}\"")).is_none(), "non-ASCII text is no object");
        assert!(decode_object(&Value::str("/w==")).is_none(), "not UTF-8");
    }

    #[test]
    fn lenient_comparisons_follow_python() {
        let Ok(mapping) = OutcomeMapping::i05_v3() else { panic!("mapping") };
        let identity = Identity { api_version: "v1".into(), kind: Kind::Pod, namespace: "planeon-qual".into(),
                                  name: "probe-pod".into() };
        let outcome = value(r#"{"result":"OK","actionId":1,"classification":"DELIVERED_RESULT","httpStatus":404.0}"#);
        let absent = value(r#"{"actionId":true,"outcome":"ABSENT"}"#);
        assert_eq!(mapping.check_agreement(Verb::Get, &identity, &outcome, &absent), None, "404.0 == 404 and True == 1");
        let text_status = value(r#"{"result":"OK","actionId":1,"classification":"DELIVERED_RESULT","httpStatus":"404"}"#);
        assert_eq!(mapping.check_agreement(Verb::Get, &identity, &text_status, &absent), Some(Mismatch::M02));
        let no_ids = value(r#"{"result":"OK","classification":"IO_AMBIGUOUS"}"#);
        assert_eq!(mapping.check_agreement(Verb::Get, &identity, &no_ids, &value(r#"{"outcome":"AMBIGUOUS"}"#)), None);
        assert_eq!(mapping.check_agreement(Verb::Get, &identity, &value("[]"), &absent), Some(Mismatch::M00));
        assert_eq!(mapping.check_agreement(Verb::Get, &identity, &outcome, &value("[]")), Some(Mismatch::M01));
    }

    #[test]
    fn refuses_malformed_tables() {
        for text in [r#"{"schemaVersion":"x","rows":[]}"#,
                     r#"{"schemaVersion":"planeon.internal.effect-gate-outcome-mapping/v2","rows":[]}"#,
                     r#"{"schemaVersion":"planeon.internal.effect-gate-outcome-mapping/v2","rows":[{"verb":"PATCH"}],
                         "deleteResponseBody":{"Pod":"OBJECT","ConfigMap":"STATUS","Service":"OBJECT"}}"#] {
            assert!(OutcomeMapping::from_json(text.as_bytes()).is_err(), "{text}");
        }
    }
}
