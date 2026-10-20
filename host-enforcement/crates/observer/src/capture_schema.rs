//! The qualification schemas for the kernel captures' checks (HE-004D1 DESIGN-D1 section 6; owner decision Q-HE4D1-3 (a);
//! MODEL_DEFINED R122; HE-004D2 DESIGN-D2 section 4.1, unit B1, Amendment A2). A logic module: pure, std's ordered
//! collections and i05-protocol's json, sha256 and schema only, no panic.
//!
//! [`CaptureSchema::embedded`] runs once in `serve` (status 25 on any failure) and loads two embedded schemas, each by
//! its own steps: native-profile v4's for the record ([`RecordSchema::from_bytes`]) and native-profile v5's for the
//! captures ([`CaptureSchema::from_bytes`]). Each parses the bytes with i05-protocol, requires the sha256 of their
//! canonical encoding to be the model's pin (v4's `3bf244b2…`, v5's `5f6703ca…`; the models pin the schemas that way,
//! `tools/gate.py` pins the files' own sha256), rewrites every `if/then/else` (below), and builds its validators, each
//! `{"$ref": "#/$defs/<variant>", "$defs": <the rewritten $defs>}` (the models' own wrapper): from v4, the record's, used
//! once by `Enrolled::new` and then dropped; from v5, the capture's, the lifecycle capture's and the backend capture's,
//! which stay resident.
//!
//! **The rewrite.** i05-protocol's subset has `if` and `then` but no `else`. At load, every schema object holding
//! `else` must hold `if` and `then` too (the closed form; anything else refuses), and becomes the same object without
//! those three keywords and with two members appended to its `allOf` (created if absent): `{"if": A, "then": B}` and
//! `{"anyOf": [A, C]}`. `if A then B else C` holds exactly when (A implies B) and (A or C), the first member is
//! i05-protocol's own `if/then` with its vacuous-`if` semantics and the second evaluates A with the same engine, so
//! validity is unchanged for every instance. Only schema positions are walked (as i05-protocol's loader recurses:
//! `$defs` values, `properties` values, `items`, `not`, `if`, `then`, `else`, the members of `allOf`, `anyOf` and
//! `oneOf`, a schema-valued `additionalProperties` and `propertyNames`); `const` and `enum` values are data and are never
//! touched. The rewritten value is loaded by i05-protocol unchanged, which still refuses `else` anywhere, so a missed
//! node would fail the load. In each pinned schema exactly two objects hold `else`: `$defs/capture/allOf/0` and
//! `$defs/capture/allOf/3` (the record loader still rewrites v4's, since it loads the whole `$defs`).

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::schema::Schema;
use i05_protocol::sha256;

/// The models' pins of the two schemas: the sha256 of their canonical encodings (`native_qualification_v4.py`'s and
/// `native_qualification_v5.py`'s `SCHEMA_SHA256`).
pub const RECORD_CANONICAL_PIN: &str = "3bf244b21f91e30062ad56a7a21f3f0b4554daa71a0c3b624bcac058fee58d80";
pub const CAPTURE_CANONICAL_PIN: &str = "5f6703ca38d0919f6446772e8edd75e92609a9a3971b8cb052b53a7e9ab50393";

/// The deepest schema nesting the rewrite follows (i05-protocol's loader allows 128).
const MAX_SCHEMA_DEPTH: usize = 128;

/// Why the rewrite refused a schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewriteError {
    /// An object holds `else` without `if` or `then`.
    OpenConditional(String),
    /// An `allOf` that is not an array.
    AllOf(String),
    /// Nesting past the loader's bound.
    Depth,
}

/// Why an embedded schema did not load (status 25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaLoadError {
    /// Not UTF-8 or not JSON.
    Parse,
    /// The canonical encoding's sha256 is not the model's pin.
    Pin,
    /// The rewrite refused.
    Rewrite(RewriteError),
    /// No `$defs`, or i05-protocol refused a variant.
    Load(&'static str),
}

/// The three capture validators (native-profile v5).
pub struct CaptureSchema {
    capture: Schema,
    lifecycle: Schema,
    backend: Schema,
}

/// The record's validator (native-profile v4), used once by `Enrolled::new` and then dropped.
pub struct RecordSchema {
    record: Schema,
}

impl RecordSchema {
    /// Parses native-profile v4's schema, checks its canonical pin, rewrites the conditionals and builds the `record`
    /// validator (the tests' altered copies use it directly).
    pub fn from_bytes(bytes: &[u8]) -> Result<RecordSchema, SchemaLoadError> {
        let defs = pinned_defs(bytes, RECORD_CANONICAL_PIN)?;
        Ok(RecordSchema { record: variant(&defs, "record")? })
    }

    /// Whether `value` is valid as the `record` variant.
    pub fn is_valid(&self, value: &Value) -> bool {
        self.record.is_valid(value)
    }
}

/// A schema's rewritten `$defs`, after its parse and its canonical pin.
fn pinned_defs(bytes: &[u8], pin: &str) -> Result<Value, SchemaLoadError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SchemaLoadError::Parse)?;
    let value = json::parse(text).map_err(|_| SchemaLoadError::Parse)?;
    let encoded = json::canonical(&value).map_err(|_| SchemaLoadError::Parse)?;
    if sha256::hex(&sha256::digest(&encoded)) != pin {
        return Err(SchemaLoadError::Pin);
    }
    let (rewritten, _) = rewrite_conditionals(&value).map_err(SchemaLoadError::Rewrite)?;
    drop(value);
    rewritten.get("$defs").cloned().ok_or(SchemaLoadError::Load("the schema has no $defs"))
}

/// A variant validator over the rewritten `$defs`.
fn variant(defs: &Value, name: &str) -> Result<Schema, SchemaLoadError> {
    let mut root = Object::new();
    root.insert(JStr::new("$ref"), Value::str(&format!("#/$defs/{name}")));
    root.insert(JStr::new("$defs"), defs.clone());
    Schema::from_value(&Value::Object(root)).map_err(|_| SchemaLoadError::Load("a variant does not load"))
}

impl CaptureSchema {
    /// Loads the two embedded schemas (see the module documentation): native-profile v4's record validator and
    /// native-profile v5's three capture validators.
    pub fn embedded() -> Result<(CaptureSchema, RecordSchema), SchemaLoadError> {
        let record = RecordSchema::from_bytes(crate::contracts::NATIVE_PROFILE_V4_SCHEMA)?;
        let capture = CaptureSchema::from_bytes(crate::contracts::NATIVE_PROFILE_V5_SCHEMA)?;
        Ok((capture, record))
    }

    /// Parses native-profile v5's schema, checks its canonical pin, rewrites the conditionals and builds the three
    /// capture validators (the tests' altered copies use it directly).
    pub fn from_bytes(bytes: &[u8]) -> Result<CaptureSchema, SchemaLoadError> {
        let defs = pinned_defs(bytes, CAPTURE_CANONICAL_PIN)?;
        let capture = variant(&defs, "capture")?;
        let lifecycle = variant(&defs, "lifecycleCapture")?;
        let backend = variant(&defs, "backendCapture")?;
        Ok(CaptureSchema { capture, lifecycle, backend })
    }

    /// Whether `value` is valid as the `capture` variant.
    pub fn capture_valid(&self, value: &Value) -> bool {
        self.capture.is_valid(value)
    }

    /// Whether `value` is valid as the `lifecycleCapture` variant.
    pub fn lifecycle_valid(&self, value: &Value) -> bool {
        self.lifecycle.is_valid(value)
    }

    /// Whether `value` is valid as the `backendCapture` variant.
    pub fn backend_valid(&self, value: &Value) -> bool {
        self.backend.is_valid(value)
    }
}

/// The closed rewrite of every `if/then/else` in a schema document (see the module documentation): the rewritten value
/// and the location of each rewritten object (`$defs/capture/allOf/0` style), in walk order.
pub fn rewrite_conditionals(document: &Value) -> Result<(Value, Vec<String>), RewriteError> {
    let mut rewritten = Vec::new();
    let value = schema_node(document, "", 0, &mut rewritten)?;
    Ok((value, rewritten))
}

fn child(at: &str, key: &str) -> String {
    if at.is_empty() { key.to_string() } else { format!("{at}/{key}") }
}

/// One schema position: a boolean stays; an object has its schema-valued members rewritten, then its own `else`.
fn schema_node(node: &Value, at: &str, depth: usize, rewritten: &mut Vec<String>) -> Result<Value, RewriteError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(RewriteError::Depth);
    }
    let Some(object) = node.as_object() else { return Ok(node.clone()) };
    let deeper = depth.saturating_add(1);
    let mut out = Object::new();
    for (key, member) in object.iter() {
        let name = key.as_str().unwrap_or("");
        let here = child(at, name);
        let value = match name {
            "$defs" | "properties" => {
                let Some(members) = member.as_object() else {
                    out.insert(key.clone(), member.clone());
                    continue;
                };
                let mut mapped = Object::new();
                for (inner, schema) in members.iter() {
                    let place = child(&here, inner.as_str().unwrap_or(""));
                    mapped.insert(inner.clone(), schema_node(schema, &place, deeper, rewritten)?);
                }
                Value::Object(mapped)
            }
            "items" | "not" | "if" | "then" | "else" | "propertyNames" | "additionalProperties" => {
                schema_node(member, &here, deeper, rewritten)?
            }
            "allOf" | "anyOf" | "oneOf" => match member.as_array() {
                Some(items) => {
                    let mut mapped = Vec::with_capacity(items.len());
                    for (index, item) in items.iter().enumerate() {
                        mapped.push(schema_node(item, &child(&here, &index.to_string()), deeper, rewritten)?);
                    }
                    Value::Array(mapped)
                }
                None => member.clone(),
            },
            _ => member.clone(),
        };
        out.insert(key.clone(), value);
    }
    let else_key = JStr::new("else");
    if !out.contains_key(&else_key) {
        return Ok(Value::Object(out));
    }
    let (if_key, then_key, all_key) = (JStr::new("if"), JStr::new("then"), JStr::new("allOf"));
    let (Some(condition), Some(consequence), Some(alternative)) =
        (out.remove(&if_key), out.remove(&then_key), out.remove(&else_key))
    else {
        return Err(RewriteError::OpenConditional(at.to_string()));
    };
    let mut implication = Object::new();
    implication.insert(if_key, condition.clone());
    implication.insert(then_key, consequence);
    let mut either = Object::new();
    either.insert(JStr::new("anyOf"), Value::Array(vec![condition, alternative]));
    match out.get_key_mut(&all_key) {
        None => out.insert(all_key, Value::Array(vec![Value::Object(implication), Value::Object(either)])),
        Some(Value::Array(items)) => {
            items.push(Value::Object(implication));
            items.push(Value::Object(either));
        }
        Some(_) => return Err(RewriteError::AllOf(at.to_string())),
    }
    rewritten.push(at.to_string());
    Ok(Value::Object(out))
}
