//! The JSON Schema Draft 2020-12 subset of the I05 v3 and I07 v3 schemas (DESIGN §6), with the semantics of the
//! pinned Python `jsonschema` validator for the values the frame pipeline lets through.
//!
//! Keywords: `$schema` (root only, the 2020-12 URI), `$id` (root only) and `title` (annotations), `type`, `properties`,
//! `required`, `additionalProperties` (boolean or schema), `const`, `enum`, `minimum`, `maximum`, `minLength`,
//! `maxLength`, `pattern`, `oneOf`, `anyOf`, `allOf`, `not`, `if`/`then`, `items`, `minItems`, `maxItems`,
//! `uniqueItems`, `maxProperties`, `propertyNames`, `$defs` (root only) and `$ref` (`#/$defs/<name>`). Any other keyword
//! refuses the schema when it is loaded. Each keyword applies only to instances of its own type (so an `if` over an
//! absent or non-numeric property holds vacuously and its `then` applies); `const`, `enum` and `uniqueItems` compare
//! with type (`true` is not `1`); `minimum` and `maximum` compare exact integers.

use std::cmp::Ordering;

use crate::json::{self, JStr, Value};
use crate::regex::Regex;

pub const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

/// Nested evaluations allowed before validation gives up and refuses the instance (only reachable with instances far
/// deeper than the frame pipeline's 16 levels, or with a `$ref` cycle that never descends into the instance).
const MAX_EVALUATION_DEPTH: u32 = 512;
const MAX_SCHEMA_DEPTH: usize = 128;

/// Why a schema document is outside the supported subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(pub String);

fn refuse<T>(message: impl Into<String>) -> Result<T, SchemaError> {
    Err(SchemaError(message.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonType {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Array,
    Object,
}

#[derive(Debug, Clone)]
enum Additional {
    Allowed(bool),
    Schema(Node),
}

#[derive(Debug, Clone, Default)]
struct Keywords {
    types: Option<Vec<JsonType>>,
    properties: Vec<(JStr, Node)>,
    required: Vec<JStr>,
    additional: Option<Additional>,
    constant: Option<Value>,
    enumeration: Option<Vec<Value>>,
    minimum: Option<Value>,
    maximum: Option<Value>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    pattern: Option<Regex>,
    one_of: Option<Vec<Node>>,
    any_of: Option<Vec<Node>>,
    all_of: Option<Vec<Node>>,
    not: Option<Box<Node>>,
    if_: Option<Box<Node>>,
    then: Option<Box<Node>>,
    items: Option<Box<Node>>,
    min_items: Option<u64>,
    max_items: Option<u64>,
    unique_items: bool,
    max_properties: Option<u64>,
    property_names: Option<Box<Node>>,
    reference: Option<usize>,
}

#[derive(Debug, Clone)]
enum Node {
    Bool(bool),
    Keywords(Box<Keywords>),
}

/// A loaded schema.
#[derive(Debug, Clone)]
pub struct Schema {
    root: Node,
    definitions: Vec<Node>,
}

struct Loader {
    names: Vec<String>,
}

impl Loader {
    fn count(value: &Value, keyword: &str) -> Result<u64, SchemaError> {
        value.as_int().and_then(json::Int::to_u64).map_or_else(|| refuse(format!("{keyword} is not a count")), Ok)
    }

    /// A `const` or `enum` value, bounded in depth so that holding and comparing it stays shallow.
    fn literal(value: &Value) -> Result<Value, SchemaError> {
        if json::depth(value) > MAX_SCHEMA_DEPTH {
            return refuse("a const or enum value is nested too deep");
        }
        Ok(value.clone())
    }

    fn number(value: &Value, keyword: &str) -> Result<Value, SchemaError> {
        match value {
            Value::Int(_) | Value::Float(_) => Ok(value.clone()),
            _ => refuse(format!("{keyword} is not a number")),
        }
    }

    fn list(&self, value: &Value, keyword: &str, depth: usize) -> Result<Vec<Node>, SchemaError> {
        let items = value.as_array().filter(|items| !items.is_empty());
        let items = items.map_or_else(|| refuse(format!("{keyword} is not a non-empty array")), Ok)?;
        items.iter().map(|item| self.node(item, false, depth)).collect()
    }

    fn type_name(value: &Value) -> Result<JsonType, SchemaError> {
        Ok(match value.as_str() {
            Some("null") => JsonType::Null,
            Some("boolean") => JsonType::Boolean,
            Some("integer") => JsonType::Integer,
            Some("number") => JsonType::Number,
            Some("string") => JsonType::String,
            Some("array") => JsonType::Array,
            Some("object") => JsonType::Object,
            _ => return refuse("unknown type"),
        })
    }

    fn node(&self, value: &Value, root: bool, depth: usize) -> Result<Node, SchemaError> {
        if depth > MAX_SCHEMA_DEPTH {
            return refuse("schema nesting too deep");
        }
        let depth = depth.saturating_add(1);
        let object = match value {
            Value::Bool(flag) => return Ok(Node::Bool(*flag)),
            Value::Object(object) => object,
            _ => return refuse("a schema is an object or a boolean"),
        };
        let mut k = Keywords::default();
        for (key, member) in object.iter() {
            let Some(name) = key.as_str() else { return refuse("keyword is not text") };
            match name {
                "$schema" if root => {
                    if member.as_str() != Some(DRAFT_2020_12) {
                        return refuse("$schema is not Draft 2020-12");
                    }
                }
                "$id" if root => {
                    if member.as_str().is_none() {
                        return refuse("$id is not text");
                    }
                }
                "$defs" if root => {
                    if member.as_object().is_none() {
                        return refuse("$defs is not an object");
                    }
                }
                "title" => {
                    if member.as_str().is_none() {
                        return refuse("title is not text");
                    }
                }
                "type" => {
                    let names = match member {
                        Value::Array(items) => items.iter().map(Loader::type_name).collect::<Result<Vec<_>, _>>()?,
                        other => vec![Loader::type_name(other)?],
                    };
                    k.types = Some(names);
                }
                "properties" => {
                    let Some(properties) = member.as_object() else { return refuse("properties is not an object") };
                    for (property, schema) in properties.iter() {
                        k.properties.push((property.clone(), self.node(schema, false, depth)?));
                    }
                }
                "required" => {
                    let Some(items) = member.as_array() else { return refuse("required is not an array") };
                    for item in items {
                        match item {
                            Value::Str(text) => k.required.push(text.clone()),
                            _ => return refuse("required names are text"),
                        }
                    }
                }
                "additionalProperties" => {
                    k.additional = Some(match member {
                        Value::Bool(flag) => Additional::Allowed(*flag),
                        other => Additional::Schema(self.node(other, false, depth)?),
                    });
                }
                "const" => k.constant = Some(Loader::literal(member)?),
                "enum" => {
                    let Some(items) = member.as_array() else { return refuse("enum is not an array") };
                    k.enumeration = Some(items.iter().map(Loader::literal).collect::<Result<Vec<_>, _>>()?);
                }
                "minimum" => k.minimum = Some(Loader::number(member, name)?),
                "maximum" => k.maximum = Some(Loader::number(member, name)?),
                "minLength" => k.min_length = Some(Loader::count(member, name)?),
                "maxLength" => k.max_length = Some(Loader::count(member, name)?),
                "pattern" => {
                    let Some(pattern) = member.as_str() else { return refuse("pattern is not text") };
                    k.pattern = Some(Regex::new(pattern).map_err(|error| SchemaError(error.0))?);
                }
                "oneOf" => k.one_of = Some(self.list(member, name, depth)?),
                "anyOf" => k.any_of = Some(self.list(member, name, depth)?),
                "allOf" => k.all_of = Some(self.list(member, name, depth)?),
                "not" => k.not = Some(Box::new(self.node(member, false, depth)?)),
                "if" => k.if_ = Some(Box::new(self.node(member, false, depth)?)),
                "then" => k.then = Some(Box::new(self.node(member, false, depth)?)),
                "items" => k.items = Some(Box::new(self.node(member, false, depth)?)),
                "minItems" => k.min_items = Some(Loader::count(member, name)?),
                "maxItems" => k.max_items = Some(Loader::count(member, name)?),
                "uniqueItems" => {
                    let Some(flag) = member.as_bool() else { return refuse("uniqueItems is not a boolean") };
                    k.unique_items = flag;
                }
                "maxProperties" => k.max_properties = Some(Loader::count(member, name)?),
                "propertyNames" => k.property_names = Some(Box::new(self.node(member, false, depth)?)),
                "$ref" => {
                    let target = member.as_str().and_then(|text| text.strip_prefix("#/$defs/"));
                    let index = target.and_then(|name| self.names.iter().position(|known| known == name));
                    match index {
                        Some(index) => k.reference = Some(index),
                        None => return refuse("$ref is not a local #/$defs/ reference"),
                    }
                }
                other => return refuse(format!("unsupported keyword {other}")),
            }
        }
        Ok(Node::Keywords(Box::new(k)))
    }
}

/// Validation stopped because the evaluation budget ran out; the instance is refused.
struct Exhausted;

impl Schema {
    /// Loads a schema document (UTF-8 JSON bytes).
    pub fn from_json(raw: &[u8]) -> Result<Schema, SchemaError> {
        let text = std::str::from_utf8(raw).map_err(|_| SchemaError("schema is not UTF-8".into()))?;
        let document = json::parse(text).map_err(|_| SchemaError("schema is not JSON".into()))?;
        Schema::from_value(&document)
    }

    pub fn from_value(document: &Value) -> Result<Schema, SchemaError> {
        let empty = json::Object::new();
        let defs = match document.get("$defs") {
            Some(Value::Object(defs)) => defs,
            Some(_) => return refuse("$defs is not an object"),
            None => &empty,
        };
        let mut names = Vec::new();
        for (name, _) in defs.iter() {
            let Some(name) = name.as_str() else { return refuse("definition name is not text") };
            names.push(name.to_string());
        }
        let loader = Loader { names };
        let mut definitions = Vec::new();
        for (_, definition) in defs.iter() {
            definitions.push(loader.node(definition, false, 1)?);
        }
        let root = loader.node(document, true, 0)?;
        Ok(Schema { root, definitions })
    }

    /// Whether `instance` is valid.
    pub fn is_valid(&self, instance: &Value) -> bool {
        matches!(self.valid(&self.root, instance, 0), Ok(true))
    }

    fn valid(&self, node: &Node, instance: &Value, depth: u32) -> Result<bool, Exhausted> {
        if depth > MAX_EVALUATION_DEPTH {
            return Err(Exhausted);
        }
        let depth = depth.saturating_add(1);
        let k = match node {
            Node::Bool(flag) => return Ok(*flag),
            Node::Keywords(keywords) => keywords,
        };
        if let Some(index) = k.reference {
            match self.definitions.get(index) {
                Some(target) if self.valid(target, instance, depth)? => {}
                _ => return Ok(false),
            }
        }
        if let Some(types) = &k.types {
            if !types.iter().any(|kind| is_type(instance, *kind)) {
                return Ok(false);
            }
        }
        if let Some(constant) = &k.constant {
            if !json::schema_eq(instance, constant) {
                return Ok(false);
            }
        }
        if let Some(options) = &k.enumeration {
            if !options.iter().any(|option| json::schema_eq(instance, option)) {
                return Ok(false);
            }
        }
        if is_type(instance, JsonType::Number) {
            if let Some(minimum) = &k.minimum {
                if number_cmp(instance, minimum) == Some(Ordering::Less) {
                    return Ok(false);
                }
            }
            if let Some(maximum) = &k.maximum {
                if number_cmp(instance, maximum) == Some(Ordering::Greater) {
                    return Ok(false);
                }
            }
        }
        if let Value::Str(text) = instance {
            let length = text.len_code_points() as u64;
            if k.min_length.is_some_and(|minimum| length < minimum) || k.max_length.is_some_and(|maximum| length > maximum) {
                return Ok(false);
            }
            if k.pattern.as_ref().is_some_and(|pattern| !pattern.is_match(text)) {
                return Ok(false);
            }
        }
        if let Value::Array(items) = instance {
            let count = items.len() as u64;
            if k.min_items.is_some_and(|minimum| count < minimum) || k.max_items.is_some_and(|maximum| count > maximum) {
                return Ok(false);
            }
            if k.unique_items {
                for (index, item) in items.iter().enumerate() {
                    if items.iter().skip(index.saturating_add(1)).any(|other| json::schema_eq(item, other)) {
                        return Ok(false);
                    }
                }
            }
            if let Some(schema) = &k.items {
                for item in items {
                    if !self.valid(schema, item, depth)? {
                        return Ok(false);
                    }
                }
            }
        }
        if let Value::Object(object) = instance {
            if k.max_properties.is_some_and(|maximum| object.len() as u64 > maximum) {
                return Ok(false);
            }
            if k.required.iter().any(|name| !object.contains_key(name)) {
                return Ok(false);
            }
            for (name, schema) in &k.properties {
                if let Some(member) = object.get_key(name) {
                    if !self.valid(schema, member, depth)? {
                        return Ok(false);
                    }
                }
            }
            if let Some(additional) = &k.additional {
                for (name, member) in object.iter() {
                    if k.properties.iter().any(|(known, _)| known == name) {
                        continue;
                    }
                    let allowed = match additional {
                        Additional::Allowed(flag) => *flag,
                        Additional::Schema(schema) => self.valid(schema, member, depth)?,
                    };
                    if !allowed {
                        return Ok(false);
                    }
                }
            }
            if let Some(schema) = &k.property_names {
                for (name, _) in object.iter() {
                    if !self.valid(schema, &Value::Str(name.clone()), depth)? {
                        return Ok(false);
                    }
                }
            }
        }
        if let Some(all) = &k.all_of {
            for schema in all {
                if !self.valid(schema, instance, depth)? {
                    return Ok(false);
                }
            }
        }
        if let Some(any) = &k.any_of {
            let mut found = false;
            for schema in any {
                if self.valid(schema, instance, depth)? {
                    found = true;
                    break;
                }
            }
            if !found {
                return Ok(false);
            }
        }
        if let Some(one) = &k.one_of {
            let mut matched = 0usize;
            for schema in one {
                if self.valid(schema, instance, depth)? {
                    matched = matched.saturating_add(1);
                }
            }
            if matched != 1 {
                return Ok(false);
            }
        }
        if let Some(schema) = &k.not {
            if self.valid(schema, instance, depth)? {
                return Ok(false);
            }
        }
        if let Some(condition) = &k.if_ {
            if self.valid(condition, instance, depth)? {
                if let Some(consequence) = &k.then {
                    if !self.valid(consequence, instance, depth)? {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }
}

/// `jsonschema`'s Draft 2020-12 type checker: booleans are neither integers nor numbers; a float with an integral
/// value is an integer (Draft 6 and later).
fn is_type(instance: &Value, kind: JsonType) -> bool {
    match (kind, instance) {
        (JsonType::Null, Value::Null) => true,
        (JsonType::Boolean, Value::Bool(_)) => true,
        (JsonType::Integer, Value::Int(_)) => true,
        (JsonType::Integer, Value::Float(x)) => x.is_finite() && x.fract() == 0.0,
        (JsonType::Number, Value::Int(_) | Value::Float(_)) => true,
        (JsonType::String, Value::Str(_)) => true,
        (JsonType::Array, Value::Array(_)) => true,
        (JsonType::Object, Value::Object(_)) => true,
        _ => false,
    }
}

fn number_cmp(instance: &Value, bound: &Value) -> Option<Ordering> {
    match (instance, bound) {
        (Value::Int(x), Value::Int(y)) => Some(x.cmp(y)),
        (Value::Int(x), Value::Float(y)) => x.cmp_f64(*y),
        (Value::Float(x), Value::Int(y)) => y.cmp_f64(*x).map(Ordering::reverse),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(text: &str) -> Schema {
        match Schema::from_json(text.as_bytes()) {
            Ok(schema) => schema,
            Err(error) => panic!("{text}: {error:?}"),
        }
    }

    fn valid(schema: &Schema, instance: &str) -> bool {
        match json::parse(instance) {
            Ok(value) => schema.is_valid(&value),
            Err(error) => panic!("{instance}: {error:?}"),
        }
    }

    #[test]
    fn type_keyword() {
        let integer = schema(r#"{"type":"integer"}"#);
        assert!(valid(&integer, "3") && valid(&integer, "-0") && valid(&integer, "1.0"));
        assert!(!valid(&integer, "true") && !valid(&integer, "1.5") && !valid(&integer, "\"1\""));
        let number = schema(r#"{"type":"number"}"#);
        assert!(valid(&number, "1.5") && valid(&number, "2") && !valid(&number, "false"));
        let many = schema(r#"{"type":["null","string"]}"#);
        assert!(valid(&many, "null") && valid(&many, "\"x\"") && !valid(&many, "[]"));
        for (name, good, bad) in [("null", "null", "0"), ("boolean", "true", "1"), ("string", "\"\"", "null"),
                                  ("array", "[]", "{}"), ("object", "{}", "[]")] {
            let typed = schema(&format!(r#"{{"type":"{name}"}}"#));
            assert!(valid(&typed, good) && !valid(&typed, bad), "{name}");
        }
    }

    #[test]
    fn object_keywords() {
        let closed = schema(r#"{"type":"object","properties":{"a":{"type":"integer"}},"required":["a"],
                                "additionalProperties":false,"maxProperties":1}"#);
        assert!(valid(&closed, r#"{"a":1}"#));
        assert!(!valid(&closed, r#"{}"#) && !valid(&closed, r#"{"a":"x"}"#) && !valid(&closed, r#"{"a":1,"b":2}"#));
        let untyped = schema(r#"{"properties":{"a":{"type":"integer"}},"required":["a"],"additionalProperties":false,"maxProperties":0}"#);
        assert!(valid(&untyped, "[]") && valid(&untyped, "\"x\"") && !valid(&untyped, "{}"), "object keywords ignore other types");
        let open = schema(r#"{"additionalProperties":{"type":"string"},"properties":{"n":{"type":"integer"}}}"#);
        assert!(valid(&open, r#"{"n":1,"x":"y"}"#) && !valid(&open, r#"{"n":1,"x":2}"#));
        let names = schema(r#"{"propertyNames":{"minLength":1,"maxLength":3,"pattern":"^[ -~]+$"}}"#);
        assert!(valid(&names, r#"{"abc":1}"#) && !valid(&names, r#"{"abcd":1}"#) && !valid(&names, r#"{"":1}"#));
        assert!(!valid(&names, "{\"\u{e9}\":1}"));
        let empty = schema(r#"{"maxProperties":0}"#);
        assert!(valid(&empty, "{}") && !valid(&empty, r#"{"a":null}"#));
    }

    #[test]
    fn value_keywords() {
        let constant = schema(r#"{"const":1}"#);
        assert!(valid(&constant, "1") && valid(&constant, "1.0") && !valid(&constant, "true"));
        let flag = schema(r#"{"const":false}"#);
        assert!(valid(&flag, "false") && !valid(&flag, "0"));
        let options = schema(r#"{"enum":["A",200,null]}"#);
        assert!(valid(&options, "\"A\"") && valid(&options, "200") && valid(&options, "null"));
        assert!(!valid(&options, "\"B\"") && !valid(&options, "201"));
        let bounded = schema(r#"{"minimum":1,"maximum":9007199254740991}"#);
        assert!(valid(&bounded, "1") && valid(&bounded, "9007199254740991") && valid(&bounded, "\"x\""));
        assert!(!valid(&bounded, "0") && !valid(&bounded, "9007199254740992") && !valid(&bounded, "0.5"));
        assert!(!valid(&bounded, "99999999999999999999"));
        assert!(valid(&bounded, "true"), "bounds ignore booleans");
        let text = schema(r#"{"minLength":2,"maxLength":3,"pattern":"^[a-z]+$"}"#);
        assert!(valid(&text, "\"ab\"") && !valid(&text, "\"a\"") && !valid(&text, "\"abcd\"") && !valid(&text, "\"A1\""));
        assert!(valid(&text, "7"), "string keywords ignore other types");
        let lone = schema(r#"{"maxLength":1}"#);
        assert!(valid(&lone, "\"\\ud800\""), "a lone surrogate is one code point");
    }

    #[test]
    fn array_keywords() {
        let list = schema(r#"{"items":{"type":"integer"},"minItems":1,"maxItems":2,"uniqueItems":true}"#);
        assert!(valid(&list, "[1]") && valid(&list, "[1,2]"));
        assert!(!valid(&list, "[]") && !valid(&list, "[1,2,3]") && !valid(&list, "[1,1]") && !valid(&list, "[\"a\"]"));
        assert!(!valid(&list, "[1,1.0]"), "1 and 1.0 are equal");
        let mixed = schema(r#"{"uniqueItems":true}"#);
        assert!(valid(&mixed, "[1,true]") && valid(&mixed, "[0,false]") && !valid(&mixed, r#"[{"a":1},{"a":1}]"#));
    }

    #[test]
    fn combinators_and_conditionals() {
        let one = schema(r#"{"oneOf":[{"type":"integer"},{"minimum":0}]}"#);
        assert!(valid(&one, "-1") && !valid(&one, "1") && valid(&one, "0.5") && !valid(&one, "-0.5"));
        let any = schema(r#"{"anyOf":[{"enum":[200,201]},{"type":"integer","minimum":400,"maximum":499,"not":{"const":408}}]}"#);
        assert!(valid(&any, "201") && valid(&any, "404") && !valid(&any, "408") && !valid(&any, "500"));
        let all = schema(r#"{"allOf":[{"minimum":1},{"maximum":2}]}"#);
        assert!(valid(&all, "1") && !valid(&all, "3"));
        let negated = schema(r#"{"not":{"type":"null"}}"#);
        assert!(valid(&negated, "0") && !valid(&negated, "null"));
        let conditional = schema(r#"{"if":{"properties":{"s":{"minimum":400}}},"then":{"properties":{"u":{"type":"null"}}}}"#);
        assert!(valid(&conditional, r#"{"s":404,"u":null}"#) && !valid(&conditional, r#"{"s":404,"u":"x"}"#));
        assert!(valid(&conditional, r#"{"s":200,"u":"x"}"#));
        assert!(!valid(&conditional, r#"{"s":null,"u":"x"}"#), "an if over a non-numeric property holds vacuously");
        assert!(!valid(&conditional, r#"{"u":"x"}"#), "an if over an absent property holds vacuously");
    }

    #[test]
    fn local_references() {
        let recursive = schema(r##"{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:x","title":"t",
            "$defs":{"value":{"oneOf":[{"type":"integer"},{"type":"array","items":{"$ref":"#/$defs/value"}}]}},
            "$ref":"#/$defs/value"}"##);
        assert!(valid(&recursive, "[1,[2,[3]]]") && !valid(&recursive, "[1,[\"x\"]]"));
        let cycle = schema(r##"{"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}"##);
        assert!(!valid(&cycle, "1"), "a reference cycle exhausts the budget and refuses");
        let negated_cycle = schema(r##"{"$defs":{"a":{"$ref":"#/$defs/a"}},"not":{"$ref":"#/$defs/a"}}"##);
        assert!(!valid(&negated_cycle, "1"), "exhaustion is never inverted by not");
        let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
        let any_items = schema(r##"{"$defs":{"v":{"items":{"$ref":"#/$defs/v"}}},"$ref":"#/$defs/v"}"##);
        assert!(!valid(&any_items, &deep), "very deep instances are refused, not overflowed");
    }

    #[test]
    fn refuses_outside_the_subset() {
        for text in [r#"{"format":"date"}"#, r#"{"else":{}}"#, r#"{"patternProperties":{}}"#, r#"{"$ref":"other.json"}"#,
                     r##"{"$ref":"#/$defs/missing"}"##, r##"{"$schema":"http://json-schema.org/draft-07/schema#"}"##,
                     r#"{"properties":{"a":{"$schema":"https://json-schema.org/draft/2020-12/schema"}}}"#,
                     r#"{"properties":{"a":{"$id":"urn:y"}}}"#, r#"{"pattern":"\\d"}"#, r#"{"type":"float"}"#,
                     r#"{"minLength":-1}"#, r#"{"oneOf":[]}"#, "1", r#"{"uniqueItems":1}"#] {
            assert!(Schema::from_json(text.as_bytes()).is_err(), "{text}");
        }
        for text in [format!("{{\"const\":{}{}}}", "[".repeat(200), "]".repeat(200)),
                     format!("{{\"enum\":[{}{}]}}", "[".repeat(200), "]".repeat(200))] {
            assert!(Schema::from_json(text.as_bytes()).is_err(), "{text}");
        }
    }

    #[test]
    fn contract_schemas_load() {
        assert!(Schema::from_json(crate::contracts::I05_V3_SCHEMA).is_ok());
        assert!(Schema::from_json(crate::contracts::I07_V3_SCHEMA).is_ok());
    }
}
