//! HE-004D1 DESIGN-D1 sections 6.1-6.3 (owner decision Q-HE4D1-3 (a); MODEL_DEFINED R122): the embedded schema's
//! canonical digest pin, and the `if/then/else` rewrite: the truth table over all eight (A, B, C) combinations with
//! siblings and an existing `allOf` kept in order, the closed forms, and the pinned schema's exactly two rewritten nodes,
//! no `else` left and every variant loading.

use i05_protocol::json::{self, Value};
use i05_protocol::schema::Schema;
use planeon_observer::capture_schema::{rewrite_conditionals, CaptureSchema, RewriteError, SchemaLoadError, CANONICAL_PIN};
use planeon_observer::contracts;

fn parse(text: &str) -> Value {
    json::parse(text).unwrap_or_else(|error| panic!("{text}: {error:?}"))
}

fn rewritten(text: &str) -> (Value, Vec<String>) {
    rewrite_conditionals(&parse(text)).expect("a closed conditional rewrites")
}

fn load(value: &Value) -> Schema {
    Schema::from_value(value).expect("the rewritten schema loads")
}

const A: &str = r#"{"properties": {"a": {"const": true}}}"#;
const B: &str = r#"{"properties": {"b": {"const": true}}}"#;
const C: &str = r#"{"properties": {"c": {"const": true}}}"#;

fn instance(a: bool, b: bool, c: bool) -> Value {
    parse(&format!(r#"{{"a": {a}, "b": {b}, "c": {c}}}"#))
}

#[test]
fn the_truth_table_over_all_eight_combinations() {
    let (value, places) = rewritten(&format!(r#"{{"if": {A}, "then": {B}, "else": {C}}}"#));
    assert_eq!(places, vec![String::new()]);
    let schema = load(&value);
    for a in [false, true] {
        for b in [false, true] {
            for c in [false, true] {
                assert_eq!(schema.is_valid(&instance(a, b, c)), if a { b } else { c }, "a={a} b={b} c={c}");
            }
        }
    }
    // i05-protocol itself still refuses `else`.
    assert!(Schema::from_value(&parse(&format!(r#"{{"if": {A}, "then": {B}, "else": {C}}}"#))).is_err());
}

#[test]
fn siblings_and_an_existing_all_of_are_kept_in_order() {
    let text = format!(r#"{{"type": "object", "allOf": [{{"required": ["a"]}}], "if": {A}, "then": {B}, "else": {C},
                          "maxProperties": 3}}"#);
    let (value, _) = rewritten(&text);
    let keys: Vec<&str> = value.as_object().expect("an object").iter().map(|(key, _)| key.as_str().unwrap_or("")).collect();
    assert_eq!(keys, vec!["type", "allOf", "maxProperties"]);
    let members = value.get("allOf").and_then(Value::as_array).expect("allOf");
    assert_eq!(members.len(), 3);
    assert!(json::json_eq(&members[0], &parse(r#"{"required": ["a"]}"#)));
    assert!(json::json_eq(&members[1], &parse(&format!(r#"{{"if": {A}, "then": {B}}}"#))));
    assert!(json::json_eq(&members[2], &parse(&format!(r#"{{"anyOf": [{A}, {C}]}}"#))));
    let schema = load(&value);
    for a in [false, true] {
        for b in [false, true] {
            for c in [false, true] {
                assert_eq!(schema.is_valid(&instance(a, b, c)), if a { b } else { c }, "a={a} b={b} c={c}");
            }
        }
    }
    assert!(!schema.is_valid(&parse(r#"{"b": true, "c": true}"#)), "the existing allOf member still applies");
    // A nested conditional inside `then` and one inside `properties` are both rewritten, innermost first.
    let nested = format!(r#"{{"properties": {{"x": {{"if": {A}, "then": {B}, "else": {C}}}}},
                            "if": {A}, "then": {{"if": {B}, "then": {C}, "else": {A}}}, "else": {B}}}"#);
    let (value, places) = rewritten(&nested);
    assert_eq!(places, vec!["properties/x".to_string(), "then".to_string(), String::new()]);
    load(&value);
}

#[test]
fn the_closed_form_is_required_and_data_is_untouched() {
    for text in [format!(r#"{{"then": {B}, "else": {C}}}"#), format!(r#"{{"if": {A}, "else": {C}}}"#),
                 format!(r#"{{"$defs": {{"d": {{"else": {C}}}}}}}"#)] {
        assert!(matches!(rewrite_conditionals(&parse(&text)), Err(RewriteError::OpenConditional(_))), "{text}");
    }
    assert!(matches!(rewrite_conditionals(&parse(&format!(r#"{{"allOf": {A}, "if": {A}, "then": {B}, "else": {C}}}"#))),
                     Err(RewriteError::AllOf(_))));
    // Properties named if, then and else, and const and enum values holding those keys, are data.
    let data = r#"{"properties": {"if": {"type": "string"}, "else": {"const": {"else": 1, "if": 2}}},
                   "enum": [{"else": 3}], "required": ["else"]}"#;
    let (value, places) = rewritten(data);
    assert!(places.is_empty());
    assert!(json::json_eq(&value, &parse(data)));
    // An if/then without else is i05-protocol's own and stays.
    let plain = format!(r#"{{"if": {A}, "then": {B}}}"#);
    let (value, places) = rewritten(&plain);
    assert!(places.is_empty() && json::json_eq(&value, &parse(&plain)));
}

/// Every object key named `else` at any depth of a value.
fn else_keys(value: &Value) -> usize {
    let mut count = 0;
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(object) => {
                for (key, member) in object.iter() {
                    count += usize::from(key.as_str() == Some("else"));
                    stack.push(member);
                }
            }
            Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    count
}

#[test]
fn the_pinned_schema_has_exactly_two_conditionals_and_every_variant_loads() {
    let text = std::str::from_utf8(contracts::NATIVE_PROFILE_V4_SCHEMA).expect("ASCII");
    let original = parse(text);
    assert_eq!(else_keys(&original), 2);
    let (value, places) = rewrite_conditionals(&original).expect("the pinned schema rewrites");
    assert_eq!(places, vec!["$defs/capture/allOf/0".to_string(), "$defs/capture/allOf/3".to_string()]);
    assert_eq!(else_keys(&value), 0);
    // The two plain if/then members (allOf/1 and allOf/2) are unchanged.
    let before = original.get("$defs").and_then(|defs| defs.get("capture")).and_then(|capture| capture.get("allOf"));
    let after = value.get("$defs").and_then(|defs| defs.get("capture")).and_then(|capture| capture.get("allOf"));
    let (before, after) = (before.and_then(Value::as_array).expect("allOf"), after.and_then(Value::as_array).expect("allOf"));
    assert_eq!(before.len(), after.len());
    assert!(json::json_eq(&before[1], &after[1]) && json::json_eq(&before[2], &after[2]));
    assert!(!json::json_eq(&before[0], &after[0]) && !json::json_eq(&before[3], &after[3]));
    assert!(CaptureSchema::embedded().is_ok(), "every variant loads");
}

#[test]
fn the_canonical_digest_pin_is_checked() {
    assert_eq!(CANONICAL_PIN, "3bf244b21f91e30062ad56a7a21f3f0b4554daa71a0c3b624bcac058fee58d80");
    let text = std::str::from_utf8(contracts::NATIVE_PROFILE_V4_SCHEMA).expect("ASCII");
    let encoded = json::canonical(&parse(text)).expect("canonical");
    assert_eq!(i05_protocol::sha256::hex(&i05_protocol::sha256::digest(&encoded)), CANONICAL_PIN);
    // Whitespace does not change the canonical pin; a changed value does.
    let spaced = text.replacen("{", "{ ", 1);
    assert!(CaptureSchema::from_bytes(spaced.as_bytes()).is_ok());
    let changed = text.replacen("\"DATA_CHECK_ONLY\"", "\"DATA_CHECK_ONLY_\"", 1);
    assert!(matches!(CaptureSchema::from_bytes(changed.as_bytes()), Err(SchemaLoadError::Pin)));
    assert!(matches!(CaptureSchema::from_bytes(&contracts::NATIVE_PROFILE_V4_SCHEMA[1..]), Err(SchemaLoadError::Parse)));
    assert!(matches!(CaptureSchema::from_bytes(b"\xff"), Err(SchemaLoadError::Parse)));
}
