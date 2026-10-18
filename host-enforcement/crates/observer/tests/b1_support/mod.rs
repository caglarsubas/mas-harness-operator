//! Shared helpers for HE-004B1's tests: JSON through i05-protocol's own parser, list inputs in the apiserver's shape, and
//! the I06 v2 vector loader (`set`, `delete`, `append`, with the list-element selector matched by `py_eq`, D1-18).
#![allow(dead_code)]

use i05_protocol::json::{self, JStr, Value};
use planeon_observer::inputs::{Inputs, ListBody, ListInput, Resource};

pub fn parse(text: &str) -> Value {
    json::parse(text).expect("test JSON parses")
}

pub fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

pub fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    field(value, key).as_str().unwrap_or_else(|| panic!("{key} is not text"))
}

/// A value's canonical JSON text (i05-protocol's encoder: sorted keys, no whitespace).
pub fn canonical_text(value: &Value) -> String {
    String::from_utf8(json::canonical(value).expect("canonical")).expect("UTF-8")
}

pub fn rows<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    field(value, key).as_array().unwrap_or_else(|| panic!("{key} is not an array"))
}

/// A complete list answer for a closed-set entry holding `items` (a JSON array text).
pub fn list_value(resource: Resource, items: &str) -> Value {
    let (kind, api_version) = resource.list_kind();
    parse(&format!(r#"{{"kind": "{kind}", "apiVersion": "{api_version}", "metadata": {{"resourceVersion": "7"}}, "items": {items}}}"#))
}

pub fn served(resource: Resource, items: &str) -> ListInput {
    ListInput { spec: resource.spec(), body: ListBody::Served(list_value(resource, items)) }
}

pub fn unserved(resource: Resource) -> ListInput {
    ListInput { spec: resource.spec(), body: ListBody::NotServed }
}

pub fn inputs(pairs: Vec<ListInput>) -> Inputs {
    Inputs::new(pairs).expect("the inputs are complete")
}

/// Every closed-set entry as an empty complete list, except those `replace` gives.
pub fn all_empty_except(replace: Vec<ListInput>) -> Vec<ListInput> {
    let mut pairs: Vec<ListInput> = Resource::ALL
        .into_iter()
        .filter(|resource| !replace.iter().any(|input| Resource::of_spec(&input.spec) == Some(*resource)))
        .map(|resource| served(resource, "[]"))
        .collect();
    pairs.extend(replace);
    pairs
}

// ------------------------------------------------------------------------------------------------ vector operations

/// The validator's `_locate`: an index, or the one array element whose members equal the selector's under Python `==`
/// (`item.get(k) == v`, so a missing member reads as null).
fn locate(node: &Value, key: &Value) -> usize {
    match key {
        Value::Object(selector) => {
            let items = node.as_array().expect("a selector applies to an array");
            let found: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, item)| {
                    let object = item.as_object().expect("a selected element is an object");
                    selector.iter().all(|(name, wanted)| json::py_eq(object.get_key(name).unwrap_or(&Value::Null), wanted))
                })
                .map(|(index, _)| index)
                .collect();
            assert_eq!(found.len(), 1, "a selector picks out a single element of the array");
            found[0]
        }
        Value::Int(index) => {
            let length = node.as_array().expect("an index applies to an array").len() as i64;
            let index = index.to_i64().expect("small index");
            usize::try_from(if index < 0 { length + index } else { index }).expect("index in range")
        }
        _ => panic!("an array step is a selector or an index"),
    }
}

fn child<'a>(node: &'a mut Value, key: &Value) -> &'a mut Value {
    if let Value::Str(name) = key {
        return match node {
            Value::Object(object) => object.get_key_mut(name).expect("the key exists"),
            _ => panic!("a key applies to an object"),
        };
    }
    let index = locate(node, key);
    match node {
        Value::Array(items) => &mut items[index],
        _ => panic!("an index applies to an array"),
    }
}

fn set(node: &mut Value, last: &Value, new: Value) {
    if let (Value::Str(name), Value::Object(object)) = (last, &mut *node) {
        object.insert(name.clone(), new);
        return;
    }
    let index = locate(node, last);
    match node {
        Value::Array(items) => items[index] = new,
        _ => panic!("set applies to an object key or an array element"),
    }
}

fn delete(node: &mut Value, last: &Value) {
    if let (Value::Str(name), Value::Object(object)) = (last, &mut *node) {
        object.remove(name).expect("the deleted key exists");
        return;
    }
    let index = locate(node, last);
    match node {
        Value::Array(items) => {
            items.remove(index);
        }
        _ => panic!("delete applies to an object key or an array element"),
    }
}

/// The validator's `_apply`: a copy of `value` with each operation applied in order.
pub fn apply(value: &Value, ops: &[Value]) -> Value {
    let mut value = value.clone();
    for op in ops {
        let path = rows(op, "path");
        let (last, parents) = path.split_last().expect("a non-empty path");
        let mut node = &mut value;
        for key in parents {
            node = child(node, key);
        }
        match text(op, "op") {
            "set" => set(node, last, field(op, "value").clone()),
            "delete" => delete(node, last),
            "append" => match child(node, last) {
                Value::Array(items) => items.push(field(op, "value").clone()),
                _ => panic!("append applies to an array"),
            },
            other => panic!("closed vector operation, not {other}"),
        }
    }
    value
}

pub fn key(name: &str) -> JStr {
    JStr::new(name)
}
