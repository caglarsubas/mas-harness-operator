//! Shared localisation of best-match schema refusals (HE-004D2 DESIGN-D2 sections 11 and 15.1): B1's rule as HE-004D1
//! extended it to resolve conditionals. A vector's `schema <path> <keyword>` refusal is localised when, walking the
//! original schema to the path's end, one node holding `keyword` refuses the sub-instance as a one-keyword schema built
//! from that node (`additionalProperties` with the node's `properties` names); the one-off schemas carry the rewritten
//! `$defs`, which i05-protocol loads. HE-004D2's replays use it from phase A; HE-004D2's unit B1 moves the capture
//! replay's own copy of these helpers here (DESIGN-D2 section 4.4).
#![allow(dead_code)]

use i05_protocol::json::{JStr, Object, Value};
use i05_protocol::schema::Schema;
use planeon_observer::capture_schema::rewrite_conditionals;

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

/// jsonschema's `json_path`: `$`, then `.key` or `[index]` per element.
fn steps(path: &str) -> Vec<Step> {
    let rest = path.strip_prefix('$').expect("a JSON path starts with $");
    let bytes = rest.as_bytes();
    let (mut found, mut at) = (Vec::new(), 0);
    while at < bytes.len() {
        if bytes[at] == b'.' {
            let end = rest[at + 1..].find(['.', '[']).map_or(rest.len(), |offset| at + 1 + offset);
            found.push(Step::Key(rest[at + 1..end].to_string()));
            at = end;
        } else {
            let end = rest[at..].find(']').expect("a closing bracket") + at;
            found.push(Step::Index(rest[at + 1..end].parse().expect("an index")));
            at = end + 1;
        }
    }
    found
}

/// A one-off schema: `members` with the `$defs` of the walked schema.
fn one_off(members: Vec<(String, Value)>, defs: &Value) -> Schema {
    let mut root = Object::new();
    for (key, member) in members {
        root.insert(JStr::new(&key), member);
    }
    root.insert(JStr::new("$defs"), defs.clone());
    Schema::from_value(&Value::Object(root)).expect("a one-off schema loads")
}

fn members_of(node: &Value) -> Vec<(String, Value)> {
    node.as_object()
        .map(|object| object.iter().map(|(key, member)| (key.as_str().unwrap_or("").to_string(), member.clone())).collect())
        .unwrap_or_default()
}

/// The schema nodes that apply at one instance location: the node, what its `$ref` names, every `allOf` member, and
/// the branch of a conditional its `if` selects (evaluated on a one-off schema of the `if` over the loadable `$defs`).
/// With `branches` (HE-004D2), every `oneOf` and `anyOf` member too: jsonschema's best match descends into a failed
/// combinator's branches (the v4 record's `backendProfile` is a one-branch `oneOf` of constants).
fn applicable<'a>(node: &'a Value, defs: &'a Value, loadable: &Value, instance: &Value, branches: bool, out: &mut Vec<&'a Value>) {
    if node.as_object().is_none() {
        return;
    }
    out.push(node);
    if let Some(reference) = node.get("$ref").and_then(Value::as_str) {
        let name = reference.strip_prefix("#/$defs/").expect("a local reference");
        applicable(field(defs, name), defs, loadable, instance, branches, out);
    }
    let combinators: &[&str] = if branches { &["allOf", "oneOf", "anyOf"] } else { &["allOf"] };
    for combinator in combinators {
        for member in node.get(combinator).and_then(Value::as_array).unwrap_or_default() {
            applicable(member, defs, loadable, instance, branches, out);
        }
    }
    if let Some(condition) = node.get("if") {
        let holds = one_off(members_of(condition), loadable).is_valid(instance);
        let branch = if holds { node.get("then") } else { node.get("else") };
        if let Some(branch) = branch {
            applicable(branch, defs, loadable, instance, branches, out);
        }
    }
}

/// The nodes reached at the end of `path` from `node`, following `properties`, a schema-valued
/// `additionalProperties` and `items`.
fn reach<'a>(node: &'a Value, defs: &'a Value, loadable: &Value, instance: &Value, path: &[Step], branches: bool,
             out: &mut Vec<&'a Value>) {
    let mut here = Vec::new();
    applicable(node, defs, loadable, instance, branches, &mut here);
    let Some((first, rest)) = path.split_first() else {
        out.extend(here);
        return;
    };
    for candidate in here {
        match first {
            Step::Key(key) => {
                let Some(sub) = instance.get(key) else { continue };
                match candidate.get("properties").and_then(|properties| properties.get(key)) {
                    Some(child) => reach(child, defs, loadable, sub, rest, branches, out),
                    None => {
                        if let Some(extra) = candidate.get("additionalProperties").filter(|extra| extra.as_object().is_some()) {
                            reach(extra, defs, loadable, sub, rest, branches, out);
                        }
                    }
                }
            }
            Step::Index(index) => {
                let Some(sub) = instance.as_array().and_then(|items| items.get(*index)) else { continue };
                if let Some(items) = candidate.get("items") {
                    reach(items, defs, loadable, sub, rest, branches, out);
                }
            }
        }
    }
}

/// The value at `path` in `instance`.
fn locate<'a>(instance: &'a Value, path: &[Step]) -> &'a Value {
    path.iter().fold(instance, |node, step| match step {
        Step::Key(key) => field(node, key),
        Step::Index(index) => &node.as_array().expect("an array")[*index],
    })
}

/// Whether the refusal `schema <path> <keyword>` of `instance` as `variant` of `schema_root` is localised (see the module
/// documentation), following `allOf` and conditionals only (D1's rule).
pub fn localised(schema_root: &Value, variant: &str, instance: &Value, path: &str, keyword: &str) -> bool {
    localised_at(schema_root, variant, instance, path, keyword, false)
}

/// [`localised`] that also follows `oneOf` and `anyOf` branches; the replays use it only after the plain rule fails, and
/// count those cases.
pub fn localised_in_branch(schema_root: &Value, variant: &str, instance: &Value, path: &str, keyword: &str) -> bool {
    localised_at(schema_root, variant, instance, path, keyword, true)
}

fn localised_at(schema_root: &Value, variant: &str, instance: &Value, path: &str, keyword: &str, branches: bool) -> bool {
    let defs = field(schema_root, "$defs");
    let (rewritten, _) = rewrite_conditionals(schema_root).expect("the schema rewrites");
    let loadable = field(&rewritten, "$defs");
    let path = steps(path);
    let mut ends = Vec::new();
    reach(field(defs, variant), defs, loadable, instance, &path, branches, &mut ends);
    let sub = locate(instance, &path);
    ends.iter().filter(|node| node.get(keyword).is_some()).any(|node| {
        let mut members = vec![(keyword.to_string(), field(node, keyword).clone())];
        if keyword == "additionalProperties" {
            let mut names = Object::new();
            for (name, _) in node.get("properties").and_then(Value::as_object).map(|object| object.iter().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                names.insert(name.clone(), Value::Bool(true));
            }
            members.push(("properties".to_string(), Value::Object(names)));
        }
        !one_off(members, loadable).is_valid(sub)
    })
}

/// A schema-valued validator `{"$ref": "#/$defs/<variant>", "$defs": ...}` over a schema document loaded unchanged
/// (one without `else`, such as the native-profile v1-v3 schemas).
pub fn variant_validator(schema_root: &Value, variant: &str) -> Schema {
    let mut root = Object::new();
    root.insert(JStr::new("$ref"), Value::str(&format!("#/$defs/{variant}")));
    root.insert(JStr::new("$defs"), field(schema_root, "$defs").clone());
    Schema::from_value(&Value::Object(root)).expect("the schema loads unchanged")
}
