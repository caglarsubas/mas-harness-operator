//! HE-004B1 DESIGN-B section 8 (D1-18): the test-side vector loader the I06 v2 replays use: `set`, `delete` and `append`
//! on object keys and array elements, with the list-element selector matched under Python `==` (i05-protocol's `py_eq`),
//! a missing member reading as null, and negative indices as Python's.

mod b1_support;

use b1_support::{apply, canonical_text, parse};

fn run(value: &str, ops: &str) -> String {
    let ops = parse(ops);
    canonical_text(&apply(&parse(value), ops.as_array().expect("ops")))
}

#[test]
fn set_delete_and_append_on_keys_and_elements() {
    assert_eq!(run(r#"{"a": 1}"#, r#"[{"op": "set", "path": ["b"], "value": [2]}]"#), r#"{"a":1,"b":[2]}"#);
    assert_eq!(run(r#"{"a": 1}"#, r#"[{"op": "set", "path": ["a"], "value": null}]"#), r#"{"a":null}"#);
    assert_eq!(run(r#"{"a": [1, 2, 3]}"#, r#"[{"op": "set", "path": ["a", 1], "value": 9}]"#), r#"{"a":[1,9,3]}"#);
    assert_eq!(run(r#"{"a": [1, 2, 3]}"#, r#"[{"op": "set", "path": ["a", -1], "value": 9}]"#), r#"{"a":[1,2,9]}"#);
    assert_eq!(run(r#"{"a": 1, "b": 2}"#, r#"[{"op": "delete", "path": ["a"]}]"#), r#"{"b":2}"#);
    assert_eq!(run(r#"{"a": [1, 2, 3]}"#, r#"[{"op": "delete", "path": ["a", 0]}]"#), r#"{"a":[2,3]}"#);
    assert_eq!(run(r#"{"a": {"b": []}}"#, r#"[{"op": "append", "path": ["a", "b"], "value": {"c": 1}}]"#), r#"{"a":{"b":[{"c":1}]}}"#);
    // Operations apply in order, each to the previous result; the input is not changed.
    let value = parse(r#"{"a": [1]}"#);
    let ops = parse(r#"[{"op": "append", "path": ["a"], "value": 2}, {"op": "set", "path": ["a", 0], "value": 0}]"#);
    assert_eq!(canonical_text(&apply(&value, ops.as_array().expect("ops"))), r#"{"a":[0,2]}"#);
    assert_eq!(canonical_text(&value), r#"{"a":[1]}"#);
}

#[test]
fn the_selector_matches_one_element_under_python_equality() {
    let subjects = r#"{"s": [{"kind": "User", "name": "a", "n": 1}, {"kind": "Group", "name": "a", "n": 2.0}, {"kind": "User", "name": "b"}]}"#;
    assert_eq!(run(subjects, r#"[{"op": "set", "path": ["s", {"kind": "Group", "name": "a"}, "n"], "value": 3}]"#),
               r#"{"s":[{"kind":"User","n":1,"name":"a"},{"kind":"Group","n":3,"name":"a"},{"kind":"User","name":"b"}]}"#);
    // 1 == 1.0 == true under Python ==: the selector {"n": true} picks the first element, {"n": 2} the second.
    assert_eq!(run(subjects, r#"[{"op": "delete", "path": ["s", {"n": true}]}]"#),
               r#"{"s":[{"kind":"Group","n":2.0,"name":"a"},{"kind":"User","name":"b"}]}"#);
    assert_eq!(run(subjects, r#"[{"op": "delete", "path": ["s", {"n": 2}]}]"#),
               r#"{"s":[{"kind":"User","n":1,"name":"a"},{"kind":"User","name":"b"}]}"#);
    // A missing member reads as null (Python's item.get(k) == v).
    assert_eq!(run(subjects, r#"[{"op": "delete", "path": ["s", {"n": null}]}]"#),
               r#"{"s":[{"kind":"User","n":1,"name":"a"},{"kind":"Group","n":2.0,"name":"a"}]}"#);
}

#[test]
#[should_panic(expected = "a selector picks out a single element")]
fn a_selector_matching_two_elements_is_refused() {
    run(r#"{"s": [{"name": "a"}, {"name": "a"}]}"#, r#"[{"op": "delete", "path": ["s", {"name": "a"}]}]"#);
}

#[test]
#[should_panic(expected = "a selector picks out a single element")]
fn a_selector_matching_nothing_is_refused() {
    run(r#"{"s": [{"name": "a"}]}"#, r#"[{"op": "delete", "path": ["s", {"name": "b"}]}]"#);
}
