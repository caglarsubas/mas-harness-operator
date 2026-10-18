//! Watch-event lines (HE-004C DESIGN-C sections 5.2 and 9.2, Q-HE4C-1 (a); MODEL_DEFINED R110 and R114): one event per
//! LF-terminated line of a watch stream's decoded body. Watches are only a continuity and change detector: no object
//! is cached, diffed or fed to B1.
//!
//! - A line of at most 64 KiB is parsed strictly with i05-protocol's parser (duplicate keys refused): an object with
//!   exactly the members `type` and `object`, `object` an object whose `kind` is the stream's kind
//!   (`PartialObjectMetadata` for OR05's metadata-only watches).
//! - `ADDED`, `MODIFIED` and `DELETED` are changes. A line that grows past 64 KiB is a change at once (no bookmark or
//!   `ERROR` event is that long): the stream stops reading and every watch closes for a fresh snapshot (D1-7).
//! - `BOOKMARK` needs `object.metadata.resourceVersion` decimal, 1-20 digits and at most 2^64-1: the stream's mark.
//! - `ERROR`, any other type, or a malformed line is a gap (status 92).

use i05_protocol::json::{self, Value};

/// A watch line's bound (64 KiB, the LF excluded).
pub const LINE_LIMIT: usize = 64 << 10;

/// What one complete line means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `ADDED`, `MODIFIED` or `DELETED`.
    Change,
    /// `BOOKMARK` at this resourceVersion.
    Bookmark(u64),
    /// `ERROR`, another type or a malformed line.
    Gap(&'static str),
}

/// A line that grew past [`LINE_LIMIT`] before its LF: a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongLine;

/// A resourceVersion in the form the progress rule compares: 1 to 20 decimal digits, at most 2^64 - 1.
pub fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok()
}

/// The meaning of one complete line of a watch stream whose objects are of kind `kind`.
pub fn classify(line: &[u8], kind: &str) -> Event {
    let Ok(text) = std::str::from_utf8(line) else { return Event::Gap("a watch line is not UTF-8") };
    let Ok(value) = json::parse(text) else { return Event::Gap("a watch line is not strict JSON") };
    let Some(members) = value.as_object() else { return Event::Gap("a watch line is not an object") };
    if members.len() != 2 {
        return Event::Gap("a watch event does not hold exactly type and object");
    }
    let (Some(kind_of), Some(object)) = (members.get("type").and_then(Value::as_str), members.get("object")) else {
        return Event::Gap("a watch event does not hold exactly type and object");
    };
    if object.as_object().is_none() {
        return Event::Gap("a watch event's object is not an object");
    }
    if kind_of == "ERROR" {
        return Event::Gap("an ERROR watch event");
    }
    if object.get("kind").and_then(Value::as_str) != Some(kind) {
        return Event::Gap("a watch event's object is not of the stream's kind");
    }
    match kind_of {
        "ADDED" | "MODIFIED" | "DELETED" => Event::Change,
        "BOOKMARK" => {
            let version = object.get("metadata").and_then(|meta| meta.get("resourceVersion")).and_then(Value::as_str);
            match version.and_then(decimal) {
                Some(mark) => Event::Bookmark(mark),
                None => Event::Gap("a bookmark's resourceVersion is not decimal"),
            }
        }
        _ => Event::Gap("a watch event of another type"),
    }
}

/// The line framing of a watch stream's decoded bytes: complete lines out, at most [`LINE_LIMIT`] bytes held.
#[derive(Debug, Default)]
pub struct Lines {
    held: Vec<u8>,
}

impl Lines {
    pub fn new() -> Lines {
        Lines { held: Vec::new() }
    }

    /// Feeds decoded bytes; complete lines (without their LF) are appended to `out`. A line that grows past the bound
    /// refuses at once (the bytes after it are not looked at).
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<Vec<u8>>) -> Result<(), LongLine> {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let (body, ended) = match part.strip_suffix(b"\n") {
                Some(body) => (body, true),
                None => (part, false),
            };
            if self.held.len().saturating_add(body.len()) > LINE_LIMIT {
                self.held = Vec::new();
                return Err(LongLine);
            }
            self.held.extend_from_slice(body);
            if ended {
                out.push(std::mem::take(&mut self.held));
            }
        }
        Ok(())
    }

    /// The bytes of an unfinished line.
    pub fn held(&self) -> usize {
        self.held.len()
    }
}
