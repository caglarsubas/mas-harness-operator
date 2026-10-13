//! The JSON value model of the I05 wire and of `check_agreement` (DESIGN §5): the strict parser, the canonical encoder
//! and the three equalities the contract uses.
//!
//! The parser accepts exactly what the pinned CPython 3.12 `json.loads` accepts with a duplicate-refusing
//! `object_pairs_hook` and a `parse_constant` that refuses `NaN`, `Infinity` and `-Infinity`, and reports the first
//! error in document order: a refused constant at its token, a duplicate key when its object closes, anything else
//! (syntax, a raw control character in a string, an integer of more than 4300 digits) at its position. It never
//! recurses, so nesting depth costs only heap.
//!
//! The canonical encoder is Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False,
//! allow_nan=False)` followed by UTF-8 encoding: keys sorted by code point, floats as Python `repr`, a lone surrogate or
//! a non-finite float is an encoding error.

use std::cmp::Ordering;
use std::collections::HashSet;

/// CPython's default limit on the digits of an integer literal (`sys.get_int_max_str_digits()`).
pub const MAX_INT_DIGITS: usize = 4300;

// ------------------------------------------------------------------------------------------------ strings

/// A JSON string as a sequence of code points, which (as in Python) may hold lone surrogates. It is stored as
/// generalized UTF-8: valid UTF-8 except that a lone surrogate is the three-byte form of its code point. Byte order is
/// code-point order, so sorting by bytes sorts keys as Python does.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct JStr(Vec<u8>);

impl JStr {
    pub fn new(text: &str) -> JStr {
        JStr(text.as_bytes().to_vec())
    }

    /// The text, or `None` when the string holds a lone surrogate.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn has_lone_surrogate(&self) -> bool {
        self.as_str().is_none()
    }

    pub fn code_points(&self) -> CodePoints<'_> {
        CodePoints { bytes: &self.0, pos: 0 }
    }

    /// Python `len()`: the number of code points.
    pub fn len_code_points(&self) -> usize {
        self.0.iter().filter(|byte| (**byte & 0xC0) != 0x80).count()
    }

    fn push(&mut self, cp: u32) {
        if cp < 0x80 {
            self.0.push(cp as u8);
        } else if cp < 0x800 {
            self.0.push(0xC0 | (cp >> 6) as u8);
            self.0.push(0x80 | (cp & 0x3F) as u8);
        } else if cp < 0x1_0000 {
            self.0.push(0xE0 | (cp >> 12) as u8);
            self.0.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            self.0.push(0x80 | (cp & 0x3F) as u8);
        } else {
            self.0.push(0xF0 | ((cp >> 18) & 0x07) as u8);
            self.0.push(0x80 | ((cp >> 12) & 0x3F) as u8);
            self.0.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            self.0.push(0x80 | (cp & 0x3F) as u8);
        }
    }
}

impl From<&str> for JStr {
    fn from(text: &str) -> JStr {
        JStr::new(text)
    }
}

/// The code points of a [`JStr`].
pub struct CodePoints<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Iterator for CodePoints<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let first = *self.bytes.get(self.pos)?;
        let (length, mut cp) = if first < 0x80 {
            (1, u32::from(first))
        } else if first >= 0xF0 {
            (4, u32::from(first & 0x07))
        } else if first >= 0xE0 {
            (3, u32::from(first & 0x0F))
        } else {
            (2, u32::from(first & 0x1F))
        };
        for offset in 1..length {
            let byte = *self.bytes.get(self.pos.saturating_add(offset))?;
            cp = (cp << 6) | u32::from(byte & 0x3F);
        }
        self.pos = self.pos.saturating_add(length);
        Some(cp)
    }
}

// ------------------------------------------------------------------------------------------------ integers

/// An exact integer of any length (the parser bounds it at 4300 digits), compared exactly and never through `f64`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Int {
    negative: bool,
    /// Decimal digits without leading zeros; zero is `"0"` and never negative.
    magnitude: String,
}

impl Int {
    pub fn zero() -> Int {
        Int { negative: false, magnitude: "0".to_string() }
    }

    pub fn from_i64(value: i64) -> Int {
        Int { negative: value < 0, magnitude: value.unsigned_abs().to_string() }
    }

    pub fn from_u64(value: u64) -> Int {
        Int { negative: false, magnitude: value.to_string() }
    }

    /// `[-]digits`, leading zeros allowed and stripped; `None` for anything else.
    pub fn parse_decimal(text: &str) -> Option<Int> {
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let trimmed = digits.trim_start_matches('0');
        if trimmed.is_empty() {
            return Some(Int::zero());
        }
        Some(Int { negative, magnitude: trimmed.to_string() })
    }

    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// The number of decimal digits (without the sign).
    pub fn digits(&self) -> usize {
        self.magnitude.len()
    }

    pub fn to_i128(&self) -> Option<i128> {
        if self.magnitude.len() > 38 {
            return None;
        }
        let magnitude: i128 = self.magnitude.parse().ok()?;
        Some(if self.negative { -magnitude } else { magnitude })
    }

    pub fn to_i64(&self) -> Option<i64> {
        i64::try_from(self.to_i128()?).ok()
    }

    pub fn to_u64(&self) -> Option<u64> {
        u64::try_from(self.to_i128()?).ok()
    }

    pub fn to_decimal(&self) -> String {
        if self.negative {
            format!("-{}", self.magnitude)
        } else {
            self.magnitude.clone()
        }
    }

    /// Exact comparison with a float (`None` for NaN), as Python compares `int` with `float`.
    pub fn cmp_f64(&self, x: f64) -> Option<Ordering> {
        if x.is_nan() {
            return None;
        }
        if x.is_infinite() {
            return Some(if x > 0.0 { Ordering::Less } else { Ordering::Greater });
        }
        let whole = x.trunc();
        // Formatting with an explicit precision is exact, so this is the integer part's exact decimal expansion.
        let exact = Int::parse_decimal(&format!("{whole:.0}"))?;
        Some(match self.cmp(&exact) {
            Ordering::Equal => {
                let fraction = x - whole;
                if fraction > 0.0 {
                    Ordering::Less
                } else if fraction < 0.0 {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            }
            other => other,
        })
    }
}

impl Ord for Int {
    fn cmp(&self, other: &Int) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (negative, _) => {
                let magnitude = self
                    .magnitude
                    .len()
                    .cmp(&other.magnitude.len())
                    .then_with(|| self.magnitude.cmp(&other.magnitude));
                if negative { magnitude.reverse() } else { magnitude }
            }
        }
    }
}

impl PartialOrd for Int {
    fn partial_cmp(&self, other: &Int) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ------------------------------------------------------------------------------------------------ values

/// A decoded JSON value: Python's `None`, `bool`, `int`, `float`, `str`, `list` and `dict`.
#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Bool(bool),
    Int(Int),
    Float(f64),
    Str(JStr),
    Array(Vec<Value>),
    Object(Object),
}

/// An object's members in document order; keys are unique.
#[derive(Clone, Debug, Default)]
pub struct Object {
    entries: Vec<(JStr, Value)>,
}

/// Freeing a value never recurses: nested containers are emptied onto a heap stack first, so a deeply nested value
/// (a 16 KiB frame nests up to 8192 levels; an agreement-mode object is unbounded) cannot overflow the thread's stack.
impl Drop for Value {
    fn drop(&mut self) {
        fn take_children(value: &mut Value, into: &mut Vec<Value>) {
            match value {
                Value::Array(items) => into.append(items),
                Value::Object(object) => into.extend(object.entries.drain(..).map(|(_, member)| member)),
                _ => {}
            }
        }
        let mut pending = Vec::new();
        take_children(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            take_children(&mut value, &mut pending);
        }
    }
}

impl Object {
    pub fn new() -> Object {
        Object { entries: Vec::new() }
    }

    /// An empty object usable in a `static`.
    pub const fn const_empty() -> Object {
        Object { entries: Vec::new() }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(name, _)| name.as_bytes() == key.as_bytes()).map(|(_, value)| value)
    }

    pub fn get_key(&self, key: &JStr) -> Option<&Value> {
        self.entries.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn get_key_mut(&mut self, key: &JStr) -> Option<&mut Value> {
        self.entries.iter_mut().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn contains_key(&self, key: &JStr) -> bool {
        self.entries.iter().any(|(name, _)| name == key)
    }

    /// Python `dict[key] = value`: replaces in place, or appends.
    pub fn insert(&mut self, key: JStr, value: Value) {
        match self.entries.iter_mut().find(|(name, _)| *name == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    pub fn remove(&mut self, key: &JStr) -> Option<Value> {
        let index = self.entries.iter().position(|(name, _)| name == key)?;
        Some(self.entries.remove(index).1)
    }

    pub fn iter(&self) -> std::slice::Iter<'_, (JStr, Value)> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Value {
    pub fn str(text: &str) -> Value {
        Value::Str(JStr::new(text))
    }

    pub fn int(value: i64) -> Value {
        Value::Int(Int::from_i64(value))
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(object) => Some(object),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The text of a string without lone surrogates.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(text) => text.as_str(),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<&Int> {
        match self {
            Value::Int(int) => Some(int),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// `value.get(key)` on an object; `None` for a missing key or a non-object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.get(key)
    }
}

// ------------------------------------------------------------------------------------------------ parser

/// Why a text is not a JSON value. The frame decoder maps `Constant` to F03, `Duplicate` to F05 and `Syntax` to F06.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// `NaN`, `Infinity` or `-Infinity` (Python's `parse_constant`).
    Constant,
    /// A key repeated within one object, found when that object closes.
    Duplicate,
    /// Anything else: syntax, a raw control character in a string, an over-long integer, trailing data.
    Syntax,
}

/// Parses one JSON text (whitespace allowed around tokens, as Python's decoder allows).
pub fn parse(text: &str) -> Result<Value, ParseError> {
    Parser { bytes: text.as_bytes(), pos: 0 }.run()
}

enum Open {
    Array(Vec<Value>),
    Object(Vec<(JStr, Value)>, JStr),
}

enum Next {
    Value,
    Close(Value),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos.saturating_add(offset)).copied()
    }

    fn advance(&mut self, count: usize) {
        self.pos = self.pos.saturating_add(count);
    }

    fn rest_starts_with(&self, literal: &[u8]) -> bool {
        self.bytes.get(self.pos..).is_some_and(|rest| rest.starts_with(literal))
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.advance(1);
        }
    }

    fn run(mut self) -> Result<Value, ParseError> {
        let mut stack: Vec<Open> = Vec::new();
        self.skip_ws();
        loop {
            // One value starts here.
            let mut value = match self.peek() {
                Some(b'{') => {
                    self.advance(1);
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        self.advance(1);
                        Value::Object(Object::new())
                    } else {
                        let key = self.key()?;
                        stack.push(Open::Object(Vec::new(), key));
                        continue;
                    }
                }
                Some(b'[') => {
                    self.advance(1);
                    self.skip_ws();
                    if self.peek() == Some(b']') {
                        self.advance(1);
                        Value::Array(Vec::new())
                    } else {
                        stack.push(Open::Array(Vec::new()));
                        continue;
                    }
                }
                Some(b'"') => Value::Str(self.string()?),
                _ => self.scalar()?,
            };
            // Attach the finished value to its container, closing containers as far as they end here.
            loop {
                let next = match stack.last_mut() {
                    None => {
                        self.skip_ws();
                        return if self.pos == self.bytes.len() { Ok(value) } else { Err(ParseError::Syntax) };
                    }
                    Some(Open::Array(items)) => {
                        items.push(value);
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => {
                                self.advance(1);
                                self.skip_ws();
                                Next::Value
                            }
                            Some(b']') => {
                                self.advance(1);
                                Next::Close(Value::Array(std::mem::take(items)))
                            }
                            _ => return Err(ParseError::Syntax),
                        }
                    }
                    Some(Open::Object(pairs, key)) => {
                        pairs.push((std::mem::take(key), value));
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => {
                                self.advance(1);
                                self.skip_ws();
                                *key = self.key()?;
                                Next::Value
                            }
                            Some(b'}') => {
                                self.advance(1);
                                Next::Close(Value::Object(unique_object(std::mem::take(pairs))?))
                            }
                            _ => return Err(ParseError::Syntax),
                        }
                    }
                };
                match next {
                    Next::Value => break,
                    Next::Close(closed) => {
                        stack.pop();
                        value = closed;
                    }
                }
            }
        }
    }

    /// A member name and its `:`.
    fn key(&mut self) -> Result<JStr, ParseError> {
        if self.peek() != Some(b'"') {
            return Err(ParseError::Syntax);
        }
        let key = self.string()?;
        self.skip_ws();
        if self.peek() != Some(b':') {
            return Err(ParseError::Syntax);
        }
        self.advance(1);
        self.skip_ws();
        Ok(key)
    }

    fn scalar(&mut self) -> Result<Value, ParseError> {
        match self.peek() {
            Some(b'n') if self.rest_starts_with(b"null") => {
                self.advance(4);
                Ok(Value::Null)
            }
            Some(b't') if self.rest_starts_with(b"true") => {
                self.advance(4);
                Ok(Value::Bool(true))
            }
            Some(b'f') if self.rest_starts_with(b"false") => {
                self.advance(5);
                Ok(Value::Bool(false))
            }
            Some(b'N') if self.rest_starts_with(b"NaN") => Err(ParseError::Constant),
            Some(b'I') if self.rest_starts_with(b"Infinity") => Err(ParseError::Constant),
            Some(b'-') if self.peek_at(1) == Some(b'I') => {
                if self.rest_starts_with(b"-Infinity") {
                    Err(ParseError::Constant)
                } else {
                    Err(ParseError::Syntax)
                }
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(ParseError::Syntax),
        }
    }

    /// Python's number grammar: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`, where a `.` or an exponent marker
    /// without digits ends the number before it (the next token is then refused).
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.advance(1);
        }
        match self.peek() {
            Some(b'0') => self.advance(1),
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.advance(1);
                }
            }
            _ => return Err(ParseError::Syntax),
        }
        let integer_end = self.pos;
        let mut is_float = false;
        if self.peek() == Some(b'.') && matches!(self.peek_at(1), Some(b'0'..=b'9')) {
            is_float = true;
            self.advance(2);
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.advance(1);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let exponent_start = self.pos;
            self.advance(1);
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.advance(1);
            }
            let digits_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.advance(1);
            }
            if self.pos > digits_start {
                is_float = true;
            } else {
                self.pos = exponent_start;
            }
        }
        let text = self.bytes.get(start..self.pos).and_then(|raw| std::str::from_utf8(raw).ok());
        let text = text.ok_or(ParseError::Syntax)?;
        if is_float {
            return text.parse::<f64>().map(Value::Float).map_err(|_| ParseError::Syntax);
        }
        let digits = integer_end.saturating_sub(start).saturating_sub(usize::from(negative));
        if digits > MAX_INT_DIGITS {
            return Err(ParseError::Syntax);
        }
        Int::parse_decimal(text).map(Value::Int).ok_or(ParseError::Syntax)
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(byte @ b'0'..=b'9') => byte - b'0',
                Some(byte @ b'a'..=b'f') => byte - b'a' + 10,
                Some(byte @ b'A'..=b'F') => byte - b'A' + 10,
                _ => return Err(ParseError::Syntax),
            };
            value = (value << 4) | u32::from(digit);
            self.advance(1);
        }
        Ok(value)
    }

    /// A string; the cursor is on its opening quote. Escaped surrogate pairs join; lone surrogates stay.
    fn string(&mut self) -> Result<JStr, ParseError> {
        self.advance(1);
        let mut out = JStr::default();
        loop {
            let byte = self.peek().ok_or(ParseError::Syntax)?;
            match byte {
                b'"' => {
                    self.advance(1);
                    return Ok(out);
                }
                b'\\' => {
                    let escape = self.peek_at(1).ok_or(ParseError::Syntax)?;
                    self.advance(2);
                    let cp = match escape {
                        b'"' => 0x22,
                        b'\\' => 0x5C,
                        b'/' => 0x2F,
                        b'b' => 0x08,
                        b'f' => 0x0C,
                        b'n' => 0x0A,
                        b'r' => 0x0D,
                        b't' => 0x09,
                        b'u' => {
                            let high = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&high) && self.rest_starts_with(b"\\u") {
                                let resume = self.pos;
                                self.advance(2);
                                let low = self.hex4()?;
                                if (0xDC00..=0xDFFF).contains(&low) {
                                    0x1_0000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                                } else {
                                    self.pos = resume;
                                    high
                                }
                            } else {
                                high
                            }
                        }
                        _ => return Err(ParseError::Syntax),
                    };
                    out.push(cp);
                }
                0x00..=0x1F => return Err(ParseError::Syntax),
                _ => {
                    // Raw text, multi-byte UTF-8 included (the input is a valid `&str`).
                    out.0.push(byte);
                    self.advance(1);
                }
            }
        }
    }
}

fn unique_object(pairs: Vec<(JStr, Value)>) -> Result<Object, ParseError> {
    let mut seen: HashSet<&[u8]> = HashSet::with_capacity(pairs.len());
    for (key, _) in &pairs {
        if !seen.insert(key.as_bytes()) {
            return Err(ParseError::Duplicate);
        }
    }
    Ok(Object { entries: pairs })
}

// ------------------------------------------------------------------------------------------------ encoder

/// Why a value has no canonical encoding (each is a Python `ValueError` in `json.dumps` or the UTF-8 encode).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    LoneSurrogate,
    NonFiniteFloat,
    IntegerTooLong,
}

/// The canonical encoding of a value, without recursion.
pub fn canonical(value: &Value) -> Result<Vec<u8>, EncodeError> {
    enum Task<'a> {
        Value(&'a Value),
        Byte(u8),
        Key(&'a JStr),
    }
    let mut out = Vec::new();
    let mut tasks = vec![Task::Value(value)];
    while let Some(task) = tasks.pop() {
        match task {
            Task::Byte(byte) => out.push(byte),
            Task::Key(key) => {
                write_jstr(&mut out, key)?;
                out.push(b':');
            }
            Task::Value(Value::Null) => out.extend_from_slice(b"null"),
            Task::Value(Value::Bool(true)) => out.extend_from_slice(b"true"),
            Task::Value(Value::Bool(false)) => out.extend_from_slice(b"false"),
            Task::Value(Value::Int(int)) => {
                if int.digits() > MAX_INT_DIGITS {
                    return Err(EncodeError::IntegerTooLong);
                }
                out.extend_from_slice(int.to_decimal().as_bytes());
            }
            Task::Value(Value::Float(x)) => {
                out.extend_from_slice(py_float_repr(*x).ok_or(EncodeError::NonFiniteFloat)?.as_bytes());
            }
            Task::Value(Value::Str(text)) => write_jstr(&mut out, text)?,
            Task::Value(Value::Array(items)) => {
                out.push(b'[');
                tasks.push(Task::Byte(b']'));
                for (index, item) in items.iter().enumerate().rev() {
                    tasks.push(Task::Value(item));
                    if index > 0 {
                        tasks.push(Task::Byte(b','));
                    }
                }
            }
            Task::Value(Value::Object(object)) => {
                out.push(b'{');
                tasks.push(Task::Byte(b'}'));
                let mut members: Vec<&(JStr, Value)> = object.iter().collect();
                members.sort_by(|left, right| left.0.cmp(&right.0));
                for (index, (key, member)) in members.into_iter().enumerate().rev() {
                    tasks.push(Task::Value(member));
                    tasks.push(Task::Key(key));
                    if index > 0 {
                        tasks.push(Task::Byte(b','));
                    }
                }
            }
        }
    }
    Ok(out)
}

fn write_jstr(out: &mut Vec<u8>, text: &JStr) -> Result<(), EncodeError> {
    if text.has_lone_surrogate() {
        return Err(EncodeError::LoneSurrogate);
    }
    escape_into(out, text.as_bytes());
    Ok(())
}

/// Python's `ensure_ascii=False` string escaping of valid UTF-8 text.
fn escape_into(out: &mut Vec<u8>, text: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    for &byte in text {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x00..=0x1F => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(byte >> 4)]);
                out.push(HEX[usize::from(byte & 0x0F)]);
            }
            _ => out.push(byte),
        }
    }
    out.push(b'"');
}

/// The significant digits and decimal exponent of `{x:e}` for a finite, non-negative `x` (`x = d.ddd × 10^e`).
fn scientific_digits(text: &str) -> Option<(String, i64)> {
    let (mantissa, exponent) = text.split_once('e')?;
    let exponent: i64 = exponent.parse().ok()?;
    let mut digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    Some((digits, exponent))
}

/// CPython's shortest repr (David Gay's `dtoa` mode 0) breaks an exact tie between two shortest candidates toward the
/// even last digit, where Rust's shortest formatting rounds the tie up. Returns the even candidate when `digits` is the
/// odd one of such a tie (for example 111659285584252.125: Python prints `…252.12`).
fn tie_to_even(x: f64, digits: &str, exponent: i64) -> Option<String> {
    // ASCII '0' is even, so a digit's parity is its byte's parity.
    if digits.bytes().last()? % 2 == 0 {
        return None;
    }
    // A double's exact decimal expansion has at most 767 significant digits, so this is exact.
    let (exact, exact_exponent) = {
        let text = format!("{x:.1100e}");
        let (mantissa, exponent) = text.split_once('e')?;
        (mantissa.chars().filter(char::is_ascii_digit).collect::<String>(), exponent.parse::<i64>().ok()?)
    };
    if exact_exponent != exponent {
        return None;
    }
    let truncated = exact.get(..digits.len())?;
    let rest = exact.get(digits.len()..)?;
    if !(rest.starts_with('5') && rest.bytes().skip(1).all(|byte| byte == b'0')) {
        return None;
    }
    let alternative = if digits == truncated {
        // The candidate above: add one in the last place (no carry past an odd digit).
        let mut bytes = truncated.as_bytes().to_vec();
        let last = bytes.last_mut()?;
        *last = last.checked_add(1)?;
        String::from_utf8(bytes).ok()?
    } else {
        truncated.to_string()
    };
    if alternative.len() != digits.len() || alternative.ends_with('0') {
        return None;
    }
    let reparsed: f64 = format!("{}.{}e{}", alternative.get(..1)?, alternative.get(1..)?, exponent).parse().ok()?;
    (reparsed == x).then_some(alternative)
}

/// Python `float.__repr__`: the shortest digits that round-trip (an exact tie between two shortest candidates goes to
/// the even digit), fixed notation for decimal exponents -4 to 15 (with at least one fractional digit), otherwise
/// `d[.ddd]e±XX`. `None` for NaN and the infinities.
pub fn py_float_repr(x: f64) -> Option<String> {
    if !x.is_finite() {
        return None;
    }
    let negative = x.is_sign_negative();
    let magnitude = x.abs();
    // Rust's `{:e}` prints the shortest round-trip digits in scientific form, e.g. `1.5e-7`, `0e0`.
    let (mut digits, exponent) = scientific_digits(&format!("{magnitude:e}"))?;
    if let Some(even) = tie_to_even(magnitude, &digits, exponent) {
        digits = even;
    }
    let count = i64::try_from(digits.len()).ok()?;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if (-4..=15).contains(&exponent) {
        let point = exponent.checked_add(1)?;
        if point <= 0 {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', usize::try_from(-point).ok()?));
            out.push_str(&digits);
        } else if point < count {
            let split = usize::try_from(point).ok()?;
            out.push_str(digits.get(..split)?);
            out.push('.');
            out.push_str(digits.get(split..)?);
        } else {
            out.push_str(&digits);
            out.extend(std::iter::repeat_n('0', usize::try_from(point - count).ok()?));
            out.push_str(".0");
        }
    } else {
        out.push_str(digits.get(..1)?);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(digits.get(1..)?);
        }
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exponent.unsigned_abs()));
    }
    Some(out)
}

// ------------------------------------------------------------------------------------------------ documents

/// A document the gate builds itself (responses, journal records, digests' inputs): only text, integers, booleans
/// and null, so its canonical encoding cannot fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Doc {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Doc>),
    Object(Vec<(String, Doc)>),
}

impl Doc {
    pub fn str(text: &str) -> Doc {
        Doc::Str(text.to_string())
    }

    pub fn opt_str(text: Option<&str>) -> Doc {
        text.map_or(Doc::Null, Doc::str)
    }

    pub fn object(members: Vec<(&str, Doc)>) -> Doc {
        Doc::Object(members.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
    }

    /// The canonical encoding (gate documents are shallow, so this recursion is bounded by the gate's own code).
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Doc::Null => out.extend_from_slice(b"null"),
            Doc::Bool(true) => out.extend_from_slice(b"true"),
            Doc::Bool(false) => out.extend_from_slice(b"false"),
            Doc::Int(value) => out.extend_from_slice(value.to_string().as_bytes()),
            Doc::Str(text) => escape_into(out, text.as_bytes()),
            Doc::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    item.write(out);
                }
                out.push(b']');
            }
            Doc::Object(members) => {
                let mut sorted: Vec<&(String, Doc)> = members.iter().collect();
                sorted.sort_by(|left, right| left.0.cmp(&right.0));
                out.push(b'{');
                for (index, (key, member)) in sorted.into_iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    escape_into(out, key.as_bytes());
                    out.push(b':');
                    member.write(out);
                }
                out.push(b'}');
            }
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Doc::Null => Value::Null,
            Doc::Bool(flag) => Value::Bool(*flag),
            Doc::Int(value) => Value::int(*value),
            Doc::Str(text) => Value::str(text),
            Doc::Array(items) => Value::Array(items.iter().map(Doc::to_value).collect()),
            Doc::Object(members) => {
                let mut object = Object::new();
                for (key, member) in members {
                    object.insert(JStr::new(key), member.to_value());
                }
                Value::Object(object)
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------ walks

/// Iterative nesting depth (M5): scalars count 0 and an empty array or object counts 1.
pub fn depth(value: &Value) -> usize {
    let mut deepest = 0usize;
    let mut stack = vec![(value, 0usize)];
    while let Some((node, level)) = stack.pop() {
        match node {
            Value::Array(items) => {
                deepest = deepest.max(level.saturating_add(1));
                stack.extend(items.iter().map(|item| (item, level.saturating_add(1))));
            }
            Value::Object(object) => {
                deepest = deepest.max(level.saturating_add(1));
                stack.extend(object.iter().map(|(_, member)| (member, level.saturating_add(1))));
            }
            _ => {}
        }
    }
    deepest
}

/// Whether any value is a float.
pub fn contains_float(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Float(_) => return true,
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(object) => stack.extend(object.iter().map(|(_, member)| member)),
            _ => {}
        }
    }
    false
}

/// Whether any string value or member name holds a C0 control character or DEL.
pub fn contains_control(value: &Value) -> bool {
    let control = |text: &JStr| text.as_bytes().iter().any(|byte| *byte < 0x20 || *byte == 0x7F);
    let mut stack = vec![value];
    while let Some(node) = stack.pop() {
        match node {
            Value::Str(text) if control(text) => return true,
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(object) => {
                for (key, member) in object.iter() {
                    if control(key) {
                        return true;
                    }
                    stack.push(member);
                }
            }
            _ => {}
        }
    }
    false
}

// ------------------------------------------------------------------------------------------------ equalities

/// Exact numeric comparison of two numbers (`int` and `float`, booleans as 0 and 1 when `bool_is_int`).
fn number_cmp(left: &Value, right: &Value, bool_is_int: bool) -> Option<Ordering> {
    let as_int = |value: &Value| -> Option<Int> {
        match value {
            Value::Int(int) => Some(int.clone()),
            Value::Bool(flag) if bool_is_int => Some(Int::from_i64(i64::from(*flag))),
            _ => None,
        }
    };
    match (left, right) {
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y),
        (Value::Float(x), other) => as_int(other)?.cmp_f64(*x).map(Ordering::reverse),
        (other, Value::Float(y)) => as_int(other)?.cmp_f64(*y),
        _ => Some(as_int(left)?.cmp(&as_int(right)?)),
    }
}

/// Exact structural equality (types must agree; objects compare as maps). Used to compare outputs with vectors.
pub fn json_eq(left: &Value, right: &Value) -> bool {
    structural_eq(left, right, |a, b| match (a, b) {
        (Value::Null, Value::Null) => Some(true),
        (Value::Bool(x), Value::Bool(y)) => Some(x == y),
        (Value::Int(x), Value::Int(y)) => Some(x == y),
        (Value::Float(x), Value::Float(y)) => Some(x == y),
        (Value::Str(x), Value::Str(y)) => Some(x == y),
        (Value::Array(_), Value::Array(_)) | (Value::Object(_), Value::Object(_)) => None,
        _ => Some(false),
    })
}

/// Python `==` on decoded values: `True == 1 == 1.0`, `None` only equals `None`.
pub fn py_eq(left: &Value, right: &Value) -> bool {
    structural_eq(left, right, |a, b| match (a, b) {
        (Value::Null, Value::Null) => Some(true),
        (Value::Str(x), Value::Str(y)) => Some(x == y),
        (Value::Array(_), Value::Array(_)) | (Value::Object(_), Value::Object(_)) => None,
        (Value::Bool(_) | Value::Int(_) | Value::Float(_), Value::Bool(_) | Value::Int(_) | Value::Float(_)) => {
            Some(number_cmp(a, b, true) == Some(Ordering::Equal))
        }
        _ => Some(false),
    })
}

/// The `jsonschema` equality behind `const`, `enum` and `uniqueItems`: like Python `==`, except that a boolean only
/// equals a boolean (`true` is not `1`).
pub fn schema_eq(left: &Value, right: &Value) -> bool {
    structural_eq(left, right, |a, b| match (a, b) {
        (Value::Null, Value::Null) => Some(true),
        (Value::Bool(x), Value::Bool(y)) => Some(x == y),
        (Value::Str(x), Value::Str(y)) => Some(x == y),
        (Value::Array(_), Value::Array(_)) | (Value::Object(_), Value::Object(_)) => None,
        (Value::Int(_) | Value::Float(_), Value::Int(_) | Value::Float(_)) => {
            Some(number_cmp(a, b, false) == Some(Ordering::Equal))
        }
        _ => Some(false),
    })
}

/// Iterative structural comparison; `scalar` decides every pair that is not two arrays or two objects.
fn structural_eq(left: &Value, right: &Value, scalar: impl Fn(&Value, &Value) -> Option<bool>) -> bool {
    let mut stack = vec![(left, right)];
    while let Some((a, b)) = stack.pop() {
        if let Some(equal) = scalar(a, b) {
            if !equal {
                return false;
            }
            continue;
        }
        match (a, b) {
            (Value::Array(x), Value::Array(y)) => {
                if x.len() != y.len() {
                    return false;
                }
                stack.extend(x.iter().zip(y.iter()));
            }
            (Value::Object(x), Value::Object(y)) => {
                if x.len() != y.len() {
                    return false;
                }
                for (key, member) in x.iter() {
                    match y.get_key(key) {
                        Some(other) => stack.push((member, other)),
                        None => return false,
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(text: &str) -> Result<(), ParseError> {
        parse(text).map(|_| ())
    }

    #[test]
    fn parser_accepts_python_json() {
        for text in ["{}", " {} ", "[1 , 2]", "\t[1]\r\n", "true", "null", "\"\\/\"", "-0", "-0.0", "1e5", "0.1e1",
                     "1.0E+2", "\"\u{7f}\"", "\"a\u{2028}\""] {
            assert!(parse(text).is_ok(), "{text:?}");
        }
        assert!(matches!(parse("1e400"), Ok(Value::Float(x)) if x.is_infinite()));
        assert!(matches!(parse("-0"), Ok(Value::Int(ref int)) if *int == Int::zero()));
    }

    #[test]
    fn parser_refuses_like_python() {
        for text in ["01", "-", "1.", ".5", "+1", "[1,]", "{\"a\":1,}", "\u{feff}{}", "\"\u{1f}\"", "\"\\x41\"", "nul",
                     "-01", "2.", "1e", "1e+", "[-]", "-NaN", "[1]x", "", " ", "\"abc", "[1", "{\"a\" 1}", "\"\\u12\""] {
            assert_eq!(code(text), Err(ParseError::Syntax), "{text:?}");
        }
        for text in ["NaN", "Infinity", "-Infinity", "[1, NaN]", "{\"a\":1,\"a\":NaN}"] {
            assert_eq!(code(text), Err(ParseError::Constant), "{text:?}");
        }
        assert_eq!(code("{\"a\":1,\"a\":2}"), Err(ParseError::Duplicate));
        assert_eq!(code("{\"a\":1,\"a\":2}x"), Err(ParseError::Duplicate));
        assert_eq!(code("{\"a\":1,\"a\":2,"), Err(ParseError::Syntax));
        assert_eq!(code(&"1".repeat(4300)), Ok(()));
        assert_eq!(code(&format!("-{}", "1".repeat(4300))), Ok(()));
        assert_eq!(code(&"1".repeat(4301)), Err(ParseError::Syntax));
        assert_eq!(code(&format!("[{}]", "1".repeat(4301))), Err(ParseError::Syntax));
        assert_eq!(code(&format!("{{\"a\":1,\"a\":{}}}", "1".repeat(4301))), Err(ParseError::Syntax));
    }

    #[test]
    fn surrogates_join_only_as_escaped_pairs() {
        let pair = parse("\"\\ud83d\\ude00\"").ok();
        assert_eq!(pair.as_ref().and_then(Value::as_str), Some("\u{1f600}"));
        let lone = parse("\"\\ud83d\\u0041\"").ok();
        assert!(matches!(&lone, Some(Value::Str(text)) if text.has_lone_surrogate() && text.len_code_points() == 2));
        let reversed = parse("\"\\udc00\\ud800\"").ok();
        assert!(matches!(&reversed, Some(Value::Str(text)) if text.len_code_points() == 2));
        assert_eq!(code("{\"\\ud800\":1,\"\\ud800\":2}"), Err(ParseError::Duplicate));
        assert_eq!(code("{\"\\ud800\":1,\"\\udbff\":2}"), Ok(()));
    }

    #[test]
    fn deep_nesting_parses_without_recursion() {
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert_eq!(parse(&deep).map(|value| depth(&value)), Ok(100_000));
        assert_eq!(code(&"[".repeat(100_000)), Err(ParseError::Syntax));
    }

    #[test]
    fn float_repr_matches_python() {
        for (x, text) in [(1.0, "1.0"), (1e16, "1e+16"), (1e15, "1000000000000000.0"), (1.5e16, "1.5e+16"),
                          (1e-5, "1e-05"), (1e-4, "0.0001"), (5e-324, "5e-324"), (-0.0, "-0.0"), (0.0, "0.0"),
                          (0.1, "0.1"), (123456789012345680.0, "1.2345678901234568e+17"),
                          (1.7976931348623157e308, "1.7976931348623157e+308"), (2.5, "2.5"), (100.0, "100.0"),
                          (1e22, "1e+22"), (0.00012345, "0.00012345"), (123.456, "123.456"), (-1.5e-7, "-1.5e-07"),
                          (-1113178120592002.25, "-1113178120592002.2"), (-233891771783429.625, "-233891771783429.62"),
                          (111659285584252.125, "111659285584252.12")] {
            assert_eq!(py_float_repr(x).as_deref(), Some(text), "{x:e}");
        }
        assert_eq!(py_float_repr(f64::INFINITY), None);
        assert_eq!(py_float_repr(f64::NAN), None);
    }

    #[test]
    fn canonical_matches_python_dumps() {
        let value = parse("{\"b\":[1,2.5,true,null],\"a\":\"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\\\"\\\\/\u{7f}\u{2028}\"}");
        let encoded = value.as_ref().ok().map(canonical);
        let expected = "{\"a\":\"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\\\"\\\\/\u{7f}\u{2028}\",\"b\":[1,2.5,true,null]}";
        assert_eq!(encoded, Some(Ok(expected.as_bytes().to_vec())));
        // Code-point key order, not UTF-16 order: U+FF01 sorts before U+1F600.
        let keys = parse("{\"\u{1f600}\":2,\"\u{ff01}\":1}").ok().map(|value| canonical(&value));
        assert_eq!(keys, Some(Ok("{\"\u{ff01}\":1,\"\u{1f600}\":2}".as_bytes().to_vec())));
        assert_eq!(parse("\"\\ud800\"").ok().map(|value| canonical(&value)), Some(Err(EncodeError::LoneSurrogate)));
        assert_eq!(canonical(&Value::Float(f64::INFINITY)), Err(EncodeError::NonFiniteFloat));
        assert_eq!(parse("-0").ok().map(|value| canonical(&value)), Some(Ok(b"0".to_vec())));
    }

    #[test]
    fn doc_encoding_matches_value_encoding() {
        let doc = Doc::object(vec![("z", Doc::Array(vec![Doc::Int(-3), Doc::Null, Doc::Bool(true)])),
                                   ("a", Doc::str("q\"\n\u{1}"))]);
        assert_eq!(canonical(&doc.to_value()), Ok(doc.canonical()));
    }

    #[test]
    fn integers_compare_exactly() {
        let big = Int::parse_decimal("9007199254740993").unwrap_or_else(Int::zero);
        assert_eq!(big.cmp_f64(9007199254740992.0), Some(Ordering::Greater));
        let two_70 = Int::parse_decimal("1180591620717411303424").unwrap_or_else(Int::zero);
        assert_eq!(two_70.cmp_f64(2f64.powi(70)), Some(Ordering::Equal));
        assert_eq!(Int::from_i64(1).cmp_f64(1.5), Some(Ordering::Less));
        assert_eq!(Int::from_i64(-2).cmp_f64(-1.5), Some(Ordering::Less));
        assert_eq!(Int::from_i64(-1).cmp(&Int::from_i64(-10)), Ordering::Greater);
        assert_eq!(Int::zero().cmp_f64(-0.0), Some(Ordering::Equal));
    }

    #[test]
    fn equalities_follow_python_and_jsonschema() {
        let one = Value::int(1);
        assert!(py_eq(&Value::Bool(true), &one) && py_eq(&Value::Float(1.0), &one));
        assert!(!schema_eq(&Value::Bool(true), &one) && schema_eq(&Value::Float(1.0), &one));
        assert!(!json_eq(&Value::Float(1.0), &one));
        let a = parse("{\"x\":[1,{\"y\":null}],\"z\":\"s\"}").ok();
        let b = parse("{\"z\":\"s\",\"x\":[1,{\"y\":null}]}").ok();
        assert!(matches!((&a, &b), (Some(a), Some(b)) if json_eq(a, b)));
    }
}
