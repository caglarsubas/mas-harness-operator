//! HTTP/1.1 for the observer's apiserver reads (HE-004C DESIGN-C section 5, Q-HE4C-2 (a); MODEL_DEFINED R110):
//!
//! - [`render`]: `GET <target> HTTP/1.1`, then exactly `Host`, `User-Agent: planeon-observer`, one `Accept` value per
//!   request kind and `Connection: close`, then CRLF. No body, no `Authorization` (client-certificate authentication),
//!   no `Accept-Encoding`. A pure function, tested byte for byte.
//! - [`Framer`]: gate-tls's `ResponseReader` state machines (R63), copied and parameterised: the status line exactly
//!   `HTTP/1.1 SP 3DIGIT SP reason CRLF` (100-599; 100, 102 and 103 skipped, at most four; 101 and 104-199 refused), all
//!   heads together at most 16 KiB, case-insensitive field names, one `Content-Length` or one `Transfer-Encoding:
//!   chunked` and never both, `Content-Encoding` only `identity`, no body on 204 or 304 and no close-delimited body,
//!   strict chunking (1-7 hex digits, no extension, CRLF after each chunk, the zero chunk then CRLF, no trailer), and
//!   any byte after the complete answer refused. The decoded body bound and the chunked raw bound are parameters (none
//!   for a watch stream); the decoded bytes go to the caller. It also keeps the final head's `Content-Type` value.
//! - [`AnswerReader`]: the framer collecting the decoded body (lists 4 MiB, small documents 64 KiB, raw chunked at most
//!   the bound plus 64 KiB). On HE-003C's framing cases it gives the same outcome as gate-tls's reader (parity test).
//! - [`StreamReader`]: the same framer handing the decoded bytes to a sink as they arrive (the `/metrics` exposition,
//!   raw at most 64 MiB; a watch stream, unbounded in total and bounded per line by `watch`).
//! - [`media_type`]: the type and subtype of a `Content-Type` value, compared without its parameters.

/// The longest head (all heads together), CRLF CRLF included.
pub const HEAD_LIMIT: usize = 16_384;
/// The interim answers (100, 102, 103) skipped before the final one, at most.
pub const INTERIM_LIMIT: usize = 4;
/// A list's decoded body, at most (4 MiB).
pub const LIST_BODY_LIMIT: usize = 4 << 20;
/// A small document's decoded body (discovery, `/version`, `/readyz`, the progress read), at most (64 KiB).
pub const SMALL_BODY_LIMIT: usize = 64 << 10;
/// The decoded list bodies of one snapshot together, at most (16 MiB).
pub const SNAPSHOT_BODY_LIMIT: usize = 16 << 20;
/// A chunked body's framing allowance beyond its decoded bound (64 KiB).
pub const RAW_SLACK: usize = 64 << 10;
/// The `/metrics` answer's raw bytes, at most (64 MiB).
pub const METRICS_RAW_LIMIT: usize = 64 << 20;
/// The hex digits of one chunk size, at most.
const CHUNK_SIZE_DIGITS: usize = 7;
/// The decimal digits of a `Content-Length`, at least this many are accepted (more when the bound needs them).
const LENGTH_DIGITS: usize = 7;

/// The `User-Agent` line's value.
pub const USER_AGENT: &str = "planeon-observer";
/// The `Accept` values, one per request kind (D1-15).
pub const ACCEPT_JSON: &str = "application/json";
pub const ACCEPT_METADATA_LIST: &str = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1";
pub const ACCEPT_METADATA_WATCH: &str = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1";
pub const ACCEPT_TEXT: &str = "text/plain";
pub const ACCEPT_METRICS: &str = "text/plain;version=0.0.4";

/// One request: its target (path and query) and its `Accept` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub target: String,
    pub accept: &'static str,
}

/// The request's bytes for the apiserver at `authority` (the configured literal, the `Host` line).
pub fn render(request: &Request, authority: &str) -> Vec<u8> {
    format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: {}\r\nConnection: close\r\n\r\n", request.target,
            authority, USER_AGENT, request.accept)
        .into_bytes()
}

/// The type and subtype of a `Content-Type` value, ASCII-lowercased and trimmed, and its parameters as (name
/// lowercased, value) pairs; `None` for a value without a `/`.
pub fn media_type(value: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let text = std::str::from_utf8(value).ok()?;
    let mut parts = text.split(';');
    let essence = parts.next()?.trim().to_ascii_lowercase();
    let (kind, subtype) = essence.split_once('/')?;
    if kind.is_empty() || subtype.is_empty() {
        return None;
    }
    let mut parameters = Vec::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, value) = part.split_once('=')?;
        parameters.push((name.trim().to_ascii_lowercase(), value.trim().trim_matches('"').to_string()));
    }
    Some((essence, parameters))
}

/// Whether a `Content-Type` value's type and subtype are `essence` (parameters are T04's).
pub fn media_is(value: Option<&[u8]>, essence: &str) -> bool {
    value.and_then(media_type).is_some_and(|(found, _)| found == essence)
}

/// Whether a `Content-Type` value is `text/plain` with a `version=0.0.4` parameter (the `/metrics` exposition).
pub fn media_is_exposition(value: Option<&[u8]>) -> bool {
    value.and_then(media_type).is_some_and(|(found, parameters)| {
        found == "text/plain" && parameters.iter().any(|(name, value)| name == "version" && value == "0.0.4")
    })
}

/// Why an answer is refused (a framing refusal).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not `HTTP/1.1 SP 3DIGIT SP reason CRLF` with a status in 100-599.
    StatusLine,
    /// 101 or 104-199, or more than four interim answers.
    Interim,
    /// The heads together (interim and final) exceed 16,384 bytes.
    HeadSize,
    /// A field line that is not `name: value` (an obs-fold, a control byte, a bare CR or LF, an empty name).
    Field,
    /// A duplicate, malformed or oversize `Content-Length`, a duplicate `Transfer-Encoding`, or both present.
    Length,
    /// A transfer-coding other than `chunked`, or a `Content-Encoding` other than `identity`.
    Coding,
    /// No `Content-Length` or `chunked` on a status that has a body, or a body on 204 or 304.
    Body,
    /// A chunk size, extension or chunk delimiter outside the strict form, or a trailer.
    Chunk,
    /// The decoded body over its bound, or the raw chunked body over its bound.
    Size,
    /// Bytes after the complete answer.
    Surplus,
}

/// What the answer received so far holds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    NeedMore,
    /// The final answer is complete.
    Complete,
    Refused(Refusal),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Chunk {
    /// Reading a size line: the digits so far and their value.
    Size { digits: usize, value: usize },
    /// The LF after a size line's CR.
    SizeLf { size: usize },
    /// Chunk data still to come.
    Data { left: usize },
    /// The CR, then the LF, after a chunk's data.
    DataCr,
    DataLf,
    /// The CR, then the LF, after the zero chunk (no trailers).
    EndCr,
    EndLf,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Stage {
    Head,
    Length { left: usize },
    Chunked(Chunk),
    Done,
    Refused(Refusal),
}

/// The bounds of one answer: the decoded body and the raw chunked body (`None`: unbounded, a watch stream).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub body: Option<usize>,
    pub raw: Option<usize>,
}

impl Bounds {
    /// A complete answer of at most `body` decoded bytes, chunked raw at most `body` + 64 KiB.
    pub fn answer(body: usize) -> Bounds {
        Bounds { body: Some(body), raw: Some(body.saturating_add(RAW_SLACK)) }
    }

    /// The `/metrics` answer: at most 64 MiB, decoded and raw.
    pub fn exposition() -> Bounds {
        Bounds { body: Some(METRICS_RAW_LIMIT), raw: Some(METRICS_RAW_LIMIT) }
    }

    /// A watch stream: no total bound (each line is bounded by `watch`).
    pub fn stream() -> Bounds {
        Bounds { body: None, raw: None }
    }

    fn length_digits(&self) -> usize {
        let mut digits = 1usize;
        let mut rest = self.body.unwrap_or(0) / 10;
        while rest > 0 {
            digits = digits.saturating_add(1);
            rest /= 10;
        }
        digits.max(LENGTH_DIGITS)
    }
}

/// The strict, incremental framer of one answer (see the module documentation), fed the decrypted bytes as they
/// arrive; the decoded body bytes are appended to the caller's buffer.
#[derive(Debug)]
pub struct Framer {
    stage: Stage,
    head: Vec<u8>,
    heads: usize,
    interim: usize,
    status: u16,
    content_type: Option<Vec<u8>>,
    decoded: usize,
    raw: usize,
    bounds: Bounds,
}

/// The value of a field line whose name equals `name` (ASCII case-insensitive), with optional whitespace trimmed.
fn field_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    let (field, rest) = (line.get(..colon)?, line.get(colon.checked_add(1)?..)?);
    if !field.eq_ignore_ascii_case(name) {
        return None;
    }
    Some(rest.trim_ascii())
}

/// A token character (RFC 9110 section 5.6.2).
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// A field line: a non-empty token name, a colon, then visible bytes, obs-text, spaces and tabs only.
fn field_line_ok(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else { return false };
    let (Some(name), Some(value)) = (line.get(..colon), colon.checked_add(1).and_then(|start| line.get(start..))) else {
        return false;
    };
    colon > 0
        && name.iter().all(|byte| is_tchar(*byte))
        && value.iter().all(|byte| *byte == b'\t' || *byte == b' ' || (0x21..=0x7E).contains(byte) || *byte >= 0x80)
}

/// The status of `HTTP/1.1 SP 3DIGIT SP reason`, the reason holding tabs, spaces, visible bytes and obs-text only.
fn status_line(line: &[u8]) -> Option<u16> {
    let rest = line.strip_prefix(b"HTTP/1.1 ")?;
    let (digits, reason) = (rest.get(..3)?, rest.get(3..)?);
    let reason = reason.strip_prefix(b" ")?;
    if !digits.iter().all(u8::is_ascii_digit)
        || !reason.iter().all(|byte| *byte == b'\t' || *byte == b' ' || (0x21..=0x7E).contains(byte) || *byte >= 0x80)
    {
        return None;
    }
    let status = digits.iter().fold(0u16, |value, digit| value * 10 + u16::from(digit - b'0'));
    (100..=599).contains(&status).then_some(status)
}

impl Framer {
    pub fn new(bounds: Bounds) -> Framer {
        Framer { stage: Stage::Head, head: Vec::new(), heads: 0, interim: 0, status: 0, content_type: None, decoded: 0,
                 raw: 0, bounds }
    }

    /// The progress so far, without new bytes.
    pub fn progress(&self) -> Progress {
        match self.stage {
            Stage::Done => Progress::Complete,
            Stage::Refused(refusal) => Progress::Refused(refusal),
            _ => Progress::NeedMore,
        }
    }

    /// The final answer's status once its head is complete (`None` before, or once refused).
    pub fn status(&self) -> Option<u16> {
        match self.stage {
            Stage::Head | Stage::Refused(_) => None,
            _ => Some(self.status),
        }
    }

    /// The final head's `Content-Type` value (the last one, if repeated), once the head is complete.
    pub fn content_type(&self) -> Option<&[u8]> {
        self.status().and(self.content_type.as_deref())
    }

    fn refuse(&mut self, refusal: Refusal) -> Progress {
        self.stage = Stage::Refused(refusal);
        self.head = Vec::new();
        Progress::Refused(refusal)
    }

    /// Feeds the next bytes, appending decoded body bytes to `out`: after a complete answer any byte is surplus; after
    /// a refusal nothing changes.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<u8>) -> Progress {
        let mut at = 0usize;
        while let Some(rest) = bytes.get(at..).filter(|rest| !rest.is_empty()) {
            match self.stage {
                Stage::Refused(refusal) => return Progress::Refused(refusal),
                Stage::Done => return self.refuse(Refusal::Surplus),
                Stage::Head => {
                    let byte = rest.first().copied().unwrap_or(0);
                    at = at.saturating_add(1);
                    self.head.push(byte);
                    if self.heads.saturating_add(self.head.len()) > HEAD_LIMIT {
                        return self.refuse(Refusal::HeadSize);
                    }
                    if self.head.ends_with(b"\r\n\r\n") {
                        if let Err(refusal) = self.end_of_head() {
                            return self.refuse(refusal);
                        }
                    }
                }
                Stage::Length { left } => {
                    let take = left.min(rest.len());
                    out.extend_from_slice(rest.get(..take).unwrap_or(&[]));
                    self.decoded = self.decoded.saturating_add(take);
                    at = at.saturating_add(take);
                    self.stage = if left == take { Stage::Done } else { Stage::Length { left: left - take } };
                }
                Stage::Chunked(chunk) => {
                    let taken = match self.chunked(chunk, rest, out) {
                        Ok(taken) => taken,
                        Err(refusal) => return self.refuse(refusal),
                    };
                    self.raw = self.raw.saturating_add(taken);
                    at = at.saturating_add(taken);
                    if self.bounds.raw.is_some_and(|bound| self.raw > bound) {
                        return self.refuse(Refusal::Size);
                    }
                }
            }
        }
        self.progress()
    }

    /// One step of the chunked decoder over `bytes` (never empty): how many bytes it took.
    fn chunked(&mut self, chunk: Chunk, bytes: &[u8], out: &mut Vec<u8>) -> Result<usize, Refusal> {
        let byte = bytes.first().copied().ok_or(Refusal::Chunk)?;
        let next = match chunk {
            Chunk::Size { digits, value } => match byte {
                b'\r' if digits > 0 => Chunk::SizeLf { size: value },
                _ if byte.is_ascii_hexdigit() && digits < CHUNK_SIZE_DIGITS => {
                    let digit = char::from(byte).to_digit(16).unwrap_or(0) as usize;
                    Chunk::Size { digits: digits + 1, value: value * 16 + digit }
                }
                _ => return Err(Refusal::Chunk),
            },
            Chunk::SizeLf { size } if byte == b'\n' => {
                if size == 0 {
                    Chunk::EndCr
                } else if self.bounds.body.is_some_and(|bound| self.decoded.saturating_add(size) > bound) {
                    return Err(Refusal::Size);
                } else {
                    Chunk::Data { left: size }
                }
            }
            Chunk::Data { left } => {
                let take = left.min(bytes.len());
                out.extend_from_slice(bytes.get(..take).unwrap_or(&[]));
                self.decoded = self.decoded.saturating_add(take);
                self.stage = Stage::Chunked(if left == take { Chunk::DataCr } else { Chunk::Data { left: left - take } });
                return Ok(take);
            }
            Chunk::DataCr if byte == b'\r' => Chunk::DataLf,
            Chunk::DataLf if byte == b'\n' => Chunk::Size { digits: 0, value: 0 },
            Chunk::EndCr if byte == b'\r' => Chunk::EndLf,
            Chunk::EndLf if byte == b'\n' => {
                self.stage = Stage::Done;
                return Ok(1);
            }
            _ => return Err(Refusal::Chunk),
        };
        self.stage = Stage::Chunked(next);
        Ok(1)
    }

    /// A head ended (its CRLF CRLF just arrived): an interim answer is skipped, a final one picks the body's framing.
    fn end_of_head(&mut self) -> Result<(), Refusal> {
        let head = std::mem::take(&mut self.head);
        self.heads = self.heads.saturating_add(head.len());
        // The lines between the status line and the empty line; any other CR or LF is a bare one.
        let text = head.get(..head.len().saturating_sub(4)).unwrap_or(&[]);
        let mut status = None;
        let mut fields: Vec<&[u8]> = Vec::new();
        let count = text.iter().filter(|byte| **byte == b'\n').count() + 1;
        for (index, line) in text.split(|byte| *byte == b'\n').enumerate() {
            let line = if index + 1 < count { line.strip_suffix(b"\r").ok_or(Refusal::Field)? } else { line };
            if line.contains(&b'\r') {
                return Err(Refusal::Field);
            }
            if index == 0 {
                status = Some(status_line(line).ok_or(Refusal::StatusLine)?);
            } else if field_line_ok(line) {
                fields.push(line);
            } else {
                return Err(Refusal::Field);
            }
        }
        let status = status.ok_or(Refusal::StatusLine)?;
        match status {
            100 | 102 | 103 => {
                self.interim += 1;
                return if self.interim > INTERIM_LIMIT { Err(Refusal::Interim) } else { Ok(()) };
            }
            101..=199 => return Err(Refusal::Interim),
            _ => {}
        }
        self.status = status;
        let digits = self.bounds.length_digits();
        let mut length: Option<usize> = None;
        let mut chunked = false;
        for line in &fields {
            if let Some(value) = field_value(line, b"content-length") {
                if length.is_some() || value.is_empty() || value.len() > digits || !value.iter().all(u8::is_ascii_digit) {
                    return Err(Refusal::Length);
                }
                let parsed = value.iter().fold(0usize, |total, digit| total.saturating_mul(10).saturating_add(usize::from(digit - b'0')));
                if self.bounds.body.is_some_and(|bound| parsed > bound) {
                    return Err(Refusal::Length);
                }
                length = Some(parsed);
            } else if let Some(value) = field_value(line, b"transfer-encoding") {
                if chunked {
                    return Err(Refusal::Length);
                }
                if !value.eq_ignore_ascii_case(b"chunked") {
                    return Err(Refusal::Coding);
                }
                chunked = true;
            } else if let Some(value) = field_value(line, b"content-encoding") {
                if !value.eq_ignore_ascii_case(b"identity") {
                    return Err(Refusal::Coding);
                }
            } else if let Some(value) = field_value(line, b"content-type") {
                self.content_type = Some(value.to_vec());
            }
        }
        if chunked && length.is_some() {
            return Err(Refusal::Length);
        }
        self.stage = match (status, length, chunked) {
            (204 | 304, Some(0) | None, false) => Stage::Done,
            (204 | 304, _, _) => return Err(Refusal::Body),
            (_, Some(0), false) => Stage::Done,
            (_, Some(left), false) => Stage::Length { left },
            (_, None, true) => Stage::Chunked(Chunk::Size { digits: 0, value: 0 }),
            _ => return Err(Refusal::Body),
        };
        Ok(())
    }
}

/// A complete answer: its status, its `Content-Type` value and its decoded body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub content_type: Option<Vec<u8>>,
    pub body: Vec<u8>,
}

/// The reader of one complete answer: the framer collecting the decoded body.
#[derive(Debug)]
pub struct AnswerReader {
    framer: Framer,
    body: Vec<u8>,
}

impl AnswerReader {
    /// A reader whose decoded body is at most `body` bytes (chunked raw at most `body` + 64 KiB).
    pub fn new(body: usize) -> AnswerReader {
        AnswerReader { framer: Framer::new(Bounds::answer(body)), body: Vec::new() }
    }

    pub fn progress(&self) -> Progress {
        self.framer.progress()
    }

    /// Feeds the next bytes.
    pub fn push(&mut self, bytes: &[u8]) -> Progress {
        let progress = self.framer.push(bytes, &mut self.body);
        if let Progress::Refused(_) = progress {
            self.body = Vec::new();
        }
        progress
    }

    /// The complete answer (`None` before it is complete, or once refused).
    pub fn answer(self) -> Option<Answer> {
        if self.framer.progress() != Progress::Complete {
            return None;
        }
        let content_type = self.framer.content_type().map(<[u8]>::to_vec);
        Some(Answer { status: self.framer.status, content_type, body: self.body })
    }
}

/// The streaming reader of one answer: each push hands back the decoded bytes it produced.
#[derive(Debug)]
pub struct StreamReader {
    framer: Framer,
}

impl StreamReader {
    pub fn new(bounds: Bounds) -> StreamReader {
        StreamReader { framer: Framer::new(bounds) }
    }

    pub fn progress(&self) -> Progress {
        self.framer.progress()
    }

    /// The final status once the head is complete.
    pub fn status(&self) -> Option<u16> {
        self.framer.status()
    }

    /// The final head's `Content-Type` value once the head is complete.
    pub fn content_type(&self) -> Option<&[u8]> {
        self.framer.content_type()
    }

    /// Feeds the next bytes; the decoded body bytes among them are appended to `out`.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<u8>) -> Progress {
        self.framer.push(bytes, out)
    }
}
