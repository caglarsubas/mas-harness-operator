//! HTTP/1.1 on I04 (HE-003B DESIGN §6; MODEL_DEFINED R48, R49, R52): request framing, which only finds the request's
//! end (the model compares the exact head and the body digest), and response rendering, the only bytes the gate ever
//! writes as HTTP. HE-003C (DESIGN §4; MODEL_DEFINED R63) adds the client side: the strict, incremental reading of
//! the apiserver's answer on the upstream leg ([`ResponseReader`]).

use i05_protocol::sha256;

/// The longest head, CRLF CRLF included.
pub const HEAD_LIMIT: usize = 16_384;
/// The longest request body.
pub const BODY_LIMIT: usize = 16_384;
/// The longest response body (MET-REPAIR-009 :162).
pub const RESPONSE_BODY_LIMIT: usize = 4_194_304;

/// What the bytes received so far hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// No complete request yet.
    NeedMore,
    /// 16,384 bytes without the end of a head: no head, so no request (a `Disconnect`).
    OversizeHead,
    /// A complete request, or a complete head that can never be framed (fed at once without a body digest).
    Request { head: String, body: Vec<u8>, body_digest: Option<String> },
}

/// The body length a head's length lines give: `None` without a length line, `Some(n)` for one canonical
/// `Content-Length`, and `Err(())` for a head that can never be framed.
fn body_length(head: &[u8]) -> Result<Option<usize>, ()> {
    let mut found = Vec::new();
    for line in head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(b"content-length") || lower.starts_with(b"transfer-encoding") {
            found.push(line);
        }
    }
    match found.as_slice() {
        [] => Ok(None),
        [line] => {
            let digits = line.strip_prefix(b"Content-Length: ").ok_or(())?;
            let canonical = !digits.is_empty()
                && digits.len() <= 5
                && digits.iter().all(u8::is_ascii_digit)
                && (digits.len() == 1 || digits[0] != b'0');
            if !canonical {
                return Err(());
            }
            let value = digits.iter().fold(0usize, |value, digit| value * 10 + usize::from(digit - b'0'));
            if value > BODY_LIMIT { Err(()) } else { Ok(Some(value)) }
        }
        _ => Err(()),
    }
}

/// Frames the plaintext received so far (DESIGN §6.1): the head is the bytes through the first CRLF CRLF, at most
/// 16,384; the body is exactly one canonical `Content-Length` (at most 16,384) of bytes, or none without a length line.
/// A head with any other length or Transfer-Encoding line is unframeable and complete as it stands. A head that is not
/// UTF-8 is converted lossily, so it can never equal a rendering. Bytes after the request's end are never looked at.
pub fn frame(received: &[u8]) -> Frame {
    let window = &received[..received.len().min(HEAD_LIMIT)];
    let Some(end) = window.windows(4).position(|four| four == b"\r\n\r\n").map(|position| position + 4) else {
        return if received.len() >= HEAD_LIMIT { Frame::OversizeHead } else { Frame::NeedMore };
    };
    let head_bytes = &received[..end];
    let head = String::from_utf8_lossy(head_bytes).into_owned();
    match body_length(head_bytes) {
        Err(()) => Frame::Request { head, body: Vec::new(), body_digest: None },
        Ok(None) => Frame::Request { head, body: Vec::new(), body_digest: None },
        Ok(Some(length)) => match received.get(end..end + length) {
            Some(body) => Frame::Request { head, body: body.to_vec(), body_digest: Some(sha256::prefixed(body)) },
            None => Frame::NeedMore,
        },
    }
}

/// Why a response was not rendered (the connection then closes without a byte).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RenderRefusal {
    /// Outside 200-599 (1xx included).
    Status,
    /// A body over 4,194,304 bytes.
    Size,
    /// A 204 or 304 with a body.
    Body,
}

/// RFC 9110 §15's registered reason phrases for 2xx to 5xx (a closed table; any other code has an empty reason).
fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        426 => "Upgrade Required",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// The response the I04 client receives (DESIGN §6.2): a status line with the registered reason (or an empty one),
/// a fixed media type, one canonical `Content-Length` (none for 204 and 304, which need an empty body),
/// `Connection: close`, then the body unchanged. No upstream header is relayed.
pub fn render_response(status: u16, body: &[u8]) -> Result<Vec<u8>, RenderRefusal> {
    if !(200..=599).contains(&status) {
        return Err(RenderRefusal::Status);
    }
    if body.len() > RESPONSE_BODY_LIMIT {
        return Err(RenderRefusal::Size);
    }
    let no_length = status == 204 || status == 304;
    if no_length && !body.is_empty() {
        return Err(RenderRefusal::Body);
    }
    let mut head = format!("HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\n", reason(status));
    if !no_length {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

// ------------------------------------------------------------------------------------------ the upstream answer (HE-003C)

/// The interim answers (100, 102, 103) skipped before the final one, at most.
pub const INTERIM_LIMIT: usize = 4;
/// The raw bytes of a chunked body, framing included: the decoded limit plus 64 KiB.
pub const CHUNKED_RAW_LIMIT: usize = RESPONSE_BODY_LIMIT + 64 * 1024;
/// The hex digits of one chunk size, at most.
const CHUNK_SIZE_DIGITS: usize = 7;
/// The decimal digits of a `Content-Length`, at most.
const LENGTH_DIGITS: usize = 7;

/// Why an upstream answer is refused (the exchange ends LOST).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseRefusal {
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
    /// The decoded body over 4 MiB, or the raw chunked body over 4 MiB plus 64 KiB.
    Size,
    /// Bytes after the complete answer.
    Surplus,
}

/// What the answer received so far holds.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseProgress {
    NeedMore,
    /// The final answer is complete; [`ResponseReader::answer`] gives it.
    Complete,
    Refused(ResponseRefusal),
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
    Refused(ResponseRefusal),
}

/// The strict, incremental reader of one upstream answer (HE-003C DESIGN §4), fed the decrypted bytes as they arrive:
///
/// - the status line exactly `HTTP/1.1 SP 3DIGIT SP reason CRLF`, status 100-599; 100, 102 and 103 are skipped (at most
///   four), 101 and 104-199 refused; all heads together at most 16,384 bytes;
/// - field names case-insensitive; one `Content-Length` of 1-7 digits at most 4 MiB, or one `Transfer-Encoding:
///   chunked`, never both; `Content-Encoding` only `identity`; 204 and 304 have no body, every other status needs a
///   length or `chunked` (no body delimited by the close);
/// - chunked strictly: sizes of 1-7 hex digits without extensions, CRLF after each chunk, the zero chunk then CRLF (no
///   trailers), at most 4 MiB decoded and 4 MiB plus 64 KiB raw;
/// - any byte after the complete answer is surplus (refused).
///
/// Nothing is buffered beyond one head and the decoded body.
#[derive(Debug)]
pub struct ResponseReader {
    stage: Stage,
    head: Vec<u8>,
    heads: usize,
    interim: usize,
    status: u16,
    body: Vec<u8>,
    raw: usize,
}

impl Default for ResponseReader {
    fn default() -> ResponseReader {
        ResponseReader::new()
    }
}

/// The value of a field line whose name equals `name` (ASCII case-insensitive), with optional whitespace trimmed.
fn field_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    if !line[..colon].eq_ignore_ascii_case(name) {
        return None;
    }
    Some(line[colon + 1..].trim_ascii())
}

/// A token character (RFC 9110 §5.6.2).
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// A field line: a non-empty token name, a colon, then visible bytes, obs-text, spaces and tabs only.
fn field_line_ok(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else { return false };
    colon > 0
        && line[..colon].iter().all(|byte| is_tchar(*byte))
        && line[colon + 1..].iter().all(|byte| *byte == b'\t' || *byte == b' ' || (0x21..=0x7E).contains(byte) || *byte >= 0x80)
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

impl ResponseReader {
    pub fn new() -> ResponseReader {
        ResponseReader { stage: Stage::Head, head: Vec::new(), heads: 0, interim: 0, status: 0, body: Vec::new(), raw: 0 }
    }

    /// The progress so far, without new bytes.
    pub fn progress(&self) -> ResponseProgress {
        match self.stage {
            Stage::Done => ResponseProgress::Complete,
            Stage::Refused(refusal) => ResponseProgress::Refused(refusal),
            _ => ResponseProgress::NeedMore,
        }
    }

    /// The complete answer's status and decoded body (`None` before it is complete, or once refused).
    pub fn answer(self) -> Option<(u16, Vec<u8>)> {
        (self.stage == Stage::Done).then_some((self.status, self.body))
    }

    fn refuse(&mut self, refusal: ResponseRefusal) -> ResponseProgress {
        self.stage = Stage::Refused(refusal);
        self.body = Vec::new();
        self.head = Vec::new();
        ResponseProgress::Refused(refusal)
    }

    /// Feeds the next bytes: after a complete answer any byte is surplus; after a refusal nothing changes.
    pub fn push(&mut self, bytes: &[u8]) -> ResponseProgress {
        let mut at = 0;
        while at < bytes.len() {
            match self.stage {
                Stage::Refused(refusal) => return ResponseProgress::Refused(refusal),
                Stage::Done => return self.refuse(ResponseRefusal::Surplus),
                Stage::Head => {
                    let byte = bytes[at];
                    at += 1;
                    self.head.push(byte);
                    if self.heads + self.head.len() > HEAD_LIMIT {
                        return self.refuse(ResponseRefusal::HeadSize);
                    }
                    if self.head.ends_with(b"\r\n\r\n") {
                        if let Err(refusal) = self.end_of_head() {
                            return self.refuse(refusal);
                        }
                    }
                }
                Stage::Length { left } => {
                    let take = left.min(bytes.len() - at);
                    self.body.extend_from_slice(&bytes[at..at + take]);
                    at += take;
                    self.stage = if left == take { Stage::Done } else { Stage::Length { left: left - take } };
                }
                Stage::Chunked(chunk) => {
                    let taken = match self.chunked(chunk, &bytes[at..]) {
                        Ok(taken) => taken,
                        Err(refusal) => return self.refuse(refusal),
                    };
                    self.raw = self.raw.saturating_add(taken);
                    at += taken;
                    if self.raw > CHUNKED_RAW_LIMIT {
                        return self.refuse(ResponseRefusal::Size);
                    }
                }
            }
        }
        self.progress()
    }

    /// One step of the chunked decoder over `bytes` (never empty): how many bytes it took.
    fn chunked(&mut self, chunk: Chunk, bytes: &[u8]) -> Result<usize, ResponseRefusal> {
        let byte = bytes[0];
        let next = match chunk {
            Chunk::Size { digits, value } => match byte {
                b'\r' if digits > 0 => Chunk::SizeLf { size: value },
                _ if byte.is_ascii_hexdigit() && digits < CHUNK_SIZE_DIGITS => {
                    let digit = char::from(byte).to_digit(16).unwrap_or(0) as usize;
                    Chunk::Size { digits: digits + 1, value: value * 16 + digit }
                }
                _ => return Err(ResponseRefusal::Chunk),
            },
            Chunk::SizeLf { size } if byte == b'\n' => {
                if size == 0 {
                    Chunk::EndCr
                } else if self.body.len().saturating_add(size) > RESPONSE_BODY_LIMIT {
                    return Err(ResponseRefusal::Size);
                } else {
                    Chunk::Data { left: size }
                }
            }
            Chunk::Data { left } => {
                let take = left.min(bytes.len());
                self.body.extend_from_slice(&bytes[..take]);
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
            _ => return Err(ResponseRefusal::Chunk),
        };
        self.stage = Stage::Chunked(next);
        Ok(1)
    }

    /// A head ended (its CRLF CRLF just arrived): an interim answer is skipped, a final one picks the body's framing.
    fn end_of_head(&mut self) -> Result<(), ResponseRefusal> {
        let head = std::mem::take(&mut self.head);
        self.heads += head.len();
        // The lines between the status line and the empty line; any other CR or LF is a bare one.
        let text = &head[..head.len().saturating_sub(4)];
        let mut status = None;
        let mut fields: Vec<&[u8]> = Vec::new();
        let count = text.iter().filter(|byte| **byte == b'\n').count() + 1;
        for (index, line) in text.split(|byte| *byte == b'\n').enumerate() {
            let line = if index + 1 < count { line.strip_suffix(b"\r").ok_or(ResponseRefusal::Field)? } else { line };
            if line.contains(&b'\r') {
                return Err(ResponseRefusal::Field);
            }
            if index == 0 {
                status = Some(status_line(line).ok_or(ResponseRefusal::StatusLine)?);
            } else if field_line_ok(line) {
                fields.push(line);
            } else {
                return Err(ResponseRefusal::Field);
            }
        }
        let status = status.ok_or(ResponseRefusal::StatusLine)?;
        match status {
            100 | 102 | 103 => {
                self.interim += 1;
                return if self.interim > INTERIM_LIMIT { Err(ResponseRefusal::Interim) } else { Ok(()) };
            }
            101..=199 => return Err(ResponseRefusal::Interim),
            _ => {}
        }
        self.status = status;
        let mut length: Option<usize> = None;
        let mut chunked = false;
        for line in &fields {
            if let Some(value) = field_value(line, b"content-length") {
                if length.is_some() || value.is_empty() || value.len() > LENGTH_DIGITS || !value.iter().all(u8::is_ascii_digit) {
                    return Err(ResponseRefusal::Length);
                }
                let parsed = value.iter().fold(0usize, |total, digit| total * 10 + usize::from(digit - b'0'));
                if parsed > RESPONSE_BODY_LIMIT {
                    return Err(ResponseRefusal::Length);
                }
                length = Some(parsed);
            } else if let Some(value) = field_value(line, b"transfer-encoding") {
                if chunked {
                    return Err(ResponseRefusal::Length);
                }
                if !value.eq_ignore_ascii_case(b"chunked") {
                    return Err(ResponseRefusal::Coding);
                }
                chunked = true;
            } else if let Some(value) = field_value(line, b"content-encoding") {
                if !value.eq_ignore_ascii_case(b"identity") {
                    return Err(ResponseRefusal::Coding);
                }
            }
        }
        if chunked && length.is_some() {
            return Err(ResponseRefusal::Length);
        }
        self.stage = match (status, length, chunked) {
            (204 | 304, Some(0) | None, false) => Stage::Done,
            (204 | 304, _, _) => return Err(ResponseRefusal::Body),
            (_, Some(0), false) => Stage::Done,
            (_, Some(left), false) => Stage::Length { left },
            (_, None, true) => Stage::Chunked(Chunk::Size { digits: 0, value: 0 }),
            _ => return Err(ResponseRefusal::Body),
        };
        Ok(())
    }
}
