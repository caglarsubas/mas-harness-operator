//! HTTP/1.1 on I04 (HE-003B DESIGN §6; MODEL_DEFINED R48, R49, R52): request framing, which only finds the request's
//! end (the model compares the exact head and the body digest), and response rendering, the only bytes the gate ever
//! writes as HTTP.

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
