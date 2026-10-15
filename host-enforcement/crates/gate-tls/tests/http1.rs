//! HE-003B: HTTP/1.1 framing and rendering (DESIGN §6.1, §6.2, §9; MODEL_DEFINED R48, R49, R52): every framing rule
//! (the head at 16,383, 16,384 and 16,385 bytes, each length-line case, `Content-Length: 0`, chunked, a lowercase name,
//! a duplicate, a leading zero, 16,385, a non-UTF-8 head, surplus, a second request) and the counting boundary of
//! Q-HE3B-25; `render_response`'s reason table, 204 and 304, an empty reason, the size bound and 1xx.

use gate_tls::{frame, render_response, Frame, RenderRefusal, BODY_LIMIT, HEAD_LIMIT, RESPONSE_BODY_LIMIT};
use i05_protocol::sha256;

const GET: &str = "GET /api/v1/namespaces/planeon-qual/pods/probe-pod HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                   Accept: application/json\r\n\r\n";

fn post(length_line: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("POST /api/v1/namespaces/planeon-qual/pods HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\
                             Accept: application/json\r\nContent-Type: application/json\r\nX-Probe: 1\r\n{length_line}\r\n")
        .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// A head of exactly `size` bytes (CRLF CRLF included), without a length line.
fn head_of(size: usize) -> Vec<u8> {
    let fixed = "GET / HTTP/1.1\r\nX-Pad: \r\n\r\n".len();
    format!("GET / HTTP/1.1\r\nX-Pad: {}\r\n\r\n", "a".repeat(size - fixed)).into_bytes()
}

fn request(head: &[u8], body: &[u8], digest: Option<String>) -> Frame {
    Frame::Request { head: String::from_utf8_lossy(head).into_owned(), body: body.to_vec(), body_digest: digest }
}

#[test]
fn a_get_has_no_body_and_no_digest() {
    assert_eq!(frame(GET.as_bytes()), request(GET.as_bytes(), b"", None));
    assert_eq!(frame(&GET.as_bytes()[..GET.len() - 1]), Frame::NeedMore);
}

#[test]
fn the_head_limit_is_16384_bytes_with_its_crlf_crlf() {
    for size in [HEAD_LIMIT - 1, HEAD_LIMIT] {
        let head = head_of(size);
        assert_eq!(head.len(), size);
        assert_eq!(frame(&head), request(&head, b"", None), "{size}");
    }
    let over = head_of(HEAD_LIMIT + 1);
    assert_eq!(frame(&over[..HEAD_LIMIT - 1]), Frame::NeedMore);
    assert_eq!(frame(&over), Frame::OversizeHead);
    assert_eq!(frame(&over[..HEAD_LIMIT]), Frame::OversizeHead, "16,384 buffered bytes without the end of a head");
}

#[test]
fn one_canonical_content_length_frames_the_body() {
    let body = b"{\"kind\":\"Pod\"}";
    let bytes = post(&format!("Content-Length: {}\r\n", body.len()), body);
    let head = &bytes[..bytes.len() - body.len()];
    assert_eq!(frame(&bytes), request(head, body, Some(sha256::prefixed(body))));
    assert_eq!(frame(&bytes[..bytes.len() - 1]), Frame::NeedMore, "a body cut short waits (a Disconnect at the deadline)");
    let zero = post("Content-Length: 0\r\n", b"");
    assert_eq!(frame(&zero), request(&zero, b"", Some(sha256::prefixed(b""))), "Some also for 0");
    let largest = vec![b'x'; BODY_LIMIT];
    let bytes = post(&format!("Content-Length: {BODY_LIMIT}\r\n"), &largest);
    assert!(matches!(frame(&bytes), Frame::Request { body_digest: Some(_), .. }));
}

#[test]
fn every_other_length_line_makes_the_head_unframeable() {
    for line in ["Content-Length: 016\r\n", "Content-Length: 16385\r\n", "content-length: 5\r\n", "Content-length: 5\r\n",
                 "Content-Length:5\r\n", "Content-Length:  5\r\n", "Content-Length: 5 \r\n", "Content-Length: +5\r\n",
                 "Content-Length: 5\r\nContent-Length: 5\r\n", "Transfer-Encoding: chunked\r\n",
                 "Content-Length: 5\r\nTransfer-Encoding: identity\r\n", "Content-Length-X: 5\r\n",
                 "Content-Length: 123456\r\n", "Content-Length: \r\n"] {
        let bytes = post(line, b"hello");
        let head_end = bytes.windows(4).position(|four| four == b"\r\n\r\n").expect("a head") + 4;
        assert_eq!(frame(&bytes), request(&bytes[..head_end], b"", None), "{line:?}: fed at once, without a digest");
    }
}

#[test]
fn a_non_utf8_head_is_fed_lossily() {
    let mut bytes = b"GET /\xff HTTP/1.1\r\nHost: 198.51.100.7:6443\r\n\r\n".to_vec();
    let Frame::Request { head, body_digest, .. } = frame(&bytes) else { panic!("a request") };
    assert!(head.contains('\u{fffd}') && body_digest.is_none());
    bytes.push(b'x');
    assert!(matches!(frame(&bytes), Frame::Request { .. }));
}

#[test]
fn surplus_bytes_and_a_second_request_are_never_parsed() {
    let mut bytes = GET.as_bytes().to_vec();
    bytes.extend_from_slice(GET.as_bytes());
    bytes.extend_from_slice(b"garbage");
    assert_eq!(frame(&bytes), request(GET.as_bytes(), b"", None), "one request, its own bytes only");
    let body = b"12345";
    let mut posted = post("Content-Length: 5\r\n", body);
    posted.extend_from_slice(b"surplus");
    let head_end = posted.len() - body.len() - b"surplus".len();
    assert_eq!(frame(&posted), request(&posted[..head_end], body, Some(sha256::prefixed(body))));
}

#[test]
fn every_reason_of_the_table_and_the_rendered_shape() {
    let table = [(200, "OK"), (201, "Created"), (202, "Accepted"), (203, "Non-Authoritative Information"),
                 (205, "Reset Content"), (206, "Partial Content"), (300, "Multiple Choices"), (301, "Moved Permanently"),
                 (302, "Found"), (303, "See Other"), (305, "Use Proxy"), (307, "Temporary Redirect"),
                 (308, "Permanent Redirect"), (400, "Bad Request"), (401, "Unauthorized"), (402, "Payment Required"),
                 (403, "Forbidden"), (404, "Not Found"), (405, "Method Not Allowed"), (406, "Not Acceptable"),
                 (407, "Proxy Authentication Required"), (408, "Request Timeout"), (409, "Conflict"), (410, "Gone"),
                 (411, "Length Required"), (412, "Precondition Failed"), (413, "Content Too Large"),
                 (414, "URI Too Long"), (415, "Unsupported Media Type"), (416, "Range Not Satisfiable"),
                 (417, "Expectation Failed"), (421, "Misdirected Request"), (422, "Unprocessable Content"),
                 (426, "Upgrade Required"), (500, "Internal Server Error"), (501, "Not Implemented"),
                 (502, "Bad Gateway"), (503, "Service Unavailable"), (504, "Gateway Timeout"),
                 (505, "HTTP Version Not Supported")];
    for (status, reason) in table {
        let rendered = render_response(status, b"{}").expect("rendered");
        let expected = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\
                                Connection: close\r\n\r\n{{}}");
        assert_eq!(String::from_utf8(rendered).expect("ASCII"), expected);
    }
    assert_eq!(render_response(299, b"").expect("rendered")[..15].to_vec(), b"HTTP/1.1 299 \r\n".to_vec(), "empty reason");
    assert!(String::from_utf8(render_response(429, b"").expect("rendered")).expect("ASCII").starts_with("HTTP/1.1 429 \r\n"));
}

#[test]
fn no_content_and_not_modified_carry_no_length_and_no_body() {
    for (status, reason) in [(204, "No Content"), (304, "Not Modified")] {
        let rendered = String::from_utf8(render_response(status, b"").expect("rendered")).expect("ASCII");
        assert_eq!(rendered, format!("HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"));
        assert_eq!(render_response(status, b"x"), Err(RenderRefusal::Body));
    }
}

#[test]
fn the_status_and_size_bounds_refuse() {
    for status in [100, 101, 103, 199, 600, 0, 999] {
        assert_eq!(render_response(status, b""), Err(RenderRefusal::Status), "{status}");
    }
    let largest = vec![b'a'; RESPONSE_BODY_LIMIT];
    let rendered = render_response(200, &largest).expect("4,194,304 bytes are relayed");
    assert!(rendered.ends_with(&largest));
    assert_eq!(render_response(200, &vec![b'a'; RESPONSE_BODY_LIMIT + 1]), Err(RenderRefusal::Size));
}
