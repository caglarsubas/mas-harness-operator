//! HE-003C: the upstream answer's framing (DESIGN §4; MODEL_DEFINED R63), on `http1::ResponseReader` directly and
//! through the port with the scripted apiserver: Content-Length and chunked answers (whole and byte by byte), interim
//! answers skipped, 101 and 104-199 refused, an interim flood, the head limit, oversize lengths and bodies, both
//! framing headers, duplicates, codings, an overlong chunk size and the chunk grammar, one-byte chunks at the raw cap,
//! 204 and 304, the status line and field-line forms, and surplus bytes.

mod tls_support;
mod upstream_support;

use effect_gate::{Event, PolicyEvent, UpstreamOutcome};
use gate_tls::{ResponseProgress, ResponseReader, ResponseRefusal, CHUNKED_RAW_LIMIT, HEAD_LIMIT, INTERIM_LIMIT,
               RESPONSE_BODY_LIMIT};
use i05_protocol::{sha256, Kind, Verb};

use upstream_support::*;

fn read(bytes: &[u8]) -> (ResponseProgress, Option<(u16, Vec<u8>)>) {
    let mut reader = ResponseReader::new();
    let progress = reader.push(bytes);
    (progress, reader.answer())
}

/// The same bytes one at a time: the result must not depend on the segmentation (surplus aside).
fn read_bytewise(bytes: &[u8]) -> (ResponseProgress, Option<(u16, Vec<u8>)>) {
    let mut reader = ResponseReader::new();
    let mut progress = reader.progress();
    for byte in bytes {
        progress = reader.push(std::slice::from_ref(byte));
    }
    (progress, reader.answer())
}

fn complete(bytes: &[u8]) -> (u16, Vec<u8>) {
    let (progress, answer) = read(bytes);
    assert_eq!(progress, ResponseProgress::Complete, "{}", String::from_utf8_lossy(bytes));
    assert_eq!(read_bytewise(bytes), (ResponseProgress::Complete, answer.clone()));
    answer.expect("an answer")
}

fn refused(bytes: &[u8], refusal: ResponseRefusal) {
    let (progress, answer) = read(bytes);
    assert_eq!(progress, ResponseProgress::Refused(refusal), "{}", String::from_utf8_lossy(&bytes[..bytes.len().min(200)]));
    assert_eq!(answer, None);
}

#[test]
fn content_length_and_chunked_answers_are_read_whole_and_byte_by_byte() {
    assert_eq!(complete(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"),
               (200, b"{}".to_vec()));
    assert_eq!(complete(b"HTTP/1.1 201 Created\r\ncontent-LENGTH:   0002 \r\n\r\nab"), (201, b"ab".to_vec()));
    assert_eq!(complete(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"), (404, Vec::new()));
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\nA\r\n, 0123456 \r\n0\r\n\r\n";
    assert_eq!(complete(chunked), (200, b"hello, 0123456 ".to_vec()));
    assert_eq!(complete(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0000000\r\n\r\n"), (200, Vec::new()));
    // Not complete until the last byte.
    let (progress, _) = read(&chunked[..chunked.len() - 1]);
    assert_eq!(progress, ResponseProgress::NeedMore);
    // Content-Encoding identity is allowed; the reason may be empty or hold spaces, tabs and obs-text.
    complete(b"HTTP/1.1 200 \r\nContent-Encoding: IDENTITY\r\nContent-Length: 0\r\n\r\n");
    complete(b"HTTP/1.1 500 Internal\tServer \xe2\x9c\x97\r\nContent-Length: 0\r\n\r\n");
}

#[test]
fn interim_answers_are_skipped_up_to_four_and_101_or_104_to_199_refused() {
    let interim = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n";
    let mut answer = interim.to_vec();
    answer.extend_from_slice(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}");
    assert_eq!(complete(&answer), (201, b"{}".to_vec()));
    let mut flood = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(INTERIM_LIMIT);
    flood.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    complete(&flood);
    refused(&b"HTTP/1.1 100 Continue\r\n\r\n".repeat(INTERIM_LIMIT + 1), ResponseRefusal::Interim);
    for status in ["101 Switching Protocols", "104 Unknown", "150 x", "199 x"] {
        refused(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes(), ResponseRefusal::Interim);
    }
}

#[test]
fn the_heads_together_are_at_most_16_kib() {
    let value = "v".repeat(HEAD_LIMIT);
    refused(format!("HTTP/1.1 200 OK\r\nX-Long: {value}\r\n\r\n").as_bytes(), ResponseRefusal::HeadSize);
    // Interim heads count toward the same budget.
    let interim = format!("HTTP/1.1 103 Early Hints\r\nLink: {}\r\n\r\n", "l".repeat(HEAD_LIMIT / 2));
    let mut answer = interim.repeat(2).into_bytes();
    answer.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    refused(&answer, ResponseRefusal::HeadSize);
    // A head of exactly 16,384 bytes passes.
    let fill = HEAD_LIMIT - "HTTP/1.1 204 No Content\r\nX: \r\n\r\n".len();
    complete(format!("HTTP/1.1 204 No Content\r\nX: {}\r\n\r\n", "f".repeat(fill)).as_bytes());
}

#[test]
fn lengths_codings_and_duplicates_follow_the_strict_rules() {
    refused(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", RESPONSE_BODY_LIMIT + 1).as_bytes(),
            ResponseRefusal::Length);
    refused(b"HTTP/1.1 200 OK\r\nContent-Length: 00000001\r\n\r\nx", ResponseRefusal::Length);
    for value in ["", "+1", "-1", "1 2", "0x10", "1,1"] {
        refused(format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\n").as_bytes(), ResponseRefusal::Length);
    }
    refused(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}", ResponseRefusal::Length);
    refused(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n", ResponseRefusal::Length);
    refused(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n", ResponseRefusal::Length);
    refused(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n", ResponseRefusal::Length);
    for coding in ["gzip", "chunked, gzip", "gzip, chunked", "identity"] {
        refused(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {coding}\r\n\r\n").as_bytes(), ResponseRefusal::Coding);
    }
    for coding in ["gzip", "identity, gzip", "br"] {
        refused(format!("HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                ResponseRefusal::Coding);
    }
    // No framing on a status with a body: no body delimited by the close.
    refused(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}", ResponseRefusal::Body);
}

#[test]
fn bodies_of_204_and_304_are_empty() {
    assert_eq!(complete(b"HTTP/1.1 204 No Content\r\n\r\n"), (204, Vec::new()));
    assert_eq!(complete(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n"), (304, Vec::new()));
    refused(b"HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\n{}", ResponseRefusal::Body);
    refused(b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", ResponseRefusal::Body);
    refused(b"HTTP/1.1 204 No Content\r\n\r\nx", ResponseRefusal::Surplus);
}

#[test]
fn the_chunk_grammar_is_strict() {
    let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    for body in ["10000000\r\n", "5;ext=1\r\nhello\r\n0\r\n\r\n", "5 \r\nhello\r\n0\r\n\r\n", "\r\n", "g\r\n",
                 "5\nhello\r\n0\r\n\r\n", "5\r\nhelloX\r\n", "5\r\nhello\n0\r\n\r\n", "0\r\nTrailer: x\r\n\r\n",
                 "0\r\n\n"] {
        refused(format!("{head}{body}").as_bytes(), ResponseRefusal::Chunk);
    }
    // A chunk past the decoded limit is refused at its size line.
    refused(format!("{head}{:x}\r\n", RESPONSE_BODY_LIMIT + 1).as_bytes(), ResponseRefusal::Size);
    let mut two = format!("{head}{:x}\r\n", RESPONSE_BODY_LIMIT).into_bytes();
    two.extend(std::iter::repeat_n(b'a', RESPONSE_BODY_LIMIT));
    two.extend_from_slice(b"\r\n1\r\n");
    refused(&two, ResponseRefusal::Size);
}

#[test]
fn one_byte_chunks_meet_the_raw_cap() {
    // Each one-byte chunk is six raw bytes ("1\r\nX\r\n"); the raw cap is 4 MiB plus 64 KiB, so a body of one-byte
    // chunks ends far below 4 MiB decoded (the 0.5 KiB chunk assumption that T04 confirms for the apiserver).
    let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    let fits = (CHUNKED_RAW_LIMIT - 5) / 6;
    let mut answer = head.to_vec();
    for _ in 0..fits {
        answer.extend_from_slice(b"1\r\nX\r\n");
    }
    answer.extend_from_slice(b"0\r\n\r\n");
    let mut reader = ResponseReader::new();
    assert_eq!(reader.push(&answer), ResponseProgress::Complete);
    assert_eq!(reader.answer().map(|(_, body)| body.len()), Some(fits));
    let over = CHUNKED_RAW_LIMIT / 6 + 1;
    let mut answer = head.to_vec();
    for _ in 0..over {
        answer.extend_from_slice(b"1\r\nX\r\n");
    }
    let mut reader = ResponseReader::new();
    assert_eq!(reader.push(&answer), ResponseProgress::Refused(ResponseRefusal::Size));
    assert!(over < RESPONSE_BODY_LIMIT);
}

#[test]
fn status_lines_and_field_lines_outside_the_strict_forms_are_refused() {
    for line in ["HTTP/1.0 200 OK", "HTTP/1.1 200", "HTTP/1.1  200 OK", "HTTP/1.1 2000 OK", "HTTP/1.1 099 Low",
                 "HTTP/1.1 600 High", "HTTP/1.1 20x OK", "http/1.1 200 OK", "HTTP/1.1 200 O\x01K", "HTTP/2 200 OK"] {
        refused(format!("{line}\r\nContent-Length: 0\r\n\r\n").as_bytes(), ResponseRefusal::StatusLine);
    }
    for field in [" Folded: x", "Bad Name: x", "Name : x", "NoColon", ": empty", "X: a\x00b", "X: a\x7fb", "X: a\rb"] {
        refused(format!("HTTP/1.1 200 OK\r\n{field}\r\nContent-Length: 0\r\n\r\n").as_bytes(), ResponseRefusal::Field);
    }
    refused(b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n", ResponseRefusal::Field);
    refused(b"HTTP/1.1 200 OK\r\nX: a\nContent-Length: 0\r\n\r\n", ResponseRefusal::Field);
}

#[test]
fn bytes_after_the_complete_answer_are_surplus_and_a_refusal_is_final() {
    refused(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}x", ResponseRefusal::Surplus);
    refused(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}HTTP/1.1 200 OK\r\n\r\n", ResponseRefusal::Surplus);
    refused(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n\r\n", ResponseRefusal::Surplus);
    let mut reader = ResponseReader::new();
    assert_eq!(reader.push(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"), ResponseProgress::Complete);
    assert_eq!(reader.push(b""), ResponseProgress::Complete, "nothing more is not surplus");
    assert_eq!(reader.push(b"x"), ResponseProgress::Refused(ResponseRefusal::Surplus), "a later push");
    assert_eq!(reader.push(b"HTTP/1.1 200 OK\r\n\r\n"), ResponseProgress::Refused(ResponseRefusal::Surplus));
    assert_eq!(reader.answer(), None);
}

// ------------------------------------------------------------------------------------------ through the port

#[test]
fn a_chunked_answer_is_relayed_with_the_digest_of_its_decoded_body() {
    let mut rig = rig();
    let body = br#"{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u-9","resourceVersion":"7"}}"#;
    let mut answer = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for piece in body.chunks(9) {
        answer.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        answer.extend_from_slice(piece);
        answer.extend_from_slice(b"\r\n");
    }
    answer.extend_from_slice(b"0\r\n\r\n");
    let (_, events) = rig.i05_exchange(Verb::Get, Kind::Pod, "probe-pod", &answer);
    match &events[..] {
        [PolicyEvent::Base(Event::UpstreamResponse { conn, response })] => {
            assert_eq!(conn, "i04-7");
            assert_eq!(response.body_digest, sha256::prefixed(body));
            assert_eq!((response.uid.as_deref(), response.resource_version.as_deref()), (Some("u-9"), Some("7")));
        }
        other => panic!("one response, not {other:?}"),
    }
    let staged = rig.exchange.borrow_mut().take_response().expect("staged for the I04 relay");
    assert_eq!(staged.body, body.to_vec(), "the decoded body is relayed (re-rendered with Content-Length)");
}

#[test]
fn a_non_json_error_body_is_relayed_byte_exact_with_its_digest() {
    let mut rig = rig();
    let body = b"upstream says: no\n\xff\xfe";
    let (_, events) = rig.i05_exchange(Verb::Create, Kind::Pod, "probe-pod", &http("503 Service Unavailable", body));
    match &events[..] {
        [PolicyEvent::Base(Event::UpstreamResponse { response, .. })] => {
            assert_eq!(response.http_status, 503);
            assert_eq!(response.body_digest, sha256::prefixed(body));
            assert_eq!((response.uid.clone(), response.resource_version.clone()), (None, None));
        }
        other => panic!("one response, not {other:?}"),
    }
}

#[test]
fn surplus_101_an_interim_flood_and_an_unframed_body_are_lost_through_the_port() {
    let mut surplus = http("200 OK", br#"{"metadata":{"uid":"u","resourceVersion":"1"}}"#);
    surplus.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let answers: Vec<Vec<u8>> = vec![
        surplus,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n".to_vec(),
        b"HTTP/1.1 100 Continue\r\n\r\n".repeat(INTERIM_LIMIT + 1),
        b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
    ];
    for answer in answers {
        let mut rig = rig();
        let (apiserver, events) = rig.i07_exchange(ROLE_CREATE, &answer);
        assert!(matches!(&events[..], [PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Lost }]),
                "{}: {events:?}", String::from_utf8_lossy(&answer));
        assert!(rig.closed(apiserver.source));
    }
}

#[test]
fn an_answer_split_across_wakes_completes_on_its_last_byte() {
    let mut rig = rig();
    rig.forward_i05(Verb::Get, Kind::Pod, "probe-pod");
    let (mut apiserver, _) = rig.handshake();
    let answer = http("200 OK", br#"{"metadata":{"uid":"u-1","resourceVersion":"5"}}"#);
    let (first, rest) = answer.split_at(answer.len() / 2);
    assert!(rig.answer(&mut apiserver, first).is_empty());
    assert!(rig.port.is_open());
    let events = rig.answer(&mut apiserver, rest);
    assert!(matches!(&events[..], [PolicyEvent::Base(Event::UpstreamResponse { .. })]), "{events:?}");
}
