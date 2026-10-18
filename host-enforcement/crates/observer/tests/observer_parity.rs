//! HE-004C DESIGN-C sections 4.3, 5.2 and 17 (Q-HE4-5 (a), D1-15): the copies cannot drift silently. The observer's
//! `AnswerReader` (4 MiB) gives the same outcome as gate-tls's `ResponseReader` on HE-003C's framing cases, whole and
//! byte by byte; and the first flights of the observer's `client_config` and of gate-tls's (the test-only dev
//! dependency), from the same identity and roots, offer equal versions, cipher suites, supported groups, signature
//! algorithms and ALPN, and neither offers `pre_shared_key`, `early_data` or `server_name` (the random values, the
//! session id and the key shares are excluded).

mod b1_rbac_support;
mod b1_support;
mod c_support;

use std::sync::Arc;

use c_support::*;
use gate_tls::{ResponseReader, TlsClientIdentity, CHUNKED_RAW_LIMIT, RESPONSE_BODY_LIMIT};
use planeon_observer::http::{AnswerReader, LIST_BODY_LIMIT};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use zeroize::Zeroizing;

/// HE-003C's framing cases (`gate-tls/tests/upstream_framing.rs`), and their neighbours.
fn cases() -> Vec<Vec<u8>> {
    let mut cases: Vec<Vec<u8>> = [
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 201 Created\r\ncontent-LENGTH:   0002 \r\n\r\nab",
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\nA\r\n, 0123456 \r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0000000\r\n\r\n",
        b"HTTP/1.1 200 \r\nContent-Encoding: IDENTITY\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 500 Internal\tServer \xe2\x9c\x97\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
        b"HTTP/1.1 104 Unknown\r\n\r\n",
        b"HTTP/1.1 199 x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 12345678\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12345678\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloX\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nTrailer: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello",
        b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"http/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 099 x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 600 x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 2x0 OK\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: a\r\n folded\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n: empty\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: \x01\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}x",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nHTTP",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel",
    ]
    .iter()
    .map(|bytes| bytes.to_vec())
    .collect();
    let mut flood = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(4);
    flood.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    cases.push(flood);
    cases.push(b"HTTP/1.1 100 Continue\r\n\r\n".repeat(5));
    cases.push(format!("HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: 0\r\n\r\n", "v".repeat(16_384)).into_bytes());
    cases.push(format!("HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: 0\r\n\r\n", "v".repeat(16_384 - 47)).into_bytes());
    // The decoded and raw bounds of a chunked body at 4 MiB.
    let mut at_bound = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..4 {
        at_bound.extend_from_slice(format!("{:x}\r\n", 1 << 20).as_bytes());
        at_bound.extend_from_slice(&vec![b'c'; 1 << 20]);
        at_bound.extend_from_slice(b"\r\n");
    }
    let mut over = at_bound.clone();
    at_bound.extend_from_slice(b"0\r\n\r\n");
    cases.push(at_bound);
    over.extend_from_slice(b"1\r\nc\r\n0\r\n\r\n");
    cases.push(over);
    let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..13_200 {
        raw.extend_from_slice(b"1\r\nc\r\n");
    }
    raw.extend_from_slice(b"0\r\n\r\n");
    cases.push(raw);
    let mut content = b"HTTP/1.1 200 OK\r\nContent-Length: 4194304\r\n\r\n".to_vec();
    content.extend_from_slice(&vec![b'd'; 4_194_304]);
    cases.push(content);
    cases
}

fn gate(bytes: &[u8], bytewise: bool) -> (String, Option<(u16, Vec<u8>)>) {
    let mut reader = ResponseReader::new();
    let mut progress = reader.progress();
    if bytewise {
        for byte in bytes {
            progress = reader.push(std::slice::from_ref(byte));
        }
    } else {
        progress = reader.push(bytes);
    }
    (format!("{progress:?}"), reader.answer())
}

fn observer(bytes: &[u8], bytewise: bool) -> (String, Option<(u16, Vec<u8>)>) {
    let mut reader = AnswerReader::new(LIST_BODY_LIMIT);
    let mut progress = reader.progress();
    if bytewise {
        for byte in bytes {
            progress = reader.push(std::slice::from_ref(byte));
        }
    } else {
        progress = reader.push(bytes);
    }
    (format!("{progress:?}"), reader.answer().map(|answer| (answer.status, answer.body)))
}

#[test]
fn the_answer_reader_matches_gate_tls_on_the_framing_cases() {
    assert_eq!((LIST_BODY_LIMIT, LIST_BODY_LIMIT + (64 << 10)), (RESPONSE_BODY_LIMIT, CHUNKED_RAW_LIMIT));
    let cases = cases();
    assert!(cases.len() >= 50);
    for (index, bytes) in cases.iter().enumerate() {
        let whole = gate(bytes, false);
        assert_eq!(observer(bytes, false), whole, "case {index}: {}", String::from_utf8_lossy(&bytes[..bytes.len().min(120)]));
        if bytes.len() < 100_000 {
            assert_eq!(observer(bytes, true), gate(bytes, true), "case {index} byte by byte");
        }
    }
}

/// The first flight of a client configuration for the apiserver at 127.0.0.1.
fn first_flight(config: Arc<ClientConfig>) -> Vec<u8> {
    let mut connection = ClientConnection::new(config, ServerName::try_from("127.0.0.1").expect("name")).expect("a client");
    let mut bytes = Vec::new();
    while connection.wants_write() {
        connection.write_tls(&mut bytes).expect("written");
    }
    bytes
}

/// The parts of a ClientHello that the parity compares: cipher suites and the extensions, without the key shares.
fn offered(record: &[u8]) -> (Vec<u8>, Vec<(u16, Vec<u8>)>) {
    let body = &record[5..];
    let mut at = 4 + 2 + 32;
    at += 1 + body[at] as usize;
    let suites_length = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    let suites = body[at + 2..at + 2 + suites_length].to_vec();
    at += 2 + suites_length;
    at += 1 + body[at] as usize;
    let total = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2;
    let end = at + total;
    let mut extensions = Vec::new();
    while at < end {
        let kind = u16::from_be_bytes([body[at], body[at + 1]]);
        let length = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        if kind != 51 {
            extensions.push((kind, body[at + 4..at + 4 + length].to_vec()));
        }
        at += 4 + length;
    }
    extensions.sort();
    (suites, extensions)
}

#[test]
fn the_client_hello_matches_gate_tls() {
    let pki = shared_pki();
    let observer_config = observer_tls(&pki, &pki.serving_ca);
    let gate_identity = TlsClientIdentity { chain: vec![pki.observer.clone()], key: Zeroizing::new(pki.observer_key.pkcs8.clone()) };
    let gate_config = gate_tls::client_config(gate_identity, &[pki.serving_ca.clone()], fixed_time()).expect("gate-tls's client");
    let (observer_suites, observer_extensions) = offered(&first_flight(observer_config));
    let (gate_suites, gate_extensions) = offered(&first_flight(gate_config));
    assert_eq!(observer_suites, gate_suites, "cipher suites");
    assert_eq!(observer_suites.len(), 2 * 3, "three TLS 1.3 suites");
    assert_eq!(observer_extensions, gate_extensions);
    let kinds: Vec<u16> = observer_extensions.iter().map(|(kind, _)| *kind).collect();
    for wanted in [43u16, 10, 13, 16] {
        assert!(kinds.contains(&wanted), "{wanted} in {kinds:?}");
    }
    for absent in [0u16, 41, 42] {
        assert!(!kinds.contains(&absent), "{absent} in {kinds:?}");
    }
}
