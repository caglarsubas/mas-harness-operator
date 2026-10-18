//! HE-004C DESIGN-C section 5 (Q-HE4C-2 (a); D1-15): the request bytes, Accept included, for every request kind; the
//! answer reader's bounds (lists 4 MiB, small documents 64 KiB, raw chunked bound + 64 KiB, heads 16 KiB; the 16 MiB
//! aggregate is the epoch's, in `observer_observe.rs`); the streaming reader at every chunk boundary; codings refused;
//! media types on type and subtype.

use planeon_observer::http::{media_is, media_is_exposition, media_type, render, AnswerReader, Bounds, Progress, Refusal,
                             Request, StreamReader, ACCEPT_JSON, ACCEPT_METADATA_LIST, ACCEPT_METADATA_WATCH, ACCEPT_METRICS,
                             ACCEPT_TEXT, HEAD_LIMIT, LIST_BODY_LIMIT, METRICS_RAW_LIMIT, RAW_SLACK, SMALL_BODY_LIMIT,
                             SNAPSHOT_BODY_LIMIT};
use planeon_observer::inputs::Resource;
use planeon_observer::requests::{self, Mode};

fn bytes_of(request: &Request) -> String {
    String::from_utf8(render(request, "127.0.0.1:6443")).expect("ASCII")
}

fn head(target: &str, accept: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:6443\r\nUser-Agent: planeon-observer\r\nAccept: {accept}\r\nConnection: close\r\n\r\n")
}

#[test]
fn the_request_bytes_of_every_kind() {
    assert_eq!(bytes_of(&requests::readyz()), head("/readyz/poststarthook/rbac/bootstrap-roles", "text/plain"));
    assert_eq!(bytes_of(&requests::metrics()), head("/metrics", "text/plain;version=0.0.4"));
    assert_eq!(bytes_of(&requests::version()), head("/version", "application/json"));
    assert_eq!(bytes_of(&requests::progress()), head("/api/v1/namespaces?limit=1", "application/json"));
    assert_eq!(bytes_of(&requests::discovery_group()), head("/apis/admissionregistration.k8s.io", "application/json"));
    assert_eq!(bytes_of(&requests::discovery_version("v1")), head("/apis/admissionregistration.k8s.io/v1", "application/json"));
    assert_eq!(bytes_of(&requests::list(Resource::Roles, &Mode::Fresh)), head("/apis/rbac.authorization.k8s.io/v1/roles", "application/json"));
    assert_eq!(bytes_of(&requests::list(Resource::Namespaces, &Mode::Exact("1000".into()))),
               head("/api/v1/namespaces?resourceVersion=1000&resourceVersionMatch=Exact", "application/json"));
    assert_eq!(bytes_of(&requests::list(Resource::ClusterRoles, &Mode::Watch("1000".into()))),
               head("/apis/rbac.authorization.k8s.io/v1/clusterroles?watch=true&allowWatchBookmarks=true&resourceVersion=1000",
                    "application/json"));
    assert_eq!(bytes_of(&requests::list(Resource::ApiServices, &Mode::Probe)),
               head("/apis/apiregistration.k8s.io/v1/apiservices?limit=1", "application/json"));
    let secrets = "fieldSelector=type%3Dkubernetes.io%2Fservice-account-token";
    assert_eq!(bytes_of(&requests::list(Resource::ServiceAccountTokenSecrets, &Mode::Fresh)),
               head(&format!("/api/v1/secrets?{secrets}"), ACCEPT_METADATA_LIST));
    assert_eq!(bytes_of(&requests::list(Resource::ServiceAccountTokenSecrets, &Mode::Exact("7".into()))),
               head(&format!("/api/v1/secrets?{secrets}&resourceVersion=7&resourceVersionMatch=Exact"), ACCEPT_METADATA_LIST));
    assert_eq!(bytes_of(&requests::list(Resource::BootstrapTokenSecrets, &Mode::Watch("7".into()))),
               head("/api/v1/secrets?fieldSelector=type%3Dbootstrap.kubernetes.io%2Ftoken&watch=true&allowWatchBookmarks=true&resourceVersion=7",
                    ACCEPT_METADATA_WATCH));
    assert_eq!(bytes_of(&requests::list(Resource::BootstrapTokenSecrets, &Mode::Probe)),
               head("/api/v1/secrets?fieldSelector=type%3Dbootstrap.kubernetes.io%2Ftoken&limit=1", ACCEPT_METADATA_LIST));
    assert_eq!((ACCEPT_JSON, ACCEPT_TEXT, ACCEPT_METRICS), ("application/json", "text/plain", "text/plain;version=0.0.4"));
    assert_eq!(ACCEPT_METADATA_WATCH, "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1");
    // No body, Authorization or Accept-Encoding.
    let text = bytes_of(&requests::metrics());
    assert!(!text.contains("Authorization") && !text.contains("Accept-Encoding") && text.ends_with("\r\n\r\n"));
}

fn read(body: usize, bytes: &[u8]) -> (Progress, Option<(u16, Vec<u8>)>) {
    let mut reader = AnswerReader::new(body);
    let progress = reader.push(bytes);
    (progress, reader.answer().map(|answer| (answer.status, answer.body)))
}

fn chunked(data: &[u8], size: usize) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for piece in data.chunks(size) {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

#[test]
fn the_answer_reader_bounds() {
    assert_eq!((LIST_BODY_LIMIT, SMALL_BODY_LIMIT, SNAPSHOT_BODY_LIMIT, RAW_SLACK, HEAD_LIMIT), (4 << 20, 64 << 10, 16 << 20, 64 << 10, 16_384));
    // A small document: 64 KiB decoded exactly passes, one more byte refuses (length and chunked).
    let exact = vec![b'a'; SMALL_BODY_LIMIT];
    let mut answer = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", exact.len()).into_bytes();
    answer.extend_from_slice(&exact);
    assert_eq!(read(SMALL_BODY_LIMIT, &answer).0, Progress::Complete);
    let over = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", SMALL_BODY_LIMIT + 1).into_bytes();
    assert_eq!(read(SMALL_BODY_LIMIT, &over).0, Progress::Refused(Refusal::Length));
    assert_eq!(read(SMALL_BODY_LIMIT, &chunked(&exact, 4096)).0, Progress::Complete);
    assert_eq!(read(SMALL_BODY_LIMIT, &chunked(&vec![b'a'; SMALL_BODY_LIMIT + 1], 4096)).0, Progress::Refused(Refusal::Size));
    // The raw chunked bound (decoded bound + 64 KiB): 30,000 one-byte chunks are 180,000 raw bytes for 30,000 decoded.
    assert_eq!(read(SMALL_BODY_LIMIT, &chunked(&vec![b'a'; 30_000], 1)).0, Progress::Refused(Refusal::Size));
    assert_eq!(read(SMALL_BODY_LIMIT, &chunked(&vec![b'a'; 20_000], 1)).0, Progress::Complete);
    // A list: 4 MiB passes, more refuses.
    let list = vec![b'l'; LIST_BODY_LIMIT];
    let mut answer = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", list.len()).into_bytes();
    answer.extend_from_slice(&list);
    let mut reader = AnswerReader::new(LIST_BODY_LIMIT);
    assert_eq!(reader.push(&answer), Progress::Complete);
    let complete = reader.answer().expect("an answer");
    assert_eq!((complete.status, complete.body.len(), complete.content_type.as_deref()), (200, LIST_BODY_LIMIT, Some(b"application/json".as_slice())));
    let over = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", LIST_BODY_LIMIT + 1).into_bytes();
    assert_eq!(read(LIST_BODY_LIMIT, &over).0, Progress::Refused(Refusal::Length));
    // The heads together are at most 16 KiB.
    let long = format!("HTTP/1.1 200 OK\r\nX-Pad: {}\r\nContent-Length: 0\r\n\r\n", "p".repeat(HEAD_LIMIT));
    assert_eq!(read(SMALL_BODY_LIMIT, long.as_bytes()).0, Progress::Refused(Refusal::HeadSize));
    // Surplus after the complete answer refuses; the Content-Type of the final head is kept.
    assert_eq!(read(SMALL_BODY_LIMIT, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}x").0, Progress::Refused(Refusal::Surplus));
    let mut reader = AnswerReader::new(SMALL_BODY_LIMIT);
    reader.push(b"HTTP/1.1 103 Early Hints\r\nContent-Type: text/html\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n");
    let answer = reader.answer().expect("an answer");
    assert_eq!((answer.status, answer.content_type.as_deref()), (404, Some(b"application/json".as_slice())));
}

#[test]
fn codings_other_than_identity_and_chunked_are_refused() {
    for field in ["Content-Encoding: gzip", "Content-Encoding: deflate", "Content-Encoding: br", "Transfer-Encoding: gzip",
                  "Transfer-Encoding: gzip, chunked"] {
        let answer = format!("HTTP/1.1 200 OK\r\n{field}\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(read(SMALL_BODY_LIMIT, answer.as_bytes()).0, Progress::Refused(Refusal::Coding), "{field}");
    }
    assert_eq!(read(SMALL_BODY_LIMIT, b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 0\r\n\r\n").0, Progress::Complete);
}

/// The decoded bytes of `answer` pushed in two parts split at `at`.
fn stream_split(answer: &[u8], at: usize) -> (Progress, Vec<u8>, Option<u16>) {
    let mut reader = StreamReader::new(Bounds::stream());
    let mut out = Vec::new();
    reader.push(&answer[..at], &mut out);
    let progress = reader.push(&answer[at..], &mut out);
    (progress, out, reader.status())
}

#[test]
fn the_stream_reader_at_every_chunk_boundary() {
    let body = b"{\"type\":\"BOOKMARK\"}\n{\"type\":\"MODIFIED\"}\nline three\n";
    let answer = chunked(body, 7);
    for at in 0..=answer.len() {
        assert_eq!(stream_split(&answer, at), (Progress::Complete, body.to_vec(), Some(200)), "split at {at}");
    }
    // One byte at a time.
    let mut reader = StreamReader::new(Bounds::stream());
    let mut out = Vec::new();
    for byte in &answer {
        reader.push(std::slice::from_ref(byte), &mut out);
    }
    assert_eq!((reader.progress(), out.as_slice()), (Progress::Complete, body.as_slice()));
    // A stream is unbounded in total (each line is bounded by the watch reader).
    let big = vec![b'z'; LIST_BODY_LIMIT + 1];
    let mut reader = StreamReader::new(Bounds::stream());
    let mut out = Vec::new();
    assert_eq!(reader.push(&chunked(&big, 1 << 20), &mut out), Progress::Complete);
    assert_eq!(out.len(), big.len());
    // The exposition's bounds: 64 MiB, so an 8-digit Content-Length is read (a list's 7 digits are the limit there).
    let mut reader = StreamReader::new(Bounds::exposition());
    let mut out = Vec::new();
    assert_eq!(reader.push(b"HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\n", &mut out), Progress::NeedMore);
    let mut reader = StreamReader::new(Bounds::exposition());
    let over = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", METRICS_RAW_LIMIT + 1);
    assert_eq!(reader.push(over.as_bytes(), &mut out), Progress::Refused(Refusal::Length));
    assert_eq!(read(LIST_BODY_LIMIT, b"HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\n").0, Progress::Refused(Refusal::Length));
}

#[test]
fn media_types_compare_type_and_subtype() {
    assert_eq!(media_type(b"Application/JSON; charset=utf-8"),
               Some(("application/json".to_string(), vec![("charset".to_string(), "utf-8".to_string())])));
    assert!(media_is(Some(b"application/json"), "application/json"));
    assert!(media_is(Some(b"application/json;as=Table;v=v1"), "application/json"));
    assert!(!media_is(Some(b"application/yaml"), "application/json"));
    assert!(!media_is(Some(b"application/jsonx"), "application/json"));
    assert!(!media_is(None, "application/json"));
    assert!(!media_is(Some(b"json"), "application/json"));
    assert!(media_is_exposition(Some(b"text/plain; version=0.0.4; charset=utf-8; escaping=underscores")));
    assert!(media_is_exposition(Some(b"text/plain;version=\"0.0.4\"")));
    assert!(!media_is_exposition(Some(b"text/plain")));
    assert!(!media_is_exposition(Some(b"text/plain; version=1.0.0")));
    assert!(!media_is_exposition(Some(b"application/openmetrics-text; version=0.0.4")));
}
