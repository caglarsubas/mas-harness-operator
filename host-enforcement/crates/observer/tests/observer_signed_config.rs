//! HE-004C DESIGN-C section 11 (Q-HE4C-3 (a) with (i), Q-HE4C-12 (a)): the observer's signed configuration through the
//! file layer (`signed_config::load_from(dir, key)`), with a fixed-seed test key (`Ed25519KeyPair::from_seed_unchecked`,
//! test only): the empty compiled-in key (12), small-order keys, bad and short signatures, the gate's domain refused,
//! the size bounds and the EOF probe (11). Files are written under cargo's `CARGO_TARGET_TMPDIR`.

use std::io::{self, Read};

use planeon_observer::signed_config::{check_key, fill, load, load_from, payload, verify, LoadError, VerifyError, COMPILED_KEY,
                                      DOCUMENT_LIMIT, DOCUMENT_NAME, PRODUCTION_DIR, SIGNATURE_NAME};
use planeon_observer::status;
use ring::signature::{Ed25519KeyPair, KeyPair};

const DOCUMENT: &[u8] = b"{\"format\":\"planeon.observer-config/v1\"}";

fn signer(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("a fixed-seed test key")
}

fn public(seed: u8) -> Vec<u8> {
    signer(seed).public_key().as_ref().to_vec()
}

fn signed(seed: u8, document: &[u8]) -> Vec<u8> {
    signer(seed).sign(&payload(document)).as_ref().to_vec()
}

/// A fresh directory holding `document` and `signature`.
fn place(case: &str, document: &[u8], signature: &[u8]) -> String {
    let dir = format!("{}/he004c/signed-config/{case}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    std::fs::write(format!("{dir}/{DOCUMENT_NAME}"), document).expect("document");
    std::fs::write(format!("{dir}/{SIGNATURE_NAME}"), signature).expect("signature");
    dir
}

/// libsodium's seven small-order y values (little-endian), each with both sign bits: 14 keys.
fn small_order_keys() -> Vec<[u8; 32]> {
    let mut seven = vec![[0u8; 32], {
        let mut one = [0u8; 32];
        one[0] = 1;
        one
    }];
    for hex in ["26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"] {
        let mut y = [0u8; 32];
        for (byte, pair) in y.iter_mut().zip(hex.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex");
        }
        seven.push(y);
    }
    for low in [0xec, 0xed, 0xee] {
        let mut y = [0xffu8; 32];
        y[0] = low;
        y[31] = 0x7f;
        seven.push(y);
    }
    let mut keys = Vec::new();
    for y in seven {
        keys.push(y);
        let mut signed = y;
        signed[31] |= 0x80;
        keys.push(signed);
    }
    keys
}

#[test]
fn the_paths_and_the_domain_are_the_observers() {
    assert_eq!((PRODUCTION_DIR, DOCUMENT_NAME, SIGNATURE_NAME), ("/etc/planeon/policy-observer", "config.json", "config.json.sig"));
    assert_eq!(payload(b"x"), b"planeon.observer-config/v1\0x".to_vec());
}

#[test]
fn a_good_signature_loads_the_document() {
    let dir = place("good", DOCUMENT, &signed(7, DOCUMENT));
    assert_eq!(load_from(&dir, &public(7)), Ok(DOCUMENT.to_vec()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_empty_compiled_in_key_refuses_every_document() {
    // HE-008 sets the key; until then every document is refused (status 12), and the production read refuses.
    assert!(COMPILED_KEY.is_empty() || check_key(COMPILED_KEY).is_ok());
    if COMPILED_KEY.is_empty() {
        let dir = place("compiled", DOCUMENT, &signed(7, DOCUMENT));
        let refused = load_from(&dir, COMPILED_KEY);
        assert_eq!(refused, Err(LoadError::Signature(VerifyError::KeyNotSet)));
        assert_eq!(status::config_load(&refused.expect_err("refused")), 12);
        assert!(load().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn small_order_and_malformed_keys_are_refused() {
    let dir = place("keys", DOCUMENT, &signed(7, DOCUMENT));
    assert_eq!(load_from(&dir, &public(7)[..31]), Err(LoadError::Signature(VerifyError::KeyLength)));
    assert_eq!(load_from(&dir, &[public(7), vec![0]].concat()), Err(LoadError::Signature(VerifyError::KeyLength)));
    let keys = small_order_keys();
    assert_eq!(keys.len(), 14);
    for key in &keys {
        assert_eq!(check_key(key), Err(VerifyError::SmallOrder), "{key:02x?}");
        assert_eq!(load_from(&dir, key), Err(LoadError::Signature(VerifyError::SmallOrder)), "{key:02x?}");
    }
    assert_eq!(check_key(&public(7)), Ok(()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn bad_and_short_signatures_and_the_gates_domain_are_refused() {
    let signature = signed(7, DOCUMENT);
    let mut flipped = signature.clone();
    flipped[10] ^= 0x40;
    assert_eq!(verify(DOCUMENT, &flipped, &public(7)), Err(VerifyError::Signature));
    assert_eq!(verify(DOCUMENT, &signature[..63], &public(7)), Err(VerifyError::Signature));
    assert_eq!(verify(DOCUMENT, &signature, &public(8)), Err(VerifyError::Signature));
    assert_eq!(verify(DOCUMENT, &signature, &public(7)), Ok(()));
    // A signature over the gate's domain, the bare document, or the prefix without its zero byte never verifies.
    for message in [[b"planeon.effect-gate-config/v3\0".as_slice(), DOCUMENT].concat(),
                    [b"planeon.effect-gate-config/v2\0".as_slice(), DOCUMENT].concat(), DOCUMENT.to_vec(),
                    [b"planeon.observer-config/v1".as_slice(), DOCUMENT].concat()] {
        let other = signer(7).sign(&message).as_ref().to_vec();
        let dir = place("domain", DOCUMENT, &other);
        assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Signature(VerifyError::Signature)));
        let _ = std::fs::remove_dir_all(dir);
    }
    // The signature file is exactly 64 bytes (else a read refusal, 11).
    for length in [63usize, 65, 0, 128] {
        let mut bytes = signature.clone();
        bytes.resize(length, 0);
        let dir = place(&format!("sig-{length}"), DOCUMENT, &bytes);
        assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read), "{length} bytes");
        let _ = std::fs::remove_dir_all(dir);
    }
    assert_eq!(status::config_load(&LoadError::Read), 11);
}

#[test]
fn the_size_bounds_and_the_files() {
    let signature = signed(7, DOCUMENT);
    let dir = place("empty", b"", &signature);
    assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read));
    let big = vec![b' '; DOCUMENT_LIMIT + 1];
    let dir = place("big", &big, &signer(7).sign(&payload(&big)).as_ref().to_vec());
    assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read));
    let limit = vec![b' '; DOCUMENT_LIMIT];
    let dir = place("limit", &limit, &signer(7).sign(&payload(&limit)).as_ref().to_vec());
    assert_eq!(load_from(&dir, &public(7)).map(|bytes| bytes.len()), Ok(DOCUMENT_LIMIT));
    let dir = place("missing", DOCUMENT, &signature);
    std::fs::remove_file(format!("{dir}/{SIGNATURE_NAME}")).expect("remove");
    assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read));
    std::fs::remove_file(format!("{dir}/{DOCUMENT_NAME}")).expect("remove");
    assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read));
    assert_eq!(load_from(&format!("{dir}/absent"), &public(7)), Err(LoadError::Read));
    assert_eq!(load_from("relative/dir", &public(7)), Err(LoadError::Read));
    std::fs::create_dir(format!("{dir}/{DOCUMENT_NAME}")).expect("directory");
    std::fs::write(format!("{dir}/{SIGNATURE_NAME}"), &signature).expect("signature");
    assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read));
    let _ = std::fs::remove_dir_all(dir);
}

/// A reader holding `bytes`, interrupted once, then giving at most `step` bytes per read.
struct Scripted {
    bytes: Vec<u8>,
    at: usize,
    step: usize,
    interrupted: bool,
}

impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = buffer.len().min(self.step).min(self.bytes.len() - self.at);
        buffer[..count].copy_from_slice(&self.bytes[self.at..self.at + count]);
        self.at += count;
        Ok(count)
    }
}

#[test]
fn the_eof_probe_sees_a_document_that_grew_or_shrank() {
    // The read fills a buffer of size + 1: a document of exactly its fstat size reads size bytes; one that grew after
    // fstat fills the extra byte (size + 1, refused); one that shrank reads fewer (refused). Interrupted reads retry.
    let size = 10;
    for (held, expected) in [(10usize, 10usize), (11, 11), (64, 11), (9, 9)] {
        let mut reader = Scripted { bytes: vec![b'x'; held], at: 0, step: 3, interrupted: false };
        let mut buffer = vec![0u8; size + 1];
        assert_eq!(fill(&mut reader, &mut buffer).expect("read"), expected, "{held} held");
    }
    let mut failing = io::repeat(0).take(0);
    assert_eq!(fill(&mut failing, &mut [0u8; 4]).expect("read"), 0);
}

#[test]
fn an_unsigned_document_is_never_parsed() {
    let deep = [vec![b'['; 10_000], vec![b']'; 10_000]].concat();
    for (case, document) in [("not-json", b"\xff\xfe not json".to_vec()), ("deep", deep)] {
        let dir = place(case, &document, &[0u8; 64]);
        assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Signature(VerifyError::Signature)), "{case}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
