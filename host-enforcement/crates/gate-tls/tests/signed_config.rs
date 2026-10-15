//! HE-003D DESIGN sections 3.1, 3.5 and 8 (Q-HE3D-7 (d), D2-4, D2-7): the signed configuration's read and Ed25519
//! check through the file layer (`signed_config::load_from(dir, key)`), with a fixed-seed test key
//! (`Ed25519KeyPair::from_seed_unchecked`, test only). Files are written under cargo's `CARGO_TARGET_TMPDIR`.

use gate_tls::signed_config::{check_key, load_from, payload, verify, LoadError, VerifyError, COMPILED_KEY, DOCUMENT_LIMIT,
                              DOCUMENT_NAME, SIGNATURE_NAME};
use ring::signature::{Ed25519KeyPair, KeyPair};

const DOCUMENT: &[u8] = b"{\"format\":\"planeon.effect-gate-config/v1\"}";

fn signer(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("a fixed-seed test key")
}

fn public(seed: u8) -> Vec<u8> {
    signer(seed).public_key().as_ref().to_vec()
}

/// A fresh directory holding `document` and `signature`.
fn place(case: &str, document: &[u8], signature: &[u8]) -> String {
    let dir = format!("{}/he003d/signed-config/{case}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    std::fs::write(format!("{dir}/{DOCUMENT_NAME}"), document).expect("document");
    std::fs::write(format!("{dir}/{SIGNATURE_NAME}"), signature).expect("signature");
    dir
}

fn signed(seed: u8, document: &[u8]) -> Vec<u8> {
    signer(seed).sign(&payload(document)).as_ref().to_vec()
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
fn a_good_signature_loads_the_document() {
    let dir = place("good", DOCUMENT, &signed(7, DOCUMENT));
    assert_eq!(load_from(&dir, &public(7)), Ok(DOCUMENT.to_vec()));
    assert_eq!(payload(b"x"), b"planeon.effect-gate-config/v1\0x".to_vec());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_changed_document_wrong_key_or_wrong_domain_is_refused() {
    let signature = signed(7, DOCUMENT);
    let mut flipped = DOCUMENT.to_vec();
    flipped[3] ^= 0x01;
    let dir = place("flipped", &flipped, &signature);
    assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Signature(VerifyError::Signature)));
    let dir = place("wrong-key", DOCUMENT, &signature);
    assert_eq!(load_from(&dir, &public(8)), Err(LoadError::Signature(VerifyError::Signature)));
    // The domain prefix is part of the signed payload: a signature over the bare document, over another version's
    // prefix or without the zero byte does not verify.
    for message in [DOCUMENT.to_vec(), [b"planeon.effect-gate-config/v2\0".as_slice(), DOCUMENT].concat(),
                    [b"planeon.effect-gate-config/v1".as_slice(), DOCUMENT].concat()] {
        let other = signer(7).sign(&message).as_ref().to_vec();
        let dir = place("domain", DOCUMENT, &other);
        assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Signature(VerifyError::Signature)));
    }
    let mut bad = signature.clone();
    bad[10] ^= 0x40;
    assert_eq!(verify(DOCUMENT, &bad, &public(7)), Err(VerifyError::Signature));
    assert_eq!(verify(DOCUMENT, &signature, &public(7)), Ok(()));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_signature_file_is_exactly_64_bytes() {
    let signature = signed(7, DOCUMENT);
    for length in [63usize, 65, 0, 128] {
        let mut bytes = signature.clone();
        bytes.resize(length, 0);
        let dir = place(&format!("sig-{length}"), DOCUMENT, &bytes);
        assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read), "{length} bytes");
    }
    assert_eq!(verify(DOCUMENT, &signature[..63], &public(7)), Err(VerifyError::Signature));
}

#[test]
fn the_files_are_read_as_specified() {
    let signature = signed(7, DOCUMENT);
    // An empty document and one above 1 MiB are refused at the read; so are missing files and a missing directory.
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
    // A directory at the document's name is not a regular file.
    std::fs::create_dir(format!("{dir}/{DOCUMENT_NAME}")).expect("directory");
    std::fs::write(format!("{dir}/{SIGNATURE_NAME}"), &signature).expect("signature");
    assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Read));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn an_unsigned_document_is_never_parsed() {
    // Not JSON, or nested far past the canonical subset's 16: refused at the signature step, whatever the bytes.
    let deep = [vec![b'['; 10_000], vec![b']'; 10_000]].concat();
    for (case, document) in [("not-json", b"\xff\xfe not json".to_vec()), ("deep", deep)] {
        let dir = place(case, &document, &[0u8; 64]);
        assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Signature(VerifyError::Signature)), "{case}");
        let dir = place(case, &document, &signed(8, &document));
        assert_eq!(load_from(&dir, &public(7)), Err(LoadError::Signature(VerifyError::Signature)), "{case}");
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn the_key_must_be_set_and_not_of_small_order() {
    let signature = signed(7, DOCUMENT);
    let dir = place("keys", DOCUMENT, &signature);
    assert_eq!(load_from(&dir, &[]), Err(LoadError::Signature(VerifyError::KeyNotSet)));
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
fn the_compiled_in_key_is_empty_or_usable() {
    // The build-time check over the compiled-in bytes: empty until HE-008 sets the key (every document refused), else
    // 32 bytes not of small order.
    assert!(COMPILED_KEY.is_empty() || check_key(COMPILED_KEY).is_ok());
    if COMPILED_KEY.is_empty() {
        assert_eq!(verify(DOCUMENT, &signed(7, DOCUMENT), COMPILED_KEY), Err(VerifyError::KeyNotSet));
    }
}
