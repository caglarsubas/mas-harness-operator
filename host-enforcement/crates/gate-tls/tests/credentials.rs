//! HE-003D DESIGN sections 3.4 and 8 (D1-7): the credential and CA reads through the file layer: the pinned sha256,
//! the size bounds (1 to 65,536 bytes), a file that grew or shrank after `fstat`, and a key read into the one buffer
//! allocated for it (address and capacity unchanged, length cut to the size). The configured files compose into the
//! TLS inputs that the production builders accept (the test PKI of `tls_support`). Files are written under cargo's
//! `CARGO_TARGET_TMPDIR`.

mod tls_support;

use std::io::Write;

use effect_gate::gate_config::{FileRef, IdentityFiles};
use gate_tls::credentials::MAX_FILE_BYTES;
use gate_tls::{client_config, client_identity, read_certificate, read_key, server_config, server_inputs, serving_roots,
               time_provider, CredentialError, CredentialFile, KeyBytes};
use i05_protocol::sha256;

fn scratch(case: &str) -> String {
    let dir = format!("{}/he003d/credentials/{case}", env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// Writes `bytes` to `<dir>/<name>` and returns its reference with the right pin.
fn written(dir: &str, name: &str, bytes: &[u8]) -> FileRef {
    let path = format!("{dir}/{name}");
    std::fs::write(&path, bytes).expect("write");
    FileRef { path, sha256: sha256::prefixed(bytes) }
}

#[test]
fn a_certificate_is_read_and_checked_against_its_pin() {
    let dir = scratch("pin");
    let file = written(&dir, "a.crt", b"certificate bytes");
    assert_eq!(read_certificate(&file), Ok(b"certificate bytes".to_vec()));
    let wrong = FileRef { sha256: sha256::prefixed(b"other bytes"), ..file.clone() };
    assert_eq!(read_certificate(&wrong), Err(CredentialError::Digest));
    assert_eq!(read_key(&wrong).err(), Some(CredentialError::Digest));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_size_is_one_to_65536_bytes() {
    let dir = scratch("size");
    let largest = written(&dir, "largest.crt", &vec![7u8; MAX_FILE_BYTES]);
    assert_eq!(read_certificate(&largest).map(|bytes| bytes.len()), Ok(MAX_FILE_BYTES));
    let over = written(&dir, "over.crt", &vec![7u8; MAX_FILE_BYTES + 1]);
    assert_eq!(read_certificate(&over), Err(CredentialError::Size));
    let empty = written(&dir, "empty.crt", b"");
    assert_eq!(read_certificate(&empty), Err(CredentialError::Size));
    assert_eq!(read_key(&empty).err(), Some(CredentialError::Size));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_file_that_cannot_be_opened_is_refused() {
    let dir = scratch("open");
    let pin = sha256::prefixed(b"x");
    for path in [format!("{dir}/absent.crt"), format!("{dir}/absent/x.crt"), "relative.crt".to_string(), dir.clone()] {
        assert_eq!(read_certificate(&FileRef { path: path.clone(), sha256: pin.clone() }), Err(CredentialError::Open), "{path}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_file_that_grew_or_shrank_after_fstat_is_refused() {
    let dir = scratch("change");
    let file = written(&dir, "a.crt", b"0123456789");
    let opened = CredentialFile::at(&file.path).expect("opens");
    assert_eq!(opened.size(), 10);
    std::fs::OpenOptions::new().append(true).open(&file.path).expect("append").write_all(b"x").expect("grow");
    assert_eq!(opened.read(&file.sha256), Err(CredentialError::Read), "grew");
    let file = written(&dir, "b.crt", b"0123456789");
    let opened = CredentialFile::at(&file.path).expect("opens");
    std::fs::write(&file.path, b"01234").expect("shrink");
    assert_eq!(opened.read(&file.sha256), Err(CredentialError::Read), "shrank");
    let key = written(&dir, "c.key", b"0123456789");
    let opened = CredentialFile::at(&key.path).expect("opens");
    let buffer = KeyBytes::with_size(opened.size()).expect("a buffer");
    std::fs::write(&key.path, b"012345678901").expect("grow");
    assert_eq!(opened.read_key(buffer, &key.sha256).err(), Some(CredentialError::Read));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_key_stays_in_the_buffer_allocated_for_it() {
    let dir = scratch("key");
    let bytes = (0u8..=200).collect::<Vec<u8>>();
    let key = written(&dir, "a.key", &bytes);
    let opened = CredentialFile::at(&key.path).expect("opens");
    let buffer = KeyBytes::with_size(opened.size()).expect("a buffer");
    assert_eq!(buffer.len(), bytes.len() + 1);
    let (address, capacity) = (buffer.as_ptr(), buffer.capacity());
    let read = opened.read_key(buffer, &key.sha256).expect("reads");
    assert_eq!((read.as_ptr(), read.capacity(), read.len()), (address, capacity, bytes.len()));
    assert_eq!(read.into_inner().as_slice(), bytes.as_slice());
    // A buffer of another size is refused before any read.
    let opened = CredentialFile::at(&key.path).expect("opens");
    assert_eq!(opened.read_key(KeyBytes::with_size(3).expect("a buffer"), &key.sha256).err(), Some(CredentialError::Size));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_configured_files_compose_into_the_tls_inputs() {
    let dir = scratch("compose");
    let pki = tls_support::pki();
    let server = IdentityFiles { chain: vec![written(&dir, "server.crt", &pki.server)],
                                 key: written(&dir, "server.key", &pki.server_key.pkcs8) };
    let client_ca = written(&dir, "client-ca.crt", &pki.ca);
    let inputs = server_inputs(&server, &client_ca).expect("the server's files read");
    assert_eq!((inputs.chain.len(), inputs.key.len(), inputs.client_cas.len()), (1, pki.server_key.pkcs8.len(), 1));
    assert!(server_config(inputs, tls_support::fixed_time()).is_ok(), "the I04 server configuration builds");
    let identity = IdentityFiles { chain: vec![written(&dir, "client.crt", &pki.client), written(&dir, "ca.crt", &pki.ca)],
                                   key: written(&dir, "client.key", &pki.client_key.pkcs8) };
    let roots = serving_roots(&written(&dir, "serving-ca.crt", &pki.ca)).expect("the serving CA reads");
    assert_eq!(roots.len(), 1, "exactly one serving CA (R1-3)");
    let client = client_identity(&identity).expect("the identity's files read");
    assert_eq!(client.chain.len(), 2);
    assert!(client_config(client, &roots, tls_support::fixed_time()).is_ok(), "the client configuration builds");
    // A key that does not match its leaf passes the read (the pin is the file's) and fails the builder (status 21).
    let mismatched = IdentityFiles { key: written(&dir, "other.key", &pki.other_ca_key.pkcs8), ..identity.clone() };
    assert!(client_config(client_identity(&mismatched).expect("reads"), &roots, tls_support::fixed_time()).is_err());
    // One damaged file fails the whole read (status 20).
    let damaged = IdentityFiles { chain: vec![FileRef { sha256: sha256::prefixed(b"x"), ..identity.chain[0].clone() }],
                                  ..identity.clone() };
    assert_eq!(client_identity(&damaged).err(), Some(CredentialError::Digest));
    assert!(time_provider().current_time().is_some());
    let _ = std::fs::remove_dir_all(dir);
}
