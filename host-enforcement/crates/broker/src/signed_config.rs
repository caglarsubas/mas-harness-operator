//! The capacity broker's signed configuration: its read and Ed25519 check (HE-005C: DESIGN-HE005 revision 5 section
//! 3.1 and O19, moved to HE-005C by the scope notes; the HE-005C plan's Q-HE5C-1 (a) and Q-HE5C-2 (a); delta C3
//! revision 2). A third copy, in the observer's form: the observer's `signed_config.rs` (HE-004C, itself adapted from
//! gate-tls's, R69) with the broker's own directory, domain and compiled-in key. `main` calls it between the seal's two
//! stages, as the gate's main does (Q-HE5C-1 (a)), so the read-only `openat`, `fstat` and `read` run before the BROKER
//! filter is installed.
//!
//! - Files (fixed, no argv): `/etc/planeon/capacity-broker/config.json` (1 byte to 1 MiB) and `config.json.sig`
//!   (exactly 64 raw bytes), each opened through gate-sys's read-only `Dir`, sized by `fstat` and read into one buffer of
//!   size + 1 with a plain `read` loop, so a document that grew or shrank is refused (the EOF probe, R69's method).
//! - The key is compiled in from `crates/broker/config-signer.pub` (0 or 32 bytes, a gate rule), empty until HE-008:
//!   every document is then refused (status 12). A key of small order is refused by libsodium's method (the 14
//!   encodings, R69).
//! - The payload is `UTF8("planeon.capacity-broker-config/v1") || 0x00 || document`, verified with ring's
//!   `UnparsedPublicKey::new(&ED25519, key).verify`. The domain differs from the gate's and the observer's, so neither
//!   role's signature verifies as a broker document. Verification comes first: an unsigned or invalid document is never
//!   parsed.

use std::io;
use std::io::Read;

use gate_sys::Dir;
use ring::signature::{UnparsedPublicKey, ED25519};

use crate::config::FORMAT;

/// The configuration directory (DESIGN-HE005 section 3.1).
pub const PRODUCTION_DIR: &str = "/etc/planeon/capacity-broker";
/// The document's name.
pub const DOCUMENT_NAME: &str = "config.json";
/// The detached signature's name.
pub const SIGNATURE_NAME: &str = "config.json.sig";
/// The largest document.
pub const DOCUMENT_LIMIT: usize = 1 << 20;
/// An Ed25519 signature's length.
pub const SIGNATURE_BYTES: usize = 64;
/// An Ed25519 public key's length.
pub const KEY_BYTES: usize = 32;

/// The broker's signer key, compiled in from `crates/broker/config-signer.pub` (D-U2-1 (a)); empty until HE-008
/// generates the key and an R10 packet sets it. HE-008 decides whether it holds the same value as the gate's or the
/// observer's key.
pub const COMPILED_KEY: &[u8] = include_bytes!("../config-signer.pub");

/// libsodium's small-order y values (little-endian, sign bit clear): 0, 1, the two order-8 points' y, p - 1, p and
/// p + 1, where p = 2^255 - 19 (copied from the observer's, itself gate-tls's).
const SMALL_ORDER_Y: [[u8; KEY_BYTES]; 7] = [
    [0; 32],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac,
     0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
    [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53,
     0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
    [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
    [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
];

/// Why the key or the signature was refused (status 12).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The compiled-in key is empty: not yet set.
    KeyNotSet,
    /// The key is not 32 bytes.
    KeyLength,
    /// The key is one of the 14 small-order encodings.
    SmallOrder,
    /// The signature is not 64 bytes or does not verify.
    Signature,
}

/// Why the configuration could not be loaded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// A document could not be read as specified (status 11).
    Read,
    /// The key or the signature (status 12).
    Signature(VerifyError),
}

/// The read loop: `read` into `buffer` until it is full or the reader reports the end, retrying an interrupted read;
/// the number of bytes read. It never grows or replaces the buffer.
pub fn fill(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut total = 0usize;
    while let Some(rest) = buffer.get_mut(total..).filter(|rest| !rest.is_empty()) {
        match reader.read(rest) {
            Ok(0) => break,
            Ok(count) => total = total.saturating_add(count),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(total)
}

/// One entry of `dir`, `low` to `high` bytes by `fstat`, read whole into a buffer of size + 1 (the EOF probe).
fn read_entry(dir: &Dir, name: &str, low: usize, high: usize) -> Option<Vec<u8>> {
    let mut opened = dir.file_ro(name).ok()?;
    let size = usize::try_from(opened.metadata().ok()?.len()).ok()?;
    if size < low || size > high {
        return None;
    }
    let mut buffer = vec![0u8; size.checked_add(1)?];
    if fill(&mut opened, &mut buffer).ok()? != size {
        return None;
    }
    buffer.truncate(size);
    Some(buffer)
}

/// A usable key: 32 bytes, not of small order.
pub fn check_key(key: &[u8]) -> Result<(), VerifyError> {
    if key.is_empty() {
        return Err(VerifyError::KeyNotSet);
    }
    let Ok(mut y) = <[u8; KEY_BYTES]>::try_from(key) else { return Err(VerifyError::KeyLength) };
    if let Some(last) = y.last_mut() {
        *last &= 0x7f;
    }
    if SMALL_ORDER_Y.contains(&y) {
        return Err(VerifyError::SmallOrder);
    }
    Ok(())
}

/// The signed payload: the broker's domain, a zero byte, the document.
pub fn payload(document: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(FORMAT.len().saturating_add(1).saturating_add(document.len()));
    payload.extend_from_slice(FORMAT.as_bytes());
    payload.push(0);
    payload.extend_from_slice(document);
    payload
}

/// Verifies `signature` over the document's payload with `key` (pure; the key checks first).
pub fn verify(document: &[u8], signature: &[u8], key: &[u8]) -> Result<(), VerifyError> {
    check_key(key)?;
    if signature.len() != SIGNATURE_BYTES {
        return Err(VerifyError::Signature);
    }
    UnparsedPublicKey::new(&ED25519, key).verify(&payload(document), signature).map_err(|_| VerifyError::Signature)
}

/// Reads both entries of `dir` and verifies the document with `key`; the verified document's bytes.
pub fn load_from(dir: &str, key: &[u8]) -> Result<Vec<u8>, LoadError> {
    let directory = Dir::at(dir).map_err(|_| LoadError::Read)?;
    let document = read_entry(&directory, DOCUMENT_NAME, 1, DOCUMENT_LIMIT).ok_or(LoadError::Read)?;
    let signature = read_entry(&directory, SIGNATURE_NAME, SIGNATURE_BYTES, SIGNATURE_BYTES).ok_or(LoadError::Read)?;
    verify(&document, &signature, key).map_err(LoadError::Signature)?;
    Ok(document)
}

/// The production read: [`load_from`] of [`PRODUCTION_DIR`] with [`COMPILED_KEY`]. The key passes through
/// `core::hint::black_box` first (R69's form, Q-HE3D-B1 (a); DESIGN-HE005 section 3.1, H5E-7; delta C3's G-HE5C-12):
/// while it is empty the optimiser could otherwise prove that `check_key` always refuses and drop everything `main`
/// does after this call, so the shipped binary would not hold the startup run, the lifecycle or the WORKER bytes. The
/// value is unchanged (an identity), so an empty key still refuses every document.
pub fn load() -> Result<Vec<u8>, LoadError> {
    load_from(PRODUCTION_DIR, core::hint::black_box(COMPILED_KEY))
}
