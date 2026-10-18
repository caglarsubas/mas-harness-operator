//! The observer's credential and CA reads after the seal (HE-004C DESIGN-C section 11; R73's reader, adapted from
//! gate-tls's `credentials.rs`, owner decision Q-HE4-5 (a)): each certificate or key the signed configuration names is
//! opened with gate-sys's `Dir::file_ro` (the directory is its parent), sized by `fstat` (1 to 65,536 bytes) and read
//! with a plain `read` loop into one buffer of size + 1, allocated once (for the key an `ObserverKeyBytes`, which holds
//! it in `Zeroizing`), never a growing one; a total other than the size is refused, and the length is then cut to the
//! size without reallocation (zeroize 1.9.1 clears the spare capacity on drop). The bytes are compared with the pinned
//! sha256 and moved into `ObserverIdentity` or the serving CA with no other copy. Every refusal is status 20.
//!
//! Adapted from gate-tls: the opened-entry helper holds its handle in `opened` (the observer's post-seal word rule
//! refuses the identifier `file`), and `observer_inputs` returns the one serving CA and the `planeon:policy-observer`
//! identity. HE-008 issues that certificate with exactly `CN=planeon:policy-observer`, no `O` values and the clientAuth
//! EKU, and keeps its files root 0400 of type `planeon_observer_cred_t` (carried, R108). Neither holder type formats its
//! bytes; both are secret types for `tools/gate.py` (no derived Debug). Residual (next to R58): the hasher's state over
//! a key keeps its last block uncleared.

use std::fmt;
use std::fs::File;

use gate_sys::Dir;
use i05_protocol::sha256;
use zeroize::Zeroizing;

use crate::config::{CredentialFiles, FileRef};
use crate::signed_config::fill;

/// The largest credential or CA entry.
pub const MAX_ENTRY_BYTES: usize = 65_536;

/// Why an entry was refused (status 20).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CredentialError {
    /// The name, its directory or the entry could not be opened (or is not a regular entry).
    Open,
    /// The size is not 1 to 65,536 bytes, or a buffer does not fit it.
    Size,
    /// A read failed, or the entry grew or shrank after `fstat`.
    Read,
    /// The bytes' sha256 is not the pinned one.
    Digest,
}

/// The `planeon:policy-observer` identity, DER only: its chain (leaf first) and its PKCS#8 key, cleared on every drop
/// path; the key leaves it only when it is moved into rustls (`tls::client_config`).
pub struct ObserverIdentity {
    pub chain: Vec<Vec<u8>>,
    pub key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ObserverIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObserverIdentity")
            .field("chain_certificates", &self.chain.len())
            .field("key_bytes", &self.key.len())
            .finish()
    }
}

/// One opened, sized entry (the helper type).
pub struct ObserverCredential {
    opened: File,
    size: usize,
}

/// A PKCS#8 key's bytes, cleared on every drop path (the holder type).
pub struct ObserverKeyBytes(Zeroizing<Vec<u8>>);

impl ObserverKeyBytes {
    /// A zeroed buffer of `size` + 1 bytes, allocated once.
    pub fn with_size(size: usize) -> Result<ObserverKeyBytes, CredentialError> {
        let length = size.checked_add(1).ok_or(CredentialError::Size)?;
        Ok(ObserverKeyBytes(Zeroizing::new(vec![0u8; length])))
    }

    /// The buffer's address (the tests check that reading never moves it).
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The key for `ObserverIdentity` (moved, not copied).
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// A name's directory and last component.
fn split(name: &str) -> Result<(&str, &str), CredentialError> {
    match name.rsplit_once('/') {
        Some(("", last)) => Ok(("/", last)),
        Some(parts) => Ok(parts),
        None => Err(CredentialError::Open),
    }
}

impl ObserverCredential {
    /// Opens `name` read-only through its directory and sizes it (1 to 65,536 bytes).
    pub fn at(name: &str) -> Result<ObserverCredential, CredentialError> {
        let (parent, last) = split(name)?;
        let opened = Dir::at(parent).and_then(|dir| dir.file_ro(last)).map_err(|_| CredentialError::Open)?;
        let size =
            opened.metadata().ok().and_then(|found| usize::try_from(found.len()).ok()).ok_or(CredentialError::Size)?;
        if size == 0 || size > MAX_ENTRY_BYTES {
            return Err(CredentialError::Size);
        }
        Ok(ObserverCredential { opened, size })
    }

    /// The size `fstat` reported.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The read loop into `buffer` (exactly size + 1 bytes), then its length cut to the size.
    fn read_into(&mut self, buffer: &mut Vec<u8>) -> Result<(), CredentialError> {
        if Some(buffer.len()) != self.size.checked_add(1) {
            return Err(CredentialError::Size);
        }
        if fill(&mut self.opened, buffer).map_err(|_| CredentialError::Read)? != self.size {
            return Err(CredentialError::Read);
        }
        buffer.truncate(self.size);
        Ok(())
    }

    /// A certificate's bytes, checked against `pin`.
    pub fn read(mut self, pin: &str) -> Result<Vec<u8>, CredentialError> {
        let mut buffer = vec![0u8; self.size.checked_add(1).ok_or(CredentialError::Size)?];
        self.read_into(&mut buffer)?;
        pinned(&buffer, pin)?;
        Ok(buffer)
    }

    /// A key's bytes into `key` (from [`ObserverKeyBytes::with_size`] of this entry's size), checked against `pin`.
    pub fn read_key(mut self, mut key: ObserverKeyBytes, pin: &str) -> Result<ObserverKeyBytes, CredentialError> {
        self.read_into(&mut key.0)?;
        pinned(&key.0, pin)?;
        Ok(key)
    }
}

fn pinned(bytes: &[u8], pin: &str) -> Result<(), CredentialError> {
    if sha256::prefixed(bytes) == pin { Ok(()) } else { Err(CredentialError::Digest) }
}

/// A certificate the configuration names.
pub fn read_certificate(entry: &FileRef) -> Result<Vec<u8>, CredentialError> {
    ObserverCredential::at(&entry.path)?.read(&entry.sha256)
}

/// A key the configuration names.
pub fn read_key(entry: &FileRef) -> Result<ObserverKeyBytes, CredentialError> {
    let opened = ObserverCredential::at(&entry.path)?;
    let key = ObserverKeyBytes::with_size(opened.size())?;
    opened.read_key(key, &entry.sha256)
}

/// The observer's TLS inputs: exactly the one configured apiserver serving CA (as R70), then the identity's chain (leaf
/// first) and its key, read last.
pub fn observer_inputs(files: &CredentialFiles) -> Result<(Vec<u8>, ObserverIdentity), CredentialError> {
    let serving_ca = read_certificate(&files.serving_ca)?;
    let chain = files.chain.iter().map(read_certificate).collect::<Result<Vec<_>, _>>()?;
    let key = read_key(&files.key)?;
    Ok((serving_ca, ObserverIdentity { chain, key: key.into_inner() }))
}
