//! The credential and CA files, read after the seal (HE-003D DESIGN section 3.4, D1-7; HE-003B's key read-buffer
//! hygiene, C7): each file the signed configuration names is opened with gate-sys's `Dir::file_ro` (the directory is
//! its parent), sized by `fstat` (1 to 65,536 bytes) and read with a plain `read` loop into one buffer of size + 1,
//! allocated once (for a key a `Zeroizing<Vec<u8>>`), never a growing one; a total other than the size (the file grew
//! or shrank) is refused, and the length is then cut to the size without reallocation (zeroize 1.9.1 clears the spare
//! capacity on drop). The bytes are compared with the pinned sha256, then moved into `TlsServerInputs`,
//! `TlsClientIdentity` or the CA list with no other copy. Every refusal is status 20.
//!
//! Residual (next to R58): the hasher's state over a key keeps its last block uncleared. Neither holder type formats
//! its bytes; both are secret types for `tools/gate.py` (no derived Debug). gate-tls also hands the binary rustls's
//! default time provider, so `crates/gate` names no registry crate (Q-HE3D-11 (a)).

use std::fs::File;
use std::sync::Arc;

use effect_gate::gate_config::{FileRef, IdentityFiles};
use gate_sys::Dir;
use i05_protocol::sha256;
use rustls::time_provider::{DefaultTimeProvider, TimeProvider};
use zeroize::Zeroizing;

use crate::signed_config::fill;
use crate::tls::TlsServerInputs;
use crate::tls_client::TlsClientIdentity;

/// The largest credential or CA file.
pub const MAX_FILE_BYTES: usize = 65_536;

/// Why a file was refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CredentialError {
    /// The path, its directory or the file could not be opened (or is not a regular file).
    Open,
    /// The size is not 1 to 65,536 bytes, or a buffer does not fit it.
    Size,
    /// A read failed, or the file grew or shrank after `fstat`.
    Read,
    /// The bytes' sha256 is not the pinned one.
    Digest,
}

/// One opened, sized file (the helper type).
pub struct CredentialFile {
    file: File,
    size: usize,
}

/// A PKCS#8 key's bytes, cleared on every drop path (the holder type).
pub struct KeyBytes(Zeroizing<Vec<u8>>);

impl KeyBytes {
    /// A zeroed buffer of `size` + 1 bytes, allocated once.
    pub fn with_size(size: usize) -> Result<KeyBytes, CredentialError> {
        let length = size.checked_add(1).ok_or(CredentialError::Size)?;
        Ok(KeyBytes(Zeroizing::new(vec![0u8; length])))
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

    /// The key for `TlsServerInputs` or `TlsClientIdentity` (moved, not copied).
    pub fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// `path`'s directory and name.
fn split(path: &str) -> Result<(&str, &str), CredentialError> {
    match path.rsplit_once('/') {
        Some(("", name)) => Ok(("/", name)),
        Some(parts) => Ok(parts),
        None => Err(CredentialError::Open),
    }
}

impl CredentialFile {
    /// Opens `path` read-only through its directory and sizes it (1 to 65,536 bytes).
    pub fn at(path: &str) -> Result<CredentialFile, CredentialError> {
        let (parent, name) = split(path)?;
        let file = Dir::at(parent).and_then(|dir| dir.file_ro(name)).map_err(|_| CredentialError::Open)?;
        let size = file.metadata().ok().and_then(|found| usize::try_from(found.len()).ok()).ok_or(CredentialError::Size)?;
        if size == 0 || size > MAX_FILE_BYTES {
            return Err(CredentialError::Size);
        }
        Ok(CredentialFile { file, size })
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
        if fill(&mut self.file, buffer).map_err(|_| CredentialError::Read)? != self.size {
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

    /// A key's bytes into `key` (from [`KeyBytes::with_size`] of this file's size), checked against `pin`.
    pub fn read_key(mut self, mut key: KeyBytes, pin: &str) -> Result<KeyBytes, CredentialError> {
        self.read_into(&mut key.0)?;
        pinned(&key.0, pin)?;
        Ok(key)
    }
}

fn pinned(bytes: &[u8], pin: &str) -> Result<(), CredentialError> {
    if sha256::prefixed(bytes) == pin { Ok(()) } else { Err(CredentialError::Digest) }
}

/// A certificate file of the configuration.
pub fn read_certificate(file: &FileRef) -> Result<Vec<u8>, CredentialError> {
    CredentialFile::at(&file.path)?.read(&file.sha256)
}

/// A key file of the configuration.
pub fn read_key(file: &FileRef) -> Result<KeyBytes, CredentialError> {
    let opened = CredentialFile::at(&file.path)?;
    let key = KeyBytes::with_size(opened.size())?;
    opened.read_key(key, &file.sha256)
}

/// The I04 server's inputs: its chain (leaf first), its key (read last) and the one I04 client CA.
pub fn server_inputs(identity: &IdentityFiles, client_ca: &FileRef) -> Result<TlsServerInputs, CredentialError> {
    let chain = identity.chain.iter().map(read_certificate).collect::<Result<Vec<_>, _>>()?;
    let client_cas = vec![read_certificate(client_ca)?];
    let key = read_key(&identity.key)?;
    Ok(TlsServerInputs { chain, key: key.into_inner(), client_cas })
}

/// One upstream client identity: its chain (leaf first) and its key (read last).
pub fn client_identity(identity: &IdentityFiles) -> Result<TlsClientIdentity, CredentialError> {
    let chain = identity.chain.iter().map(read_certificate).collect::<Result<Vec<_>, _>>()?;
    let key = read_key(&identity.key)?;
    Ok(TlsClientIdentity { chain, key: key.into_inner() })
}

/// The apiserver's trust anchors: exactly the one configured serving CA (HE-003C PR R1-3, Q-HE3D-8 (a)).
pub fn serving_roots(serving_ca: &FileRef) -> Result<Vec<Vec<u8>>, CredentialError> {
    Ok(vec![read_certificate(serving_ca)?])
}

/// rustls's default time provider (std's `SystemTime`), for `server_config` and `client_config`.
pub fn time_provider() -> Arc<dyn TimeProvider> {
    Arc::new(DefaultTimeProvider)
}
