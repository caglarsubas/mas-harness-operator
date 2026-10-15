//! The upstream TLS client configuration (HE-003C DESIGN §3; MODEL_DEFINED R64): one builder function, called once per
//! client identity, mirroring the server's `tls.rs`.
//!
//! - Two identities (Q-HE3C-3 (a)): the gate effect identity (`planeon:effect-gate`) for I05 exchanges and the gate
//!   writer identity (`planeon:policy-writer`) for I07 writes, each a DER chain (leaf first) and a PKCS#8 DER key held
//!   in `Zeroizing`, so every drop path clears it; the key leaves it only when it is moved into rustls, whose
//!   `with_client_auth_cert` runs `CertifiedKey::from_der` (the key must match the leaf).
//! - The apiserver is verified by webpki against the configured apiserver serving CA (Q-HE3C-2 (a)), with the IP
//!   address of `apiserverAuthority` as the server name: its certificate must carry that IP SAN. No custom verifier.
//! - The ring provider of `tls.rs` (the three TLS 1.3 suites, X25519, P-256, P-384), passed explicitly to both
//!   builders; TLS 1.3 only (Q-HE3B-5 (a)); no session store and so no resumption, no early data, no SNI (redundant for
//!   an IP name, which rustls never sends as SNI, but explicit); ALPN `http/1.1` only.
//!
//! Residual (R58's kind): ring's parsed key pair of each identity lives for the process; nothing here formats a
//! configuration, connection or key object.

use std::fmt;
use std::sync::Arc;

use effect_gate::net::{InetAddress, IpLiteral};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, IpAddr, Ipv4Addr, Ipv6Addr, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::time_provider::TimeProvider;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use zeroize::Zeroizing;

use crate::tls::{provider, ALPN_HTTP11};

/// One client identity, DER only (HE-003D reads it from its configuration).
pub struct TlsClientIdentity {
    /// The identity's certificate chain, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// The identity's PKCS#8 private key.
    pub key: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for TlsClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsClientIdentity")
            .field("chain_certificates", &self.chain.len())
            .field("key_bytes", &self.key.len())
            .finish()
    }
}

/// Why a client configuration could not be built.
#[derive(Debug)]
pub enum TlsClientSetupError {
    /// No certificate in the identity's chain.
    NoChain,
    /// No apiserver serving CA.
    NoServerCa,
    /// A serving CA does not parse.
    ServerCa(rustls::Error),
    /// The server verifier could not be built.
    Verifier(String),
    /// The provider does not support TLS 1.3.
    Versions(rustls::Error),
    /// The key does not parse, or does not match the leaf.
    Key(rustls::Error),
}

/// The client configuration of one identity (see the module documentation), built once per identity and shared by
/// every exchange of its channel. `roots` are the apiserver serving CA certificates (at least one).
pub fn client_config(identity: TlsClientIdentity, roots: &[Vec<u8>], time: Arc<dyn TimeProvider>)
                     -> Result<Arc<ClientConfig>, TlsClientSetupError> {
    let TlsClientIdentity { chain, mut key } = identity;
    // Refusals before the key leaves its `Zeroizing` (whose drop clears it).
    if chain.is_empty() {
        return Err(TlsClientSetupError::NoChain);
    }
    if roots.is_empty() {
        return Err(TlsClientSetupError::NoServerCa);
    }
    let provider = Arc::new(provider());
    let mut store = RootCertStore::empty();
    for ca in roots {
        store.add(CertificateDer::from(ca.clone())).map_err(TlsClientSetupError::ServerCa)?;
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider.clone())
        .build()
        .map_err(|error| TlsClientSetupError::Verifier(error.to_string()))?;
    let builder = ClientConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&TLS13])
        .map_err(TlsClientSetupError::Versions)?
        .with_webpki_verifier(verifier);
    let chain: Vec<CertificateDer<'static>> = chain.into_iter().map(CertificateDer::from).collect();
    // The key last: moved, not copied, into rustls, which parses it inside its own `Zeroizing`.
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *key)));
    let mut config = builder.with_client_auth_cert(chain, key).map_err(TlsClientSetupError::Key)?;
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Ok(Arc::new(config))
}

/// The server name of the apiserver: its literal IP address (pki-types' own `Ipv4Addr` from the four octets, or
/// `Ipv6Addr` from the sixteen bytes read as eight big-endian pairs, since pki-types has no conversion from 16 bytes).
pub fn server_name(address: &InetAddress) -> ServerName<'static> {
    match address.ip {
        IpLiteral::V4(octets) => ServerName::IpAddress(IpAddr::V4(Ipv4Addr::from(octets))),
        IpLiteral::V6(octets) => {
            let mut groups = [0u16; 8];
            for (group, pair) in groups.iter_mut().zip(octets.chunks_exact(2)) {
                *group = pair.iter().fold(0u16, |value, byte| (value << 8) | u16::from(*byte));
            }
            ServerName::IpAddress(IpAddr::V6(Ipv6Addr::from(groups)))
        }
    }
}
