//! The effect gate's I04 server (HE-003B): the TLS 1.3 mutual server over the vendored rustls 0.23.46 with the ring
//! provider (`tls`), HTTP/1.1 request framing and response rendering (`http1`), the exchange board shared with HE-003C's
//! upstream port (`exchange`) and the I04 port in the channel substrate's loop (`i04`, generic over effect-gate's
//! `StreamNet`). Safe Rust only (the root forbids `unsafe_code`), no panics on any input; `tools/gate.py` holds its
//! sources to the linked-crate tripwires, the TLS deny-list and the exact-settings rule.
//!
//! HE-003D adds the gate binary's signed configuration read and Ed25519 check (`signed_config`, the only gate-tls
//! code `main` runs between the seal's two stages) and the credential reads after the seal (`credentials`), which hand
//! the binary its TLS inputs and rustls's default time provider.
//!
//! Behaviour defined here rather than by a pinned model is listed in effect-gate's `MODEL_DEFINED.md` (R43-R58, and
//! HE-003D's from R69).
#![forbid(unsafe_code)]

pub mod credentials;
pub mod exchange;
pub mod http1;
pub mod i04;
pub mod signed_config;
pub mod tls;
pub mod tls_client;
pub mod upstream;

pub use credentials::{client_identity, read_certificate, read_key, server_inputs, serving_roots, time_provider,
                      CredentialError, CredentialFile, KeyBytes};
pub use exchange::{is_resource_version, is_uid, write_response, BoardError, Exchange, SharedExchange, StagedRequest,
                   StagedResponse};
pub use http1::{frame, render_response, Frame, RenderRefusal, BODY_LIMIT, HEAD_LIMIT, RESPONSE_BODY_LIMIT};
pub use http1::{ResponseProgress, ResponseReader, ResponseRefusal, CHUNKED_RAW_LIMIT, INTERIM_LIMIT};
pub use i04::{I04Server, ACCEPTS_PER_READY, CONNECTION_CAP, DRAIN_LIMIT, PHASE_DEADLINE, READ_BUDGET};
pub use tls::{certificate_digest, server_config, TlsServerInputs, TlsSetupError, ALPN_HTTP11};
pub use tls_client::{client_config, server_name, TlsClientIdentity, TlsClientSetupError};
pub use upstream::{UpstreamClient, CONNECT_DEADLINE, HANDSHAKE_DEADLINE, UPSTREAM_BOUND, WRITE_BOUND};
