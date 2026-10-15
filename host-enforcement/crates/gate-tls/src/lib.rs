//! The effect gate's I04 server (HE-003B): the TLS 1.3 mutual server over the vendored rustls 0.23.46 with the ring
//! provider (`tls`), HTTP/1.1 request framing and response rendering (`http1`), the exchange board shared with HE-003C's
//! upstream port (`exchange`) and the I04 port in the channel substrate's loop (`i04`, generic over effect-gate's
//! `StreamNet`). Safe Rust only (the root forbids `unsafe_code`), no panics on any input; `tools/gate.py` holds its
//! sources to the linked-crate tripwires, the TLS deny-list and the exact-settings rule.
//!
//! Behaviour defined here rather than by a pinned model is listed in effect-gate's `MODEL_DEFINED.md` (R43-R58).
#![forbid(unsafe_code)]

pub mod exchange;
pub mod http1;
pub mod i04;
pub mod tls;

pub use exchange::{BoardError, Exchange, SharedExchange, StagedRequest, StagedResponse};
pub use http1::{frame, render_response, Frame, RenderRefusal, BODY_LIMIT, HEAD_LIMIT, RESPONSE_BODY_LIMIT};
pub use i04::{I04Server, ACCEPTS_PER_READY, CONNECTION_CAP, DRAIN_LIMIT, PHASE_DEADLINE, READ_BUDGET};
pub use tls::{certificate_digest, server_config, TlsServerInputs, TlsSetupError, ALPN_HTTP11};
