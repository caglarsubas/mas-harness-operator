//! I05 v3 effect-gate protocol logic (HE-002): the strict wire codec, the canonical encoder, SHA-256, strict base64, the
//! schema-subset interpreter and its pattern matcher, the outcome mapping with `check_agreement`, and the request
//! rendering (`render_request`, `template_digest`, `identity_of`). Std only, safe Rust (`unsafe_code` is forbidden
//! below), no panics on any input.
//!
//! The contract is harness-onion `a2eab93` (`host-enforcement/contracts/`); where its READMEs are silent the pinned
//! reference model is the specification, and every such point is listed in `crates/effect-gate/MODEL_DEFINED.md`.
#![forbid(unsafe_code)]

pub mod base64;
pub mod contracts;
pub mod frame;
pub mod json;
pub mod mapping;
pub mod regex;
pub mod render;
pub mod schema;
pub mod sha256;

pub use frame::{check_frame, decode_frame, Datagram, FrameError, MAX_DEPTH, MAX_FRAME_BYTES};
pub use json::{Doc, Value};
pub use mapping::{Identity, Mismatch, OutcomeMapping};
pub use render::{identity_of, outcome_is_final, render_request, template_digest, Kind, Manifest, RenderedRequest, Verb};
pub use schema::Schema;

/// The I05 v3 frame version.
pub const FRAME_VERSION: &str = "planeon.internal.effect-gate-frame/v3";

/// The all-zero previous digest of a channel's first frame.
pub const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The I05 v3 frame schema, loaded from the embedded contract.
pub fn i05_v3_schema() -> Result<Schema, schema::SchemaError> {
    Schema::from_json(contracts::I05_V3_SCHEMA)
}

/// The I07 v3 frame schema, loaded from the embedded contract.
pub fn i07_v3_schema() -> Result<Schema, schema::SchemaError> {
    Schema::from_json(contracts::I07_V3_SCHEMA)
}
