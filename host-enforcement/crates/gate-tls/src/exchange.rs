//! The exchange board (HE-003B DESIGN §7.5; MODEL_DEFINED R53), shared as `Rc<RefCell<Exchange>>` by the I04 port and
//! HE-003C's upstream port. At most one request and one response are staged at a time (one exchange, I05 Decision 2).
//!
//! - The request is staged by the I04 port when it returns `Request`, confirmed with the `Forward`'s action ID, and
//!   dropped on `Close`. The upstream port takes it only when it is confirmed with its own `Forward`'s action ID.
//! - The response is staged only through [`Exchange::stage_response`], which computes the body digest and builds the
//!   upstream event from the same status, digest, UID and resourceVersion, so the values the model journals are those
//!   of the bytes the I04 port relays. Every `Upstream` output and `LateUpstream` remove it.

use std::cell::RefCell;
use std::rc::Rc;

use effect_gate::{Event, PolicyEvent, UpstreamResponse};
use i05_protocol::sha256;

use crate::http1::RESPONSE_BODY_LIMIT;

/// The request the I04 port read, exactly as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedRequest {
    pub conn: String,
    pub head: String,
    pub body: Vec<u8>,
    /// The action ID of the `Forward` that admitted it, once confirmed.
    pub forwarded: Option<u16>,
}

/// The upstream response the I04 port relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedResponse {
    pub conn: String,
    pub status: u16,
    pub body: Vec<u8>,
    /// `sha256:<hex>` of `body`, computed by [`Exchange::stage_response`].
    pub body_digest: String,
    pub uid: Option<String>,
    pub resource_version: Option<String>,
}

/// Why the board refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BoardError {
    /// The slot holds an earlier request or response.
    Occupied,
    /// A status outside 200-599.
    Status,
    /// A body over 4 MiB.
    Size,
}

/// The board.
#[derive(Debug, Default)]
pub struct Exchange {
    request: Option<StagedRequest>,
    response: Option<StagedResponse>,
}

/// The board, shared by the two ports.
pub type SharedExchange = Rc<RefCell<Exchange>>;

impl Exchange {
    pub fn shared() -> SharedExchange {
        Rc::new(RefCell::new(Exchange::default()))
    }

    /// Stages the request the I04 port is returning; an occupied slot refuses.
    pub fn stage_request(&mut self, conn: &str, head: &str, body: &[u8]) -> Result<(), BoardError> {
        if self.request.is_some() {
            return Err(BoardError::Occupied);
        }
        self.request = Some(StagedRequest { conn: conn.to_string(), head: head.to_string(), body: body.to_vec(),
                                            forwarded: None });
        Ok(())
    }

    /// Confirms the staged request of `conn` with the `Forward`'s action ID; false when none is staged for it.
    pub fn confirm_request(&mut self, conn: &str, action_id: u16) -> bool {
        match self.request.as_mut() {
            Some(request) if request.conn == conn && request.forwarded.is_none() => {
                request.forwarded = Some(action_id);
                true
            }
            _ => false,
        }
    }

    /// Drops the staged request (a `Close`).
    pub fn drop_request(&mut self) {
        self.request = None;
    }

    /// The staged request, read only.
    pub fn request(&self) -> Option<&StagedRequest> {
        self.request.as_ref()
    }

    /// Takes the staged request, only when it is confirmed with `action_id` (HE-003C's `apply(Forward)`, D2-4).
    pub fn take_request(&mut self, action_id: u16) -> Option<StagedRequest> {
        if self.request.as_ref().is_some_and(|request| request.forwarded == Some(action_id)) {
            return self.request.take();
        }
        None
    }

    /// The only way to stage a response: computes the body's digest, refuses an occupied slot, a status outside
    /// 200-599 and a body over 4 MiB, and returns the event HE-003C feeds, built from the same values.
    pub fn stage_response(&mut self, conn: &str, status: u16, body: Vec<u8>, uid: Option<String>,
                          resource_version: Option<String>) -> Result<PolicyEvent, BoardError> {
        if self.response.is_some() {
            return Err(BoardError::Occupied);
        }
        if !(200..=599).contains(&status) {
            return Err(BoardError::Status);
        }
        if body.len() > RESPONSE_BODY_LIMIT {
            return Err(BoardError::Size);
        }
        let body_digest = sha256::prefixed(&body);
        let response = UpstreamResponse { http_status: i64::from(status), body_digest: body_digest.clone(),
                                          uid: uid.clone(), resource_version: resource_version.clone() };
        self.response = Some(StagedResponse { conn: conn.to_string(), status, body, body_digest, uid, resource_version });
        Ok(PolicyEvent::Base(Event::UpstreamResponse { conn: conn.to_string(), response }))
    }

    /// Takes the staged response (the I04 port on `Upstream { relayed: true }`).
    pub fn take_response(&mut self) -> Option<StagedResponse> {
        self.response.take()
    }

    /// Drops the staged response.
    pub fn drop_response(&mut self) {
        self.response = None;
    }

    /// Whether a response is staged.
    pub fn has_response(&self) -> bool {
        self.response.is_some()
    }
}
