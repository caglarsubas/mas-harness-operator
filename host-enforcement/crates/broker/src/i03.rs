//! I03, the broker's START to the original worker (HE-005B: DESIGN-HE005 revision 5 sections 1 (O13, O21) and 3.3
//! step 9; the HE-005B plan's item 3; MON-HE005B-PLAN, Q-HE5B-4 (a)). A logic module: pure (no I/O, no system call,
//! safe Rust only), no panic, std only, i05-protocol's public json items and i02.rs's schemas and decode. Nothing in
//! `main`, `serve`, `seal.rs`, `status.rs` or `linux_listen.rs` names it, so planeon-broker's behaviour stays HE-005A's
//! (G-HE5B-1).
//!
//! [`start`] builds the worker's one START frame (`$defs/workerStart` of the vendored broker handoff schema):
//! `planeon.internal.broker-worker/v1`, operation START, and the closed execution, binding, case, request and
//! generation identifiers, nothing else (the readiness guide: START "carries only the closed
//! execution/case/binding/request/generation identifiers"). It is canonical, at most 16 KiB (O21) and checked against
//! `$defs/workerStart` before it is returned. It is built only from a checked DISPATCH ([`Dispatch`]), so its binding
//! has passed Q-HE5B-2's check, and nothing in it selects a file, a uid or an executable.
//!
//! The worker's own leg on FD3 is not registered: edge record v12 registers only the broker's START. A registered shape
//! for that leg is queued with R00 as a prerequisite of HE-005D (Q-HE5B-4 (a)), so this module builds START only. When
//! START is queued (directly after W4's thaw, section 3.3 step 9) is HE-005C's and HE-005D's.

use i05_protocol::json::{self, JStr, Object, Value};
use i05_protocol::FrameError;

use crate::i02::{decode_datagram, Dispatch, Schemas, MAX_CONTROL_BYTES};

/// START's registered schema version and operation.
pub const START_VERSION: &str = "planeon.internal.broker-worker/v1";
pub const START_OPERATION: &str = "START";

/// The DISPATCH fields START carries beside the broker's execution id.
pub const START_FIELDS: [&str; 4] = ["bindingDigest", "caseId", "requestDigest", "generation"];

/// The START frame for a checked DISPATCH and the broker's execution id (64 lowercase hexadecimal digits): canonical,
/// at most 16 KiB and valid under `$defs/workerStart`, or the refusal its check gives.
pub fn start(dispatch: &Dispatch, execution_id: &str, schemas: &Schemas) -> Result<Vec<u8>, FrameError> {
    let mut frame = Object::new();
    frame.insert(JStr::new("schemaVersion"), Value::str(START_VERSION));
    frame.insert(JStr::new("operation"), Value::str(START_OPERATION));
    frame.insert(JStr::new("executionId"), Value::str(execution_id));
    for name in START_FIELDS {
        let value = dispatch.echo().get(name).ok_or(FrameError::F00)?;
        frame.insert(JStr::new(name), Value::str(value));
    }
    let raw = json::canonical(&Value::Object(frame)).map_err(|_| FrameError::F06)?;
    let _checked = decode_datagram(&raw, MAX_CONTROL_BYTES, schemas.worker_start())?;
    Ok(raw)
}
