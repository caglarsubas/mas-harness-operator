//! The frame pipeline (DESIGN §5). `decode_frame` checks bytes as received: a byte string (F07) of at most 16 KiB
//! (F02), UTF-8 over the whole datagram (F06), parsed with the first error in document order winning (F03 for a refused
//! constant, F05 for a duplicate key when its object closes, F06 otherwise), re-encoded canonically and compared byte
//! for byte (F06), then `check_frame`. `check_frame` checks a value: depth at most 16 (F01) first, then no float
//! (F03), no C0 control character or DEL in any string or member name (F04), the closed schema (F00) and the canonical
//! size (F02).

use crate::json::{self, ParseError, Value};
use crate::schema::Schema;

pub const MAX_FRAME_BYTES: usize = 16384;
pub const MAX_DEPTH: usize = 16;

/// A received datagram. Production callers always pass bytes; `NotBytes` stands for the vectors' bytearray and text
/// inputs (B12, B13), which the pinned decoder refuses by type.
#[derive(Clone, Copy, Debug)]
pub enum Datagram<'a> {
    Bytes(&'a [u8]),
    NotBytes,
}

/// The frame refusal codes, in the contract's wording.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    F00,
    F01,
    F02,
    F03,
    F04,
    F05,
    F06,
    F07,
}

impl FrameError {
    pub fn code(self) -> &'static str {
        match self {
            FrameError::F00 => "F00",
            FrameError::F01 => "F01",
            FrameError::F02 => "F02",
            FrameError::F03 => "F03",
            FrameError::F04 => "F04",
            FrameError::F05 => "F05",
            FrameError::F06 => "F06",
            FrameError::F07 => "F07",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            FrameError::F00 => "F00 frame outside the closed schema",
            FrameError::F01 => "F01 frame deeper than 16",
            FrameError::F02 => "F02 frame larger than 16 KiB",
            FrameError::F03 => "F03 frame contains a non-integer number",
            FrameError::F04 => "F04 frame string contains a control character",
            FrameError::F05 => "F05 duplicate key",
            FrameError::F06 => "F06 frame is not canonical JSON",
            FrameError::F07 => "F07 frame is not a byte string",
        }
    }
}

/// Decodes one received datagram into a frame value.
pub fn decode_frame(datagram: Datagram<'_>, schema: &Schema) -> Result<Value, FrameError> {
    let raw = match datagram {
        Datagram::Bytes(raw) => raw,
        Datagram::NotBytes => return Err(FrameError::F07),
    };
    if raw.len() > MAX_FRAME_BYTES {
        return Err(FrameError::F02);
    }
    let text = std::str::from_utf8(raw).map_err(|_| FrameError::F06)?;
    let frame = json::parse(text).map_err(|error| match error {
        ParseError::Constant => FrameError::F03,
        ParseError::Duplicate => FrameError::F05,
        ParseError::Syntax => FrameError::F06,
    })?;
    let encoded = json::canonical(&frame).map_err(|_| FrameError::F06)?;
    if encoded != raw {
        return Err(FrameError::F06);
    }
    // The bytes are canonical and at most 16 KiB, so check_frame's size step holds.
    check_structure(&frame, schema)?;
    Ok(frame)
}

/// Checks one frame value.
pub fn check_frame(frame: &Value, schema: &Schema) -> Result<(), FrameError> {
    check_frame_encoded(frame, schema).map(|_| ())
}

/// `check_frame`, returning the canonical bytes it measured (the bytes the next frame's `previousDigest` covers).
pub fn check_frame_encoded(frame: &Value, schema: &Schema) -> Result<Vec<u8>, FrameError> {
    check_structure(frame, schema)?;
    // A schema-valid frame always has a canonical encoding (its strings are ASCII by pattern or constant and floats
    // are refused above); if one ever had none, it is refused as not canonical (R10-defined, unreachable).
    let encoded = json::canonical(frame).map_err(|_| FrameError::F06)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(FrameError::F02);
    }
    Ok(encoded)
}

fn check_structure(frame: &Value, schema: &Schema) -> Result<(), FrameError> {
    if json::depth(frame) > MAX_DEPTH {
        return Err(FrameError::F01);
    }
    if json::contains_float(frame) {
        return Err(FrameError::F03);
    }
    if json::contains_control(frame) {
        return Err(FrameError::F04);
    }
    if !schema.is_valid(frame) {
        return Err(FrameError::F00);
    }
    Ok(())
}
