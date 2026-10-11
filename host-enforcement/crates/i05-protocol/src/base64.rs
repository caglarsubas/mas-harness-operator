//! Strict base64 as Python `base64.b64decode(data, validate=True)` (CPython 3.12 `a2b_base64` strict mode): only the
//! standard alphabet, padding required to a multiple of four, at most two `=` and only at the end, nothing after the
//! padding; non-zero trailing bits are accepted (`QR==` decodes to `A`).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn sextet(byte: u8) -> Option<u32> {
    let value = match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(value))
}

/// Decodes `input` strictly; `None` when Python's strict decoder would raise.
pub fn decode_strict(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() % 4 != 0 {
        return None;
    }
    let padding = input.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let data = input.get(..input.len().saturating_sub(padding))?;
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 2);
    for chunk in data.chunks(4) {
        let mut accumulator = 0u32;
        for byte in chunk {
            accumulator = (accumulator << 6) | sextet(*byte)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(accumulator >> 16) as u8, (accumulator >> 8) as u8, accumulator as u8]),
            3 => out.extend_from_slice(&[(accumulator >> 10) as u8, (accumulator >> 2) as u8]),
            2 => out.push((accumulator >> 4) as u8),
            _ => return None,
        }
    }
    Some(out)
}

/// Standard padded base64.
pub fn encode(data: &[u8]) -> String {
    let symbol = |index: u32| char::from(ALPHABET[(index & 0x3F) as usize]);
    let mut out = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for chunk in data.chunks(3) {
        let mut accumulator = 0u32;
        for (position, byte) in chunk.iter().enumerate() {
            accumulator |= u32::from(*byte) << (16 - 8 * position as u32);
        }
        out.push(symbol(accumulator >> 18));
        out.push(symbol(accumulator >> 12));
        out.push(if chunk.len() > 1 { symbol(accumulator >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { symbol(accumulator) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_decoding_matches_python() {
        let accepted: [(&str, &[u8]); 9] = [("", b""), ("QQ==", b"A"), ("QR==", b"A"), ("QUI=", b"AB"), ("QUJ=", b"AB"),
            ("QUK=", b"AB"), ("QUJD", b"ABC"), ("QUJDRA==", b"ABCD"), ("+/==", b"\xfb")];
        for (text, raw) in accepted {
            assert_eq!(decode_strict(text.as_bytes()).as_deref(), Some(raw), "{text:?}");
        }
        for text in ["=", "==", "Q", "QQ", "QQ=", "QQ===", "QQ==QQ==", "QQ==Q", "Q===", "QUJD=", "QUJD==", "QU=D",
                     "QU JD", "QUJD\n", "Q=Q=", "=QQ=", "QQ=a", "AAAA====", "QUJDRA=", "QUJDRA", "QUJ\0D", "-_==",
                     "QQ\r\n=="] {
            assert_eq!(decode_strict(text.as_bytes()), None, "{text:?}");
        }
    }

    #[test]
    fn encoding_round_trips() {
        for length in 0..40usize {
            let data: Vec<u8> = (0..length).map(|n| (n * 37 % 256) as u8).collect();
            assert_eq!(decode_strict(encode(&data).as_bytes()), Some(data));
        }
        assert_eq!(encode(b"A"), "QQ==");
    }
}
