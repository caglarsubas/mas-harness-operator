//! Literal TCP authorities (HE-003B DESIGN §3.2): `a.b.c.d:port` or `[v6]:port`, parsed into an [`InetAddress`]. It
//! is the I04 listener's address parser, and it is there for HE-003C's literal upstream authorities. Portable, safe and
//! host-tested; no name is ever resolved.
//!
//! - IPv4: four decimal parts 0-255, without leading zeros (`0` itself is a part).
//! - IPv6 (RFC 4291 §2.2 text forms): hex groups of 1-4 digits, at most one `::`, an embedded IPv4 tail in the last
//!   32 bits allowed, no zone identifier.
//! - The port: decimal 1-65535, without sign or leading zero, always present.
//! - Nothing else: no names, no whitespace, at most 64 characters.

/// An IP address literal.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IpLiteral {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// A literal address and port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InetAddress {
    pub ip: IpLiteral,
    pub port: u16,
}

/// Why an authority was refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuthorityError {
    /// Empty, longer than 64 characters, or holding a character outside printable ASCII or a space.
    Text,
    /// Not `host:port` or `[v6]:port`.
    Form,
    /// The IPv4 literal.
    Ipv4,
    /// The IPv6 literal.
    Ipv6,
    /// The port.
    Port,
}

/// The longest authority accepted.
pub const AUTHORITY_LIMIT: usize = 64;

/// Parses a literal authority (see the module documentation).
pub fn parse_authority(text: &str) -> Result<InetAddress, AuthorityError> {
    if text.is_empty() || text.len() > AUTHORITY_LIMIT || !text.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(AuthorityError::Text);
    }
    if let Some(rest) = text.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or(AuthorityError::Form)?;
        let port = after.strip_prefix(':').ok_or(AuthorityError::Form)?;
        let ip = parse_ipv6(inner).ok_or(AuthorityError::Ipv6)?;
        return Ok(InetAddress { ip: IpLiteral::V6(ip), port: parse_port(port)? });
    }
    let (host, port) = text.split_once(':').ok_or(AuthorityError::Form)?;
    if port.contains(':') {
        return Err(AuthorityError::Form);
    }
    let ip = parse_ipv4(host).ok_or(AuthorityError::Ipv4)?;
    Ok(InetAddress { ip: IpLiteral::V4(ip), port: parse_port(port)? })
}

/// Decimal 1-65535, without sign or leading zero.
fn parse_port(text: &str) -> Result<u16, AuthorityError> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|byte| byte.is_ascii_digit()) || text.starts_with('0') {
        return Err(AuthorityError::Port);
    }
    match text.parse::<u32>() {
        Ok(value) if (1..=65_535).contains(&value) => u16::try_from(value).map_err(|_| AuthorityError::Port),
        _ => Err(AuthorityError::Port),
    }
}

/// Four decimal parts 0-255 without leading zeros.
pub fn parse_ipv4(text: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in octets.iter_mut() {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        *octet = u8::try_from(part.parse::<u16>().ok()?).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// The 16-bit groups of one side of an IPv6 literal (`None` for a malformed side); `tail` allows an IPv4 tail as the
/// last element, counted as two groups.
fn groups(text: &str, tail: bool) -> Option<Vec<u16>> {
    if text.is_empty() {
        return Some(Vec::new());
    }
    let pieces: Vec<&str> = text.split(':').collect();
    let mut out = Vec::new();
    for (index, piece) in pieces.iter().enumerate() {
        if tail && index + 1 == pieces.len() && piece.contains('.') {
            let [a, b, c, d] = parse_ipv4(piece)?;
            out.push(u16::from_be_bytes([a, b]));
            out.push(u16::from_be_bytes([c, d]));
            continue;
        }
        if piece.is_empty() || piece.len() > 4 || !piece.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u16::from_str_radix(piece, 16).ok()?);
    }
    Some(out)
}

/// An IPv6 literal in an RFC 4291 §2.2 text form, without a zone identifier.
pub fn parse_ipv6(text: &str) -> Option<[u8; 16]> {
    let words: Vec<u16> = match text.split_once("::") {
        Some((head, tail)) => {
            if tail.contains("::") {
                return None;
            }
            let head = groups(head, false)?;
            let tail = groups(tail, true)?;
            if head.len() + tail.len() > 7 {
                return None;
            }
            let mut words = head;
            words.resize(8 - tail.len(), 0);
            words.extend(tail);
            words
        }
        None => {
            let words = groups(text, true)?;
            if words.len() != 8 {
                return None;
            }
            words
        }
    };
    let mut bytes = [0u8; 16];
    for (pair, word) in bytes.chunks_exact_mut(2).zip(words) {
        pair.copy_from_slice(&word.to_be_bytes());
    }
    Some(bytes)
}
