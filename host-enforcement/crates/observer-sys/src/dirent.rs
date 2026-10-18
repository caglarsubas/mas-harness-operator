//! The parser of a `getdents64` record buffer (HE-004D1 DESIGN-D1 section 4.3), portable and host-tested on byte
//! buffers. A record is `struct linux_dirent64`: `d_ino` (u64) at 0, `d_off` (i64) at 8, `d_reclen` (u16) at 16,
//! `d_type` (u8) at 18 and the NUL-terminated `d_name` from 19, padded to `d_reclen` (the vendored libc 0.2.190's
//! `linux_l4re_shared.rs`); `DT_DIR` is 4 (its `unix/mod.rs`). Native byte order: both musl targets are little-endian.
//!
//! At offset `o` a record needs `o + 19 < len`, a `d_reclen` of at least 24, a multiple of 8, with `o + d_reclen <= len`,
//! a NUL inside the record, and a name of 1 to 255 bytes without `/` that is UTF-8 text. `.` and `..` are skipped. Any
//! violation refuses the whole buffer: nothing partial is returned (D1-4).

/// A directory entry's type for a directory.
pub const DT_DIR: u8 = 4;

/// Where `d_reclen`, `d_type` and `d_name` sit in a record.
const RECLEN_AT: usize = 16;
const TYPE_AT: usize = 18;
const NAME_AT: usize = 19;
/// The smallest record: the 19-byte head, one name byte and its NUL, padded to 8.
const MIN_RECORD: usize = 24;
/// The longest name (`NAME_MAX`).
const MAX_NAME: usize = 255;

/// Why a record buffer is refused.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DirentError {
    /// A record runs past the buffer or has a bad length.
    Length,
    /// A record has no NUL, or its name is empty, too long, holds `/` or is not UTF-8 text.
    Name,
}

/// The type name only, as every manual `Debug` of this crate prints (no type here derives `Debug`).
impl core::fmt::Debug for DirentError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.pad("DirentError")
    }
}

/// Every entry of `buffer` as `(d_type, name)`, in order, `.` and `..` skipped; any malformed record refuses.
pub fn entries(buffer: &[u8]) -> Result<Vec<(u8, String)>, DirentError> {
    let mut found = Vec::new();
    let mut offset = 0usize;
    while offset < buffer.len() {
        if offset.checked_add(NAME_AT).is_none_or(|head| head >= buffer.len()) {
            return Err(DirentError::Length);
        }
        let reclen = match buffer.get(offset + RECLEN_AT..offset + RECLEN_AT + 2) {
            Some(&[low, high]) => usize::from(u16::from_ne_bytes([low, high])),
            _ => return Err(DirentError::Length),
        };
        let end = offset.checked_add(reclen).ok_or(DirentError::Length)?;
        if reclen < MIN_RECORD || reclen % 8 != 0 || end > buffer.len() {
            return Err(DirentError::Length);
        }
        let kind = buffer.get(offset + TYPE_AT).copied().ok_or(DirentError::Length)?;
        let area = buffer.get(offset + NAME_AT..end).ok_or(DirentError::Length)?;
        let Some(length) = area.iter().position(|byte| *byte == 0) else { return Err(DirentError::Name) };
        let name = area.get(..length).ok_or(DirentError::Name)?;
        if name.is_empty() || name.len() > MAX_NAME || name.contains(&b'/') {
            return Err(DirentError::Name);
        }
        let text = std::str::from_utf8(name).map_err(|_| DirentError::Name)?;
        if text != "." && text != ".." {
            found.push((kind, text.to_string()));
        }
        offset = end;
    }
    Ok(found)
}
