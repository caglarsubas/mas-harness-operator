//! The `/metrics` exposition reader (HE-004C DESIGN-C sections 7.2 and 8.1, Q-HE4C-6 (a), Q-HE4C-8 (a); MODEL_DEFINED
//! R112 and R113): a streaming line parser that keeps only two metric names, so a full exposition never sits in memory.
//!
//! - Lines are LF-terminated, each at most 16 KiB (the LF excluded); a final line without LF refuses.
//! - `#` lines and other names are skipped after the length check. The name is the text up to `{`, a space or a tab.
//! - `apiserver_manifest_admission_config_controller_last_config_info` (B1's `METRIC_NAME`): exactly the label set
//!   {`plugin`, `apiserver_id_hash`, `hash`} in any order, each label once; values decoded for `\\`, `\"` and `\n` and
//!   valid UTF-8; then the value text exactly `1` (an info gauge) and no timestamp. A repeated label set refuses.
//!   Every sample goes to B1 unfiltered, so B1's rules decide (a foreign plugin's sample gives UNAVAILABLE).
//! - `process_start_time_seconds`: unlabelled, a decimal number (digits, an optional fraction, an optional exponent)
//!   and no timestamp; its exact text is the restart marker. Zero or several samples refuse ([`Exposition::marker`]).
//! - At most 16 kept samples in all.
//!
//! The exposition's content type and line forms are T04 and W03 distribution check items.

use crate::admission::{MetricSample, METRIC_NAME};

/// The restart marker's metric.
pub const START_TIME: &str = "process_start_time_seconds";
/// An exposition line's bound (16 KiB, the LF excluded).
pub const LINE_LIMIT: usize = 16 << 10;
/// The kept samples of one exposition, at most.
pub const SAMPLE_LIMIT: usize = 16;

/// Why an exposition is refused (status 84).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpositionError {
    /// A line over 16 KiB.
    LineLength,
    /// The last line has no LF.
    FinalLine,
    /// More than 16 kept samples.
    Samples,
    /// Two ADM-4 samples with one label set.
    Repeated,
    /// A kept line outside its form.
    Malformed(&'static str),
    /// Zero or several restart-marker samples.
    Marker,
}

/// The kept samples of one exposition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exposition {
    /// The exact value texts of `process_start_time_seconds`.
    pub markers: Vec<String>,
    /// Every ADM-4 sample, unfiltered.
    pub samples: Vec<MetricSample>,
}

impl Exposition {
    /// The restart marker: the one start-time sample's text.
    pub fn marker(&self) -> Result<&str, ExpositionError> {
        match self.markers.as_slice() {
            [one] => Ok(one.as_str()),
            _ => Err(ExpositionError::Marker),
        }
    }
}

/// The streaming reader.
#[derive(Debug, Default)]
pub struct ExpositionReader {
    held: Vec<u8>,
    kept: Exposition,
    failed: Option<ExpositionError>,
}

/// The value text of a sample: one or more spaces or tabs, then the value, then the end of the line.
fn value_text(rest: &[u8]) -> Result<&[u8], ExpositionError> {
    let start = rest.iter().position(|byte| *byte != b' ' && *byte != b'\t').unwrap_or(rest.len());
    if start == 0 {
        return Err(ExpositionError::Malformed("no space before a sample's value"));
    }
    let value = rest.get(start..).unwrap_or(&[]);
    if value.is_empty() {
        return Err(ExpositionError::Malformed("a sample without a value"));
    }
    if value.iter().any(|byte| *byte == b' ' || *byte == b'\t') {
        return Err(ExpositionError::Malformed("a sample with a timestamp or trailing text"));
    }
    Ok(value)
}

/// A decimal number: digits, an optional fraction of digits, an optional exponent `e` or `E` with an optional sign.
fn is_decimal_number(text: &[u8]) -> bool {
    let digits = |bytes: &[u8]| !bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit);
    let (mantissa, exponent) = match text.iter().position(|byte| *byte == b'e' || *byte == b'E') {
        Some(at) => (text.get(..at).unwrap_or(&[]), Some(text.get(at.saturating_add(1)..).unwrap_or(&[]))),
        None => (text, None),
    };
    let mantissa_ok = match mantissa.iter().position(|byte| *byte == b'.') {
        Some(at) => digits(mantissa.get(..at).unwrap_or(&[])) && digits(mantissa.get(at.saturating_add(1)..).unwrap_or(&[])),
        None => digits(mantissa),
    };
    let exponent_ok = exponent.is_none_or(|exponent| {
        let unsigned = exponent.strip_prefix(b"+").or_else(|| exponent.strip_prefix(b"-")).unwrap_or(exponent);
        digits(unsigned)
    });
    mantissa_ok && exponent_ok
}

/// The label set of an ADM-4 sample, from just after `{`: the three labels and the rest after `}`.
fn labels(text: &[u8]) -> Result<(MetricSample, &[u8]), ExpositionError> {
    let mut plugin = None;
    let mut apiserver = None;
    let mut hash = None;
    let mut at = 0usize;
    loop {
        let rest = text.get(at..).unwrap_or(&[]);
        let name_end = rest.iter().position(|byte| *byte == b'=').ok_or(ExpositionError::Malformed("a label without ="))?;
        let name = rest.get(..name_end).unwrap_or(&[]);
        let after = rest.get(name_end.saturating_add(1)..).unwrap_or(&[]);
        let quoted = after.strip_prefix(b"\"").ok_or(ExpositionError::Malformed("a label value without quotes"))?;
        let mut value = Vec::new();
        let mut index = 0usize;
        let closed = loop {
            match quoted.get(index) {
                None => break None,
                Some(b'"') => break Some(index),
                Some(b'\\') => {
                    let escaped = match quoted.get(index.saturating_add(1)) {
                        Some(b'\\') => b'\\',
                        Some(b'"') => b'"',
                        Some(b'n') => b'\n',
                        _ => return Err(ExpositionError::Malformed("a label value with another escape")),
                    };
                    value.push(escaped);
                    index = index.saturating_add(2);
                }
                Some(byte) => {
                    value.push(*byte);
                    index = index.saturating_add(1);
                }
            }
        };
        let close = closed.ok_or(ExpositionError::Malformed("an unterminated label value"))?;
        let value = String::from_utf8(value).map_err(|_| ExpositionError::Malformed("a label value is not UTF-8"))?;
        let slot = match name {
            b"plugin" => &mut plugin,
            b"apiserver_id_hash" => &mut apiserver,
            b"hash" => &mut hash,
            _ => return Err(ExpositionError::Malformed("a label outside plugin, apiserver_id_hash and hash")),
        };
        if slot.is_some() {
            return Err(ExpositionError::Malformed("a label given twice"));
        }
        *slot = Some(value);
        // After the closing quote: `,` and the next label, or `}`.
        let consumed = name_end.saturating_add(2).saturating_add(close).saturating_add(1);
        at = at.saturating_add(consumed);
        match text.get(at) {
            Some(b',') => at = at.saturating_add(1),
            Some(b'}') => {
                let rest = text.get(at.saturating_add(1)..).unwrap_or(&[]);
                return match (plugin, apiserver, hash) {
                    (Some(plugin), Some(apiserver_id_hash), Some(hash)) => {
                        Ok((MetricSample { plugin, apiserver_id_hash, hash }, rest))
                    }
                    _ => Err(ExpositionError::Malformed("a label set without plugin, apiserver_id_hash and hash")),
                };
            }
            _ => return Err(ExpositionError::Malformed("a label set outside its form")),
        }
    }
}

impl ExpositionReader {
    pub fn new() -> ExpositionReader {
        ExpositionReader::default()
    }

    fn keep(&mut self) -> Result<(), ExpositionError> {
        if self.kept.markers.len().saturating_add(self.kept.samples.len()) >= SAMPLE_LIMIT {
            return Err(ExpositionError::Samples);
        }
        Ok(())
    }

    /// One complete line (without its LF).
    fn line(&mut self, line: &[u8]) -> Result<(), ExpositionError> {
        if line.first() == Some(&b'#') {
            return Ok(());
        }
        let name_end = line.iter().position(|byte| matches!(byte, b'{' | b' ' | b'\t')).unwrap_or(line.len());
        let name = line.get(..name_end).unwrap_or(&[]);
        let rest = line.get(name_end..).unwrap_or(&[]);
        if name == METRIC_NAME.as_bytes() {
            let inside = rest.strip_prefix(b"{").ok_or(ExpositionError::Malformed("an ADM-4 sample without labels"))?;
            let (sample, after) = labels(inside)?;
            if value_text(after)? != b"1" {
                return Err(ExpositionError::Malformed("an ADM-4 sample whose value is not 1"));
            }
            self.keep()?;
            if self.kept.samples.contains(&sample) {
                return Err(ExpositionError::Repeated);
            }
            self.kept.samples.push(sample);
        } else if name == START_TIME.as_bytes() {
            if rest.first() == Some(&b'{') {
                return Err(ExpositionError::Malformed("a labelled restart-marker sample"));
            }
            let value = value_text(rest)?;
            if !is_decimal_number(value) {
                return Err(ExpositionError::Malformed("a restart-marker value that is not a decimal number"));
            }
            self.keep()?;
            let text = String::from_utf8(value.to_vec()).map_err(|_| ExpositionError::Malformed("not UTF-8"))?;
            self.kept.markers.push(text);
        }
        Ok(())
    }

    /// Feeds decoded bytes; the first refusal sticks.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ExpositionError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let (body, ended) = match part.strip_suffix(b"\n") {
                Some(body) => (body, true),
                None => (part, false),
            };
            if self.held.len().saturating_add(body.len()) > LINE_LIMIT {
                self.failed = Some(ExpositionError::LineLength);
                return Err(ExpositionError::LineLength);
            }
            self.held.extend_from_slice(body);
            if ended {
                let line = std::mem::take(&mut self.held);
                if let Err(error) = self.line(&line) {
                    self.failed = Some(error);
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// The exposition at the answer's end: a final line without LF refuses.
    pub fn finish(self) -> Result<Exposition, ExpositionError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if !self.held.is_empty() {
            return Err(ExpositionError::FinalLine);
        }
        Ok(self.kept)
    }
}
