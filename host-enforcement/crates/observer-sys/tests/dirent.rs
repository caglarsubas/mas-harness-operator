//! HE-004D1 DESIGN-D1 sections 4.3 and 20: the `getdents64` record parser on byte buffers (portable, host-tested):
//! well-formed buffers, the length rules (`d_reclen` 0, unaligned, past the end), a record without its NUL, a name with
//! `/`, `.` and `..` skipped, and 255- and 256-byte names. Any violation refuses the whole buffer.

use observer_sys::dirent::{entries, DirentError, DT_DIR};

const DT_REG: u8 = 8;

/// One record: the 19-byte head, the name, its NUL, zero padding to a multiple of 8 (or `reclen` when given).
fn record(kind: u8, name: &[u8], reclen: Option<u16>) -> Vec<u8> {
    let natural = (19 + name.len() + 1).div_ceil(8) * 8;
    let length = reclen.map_or(natural, usize::from);
    let mut out = vec![0u8; 19];
    out[0..8].copy_from_slice(&7u64.to_ne_bytes());
    out[8..16].copy_from_slice(&1i64.to_ne_bytes());
    out[16..18].copy_from_slice(&(length as u16).to_ne_bytes());
    out[18] = kind;
    out.extend_from_slice(name);
    out.push(0);
    out.resize(length.max(out.len()), 0);
    out.truncate(length.max(19));
    out
}

fn buffer(records: &[Vec<u8>]) -> Vec<u8> {
    records.concat()
}

#[test]
fn well_formed_buffers_give_their_entries_in_order() {
    let parsed = entries(&buffer(&[
        record(DT_DIR, b".", None),
        record(DT_DIR, b"..", None),
        record(DT_DIR, b"1", None),
        record(DT_REG, b"cgroup.procs", None),
        record(DT_DIR, b"4096", None),
    ]))
    .expect("a well-formed buffer");
    assert_eq!(parsed, vec![(DT_DIR, "1".to_string()), (DT_REG, "cgroup.procs".to_string()), (DT_DIR, "4096".to_string())]);
    assert_eq!(entries(&[]).expect("an empty buffer"), Vec::new());
    assert_eq!(DT_DIR, 4);
}

#[test]
fn dot_and_dot_dot_are_skipped() {
    let parsed = entries(&buffer(&[record(DT_DIR, b".", None), record(DT_DIR, b"..", None)])).expect("only dots");
    assert!(parsed.is_empty());
    let parsed = entries(&record(DT_DIR, b"...", None)).expect("three dots are a name");
    assert_eq!(parsed, vec![(DT_DIR, "...".to_string())]);
}

#[test]
fn bad_record_lengths_refuse_the_whole_buffer() {
    let good = record(DT_DIR, b"12", None);
    for bad in [
        record(DT_DIR, b"12", Some(0)),
        record(DT_DIR, b"12", Some(23)),
        record(DT_DIR, b"12", Some(28)),
        record(DT_DIR, b"12", Some(16)),
    ] {
        assert_eq!(entries(&buffer(&[good.clone(), bad])), Err(DirentError::Length));
    }
    // A record whose length runs past the end of the buffer.
    let mut past = record(DT_DIR, b"12", None);
    past[16..18].copy_from_slice(&64u16.to_ne_bytes());
    assert_eq!(entries(&buffer(&[good.clone(), past])), Err(DirentError::Length));
    // A trailing fragment shorter than a record's head.
    let mut fragment = good.clone();
    fragment.extend_from_slice(&[0u8; 10]);
    assert_eq!(entries(&fragment), Err(DirentError::Length));
}

#[test]
fn names_without_nul_with_a_slash_empty_or_not_text_refuse() {
    let mut no_nul = record(DT_DIR, b"1234", None);
    for byte in no_nul.iter_mut().skip(19) {
        *byte = b'7';
    }
    assert_eq!(entries(&no_nul), Err(DirentError::Name));
    assert_eq!(entries(&record(DT_DIR, b"a/b", None)), Err(DirentError::Name));
    assert_eq!(entries(&record(DT_DIR, b"", None)), Err(DirentError::Name));
    assert_eq!(entries(&record(DT_DIR, &[0xff, 0xfe], None)), Err(DirentError::Name));
}

#[test]
fn a_255_byte_name_passes_and_a_256_byte_name_refuses() {
    let long = vec![b'x'; 255];
    let parsed = entries(&record(DT_REG, &long, None)).expect("a 255-byte name");
    assert_eq!(parsed, vec![(DT_REG, "x".repeat(255))]);
    assert_eq!(entries(&record(DT_REG, &vec![b'x'; 256], None)), Err(DirentError::Name));
}
