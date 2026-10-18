//! HE-004C DESIGN-C sections 7.2 and 8.1 (Q-HE4C-6 (a), Q-HE4C-8 (a)): the `/metrics` exposition reader: the ADM-4
//! sample's label set, escapes, the value `1`, no timestamp, repeated label sets, more than 16 samples, a line over
//! 16 KiB, the raw total over 64 MiB, a final line without LF, and the restart marker's forms.

use planeon_observer::admission::{MetricSample, METRIC_NAME};
use planeon_observer::exposition::{Exposition, ExpositionError, ExpositionReader, LINE_LIMIT, SAMPLE_LIMIT, START_TIME};
use planeon_observer::http::{Bounds, Progress, Refusal, StreamReader, METRICS_RAW_LIMIT};

const HASH: &str = "sha256:5aa2cdec00000000000000000000000000000000000000000000000000000000";

fn read(text: &str) -> Result<Exposition, ExpositionError> {
    let mut reader = ExpositionReader::new();
    reader.push(text.as_bytes())?;
    reader.finish()
}

/// The same text pushed one byte at a time.
fn read_bytewise(text: &str) -> Result<Exposition, ExpositionError> {
    let mut reader = ExpositionReader::new();
    for byte in text.as_bytes() {
        reader.push(std::slice::from_ref(byte))?;
    }
    reader.finish()
}

fn adm4(labels: &str) -> String {
    format!("{METRIC_NAME}{{{labels}}} 1\n")
}

fn good_labels() -> String {
    format!(r#"plugin="planeon",apiserver_id_hash="sha256:aa",hash="{HASH}""#)
}

#[test]
fn the_two_kept_metrics_and_everything_else_skipped() {
    let text = format!("# HELP {START_TIME} Start.\n# TYPE {START_TIME} gauge\n{START_TIME} 1.7801920e+09\n\
                        apiserver_request_total{{code=\"200\"}} 12\n{METRIC_NAME}_other{{x=\"y\"}} 3 1234\n\n{}",
                       adm4(&good_labels()));
    let exposition = read(&text).expect("a good exposition");
    assert_eq!(exposition.marker(), Ok("1.7801920e+09"));
    assert_eq!(exposition.samples, vec![MetricSample { plugin: "planeon".to_string(), apiserver_id_hash: "sha256:aa".to_string(),
                                                       hash: HASH.to_string() }]);
    assert_eq!(read_bytewise(&text), Ok(exposition));
    assert_eq!(START_TIME, "process_start_time_seconds");
}

#[test]
fn the_adm4_label_set_is_exactly_plugin_apiserver_id_hash_and_hash() {
    // Any order, each label once.
    let order = format!(r#"hash="{HASH}",plugin="p",apiserver_id_hash="h""#);
    assert_eq!(read(&adm4(&order)).expect("good").samples[0].plugin, "p");
    for labels in [r#"plugin="p",hash="x""#.to_string(), format!(r#"{},extra="e""#, good_labels()),
                   format!(r#"{},plugin="q""#, good_labels()), r#"plugin="p",apiserver_id_hash="h",hash="x","#.to_string(),
                   r#"plugin=p,apiserver_id_hash="h",hash="x""#.to_string(), r#" plugin="p",apiserver_id_hash="h",hash="x""#.to_string(),
                   r#"plugin="p" ,apiserver_id_hash="h",hash="x""#.to_string(), r#"plugin="p,apiserver_id_hash="h",hash="x""#.to_string()] {
        assert!(matches!(read(&adm4(&labels)), Err(ExpositionError::Malformed(_))), "{labels}");
    }
    assert!(matches!(read(&format!("{METRIC_NAME} 1\n")), Err(ExpositionError::Malformed(_))));
    assert!(matches!(read(&format!("{METRIC_NAME}{{{}\n", good_labels())), Err(ExpositionError::Malformed(_))));
}

#[test]
fn label_values_are_decoded_for_three_escapes_and_must_be_utf8() {
    let labels = r#"plugin="a\\b\"c\nd",apiserver_id_hash="h",hash="x""#;
    assert_eq!(read(&adm4(labels)).expect("good").samples[0].plugin, "a\\b\"c\nd");
    for bad in [r#"plugin="a\tb",apiserver_id_hash="h",hash="x""#, r#"plugin="a\x41",apiserver_id_hash="h",hash="x""#,
                r#"plugin="a\",apiserver_id_hash="h",hash="x""#] {
        assert!(matches!(read(&adm4(bad)), Err(ExpositionError::Malformed(_))), "{bad}");
    }
    let mut bytes = adm4(r#"plugin="X",apiserver_id_hash="h",hash="x""#).into_bytes();
    let at = bytes.iter().position(|byte| *byte == b'X').expect("X");
    bytes[at] = 0xff;
    let mut reader = ExpositionReader::new();
    assert!(matches!(reader.push(&bytes), Err(ExpositionError::Malformed(_))));
    // UTF-8 values pass.
    assert_eq!(read(&adm4(r#"plugin="pl\u{fc}g",apiserver_id_hash="h",hash="x""#).replace("\\u{fc}", "\u{fc}")).expect("good")
                   .samples[0].plugin, "pl\u{fc}g");
}

#[test]
fn the_value_is_exactly_1_without_a_timestamp() {
    let line = |value: &str| format!("{METRIC_NAME}{{{}}}{value}\n", good_labels());
    assert!(read(&line(" 1")).is_ok());
    assert!(read(&line("\t 1")).is_ok());
    for value in [" 0", " 1.0", " 2", " 1 1712345678000", " 1 ", "1", " +1", " ", ""] {
        assert!(matches!(read(&line(value)), Err(ExpositionError::Malformed(_))), "{value:?}");
    }
}

#[test]
fn repeated_label_sets_and_more_than_16_samples_refuse() {
    let one = adm4(&good_labels());
    assert_eq!(read(&format!("{one}{one}")), Err(ExpositionError::Repeated));
    let many: String = (0..SAMPLE_LIMIT).map(|index| adm4(&format!(r#"plugin="p{index}",apiserver_id_hash="h",hash="x""#))).collect();
    assert_eq!(read(&many).expect("16 samples").samples.len(), 16);
    let over = format!("{many}{START_TIME} 1\n");
    assert_eq!(read(&over), Err(ExpositionError::Samples));
    assert_eq!(SAMPLE_LIMIT, 16);
}

#[test]
fn a_line_over_16_kib_and_a_final_line_without_lf_refuse() {
    let comment = format!("# {}\n", "c".repeat(LINE_LIMIT - 2));
    assert!(read(&comment).is_ok(), "a 16 KiB line (the LF excluded) passes");
    let comment = format!("# {}\n", "c".repeat(LINE_LIMIT - 1));
    assert_eq!(read(&comment), Err(ExpositionError::LineLength));
    let other = format!("other_metric {}\n", "9".repeat(LINE_LIMIT));
    assert_eq!(read(&other), Err(ExpositionError::LineLength), "the bound applies before the name is looked at");
    assert_eq!(read(&format!("{START_TIME} 1")), Err(ExpositionError::FinalLine));
    assert_eq!(read(""), Ok(Exposition::default()));
    // The first refusal sticks.
    let mut reader = ExpositionReader::new();
    assert!(reader.push(format!("{START_TIME} x\n").as_bytes()).is_err());
    assert!(reader.push(b"\n").is_err());
    assert!(reader.finish().is_err());
}

#[test]
fn the_raw_total_is_at_most_64_mib() {
    assert_eq!(METRICS_RAW_LIMIT, 64 << 20);
    let mut reader = StreamReader::new(Bounds::exposition());
    let mut out = Vec::new();
    let over = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", METRICS_RAW_LIMIT + 1);
    assert_eq!(reader.push(over.as_bytes(), &mut out), Progress::Refused(Refusal::Length));
    // Chunked: the raw framing counts too.
    let mut reader = StreamReader::new(Bounds::exposition());
    let mut sent = reader.push(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", &mut out);
    let chunk = format!("{:x}\r\n{}\r\n", 1 << 20, "#".repeat(1 << 20)).into_bytes();
    for _ in 0..64 {
        out.clear();
        sent = reader.push(&chunk, &mut out);
        if sent != Progress::NeedMore {
            break;
        }
    }
    assert_eq!(sent, Progress::Refused(Refusal::Size));
}

#[test]
fn the_restart_markers_forms() {
    for value in ["1712345678", "1.712345678e+09", "1712345678.5", "1.7E9", "0", "1e-3"] {
        let exposition = read(&format!("{START_TIME} {value}\n")).expect(value);
        assert_eq!(exposition.marker(), Ok(value));
    }
    for value in ["+Inf", "NaN", "-1", "1e", "1.", ".5", "abc", "1 1712345678000", "0x10", "1,5"] {
        assert!(matches!(read(&format!("{START_TIME} {value}\n")), Err(ExpositionError::Malformed(_))), "{value}");
    }
    assert!(matches!(read(&format!("{START_TIME}{{a=\"b\"}} 1\n")), Err(ExpositionError::Malformed(_))));
    assert!(matches!(read(&format!("{START_TIME}{{}} 1\n")), Err(ExpositionError::Malformed(_))));
    // Zero or several samples: no marker.
    assert_eq!(read("").expect("empty").marker(), Err(ExpositionError::Marker));
    assert_eq!(read(&format!("{START_TIME} 1\n{START_TIME} 1\n")).expect("two").marker(), Err(ExpositionError::Marker));
    // A longer name is another metric.
    assert_eq!(read(&format!("{START_TIME}_total 1\n")).expect("other").marker(), Err(ExpositionError::Marker));
}
