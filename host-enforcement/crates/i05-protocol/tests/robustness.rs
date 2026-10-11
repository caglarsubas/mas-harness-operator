//! No panics and no stack overflow on any input: seeded pseudo-random datagrams, texts, agreement inputs and deeply
//! nested values through the decoder, the parser, agreement mode and the schema interpreter.

use i05_protocol::json::{self, Value};
use i05_protocol::{base64, decode_frame, Datagram, Identity, Kind, OutcomeMapping, Verb};

/// xorshift64*, seeded: deterministic test inputs without a crate.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const PIECES: [&[u8]; 34] = [b" ", b"\"", b"\\", b",", b":", b"{", b"}", b"[", b"]", b"0", b"1", b"-", b".", b"e", b"E",
    b"+", b"N", b"\x7f", b"\x1f", b"\n", b"\xff", b"\xc3\xa9", b"\\u0041", b"\\ud800", b"\\n", b"\\u007f", b"NaN",
    b"Infinity", b"1.0", b"1e+16", b"-0", b"\t", b"\xed\xa0\x80", b"\xf0\x9f\x98\x80"];

fn base_frame() -> Vec<u8> {
    let text = format!("{{\"challenge\":\"{}\",\"direction\":\"BROKER_TO_GATE\",\"generation\":\"{}\",\"operation\":\
                        \"GENERATION_STATUS\",\"payload\":{{}},\"previousDigest\":\"sha256:{}\",\"schemaVersion\":\
                        \"planeon.internal.effect-gate-frame/v3\",\"sequence\":1}}",
                       "c".repeat(64), "a".repeat(64), "0".repeat(64));
    text.into_bytes()
}

fn mutate(rng: &mut Rng, raw: &[u8]) -> Vec<u8> {
    let mut out = raw.to_vec();
    for _ in 0..=rng.below(4) {
        let position = rng.below(out.len() + 1);
        let piece = rng.pick(&PIECES);
        match rng.below(3) {
            0 => out.splice(position..position, piece.iter().copied()).for_each(drop),
            1 => {
                let end = (position + 1 + rng.below(3)).min(out.len());
                out.drain(position..end);
            }
            _ => {
                let end = (position + piece.len()).min(out.len());
                out.splice(position..end, piece.iter().copied()).for_each(drop);
            }
        }
    }
    out
}

#[test]
fn decoder_and_parser_never_panic() {
    let schema = i05_protocol::i05_v3_schema().expect("schema");
    let base = base_frame();
    assert!(decode_frame(Datagram::Bytes(&base), &schema).is_ok());
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let raw = if rng.below(4) == 0 {
            (0..rng.below(64)).flat_map(|_| rng.pick(&PIECES).to_vec()).collect()
        } else {
            mutate(&mut rng, &base)
        };
        let _ = decode_frame(Datagram::Bytes(&raw), &schema);
        if let Ok(text) = std::str::from_utf8(&raw) {
            if let Ok(value) = json::parse(text) {
                let _ = json::canonical(&value);
                let _ = i05_protocol::check_frame(&value, &schema);
            }
        }
    }
}

#[test]
fn deep_inputs_never_overflow_the_stack() {
    let schema = i05_protocol::i05_v3_schema().expect("schema");
    for (open, close) in [("[", "]"), ("{\"a\":", "}")] {
        let within = format!("{}{}", open.repeat(8192 / open.len().max(1)), close.repeat(8192 / open.len().max(1)));
        let raw = within.as_bytes();
        let raw = &raw[..raw.len().min(16384)];
        let _ = decode_frame(Datagram::Bytes(raw), &schema);
        let huge = format!("{}1{}", open.repeat(200_000), close.repeat(200_000));
        let value = json::parse(&huge).expect("deep but valid");
        assert_eq!(json::depth(&value), 200_000);
        assert!(i05_protocol::check_frame(&value, &schema).is_err());
        assert!(!schema.is_valid(&value));
        assert!(json::canonical(&value).is_ok());
        assert!(json::json_eq(&value, &value) && json::py_eq(&value, &value) && json::schema_eq(&value, &value));
        let encoded = Value::str(&base64::encode(huge.as_bytes()));
        assert!(i05_protocol::mapping::decode_object(&encoded).is_none());
        drop(value);
    }
}

#[test]
fn agreement_never_panics() {
    let mapping = OutcomeMapping::i05_v3().expect("mapping");
    let identity = Identity { api_version: "v1".into(), kind: Kind::ConfigMap, namespace: "planeon-qual".into(),
                              name: "probe-config".into() };
    let scalars = ["null", "true", "false", "0", "1", "1.0", "201", "200.0", "404", "408", "500", "1e400", "-0.0",
                   "\"OK\"", "\"DELIVERED_RESULT\"", "\"IO_AMBIGUOUS\"", "\"NOT_FORWARDED\"", "\"DELETED\"", "\"DENIED\"",
                   "\"AMBIGUOUS\"", "\"\\ud800\"", "[]", "{}", "\"404\"", "[1]", "{\"a\":1}"];
    let objects = [base64::encode(b"{\"kind\":\"Status\",\"status\":\"Success\",\"details\":{\"name\":\"probe-config\",\
                                    \"kind\":\"configmaps\",\"uid\":\"u\"}}"),
                   base64::encode(b"{\"details\":[]}"), base64::encode(b"[1]"), "e30=".to_string(), "!".to_string()];
    let mut rng = Rng(42);
    for _ in 0..20_000 {
        let mut outcome = String::from("{");
        for (index, key) in ["result", "actionId", "classification", "httpStatus", "observedUid", "observedResourceVersion"]
            .iter()
            .enumerate()
        {
            if index > 0 {
                outcome.push(',');
            }
            let value = if *key == "result" && rng.below(3) > 0 { "\"OK\"" } else { rng.pick(&scalars) };
            outcome.push_str(&format!("\"{key}\":{value}"));
        }
        outcome.push('}');
        let data = if rng.below(2) == 0 { format!("\"{}\"", rng.pick(&objects)) } else { rng.pick(&scalars).to_string() };
        let result = format!("{{\"actionId\":{},\"outcome\":{},\"objectBase64\":{}}}", rng.pick(&scalars), rng.pick(&scalars), data);
        let (Ok(outcome), Ok(result)) = (json::parse(&outcome), json::parse(&result)) else { continue };
        let verb = *rng.pick(&[Verb::Create, Verb::Get, Verb::Delete]);
        let _ = mapping.check_agreement(verb, &identity, &outcome, &result);
    }
}
