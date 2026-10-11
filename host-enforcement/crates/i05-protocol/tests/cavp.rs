//! SHA-256 against the NIST CAVP byte-oriented response files (CAVS 11.1, `shabytetestvectors.zip`): every short and
//! long message, and the SHAVS Monte Carlo test (100 checkpoints of 1000 chained iterations each).

use i05_protocol::sha256;

const SHORT: &str = include_str!("cavp/SHA256ShortMsg.rsp");
const LONG: &str = include_str!("cavp/SHA256LongMsg.rsp");
const MONTE: &str = include_str!("cavp/SHA256Monte.rsp");

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digit"))
        .collect()
}

fn fields(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('['))
        .map(|line| line.split_once(" = ").expect("a `name = value` line"))
        .collect()
}

/// Every (Len, Msg, MD) record; returns the number checked.
fn check_messages(text: &str) -> usize {
    let fields = fields(text);
    let mut checked = 0;
    for record in fields.chunks(3) {
        let [("Len", length), ("Msg", message), ("MD", expected)] = record else { panic!("record shape {record:?}") };
        let bits: usize = length.parse().expect("Len");
        assert_eq!(bits % 8, 0, "byte-oriented vectors only");
        let message = unhex(message);
        let message = &message[..bits / 8];
        assert_eq!(sha256::hex(&sha256::digest(message)), *expected, "Len = {bits}");
        checked += 1;
    }
    checked
}

#[test]
fn short_messages() {
    assert_eq!(check_messages(SHORT), 65);
}

#[test]
fn long_messages() {
    assert_eq!(check_messages(LONG), 64);
}

#[test]
fn monte_carlo() {
    let fields = fields(MONTE);
    let ("Seed", seed) = fields[0] else { panic!("seed first") };
    let mut seed = unhex(seed);
    let checkpoints: Vec<(&str, &str)> = fields[1..].to_vec();
    assert_eq!(checkpoints.len(), 200);
    for (round, pair) in checkpoints.chunks(2).enumerate() {
        let [("COUNT", count), ("MD", expected)] = pair else { panic!("checkpoint shape {pair:?}") };
        assert_eq!(count.parse::<usize>().expect("COUNT"), round);
        let mut window = [seed.clone(), seed.clone(), seed.clone()];
        for _ in 3..1003 {
            let mut message = Vec::with_capacity(96);
            for digest in &window {
                message.extend_from_slice(digest);
            }
            let next = sha256::digest(&message).to_vec();
            window = [window[1].clone(), window[2].clone(), next];
        }
        seed = window[2].clone();
        assert_eq!(sha256::hex(&seed), *expected, "COUNT = {round}");
    }
}
