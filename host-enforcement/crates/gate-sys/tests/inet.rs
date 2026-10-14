//! gate-sys's literal-authority parser on the build host (HE-003B DESIGN §3.2, §9): every accepted form and every
//! refusal of `parse_authority`. The raw calls of `tcp.rs` are Linux only and wait for T04.

use gate_sys::inet::{parse_authority, parse_ipv4, parse_ipv6, AuthorityError, InetAddress, IpLiteral, AUTHORITY_LIMIT};

fn v4(octets: [u8; 4], port: u16) -> Result<InetAddress, AuthorityError> {
    Ok(InetAddress { ip: IpLiteral::V4(octets), port })
}

fn v6(words: [u16; 8], port: u16) -> Result<InetAddress, AuthorityError> {
    let mut bytes = [0u8; 16];
    for (pair, word) in bytes.chunks_exact_mut(2).zip(words) {
        pair.copy_from_slice(&word.to_be_bytes());
    }
    Ok(InetAddress { ip: IpLiteral::V6(bytes), port })
}

#[test]
fn ipv4_authorities_are_parsed_exactly() {
    assert_eq!(parse_authority("127.0.0.1:6443"), v4([127, 0, 0, 1], 6443));
    assert_eq!(parse_authority("198.51.100.7:443"), v4([198, 51, 100, 7], 443));
    assert_eq!(parse_authority("0.0.0.0:1"), v4([0, 0, 0, 0], 1));
    assert_eq!(parse_authority("255.255.255.255:65535"), v4([255, 255, 255, 255], 65535));
    for refused in ["256.0.0.1:443", "1.2.3:443", "1.2.3.4.5:443", "01.2.3.4:443", "1.2.3.04:443", "1..3.4:443",
                    "1.2.3.4a:443", "a.b.c.d:443", "-1.2.3.4:443", "+1.2.3.4:443", "1.2.3.1000:443", "localhost:443",
                    "1.2.3.4:"] {
        assert!(parse_authority(refused).is_err(), "{refused}");
    }
    assert_eq!(parse_authority("localhost:443"), Err(AuthorityError::Ipv4));
    assert_eq!(parse_ipv4("10.0.0.255"), Some([10, 0, 0, 255]));
    assert_eq!(parse_ipv4("10.0.0"), None);
}

#[test]
fn ipv6_authorities_take_every_rfc_4291_text_form() {
    assert_eq!(parse_authority("[::1]:6443"), v6([0, 0, 0, 0, 0, 0, 0, 1], 6443));
    assert_eq!(parse_authority("[::]:1024"), v6([0; 8], 1024));
    assert_eq!(parse_authority("[2001:db8::7]:443"), v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 7], 443));
    assert_eq!(parse_authority("[2001:DB8:0:0:8:800:200C:417A]:443"),
               v6([0x2001, 0xdb8, 0, 0, 8, 0x800, 0x200c, 0x417a], 443));
    assert_eq!(parse_authority("[1::]:443"), v6([1, 0, 0, 0, 0, 0, 0, 0], 443));
    assert_eq!(parse_authority("[1:2:3:4:5:6:7::]:443"), v6([1, 2, 3, 4, 5, 6, 7, 0], 443));
    assert_eq!(parse_authority("[::2:3:4:5:6:7:8]:443"), v6([0, 2, 3, 4, 5, 6, 7, 8], 443));
    assert_eq!(parse_authority("[::ffff:192.0.2.1]:443"), v6([0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201], 443));
    assert_eq!(parse_authority("[1:2:3:4:5:6:1.2.3.4]:443"), v6([1, 2, 3, 4, 5, 6, 0x0102, 0x0304], 443));
    assert_eq!(parse_ipv6("0:0:0:0:0:0:0:1"), parse_ipv6("::1"));
}

#[test]
fn malformed_ipv6_literals_are_refused() {
    for refused in ["[1:2:3:4:5:6:7:8:9]:443", "[1:2:3:4:5:6:7]:443", "[1::2::3]:443", "[:::1]:443", "[1:::]:443",
                    "[:1:2:3:4:5:6:7]:443", "[1:2:3:4:5:6:7:]:443", "[12345::1]:443", "[g::1]:443",
                    "[fe80::1%eth0]:443", "[1.2.3.4::]:443", "[::1.2.3]:443", "[1:2:3:4:5:6:7:1.2.3.4]:443",
                    "[1:2:3:4:5:6:7::8]:443", "[]:443"] {
        assert_eq!(parse_authority(refused), Err(AuthorityError::Ipv6), "{refused}");
    }
}

#[test]
fn ports_are_canonical_decimals_and_required() {
    assert_eq!(parse_authority("1.2.3.4:65535").map(|address| address.port), Ok(65535));
    for refused in ["1.2.3.4:0", "1.2.3.4:65536", "1.2.3.4:0443", "1.2.3.4:+443", "1.2.3.4:-1", "1.2.3.4:44a",
                    "1.2.3.4:", "1.2.3.4:999999", "[::1]:", "[::1]:00"] {
        assert_eq!(parse_authority(refused), Err(AuthorityError::Port), "{refused}");
    }
}

#[test]
fn the_text_and_form_rules_come_first() {
    assert_eq!(parse_authority(""), Err(AuthorityError::Text));
    assert_eq!(parse_authority("1.2.3.4: 443"), Err(AuthorityError::Text));
    assert_eq!(parse_authority(" 1.2.3.4:443"), Err(AuthorityError::Text));
    assert_eq!(parse_authority("1.2.3.4:443\n"), Err(AuthorityError::Text));
    assert_eq!(parse_authority("1.2.3.4:443\u{e9}"), Err(AuthorityError::Text));
    let long = format!("[{}::1]:443", "1:".repeat(30));
    assert!(long.len() > AUTHORITY_LIMIT);
    assert_eq!(parse_authority(&long), Err(AuthorityError::Text));
    for refused in ["1.2.3.4", "[::1]", "[::1]443", "[::1:443", "::1:443", "1.2.3.4:443:1", "https://1.2.3.4:443"] {
        assert_eq!(parse_authority(refused).map(|_| ()).err().map(|error| error == AuthorityError::Text), Some(false),
                   "{refused}");
        assert!(parse_authority(refused).is_err(), "{refused}");
    }
    assert_eq!(parse_authority("::1:443"), Err(AuthorityError::Form));
}
