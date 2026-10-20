//! HE-004D2 DESIGN-D2 sections 5.3 and 15.1 (MODEL_DEFINED R139): table tests of the parts of `check_record` the model
//! leaves to Python and R10 writes itself: the IP text (CPython 3.12.14's `ipaddress.ip_address`, `str()` and the
//! properties the record rule reads; the IPv4-mapped loopback is R10's stricter reading), the eleven kernel-parameter
//! matchers, the string walk, and the backend exec-type table against the vendored v4 schema's constants; and (A3) I06
//! v1's three pattern matchers and `str.strip()`'s whitespace set. Each expected IP and whitespace result was read from
//! CPython 3.12.14 (no network).

mod b1_support;
mod d2_support;

use d2_support::{field, parse, V4_SCHEMA};
use i05_protocol::json::Value;
use planeon_observer::record_check::{ip_text, kernel_parameter, strings, BACKEND_EXEC_TYPES};
use planeon_observer::i06_evidence::{canonical_path, digest_form, implementation_form, stripped_text, whitespace};

#[test]
fn ip_text_reads_as_cpython() {
    // (text, CPython's str(ip), version 6, unspecified, multicast, IPv4-mapped, zone)
    let read: [(&str, &str, bool, bool, bool, bool, bool); 20] = [
        ("::1", "::1", true, false, false, false, false),
        ("0.0.0.0", "0.0.0.0", false, true, false, false, false),
        ("10.0.0.1", "10.0.0.1", false, false, false, false, false),
        ("127.0.0.1", "127.0.0.1", false, false, false, false, false),
        ("127.0.0.2", "127.0.0.2", false, false, false, false, false),
        ("0:0:0:0:0:0:0:1", "::1", true, false, false, false, false),
        ("0000:0000:0000:0000:0000:0000:0000:0001", "::1", true, false, false, false, false),
        ("::ffff:127.0.0.1", "::ffff:127.0.0.1", true, false, false, true, false),
        ("::ffff:0.0.0.0", "::ffff:0.0.0.0", true, true, false, true, false),
        ("::ffff:224.0.0.1", "::ffff:224.0.0.1", true, false, true, true, false),
        ("fe80::1%eth0", "fe80::1%eth0", true, false, false, false, true),
        ("::%eth0", "::%eth0", true, true, false, false, true),
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1", true, false, false, false, false),
        ("2001:0db8::1", "2001:db8::1", true, false, false, false, false),
        ("1:0:0:2:0:0:0:3", "1:0:0:2::3", true, false, false, false, false),
        ("1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0", true, false, false, false, false),
        ("::2:3:4:5:6:7:8", "0:2:3:4:5:6:7:8", true, false, false, false, false),
        ("1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304", true, false, false, false, false),
        ("ABCD::EF", "abcd::ef", true, false, false, false, false),
        ("ff02::1", "ff02::1", true, false, true, false, false),
    ];
    for (input, canonical, v6, unspecified, multicast, mapped, zone) in read {
        let ip = ip_text(input).unwrap_or_else(|| panic!("{input} parses"));
        assert_eq!((ip.canonical().as_str(), ip.is_v6(), ip.is_unspecified(), ip.is_multicast(), ip.is_ipv4_mapped(), ip.has_zone()),
                   (canonical, v6, unspecified, multicast, mapped, zone), "{input}");
    }
    for (input, loopback) in [("127.0.0.1", true), ("127.255.0.9", true), ("128.0.0.1", false), ("::1", true), ("::2", false),
                              ("::ffff:127.0.0.1", false), ("10.0.0.1", false)] {
        assert_eq!(ip_text(input).map(|ip| ip.is_loopback()), Some(loopback), "{input}");
    }
    assert_eq!(ip_text("224.0.0.1").map(|ip| ip.is_multicast()), Some(true));
    // CPython's ValueError cases.
    for input in ["127.000.0.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "256.1.1.1", "1:2:3:4:5:6:7:8:9", "1::2::3", ":1::2", "1::2:",
                  "12345::", "g::1", "fe80::1%", "fe80::1%a%b", "1.2.3.4%x", "::/1", "0.0.0.0%x", "1:2:3:4:5:6:7:1.2.3.4", "",
                  ":", "::::", "1.2.3.4/32", " 1.2.3.4", "1.2.3.4 ", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa::",
                  "\u{0661}.2.3.4"] {
        assert!(ip_text(input).is_none(), "{input:?} is refused");
    }
}

#[test]
fn the_eleven_kernel_parameter_matchers() {
    let accepted = [
        "initrd=\\planeon\\initrd-6.12.img", "initrd=a\\b", "initrd=/boot/initrd.img+x_y-1", "root=UUID=0b1d2c3e-0000-4000-8000-000000000001",
        "root=PARTUUID=abc.def_1", "root=LABEL=root-fs", "root=/dev/sda1", "root=/dev/mapper/vg_root-lv.1", "ro", "rw",
        "security=selinux", "selinux=1", "enforcing=1", "lockdown=integrity", "quiet", "loglevel=0", "loglevel=7",
    ];
    for word in accepted {
        assert!(kernel_parameter(word), "{word} is in the grammar");
    }
    let refused = [
        "initrd=a\"b", "initrd=", "initrd=a b", "initrd=a:b", "INITRD=a", "root=UUID=", "root=UUID=a/b", "root=UUID=PARTUUID=x",
        "root=uuid=a", "root=/dev/", "root=/dev/a:b", "root=/dev", "root=sda1", "ro ", " ro", "r", "rw=1", "security=apparmor",
        "selinux=0", "enforcing=0", "lockdown=confidentiality", "quiet=1", "loglevel=8", "loglevel=", "loglevel=10", "loglevel=-1",
        "systemd.unit=planeon-maintenance.target", "console=ttyS0", "--", "", "init=/bin/sh", "rd.break", "rootflags=x",
    ];
    for word in refused {
        assert!(!kernel_parameter(word), "{word:?} is outside the grammar");
    }
}

#[test]
fn the_string_walk_reads_keys_and_strings_in_document_order() {
    let value = parse(r#"{"b": ["x", 1, {"c": "y", "d": null}], "a": true, "e": {"f": [["z"]]}}"#);
    let found: Vec<&str> = strings(&value).into_iter().map(|name| name.as_str().expect("text")).collect();
    assert_eq!(found, ["b", "x", "c", "y", "d", "a", "e", "f", "z"]);
    assert!(strings(&Value::int(3)).is_empty());
    assert_eq!(strings(&Value::str("only")).len(), 1);
}

#[test]
fn the_backend_exec_types_are_the_schema_s_constants() {
    let schema = parse(V4_SCHEMA);
    let components = field(field(field(&schema, "$defs"), "backendComponents"), "properties").as_object().expect("properties");
    let mut found = Vec::new();
    for (_, rule) in components.iter() {
        let label = field(field(field(&field(rule, "allOf").as_array().expect("allOf")[1], "properties"), "executableLabel"), "const")
            .as_str().expect("a constant label");
        found.push(label.split(':').nth(2).expect("a type").to_string());
    }
    assert_eq!(found, BACKEND_EXEC_TYPES);
}

#[test]
fn the_i06_v1_pattern_matchers() {
    let longest = format!("a{}", "b".repeat(127));
    for text in ["unit-distribution", "a", "0.1-2", longest.as_str()] {
        assert!(implementation_form(text), "{text}");
    }
    for text in ["", "Unit", "-a", ".a", "a_b", "a b", "\u{e9}", format!("{longest}c").as_str()] {
        assert!(!implementation_form(text), "{text:?}");
    }
    for text in ["/a", "/a/b", "/run/qualification-k8s/datastore.sock", "/a@b+c_d.e-f", "/a/.b", "/a/..b"] {
        assert!(canonical_path(&Value::str(text)), "{text}");
    }
    for text in ["", "/", "a", "a/b", "/a/", "/a//b", "/a/.", "/a/./b", "/a/../b", "/..", "/a b", "/a:b", "/\u{e9}"] {
        assert!(!canonical_path(&Value::str(text)), "{text:?}");
    }
    assert!(!canonical_path(&Value::Null) && !canonical_path(&Value::int(1)));
    let hex = "0123456789abcdef".repeat(4);
    assert!(digest_form(&format!("sha256:{hex}")));
    for text in [format!("sha256:{}", hex.to_uppercase()), format!("sha256:{hex}0"), format!("sha256:{}", &hex[1..]),
                 format!("SHA256:{hex}"), format!("sha512:{hex}"), hex.clone()] {
        assert!(!digest_form(&text), "{text}");
    }
}

#[test]
fn the_strip_set_is_cpython_s() {
    // CPython 3.12.14's str.isspace code points, read from the local interpreter.
    let spaces: [u32; 29] = [0x9, 0xa, 0xb, 0xc, 0xd, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002,
                             0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000];
    let found: Vec<u32> = (0..0x11_0000u32).filter(|point| whitespace(*point)).collect();
    assert_eq!(found, spaces);
    for text in ["a", "a b", "unit-distribution", "x\u{200b}", "\u{180e}x", "\u{feff}"] {
        assert!(stripped_text(&Value::str(text)), "{text:?}");
    }
    for text in ["", " a", "a ", "\ta", "a\n", "\u{85}a", "a\u{a0}", "\u{3000}a", "a\u{2029}", " "] {
        assert!(!stripped_text(&Value::str(text)), "{text:?}");
    }
    assert!(!stripped_text(&Value::Null) && !stripped_text(&Value::Bool(true)));
}
