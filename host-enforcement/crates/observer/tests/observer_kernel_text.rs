//! HE-004D1 DESIGN-D1 sections 8 and 20 (MODEL_DEFINED R125): every portable parser of the kernel text the captures
//! read: `stat` (a `comm` with spaces and parentheses), `status` (four unequal `Uid` values, capability bit 41, duplicate
//! keys), `cgroup`, `attr/current`, `maps` (`[vdso]`, an anonymous executable line, the device encoding), the namespace
//! and `exe` links (` (deleted)`), `cgroup.events`, `cgroup.stat`, the limits (`max`), the verity reply's algorithm and
//! size, canonical UTC seconds and milliseconds, the call count (D1-10) and the mode (D1-5); and the capability table.

use planeon_observer::kernel_text::{self, Mapping, Stat, CAPABILITY_NAMES, CAP_LAST_CAP};
use planeon_observer::seal;

#[test]
fn stat_reads_ppid_and_start_after_the_last_parenthesis() {
    let tail = "S 1 3000 3000 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 4 0 5000 100000 200 18446744073709551615";
    let parsed = kernel_text::stat(format!("3000 (python3) {tail}\n").as_bytes());
    assert_eq!(parsed, Some(Stat { pid: 3000, ppid: 1, start_ticks: 5000 }));
    // A comm holding spaces and parentheses cannot shift a field.
    let parsed = kernel_text::stat(format!("3000 (a (b) ) c)) {tail}").as_bytes());
    assert_eq!(parsed, Some(Stat { pid: 3000, ppid: 1, start_ticks: 5000 }));
    for bad in ["3000 python3 S 1", "x (c) S 1 3000", "3000 (c) S -1 3000 3000 0 -1 1 1 1 1 1 1 1 1 1 1 1 1 1 5000",
                "3000 (c) S 1 2 3"] {
        assert_eq!(kernel_text::stat(bad.as_bytes()), None, "{bad}");
    }
}

fn status_text(uid: &str, caps: &str) -> String {
    format!("Name:\tx\nUid:\t{uid}\nGid:\t0\t0\t0\t0\nThreads:\t4\nCapInh:\t0000000000000000\nCapPrm:\t{caps}\n\
             CapEff:\t{caps}\nCapBnd:\t{caps}\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n")
}

#[test]
fn status_requires_equal_ids_known_capabilities_and_unique_keys() {
    let parsed = kernel_text::status(status_text("0\t0\t0\t0", "0000008000001000").as_bytes()).expect("a status");
    assert_eq!((parsed.uid, parsed.gid, parsed.threads, parsed.no_new_privs, parsed.seccomp_mode, parsed.seccomp_filters),
               (0, 0, 4, 1, 2, 1));
    assert_eq!(parsed.permitted, 1 << 12 | 1 << 39);
    assert_eq!(kernel_text::capability_names(parsed.effective), vec!["CAP_BPF".to_string(), "CAP_NET_ADMIN".to_string()]);
    assert_eq!(kernel_text::status(status_text("0\t0\t0\t1", "0000008000001000").as_bytes()), None, "four unequal Uid values");
    assert_eq!(kernel_text::status(status_text("0\t0\t0", "0000008000001000").as_bytes()), None);
    assert_eq!(kernel_text::status(status_text("0\t0\t0\t0", "0000020000000000").as_bytes()), None, "capability bit 41");
    assert!(kernel_text::status(status_text("0\t0\t0\t0", "0000010000000000").as_bytes()).is_some(), "bit 40");
    let duplicated = format!("{}Threads:\t4\n", status_text("0\t0\t0\t0", "0000000000000000"));
    assert_eq!(kernel_text::status(duplicated.as_bytes()), None, "a duplicate key");
    let missing = status_text("0\t0\t0\t0", "0000000000000000").replace("Seccomp_filters:\t1\n", "");
    assert_eq!(kernel_text::status(missing.as_bytes()), None);
}

#[test]
fn the_capability_table_covers_bits_0_to_40_once_and_agrees_with_the_seal() {
    assert_eq!(CAPABILITY_NAMES.len(), 41);
    assert_eq!(CAP_LAST_CAP, seal::CAP_LAST_CAP);
    let distinct: std::collections::BTreeSet<&str> = CAPABILITY_NAMES.iter().copied().collect();
    assert_eq!(distinct.len(), 41);
    assert_eq!(CAPABILITY_NAMES[seal::CAP_NET_ADMIN as usize], "CAP_NET_ADMIN");
    assert_eq!(CAPABILITY_NAMES[seal::CAP_BPF as usize], "CAP_BPF");
    assert_eq!(CAPABILITY_NAMES[10], "CAP_NET_BIND_SERVICE");
    assert_eq!(kernel_text::capability_names(u64::MAX >> 23).len(), 41);
    assert_eq!(kernel_text::capability_mask("0000020000000000"), None);
    assert_eq!(kernel_text::capability_mask("000001ffffffffff"), Some((1 << 41) - 1));
    assert_eq!(kernel_text::capability_mask("1ffffffffff"), None);
}

#[test]
fn cgroup_and_label_lines() {
    assert_eq!(kernel_text::cgroup_line(b"0::/planeon.slice/a.service\n").as_deref(), Some("/planeon.slice/a.service"));
    for bad in [&b"0::/a\n0::/b\n"[..], b"1:name=x:/a\n", b"0::a\n", b"0::/a\n\n"] {
        assert_eq!(kernel_text::cgroup_line(bad), None);
    }
    assert_eq!(kernel_text::label(b"system_u:system_r:planeon_server_t:s0\0\n").as_deref(),
               Some("system_u:system_r:planeon_server_t:s0"));
    assert_eq!(kernel_text::label(b"system_u:system_r:planeon_server_t:s0\n").as_deref(),
               Some("system_u:system_r:planeon_server_t:s0"));
    assert_eq!(kernel_text::label(b"\0"), None);
    assert_eq!(kernel_text::label_type("system_u:system_r:planeon_server_t:s0"), Some("planeon_server_t"));
    assert_eq!(kernel_text::label_type("system_u:system_r:planeon_server_t:s0:c0.c1023"), Some("planeon_server_t"));
    assert_eq!(kernel_text::label_type("system_u::planeon_server_t:s0"), None);
    assert_eq!(kernel_text::label_type("planeon_server_t"), None);
}

#[test]
fn maps_keep_executable_lines_skip_vdso_and_refuse_anonymous_ones() {
    let device = kernel_text::makedev(0x103, 0x2a5);
    let (major, minor) = kernel_text::device_parts(device);
    assert_eq!((major, minor), (0x103, 0x2a5));
    for value in [0u64, 1, 123, 0xfff_ff00, 0x1234_5678_9abc] {
        let (major, minor) = kernel_text::device_parts(value);
        assert_eq!(kernel_text::makedev(major, minor), value, "{value}");
    }
    let text = "55d0c0000000-55d0c0001000 r--p 00000000 103:2a5 2004                       /opt/planeon/bin/python3.12\n\
                55d0c0001000-55d0c0002000 r-xp 00001000 103:2a5 2004                       /opt/planeon/bin/python3.12\n\
                7ffc0000e000-7ffc00010000 r-xp 00000000 00:00 0                          [vdso]\n\
                ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]\n\
                7f0000000000-7f0000021000 rw-p 00000000 00:00 0 \n";
    let parsed = kernel_text::maps(text.as_bytes()).expect("maps");
    assert_eq!(parsed, vec![Mapping { path: "/opt/planeon/bin/python3.12".to_string(), offset: 0x1000, length: 0x1000,
                                      permissions: "r-xp".to_string(), device, inode: 2004 }]);
    let anonymous = "7f0000000000-7f0000021000 r-xp 00000000 00:00 0 \n";
    assert_eq!(kernel_text::maps(anonymous.as_bytes()), None);
    let named = "7f0000000000-7f0000021000 r-xp 00000000 00:00 0                          [anon:jit]\n";
    assert_eq!(kernel_text::maps(named.as_bytes()), None);
    assert_eq!(kernel_text::maps(b"zz-10 r-xp 0 00:00 0 /a\n"), None);
    assert_eq!(kernel_text::maps(b"10-0 r-xp 0 00:00 0 /a\n"), None);
}

#[test]
fn links_events_stat_and_limits() {
    assert_eq!(kernel_text::namespace_inode("user:[4026531837]", "user"), Some(4026531837));
    assert_eq!(kernel_text::namespace_inode("mnt:[4026531837]", "user"), None);
    assert_eq!(kernel_text::namespace_inode("user:[0]", "user"), None);
    assert_eq!(kernel_text::exe_path("/opt/planeon/bin/gate").as_deref(), Some("/opt/planeon/bin/gate"));
    assert_eq!(kernel_text::exe_path("/opt/planeon/bin/gate (deleted)"), None);
    assert_eq!(kernel_text::exe_path("gate"), None);
    assert_eq!(kernel_text::events(b"populated 1\nfrozen 0\n"), Some((1, 0)));
    assert_eq!(kernel_text::events(b"populated 1\nfrozen 1\nfrozen 1\n"), None);
    assert_eq!(kernel_text::events(b"populated 1\n"), None);
    assert_eq!(kernel_text::events(b"populated 2\nfrozen 0\n"), None);
    assert_eq!(kernel_text::descendants(b"nr_descendants 3\nnr_dying_descendants 0\n"), Some(3));
    assert_eq!(kernel_text::limit(b"268435456\n"), Some(268_435_456));
    assert_eq!(kernel_text::limit(b"max\n"), None);
    assert_eq!(kernel_text::limit(b"-1\n"), None);
    assert_eq!(kernel_text::cpu_max(b"100000 100000\n"), Some((100_000, 100_000)));
    assert_eq!(kernel_text::cpu_max(b"max 100000\n"), None);
    assert_eq!(kernel_text::procs(b"3000\n3001\n"), Some(vec![3000, 3001]));
    assert_eq!(kernel_text::procs(b""), Some(vec![]));
    assert_eq!(kernel_text::procs(b"0\n"), None);
}

#[test]
fn the_verity_reply_needs_sha256_and_32_bytes() {
    let digest = [0x5au8; 32];
    assert_eq!(kernel_text::verity_text(1, 32, &digest).as_deref(), Some(format!("sha256:{}", "5a".repeat(32)).as_str()));
    assert_eq!(kernel_text::verity_text(2, 32, &digest), None, "SHA-512");
    assert_eq!(kernel_text::verity_text(1, 64, &digest), None);
    assert_eq!(kernel_text::verity_text(1, 32, &digest[..31]), None);
}

#[test]
fn utc_seconds_and_milliseconds() {
    assert_eq!(kernel_text::utc_seconds("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(kernel_text::utc_seconds("2026-09-08T00:10:00Z"), Some(1_788_826_200));
    assert_eq!(kernel_text::utc_millis("2026-09-08T00:10:00Z"), Some(1_788_826_200_000));
    assert_eq!(kernel_text::utc_text(1_788_826_200).as_deref(), Some("2026-09-08T00:10:00Z"));
    assert_eq!(kernel_text::utc_text(951_782_400).as_deref(), Some("2000-02-29T00:00:00Z"));
    assert_eq!(kernel_text::utc_seconds("2000-02-29T00:00:00Z"), Some(951_782_400));
    assert_eq!(kernel_text::utc_text(kernel_text::MAX_UTC_SECONDS).as_deref(), Some("9999-12-31T23:59:59Z"));
    assert_eq!(kernel_text::utc_text(kernel_text::MAX_UTC_SECONDS + 1), None);
    for bad in ["2026-02-30T00:00:00Z", "2026-9-08T00:10:00Z", "2026-09-08 00:10:00Z", "2026-09-08T24:00:00Z",
                "2026-09-08T00:10:00", "1969-12-31T23:59:59Z", "2026-09-08T00:10:60Z", "+026-09-08T00:10:00Z"] {
        assert_eq!(kernel_text::utc_seconds(bad), None, "{bad}");
    }
}

/// One instruction: opcode, registers (source in the high nibble), offset and immediate.
fn instruction(code: u8, source: u8) -> [u8; 8] {
    [code, source << 4, 0, 0, 1, 0, 0, 0]
}

#[test]
fn the_call_count_counts_helpers_and_kfuncs_only() {
    let program: Vec<u8> = [instruction(0xb7, 0), instruction(0x85, 0), instruction(0x85, 2), instruction(0x85, 1),
                            instruction(0x95, 0)].concat();
    assert_eq!(kernel_text::call_count(&program), Some(2));
    assert_eq!(kernel_text::call_count(&[instruction(0xb7, 0), instruction(0x95, 0)].concat()), Some(0));
    assert_eq!(kernel_text::call_count(&instruction(0x85, 3)), None, "source register 3");
    assert_eq!(kernel_text::call_count(&program[..12]), None, "not a multiple of 8");
}

#[test]
fn modes_render_their_special_bits() {
    for (mode, text) in [(0o100555, "0555"), (0o104555, "4555"), (0o102555, "2555"), (0o101555, "1555"), (0o100755, "0755"),
                         (0o104444, "4444")] {
        assert_eq!(kernel_text::mode_text(mode), text);
    }
    assert_eq!(kernel_text::decimal("007"), None);
    assert_eq!(kernel_text::decimal("0"), Some(0));
    assert_eq!(kernel_text::pid("0"), None);
}
