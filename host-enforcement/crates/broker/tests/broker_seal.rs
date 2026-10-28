//! The broker seal's portable parts on the build host (HE-005A: DESIGN-HE005 revision 5 sections 2 and 4, HE-005A;
//! MON-HE005A-LAUNCH): the two embedded BROKER programs (sha256, length and the pinned instruction counts), the role
//! specification's values, and the start-state pre-check with a failing row for each of its refusals. The stages
//! themselves are role-seal's, whose engine's tests run over a fake kernel inside its lib.rs; the raw calls wait for T04.

use std::io;

use planeon_broker::seal::{pre_check, spec, Arch, StartCheck, CAP_BPF, CAP_NET_ADMIN, CAP_SETGID, CAP_SETUID,
                           INSTRUCTIONS_AARCH64, INSTRUCTIONS_X86_64, KEPT, PROGRAM_AARCH64, PROGRAM_X86_64, RUNNING_ARCH};
use role_seal::{capability_words, filter_length, CapabilitySets, RoleSpec};

/// SHA-256 (FIPS 180-4) in lowercase hex, kept in this test so planeon-broker's closure stays its three crates; checked
/// against two published vectors below.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut state: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let bits = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bits.to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
            w[index] = w[index - 16].wrapping_add(s0).wrapping_add(w[index - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(choice).wrapping_add(K[index]).wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (word, added) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(added);
        }
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

#[test]
fn the_test_sha256_matches_published_vectors() {
    assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

#[test]
fn the_embedded_programs_are_the_published_bytes() {
    // Edge record v11's rows (DESIGN-HE005 section 2): BROKER aarch64 311 instructions, x86_64 326.
    for (program, digest, bytes) in [
        (PROGRAM_X86_64.as_slice(), "95221bd0db753aa22ead2eb49eeac8dae3d24c3dad72811de86c9392f4894dcc", 2608),
        (PROGRAM_AARCH64.as_slice(), "bc9c5a3797277ca753b5168e8e55132e1878fed2a726de361fd7d80e0fababf8", 2488),
    ] {
        assert_eq!(program.len(), bytes);
        assert_eq!(sha256_hex(program), digest);
    }
    assert_eq!((INSTRUCTIONS_X86_64, INSTRUCTIONS_AARCH64), (326, 311));
    assert_eq!(filter_length(PROGRAM_X86_64), Some(326));
    assert_eq!(filter_length(PROGRAM_AARCH64), Some(311));
    assert_eq!(Arch::X86_64.program(), PROGRAM_X86_64.as_slice());
    assert_eq!(Arch::Aarch64.program(), PROGRAM_AARCH64.as_slice());
    assert_eq!((Arch::X86_64.instructions(), Arch::Aarch64.instructions()), (326, 311));
    let running = if cfg!(target_arch = "x86_64") { Arch::X86_64 } else { Arch::Aarch64 };
    assert_eq!(RUNNING_ARCH, running, "cfg(target_arch) selects the installed program");
}

#[test]
fn the_specification_holds_the_four_capabilities_and_the_program() {
    assert_eq!((CAP_SETGID, CAP_SETUID, CAP_NET_ADMIN, CAP_BPF), (6, 7, 12, 39));
    assert_eq!(KEPT, 0x0000_0080_0000_10C0);
    for arch in [Arch::X86_64, Arch::Aarch64] {
        assert_eq!(spec(arch), RoleSpec { bounding: KEPT, kept: KEPT, program: arch.program(),
                                          instructions: arch.instructions() }, "{arch:?}");
    }
    // The kept set as the two version-3 words: CAP_SETGID, CAP_SETUID and CAP_NET_ADMIN in the first, CAP_BPF as bit 7
    // of the second; inheritable empty.
    let kept = CapabilitySets { effective: KEPT, permitted: KEPT, inheritable: 0 };
    assert_eq!(capability_words(kept), [[0x10C0, 0x10C0, 0], [1 << 7, 1 << 7, 0]]);
}

/// A status file as the kernel writes it for a root process with no supplementary group, with `uid`, `gid` and
/// `groups` (the text after `Groups:`) in place.
fn status(uid: &str, gid: &str, groups: &str) -> Vec<u8> {
    format!("Name:\tplaneon-broker\nUmask:\t0022\nState:\tR (running)\nTgid:\t812\nPid:\t812\nPPid:\t1\n\
             Uid:{uid}\nGid:{gid}\nFDSize:\t64\nGroups:{groups}\nThreads:\t1\nSigQ:\t0/15000\n")
        .into_bytes()
}

const ROOT: &str = "\t0\t0\t0\t0";

#[test]
fn a_root_start_state_without_groups_passes() {
    for groups in ["\t \t", "\t ", "\t", "", " "] {
        assert_eq!(pre_check(Ok(status(ROOT, ROOT, groups))), Ok(()), "{groups:?}");
    }
    // Only the fourth field is the pre-check's: the other three are role-seal's getresuid and getresgid.
    assert_eq!(pre_check(Ok(status("\t1000\t1000\t1000\t0", "\t5\t5\t5\t0", "\t "))), Ok(()));
    assert_eq!(pre_check(Ok(status(" 0 0 0 0", "  0\t 0 0\t0", "\t "))), Ok(()), "tabs or spaces separate the fields");
}

#[test]
fn a_failed_status_read_is_refused_as_status() {
    for errno in [2, 13, 24] {
        assert_eq!(pre_check(Err(io::Error::from_raw_os_error(errno))), Err(StartCheck::Status));
    }
    assert_eq!(pre_check(Err(io::Error::new(io::ErrorKind::InvalidData, "too long"))), Err(StartCheck::Status));
}

#[test]
fn a_filesystem_uid_other_than_0_is_refused() {
    for uid in ["\t0\t0\t0\t1000", "\t0\t0\t0\t1", "\t0\t0\t0\t4294967295"] {
        assert_eq!(pre_check(Ok(status(uid, ROOT, "\t "))), Err(StartCheck::FsUid), "{uid:?}");
    }
    // Not one line of four decimal fields: refused as the uid line too.
    for uid in ["\t0\t0\t0", "\t0\t0\t0\t0\t0", "", "\t", "\t0\t0\t0\t-0", "\t0\t0\t0\t+0", "\t0\t0\t0\t0x0",
                "\t0\t0\t0\t4294967296", "\t0\t0\t0\t0\r", "\t0\t0\t0\tzero"] {
        assert_eq!(pre_check(Ok(status(uid, ROOT, "\t "))), Err(StartCheck::FsUid), "{uid:?}");
    }
    let missing = String::from_utf8(status(ROOT, ROOT, "\t ")).unwrap_or_default().replace("Uid:", "Uids:");
    assert_eq!(pre_check(Ok(missing.into_bytes())), Err(StartCheck::FsUid), "no Uid: line");
    let twice = String::from_utf8(status(ROOT, ROOT, "\t ")).unwrap_or_default() + "Uid:\t0\t0\t0\t0\n";
    assert_eq!(pre_check(Ok(twice.into_bytes())), Err(StartCheck::FsUid), "two Uid: lines");
}

#[test]
fn a_filesystem_gid_other_than_0_is_refused() {
    for gid in ["\t0\t0\t0\t1000", "\t0\t0\t0\t7"] {
        assert_eq!(pre_check(Ok(status(ROOT, gid, "\t "))), Err(StartCheck::FsGid), "{gid:?}");
    }
    for gid in ["\t0\t0\t0", "\t0\t0\t0\t0\t0", "", "\t0\t0\t0\tx"] {
        assert_eq!(pre_check(Ok(status(ROOT, gid, "\t "))), Err(StartCheck::FsGid), "{gid:?}");
    }
    let missing = String::from_utf8(status(ROOT, ROOT, "\t ")).unwrap_or_default().replace("Gid:", "Gids:");
    assert_eq!(pre_check(Ok(missing.into_bytes())), Err(StartCheck::FsGid), "no Gid: line");
}

#[test]
fn a_listed_supplementary_group_is_refused() {
    for groups in ["\t0 ", "\t4 24 27 ", "\t1000", "\t \t5", "\tx"] {
        assert_eq!(pre_check(Ok(status(ROOT, ROOT, groups))), Err(StartCheck::Groups), "{groups:?}");
    }
    let missing = String::from_utf8(status(ROOT, ROOT, "\t ")).unwrap_or_default().replace("Groups:", "Group:");
    assert_eq!(pre_check(Ok(missing.into_bytes())), Err(StartCheck::Groups), "no Groups: line");
    let twice = String::from_utf8(status(ROOT, ROOT, "\t ")).unwrap_or_default() + "Groups:\t \n";
    assert_eq!(pre_check(Ok(twice.into_bytes())), Err(StartCheck::Groups), "two Groups: lines");
}

#[test]
fn the_pre_check_reports_the_first_refusal_in_its_order() {
    let all_wrong = status("\t0\t0\t0\t1", "\t0\t0\t0\t1", "\t4 ");
    assert_eq!(pre_check(Ok(all_wrong)), Err(StartCheck::FsUid));
    assert_eq!(pre_check(Ok(status(ROOT, "\t0\t0\t0\t1", "\t4 "))), Err(StartCheck::FsGid));
    assert_eq!(pre_check(Ok(status(ROOT, ROOT, "\t4 "))), Err(StartCheck::Groups));
}
