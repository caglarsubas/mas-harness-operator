//! The observer seal's portable parts on the build host (HE-004A DESIGN sections 4 and 8): the helpers copied from
//! effect-gate's seal, run against the same cases as effect-gate's tests/seal.rs (owner decision Q-HE4A-6 (a)), and the
//! two embedded OBSERVER programs (sha256, length and the pinned instruction counts, and a classic-BPF decode; since
//! HE-004-I01a the seccomp-v5 programs, DESIGN-I01A section 3). The engine's tests run over a fake kernel inside
//! `src/seal.rs`, because the engine is crate-private (D6); the raw calls wait for T04.

use i05_protocol::sha256;
use planeon_observer::seal::{capability_sets, capability_words, filter_length, status_threads, Arch, CapabilitySets,
                             Prctl, BPF_MAXINSNS, CAP_BPF, CAP_LAST_CAP, CAP_NET_ADMIN, INSTRUCTIONS_AARCH64,
                             INSTRUCTIONS_X86_64, KEPT, PROGRAM_AARCH64, PROGRAM_X86_64, RUNNING_ARCH};

/// Classic-BPF opcodes the programs use: `BPF_LD|BPF_W|BPF_ABS`, `BPF_JMP|BPF_JEQ|BPF_K`, `BPF_JMP|BPF_JGE|BPF_K`,
/// `BPF_ALU|BPF_AND|BPF_K` and `BPF_RET|BPF_K`.
const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const AND_K: u16 = 0x54;
const RET_K: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
/// `SECCOMP_RET_ERRNO | ENOSYS` (the OBSERVER row's answer to clone3).
const SECCOMP_RET_ERRNO_ENOSYS: u32 = 0x0005_0026;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// `offsetof(struct seccomp_data, nr)` and `offsetof(struct seccomp_data, arch)`.
const NR: u32 = 0;
const ARCH: u32 = 4;

/// One instruction: `(code, jt, jf, k)`.
type Instruction = (u16, u8, u8, u32);

fn decode(program: &[u8]) -> Vec<Instruction> {
    assert_eq!(program.len() % 8, 0, "whole instructions");
    program
        .chunks_exact(8)
        .map(|raw| {
            (u16::from_le_bytes([raw[0], raw[1]]), raw[2], raw[3], u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]))
        })
        .collect()
}

#[test]
fn capability_sets_split_into_two_version_3_words() {
    let sets = CapabilitySets { effective: 1 << 8, permitted: 1 << 8 | 1 << 32, inheritable: 1 << 40 };
    assert_eq!(capability_words(sets), [[1 << 8, 1 << 8, 0], [0, 1, 1 << 8]]);
    assert_eq!(capability_words(CapabilitySets::default()), [[0; 3]; 2]);
    let all = (1u64 << 41) - 1;
    let full = CapabilitySets { effective: all, permitted: all, inheritable: all };
    assert_eq!(capability_words(full), [[u32::MAX; 3], [0x1FF; 3]], "capabilities 32-40 are the second word's 0-8");
    for sets in [sets, full, CapabilitySets::default(), CapabilitySets { effective: 1, permitted: 1 << 31, inheritable: 1 << 33 }] {
        assert_eq!(capability_sets(capability_words(sets)), sets);
    }
    // Bits past capability 40 survive, so a stray bit read back is a mismatch rather than lost.
    assert_eq!(capability_sets([[0; 3], [0x8000_0000, 0, 0]]).effective, 1 << 63);
    assert_eq!(capability_sets([[7, 0, 0], [0, 0, 2]]), CapabilitySets { effective: 7, permitted: 0, inheritable: 1 << 33 });
    // The observer's kept set: CAP_NET_ADMIN in the first word, CAP_BPF as bit 7 of the second.
    assert_eq!((CAP_NET_ADMIN, CAP_BPF), (12, 39));
    let kept = CapabilitySets { effective: KEPT, permitted: KEPT, inheritable: 0 };
    assert_eq!(capability_words(kept), [[1 << 12, 1 << 12, 0], [1 << 7, 1 << 7, 0]]);
}

#[test]
fn the_sock_fprog_length_counts_whole_instructions() {
    assert_eq!(filter_length(PROGRAM_X86_64), Some(253));
    assert_eq!(filter_length(PROGRAM_AARCH64), Some(242));
    assert_eq!((INSTRUCTIONS_X86_64, INSTRUCTIONS_AARCH64), (253, 242));
    assert_eq!(filter_length(&[]), None);
    assert_eq!(filter_length(&[0; 7]), None);
    assert_eq!(filter_length(&[0; 8]), Some(1));
    assert_eq!(filter_length(&[0; 9]), None);
    assert_eq!(filter_length(&vec![0; 8 * BPF_MAXINSNS]), Some(4096));
    assert_eq!(filter_length(&vec![0; 8 * BPF_MAXINSNS + 8]), None);
}

#[test]
fn every_prctl_call_carries_exactly_four_further_arguments() {
    let cases = [
        (Prctl::BoundingRead(0), (23, [0, 0, 0, 0])),
        (Prctl::BoundingRead(CAP_LAST_CAP + 1), (23, [41, 0, 0, 0])),
        (Prctl::AmbientIsSet(CAP_LAST_CAP), (47, [1, 40, 0, 0])),
        (Prctl::SetNoNewPrivs, (38, [1, 0, 0, 0])),
        (Prctl::GetNoNewPrivs, (39, [0, 0, 0, 0])),
    ];
    for (call, expected) in cases {
        assert_eq!(call.arguments(), expected, "{call:?}");
    }
}

#[test]
fn the_threads_line_is_parsed_strictly() {
    let status = |threads: &str| {
        format!("Name:\tplaneon-observ\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t812\nThreads:{threads}\nSigQ:\t0/15000\n")
    };
    for (value, expected) in [("\t1", 1), ("\t17", 17), (" 2", 2), ("1", 1), ("\t \t3", 3), ("\t18446744073709551615", u64::MAX)] {
        assert_eq!(status_threads(status(value).as_bytes()), Some(expected), "{value:?}");
    }
    assert_eq!(status_threads(b"Threads:\t1"), Some(1), "no final newline");
    for value in ["", "\t", "\t1 ", "\t-1", "\t+1", "\t1x", "\tone", "\t0x1", "\t18446744073709551616", "\t1\r", "\t1\t"] {
        assert_eq!(status_threads(status(value).as_bytes()), None, "{value:?}");
    }
    for text in [&b""[..], b"Name:\tx\nSigQ:\t0/1\n", b"Threads:\t1\nThreads:\t1\n", b"Threads:\t1\nThreads:\t2\n",
                 b"Name:\tx Threads:\t1\n", b"threads:\t1\n", b" Threads:\t1\n", b"Threads\t1\n"] {
        assert_eq!(status_threads(text), None, "{:?}", String::from_utf8_lossy(text));
    }
}

#[test]
fn the_embedded_programs_are_the_published_bytes() {
    for (program, digest, bytes) in [
        (PROGRAM_X86_64.as_slice(), "a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9", 2024),
        (PROGRAM_AARCH64.as_slice(), "887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184", 1936),
    ] {
        assert_eq!(program.len(), bytes);
        assert_eq!(sha256::hex(&sha256::digest(program)), digest);
    }
    assert_eq!(Arch::X86_64.program(), PROGRAM_X86_64.as_slice());
    assert_eq!(Arch::Aarch64.program(), PROGRAM_AARCH64.as_slice());
    assert_eq!((Arch::X86_64.instructions(), Arch::Aarch64.instructions()), (253, 242));
    let running = if cfg!(target_arch = "x86_64") { Arch::X86_64 } else { Arch::Aarch64 };
    assert_eq!(RUNNING_ARCH, running, "cfg(target_arch) selects the installed program");
}

#[test]
fn a_classic_bpf_decode_of_each_program() {
    for (arch, count, audit) in [(Arch::X86_64, 253, AUDIT_ARCH_X86_64), (Arch::Aarch64, 242, AUDIT_ARCH_AARCH64)] {
        let program = decode(arch.program());
        assert_eq!(program.len(), count, "{arch:?}");
        // The architecture check: load seccomp_data.arch, kill unless it is this architecture's.
        assert_eq!(program[0], (LD_W_ABS, 0, 0, ARCH), "{arch:?}");
        assert_eq!(program[1], (JEQ_K, 1, 0, audit), "{arch:?}");
        assert_eq!(program[2], (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS), "{arch:?}");
        assert_eq!(program[3], (LD_W_ABS, 0, 0, NR), "{arch:?}");
        // x32 refusal: on x86_64 a system call number with the x32 bit kills; aarch64 has no such check.
        let x32: Vec<usize> = (0..count).filter(|index| program[*index].0 == JGE_K).collect();
        if arch == Arch::X86_64 {
            assert_eq!(x32, [4]);
            assert_eq!(program[4], (JGE_K, 0, 1, X32_SYSCALL_BIT));
            assert_eq!(program[5], (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS));
        } else {
            assert!(x32.is_empty(), "no x32 check on aarch64");
        }
        // The terminal instruction kills the process.
        assert_eq!(program[count - 1], (RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS), "{arch:?}");
        // Five opcodes only; every jump lands inside the program; every return is ALLOW, KILL_PROCESS or ERRNO(ENOSYS);
        // only seccomp_data's fields are loaded (nr, arch, and argument words' low halves at 16 + 8n).
        let mut returns = [0usize; 3];
        for (index, &(code, jt, jf, k)) in program.iter().enumerate() {
            match code {
                LD_W_ABS => assert!(k == NR || k == ARCH || (16..=56).contains(&k) && k % 8 == 0, "{arch:?} {index}: {k}"),
                JEQ_K | JGE_K => assert!(index + 1 + usize::from(jt.max(jf)) < count, "{arch:?} {index}: jump out"),
                AND_K => {}
                RET_K => match k {
                    SECCOMP_RET_ALLOW => returns[0] += 1,
                    SECCOMP_RET_KILL_PROCESS => returns[1] += 1,
                    SECCOMP_RET_ERRNO_ENOSYS => returns[2] += 1,
                    other => panic!("{arch:?} {index}: return {other:#x}"),
                },
                other => panic!("{arch:?} {index}: opcode {other:#x}"),
            }
        }
        assert!(returns.iter().all(|count| *count > 0), "{arch:?}: {returns:?}");
        assert_eq!(returns[2], 1, "{arch:?}: one ERRNO(ENOSYS) return, clone3's");
    }
}
