#!/usr/bin/env python3
"""HE-001 gate: toolchain pin, workspace and lock, closure table, crt objects, binaries, start-up lint and SBOM.

HE-002C adds three lexical tripwires over the workspace's Rust sources: no refused std path in the sources linked into
EFFECT_GATE (a list of refused modules and items, not an allowlist of std modules), the word `unsafe` only in gate-sys's
openat module, and no code included from a file the scans do not read. They match text, not Rust: the compiler's `#![forbid(unsafe_code)]` on the effect-gate and
i05-protocol roots enforces those crates' unsafe rule, and any form the tripwires do not refuse is code review's.

HE-002S (the EFFECT_GATE process seal) pins the two published EFFECT_GATE seccomp programs among the contract files,
allows the word `unsafe` in gate-sys's seal module too, excepts one occurrence of the one expression that opens the
process's own status file in that module from the start-up lint, and adds two lexical tripwires over the linked
sources: a per-file allowlist of the foreign symbols each may declare (read with comments and literal contents removed,
every `extern` read or refused), and none of a list of std APIs that reach a system call the EFFECT_GATE filter kills
after the seal (HE-002S DESIGN section 5's list plus set_modified and is_terminal).

HE-003A (the effect gate's channel substrate) allows the word `unsafe` in gate-sys's channel module too, with its own
foreign-symbol allowlist, and the std::os::fd items there as in the openat module; turns the start-up lint's exception
into a per-file list of exact expressions, each excepted once (the channel module's two openings in the proc
filesystem); refuses `derive(Debug)`, also under `cfg_attr`, on a struct or enum of the linked crates whose field types
mention a type whose `Debug` would format a `File` or a descriptor; and checks the workspace's shape (HE-002C PR review
round 3, R3-2: members under crates/, crates not a symlink, the crates effect-gate links, edition 2024 inherited and
not overridden by a target table).

HE-003B (the effect gate's I04 TLS server; DESIGN sections 2, 19 and 20) vendors 25 crates under host-enforcement/vendor/
(rustls 0.23.46, ring 0.17.14 and their closure; 11 of them lock-only stubs) and pins them file by file against the
vendor table (check_vendor), which the source scans therefore skip; the cargo configuration gains the vendored source
replacement and the C toolchain's [env] (check_cargo_config, derived from toolchain.json's cToolchain, and the Command
Line Tools' version becomes a failing pin); the lock names exactly the vendored packages with their checksums and
edges; gate-tls joins the linked crates, gate-sys's tcp module the files allowed `unsafe` with its eight foreign items;
derive(Debug) is refused on the secret-holding types; gate-tls's sources pass a TLS deny-list and name the closed
settings exactly once; and the SBOM lists the vendored crates a binary links (none until HE-003D).

HE-003C (the upstream apiserver client; DESIGN section 5, Q-HE3C-5 (b)) keeps the TLS deny-list one global list over
gate-tls's sources and amends it with the client hazards; the client's three closed settings join the exactly-once
rule, tls_client.rs names with_client_auth_cert( and with_webpki_verifier( exactly once each, and among gate-tls's
sources only exchange.rs constructs `UpstreamResponse {`; gate-sys's tcp module gains connect and getsockopt; the
client's configuration, connection and identity types join the secret types and its connector the Debug hazards.

The owner-operated verifier runs it as `python3 -I -B host-enforcement/tools/gate.py` from the repository root, after
the two musl release builds. Stdlib only. Every line it prints starts with "he-gate: ", so no line starts with one of the
verifier's evidence prefixes. It fails closed on the first violation (exit 1).
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
import sys
import tomllib
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HE = ROOT / "host-enforcement"
PREFIX = "he-gate: "
VERSION = "0.1.0"
BINARIES = ("planeon-containment", "planeon-broker", "planeon-observer", "planeon-gate", "planeon-writer")
TABLE = HE / "licenses/closure-1.99.0.json"
TABLE_SHA256 = "e085f1b784c1635b609734575d23d858beaffdd5b8b63a7fce585a38984e54a1"
# HE-003B DESIGN section 2.7: the vendor table (one row per vendored crate), pinned like the sysroot table.
VENDOR = HE / "vendor"
VENDOR_TABLE = HE / "licenses/vendor-crates.json"
VENDOR_TABLE_SHA256 = "32a6dc79a8bf47e04032b245cf2c6364e328074f3e81a2e2a3ee76f4fc19602e"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
# HE-003B DESIGN sections 2.4 and 20: the only registry dependency lines of the workspace, all in gate-tls's
# [dependencies] (the ring dev-dependency fallback of section 9 was not needed, B6).
REGISTRY_LINES = {"crates/gate-tls": {
    "rustls": {"version": "=0.23.46", "default-features": False, "features": ["ring", "std"]},
    "getrandom": {"version": "=0.2.17", "default-features": False, "features": ["linux_disable_fallback"]},
    "zeroize": {"version": "=1.9.1", "default-features": False, "features": ["alloc"]},
}}
# DESIGN sections 2.2 and 19: C-family, assembly and perl suffixes; only ring holds such files, and cc its two
# compiler-probe sources, each pinned by path and sha256.
NATIVE_SUFFIXES = {".c", ".h", ".inl", ".inc", ".cpp", ".cc", ".hpp", ".S", ".s", ".asm", ".pl", ".pm"}
CC_PROBES = {"src/detect_compiler_family.c": "97ca4b021495611e828becea6187add37414186a16dfedd26c2947cbce6e8b2f",
             "src/detect_cpp_stdlib.cpp": "b2ef811b2eaec1bfa305241d3a2ba26ed4c9898dc3a5a076a4ec6fcab8410540"}
# DESIGN section 2.6: among the linked and build-host crates, exactly these have a build script.
BUILD_SCRIPTS = {"libc", "ring", "rustls"}
# harness-onion contract files R10 holds, byte-exact, registered in harness-onion's operator -> harness-engineering
# buildArtifact edge record (owner decision Q-HE2-A; the two EFFECT_GATE programs in its record v2, MET-ENFORCE-025,
# pinned at the published digests); provenance in contracts/PROVENANCE.md.
CONTRACTS = {
    "contracts/i05-v1/README.md": "dc9aa22017b2cdf71f886fb7890aff3f6e7095b9afc25bd37645cb0dee23b498",
    "contracts/i05-v2/README.md": "1cb07cef90b0881c42370d8bbaeea08c6abc48478bed3939286b651601d2cca3",
    "contracts/i05-v3/README.md": "f82f43330125640d3ac946d2afc9a1804a21e5e60a7ac4b94e5d6cb6ed2ea3aa",
    "contracts/i05-v3/channel.schema.json": "3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f",
    "contracts/i05-v3/outcome-mapping.json": "4466f379f1cc669e047cffd8afa5fa88b2cc7648a51e2d38b17f0bd5e2252a3a",
    "contracts/i05-v3/vectors.json": "ab75d86fe54ade7ee2695ef84b200d0473e14e4112e64e7702032593658763ed",
    "contracts/i05-v3-supplement/vectors.json": "1c00bdb3ea112af6098a09158cce3e4a7a6098c9670f490ead4ca65d8bdbb5ac",
    "contracts/i07-v1/README.md": "9e5cb3d1023bc12b9e2643ae42dde5a87640cf04fc8ac1aa88350c65b12ba2dc",
    "contracts/i07-v2/README.md": "cde20d7fee8661cd9314350849870fe5b0838b7914a60237d0eeb1f5dca39d39",
    "contracts/i07-v3/README.md": "a8c51a725b99d84351aba7a326196e7078c239ba4e28d3eaec1cf09fb3dca43d",
    "contracts/i07-v3/channel.schema.json": "c68721a1002fccc7d6e59eeee9016a0a0f4a7428fad714e5a3d90a362d30ce09",
    "contracts/i07-v3/policy-kinds.json": "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0",
    "contracts/i07-v3/vectors.json": "c4c24c5ff15618aa2f0fe0f016011359bc4316220c6e40d5168f9ee24b6f736d",
    "contracts/seccomp-v3/EFFECT_GATE.aarch64.bpf": "0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a",
    "contracts/seccomp-v3/EFFECT_GATE.x86_64.bpf": "ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115",
}
ACCEPTED = ("ACCEPTED_AND", "ACCEPTED_OR", "ALLOWED_EXCEPTION_EXPRESSION", "DEFAULT_ALLOWED")
MACHINE = {"x86_64-unknown-linux-musl": 62, "aarch64-unknown-linux-musl": 183}
RELATIVE = {"x86_64-unknown-linux-musl": 8, "aarch64-unknown-linux-musl": 1027}
FORBIDDEN_SOURCE = ("available_parallelism", "current_exe", "current_dir", "env::var", "var_os", "vars", "/proc", "/sys")
HOST_PATHS = (b"/Users/", b"/opt/planeon/", b"/private/tmp/", b"/private/var/")
# HE-002C DESIGN section 9: the crates EFFECT_GATE will link, checked over their non-test sources (src/).
LINKED_CRATES = ("crates/effect-gate", "crates/gate-sys", "crates/i05-protocol", "crates/gate-tls")
OPENAT = "crates/gate-sys/src/openat.rs"
SEAL = "crates/gate-sys/src/seal.rs"
CHANNEL = "crates/gate-sys/src/channel.rs"
TCP = "crates/gate-sys/src/tcp.rs"
GATE_TLS = "crates/gate-tls"
# The workspace sources where the word unsafe may appear (HE-002C DESIGN section 3, HE-002S DESIGN section 6, HE-003A
# DESIGN section 8, HE-003B DESIGN section 3).
UNSAFE_FILES = (OPENAT, SEAL, CHANNEL, TCP)
# The linked sources that may name std::os::fd items (HE-003A DESIGN section 8): effect-gate holds gate-sys's opaque
# types and names no descriptor.
FD_FILES = (OPENAT, CHANNEL, TCP)
# HE-002S DESIGN section 6 (owner decision Q-HE2S-5 (a), D3; PR review round 1, R1-5) and HE-003A DESIGN section 8:
# the start-up lint's exceptions, a per-file list of exact expressions (whitespace between their tokens ignored), each
# removed once before the scan: in gate-sys's seal module the expression that opens the process's own status file, in
# its channel module the two that open the thread's own attribute directory and a peer's process directory. Any other
# /proc (a second occurrence, a raw string, concat!, another file name, another file) still refuses.
STATUS_READ = 'Dir::at("/proc/self")?.file_ro("status")'
SOCKCREATE_DIR = 'Dir::at("/proc/thread-self/attr")'
PEER_DIR = 'Dir::at(&format!("/proc/{}", pid))'
STARTUP_EXCEPTIONS = {
    SEAL: ((STATUS_READ,
            re.compile(r'\bDir\s*::\s*at\s*\(\s*"/proc/self"\s*\)\s*\?\s*\.\s*file_ro\s*\(\s*"status"\s*\)')),),
    CHANNEL: ((SOCKCREATE_DIR, re.compile(r'\bDir\s*::\s*at\s*\(\s*"/proc/thread-self/attr"\s*\)')),
              (PEER_DIR, re.compile(r'\bDir\s*::\s*at\s*\(\s*&\s*format\s*!\s*\(\s*"/proc/\{\}"\s*,\s*pid\s*\)\s*\)'))),
}
# HE-002S DESIGN section 6 (D8): the foreign symbols each linked source declares, exactly; no other linked source
# declares a foreign item. Extern items are private, none is declared `safe`, and no linked source names link_name.
# PR review round 1, R1-1: the sources are read with comments removed and literal contents emptied (rust_code), every
# `extern` must be a block, `extern crate` or a function's ABI, a block's body must hold only items the reader follows,
# and the files allowed `unsafe` define no macro; anything else refuses. HE-003A DESIGN section 3: the channel module's
# twelve symbols (accept4 only through syscall).
FOREIGN_ITEMS = {OPENAT: {"openat"},
                 SEAL: {"prctl", "capset", "capget", "prlimit", "getresuid", "getresgid", "syscall"},
                 CHANNEL: {"socket", "bind", "listen", "setsockopt", "getsockopt", "recvmsg", "sendmsg", "epoll_create1",
                           "epoll_ctl", "epoll_pwait", "ppoll", "syscall"},
                 # HE-003B DESIGN section 3.1: the I04 listener's eight (accept4 only through syscall); HE-003C DESIGN
                 # sections 5 and 6: the upstream client's connect and getsockopt (SO_ERROR), ten in all.
                 TCP: {"socket", "setsockopt", "bind", "listen", "connect", "getsockopt", "recv", "send", "shutdown",
                       "syscall"}}
# HE-003A DESIGN section 8: the types whose Debug would format a std File (whose own Debug reads the descriptor's link
# with a call the EFFECT_GATE program kills) or print a descriptor. derive(Debug), also under cfg_attr, is refused on a
# struct or enum of the linked crates whose field types mention one of them anywhere (Option<File> included); manual
# impls and direct formatting are code review's.
DEBUG_HAZARDS = ("File", "Dir", "FileStores", "Conn", "Listener", "Poller", "PidFd", "ProcDir", "TcpListener", "TcpConn",
                 "NetTable", "LinuxConnector")
# HE-003B DESIGN section 2.6 (D1-4): the types that hold the server key or rustls's key and configuration objects;
# derive(Debug) is refused on an item named one of them and on an item whose field types mention one.
SECRET_TYPES = ("TlsServerInputs", "PrivateKeyDer", "PrivatePkcs8KeyDer", "CertifiedKey", "ServerConfig",
                "ServerConnection", "ClientConfig", "ClientConnection", "TlsClientIdentity")
DEBUG_HAZARD = re.compile(r"\b(?:%s)\b" % "|".join(DEBUG_HAZARDS + SECRET_TYPES))
OUTER_ATTRIBUTE = re.compile(r"#\s*\[")
ITEM_AFTER_ATTRIBUTES = re.compile(r"\s*(?:#\s*\[|(?:pub\s*(?:\([^)]*\)\s*)?)?(struct|enum|union)\s+([A-Za-z_]\w*))")
FIELD_NAME = re.compile(r"\b[A-Za-z_]\w*\s*:(?!:)")
TYPE_TOKEN = re.compile(r"#\s*\[[^\]]*\]|[A-Za-z_]\w*|\S")
# HE-002C PR review round 3, R3-2 (1)-(4): the workspace's shape.
WORKSPACE_MEMBER = re.compile(r"crates/[A-Za-z0-9_-]+")
WORKSPACE_EDITION = "2024"
EXTERN_WORD = re.compile(r"\bextern\b")
EXTERN_BLOCK = re.compile(r'\bextern\s*(?:""\s*)?\{')
EXTERN_OTHER = re.compile(r'\bextern\s*(?:crate\b|(?:""\s*)?fn\b)')
FOREIGN_ITEM = re.compile(r"\s*(?:unsafe\s+)?(?:fn\s+([A-Za-z_]\w*)\s*\(|static\s+(?:mut\s+)?([A-Za-z_]\w*)\s*:"
                          r"|type\s+([A-Za-z_]\w*)\s*$)")
# The lexer's literals: a character or byte literal (one character or one escape), a raw string's opening, a lifetime
# or label (any other quote is not Rust).
CHAR_LITERAL = re.compile(r"""'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,8}\}|[nrt\\0'"])|[^\\'\n\r\t])'""")
RAW_STRING = re.compile(r'(?<![\w])(?:br|cr|r)(#*)"')
LIFETIME = re.compile(r"'(?:r#)?[^\W\d]\w*")
# HE-002S DESIGN section 5 (D7): std APIs that reach a system call the EFFECT_GATE filter kills, so the code that runs
# after the seal must not name them; matched with the whitespace around `::` removed. The std path openers are
# LINKED_FORBIDDEN's. try_clone (fcntl F_DUPFD_CLOEXEC) is allowed. PR review round 1, R1-2: i05-protocol's code runs
# after the seal too, and is_terminal (musl's isatty: ioctl TIOCGWINSZ) joins the list. It is a list, not a proof:
# anything it does not name is code review's and T04's (the steady-state trace).
POST_SEAL_CRATES = ("crates/effect-gate", "crates/gate-sys", "crates/i05-protocol", "crates/gate-tls")
POST_SEAL_FORBIDDEN = ((r"\bset_nonblocking\b", "set_nonblocking (ioctl FIONBIO)"),
                       (r"\bread_dir\b", "read_dir (getdents64)"),
                       (r"\bcurrent_exe\b", "current_exe (readlink, readlinkat)"),
                       (r"\buname\b", "uname"),
                       (r"\bmembarrier\b", "membarrier"),
                       (r"\bset_len\b", "set_len (ftruncate)"),
                       (r"\bset_permissions\b", "set_permissions (fchmod)"),
                       (r"\bset_times\b", "set_times (utimensat)"),
                       (r"\bset_modified\b", "set_modified (utimensat)"),
                       (r"\bio::copy\b", "io::copy (copy_file_range, sendfile, splice)"),
                       (r"\bio::\{[^}]*\bcopy\b", "io::copy in a grouped import"),
                       (r"\bis_terminal\b", "is_terminal (isatty: ioctl TIOCGWINSZ)"),
                       (r"\bIsTerminal\b", "IsTerminal (isatty: ioctl TIOCGWINSZ)"))
CRATE_ROOTS = {"crates/i05-protocol/src/lib.rs": "#![forbid(unsafe_code)]",
               "crates/effect-gate/src/lib.rs": "#![forbid(unsafe_code)]",
               "crates/gate-sys/src/lib.rs": "#![deny(unsafe_code)]",
               "crates/gate-tls/src/lib.rs": "#![forbid(unsafe_code)]"}
# HE-003B DESIGN section 2.6 (D1-5, D2-1): the TLS deny-list over gate-tls's non-test sources, raw text with comments,
# each a case-sensitive regular expression tolerant of whitespace around `=`, `(` and `::`. HE-003C DESIGN section 5
# (D1-8, Q-HE3C-5 (b)): one global list, kept whole and amended with the client hazards (session stores and TLS 1.2
# resumption, ECH, which sends an outer SNI whatever enable_sni says, a client certificate resolver, ticket requests).
TLS_FORBIDDEN = tuple((re.compile(pattern), name) for pattern, name in (
    (r"KeyLogFile", "KeyLogFile"), (r"SSLKEYLOGFILE", "SSLKEYLOGFILE"), (r"KeyLog", "KeyLog"), (r"key_log", "key_log"),
    (r"PemObject", "PemObject"), (r"pem\s*::", "pem::"), (r"from_pem", "from_pem"),
    (r"install_default", "install_default"), (r"get_default", "get_default"), (r"::\s*builder\s*\(", "::builder("),
    (r"builder_with_protocol_versions", "builder_with_protocol_versions"),
    (r"danger", "danger"), (r"allow_unauthenticated", "allow_unauthenticated"),
    (r"with_no_client_auth", "with_no_client_auth"), (r"NoClientAuth", "NoClientAuth"),
    (r"ServerSessionMemoryCache", "ServerSessionMemoryCache"), (r"Ticketer", "Ticketer"),
    (r"ticketer\s*=(?!=)", "ticketer ="), (r"enable_secret_extraction", "enable_secret_extraction"),
    (r"dangerous_extract_secrets", "dangerous_extract_secrets"),
    (r"in_memory_sessions", "in_memory_sessions"), (r"Resumption\s*::\s*store", "Resumption::store"),
    (r"ClientSessionMemoryCache", "ClientSessionMemoryCache"), (r"tls12_resumption", "tls12_resumption"),
    (r"with_ech", "with_ech"), (r"EchMode", "EchMode"), (r"with_client_cert_resolver", "with_client_cert_resolver"),
    (r"send_ticket_request", "send_ticket_request")))
# The settings gate-tls's sources (read with comments removed and literal contents emptied) name exactly once, each as
# this assignment; and, in tls.rs, the certificate resolver of DESIGN section 20.
TLS_SETTINGS = (("max_early_data_size", r"\bmax_early_data_size\s*=\s*0\b"),
                ("send_tls13_tickets", r"\bsend_tls13_tickets\s*=\s*0\b"),
                ("send_half_rtt_data", r"\bsend_half_rtt_data\s*=\s*false\b"),
                ("session_storage", r"\bsession_storage\s*=\s*Arc\s*::\s*new\s*\(\s*NoServerSessionStorage\s*\{\s*\}\s*\)"),
                # HE-003C DESIGN section 5: the client's positive settings, each counted once across gate-tls too.
                ("resumption", r"\bresumption\s*=\s*Resumption\s*::\s*disabled\s*\(\s*\)"),
                ("enable_early_data", r"\benable_early_data\s*=\s*false\b"),
                ("enable_sni", r"\benable_sni\s*=\s*false\b"))
TLS_RESOLVER = ((r"\bwith_cert_resolver\s*\(", "with_cert_resolver("),
                (r"\bSingleCertAndKey\s*::\s*from\s*\(", "SingleCertAndKey::from("))
# HE-003C DESIGN section 5 (D1-8): the client's authentication and its webpki verifier, each named exactly once, in
# tls_client.rs (mirroring TLS_RESOLVER).
TLS_CLIENT_AUTH = ((r"\bwith_client_auth_cert\s*\(", "with_client_auth_cert("),
                   (r"\bwith_webpki_verifier\s*\(", "with_webpki_verifier("))
# HE-003C DESIGN section 5 (D2-4 of HE-003B): among gate-tls's non-test sources only exchange.rs constructs an
# UpstreamResponse (stage_response and write_response build it from the bytes they digest). Effect-gate's constructions
# are test-only, and its non-test mentions are the definition and patterns, so the rule is scoped to gate-tls.
UPSTREAM_RESPONSE = re.compile(r"\bUpstreamResponse\s*\{")
UPSTREAM_RESPONSE_HOME = "crates/gate-tls/src/exchange.rs"
# The linked-source patterns below are matched against the source with the whitespace around every `::` removed
# (PATH_SPACE), so `std :: process` is `std::process` to them.
PATH_SPACE = re.compile(r"\s*::\s*")
# std's own openers and the modules no linked crate names; the workspace's Gate::create, Gate::open,
# PolicyGate::create, PolicyGate::open and FileStores::open do not match. TryLockError and Metadata are never named.
LINKED_FORBIDDEN = (r"std::process", r"std::env", r"std::net", r"std::path", r"\bPath\b", r"\bPathBuf\b", r"DirBuilder",
                    r"OpenOptions", r"File::open", r"File::create", r"File::options", r"\bTryLockError\b", r"\bMetadata\b")
# Forms that would name std's modules without spelling their paths: a top-level grouped or glob std import (a nested
# group such as std::collections::{..} is still read), a std path a macro completes, and an extern crate (an alias).
LINKED_FORMS = ((re.compile(r"\bextern\s+crate\b"), "declares an extern crate"),
                (re.compile(r"std::[{*]"), "imports a top-level group or glob of std"),
                (re.compile(r"std(?:::\w+)+::\*"), "imports a nested glob of std"),
                (re.compile(r"\bstd\s+as\b"), "renames std"),
                (re.compile(r"std::\$"), "completes a std path in a macro"),
                # PR review round 1, R1-4: the word asm at all (inline assembly needs the asm macro named somewhere in
                # the crate, so no macro or renaming import can call it from a linked source).
                (re.compile(r"\basm\b"), "names asm (inline assembly)"))
# PR review round 1, R1-2: a use declaration (not `use<..>`, precise capturing), read with comments removed and literal
# contents emptied, and its tree's tokens; a tree holding anything else refuses.
USE_DECLARATION = re.compile(r"\buse\b(?!\s*<)([^;]*);")
USE_TOKEN = re.compile(r"\s*(::|[A-Za-z_]\w*|[{},*])")
# The std::os paths a linked source may name besides the fs items: the fd items, in FD_FILES only (HE-003A adds the
# channel module).
OPENAT_FD_PATH = re.compile(r"std::os::fd::\w+")
FD_ITEMS = re.compile(r"std::os::fd|\b(?:FromRawFd|AsRawFd|IntoRawFd|RawFd|OwnedFd|BorrowedFd|AsFd)\b")
# The only std fs items a linked source may name, each where it may (longest first): any other occurrence of the word
# fs (another item, a module import, a grouped import of these) refuses.
FS_ITEMS = (("std::os::unix::fs::MetadataExt", lambda rel: rel.startswith("crates/gate-sys/")),
            ("std::os::unix::fs::FileExt",
             lambda rel: rel.startswith("crates/gate-sys/") or rel == "crates/effect-gate/src/file_store.rs"),
            ("std::fs::File", lambda rel: True))
STD_USE = re.compile(r"\buse\b\s*(?:::)?std\b[^;]*;", re.S)
UNSAFE = re.compile(r"\bunsafe\b")
# Code from a file the scans do not read: a path attribute on a module (also under cfg_attr), and the macro include!
# under any spelling (the word include: include!, a path to it, an import renaming it; include_str! and include_bytes!
# are other words).
INCLUDED_CODE = ((re.compile(r"#\s*!?\s*\[\s*(?:path\b|cfg_attr\s*\([^\]]*\bpath\s*=)"), "has a path attribute"),
                 (re.compile(r"\binclude\b"), "names include"),
                 # Forms the other patterns cannot read: a raw identifier (r#process, r#path) and inline assembly
                 # (asm!, and the words global_asm and naked_asm, so a renaming import is refused too: HE-002C PR
                 # review round 3, R3-1; the word asm after arch:: (also in a group) and before `as`: HE-002S PR
                 # review round 1, R1-4).
                 (re.compile(r"\br#[A-Za-z_]"), "uses a raw identifier"),
                 (re.compile(r"\b(?:global_asm|naked_asm)\b|\basm\s*!|\barch\s*::\s*(?:\{[^}]*)?\basm\b|\basm\s+as\b"),
                  "uses inline assembly"))
# Cargo target tables whose path key would compile a file the scans do not read, and the package's build-script key.
MANIFEST_TARGETS = ("lib", "bin", "test", "bench", "example")
CRT_OBJECTS = ("crtbegin.o", "crtbeginS.o", "crtend.o", "crtendS.o")
CRT_MARKERS = {"crtbegin": ({"__do_init", "__do_fini"}, {"frame_dummy", "__do_global_dtors_aux"}),
               "crtend": ({"__EH_FRAME_LIST_END__"}, {"__FRAME_END__", "__TMC_END__"})}
ET_EXEC, ET_DYN = 2, 3
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474E551, 0x6474E552
PF_X, PF_W = 1, 2
SHT_SYMTAB = 2
DT_NULL, DT_NEEDED, DT_RELA, DT_RELASZ, DT_RELAENT, DT_REL, DT_JMPREL, DT_RELR = 0, 1, 7, 8, 9, 17, 23, 36
DT_FLAGS_1, DF_1_PIE = 0x6FFFFFFB, 0x08000000


class GateError(Exception):
    pass


def say(message: str) -> None:
    for line in str(message).splitlines() or [""]:
        print(PREFIX + line, flush=True)


def require(condition: object, message: str) -> None:
    if not condition:
        raise GateError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def run(argv: list[str]) -> str:
    return subprocess.run(argv, capture_output=True, text=True, check=True, timeout=120).stdout


# --- ELF ----------------------------------------------------------------------------------------------

def elf_header(raw: bytes) -> dict:
    require(len(raw) >= 64 and raw[:4] == b"\x7fELF" and raw[4] == 2 and raw[5] == 1, "not a little-endian ELF64 file")
    e_type, e_machine = struct.unpack_from("<HH", raw, 16)
    e_phoff, e_shoff = struct.unpack_from("<QQ", raw, 32)
    e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHHHH", raw, 54)
    return {"type": e_type, "machine": e_machine, "phoff": e_phoff, "shoff": e_shoff, "phentsize": e_phentsize,
            "phnum": e_phnum, "shentsize": e_shentsize, "shnum": e_shnum, "shstrndx": e_shstrndx}


def program_headers(raw: bytes, header: dict) -> list[tuple]:
    require(header["phentsize"] == 56 and header["phoff"] + header["phnum"] * 56 <= len(raw), "program header table")
    return [struct.unpack_from("<IIQQQQQQ", raw, header["phoff"] + index * 56) for index in range(header["phnum"])]


def sections(raw: bytes, header: dict) -> list[tuple[str, tuple]]:
    """(name, header) pairs in section order; header = (name, type, flags, addr, offset, size, link, info, align, entsize)."""
    require(header["shentsize"] == 64 and header["shoff"] + header["shnum"] * 64 <= len(raw), "section header table")
    require(header["shstrndx"] < header["shnum"], "section name table index")
    entries = [struct.unpack_from("<IIQQQQIIQQ", raw, header["shoff"] + index * 64) for index in range(header["shnum"])]
    names = entries[header["shstrndx"]]
    strtab = raw[names[4]:names[4] + names[5]]
    return [(strtab[entry[0]:strtab.index(b"\0", entry[0])].decode("ascii", "replace"), entry) for entry in entries]


def section_bytes(raw: bytes, entry: tuple) -> bytes:
    require(entry[4] + entry[5] <= len(raw), "section outside the file")
    return raw[entry[4]:entry[4] + entry[5]]


def symbol_names(raw: bytes) -> set[str]:
    """Every symbol name in .symtab, local ones included (the crt markers are static symbols)."""
    table = sections(raw, elf_header(raw))
    symtabs = [entry for _, entry in table if entry[1] == SHT_SYMTAB]
    require(len(symtabs) == 1, "no single .symtab")
    symtab = symtabs[0]
    require(symtab[6] < len(table) and symtab[9] == 24, "symbol table layout")
    strings = section_bytes(raw, table[symtab[6]][1])
    entries = section_bytes(raw, symtab)
    names = set()
    for offset in range(0, len(entries) - len(entries) % 24, 24):
        name_offset = struct.unpack_from("<I", entries, offset)[0]
        names.add(strings[name_offset:strings.index(b"\0", name_offset)].decode("ascii", "replace"))
    names.discard("")
    return names


def vaddr_offset(phdrs: list[tuple], vaddr: int) -> int:
    for p_type, _, offset, address, _, filesz, _, _ in phdrs:
        if p_type == PT_LOAD and address <= vaddr < address + filesz:
            return offset + (vaddr - address)
    raise GateError("address outside every PT_LOAD")


def comment_markers(pin: dict) -> tuple[bytes, bytes]:
    """The .comment lines every binary must carry: rustc's release and commit, and LLD of rustc's LLVM version."""
    return (("rustc version %s (%s " % (pin["rustc"]["release"], pin["rustc"]["commit"][:9])).encode(),
            ("Linker: LLD %s " % pin["rustc"]["llvm"]).encode())


def check_binary(raw: bytes, target: str, shape: str, markers: tuple[bytes, bytes],
                 host_paths: tuple[bytes, ...] = HOST_PATHS) -> None:
    header = elf_header(raw)
    require(header["machine"] == MACHINE[target], "wrong e_machine")
    phdrs = program_headers(raw, header)
    types = [p[0] for p in phdrs]
    require(PT_INTERP not in types, "PT_INTERP present")
    stacks = [p for p in phdrs if p[0] == PT_GNU_STACK]
    require(len(stacks) == 1 and not stacks[0][1] & PF_X, "PT_GNU_STACK missing or executable")
    require(not any(p[0] == PT_LOAD and p[1] & PF_W and p[1] & PF_X for p in phdrs), "a writable and executable PT_LOAD")
    if shape == "static-pie":
        require(header["type"] == ET_DYN, "static-pie must be ET_DYN")
        require(PT_GNU_RELRO in types, "PT_GNU_RELRO missing")
        dynamic = [p for p in phdrs if p[0] == PT_DYNAMIC]
        require(len(dynamic) == 1 and dynamic[0][2] + dynamic[0][5] <= len(raw), "static-pie needs exactly one PT_DYNAMIC")
        tags: dict[int, int] = {}
        for offset in range(dynamic[0][2], dynamic[0][2] + dynamic[0][5] - 15, 16):
            tag, value = struct.unpack_from("<qQ", raw, offset)
            if tag == DT_NULL:
                break
            require(tag != DT_NEEDED, "DT_NEEDED in a static binary")
            require(tag not in (DT_REL, DT_JMPREL, DT_RELR), "relocations other than RELA")
            tags[tag] = value
        require(tags.get(DT_FLAGS_1, 0) & DF_1_PIE, "DF_1_PIE missing")
        if DT_RELA in tags:
            require(tags.get(DT_RELAENT) == 24, "RELA entry size")
            start = vaddr_offset(phdrs, tags[DT_RELA])
            require(start + tags.get(DT_RELASZ, 0) <= len(raw), "RELA table outside the file")
            for offset in range(start, start + tags.get(DT_RELASZ, 0), 24):
                info = struct.unpack_from("<Q", raw, offset + 8)[0]
                require(info & 0xFFFFFFFF == RELATIVE[target], "a non-relative relocation")
    else:
        require(shape == "static" and header["type"] == ET_EXEC and PT_DYNAMIC not in types,
                "static must be ET_EXEC without PT_DYNAMIC")
    comments = [entry for name, entry in sections(raw, header) if name == ".comment"]
    require(len(comments) == 1, ".comment missing")
    lines = section_bytes(raw, comments[0]).split(b"\0")
    for marker in markers:
        require(any(line.startswith(marker) for line in lines), ".comment does not name %s" % marker.decode().strip())
    for needle in host_paths:
        require(needle not in raw, "a build-host path is in the binary")


def check_crt_symbols(name: str, names: set[str]) -> None:
    required, forbidden = CRT_MARKERS["crtbegin" if name.startswith("crtbegin") else "crtend"]
    require(required <= names and not forbidden & names, "%s is not compiler-rt's crt object" % name)


# --- toolchain, workspace, table, sources ---------------------------------------------------------------

def check_toolchain(pin: dict) -> str:
    fields = dict(line.split(": ", 1) for line in run(["rustc", "-vV"]).splitlines()[1:] if ": " in line)
    require(fields.get("release") == pin["rustc"]["release"] and fields.get("commit-hash") == pin["rustc"]["commit"]
            and fields.get("host") == pin["host"] and fields.get("LLVM version") == pin["rustc"]["llvm"],
            "rustc is not the pinned toolchain")
    require(run(["cargo", "-V"]).strip() == pin["cargo"], "cargo is not the pinned toolchain")
    sysroot = run(["rustc", "--print", "sysroot"]).strip()
    require(sysroot == pin["sysroot"], "rustc's sysroot is not the pinned tree")
    for target in pin["targets"]:
        libdir = run(["rustc", "--print", "target-libdir", "--target", target]).strip()
        require(libdir == "%s/lib/rustlib/%s/lib" % (sysroot, target), "target libdir for " + target)
    tools = Path(pin["commandLineTools"]["path"])
    clang = tools / "usr/bin/clang"
    settings = tools / "SDKs/MacOSX.sdk/SDKSettings.json"
    require(clang.is_file() and settings.is_file(), "the Command Line Tools are missing")
    found = run([str(clang), "--version"]).splitlines()[0]
    sdk = json.loads(settings.read_text(encoding="utf-8"))["Version"]
    say("toolchain: rustc %s (%s), %s; Command Line Tools: %s, SDK %s"
        % (fields["release"], fields["commit-hash"][:9], pin["cargo"], found, sdk))
    # HE-003B DESIGN section 2.5 (owner decision Q-HE3B-3 (a)): ring's C and assembly in the effect gate are compiled by
    # this clang, so a different clang version or SDK fails; the pinned compiler and archiver are the Command Line
    # Tools' own, xcode-select names them (so the /usr/bin/cc shim of the darwin build resolves to the same clang), and
    # nothing earlier on PATH shadows cc or ar (Q-HE3B-23 (a)).
    require((found, sdk) == (pin["commandLineTools"]["clang"], pin["commandLineTools"]["sdk"]),
            "the Command Line Tools differ from toolchain.json (clang %r, SDK %r)" % (found, sdk))
    c_toolchain = pin["cToolchain"]
    require(c_toolchain["compiler"] == str(clang), "the pinned C compiler is not the Command Line Tools' clang")
    require(c_toolchain["archiver"] == str(tools / "usr/bin/ar") and Path(c_toolchain["archiver"]).is_file(),
            "the pinned archiver is not the Command Line Tools' ar")
    require(run(["xcode-select", "-p"]).strip() == str(tools), "xcode-select does not name the pinned Command Line Tools")
    require(shutil.which("cc") == "/usr/bin/cc" and shutil.which("ar") == "/usr/bin/ar",
            "the first cc and ar on PATH are not /usr/bin/cc and /usr/bin/ar")
    return sysroot


def cargo_env(pin: dict) -> dict:
    """The cargo config's [env], derived from toolchain.json's cToolchain (HE-003B DESIGN section 2.3): the pinned
    compiler and archiver for both musl targets and the x86_64 flag line, each in its `force = true` form."""
    c_toolchain = pin["cToolchain"]
    env = {}
    for target in pin["targets"]:
        key = target.replace("-", "_")
        env["CC_" + key] = {"value": c_toolchain["compiler"], "force": True}
        env["AR_" + key] = {"value": c_toolchain["archiver"], "force": True}
        if c_toolchain["cflags"].get(target):
            env["CFLAGS_" + key] = {"value": c_toolchain["cflags"][target], "force": True}
    return env


VENDORED_SOURCE = {"crates-io": {"replace-with": "vendored-sources"},
                   "vendored-sources": {"directory": "host-enforcement/vendor"}}


def check_cargo_config(pin: dict, root: Path) -> None:
    """The repository-root cargo config (HE-003B DESIGN section 2.6, formerly check_linker): exactly [net], [target],
    [source] and [env]; it links both musl targets through the wrapper, and the wrapper execs the pinned rust-lld with
    the pinned sysroot's lib/ on the dylib search path (so a pin change cannot miss the wrapper); crates.io is replaced
    by the vendored directory source; [env] is the table derived from cToolchain."""
    config = tomllib.loads((root / ".cargo/config.toml").read_text(encoding="utf-8"))
    require(set(config) == {"net", "target", "source", "env"},
            "the cargo config must hold only [net], [target], [source] and [env]")
    require(config.get("net") == {"offline": True}, "the cargo config must set [net] offline = true and nothing else")
    flags = ["-C", "link-self-contained=yes", "-C", "target-feature=+crt-static"]
    require(set(config.get("target", {})) == set(pin["targets"]), "the cargo config must name exactly the pinned targets")
    for target in pin["targets"]:
        require(config["target"][target] == {"linker": pin["linkerWrapper"], "rustflags": flags},
                "the cargo config for %s is not the wrapper with the static flags" % target)
    require(config.get("source") == VENDORED_SOURCE, "the cargo config's [source] is not the vendored directory source")
    require(config.get("env") == cargo_env(pin), "the cargo config's [env] is not the table toolchain.json pins")
    lines = (root / pin["linkerWrapper"]).read_text(encoding="utf-8").splitlines()
    require(lines[:1] == ["#!/bin/sh"], "the linker wrapper must start with #!/bin/sh")
    commands = [line for line in lines if line and not line.startswith("#")]
    require(commands == ["DYLD_FALLBACK_LIBRARY_PATH=%s/lib" % pin["sysroot"], "export DYLD_FALLBACK_LIBRARY_PATH",
                         'exec %s/lib/rustlib/%s/bin/rust-lld "$@"' % (pin["sysroot"], pin["host"])],
            "the linker wrapper does not exec the pinned rust-lld")


def check_contracts(base: Path) -> int:
    """Every registered harness-onion contract file is present byte-exact, and contracts/ holds nothing else."""
    root = base / "contracts"
    found = {path.relative_to(base).as_posix() for path in root.rglob("*") if path.is_file() or path.is_symlink()}
    require(found == set(CONTRACTS) | {"contracts/PROVENANCE.md"}, "contracts/ holds exactly the registered files")
    for path, expected in CONTRACTS.items():
        require(not (base / path).is_symlink() and sha256((base / path).read_bytes()) == expected,
                "a contract file differs from its registered bytes: " + path)
    return len(CONTRACTS)


def linked(dependencies: dict, name: str) -> set:
    """The workspace crates in a crate's dependency closure, the crate included."""
    seen, todo = set(), [name]
    while todo:
        crate = todo.pop()
        if crate not in seen:
            seen.add(crate)
            todo.extend(dependencies[crate])
    return seen


def check_workspace(base: Path, vendor: list[dict] | None = None) -> dict:
    """The workspace members, each with its direct workspace (path) dependencies. HE-003B DESIGN section 2.6: besides
    path dependencies, only REGISTRY_LINES (gate-tls's exact registry lines); no [patch] or [replace]; in Cargo.lock the
    packages without a source are exactly the workspace crates, and the packages with one are exactly the vendor table's
    rows (`vendor`), each from crates.io with the row's checksum and dependency list."""
    workspace = tomllib.loads((base / "Cargo.toml").read_text(encoding="utf-8"))
    require("patch" not in workspace and "replace" not in workspace, "the workspace manifest has a [patch] or [replace]")
    names, paths = {}, {}
    manifests = []
    for member in workspace["workspace"]["members"]:
        manifest = tomllib.loads((base / member / "Cargo.toml").read_text(encoding="utf-8"))
        package = manifest["package"]
        require("build" not in package and not (base / member / "build.rs").exists(), "a build script in " + member)
        library = manifest.get("lib", {})
        require(not library.get("proc-macro") and not library.get("proc_macro"), "a proc-macro crate in " + member)
        require("build-dependencies" not in manifest and "target" not in manifest, "build or target dependencies in " + member)
        # A feature could enable a registry crate's features (rustls/tls12) without changing Cargo.lock (PR review R1-3).
        require("features" not in manifest, "a [features] table in " + member)
        names[package["name"]] = set()
        paths[(base / member).resolve()] = package["name"]
        manifests.append((member, package["name"], manifest))
    for member, name, manifest in manifests:
        lines = REGISTRY_LINES.get(member, {})
        for table in ("dependencies", "dev-dependencies"):
            for dependency, spec in manifest.get(table, {}).items():
                if table == "dependencies" and dependency in lines:
                    require(spec == lines[dependency], "the registry dependency %s of %s is not its pinned line"
                            % (dependency, member))
                    continue
                require(type(spec) is dict and set(spec) == {"path"} and (base / member / spec["path"]).resolve() in paths
                        and paths[(base / member / spec["path"]).resolve()] == dependency,
                        "a dependency outside the workspace in " + member)
                if table == "dependencies":
                    names[name].add(dependency)
    packages = tomllib.loads((base / "Cargo.lock").read_text(encoding="utf-8"))["package"]
    local = [package for package in packages if "source" not in package]
    require(sorted(package["name"] for package in local) == sorted(names) and all("checksum" not in package for package in local),
            "Cargo.lock does not list exactly the workspace crates")
    rows = {(row["name"], row["version"]): row for row in (vendor or [])}
    registry = [package for package in packages if "source" in package]
    require(len(registry) == len(rows) and all(package["source"] == REGISTRY and (package["name"], package["version"]) in rows
                                               for package in registry),
            "Cargo.lock names a registry or git package outside the vendor table")
    for package in registry:
        row = rows[(package["name"], package["version"])]
        require(package.get("checksum") == row["sha256"], "Cargo.lock's checksum of %s is not the approved one" % row["name"])
        require(sorted(package.get("dependencies", [])) == row["dependencies"],
                "Cargo.lock's dependencies of %s are not the vendor table's" % row["name"])
    return names


def load_table(raw: bytes, expected: str) -> list[dict]:
    require(sha256(raw) == expected, "the closure table is not the reviewed table")
    table = json.loads(raw)
    require(table["acceptedOutcomes"] == list(ACCEPTED), "accepted outcomes changed")
    keys = [(row["target"], row["path"]) for row in table["rows"]]
    require(len(set(keys)) == len(keys), "duplicate closure rows")
    require(all(row["outcome"] in ACCEPTED for row in table["rows"]), "an outcome that is not accepted")
    return table["rows"]


def check_tree(rows: list[dict], sysroot: Path, targets: list[str]) -> None:
    for target in targets:
        base = sysroot / "lib/rustlib" / target
        files = {}
        for path in base.rglob("*"):
            require(not path.is_symlink(), "a symbolic link in the toolchain tree")
            if path.is_file():
                files[path.relative_to(base).as_posix()] = sha256(path.read_bytes())
        expected = {row["path"]: row["sha256"] for row in rows if row["target"] == target}
        require(files and set(files) == set(expected), "the shipped files of %s differ from the closure table" % target)
        require(all(files[path] == expected[path] for path in files), "a shipped file of %s differs from its row" % target)


def check_sources(base: Path) -> int:
    """The start-up lint: no workspace source contains a forbidden token, except one occurrence of each expression
    STARTUP_EXCEPTIONS allows in its file (removed before the scan, so a second occurrence or any other form still
    refuses)."""
    count = 0
    for path in sorted(base.rglob("*.rs")):
        if path.relative_to(base).parts[0] in ("target", "vendor"):   # the build directory; the pinned vendored crates
            continue
        rel = path.relative_to(base).as_posix()
        text = path.read_text(encoding="utf-8")
        for _, expression in STARTUP_EXCEPTIONS.get(rel, ()):
            text = expression.sub("", text, count=1)
        for token in FORBIDDEN_SOURCE:
            require(token not in text, "%s uses %s (start-up lint)" % (rel, token))
        count += 1
    return count


def workspace_sources(base: Path) -> list[Path]:
    """Every .rs file of the workspace outside the build directory and the vendored crates (tests and binaries
    included). HE-003B DESIGN section 2.1: vendor/ is excluded because check_vendor pins every file under it."""
    return [path for path in sorted(base.rglob("*.rs")) if path.relative_to(base).parts[0] not in ("target", "vendor")]


def check_included_code(base: Path) -> int:
    """A lexical tripwire: no workspace source takes code from a file the other scans do not read (a path attribute,
    include!, a crate manifest's target path or build key, a symlink under crates/) or uses a form the other patterns
    cannot read (a raw identifier, inline assembly), and a crate's src/ holds only .rs files."""
    for path in sorted((base / "crates").rglob("*")):
        require(not path.is_symlink(), "%s is a symlink under crates/" % path.relative_to(base).as_posix())
    for manifest in sorted(base.glob("crates/*/Cargo.toml")):
        table = tomllib.loads(manifest.read_text(encoding="utf-8"))
        rel = manifest.relative_to(base).as_posix()
        require("build" not in table.get("package", {}), "%s names a build script" % rel)
        for kind in MANIFEST_TARGETS:
            targets = table.get(kind, [])
            for target in targets if isinstance(targets, list) else [targets]:
                require(not isinstance(target, dict) or "path" not in target, "%s gives a %s target a path" % (rel, kind))
    for directory in sorted(base.glob("crates/*/src")):
        for path in sorted(directory.rglob("*")):
            require(path.is_dir() and not path.is_symlink() or path.suffix == ".rs",
                    "%s is not a .rs file but lies under a crate's src/" % path.relative_to(base).as_posix())
    count = 0
    for path in workspace_sources(base):
        text = path.read_text(encoding="utf-8")
        for pattern, form in INCLUDED_CODE:
            require(not pattern.search(text), "%s %s (code from a file the scans do not read)"
                    % (path.relative_to(base).as_posix(), form))
        count += 1
    return count


def rust_code(text: str, comments: bool = False) -> str:
    """A source as the lexical checks read it (HE-002S PR review round 1, R1-1): line and nested block comments become
    one space (kept as they are with `comments`), string, byte-string and C-string literals keep only their quotes and
    prefix (`""`, `b""`), raw-string literals become `""`, and character and byte literals become `''` (`b''`);
    lifetimes and labels stay. Anything it cannot lex
    refuses: an unterminated block comment or literal, or a quote that starts neither a character literal nor a
    lifetime."""
    out, index, length = [], 0, len(text)
    while index < length:
        char = text[index]
        if text.startswith("//", index):
            end = text.find("\n", index)
            end = length if end < 0 else end
            out.append(text[index:end] if comments else " ")
            index = end
        elif text.startswith("/*", index):
            depth, cursor = 1, index + 2
            while depth:
                require(cursor < length, "an unterminated block comment")
                if text.startswith("/*", cursor):
                    depth, cursor = depth + 1, cursor + 2
                elif text.startswith("*/", cursor):
                    depth, cursor = depth - 1, cursor + 2
                else:
                    cursor += 1
            out.append(text[index:cursor] if comments else " ")
            index = cursor
        elif char in "bcr" and (raw := RAW_STRING.match(text, index)):
            end = text.find('"' + raw.group(1), raw.end())
            require(end >= 0, "an unterminated raw string literal")
            out.append('""')
            index = end + 1 + len(raw.group(1))
        elif char == '"':
            cursor = index + 1
            while True:
                require(cursor < length, "an unterminated string literal")
                if text[cursor] == "\\":
                    cursor += 2
                elif text[cursor] == '"':
                    break
                else:
                    cursor += 1
            out.append('""')
            index = cursor + 1
        elif char == "'":
            literal = CHAR_LITERAL.match(text, index)
            if literal:
                out.append("''")
                index = literal.end()
            else:
                lifetime = LIFETIME.match(text, index)
                require(lifetime, "a quote that starts neither a character literal nor a lifetime")
                out.append(lifetime.group(0))
                index = lifetime.end()
        else:
            out.append(char)
            index += 1
    return "".join(out)


def use_paths(tree: str) -> list[tuple[tuple[str, ...], str | None]]:
    """The paths of a use declaration's tree (the text between `use` and `;`), each with its rename or None; a leading
    `::` is dropped, and `self` stays a segment. A tree holding anything but identifiers, `::`, braces, commas and `*`,
    or not in use-tree form, refuses."""
    tokens, index = [], 0
    while tree[index:].strip():
        token = USE_TOKEN.match(tree, index)
        require(token, "a use declaration the linked-source check cannot read")
        tokens.append(token.group(1))
        index = token.end()
    paths: list[tuple[tuple[str, ...], str | None]] = []

    def at(position: int) -> str:
        require(position < len(tokens), "a use declaration the linked-source check cannot read")
        return tokens[position]

    def identifier(token: str) -> bool:
        return token not in ("::", "{", "}", ",", "*", "as")

    def read(position: int, prefix: tuple[str, ...]) -> int:
        if not prefix and at(position) == "::":
            position += 1
        path = prefix
        while True:
            token = at(position)
            if token == "*":
                paths.append((path + ("*",), None))
                return position + 1
            if token == "{":
                position += 1
                while at(position) != "}":
                    position = read(position, path)
                    if at(position) == ",":
                        position += 1
                    else:
                        require(at(position) == "}", "a use declaration the linked-source check cannot read")
                return position + 1
            require(identifier(token), "a use declaration the linked-source check cannot read")
            path, position = path + (token,), position + 1
            if position < len(tokens) and tokens[position] == "::":
                position += 1
                continue
            rename = None
            if position < len(tokens) and tokens[position] == "as":
                rename = at(position + 1)
                require(identifier(rename), "a use declaration the linked-source check cannot read")
                position += 2
            paths.append((path, rename))
            return position

    require(read(0, ()) == len(tokens), "a use declaration the linked-source check cannot read")
    return paths


def source_uses(rel: str, raw: str) -> list[tuple[tuple[str, ...], str | None]]:
    """Every path (with its rename) of a source's use declarations, read with comments and literal contents removed;
    a source or declaration the reader cannot follow refuses, naming the file."""
    try:
        return [path for declaration in USE_DECLARATION.finditer(rust_code(raw))
                for path in use_paths(declaration.group(1))]
    except GateError as error:
        raise GateError("%s: %s (linked-source tripwire)" % (rel, error)) from None


def std_names(uses: list[tuple[tuple[str, ...], str | None]]) -> set[str]:
    """`std` and every name the given use paths bind from a std path: the rename, the last segment, or the module
    before a `self` (renames and globs of std are refused by the linked-source checks themselves)."""
    names = {"std"}
    for path, rename in uses:
        if path[0] == "std" and path[-1] != "*":
            names.add(rename or (path[-2] if path[-1] == "self" and len(path) > 1 else path[-1]))
    return names


def check_linked_sources(base: Path) -> int:
    """A lexical tripwire over the non-test sources of the crates EFFECT_GATE will link, with the whitespace around `::`
    removed first: none names a refused std path (LINKED_FORBIDDEN; the fd items outside FD_FILES; std fs items
    other than the allowed ones; std::os paths other than those), renames a std module or item, or uses a form that
    names std's modules without spelling their paths or the word asm (LINKED_FORMS); and their crate-root attributes.
    A rename is refused in a use of std and, read from the source with comments and literal contents removed, in any
    use whose renamed path has a segment that is `std` or a name some linked source imports from std (the union over
    the three crates, whatever the order, so a `crate::`, `self::` or `super::` path through such a name refuses too;
    HE-002S PR review round 1, R1-2); a glob is refused through the same names (round 2, R2-1). Other std paths pass: it refuses a list, it is not an allowlist of std modules. It
    matches text, not Rust: the compiler's `#![forbid(unsafe_code)]` enforces the roots' rule, and any other form is
    code review's."""
    for root, attribute in CRATE_ROOTS.items():
        require(attribute in (base / root).read_text(encoding="utf-8").splitlines(), "%s lacks %s" % (root, attribute))
    sources = [(path.relative_to(base).as_posix(), path.read_text(encoding="utf-8"))
               for crate in LINKED_CRATES for path in sorted((base / crate / "src").rglob("*.rs"))]
    uses = {rel: source_uses(rel, raw) for rel, raw in sources}
    from_std = std_names([path for paths in uses.values() for path in paths])
    count = 0
    for rel, raw in sources:
        text = PATH_SPACE.sub("::", raw)
        for pattern in LINKED_FORBIDDEN:
            require(not re.search(pattern, text), "%s names %s (linked-source tripwire)" % (rel, pattern.replace("\\b", "")))
        require(rel in FD_FILES or not FD_ITEMS.search(text),
                "%s names a std::os::fd item outside %s" % (rel, " and ".join(FD_FILES)))
        rest = text
        for item, allowed in FS_ITEMS:
            if allowed(rel):
                rest = re.sub(re.escape(item) + r"(?!\w)", "", rest)
        require(not re.search(r"\bfs\b", rest),
                "%s names a std fs item other than its allowed ones, one item per use line (linked-source tripwire)" % rel)
        if rel in FD_FILES:
            rest = OPENAT_FD_PATH.sub("", rest)
        require(not re.search(r"std::os\b", rest),
                "%s names a std::os item other than its allowed ones (linked-source tripwire)" % rel)
        for use in STD_USE.finditer(text):
            require(not re.search(r"\sas\s", use.group(0)), "%s renames a std item in a use statement" % rel)
        for pattern, form in LINKED_FORMS:
            require(not pattern.search(text), "%s %s (linked-source tripwire)" % (rel, form))
        for path, rename in uses[rel]:
            require(rename is None or not from_std & set(path),
                    "%s renames a std module or item through a use of a name imported from std (linked-source "
                    "tripwire)" % rel)
            # HE-002S PR review round 2, R2-1: a glob through std or a name imported from std would name std's items
            # without spelling them.
            require(path[-1] != "*" or not from_std & set(path[:-1]),
                    "%s imports a glob through std or a name imported from std (linked-source tripwire)" % rel)
        count += 1
    return count


def extern_blocks(text: str) -> list[str]:
    """The bodies of a source's extern blocks, read from the source with comments removed and literal contents emptied
    (rust_code), so neither can hide a block or end one early: from each block's opening brace to its matching one.
    Every other `extern` must be `extern crate` or a function's ABI (`extern "C" fn`); any other form refuses, since
    the check could not read it (HE-002S PR review round 1, R1-1)."""
    code = rust_code(text)
    blocks = []
    for word in EXTERN_WORD.finditer(code):
        block = EXTERN_BLOCK.match(code, word.start())
        if block is None:
            require(EXTERN_OTHER.match(code, word.start()), "an extern the foreign-item check cannot read")
            continue
        depth, index = 1, block.end()
        while depth and index < len(code):
            depth += {"{": 1, "}": -1}.get(code[index], 0)
            index += 1
        require(depth == 0, "an extern block without its closing brace")
        blocks.append(code[block.end():index - 1])
    return blocks


def foreign_items(body: str) -> set[str]:
    """The symbols an extern block's body (from extern_blocks) declares, read strictly: items ending in `;` outside
    parentheses and brackets, each a `fn` (also `unsafe fn`), `static` (also `mut`) or `type` with its name. A body
    holding anything the reader does not follow (a macro call or metavariable, `!` or `$`; an attribute, `#`; a brace;
    an initialiser, `=`) or an item of another form refuses."""
    require(not any(char in body for char in "$!#{}="), "an extern block the foreign-item check cannot read")
    names, depth, start = set(), 0, 0
    for index, char in enumerate(body):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
            require(depth >= 0, "an extern block the foreign-item check cannot read")
        elif char == ";" and depth == 0:
            item = FOREIGN_ITEM.match(body[start:index])
            require(item, "an extern block the foreign-item check cannot read")
            names.add(next(name for name in item.groups() if name))
            start = index + 1
    require(depth == 0 and not body[start:].strip(), "an extern block the foreign-item check cannot read")
    return names


def check_foreign_items(base: Path) -> int:
    """A lexical tripwire over the non-test sources of the linked crates (HE-002S DESIGN section 6, D8): each file of
    FOREIGN_ITEMS declares exactly its foreign symbols, no other linked source declares one, no extern item is public or
    declared `safe`, and no linked source names link_name. The sources are read with comments removed and literal
    contents emptied; every `extern` is an extern block, read strictly (foreign_items), `extern crate` or a function's
    ABI; and the files allowed `unsafe` define no macro (`macro_rules`, or any `$` outside string and character
    literals). Anything the check cannot read refuses, so it reads every extern block of these sources (HE-002S PR
    review round 1, R1-1)."""
    count = 0
    for crate in LINKED_CRATES:
        for path in sorted((base / crate / "src").rglob("*.rs")):
            rel = path.relative_to(base).as_posix()
            text = path.read_text(encoding="utf-8")
            require(not re.search(r"\blink_name\b", text), "%s names link_name (foreign-item check)" % rel)
            try:
                if rel in UNSAFE_FILES:
                    kept = rust_code(text, comments=True)
                    require(not re.search(r"\bmacro_rules\b", kept) and "$" not in kept,
                            "defines a macro (macro_rules or $), which the check cannot read")
                blocks = extern_blocks(text)
            except GateError as error:
                raise GateError("%s: %s (foreign-item check)" % (rel, error)) from None
            declared = set()
            for body in blocks:
                require(not re.search(r"\bpub\b", body), "%s declares a public foreign item (foreign-item check)" % rel)
                require(not re.search(r"\bsafe\b", body), "%s declares a safe foreign item (foreign-item check)" % rel)
                try:
                    declared |= foreign_items(body)
                except GateError as error:
                    raise GateError("%s: %s (foreign-item check)" % (rel, error)) from None
            allowed = FOREIGN_ITEMS.get(rel, set())
            require(declared == allowed, "%s declares the foreign items %s, not exactly %s (foreign-item check)"
                    % (rel, sorted(declared), sorted(allowed)))
            count += 1
    for rel in FOREIGN_ITEMS:
        require((base / rel).is_file(), "%s is missing (foreign-item check)" % rel)
    return count


def check_post_seal_sources(base: Path) -> int:
    """A lexical tripwire over the non-test sources of effect-gate, gate-sys and i05-protocol, whose code runs after the
    seal, with the whitespace around `::` removed: none of the std APIs of POST_SEAL_FORBIDDEN (HE-002S DESIGN section
    5's list plus set_modified and is_terminal), each of which reaches a system call the EFFECT_GATE filter kills. A
    std API the list does not name is code review's and T04's (HE-002S PR review round 1, R1-2)."""
    count = 0
    for crate in POST_SEAL_CRATES:
        for path in sorted((base / crate / "src").rglob("*.rs")):
            rel = path.relative_to(base).as_posix()
            text = PATH_SPACE.sub("::", path.read_text(encoding="utf-8"))
            for pattern, name in POST_SEAL_FORBIDDEN:
                require(not re.search(pattern, text), "%s names %s (post-seal check)" % (rel, name))
            count += 1
    return count


def check_unsafe(base: Path) -> int:
    """A lexical tripwire: the word unsafe appears in no workspace source but gate-sys's openat, seal and channel modules
    (tests and binaries included)."""
    count = 0
    for path in workspace_sources(base):
        rel = path.relative_to(base).as_posix()
        if rel not in UNSAFE_FILES:
            require(not UNSAFE.search(path.read_text(encoding="utf-8")),
                    "%s contains unsafe outside %s" % (rel, " and ".join(UNSAFE_FILES)))
        count += 1
    return count


def bracket_end(code: str, start: int) -> int:
    """The index after the `]` that closes the `[` at or after `start` (literal contents are already emptied)."""
    depth = 0
    for index in range(code.index("[", start), len(code)):
        if code[index] == "[":
            depth += 1
        elif code[index] == "]":
            depth -= 1
            if depth == 0:
                return index + 1
    raise GateError("an attribute without its closing bracket")


def item_rest(code: str, start: int) -> str:
    """An item's text from `start` (after its name) to its end: the `}` that closes its body, or the `;` at depth 0
    (a tuple or unit struct). Anything else refuses."""
    depth = 0
    for index in range(start, len(code)):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            require(depth >= 0, "an item the Debug check cannot read")
            if depth == 0 and char == "}":
                return code[start:index + 1]
        elif char == ";" and depth == 0:
            return code[start:index]
    raise GateError("an item the Debug check cannot read")


def field_types(kind: str, rest: str) -> str:
    """The text of an item's field types: its generics, body and payloads with the field names removed and, for an
    enum, the variant names (the first identifier after the body's `{` or a `,` at the body's depth) removed too."""
    text = FIELD_NAME.sub(" ", rest)
    if kind != "enum":
        return text
    kept, depth, at_variant = [], 0, False
    for match in TYPE_TOKEN.finditer(text):
        token = match.group(0)
        if token.startswith("#"):
            continue
        if token in ("(", "[", "{"):
            depth += 1
            at_variant = depth == 1 and token == "{"
        elif token in (")", "]", "}"):
            depth -= 1
            at_variant = False
        elif token == ",":
            at_variant = depth == 1
        elif at_variant and re.match(r"[A-Za-z_]", token):
            at_variant = False
            continue
        kept.append(token)
    return " ".join(kept)


def check_debug_derives(base: Path) -> int:
    """A lexical tripwire over the sources of the crates EFFECT_GATE will link (HE-003A DESIGN section 8), read with
    comments removed and literal contents emptied: an outer attribute that derives Debug (`derive(.. Debug ..)`, also
    inside `cfg_attr`) must be followed, after other attributes and a visibility, by a struct, enum or union whose field
    types mention none of DEBUG_HAZARDS (field and variant names are not types). An attribute or item the check cannot
    read refuses. Manual impls and direct formatting are code review's."""
    count = 0
    for crate in LINKED_CRATES:
        for path in sorted((base / crate / "src").rglob("*.rs")):
            rel = path.relative_to(base).as_posix()
            try:
                code = rust_code(path.read_text(encoding="utf-8"))
                for attribute in OUTER_ATTRIBUTE.finditer(code):
                    end = bracket_end(code, attribute.start())
                    body = code[attribute.start():end]
                    if not (re.search(r"\bderive\s*\(", body) and re.search(r"\bDebug\b", body)):
                        continue
                    cursor = end
                    while True:
                        item = ITEM_AFTER_ATTRIBUTES.match(code, cursor)
                        require(item, "a derive(Debug) on something the Debug check cannot read")
                        if item.group(1) is None:   # another attribute first
                            cursor = bracket_end(code, item.end() - 1)
                            continue
                        break
                    require(item.group(2) not in SECRET_TYPES, "%s derives Debug on %s %s, a secret type (Debug check)"
                            % (rel, item.group(1), item.group(2)))
                    types = field_types(item.group(1), item_rest(code, item.end()))
                    hazard = DEBUG_HAZARD.search(types)
                    require(not hazard, "%s derives Debug on %s %s, whose field types mention %s (Debug check)"
                            % (rel, item.group(1), item.group(2), hazard.group(0) if hazard else ""))
            except GateError as error:
                if "(Debug check)" in str(error):
                    raise
                raise GateError("%s: %s (Debug check)" % (rel, error)) from None
            count += 1
    return count


def check_workspace_shape(base: Path, workspace: dict) -> int:
    """HE-002C PR review round 3, R3-2 (1)-(4): every workspace member is `crates/<name>`; `crates` itself is not a
    symlink; the crates effect-gate links (its path dependencies, transitively, with itself) are exactly LINKED_CRATES;
    the workspace edition is 2024 and every member inherits it (the unsafe tripwire relies on edition 2024's `unsafe
    extern` and `#[unsafe(no_mangle)]`), and no target table of a member manifest ([lib], [[bin]], [[test]], [[bench]],
    [[example]]) overrides the edition (HE-003A PR review round 1, R1-1). `workspace` is check_workspace's result."""
    require(not (base / "crates").is_symlink(), "crates is a symlink (workspace shape)")
    manifest = tomllib.loads((base / "Cargo.toml").read_text(encoding="utf-8"))
    members = manifest.get("workspace", {}).get("members", [])
    for member in members:
        require(type(member) is str and WORKSPACE_MEMBER.fullmatch(member),
                "the workspace member %r is not crates/<name> (workspace shape)" % (member,))
    require(manifest.get("workspace", {}).get("package", {}).get("edition") == WORKSPACE_EDITION,
            "the workspace edition is not %s (workspace shape)" % WORKSPACE_EDITION)
    names = {}
    for member in members:
        table = tomllib.loads((base / member / "Cargo.toml").read_text(encoding="utf-8"))
        package = table.get("package", {})
        require(package.get("edition") == {"workspace": True},
                "%s does not inherit the workspace edition (workspace shape)" % member)
        for kind in MANIFEST_TARGETS:
            targets = table.get(kind, [])
            for target in targets if isinstance(targets, list) else [targets]:
                require(not isinstance(target, dict) or "edition" not in target,
                        "%s gives a %s target its own edition (workspace shape)" % (member, kind))
        names[package.get("name")] = member
    require("effect-gate" in names and "effect-gate" in workspace, "no effect-gate member (workspace shape)")
    # HE-003B DESIGN section 2.6: the linked crates are the union of effect-gate's and gate-tls's closures (gate-tls
    # depends on effect-gate, not the reverse).
    roots = ["effect-gate"] + [name for name in ("gate-tls",) if name in names and name in workspace]
    closure = {names.get(name) for root in roots for name in linked(workspace, root)}
    require(closure == set(LINKED_CRATES), "the crates effect-gate and gate-tls link are %s, not %s (workspace shape)"
            % (sorted(str(path) for path in closure), sorted(LINKED_CRATES)))
    return len(members)


def printable_path(rel: str) -> bool:
    return all(0x20 <= ord(char) <= 0x7E for char in rel)


def build_script(manifest: dict, files: set[str]) -> bool:
    """Whether a crate has a build script: the file its manifest's `build` names, or an implicit build.rs."""
    build = manifest.get("package", {}).get("build")
    if isinstance(build, str):
        return build in files
    return build is not False and "build.rs" in files


def check_vendor(base: Path, raw: bytes, expected: str = VENDOR_TABLE_SHA256) -> tuple[list[dict], int]:
    """HE-003B DESIGN sections 2.2, 2.6, 17 and 19: the vendor table is the reviewed one; vendor/ holds exactly one
    directory per row, and every file under it is pinned. Per crate: no symlink, no executable bit, printable-ASCII and
    letter-case-distinct paths; .cargo-checksum.json's package is the approved sha256 and its files are exactly the files
    present with their sha256; the tree digest and file count are the row's; the manifest's name and version are the
    row's and it is no proc-macro; it has a build script exactly when the row says so, and among the linked and
    build-host crates exactly libc, ring and rustls do; the non-UTF-8 files (found by decoding), the suffix inventory
    and the C-family, assembly and perl files are the row's, and only ring and cc (its two compiler probes, pinned
    here) have any of the last; a stub holds exactly its kept files, its empty library file and the checksum file. The
    rows and the number of files."""
    require(sha256(raw) == expected, "the vendor table is not the reviewed table")
    table = json.loads(raw)
    require(table["acceptedOutcomes"] == list(ACCEPTED), "the vendor table's accepted outcomes changed")
    rows = table["rows"]
    require(all(row["outcome"] in ACCEPTED for row in rows), "a vendored crate's outcome is not accepted")
    names = ["%s-%s" % (row["name"], row["version"]) for row in rows]
    require(len(set(names)) == len(names), "duplicate vendor rows")
    vendor = base / "vendor"
    require(vendor.is_dir() and not vendor.is_symlink(), "vendor/ is missing or a symlink")
    require(sorted(entry.name for entry in vendor.iterdir()) == sorted(names) and all(
        (vendor / name).is_dir() and not (vendor / name).is_symlink() for name in names),
        "vendor/ does not hold exactly one directory per vendor row")
    with_scripts = set()
    files_seen = 0
    for row, name in zip(rows, names):
        root = vendor / name
        files: dict[str, bytes] = {}
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).as_posix()
            require(not path.is_symlink(), "%s/%s is a symlink (vendor check)" % (name, rel))
            require(printable_path(rel), "%s holds a path that is not printable ASCII (vendor check)" % name)
            if path.is_file():
                require(not path.stat().st_mode & 0o111, "%s/%s is executable (vendor check)" % (name, rel))
                files[rel] = path.read_bytes()
            else:
                require(path.is_dir(), "%s/%s is neither a file nor a directory (vendor check)" % (name, rel))
        require(len({rel.lower() for rel in files}) == len(files), "%s holds paths that differ in case only" % name)
        files_seen += len(files)
        digests = {rel: sha256(data) for rel, data in files.items()}
        require(".cargo-checksum.json" in files, "%s has no .cargo-checksum.json (vendor check)" % name)
        checksum = json.loads(files[".cargo-checksum.json"])
        require(checksum.get("package") == row["sha256"], "%s's checksum package is not the approved sha256" % name)
        require(checksum.get("files") == {rel: digest for rel, digest in digests.items() if rel != ".cargo-checksum.json"},
                "%s's .cargo-checksum.json does not list exactly its files (vendor check)" % name)
        require(sha256(canonical(digests)) == row["treeDigest"] and len(files) == row["fileCount"],
                "%s's files differ from its vendor row (vendor check)" % name)
        manifest = tomllib.loads(files["Cargo.toml"].decode("utf-8"))
        require((manifest["package"]["name"], manifest["package"]["version"]) == (row["name"], row["version"]),
                "%s's manifest names another crate (vendor check)" % name)
        library = manifest.get("lib", {})
        require(not library.get("proc-macro") and not library.get("proc_macro"), "%s is a proc-macro crate" % name)
        script = build_script(manifest, set(files))
        require(script == row["buildScript"], "%s's build script differs from its vendor row (vendor check)" % name)
        if script and row["role"] in ("LINKED", "BUILD_HOST"):
            with_scripts.add(row["name"])
        non_utf8 = []
        for rel, data in files.items():
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                non_utf8.append({"path": rel, "sha256": digests[rel]})
        require(non_utf8 == row["nonUtf8"], "%s's non-UTF-8 files differ from its vendor row (vendor check)" % name)
        suffixes: dict[str, int] = {}
        for rel in files:
            suffix = Path(rel).suffix
            suffixes[suffix] = suffixes.get(suffix, 0) + 1
        require(suffixes == row["suffixes"], "%s's suffix inventory differs from its vendor row (vendor check)" % name)
        native = [{"path": rel, "sha256": digests[rel]} for rel in files if Path(rel).suffix in NATIVE_SUFFIXES]
        require(native == row["nativeFiles"], "%s's C-family, assembly or perl files differ from its row" % name)
        if row["name"] == "cc":
            require({entry["path"]: entry["sha256"] for entry in native} == CC_PROBES,
                    "cc holds C-family files other than its two compiler probes (vendor check)")
        elif row["name"] != "ring":
            require(not native, "%s holds a C-family, assembly or perl file (vendor check)" % name)
        if row["form"] == "STUB":
            stub = row["stub"]
            expected_files = {entry["path"] for entry in stub["kept"]} | {stub["emptyLibrary"], ".cargo-checksum.json"}
            require(set(files) == expected_files and files[stub["emptyLibrary"]] == b"",
                    "%s is not exactly its stub (vendor check)" % name)
            require(all(digests[entry["path"]] == entry["sha256"] for entry in stub["kept"]),
                    "%s's kept files differ from its vendor row (vendor check)" % name)
            require(row["role"] == "LOCK_ONLY", "%s is a stub but not lock-only" % name)
        else:
            require(row["form"] == "FULL" and row["role"] in ("LINKED", "BUILD_HOST"), "%s's role or form" % name)
        require(all(digests.get(entry["path"]) == entry["sha256"] for entry in row["licenseFiles"]) and row["licenseFiles"],
                "%s's licence files differ from its vendor row (vendor check)" % name)
    require(with_scripts == BUILD_SCRIPTS, "the linked and build-host crates with a build script are %s, not %s"
            % (sorted(with_scripts), sorted(BUILD_SCRIPTS)))
    return rows, files_seen


def check_tls(base: Path) -> int:
    """HE-003B DESIGN sections 2.6 and 20 (D1-5, D2-1): gate-tls's non-test sources hold none of TLS_FORBIDDEN in their
    raw text (comments included); read with comments removed and literal contents emptied, they name each of the
    closed settings exactly once, as its assignment, and tls.rs names the certificate resolver exactly once each.
    HE-003C DESIGN section 5: the list and the settings include the client's, tls_client.rs names TLS_CLIENT_AUTH
    exactly once each, and no source but exchange.rs constructs `UpstreamResponse {` (read without comments and
    literal contents). Text, not Rust: a renamed import, a type alias or a macro could evade it, and code review stays."""
    sources = [(path.relative_to(base).as_posix(), path.read_text(encoding="utf-8"))
               for path in sorted((base / GATE_TLS / "src").rglob("*.rs"))]
    require(sources, "gate-tls has no sources (TLS deny-list)")
    code = ""
    for rel, text in sources:
        for pattern, name in TLS_FORBIDDEN:
            require(not pattern.search(text), "%s names %s (TLS deny-list)" % (rel, name))
        try:
            source_code = rust_code(text)
        except GateError as error:
            raise GateError("%s: %s (TLS deny-list)" % (rel, error)) from None
        require(rel == UPSTREAM_RESPONSE_HOME or not UPSTREAM_RESPONSE.search(source_code),
                "%s constructs UpstreamResponse outside %s (TLS deny-list)" % (rel, UPSTREAM_RESPONSE_HOME))
        code += source_code + "\n"
    for name, assignment in TLS_SETTINGS:
        require(len(re.findall(r"\b%s\b" % name, code)) == 1 and len(re.findall(assignment, code)) == 1,
                "gate-tls does not set %s exactly once, as the closed setting (TLS deny-list)" % name)
    tls = base / GATE_TLS / "src/tls.rs"
    require(tls.is_file(), "gate-tls has no tls.rs (TLS deny-list)")
    tls_code = rust_code(tls.read_text(encoding="utf-8"))
    for pattern, name in TLS_RESOLVER:
        require(len(re.findall(pattern, tls_code)) == 1, "tls.rs does not name %s exactly once (TLS deny-list)" % name)
    client = base / GATE_TLS / "src/tls_client.rs"
    require(client.is_file(), "gate-tls has no tls_client.rs (TLS deny-list)")
    client_code = rust_code(client.read_text(encoding="utf-8"))
    for pattern, name in TLS_CLIENT_AUTH:
        require(len(re.findall(pattern, code)) == 1 and len(re.findall(pattern, client_code)) == 1,
                "gate-tls does not name %s exactly once, in tls_client.rs (TLS deny-list)" % name)
    return len(sources)


def lock_closure(packages: list[dict], name: str) -> set:
    """The package names a lock package reaches through its `dependencies`, itself included."""
    by_name = {package["name"]: package for package in packages}
    seen, todo = set(), [name]
    while todo:
        current = todo.pop()
        if current in seen or current not in by_name:
            continue
        seen.add(current)
        todo.extend(dependency.split(" ")[0] for dependency in by_name[current].get("dependencies", []))
    return seen


def vendor_components(vendor_rows: list[dict], closure: set) -> list[dict]:
    """HE-003B DESIGN section 2.7: an SBOM component for each LINKED vendor row in a binary's lock closure."""
    return [{"type": "library", "name": row["name"], "version": row["version"],
             "licenses": [{"expression": row["canonical"]}], "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
             "properties": [{"name": "planeon:path", "value": "host-enforcement/vendor/%s-%s" % (row["name"], row["version"])},
                            {"name": "planeon:outcome", "value": row["outcome"]}]}
            for row in vendor_rows if row["role"] == "LINKED" and row["name"] in closure]


def sbom(binary: str, target: str, digest: str, rows: list[dict], workspace: set, vendored: list[dict] = ()) -> bytes:
    """workspace: the workspace crates in the binary's dependency closure; vendored: its vendored components."""
    components = [{"type": "library", "name": row["component"], "version": row["version"],
                   "licenses": [{"expression": row["canonical"]}], "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                   "properties": [{"name": "planeon:path", "value": row["path"]},
                                  {"name": "planeon:outcome", "value": row["outcome"]}]}
                  for row in rows if row["target"] == target and row["role"] == "LINKED"]
    components += [{"type": "library", "name": name, "version": VERSION, "licenses": [{"expression": "Apache-2.0"}],
                    "properties": [{"name": "planeon:path", "value": "host-enforcement (workspace crate)"}]}
                   for name in sorted(workspace)]
    components += list(vendored)
    components.sort(key=lambda item: canonical(item))
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components,
                "metadata": {"component": {"type": "application", "name": binary, "version": VERSION,
                                           "hashes": [{"alg": "SHA-256", "content": digest}],
                                           "properties": [{"name": "planeon:target", "value": target}]}}}
    # RFC 4122 name-based (version 5) UUID of the document's content: deterministic, with version and variant bits.
    document["serialNumber"] = uuid.uuid5(uuid.NAMESPACE_URL, "urn:planeon:sbom:sha256:" + sha256(canonical(document))).urn
    return canonical(document)


def self_test() -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromName("test_gate")
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
    for line in stream.getvalue().splitlines():
        if line.strip():
            say("self-test: " + line)
    require(result.wasSuccessful(), "the gate's self-test failed")


def main() -> int:
    try:
        self_test()
        pin = json.loads((HE / "toolchain.json").read_text(encoding="utf-8"))
        sysroot = Path(check_toolchain(pin))
        targets = list(pin["targets"])
        require(sorted(targets) == sorted(MACHINE), "toolchain.json must name both musl targets")
        require(TABLE.name == "closure-%s.json" % pin["rustc"]["release"], "the closure table is not the pinned release's")
        c_toolchain = pin["cToolchain"]
        say("C toolchain: %s and %s, x86_64 flags %r (a failing pin: the Command Line Tools' version and SDK, "
            "xcode-select, the first cc and ar on PATH)" % (c_toolchain["compiler"], c_toolchain["archiver"],
                                                              c_toolchain["cflags"]["x86_64-unknown-linux-musl"]))
        check_cargo_config(pin, ROOT)
        say("cargo config: [net] offline; both targets linked through %s, which execs the pinned rust-lld; crates.io "
            "replaced by the vendored directory source host-enforcement/vendor; [env] is %s, each forced"
            % (pin["linkerWrapper"], ", ".join(sorted(cargo_env(pin)))))
        vendor_rows, vendor_files = check_vendor(HE, VENDOR_TABLE.read_bytes())
        roles = {role: sum(row["role"] == role for row in vendor_rows) for role in ("LINKED", "BUILD_HOST", "LOCK_ONLY")}
        say("vendor: %d crates (%d linked, %d build-host, %d lock-only stubs), %d files match the vendor table %s; "
            "build scripts only in %s among the linked and build-host crates; C-family, assembly and perl files only in "
            "ring and cc's two compiler probes" % (len(vendor_rows), roles["LINKED"], roles["BUILD_HOST"],
                                                   roles["LOCK_ONLY"], vendor_files, VENDOR_TABLE_SHA256,
                                                   ", ".join(sorted(BUILD_SCRIPTS))))
        workspace = check_workspace(HE, vendor_rows)
        say("workspace: %d crates, no build script or proc-macro; the only registry dependencies are %s of gate-tls; "
            "Cargo.lock's %d registry packages are exactly the vendor table's, with their checksums and dependency "
            "lists" % (len(workspace), ", ".join(sorted(REGISTRY_LINES["crates/gate-tls"])), len(vendor_rows)))
        say("workspace shape: %d members, each crates/<name> and inheriting edition %s; crates is not a symlink; "
            "effect-gate and gate-tls link exactly %s" % (check_workspace_shape(HE, workspace), WORKSPACE_EDITION,
                                                          ", ".join(LINKED_CRATES)))
        say("contracts: %d files match the registered harness-onion bytes" % check_contracts(HE))
        rows = load_table(TABLE.read_bytes(), TABLE_SHA256)
        check_tree(rows, sysroot, targets)
        say("closure: %d shipped files match the reviewed table %s" % (len(rows), TABLE_SHA256))
        for target in targets:
            for name in CRT_OBJECTS:
                check_crt_symbols(name, symbol_names((sysroot / "lib/rustlib" / target / "lib/self-contained" / name)
                                                     .read_bytes()))
        say("crt objects: compiler-rt's crtbegin and crtend on both targets")
        say("start-up lint: %d workspace sources without a forbidden API (excepted once each: %s)"
            % (check_sources(HE), "; ".join("%s in %s" % (expression, rel) for rel, expressions
                                             in STARTUP_EXCEPTIONS.items() for expression, _ in expressions)))
        say("included code: %d workspace sources pass the lexical tripwire (no path attribute, include!, raw "
            "identifier or inline assembly; no manifest target path, build key or symlink), crates' src/ hold only .rs "
            "files" % check_included_code(HE))
        linked_names = ", ".join(crate.split("/")[1] for crate in LINKED_CRATES)
        say("linked sources: %d sources of %s name no refused std path, rename or glob no std module or item and do not "
            "name asm (lexical tripwire), crate roots forbid or deny unsafe_code" % (check_linked_sources(HE), linked_names))
        say("foreign items: %d sources of the linked crates, every extern read with comments and "
            "literal contents removed; %s; no other declares a foreign item, none is public or safe, no link_name, no "
            "macro in any of them (lexical tripwire)"
            % (check_foreign_items(HE), "; ".join("%s declares exactly %s" % (rel, ", ".join(sorted(items)))
                                                  for rel, items in FOREIGN_ITEMS.items())))
        say("Debug: %d sources of the linked crates derive Debug on no struct or enum named %s or whose field types "
            "mention %s (lexical tripwire)" % (check_debug_derives(HE), ", ".join(SECRET_TYPES),
                                               ", ".join(DEBUG_HAZARDS + SECRET_TYPES)))
        say("TLS deny-list: %d gate-tls sources name none of its %d refused tokens; %s are each set exactly once as "
            "the closed setting; tls.rs names with_cert_resolver( and SingleCertAndKey::from( once each; tls_client.rs "
            "names with_client_auth_cert( and with_webpki_verifier( once each; only exchange.rs constructs "
            "UpstreamResponse {" % (check_tls(HE), len(TLS_FORBIDDEN),
                                    ", ".join(name for name, _ in TLS_SETTINGS)))
        say("post-seal: %d sources of the linked crates name none of HE-002S DESIGN section 5's "
            "std APIs (plus set_modified and is_terminal), each of which reaches a system call the EFFECT_GATE filter "
            "kills (lexical tripwire)" % check_post_seal_sources(HE))
        say("unsafe: the lexical tripwire finds the word only in %s among %d workspace sources"
            % (" and ".join(UNSAFE_FILES), check_unsafe(HE)))
        lock = tomllib.loads((HE / "Cargo.lock").read_text(encoding="utf-8"))["package"]
        markers = comment_markers(pin)
        host_paths = HOST_PATHS + tuple(path.encode() for path in (str(ROOT), str(Path.home())) if len(path) > 1)
        for target in targets:
            shape = pin["targets"][target]["shape"]
            for binary in BINARIES:
                raw = (HE / "target" / target / "release" / binary).read_bytes()
                check_binary(raw, target, shape, markers, host_paths)
                digest = sha256(raw)
                vendored = vendor_components(vendor_rows, lock_closure(lock, binary))
                document = sbom(binary, target, digest, rows, linked(workspace, binary), vendored)
                out = HE / "target/sbom" / target / (binary + ".cdx.json")
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(document)
                say("%s %s: %s, sha256 %s, SBOM sha256 %s" % (target, binary, shape, digest, sha256(document)))
    except Exception as error:   # fail closed on anything, with the prefix on every line
        say("FAILED: %s: %s" % (type(error).__name__, error))
        return 1
    say("passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
