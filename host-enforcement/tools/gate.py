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

HE-003D (the gate binary; DESIGN sections 2, 3.1 and 5) admits exactly one [patch] table (the 11 LINKED vendored crates
as path packages, so planeon-gate carries no build-host path) and gate-tls's ring line; the binary's crate joins the
linked crates with one exit import; main.rs follows the seal-order grammar and names no socket or thread before the
second stage (nor do the configuration's two modules); gate-sys's socket modules are reached only from effect-gate's
two Linux modules; no linked source names threads, code before main or printing; the TLS rules cover the binary, count
any mention and refuse every UpstreamResponse mention outside exchange.rs; the signer key file is 0 or 32 bytes; and
planeon-gate's symbol table has no membarrier and only reviewed wrappers of killed calls.

HE-004A (the observer substrate; DESIGN-A rev 2.1 sections 2, 3 and 6) pins the two OBSERVER programs among the contract
files; planeon-observer's crates (crates/observer and gate-sys) must be exactly its closure, and its library and main.rs
roots forbid unsafe_code; every linked-crate scan (linked sources, foreign items, Debug, socket modules, read_link,
macros, code before main, prints) reads crates/observer too, and main.rs has the binary's one exit import; the seal-order
grammar is parameterised by file and allowed calls, and the observer's main.rs holds stage 1 first, nothing between, the
exact stage-2 statement and the pinned tail `ExitCode::from(status::NOT_YET_SERVING)`; crates/observer's sources name
none of the gate's post-seal APIs nor the method calls the OBSERVER filter kills that the gate's allows; and each built
planeon-observer has no membarrier symbol and holds its architecture's OBSERVER program bytes exactly once. Its wrapper
inventory is not in HE-004A (owner decision Q-HE4A-B2 (a), open item OBSERVER-WRAPPER-INVENTORY in MODEL_DEFINED).

HE-003A3 (the I05 gate channel v4 adoption; DESIGN rev 2.2 sections 2, 5 and 6) pins the v4 README and vectors among
the contract files; excepts the observation's two root opens in linux_os.rs from the start-up lint; pins the callers of
the observation's openers by exact call forms (open_kernel_root, open_after_seal, FixedPath's two constructors and
open_fixed), the implementations of the observation's traits by (trait, type) pairs, the fake kernel's names to its
own module and strict #[cfg(test)] blocks, its module's shape, the two exempted `type Pidfd` bindings, LinuxKernelReads's
two root fields and linux_os.rs's lack of static state; refuses renames and aliases of the observation's types; pins
serve's two statements (the kernel roots before the stores, the Linux observer after the PolicyGate, before the
substrate) with their imports and the stage-2 refusal of KernelRoots; adds KernelRoot to the Debug hazards; and reads
struct bodies with the STRUCT-ANGLE rule (owner decision Q-HE4A-5 (a)): the generic list and any where-clause skipped
with a context-aware bracket scanner, angles nesting in type position and ignored in expressions.

HE-004B1 (the observer's RBAC snapshot, OR predicates and ADM-4 logic; DESIGN-B rev 2.2 section 6, owner decisions
Q-HE4B-0..12) pins edge record v4's ten I06 v2, I06 v1 and admission v3 files among the contract files; planeon-observer
links i05-protocol too (its closure and SBOM follow); the observer post-seal rule also reads i05-protocol's sources, with
the single memory-only `impl Drop for Value` in json.rs excepted once; the observer's five logic modules (inputs, rbac,
snapshot, operational, admission) name only whitelisted path roots (their own modules and the embedded contracts,
i05-protocol's json, sha256 and contracts, std's ordered collections and pure modules), no super:: or foreign self::
path, glob, renaming import, HashMap, HashSet or RandomState, no include macro, and no panicking macro or call outside
strict #[cfg(test)] blocks; every include_bytes!/include_str! of the observer's sources is one plain literal naming a
registered contract file, only in contracts.rs (and seal.rs's two OBSERVER programs). Carried from HE-003A3's PR review
(R1-2, R1-3): serve binds gate in no other let pattern and assigns it nowhere, and after the observer's attach names it
only in gate.apiserver_address() and Substrate::new(gate, ..); observation.rs defines no module outside its strict test
module and Unobserved and KernelObserver exactly once each at its top level.

HE-004C (the observer's apiserver read client and live wiring; DESIGN-C rev 4 section 15, owner decisions Q-HE4-5,
Q-HE4-6 and Q-HE4C-1..14, all (a)) gives crates/observer its own registry lines, each equal to gate-tls's (G1), and keeps
planeon-observer's closure (G2; the gate-tls dev-dependency is outside it); check_tls reads two groups, gate-tls with the
binary unchanged and crates/observer with the whole deny-list, a server-side list, its three client settings exactly
once and the client authentication and webpki verifier once each in its tls.rs (G3); the observer's linux_net.rs joins
the socket modules (G4); the observer's main.rs ends with exactly `ExitCode::from(serve(&<the stage-2 binding>))`, holds
fn serve with its pinned imports, and serve calls the configuration's load, parse and lifetime, the credentials, the TLS
configuration, the wire, the embedded closure and the epoch each exactly once in that order (G5); the observer's signed
configuration includes its own signer key, and both key files are 0 or 32 bytes (G6); contracts.rs holds only pinned
constant items (G7, R1-3); the no-panic tripwire covers every new observer module, main.rs and status.rs (G8); each built
planeon-observer holds a rustls client-connection symbol and an observer client, http, watch or observe symbol (G9); the
observer's secret types and its wire join the Debug rules (G10). No wrapper inventory (owner rule Q-HE4A-B2).

HE-004D1 (the observer's kernel captures and NP-3; DESIGN-D1 rev 4 section 19, owner decisions Q-HE4D1-1..12 (a),
Q-HE4D1-D1 (c), -D2 (a) and -D3 (a)) adds observer-sys, a std-only crate without dependencies, to planeon-observer's
closure and every linked-crate scan (G-D1-1); its kernel.rs is the one file of it allowed `unsafe`, std::os::fd items and
MetadataExt, and declares exactly the foreign item syscall (G-D1-2), whose calls are pinned: six numbers, seven
arguments, named constants in the checked positions, one ioctl request and three bpf commands, and no other route to the
item (G-D1-3); the open flags are four named sets of read-only flags each with its compile-time assert, the cgroup file
names are exactly seven, no observer source names freeze and observer-sys names no write (G-D1-4, NP-3); five exact
private root constants are excepted once each from the start-up lint and from the linked-source `fs` scan (G-D1-5,
R3-1, R4-1); observer_sys is named only in linux_capture.rs, which re-exports nothing and whose public items name no
observer-sys type, and its constructor is called once, as LinuxCapture::new(sealed) in serve (G-D1-6); link_text and
own_pid are pinned to their reads and called only in linux_capture.rs (G-D1-7); serve's wiring has twelve calls
(G-D1-8); the four native-profile contract files are pinned and the embedded schema has one use site (G-D1-9); three new
logic modules take B1's logic rule (G-D1-10); the no-panic, post-seal and Debug rules cover the new sources and handles
(G-D1-11..13); planeon-observer's symbol table holds the two not-inlined constructors (G-D1-14); and its host-path scan
exempts exactly one span, the pinned v4 schema's bytes, which must occur once (G-D1-16; HOST_PATHS unchanged).

HE-004D2 (the observer's qualification and acceptance logic; DESIGN-D2 rev 2 section 12, owner decisions Q-HE4D2-1..11,
all (a)) registers edge record v6's five HE-004D2 rows among the contract files (G-D2-1, 40 files); contracts.rs may embed
only the files OBSERVER_EMBEDDED_CONTRACTS names (G-D2-2); observer-sys's lib.rs, dirent.rs and Cargo.toml join kernel.rs
among the whole-file pins (G-D2-10, R4-1); and serve's two Linux constructors are counted in their qualified forms too
(G-D2-11, R1-5). Unit B1 registers edge record v7's six rows (46 files), lets contracts.rs embed native-profile v5's
schema for the capture validators, and holds both schema constants to one use site each (G-D2-3). The acceptance tokens
(EvidenceAccepted from A3) are minted only by their one function and never changed or copied (G-D2-8, with design review
round 2's R2-1 field-type and cfg_attr rules). Its logic modules (record_check in phase A's A2, then i06_evidence and
qualification; composition in phase B) take B1's logic rule with D1's whitelist plus the four modules (G-D2-4); none
of their names, nor any type they define, occurs in another crates/observer source, and they implement nothing on another
type (G-D2-5, the source-level proof that serve cannot reach them); /opt/planeon/ occurs only in record_check.rs's one
interpreter-tree constant (G-D2-6), whose two root constants join G-D1-5's exceptions (G-D2-9); and planeon-observer's
symbol table holds no symbol of the four modules on either target (G-D2-7, build-time corroboration).

HE-004-I01a (the observer's I01 listener, custody, request checks, quota pair and role pin; DESIGN-I01A revision 6
section 12, owner decisions Q-HE4I1-1..13 and Q-I01A-1..9) registers edge record v8's two seccomp-v5 OBSERVER programs
among the contract files and points OBSERVER_PROGRAMS at them, the v3 ones held but no longer embedded (unit U1, 48).
Unit U4: the I01 service and its request checks are exactly the i01_ sources, the checks a logic module
(I01_LOGIC_PATHS), both on the no-panic list, and serve's wiring has thirteen calls (the server identity after
Enrolled::new). Unit U3: the observer's I01 listener file joins the socket files, the whole-file pins (with linux_net.rs re-pinned),
the no-panic list and, through I01Socket, the Debug hazards; the observer names no unlink, remove or rename call
(G-I01-1); every wire wait is the one inside Client::wait_serving, beside linux_net.rs's poller wait, and the service
step is called once, there (G-I01-2); the I01 path lives only in linux_listen.rs's constant (G-I01-4); nothing leaves
I01a: no peer_send, no channel send reachable from the socket files, only the built i01_ sources, naming none of the
client's words, and PeerOps without a supertrait (G-I01-5); I01Socket is named only in its two files and built once,
inside LinuxWire::new (G-I01-6). Unit U6 registers edge record v8's two I06 v4 rows (50 files); the role pin
(observer_rbac.rs) is a logic module on the no-panic list, its rule constants match the v4 vectors' objectsPositive,
and observe.rs calls it once, right after the closure check with only let statements between, before `let dropped`
and drop(produced) (G-I01-3).

HE-004-I01A2 (HE-004-I01a's unit U7; DESIGN-I01A revision 6 sections 3, 7 and 15, owner decisions Q-HE4I1-10 (a),
Q-I01A-1 and Q-U7-1..3 (a)) registers edge record v9's two I01 wire rows, the channel schema and the vectors the
request replay reads (52 files). With it, three of HE-004-I01a's PR review round 1 notes: G-I01-5 and the socket-item
rule follow a source's own aliases of gate_sys and of its socket modules (resolved_uses), and G-I01-5 refuses a rename
or glob of gate_sys and an extern crate in the observer's two socket files (R1-3); serve's wire construction is the one
match mapping its refusal through status::wire_setup (R1-5); the no-panic rule names the four I01 sources (R1-6).

HE-004-I01B1 (the I01 digest port; DESIGN-I01B rev 3 sections 2 and 6 and DESIGN-I01B1 rev 2, closed under Q-I01B-CAP;
the monitor's Q-I01B-7..27, R-B3-A, R-B3-PIN and MON-I01B1-A/B) registers edge record v10's four rows, the I01 digest
contract's definitions, vectors and README and the proxy-contract vectors (G-I01B-2, 56 files, none embedded). Its three
logic modules (i01_digest, i01_admission_render, i01_gate) take the I01 logic and no-panic rules, are the i01_ sources
beside the service and its request checks, and are reachable from no source but each other and lib.rs's pub mod lines
(G-I01B-1's I01B1 form, G-D2-5's construction; their symbols absent from planeon-observer's symbol table); lib.rs
declares exactly OBSERVER_LIB_MODULES in file form and no other source declares a module (G-I01B-7); the gate bound
and the three R10 constants it sums match definitions.json, ANSWER_LIMIT, the freshness window and the exchange
deadline are literal pins with their citations, and the modules' refusal texts are exactly the contract's (G-I01B-8).
R-B3-PIN pins the six guarded files not yet pinned (effect-gate's two socket files, the observer's config.rs,
i01_request.rs, i01_service.rs and client.rs) whole, keeps i01_answer.rs absent, refuses a casefolded sibling of a
guarded name and an inline module in place of a guarded one; and no use declaration of either crate aliases a socket
module, re-exports through one, names a scope root alone or globs one outside a crate root (B3-1, G-I01B-6 (e); PR
review round 1, R1-2). The casefold clause reads a directory listing, so its self-test runs on any file system (R1-4).

HE-004-I01B4 (LPK-1's S3 with W3, the I01 digest contract v2 re-vendor; DESIGN-I01B4 rev 2 sections 1, 5 and 11; the
monitor's Q-I01B4-1..12 and the owner's Q-I01B4-ZB) registers edge record v11's seven rows, the contract v2's
definitions, vectors and README, admission v4's README, vectors and sealed planeon-a2.json, and profile v2's vectors
(G-I01B-2 over both records' rows, 63 files, none embedded); v1's four files and admission v3's three stay held and
pinned. G-I01B-8 reads the contract v2's definitions, whose texts and bound equal v1's. G-I01B4-1, the absence clause
(Q-I01B4-5; I4D-1, I4D-2): no registered or held contract file is profile v2's schema, by name or by bytes; row 79's file
is included only by the digest replay, exactly once, and named in no other crate source; and no crate source declares
an item under the names clauses (c) and (c1) read (validate_profile, precondition or a proxy_profile_v2 item; a const
fn is read as its fn), names a file after profile v2, or
holds row 79's negative texts or the schema's digest outside the digest replay. R-B3-PIN is unchanged: I01B4 changes
no guarded file.

The owner-operated verifier runs it as `python3 -I -B host-enforcement/tools/gate.py` from the repository root, after
the two musl release builds. Stdlib only. Every line it prints starts with "he-gate: ", so no line starts with one of the
verifier's evidence prefixes. It fails closed on the first violation (exit 1).
"""
from __future__ import annotations

import hashlib
import io
import json
import posixpath
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
# [dependencies] (the ring dev-dependency fallback of section 9 was not needed, B6). HE-003D DESIGN section 3.1
# (Q-HE3D-6 (a)): ring's Ed25519 for the signed configuration, `ring = "=0.17.14"` exactly in that form.
GATE_TLS_REGISTRY_LINES = {
    "rustls": {"version": "=0.23.46", "default-features": False, "features": ["ring", "std"]},
    "getrandom": {"version": "=0.2.17", "default-features": False, "features": ["linux_disable_fallback"]},
    "zeroize": {"version": "=1.9.1", "default-features": False, "features": ["alloc"]},
    "ring": "=0.17.14",
}
# HE-004C DESIGN-C sections 3 and 15 (G1; owner decision Q-HE4-5 (a)): the observer's apiserver client links the same
# vendored crates through its own entry, each of its four lines equal to gate-tls's (no package is added; Cargo.lock
# gains only planeon-observer's edges). Its gate-tls dev-dependency is a path edge, outside REGISTRY_LINES and outside
# the closure, which reads [dependencies] only.
REGISTRY_LINES = {"crates/gate-tls": GATE_TLS_REGISTRY_LINES, "crates/observer": dict(GATE_TLS_REGISTRY_LINES)}
# HE-003D DESIGN sections 2 and 5 (phase 1): the workspace manifest's only [patch] table maps exactly these 11 LINKED
# vendored crates to their vendor/ directories (path packages inside the workspace root, so rustc receives
# workspace-relative paths and planeon-gate carries no build-host path); in Cargo.lock they are path packages (no
# source, no checksum) whose names, versions and edges are their vendor rows'. check_vendor stays their file-level pin
# (cargo no longer verifies a patched package's .cargo-checksum.json digests, phase 1).
PATCH_CRATES = (("cfg-if", "1.0.5"), ("getrandom", "0.2.17"), ("libc", "0.2.190"), ("once_cell", "1.21.4"),
                ("ring", "0.17.14"), ("rustls", "0.23.46"), ("rustls-pki-types", "1.15.1"), ("rustls-webpki", "0.103.15"),
                ("subtle", "2.6.1"), ("untrusted", "0.9.0"), ("zeroize", "1.9.1"))
# DESIGN sections 2.2 and 19: C-family, assembly and perl suffixes; only ring holds such files, and cc its two
# compiler-probe sources, each pinned by path and sha256.
NATIVE_SUFFIXES = {".c", ".h", ".inl", ".inc", ".cpp", ".cc", ".hpp", ".S", ".s", ".asm", ".pl", ".pm"}
CC_PROBES = {"src/detect_compiler_family.c": "97ca4b021495611e828becea6187add37414186a16dfedd26c2947cbce6e8b2f",
             "src/detect_cpp_stdlib.cpp": "b2ef811b2eaec1bfa305241d3a2ba26ed4c9898dc3a5a076a4ec6fcab8410540"}
# DESIGN section 2.6: among the linked and build-host crates, exactly these have a build script.
BUILD_SCRIPTS = {"libc", "ring", "rustls"}
# harness-onion contract files R10 holds, byte-exact, registered in harness-onion's operator -> harness-engineering
# buildArtifact edge record (owner decision Q-HE2-A; the two EFFECT_GATE programs in its record v2, MET-ENFORCE-025,
# pinned at the published digests); provenance in contracts/PROVENANCE.md. HE-003A2 (DESIGN section 2, owner decision
# Q-A2-1 (a)): the seccomp-v4 EFFECT_GATE programs of its record v3 (MET-ENFORCE-029) join them and are the ones the seal
# embeds; the seccomp-v3 ones stay pinned, held but no longer embedded (17 files). HE-004A (DESIGN section 2, owner
# decision Q-HE4A-4 (a)): the two OBSERVER programs its record v2 and v3 register for HE-004 (MET-ENFORCE-025), which
# the observer's seal embeds (19 files). HE-003A3 (DESIGN section 2, owner decisions Q-A3-1..15 (a)): the I05 gate
# channel v4 README and vectors its record v4 registers for HE-003A3 (MET-ENFORCE-030, merged as fd362f9e), 21 files.
# HE-004B1 (DESIGN-B section 2, owner decision Q-HE4B-7 (a)): the ten I06 v2, I06 v1 and admission v3 files record v4
# registers for HE-004 (rows 34-43), 31 files. HE-004D1 (DESIGN-D1 section 2, G-D1-9): edge record v5's three HE-004D1
# rows (native-profile v4's schema, vectors and README) and its native-profile v3 schema row, held under the byte rule
# for the cross-version cases X12-X14 (owner decision Q-HE4D1-11 (a)), 35 files. HE-004D2 (DESIGN-D2 section 2, G-D2-1):
# edge record v6's five HE-004D2 rows (the native-profile v1 and v2 schemas, which check_migration pins, and I06 v3's
# vectors, criteria and README), read by the tests only, 40 files. HE-004D2 unit B1 (DESIGN-D2 sections 2 and 4, G-D2-1;
# owner decision Q-HE4D2-3 (a)): edge record v7's six HE-004D2 rows (native-profile v5's schema, which the capture
# validators load, its vectors and README, and the native-profile v1, v2 and v3 vectors the history replay reads), 46.
# HE-004-I01a unit U1 (DESIGN-I01A sections 3 and 12): edge record v8's two seccomp-v5 OBSERVER rows (harness-onion
# compiled filter programs v3, MET-ENFORCE-036), which the observer's seal embeds from now on; the seccomp-v3 OBSERVER
# programs stay pinned, held but no longer embedded (Q-P2-3 (a)), 48. Unit U6 (DESIGN-I01A section 10, Q-I01A-4 (a)):
# edge record v8's two I06 v4 rows (harness-onion MET-ENFORCE-039, the backend profile v4's criteria and vectors), read
# by the tests and by the role pin's constants check, 50. HE-004-I01A2, HE-004-I01a's unit U7 (DESIGN-I01A sections 3 and
# 7, Q-HE4I1-10 (a), Q-I01A-1): edge record v9's two rows (harness-onion MET-ENFORCE-040, the I01 wire's channel schema
# and vectors at providerCommit 108e6195), read by the tests only (the request replay), 52. HE-004-I01B1 (DESIGN-I01B rev
# 3 section 2, G-I01B-2; Q-I01B-26 (a)): edge record v10's four rows 69-72 (I01B_EDGE_V10_ROWS: the I01 digest contract's
# definitions, vectors and README, published by MET-ENFORCE-041 and merged at 2043cc27, and the proxy-contract vectors at
# providerCommit 33de300c), read by the tests only (the digest replay), none embedded, 56. HE-004-I01B4 (DESIGN-I01B4
# rev 2 sections 1.1 and 1.2, G-I01B-2; Q-I01B4-2 and Q-I01B4-3): edge record v11's seven rows 73-79
# (I01B_EDGE_V11_ROWS: the I01 digest contract v2's definitions, vectors and README, published by MET-ENFORCE-042 and
# merged at f9882c1a, and admission v4's README, vectors and sealed planeon-a2.json and profile v2's vectors at
# providerCommit 675daccb), read by the tests only (the digest, render and PV replays); v10's rows 69-72 and admission
# v3's rows 41-43 stay held and pinned; none embedded, 63.
CONTRACTS = {
    "contracts/i05-v1/README.md": "dc9aa22017b2cdf71f886fb7890aff3f6e7095b9afc25bd37645cb0dee23b498",
    "contracts/i05-v2/README.md": "1cb07cef90b0881c42370d8bbaeea08c6abc48478bed3939286b651601d2cca3",
    "contracts/i05-v3/README.md": "f82f43330125640d3ac946d2afc9a1804a21e5e60a7ac4b94e5d6cb6ed2ea3aa",
    "contracts/i05-v3/channel.schema.json": "3bfee13c9d32e82fe5ab908eb6f716bc11881f9d57b324f8ea4a21a3ad35356f",
    "contracts/i05-v3/outcome-mapping.json": "4466f379f1cc669e047cffd8afa5fa88b2cc7648a51e2d38b17f0bd5e2252a3a",
    "contracts/i05-v3/vectors.json": "ab75d86fe54ade7ee2695ef84b200d0473e14e4112e64e7702032593658763ed",
    "contracts/i05-v3-supplement/vectors.json": "1c00bdb3ea112af6098a09158cce3e4a7a6098c9670f490ead4ca65d8bdbb5ac",
    "contracts/i05-v4/README.md": "b0af1f8784c7e9bcdd3793a1002d1000e222a13e5a7613b50b04ce5a116ed04d",
    "contracts/i05-v4/vectors.json": "f314610f7ee3feb08533cb535f0a4c19fc991384b852b99a50a1646b0739b1e9",
    "contracts/i07-v1/README.md": "9e5cb3d1023bc12b9e2643ae42dde5a87640cf04fc8ac1aa88350c65b12ba2dc",
    "contracts/i07-v2/README.md": "cde20d7fee8661cd9314350849870fe5b0838b7914a60237d0eeb1f5dca39d39",
    "contracts/i07-v3/README.md": "a8c51a725b99d84351aba7a326196e7078c239ba4e28d3eaec1cf09fb3dca43d",
    "contracts/i07-v3/channel.schema.json": "c68721a1002fccc7d6e59eeee9016a0a0f4a7428fad714e5a3d90a362d30ce09",
    "contracts/i07-v3/policy-kinds.json": "4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0",
    "contracts/i07-v3/vectors.json": "c4c24c5ff15618aa2f0fe0f016011359bc4316220c6e40d5168f9ee24b6f736d",
    "contracts/seccomp-v3/EFFECT_GATE.aarch64.bpf": "0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a",
    "contracts/seccomp-v3/EFFECT_GATE.x86_64.bpf": "ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115",
    "contracts/seccomp-v4/EFFECT_GATE.aarch64.bpf": "8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044",
    "contracts/seccomp-v4/EFFECT_GATE.x86_64.bpf": "4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3",
    "contracts/seccomp-v3/OBSERVER.aarch64.bpf": "d31c841042de456bb784e8412f61429be7700aea2ffa508af2637283ebcb3707",
    "contracts/seccomp-v3/OBSERVER.x86_64.bpf": "e793aae5ad04a7c82a67d3f102b837064e645a585b83ace0586169a1746eb25a",
    "contracts/seccomp-v5/OBSERVER.aarch64.bpf": "887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184",
    "contracts/seccomp-v5/OBSERVER.x86_64.bpf": "a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9",
    "contracts/i06-v2/vectors.json": "1a5e168f0d8fff233f5072b1440e75a633b38e428f87b2893a96e579122a430e",
    "contracts/i06-v2/criteria.json": "026206c57d3025c0f0129b6615e46c83d5a8000ddc3288f000a1fe4570050cda",
    "contracts/i06-v2/README.md": "553880b957586dbfa50eabc4a99d51735eef2a1b0a82641ea51d8e3ea8cf72eb",
    "contracts/i06-v1/identity-closure.json": "0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb",
    "contracts/i06-v1/writer-inventory.json": "8e6b3b7565cfc93a61162b84d740cffb2871eb66ab85e8c4e80ac813f1af3077",
    "contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json":
        "7529c2a713af2fb90163175924c264d95f4242d7e0c26b1452c77febb13ed50e",
    "contracts/i06-v1/README.md": "ccf952d40b4f6229c0cdea79f976253cd4abb19438c1eebc5794e748a708e4b7",
    "contracts/admission-v3/vectors.json": "a3e2dc9818742ae2188e0e83cf91bb833be836115975b3fb23d5f280f6928cc1",
    "contracts/admission-v3/README.md": "c3106482b4ff79649cbef7c65797c6fcd6b64f8419e871ae7d89eecad3ff98ab",
    "contracts/admission-v3/admission-manifests/planeon-a2.json":
        "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741",
    "contracts/native-profile-v4/qualification.schema.json":
        "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
    "contracts/native-profile-v4/vectors.json": "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
    "contracts/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
    "contracts/native-profile-v3/qualification.schema.json":
        "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
    "contracts/native-profile-v1/qualification.schema.json":
        "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3",
    "contracts/native-profile-v2/qualification.schema.json":
        "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0",
    "contracts/i06-v3/vectors.json": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
    "contracts/i06-v3/criteria.json": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
    "contracts/i06-v3/README.md": "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77",
    "contracts/native-profile-v5/qualification.schema.json":
        "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
    "contracts/native-profile-v5/vectors.json": "b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1",
    "contracts/native-profile-v5/README.md": "76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692",
    "contracts/native-profile-v1/vectors.json": "cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f",
    "contracts/i06-v4/criteria.json": "10aa3a8fe08a930e3a4a13f7a11b38404cd82bd1a12164a40ef13141af37d09a",
    "contracts/i06-v4/vectors.json": "27aba3bf7296a08b90adef1663d6498fda9ae98499707d0c0950aa6c4ba14eb7",
    "contracts/native-profile-v2/vectors.json": "6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396",
    "contracts/native-profile-v3/vectors.json": "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d",
    "contracts/i01-v1/channel.schema.json": "fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e",
    "contracts/i01-v1/vectors.json": "1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124",
    "contracts/i01-digests-v1/definitions.json": "086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa",
    "contracts/i01-digests-v1/vectors.json": "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
    "contracts/i01-digests-v1/README.md": "e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae",
    "contracts/i01-v1/proxy-contract-vectors.json": "edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7",
    "contracts/i01-digests-v2/definitions.json": "fef08fddfb94e06eeff5bc4bdaf37246f9142fd072dd6427f629350c8d5cb2f2",
    "contracts/i01-digests-v2/vectors.json": "68eab4709431f73ce6f977aad7e5a087dccf9b5635c4ce04b8c08387bdce2594",
    "contracts/i01-digests-v2/README.md": "fbb28445c5ec35bbf65bec5d852bd94de8b7c4acf8d2c239ee234e00c10d6090",
    "contracts/admission-v4/README.md": "f7794aa857aa50800f05b651f7b0a56eda7407f67855bc2f0437b27b3fe297fa",
    "contracts/admission-v4/vectors.json": "5706b1a8df5cabd978caa219400b40a9c4ef6cbdbca8ea2f7c6f69b69474301c",
    "contracts/admission-v4/admission-manifests/planeon-a2.json":
        "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32",
    "contracts/i01-v2/proxy-profile-v2-vectors.json":
        "011a650bcd2a11f2eaeba531693f3e7ee9c30c1f6ede2d5ecf87919f206affcc",
}
# HE-004-I01B1 DESIGN-I01B rev 3 sections 2 and 6 (G-I01B-2): edge record v10's rows 69-72, each file's row, provider
# path and sha256 (status REGISTERED_BEFORE_USE, relation BYTE_IDENTICAL, mode 100644, consumer packet HE-004-I01B).
I01B_EDGE_V10_ROWS = {
    "contracts/i01-digests-v1/definitions.json":
        (69, "architecture/policy-observation-digests/definitions.json",
         "086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa"),
    "contracts/i01-digests-v1/vectors.json":
        (70, "architecture/policy-observation-digests/vectors.json",
         "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84"),
    "contracts/i01-digests-v1/README.md":
        (71, "architecture/policy-observation-digests/README.md",
         "e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae"),
    "contracts/i01-v1/proxy-contract-vectors.json":
        (72, "architecture/proxy-contract-inputs/vectors.json",
         "edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7"),
}
# HE-004-I01B4 DESIGN-I01B4 rev 2 sections 1.1 and 5 (G-I01B-2, the I01B4 set): edge record v11's rows 73-79, in
# I01B_EDGE_V10_ROWS' form (status REGISTERED_BEFORE_USE, relation BYTE_IDENTICAL, mode 100644, consumer packet
# HE-004-I01B4).
I01B_EDGE_V11_ROWS = {
    "contracts/i01-digests-v2/definitions.json":
        (73, "architecture/policy-observation-digests-v2/definitions.json",
         "fef08fddfb94e06eeff5bc4bdaf37246f9142fd072dd6427f629350c8d5cb2f2"),
    "contracts/i01-digests-v2/vectors.json":
        (74, "architecture/policy-observation-digests-v2/vectors.json",
         "68eab4709431f73ce6f977aad7e5a087dccf9b5635c4ce04b8c08387bdce2594"),
    "contracts/i01-digests-v2/README.md":
        (75, "architecture/policy-observation-digests-v2/README.md",
         "fbb28445c5ec35bbf65bec5d852bd94de8b7c4acf8d2c239ee234e00c10d6090"),
    "contracts/admission-v4/README.md":
        (76, "architecture/admission-semantics-v4/README.md",
         "f7794aa857aa50800f05b651f7b0a56eda7407f67855bc2f0437b27b3fe297fa"),
    "contracts/admission-v4/vectors.json":
        (77, "architecture/admission-semantics-v4/vectors.json",
         "5706b1a8df5cabd978caa219400b40a9c4ef6cbdbca8ea2f7c6f69b69474301c"),
    "contracts/admission-v4/admission-manifests/planeon-a2.json":
        (78, "architecture/admission-semantics-v4/admission-manifests/planeon-a2.json",
         "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32"),
    "contracts/i01-v2/proxy-profile-v2-vectors.json":
        (79, "architecture/proxy-profile-v2/vectors.json",
         "011a650bcd2a11f2eaeba531693f3e7ee9c30c1f6ede2d5ecf87919f206affcc"),
}
# HE-004-I01B4 G-I01B4-1, the absence clause (DESIGN-I01B4 rev 2 section 5; Q-I01B4-5; I4D-1, I4D-2): profile v2's
# schema by name and by file sha256 (the v2 model's PROFILE_SCHEMA, harness-onion
# scripts/policy_observation_digests_v2.py:150-151, not registered and not vendored); row 79's file, its one reader
# and the number of its distinct negative expect texts; and the names a profile v2 validator would take: clause (c)'s
# fn and mod names, clause (c1)'s identifiers and clause (c2)'s file-name part, each read case-insensitively with
# underscores removed (and hyphens, in a path). A `const` followed by `fn`, `unsafe`, `extern` or `async` is a qualifier,
# not an item, so `[pub] const [unsafe|extern ".."] fn NAME` is read as the fn NAME (PR review round 1, R1-1).
PROFILE_V2_SCHEMA_NAME = "profile.schema.json"
PROFILE_V2_SCHEMA_SHA256 = "e5ef3c3d112bce97d94da4b465b52feb69935a144f26dd711440acd6c67ad592"
I01B4_ROW79 = "contracts/i01-v2/proxy-profile-v2-vectors.json"
I01B4_ROW79_READER = "crates/observer/tests/observer_i01_digest_replay.rs"
I01B4_ROW79_TEXTS = 28
I01B4_FN_MOD_NAMES = ("validate_profile", "precondition")
I01B4_FN_MOD_PART = "profile_v2"
I01B4_ITEM_NAMES = ("validateprofile", "precondition", "preconditions")
I01B4_ITEM_PART = "proxyprofilev2"
I01B4_PATH_PART, I01B4_PATH_EXEMPT = "profilev2", "nativeprofile"
I01B4_ITEM = re.compile(r"\b(?:(fn|mod|struct|enum|trait|type|const(?!\s+(?:fn|unsafe|extern|async)\b)|static)\s+"
                        r"(?:mut\s+)?|(macro_rules)\s*!\s*)(?:r#)?([A-Za-z_]\w*)")
# HE-004D2 DESIGN-D2 section 2 (G-D2-2): the registered files crates/observer/src/contracts.rs may embed (I06 v1's
# closure, inventory and bootstrap RBAC, B1's; native-profile v4's schema, D1's, G-D1-16's one exempt span, now the record
# validator's; native-profile v5's schema, unit B1's, the capture validators'). Every other registered file is read by
# the tests only.
OBSERVER_EMBEDDED_CONTRACTS = ("contracts/i06-v1/identity-closure.json", "contracts/i06-v1/writer-inventory.json",
                               "contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json",
                               "contracts/native-profile-v4/qualification.schema.json",
                               "contracts/native-profile-v5/qualification.schema.json")
# HE-004D2 DESIGN-D2 sections 4.1 and 12 (G-D2-3, G-D1-9 generalised): the schema constants of contracts.rs, each defined
# there once and named once in capture_schema.rs, inside CaptureSchema::embedded, and nowhere else.
NATIVE_PROFILE_SCHEMAS = ("NATIVE_PROFILE_V4_SCHEMA", "NATIVE_PROFILE_V5_SCHEMA")
ACCEPTED = ("ACCEPTED_AND", "ACCEPTED_OR", "ALLOWED_EXCEPTION_EXPRESSION", "DEFAULT_ALLOWED")
MACHINE = {"x86_64-unknown-linux-musl": 62, "aarch64-unknown-linux-musl": 183}
RELATIVE = {"x86_64-unknown-linux-musl": 8, "aarch64-unknown-linux-musl": 1027}
FORBIDDEN_SOURCE = ("available_parallelism", "current_exe", "current_dir", "env::var", "var_os", "vars", "/proc", "/sys")
HOST_PATHS = (b"/Users/", b"/opt/planeon/", b"/private/tmp/", b"/private/var/")
# HE-002C DESIGN section 9: the crates EFFECT_GATE will link, checked over their non-test sources (src/). HE-003D
# DESIGN section 5 (O4): the gate binary's own crate joins them.
LINKED_CRATES = ("crates/effect-gate", "crates/gate-sys", "crates/i05-protocol", "crates/gate-tls", "crates/gate")
# HE-004A DESIGN-A section 6 (D2-4): planeon-observer links exactly its own crate and gate-sys (a closure check), and the
# observer's crate joins every scan of the linked crates' sources (gate-sys is already among them). HE-004B1 DESIGN-B
# sections 3 and 6 (owner decision Q-HE4B-6 (a)): it links i05-protocol too, which every linked-crate scan already
# reads (LINKED_CRATES); the closure check and the SBOM's workspace set follow.
OBSERVER_CRATE = "crates/observer"
# HE-004D1 DESIGN-D1 sections 3 and 19 (G-D1-1; owner decision Q-HE4D1-4 (a)): observer-sys, the observer's std-only
# kernel-read crate, joins planeon-observer's closure and every linked-crate scan; its manifest has no dependency.
OBSERVER_SYS = "crates/observer-sys"
OBSERVER_SYS_LIB = "crates/observer-sys/src/lib.rs"
OBSERVER_SYS_KERNEL = "crates/observer-sys/src/kernel.rs"
OBSERVER_LINKED_CRATES = (OBSERVER_CRATE, "crates/gate-sys", "crates/i05-protocol", OBSERVER_SYS)
SCANNED_CRATES = LINKED_CRATES + (OBSERVER_CRATE, OBSERVER_SYS)
OBSERVER_MAIN = "crates/observer/src/main.rs"
OBSERVER_LIB = "crates/observer/src/lib.rs"
GATE_MAIN = "crates/gate/src/main.rs"
GATE_CONFIG = "crates/effect-gate/src/gate_config.rs"
SIGNED_CONFIG = "crates/gate-tls/src/signed_config.rs"
# HE-003D DESIGN section 5 (O4, the STARTUP_EXCEPTIONS pattern): the binary's exit, std::process::ExitCode, is allowed
# only as this one use declaration of main.rs (whitespace around its tokens ignored), removed once before the
# LINKED_FORBIDDEN scan; a second one, another std::process item or another file still refuses. No std::env (no argv).
EXIT_USE = "use std::process::ExitCode;"
LINKED_EXCEPTIONS = {GATE_MAIN: ((EXIT_USE, re.compile(r"\buse\s+std::process::ExitCode\s*;")),),
                     # HE-004A DESIGN-A section 6: the observer binary's exit, the same single allowance.
                     OBSERVER_MAIN: ((EXIT_USE, re.compile(r"\buse\s+std::process::ExitCode\s*;")),)}
# HE-003D DESIGN section 5 (O2; D1-3, D2-2): the seal-order grammar over main.rs read without comments. Exactly one
# `#[cfg(target_os = "linux")] fn main() -> ExitCode` (and at most one non-Linux stub that only returns status::NOT_LINUX);
# its body starts with `let <name> = match seal_stage1() {`; between that `seal_stage1(` and the single `seal_stage2(`
# only identifiers, paths, literals, `::`, `=>`, `=`, `&`, `,`, `;`, braces and parentheses, the keywords let, match and
# return, the calls below (status::seal( only as the argument of ExitCode::from( ), the patterns Ok( and Err(, and
# tuple-variant patterns (an upper-case last segment whose parentheses close straight into `=>`): no method call,
# closure, macro, `?` or other call.
SEAL_CALLS = ("signed_config::load", "GateConfig::parse", "ExitCode::from", "status::seal", "Ok", "Err")
LINUX_MAIN = re.compile(r'#\s*\[\s*cfg\s*\(\s*target_os\s*=\s*"linux"\s*\)\s*\]\s*fn\s+main\s*\(\s*\)\s*->\s*ExitCode\s*\{')
LINUX_MAIN_CODE = re.compile(r'#\s*\[\s*cfg\s*\(\s*target_os\s*=\s*""\s*\)\s*\]\s*fn\s+main\s*\(\s*\)\s*->\s*ExitCode\s*\{')
OTHER_MAIN = re.compile(r'#\s*\[\s*cfg\s*\(\s*not\s*\(\s*target_os\s*=\s*"linux"\s*\)\s*\)\s*\]\s*fn\s+main\s*\(\s*\)\s*->\s*'
                        r'ExitCode\s*\{\s*ExitCode\s*::\s*from\s*\(\s*status\s*::\s*NOT_LINUX\s*\)\s*\}')
FN_MAIN = re.compile(r"\bfn\s+main\b")
STAGE1_BINDING = re.compile(r"\s*let\s+([A-Za-z_]\w*)\s*=\s*match\s+seal_stage1\s*\(\s*\)\s*\{")
# PR review round 1, R1-1 (Q-HE3D-R1 (a)): the whole stage-2 statement, exactly (comments removed, whitespace free):
# `let <n> = match seal_stage2(<stage-1 binding>) { Ok(<x>) => <x>, Err(<e>) => return ExitCode::from(status::seal(&<e>)), };`
# so no code runs in its argument (before the second stage) or in either arm.
STAGE2_STATEMENT = re.compile(
    r"\blet\s+([A-Za-z_]\w*)\s*=\s*match\s+seal_stage2\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\{\s*Ok\s*\(\s*([A-Za-z_]\w*)\s*\)\s*=>"
    r"\s*([A-Za-z_]\w*)\s*,\s*Err\s*\(\s*([A-Za-z_]\w*)\s*\)\s*=>\s*return\s+ExitCode\s*::\s*from\s*\(\s*status\s*::\s*seal\s*"
    r"\(\s*&\s*([A-Za-z_]\w*)\s*\)\s*\)\s*,?\s*\}\s*;")
# R1-2: main.rs's exact imports (path, rename) as a multiset: the top level's and serve's in-body ones; its only items
# are the Linux main, the non-Linux stub and serve; its only attributes are these three (whitespace removed).
MAIN_USES = tuple(sorted(
    [(("std", "process", "ExitCode"), None), (("effect_gate", "status"), None)]
    + [(("effect_gate", name), None) for name in ("seal_stage1", "seal_stage2", "GateConfig", "Sealed")]
    + [(("gate_tls", "signed_config", "self"), None), (("gate_tls", "signed_config", "LoadError"), None)]
    + [(("effect_gate", "file_store", "fstat_device"), None), (("effect_gate", "linux_os", "LinuxOs"), None)]
    # HE-003A3 (DESIGN section 5, D2-2): the observation's roots, its Linux reads and the driver.
    + [(("effect_gate", "linux_os", "KernelRoots"), None), (("effect_gate", "linux_os", "LinuxKernelReads"), None),
       (("effect_gate", "KernelObserver"), None)]
    + [(("effect_gate", "linux_net", name), None) for name in ("LinuxConnector", "LinuxStreams", "NetTable")]
    + [(("effect_gate", name), None) for name in ("ExpectedPeers", "FileStores", "ListenerPlan", "Owner", "PolicyGate",
                                                  "Stores", "Substrate")]
    + [(("gate_tls", name), None) for name in ("client_config", "credentials", "server_config", "Exchange", "I04Server",
                                               "UpstreamClient")]))
MAIN_FUNCTIONS = ["main", "main", "serve"]
MAIN_ATTRIBUTES = ("#![forbid(unsafe_code)]", '#[cfg(target_os="linux")]', '#[cfg(not(target_os="linux"))]')
MAIN_ITEMS = re.compile(r"(?<!')\b(mod|struct|enum|union|trait|type|impl|const|static|macro_rules|macro|extern)\b")
# HE-004A DESIGN-A sections 5 and 6 (D2-3): the observer's main.rs is held to the same grammar with its own parameters
# (check_seal_order's `site`): no configuration file, between the stages only the stage-1 statement's own arms
# (SEAL_CALLS without the configuration's two calls), its own pinned imports, two `fn main` and no other function. Beyond
# the gate's rules (`adjacent`): the stage-1 statement is exact, `let <n> = match seal_stage1() { Ok(<x>) => <x>, Err(<e>)
# => return ExitCode::from(status::seal(&<e>)), };`, the stage-2 statement follows it with nothing between, and after it
# comes exactly the tail OBSERVER_TAIL, which closes main: nothing but the not-yet-serving exit runs under the filter.
STAGE1_STATEMENT = re.compile(
    r"\s*let\s+([A-Za-z_]\w*)\s*=\s*match\s+seal_stage1\s*\(\s*\)\s*\{\s*Ok\s*\(\s*([A-Za-z_]\w*)\s*\)\s*=>\s*"
    r"([A-Za-z_]\w*)\s*,\s*Err\s*\(\s*([A-Za-z_]\w*)\s*\)\s*=>\s*return\s+ExitCode\s*::\s*from\s*\(\s*status\s*::\s*seal\s*"
    r"\(\s*&\s*([A-Za-z_]\w*)\s*\)\s*\)\s*,?\s*\}\s*;")
# HE-004C DESIGN-C sections 14 and 15 (G5, D1-1): the tail becomes exactly `ExitCode::from(serve(&<the stage-2
# binding>))`, which closes main (the binding is the stage-2 statement's own name, filled in at check time); main.rs's
# functions are the two main and serve, and its pinned imports gain Sealed (serve's signature) and serve's in-body ones.
OBSERVER_TAIL = r"\s*ExitCode\s*::\s*from\s*\(\s*serve\s*\(\s*&\s*%s\s*\)\s*\)\s*\}"
OBSERVER_SEAL_CALLS = ("ExitCode::from", "status::seal", "Ok", "Err")
OBSERVER_MAIN_USES = tuple(sorted(
    [(("std", "process", "ExitCode"), None), (("planeon_observer", "status"), None)]
    + [(("planeon_observer", name), None) for name in ("seal_stage1", "seal_stage2", "Sealed")]
    + [(("planeon_observer", "config", "self"), None), (("planeon_observer", "config", "ObserverConfig"), None)]
    + [(("planeon_observer", name), None) for name in ("credentials", "observe", "signed_config", "utc")]
    + [(("planeon_observer", "linux_net", "LinuxWire"), None), (("planeon_observer", "snapshot", "Closure"), None)]
    + [(("planeon_observer", "tls", name), None) for name in ("client_config", "time_provider")]
    # HE-004D1 DESIGN-D1 section 17.3 (G-D1-8): serve's in-body imports of the capture setup.
    + [(("planeon_observer", "capture", "CaptureEngine"), None), (("planeon_observer", "capture_schema", "CaptureSchema"), None),
       (("planeon_observer", "enrolled", "self"), None), (("planeon_observer", "enrolled", "Enrolled"), None),
       (("planeon_observer", "linux_capture", "LinuxCapture"), None)]))
GATE_SEAL_SITE = {"main": GATE_MAIN, "before": (GATE_CONFIG, SIGNED_CONFIG), "calls": SEAL_CALLS, "uses": MAIN_USES,
                  "functions": MAIN_FUNCTIONS, "adjacent": False}
OBSERVER_SEAL_SITE = {"main": OBSERVER_MAIN, "before": (), "calls": OBSERVER_SEAL_CALLS, "uses": OBSERVER_MAIN_USES,
                      "functions": ["main", "main", "serve"], "adjacent": True}
# G5's wiring rule (D1-1): in serve, read without comments and use declarations, the whitespace around `::` removed, each
# of these calls appears exactly once, in this order. HE-004D1 DESIGN-D1 section 17.3 (G-D1-8): twelve calls, the v2
# parse with the record's reference in place of the v1 parse, the capture schema, the record's read, the enrolled record
# and the capture roots joining them. HE-004-I01a DESIGN-I01A sections 6 and 12: thirteen, the enrolled record's server
# identity (`enrolled.server_identity(`) right after Enrolled::new and before the record moves into the capture engine
# (the I01 service's identity, which observe::run takes).
OBSERVER_WIRING = tuple((re.compile(pattern), name) for pattern, name in (
    (r"\bsigned_config::load\s*\(", "signed_config::load("),
    (r"\bObserverConfig::parse_with_record\s*\(", "ObserverConfig::parse_with_record("),
    (r"(?<![\w:])config::check_lifetime\s*\(", "config::check_lifetime("),
    (r"\bcredentials::observer_inputs\s*\(", "credentials::observer_inputs("),
    (r"(?<![\w:])client_config\s*\(", "client_config("), (r"\bCaptureSchema::embedded\s*\(", "CaptureSchema::embedded("),
    (r"(?<![\w:])enrolled::load_record\s*\(", "enrolled::load_record("), (r"\bEnrolled::new\s*\(", "Enrolled::new("),
    (r"(?<![\w:.])enrolled\s*\.\s*server_identity\s*\(", "enrolled.server_identity("),
    (r"\bLinuxWire::new\s*\(", "LinuxWire::new("), (r"\bLinuxCapture::new\s*\(", "LinuxCapture::new("),
    (r"\bClosure::embedded\s*\(", "Closure::embedded("), (r"(?<![\w:])observe::run\s*\(", "observe::run(")))
# The v1 parse no longer appears in serve (G-D1-8).
OBSERVER_V1_PARSE = re.compile(r"\bObserverConfig::parse\s*\(")
# HE-004-I01A2 (HE-004-I01a PR review round 1, R1-5): serve maps LinuxWire::new's refusal through status::wire_setup (24
# for the poller, 31-34 for the I01 listener's steps) in exactly this match, so a return to one status for every setup
# refusal refuses (read without comments, the whitespace around `::` removed, any other spacing allowed).
WIRE_SETUP_MATCH = re.compile(r"\blet\s+wire\s*=\s*match\s+LinuxWire::new\s*\(\s*sealed\s*\)\s*\{\s*Ok\s*\(\s*wire\s*\)\s*"
                              r"=>\s*wire\s*,\s*Err\s*\(\s*error\s*\)\s*=>\s*return\s+status::wire_setup\s*\(\s*&\s*"
                              r"error\s*\)\s*,?\s*\}\s*;")
# HE-004D2 (G-D2-11; HE-004D1 PR review round 1, R1-5): the two Linux constructors in the spellings of a path to `new`:
# `LinuxWire::new`, `<LinuxWire>::new`, `< LinuxCapture >::new`, and (HE-004D2 PR review round 1, R1-7) empty generic
# arguments and a parenthesised type, `LinuxWire::<>::new`, `<(LinuxWire)>::new`, `<LinuxCapture<>>::new`, spaces allowed.
# serve also names each type only once (check_observer_serve); in the whole crate neither type is renamed with `as`,
# no `type` item names either (R2-1, R3-1), and each is named in code only in its own file and inside main.rs's serve
# (check_observer_capture_callers, R3-1), so no other spelling of the type's path reaches `new` a second time. A type
# item is read to its `;` at bracket depth 0 (R4-1). The two home files are pinned whole (OBSERVER_HOME_PINS, owner
# decision Q-D2-END), so no added associated fn, trait impl, alias, default or projection can give another route there
# (R2-2, R3-1, R4-2), and outside them and main.rs's serve the naming rule refuses any code naming either type. These
# rules are textual: serve's own control flow around its one counted construction (a loop, or a closure or iterator
# calling it more than once) is not read by them and stays code review's (PR review round 5, R5-1), beside R118's residual.
def constructor_call(name: str) -> re.Pattern:
    return re.compile(r"\b%s\b(?:\s*<\s*>)?(?:\s*\))*(?:\s*>)?(?:\s*::\s*<\s*>)?\s*::\s*new\b" % name)


LINUX_CAPTURE_NEW = constructor_call("LinuxCapture")
QUALIFIED_CONSTRUCTORS = ((constructor_call("LinuxWire"), "LinuxWire"), (LINUX_CAPTURE_NEW, "LinuxCapture"))
FN_SERVE = re.compile(r"\bfn\s+serve\s*\(")
SEAL_TOKEN = re.compile(r"\s*(::|=>|b\"\"|\"\"|''|[A-Za-z_]\w*|[0-9]\w*|[(){},;=&])")
SEAL_KEYWORDS = {"let", "match", "return"}
RUST_KEYWORDS = {"as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "fn",
                 "for", "gen", "if", "impl", "in", "loop", "mod", "move", "mut", "pub", "ref", "self", "Self", "static",
                 "struct", "super", "trait", "type", "union", "unsafe", "use", "where", "while", "yield", "box", "try",
                 "macro", "become", "do", "final", "override", "priv", "typeof", "unsized", "virtual", "abstract"}
# The socket and thread names refused in main.rs before `seal_stage2(` and in all of gate_config.rs and
# signed_config.rs (comments removed, whitespace around `::` removed). signed_config.rs reads its two files through
# gate-sys's read-only opener (DESIGN section 3.1; departure A2, accepted 2026-10-15), so exactly one statement
# `use gate_sys::Dir;` at the start of a line is removed there first; a second one, `pub use`, a group, a rename,
# another gate-sys path or a qualified `gate_sys::` expression still refuses.
BEFORE_SEAL_REFUSED = (r"\bgate_sys\b", r"\bPoller\b", r"\blisten_", r"\bconnect_", r"\bNetTable\b", r"\bLinuxOs\b",
                       r"\bLinuxConnector\b", r"\bstd::net\b", r"\bstd::thread\b", r"\bthread::",
                       # HE-003A3 (DESIGN section 5, D2-2): the observation's roots exist only after the seal.
                       r"\bKernelRoots\b",
                       # HE-004D1 DESIGN-D1 section 17.3 (G-D1-6): the capture roots too.
                       r"\bobserver_sys\b", r"\bLinuxCapture\b")
SIGNED_CONFIG_DIR = re.compile(r"(?m)^[ \t]*use\s+gate_sys::Dir\s*;")
# HE-003D DESIGN section 5 (D1-3, D2-6): gate-sys's socket modules are reached only from effect-gate's linux_os.rs and
# linux_net.rs (whose public constructors take &Sealed), which re-export nothing (no `pub use`), and from gate-sys.
# HE-004C DESIGN-C section 15 (G4, D1-14 (a) and (d)): the observer's one socket module, whose only constructor takes the
# observer's &Sealed (code review's, as for the gate); every other crates/observer source still refuses gate-sys's socket
# modules, which is why client.rs's Wire has its own portable types.
OBSERVER_LINUX_NET = "crates/observer/src/linux_net.rs"
# HE-004-I01a DESIGN-I01A sections 4 and 12 (Q-HE4I1-5 (a)): the observer's I01 listener file, the second socket file
# of the observer, built only inside LinuxWire::new (G-I01-6) and pinned whole (OBSERVER_HOME_PINS). Its pub(crate)
# API names only client.rs's portable types, Sealed and the data type Watched, so the R1-3 socket-item rule passes
# unchanged (Q-HE3D-R1 (a)).
OBSERVER_LINUX_LISTEN = "crates/observer/src/linux_listen.rs"
SOCKET_FILES = ("crates/effect-gate/src/linux_os.rs", "crates/effect-gate/src/linux_net.rs", OBSERVER_LINUX_NET,
                OBSERVER_LINUX_LISTEN)
SOCKET_MODULES = ("channel", "tcp")
SOCKET_TEXT = re.compile(r"\bgate_sys::(?:channel|tcp)\b")
PUB_USE = re.compile(r"\bpub\s*(?:\([^)]*\)\s*)?use\b")
# PR review round 1, R1-3 (Q-HE3D-R1 (a)): in SOCKET_FILES no `pub` (or `pub(..)`) type alias, const, static or fn
# signature names a gate-sys channel or tcp item (through an import, a module import or a qualified path), except these
# data types, which create nothing: the two listen errors and the borrowed view of an existing descriptor (today's
# `NetTable::listen_i04` returns a TcpListenError and `NetTable::watched`, pub(crate), a Watched).
SOCKET_DATA_TYPES = ("ListenError", "TcpListenError", "Watched")
PUB_ITEM = re.compile(r"\bpub\s*(?:\([^)]*\)\s*)?(?:(?:unsafe|const|async|extern)\s+(?:\"\"\s*)?)*(fn|type|const|static)\b")
# PR review round 2, R2-1 (Q-HE3D-R2 (a)): also in SOCKET_FILES, no private type alias (an alias chain would hide a
# socket item from a pub one; none exists), no pub struct field whose type names a channel or tcp item (other than
# SOCKET_DATA_TYPES) or is a fn pointer, and no pub const or static of a fn-pointer type (a pointer to a private fn).
TYPE_ITEM = re.compile(r"\btype\s+[A-Za-z_]\w*")
PUB_PREFIX = re.compile(r"\bpub\s*(?:\([^)]*\)\s*)?$")
STRUCT_ITEM = re.compile(r"\bstruct\s+[A-Za-z_]\w*")
FN_POINTER = re.compile(r"\bfn\s*\(|\bextern\s*(?:\"\"\s*)?fn\b")
# HE-003D PR review round 2 confirmation, N1 (HE-003A2 DESIGN section 6, owner decision Q-A2-9 (a), D1-3, D2-1): the
# R2-1 rule also reads Fn-trait types, `dyn` or `impl` followed by Fn, FnMut or FnOnce (after other bounds, a lifetime
# or a higher-ranked `for<..>`), next to fn pointers, in pub type aliases, the types of pub consts and statics, and pub
# struct fields (braced and tuple); and it reads the variants of `pub` (or `pub(..)`) enums, tuple and named-field,
# through their field types only (never a variant or field name), for gate-sys socket items (SOCKET_DATA_TYPES exempt),
# fn pointers and Fn-trait types. A private enum (linux_net.rs's Stream) stays outside, like a private struct. N2 is
# documentation: an associated type in a socket file is refused as a private alias (R72). PR review round 1, R1-1
# (Q-A2-R1 (a)): the trait may be path-qualified (`std::ops::Fn`, `core::ops::FnMut`, `::core::ops::FnOnce`) and
# parenthesised (`dyn (Fn())`), also higher-ranked and after nested generic bounds; any `Fn(`, `FnMut(` or `FnOnce(`
# (or `<`) in the typed text refuses, whatever precedes it. Residual (code review's, R72): trait-impl associated consts
# and items, pub fn bodies and return types, generic parameters (defaults, bounds, where-clauses) and subtraits of Fn.
FN_TRAIT = re.compile(r"\b(?:dyn|impl)\s+(?:(?:for\s*<[^>]*>|'\w+|\??(?:::)?[A-Za-z_][\w:]*(?:\s*<[^<>]*>)?)\s*\+\s*)*"
                      r"\(?\s*(?:for\s*<[^>]*>\s*)?(?:::)?(?:[A-Za-z_]\w*::)*(?:Fn|FnMut|FnOnce)\b"
                      r"|\b(?:Fn|FnMut|FnOnce)\s*[(<]")
PUB_ENUM = re.compile(r"\bpub\s*(?:\([^)]*\)\s*)?enum\s+[A-Za-z_]\w*")
# R1-3: no macro in any linked crate's non-test sources or the binary (a macro could complete a gate-sys socket path
# that neither the use-tree reading nor the text scan sees): macro_rules, a `macro` item, #[macro_export].
MACROS = ((re.compile(r"\bmacro_rules\b"), "macro_rules"), (re.compile(r"(?<![\w$])macro\s+[A-Za-z_]"), "a macro item"),
          (re.compile(r"#\s*!?\s*\[\s*macro_export\b"), "#[macro_export]"))
THREADS = (re.compile(r"\bstd::thread\b"), re.compile(r"\bthread::"))
# HE-003D departure A1 (accepted 2026-10-15): the binary opens its stores only with FileStores::open_bound (the
# generation binding of DESIGN section 3.3); in crates/gate's sources (comments removed, whitespace around `::`
# removed) `FileStores::open_bound(` appears exactly once, `::open` appears only as `PolicyGate::open`, and neither
# FileStores nor PolicyGate is renamed, aliased or used as a rename's name.
OPEN_BOUND = re.compile(r"\bFileStores::open_bound\s*\(")
# PR review round 1, R1-4: no linked source (file_store.rs included, whose `pub fn open` is the definition) calls
# FileStores::open, so a library wrapper cannot hand the binary an unbound opening; file_store.rs not `Self::open` either.
UNBOUND_OPEN = re.compile(r"\bFileStores\s*>?::open\b")
SELF_OPEN = re.compile(r"\bSelf\s*>?::open\b")
FILE_STORE = "crates/effect-gate/src/file_store.rs"
POLICY_OPEN = re.compile(r"(?<![\w>])PolicyGate::open\b")
ANY_OPEN = re.compile(r"::open\b")
STORE_ALIASES = (re.compile(r"\b(?:FileStores|PolicyGate)\s+as\b"), re.compile(r"\bas\s+(?:FileStores|PolicyGate)\b"),
                 re.compile(r"\btype\s+\w+\s*(?:<[^>]*>)?\s*=\s*[\w:<> ]*\b(?:FileStores|PolicyGate)\b"),
                 re.compile(r"\btype\s+(?:FileStores|PolicyGate)\b"))
# DESIGN section 5 (D1-3): no code that runs before main, in any linked crate or the binary.
PRE_MAIN = ((re.compile(r"\blink_section\b"), "link_section"), (re.compile(r"#\s*!?\s*\[\s*used\b"), "#[used]"),
            (re.compile(r"\binit_array\b"), "init_array"), (re.compile(r"\bno_mangle\b"), "no_mangle"),
            (re.compile(r"\bexport_name\b"), "export_name"))
# DESIGN sections 4 and 5 (D1-10, D2-6): nothing printed; any mention of stdout or stderr (any case) refuses.
PRINTS = ((re.compile(r"\bprint\s*!"), "print!"), (re.compile(r"\bprintln\s*!"), "println!"),
          (re.compile(r"\beprint\s*!"), "eprint!"), (re.compile(r"\beprintln\s*!"), "eprintln!"),
          (re.compile(r"\bdbg\s*!"), "dbg!"), (re.compile(r"(?i)\bstd(?:out|err)\b"), "stdout or stderr"))
# DESIGN section 3.1 (Q-HE3D-7 (d)): the compiled-in signer key file holds exactly 0 (not yet set) or 32 bytes.
SIGNER_KEY = "crates/gate-tls/config-signer.pub"
# HE-004C DESIGN-C sections 11 and 15 (G6, Q-HE4C-3 (i)): the observer's own compiled-in key, empty until HE-008, under
# the same rule; the gate run reads both.
OBSERVER_SIGNER_KEY = "crates/observer/config-signer.pub"
SIGNER_KEYS = (SIGNER_KEY, OBSERVER_SIGNER_KEY)
# HE-003D DESIGN section 5 (O3, C8): planeon-gate's symbol inventory. MEMBARRIER must be absent (musl's membarrier.lo
# defines both; its __membarrier_init is WEAK in pthread_create.lo and harmless). KILLED_WRAPPERS are the musl 1.2.5
# wrappers whose system call the pinned EFFECT_GATE programs kill unconditionally on at least one target: each name's
# primary system call number (x86_64, aarch64) run through a classic-BPF interpreter over contracts/seccomp-v4/ with
# every argument vector SECCOMP_RET_KILL_PROCESS (argument-filtered calls such as socket, prctl, mremap and fcntl are not
# listed; T04's steady-state trace stays the proof). HE-003A2 (DESIGN section 2, D1-13) re-derived it over the v4
# programs with the kept classifier tools/w03/he003a2/classify_wrappers.py (sha256
# 97cb5f2b90aa68ae73dd87cab4c67f89055aebb4dc4c736b3fcc9927d4c71ca0; 90 argument vectors, sha256
# 694dfd2daf4bc10083b71a242bb51c4ef0fa843f28a776f0f400b4fed2ed966c; HE-003D's was over contracts/seccomp-v3/ with 147):
# readlinkat left (allowed under v4 with a non-negative dirfd on both targets); readlink stays (x86_64's call 89 is
# killed unconditionally). A present one must be in WRAPPER_JUSTIFICATIONS, the
# reviewed list built from phase 2's actual set (both targets of the shipped binary, which holds the composed gate
# since Q-HE3D-B1 (a); the same twelve as a scratch build with a 32-byte stand-in key) and recorded in MODEL_DEFINED
# (R77).
MEMBARRIER = ("membarrier", "__membarrier")
# Owner decision Q-HE3D-B1 (a): the shipped planeon-gate holds the composed gate (signed_config::load passes the
# compiled-in key through core::hint::black_box, so LTO cannot drop what follows it while the key is empty). Its
# .symtab must hold symbols of gate-tls and rustls (a Rust path whose crate root is that crate, legacy or v0 mangling)
# and of ring's C and assembly core (the ring_core_0_17_14_ prefix).
CRATE_SYMBOLS = (("gate_tls", re.compile(r"(?:^_ZN|C(?:s[0-9A-Za-z]*_)?)8gate_tls(?=[0-9A-Z]|$)")),
                 ("rustls", re.compile(r"(?:^_ZN|C(?:s[0-9A-Za-z]*_)?)6rustls(?=[0-9A-Z]|$)")),
                 ("ring", re.compile(r"^ring_core_0_17_14_")))
KILLED_WRAPPERS = ("__membarrier", "accept", "access", "capget", "capset", "chdir", "chmod", "chown", "chroot",
                   "clock_settime", "copy_file_range", "creat", "dup", "dup2", "dup3", "eventfd", "execv", "execve",
                   "execvp", "faccessat", "fchdir", "fchmod", "fchmodat", "fchown", "fexecve", "fork", "ftruncate",
                   "futimens", "getcwd", "getdents", "getegid", "geteuid", "getgid", "getpriority", "getresgid",
                   "getresuid", "getuid", "inotify_init1", "ioctl", "isatty", "kill", "link", "lstat", "lstat64",
                   "membarrier", "memfd_create", "mkdir", "mkdirat", "mknod", "mlock", "mount", "msync", "open",
                   "open64", "pause", "personality", "pipe", "pipe2", "popen", "posix_spawn", "process_vm_readv",
                   "ptrace", "readdir", "readlink", "realpath", "rename", "renameat", "rmdir",
                   "sched_setaffinity", "seccomp", "sendfile", "setgid", "setpgid", "setpriority", "setrlimit",
                   "setsid", "settimeofday", "setuid", "shmget", "signalfd", "socketpair", "splice", "stat",
                   "stat64", "statx", "symlink", "sysinfo", "system", "tcgetattr", "tee", "timerfd_create",
                   "truncate", "uname", "unlink", "unlinkat", "utimensat", "utimes", "vfork")
WRAPPER_JUSTIFICATIONS = {
    "capget": "the seal's own read (gate-sys seal.rs), made only before the filter is installed (stage 2 step 9)",
    "capset": "the seal's own write (gate-sys seal.rs), made only in stages 1 and 2 before the filter",
    "getresuid": "the seal's precondition (gate-sys seal.rs), before stage 1's first change",
    "getresgid": "the seal's precondition (gate-sys seal.rs), before stage 1's first change",
    "open": "std's start-up, before main (a closed fd 0-2 is reopened on /dev/null); on aarch64 musl's open is openat, "
            "allowed; the linked crates name no std opener (LINKED_FORBIDDEN); no direct call in the composed text",
    "readlink": "called only by realpath; std's File Debug and current_exe paths (no File is formatted after the seal, "
                "DEBUG_HAZARDS; current_exe is refused by the start-up lint)",
    "realpath": "std's canonicalize and backtrace paths; no direct call or jump in the composed text; std::path and Path "
                "are refused in the linked crates; a panic with RUST_BACKTRACE set dies by SIGSYS (HE-008 leaves it unset)",
    "getcwd": "called only by realpath (and std's current_dir, refused by the start-up lint)",
    "stat": "std's path-based metadata (std::path and Path are refused in the linked crates); no direct call in the "
            "composed text",
    "dup": "linked from std's runtime, no direct call or jump in the composed text; the gate's code duplicates no "
           "descriptor (try_clone is fcntl F_DUPFD_CLOEXEC, allowed)",
    "pause": "linked from musl or std, no direct call or jump in the composed text; on aarch64 it is ppoll, allowed",
    "sysinfo": "called only by musl's sysconf for _SC_PHYS_PAGES and _SC_AVPHYS_PAGES; std asks sysconf only for the page "
               "size (from the auxiliary vector, no system call)",
}
# HE-004A DESIGN-A section 6 (D1-10, D2-5): each target's planeon-observer must hold this contract file's bytes exactly
# once. HE-004-I01a (DESIGN-I01A sections 3 and 12): the seccomp-v5 programs, which give the sealed observer bind,
# listen and accept4 for its I01 listener (seal.rs pins their sizes, 2,024 and 1,936 bytes, and their instruction counts,
# 253 and 242); seal.rs may embed only these two (check_observer_includes).
OBSERVER_PROGRAMS = {"x86_64-unknown-linux-musl": "contracts/seccomp-v5/OBSERVER.x86_64.bpf",
                     "aarch64-unknown-linux-musl": "contracts/seccomp-v5/OBSERVER.aarch64.bpf"}
# HE-004C DESIGN-C section 15 (G9, D1-6, D2-8; owner decision Q-HE4C-12 (a)): symbols only the path after the
# configuration keeps, so the shipped planeon-observer holds the composed client while its key is empty (the compiled
# key passes core::hint::black_box). A symbol counts by its own path: the mangled name (legacy `_ZN` or v0 `_R`) is read
# down its first path component to its first crate root (symbol_path), so a generic instantiation of another crate's
# item (core's drop glue of a rustls type, alloc's B-tree over an observer type) or the instantiating-crate suffix never
# counts. The client symbol: a rustls symbol naming ClientConnection (the length-prefixed identifier); LTO inlines every
# one in both shipped builds, so the recorded substitute applies: a rustls symbol of the client handshake modules
# (rustls::client::hs or rustls::client::tls13: emit_client_hello_for_retry, handle_server_hello, the Expect* states),
# which only a client connection drives. The module symbol: a planeon_observer symbol of its client, http, watch or
# observe module. Verified on both musl builds and recorded in MODEL_DEFINED R118. No wrapper inventory (owner rule
# Q-HE4A-B2).
OBSERVER_CLIENT_CONNECTION = re.compile(r"(?<!\d)16ClientConnection(?![a-z])")
OBSERVER_CLIENT_MODULES = (("rustls", "client", "hs"), ("rustls", "client", "tls13"))
OBSERVER_MODULES = ("client", "http", "watch", "observe")
SYMBOL_IDENT = re.compile(r"(\d+)_?")
OPENAT = "crates/gate-sys/src/openat.rs"
SEAL = "crates/gate-sys/src/seal.rs"
CHANNEL = "crates/gate-sys/src/channel.rs"
TCP = "crates/gate-sys/src/tcp.rs"
GATE_TLS = "crates/gate-tls"
# The workspace sources where the word unsafe may appear (HE-002C DESIGN section 3, HE-002S DESIGN section 6, HE-003A
# DESIGN section 8, HE-003B DESIGN section 3; HE-004D1 DESIGN-D1 section 4.4, G-D1-2: observer-sys's kernel.rs).
UNSAFE_FILES = (OPENAT, SEAL, CHANNEL, TCP, OBSERVER_SYS_KERNEL)
# The linked sources that may name std::os::fd items (HE-003A DESIGN section 8): effect-gate holds gate-sys's opaque
# types and names no descriptor. HE-004D1 (G-D1-2): observer-sys's kernel.rs.
FD_FILES = (OPENAT, CHANNEL, TCP, OBSERVER_SYS_KERNEL)
# HE-002S DESIGN section 6 (owner decision Q-HE2S-5 (a), D3; PR review round 1, R1-5) and HE-003A DESIGN section 8:
# the start-up lint's exceptions, a per-file list of exact expressions (whitespace between their tokens ignored), each
# removed once before the scan: in gate-sys's seal module the expression that opens the process's own status file, in
# its channel module the two that open the thread's own attribute directory and a peer's process directory. Any other
# /proc (a second occurrence, a raw string, concat!, another file name, another file) still refuses.
STATUS_READ = 'Dir::at("/proc/self")?.file_ro("status")'
SOCKCREATE_DIR = 'Dir::at("/proc/thread-self/attr")'
PEER_DIR = 'Dir::at(&format!("/proc/{}", pid))'
# HE-003A3 (DESIGN sections 5 and 6, D2-5): the observation's two root opens, each exactly once in linux_os.rs (the
# observation rules pin both inside KernelRoots::open_after_seal).
LINUX_OS = "crates/effect-gate/src/linux_os.rs"
CGROUP_ROOT = 'KernelRoot::open_kernel_root("/sys/fs/cgroup")'
PROC_ROOT = 'KernelRoot::open_kernel_root("/proc")'
CGROUP_ROOT_CALL = re.compile(r'\bKernelRoot\s*::\s*open_kernel_root\s*\(\s*"/sys/fs/cgroup"\s*\)')
PROC_ROOT_CALL = re.compile(r'\bKernelRoot\s*::\s*open_kernel_root\s*\(\s*"/proc"\s*\)')
# HE-004D1 DESIGN-D1 section 19 (G-D1-5; B1's pattern for a record module, Q-HE4B-5 (a)): five exact private root
# constants, each removed once in its own file. A pattern ignores whitespace between the tokens and is anchored to a line
# start with only spaces or tabs before `const`, so a `pub`, `pub(crate)` or same-line attribute form is not removed and
# still refuses; a raw string, concat!, a comment between the tokens or a changed string is not the expression either.
OBSERVER_ENROLLED = "crates/observer/src/enrolled.rs"
OBSERVER_CAPTURE_CHECK = "crates/observer/src/capture_check.rs"


def root_constant(name: str, value: str) -> tuple[str, re.Pattern]:
    """The exact item `const <name>: &str = "<value>";` and its anchored, whitespace-tolerant pattern (G-D1-5)."""
    return ('const %s: &str = "%s";' % (name, value),
            re.compile(r'(?m)^[ \t]*const\s+%s\s*:\s*&\s*str\s*=\s*"%s"\s*;' % (name, re.escape(value))))


D1_ROOT_CONSTANTS = {
    OBSERVER_SYS_KERNEL: (root_constant("PROC_ROOT", "/proc"), root_constant("CGROUP_ROOT", "/sys/fs/cgroup")),
    OBSERVER_ENROLLED: (root_constant("CGROUP_ROOT", "/sys/fs/cgroup"), root_constant("PIN_ROOT", "/sys/fs/bpf/planeon")),
    OBSERVER_CAPTURE_CHECK: (root_constant("CGROUP_ROOT", "/sys/fs/cgroup"),),
}
# HE-004D2 DESIGN-D2 section 5.4 (G-D2-9; B2's two, Q-HE4B-5 (a)): record_check.rs's two private root constants, under
# the same anchored patterns.
OBSERVER_RECORD_CHECK = "crates/observer/src/record_check.rs"
D2_ROOT_CONSTANTS = {
    OBSERVER_RECORD_CHECK: (root_constant("CGROUP_ROOT", "/sys/fs/cgroup"), root_constant("PIN_ROOT", "/sys/fs/bpf/planeon")),
}
ROOT_CONSTANTS = {**D1_ROOT_CONSTANTS, **D2_ROOT_CONSTANTS}
# HE-004D2 DESIGN-D2 sections 5.4 and 9 (G-D2-6): the one /opt/planeon/ text of crates/observer's sources.
INTERPRETER_TREE = root_constant("INTERPRETER_TREE", "/opt/planeon/python/")
STARTUP_EXCEPTIONS = {
    LINUX_OS: ((CGROUP_ROOT, CGROUP_ROOT_CALL), (PROC_ROOT, PROC_ROOT_CALL)),
    SEAL: ((STATUS_READ,
            re.compile(r'\bDir\s*::\s*at\s*\(\s*"/proc/self"\s*\)\s*\?\s*\.\s*file_ro\s*\(\s*"status"\s*\)')),),
    CHANNEL: ((SOCKCREATE_DIR, re.compile(r'\bDir\s*::\s*at\s*\(\s*"/proc/thread-self/attr"\s*\)')),
              (PEER_DIR, re.compile(r'\bDir\s*::\s*at\s*\(\s*&\s*format\s*!\s*\(\s*"/proc/\{\}"\s*,\s*pid\s*\)\s*\)'))),
    **ROOT_CONSTANTS,
}
# HE-004D1 DESIGN-D1 section 19 (G-D1-5, R3-1): the linked-source scan refuses the word fs in the raw text of every
# non-test source, so the same five expressions are removed once each, in their own files, before that scan (as R96's
# one cgroup2-root open in linux_os.rs); the PROC_ROOT one holds no fs. Any other fs word still refuses.
FS_SCAN_EXCEPTIONS = ROOT_CONSTANTS
# HE-002S DESIGN section 6 (D8): the foreign symbols each linked source declares, exactly; no other linked source
# declares a foreign item. Extern items are private, none is declared `safe`, and no linked source names link_name.
# PR review round 1, R1-1: the sources are read with comments removed and literal contents emptied (rust_code), every
# `extern` must be a block, `extern crate` or a function's ABI, a block's body must hold only items the reader follows,
# and the files allowed `unsafe` define no macro; anything else refuses. HE-003A DESIGN section 3: the channel module's
# twelve symbols (accept4 only through syscall). HE-003A2 DESIGN section 3 (Q-A2-2 (a), D1-6): the openat module's
# readlinkat (Dir::read_link, through musl's wrapper, which passes the dirfd unchanged and has no fallback), refused in
# any other linked source.
FOREIGN_ITEMS = {OPENAT: {"openat", "readlinkat"},
                 SEAL: {"prctl", "capset", "capget", "prlimit", "getresuid", "getresgid", "syscall"},
                 CHANNEL: {"socket", "bind", "listen", "setsockopt", "getsockopt", "recvmsg", "sendmsg", "epoll_create1",
                           "epoll_ctl", "epoll_pwait", "ppoll", "syscall"},
                 # HE-003B DESIGN section 3.1: the I04 listener's eight (accept4 only through syscall); HE-003C DESIGN
                 # sections 5 and 6: the upstream client's connect and getsockopt (SO_ERROR), ten in all.
                 TCP: {"socket", "setsockopt", "bind", "listen", "connect", "getsockopt", "recv", "send", "shutdown",
                       "syscall"},
                 # HE-004D1 DESIGN-D1 section 4.1 (G-D1-2; owner decision Q-HE4D1-5 (a)): observer-sys's one item.
                 OBSERVER_SYS_KERNEL: {"syscall"}}
# HE-004D1 DESIGN-D1 sections 4.1 and 19 (G-D1-3, D1-6): kernel.rs's calls of its one foreign item. Read without comments
# and with literals kept: the word syscall is its extern declaration `fn syscall(` once and otherwise only a plain call
# `syscall(` (not after `::` or `.`); every call has exactly seven arguments, the first one of the six SYS_ constants;
# each SYS_ constant is defined once per target module with its pinned value, there is no other, and the names occur
# only there and as a call's first argument; the checked positions (openat's flags, the fourth argument; ioctl's
# request, the third; bpf's command, the second) are single named constants, the request FS_IOC_MEASURE_VERITY and
# the command one of the three BPF commands, each defined once with its pinned value. In observer's and observer-sys's
# other sources neither syscall nor a SYS_ name occurs (R4-2).
SYS_NUMBERS = {"x86_64": {"SYS_OPENAT": 257, "SYS_GETDENTS64": 217, "SYS_READLINKAT": 267, "SYS_FSTATFS": 138,
                          "SYS_IOCTL": 16, "SYS_BPF": 321},
               "aarch64": {"SYS_OPENAT": 56, "SYS_GETDENTS64": 61, "SYS_READLINKAT": 78, "SYS_FSTATFS": 44,
                           "SYS_IOCTL": 29, "SYS_BPF": 280}}
SYS_CHECKED = {"SYS_OPENAT": 3, "SYS_IOCTL": 2, "SYS_BPF": 1}
IOCTL_REQUESTS = {"FS_IOC_MEASURE_VERITY": 0xC0046686}
BPF_COMMANDS = {"BPF_OBJ_GET": 7, "BPF_OBJ_GET_INFO_BY_FD": 15, "BPF_PROG_QUERY": 16}
SYS_NAME = re.compile(r"\bSYS_[A-Za-z0-9_]+\b")
SYSCALL_WORD = re.compile(r"\bsyscall\b")
NUMBERS_MODULE = re.compile(r'#\s*\[\s*cfg\s*\(\s*target_arch\s*=\s*"(x86_64|aarch64)"\s*\)\s*\]\s*mod\s+numbers\s*\{')
# G-D1-4 (NP-3): every openat call's flags are one of these sets, each built only from the read-only flags and each
# asserted against the OBSERVER row's write-and-create mask; the cgroup file names are exactly these seven, each once;
# no observer or observer-sys source names freeze (code) or holds "cgroup.freeze" (literals), and observer-sys's code
# names no write, Write or write_all.
OPEN_FLAG_SETS = ("ROOT_PATH_FLAGS", "DIR_FLAGS", "READ_FLAGS", "TARGET_FLAGS")
READ_ONLY_FLAGS = ("O_RDONLY", "O_PATH", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
WRITE_MASK = "0x400643"
CGROUP_FILE_NAMES = ("cgroup.procs", "cgroup.events", "cgroup.stat", "memory.max", "pids.max", "pids.current", "cpu.max")
DOTTED_NAME = re.compile(r'"([0-9A-Za-z_]+(?:\.[0-9A-Za-z_]+)+)"')
FREEZE_WORD = re.compile(r"\bfreeze\b")
WRITE_WORDS = re.compile(r"\b(?:write|Write|write_all)\b")
# G-D1-7: link_text is defined once in kernel.rs and reads only ProcLink's five names; Roots::own_pid reads the proc
# root's `self` link, the one other link name; link_at, their one helper, is called exactly in those two places; and
# link_text and own_pid are called (among the observer's and observer-sys's sources) only in linux_capture.rs.
OBSERVER_LINUX_CAPTURE = "crates/observer/src/linux_capture.rs"
PROC_LINK_NAMES = ("exe", "ns/user", "ns/mnt", "ns/pid", "ns/net")
LINK_TEXT_CALL = re.compile(r"\blink_at\s*\(\s*&\s*self\s*\.\s*handle\s*,\s*&\s*name\s*\(\s*which\s*\.\s*name\s*\(\s*\)\s*\)")
OWN_PID_CALL = re.compile(r'\blink_at\s*\(\s*&\s*self\s*\.\s*proc_root\s*,\s*&\s*name\s*\(\s*"self"\s*\)')
# PR review round 1, R1-2: the names kernel.rs's pins read are bound once. No item inside a function body (the `const`
# of a `*const` pointer type and of `&raw const` is not an item), and on the link-read path each function names the free
# fn `name` exactly so: (free calls, method calls, other words); `link_at`'s one other word is its parameter's use.
BODY_ITEM = re.compile(r"\b(?:fn|static|use|impl|mod|struct|enum|union|trait|type|extern|macro_rules|macro)\b"
                       r"|(?<!\*)(?<!raw\s)\bconst\b")
LINK_PATH_NAMES = {"link_text": (1, 1, 0), "own_pid": (1, 0, 0), "link_at": (0, 0, 1)}
# PR review round 2, R2-1 (G-D1-7): the link-read path's three functions, pinned exactly. Each is read from kernel.rs
# without comments and with literals kept, from its visibility to its closing brace, as tokens (a whole string literal,
# an identifier, a number or one other character) joined by single spaces, so whitespace and comments do not count and
# any other text refuses: neither a rebound or retyped `which`, an added or retyped parameter, a generic parameter, a
# changed visibility nor a changed body can move a link read off ProcLink's five names and the proc root's `self`.
LINK_TOKEN = re.compile(r'''"(?:[^"\\]|\\.)*"|[A-Za-z_]\w*|\d\w*|'\w+|\S''')
LINK_PATH_PINS = {
    'link_text': (
        'pub fn link_text ( & self , which : ProcLink , buffer : & mut [ u8 ] ) - > io : : Result < usize > { let '
        'limit = buffer . len ( ) . min ( LINK_BUFFER ) ; let buffer = buffer . get_mut ( . . limit ) . '
        'ok_or_else ( | | refusal ( "a link buffer" ) ) ? ; link_at ( & self . handle , & name ( which . name ( ) '
        ') ? , buffer ) }'),
    'own_pid': (
        'pub fn own_pid ( & self ) - > io : : Result < i32 > { let mut buffer = [ 0u8 ; 32 ] ; let count = '
        'link_at ( & self . proc_root , & name ( "self" ) ? , & mut buffer ) ? ; let text = std : : str : : '
        'from_utf8 ( buffer . get ( . . count ) . unwrap_or_default ( ) ) . map_err ( | _ | refusal ( "the self '
        'link" ) ) ? ; number ( text ) . ok_or_else ( | | refusal ( "the self link is not a process number" ) ) }'),
    'link_at': (
        'fn link_at ( dir : & File , name : & CStr , buffer : & mut [ u8 ] ) - > io : : Result < usize > { if '
        'buffer . is_empty ( ) { return Err ( refusal ( "a link buffer must hold at least one byte" ) ) ; } let '
        'size = c_long : : try_from ( buffer . len ( ) ) . map_err ( | _ | refusal ( "a link buffer\'s length" ) ) '
        '? ; let value = unsafe { syscall ( SYS_READLINKAT , raw ( dir ) , name . as_ptr ( ) , buffer . '
        'as_mut_ptr ( ) , size , ZERO , ZERO ) } ; match counted ( value ) ? { 0 = > Err ( refusal ( "a link read '
        'back empty" ) ) , count if count < buffer . len ( ) = > Ok ( count ) , _ = > Err ( refusal ( "a link '
        'filled its buffer and may be longer" ) ) , } }'),
}
# PR review round 3, R3-1 (monitor decision (a)): observer-sys's kernel.rs pinned whole by sha256, checked like CONTRACTS,
# alongside the lexical rules above, which stay for intent and clear refusals. The pinned link-read functions' callees
# (the free fn `name`, and ProcLink's name() in any impl, through an alias or a trait impl) cannot change without a new
# pin; any change to the file refuses. HE-004D2 (DESIGN-D2 section 12, G-D2-10; HE-004D1 PR review round 4, R4-1): the
# crate's other two sources and its manifest are pinned the same way, so no module can be added to observer-sys (an
# inline `pub mod` in lib.rs included) and no dependency or target can join it; kernel.rs's pin is unchanged.
OBSERVER_SYS_PINS = {
    "crates/observer-sys/src/kernel.rs": "0b3d0151c9eaf1f44dd56436795aefd8cb7140ce9f4d16fe5f4eaf7130e61d43",
    "crates/observer-sys/src/lib.rs": "e718fc32fc13a28b4bfc58d6917cd9ac88479e2f5779ab9d351fdc5723f19029",
    "crates/observer-sys/src/dirent.rs": "133b05b3b231757078efd6c62259dcdafcd3b60f0f9fbae0ba0c0653c15ef510",
    "crates/observer-sys/Cargo.toml": "4d1299774cccfd74a5a8f7e353c47afde7c6014cc7eb04deadad3d05e5d6fcc4",
}
# HE-004D2 PR review round 4, owner decision Q-D2-END (a): the two Linux constructors' home files pinned whole, as kernel.rs
# was in HE-004D1, so no alias, default, projection or further constructor route can be written where naming the type is
# allowed. With the naming rule (each type named in code only in its own file and inside main.rs's serve), no alias or
# added route to a second construction remains outside these reviewed bytes; serve's own control flow around its one
# counted construction stays code review's (R5-1).
# HE-004-I01a DESIGN-I01A section 12 (G-I01-6): the I01 listener file is pinned whole too, and linux_net.rs re-pinned
# after its I01 changes (the listener's registration, the I01 watch of each wait, PeerOps).
OBSERVER_HOME_PINS = {
    "crates/observer/src/linux_capture.rs": "77e50074e81eefc782ba287fad874ba83c3a5c01225ee6a1d5c69407b0be1862",
    "crates/observer/src/linux_net.rs": "41a23aa7d6215d5f8194b703da511a8945d7600f1f0d306affb94cd830ac17ac",
    "crates/observer/src/linux_listen.rs": "d06742932d92eaf05308158d37ce670859f316e1b0fe7a1972b8e4c93be5433b",
}
# HE-004-I01B1 R-B3-PIN (the monitor's ruling closing DESIGN-I01B under Q-I01B-CAP; DESIGN-I01B1 rev 2 section 1): every
# guarded file is pinned whole by sha256. The six not yet pinned are pinned here at their dd7422ed bytes (I01B1 changes
# none of them); linux_listen.rs and linux_net.rs stay in OBSERVER_HOME_PINS; i01_answer.rs must be absent (no directory
# entry, lexists) until I01B3 replaces the absence with its pin. Each guarded module is declared only in file form, once,
# in its crate's lib.rs (I1D-3), and no entry of a guarded file's directory casefolds to a guarded name but that name
# (I1D-10).
EFFECT_GATE_CRATE = "crates/effect-gate"
I01B_GUARDED_PINS = {
    "crates/effect-gate/src/linux_os.rs": "88e70bf599f0b3cb733aa018c0ea08da6b973ccd21aea8b1b15e3d1cfa7475a6",
    "crates/effect-gate/src/linux_net.rs": "d452aa507f1325028ce4dd62c77d5dfa808a5e18a77dc1cb1e5036db209e6fbd",
    # HE-004-I01B2 (DESIGN-I01B2 rev 3 section 1): these three re-pinned at I01B2's bytes (configuration v3, its
    # load-time checks and the private binding with its accessor; the closed I01Binding and from_config; the service
    # holding the binding and closing a passing request as NotAnswered).
    "crates/observer/src/config.rs": "173b7adf575c946e55fb3384467bcb37377f0505a41d36d21308c04c458624da",
    "crates/observer/src/i01_request.rs": "e87c1e44208007b2ae07be175e958ed72d04c9e722d65590ba242a5fa56b46c3",
    "crates/observer/src/i01_service.rs": "56a07477300a385d2ca208475a575c9a6486951353524c4c65502026db21fbaa",
    "crates/observer/src/client.rs": "2987e41d212a699b57e57872793c1dfd3151e09969e0c091af9ab2a68650f741",
}
I01B_ABSENT = ("crates/observer/src/i01_answer.rs",)
I01B_FILE_FORM = {"crates/observer/src/lib.rs": ("config", "i01_request", "i01_service", "client", "linux_listen",
                                                 "linux_net"),
                  "crates/effect-gate/src/lib.rs": ("linux_os", "linux_net")}
# HE-004-I01B1 B3-1 (G-I01B-6 (e); DESIGN-I01B1 rev 2 sections 2 and 6, I1D-1 and I1D-2): each crate's socket modules, the
# scope roots a use path's head may hold, and the binary's library root (main.rs only).
SOCKET_CRATE_MODULES = {EFFECT_GATE_CRATE: ("linux_os", "linux_net"), OBSERVER_CRATE: ("linux_net", "linux_listen")}
SCOPE_ROOTS = ("crate", "self", "super")
# HE-003A2 DESIGN section 3 (Q-A2-2 (a), D1-9, D2-2): Dir::read_link is pub (gate-sys's host tests call it), so among
# the linked crates' non-test sources, read without comments and with literals kept, the word read_link appears exactly
# twice: its definition `fn read_link(` in openat.rs and the one call `read_link("exe",` in channel.rs (ProcDir::exe).
# A second call, a call in another file or with another name, and a reference without a call (a fn item) refuse.
READ_LINK = re.compile(r"\bread_link\b")
READ_LINK_DEFINITION = re.compile(r"\bfn\s+read_link\s*\(")
READ_LINK_CALL = re.compile(r'\bread_link\s*\(\s*"exe"\s*,')
# PR review round 1, R1-3 (Q-A2-R1 (a)): the word readlinkat occurs exactly twice in openat.rs (read without comments,
# literals kept and emptied alike), as its declaration inside the extern block and as the one call inside read_link's
# body, and nowhere in another linked source, so no second wrapper under another name can read a link.
READLINKAT = re.compile(r"\breadlinkat\b")
READLINKAT_DECLARATION = re.compile(r"\bfn\s+readlinkat\s*\(")
# HE-003A3 (DESIGN sections 4-6; D2-1, D2-5, D3-1, D3-2, D3-4): the observation's rules over the linked crates'
# non-test sources. Callers: each distinctive opener or constructor word occurs only as its definition and its exact
# calls (read without comments, literals kept). Implementations: every impl header naming WorkerObserver or KernelReads
# is one of OBSERVATION_IMPLS, each exactly once in its file (no other, blanket, generic or primitive impl). The fake
# kernel: its module name and its two names occur only in fake_kernel.rs, lib.rs's one `pub mod fake_kernel;` and
# strict `#[cfg(test)] mod tests { .. }` blocks; fake_kernel.rs defines no other type, alias, re-export or wrapper.
# Renames and aliases of OBSERVATION_TYPES refuse anywhere. LinuxKernelReads's only fields are two KernelRoots, and
# linux_os.rs holds no static or thread-local state.
OBSERVATION_RS = "crates/effect-gate/src/observation.rs"
FAKE_KERNEL = "crates/effect-gate/src/fake_kernel.rs"
EFFECT_GATE_LIB = "crates/effect-gate/src/lib.rs"
PROBE_WORKER_LEAF = "planeon.slice/planeon-capacity-broker.service/probe-worker/cgroup.procs"
OBSERVATION_CALLERS = (
    # (word, the definition's file, the definition, the calling file, the exact call forms in it, exactly or at least)
    ("open_kernel_root", OPENAT, r"\bfn\s+open_kernel_root\s*\(", LINUX_OS, (CGROUP_ROOT_CALL, PROC_ROOT_CALL), "exactly"),
    ("open_after_seal", LINUX_OS, r"\bfn\s+open_after_seal\s*\(", GATE_MAIN,
     (re.compile(r"\bKernelRoots\s*::\s*open_after_seal\s*\(\s*sealed\s*\)"),), "exactly"),
    ("from_constant", OPENAT, r"\bfn\s+from_constant\s*\(", LINUX_OS,
     (re.compile(r'\bFixedPath\s*::\s*from_constant\s*\(\s*"%s"\s*\)' % re.escape(PROBE_WORKER_LEAF)),), "exactly"),
    ("pid_stat", OPENAT, r"\bfn\s+pid_stat\s*\(", LINUX_OS, (re.compile(r"\bFixedPath\s*::\s*pid_stat\s*\("),), "exactly"),
    ("open_fixed", OPENAT, r"\bfn\s+open_fixed\s*\(", LINUX_OS, (re.compile(r"\.\s*open_fixed\s*\("),), "at least"),
)
OBSERVATION_IMPLS = {
    "impl WorkerObserver for Unobserved": OBSERVATION_RS,
    "impl < K : KernelReads > WorkerObserver for KernelObserver < K >": OBSERVATION_RS,
    "impl < K : KernelReads > KernelObserver < K >": OBSERVATION_RS,
    "impl KernelReads for LinuxKernelReads": LINUX_OS,
    "impl KernelReads for FakeKernel": FAKE_KERNEL,
}
OBSERVATION_TRAITS = re.compile(r"\b(?:WorkerObserver|KernelReads)\b")
IMPL_WORD = re.compile(r"\bimpl\b")
HEADER_TOKEN = re.compile(r"[A-Za-z_]\w*|'\w+|\S")
FAKE_NAMES = re.compile(r"\b(?:fake_kernel|FakeKernel|convert_v3_config)\b")
FAKE_MOD = re.compile(r"\bpub\s+mod\s+fake_kernel\s*;")
CFG_TEST_LINE = re.compile(r"(?m)^[ \t]*#[ \t]*\[[ \t]*cfg[ \t]*\([ \t]*test[ \t]*\)[ \t]*\][ \t]*\n[ \t]*mod[ \t]+tests[ \t]*\{")
OBSERVATION_TYPES = ("WorkerObserver", "KernelReads", "KernelObserver", "FakeKernel", "KernelRoot", "KernelRoots",
                     "FixedPath", "LinuxKernelReads")
OBSERVATION_ALIASES = (re.compile(r"\b(?:%s)\s+as\b" % "|".join(OBSERVATION_TYPES)),
                       re.compile(r"\bas\s+(?:%s)\b" % "|".join(OBSERVATION_TYPES)),
                       re.compile(r"\btype\s+\w+\s*(?:<[^>]*>)?\s*=\s*[\w:<> ]*\b(?:%s)\b" % "|".join(OBSERVATION_TYPES)),
                       re.compile(r"\btype\s+(?:%s)\b" % "|".join(OBSERVATION_TYPES)))
PIDFD_TYPE = {LINUX_OS: (re.compile(r"\bimpl\s+KernelReads\s+for\s+LinuxKernelReads\s*\{"),
                         re.compile(r"\btype\s+Pidfd\s*=\s*PidFd\s*;")),
              FAKE_KERNEL: (re.compile(r"\bimpl\s+KernelReads\s+for\s+FakeKernel\s*\{"),
                            re.compile(r"\btype\s+Pidfd\s*=[^;]*;"))}
LINUX_OS_STATE = ((re.compile(r"(?<!')\bstatic\b"), "static"), (re.compile(r"\bthread_local\b"), "thread_local!"),
                  (re.compile(r"\b(?:OnceLock|OnceCell|LazyLock|LazyCell)\b"), "a lazy or once cell"))
ROOT_FIELD = re.compile(r"\s*[a-z_]\w*\s*:\s*KernelRoot\s*")
# DESIGN section 5 (D1-3, D2-2): serve's two statements, each exactly once and in this order: LinuxOs::with_net, the
# roots, FileStores::open_bound, the PolicyGate's observer, Substrate::new (which takes that `gate`).
ROOTS_STATEMENT = re.compile(r"\blet\s+Ok\s*\(\s*kernel\s*\)\s*=\s*KernelRoots\s*::\s*open_after_seal\s*\(\s*sealed\s*\)\s*else"
                             r"\s*\{\s*return\s+status\s*::\s*OBSERVER_ROOTS\s*;?\s*\}\s*;")
OBSERVER_STATEMENT = re.compile(r"\blet\s+gate\s*=\s*gate\s*\.\s*with_observer\s*\(\s*Box\s*::\s*new\s*\(\s*KernelObserver\s*::"
                                r"\s*new\s*\(\s*LinuxKernelReads\s*::\s*new\s*\(\s*kernel\s*\)\s*\)\s*\)\s*\)\s*;")
WIRING_ORDER = (re.compile(r"\bLinuxOs\s*::\s*with_net\s*\("), ROOTS_STATEMENT, re.compile(r"\bFileStores\s*::\s*open_bound\s*\("),
                OBSERVER_STATEMENT, re.compile(r"\bSubstrate\s*::\s*new\s*\(\s*gate\s*,"))
# HE-003A3 PR review round 1, R1-2 and R1-3 (carried to HE-004B1): serve's other binding forms of gate, and the
# observation module's own shape.
LET_WORD = re.compile(r"\blet\b")
GATE_ASSIGNMENT = re.compile(r"\bgate\s*=(?![=>])")
AFTER_ATTACH_USES = (re.compile(r"\bgate\s*\.\s*apiserver_address\s*\(\s*\)"),
                     re.compile(r"\bSubstrate\s*::\s*new\s*\(\s*(gate)\s*,"))
MODULE_ITEM = re.compile(r"\bmod\s+[A-Za-z_]\w*")
OBSERVATION_HOME_TYPES = ("Unobserved", "KernelObserver")
# HE-003A DESIGN section 8: the types whose Debug would format a std File (whose own Debug reads the descriptor's link
# with a call the EFFECT_GATE program kills) or print a descriptor. derive(Debug), also under cfg_attr, is refused on a
# struct or enum of the linked crates whose field types mention one of them anywhere (Option<File> included); manual
# impls and direct formatting are code review's.
DEBUG_HAZARDS = ("File", "Dir", "FileStores", "Conn", "Listener", "Poller", "PidFd", "ProcDir", "TcpListener", "TcpConn",
                 "NetTable", "LinuxConnector",
                 # HE-003A3 (DESIGN section 5, D2-7): the observation's O_PATH root handle.
                 "KernelRoot",
                 # HE-004C DESIGN-C section 15 (G10): the observer's wire holds the poller and its TCP connections.
                 "LinuxWire",
                 # HE-004D1 DESIGN-D1 section 19 (G-D1-13): observer-sys's handles (its ProcDir shares gate-sys's name,
                 # already listed) and the observer's capture view over them.
                 "Roots", "CgroupDir", "Opened", "ProgFd", "LinuxCapture",
                 # HE-004-I01a DESIGN-I01A section 12 (G-I01-6, R4-6): the I01 listener and its held peer.
                 "I01Socket")
# HE-003B DESIGN section 2.6 (D1-4): the types that hold the server key or rustls's key and configuration objects;
# derive(Debug) is refused on an item named one of them and on an item whose field types mention one.
SECRET_TYPES = ("TlsServerInputs", "PrivateKeyDer", "PrivatePkcs8KeyDer", "CertifiedKey", "ServerConfig",
                "ServerConnection", "ClientConfig", "ClientConnection", "TlsClientIdentity",
                # HE-003D DESIGN section 3.4 (D1-7): the credential read's helper and key holder.
                "CredentialFile", "KeyBytes",
                # HE-004C DESIGN-C section 15 (G10): the observer's identity, key holder and credential helper.
                "ObserverIdentity", "ObserverKeyBytes", "ObserverCredential")
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
POST_SEAL_CRATES = ("crates/effect-gate", "crates/gate-sys", "crates/i05-protocol", "crates/gate-tls", "crates/gate")
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
# HE-004A DESIGN-A section 6 (D1-3, D2-2): crates/observer's sources (only them: gate-sys's own Dir::file and Dir::sync
# definitions stay, and the observer reaches gate-sys only through this rule and the socket-module rule) name none of
# POST_SEAL_FORBIDDEN and none of these names, which reach a system call the OBSERVER filter kills and the EFFECT_GATE
# filter allows: gate-sys's O_RDWR opener (file, FileMode) and Dir::sync (fsync), std's sync_all and sync_data (fsync,
# fdatasync), the lock family (flock; lock also refuses Mutex::lock in the single-threaded observer), and positioned
# writes (pwrite64). PR review round 1, R1-1: they are matched as words in the code with comments and literal contents
# removed and the whitespace around `::` removed, so a method call, a path call (`Dir::sync(d)`, `File::lock(f)`), a
# function item (`let s = Dir::sync;`), a turbofish, a type path (`FileMode::Existing`) and an import are each refused;
# only sync followed by `::` (other than a turbofish) is a module path segment and passes (`std::sync::atomic`). R1-4:
# Drop joins them, so no destructor defined in crates/observer runs under the filter (gate-sys's own Drop impls are
# role-neutral: SockCreate's, in the channel module, which the socket-module rule keeps from the observer).
OBSERVER_POST_SEAL_FORBIDDEN = tuple(
    (r"\b%s\b%s" % (word, r"(?!::(?!<))" if word == "sync" else ""), "%s (%s)" % (word, calls)) for word, calls in (
    ("file", "gate-sys's O_RDWR opener"), ("FileMode", "gate-sys's O_RDWR or O_CREAT opener"),
    ("sync", "gate-sys's Dir::sync: fsync"), ("sync_all", "fsync"), ("sync_data", "fdatasync"),
    ("lock_shared", "flock"), ("try_lock", "flock"), ("try_lock_shared", "flock"), ("unlock", "flock"),
    ("lock", "flock; also Mutex::lock"), ("write_at", "pwrite64"), ("write_all_at", "pwrite64"),
    ("Drop", "a destructor run under the filter, R1-4")))
# HE-004B1 DESIGN-B sections 3 and 6 (owner decision Q-HE4B-6 (a)): i05-protocol, linked into planeon-observer since
# HE-004B1, joins the observer post-seal rule (gate-sys stays outside it). Its one observer-list word, the memory-only
# `impl Drop for Value` in json.rs (a parsed value freed iteratively: munmap and brk, both in the OBSERVER row; a recorded
# residual), is removed once from that file's code before the word scan; a second one, another type's Drop, or the impl
# in another file still refuses.
# HE-004D1 DESIGN-D1 section 19 (G-D1-12): observer-sys's code runs after the seal too.
OBSERVER_POST_SEAL_CRATES = (OBSERVER_CRATE, "crates/i05-protocol", OBSERVER_SYS)
I05_JSON = "crates/i05-protocol/src/json.rs"
OBSERVER_DROP_EXCEPTIONS = {I05_JSON: re.compile(r"\bimpl\s+Drop\s+for\s+Value\b")}
# HE-004B1 DESIGN-B section 6 (D1-7, D2-5, D3-2): the observer's five logic modules. Read with comments removed, literal
# contents emptied and the whitespace around `::` removed, every path rooted at a crate (a leading `::`, or a first
# segment in CRATE_PATH_ROOTS), in a use declaration or in the code, starts with one of OBSERVER_LOGIC_PATHS: the logic
# modules and the embedded contracts, i05-protocol's json, sha256 and contracts, std's ordered collections and its pure
# modules. Refused there besides: super:: paths and self:: paths to anything but the logic modules (neither is in the
# whitelist), globs and renaming imports (`as` inside a use declaration only: casts are not imports, D3-2), the words
# HashMap, HashSet and RandomState (std's default hasher asks getrandom), include_bytes!/include_str! (the embedded
# contracts live in contracts.rs), and, outside strict #[cfg(test)] mod tests blocks, the panicking macros and calls
# (the i05-protocol precedent: every input gets an error). The claim is "no system call beyond memory allocation" for
# these modules' own code; indexing and arithmetic overflow are code review's (each index guarded, checked arithmetic).
OBSERVER_LOGIC_NAMES = ("inputs", "rbac", "snapshot", "operational", "admission")
OBSERVER_LOGIC = tuple("crates/observer/src/%s.rs" % name for name in OBSERVER_LOGIC_NAMES)
OBSERVER_CONTRACTS = "crates/observer/src/contracts.rs"
OBSERVER_SEAL_RS = "crates/observer/src/seal.rs"
# HE-004D1 (G-D1-10): observer_sys is a crate root too, so a logic module naming it names a rooted path and refuses.
CRATE_PATH_ROOTS = ("std", "core", "alloc", "crate", "self", "super", "i05_protocol", "gate_sys", "planeon_observer",
                    "observer_sys")
OBSERVER_LOGIC_PATHS = (tuple(("crate", name) for name in OBSERVER_LOGIC_NAMES + ("contracts",))
                        + tuple(("self", name) for name in OBSERVER_LOGIC_NAMES)
                        + (("i05_protocol", "json"), ("i05_protocol", "sha256"), ("i05_protocol", "contracts"))
                        + tuple(("std", "collections", name) for name in ("BTreeMap", "BTreeSet", "VecDeque"))
                        + tuple(("std", name) for name in ("cmp", "fmt", "string", "vec", "iter", "ops", "str", "borrow",
                                                           "convert", "option", "result")))
# HE-004D1 DESIGN-D1 section 19 (G-D1-10): the capture checks' three logic modules take B1's rule with the whitelist
# extended by i05-protocol's schema module and the three modules themselves (B1's five keep theirs).
D1_LOGIC_NAMES = ("capture_schema", "capture_check", "kernel_text")
D1_LOGIC = tuple("crates/observer/src/%s.rs" % name for name in D1_LOGIC_NAMES)
D1_LOGIC_PATHS = (OBSERVER_LOGIC_PATHS + (("i05_protocol", "schema"),)
                  + tuple(("crate", name) for name in D1_LOGIC_NAMES) + tuple(("self", name) for name in D1_LOGIC_NAMES))
# HE-004D2 DESIGN-D2 section 12 (G-D2-4): the four D2 logic modules take B1's rule with D1's whitelist plus their own
# paths; each joins LOGIC_MODULES as its unit adds it (D2_LOGIC_BUILT). D1's rule already refuses, among others,
# crate::capture, crate::observe, crate::enrolled, gate_sys, observer_sys, i05_protocol::regex and std::net there.
D2_LOGIC_NAMES = ("record_check", "qualification", "i06_evidence", "composition")
D2_LOGIC_BUILT = ("record_check", "i06_evidence", "qualification", "composition")
D2_LOGIC = tuple("crates/observer/src/%s.rs" % name for name in D2_LOGIC_BUILT)
D2_LOGIC_PATHS = (D1_LOGIC_PATHS + tuple(("crate", name) for name in D2_LOGIC_NAMES)
                  + tuple(("self", name) for name in D2_LOGIC_NAMES))
# HE-004-I01a DESIGN-I01A section 12: the I01 request checks (i01_request, the pure part of the I01 service, unit U4)
# and the role pin (observer_rbac, unit U6) take B1's logic rule with B1's whitelist plus their own paths, each as its
# unit adds it (I01_LOGIC_BUILT); they reach neither the I01 service, the wire nor D2's modules.
# HE-004-I01B1 (DESIGN-I01B rev 3 section 2; G-I01B-7 (d)): the digest port's three logic modules join them, the
# whitelist gaining their crate:: and self:: paths; none reaches the capture engine, the epoch, the configuration, the
# enrolled record's loader, the quota pair or std::time, and none is reachable from serve (G-I01B-1).
I01B1_MODULES = ("i01_digest", "i01_admission_render", "i01_gate")
I01_LOGIC_NAMES = ("i01_request", "observer_rbac") + I01B1_MODULES
I01_LOGIC_BUILT = ("i01_request", "observer_rbac") + I01B1_MODULES
I01_LOGIC = tuple("crates/observer/src/%s.rs" % name for name in I01_LOGIC_BUILT)
I01_LOGIC_PATHS = (OBSERVER_LOGIC_PATHS + tuple(("crate", name) for name in I01_LOGIC_NAMES)
                   + tuple(("self", name) for name in I01_LOGIC_NAMES))
LOGIC_MODULES = (tuple((rel, OBSERVER_LOGIC_PATHS) for rel in OBSERVER_LOGIC) + tuple((rel, D1_LOGIC_PATHS) for rel in D1_LOGIC)
                 + tuple((rel, D2_LOGIC_PATHS) for rel in D2_LOGIC) + tuple((rel, I01_LOGIC_PATHS) for rel in I01_LOGIC))
# G-D2-5: the items whose names make the D2 type set, and a use declaration's `pub` form.
D2_TYPE_ITEM = re.compile(r"\b(?:struct|enum|union|trait|type)\s+([A-Za-z_]\w*)")
PUB_USE_DECLARATION = re.compile(r"\bpub\s*(?:\([^)]*\)\s*)?use\b([^;]*);")
CODE_PATH = re.compile(r"(?<![\w:])(::)?([A-Za-z_]\w*)((?:::[A-Za-z_]\w*)+)")
OBSERVER_LOGIC_WORDS = ((re.compile(r"\b(?:HashMap|HashSet|RandomState)\b"), "HashMap, HashSet or RandomState (getrandom)"),
                        (re.compile(r"\binclude_(?:bytes|str)\s*!"), "include_bytes! or include_str! (only contracts.rs embeds)"))
PANICS = tuple((re.compile(pattern), name) for pattern, name in (
    (r"\bunwrap\s*\(", "unwrap("), (r"\bexpect\s*\(", "expect("), (r"\bpanic\s*!", "panic!"),
    (r"\bunreachable\s*!", "unreachable!"), (r"\btodo\s*!", "todo!"), (r"\bunimplemented\s*!", "unimplemented!"),
    (r"\bassert\s*!", "assert!"), (r"\bassert_eq\s*!", "assert_eq!"), (r"\bassert_ne\s*!", "assert_ne!"),
    (r"\bdebug_assert(?:_eq|_ne)?\s*!", "debug_assert!")))
# The contracts module (DESIGN-B section 6, D2-5): in crates/observer's sources every include_bytes!/include_str! is one
# plain string literal (no escape, no raw string, no concat!) naming, relative to its file, a registered CONTRACTS file;
# only contracts.rs and seal.rs hold one, and seal.rs only its two OBSERVER programs.
OBSERVER_INCLUDE = re.compile(r"\binclude_(?:bytes|str)\s*!")
# HE-004C DESIGN-C section 15 (G6): exactly one more include, the observer's signer key in its signed_config.rs.
OBSERVER_SIGNED_CONFIG = "crates/observer/src/signed_config.rs"
OBSERVER_KEY_INCLUDE = "../config-signer.pub"
# HE-004C DESIGN-C section 15 (G7; HE-004B1 PR review R1-3): contracts.rs, read without comments and with literals kept,
# holds only these two item forms (doc comments are comments): the bytes of a registered contract file, and a registered
# CONTRACTS pin as 64 lowercase hex. A fn, a use (pub or not), a static, another type, an unpinned value, an attribute or a
# mod refuses.
CONTRACT_BYTES_ITEM = re.compile(r'\bpub\s+const\s+[A-Z][A-Z0-9_]*\s*:\s*&\s*\[\s*u8\s*\]\s*=\s*include_bytes\s*!\s*\(\s*'
                                 r'"([^"\\]*)"\s*\)\s*;')
CONTRACT_PIN_ITEM = re.compile(r'\bpub\s+const\s+[A-Z][A-Z0-9_]*\s*:\s*&\s*str\s*=\s*"([^"\\]*)"\s*;')
# HE-004C DESIGN-C section 15 (G8, D1-14 (c)): the no-panic tripwire also covers every HE-004C module and the changed
# main.rs and status.rs (seal.rs and the logic modules keep their own rules).
OBSERVER_C_NAMES = ("signed_config", "config", "credentials", "tls", "http", "exposition", "watch", "requests", "quota",
                    "utc", "client", "linux_net", "observe")
OBSERVER_C_MODULES = tuple("crates/observer/src/%s.rs" % name for name in OBSERVER_C_NAMES)
OBSERVER_STATUS = "crates/observer/src/status.rs"
# HE-004D1 DESIGN-D1 section 19 (G-D1-11): the capture engine, the enrolled record and the Linux capture view join it;
# observer-sys's three sources have their own list, where only an item-level compile-time assert, `const _: () =
# assert!(..);` at brace depth 0 (evaluated by the compiler, which fails the build instead of panicking), is removed
# before the scan, and only when its argument holds no `{` or `}` (PR review round 1, R1-1: a block argument can hold an
# item, an impl's runtime methods among them, so it stays and is scanned); an assert! anywhere else still refuses.
# HE-004-I01a DESIGN-I01A section 12: the I01 listener joins it (unit U3); the I01 service, its request checks and
# the role pin as their units add them (I01_NO_PANIC_BUILT). HE-004-I01B1 (G-I01B-7 (d)): the digest port's three.
I01_NO_PANIC_BUILT = ("linux_listen", "i01_service", "i01_request", "observer_rbac") + I01B1_MODULES
OBSERVER_NO_PANIC = OBSERVER_C_MODULES + (OBSERVER_MAIN, OBSERVER_STATUS) + tuple(
    "crates/observer/src/%s.rs" % name for name in ("enrolled", "capture", "linux_capture") + I01_NO_PANIC_BUILT)
OBSERVER_SYS_NO_PANIC = (OBSERVER_SYS_LIB, "crates/observer-sys/src/dirent.rs", OBSERVER_SYS_KERNEL)
CONST_ASSERT = re.compile(r"\bconst\s+_\s*:\s*\(\s*\)\s*=\s*assert\s*!\s*\(")
OBSERVER_INCLUDE_FORM = re.compile(r'\binclude_(?:bytes|str)\s*!\s*\(\s*"([^"\\]*)"\s*\)')
CRATE_ROOTS = {"crates/i05-protocol/src/lib.rs": "#![forbid(unsafe_code)]",
               "crates/effect-gate/src/lib.rs": "#![forbid(unsafe_code)]",
               "crates/gate-sys/src/lib.rs": "#![deny(unsafe_code)]",
               "crates/gate-tls/src/lib.rs": "#![forbid(unsafe_code)]",
               GATE_MAIN: "#![forbid(unsafe_code)]",
               # HE-004A DESIGN-A section 3 (D2-4): the observer's library and binary roots.
               OBSERVER_LIB: "#![forbid(unsafe_code)]",
               OBSERVER_MAIN: "#![forbid(unsafe_code)]",
               # HE-004D1 DESIGN-D1 section 4 (G-D1-1): observer-sys's root denies unsafe_code; kernel.rs allows it.
               OBSERVER_SYS_LIB: "#![deny(unsafe_code)]"}
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
    (r"send_ticket_request", "send_ticket_request"),
    # HE-003D DESIGN section 5 (HE-003C PR R1-1, D1-2): a second way to set the client's trust anchors.
    (r"with_root_certificates", "with_root_certificates")))
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
# tls_client.rs (mirroring TLS_RESOLVER). HE-003D DESIGN section 5 (HE-003C PR R1-1, D1-2): any mention counts (read
# without comments), over gate-tls's and the binary's sources together.
TLS_CLIENT_AUTH = ((r"\bwith_client_auth_cert\b", "with_client_auth_cert"),
                   (r"\bwith_webpki_verifier\b", "with_webpki_verifier"))
# HE-003C DESIGN section 5 (D2-4 of HE-003B): among gate-tls's non-test sources only exchange.rs constructs an
# UpstreamResponse (stage_response and write_response build it from the bytes they digest). Effect-gate's constructions
# are test-only, and its non-test mentions are the definition and patterns, so the rule is scoped to gate-tls. HE-003D
# DESIGN section 5 (R1-1, D1-2): outside exchange.rs no gate-tls source and no source of the binary names it at all
# (read without comments: a use, a rename, an alias, a where-clause, a clone are all mentions), and neither defines a
# macro (macro_rules), which could assemble the name.
UPSTREAM_RESPONSE = re.compile(r"\bUpstreamResponse\b")
UPSTREAM_RESPONSE_HOME = "crates/gate-tls/src/exchange.rs"
MACRO_RULES = re.compile(r"\bmacro_rules\b")
# The crates check_tls reads: gate-tls (which must have sources) and the binary (HE-003D DESIGN section 5, C7).
TLS_CRATES = (GATE_TLS, "crates/gate")
# HE-004C DESIGN-C section 15 (G3; D1-14 (b)): check_tls's group O, crates/observer, a client only. Its non-test sources
# hold none of TLS_FORBIDDEN nor of this server-side list in their raw text (comments included); read with comments
# removed and literal contents emptied they set resumption, enable_early_data and enable_sni exactly once each, as the
# closed setting, name with_client_auth_cert and with_webpki_verifier exactly once each, in crates/observer/src/tls.rs,
# and define no macro_rules macro. The counts are per group, so planeon-gate's sources and counts stay as they are.
OBSERVER_TLS = "crates/observer/src/tls.rs"
OBSERVER_TLS_FORBIDDEN = tuple((re.compile(name), name) for name in (
    "ServerConfig", "ServerConnection", "WebPkiClientVerifier", "with_cert_resolver", "with_single_cert",
    "max_early_data_size", "send_tls13_tickets", "send_half_rtt_data", "session_storage", "NoServerSessionStorage",
    "SingleCertAndKey", "ResolvesServerCert"))
OBSERVER_TLS_SETTINGS = tuple(setting for setting in TLS_SETTINGS if setting[0] in ("resumption", "enable_early_data",
                                                                                     "enable_sni"))
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
# HE-004D1 (G-D1-2): MetadataExt also in observer-sys (kernel.rs reads its own descriptors' device, inode and mode).
FS_ITEMS = (("std::os::unix::fs::MetadataExt", lambda rel: rel.startswith(("crates/gate-sys/", "crates/observer-sys/"))),
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
                 host_paths: tuple[bytes, ...] = HOST_PATHS, exempt: bytes = b"") -> int:
    """The shape, the .comment markers and no build-host path. HE-004D1 (G-D1-16; owner decision Q-HE4D1-D3 (a)): with
    `exempt` (planeon-observer's embedded native-profile v4 schema), those bytes must occur exactly once, and the host-path
    scan reads a copy with that one span blanked (zero bytes of the same length); every needle outside it still fails.
    The span's offset, or -1 without `exempt`."""
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
    offset, scanned = -1, raw
    if exempt:
        count = raw.count(exempt)
        require(count == 1, "the exempt span (the embedded schema) occurs %d times, not exactly once (G-D1-16)" % count)
        offset = raw.find(exempt)
        scanned = raw[:offset] + bytes(len(exempt)) + raw[offset + len(exempt):]
    for needle in host_paths:
        require(needle not in scanned, "a build-host path is in the binary")
    return offset


# HE-004D1 DESIGN-D1 section 19 (G-D1-16): the one binary with an exempt span, and the contract file whose bytes it is.
EXEMPT_SPANS = {"planeon-observer": "contracts/native-profile-v4/qualification.schema.json"}


def binary_exempt(binary: str, base: Path) -> bytes:
    """The bytes check_binary exempts for `binary` (G-D1-16): planeon-observer's embedded schema, read from `base` and
    checked against its CONTRACTS pin first; nothing for every other binary."""
    rel = EXEMPT_SPANS.get(binary)
    if rel is None:
        return b""
    data = (base / rel).read_bytes()
    require(sha256(data) == CONTRACTS[rel], "%s differs from its registered bytes (G-D1-16)" % rel)
    return data


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


def patch_table() -> dict:
    """The one [patch] table the workspace manifest may hold (HE-003D DESIGN section 2)."""
    return {"crates-io": {name: {"path": "vendor/%s-%s" % (name, version)} for name, version in PATCH_CRATES}}


def check_workspace(base: Path, vendor: list[dict] | None = None) -> dict:
    """The workspace members, each with its direct workspace (path) dependencies. HE-003B DESIGN section 2.6: besides
    path dependencies, only REGISTRY_LINES (gate-tls's exact registry lines); no [replace]; in Cargo.lock the packages
    with a source are exactly the vendor table's rows (`vendor`) that are not patched, each from crates.io with the row's
    checksum and dependency list. HE-003D DESIGN sections 2 and 5: when the vendor table has LINKED rows, they must be
    exactly PATCH_CRATES, the manifest's [patch] must be exactly patch_table(), and the packages without a source are
    exactly the workspace crates plus those rows, each patched package with the row's version and dependency list and
    no checksum; without LINKED rows (the self-tests' tables) no [patch] is allowed."""
    workspace = tomllib.loads((base / "Cargo.toml").read_text(encoding="utf-8"))
    patched = {(row["name"], row["version"]) for row in (vendor or []) if row.get("role") == "LINKED"}
    require("replace" not in workspace, "the workspace manifest has a [patch] or [replace]")
    if patched:
        require(patched == set(PATCH_CRATES), "the vendor table's LINKED crates are not the [patch] table's")
        require(workspace.get("patch") == patch_table(),
                "the workspace manifest's [patch] or [replace] is not exactly the vendored path table")
    else:
        require("patch" not in workspace, "the workspace manifest has a [patch] or [replace]")
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
    is_patched = lambda package: (package["name"], package.get("version")) in patched
    require(sorted(package["name"] for package in local if not is_patched(package)) == sorted(names)
            and all("checksum" not in package for package in local),
            "Cargo.lock does not list exactly the workspace crates")
    rows = {(row["name"], row["version"]): row for row in (vendor or [])}
    require(sorted((package["name"], package["version"]) for package in local if is_patched(package)) == sorted(patched),
            "Cargo.lock does not list exactly the patched vendored crates as path packages")
    for package in local:
        if is_patched(package):
            require(sorted(package.get("dependencies", [])) == rows[(package["name"], package["version"])]["dependencies"],
                    "Cargo.lock's dependencies of the patched %s are not the vendor table's" % package["name"])
    registry = [package for package in packages if "source" in package]
    require(len(registry) == len(rows) - len(patched)
            and all(package["source"] == REGISTRY and (package["name"], package["version"]) in rows
                    and not is_patched(package) for package in registry),
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


def rust_code(text: str, comments: bool = False, literals: bool = False) -> str:
    """A source as the lexical checks read it (HE-002S PR review round 1, R1-1): line and nested block comments become
    one space (kept as they are with `comments`), string, byte-string and C-string literals keep only their quotes and
    prefix (`""`, `b""`), raw-string literals become `""`, and character and byte literals become `''` (`b''`);
    lifetimes and labels stay; with `literals` (HE-003D, the seal-order grammar's cfg attributes) every literal is
    kept as written. Anything it cannot lex
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
            out.append(text[index:end + 1 + len(raw.group(1))] if literals else '""')
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
            out.append(text[index:cursor + 1] if literals else '""')
            index = cursor + 1
        elif char == "'":
            literal = CHAR_LITERAL.match(text, index)
            if literal:
                out.append(literal.group(0) if literals else "''")
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


def resolved_uses(uses: list[tuple[tuple[str, ...], str | None]]) -> list[tuple[tuple[str, ...], str | None]]:
    """HE-004-I01A2 (HE-004-I01a PR review round 1, R1-3; Q-U7-2 (a)): a source's use paths (source_uses) with the
    source's own aliases followed. A name one of its use paths binds under gate_sys (a rename of gate_sys itself, as
    `use gate_sys as gs;` or `use gate_sys::{self as gs};`, or the last segment or rename of a path below it, as
    `use gs::channel as c;` once gs is known) stands for that gate_sys path: a path starting with it (after a leading
    `self`) is read as the gate_sys path and its remaining segments, again until nothing changes, so a chain of aliases
    resolves. Each path keeps its rename; globs bind nothing."""
    paths = [(path[1:] if path[:1] == ("self",) and len(path) > 1 else path, rename) for path, rename in uses]
    for _ in range(len(paths) + 1):
        bound = {}
        for path, rename in paths:
            if path[:1] != ("gate_sys",) or path[-1] == "*":
                continue
            target = path[:-1] if path[-1] == "self" else path
            name = rename or target[-1]
            if name != "gate_sys":
                bound[name] = target
        resolved = [(bound[path[0]] + path[1:], rename) if path and path[0] in bound else (path, rename)
                    for path, rename in paths]
        if resolved == paths:
            break
        paths = resolved
    return paths


def gate_sys_aliases(uses: list[tuple[tuple[str, ...], str | None]]) -> set[str]:
    """HE-004-I01A2 (R1-3): the names resolved use paths (resolved_uses) bind to gate_sys itself."""
    return {rename for path, rename in uses if rename is not None and path in (("gate_sys",), ("gate_sys", "self"))}


def std_names(uses: list[tuple[tuple[str, ...], str | None]]) -> set[str]:
    """`std` and every name the given use paths bind from a std path: the rename, the last segment, or the module
    before a `self` (renames and globs of std are refused by the linked-source checks themselves)."""
    names = {"std"}
    for path, rename in uses:
        if path[0] == "std" and path[-1] != "*":
            names.add(rename or (path[-2] if path[-1] == "self" and len(path) > 1 else path[-1]))
    return names


def check_linked_sources(base: Path) -> int:
    """A lexical tripwire over the non-test sources of the crates EFFECT_GATE will link and of planeon-observer's crate
    (SCANNED_CRATES, HE-004A), with the whitespace around `::` removed first: none names a refused std path (LINKED_FORBIDDEN; the fd items outside FD_FILES; std fs items
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
               for crate in SCANNED_CRATES for path in sorted((base / crate / "src").rglob("*.rs"))]
    uses = {rel: source_uses(rel, raw) for rel, raw in sources}
    from_std = std_names([path for paths in uses.values() for path in paths])
    count = 0
    for rel, raw in sources:
        text = PATH_SPACE.sub("::", raw)
        scanned = text
        for _, expression in LINKED_EXCEPTIONS.get(rel, ()):   # HE-003D (O4): the binary's one exit import
            scanned = expression.sub("", scanned, count=1)
        for pattern in LINKED_FORBIDDEN:
            require(not re.search(pattern, scanned), "%s names %s (linked-source tripwire)" % (rel, pattern.replace("\\b", "")))
        require(rel in FD_FILES or not FD_ITEMS.search(text),
                "%s names a std::os::fd item outside %s" % (rel, " and ".join(FD_FILES)))
        # HE-003A3 (R96): the cgroup2 root's one exact open in linux_os.rs holds the path segment `fs`, excepted once
        # there, as in the start-up lint; any other `fs` word still refuses.
        rest = CGROUP_ROOT_CALL.sub(" ", text, count=1) if rel == LINUX_OS else text
        # HE-004D1 (G-D1-5, R3-1): the file's own root constants, each removed once.
        for _, expression in FS_SCAN_EXCEPTIONS.get(rel, ()):
            rest = expression.sub(" ", rest, count=1)
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
    """A lexical tripwire over the non-test sources of the linked crates and the observer's (SCANNED_CRATES, HE-004A;
    HE-002S DESIGN section 6, D8): each file of
    FOREIGN_ITEMS declares exactly its foreign symbols, no other linked source declares one, no extern item is public or
    declared `safe`, and no linked source names link_name. The sources are read with comments removed and literal
    contents emptied; every `extern` is an extern block, read strictly (foreign_items), `extern crate` or a function's
    ABI; and the files allowed `unsafe` define no macro (`macro_rules`, or any `$` outside string and character
    literals). Anything the check cannot read refuses, so it reads every extern block of these sources (HE-002S PR
    review round 1, R1-1)."""
    count = 0
    for crate in SCANNED_CRATES:
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


def check_observer_post_seal(base: Path) -> int:
    """HE-004A DESIGN-A section 6 (D1-3, D2-2): crates/observer's non-test sources (and only theirs), with the whitespace
    around `::` removed, name none of POST_SEAL_FORBIDDEN (in the raw text, as for the gate's crates) and, in the code
    with comments and literal contents removed, none of OBSERVER_POST_SEAL_FORBIDDEN's words in any form (method call,
    path call, function item, turbofish, import; PR review round 1, R1-1) nor Drop (R1-4), each of which reaches a system
    call the OBSERVER filter kills or would run code under it. In HE-004A only the not-yet-serving exit runs after the
    seal; the rule settles the list before HE-004B..D add code. A list, not a proof: T04's steady-state trace stays the
    proof. HE-004B1 DESIGN-B section 6: i05-protocol's sources too (OBSERVER_POST_SEAL_CRATES), json.rs's one `impl Drop
    for Value` removed once from its code first (OBSERVER_DROP_EXCEPTIONS). The number of sources."""
    count = 0
    for crate in OBSERVER_POST_SEAL_CRATES:
        found = 0
        for path in sorted((base / crate / "src").rglob("*.rs")):
            rel = path.relative_to(base).as_posix()
            raw = path.read_text(encoding="utf-8")
            text, code = PATH_SPACE.sub("::", raw), PATH_SPACE.sub("::", rust_code(raw))
            if rel in OBSERVER_DROP_EXCEPTIONS:
                code = OBSERVER_DROP_EXCEPTIONS[rel].sub(" ", code, count=1)
            for pattern, name in POST_SEAL_FORBIDDEN:
                require(not re.search(pattern, text), "%s names %s (observer post-seal check)" % (rel, name))
            for pattern, name in OBSERVER_POST_SEAL_FORBIDDEN:
                require(not re.search(pattern, code), "%s names %s (observer post-seal check)" % (rel, name))
            found += 1
        require(found or crate != OBSERVER_CRATE, "%s has no sources (observer post-seal check)" % OBSERVER_CRATE)
        count += found
    return count


def allowed_logic_path(path: tuple[str, ...], rooted: bool, prefixes: tuple = OBSERVER_LOGIC_PATHS) -> bool:
    """Whether a path of an observer logic module passes the whitelist: a path not rooted at a crate (its first segment
    a local name, or an imported module or type) passes; a rooted one must start with an entry of `prefixes`
    (OBSERVER_LOGIC_PATHS for B1's modules, D1_LOGIC_PATHS for D1's)."""
    if not rooted and path[0] not in CRATE_PATH_ROOTS:
        return True
    return any(path[:len(prefix)] == prefix for prefix in prefixes)


def check_observer_logic(base: Path) -> int:
    """HE-004B1 DESIGN-B section 6 (D1-7, D2-5, D3-2) over the observer's logic modules (OBSERVER_LOGIC, each required),
    read with comments removed, literal contents emptied and the whitespace around `::` removed: every use path (no
    rename, no glob) and every crate-rooted code path starts with an OBSERVER_LOGIC_PATHS entry; none of
    OBSERVER_LOGIC_WORDS; and, outside strict #[cfg(test)] mod tests blocks, none of PANICS. HE-004D1 (G-D1-10): D1's
    three logic modules too, each path starting with a D1_LOGIC_PATHS entry (LOGIC_MODULES). The number of modules."""
    for rel, _ in LOGIC_MODULES:
        require((base / rel).is_file(), "%s is missing (observer logic rules)" % rel)
    for rel, prefixes in LOGIC_MODULES:
        raw = (base / rel).read_text(encoding="utf-8")
        try:
            code = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (observer logic rules)" % (rel, error)) from None
        for path, rename in source_uses(rel, raw):
            require(rename is None, "%s renames an import (observer logic rules)" % rel)
            require(path[-1] != "*", "%s imports a glob (observer logic rules)" % rel)
            require(allowed_logic_path(path, False, prefixes), "%s imports %s, outside the observer logic whitelist (observer logic "
                    "rules)" % (rel, "::".join(path)))
        for match in CODE_PATH.finditer(USE_DECLARATION.sub(" ", code)):
            leading, root, tail = match.groups()
            path = (root,) + tuple(tail.split("::")[1:])
            require(allowed_logic_path(path, bool(leading), prefixes), "%s names %s%s, outside the observer logic whitelist "
                    "(observer logic rules)" % (rel, leading or "", "::".join(path)))
        for pattern, name in OBSERVER_LOGIC_WORDS:
            require(not pattern.search(code), "%s names %s (observer logic rules)" % (rel, name))
        scanned = code
        for start, end in reversed(cfg_test_blocks(scanned)):
            scanned = scanned[:start] + " " + scanned[end:]
        for pattern, name in PANICS:
            require(not pattern.search(scanned), "%s names %s outside a strict #[cfg(test)] mod tests block (observer "
                    "no-panic tripwire)" % (rel, name))
    return len(LOGIC_MODULES)


def check_observer_includes(base: Path) -> int:
    """HE-004B1 DESIGN-B section 6 (D2-5): crates/observer/src/contracts.rs exists; in crates/observer's sources (read
    without comments, literals kept) every include_bytes!/include_str! is OBSERVER_INCLUDE_FORM, one plain literal that
    names, relative to its file, a registered CONTRACTS file; only contracts.rs and seal.rs hold one, seal.rs only the
    OBSERVER programs. The number of embedded files."""
    require((base / OBSERVER_CONTRACTS).is_file(), "%s is missing (observer contracts rule)" % OBSERVER_CONTRACTS)
    count = 0
    for path in sorted((base / OBSERVER_CRATE / "src").rglob("*.rs")):
        rel = path.relative_to(base).as_posix()
        raw = path.read_text(encoding="utf-8")
        try:
            code, kept = rust_code(raw), rust_code(raw, literals=True)
        except GateError as error:
            raise GateError("%s: %s (observer contracts rule)" % (rel, error)) from None
        forms = OBSERVER_INCLUDE_FORM.findall(kept)
        require(len(OBSERVER_INCLUDE.findall(code)) == len(forms) == len(OBSERVER_INCLUDE.findall(kept)),
                "%s holds an include_bytes! or include_str! that is not one plain path literal (observer contracts rule)"
                % rel)
        if not forms:
            continue
        # HE-004C (G6): the signed configuration's one include is the observer's own signer key, and nothing else there.
        if rel == OBSERVER_SIGNED_CONFIG:
            require(forms == [OBSERVER_KEY_INCLUDE] and re.search(r"\binclude_bytes\s*!", code),
                    "%s embeds something other than exactly include_bytes!(\"%s\") (observer contracts rule)"
                    % (rel, OBSERVER_KEY_INCLUDE))
            continue
        require(rel in (OBSERVER_CONTRACTS, OBSERVER_SEAL_RS), "%s embeds a file; only %s embeds contract bytes "
                "(observer contracts rule)" % (rel, OBSERVER_CONTRACTS))
        for literal in forms:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), literal))
            require(target in CONTRACTS, "%s embeds %s, which is not a registered contract file (observer contracts rule)"
                    % (rel, literal))
            require(rel != OBSERVER_SEAL_RS or target in OBSERVER_PROGRAMS.values(),
                    "%s embeds %s, not an OBSERVER program (observer contracts rule)" % (rel, literal))
        count += len(forms)
    return count


def check_observer_serve(base: Path) -> int:
    """HE-004C DESIGN-C sections 14 and 15 (G5's wiring rule, D1-1): the observer's main.rs holds one fn serve, and in its
    body, read without comments and use declarations and with the whitespace around `::` removed, each OBSERVER_WIRING
    call appears exactly once, in that order: load, parse, lifetime, credentials, TLS configuration, wire, embedded closure,
    epoch. HE-004D1 (G-D1-8): the twelve calls of DESIGN-D1 section 17.3, and no v1 parse; HE-004-I01a: thirteen, the
    server identity after Enrolled::new. HE-004D2 (G-D2-11; HE-004D1
    PR review round 1, R1-5): the two Linux constructors are also counted in their qualified forms (`<LinuxWire>::new`,
    `< LinuxCapture >::new`, and since HE-004D2 PR review round 1, R1-7, `LinuxWire::<>::new`, `<(LinuxWire)>::new` and
    `<LinuxCapture<>>::new`), each exactly once in serve, and serve names each of the two types only once; with neither
    type renamed with `as` or named by a `type` item anywhere in the crate, and each named in code only in its own file
    and in serve (G-D1-6, R2-1, R3-1, R4-1, check_observer_capture_callers), a second construction in any spelling of the
    type's path refuses. The two home files are pinned whole (check_observer_home_pins, owner decision Q-D2-END), so no
    added associated fn, trait impl, alias, default or projection gives another route (R2-2, R3-1, R4-2); the pinned
    bytes hold no constructor call besides each type's own `fn new`. The rules are textual: serve's own control flow
    around its one counted construction (a loop, or a closure or iterator calling it more than once) is not read and
    stays code review's (R5-1), as what any other called function does in turn. HE-004-I01A2 (HE-004-I01a PR review
    round 1, R1-5): the wire's construction is exactly once WIRE_SETUP_MATCH, `let wire = match LinuxWire::new(sealed)
    { Ok(wire) => wire, Err(error) => return status::wire_setup(&error), };`, so its refusal keeps the statuses 24 and
    31-34. The number of calls."""
    rel = OBSERVER_MAIN
    require((base / rel).is_file(), "%s is missing (observer wiring order)" % rel)
    try:
        code = PATH_SPACE.sub("::", rust_code((base / rel).read_text(encoding="utf-8")))
    except GateError as error:
        raise GateError("%s: %s (observer wiring order)" % (rel, error)) from None
    found = list(FN_SERVE.finditer(code))
    require(len(found) == 1, "%s does not hold exactly one fn serve (observer wiring order)" % rel)
    opening = code.find("{", found[0].end())
    require(opening >= 0, "%s's fn serve has no body (observer wiring order)" % rel)
    body = USE_DECLARATION.sub(" ", code[opening:block_end(code, opening)])
    require(not OBSERVER_V1_PARSE.search(body), "serve calls the v1 ObserverConfig::parse( (observer wiring order, G-D1-8)")
    positions = []
    for pattern, name in OBSERVER_WIRING:
        calls = list(pattern.finditer(body))
        require(len(calls) == 1, "serve does not call %s exactly once (observer wiring order)" % name)
        positions.append(calls[0].start())
    require(positions == sorted(positions), "serve does not call %s in this order (observer wiring order)"
            % ", ".join(name for _, name in OBSERVER_WIRING))
    for pattern, name in QUALIFIED_CONSTRUCTORS:
        require(len(pattern.findall(body)) == 1, "serve constructs %s other than exactly once, counting its qualified "
                "forms (observer wiring order, G-D2-11)" % name)
        require(len(re.findall(r"\b%s\b" % name, body)) == 1, "serve names %s other than once, in its one construction "
                "(observer wiring order, G-D2-11, R1-7)" % name)
    require(len(WIRE_SETUP_MATCH.findall(body)) == 1, "serve does not map LinuxWire::new's refusal exactly once as `let "
            "wire = match LinuxWire::new(sealed) { Ok(wire) => wire, Err(error) => return status::wire_setup(&error), };` "
            "(observer wiring order, HE-004-I01A2, R1-5)")
    return len(OBSERVER_WIRING)


def check_observer_contracts_module(base: Path) -> int:
    """HE-004C DESIGN-C section 15 (G7; HE-004B1 PR review R1-3): crates/observer/src/contracts.rs, read without comments
    and with literals kept, holds only CONTRACT_BYTES_ITEM items naming a registered contract file (relative to it) and
    CONTRACT_PIN_ITEM items whose text is one of the CONTRACTS pins; nothing else (no fn, use, static, other type,
    attribute, mod or unpinned value). HE-004D2 (G-D2-2): each embedded file is one of OBSERVER_EMBEDDED_CONTRACTS; any
    other registered file (a predecessor schema, a vector set, I06 v3's files) is the tests' to read. The number of
    items."""
    rel = OBSERVER_CONTRACTS
    require((base / rel).is_file(), "%s is missing (contracts pin)" % rel)
    try:
        code = rust_code((base / rel).read_text(encoding="utf-8"), literals=True)
    except GateError as error:
        raise GateError("%s: %s (contracts pin)" % (rel, error)) from None
    items = 0
    for item in CONTRACT_BYTES_ITEM.finditer(code):
        target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), item.group(1)))
        require(target in CONTRACTS, "%s embeds %s, which is not a registered contract file (contracts pin)"
                % (rel, item.group(1)))
        require(target in OBSERVER_EMBEDDED_CONTRACTS, "%s embeds %s, a registered contract file it may not embed; only "
                "the tests read it (contracts pin, G-D2-2)" % (rel, item.group(1)))
        items += 1
    pins = set(CONTRACTS.values())
    for item in CONTRACT_PIN_ITEM.finditer(code):
        require(re.fullmatch(r"[0-9a-f]{64}", item.group(1)) and item.group(1) in pins,
                "%s holds the text %r, which is not a registered contract pin (contracts pin)" % (rel, item.group(1)[:16]))
        items += 1
    rest = CONTRACT_PIN_ITEM.sub(" ", CONTRACT_BYTES_ITEM.sub(" ", code)).strip()
    require(not rest, "%s holds %r, not only pinned constant items (contracts pin)" % (rel, rest[:40]))
    require(items, "%s holds no item (contracts pin)" % rel)
    return items


def const_asserts(code: str) -> list[tuple[int, int]]:
    """The item-level compile-time asserts of a source read without comments and with literal contents emptied: each
    `const _: () = assert!(..);` at brace depth 0 whose argument holds no `{` or `}`, as (start, end) through its `;`
    (G-D1-11; PR review round 1, R1-1). A form whose argument holds a brace is not returned, so it is scanned whole and
    its `assert!` refuses."""
    spans = []
    for match in CONST_ASSERT.finditer(code):
        if brace_depth(code, match.start()) != 0:
            continue
        depth, index = 1, match.end()
        while depth and index < len(code):
            depth += {"(": 1, ")": -1}.get(code[index], 0)
            index += 1
        rest = re.match(r"\s*;", code[index:])
        require(depth == 0 and rest, "a compile-time assert the no-panic tripwire cannot read")
        if "{" in code[match.end():index] or "}" in code[match.end():index]:
            continue
        spans.append((match.start(), index + rest.end()))
    return spans


def check_observer_no_panic(base: Path) -> int:
    """HE-004C DESIGN-C section 15 (G8, D1-14 (c)): each of OBSERVER_NO_PANIC (the HE-004C modules, main.rs and
    status.rs; HE-004D1, G-D1-11: enrolled.rs, capture.rs and linux_capture.rs; HE-004-I01a, I01_NO_PANIC_BUILT: the
    four I01 sources linux_listen.rs, i01_service.rs, i01_request.rs and observer_rbac.rs, named here since HE-004-I01A2,
    R1-6, and HE-004-I01B1's i01_digest.rs, i01_admission_render.rs and i01_gate.rs, G-I01B-7 (d)) exists and, read
    with comments removed, literal contents emptied and the whitespace around `::` removed, names
    no panicking macro or call (PANICS) outside strict #[cfg(test)] mod tests blocks. HE-004D1: observer-sys's three
    sources (OBSERVER_SYS_NO_PANIC) too, after their item-level compile-time asserts are removed (const_asserts). The
    number of sources."""
    for rel in OBSERVER_NO_PANIC + OBSERVER_SYS_NO_PANIC:
        require((base / rel).is_file(), "%s is missing (observer no-panic tripwire)" % rel)
    for rel in OBSERVER_NO_PANIC + OBSERVER_SYS_NO_PANIC:
        try:
            code = PATH_SPACE.sub("::", rust_code((base / rel).read_text(encoding="utf-8")))
            if rel in OBSERVER_SYS_NO_PANIC:
                for start, end in reversed(const_asserts(code)):
                    code = code[:start] + " " + code[end:]
        except GateError as error:
            raise GateError("%s: %s (observer no-panic tripwire)" % (rel, error)) from None
        for start, end in reversed(cfg_test_blocks(code)):
            code = code[:start] + " " + code[end:]
        for pattern, name in PANICS:
            require(not pattern.search(code), "%s names %s outside a strict #[cfg(test)] mod tests block (observer "
                    "no-panic tripwire)" % (rel, name))
    return len(OBSERVER_NO_PANIC) + len(OBSERVER_SYS_NO_PANIC)


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
    """A lexical tripwire over the sources of the crates EFFECT_GATE will link and the observer's (SCANNED_CRATES,
    HE-004A; HE-003A DESIGN section 8), read with
    comments removed and literal contents emptied: an outer attribute that derives Debug (`derive(.. Debug ..)`, also
    inside `cfg_attr`) must be followed, after other attributes and a visibility, by a struct, enum or union whose field
    types mention none of DEBUG_HAZARDS (field and variant names are not types). An attribute or item the check cannot
    read refuses. Manual impls and direct formatting are code review's."""
    count = 0
    for crate in SCANNED_CRATES:
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
    symlink; the crates effect-gate, gate-tls and planeon-gate link (their path dependencies, transitively, with
    themselves) are exactly LINKED_CRATES;
    the workspace edition is 2024 and every member inherits it (the unsafe tripwire relies on edition 2024's `unsafe
    extern` and `#[unsafe(no_mangle)]`), and no target table of a member manifest ([lib], [[bin]], [[test]], [[bench]],
    [[example]]) overrides the edition (HE-003A PR review round 1, R1-1); and, when planeon-observer is a member, it links
    exactly OBSERVER_LINKED_CRATES (HE-004A). `workspace` is check_workspace's result."""
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
    # depends on effect-gate, not the reverse). HE-003D DESIGN section 5: and planeon-gate's, the binary's.
    roots = ["effect-gate"] + [name for name in ("gate-tls", "planeon-gate") if name in names and name in workspace]
    closure = {names.get(name) for root in roots for name in linked(workspace, root)}
    require(closure == set(LINKED_CRATES), "the crates effect-gate, gate-tls and planeon-gate link are %s, not %s "
            "(workspace shape)" % (sorted(str(path) for path in closure), sorted(LINKED_CRATES)))
    # HE-004A DESIGN-A section 6 (D2-4): planeon-observer, a member, links exactly its own crate and gate-sys (its
    # path dependencies, transitively; a dev-dependency is not linked and not in `workspace`). HE-004B1 (Q-HE4B-6 (a)):
    # and i05-protocol.
    if "planeon-observer" in names:
        require("planeon-observer" in workspace, "no planeon-observer crate in the workspace (workspace shape)")
        observer = {names.get(name) for name in linked(workspace, "planeon-observer")}
        require(observer == set(OBSERVER_LINKED_CRATES), "planeon-observer links %s, not %s (workspace shape)"
                % (sorted(str(path) for path in observer), sorted(OBSERVER_LINKED_CRATES)))
    # HE-004D1 DESIGN-D1 section 3 (G-D1-1): observer-sys is std-only, its manifest names no dependency of any kind.
    if OBSERVER_SYS in members:
        table = tomllib.loads((base / OBSERVER_SYS / "Cargo.toml").read_text(encoding="utf-8"))
        require(not any(key in table for key in ("dependencies", "dev-dependencies", "build-dependencies", "target")),
                "observer-sys has a dependency; it is std-only (workspace shape, G-D1-1)")
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
    exactly once each, and no source but exchange.rs constructs an UpstreamResponse. HE-003D DESIGN section 5 (C7,
    HE-003C PR R1-1): the binary's sources join every one of these rules (TLS_CRATES); TLS_CLIENT_AUTH counts any
    mention; outside exchange.rs no source names UpstreamResponse at all, and none defines a macro (macro_rules); the
    list gains with_root_certificates. Text, not Rust: what a renamed import, an alias or a macro could do is refused by
    the any-mention and macro rules, and code review stays for values handed out of exchange.rs."""
    sources = [(path.relative_to(base).as_posix(), path.read_text(encoding="utf-8"))
               for crate in TLS_CRATES for path in sorted((base / crate / "src").rglob("*.rs"))]
    require(any(rel.startswith(GATE_TLS + "/") for rel, _ in sources), "gate-tls has no sources (TLS deny-list)")
    code = ""
    for rel, text in sources:
        for pattern, name in TLS_FORBIDDEN:
            require(not pattern.search(text), "%s names %s (TLS deny-list)" % (rel, name))
        try:
            source_code = rust_code(text)
        except GateError as error:
            raise GateError("%s: %s (TLS deny-list)" % (rel, error)) from None
        require(rel == UPSTREAM_RESPONSE_HOME or not UPSTREAM_RESPONSE.search(source_code),
                "%s names UpstreamResponse outside %s (TLS deny-list)" % (rel, UPSTREAM_RESPONSE_HOME))
        require(not MACRO_RULES.search(source_code), "%s defines a macro with macro_rules (TLS deny-list)" % rel)
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
                "gate-tls and the binary do not mention %s exactly once, in tls_client.rs (TLS deny-list)" % name)
    return len(sources) + check_observer_tls(base)


def check_observer_tls(base: Path) -> int:
    """HE-004C DESIGN-C section 15 (G3; D1-14 (b)): check_tls's group O, crates/observer's non-test sources (which must
    exist), a client only: none of TLS_FORBIDDEN or OBSERVER_TLS_FORBIDDEN in their raw text (comments included); read
    with comments removed and literal contents emptied, OBSERVER_TLS_SETTINGS each set exactly once as the closed setting,
    TLS_CLIENT_AUTH each mentioned exactly once, in crates/observer/src/tls.rs, and no macro_rules. The group's own counts,
    so group G's stay as they are. The number of its sources."""
    sources = [(source.relative_to(base).as_posix(), source.read_text(encoding="utf-8"))
               for source in sorted((base / OBSERVER_CRATE / "src").rglob("*.rs"))]
    require(sources, "crates/observer has no sources (TLS deny-list, group O)")
    code = ""
    for rel, text in sources:
        for pattern, name in TLS_FORBIDDEN + OBSERVER_TLS_FORBIDDEN:
            require(not pattern.search(text), "%s names %s (TLS deny-list, group O)" % (rel, name))
        try:
            source_code = rust_code(text)
        except GateError as error:
            raise GateError("%s: %s (TLS deny-list, group O)" % (rel, error)) from None
        require(not MACRO_RULES.search(source_code), "%s defines a macro with macro_rules (TLS deny-list, group O)" % rel)
        code += source_code + "\n"
    for name, assignment in OBSERVER_TLS_SETTINGS:
        require(len(re.findall(r"\b%s\b" % name, code)) == 1 and len(re.findall(assignment, code)) == 1,
                "crates/observer does not set %s exactly once, as the closed setting (TLS deny-list, group O)" % name)
    tls = base / OBSERVER_TLS
    require(tls.is_file(), "crates/observer has no tls.rs (TLS deny-list, group O)")
    tls_code = rust_code(tls.read_text(encoding="utf-8"))
    for pattern, name in TLS_CLIENT_AUTH:
        require(len(re.findall(pattern, code)) == 1 and len(re.findall(pattern, tls_code)) == 1,
                "crates/observer does not mention %s exactly once, in tls.rs (TLS deny-list, group O)" % name)
    return len(sources)


def call_end(tokens: list[str], start: int) -> int:
    """The index after the `)` that closes the `(` at `start`."""
    depth = 0
    for index in range(start, len(tokens)):
        depth += {"(": 1, ")": -1}.get(tokens[index], 0)
        if depth == 0:
            return index + 1
    raise GateError("a call without its closing parenthesis (seal-order grammar)")


def check_seal_order(base: Path, site: dict = GATE_SEAL_SITE) -> str:
    """HE-003D DESIGN section 5 (O2; D1-3, D2-2): the seal-order grammar over the binary's main.rs read without
    comments (SEAL_CALLS and the patterns above), then the socket and thread names of BEFORE_SEAL_REFUSED in main.rs
    up to `seal_stage2(` and in all of gate_config.rs and signed_config.rs (one `use gate_sys::Dir;` excepted in the
    latter). What the functions called between the stages call in turn, and new public functions in linux_os.rs and
    linux_net.rs, stay code review's (MODEL_DEFINED R72). HE-004A DESIGN-A section 6 (D2-3): parameterised by `site`,
    the main.rs, the files read before the seal, the calls allowed between the stages, the pinned imports and functions
    (GATE_SEAL_SITE by default, OBSERVER_SEAL_SITE for the observer); with `adjacent`, the stage-1 statement is exact,
    the stage-2 statement follows it with nothing between, and OBSERVER_TAIL follows that and closes main. Returns the
    calls found between the stages."""
    main_rel = site["main"]
    for rel in (main_rel,) + tuple(site["before"]):
        require((base / rel).is_file(), "%s is missing (seal-order grammar)" % rel)
    raw = (base / main_rel).read_text(encoding="utf-8")
    try:
        written, code = rust_code(raw, literals=True), rust_code(raw)
    except GateError as error:
        raise GateError("%s: %s (seal-order grammar)" % (main_rel, error)) from None
    linux = list(LINUX_MAIN.finditer(written))
    others = list(OTHER_MAIN.finditer(written))
    require(len(linux) == 1 and len(LINUX_MAIN_CODE.findall(code)) == 1 and len(others) <= 1
            and len(FN_MAIN.findall(code)) == 1 + len(others),
            "%s must hold exactly one #[cfg(target_os = \"linux\")] fn main() -> ExitCode and at most a non-Linux stub "
            "returning status::NOT_LINUX (seal-order grammar)" % main_rel)
    body = LINUX_MAIN_CODE.search(code).end()
    binding = STAGE1_BINDING.match(code, body)
    require(binding, "main does not start with `let <name> = match seal_stage1() {` (seal-order grammar)")
    require(len(re.findall(r"\bseal_stage1\s*\(", code)) == 1 and len(re.findall(r"\bseal_stage2\s*\(", code)) == 1,
            "%s does not call seal_stage1 and seal_stage2 exactly once each (seal-order grammar)" % main_rel)
    stage2 = re.search(r"\bseal_stage2\s*\(", code).start()
    require(stage2 > binding.end(), "seal_stage2 comes before seal_stage1 (seal-order grammar)")
    statements = [match for match in STAGE2_STATEMENT.finditer(code)]
    statement = next((match for match in statements if match.start(2) > stage2 > match.start()), None)
    require(statement and len(statements) == 1,
            "the second stage is not exactly `let <name> = match seal_stage2(<stage-1 binding>) { Ok(<x>) => <x>, "
            "Err(<e>) => return ExitCode::from(status::seal(&<e>)), };` (seal-order grammar)")
    require(statement.group(2) == binding.group(1) and statement.group(3) == statement.group(4)
            and statement.group(5) == statement.group(6),
            "the second stage's argument or arms are not the stage-1 binding and the bound names (seal-order grammar)")
    check_main_shape(raw, written, code, linux[0], site)
    end = statement.end()
    if site["adjacent"]:
        first = STAGE1_STATEMENT.match(code, body)
        require(first and first.group(2) == first.group(3) and first.group(4) == first.group(5),
                "the first stage is not exactly `let <name> = match seal_stage1() { Ok(<x>) => <x>, Err(<e>) => return "
                "ExitCode::from(status::seal(&<e>)), };` (seal-order grammar)")
        require(not code[first.end():statement.start()].strip(),
                "%s runs something between the seal's stages (seal-order grammar)" % main_rel)
        tail = re.compile(OBSERVER_TAIL % re.escape(statement.group(1))).match(code, end)
        require(tail, "after the second stage %s does not end main with exactly `ExitCode::from(serve(&<the stage-2 "
                "binding>))` (seal-order grammar)" % main_rel)
        end = tail.end()
    depth = 1
    for index in range(body, end):
        depth += {"{": 1, "}": -1}.get(code[index], 0)
        require(depth > 0 or index == end - 1 and site["adjacent"], "seal_stage2 is not called inside main (seal-order "
                "grammar)")
    require(not site["adjacent"] or depth == 0, "the pinned tail does not close main (seal-order grammar)")
    segment = code[re.search(r"\bseal_stage1\s*\(", code).end():statement.start()]
    tokens, index = [], 0
    while segment[index:].strip():
        token = SEAL_TOKEN.match(segment, index)
        require(token, "main names %r between the seal's stages, which the seal-order grammar does not allow"
                % segment[index:].strip()[:24])
        tokens.append(token.group(1))
        index = token.end()
    calls, patterns = set(), set()
    position = 0
    while position < len(tokens):
        token = tokens[position]
        if not re.match(r"[A-Za-z_]", token):
            position += 1
            continue
        require(token not in RUST_KEYWORDS or token in SEAL_KEYWORDS,
                "main uses the keyword %s between the seal's stages (seal-order grammar)" % token)
        path, cursor = [token], position + 1
        while cursor + 1 < len(tokens) and tokens[cursor] == "::" and re.match(r"[A-Za-z_]", tokens[cursor + 1]):
            path.append(tokens[cursor + 1])
            cursor += 2
        name = "::".join(path)
        if cursor < len(tokens) and tokens[cursor] == "(":
            end_call = call_end(tokens, cursor)
            rest = end_call
            while rest < len(tokens) and tokens[rest] == ")":
                rest += 1
            pattern = path[-1][:1].isupper() and rest < len(tokens) and tokens[rest] == "=>"
            require(name in site["calls"] or pattern,
                    "main calls %s( between the seal's stages (seal-order grammar)" % name)
            if name == "status::seal":
                require(tokens[max(0, position - 4):position] == ["ExitCode", "::", "from", "("],
                        "status::seal( is not the argument of ExitCode::from( (seal-order grammar)")
            (calls if name in site["calls"] else patterns).add(name)
        position = cursor
    for rel, text in ((main_rel, code[:statement.end()]),) + tuple((rel, None) for rel in site["before"]):
        if text is None:
            try:
                text = rust_code((base / rel).read_text(encoding="utf-8"))
            except GateError as error:
                raise GateError("%s: %s (seal-order grammar)" % (rel, error)) from None
        text = PATH_SPACE.sub("::", text)
        if rel == SIGNED_CONFIG:
            text = SIGNED_CONFIG_DIR.sub("", text, count=1)
        for pattern in BEFORE_SEAL_REFUSED:
            require(not re.search(pattern, text), "%s names %s before the seal (seal-order grammar)"
                    % (rel, pattern.replace("\\b", "")))
    return "%s (and the tuple-variant patterns %s)" % (", ".join(sorted(calls)), ", ".join(sorted(patterns)) or "none")


def check_main_shape(raw: str, written: str, code: str, linux: re.Match, site: dict = GATE_SEAL_SITE) -> None:
    """PR review round 1, R1-2 (Q-HE3D-R1 (a)): main.rs (read without comments) imports exactly MAIN_USES (no rename,
    no glob, nothing else), defines no item but the two `fn main` and `fn serve` (no mod, struct, enum, union, trait,
    type, impl, const, static, macro or extern), carries only MAIN_ATTRIBUTES, and nothing but its cfg precedes the
    Linux main. So no code defined in main.rs runs between the stages under an allowed name. HE-004A (D2-3): the imports
    and functions are the site's (the observer's: OBSERVER_MAIN_USES, two `fn main` and nothing else)."""
    uses = source_uses(site["main"], raw)
    for path, rename in uses:
        require(rename is None, "main.rs renames an import (seal-order grammar)")
        require(path[-1] != "*", "main.rs imports a glob (seal-order grammar)")
    require(tuple(sorted(uses)) == site["uses"], "main.rs's imports are not exactly the pinned set (seal-order grammar)")
    item = MAIN_ITEMS.search(code)
    require(not item, "main.rs defines a %s item (the keyword); only %s are allowed (seal-order grammar)"
            % (item.group(1) if item else "", " and ".join("fn " + name for name in sorted(set(site["functions"])))))
    require(sorted(re.findall(r"\bfn\s+([A-Za-z_]\w*)", code)) == site["functions"],
            "main.rs defines functions other than %s (seal-order grammar)"
            % " and ".join("fn " + name for name in sorted(set(site["functions"]))))
    for attribute in OUTER_ATTRIBUTE.finditer(written):
        text = re.sub(r"\s+", "", written[attribute.start():bracket_end(written, attribute.start())])
        require(text in MAIN_ATTRIBUTES, "main.rs carries the attribute %s (seal-order grammar)" % text)
    for inner in re.finditer(r"#\s*!\s*\[", written):
        text = re.sub(r"\s+", "", written[inner.start():bracket_end(written, inner.start())])
        require(text in MAIN_ATTRIBUTES, "main.rs carries the attribute %s (seal-order grammar)" % text)
    require(not written[:linux.start()].rstrip().endswith("]"),
            "an attribute other than its cfg precedes the Linux main (seal-order grammar)")


def linked_sources(base: Path) -> list[tuple[str, str]]:
    """(relative path, text) of every non-test source of the linked crates (the binary included) and, since HE-004A,
    of planeon-observer's crate (SCANNED_CRATES), for the socket-module, store-opening, read_link, macro, code-before-main
    and print rules."""
    return [(path.relative_to(base).as_posix(), path.read_text(encoding="utf-8"))
            for crate in SCANNED_CRATES for path in sorted((base / crate / "src").rglob("*.rs"))]


def check_socket_modules(base: Path) -> int:
    """HE-003D DESIGN section 5 (D1-3, D2-6): read from every linked source's use trees (groups, globs and renames
    included), a path through gate_sys to channel or tcp, a glob of gate_sys and a rename of gate_sys itself appear
    only in SOCKET_FILES and gate-sys; the fully qualified gate_sys::channel and gate_sys::tcp (read without comments,
    whitespace around `::` removed) likewise; SOCKET_FILES re-export nothing (no `pub use`); and no linked source names
    std::thread or `thread::` (the gate is single-threaded)."""
    sources = linked_sources(base)
    for rel in SOCKET_FILES:
        require((base / rel).is_file(), "%s is missing (socket-module check)" % rel)
    for rel, raw in sources:
        try:
            code = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (socket-module check)" % (rel, error)) from None
        for pattern in THREADS:
            require(not pattern.search(code), "%s names std::thread or thread:: (socket-module check)" % rel)
        if rel in SOCKET_FILES:
            require(not PUB_USE.search(code), "%s re-exports with pub use (socket-module check)" % rel)
            check_socket_items(rel, raw, code)
            continue
        if rel.startswith("crates/gate-sys/"):
            continue
        for path, rename in source_uses(rel, raw):
            if "gate_sys" not in path:
                continue
            rest = path[path.index("gate_sys") + 1:]
            require(not rest or rest[0] not in SOCKET_MODULES + ("*",),
                    "%s imports gate-sys's socket modules (socket-module check)" % rel)
            require(rename is None or rest not in ((), ("self",)), "%s renames gate_sys (socket-module check)" % rel)
        require(not SOCKET_TEXT.search(code), "%s names gate_sys::channel or gate_sys::tcp (socket-module check)" % rel)
    return len(sources)


def check_gate_stores(base: Path) -> int:
    """HE-003D departure A1 (accepted 2026-10-15): crates/gate's sources, read without comments and with the whitespace
    around `::` removed, call FileStores::open_bound exactly once, name `::open` only as PolicyGate::open, and neither
    rename nor alias FileStores or PolicyGate (as far as text allows: a call through a value the binary does not name
    stays code review's). The number of sources."""
    sources = [(path.relative_to(base).as_posix(), path.read_text(encoding="utf-8"))
               for path in sorted((base / "crates/gate/src").rglob("*.rs"))]
    calls = 0
    for rel, raw in sources:
        try:
            code = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (store opening rule)" % (rel, error)) from None
        calls += len(OPEN_BOUND.findall(code))
        require(not ANY_OPEN.search(POLICY_OPEN.sub("", code)),
                "%s names ::open other than PolicyGate::open, so not only FileStores::open_bound (store opening rule)" % rel)
        for pattern in STORE_ALIASES:
            require(not pattern.search(code), "%s renames or aliases FileStores or PolicyGate (store opening rule)" % rel)
    require(calls == 1, "crates/gate calls FileStores::open_bound %d times, not exactly once (store opening rule)" % calls)
    for rel, raw in linked_sources(base):
        try:
            code = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (store opening rule)" % (rel, error)) from None
        require(not UNBOUND_OPEN.search(code) and not (rel == FILE_STORE and SELF_OPEN.search(code)),
                "%s calls FileStores::open, the unbound opening (store opening rule)" % rel)
    return len(sources)


def item_text(code: str, start: int, kind: str) -> str:
    """An item's text from `start`: a fn up to its body's `{` (or `;`), anything else up to its `;`, at depth 0."""
    depth = 0
    for index in range(start, len(code)):
        char = code[index]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "{":
            if kind == "fn" and depth == 0:
                return code[start:index]
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == ";" and depth == 0:
            return code[start:index]
    raise GateError("an item the socket-module check cannot read")


def bracket_scan(code: str, index: int, stops: str, what: str, body: bool = False) -> tuple[int, list[int], list[int]]:
    """HE-003A3 (STRUCT-ANGLE, owner decision Q-HE4A-5 (a), DESIGN section 6, D1-5, D2-3, D3-3): walks `code` from
    `index` in type position with an empty bracket stack until one of `stops` at depth 0 (the stack empty); returns
    that index and the positions of the commas and of the `=` at depth 0. In type position every `(`, `[` and `<` opens
    and every `)`, `]` and `>` closes its own kind (`>>` is two closers, `->` is no bracket), so a generic argument list,
    a qualified path `<u8 as Tr<u8, u8>>::A` and a higher-ranked `for<'a>` all nest; an array length after its `;` up
    to the matching `]` and every `{ .. }` block are expression contexts, where `<` and `>` (and `<<`, `>>`, `<=`, `>=`)
    are operators and everything nested is an expression too. In a struct `body`, a `=` at depth 0 (a field default)
    makes the rest of that field an expression context too, up to the next comma at depth 0 (D3-3), so the caller sees
    the `=` and refuses it; generic defaults are types and keep the type rule. A closer of the wrong kind, a `>` with
    no open angle or the end of the code refuses (`what` names the reader)."""
    stack: list[list[str]] = []
    commas, equals = [], []
    default = False
    while index < len(code):
        char = code[index]
        if code.startswith("->", index):
            index += 2
            continue
        if not stack and char in stops:
            return index, commas, equals
        mode = stack[-1][1] if stack else ("expr" if default else "type")
        if char in "([{":
            stack.append([char, "expr" if mode == "expr" or char == "{" else "type"])
        elif char == "<" and mode == "type":
            stack.append(["<", "type"])
        elif char == ">" and mode == "type":
            require(stack and stack[-1][0] == "<", "%s cannot read" % what)
            stack.pop()
        elif char in ")]}":
            require(stack and stack[-1][0] == {")": "(", "]": "[", "}": "{"}[char], "%s cannot read" % what)
            stack.pop()
        elif char == ";" and stack and stack[-1] == ["[", "type"]:
            stack[-1][1] = "expr"
        elif char == "," and not stack:
            commas.append(index)
            default = False
        elif char == "=" and not stack:
            equals.append(index)
            default = body
        index += 1
    raise GateError("%s cannot read" % what)


def struct_fields(code: str, start: int) -> list[str]:
    """The field texts of the struct whose name ends at `start` (HE-003A3, the STRUCT-ANGLE rule and the struct-body
    defect, Q-HE4A-5 (a)): the generic parameter list is skipped with `bracket_scan`'s angle rule (so `S<F: Fn(u8) ->
    (u8, u8)>` or a default `{ 1 << 2 }` never ends it early); then a `(` opens a tuple body, after which only an
    optional where-clause and `;` may follow; otherwise an optional where-clause is skipped up to the `{` at depth 0 of
    all four bracket kinds (braces inside a where-clause or a generic default are nested, never the body), or a unit
    struct ends at its `;` at depth 0 after any where-clause. The body is split at its commas at depth 0 of `(`, `[`,
    `{` and `<` under the same rule. A `=` at the body's depth 0 (a field default) refuses, so no default expression
    can hide a field; so does anything the reader cannot delimit."""
    what = "a struct the socket-module check"
    index = start
    while index < len(code) and code[index].isspace():
        index += 1
    if code.startswith("<", index):
        index = bracket_scan(code, index + 1, ">", what)[0] + 1
    rest = re.compile(r"\s*").match(code, index).end()
    if code.startswith("(", rest):
        close, commas, equals = bracket_scan(code, rest + 1, ")", what, body=True)
        tail = re.compile(r"\s*").match(code, close + 1).end()
        if re.match(r"where\b", code[tail:]):
            tail = bracket_scan(code, tail, ";{", what)[0]
        require(code.startswith(";", tail), "%s cannot read" % what)
        body, opening = code[rest + 1:close], rest + 1
    else:
        require(code.startswith(("{", ";"), rest) or re.match(r"where\b", code[rest:]), "%s cannot read" % what)
        stop = bracket_scan(code, rest, "{;", what)[0]
        if code[stop] == ";":
            return []
        close, commas, equals = bracket_scan(code, stop + 1, "}", what, body=True)
        body, opening = code[stop + 1:close], stop + 1
    require(not equals, "%s cannot read (a field default)" % what)
    fields, begin = [], 0
    for comma in commas:
        fields.append(body[begin:comma - opening])
        begin = comma - opening + 1
    fields.append(body[begin:])
    return [field for field in fields if field.strip()]


def enum_variant_types(code: str, start: int) -> list[str]:
    """HE-003A2 (N1, D2-1): the field types of each variant of the enum whose name ends at `start`: a tuple variant's
    parenthesised types and a named-field variant's field types with the names removed (unit variants and
    discriminants have none). Variant names are never returned. A body the reader cannot close or a variant it cannot
    read refuses."""
    opening = code.find("{", start)
    require(opening >= 0 and ";" not in code[start:opening], "an enum the socket-module check cannot read")
    depth, index = 0, opening
    while index < len(code):
        depth += {"{": 1, "}": -1}.get(code[index], 0)
        if depth == 0:
            break
        index += 1
    require(depth == 0, "an enum the socket-module check cannot read")
    body = code[opening + 1:index].replace("->", "  ")
    # PR review round 1, R1-2: variants are split at commas outside parentheses, brackets and braces only (a
    # discriminant such as `1 << 2` holds angle brackets that are no generics), and each variant's field types must
    # hold balanced angle brackets, or the reader refuses.
    variants, depth, begin = [], 0, 0
    for position, char in enumerate(body):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            require(depth >= 0, "an enum the socket-module check cannot read")
        elif char == "," and depth == 0:
            variants.append(body[begin:position])
            begin = position + 1
    variants.append(body[begin:])
    types = []
    for variant in variants:
        text = re.sub(r"#\s*\[[^\]]*\]", " ", variant).strip()
        if not text:
            continue
        shape = re.match(r"[A-Za-z_]\w*\s*(.*)$", text, re.S)
        require(shape, "an enum variant the socket-module check cannot read")
        rest = shape.group(1).strip()
        if rest[:1] in ("(", "{"):
            # The fields up to their closing bracket; after it only an explicit discriminant (`= <expr>`) may follow.
            level, close = 0, -1
            for position, char in enumerate(rest):
                level += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(char, 0)
                if level == 0:
                    close = position
                    break
            tail = rest[close + 1:].strip() if close > 0 else "?"
            require(close > 0 and (tail == "" or tail.startswith("=")),
                    "an enum variant the socket-module check cannot read")
            inner = rest[1:close]
            types.append(inner if rest[0] == "(" else FIELD_NAME.sub(" ", inner))
        else:
            require(rest == "" or rest.startswith("="), "an enum variant the socket-module check cannot read")
            continue
        angle = 0
        for char in types[-1]:
            angle += {"<": 1, ">": -1}.get(char, 0)
            require(angle >= 0, "an enum variant the socket-module check cannot read (unbalanced angle brackets)")
        require(angle == 0, "an enum variant the socket-module check cannot read (unbalanced angle brackets)")
    return types


def block_end(code: str, opening: int) -> int:
    """The index after the `}` that closes the `{` at `opening` (comments removed, literal contents emptied)."""
    depth = 0
    for index in range(opening, len(code)):
        depth += {"{": 1, "}": -1}.get(code[index], 0)
        if depth == 0:
            return index + 1
    raise GateError("a block without its closing brace")


def check_socket_items(rel: str, raw: str, code: str) -> None:
    """R1-3: in a SOCKET_FILES source (code read without comments, `::` spacing removed), no `pub` type alias, const,
    static or fn signature names a gate-sys channel or tcp item other than SOCKET_DATA_TYPES; no glob of those modules.
    R2-1: no private type alias, no pub const or static of a fn-pointer type, and no pub struct field whose type names
    such an item or is a fn pointer. HE-003A2 (N1): no pub type alias, pub const or static type or pub struct field of
    a fn-pointer or Fn-trait type, and no variant of a pub enum whose field types name such an item or are a fn pointer
    or an Fn-trait type. A text tripwire over names: a wrapper type or a pub fn's body stays code review's. HE-004-I01A2
    (HE-004-I01a PR review round 1, R1-3): the use paths are read with the source's aliases followed (resolved_uses), so
    an import through a rename of gate_sys (`use gate_sys as gs; use gs::channel::{Conn};`) or of a socket module
    (`use gs::channel as c; use c::Conn;`) binds its items as the direct form does, and a gate_sys rename's qualified
    paths (`gs::channel::Conn`) are read as gate_sys's."""
    modules, items = set(), {}
    uses = resolved_uses(source_uses(rel, raw))
    for path, rename in uses:
        if len(path) < 2 or path[0] != "gate_sys" or path[1] not in SOCKET_MODULES:
            continue
        require(path[-1] != "*", "%s imports a glob of gate-sys's socket module (socket-module check)" % rel)
        if len(path) == 2 or path[2:] == ("self",):
            modules.add(rename or path[1])
        else:
            items[rename or path[-1]] = path[-1]
    crates = gate_sys_aliases(uses)

    def hazards(text: str) -> list[str]:
        named = set(re.findall(r"\bgate_sys::(?:channel|tcp)::(\w+)", text))
        for alias in crates:
            named |= set(re.findall(r"(?<!::)\b%s::(?:channel|tcp)::(\w+)" % re.escape(alias), text))
        for module in modules:
            named |= set(re.findall(r"(?<!::)\b%s::(\w+)" % re.escape(module), text))
        named |= {original for binding, original in items.items() if re.search(r"(?<!::)\b%s\b" % re.escape(binding), text)}
        return sorted(named - set(SOCKET_DATA_TYPES))

    for item in PUB_ITEM.finditer(code):
        text = item_text(code, item.start(), item.group(1))
        found = hazards(text)
        require(not found, "%s has a pub item naming gate-sys's socket items %s (socket-module check)" % (rel, found))
        if item.group(1) in ("const", "static", "type"):
            typed = text if item.group(1) == "type" else text.split("=", 1)[0]
            require(not FN_POINTER.search(typed),
                    "%s has a pub %s of a fn-pointer type (socket-module check)" % (rel, item.group(1)))
            require(not FN_TRAIT.search(typed),
                    "%s has a pub %s of an Fn-trait type (socket-module check)" % (rel, item.group(1)))
    exempt = pidfd_binding(rel, code, "socket-module check", required=False)
    for alias in TYPE_ITEM.finditer(code):
        if alias.start() == exempt:
            continue
        require(PUB_PREFIX.search(code[:alias.start()]), "%s defines a private type alias (socket-module check)" % rel)
    for struct in STRUCT_ITEM.finditer(code):
        for field in struct_fields(code, struct.end()):
            if not re.match(r"\s*(?:#\s*\[[^\]]*\]\s*)*pub\b", field):
                continue
            found = hazards(field)
            require(not found, "%s has a pub field naming gate-sys's socket items %s (socket-module check)" % (rel, found))
            require(not FN_POINTER.search(field), "%s has a pub field of a fn-pointer type (socket-module check)" % rel)
            require(not FN_TRAIT.search(field), "%s has a pub field of an Fn-trait type (socket-module check)" % rel)
    for enum in PUB_ENUM.finditer(code):
        for types in enum_variant_types(code, enum.end()):
            found = hazards(types)
            require(not found, "%s has a pub enum variant naming gate-sys's socket items %s (socket-module check)"
                    % (rel, found))
            require(not FN_POINTER.search(types), "%s has a pub enum variant of a fn-pointer type (socket-module check)"
                    % rel)
            require(not FN_TRAIT.search(types), "%s has a pub enum variant of an Fn-trait type (socket-module check)"
                    % rel)


def check_read_link(base: Path) -> int:
    """HE-003A2 DESIGN section 3 (D2-2): over the linked crates' non-test sources (the binary included), read without
    comments and with literals kept, the word read_link occurs exactly twice: once in openat.rs as its definition
    (`fn read_link(`) and once in channel.rs as the call `read_link("exe", ..)`. The number of occurrences."""
    found = {}
    for rel, raw in linked_sources(base):
        try:
            code = rust_code(raw, literals=True)
        except GateError as error:
            raise GateError("%s: %s (read_link rule)" % (rel, error)) from None
        if READ_LINK.search(code):
            found[rel] = code
    for rel in found:
        require(rel in (OPENAT, CHANNEL), "%s names read_link; only openat.rs defines it and channel.rs calls it "
                "(read_link rule)" % rel)
    definition, call = found.get(OPENAT, ""), found.get(CHANNEL, "")
    require(len(READ_LINK.findall(definition)) == 1 and READ_LINK_DEFINITION.search(definition),
            "%s does not name read_link exactly once, as its definition (read_link rule)" % OPENAT)
    require(len(READ_LINK.findall(call)) == 1 and READ_LINK_CALL.search(call),
            "%s does not name read_link exactly once, as the call read_link(\"exe\", ..) (read_link rule)" % CHANNEL)
    # R1-3: readlinkat, twice in openat.rs (the declaration in the extern block, the one call in read_link's body).
    for rel, raw in linked_sources(base):
        if rel != OPENAT:
            require(not READLINKAT.search(rust_code(raw, literals=True)),
                    "%s names readlinkat; only openat.rs declares it and calls it in read_link (read_link rule)" % rel)
    raw = (base / OPENAT).read_text(encoding="utf-8")
    code, kept = rust_code(raw), rust_code(raw, literals=True)
    message = "%s does not name readlinkat exactly twice, as its declaration and one call in read_link (read_link rule)"
    positions = [match.start() for match in READLINKAT.finditer(code)]
    require(len(positions) == 2 and len(READLINKAT.findall(kept)) == 2, message % OPENAT)
    declaration = READLINKAT_DECLARATION.search(code)
    blocks = [(block.end() - 1, block_end(code, block.end() - 1)) for block in EXTERN_BLOCK.finditer(code)]
    require(declaration and any(start < declaration.start() < end for start, end in blocks), message % OPENAT)
    named = declaration.start() + declaration.group(0).index("readlinkat")
    definition = READ_LINK_DEFINITION.search(code)
    opening = code.find("{", definition.end()) if definition else -1
    require(opening >= 0, message % OPENAT)
    body = (opening, block_end(code, opening))
    calls = [position for position in positions if position != named]
    require(named in positions and len(calls) == 1 and body[0] < calls[0] < body[1]
            and re.match(r"readlinkat\s*\(", code[calls[0]:]), message % OPENAT)
    return sum(len(READ_LINK.findall(code)) for code in found.values())


def pidfd_binding(rel: str, code: str, rule: str, required: bool = True) -> int:
    """HE-003A3 (DESIGN section 5, D3-1): the position of the one associated `type Pidfd = ..;` binding a file may
    hold, inside its `impl KernelReads for <its type>` block (`type Pidfd = PidFd;` in linux_os.rs, any one type in
    fake_kernel.rs); -1 for any other file, and (unless `required`) for a file without that block. More than one such
    block, or a block without exactly one such binding, refuses. The binding in linux_os.rs exposes gate-sys's PidFd,
    which creates no socket, from a LinuxKernelReads that exists only after open_after_seal(&Sealed)."""
    if rel not in PIDFD_TYPE:
        return -1
    header, binding = PIDFD_TYPE[rel]
    blocks = list(header.finditer(code))
    if not blocks and not required:
        return -1
    require(len(blocks) == 1, "%s does not hold exactly one KernelReads impl block (%s)" % (rel, rule))
    opening = blocks[0].end() - 1
    inside = [match for match in binding.finditer(code) if opening < match.start() < block_end(code, opening)]
    require(len(inside) == 1, "%s does not bind exactly one type Pidfd in its KernelReads impl (%s)" % (rel, rule))
    return inside[0].start()


def impl_headers(rel: str, code: str) -> list[tuple[int, str]]:
    """Each item-level impl header of a source (read without comments, literal contents emptied) as (position, its
    tokens joined by single spaces), from `impl` to the `{` or `;` at depth 0 of the STRUCT-ANGLE scanner. An item-level
    `impl` starts the file or follows `{`, `}`, `;`, an attribute's `]` or `unsafe`; `impl Trait` in a parameter or
    return type (after `:`, `(`, `,`, `<`, `&` or `->`) is a type, not an implementation."""
    headers = []
    for word in IMPL_WORD.finditer(code):
        before = code[:word.start()].rstrip()
        if before and before[-1] not in "{};]" and not re.search(r"\bunsafe$", before):
            continue
        end = bracket_scan(code, word.end(), "{;", "%s: an impl header the observation rules" % rel)[0]
        headers.append((word.start(), " ".join(HEADER_TOKEN.findall(code[word.start():end]))))
    return headers


def cfg_test_blocks(code: str) -> list[tuple[int, int]]:
    """The strict in-source test modules of a source read without comments (D3-2): `#[cfg(test)]` alone on its line,
    directly above `mod tests {`, with no other attribute on the line above it; each as (start, end) of the block."""
    blocks = []
    for match in CFG_TEST_LINE.finditer(code):
        before = code[:match.start()].rstrip()
        if before.endswith("]"):
            continue
        blocks.append((match.start(), block_end(code, match.end() - 1)))
    return blocks


def brace_depth(code: str, index: int) -> int:
    """The brace depth at `index` of a source read without comments and with literal contents emptied."""
    return code.count("{", 0, index) - code.count("}", 0, index)


def check_observation(base: Path) -> int:
    """HE-003A3 DESIGN sections 4-6 (D2-1, D2-5, D3-1, D3-2, D3-4) over the linked crates' non-test sources:
    - callers: each OBSERVATION_CALLERS word occurs (read without comments, literals kept) only as its one definition
      in its file and its exact calls in the calling file (exactly those, or at least one for open_fixed); the two
      root opens lie inside KernelRoots::open_after_seal's body;
    - implementations: every impl header naming WorkerObserver or KernelReads is one of OBSERVATION_IMPLS, in its file,
      each exactly once (no other, blanket, generic, primitive or path-qualified impl);
    - the fake kernel: fake_kernel, FakeKernel and convert_v3_config occur (read without comments, literal contents
      emptied) only in fake_kernel.rs, as lib.rs's one `pub mod fake_kernel;` and inside strict #[cfg(test)] mod tests
      blocks; fake_kernel.rs re-exports nothing, defines no struct but FakeKernel, no enum, union or trait, no impl but
      `impl FakeKernel` and `impl KernelReads for FakeKernel`, no type item but its one `type Pidfd`, and names neither
      KernelObserver nor WorkerObserver (no wrapper);
    - no linked source renames or aliases OBSERVATION_TYPES;
    - linux_os.rs: LinuxKernelReads's only fields are two KernelRoots, and the file names no static, thread_local! or
      once or lazy cell.
    The number of sources."""
    sources = linked_sources(base)
    rule = "observation rules"
    for rel in (OBSERVATION_RS, FAKE_KERNEL, EFFECT_GATE_LIB, LINUX_OS, OPENAT, GATE_MAIN):
        require((base / rel).is_file(), "%s is missing (%s)" % (rel, rule))
    kept, codes = {}, {}
    for rel, raw in sources:
        try:
            kept[rel], codes[rel] = rust_code(raw, literals=True), rust_code(raw)
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
    for word, home, definition, caller, calls, how in OBSERVATION_CALLERS:
        pattern = re.compile(r"\b%s\b" % word)
        for rel, code in kept.items():
            if rel not in (home, caller):
                require(not pattern.search(code), "%s names %s; only %s defines it and %s calls it (%s)"
                        % (rel, word, home, caller, rule))
        own = kept[home]
        require(len(pattern.findall(own)) == 1 and re.search(definition, own),
                "%s does not name %s exactly once, as its definition (%s)" % (home, word, rule))
        found = kept[caller]
        exact = [match for call in calls for match in call.finditer(found)]
        if how == "exactly":
            require(len(pattern.findall(found)) == len(calls) and len(exact) == len(calls)
                    and all(len(call.findall(found)) == 1 for call in calls),
                    "%s does not name %s exactly as its pinned calls (%s)" % (caller, word, rule))
        else:
            require(exact and len(pattern.findall(found)) == len(exact),
                    "%s names %s other than as a method call (%s)" % (caller, word, rule))
    definition = re.search(r"\bfn\s+open_after_seal\s*\(", kept[LINUX_OS])
    opening = kept[LINUX_OS].find("{", definition.end())
    body = (opening, block_end(kept[LINUX_OS], opening))
    for call in (CGROUP_ROOT_CALL, PROC_ROOT_CALL):
        position = call.search(kept[LINUX_OS]).start()
        require(body[0] < position < body[1], "%s opens a kernel root outside KernelRoots::open_after_seal (%s)"
                % (LINUX_OS, rule))
    seen = {header: 0 for header in OBSERVATION_IMPLS}
    for rel, code in codes.items():
        for _, header in impl_headers(rel, code):
            if not OBSERVATION_TRAITS.search(header):
                continue
            require(OBSERVATION_IMPLS.get(header) == rel, "%s holds the impl `%s`, not one of the observation's pinned "
                    "(trait, type) pairs (%s)" % (rel, header, rule))
            seen[header] += 1
    require(all(count == 1 for count in seen.values()), "the observation's impls are not each exactly once: %s (%s)"
            % (sorted(header for header, count in seen.items() if count != 1), rule))
    # HE-003A3 PR review round 1, R1-3 (carried to HE-004B1): the observers are pinned by path, not only by type name.
    # observation.rs defines no module outside its strict test module, Unobserved and KernelObserver each exactly once at
    # its top level, and its pinned impls lie at its top level, so no nested module holds a second observer type.
    own = codes[OBSERVATION_RS]
    for start, end in reversed(cfg_test_blocks(own)):
        own = own[:start] + " " + own[end:]
    require(not MODULE_ITEM.search(own), "%s defines a module outside its strict test module (%s, R1-3)"
            % (OBSERVATION_RS, rule))
    for name in OBSERVATION_HOME_TYPES:
        found = list(re.finditer(r"\b(?:struct|enum|union|type|trait)\s+%s\b" % name, own))
        require(len(found) == 1 and brace_depth(own, found[0].start()) == 0,
                "%s does not define %s exactly once at its top level (%s, R1-3)" % (OBSERVATION_RS, name, rule))
    for position, header in impl_headers(OBSERVATION_RS, own):
        require(header not in OBSERVATION_IMPLS or brace_depth(own, position) == 0,
                "%s holds `%s` below its top level (%s, R1-3)" % (OBSERVATION_RS, header, rule))
    for rel, code in codes.items():
        for pattern in OBSERVATION_ALIASES:
            require(not pattern.search(PATH_SPACE.sub("::", code)), "%s renames or aliases an observation type (%s)"
                    % (rel, rule))
        if rel == FAKE_KERNEL:
            continue
        rest = code
        if rel == EFFECT_GATE_LIB:
            require(len(FAKE_MOD.findall(rest)) == 1, "%s does not declare pub mod fake_kernel; exactly once (%s)"
                    % (rel, rule))
            rest = FAKE_MOD.sub(" ", rest, count=1)
        for start, end in reversed(cfg_test_blocks(rest)):
            rest = rest[:start] + " " + rest[end:]
        require(not FAKE_NAMES.search(rest), "%s names the fake kernel outside a strict #[cfg(test)] mod tests block "
                "(%s)" % (rel, rule))
    fake = codes[FAKE_KERNEL]
    require(not PUB_USE.search(fake) and not re.search(r"\buse\s+(?:self|super|crate)::fake_kernel\b", fake),
            "%s re-exports (%s)" % (FAKE_KERNEL, rule))
    require([match.group(0).split()[-1] for match in STRUCT_ITEM.finditer(fake)] == ["FakeKernel"],
            "%s defines a struct other than FakeKernel (%s)" % (FAKE_KERNEL, rule))
    require(not re.search(r"\b(?:enum|union|trait)\s+[A-Za-z_]", fake), "%s defines another type (%s)" % (FAKE_KERNEL, rule))
    require(sorted(header for _, header in impl_headers(FAKE_KERNEL, fake))
            == ["impl FakeKernel", "impl KernelReads for FakeKernel"],
            "%s holds an impl other than FakeKernel's two (%s)" % (FAKE_KERNEL, rule))
    exempt = pidfd_binding(FAKE_KERNEL, fake, rule)
    require([match.start() for match in TYPE_ITEM.finditer(fake)] == [exempt],
            "%s defines a type item other than its one type Pidfd (%s)" % (FAKE_KERNEL, rule))
    require(not re.search(r"\b(?:KernelObserver|WorkerObserver)\b", fake),
            "%s names an observer (a wrapper) (%s)" % (FAKE_KERNEL, rule))
    linux = codes[LINUX_OS]
    structs = [match for match in STRUCT_ITEM.finditer(linux) if match.group(0).split()[-1] == "LinuxKernelReads"]
    require(len(structs) == 1, "%s does not define LinuxKernelReads exactly once (%s)" % (LINUX_OS, rule))
    fields = struct_fields(linux, structs[0].end())
    require(len(fields) == 2 and all(ROOT_FIELD.fullmatch(field) for field in fields),
            "LinuxKernelReads's fields are not exactly two private KernelRoots (%s)" % rule)
    for pattern, name in LINUX_OS_STATE:
        require(not pattern.search(linux), "%s names %s (no cache for the observation's reads) (%s)" % (LINUX_OS, name, rule))
    return len(sources)


# --- HE-004D1: observer-sys's calls and NP-3, the capture wiring (DESIGN-D1 section 19) ---------------------------------

def observer_sources(base: Path, crates: tuple[str, ...] = (OBSERVER_CRATE, OBSERVER_SYS)) -> list[tuple[str, str]]:
    """(relative path, text) of every non-test source of crates/observer and observer-sys (or of `crates`)."""
    return [(path.relative_to(base).as_posix(), path.read_text(encoding="utf-8"))
            for crate in crates for path in sorted((base / crate / "src").rglob("*.rs"))]


def call_arguments(code: str, opening: int) -> list[str]:
    """The top-level arguments of the call whose `(` is at `opening` in a source read with literal contents emptied,
    each stripped (a trailing comma adds none)."""
    depth, start, arguments = 0, opening + 1, []
    for index in range(opening, len(code)):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                arguments.append(code[start:index].strip())
                return arguments[:-1] if arguments[-1] == "" else arguments
        elif char == "," and depth == 1:
            arguments.append(code[start:index].strip())
            start = index + 1
    raise GateError("a call without its closing parenthesis")


def body_of(code: str, definition: re.Pattern, what: str) -> tuple[int, int]:
    """(start, end) of the body of the one function `definition` finds in `code`; none or several refuse, naming
    `what`."""
    found = list(definition.finditer(code))
    require(len(found) == 1, "%s: not exactly one such function" % what)
    opening = code.find("{", found[0].end())
    require(opening >= 0, "%s: the function has no body" % what)
    return opening, block_end(code, opening)


def kernel_code(base: Path, rule: str) -> tuple[str, str, str]:
    """observer-sys's kernel.rs as (raw, code with literal contents emptied, code with literals kept), comments removed
    and the whitespace around `::` removed."""
    rel = OBSERVER_SYS_KERNEL
    require((base / rel).is_file(), "%s is missing (%s)" % (rel, rule))
    raw = (base / rel).read_text(encoding="utf-8")
    try:
        return raw, PATH_SPACE.sub("::", rust_code(raw)), PATH_SPACE.sub("::", rust_code(raw, literals=True))
    except GateError as error:
        raise GateError("%s: %s (%s)" % (rel, error, rule)) from None


def syscall_calls(code: str, rule: str) -> list[list[str]]:
    """The arguments of every call of the foreign item syscall in kernel.rs's code (literal contents emptied), after
    checking that the word occurs exactly once as its extern declaration and otherwise only as plain calls (G-D1-3)."""
    rel = OBSERVER_SYS_KERNEL
    blocks = [(block.end() - 1, block_end(code, block.end() - 1)) for block in EXTERN_BLOCK.finditer(code)]
    declarations, calls = 0, []
    for word in SYSCALL_WORD.finditer(code):
        before, after = code[:word.start()], code[word.end():]
        if re.match(r"\s*\(", after) and re.search(r"\bfn\s+$", before):
            require(any(start < word.start() < end for start, end in blocks),
                    "%s defines fn syscall( outside its extern block (%s)" % (rel, rule))
            declarations += 1
            continue
        require(re.match(r"\s*\(", after) and not re.search(r"(?:::|\.|\bas|\buse)\s*$", before),
                "%s names syscall other than as its extern declaration and plain calls (a reference, path, import or "
                "rename) (%s)" % (rel, rule))
        calls.append(call_arguments(code, code.index("(", word.end())))
    require(declarations == 1, "%s does not declare fn syscall( exactly once (%s)" % (rel, rule))
    return calls


def defined_once(code: str, name: str, value: int | None = None) -> bool:
    """Whether `name` is bound exactly once (a const, static or let) and, with `value`, as `const <name>: c_long =
    <value>;` (decimal, octal or hexadecimal, underscores allowed)."""
    bindings = re.findall(r"\b(?:const|static|let)\s+(?:mut\s+)?%s\b" % name, code)
    if len(bindings) != 1:
        return False
    if value is None:
        return True
    found = re.search(r"\bconst\s+%s\s*:\s*c_long\s*=\s*(0[xX][0-9A-Fa-f_]+|0[oO][0-7_]+|[0-9_]+)\s*;" % name, code)
    return bool(found) and int(found.group(1).replace("_", ""), 0) == value


def check_observer_sys_calls(base: Path) -> int:
    """HE-004D1 DESIGN-D1 sections 4.1 and 19 (G-D1-3, D1-6): kernel.rs's calls of syscall. The word syscall is its
    extern declaration once and otherwise only plain calls; every call has exactly seven arguments, the first one of the
    six SYS_ constants; each SYS_ constant is defined once in each target's numbers module with its pinned value, no
    other exists, and the names occur only there and as calls' first arguments (a shadowing let or const refuses);
    openat's flags (the fourth argument), ioctl's request (the third) and bpf's command (the second) are single named
    constants, the request FS_IOC_MEASURE_VERITY and the command one of the three BPF commands, each defined once with
    its pinned value. No other observer or observer-sys source names syscall or a SYS_ constant (R4-2). The number of
    calls."""
    rule = "observer-sys calls, G-D1-3"
    rel = OBSERVER_SYS_KERNEL
    raw, code, kept = kernel_code(base, rule)
    calls = syscall_calls(code, rule)
    names = set(SYS_NUMBERS["x86_64"])
    found = {}
    for module in NUMBERS_MODULE.finditer(kept):
        arch = module.group(1)
        require(arch not in found, "%s holds two numbers modules for %s (%s)" % (rel, arch, rule))
        body = kept[module.end():block_end(kept, module.end() - 1) - 1]
        numbers = {}
        for item in re.finditer(r"\bconst\s+(SYS_[A-Za-z0-9_]+)\s*:\s*c_long\s*=\s*([0-9_]+)\s*;", body):
            require(item.group(1) not in numbers, "%s defines %s twice for %s (%s)" % (rel, item.group(1), arch, rule))
            numbers[item.group(1)] = int(item.group(2).replace("_", ""))
        require(numbers == SYS_NUMBERS[arch], "%s's %s call numbers are %s, not the pinned %s (%s)"
                % (rel, arch, sorted(numbers.items()), sorted(SYS_NUMBERS[arch].items()), rule))
        found[arch] = numbers
    require(set(found) == set(SYS_NUMBERS), "%s does not define the call numbers in one numbers module per target (%s)"
            % (rel, rule))
    words = [match.group(0) for match in SYS_NAME.finditer(code)]
    require(set(words) <= names, "%s names %s, not one of the six calls' numbers (%s)"
            % (rel, sorted(set(words) - names), rule))
    require(len(re.findall(r"\bconst\s+SYS_", code)) == 2 * len(names) and not re.search(r"\b(?:let|static)\s+(?:mut\s+)?SYS_",
                                                                                          code),
            "%s binds a SYS_ name outside its numbers modules (a shadow) (%s)" % (rel, rule))
    require(len(words) == 2 * len(names) + len(calls),
            "%s names a SYS_ constant other than in its definitions and as a call's first argument (%s)" % (rel, rule))
    for arguments in calls:
        require(len(arguments) == 7, "%s calls syscall with %d arguments, not seven (%s)" % (rel, len(arguments), rule))
        number = arguments[0]
        require(number in names, "%s calls syscall with the number %r, not one of the six SYS_ constants (%s)"
                % (rel, number[:40], rule))
        if number in SYS_CHECKED:
            value = arguments[SYS_CHECKED[number]]
            require(re.fullmatch(r"[A-Za-z_]\w*", value), "%s's %s call passes %r in its checked position, not a named "
                    "constant (%s)" % (rel, number, value[:40], rule))
            allowed = {"SYS_OPENAT": OPEN_FLAG_SETS, "SYS_IOCTL": tuple(IOCTL_REQUESTS), "SYS_BPF": tuple(BPF_COMMANDS)}
            require(value in allowed[number], "%s's %s call passes %s, not one of %s (%s)"
                    % (rel, number, value, ", ".join(allowed[number]), rule))
    for name, value in list(IOCTL_REQUESTS.items()) + list(BPF_COMMANDS.items()):
        require(defined_once(code, name, value), "%s does not define %s once as %#x (%s)" % (rel, name, value, rule))
    for other, text in observer_sources(base):
        if other == rel:
            continue
        try:
            other_code = rust_code(text)
        except GateError as error:
            raise GateError("%s: %s (%s)" % (other, error, rule)) from None
        require(not SYSCALL_WORD.search(other_code) and not SYS_NAME.search(other_code),
                "%s names syscall or a SYS_ constant; only %s calls the foreign item (%s)" % (other, rel, rule))
    return len(calls)


def check_observer_read_only(base: Path) -> int:
    """HE-004D1 DESIGN-D1 sections 4.5, 9.4 and 19 (G-D1-4, NP-3): in kernel.rs every openat call's flags are one of the
    four named sets, each defined once from the read-only flags only and carrying its compile-time assert against the
    OBSERVER row's write-and-create mask 0x400643; kernel.rs's cgroup file names (its dotted string literals) are
    exactly the seven of section 4.5, each once; no observer or observer-sys source names freeze (raw text, so
    "cgroup.freeze" too); and observer-sys's code names no write, Write or write_all. The number of openat calls."""
    rule = "observer read-only rule, G-D1-4 (NP-3)"
    rel = OBSERVER_SYS_KERNEL
    raw, code, kept = kernel_code(base, rule)
    for other, text in observer_sources(base):
        require(not FREEZE_WORD.search(text), "%s names freeze (%s)" % (other, rule))
    for name in OPEN_FLAG_SETS:
        definitions = list(re.finditer(r"\bconst\s+%s\s*:\s*c_long\s*=\s*([^;]*);" % name, code))
        require(len(definitions) == 1 and defined_once(code, name), "%s does not define %s exactly once (%s)"
                % (rel, name, rule))
        terms = [term.strip() for term in definitions[0].group(1).split("|")]
        require(all(term in READ_ONLY_FLAGS for term in terms), "%s's %s is built from %s, not only the read-only flags "
                "%s (%s)" % (rel, name, " | ".join(terms), ", ".join(READ_ONLY_FLAGS), rule))
        squeezed = "".join(code.split())
        asserts = squeezed.count("const_:()=assert!(%s&%s==0);" % (name, WRITE_MASK))
        require(asserts == 1, "%s lacks %s's compile-time assert against %s (%s)" % (rel, name, WRITE_MASK, rule))
    opens = [arguments for arguments in syscall_calls(code, rule) if arguments[:1] == ["SYS_OPENAT"]]
    for arguments in opens:
        require(len(arguments) > 3 and arguments[3] in OPEN_FLAG_SETS, "%s opens with %r, not one of the named sets %s "
                "(%s)" % (rel, arguments[3][:40] if len(arguments) > 3 else "", ", ".join(OPEN_FLAG_SETS), rule))
    names = DOTTED_NAME.findall(kept)
    require(sorted(names) == sorted(CGROUP_FILE_NAMES), "%s's cgroup file names are %s, not exactly the seven %s, each once "
            "(%s)" % (rel, sorted(names), ", ".join(CGROUP_FILE_NAMES), rule))
    for other, text in observer_sources(base):
        if other.startswith(OBSERVER_SYS + "/"):
            try:
                other_code = rust_code(text)
            except GateError as error:
                raise GateError("%s: %s (%s)" % (other, error, rule)) from None
            require(not WRITE_WORDS.search(other_code), "%s names write, Write or write_all (%s)" % (other, rule))
    return len(opens)


def check_observer_capture_callers(base: Path) -> int:
    """HE-004D1 DESIGN-D1 sections 17.3 and 19 (G-D1-6, D1-12, R2-1): among crates/observer's sources only
    linux_capture.rs names observer_sys (raw text); linux_capture.rs re-exports nothing and no pub fn, type, const or
    static, pub struct field or pub enum variant of it names an observer-sys type (the R1-3 socket-item shape); read
    without comments and with the whitespace around `::` removed, LinuxCapture::new occurs only as the one call
    `LinuxCapture::new(sealed)` inside main.rs's serve, `impl LinuxCapture` (with its `fn new(`) and `struct
    LinuxCapture` only in linux_capture.rs, and LinuxCapture is renamed or aliased nowhere. HE-004D2 (G-D2-11, R1-5): the
    constructor is counted in its qualified forms too (`<LinuxCapture>::new`, `< LinuxCapture >::new`). HE-004D2 PR review
    round 2 (R2-1): LinuxWire is renamed or aliased nowhere either, and a parenthesised aliased type counts. Round 3
    (R3-1): no `type` item names either type, with any whitespace (a parenthesised, defaulted, where-clause or projected
    alias), and each type is named in code only in its own file (linux_capture.rs, linux_net.rs) and inside main.rs's fn
    serve. The number of sources."""
    rule = "capture callers, G-D1-6"
    sources = observer_sources(base, (OBSERVER_CRATE,))
    for rel in (OBSERVER_LINUX_CAPTURE, OBSERVER_MAIN):
        require((base / rel).is_file(), "%s is missing (%s)" % (rel, rule))
    for rel, raw in sources:
        require(rel == OBSERVER_LINUX_CAPTURE or not re.search(r"\bobserver_sys\b", raw),
                "%s names observer_sys; only %s does (%s)" % (rel, OBSERVER_LINUX_CAPTURE, rule))
        try:
            code = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
        # R2-1: LinuxWire as well, so serve's one naming of each type is its one counted construction (an alias elsewhere
        # in the crate would let serve construct it again under another name; serve's own control flow is R5-1's).
        # R3-1: a `type` item naming either type anywhere up to its `;` is an alias, whatever its whitespace, bounds,
        # defaults or projection. R4-1: the item is read to its `;` at bracket depth 0 (item_text), so a `;` inside an
        # array type or a block does not end it early.
        try:
            type_items = [item_text(code, found.start(), "type") for found in re.finditer(r"\btype\b", code)]
        except GateError:
            raise GateError("%s holds a type item the alias rule cannot read (%s)" % (rel, rule)) from None
        for constructed in ("LinuxCapture", "LinuxWire"):
            named = re.compile(r"\b%s\b" % constructed)
            require(not re.search(r"\b{0}\s+as\b|\bas\s+{0}\b".format(constructed), code)
                    and not any(named.search(text) for text in type_items),
                    "%s renames or aliases %s (%s)" % (rel, constructed, rule))
        calls = list(LINUX_CAPTURE_NEW.finditer(code))
        impls = list(re.finditer(r"\bimpl\s+LinuxCapture\s*\{", code))
        structs = list(re.finditer(r"\bstruct\s+LinuxCapture\b", code))
        if rel == OBSERVER_MAIN:
            serve = body_of(code, FN_SERVE, "%s's fn serve (%s)" % (rel, rule))
            exact = list(re.finditer(r"\bLinuxCapture::new\(\s*sealed\s*\)", code))
            require(len(calls) == 1 and len(exact) == 1 and exact[0].start() == calls[0].start()
                    and serve[0] < calls[0].start() < serve[1],
                    "%s does not call LinuxCapture::new exactly once, as LinuxCapture::new(sealed) in serve (%s)"
                    % (rel, rule))
        else:
            require(not calls, "%s names LinuxCapture::new; only main.rs's serve calls it (%s)" % (rel, rule))
        if rel == OBSERVER_LINUX_CAPTURE:
            require(len(impls) == 1 and len(structs) == 1, "%s does not define LinuxCapture and its impl exactly once (%s)"
                    % (rel, rule))
            opening = impls[0].end() - 1
            require(re.search(r"\bfn\s+new\s*\(", code[opening:block_end(code, opening)]),
                    "%s's impl LinuxCapture has no fn new (%s)" % (rel, rule))
            require(not PUB_USE.search(code), "%s re-exports with pub use (%s)" % (rel, rule))
            check_observer_sys_items(rel, raw, code, rule)
        else:
            require(not impls and not structs, "%s defines LinuxCapture or its inherent impl; only %s does (%s)"
                    % (rel, OBSERVER_LINUX_CAPTURE, rule))
        # R3-1: each type is named in code only in its own file and inside main.rs's serve (its import and its one
        # construction), which also closes a generic default or projection naming it in any other file.
        for constructed, home in (("LinuxCapture", OBSERVER_LINUX_CAPTURE), ("LinuxWire", OBSERVER_LINUX_NET)):
            if rel == home:
                continue
            named = [found.start() for found in re.finditer(r"\b%s\b" % constructed, code)]
            if rel == OBSERVER_MAIN:
                serve = body_of(code, FN_SERVE, "%s's fn serve (%s)" % (rel, rule))
                named = [at for at in named if not serve[0] < at < serve[1]]
            require(not named, "%s names %s outside %s and main.rs's serve (%s, R3-1)" % (rel, constructed, home, rule))
    return len(sources)


def check_observer_sys_items(rel: str, raw: str, code: str, rule: str) -> None:
    """The R1-3 shape for linux_capture.rs (G-D1-6): no pub fn signature, type, const or static, pub struct field or pub
    enum variant names an observer-sys item (by a qualified path, an imported module or an imported name)."""
    modules, items = {"observer_sys"}, {}
    for path, rename in source_uses(rel, raw):
        if path[0] != "observer_sys":
            continue
        require(path[-1] != "*", "%s imports a glob of observer-sys (%s)" % (rel, rule))
        if path[-1] == "self":
            modules.add(rename or path[-2])
        else:
            items[rename or path[-1]] = path[-1]

    def hazards(text: str) -> list[str]:
        named = set()
        for module in modules:
            named |= set(re.findall(r"(?<!::)\b%s::(\w+)" % re.escape(module), text))
        named |= {original for binding, original in items.items() if re.search(r"(?<!::)\b%s\b" % re.escape(binding), text)}
        return sorted(named)

    for item in PUB_ITEM.finditer(code):
        found = hazards(item_text(code, item.start(), item.group(1)))
        require(not found, "%s has a pub item naming observer-sys's items %s (%s)" % (rel, found, rule))
    for struct in STRUCT_ITEM.finditer(code):
        for field in struct_fields(code, struct.end()):
            if re.match(r"\s*(?:#\s*\[[^\]]*\]\s*)*pub\b", field):
                found = hazards(field)
                require(not found, "%s has a pub field naming observer-sys's items %s (%s)" % (rel, found, rule))
    for enum in PUB_ENUM.finditer(code):
        for types in enum_variant_types(code, enum.end()):
            found = hazards(types)
            require(not found, "%s has a pub enum variant naming observer-sys's items %s (%s)" % (rel, found, rule))


def check_observer_links(base: Path) -> int:
    """HE-004D1 DESIGN-D1 sections 4.5, 9.1 and 19 (G-D1-7, R2-6): in kernel.rs (read without comments, literals kept)
    link_text is named once, as its definition; ProcLink has five variants and its name table exactly the five names
    exe, ns/user, ns/mnt, ns/pid and ns/net; own_pid is named once, as its definition; their one helper link_at is
    named three times, its definition, the call on ProcLink's name inside link_text and the call on the proc root's
    `self` link inside own_pid. Among the observer's and observer-sys's other sources only linux_capture.rs names
    link_text and own_pid, as method calls. gate-sys's read_link and readlinkat rules stay as they are. The number of
    link reads."""
    rule = "link reads, G-D1-7"
    rel = OBSERVER_SYS_KERNEL
    raw, code, kept = kernel_code(base, rule)
    for word in ("link_text", "own_pid"):
        require(len(re.findall(r"\b%s\b" % word, kept)) == 1 and re.search(r"\bfn\s+%s\s*\(" % word, kept),
                "%s does not name %s exactly once, as its definition (%s)" % (rel, word, rule))
    enum = re.search(r"\benum\s+ProcLink\s*\{", code)
    require(enum, "%s defines no enum ProcLink (%s)" % (rel, rule))
    variants = re.findall(r"[A-Za-z_]\w*", code[enum.end():block_end(code, enum.end() - 1) - 1])
    require(len(variants) == len(PROC_LINK_NAMES), "%s's ProcLink has %d variants, not %d (%s)"
            % (rel, len(variants), len(PROC_LINK_NAMES), rule))
    table = list(re.finditer(r"\bimpl\s+ProcLink\s*\{", kept))
    require(len(table) == 1, "%s does not hold exactly one impl ProcLink (%s)" % (rel, rule))
    opening = table[0].end() - 1
    literals = re.findall(r'"([^"\\]*)"', kept[opening:block_end(kept, opening)])
    require(sorted(literals) == sorted(PROC_LINK_NAMES), "%s's ProcLink names are %s, not exactly %s (%s)"
            % (rel, sorted(literals), ", ".join(PROC_LINK_NAMES), rule))
    require(len(re.findall(r"\blink_at\b", kept)) == 3 and re.search(r"\bfn\s+link_at\s*\(", kept),
            "%s does not name link_at exactly as its definition and its two calls (%s)" % (rel, rule))
    for function, call in (("link_text", LINK_TEXT_CALL), ("own_pid", OWN_PID_CALL)):
        start, end = body_of(kept, re.compile(r"\bfn\s+%s\s*\(" % function), "%s's fn %s (%s)" % (rel, function, rule))
        found = list(call.finditer(kept))
        require(len(found) == 1 and start < found[0].start() < end, "%s's %s does not read exactly its one pinned link "
                "(%s)" % (rel, function, rule))
    calls = 0
    for other, text in observer_sources(base):
        if other == rel:
            continue
        try:
            other_kept = rust_code(text, literals=True)
        except GateError as error:
            raise GateError("%s: %s (%s)" % (other, error, rule)) from None
        for word in ("link_text", "own_pid"):
            named = len(re.findall(r"\b%s\b" % word, other_kept))
            if other == OBSERVER_LINUX_CAPTURE:
                method_calls = len(re.findall(r"\.\s*%s\s*\(" % word, other_kept))
                require(named and named == method_calls, "%s names %s other than as a method call (%s)"
                        % (other, word, rule))
                calls += method_calls
            else:
                require(not named, "%s names %s; only %s calls it (%s)" % (other, word, OBSERVER_LINUX_CAPTURE, rule))
    return calls


def function_bodies(code: str) -> list[tuple[str, int, int, int]]:
    """Each function with a body in a source read without comments and with literal contents emptied: (its name, the
    start of `fn`, its body's opening brace, the index after its closing brace). Extern declarations end with `;`."""
    found = []
    for match in re.finditer(r"\bfn\s+([A-Za-z_]\w*)", code):
        depth, index = 0, match.end()
        while index < len(code):
            char = code[index]
            if char in "([":
                depth += 1
            elif char in ")]":
                depth -= 1
            elif depth == 0 and char in "{;":
                break
            index += 1
        if index < len(code) and code[index] == "{":
            found.append((match.group(1), match.start(), index, block_end(code, index)))
    return found


def check_observer_sys_names(base: Path) -> int:
    """HE-004D1 PR review round 1, R1-2 (G-D1-3, G-D1-4, G-D1-7): the names the observer-sys pins read cannot be rebound
    in kernel.rs (read without comments, literal contents emptied, the whitespace around `::` removed). No use declaration
    renames (`use .. as`); no function body holds an item (BODY_ITEM: fn, const, static, use, impl, mod, struct, enum,
    union, trait, type, extern, macro_rules or macro); each of the four flag sets occurs exactly in its definition, its
    assert and the openat calls passing it, and the verity request and each BPF command exactly in its definition and
    the calls passing it (counted as G-D1-3 counts the SYS_ names); and on the link-read path (LINK_PATH_NAMES) the
    free function `name` and `link_at` are named exactly as pinned in `link_text`, `own_pid` and `link_at`, whose `let`
    patterns and closure parameters bind no name kernel.rs defines at its top level. PR review round 2, R2-2: the
    no-rename rule covers every observer-sys source (lib.rs's re-exports included). The number of function bodies."""
    rule = "observer-sys pinned names, R1-2"
    rel = OBSERVER_SYS_KERNEL
    raw, code, kept = kernel_code(base, rule)
    # PR review round 2, R2-2: no renaming use (a `pub use .. as` re-export included) in any observer-sys source.
    for source, text in observer_sources(base, (OBSERVER_SYS,)):
        for path, rename in source_uses(source, text):
            require(rename is None, "%s renames %s as %s in a use declaration (%s)" % (source, "::".join(path), rename, rule))
    bodies = function_bodies(code)
    for function, _, opening, end in bodies:
        item = BODY_ITEM.search(code, opening + 1, end - 1)
        require(not item, "%s holds an item (%s) inside fn %s's body (%s)" % (rel, item.group(0) if item else "", function,
                                                                          rule))
    calls = syscall_calls(code, rule)
    counted = [(name, 2, "SYS_OPENAT", 3) for name in OPEN_FLAG_SETS]
    counted += [(name, 1, "SYS_IOCTL", 2) for name in IOCTL_REQUESTS]
    counted += [(name, 1, "SYS_BPF", 1) for name in BPF_COMMANDS]
    for name, fixed, number, position in counted:
        passed = sum(1 for arguments in calls if arguments[:1] == [number] and len(arguments) > position
                     and arguments[position] == name)
        found = len(re.findall(r"\b%s\b" % name, code))
        require(found == fixed + passed, "%s names %s %d times, not exactly %d (its definition%s and the %d calls passing "
                "it) (%s)" % (rel, name, found, fixed + passed, " and assert" if fixed == 2 else "", passed, rule))
    require(len(re.findall(r"\blink_at\b", code)) == 3, "%s does not name link_at exactly as its definition and its two "
            "calls (%s)" % (rel, rule))
    top = {name for name in re.findall(r"\b(?:const|static)\s+(?:mut\s+)?([A-Za-z_]\w*)\s*:", code) if name != "_"}
    top |= {match.group(1) for match in re.finditer(r"\bfn\s+([A-Za-z_]\w*)", code) if brace_depth(code, match.start()) == 0}
    top |= {"syscall"}
    free = [match.start() for match in re.finditer(r"\bfn\s+name\s*\(", code) if brace_depth(code, match.start()) == 0]
    require(len(free) == 1, "%s does not define the free fn name exactly once at its top level (%s)" % (rel, rule))
    for function, (free_calls, method_calls, plain) in LINK_PATH_NAMES.items():
        spans = [(start, opening, end) for name, start, opening, end in bodies if name == function]
        require(len(spans) == 1, "%s does not define fn %s exactly once (%s)" % (rel, function, rule))
        start, opening, end = spans[0]
        body = code[opening + 1:end - 1]
        words = [match for match in re.finditer(r"\bname\b", body)]
        found = (sum(1 for match in words if re.match(r"\s*\(", body[match.end():])
                     and not re.search(r"\.\s*$", body[:match.start()])),
                 sum(1 for match in words if re.match(r"\s*\(", body[match.end():]) and re.search(r"\.\s*$", body[:match.start()])),
                 sum(1 for match in words if not re.match(r"\s*\(", body[match.end():])))
        require(found == (free_calls, method_calls, plain), "%s's %s names `name` as %d calls, %d method calls and %d other "
                "words, not %d, %d and %d (%s)" % (rel, function, *found, free_calls, method_calls, plain, rule))
        signature = code[start:opening]
        require(len(re.findall(r"\bname\b", signature)) == (1 if plain else 0),
                "%s's %s binds `name` in its signature other than as pinned (%s)" % (rel, function, rule))
        bound = []
        for word in re.finditer(r"\blet\b", body):
            bound += re.findall(r"[A-Za-z_]\w*", let_pattern(body, word.end()))
        for closure in re.finditer(r"(?:(?<=[(,=])|(?<=\bmove))\s*\|([^|]*)\|", body):
            bound += re.findall(r"[A-Za-z_]\w*", closure.group(1))
        shadowed = sorted(set(bound) & top)
        require(not shadowed, "%s's %s binds %s, which kernel.rs defines at its top level (%s)"
                % (rel, function, ", ".join(shadowed), rule))
    return len(bodies)


def pinned_text(kept: str, function: str, rule: str) -> str:
    """The one function `function` of a source read without comments and with literals kept, from its visibility (the
    text after the previous item's `}`, `;` or the enclosing `{`) to its closing brace, as LINK_TOKEN tokens joined by
    single spaces."""
    spans = [span for span in function_bodies(kept) if span[0] == function]
    require(len(spans) == 1, "%s: not exactly one fn %s (%s)" % (OBSERVER_SYS_KERNEL, function, rule))
    _, start, _, end = spans[0]
    prefix = max(kept.rfind("}", 0, start), kept.rfind(";", 0, start), kept.rfind("{", 0, start)) + 1
    return " ".join(LINK_TOKEN.findall(kept[prefix:end]))


def check_observer_link_pins(base: Path) -> int:
    """HE-004D1 PR review round 2, R2-1 (G-D1-7): kernel.rs's `link_text`, `own_pid` and `link_at`, signatures and bodies,
    equal their pinned token texts (LINK_PATH_PINS) after whitespace normalisation; any edit refuses. The number of
    pinned functions."""
    rule = "link-read path pinned, R2-1"
    rel = OBSERVER_SYS_KERNEL
    _, _, kept = kernel_code(base, rule)
    for function, pinned in LINK_PATH_PINS.items():
        require(pinned_text(kept, function, rule) == pinned,
                "%s's fn %s differs from its pinned signature and body (%s)" % (rel, function, rule))
    return len(LINK_PATH_PINS)


def check_observer_sys_pins(base: Path) -> int:
    """HE-004D1 PR review round 3, R3-1: every OBSERVER_SYS_PINS file is present, not a symlink, and byte-exact (its
    sha256 equals its pin). The number of pinned files."""
    for rel, expected in OBSERVER_SYS_PINS.items():
        path = base / rel
        require(path.is_file() and not path.is_symlink(), "%s is missing or a symlink (observer-sys pin, R3-1)" % rel)
        require(sha256(path.read_bytes()) == expected, "%s differs from its pinned bytes (observer-sys pin, R3-1)" % rel)
    return len(OBSERVER_SYS_PINS)


def check_observer_home_pins(base: Path) -> int:
    """HE-004D2 owner decision Q-D2-END (a): every OBSERVER_HOME_PINS file is present, not a symlink, and byte-exact (its
    sha256 equals its pin). The number of pinned files."""
    for rel, expected in OBSERVER_HOME_PINS.items():
        path = base / rel
        require(path.is_file() and not path.is_symlink(), "%s is missing or a symlink (constructor home pin, Q-D2-END)" % rel)
        require(sha256(path.read_bytes()) == expected,
                "%s differs from its pinned bytes (constructor home pin, Q-D2-END)" % rel)
    return len(OBSERVER_HOME_PINS)


def check_i01b_contracts(base: Path) -> int:
    """HE-004-I01B1 G-I01B-2 (DESIGN-I01B rev 3 sections 2 and 6, DESIGN-I01B1 rev 2 section 4): edge record v10's rows
    69-72 (I01B_EDGE_V10_ROWS). Each file is registered in CONTRACTS at its row's sha256; it is present, a regular file
    and not a symlink, of mode 100644 (no execute bit), and its bytes have that sha256; contracts/PROVENANCE.md holds
    exactly one provenance line for it (the file, `from` its provider path, its sha256 and `<length> bytes`, in the
    section's form), with its row's provider path and sha256 and its length; and it is not embedded: it is not in
    OBSERVER_EMBEDDED_CONTRACTS, and
    no crate source under crates/*/src holds an include_bytes! or include_str! literal that resolves to it. The number of
    files.

    HE-004-I01B4 (DESIGN-I01B4 rev 2 section 5): the same rule over edge record v11's rows 73-79 (I01B_EDGE_V11_ROWS),
    each refusal naming its record (v10 or v11) and row; the embedding refusal covers both tables. 4 + 7 = 11 files."""
    rule = "the I01 digest contract files, G-I01B-2"
    provenance_path = base / "contracts/PROVENANCE.md"
    require(provenance_path.is_file() and not provenance_path.is_symlink(),
            "contracts/PROVENANCE.md is missing or a symlink (%s)" % rule)
    provenance = provenance_path.read_text(encoding="utf-8")
    tables = (("v10", I01B_EDGE_V10_ROWS), ("v11", I01B_EDGE_V11_ROWS))
    for record, rows in tables:
        for rel, (row, provider, expected) in rows.items():
            require(CONTRACTS.get(rel) == expected,
                    "%s is not registered at edge record %s's row %d sha256 (%s)" % (rel, record, row, rule))
            path = base / rel
            require(path.is_file() and not path.is_symlink(), "%s is missing or a symlink (%s)" % (rel, rule))
            require(not path.stat().st_mode & 0o111, "%s is not mode 100644 (%s)" % (rel, rule))
            data = path.read_bytes()
            require(sha256(data) == expected, "%s differs from edge record %s's row %d (%s)" % (rel, record, row, rule))
            lines = re.findall(r"(?m)^- `%s` from `([^`]*)`, sha256 `([0-9a-f]{64})`, (\d+) bytes$" % re.escape(rel),
                               provenance)
            require(lines == [(provider, expected, str(len(data)))],
                    "%s has not exactly one PROVENANCE.md line with its provider path, sha256 and length (%s)"
                    % (rel, rule))
            require(rel not in OBSERVER_EMBEDDED_CONTRACTS, "%s is embedded (%s)" % (rel, rule))
    held = {rel for _, rows in tables for rel in rows}
    for path in sorted((base / "crates").glob("*/src/**/*.rs")):
        source = path.relative_to(base).as_posix()
        for literal in OBSERVER_INCLUDE_FORM.findall(path.read_text(encoding="utf-8")):
            target = posixpath.normpath(posixpath.join(posixpath.dirname(source), literal))
            require(target not in held, "%s embeds %s (%s)" % (source, target, rule))
    return len(held)


def i01b4_folded(name: str) -> str:
    """G-I01B4-1's reading of a name: casefolded, with underscores and hyphens removed."""
    return name.casefold().replace("_", "").replace("-", "")


def check_i01b4_replay_scope(base: Path) -> int:
    """HE-004-I01B4 G-I01B4-1, the absence clause (DESIGN-I01B4 rev 2 section 5; Q-I01B4-5; the section review's I4D-1
    and I4D-2): R10 replays the I01 digest contract v2's 321 checks and runs no profile v2 validator.
    - (a) No CONTRACTS path and no file or directory under contracts/ has the basename profile.schema.json (casefolded),
      and no CONTRACTS digest and no file under contracts/ is profile v2's schema by its sha256.
    - Every .rs file under crates/*/src and crates/*/tests is read without comments, literals kept (rust_code; one it
      cannot lex refuses).
    - (b) Its include_bytes! and include_str! literals resolve against its directory (posixpath.normpath, as
      check_i01b_contracts resolves them): exactly one, in the digest replay (I01B4_ROW79_READER), resolves to row
      79's file, and none in any other source; row 79's file name occurs in the digest replay only in that literal,
      and in no other source (a concat! form or a runtime read included).
    - (c) No fn or mod is named validate_profile or precondition, or has profile_v2 in its name.
    - (c1) No fn, mod, struct, enum, trait, type, const, static or macro_rules identifier, a leading r# stripped and
      read with i01b4_folded, is validateprofile, precondition or preconditions, or contains proxyprofilev2.
    - (c2) No part of a source's path below its crate (each directory, and the file's stem), read with i01b4_folded,
      contains profilev2 unless it also contains nativeprofile.
    - (c3) No source but the digest replay holds one of row 79's 28 distinct negative expect texts (read from the
      vendored file) or profile v2's schema sha256.
    The number of crate sources read."""
    rule = "the replay scope, G-I01B4-1"
    for rel, digest in CONTRACTS.items():
        require(posixpath.basename(rel).casefold() != PROFILE_V2_SCHEMA_NAME,
                "CONTRACTS registers %s, profile v2's schema by name (%s)" % (rel, rule))
        require(digest != PROFILE_V2_SCHEMA_SHA256, "CONTRACTS registers %s at profile v2's schema sha256 (%s)" % (rel, rule))
    for path in sorted((base / "contracts").rglob("*")):
        rel = path.relative_to(base).as_posix()
        require(path.name.casefold() != PROFILE_V2_SCHEMA_NAME, "%s is profile v2's schema by name (%s)" % (rel, rule))
        if path.is_file():
            require(sha256(path.read_bytes()) != PROFILE_V2_SCHEMA_SHA256,
                    "%s holds profile v2's schema bytes (%s)" % (rel, rule))
    try:
        negatives = json.loads((base / I01B4_ROW79).read_text(encoding="utf-8"))["negative"]
        texts = sorted({row["expect"] for row in negatives})
    except (OSError, ValueError, KeyError, TypeError):
        raise GateError("%s has no readable negative expect texts (%s)" % (I01B4_ROW79, rule)) from None
    require(len(texts) == I01B4_ROW79_TEXTS and all(type(text) is str and text for text in texts),
            "%s does not hold %d distinct negative expect texts (%s)" % (I01B4_ROW79, I01B4_ROW79_TEXTS, rule))
    file_name = posixpath.basename(I01B4_ROW79)
    sources = sorted((base / "crates").glob("*/src/**/*.rs")) + sorted((base / "crates").glob("*/tests/**/*.rs"))
    reader_includes = 0
    for path in sources:
        rel = path.relative_to(base).as_posix()
        try:
            code = rust_code(path.read_text(encoding="utf-8"), literals=True)
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
        reader = rel == I01B4_ROW79_READER
        targets = [posixpath.normpath(posixpath.join(posixpath.dirname(rel), literal))
                   for literal in OBSERVER_INCLUDE_FORM.findall(code)]
        includes = targets.count(I01B4_ROW79)
        require(reader or not includes, "%s includes %s, which only %s may (%s)" % (rel, I01B4_ROW79, I01B4_ROW79_READER,
                                                                                    rule))
        if reader:
            reader_includes = includes
            require(code.count(file_name) == includes,
                    "%s names %s other than in its include literal (%s)" % (rel, file_name, rule))
        else:
            require(file_name not in code, "%s names %s (%s)" % (rel, file_name, rule))
        for kind, macro, name in I01B4_ITEM.findall(code):
            kind = kind or macro
            require(kind not in ("fn", "mod") or (name not in I01B4_FN_MOD_NAMES and I01B4_FN_MOD_PART not in name),
                    "%s declares %s %s, a profile v2 validator's name (%s, clause (c))" % (rel, kind, name, rule))
            folded = i01b4_folded(name)
            require(folded not in I01B4_ITEM_NAMES and I01B4_ITEM_PART not in folded,
                    "%s declares %s %s, a profile v2 validator's name (%s, clause (c1))" % (rel, kind, name, rule))
        for part in rel.split("/")[2:]:
            folded = i01b4_folded(part[:-3] if part.endswith(".rs") else part)
            require(I01B4_PATH_PART not in folded or I01B4_PATH_EXEMPT in folded,
                    "%s is named after profile v2 (%s, clause (c2))" % (rel, rule))
        if not reader:
            for text in texts:
                require(text not in code, "%s holds row 79's negative text %r (%s, clause (c3))" % (rel, text, rule))
            require(PROFILE_V2_SCHEMA_SHA256 not in code,
                    "%s holds profile v2's schema sha256 (%s, clause (c3))" % (rel, rule))
    require(reader_includes == 1, "%s does not include %s exactly once (%s)" % (I01B4_ROW79_READER, I01B4_ROW79, rule))
    return len(sources)


def casefold_siblings(directory: str, entries: list[str], names: set[str], rule: str) -> None:
    """HE-004-I01B1 R-B3-PIN, I1D-10's casefold clause over one directory's listing (entry names, so the clause is
    exercised on any file system; PR review round 1, R1-4): an entry whose casefold equals a guarded name's, other than
    that name itself, refuses."""
    folded = {name.casefold(): name for name in names}
    for entry in sorted(entries):
        name = folded.get(entry.casefold())
        require(name is None or entry == name, "%s/%s casefolds to the guarded name %s (%s, I1D-10)"
                % (directory, entry, name, rule))


def check_i01b_guarded_pins(base: Path) -> int:
    """HE-004-I01B1 R-B3-PIN (DESIGN-I01B1 rev 2 section 1; the section review's I1D-3 and I1D-10), in
    check_observer_home_pins' form:
    - every I01B_GUARDED_PINS file is present, a regular file and not a symlink, and byte-exact (its sha256 equals its
      pin);
    - every I01B_ABSENT path has no directory entry (a dangling symlink, an empty file or a directory refuses);
    - no entry of a guarded file's directory casefolds to a guarded name (the pinned, absent and home-pinned socket
      files) other than that name itself;
    - each guarded module is declared in its crate's lib.rs exactly once, in file form, as a line-anchored `pub mod
      <name>;` (a cfg attribute before it aside), and no source of either crate holds an inline `mod <name> {`, so no
      inline module can orphan a pinned file.
    The sources are read without comments, literal contents emptied and the whitespace around `::` removed. The number
    of guarded entries (six pins and one absence)."""
    rule = "guarded pin, R-B3-PIN"
    for rel, expected in I01B_GUARDED_PINS.items():
        path = base / rel
        require(path.is_file() and not path.is_symlink(), "%s is missing or a symlink (%s)" % (rel, rule))
        require(sha256(path.read_bytes()) == expected, "%s differs from its pinned bytes (%s)" % (rel, rule))
    for rel in I01B_ABSENT:
        path = base / rel
        require(not path.is_symlink() and not path.exists(),
                "%s exists; it stays absent until HE-004-I01B3 pins it (%s)" % (rel, rule))
    guarded = list(I01B_GUARDED_PINS) + list(I01B_ABSENT) + [rel for rel in OBSERVER_HOME_PINS
                                                             if rel in (OBSERVER_LINUX_NET, OBSERVER_LINUX_LISTEN)]
    by_directory: dict[str, set[str]] = {}
    for rel in guarded:
        by_directory.setdefault(posixpath.dirname(rel), set()).add(posixpath.basename(rel))
    for directory, names in sorted(by_directory.items()):
        entries = [entry.name for entry in (base / directory).iterdir()] if (base / directory).is_dir() else []
        casefold_siblings(directory, entries, names, rule)
    codes = {}
    for rel, raw in observer_sources(base, (EFFECT_GATE_CRATE, OBSERVER_CRATE)):
        try:
            codes[rel] = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
    for lib, modules in I01B_FILE_FORM.items():
        require(lib in codes, "%s is missing (%s, I1D-3)" % (lib, rule))
        for name in modules:
            line = re.compile(r"(?m)^[ \t]*(?:#\s*\[\s*cfg\s*\([^\]]*\)\s*\]\s*)?pub\s+mod\s+%s\s*;" % name)
            require(len(line.findall(codes[lib])) == 1, "%s does not declare `pub mod %s;` exactly once, in file form "
                    "(%s, I1D-3)" % (lib, name, rule))
    names = sorted({name for modules in I01B_FILE_FORM.values() for name in modules})
    inline = re.compile(r"\bmod\s+(%s)\s*\{" % "|".join(names))
    for rel, code in sorted(codes.items()):
        found = inline.search(code)
        require(not found, "%s holds an inline `mod %s {` (%s, I1D-3)" % (rel, found.group(1) if found else "", rule))
    return len(I01B_GUARDED_PINS) + len(I01B_ABSENT)


def check_socket_module_aliases(base: Path) -> int:
    """HE-004-I01B1 B3-1, G-I01B-6 (e) (DESIGN-I01B1 rev 2 sections 2 and 6; exactly as the section review's I1D-1 and
    I1D-2 state it). Every non-test source of crates/effect-gate/src and crates/observer/src, main.rs included, is read
    as observer_code reads it (comments removed, literal contents emptied, the whitespace around `::` removed, strict
    test blocks blanked), and its use trees are expanded as use_paths expands them (an unreadable tree refuses). Each use
    path is read after its leading `crate`, `self` and `super` segments (and, in the observer's main.rs,
    `planeon_observer`) are dropped, a trailing `self` read as its module:
    - a path that is exactly a socket module of its crate (SOCKET_CRATE_MODULES), renamed or not, refuses, and so does a
      glob through one; an item import passes: a path that continues past the socket module to an item other than
      `self`, and is not pub (today's three: effect-gate linux_os.rs's `crate::linux_net::SharedNet`, the observer's
      linux_net.rs `crate::linux_listen::I01Socket` and main.rs's `planeon_observer::linux_net::LinuxWire`);
    - a `pub` or `pub(..)` use whose path names a socket module refuses;
    - a use whose path is a scope root alone refuses (`use crate as ..`, `use crate::{self as ..}`, `use self as ..`,
      `use super as ..`, and in main.rs `planeon_observer` itself); there are none at dd7422ed;
    - a glob of a scope root (`use crate::*;`, `pub use super::*;`, `use self::*;`, and in main.rs
      `use planeon_observer::*;`), at any visibility, refuses everywhere but at the top level of a crate's lib.rs (PR
      review round 1, R1-2): in any other module a pub glob of the crate root re-exports its pub socket modules under a
      new path; there are none outside strict test blocks at dd7422ed.
    The alias route needs a use site in a socket file too, which the whole-file pins refuse from I01B1 on
    (R-B3-PIN); this rule is the tripwire beside them. The number of sources read."""
    rule = "socket-module aliases, G-I01B-6 (e)"
    count = 0
    for crate, modules in SOCKET_CRATE_MODULES.items():
        for rel, raw in observer_sources(base, (crate,)):
            try:
                code = PATH_SPACE.sub("::", rust_code(raw))
            except GateError as error:
                raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
            for start, end in reversed(cfg_test_blocks(code)):
                code = code[:start] + " " * (end - start) + code[end:]
            roots = SCOPE_ROOTS + (("planeon_observer",) if rel == OBSERVER_MAIN else ())
            library_root = rel == "%s/src/lib.rs" % crate
            for declaration in USE_DECLARATION.finditer(code):
                public = bool(PUB_PREFIX.search(code, 0, declaration.start()))
                top_level = library_root and brace_depth(code, declaration.start()) == 0
                try:
                    paths = use_paths(declaration.group(1))
                except GateError:
                    raise GateError("%s holds a use declaration the alias rule cannot read (%s)" % (rel, rule)) from None
                for path, _ in paths:
                    target = path[:-1] if path[-1:] == ("self",) else path
                    head = 0
                    while head < len(target) and target[head] in roots:
                        head += 1
                    rest = target[head:]
                    require(rest, "%s imports or renames a scope root (%s)" % (rel, rule))
                    require(rest != ("*",) or top_level, "%s globs a scope root outside its crate root (%s)" % (rel, rule))
                    require(not public or not any(segment in modules for segment in rest),
                            "%s re-exports a path through a socket module (%s)" % (rel, rule))
                    require(rest[0] not in modules or (len(rest) > 1 and rest[1] not in ("self", "*")),
                            "%s imports the socket module %s itself, renamed or not (%s)" % (rel, rest[0], rule))
            count += 1
    return count


def check_i01b_sources(base: Path) -> int:
    """HE-004-I01B1 G-I01B-7 (a)-(d) (DESIGN-I01B rev 3 sections 2, 6 and 7.5; Q-I01B-28 amended; B1-4). Over
    crates/observer's sources, read as observer_code reads them (comments removed, literal contents emptied, the
    whitespace around `::` removed, strict test blocks blanked):
    (a) the `src/**/i01_*.rs` files (rglob) are exactly I01_FILES_BUILT (five in I01B1);
    (b) lib.rs's module declarations are exactly OBSERVER_LIB_MODULES, each once and in file form (`mod <name>;`), so a
        response module not named i01_* refuses too (HE-004-I01A PR review R1-4);
    (c) no other observer source declares a module item;
    (d) I01_LOGIC_BUILT and I01_NO_PANIC_BUILT hold the three I01B1 modules.
    The number of i01_ sources."""
    rule = "the i01_ sources, G-I01B-7"
    source = base / OBSERVER_CRATE / "src"
    present = sorted(path.relative_to(base).as_posix() for path in source.rglob("i01_*.rs"))
    require(present == sorted(I01_FILES_BUILT), "the i01_ sources present (%s) are not exactly %s (%s)"
            % (", ".join(present) or "none", ", ".join(sorted(I01_FILES_BUILT)), rule))
    codes = observer_code(base, rule)
    require(OBSERVER_LIB in codes, "%s is missing (%s)" % (OBSERVER_LIB, rule))
    declared = MODULE_DECLARATION.findall(codes[OBSERVER_LIB])
    require(sorted(name for name, _ in declared) == sorted(OBSERVER_LIB_MODULES) and all(end == ";" for _, end in declared),
            "%s declares the modules [%s], not exactly OBSERVER_LIB_MODULES, each once in file form (%s)"
            % (OBSERVER_LIB, ", ".join(name + end for name, end in declared), rule))
    for rel, code in sorted(codes.items()):
        if rel != OBSERVER_LIB:
            require(not MODULE_ITEM.search(code), "%s declares a module; only lib.rs does (%s)" % (rel, rule))
    missing = [name for name in I01B1_MODULES if name not in I01_LOGIC_BUILT or name not in I01_NO_PANIC_BUILT]
    require(not missing, "%s miss the logic or the no-panic rule (%s)" % (", ".join(missing), rule))
    return len(present)


def pinned_constant(base: Path, rel: str, name: str, kind: str, form: str, rule: str) -> tuple[int, list[str], int]:
    """HE-004-I01B1 G-I01B-8: the one line-anchored `pub const <name>: <kind> = <form>;` of a raw source, the only
    `const <name>` there: its value (the form's integer, underscores removed), the source's lines and the line's
    index."""
    path = base / rel
    require(path.is_file(), "%s is missing (%s)" % (rel, rule))
    raw = path.read_text(encoding="utf-8")
    lines = raw.split("\n")
    pattern = re.compile(r"pub const %s: %s = %s;" % (re.escape(name), re.escape(kind), form))
    found = [(index, match) for index, line in enumerate(lines) if (match := pattern.fullmatch(line))]
    require(len(found) == 1 and len(re.findall(r"\bconst\s+%s\b" % re.escape(name), raw)) == 1,
            "%s does not define %s exactly once, as a line-anchored pub const (%s)" % (rel, name, rule))
    index, match = found[0]
    return int(match.group(1).replace("_", "")), lines, index


def check_i01b_constants(base: Path) -> int:
    """HE-004-I01B1 G-I01B-8, the constants (DESIGN-I01B rev 3 section 6; B2-7), each against its own source, read from
    the raw sources (pinned_constant):
    - i01_gate.rs's GATE_BOUND_MS is the vendored definitions.json's captureGate.boundMs, which is its bound's cycleMs
      plus scrapeToSetMs plus setBudgetMs;
    - observe.rs's CYCLE and capture.rs's SCRAPE_TO_SET and SET_BUDGET (`Duration::from_secs(<n>)`, read in place) are
      those three, in seconds;
    - i01_gate.rs's ANSWER_LIMIT (65,536; VPO :86-88), FRESHNESS_WINDOW_SECONDS (5; VPO :128) and
      EXCHANGE_DEADLINE_SECONDS (2; Q-I01B-21 (a)) are their literal pins, each with its citation in the doc comment
      directly above it.
    One refusal per constant. The number of constants (seven)."""
    rule = "constants and texts, G-I01B-8"
    try:
        capture_gate = json.loads((base / I01B_DEFINITIONS).read_text(encoding="utf-8"))["captureGate"]
        bound, parts = capture_gate["boundMs"], capture_gate["bound"]
        sources = {member: parts[member] for _, _, member in I01B_DURATION_PINS}
    except (OSError, ValueError, KeyError, TypeError):
        raise GateError("%s has no readable captureGate bound (%s)" % (I01B_DEFINITIONS, rule)) from None
    require(all(type(value) is int for value in [bound, *sources.values()]) and bound == sum(sources.values()),
            "%s's captureGate.boundMs is not its bound's three parts (%s)" % (I01B_DEFINITIONS, rule))
    name, kind = I01B_GATE_BOUND
    value, _, _ = pinned_constant(base, I01_GATE_RS, name, kind, r"([0-9][0-9_]*)", rule)
    require(value == bound, "%s's %s is not %s's captureGate.boundMs (%s)" % (I01_GATE_RS, name, I01B_DEFINITIONS, rule))
    for rel, name, member in I01B_DURATION_PINS:
        value, _, _ = pinned_constant(base, rel, name, "Duration", r"Duration::from_secs\(([0-9][0-9_]*)\)", rule)
        require(value * 1000 == sources[member],
                "%s's %s is not %s's captureGate.bound.%s (%s)" % (rel, name, I01B_DEFINITIONS, member, rule))
    for name, kind, pinned, citation in I01B_LITERAL_PINS:
        value, lines, index = pinned_constant(base, I01_GATE_RS, name, kind, r"([0-9][0-9_]*)", rule)
        above = index
        while above > 0 and lines[above - 1].startswith("///"):
            above -= 1
        documented = " ".join(line[3:].strip() for line in lines[above:index])
        require(value == pinned and citation in documented,
                "%s does not pin %s to %d with its citation %s (%s)" % (I01_GATE_RS, name, pinned, citation, rule))
    return 1 + len(I01B_DURATION_PINS) + len(I01B_LITERAL_PINS)


def check_i01b_refusal_texts(base: Path) -> int:
    """HE-004-I01B1 G-I01B-8, the texts (DESIGN-I01B rev 3 section 6): the refusal texts the three I01B1 modules write,
    their string literals read without comments and with literals kept that start with one of the contract's eleven
    keys and `: `, are exactly the vendored definitions.json's refusalTexts, each written at least once, and no other
    key-prefixed text is written. The number of texts."""
    rule = "constants and texts, G-I01B-8"
    try:
        definitions = json.loads((base / I01B_DEFINITIONS).read_text(encoding="utf-8"))
        pinned = definitions["refusalTexts"]
        keys = list(definitions["projections"]) + list(definitions["enforcementDigests"])
    except (OSError, ValueError, KeyError, TypeError):
        raise GateError("%s has no readable refusalTexts and keys (%s)" % (I01B_DEFINITIONS, rule)) from None
    require(type(pinned) is list and all(type(text) is str for text in pinned) and len(set(pinned)) == len(pinned)
            and len(keys) == 11, "%s's refusalTexts or keys are not readable (%s)" % (I01B_DEFINITIONS, rule))
    prefix = re.compile(r"(?:%s): " % "|".join(re.escape(key) for key in keys))
    written = set()
    for name in I01B1_MODULES:
        rel = "crates/observer/src/%s.rs" % name
        require((base / rel).is_file(), "%s is missing (%s)" % (rel, rule))
        try:
            kept = rust_code((base / rel).read_text(encoding="utf-8"), literals=True)
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
        written |= {literal for literal in RUST_STRING.findall(kept) if prefix.match(literal)}
    extra, missing = sorted(written - set(pinned)), sorted(set(pinned) - written)
    require(not extra and not missing, "the I01B1 modules' refusal texts are not exactly %s's refusalTexts: extra %s, "
            "missing %s (%s)" % (I01B_DEFINITIONS, extra, missing, rule))
    return len(pinned)


def check_native_profile_use(base: Path) -> int:
    """HE-004D1 DESIGN-D1 section 19 (G-D1-9, R2-5), generalised by HE-004D2 (DESIGN-D2 section 12, G-D2-3) to each of
    NATIVE_PROFILE_SCHEMAS: read without comments, the constant occurs in crates/observer's sources only as its definition
    in contracts.rs and once in capture_schema.rs, inside CaptureSchema::embedded, so each schema's bytes have one use
    site (G-D1-16 checks the binary for the v4 one). The number of occurrences (two per schema)."""
    rule = "native-profile schema use, G-D1-9, G-D2-3"
    schema_rs = "crates/observer/src/capture_schema.rs"
    total = 0
    sources = []
    for rel, raw in observer_sources(base, (OBSERVER_CRATE,)):
        try:
            sources.append((rel, PATH_SPACE.sub("::", rust_code(raw))))
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
    for constant in NATIVE_PROFILE_SCHEMAS:
        word = re.compile(r"\b%s\b" % constant)
        count = 0
        for rel, code in sources:
            found = list(word.finditer(code))
            if rel == OBSERVER_CONTRACTS:
                require(len(found) == 1 and re.search(r"\bpub\s+const\s+%s\s*:" % constant, code),
                        "%s does not define %s exactly once (%s)" % (rel, constant, rule))
            elif rel == schema_rs:
                start, end = body_of(code, re.compile(r"\bfn\s+embedded\s*\("), "%s's fn embedded (%s)" % (rel, rule))
                require(len(found) == 1 and start < found[0].start() < end,
                        "%s does not use %s exactly once, in CaptureSchema::embedded (%s)" % (rel, constant, rule))
            else:
                require(not found, "%s names %s; only %s uses it (%s)" % (rel, constant, schema_rs, rule))
            count += len(found)
        require(count == 2, "%s is not defined and used once each (%s)" % (constant, rule))
        total += count
    return total


# --- HE-004-I01a: the observer's I01 listener (DESIGN-I01A rev 6 section 12) ---------------------------------------------

OBSERVER_CLIENT = "crates/observer/src/client.rs"
# G-I01-1: the observer never removes or renames a path.
I01_REMOVALS = re.compile(r"\b(?:unlink|remove_file|remove_dir|remove_dir_all|rename|hard_link)\b")
# G-I01-2: the one wire wait and the one step call.
WAIT_WORD = re.compile(r"\bwait\b")
WAIT_DEFINITION = re.compile(r"\bfn\s+wait\b")
STEP_WORD = re.compile(r"\bserve_peer_step\b")
STEP_DEFINITION = re.compile(r"\bfn\s+serve_peer_step\b")
STEP_PATH = re.compile(r"::\s*serve_peer_step\b")
# G-I01-4: the I01 path, written once as linux_listen.rs's private constant.
I01_PATH = "/run/planeon/live-proxy/policy-observer.sock"
I01_SOCKET_NAME = "policy-observer.sock"
I01_PATH_CONSTANT = re.compile(r'(?m)^[ \t]*const\s+I01_PATH\s*:\s*&\s*str\s*=\s*"%s"\s*;' % re.escape(I01_PATH))
# G-I01-5: nothing leaves I01a. The i01_ sources as their units add them (U4: the service and its request checks;
# U3 held none).
# HE-004-I01B1 (G-I01B-7 (a); Q-I01B-28 amended): the digest port's three logic modules make five.
I01_FILES = ("crates/observer/src/i01_service.rs", "crates/observer/src/i01_request.rs") + tuple(
    "crates/observer/src/%s.rs" % name for name in I01B1_MODULES)
I01_FILES_BUILT = I01_FILES
# HE-004-I01B1 G-I01B-7 (b) (DESIGN-I01B rev 3 section 6; B1-4; HE-004-I01A PR review R1-4's "a response module not named
# i01_*"): the observer's lib.rs declares exactly these modules, each once and in file form: HE-004-I01A2's 35 and
# I01B1's three (I01B3 adds i01_answer).
OBSERVER_LIB_MODULES = ("admission", "capture", "capture_check", "capture_schema", "client", "composition", "config",
                        "contracts", "credentials", "enrolled", "exposition", "http", "i01_request", "i01_service",
                        "i06_evidence", "inputs", "kernel_text", "linux_capture", "linux_listen", "linux_net", "observe",
                        "observer_rbac", "operational", "qualification", "quota", "rbac", "record_check", "requests",
                        "seal", "signed_config", "snapshot", "status", "tls", "utc", "watch") + I01B1_MODULES
MODULE_DECLARATION = re.compile(r"\bmod\s+([A-Za-z_]\w*)\s*([;{])")
# HE-004-I01B1 G-I01B-8 (DESIGN-I01B rev 3 section 6; B2-7): each constant against its own source. The gate bound and
# the three R10 constants it sums, from the vendored definitions.json (captureGate); G-I01B-8's three literal pins in
# i01_gate.rs, each with the citation its doc comment must hold; and the refusal texts the three modules write, read
# with literals kept, exactly definitions.json's refusalTexts. HE-004-I01B4 (DESIGN-I01B4 rev 2 section 5, I4D-10; the
# section's own choice, which the rulings do not name): the contract v2's definitions.json, the file the port now reads.
# Its refusalTexts, captureGate and eleven keys equal v1's, so G-I01B-8's counts stay 90 and 90,000.
I01_GATE_RS = "crates/observer/src/i01_gate.rs"
I01B_DEFINITIONS = "contracts/i01-digests-v2/definitions.json"
I01B_GATE_BOUND = ("GATE_BOUND_MS", "u64")
I01B_DURATION_PINS = (("crates/observer/src/observe.rs", "CYCLE", "cycleMs"),
                      ("crates/observer/src/capture.rs", "SCRAPE_TO_SET", "scrapeToSetMs"),
                      ("crates/observer/src/capture.rs", "SET_BUDGET", "setBudgetMs"))
I01B_LITERAL_PINS = (("ANSWER_LIMIT", "usize", 65536, "scripts/validate_policy_observation.py:86-88"),
                     ("FRESHNESS_WINDOW_SECONDS", "u64", 5, "scripts/validate_policy_observation.py:128"),
                     ("EXCHANGE_DEADLINE_SECONDS", "u64", 2, "Q-I01B-21 (a)"))
RUST_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"', re.S)
I01_MODULE = re.compile(r"\bmod\s+(i01_\w*)")
I01_REFUSED_WORDS = re.compile(r"\b(?:Wire|connect|ConnId|Client)\b")
PEER_SEND = re.compile(r"\bpeer_send\b")
PEER_OPS_TRAIT = re.compile(r"\btrait\s+PeerOps\b")
PEER_OPS_HEADER = re.compile(r"\bpub\s+trait\s+PeerOps\s*\{")
CHANNEL_SEND = re.compile(r"\bchannel::send\b")
# HE-004-I01A2 (R1-3): `extern crate gate_sys as gs;` is a crate alias no use declaration shows.
EXTERN_CRATE = re.compile(r"\bextern\s+crate\b")
# G-I01-6: I01Socket's two homes and its one construction, in the spellings of a path to `open` (G-D2-11's forms).
I01_SOCKET = re.compile(r"\bI01Socket\b")
I01_SOCKET_OPEN = re.compile(r"\bI01Socket\b(?:\s*<\s*>)?(?:\s*\))*(?:\s*>)?(?:\s*::\s*<\s*>)?\s*::\s*open\b")
SELF_OPEN_CALL = re.compile(r"\bSelf\s*>?(?:\s*::\s*<\s*>)?\s*::\s*open\b")
# G-I01-3 (unit U6): the role pin's one call in observe.rs, right after the closure check.
OBSERVER_OBSERVE = "crates/observer/src/observe.rs"
OBSERVER_RBAC = "crates/observer/src/observer_rbac.rs"
ROLE_PIN_WORD = re.compile(r"\bcheck_observer_snapshot\b")
ROLE_PIN_CALL = re.compile(r"\bobserver_rbac::check_observer_snapshot\s*\(")
CLOSURE_CHECK = re.compile(r"\bself\s*\.\s*closure\s*\.\s*check\s*\(")
BLOCK_STATEMENT = re.compile(r"(?:if|match|for|while|loop|unsafe)\b|\{")
STATEMENT_GOES_ON = re.compile(r"\s*(?:else\b|[.?;])")
LET_STATEMENT = re.compile(r"let\b")
LET_DROPPED = re.compile(r"let\s+dropped\s*=")
DROP_PRODUCED = re.compile(r"drop\s*\(\s*produced\s*\)\s*;")
# The role pin's constants (DESIGN-I01A section 10, Q-I01A-4 (a); review r2 I2-12), read from observer_rbac.rs with
# literals kept and held to the v4 vectors' objectsPositive.
I06_V4_VECTORS = "contracts/i06-v4/vectors.json"
ROLE_PIN_TEXTS = ("RBAC_API_VERSION", "OBSERVER_USER", "ROLE_NAME", "BINDING_NAME")
ROLE_PIN_PAIRS = ("ROLE_REF", "SUBJECT")
RUST_TEXT = r'"([^"\\]*)"'
ROLE_PIN_PAIR = re.compile(r"\(\s*%s\s*,\s*%s\s*\)" % (RUST_TEXT, RUST_TEXT))
CONTRACT_RULE = re.compile(r"\bContractRule\s*\{([^{}]*)\}")
CONTRACT_RULE_FIELD = re.compile(r"\b(\w+)\s*:\s*&\s*\[([^\[\]]*)\]")
RULE_FIELDS = (("api_groups", "apiGroups"), ("resources", "resources"), ("non_resource_urls", "nonResourceURLs"),
               ("verbs", "verbs"), ("resource_names", "resourceNames"))
ONLY_SEPARATORS = re.compile(r"[\s,]*")


def observer_code(base: Path, rule: str, literals: bool = False) -> dict[str, str]:
    """crates/observer's non-test sources as the G-I01 rules read them: without comments (literal contents emptied
    unless `literals`), the whitespace around `::` removed, and strict #[cfg(test)] mod tests blocks blanked in place."""
    codes = {}
    for rel, raw in observer_sources(base, (OBSERVER_CRATE,)):
        try:
            code = PATH_SPACE.sub("::", rust_code(raw, literals=literals))
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
        for start, end in reversed(cfg_test_blocks(code)):
            code = code[:start] + " " * (end - start) + code[end:]
        codes[rel] = code
    return codes


def blank(pattern: re.Pattern, text: str) -> str:
    """`text` with every match of `pattern` replaced by as many spaces (positions kept)."""
    return pattern.sub(lambda match: " " * len(match.group(0)), text)


def check_observer_never_unlinks(base: Path) -> int:
    """HE-004-I01a G-I01-1 (DESIGN-I01A sections 4 and 12; review r3 I3-7, r4 I4-7): crates/observer's non-test sources,
    read without comments (literal contents emptied, strict test blocks aside), name none of unlink, remove_file,
    remove_dir, remove_dir_all, rename and hard_link. The observer binds its I01 path after the seal and never removes
    it: the unit's ExecStartPre= clears it as init_t (HS53), and the seccomp-v5 OBSERVER row has no unlink call. Its
    tests may clean their scratch directories. The number of sources."""
    rule = "never unlinks, G-I01-1"
    codes = observer_code(base, rule)
    for rel, code in codes.items():
        found = I01_REMOVALS.search(code)
        require(not found, "%s names %s; the observer never removes or renames a path (%s)"
                % (rel, found.group(0) if found else "", rule))
    return len(codes)


def check_observer_wait_point(base: Path) -> int:
    """HE-004-I01a G-I01-2 (DESIGN-I01A sections 5 and 12; review r4 I4-1, r5 I5-5): over crates/observer's non-test
    sources, read without comments and with the whitespace around `::` removed, every reference to `wait` is counted,
    called or not and whatever the spacing (`.wait(`, `::wait(`, `W::wait`, `Wire::wait`, `<.. as Wire>::wait`, a
    bare name), only `fn wait` definitions aside. There are exactly two: the one wire wait, `.wait(` inside client.rs's
    `fn wait_serving`, and linux_net.rs's `self.poller.wait(` inside its one `fn wait` (LinuxWire's `Wire::wait`).
    Likewise `serve_peer_step`, its `fn` definitions aside, occurs exactly once, as the method call `.serve_peer_step(`
    inside `fn wait_serving`; any `::serve_peer_step` path refuses. So every wire wait of the observer serves I01
    (Q-HE4I1-6 (a)). The number of counted occurrences (three)."""
    rule = "the single wait point, G-I01-2"
    codes = observer_code(base, rule)
    for rel in (OBSERVER_CLIENT, OBSERVER_LINUX_NET):
        require(rel in codes, "%s is missing (%s)" % (rel, rule))
    client, net = codes[OBSERVER_CLIENT], codes[OBSERVER_LINUX_NET]
    serving = body_of(client, re.compile(r"\bfn\s+wait_serving\s*\("), "%s's fn wait_serving (%s)" % (OBSERVER_CLIENT, rule))
    waiting = body_of(net, re.compile(r"\bfn\s+wait\s*\("), "%s's fn wait (%s)" % (OBSERVER_LINUX_NET, rule))
    waits, steps = [], []
    for rel, code in codes.items():
        waits.extend((rel, found.start()) for found in WAIT_WORD.finditer(blank(WAIT_DEFINITION, code)))
        kept = blank(STEP_DEFINITION, code)
        require(not STEP_PATH.search(kept), "%s names a ::serve_peer_step path; the step is called only as the one method "
                "call in wait_serving (%s)" % (rel, rule))
        steps.extend((rel, found.start()) for found in STEP_WORD.finditer(kept))
    sites = dict(waits)
    client_at, net_at = sites.get(OBSERVER_CLIENT, -1), sites.get(OBSERVER_LINUX_NET, -1)
    require(len(waits) == 2 and len(sites) == 2, "crates/observer names wait %d times outside its definitions, not once in "
            "each of %s and %s (%s)" % (len(waits), OBSERVER_CLIENT, OBSERVER_LINUX_NET, rule))
    require(serving[0] < client_at < serving[1] and re.search(r"\.\s*$", client[:client_at])
            and re.match(r"wait\s*\(", client[client_at:]),
            "%s's one wait is not the call `.wait(` inside fn wait_serving (%s)" % (OBSERVER_CLIENT, rule))
    require(waiting[0] < net_at < waiting[1] and re.search(r"\bself\s*\.\s*poller\s*\.\s*$", net[:net_at])
            and re.match(r"wait\s*\(", net[net_at:]),
            "%s's one wait is not `self.poller.wait(` inside its fn wait (%s)" % (OBSERVER_LINUX_NET, rule))
    require(len(steps) == 1 and steps[0][0] == OBSERVER_CLIENT and serving[0] < steps[0][1] < serving[1]
            and re.search(r"\.\s*$", client[:steps[0][1]]) and re.match(r"serve_peer_step\s*\(", client[steps[0][1]:]),
            "serve_peer_step is not called exactly once, as `.serve_peer_step(` inside %s's fn wait_serving (%s)"
            % (OBSERVER_CLIENT, rule))
    return len(waits) + len(steps)


def check_observer_i01_path(base: Path) -> int:
    """HE-004-I01a G-I01-4 (DESIGN-I01A sections 4 and 12): in crates/observer's non-test sources, raw text (comments
    included), the I01 socket's name occurs only in linux_listen.rs, exactly once, inside its line-anchored private
    constant `const I01_PATH: &str = "/run/planeon/live-proxy/policy-observer.sock";` (HOST_PATHS' binary scan cannot
    say which source holds a literal). The number of occurrences (one)."""
    rule = "the I01 path, G-I01-4"
    found = 0
    for rel, raw in observer_sources(base, (OBSERVER_CRATE,)):
        if rel == OBSERVER_LINUX_LISTEN:
            require(raw.count(I01_SOCKET_NAME) == 1 and len(I01_PATH_CONSTANT.findall(raw)) == 1,
                    "%s does not hold the I01 path exactly once, as its private constant I01_PATH (%s)" % (rel, rule))
            found += 1
        else:
            require(I01_SOCKET_NAME not in raw, "%s names the I01 socket; only %s does (%s)"
                    % (rel, OBSERVER_LINUX_LISTEN, rule))
    require(found == 1, "%s is missing (%s)" % (OBSERVER_LINUX_LISTEN, rule))
    return found


def check_observer_no_send(base: Path) -> int:
    """HE-004-I01a G-I01-5 (DESIGN-I01A sections 0, 5 and 12; review r2 I2-2, r4 I4-7, r5 I5-3): nothing leaves I01a.
    Read without comments (literals kept), no crates/observer source spells peer_send. In the two socket files,
    linux_net.rs and linux_listen.rs, gate-sys's channel send is unreachable (a `Watched::Conn` hands out a `&Conn`):
    read with source_uses, as the socket-item rule reads them, no use path imports `send` from gate_sys::channel
    (braced, renamed or not) and none renames the channel module; and no `channel::send` path occurs, with any prefix.
    The i01_ sources are exactly I01_FILES_BUILT (the I01 service and its request checks, and from HE-004-I01B1 the
    digest port's three logic modules: no I01 response, observation or answer module), lib.rs declares exactly those
    i01_ modules, and they name none of Wire, connect,
    ConnId and Client. PeerOps is declared once, in client.rs, exactly as `pub trait PeerOps {` (no supertrait).
    HE-004-I01A2 (HE-004-I01a PR review round 1, R1-3; Q-U7-2 (a)): in the two socket files the use paths are read with
    the source's aliases followed (resolved_uses), so `use gate_sys as gs; use gs::channel::{send};` imports send and
    `use gs::channel as c;` renames the channel module, braced or not, and both refuse; a `name::send` path through any
    name bound to the channel module refuses as `channel::send` does; and, so that every route to the channel module is
    spelled through gate_sys, neither file renames gate_sys (`use gate_sys as ..`, `use gate_sys::{self as ..}`), imports
    a glob of it or declares an extern crate. The number of sources."""
    rule = "nothing leaves I01a, G-I01-5"
    codes = observer_code(base, rule, literals=True)
    for rel, code in codes.items():
        require(not PEER_SEND.search(code), "%s spells peer_send; I01a sends nothing (%s)" % (rel, rule))
    for rel in (OBSERVER_LINUX_NET, OBSERVER_LINUX_LISTEN, OBSERVER_CLIENT, OBSERVER_LIB):
        require(rel in codes, "%s is missing (%s)" % (rel, rule))
    for rel in (OBSERVER_LINUX_NET, OBSERVER_LINUX_LISTEN):
        raw = (base / rel).read_text(encoding="utf-8")
        code = PATH_SPACE.sub("::", rust_code(raw))
        uses = resolved_uses(source_uses(rel, raw))
        channel_uses = [(path, rename) for path, rename in uses if path[:2] == ("gate_sys", "channel")]
        for path, _ in channel_uses:
            require("send" not in path[2:], "%s imports gate-sys's channel send (%s)" % (rel, rule))
        require(not CHANNEL_SEND.search(code), "%s names gate-sys's channel send (%s)" % (rel, rule))
        for name in sorted({rename for path, rename in channel_uses if rename and path[2:] in ((), ("self",))}):
            require(not re.search(r"(?<![\w:])%s::send\b" % re.escape(name), code),
                    "%s names gate-sys's channel send through %s (%s)" % (rel, name, rule))
        for path, rename in channel_uses:
            require(path[2:] not in ((), ("self",)) or rename is None, "%s renames gate-sys's channel module (%s)" % (rel, rule))
        require(not gate_sys_aliases(uses), "%s renames gate_sys (%s)" % (rel, rule))
        require(("gate_sys", "*") not in {path for path, _ in uses}, "%s imports a glob of gate_sys (%s)" % (rel, rule))
        require(not EXTERN_CRATE.search(code), "%s declares an extern crate (%s)" % (rel, rule))
    source = base / OBSERVER_CRATE / "src"
    present = sorted(path.relative_to(base).as_posix() for path in source.glob("i01_*.rs"))
    require(present == sorted(I01_FILES_BUILT), "the i01_ sources present (%s) are not exactly %s (%s)"
            % (", ".join(present) or "none", ", ".join(sorted(I01_FILES_BUILT)) or "none", rule))
    declared = sorted(I01_MODULE.findall(codes[OBSERVER_LIB]))
    require(declared == sorted(posixpath.basename(rel)[:-3] for rel in I01_FILES_BUILT),
            "%s declares the i01_ modules %s, not exactly those built (%s)" % (OBSERVER_LIB, declared, rule))
    for rel in I01_FILES_BUILT:
        found = I01_REFUSED_WORDS.search(codes[rel])
        require(not found, "%s names %s; the I01 service is handed only the peer operations (%s)"
                % (rel, found.group(0) if found else "", rule))
    traits = [(rel, match.start()) for rel, code in codes.items() for match in PEER_OPS_TRAIT.finditer(code)]
    header = PEER_OPS_HEADER.search(codes[OBSERVER_CLIENT])
    require(len(traits) == 1 and traits[0][0] == OBSERVER_CLIENT and header and header.start() < traits[0][1] < header.end(),
            "PeerOps is not declared once, in %s, exactly as `pub trait PeerOps {` (%s)" % (OBSERVER_CLIENT, rule))
    return len(codes)


def check_observer_i01_socket(base: Path) -> int:
    """HE-004-I01a G-I01-6 (DESIGN-I01A sections 0, 4 and 12; review r3 I3-1, r4 I4-6): read without comments and with
    the whitespace around `::` removed, I01Socket is named only in linux_listen.rs (its definition and impls) and
    linux_net.rs (LinuxWire's private field and constructor); it is renamed with `as` nowhere and named by no `type`
    item of the crate (each read to its `;` at bracket depth 0, as G-D2-11's rule reads them); I01Socket::open is called
    exactly once, inside LinuxWire::new, counting its qualified spellings (`<I01Socket>::open`, `I01Socket::<>::open`,
    `<(I01Socket)>::open`), and neither file calls `Self::open`. Both files are pinned whole (OBSERVER_HOME_PINS) and
    I01Socket is a Debug hazard (DEBUG_HAZARDS). The number of sources."""
    rule = "the I01 socket, G-I01-6"
    codes = observer_code(base, rule)
    for rel in (OBSERVER_LINUX_NET, OBSERVER_LINUX_LISTEN):
        require(rel in codes, "%s is missing (%s)" % (rel, rule))
    calls = []
    for rel, code in codes.items():
        try:
            type_items = [item_text(code, found.start(), "type") for found in re.finditer(r"\btype\b", code)]
        except GateError:
            raise GateError("%s holds a type item the alias rule cannot read (%s)" % (rel, rule)) from None
        require(not re.search(r"\bI01Socket\s+as\b|\bas\s+I01Socket\b", code)
                and not any(I01_SOCKET.search(text) for text in type_items),
                "%s renames or aliases I01Socket (%s)" % (rel, rule))
        if rel not in (OBSERVER_LINUX_NET, OBSERVER_LINUX_LISTEN):
            require(not I01_SOCKET.search(code), "%s names I01Socket; only %s and %s do (%s)"
                    % (rel, OBSERVER_LINUX_LISTEN, OBSERVER_LINUX_NET, rule))
            continue
        require(not SELF_OPEN_CALL.search(code), "%s calls Self::open, a second route to the listener (%s)" % (rel, rule))
        calls.extend((rel, found.start()) for found in I01_SOCKET_OPEN.finditer(code))
    net = codes[OBSERVER_LINUX_NET]
    impls = list(re.finditer(r"\bimpl\s+LinuxWire\s*\{", net))
    require(len(impls) == 1, "%s does not hold exactly one `impl LinuxWire {` (%s)" % (OBSERVER_LINUX_NET, rule))
    opening = impls[0].end() - 1
    start, end = body_of(net[opening:block_end(net, opening)], re.compile(r"\bfn\s+new\s*\("),
                         "%s's LinuxWire::new (%s)" % (OBSERVER_LINUX_NET, rule))
    require(len(calls) == 1 and calls[0][0] == OBSERVER_LINUX_NET and opening + start < calls[0][1] < opening + end,
            "I01Socket::open is called %d times, not exactly once, inside LinuxWire::new (%s)" % (len(calls), rule))
    return len(codes)


def block_statements(code: str, inside: int, rule: str) -> list[tuple[int, int]]:
    """The statements, as (start, end) spans, of the innermost `{ }` block around position `inside` of a source read
    without comments and with literal contents emptied. A statement ends at its `;` at bracket depth 0; one that starts
    as a block expression (if, match, for, while, loop, unsafe or a bare block) ends at the `}` that brings it back to
    depth 0, unless `else`, `.`, `?` or `;` follows."""
    depth, opening = 0, -1
    for index in range(inside - 1, -1, -1):
        char = code[index]
        if char in ")]}":
            depth += 1
        elif char in "([{":
            if depth == 0 and char == "{":
                opening = index
                break
            depth = max(depth - 1, 0)
    require(opening >= 0, "no block holds the statement (%s)" % rule)
    spans, start, depth = [], opening + 1, 0
    for index in range(opening + 1, len(code)):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                if code[start:index].strip():
                    spans.append((start, index))
                return spans
            depth -= 1
            if (depth == 0 and char == "}" and BLOCK_STATEMENT.match(code[start:index + 1].lstrip())
                    and not STATEMENT_GOES_ON.match(code, index + 1)):
                spans.append((start, index + 1))
                start = index + 1
        elif char == ";" and depth == 0:
            spans.append((start, index + 1))
            start = index + 1
    raise GateError("a block without its closing brace (%s)" % rule)


def check_observer_role_pin(base: Path) -> int:
    """HE-004-I01a G-I01-3 (DESIGN-I01A sections 10 and 12; review r4 I4-5, r5 I5-4): in observe.rs's non-test code,
    read without comments, with literal contents emptied and the whitespace around `::` removed, check_observer_snapshot
    is named exactly once, as the call `observer_rbac::check_observer_snapshot(`, and `self.closure.check(` occurs
    exactly once. Among the statements of the block that holds the closure check (block_statements), the one holding
    the role pin's call comes later, with only `let` statements between (the three lists), and the next two are
    `let dropped = ...` and `drop(produced);`, in that order. So I06 v4's RB check judges every snapshot the closure
    check accepts, before the producer's output is dropped and before OR02, OR05 and OR06, and its 87 comes before
    their 88. A comment naming Closure::check is no anchor. The number of `let` statements between."""
    rule = "the role pin's call, G-I01-3"
    codes = observer_code(base, rule)
    require(OBSERVER_OBSERVE in codes, "%s is missing (%s)" % (OBSERVER_OBSERVE, rule))
    code = codes[OBSERVER_OBSERVE]
    words, calls = list(ROLE_PIN_WORD.finditer(code)), list(ROLE_PIN_CALL.finditer(code))
    require(len(words) == 1 and len(calls) == 1 and words[0].start() == calls[0].start() + len("observer_rbac::"),
            "%s does not name check_observer_snapshot exactly once, as the call observer_rbac::check_observer_snapshot( "
            "(%s)" % (OBSERVER_OBSERVE, rule))
    closures = list(CLOSURE_CHECK.finditer(code))
    require(len(closures) == 1, "%s does not hold `self.closure.check(` exactly once (%s)" % (OBSERVER_OBSERVE, rule))
    spans = block_statements(code, closures[0].start(), rule)

    def holding(position: int) -> int:
        found = [number for number, (start, end) in enumerate(spans) if start <= position < end]
        return found[0] if found else -1

    first, pin = holding(closures[0].start()), holding(calls[0].start())
    require(0 <= first < pin, "the role pin's call is not a later statement of the block that holds the closure check "
            "(%s)" % rule)
    between = [code[start:end].strip() for start, end in spans[first + 1:pin]]
    require(all(LET_STATEMENT.match(text) for text in between), "a statement other than `let` stands between the "
            "closure check and the role pin's call (%s)" % rule)
    after = [code[start:end].strip() for start, end in spans[pin + 1:pin + 3]]
    require(len(after) == 2 and LET_DROPPED.match(after[0]) and DROP_PRODUCED.fullmatch(after[1]),
            "the role pin's call is not followed by `let dropped = ...` and then `drop(produced);` (%s)" % rule)
    return len(between)


def literal_bracket_end(code: str, opening: int, rule: str) -> int:
    """The index after the bracket that closes the one at `opening`, in a source read with literals kept (a string
    literal's brackets do not count)."""
    depth, index, quoted = 0, opening, False
    while index < len(code):
        char = code[index]
        if quoted:
            if char == "\\":
                index += 1
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    raise GateError("%s: a bracket without its closing one (%s)" % (OBSERVER_RBAC, rule))


def constant_body(code: str, header: str, rule: str) -> tuple[str, int]:
    """The text inside the `[ ]` of the one `pub const` item whose header (up to its `= [`) `header` matches, and the
    length its type declares; the item ends with `];`."""
    found = list(re.finditer(r"(?m)^[ \t]*pub\s+const\s+" + header + r"\s*=\s*\[", code))
    require(len(found) == 1, "%s: not exactly one plain `pub const` item %s (%s)"
            % (OBSERVER_RBAC, header.split("\\")[0], rule))
    opening = found[0].end() - 1
    end = literal_bracket_end(code, opening, rule)
    require(re.match(r"\s*;", code[end:]), "%s: a constant array not ended by `];` (%s)" % (OBSERVER_RBAC, rule))
    return code[opening + 1:end - 1], int(found[0].group("length"))


def rust_texts(items: str, rule: str) -> list[str]:
    """The plain string literals of a comma-separated list, which holds nothing else."""
    require(ONLY_SEPARATORS.fullmatch(re.sub(RUST_TEXT, "", items)), "%s: a list of the role pin's constants holds more "
            "than plain string literals (%s)" % (OBSERVER_RBAC, rule))
    return re.findall(RUST_TEXT, items)


def check_observer_role_constants(base: Path) -> int:
    """HE-004-I01a DESIGN-I01A section 10 (owner decision Q-I01A-4 (a); review r2 I2-12): the role pin's rule data,
    compiled into observer_rbac.rs as R10 constants, is the contract's. Read with comments removed and literals kept:
    RBAC_API_VERSION, OBSERVER_USER, ROLE_NAME and BINDING_NAME are each one plain `pub const NAME: &str = "..";`;
    ROLE_REF and SUBJECT one `[(&str, &str); N]` array of plain text pairs; OBSERVER_RULES one `[ContractRule; N]` array
    of ContractRule literals, each with the five list fields once as plain `&[..]` lists of string literals. Against
    contracts/i06-v4/vectors.json's objectsPositive (registered bytes): the first ClusterRole's rules are exactly the
    eight, in order, each list as the model reads it (absent or null is empty, no other member); the role's and the
    binding's names and apiVersion are the four texts' (the observer user is the subject's name); the binding's roleRef
    is ROLE_REF and its subjects exactly [SUBJECT]. The number of constants checked."""
    rule = "the role pin's constants, DESIGN-I01A section 10"
    require((base / OBSERVER_RBAC).is_file(), "%s is missing (%s)" % (OBSERVER_RBAC, rule))
    require((base / I06_V4_VECTORS).is_file(), "%s is missing (%s)" % (I06_V4_VECTORS, rule))
    try:
        code = PATH_SPACE.sub("::", rust_code((base / OBSERVER_RBAC).read_text(encoding="utf-8"), literals=True))
    except GateError as error:
        raise GateError("%s: %s (%s)" % (OBSERVER_RBAC, error, rule)) from None
    texts = {}
    for name in ROLE_PIN_TEXTS:
        found = re.findall(r"(?m)^[ \t]*pub\s+const\s+%s\s*:\s*&\s*str\s*=\s*%s\s*;" % (name, RUST_TEXT), code)
        require(len(found) == 1, "%s: not one plain `pub const %s: &str` (%s)" % (OBSERVER_RBAC, name, rule))
        texts[name] = found[0]
    pairs = {}
    for name in ROLE_PIN_PAIRS:
        body, length = constant_body(code, r"%s\s*:\s*\[\s*\(\s*&\s*str\s*,\s*&\s*str\s*\)\s*;\s*(?P<length>\d+)\s*\]"
                                     % name, rule)
        found = ROLE_PIN_PAIR.findall(body)
        require(ONLY_SEPARATORS.fullmatch(ROLE_PIN_PAIR.sub("", body)) and len(found) == length
                and len({key for key, _ in found}) == length,
                "%s: %s is not %s distinct plain text pairs (%s)" % (OBSERVER_RBAC, name, length, rule))
        pairs[name] = dict(found)
    body, length = constant_body(code, r"OBSERVER_RULES\s*:\s*\[\s*ContractRule\s*;\s*(?P<length>\d+)\s*\]", rule)
    require(ONLY_SEPARATORS.fullmatch(CONTRACT_RULE.sub("", body)), "%s: OBSERVER_RULES holds more than ContractRule "
            "literals (%s)" % (OBSERVER_RBAC, rule))
    rules = []
    for entry in CONTRACT_RULE.finditer(body):
        fields = CONTRACT_RULE_FIELD.findall(entry.group(1))
        require(ONLY_SEPARATORS.fullmatch(CONTRACT_RULE_FIELD.sub("", entry.group(1)))
                and sorted(field for field, _ in fields) == sorted(field for field, _ in RULE_FIELDS),
                "%s: a ContractRule of OBSERVER_RULES does not set its five lists once each (%s)" % (OBSERVER_RBAC, rule))
        lists = {field: rust_texts(items, rule) for field, items in fields}
        rules.append({key: lists[field] for field, key in RULE_FIELDS})
    require(len(rules) == length, "%s: OBSERVER_RULES declares %d rules and holds %d (%s)"
            % (OBSERVER_RBAC, length, len(rules), rule))
    try:
        positive = json.loads((base / I06_V4_VECTORS).read_text(encoding="utf-8"))["objectsPositive"]
        role, binding = positive["clusterRoles"][0], positive["clusterRoleBindings"][0]
        wanted_rules = role["rules"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise GateError("%s has no readable objectsPositive (%s)" % (I06_V4_VECTORS, rule)) from None
    require(type(wanted_rules) is list and len(wanted_rules) == 8 == len(rules),
            "the contract role holds %s rules and OBSERVER_RULES %d, not eight each (%s)"
            % (len(wanted_rules) if type(wanted_rules) is list else "no", len(rules), rule))
    for number, (wanted, held) in enumerate(zip(wanted_rules, rules), 1):
        read = (type(wanted) is dict and set(wanted) <= set(held)
                and {key: [] if wanted.get(key) is None else wanted[key] for key in held} == held)
        require(read, "OBSERVER_RULES' rule %d is not the contract role's (%s)" % (number, rule))
    role_meta, binding_meta = role.get("metadata"), binding.get("metadata")
    require(type(role_meta) is dict and role_meta.get("name") == texts["ROLE_NAME"]
            and type(binding_meta) is dict and binding_meta.get("name") == texts["BINDING_NAME"],
            "ROLE_NAME or BINDING_NAME is not the contract objects' name (%s)" % rule)
    require(role.get("apiVersion") == binding.get("apiVersion") == texts["RBAC_API_VERSION"],
            "RBAC_API_VERSION is not the contract objects' apiVersion (%s)" % rule)
    require(binding.get("roleRef") == pairs["ROLE_REF"] and pairs["ROLE_REF"].get("name") == texts["ROLE_NAME"],
            "ROLE_REF is not the contract binding's roleRef (%s)" % rule)
    require(binding.get("subjects") == [pairs["SUBJECT"]] and pairs["SUBJECT"].get("kind") == "User"
            and pairs["SUBJECT"].get("name") == texts["OBSERVER_USER"],
            "SUBJECT and OBSERVER_USER are not the contract binding's one subject (%s)" % rule)
    return len(rules) + len(texts) + len(pairs)


# --- HE-004D2: the D2 logic modules' isolation and host-path literal, and their absence from the binary (DESIGN-D2 12) ---

def module_isolation(base: Path, names: tuple[str, ...], built: tuple[str, ...], label: str, rule: str) -> int:
    """G-D2-5's construction over a list of crates/observer modules (HE-004D2's D2 modules; HE-004-I01B1's three digest
    port modules, G-I01B-1's I01B1 form). Over crates/observer's non-test sources, read without comments, literal
    contents emptied and the whitespace around `::` removed: the module files present are exactly `built` (so each takes
    the logic rule); (a) the module names occur outside the modules' files only in lib.rs, each built one exactly as its
    line-anchored `pub mod <name>;` and nothing else there; (b) the type set is derived from the modules' files, every
    name they define as a struct, enum, union, trait or type item at any depth outside strict test blocks, each defined
    once among them, and none of those names occurs in another crates/observer source (whatever it is there, a
    definition included); (c) in the modules' files every impl header is exactly `impl <a name of that set> {` (no
    `for`, no generic parameter) and every `pub use` names only the modules' paths. `label` names the modules in the
    refusals. The number of type names."""
    sources = observer_sources(base, (OBSERVER_CRATE,))
    module_files = {"crates/observer/src/%s.rs" % name: name for name in names}
    present = sorted(name for rel, name in module_files.items() if (base / rel).is_file())
    require(present == sorted(built), "the %s modules present (%s) are not exactly those that take the logic rule "
            "(%s) (%s)" % (label, ", ".join(present) or "none", ", ".join(built), rule))
    codes = {}
    for rel, raw in sources:
        try:
            codes[rel] = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
    defined: dict[str, str] = {}
    for rel in sorted(rel for rel in codes if rel in module_files):
        scanned = codes[rel]
        for start, end in reversed(cfg_test_blocks(scanned)):
            scanned = scanned[:start] + " " + scanned[end:]
        for item in D2_TYPE_ITEM.finditer(scanned):
            name = item.group(1)
            require(name not in defined, "%s defines %s, which %s defines too (%s)" % (rel, name, defined.get(name), rule))
            defined[name] = rel
    module_words = re.compile(r"\b(?:%s)\b" % "|".join(names))
    type_words = re.compile(r"\b(?:%s)\b" % "|".join(re.escape(name) for name in sorted(defined))) if defined else None
    for rel, code in codes.items():
        if rel in module_files:
            continue
        rest = code
        if rel == OBSERVER_LIB:
            for name in built:
                declaration = re.compile(r"(?m)^[ \t]*pub\s+mod\s+%s\s*;" % name)
                require(len(declaration.findall(rest)) == 1, "%s does not declare `pub mod %s;` exactly once, on its own line (%s)"
                        % (rel, name, rule))
                rest = declaration.sub(" ", rest)
        found = module_words.search(rest)
        require(not found, "%s names the %s module %s other than in lib.rs's one `pub mod` line (%s)"
                % (rel, label, found.group(0) if found else "", rule))
        hit = type_words.search(code) if type_words else None
        require(not hit, "%s names %s, a type the %s module %s defines (%s)"
                % (rel, hit.group(0) if hit else "", label, defined.get(hit.group(0)) if hit else "", rule))
    for rel in sorted(rel for rel in codes if rel in module_files):
        code = codes[rel]
        for _, header in impl_headers(rel, code):
            form = re.fullmatch(r"impl ([A-Za-z_]\w*)", header)
            require(form and form.group(1) in defined, "%s has the impl header `%s`; every impl in a %s module is exactly "
                    "`impl <a type it defines> {` (%s)" % (rel, header, label, rule))
        for declaration in PUB_USE_DECLARATION.finditer(code):
            for path, _ in use_paths(declaration.group(1)):
                require(len(path) > 1 and path[0] in ("crate", "self") and path[1] in names,
                        "%s re-exports %s, not a %s item (%s)" % (rel, "::".join(path), label, rule))
    return len(defined)


def check_observer_d2_isolation(base: Path) -> int:
    """HE-004D2 DESIGN-D2 sections 9 and 12 (G-D2-5; owner decision Q-HE4D2-5 (a); D2-4): the source-level construction
    that keeps the D2 logic modules unreachable from serve (module_isolation over D2_LOGIC_NAMES, the built ones
    D2_LOGIC_BUILT). With the existing pre-main, macro and included-code rules (forced exports, assembled names), no other
    source can reach a D2 item. The number of D2 type names."""
    return module_isolation(base, D2_LOGIC_NAMES, D2_LOGIC_BUILT, "D2", "D2 isolation, G-D2-5")


def check_i01b1_isolation(base: Path) -> int:
    """HE-004-I01B1 G-I01B-1, its I01B1 form (DESIGN-I01B rev 3 section 6; DESIGN-I01B1 rev 2 section 4, I1D-5): G-D2-5's
    construction (module_isolation) over the digest port's three modules, i01_digest, i01_admission_render and
    i01_gate: (a) their names occur outside their files only in lib.rs's line-anchored `pub mod <name>;`; (b) the type
    set they define is named in no other observer source; (c) every impl header in them is `impl <a type of the set>
    {`; (d) every `pub use` in them names only their own paths. So nothing in serve reaches them in I01B1; I01B3's form
    (i01_answer) replaces this rule. The number of type names."""
    return module_isolation(base, I01B1_MODULES, I01B1_MODULES, "I01B1", "I01B1 isolation, G-I01B-1")


def check_observer_interpreter_tree(base: Path) -> int:
    """HE-004D2 DESIGN-D2 sections 5.4 and 9 (G-D2-6): in crates/observer's non-test sources, raw text, `/opt/planeon/`
    occurs only in record_check.rs, exactly once, as the line-anchored `const INTERPRETER_TREE: &str =
    "/opt/planeon/python/";` (G-D1-5's anchoring: a `pub` form, a raw string, a second one or a comment is not removed and
    refuses). The number of excepted expressions."""
    rule = "host-path literal, G-D2-6"
    count = 0
    for rel, raw in observer_sources(base, (OBSERVER_CRATE,)):
        rest = raw
        if rel == OBSERVER_RECORD_CHECK:
            found = len(INTERPRETER_TREE[1].findall(raw))
            require(found == 1, "%s holds `%s` %d times, not exactly once (%s)" % (rel, INTERPRETER_TREE[0], found, rule))
            rest = INTERPRETER_TREE[1].sub(" ", raw, count=1)
            count += 1
        require("/opt/planeon/" not in rest, "%s holds /opt/planeon/ other than as record_check.rs's one `%s` (%s)"
                % (rel, INTERPRETER_TREE[0], rule))
    require(count == 1 or "record_check" not in D2_LOGIC_BUILT, "%s is missing (%s)" % (OBSERVER_RECORD_CHECK, rule))
    return count


def check_d2_absent(names: set[str]) -> int:
    """HE-004D2 DESIGN-D2 sections 9 and 12 (G-D2-7; D2-4): no symbol of planeon-observer's .symtab has an item path
    (legacy or v0, `item_path`) or a first-crate-root path (`symbol_path`, which also reads trait impls and closures)
    beginning `planeon_observer::<a D2 module>`. A symbol that only mentions a D2 name (another module, a generic argument)
    passes. Build-time corroboration of G-D2-5, not its proof: an inlined function leaves no symbol. It holds until a
    reviewed packet wires the composition (W02-PROD). The number of symbols read."""
    for name in names:
        for path in (item_path(name), symbol_path(name)[0]):
            if path[:1] == ("planeon_observer",) and path[1:2] and path[1] in D2_LOGIC_NAMES:
                raise GateError("planeon-observer's symbol table holds %s, a symbol of the D2 module %s (G-D2-7)" % (name, path[1]))
    return len(names)


def check_i01b1_absent(names: set[str]) -> int:
    """HE-004-I01B1 G-I01B-1's corroboration (DESIGN-I01B rev 3 section 6, in G-D2-7's style; I1D-5): no symbol of
    planeon-observer's .symtab has an item path or a first-crate-root path beginning `planeon_observer::<one of the
    digest port's three modules>`; a symbol that only mentions one passes. Build-time corroboration of G-I01B-1's I01B1
    form, not its proof. The number of symbols read."""
    for name in names:
        for path in (item_path(name), symbol_path(name)[0]):
            if path[:1] == ("planeon_observer",) and path[1:2] and path[1] in I01B1_MODULES:
                raise GateError("planeon-observer's symbol table holds %s, a symbol of the I01B1 module %s (G-I01B-1)"
                                % (name, path[1]))
    return len(names)


# HE-004D2 DESIGN-D2 sections 8.1 and 12 (G-D2-8; owner decision Q-HE4D2-6 (a); D2-1; design review round 2, R2-1): the
# acceptance tokens, each with its file and its one minting function, as their units add them (EvidenceAccepted in A3,
# QualificationAccepted in B2, Composed in B3); the three token files; a token field's closed type list.
D2_TOKENS = {"EvidenceAccepted": ("crates/observer/src/i06_evidence.rs", "check_evidence"),
             "QualificationAccepted": ("crates/observer/src/qualification.rs", "check_qualification"),
             "Composed": ("crates/observer/src/composition.rs", "compose_fixture")}
D2_TOKENS_BUILT = ("EvidenceAccepted", "QualificationAccepted", "Composed")
# G-D2-8: the production entry, whose body names none of these (it answers Unavailable until W02-PROD wires it).
PRODUCTION_ENTRY = ("crates/observer/src/composition.rs", "compose_production")
PRODUCTION_REFUSED_NAMES = ("compose_fixture", "Composed", "check_qualification", "check_evidence")
D2_TOKEN_FILES = tuple("crates/observer/src/%s.rs" % name for name in ("qualification", "i06_evidence", "composition"))
TOKEN_FIELD_TYPES = ("String", "bool", "u64", "i64", "&'staticstr")
TOKEN_DERIVE_REFUSED = re.compile(r"\b(?:Clone|Copy|Default|Hash|Deserialize|Serialize)\b")
SELF_LITERAL = re.compile(r"\bSelf\s*[({]")
GETTER = re.compile(r"(?:\bpub\s*(?:\([^)]*\)\s*)?)?\bfn\s+[A-Za-z_]\w*\s*\(\s*&\s*self\s*\)\s*->\s*([^{;]+)\{")


def token_attributes(code: str, start: int) -> list[str]:
    """The outer attributes directly before the item at `start` (a `pub` visibility skipped), innermost last."""
    found, cursor = [], start
    while True:
        before = code[:cursor].rstrip()
        before = re.sub(r"\bpub\s*(?:\([^)]*\))?\s*$", "", before).rstrip() if not found else before
        if not before.endswith("]"):
            return found
        depth, index = 0, len(before) - 1
        while index >= 0:
            depth += {"]": 1, "[": -1}.get(before[index], 0)
            if depth == 0:
                break
            index -= 1
        opening = re.search(r"#\s*$", before[:index])
        require(index >= 0 and opening, "an attribute the token rule cannot read")
        found.append(before[opening.start():])
        cursor = opening.start()


def check_observer_child_modules(base: Path) -> int:
    """HE-004D2 PR review round 1, R1-6 (beside G-D2-5, G-D2-4 and G-D2-8): a child module of a logic module in its own
    file (`mod bridge;` in i06_evidence.rs, loading src/i06_evidence/bridge.rs) reaches its parent's private items and
    fields through `super::` without naming the module or its types, and the rules that read the logic files by path would
    not see it. So the observer crate's src/ holds no directory, and no logic module (B1's, D1's and D2's), read without
    comments and outside strict test blocks, declares a module, out-of-line or inline. The number of logic modules."""
    rule = "observer child modules, R1-6"
    source = base / OBSERVER_CRATE / "src"
    directories = sorted(path.relative_to(base).as_posix() for path in source.rglob("*") if path.is_dir())
    require(not directories, "%s is a directory under %s/src; a child module's file there could reach a module's private "
            "items (%s)" % (directories[0] if directories else "", OBSERVER_CRATE, rule))
    for rel, _ in LOGIC_MODULES:
        require((base / rel).is_file(), "%s is missing (%s)" % (rel, rule))
        try:
            code = rust_code((base / rel).read_text(encoding="utf-8"))
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None
        for start, end in reversed(cfg_test_blocks(code)):
            code = code[:start] + " " * (end - start) + code[end:]
        found = re.search(r"\bmod\s+(?:r#)?[A-Za-z_]\w*\s*[;{]", code)
        require(not found, "%s declares a module (`%s`) outside a strict test block (%s)"
                % (rel, re.sub(r"\s+", " ", found.group(0)) if found else "", rule))
    return len(LOGIC_MODULES)


def check_observer_tokens(base: Path) -> int:
    """HE-004D2 DESIGN-D2 sections 8.1 and 12 (G-D2-8, D2-1, R2-1). Each built token, read without comments and with
    literal contents emptied: one struct, whose fields are private and each of a type in TOKEN_FIELD_TYPES (no Cell,
    RefCell, atomic, Mutex, RwLock, OnceCell or other type that a `&self` method could change), and none of whose
    attributes derives (also inside cfg_attr) Clone, Copy, Default, Hash, Deserialize or Serialize; one inherent impl
    `impl <Token> {` holding only getters `fn <name>(&self) -> <type>` whose type names neither the token nor Self; in its
    file the token's name only in the struct, that impl header, the minting function's signature and its one literal
    `<Token> {` inside that function's body; the literal form nowhere else; outside the impl and strict test blocks,
    every `.<field>` of a token field name is a getter call `.<field>(`, so no assignment, compound assignment,
    parenthesised place, borrow, method call or rebinding reaches a field (HE-004D2 PR review round 1, R1-1); and each
    getter's body is exactly `self.<name>` or `&self.<name>`, its own field. In the token files present, no `Self {` or
    `Self(` outside strict test blocks (a child module's file is check_observer_child_modules', R1-6). Once Composed is built, `fn compose_production`'s body names none of
    PRODUCTION_REFUSED_NAMES. The number of tokens checked."""
    rule = "acceptance token, G-D2-8"
    codes = {}
    for rel, raw in observer_sources(base, (OBSERVER_CRATE,)):
        try:
            codes[rel] = PATH_SPACE.sub("::", rust_code(raw))
        except GateError as error:
            raise GateError("%s: %s (%s)" % (rel, error, rule)) from None

    def outside_tests(code: str) -> str:
        for start, end in reversed(cfg_test_blocks(code)):
            code = code[:start] + " " * (end - start) + code[end:]
        return code

    for rel in D2_TOKEN_FILES:
        if rel in codes:
            found = SELF_LITERAL.search(outside_tests(codes[rel]))
            require(not found, "%s writes `%s`; a token file names every struct or variant literal's type (%s)"
                    % (rel, re.sub(r"\s+", "", found.group(0)) if found else "", rule))
    for token in D2_TOKENS_BUILT:
        rel, minting = D2_TOKENS[token]
        require(rel in codes, "%s is missing (%s)" % (rel, rule))
        code = codes[rel]
        scanned = outside_tests(code)
        name = re.compile(r"\b%s\b" % token)
        literal = re.compile(r"\b%s\s*\{" % token)
        structs = list(re.finditer(r"\bstruct\s+%s\b" % token, code))
        require(len(structs) == 1, "%s does not define struct %s exactly once (%s)" % (rel, token, rule))
        fields = struct_fields(code, structs[0].end())
        names = []
        for field in fields:
            form = re.fullmatch(r"\s*([a-z_]\w*)\s*:\s*(.+?)\s*", field, re.S)
            require(form, "%s's %s has a field the token rule cannot read: %r (%s)" % (rel, token, field.strip(), rule))
            require(re.sub(r"\s+", "", form.group(2)) in TOKEN_FIELD_TYPES, "%s's %s field %s is of type %s, outside %s (%s)"
                    % (rel, token, form.group(1), form.group(2), ", ".join(TOKEN_FIELD_TYPES), rule))
            names.append(form.group(1))
        require(names, "%s's %s has no named field (%s)" % (rel, token, rule))
        for attribute in token_attributes(code, re.search(r"(?:\bpub\s*(?:\([^)]*\)\s*)?)?\bstruct\s+%s\b" % token,
                                                           code).start()):
            if re.search(r"\bderive\b", attribute):
                refused = TOKEN_DERIVE_REFUSED.search(attribute)
                require(not refused, "%s derives %s on %s (%s)" % (rel, refused.group(0) if refused else "", token, rule))
        impls = list(re.finditer(r"\bimpl\s+%s\s*\{" % token, code))
        require(len(impls) == 1, "%s does not hold exactly one `impl %s {` (%s)" % (rel, token, rule))
        body = code[impls[0].end():block_end(code, impls[0].end() - 1) - 1]
        functions = len(re.findall(r"\bfn\b", body))
        getters = list(GETTER.finditer(body))
        require(functions == len(getters), "%s's impl %s holds a method other than a `fn <name>(&self) -> <type>` getter (%s)"
                % (rel, token, rule))
        for getter in getters:
            require(not re.search(r"\b(?:%s|Self)\b" % token, getter.group(1)), "%s's impl %s has a getter returning %s (%s)"
                    % (rel, token, getter.group(1).strip(), rule))
            # R1-1: a getter answers its own field, so no getter reads other than the minted value.
            getter_name = re.search(r"\bfn\s+([A-Za-z_]\w*)", getter.group(0)).group(1)
            getter_body = re.sub(r"\s+", "", body[getter.end():block_end(body, getter.end() - 1) - 1])
            require(getter_name in names and getter_body in ("self.%s" % getter_name, "&self.%s" % getter_name),
                    "%s's impl %s has a getter %s whose body is not `self.%s` or `&self.%s` of its own field (%s)"
                    % (rel, token, getter_name, getter_name, getter_name, rule))
        require(not re.search(r"(?<!')\b(?:const|type|static)\b", re.sub(r"\{[^{}]*\}", "", body)),
                "%s's impl %s holds an item other than its getters (%s)" % (rel, token, rule))
        definition = re.compile(r"\bfn\s+%s\s*\(" % minting)
        opening, end = body_of(code, definition, "%s's fn %s (%s)" % (rel, minting, rule))
        signature = code[definition.search(code).start():opening]
        inside = [found for found in literal.finditer(code) if opening < found.start() < end]
        outside = [found for found in literal.finditer(code) if not (opening < found.start() < end)
                   and found.start() not in (structs[0].end() - len(token), impls[0].start() + code[impls[0].start():].find(token))]
        require(len(inside) == 1 and not outside, "%s writes the %s literal other than once, in fn %s (%s)"
                % (rel, token, minting, rule))
        require(len(name.findall(signature)) == 1 and len(name.findall(code)) == 4,
                "%s names %s other than in its struct, its impl header, fn %s's signature and its one literal (%s)"
                % (rel, token, minting, rule))
        for other, other_code in codes.items():
            if other != rel:
                require(not literal.search(other_code), "%s writes the %s literal; only %s's fn %s does (%s)"
                        % (other, token, rel, minting, rule))
        # R1-1: outside the impl (whose getters read `self.<field>`), a token field name follows a dot only as a getter
        # call, so no assignment, compound assignment, parenthesised place, `&mut`, method call or rebinding reaches it.
        impl_end = block_end(code, impls[0].end() - 1)
        for field in names:
            for use in re.finditer(r"\.\s*(?:r#)?%s\b(?!\s*\()" % field, scanned):
                require(impls[0].start() <= use.start() < impl_end,
                        "%s uses the %s field %s other than through its getter (%s)" % (rel, token, field, rule))
    if "Composed" in D2_TOKENS_BUILT:
        rel, entry = PRODUCTION_ENTRY
        code = codes.get(rel, "")
        opening, end = body_of(code, re.compile(r"\bfn\s+%s\s*\(" % entry), "%s's fn %s (%s)" % (rel, entry, rule))
        found = re.search(r"\b(?:%s)\b" % "|".join(PRODUCTION_REFUSED_NAMES), code[opening:end])
        require(not found, "%s's fn %s names %s; the production entry answers Unavailable until W02-PROD (%s)"
                % (rel, entry, found.group(0) if found else "", rule))
    return len(D2_TOKENS_BUILT)


def check_observer_wiring(base: Path) -> int:
    """HE-003A3 DESIGN section 5 (D1-3, D2-2): the binary's main.rs (read without comments) holds serve's two pinned
    statements, ROOTS_STATEMENT and OBSERVER_STATEMENT, each exactly once and in WIRING_ORDER (after LinuxOs::with_net
    the roots, before FileStores::open_bound; after it the observer, before Substrate::new, which takes that gate);
    with_observer, KernelRoots, LinuxKernelReads and KernelObserver occur nowhere else but in its imports; and exactly
    two `let gate` bindings, the second the observer's. So a production gate always carries the Linux observer. The
    number of statements."""
    try:
        code = rust_code((base / GATE_MAIN).read_text(encoding="utf-8"))
    except GateError as error:
        raise GateError("%s: %s (observer wiring)" % (GATE_MAIN, error)) from None
    positions = []
    for pattern in WIRING_ORDER:
        found = list(pattern.finditer(code))
        require(len(found) == 1, "%s does not hold exactly one %s (observer wiring)" % (GATE_MAIN, pattern.pattern[:48]))
        positions.append(found[0].start())
    require(positions == sorted(positions), "%s holds serve's statements out of order (observer wiring)" % GATE_MAIN)
    uses = re.sub(r"\buse\b[^;]*;", " ", code)
    for word, count in (("with_observer", 1), ("KernelRoots", 1), ("LinuxKernelReads", 1), ("KernelObserver", 1)):
        require(len(re.findall(r"\b%s\b" % word, uses)) == count,
                "%s names %s outside its imports and pinned statement (observer wiring)" % (GATE_MAIN, word))
    bindings = [match.start() for match in re.finditer(r"\blet\s+gate\b", code)]
    require(len(bindings) == 2 and bindings[1] == positions[3],
            "%s rebinds gate other than as the PolicyGate and its observer (observer wiring)" % GATE_MAIN)
    # HE-003A3 PR review round 1, R1-2 (carried to HE-004B1): no other binding form of gate anywhere (a let pattern
    # holding gate is exactly `gate`: no `let (gate, ..)`, `let mut gate`, `let Some(gate)`), no assignment to it, and
    # after the observer's attach gate occurs only as `gate.apiserver_address()` and in `Substrate::new(gate, ..)`, so no
    # later shadowing, rebinding or moving call can hand the substrate another gate.
    for word in LET_WORD.finditer(code):
        pattern = let_pattern(code, word.end())
        require(not re.search(r"\bgate\b", pattern) or pattern.strip() == "gate",
                "%s binds gate in the pattern `let %s` (observer wiring, R1-2)" % (GATE_MAIN, " ".join(pattern.split())))
    for assignment in GATE_ASSIGNMENT.finditer(code):
        require(re.search(r"\blet\s+$", code[:assignment.start()]),
                "%s assigns to gate (observer wiring, R1-2)" % GATE_MAIN)
    after = OBSERVER_STATEMENT.search(code).end()
    tail = code[after:]
    allowed = ({match.start() for match in AFTER_ATTACH_USES[0].finditer(tail)}
               | {match.start(1) for match in AFTER_ATTACH_USES[1].finditer(tail)})
    for use in re.finditer(r"\bgate\b", tail):
        require(use.start() in allowed, "%s names gate after the observer's attach other than in gate.apiserver_address() "
                "and Substrate::new(gate, ..) (observer wiring, R1-2)" % GATE_MAIN)
    return 2


def let_pattern(code: str, start: int) -> str:
    """A let statement's pattern: from `start` (after `let`) to the first `=` (not `==`, `=>`, `<=`, `>=` or `!=`), type
    annotation `:` (not `::`) or `;` at bracket depth 0."""
    depth, index = 0, start
    while index < len(code):
        char = code[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and char == ";":
            break
        elif depth == 0 and char == ":" and not code.startswith("::", index) and code[index - 1] != ":":
            break
        elif depth == 0 and char == "=" and code[index + 1:index + 2] not in ("=", ">") and code[index - 1] not in "=<>!":
            break
        index += 1
    return code[start:index]


def check_macros(base: Path) -> int:
    """R1-3 (Q-HE3D-R1 (a)): no linked source (the binary included), read without comments, defines a macro_rules
    macro, a `macro` item or carries #[macro_export] (none exists today)."""
    sources = linked_sources(base)
    for rel, raw in sources:
        try:
            code = rust_code(raw)
        except GateError as error:
            raise GateError("%s: %s (macro rule)" % (rel, error)) from None
        for pattern, name in MACROS:
            require(not pattern.search(code), "%s defines %s (macro rule)" % (rel, name))
    return len(sources)


def check_pre_main(base: Path) -> int:
    """HE-003D DESIGN section 5 (D1-3): no linked source (the binary included), read without comments, names
    link_section, #[used], init_array, no_mangle or export_name: no code runs before main (none exists today)."""
    sources = linked_sources(base)
    for rel, raw in sources:
        code = rust_code(raw)
        for pattern, name in PRE_MAIN:
            require(not pattern.search(code), "%s names %s (code before main)" % (rel, name))
    return len(sources)


def check_prints(base: Path) -> int:
    """HE-003D DESIGN sections 4 and 5 (D1-10, D2-6): no linked source (the binary included), read without comments,
    names print!, println!, eprint!, eprintln!, dbg!, or stdout or stderr in any case: nothing is printed by design (a
    panic message may still reach fd 2, a residual)."""
    sources = linked_sources(base)
    for rel, raw in sources:
        code = rust_code(raw)
        for pattern, name in PRINTS:
            require(not pattern.search(code), "%s names %s (print rule)" % (rel, name))
    return len(sources)


def check_signer_key(base: Path, rel: str = SIGNER_KEY) -> int:
    """HE-003D DESIGN section 3.1 (Q-HE3D-7 (d)): the compiled-in signer key file is a regular file of exactly 0 (not
    yet set: every document is refused) or 32 bytes. Its size. HE-004C (G6): the gate run reads each of SIGNER_KEYS, the
    gate's and the observer's."""
    path = base / rel
    require(path.is_file() and not path.is_symlink(), "%s is missing (signer key)" % rel)
    size = len(path.read_bytes())
    require(size in (0, 32), "%s holds %d bytes, not 0 or 32 (signer key)" % (rel, size))
    return size


def check_gate_symbols(names: set[str]) -> list[str]:
    """HE-003D DESIGN section 5 (O3, C8): planeon-gate's .symtab has no membarrier or __membarrier (musl's
    membarrier.lo would kill the first thread after the seal), and the musl wrappers of KILLED_WRAPPERS it holds are
    each in WRAPPER_JUSTIFICATIONS (a reviewed list; an unlisted one fails). Owner decision Q-HE3D-B1 (a): it also
    holds gate-tls, rustls and ring symbols (CRATE_SYMBOLS), so the evidence describes the composed gate. The
    wrappers present."""
    for crate, pattern in CRATE_SYMBOLS:
        require(any(pattern.search(name) for name in names),
                "planeon-gate's symbol table holds no %s symbol: the composed gate is not linked (composition check)"
                % crate)
    require(not names & set(MEMBARRIER), "planeon-gate links %s (membarrier check)" % sorted(names & set(MEMBARRIER)))
    present = sorted(names & set(KILLED_WRAPPERS))
    unlisted = [name for name in present if name not in WRAPPER_JUSTIFICATIONS]
    require(not unlisted, "planeon-gate links the musl wrappers %s of calls the EFFECT_GATE filter kills, without a "
            "reviewed justification (symbol inventory)" % unlisted)
    return present


def check_observer_binary(names: set[str], raw: bytes, program: bytes) -> int:
    """HE-004A DESIGN-A section 6 (D1-1; D1-10, D2-5): planeon-observer's .symtab (`names`) has no membarrier or
    __membarrier (musl's membarrier.lo passes no zero third argument, which the OBSERVER row's exact-argument rule kills),
    and the binary (`raw`) holds its architecture's OBSERVER program bytes exactly once (SEC-4 evidence beyond the source
    pin; PR review round 1, R1-3: stage 1 also names the program, so a dropped stage 2 is the seal-order grammar's to
    catch, not this check's). Its wrapper inventory is not checked here: owner decision Q-HE4A-B2 (a)
    dropped it from HE-004A (MODEL_DEFINED, OBSERVER-WRAPPER-INVENTORY). The program's size."""
    require(not names & set(MEMBARRIER), "planeon-observer links %s (membarrier check)" % sorted(names & set(MEMBARRIER)))
    require(program, "an empty OBSERVER program (program-bytes check)")
    count = raw.count(program)
    require(count == 1, "planeon-observer holds its OBSERVER program %d times, not exactly once (program-bytes check)"
            % count)
    return len(program)


def symbol_path(name: str) -> tuple[tuple[str, ...], str]:
    """A mangled symbol's own path: the identifiers from its first crate root on (as far as they run consecutively)
    and the rest of the name after that crate root. Legacy names (`_ZN`) start at their first identifier; v0 names
    (`_R`) are followed down the first component of their path: `N` and its namespace, `M` and `X` (with an optional
    `s<base62>_` disambiguator), `Y` and `I`, to the crate root `C` (and its disambiguator). Anything else gives no
    path."""
    if name.startswith("_ZN"):
        at = 3
    elif name.startswith("_R"):
        at = 2
        while True:
            tag = name[at:at + 1]
            if tag == "N" and len(name) > at + 1:
                at += 2
            elif tag in ("M", "X"):
                at += 1
                if name[at:at + 1] == "s":
                    end = name.find("_", at)
                    if end < 0:
                        return (), ""
                    at = end + 1
            elif tag in ("Y", "I"):
                at += 1
            elif tag == "C":
                at += 1
                if name[at:at + 1] == "s":
                    end = name.find("_", at)
                    if end < 0:
                        return (), ""
                    at = end + 1
                break
            else:
                return (), ""
    else:
        return (), ""
    rest, parts = name[at:], []
    while True:
        match = SYMBOL_IDENT.match(name, at)
        if not match:
            break
        length = int(match.group(1))
        if length == 0 or match.end() + length > len(name):
            break
        parts.append(name[match.end():match.end() + length])
        at = match.end() + length
    return tuple(parts), rest


def check_observer_symbols(names: set[str]) -> tuple[str, str]:
    """HE-004C DESIGN-C section 15 (G9, D1-6, D2-8): beside check_observer_binary's no-membarrier and program rules,
    planeon-observer's .symtab (`names`), each symbol read by its own path (symbol_path), holds a rustls symbol naming
    ClientConnection or, if LTO inlined them all, the recorded substitute (a rustls::client::hs or rustls::client::tls13
    symbol, OBSERVER_CLIENT_MODULES), and a planeon_observer symbol of its client, http, watch or observe module
    (OBSERVER_MODULES). What was found: the client symbol's kind ("ClientConnection" or "substitute") and the first module
    symbol in name order."""
    paths = {name: symbol_path(name) for name in names}
    client = sorted(name for name, (path, rest) in paths.items()
                    if path[:1] == ("rustls",) and OBSERVER_CLIENT_CONNECTION.search(rest))
    substitute = sorted(name for name, (path, _) in paths.items() if path[:3] in OBSERVER_CLIENT_MODULES)
    require(client or substitute, "planeon-observer's symbol table holds no rustls ClientConnection symbol and no recorded "
            "substitute: the composed client is not linked (observer symbols)")
    modules = sorted(name for name, (path, _) in paths.items()
                     if path[:1] == ("planeon_observer",) and path[1:2] and path[1] in OBSERVER_MODULES)
    require(modules, "planeon-observer's symbol table holds no planeon_observer client, http, watch or observe symbol: the "
            "composed client is not linked (observer symbols)")
    return ("ClientConnection" if client else "substitute", modules[0])


# HE-004D1 DESIGN-D1 section 19 (G-D1-14, D1-7): the two constructors marked #[inline(never)], run once after the seal,
# whose symbols planeon-observer's .symtab must hold (G9's LTO fallback named in advance); recorded in MODEL_DEFINED R134.
CAPTURE_SYMBOLS = (("observer_sys", "kernel", "Roots", "open"),
                   ("planeon_observer", "linux_capture", "LinuxCapture", "new"))
BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def v0_path(name: str) -> tuple[str, ...]:
    """The item path of a v0-mangled (`_R`) symbol: crate roots (`C`), nested names (`N`), inherent impls (`M`, read as
    their self type's path) and backrefs (`B`), so `<observer_sys::kernel::Roots>::open` reads as observer_sys, kernel,
    Roots, open. Generic arguments, trait impls and every other form give no path (an empty tuple)."""
    if not name.startswith("_R"):
        return ()
    text = name[2:]

    def number(at: int) -> tuple[int, int]:
        end = text.index("_", at)
        value = 0
        for char in text[at:end]:
            value = value * 62 + BASE62.index(char)
        return (value + 1 if end > at else 0), end + 1

    def identifier(at: int) -> tuple[str, int]:
        if text[at] == "s":
            _, at = number(at + 1)
        match = re.match(r"(0|[1-9][0-9]*)_?", text[at:])
        if text[at] == "u" or not match:
            raise ValueError("an identifier v0_path does not read")
        start = at + match.end()
        length = int(match.group(1))
        if start + length > len(text):
            raise ValueError("a truncated identifier")
        return text[start:start + length], start + length

    def path(at: int, depth: int) -> tuple[list[str], int]:
        if depth > 32:
            raise ValueError("too deep")
        tag = text[at]
        if tag == "C":
            crate, at = identifier(at + 1)
            return [crate], at
        if tag == "N":
            parent, at = path(at + 2, depth + 1)
            ident, at = identifier(at)
            return parent + [ident], at
        if tag == "M":
            at += 1
            if text[at] == "s":
                _, at = number(at + 1)
            _, at = path(at, depth + 1)
            return path(at, depth + 1)
        if tag == "B":
            target, end = number(at + 1)
            if target >= at:
                raise ValueError("a backref that does not point back")
            return path(target, depth + 1)[0], end
        raise ValueError("a path form v0_path does not read")

    try:
        return tuple(path(0, 0)[0])
    except (ValueError, IndexError):
        return ()


def item_path(name: str) -> tuple[str, ...]:
    """A symbol's whole item path: a legacy name's identifiers without the trailing hash, or v0_path's."""
    if name.startswith("_ZN"):
        parts = symbol_path(name)[0]
        return parts[:-1] if parts and re.fullmatch(r"h[0-9a-f]{16}", parts[-1]) else parts
    return v0_path(name)


def check_capture_symbols(names: set[str]) -> list[str]:
    """HE-004D1 DESIGN-D1 section 19 (G-D1-14): planeon-observer's .symtab holds, each by its whole item path, a symbol of
    observer_sys::kernel::Roots::open and one of planeon_observer::linux_capture::LinuxCapture::new (CAPTURE_SYMBOLS);
    another function's symbol, a closure inside them or a name that only mentions them does not count. The symbols
    found, one per path."""
    found = []
    for wanted in CAPTURE_SYMBOLS:
        matches = sorted(name for name in names if item_path(name) == wanted)
        require(matches, "planeon-observer's symbol table holds no %s symbol: the capture roots are not linked as built "
                "(observer symbols, G-D1-14)" % "::".join(wanted))
        found.append(matches[0])
    return found


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
        say("workspace: %d crates, no build script or proc-macro; the only registry dependencies are %s, each of %s "
            "with the same pinned line (HE-004C); the only [patch] maps the %d LINKED vendored crates to their vendor/ "
            "paths, and Cargo.lock lists them as path packages with their vendor rows' versions and edges; its %d "
            "registry packages are exactly the other vendor rows, with their checksums and dependency lists"
            % (len(workspace), ", ".join(sorted(GATE_TLS_REGISTRY_LINES)),
               " and ".join(crate.split("/")[1] for crate in sorted(REGISTRY_LINES)), len(PATCH_CRATES),
               len(vendor_rows) - len(PATCH_CRATES)))
        say("workspace shape: %d members, each crates/<name> and inheriting edition %s; crates is not a symlink; "
            "effect-gate, gate-tls and planeon-gate link exactly %s; planeon-observer links exactly %s"
            % (check_workspace_shape(HE, workspace), WORKSPACE_EDITION, ", ".join(LINKED_CRATES),
               ", ".join(OBSERVER_LINKED_CRATES)))
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
        linked_names = ", ".join(crate.split("/")[1] for crate in SCANNED_CRATES)
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
        observer_tls = check_observer_tls(HE)
        say("TLS deny-list, two groups: %d sources. Group G, gate-tls and the binary: none of its %d refused tokens; %s "
            "are each set exactly once as the closed setting; tls.rs names with_cert_resolver( and SingleCertAndKey::from( "
            "once each; with_client_auth_cert and with_webpki_verifier are mentioned once each, in tls_client.rs; outside "
            "exchange.rs none names UpstreamResponse, and none defines a macro_rules macro. Group O, crates/observer (%d "
            "sources, HE-004C): none of those tokens nor of its %d server-side tokens; %s each set exactly once; "
            "with_client_auth_cert and with_webpki_verifier mentioned once each, in %s; no macro_rules"
            % (check_tls(HE), len(TLS_FORBIDDEN), ", ".join(name for name, _ in TLS_SETTINGS), observer_tls,
               len(OBSERVER_TLS_FORBIDDEN), ", ".join(name for name, _ in OBSERVER_TLS_SETTINGS), OBSERVER_TLS))
        say("seal order: %s holds one Linux main that starts with seal stage 1, calls between the stages only %s "
            "(status::seal inside ExitCode::from) and runs stage 2 as the exact statement `let <n> = match "
            "seal_stage2(<stage 1>) { Ok(<x>) => <x>, Err(<e>) => return ExitCode::from(status::seal(&<e>)), };`; its "
            "imports are the pinned set, its only items fn main (two) and fn serve, its only attributes the crate's "
            "forbid and the two cfgs; no socket or thread name through that statement, nor in %s and %s (one use "
            "gate_sys::Dir; excepted in the latter)" % (GATE_MAIN, check_seal_order(HE), GATE_CONFIG, SIGNED_CONFIG))
        say("seal order (observer): %s holds one Linux main whose first statement is exactly `let <n> = match seal_stage1() "
            "{ Ok(<x>) => <x>, Err(<e>) => return ExitCode::from(status::seal(&<e>)), };`, followed with nothing between by "
            "the exact stage-2 statement and then exactly `ExitCode::from(serve(&<the stage-2 binding>))`, which closes "
            "main (HE-004C); calls between the stages only %s; its imports are the pinned set (serve's included), its only "
            "items two fn main and fn serve, its only attributes the crate's forbid and the two cfgs; no socket or thread "
            "name through the stage-2 statement" % (OBSERVER_MAIN, check_seal_order(HE, OBSERVER_SEAL_SITE)))
        say("observer wiring order: serve calls %d steps each exactly once, in this order: %s, and not the v1 parse "
            "(HE-004C, G5; HE-004D1, G-D1-8); LinuxWire and LinuxCapture are constructed exactly once each, their "
            "qualified forms counted (HE-004D2, G-D2-11); the wire's refusal maps through status::wire_setup "
            "(HE-004-I01A2, R1-5)"
            % (check_observer_serve(HE), ", ".join(name for _, name in OBSERVER_WIRING)))
        say("socket modules: %d linked sources reach gate-sys's channel and tcp modules only from %s (which re-export "
            "nothing and name those modules' items in no pub type, const, static or fn signature, pub field or pub enum "
            "variant except the data types %s, and hold no fn-pointer or Fn-trait type in a pub alias, const, static, "
            "field or enum variant) and gate-sys, by use tree or qualified path; none names std::thread or thread::"
            % (check_socket_modules(HE), " and ".join(SOCKET_FILES), ", ".join(SOCKET_DATA_TYPES)))
        say("store opening: %d sources of crates/gate call FileStores::open_bound exactly once, name ::open only as "
            "PolicyGate::open and rename or alias neither type; no linked source calls FileStores::open"
            % check_gate_stores(HE))
        say("read_link: the word occurs %d times in the linked sources, as its definition in %s and the one call "
            "read_link(\"exe\", ..) in %s; readlinkat occurs only in %s, as its declaration and the one call in "
            "read_link (HE-003A2)" % (check_read_link(HE), OPENAT, CHANNEL, OPENAT))
        say("observation: %d linked sources call open_kernel_root, open_after_seal, FixedPath::from_constant, "
            "FixedPath::pid_stat and open_fixed only by their pinned forms (the two root opens inside "
            "KernelRoots::open_after_seal, the probe-worker leaf literal exact); implement WorkerObserver and KernelReads "
            "only by the pairs %s; name the fake kernel only in %s, lib.rs's pub mod and strict #[cfg(test)] mod tests "
            "blocks (it defines nothing else); rename or alias none of %s; LinuxKernelReads holds two KernelRoots and "
            "linux_os.rs no static state (HE-003A3)"
            % (check_observation(HE), "; ".join(OBSERVATION_IMPLS), FAKE_KERNEL, ", ".join(OBSERVATION_TYPES)))
        say("observer wiring: %d statements of serve, the kernel roots after LinuxOs::with_net and before the stores "
            "(status OBSERVER_ROOTS) and the Linux observer on the PolicyGate before Substrate::new, each exactly once "
            "(HE-003A3)" % check_observer_wiring(HE))
        say("macros: %d linked sources define no macro_rules or macro item and carry no #[macro_export]"
            % check_macros(HE))
        say("code before main: %d linked sources name no link_section, #[used], init_array, no_mangle or export_name"
            % check_pre_main(HE))
        say("print rule: %d linked sources name no print!, println!, eprint!, eprintln!, dbg!, stdout or stderr"
            % check_prints(HE))
        say("signer keys: %s (0: not yet set, every document refused)"
            % "; ".join("%s holds %d bytes" % (rel, check_signer_key(HE, rel)) for rel in SIGNER_KEYS))
        say("post-seal: %d sources of the linked crates name none of HE-002S DESIGN section 5's "
            "std APIs (plus set_modified and is_terminal), each of which reaches a system call the EFFECT_GATE filter "
            "kills (lexical tripwire)" % check_post_seal_sources(HE))
        say("observer post-seal: %d sources of %s name none of those std APIs nor, in any form, %s, each of which reaches "
            "a system call the OBSERVER filter kills or runs code under it (lexical tripwire, %s only; %s's one impl Drop "
            "for Value excepted)"
            % (check_observer_post_seal(HE), " and ".join(OBSERVER_POST_SEAL_CRATES),
               ", ".join(name.split(" ")[0] for _, name in OBSERVER_POST_SEAL_FORBIDDEN), " and ".join(OBSERVER_POST_SEAL_CRATES),
               I05_JSON))
        say("observer logic: %d modules of %s (%s; HE-004D1, G-D1-10: %s, whose whitelist adds i05_protocol::schema and "
            "the three modules; HE-004D2, G-D2-4: %s, whose whitelist adds the four D2 modules; HE-004-I01a: %s, whose "
            "whitelist adds the I01 logic modules) name only the whitelisted "
            "path roots %s, no super:: or foreign self:: path, glob, renaming import, HashMap, HashSet, RandomState or "
            "include macro, and no panicking macro or call outside strict #[cfg(test)] blocks (lexical tripwire, HE-004B1)"
            % (check_observer_logic(HE), OBSERVER_CRATE, ", ".join(OBSERVER_LOGIC_NAMES), ", ".join(D1_LOGIC_NAMES),
               ", ".join(D2_LOGIC_BUILT), ", ".join(I01_LOGIC_BUILT),
               ", ".join("::".join(prefix) for prefix in OBSERVER_LOGIC_PATHS)))
        say("observer D2 isolation: the D2 modules present are %s; outside them the module names occur only as lib.rs's "
            "pub mod lines, and none of the %d type names they define occurs in another %s source; every D2 impl is "
            "`impl <its own type> {` and no D2 file re-exports another item (HE-004D2, G-D2-5)"
            % (", ".join(D2_LOGIC_BUILT), check_observer_d2_isolation(HE), OBSERVER_CRATE))
        say("observer child modules: %s/src holds no directory, and none of the %d logic modules declares a module "
            "outside a strict test block (HE-004D2 PR review round 1, R1-6)" % (OBSERVER_CRATE, check_observer_child_modules(HE)))
        say("observer host-path literal: /opt/planeon/ occurs in %s only as %d exact `%s` (HE-004D2, G-D2-6)"
            % (OBSERVER_CRATE, check_observer_interpreter_tree(HE), INTERPRETER_TREE[0]))
        say("observer acceptance tokens: %d token(s) (%s), each with private fields of %s, no Clone, Copy, Default, Hash or "
            "serde derive (cfg_attr included), one impl of `&self` getters returning neither it nor Self, named only in its "
            "struct, impl header, minting signature and one literal inside the minting function, each getter returning its "
            "own field, a field reached outside the impl only by its getter call (R1-1); no `Self {` or `Self(` in %s "
            "(HE-004D2, G-D2-8)"
            % (check_observer_tokens(HE), ", ".join("%s in %s's %s" % (token, D2_TOKENS[token][0], D2_TOKENS[token][1])
                                                     for token in D2_TOKENS_BUILT),
               ", ".join(TOKEN_FIELD_TYPES), ", ".join(D2_TOKEN_FILES)))
        say("observer contracts: %d embedded files, each one plain literal naming a registered contract file, only in %s "
            "and (the OBSERVER programs) %s (HE-004B1); besides them only %s's include_bytes!(\"%s\") (HE-004C)"
            % (check_observer_includes(HE), OBSERVER_CONTRACTS, OBSERVER_SEAL_RS, OBSERVER_SIGNED_CONFIG,
               OBSERVER_KEY_INCLUDE))
        say("contracts pin: %s holds %d items, each a pub const of a registered contract file's bytes or of a registered "
            "pin, and nothing else (HE-004C, R1-3); it embeds only %s (HE-004D2, G-D2-2)"
            % (OBSERVER_CONTRACTS, check_observer_contracts_module(HE), ", ".join(OBSERVER_EMBEDDED_CONTRACTS)))
        say("observer no-panic: %d sources (the HE-004C modules, main.rs, status.rs, enrolled.rs, capture.rs and "
            "linux_capture.rs, HE-004-I01a's %s, and observer-sys's three after their item-level compile-time asserts) "
            "name no panicking macro or call outside strict #[cfg(test)] blocks (HE-004C, G8; HE-004D1, G-D1-11; "
            "HE-004-I01a, I01_NO_PANIC_BUILT)"
            % (check_observer_no_panic(HE), ", ".join("%s.rs" % name for name in I01_NO_PANIC_BUILT)))
        say("observer-sys calls: %s declares the one foreign item syscall and calls it %d times, each with seven "
            "arguments, the first one of the six numbers %s (pinned per target), openat's flags, ioctl's request and "
            "bpf's command single named constants (%s; %s), no other route to syscall and no SYS_ name elsewhere "
            "(HE-004D1, G-D1-3)" % (OBSERVER_SYS_KERNEL, check_observer_sys_calls(HE), ", ".join(SYS_NUMBERS["x86_64"]),
                                    ", ".join(IOCTL_REQUESTS), ", ".join(BPF_COMMANDS)))
        say("observer read-only (NP-3): %d openat calls, each with one of the four named flag sets %s built only from %s "
            "and asserted against %s; kernel.rs's cgroup file names exactly %s; no observer source names freeze; "
            "observer-sys names no write (HE-004D1, G-D1-4)"
            % (check_observer_read_only(HE), ", ".join(OPEN_FLAG_SETS), ", ".join(READ_ONLY_FLAGS), WRITE_MASK,
               ", ".join(CGROUP_FILE_NAMES)))
        say("capture callers: %d sources of %s; only %s names observer_sys, re-exports nothing and names no observer-sys "
            "item in a pub item, field or variant; LinuxCapture::new is called once, as LinuxCapture::new(sealed) in serve, "
            "its qualified forms counted (HE-004D2, G-D2-11); LinuxCapture is defined, implemented and renamed nowhere "
            "else (HE-004D1, G-D1-6); neither LinuxCapture nor LinuxWire is renamed or named by a type item, and each is "
            "named only in its own file and in serve (HE-004D2 PR review rounds 2 and 3, R2-1, R3-1)"
            % (check_observer_capture_callers(HE), OBSERVER_CRATE, OBSERVER_LINUX_CAPTURE))
        say("link reads: link_text reads only ProcLink's five names %s and own_pid only the proc root's self link, both "
            "defined once in %s and called (%d calls) only in %s (HE-004D1, G-D1-7)"
            % (", ".join(PROC_LINK_NAMES), OBSERVER_SYS_KERNEL, check_observer_links(HE), OBSERVER_LINUX_CAPTURE))
        say("observer-sys pinned names: %d function bodies of %s hold no item, no use declaration renames, each flag set, "
            "the verity request and each BPF command occur exactly in their definition, assert and the calls passing them, "
            "and link_text, own_pid and link_at name `name` and link_at only as pinned and bind no top-level name "
            "(HE-004D1 PR review round 1, R1-2; every observer-sys source without a renaming use, R2-2)"
            % (check_observer_sys_names(HE), OBSERVER_SYS_KERNEL))
        say("link-read path: %d functions of %s (%s) equal their pinned signatures and bodies, whitespace and comments "
            "aside (HE-004D1 PR review round 2, R2-1)" % (check_observer_link_pins(HE), OBSERVER_SYS_KERNEL,
                                                          ", ".join(LINK_PATH_PINS)))
        say("observer-sys pins: %d files match their pinned sha256 (%s) (HE-004D1 PR review round 3, R3-1; HE-004D2, "
            "G-D2-10: R4-1's lib.rs, dirent.rs and Cargo.toml)"
            % (check_observer_sys_pins(HE), ", ".join("%s %s" % item for item in OBSERVER_SYS_PINS.items())))
        say("constructor home pins: %d files match their pinned sha256 (%s) (HE-004D2, owner decision Q-D2-END)"
            % (check_observer_home_pins(HE), ", ".join("%s %s" % item for item in OBSERVER_HOME_PINS.items())))
        say("I01 digest contract files (HE-004-I01B1 and HE-004-I01B4, G-I01B-2): %d files, edge record v10's %s and "
            "edge record v11's %s, each at its record's row sha256, mode 100644, with its one PROVENANCE.md line, and "
            "none embedded (OBSERVER_EMBEDDED_CONTRACTS stays at %d)"
            % (check_i01b_contracts(HE), ", ".join("%s (row %d)" % (rel, row[0]) for rel, row in I01B_EDGE_V10_ROWS.items()),
               ", ".join("%s (row %d)" % (rel, row[0]) for rel, row in I01B_EDGE_V11_ROWS.items()),
               len(OBSERVER_EMBEDDED_CONTRACTS)))
        say("I01B4 replay scope (HE-004-I01B4, G-I01B4-1): %d crate sources; no registered or contracts/ file is profile "
            "v2's %s, by name or by sha256 %s; %s is included exactly once, by %s, and named in no other source; no fn "
            "(a const fn read as its fn), mod or other item takes a profile v2 validator's name (clauses (c), (c1)), no "
            "source path is named after "
            "profile v2 (c2), and row 79's %d negative texts and the schema's sha256 occur in no other source (c3)"
            % (check_i01b4_replay_scope(HE), PROFILE_V2_SCHEMA_NAME, PROFILE_V2_SCHEMA_SHA256, I01B4_ROW79,
               I01B4_ROW79_READER, I01B4_ROW79_TEXTS))
        say("I01b guarded pins (HE-004-I01B1, R-B3-PIN): %d entries: %s pinned whole by sha256 at their dd7422ed bytes, "
            "%s absent (no directory entry); no directory entry casefolds to a guarded name but itself, and each guarded "
            "module is declared once, in file form, in its crate's lib.rs and never inline (I1D-3, I1D-10)"
            % (check_i01b_guarded_pins(HE), ", ".join(I01B_GUARDED_PINS), ", ".join(I01B_ABSENT)))
        say("socket-module aliases (HE-004-I01B1, B3-1, G-I01B-6 (e)): %d sources of %s and %s; no use declaration "
            "targets a socket module (%s) itself, renamed or not, or globs one, no pub use names one, none names a "
            "scope root alone and none globs one outside a crate root; item imports through a socket module pass"
            % (check_socket_module_aliases(HE), EFFECT_GATE_CRATE, OBSERVER_CRATE,
               "; ".join("%s: %s" % (crate, ", ".join(modules)) for crate, modules in SOCKET_CRATE_MODULES.items())))
        say("observer I01B1 isolation (HE-004-I01B1, G-I01B-1, its I01B1 form): the modules present are %s; outside them "
            "their names occur only as lib.rs's pub mod lines, none of the %d type names they define occurs in another %s "
            "source, every impl in them is `impl <its own type> {` and none re-exports another item"
            % (", ".join(I01B1_MODULES), check_i01b1_isolation(HE), OBSERVER_CRATE))
        say("observer i01_ sources (HE-004-I01B1, G-I01B-7): %d files, exactly %s; lib.rs declares exactly the %d "
            "OBSERVER_LIB_MODULES, each once in file form, and no other source declares a module; the I01B1 modules take "
            "the logic and no-panic rules" % (check_i01b_sources(HE), ", ".join(I01_FILES_BUILT), len(OBSERVER_LIB_MODULES)))
        say("I01B1 constants and texts (HE-004-I01B1, G-I01B-8): %d constants against their sources (GATE_BOUND_MS, CYCLE, "
            "SCRAPE_TO_SET and SET_BUDGET against %s's captureGate; %s as literal pins with their citations); the three "
            "modules' %d refusal texts are exactly its refusalTexts"
            % (check_i01b_constants(HE), I01B_DEFINITIONS, ", ".join(name for name, _, _, _ in I01B_LITERAL_PINS),
               check_i01b_refusal_texts(HE)))
        say("observer never unlinks (HE-004-I01a, G-I01-1): %d sources of %s name no unlink, remove_file, remove_dir, "
            "remove_dir_all, rename or hard_link outside strict test blocks" % (check_observer_never_unlinks(HE), OBSERVER_CRATE))
        say("observer wait point (HE-004-I01a, G-I01-2): %d counted occurrences: wait once as the one wire wait inside "
            "%s's fn wait_serving and once as %s's self.poller.wait( inside its fn wait, and serve_peer_step once, as the "
            "method call inside wait_serving; no ::serve_peer_step path"
            % (check_observer_wait_point(HE), OBSERVER_CLIENT, OBSERVER_LINUX_NET))
        say("observer I01 path (HE-004-I01a, G-I01-4): %s occurs %d time(s) in %s, only as %s's private constant I01_PATH"
            % (I01_PATH, check_observer_i01_path(HE), OBSERVER_CRATE, OBSERVER_LINUX_LISTEN))
        say("observer sends nothing (HE-004-I01a, G-I01-5): %d sources; no peer_send; %s and %s neither import nor name "
            "gate-sys's channel send nor rename the channel module, their aliases followed, and neither renames or globs "
            "gate_sys nor declares an extern crate (HE-004-I01A2, R1-3); the i01_ sources are exactly %s, naming none of "
            "Wire, connect, ConnId and Client; PeerOps is declared once, as `pub trait PeerOps {`"
            % (check_observer_no_send(HE), OBSERVER_LINUX_NET, OBSERVER_LINUX_LISTEN, ", ".join(I01_FILES_BUILT) or "none yet"))
        say("observer I01 socket (HE-004-I01a, G-I01-6): %d sources; I01Socket is named only in %s and %s, renamed and "
            "aliased nowhere, and I01Socket::open is called once, inside LinuxWire::new, its qualified forms counted"
            % (check_observer_i01_socket(HE), OBSERVER_LINUX_LISTEN, OBSERVER_LINUX_NET))
        say("observer role pin (HE-004-I01a, G-I01-3): %s calls observer_rbac::check_observer_snapshot once, right after "
            "self.closure.check( with %d let statement(s) between, then `let dropped` and drop(produced)"
            % (OBSERVER_OBSERVE, check_observer_role_pin(HE)))
        say("observer role pin constants (HE-004-I01a, DESIGN-I01A section 10): %d constants of %s match %s's "
            "objectsPositive (the eight rules, the names, the apiVersion, the roleRef and the subject)"
            % (check_observer_role_constants(HE), OBSERVER_RBAC, I06_V4_VECTORS))
        say("native-profile schemas: %s occur %d times in %s, each its definition in %s and its one use in "
            "CaptureSchema::embedded (HE-004D1, G-D1-9; HE-004D2, G-D2-3)"
            % (" and ".join(NATIVE_PROFILE_SCHEMAS), check_native_profile_use(HE), OBSERVER_CRATE, OBSERVER_CONTRACTS))
        say("unsafe: the lexical tripwire finds the word only in %s among %d workspace sources"
            % (" and ".join(UNSAFE_FILES), check_unsafe(HE)))
        lock = tomllib.loads((HE / "Cargo.lock").read_text(encoding="utf-8"))["package"]
        markers = comment_markers(pin)
        host_paths = HOST_PATHS + tuple(path.encode() for path in (str(ROOT), str(Path.home())) if len(path) > 1)
        for target in targets:
            shape = pin["targets"][target]["shape"]
            for binary in BINARIES:
                raw = (HE / "target" / target / "release" / binary).read_bytes()
                exempt = binary_exempt(binary, HE)
                offset = check_binary(raw, target, shape, markers, host_paths, exempt)
                if binary == "planeon-observer":
                    names = symbol_names(raw)
                    size = check_observer_binary(names, raw, (HE / OBSERVER_PROGRAMS[target]).read_bytes())
                    client, module = check_observer_symbols(names)
                    say("%s planeon-observer program and symbols: the %d bytes of %s occur exactly once; no membarrier "
                        "or __membarrier; the composed client is linked: a rustls %s symbol and %s (no wrapper "
                        "inventory: owner decision Q-HE4A-B2 (a))" % (target, size, OBSERVER_PROGRAMS[target], client, module))
                    say("%s planeon-observer capture symbols (G-D1-14): %s" % (target, ", ".join(check_capture_symbols(names))))
                    say("%s planeon-observer D2 symbols (G-D2-7): none of its %d symbols has a path in planeon_observer::%s"
                        % (target, check_d2_absent(names), ", ::".join(D2_LOGIC_NAMES)))
                    say("%s planeon-observer I01B1 symbols (G-I01B-1): none of its %d symbols has a path in "
                        "planeon_observer::%s" % (target, check_i01b1_absent(names), ", ::".join(I01B1_MODULES)))
                    say("%s planeon-observer exempt span (G-D1-16): the %d bytes of %s occur exactly once, at offset %d "
                        "(length %d); the host-path scan (%s, the build root and the home directory) reads the binary "
                        "with that one span blanked and finds none; HOST_PATHS is unchanged, and every other binary is "
                        "scanned whole" % (target, len(exempt), EXEMPT_SPANS[binary], offset, len(exempt),
                                           ", ".join(needle.decode() for needle in HOST_PATHS)))
                if binary == "planeon-gate":
                    present = check_gate_symbols(symbol_names(raw))
                    say("%s planeon-gate symbols: gate-tls, rustls and ring present (the composed gate); no membarrier "
                        "or __membarrier; the musl wrappers of killed calls present are %s, each with its reviewed "
                        "justification" % (target, ", ".join(present) or "none"))
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
