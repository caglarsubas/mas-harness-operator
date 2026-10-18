"""Self-test of gate.py (stdlib unittest): the ELF parser, the table checks and the output-prefix rule.

gate.py runs this suite in-process before its checks and re-emits the unittest stream under its prefix.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import struct
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import gate

X86, ARM = "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"
COMMENT = b"Linker: LLD 23.1.1 (https://example.invalid/llvm 0)\0rustc version 1.99.0 (b940084d7 2026-09-28)\0"
PIN = {"rustc": {"release": "1.99.0", "commit": "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4", "llvm": "23.1.1"},
       "cargo": "cargo 1.99.0 (5f94df478 2026-08-27)", "host": "aarch64-apple-darwin", "sysroot": "/sys-root",
       "linkerWrapper": "host-enforcement/tools/rust-lld",
       "targets": {X86: {"shape": "static-pie"}, ARM: {"shape": "static"}},
       "commandLineTools": {"clang": "Apple clang version 14.0.3 (clang-1403.0.22.14.1)", "sdk": "13.3"},
       "cToolchain": {"compiler": "/clt/usr/bin/clang", "archiver": "/clt/usr/bin/ar",
                      "cflags": {X86: "-nostdlibinc -ffreestanding -DRING_CORE_NOSTDLIBINC=1", ARM: ""}}}
MARKERS = gate.comment_markers(PIN)


def build_elf(*, e_type=gate.ET_DYN, machine=62, loads=(5, 6), stack=6, interp=False, relro=True,
              dynamic=((gate.DT_FLAGS_1, gate.DF_1_PIE),), rela=(8, 8), comment=COMMENT, symbols=None, payload=b""):
    """A small ELF64 file: one PT_LOAD per entry of `loads` (flags), each mapping the whole file at address 0."""
    count = len(loads) + (stack is not None) + interp + relro + (dynamic is not None)
    blob = bytearray(64 + count * 56)

    def put(raw: bytes) -> int:
        blob.extend(b"\0" * (-len(blob) % 8))
        blob.extend(raw)
        return len(blob) - len(raw)

    dynamic_at = dynamic_size = interp_at = 0
    if dynamic is not None:
        entries = list(dynamic)
        if rela:
            rela_at = put(b"".join(struct.pack("<QQq", 0, kind, 0) for kind in rela))
            entries += [(gate.DT_RELA, rela_at), (gate.DT_RELASZ, 24 * len(rela)), (gate.DT_RELAENT, 24)]
        raw = b"".join(struct.pack("<qQ", tag, value) for tag, value in entries + [(gate.DT_NULL, 0)])
        dynamic_at, dynamic_size = put(raw), len(raw)
    if interp:
        interp_at = put(b"/lib/ld-musl-x86_64.so.1\0")
    put(payload)
    named = [(b".shstrtab", 3, None, 0, None)]              # (name, type, bytes, entsize, linked section)
    if comment is not None:
        named.append((b".comment", 1, comment, 1, None))
    if symbols is not None:
        strings = b"\0" + b"".join(name.encode() + b"\0" for name in symbols)
        table, at = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0), 1
        for name in symbols:
            table += struct.pack("<IBBHQQ", at, 0, 0, 1, 0, 0)    # local (STB_LOCAL) symbols
            at += len(name) + 1
        named += [(b".symtab", gate.SHT_SYMTAB, table, 24, b".strtab"), (b".strtab", 3, strings, 0, None)]
    shstrtab = b"\0" + b"".join(entry[0] + b"\0" for entry in named)
    index = {entry[0]: number + 1 for number, entry in enumerate(named)}
    records = [bytes(64)]
    for name, kind, data, entsize, link in named:
        data = shstrtab if data is None else data
        records.append(struct.pack("<IIQQQQIIQQ", shstrtab.index(b"\0" + name + b"\0") + 1, kind, 0, 0, put(data),
                                   len(data), index.get(link, 0), 0, 1, entsize))
    blob.extend(b"\0" * (-len(blob) % 8))
    shoff = len(blob)
    blob.extend(b"".join(records))
    total = len(blob)
    phdrs = [(gate.PT_LOAD, flags, 0, 0, 0, total, total, 0x1000) for flags in loads]
    if stack is not None:
        phdrs.append((gate.PT_GNU_STACK, stack, 0, 0, 0, 0, 0, 16))
    if interp:
        phdrs.append((gate.PT_INTERP, 4, interp_at, interp_at, interp_at, 25, 25, 1))
    if relro:
        phdrs.append((gate.PT_GNU_RELRO, 4, 0, 0, 0, 0, 0, 1))
    if dynamic is not None:
        phdrs.append((gate.PT_DYNAMIC, 6, dynamic_at, dynamic_at, dynamic_at, dynamic_size, dynamic_size, 8))
    blob[:64] = struct.pack("<4sBBBBB7sHHIQQQIHHHHHH", b"\x7fELF", 2, 1, 1, 0, 0, b"\0" * 7, e_type, machine, 1, 0,
                            64, shoff, 0, 64, 56, len(phdrs), 64, len(records), 1)
    for index, phdr in enumerate(phdrs):
        struct.pack_into("<IIQQQQQQ", blob, 64 + index * 56, *phdr)
    return bytes(blob)


def static_elf(**changes):
    options = dict(e_type=gate.ET_EXEC, machine=183, relro=False, dynamic=None, rela=())
    options.update(changes)
    return build_elf(**options)


class BinaryShapeTests(unittest.TestCase):
    def assertRefused(self, raw, message, target=X86, shape="static-pie"):
        with self.assertRaisesRegex(gate.GateError, message):
            gate.check_binary(raw, target, shape, MARKERS)

    def test_good_shapes_pass(self):
        gate.check_binary(build_elf(), X86, "static-pie", MARKERS)
        gate.check_binary(build_elf(machine=183, rela=(1027,)), ARM, "static-pie", MARKERS)
        gate.check_binary(build_elf(rela=()), X86, "static-pie", MARKERS)
        gate.check_binary(static_elf(), ARM, "static", MARKERS)

    def test_not_elf64(self):
        self.assertRefused(b"\x7fELF" + b"\1" * 60, "ELF64")
        self.assertRefused(b"MZ" + b"\0" * 100, "ELF64")

    def test_machine(self):
        self.assertRefused(build_elf(machine=183), "e_machine")
        self.assertRefused(static_elf(machine=62), "e_machine", ARM, "static")

    def test_interp(self):
        self.assertRefused(build_elf(interp=True), "PT_INTERP")

    def test_stack(self):
        self.assertRefused(build_elf(stack=7), "PT_GNU_STACK")
        self.assertRefused(build_elf(stack=None), "PT_GNU_STACK")

    def test_writable_and_executable_load(self):
        self.assertRefused(build_elf(loads=(5, 7)), "writable and executable")
        self.assertRefused(static_elf(loads=(7,)), "writable and executable", ARM, "static")

    def test_static_pie_shape(self):
        self.assertRefused(build_elf(e_type=gate.ET_EXEC), "ET_DYN")
        self.assertRefused(build_elf(relro=False), "PT_GNU_RELRO")
        self.assertRefused(build_elf(dynamic=None, rela=()), "PT_DYNAMIC")
        self.assertRefused(build_elf(dynamic=()), "DF_1_PIE")
        self.assertRefused(build_elf(dynamic=((gate.DT_FLAGS_1, 1),)), "DF_1_PIE")

    def test_dynamic_dependencies_and_relocations(self):
        pie = (gate.DT_FLAGS_1, gate.DF_1_PIE)
        self.assertRefused(build_elf(dynamic=(pie, (gate.DT_NEEDED, 1))), "DT_NEEDED")
        for tag in (gate.DT_REL, gate.DT_JMPREL, gate.DT_RELR):
            self.assertRefused(build_elf(dynamic=(pie, (tag, 0))), "other than RELA")
        self.assertRefused(build_elf(rela=(8, 1)), "non-relative")
        self.assertRefused(build_elf(rela=(1027,)), "non-relative")
        self.assertRefused(build_elf(machine=183, rela=(8,)), "non-relative", ARM)

    def test_static_shape(self):
        self.assertRefused(static_elf(e_type=gate.ET_DYN), "ET_EXEC", ARM, "static")
        self.assertRefused(static_elf(dynamic=()), "ET_EXEC", ARM, "static")
        self.assertRefused(static_elf(), "ET_EXEC", ARM, "unknown-shape")

    def test_comment(self):
        self.assertRefused(build_elf(comment=None), ".comment missing")
        rustc = b"rustc version 1.99.0 (b940084d7 2026-09-28)\0"
        self.assertRefused(build_elf(comment=b"Linker: LLD 23.1.1 (x)\0"), "rustc version 1.99.0")
        self.assertRefused(build_elf(comment=b"rustc version 1.98.0 (aaaaaaaaa 2026-08-01)\0Linker: LLD 23.1.1 (x)\0"),
                           "rustc")
        self.assertRefused(build_elf(comment=b"rustc version 1.99.0 (b940084d8 2026-09-28)\0Linker: LLD 23.1.1 (x)\0"),
                           "rustc")
        self.assertRefused(build_elf(comment=rustc + b"GCC: (GNU) 13\0"), "LLD")
        for linker in (b"Linker: LLD 22.1.8 (x)", b"Linker: LLD 23.1.10 (x)", b"Linker: LLD 23.1.1"):
            self.assertRefused(build_elf(comment=rustc + linker + b"\0"), "LLD 23.1.1")

    def test_host_paths(self):
        for needle in (b"/Users/someone/src", b"/opt/planeon/toolchains", b"/private/tmp/x", b"/private/var/folders"):
            self.assertRefused(build_elf(payload=needle), "build-host path")
        with self.assertRaisesRegex(gate.GateError, "build-host path"):
            gate.check_binary(build_elf(payload=b"/srv/checkout/x"), X86, "static-pie", MARKERS, (b"/srv/checkout",))

    def test_truncated_file_fails(self):
        raw = build_elf()
        with self.assertRaises(Exception):
            gate.check_binary(raw[:200], X86, "static-pie", MARKERS)


class CrtObjectTests(unittest.TestCase):
    def test_compiler_rt_objects_pass(self):
        gate.check_crt_symbols("crtbeginS.o", gate.symbol_names(build_elf(symbols=["__do_init", "__do_fini", "x"])))
        gate.check_crt_symbols("crtend.o", gate.symbol_names(build_elf(symbols=["__EH_FRAME_LIST_END__"])))

    def test_local_symbols_are_read(self):
        self.assertEqual(gate.symbol_names(build_elf(symbols=["a", "bb"])), {"a", "bb"})

    def test_gcc_objects_fail(self):
        for name, symbols in (("crtbegin.o", ["frame_dummy", "__do_global_dtors_aux"]),
                              ("crtbegin.o", ["__do_init", "__do_fini", "frame_dummy"]),
                              ("crtbeginS.o", ["__do_init"]),
                              ("crtend.o", ["__FRAME_END__", "__TMC_END__"]),
                              ("crtendS.o", ["__EH_FRAME_LIST_END__", "__TMC_END__"])):
            with self.assertRaisesRegex(gate.GateError, "compiler-rt"):
                gate.check_crt_symbols(name, gate.symbol_names(build_elf(symbols=symbols)))

    def test_missing_symbol_table_fails(self):
        with self.assertRaisesRegex(gate.GateError, "symtab"):
            gate.symbol_names(build_elf())


def row(target, path, data, outcome="ACCEPTED_OR", role="LINKED"):
    return {"target": target, "path": path, "sha256": hashlib.sha256(data).hexdigest(), "outcome": outcome, "role": role,
            "component": "c-" + path, "version": "1", "canonical": "MIT"}


class TableTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.sysroot = Path(self.directory.name)
        self.files = {(X86, "lib/liba.rlib"): b"a", (X86, "lib/self-contained/libc.a"): b"c", (ARM, "lib/liba.rlib"): b"b"}
        for (target, path), data in self.files.items():
            target_path = self.sysroot / "lib/rustlib" / target / path
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(data)
        self.rows = [row(target, path, data) for (target, path), data in self.files.items()]

    def tearDown(self):
        self.directory.cleanup()

    def table(self, rows, outcomes=gate.ACCEPTED):
        raw = json.dumps({"acceptedOutcomes": list(outcomes), "rows": rows}).encode()
        return raw, hashlib.sha256(raw).hexdigest()

    def test_matching_tree_passes(self):
        raw, digest = self.table(self.rows)
        gate.check_tree(gate.load_table(raw, digest), self.sysroot, [X86, ARM])

    def test_table_digest_is_pinned(self):
        raw, _ = self.table(self.rows)
        with self.assertRaisesRegex(gate.GateError, "reviewed table"):
            gate.load_table(raw, "0" * 64)

    def test_outcomes(self):
        raw, digest = self.table(self.rows[:2] + [row(ARM, "lib/liba.rlib", b"b", outcome="REJECTED")])
        with self.assertRaisesRegex(gate.GateError, "not accepted"):
            gate.load_table(raw, digest)
        raw, digest = self.table(self.rows, outcomes=gate.ACCEPTED + ("NEEDS_REVIEW",))
        with self.assertRaisesRegex(gate.GateError, "accepted outcomes"):
            gate.load_table(raw, digest)

    def test_duplicate_rows(self):
        raw, digest = self.table(self.rows + self.rows[:1])
        with self.assertRaisesRegex(gate.GateError, "duplicate"):
            gate.load_table(raw, digest)

    def test_extra_missing_and_changed_files(self):
        extra = self.sysroot / "lib/rustlib" / X86 / "lib/libextra.rlib"
        extra.write_bytes(b"x")
        with self.assertRaisesRegex(gate.GateError, "differ from the closure table"):
            gate.check_tree(self.rows, self.sysroot, [X86, ARM])
        extra.unlink()
        with self.assertRaisesRegex(gate.GateError, "differ from the closure table"):
            gate.check_tree(self.rows + [row(ARM, "lib/libgone.rlib", b"g")], self.sysroot, [X86, ARM])
        (self.sysroot / "lib/rustlib" / ARM / "lib/liba.rlib").write_bytes(b"changed")
        with self.assertRaisesRegex(gate.GateError, "differs from its row"):
            gate.check_tree(self.rows, self.sysroot, [X86, ARM])

    def test_empty_target_and_symlink(self):
        with self.assertRaisesRegex(gate.GateError, "differ from the closure table"):
            gate.check_tree([], self.sysroot / "missing", [X86])
        os.symlink("liba.rlib", self.sysroot / "lib/rustlib" / X86 / "lib/link.rlib")
        with self.assertRaisesRegex(gate.GateError, "symbolic link"):
            gate.check_tree(self.rows, self.sysroot, [X86])

    def test_sbom_is_deterministic_and_lists_linked_rows(self):
        rows = self.rows + [row(X86, "lib/libunused.rlib", b"u", role="SHIPPED_NOT_LINKED")]
        first = gate.sbom("planeon-gate", X86, "ab" * 32, rows, {"host-common", "planeon-gate"})
        second = gate.sbom("planeon-gate", X86, "ab" * 32, list(reversed(rows)), {"planeon-gate", "host-common"})
        self.assertEqual(first, second)
        document = json.loads(first)
        self.assertEqual((document["bomFormat"], document["specVersion"]), ("CycloneDX", "1.5"))
        self.assertNotIn("timestamp", json.dumps(document))
        self.assertEqual(document["metadata"]["component"]["hashes"][0]["content"], "ab" * 32)
        names = sorted(component["name"] for component in document["components"])
        self.assertEqual(names, ["c-lib/liba.rlib", "c-lib/self-contained/libc.a", "host-common", "planeon-gate"])
        self.assertNotEqual(first, gate.sbom("planeon-gate", X86, "cd" * 32, rows, {"host-common", "planeon-gate"}))
        serial = uuid.UUID(document["serialNumber"])
        self.assertEqual((document["serialNumber"][:9], serial.version, serial.variant), ("urn:uuid:", 5, uuid.RFC_4122))


class WorkspaceAndSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        (self.base / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/a", "crates/b"]\n')
        for name in ("a", "b"):
            (self.base / "crates" / name / "src").mkdir(parents=True)
            (self.base / "crates" / name / "Cargo.toml").write_text('[package]\nname = "%s"\n' % name)
            (self.base / "crates" / name / "src/main.rs").write_text("fn main() { let _ = std::env::args_os(); }\n")
        self.lock('[[package]]\nname = "a"\nversion = "0.1.0"\n\n[[package]]\nname = "b"\nversion = "0.1.0"\n')

    def tearDown(self):
        self.directory.cleanup()

    def lock(self, text):
        (self.base / "Cargo.lock").write_text("version = 4\n\n" + text)

    def test_workspace_passes(self):
        self.assertEqual(gate.check_workspace(self.base), {"a": set(), "b": set()})

    def test_dependency_closure_and_workspace_only_dependencies(self):
        (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n\n[dependencies]\nb = { path = "../b" }\n')
        dependencies = gate.check_workspace(self.base)
        self.assertEqual(dependencies, {"a": {"b"}, "b": set()})
        self.assertEqual(gate.linked(dependencies, "a"), {"a", "b"})
        self.assertEqual(gate.linked(dependencies, "b"), {"b"})
        for spec in ('b = "1.0"', 'b = { path = "../b", version = "1" }', 'c = { path = "../b" }',
                     'b = { git = "https://example.invalid/b" }'):
            (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n\n[dependencies]\n%s\n' % spec)
            with self.assertRaisesRegex(gate.GateError, "dependency outside the workspace"):
                gate.check_workspace(self.base)
        (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n\n[build-dependencies]\nb = { path = "../b" }\n')
        with self.assertRaisesRegex(gate.GateError, "build or target dependencies"):
            gate.check_workspace(self.base)
        # PR review R1-3: a [features] table is refused (it could enable rustls/tls12 with Cargo.lock unchanged).
        (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n\n[features]\ndefault = ["b/x"]\n')
        with self.assertRaisesRegex(gate.GateError, "a \\[features\\] table in crates/a"):
            gate.check_workspace(self.base)

    def test_build_scripts_and_proc_macros(self):
        (self.base / "crates/a/build.rs").write_text("fn main() {}\n")
        with self.assertRaisesRegex(gate.GateError, "build script"):
            gate.check_workspace(self.base)
        (self.base / "crates/a/build.rs").unlink()
        (self.base / "crates/b/Cargo.toml").write_text('[package]\nname = "b"\nbuild = "gen.rs"\n')
        with self.assertRaisesRegex(gate.GateError, "build script"):
            gate.check_workspace(self.base)
        for spelling in ("proc-macro", "proc_macro"):
            (self.base / "crates/b/Cargo.toml").write_text('[package]\nname = "b"\n\n[lib]\n%s = true\n' % spelling)
            with self.assertRaisesRegex(gate.GateError, "proc-macro"):
                gate.check_workspace(self.base)

    def test_lock(self):
        self.lock('[[package]]\nname = "a"\nversion = "0.1.0"\n')
        with self.assertRaisesRegex(gate.GateError, "exactly the workspace crates"):
            gate.check_workspace(self.base)
        self.lock('[[package]]\nname = "a"\nversion = "0.1.0"\n\n[[package]]\nname = "b"\nversion = "0.1.0"\n\n'
                  '[[package]]\nname = "b"\nversion = "0.2.0"\n')
        with self.assertRaisesRegex(gate.GateError, "exactly the workspace crates"):
            gate.check_workspace(self.base)
        self.lock('[[package]]\nname = "a"\nversion = "0.1.0"\n\n[[package]]\nname = "b"\nversion = "0.1.0"\n\n'
                  '[[package]]\nname = "c"\nversion = "0.1.0"\n'
                  'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "00"\n')
        with self.assertRaisesRegex(gate.GateError, "registry or git"):
            gate.check_workspace(self.base)

    def test_start_up_lint(self):
        self.assertEqual(gate.check_sources(self.base), 2)
        (self.base / "target/debug").mkdir(parents=True)
        (self.base / "target/debug/generated.rs").write_text("std::thread::available_parallelism()\n")
        self.assertEqual(gate.check_sources(self.base), 2)
        nested = self.base / "crates/a/src/target/mod.rs"   # a module named target is still workspace source
        nested.parent.mkdir()
        nested.write_text("pub fn f() -> usize { std::thread::available_parallelism().map_or(1, |n| n.get()) }\n")
        with self.assertRaisesRegex(gate.GateError, "crates/a/src/target/mod.rs uses available_parallelism"):
            gate.check_sources(self.base)
        nested.unlink()
        main = self.base / "crates/a/src/main.rs"
        for token in gate.FORBIDDEN_SOURCE:
            main.write_text("fn main() { let _ = %s; }\n" % token)
            with self.assertRaisesRegex(gate.GateError, "start-up lint"):
                gate.check_sources(self.base)

    # HE-002S DESIGN section 6 (D3): one occurrence of the status read's expression is excepted in gate-sys's seal.rs
    # only (PR review round 1, R1-5: not the bare literal, and not twice).
    def test_start_up_lint_exception_is_one_expression_in_one_file(self):
        seal = self.base / "crates/gate-sys/src/seal.rs"
        seal.parent.mkdir(parents=True)
        status = 'pub fn own_status() { let _ = Dir::at("/proc/self")?.file_ro("status")?; }\n'
        for text in (status, 'fn f() { let _ = Dir :: at( "/proc/self" )\n    ? . file_ro ("status")?; }\n'):
            seal.write_text(text)
            self.assertEqual(gate.check_sources(self.base), 3)
        for text in ('let _ = Dir::at("/proc/self/status");', "// reads /proc/self", 'let _ = "/proc/self/exe";',
                     'let _ = ("/proc/self", "/sys");', 'let _ = Dir::at("/proc/self");',
                     'let _ = Dir::at(r"/proc/self")?.file_ro("status");',
                     'let _ = Dir::at(r#"/proc/self"#)?.file_ro("status");',
                     'let _ = Dir::at(concat!("/proc", "/self"))?.file_ro("status");',
                     '// Dir::at("/proc/self")?.file_ro("status")\nlet _ = Dir::at(r"/proc/self")?.file_ro("status");',
                     status + 'let _ = Dir::at("/proc/self")?.file_ro("status");',
                     'let _ = Dir::at("/proc/self")?.file_ro("environ");',
                     'let _ = Dir::at("/proc/self")?.file_ro("status")?;\nlet _ = Dir::at("/proc/1")?.file_ro("status");'):
            seal.write_text(text + "\n")
            with self.assertRaisesRegex(gate.GateError, "crates/gate-sys/src/seal.rs uses /(proc|sys) .start-up lint"):
                gate.check_sources(self.base)
        seal.unlink()
        for rel in ("crates/a/src/main.rs", "crates/gate-sys/src/openat.rs", "crates/effect-gate/src/seal.rs"):
            path = self.base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fn f() { let _ = Dir::at("/proc/self"); }\n')
            with self.assertRaisesRegex(gate.GateError, "uses /proc .start-up lint"):
                gate.check_sources(self.base)
            path.unlink()


LINKED_TREE = {
    "crates/i05-protocol/src/lib.rs": "//! Protocol.\n#![forbid(unsafe_code)]\npub mod json;\n",
    "crates/i05-protocol/src/json.rs": "use std::collections::BTreeMap;\npub fn parse() {}\n",
    "crates/effect-gate/src/lib.rs": "#![forbid(unsafe_code)]\npub mod file_store;\n",
    "crates/effect-gate/src/file_store.rs": "use std::fs::File;\nuse std::io;\nuse std::os::unix::fs::FileExt;\n"
                                           "pub fn open() {} // FileStores::open, Gate::open, Gate::create\n",
    "crates/effect-gate/tests/files.rs": "use std::process::Command;\nuse std::os::fd::AsRawFd;\n",
    "crates/gate-sys/src/lib.rs": "#![deny(unsafe_code)]\npub mod openat;\n",
    "crates/gate-tls/src/lib.rs": "#![forbid(unsafe_code)]\npub mod tls;\n",
    "crates/gate-sys/src/openat.rs": "#![allow(unsafe_code)]\nuse std::fs::File;\nuse std::os::fd::FromRawFd;\n"
                                     "use std::os::unix::fs::MetadataExt;\nunsafe extern \"C\" {}\n"
                                     "fn f(fd: i32) -> File { unsafe { std::fs::File::from_raw_fd(fd) } }\n",
    # HE-003D: the gate binary joins the linked crates (with its crate-root attribute); the broker stays unlinked.
    "crates/gate/src/main.rs": "#![forbid(unsafe_code)]\nfn main() {}\n",
    # HE-004A: the observer's library and binary roots join the scanned crates (CRATE_ROOTS).
    "crates/observer/src/lib.rs": "#![forbid(unsafe_code)]\npub mod seal;\n",
    "crates/observer/src/main.rs": "#![forbid(unsafe_code)]\nfn main() {}\n",
    # HE-004D1 (G-D1-1): observer-sys's root joins the scanned crates (CRATE_ROOTS).
    "crates/observer-sys/src/lib.rs": "//! Kernel reads.\n#![deny(unsafe_code)]\n",
    "crates/broker/src/main.rs": "fn main() {}\n",
    "target/debug/build/out.rs": "unsafe fn generated() {}\n",
}


class LinkedSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        for rel, text in LINKED_TREE.items():
            self.write(rel, text)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, rel, text):
        path = self.base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def refused(self, rel, text, message, check=gate.check_linked_sources):
        self.write(rel, text)
        with self.assertRaisesRegex(gate.GateError, message):
            check(self.base)
        if rel in LINKED_TREE:
            self.write(rel, LINKED_TREE[rel])
        else:
            (self.base / rel).unlink()

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_linked_sources(self.base), 11)
        self.assertEqual(gate.check_unsafe(self.base), 13)
        self.assertEqual(gate.check_included_code(self.base), 13)

    def test_forbidden_names_in_linked_sources(self):
        for text in ("use std::process::Command;", "let _ = std::env::args_os();", "use std::net::TcpStream;",
                     "use std::path::Path;", "fn f(_: &Path) {}", "fn f(_: PathBuf) {}", "let _ = DirBuilder::new();",
                     "let _ = OpenOptions::new();", "let _ = File::open(x);", "let _ = File::create(x);",
                     "let _ = File::options();", "Err(TryLockError::WouldBlock) => {}", "fn f(_: Metadata) {}"):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", "linked-source tripwire")
            self.refused("crates/gate-sys/src/openat.rs", LINKED_TREE["crates/gate-sys/src/openat.rs"] + text + "\n",
                         "linked-source tripwire")
        # Tests and other crates are outside the linked-source tripwire (the start-up lint and the unsafe rule still apply).
        self.write("crates/broker/src/main.rs", "use std::path::Path;\nfn main() {}\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    def test_std_fs_items(self):
        source = "crates/effect-gate/src/file_store.rs"
        for text in ("use std::fs::{File};", "use std::fs;", "let _ = std::fs::read(x);", "use std::fs::FileType;",
                     "use std::os::unix::fs::MetadataExt;", "use std::os::unix::fs;", "use std::{fs, io};", "let _ = fs::File::from_raw_fd;"):
            self.refused(source, LINKED_TREE[source] + text + "\n", "std fs item")
        self.refused("crates/effect-gate/src/gate.rs", "use std::os::unix::fs::FileExt;\n", "std fs item")
        self.refused("crates/gate-sys/src/lib.rs", LINKED_TREE["crates/gate-sys/src/lib.rs"]
                     + "use std::os::unix::fs::{FileExt, MetadataExt};\n", "std fs item")
        self.write("crates/gate-sys/src/lib.rs", LINKED_TREE["crates/gate-sys/src/lib.rs"]
                   + "use std::os::unix::fs::FileExt;\nuse std::os::unix::fs::MetadataExt;\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    def test_fd_items_only_in_openat(self):
        for text in ("use std::os::fd::AsRawFd;", "fn f(_: RawFd) {}", "use std::os::unix::io::FromRawFd;",
                     "fn f(_: OwnedFd) {}"):
            self.refused("crates/gate-sys/src/lib.rs", LINKED_TREE["crates/gate-sys/src/lib.rs"] + text + "\n",
                         "std::os::fd item outside")
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "std::os::fd item outside")

    def test_std_uses_are_not_renamed(self):
        for text in ("use std::fs::File as Handle;", "use std::io::{self as stdio};", "use std::collections::{\n  BTreeMap as Map,\n};",
                     "use std::io as z;"):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", "renames a std item")
        self.write("crates/i05-protocol/src/json.rs", "use crate::json as j;\nlet x = y as u64;\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    # HE-002S PR review round 1, R1-2 (d): a rename through a use of a name imported from std (in any linked source,
    # whatever the order), and a top-level group that renames std.
    def test_std_renames_through_other_uses(self):
        json, store = "crates/i05-protocol/src/json.rs", "crates/effect-gate/src/file_store.rs"
        message = "renames a std module or item through a use of a name imported from std"
        for rel, text in ((json, "use std::io;\nuse io as z;\nfn f() { z::copy(&mut a, &mut b); }"),
                          (json, "use io as z;\nuse std::io;"),
                          (json, "use std::io;\nuse self::io as z;"),
                          (json, "use std::io::{self, Read};\nuse io::{copy as c};"),
                          (json, "use std::io::Read;\npub use Read as R;"),
                          (json, "use {std::io as z};"),
                          (json, "use ::std::io;\nuse {io as z};"),
                          (json, "use crate::io as z;"),            # io is imported from std by file_store.rs
                          (json, "use super::m::File as F;"),
                          (store, LINKED_TREE[store] + "mod m { pub use super::io; }\nuse m::io as z;")):
            self.refused(rel, text + "\n", message)
        # A use the reader cannot follow refuses; renames of other names and the precise-capturing `use<..>` pass.
        self.refused(json, "macro_rules! m { () => { use $crate::json; } }\n", "use declaration .* cannot read")
        self.write(json, "use crate::json as j;\nuse crate::frame::{Frame as F, self as fr};\n"
                         "fn f<'a>(x: &'a u8) -> impl Sized + use<'a> { x }\n// use std::io; use io as z;\n"
                         "const S: &str = \"use io as z;\";\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    # HE-002S PR review round 2, R2-1: a glob through std or a name imported from std.
    def test_std_globs_through_other_uses(self):
        json, store = "crates/i05-protocol/src/json.rs", "crates/effect-gate/src/file_store.rs"
        message = "imports a glob through std or a name imported from std"
        for rel, text in ((json, "use std::io::{*};\nfn f() { copy(&mut a, &mut b); }"),
                          (json, "use std::io;\nuse io::*;"),
                          (json, "use std::io::{self, *};"),
                          (store, LINKED_TREE[store] + "mod m { pub use super::io::*; }")):
            self.refused(rel, text + "\n", message)
        self.write(json, "use crate::json::*;\n#[cfg(test)]\nmod tests { use super::*; }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    def test_crate_root_attributes(self):
        for rel in gate.CRATE_ROOTS:
            self.refused(rel, "pub mod x;\n", "lacks")
        self.refused("crates/gate-sys/src/lib.rs", "#![forbid(unsafe_code)]\npub mod openat;\n", "lacks")
        self.refused("crates/effect-gate/src/lib.rs", "#![deny(unsafe_code)]\npub mod file_store;\n", "lacks")

    def test_unsafe_is_confined_to_openat(self):
        for rel in ("crates/effect-gate/tests/files.rs", "crates/broker/src/main.rs", "crates/i05-protocol/src/json.rs",
                    "crates/gate-sys/src/lib.rs"):
            self.refused(rel, LINKED_TREE.get(rel, "") + "// no unsafe here\n", "contains unsafe outside",
                         check=gate.check_unsafe)
        self.write("crates/effect-gate/src/lib.rs", "#![forbid(unsafe_code)]\n// unsafe_code is a lint name\n")
        self.assertEqual(gate.check_unsafe(self.base), 13)

    # HE-002S DESIGN section 6: gate-sys's seal.rs is the second file that may contain the word unsafe.
    def test_unsafe_is_also_allowed_in_gate_sys_seal(self):
        self.write("crates/gate-sys/src/seal.rs", "#![allow(unsafe_code)]\nfn f() -> i32 { unsafe { prctl(38, 1) } }\n")
        self.assertEqual(gate.check_unsafe(self.base), 14)
        for rel in ("crates/effect-gate/src/seal.rs", "crates/gate-sys/src/seal/raw.rs", "crates/gate-sys/tests/seal.rs"):
            self.refused(rel, "fn f() { unsafe { g() } }\n", "contains unsafe outside crates/gate-sys/src/openat.rs and "
                         "crates/gate-sys/src/seal.rs", check=gate.check_unsafe)

    # HE-002C PR review round 3, R3-1: a renaming import of global_asm or naked_asm.
    def test_renamed_assembly_macros(self):
        for rel in ("crates/broker/src/main.rs", "crates/effect-gate/src/file_store.rs"):
            for text in ("use core::arch::global_asm as ga;\nga!(\".globl x\");", "use core::arch::{naked_asm as na};",
                         "use std::arch::global_asm as ga;",
                         "macro_rules! call { ($m:ident) => { core::arch::$m!(\"\"); } }\ncall!(global_asm);"):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", "uses inline assembly", check=gate.check_included_code)
        self.write("crates/broker/src/main.rs", "fn main() { let global_asmx = 1; let _ = global_asmx; }\n")
        self.assertEqual(gate.check_included_code(self.base), 13)

    # HE-002S PR review round 1, R1-4: a renaming import of asm (now possible in seal.rs too), and the word asm in a
    # linked source, where a macro could otherwise assemble the call from its arguments.
    def test_renamed_asm(self):
        for rel in ("crates/gate-sys/src/seal.rs", "crates/broker/src/main.rs", "crates/effect-gate/src/file_store.rs"):
            for text in ("use core::arch::asm as a;\nfn f() { unsafe { a!(\"nop\") } }", "use core::arch::{asm as a};",
                         "use std :: arch :: asm;", "use core::arch::{global_asm, asm};", "use core::arch::{\n    asm,\n};"):
                self.refused(rel, LINKED_TREE.get(rel, "") + text + "\n", "uses inline assembly",
                             check=gate.check_included_code)
        for rel, text in (("crates/gate-sys/src/seal.rs", "use core::arch as ar;\nfn f() { call!(unsafe ar::asm) }"),
                          ("crates/gate-sys/src/lib.rs", LINKED_TREE["crates/gate-sys/src/lib.rs"]
                           + "macro_rules! call { ($u:tt $a:ident $b:tt) => { $u { $a::asm $b (\"nop\") } } }"),
                          ("crates/i05-protocol/src/json.rs", "fn f() { let asm = 1; }")):
            self.refused(rel, text + "\n", "names asm .inline assembly. .linked-source tripwire")
        # Outside the linked crates the word alone passes; the forms above do not.
        self.write("crates/broker/src/main.rs", "fn main() { let asm = 1; let _ = asm; }\n")
        self.assertEqual(gate.check_included_code(self.base), 13)
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    # HE-002S DESIGN section 5 (D7): std APIs that reach a call the EFFECT_GATE filter kills, in effect-gate, gate-sys
    # and (PR review round 1, R1-2) i05-protocol, whose code runs after the seal too; is_terminal joins the list.
    def test_post_seal_std_apis(self):
        self.assertEqual(gate.check_post_seal_sources(self.base), 8)
        for text, name in (("let _ = stream.set_nonblocking(true);", "set_nonblocking"),
                           ("for entry in std::fs::read_dir(x) {}", "read_dir"), ("let _ = current_exe();", "current_exe"),
                           ("let _ = uname(x);", "uname"), ("membarrier(0, 0);", "membarrier"),
                           ("file.set_len(0)?;", "set_len"), ("file.set_permissions(p)?;", "set_permissions"),
                           ("file.set_times(t)?;", "set_times"), ("file.set_modified(t)?;", "set_modified"),
                           ("std::io::copy(&mut a, &mut b)?;", "io::copy"), ("let _ = io :: copy(&mut a, &mut b);", "io::copy"),
                           ("use std::io::{self, copy};", "io::copy in a grouped import"),
                           ("if file.is_terminal() { return; }", "is_terminal"),
                           ("use std::io::IsTerminal;", "IsTerminal"), ("fn f(_: &dyn IsTerminal) {}", "IsTerminal")):
            for rel in ("crates/effect-gate/src/file_store.rs", "crates/gate-sys/src/openat.rs",
                        "crates/i05-protocol/src/json.rs"):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", re.escape(name) + r" .*\(post-seal check\)",
                             check=gate.check_post_seal_sources)
        # The tests and the binary crates run no post-seal code of the gate; try_clone (fcntl) is allowed.
        self.write("crates/effect-gate/tests/files.rs", "fn f(f: &File) { let _ = f.set_len(0); }\n")
        self.write("crates/broker/src/main.rs", "fn main() { let _ = std::io::stdin().is_terminal(); }\n")
        self.write("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                   + "fn g(f: &File) { let _ = f.try_clone(); let _ = copy_from_slice; let _ = terminal; }\n")
        self.assertEqual(gate.check_post_seal_sources(self.base), 8)

    # HE-002C PR review round 2, R2-1 and R2-2: std::os paths, nested globs, std aliases, raw identifiers, inline
    # assembly, symlinks and manifest paths.

    def test_std_os_paths(self):
        for text in ("use std::os::unix::net::UnixStream;", "let _ = std::os::unix::net::UnixListener::bind(p);",
                     "use std::os;", "let _ = std :: os :: unix :: process::CommandExt;"):
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "std::os item other than")
            self.refused("crates/gate-sys/src/openat.rs", LINKED_TREE["crates/gate-sys/src/openat.rs"] + text + "\n",
                         "std::os item other than")
        self.write("crates/gate-sys/src/openat.rs", LINKED_TREE["crates/gate-sys/src/openat.rs"]
                   + "use std::os::fd::AsRawFd;\nuse std::os::fd::OwnedFd;\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    def test_nested_globs_and_std_aliases(self):
        for text, message in (("use std::collections::*;", "nested glob of std"),
                              ("use std :: io :: prelude :: * ;", "nested glob of std"),
                              ("use std::os::unix::prelude::*;", "std::os item other than"),
                              ("use {std as s};", "renames std"), ("pub use { std  as  s };", "renames std")):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", message)
        self.write("crates/i05-protocol/src/json.rs", "mod tests { use super::*; }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    def test_raw_identifiers_and_inline_assembly(self):
        for rel in ("crates/i05-protocol/src/json.rs", "crates/broker/src/main.rs", "crates/effect-gate/tests/files.rs"):
            for text, message in (("let _ = std::r#process::Command::new(x);", "uses a raw identifier"),
                                  ("use r#std as s;", "uses a raw identifier"),
                                  ('#[r#path = "x.inc"] mod m;', "uses a raw identifier"),
                                  ('core::arch::global_asm!("");', "uses inline assembly"),
                                  ('fn f() { asm ! ("nop") }', "uses inline assembly")):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", message, check=gate.check_included_code)
        self.write("crates/broker/src/main.rs", 'fn main() { let _ = r#"raw string"#; let asm = 1; }\n')
        self.assertEqual(gate.check_included_code(self.base), 13)

    def test_symlinks_and_manifest_paths(self):
        (self.base / "crates/elsewhere").mkdir()
        (self.base / "crates/linked").symlink_to(self.base / "crates/elsewhere")
        with self.assertRaisesRegex(gate.GateError, "is a symlink under crates/"):
            gate.check_included_code(self.base)
        (self.base / "crates/linked").unlink()
        (self.base / "crates/elsewhere").rmdir()
        for text, message in (('[package]\nname = "gate"\nbuild = "b.rs"\n', "names a build script"),
                              ('[package]\nname = "gate"\n[lib]\npath = "../other/lib.rs"\n', "gives a lib target a path"),
                              ('[package]\nname = "gate"\n[[bin]]\nname = "g"\npath = "x.rs"\n',
                               "gives a bin target a path")):
            self.refused("crates/gate/Cargo.toml", text, message, check=gate.check_included_code)
        self.write("crates/gate/Cargo.toml", '[package]\nname = "gate"\n[dependencies]\nhost-common = { path = "../host-common" }\n')
        self.assertEqual(gate.check_included_code(self.base), 13)

    # HE-002C PR review round 1, R1-1: the forms that passed the first tripwire.

    def test_grouped_std_imports(self):
        for text in ("use std::{process::Command};", "use std :: {net::TcpStream};", "pub use ::std::{env};",
                     "use std::*;", "pub use std :: * ;"):
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "top-level group or glob of std")
        self.write("crates/i05-protocol/src/json.rs", "use std::collections::{BTreeMap, BTreeSet};\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    def test_spaced_paths(self):
        for text, message in (("let _ = std :: process :: Command::new(x);", "std::process"),
                              ("let _ = std\n    ::env::args_os();", "std::env"),
                              ("let _ = ::std:: net ::TcpStream::connect(x);", "std::net"),
                              ("let _ = std::fs::File :: open(x);", "File::open"),
                              ("let _ = File ::create(x);", "File::create"),
                              ("use std :: os :: fd;", "std::os::fd item outside"),
                              ("use std :: fs;", "std fs item"),
                              ("use std::fs :: File as Handle;", "renames a std item")):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", message)
        self.write("crates/effect-gate/src/file_store.rs", "use std :: fs :: File;\nuse std::os::unix::fs ::FileExt;\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)

    def test_extern_crate(self):
        for text in ("extern crate std as s;\nfn f() { let _ = s::net::TcpStream::connect(x); }", "extern  crate alloc;"):
            self.refused("crates/gate-sys/src/lib.rs", LINKED_TREE["crates/gate-sys/src/lib.rs"] + text + "\n",
                         "declares an extern crate")

    def test_macro_built_std_paths(self):
        for text in ("macro_rules! m { ($k:ident) => { std::$k::Command::new(x) } }",
                     "macro_rules! m { ($k:ident) => { std :: $k :: TcpStream::connect(x) } }"):
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "completes a std path in a macro")

    def test_path_attributes(self):
        for rel in ("crates/gate-sys/src/lib.rs", "crates/broker/src/main.rs", "crates/effect-gate/tests/files.rs"):
            for text in ('#[path = "extra.inc"]\nmod extra;', '# [ path="extra.rs"] mod extra;', '#![path = "x"]',
                         '#[cfg_attr(all(), path = "extra.inc")]\nmod extra;'):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", "has a path attribute", check=gate.check_included_code)
        self.write("crates/broker/src/main.rs", '#[cfg_attr(test, derive(Debug))]\nstruct S;\nfn main() { let path = "p"; }\n')
        self.assertEqual(gate.check_included_code(self.base), 13)

    def test_include_in_a_linked_crate(self):
        for text in ('include!("extra.txt");', 'std::include !("extra.txt");', "use core::include as inc;",
                     "use core::{include as inc};"):
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "names include", check=gate.check_included_code)

    def test_include_in_a_binary_crate(self):
        self.refused("crates/broker/src/main.rs", 'include!("extra.txt");\nfn main() {}\n', "names include",
                     check=gate.check_included_code)
        self.write("crates/broker/src/main.rs", 'const A: &str = include_str!("a.txt");\n'
                                              'const B: &[u8] = include_bytes!("b.bin");\nfn main() {}\n')
        self.assertEqual(gate.check_included_code(self.base), 13)

    def test_non_rs_files_under_src(self):
        for rel in ("crates/gate-sys/src/extra.inc", "crates/gate/src/extra.txt", "crates/effect-gate/src/sub/x.rs.txt"):
            self.refused(rel, "#![allow(unsafe_code)]\nunsafe fn f() {}\n", "not a .rs file", check=gate.check_included_code)
        os.symlink("../tests", self.base / "crates/effect-gate/src/linked")
        with self.assertRaisesRegex(gate.GateError, "symlink under crates/"):
            gate.check_included_code(self.base)
        (self.base / "crates/effect-gate/src/linked").unlink()
        self.write("crates/effect-gate/tests/data.json", "{}\n")
        self.assertEqual(gate.check_included_code(self.base), 13)


SEAL_DECLARATIONS = ("unsafe extern \"C\" {\n    fn prlimit(pid: c_int, resource: c_int, new: *const R, old: *mut R) -> c_int;\n"
                     "    fn prctl(option: c_int, ...) -> c_int;\n    fn capget(h: *mut H, d: *mut D) -> c_int;\n"
                     "    fn capset(h: *mut H, d: *const D) -> c_int;\n"
                     "    fn getresuid(r: *mut c_uint, e: *mut c_uint, s: *mut c_uint) -> c_int;\n"
                     "    fn getresgid(r: *mut c_uint, e: *mut c_uint, s: *mut c_uint) -> c_int;\n"
                     "    fn syscall(number: c_long, ...) -> c_long;\n}\n")
CHANNEL_DECLARATIONS = ("unsafe extern \"C\" {\n    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;\n"
                        "    fn bind(fd: c_int, address: *const A, length: c_uint) -> c_int;\n"
                        "    fn listen(fd: c_int, backlog: c_int) -> c_int;\n"
                        "    fn setsockopt(fd: c_int, l: c_int, n: c_int, v: *const c_void, s: c_uint) -> c_int;\n"
                        "    fn getsockopt(fd: c_int, l: c_int, n: c_int, v: *mut c_void, s: *mut c_uint) -> c_int;\n"
                        "    fn recvmsg(fd: c_int, m: *mut M, flags: c_int) -> c_long;\n"
                        "    fn sendmsg(fd: c_int, m: *const M, flags: c_int) -> c_long;\n"
                        "    fn epoll_create1(flags: c_int) -> c_int;\n"
                        "    fn epoll_ctl(e: c_int, op: c_int, fd: c_int, event: *mut E) -> c_int;\n"
                        "    fn epoll_pwait(e: c_int, events: *mut E, n: c_int, t: c_int, m: *const c_void) -> c_int;\n"
                        "    fn ppoll(fds: *mut P, n: c_ulong, t: *const T, m: *const c_void) -> c_int;\n"
                        "    fn syscall(number: c_long, ...) -> c_long;\n}\n")
TCP_DECLARATIONS = ("#[allow(clashing_extern_declarations)]\nunsafe extern \"C\" {\n"
                    "    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;\n"
                    "    fn setsockopt(fd: c_int, l: c_int, n: c_int, v: *const c_void, s: c_uint) -> c_int;\n"
                    "    fn bind(fd: c_int, address: *const c_void, length: c_uint) -> c_int;\n"
                    "    fn listen(fd: c_int, backlog: c_int) -> c_int;\n"
                    "    fn connect(fd: c_int, address: *const c_void, length: c_uint) -> c_int;\n"
                    "    fn getsockopt(fd: c_int, l: c_int, n: c_int, v: *mut c_void, s: *mut c_uint) -> c_int;\n"
                    "    fn recv(fd: c_int, b: *mut c_void, n: usize, flags: c_int) -> c_long;\n"
                    "    fn send(fd: c_int, b: *const c_void, n: usize, flags: c_int) -> c_long;\n"
                    "    fn shutdown(fd: c_int, how: c_int) -> c_int;\n"
                    "    fn syscall(number: c_long, ...) -> c_long;\n}\n")
FOREIGN_TREE = {
    **LINKED_TREE,
    # HE-003A2: the openat module's two symbols, openat and readlinkat.
    "crates/gate-sys/src/openat.rs": "#![allow(unsafe_code)]\nunsafe extern \"C\" {\n    // the two calls\n"
                                     "    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;\n"
                                     "    fn readlinkat(dirfd: c_int, path: *const c_char, buffer: *mut c_char, size: usize) -> isize;\n}\n",
    "crates/gate-sys/src/seal.rs": "#![allow(unsafe_code)]\n" + SEAL_DECLARATIONS
                                   + "pub fn user_ids() -> [u32; 3] { [0; 3] }\n",
    # HE-003A: the channel module, the third file with its own allowlist (the linked tree's eighth source).
    "crates/gate-sys/src/channel.rs": "#![allow(unsafe_code)]\n" + CHANNEL_DECLARATIONS,
    # HE-003B: the tcp module, the fourth.
    "crates/gate-sys/src/tcp.rs": "#![allow(unsafe_code)]\n" + TCP_DECLARATIONS,
    # HE-004D1 (G-D1-2): observer-sys's kernel module, the fifth, with its one foreign item.
    "crates/observer-sys/src/kernel.rs": "#![allow(unsafe_code)]\nunsafe extern \"C\" {\n"
                                         "    fn syscall(number: c_long, ...) -> c_long;\n}\n",
}


class ForeignItemTests(unittest.TestCase):
    """HE-002S DESIGN section 6 (D8): the per-file allowlist of declared foreign symbols."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        for rel, text in FOREIGN_TREE.items():
            self.write(rel, text)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, rel, text):
        path = self.base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def refused(self, rel, text, message):
        self.write(rel, text)
        with self.assertRaisesRegex(gate.GateError, message):
            gate.check_foreign_items(self.base)
        if rel in FOREIGN_TREE:
            self.write(rel, FOREIGN_TREE[rel])
        else:
            (self.base / rel).unlink()

    def test_the_allowlisted_declarations_pass(self):
        self.assertEqual(gate.check_foreign_items(self.base), 15)
        self.assertEqual(gate.extern_blocks("unsafe extern \"C\" { fn a(); }\nextern {\n fn b(); }"),
                         [" fn a(); ", "\n fn b(); "])

    def test_exactly_the_allowed_symbols(self):
        seal = "crates/gate-sys/src/seal.rs"
        for text in (FOREIGN_TREE[seal] + "unsafe extern \"C\" { fn setrlimit(r: c_int, l: *const R) -> c_int; }\n",
                     FOREIGN_TREE[seal].replace("    fn syscall(number: c_long, ...) -> c_long;\n", ""),
                     FOREIGN_TREE[seal].replace("fn prctl(", "fn prctl2("),
                     FOREIGN_TREE[seal].replace("fn capget(", "static mut environ: *const u8;\n    fn capgot(")):
            self.refused(seal, text, "seal.rs declares the foreign items .* not exactly")
        self.refused("crates/gate-sys/src/openat.rs", FOREIGN_TREE["crates/gate-sys/src/openat.rs"]
                     + "unsafe extern \"C\" { fn open(path: *const c_char, flags: c_int, ...) -> c_int; }\n",
                     "openat.rs declares the foreign items")
        self.refused("crates/gate-sys/src/openat.rs", "#![allow(unsafe_code)]\n", "openat.rs declares the foreign items")
        (self.base / seal).unlink()
        with self.assertRaisesRegex(gate.GateError, "seal.rs is missing"):
            gate.check_foreign_items(self.base)

    def test_no_other_linked_source_declares_a_foreign_item(self):
        for rel, text in (("crates/effect-gate/src/seal.rs", "unsafe extern \"C\" { fn prctl(o: c_int, ...) -> c_int; }"),
                          ("crates/gate-sys/src/lib.rs", "unsafe extern { static environ: *const *const u8; }"),
                          ("crates/i05-protocol/src/json.rs", "extern \"C\"\n{\n    type Opaque;\n}"),
                          ("crates/gate-sys/src/raw.rs", SEAL_DECLARATIONS)):
            self.refused(rel, FOREIGN_TREE.get(rel, "") + text + "\n", "declares the foreign items .* not exactly \\[\\]")
        # Function pointer types and Rust-ABI definitions are not foreign items; the binary crates are not linked here.
        self.write("crates/effect-gate/src/file_store.rs", "type Callback = unsafe extern \"C\" fn(i32) -> i32;\n"
                                                           "pub extern \"C\" fn exported() {}\n")
        self.write("crates/broker/src/main.rs", "unsafe extern \"C\" { fn system(c: *const u8) -> i32; }\nfn main() {}\n")
        self.assertEqual(gate.check_foreign_items(self.base), 15)

    def test_extern_items_are_private_and_not_safe(self):
        seal = "crates/gate-sys/src/seal.rs"
        for old, new, message in (("    fn prctl(", "    pub fn prctl(", "public foreign item"),
                                  ("    fn prctl(", "    pub(crate) fn prctl(", "public foreign item"),
                                  ("    fn getresuid(", "    safe fn getresuid(", "safe foreign item"),
                                  ("    fn capget(", "    pub safe fn capget(", "public foreign item")):
            self.refused(seal, FOREIGN_TREE[seal].replace(old, new), message)
        # A comment inside the block is not read; the word unsafe before extern is not the word safe.
        self.write(seal, FOREIGN_TREE[seal].replace("    fn prctl(", "    // not pub, not safe\n    fn prctl("))
        self.assertEqual(gate.check_foreign_items(self.base), 15)

    def test_no_link_name(self):
        for rel in ("crates/gate-sys/src/seal.rs", "crates/effect-gate/src/file_store.rs"):
            self.refused(rel, FOREIGN_TREE[rel].replace("fn syscall(", "#[link_name = \"syscall\"]\n    fn syscall(")
                         if rel.endswith("seal.rs") else FOREIGN_TREE[rel] + "#[link_name = \"x\"] fn y() {}\n",
                         "names link_name")

    def test_an_unterminated_extern_block_fails(self):
        self.refused("crates/gate-sys/src/seal.rs", "unsafe extern \"C\" {\n    fn prctl(o: c_int, ...) -> c_int;\n",
                     "without its closing brace")

    # HE-002S PR review round 1, R1-1: the reviewer's three forms, each refused.
    def test_a_comment_between_the_abi_and_the_brace(self):
        seal = "crates/gate-sys/src/seal.rs"
        kill = "fn kill(pid: c_int, signal: c_int) -> c_int;"
        for extra in ("unsafe extern \"C\" /* raw */ { %s }" % kill, "unsafe extern \"C\" // raw\n{ %s }" % kill,
                      "unsafe extern /* \"C\" */ { %s }" % kill, "unsafe extern r#\"C\"# { %s }" % kill):
            self.refused(seal, FOREIGN_TREE[seal] + extra + "\n", "seal.rs declares the foreign items .*kill.* not exactly")

    def test_a_brace_inside_a_comment_or_literal_does_not_end_the_block(self):
        seal = "crates/gate-sys/src/seal.rs"
        last = "    fn syscall(number: c_long, ...) -> c_long;\n"
        kill = "    fn kill(pid: c_int, signal: c_int) -> c_int;\n"
        for inserted in ("    // end of the seven }\n", "    /* } */\n", "    /* /* } */ } */\n"):
            self.refused(seal, FOREIGN_TREE[seal].replace(last, last + inserted + kill),
                         "seal.rs declares the foreign items .*kill.* not exactly")
        # A brace or an extern block inside a literal is not code.
        self.write(seal, FOREIGN_TREE[seal] + "const A: &str = \"}\"; const B: char = '}';\n"
                   "const C: &str = r#\"unsafe extern \"C\" { fn kill(); }\"#;\nfn f<'a>(x: &'a str) -> &'a str { x }\n")
        self.assertEqual(gate.check_foreign_items(self.base), 15)

    def test_a_macro_generated_block(self):
        seal, lib = "crates/gate-sys/src/seal.rs", "crates/gate-sys/src/lib.rs"
        for extra in ("macro_rules! ext { ($n:ident) => { unsafe extern \"C\" { fn $n(pid: c_int) -> c_int; } } }\n"
                      "ext!(kill);",
                      "macro_rules! ext { ($v:vis $n:ident) => { unsafe extern \"C\" { $v fn $n(); } } }\next!(pub kill);",
                      "// $n\n", "const D: char = '$'; fn f() { macro_rules! m { () => {} } }"):
            self.refused(seal, FOREIGN_TREE[seal] + extra + "\n", "seal.rs: defines a macro")
        # In another linked source the reader refuses what it cannot read: a metavariable, a macro call or an attribute
        # in a block, or an extern it cannot place.
        for rel, text in ((lib, "macro_rules! ext { ($u:tt $n:ident) => { $u extern \"C\" { fn $n(); } } }"),
                          (lib, "macro_rules! ext { ($u:tt $v:vis) => { $u extern \"C\" { $v fn kill(); } } }"),
                          (lib, "macro_rules! ext { ($u:tt $a:tt $b:tt) => { $u extern $a $b } }"),
                          (lib, "macro_rules! ext { ($u:tt $b:tt) => { $u extern \"C\" $b } }"),
                          (seal, FOREIGN_TREE[seal].replace("    fn syscall(", "    ext!(kill);\n    fn syscall(")),
                          (seal, FOREIGN_TREE[seal].replace("    fn syscall(", "    #[cfg(all())]\n    fn syscall(")),
                          (seal, FOREIGN_TREE[seal].replace("    fn syscall(", "    static X: [u8; 2] = 0;\n    fn syscall(")),
                          (seal, FOREIGN_TREE[seal].replace("    fn syscall(", "    const X: u8;\n    fn syscall("))):
            self.refused(rel, FOREIGN_TREE.get(rel, "") + text + "\n", "cannot read")
        # A string literal may hold a $ in seal.rs; a fixed-size array parameter is read.
        self.write(seal, FOREIGN_TREE[seal].replace("fn capget(h: *mut H, d: *mut D)", "fn capget(h: *mut H, d: *mut [D; 2])")
                   + "const D: &str = \"$n macro_rules\";\n")
        self.assertEqual(gate.check_foreign_items(self.base), 15)

    def test_the_reader(self):
        self.assertEqual(gate.rust_code("a /* x /* y */ z */ b // c\nd"), "a   b  \nd")
        self.assertEqual(gate.rust_code("a /* x */ b // c\nd", comments=True), "a /* x */ b // c\nd")
        self.assertEqual(gate.rust_code(r"""f("}", r#"a"b"#, br"\", b'\'', '"', '\u{7d}', 'a', &'a T, 'l: loop, '_)"""),
                         r"""f("", "", "", b'', '', '', '', &'a T, 'l: loop, '_)""")
        self.assertEqual(gate.rust_code('"a\\"b // c" /* d */'), '""  ')
        for text, message in (('"abc', "unterminated string"), ("/* a /* b */", "unterminated block comment"),
                              ('r#"a"', "unterminated raw string"), ("let c = ' ;", "neither a character literal"),
                              ("'\\q'", "neither a character literal")):
            with self.assertRaisesRegex(gate.GateError, message):
                gate.rust_code(text)
        self.assertEqual(gate.foreign_items(" fn a(x: [u8; 4]) -> c_int; static mut b: u8;\n unsafe fn c(); type d; "),
                         {"a", "b", "c", "d"})
        self.assertEqual(gate.use_paths(" ::std::io::{self, Read as R, prelude::*}"),
                         [(("std", "io", "self"), None), (("std", "io", "Read"), "R"), (("std", "io", "prelude", "*"), None)])


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        tools = Path(self.directory.name)
        (tools / "usr/bin").mkdir(parents=True)
        (tools / "usr/bin/clang").write_text("")
        (tools / "usr/bin/ar").write_text("")
        (tools / "SDKs/MacOSX.sdk").mkdir(parents=True)
        (tools / "SDKs/MacOSX.sdk/SDKSettings.json").write_text(json.dumps({"Version": "13.3"}))
        self.pin = json.loads(json.dumps(PIN))
        self.pin["commandLineTools"]["path"] = str(tools)
        self.pin["cToolchain"]["compiler"] = str(tools / "usr/bin/clang")
        self.pin["cToolchain"]["archiver"] = str(tools / "usr/bin/ar")
        self.which = {"cc": "/usr/bin/cc", "ar": "/usr/bin/ar"}
        self.answers = {
            "rustc -vV": "rustc 1.99.0 (b940084d7 2026-09-28)\nbinary: rustc\ncommit-hash: "
                         "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4\nhost: aarch64-apple-darwin\nrelease: 1.99.0\n"
                         "LLVM version: 23.1.1\n",
            "cargo -V": "cargo 1.99.0 (5f94df478 2026-08-27)\n", "rustc --print sysroot": "/sys-root\n",
            "rustc --print target-libdir --target " + X86: "/sys-root/lib/rustlib/%s/lib\n" % X86,
            "rustc --print target-libdir --target " + ARM: "/sys-root/lib/rustlib/%s/lib\n" % ARM,
            str(tools / "usr/bin/clang") + " --version": "Apple clang version 14.0.3 (clang-1403.0.22.14.1)\nTarget: x\n",
            "xcode-select -p": str(tools) + "\n"}

    def tearDown(self):
        self.directory.cleanup()

    def check(self):
        output = io.StringIO()
        with mock.patch.object(gate, "run", lambda argv: self.answers[" ".join(argv)]), \
                mock.patch.object(gate.shutil, "which", lambda name: self.which.get(name)), contextlib.redirect_stdout(output):
            gate.check_toolchain(self.pin)
        return output.getvalue()

    def test_pinned_toolchain_passes(self):
        self.assertNotIn("differ", self.check())

    def test_rustc_cargo_and_sysroot_mismatch_fail(self):
        for key, value in (("rustc -vV", self.answers["rustc -vV"].replace("b940084d7eb6", "0000084d7eb6")),
                           ("rustc -vV", self.answers["rustc -vV"].replace("LLVM version: 23.1.1", "LLVM version: 23.1.2")),
                           ("cargo -V", "cargo 1.99.1 (aaaaaaaaa 2026-09-01)\n"),
                           ("rustc --print sysroot", "/elsewhere\n"),
                           ("rustc --print target-libdir --target " + ARM, "/elsewhere/lib\n")):
            saved, self.answers[key] = self.answers[key], value
            with self.assertRaises(gate.GateError):
                self.check()
            self.answers[key] = saved

    # HE-003B DESIGN section 2.5 (owner decision Q-HE3B-3 (a)): the Command Line Tools' version is a failing pin.
    def test_command_line_tools(self):
        self.pin["commandLineTools"]["sdk"] = "14.0"
        with self.assertRaisesRegex(gate.GateError, "Command Line Tools differ from toolchain.json"):
            self.check()
        self.pin["commandLineTools"]["sdk"] = "13.3"
        key = str(Path(self.pin["commandLineTools"]["path"]) / "usr/bin/clang") + " --version"
        saved, self.answers[key] = self.answers[key], "Apple clang version 15.0.0 (clang-1500.0.40.1)\n"
        with self.assertRaisesRegex(gate.GateError, "Command Line Tools differ from toolchain.json"):
            self.check()
        self.answers[key] = saved
        os.unlink(Path(self.pin["commandLineTools"]["path"]) / "usr/bin/clang")
        with self.assertRaisesRegex(gate.GateError, "Command Line Tools are missing"):
            self.check()

    def test_c_toolchain_xcode_select_and_path(self):
        self.pin["cToolchain"]["compiler"] = "/usr/local/bin/clang"
        with self.assertRaisesRegex(gate.GateError, "pinned C compiler"):
            self.check()
        self.pin["cToolchain"]["compiler"] = str(Path(self.pin["commandLineTools"]["path"]) / "usr/bin/clang")
        os.unlink(Path(self.pin["commandLineTools"]["path"]) / "usr/bin/ar")
        with self.assertRaisesRegex(gate.GateError, "pinned archiver"):
            self.check()
        (Path(self.pin["commandLineTools"]["path"]) / "usr/bin/ar").write_text("")
        self.answers["xcode-select -p"] = "/Applications/Xcode.app/Contents/Developer\n"
        with self.assertRaisesRegex(gate.GateError, "xcode-select"):
            self.check()
        self.answers["xcode-select -p"] = self.pin["commandLineTools"]["path"] + "\n"
        for name, shadow in (("cc", "/opt/homebrew/bin/cc"), ("ar", "/usr/local/bin/ar"), ("cc", None)):
            saved, self.which[name] = self.which[name], shadow
            with self.assertRaisesRegex(gate.GateError, "first cc and ar on PATH"):
                self.check()
            self.which[name] = saved
        self.check()


WRAPPER = ("#!/bin/sh\n# comment\nDYLD_FALLBACK_LIBRARY_PATH=/sys-root/lib\nexport DYLD_FALLBACK_LIBRARY_PATH\n"
           'exec /sys-root/lib/rustlib/aarch64-apple-darwin/bin/rust-lld "$@"\n')
CONFIG = ('[net]\noffline = true\n\n' + "".join(
    '[target.%s]\nlinker = "host-enforcement/tools/rust-lld"\n'
    'rustflags = ["-C", "link-self-contained=yes", "-C", "target-feature=+crt-static"]\n\n' % target for target in (X86, ARM))
    + '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\n'
      'directory = "host-enforcement/vendor"\n\n[env]\n'
      'CC_x86_64_unknown_linux_musl = { value = "/clt/usr/bin/clang", force = true }\n'
      'CC_aarch64_unknown_linux_musl = { value = "/clt/usr/bin/clang", force = true }\n'
      'AR_x86_64_unknown_linux_musl = { value = "/clt/usr/bin/ar", force = true }\n'
      'AR_aarch64_unknown_linux_musl = { value = "/clt/usr/bin/ar", force = true }\n'
      'CFLAGS_x86_64_unknown_linux_musl = { value = "-nostdlibinc -ffreestanding -DRING_CORE_NOSTDLIBINC=1", force = true }\n')


class LinkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        (self.root / ".cargo").mkdir()
        (self.root / "host-enforcement/tools").mkdir(parents=True)
        self.write(CONFIG, WRAPPER)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, config, wrapper):
        (self.root / ".cargo/config.toml").write_text(config)
        (self.root / "host-enforcement/tools/rust-lld").write_text(wrapper)

    def test_pinned_linker_passes(self):
        gate.check_cargo_config(PIN, self.root)

    def test_cargo_config_mutations_fail(self):
        for config in (CONFIG.replace("offline = true", "offline = false"),
                       CONFIG.replace('linker = "host-enforcement/tools/rust-lld"', 'linker = "rust-lld"', 1),
                       CONFIG.replace(', "-C", "target-feature=+crt-static"', "", 1),
                       CONFIG.replace("link-self-contained=yes", "link-self-contained=no", 1),
                       CONFIG.replace("[net]\noffline = true\n", "[target.x86_64-unknown-linux-gnu]\nlinker = \"cc\"\n"),
                       CONFIG.replace("[net]\noffline = true\n", ""),
                       # HE-003B DESIGN section 2.6: [source] and [env] exactly as pinned.
                       CONFIG.replace('replace-with = "vendored-sources"', 'replace-with = "other"'),
                       CONFIG.replace('directory = "host-enforcement/vendor"', 'directory = "vendor"'),
                       CONFIG.replace('/clt/usr/bin/clang", force = true }', '/usr/bin/clang", force = true }', 1),
                       CONFIG.replace('force = true }\nAR_x86', 'force = false }\nAR_x86'),
                       CONFIG.replace("-DRING_CORE_NOSTDLIBINC=1", "-O0"),
                       CONFIG.replace("CFLAGS_x86_64_unknown_linux_musl", "CFLAGS"),
                       CONFIG + 'CFLAGS_aarch64_unknown_linux_musl = { value = "-O0", force = true }\n',
                       CONFIG + 'RUSTC_WRAPPER = "/tmp/x"\n',
                       CONFIG.replace('CC_aarch64_unknown_linux_musl = { value = "/clt/usr/bin/clang", force = true }\n', ""),
                       CONFIG.replace('CC_aarch64_unknown_linux_musl = { value = "/clt/usr/bin/clang", force = true }',
                                      'CC_aarch64_unknown_linux_musl = "/clt/usr/bin/clang"')):
            self.write(config, WRAPPER)
            with self.assertRaisesRegex(gate.GateError, "cargo config"):
                gate.check_cargo_config(PIN, self.root)

    def test_extra_cargo_config_tables_fail(self):
        for extra in ('[build]\nrustc-wrapper = "/tmp/x"\n', '[patch.crates-io]\nring = { path = "x" }\n',
                      '[registries.x]\nindex = "https://example.invalid"\n'):
            self.write(CONFIG + extra, WRAPPER)
            with self.assertRaisesRegex(gate.GateError, "only \\[net\\], \\[target\\], \\[source\\] and \\[env\\]"):
                gate.check_cargo_config(PIN, self.root)
        self.write(CONFIG.split("[source.crates-io]")[0], WRAPPER)
        with self.assertRaisesRegex(gate.GateError, "only \\[net\\], \\[target\\], \\[source\\] and \\[env\\]"):
            gate.check_cargo_config(PIN, self.root)

    def test_wrapper_interpreter_is_pinned(self):
        for first in ("#!/bin/bash", "#!/usr/bin/env sh", "# no shebang"):
            self.write(CONFIG, WRAPPER.replace("#!/bin/sh", first, 1))
            with self.assertRaisesRegex(gate.GateError, "must start with #!/bin/sh"):
                gate.check_cargo_config(PIN, self.root)

    def test_wrapper_mutations_fail(self):
        for wrapper in (WRAPPER.replace("exec /sys-root/", "exec /old-root/"),
                        WRAPPER.replace("rustlib/aarch64-apple-darwin/bin", "rustlib/x86_64-apple-darwin/bin"),
                        WRAPPER.replace("PATH=/sys-root/lib", "PATH=/old-root/lib"),
                        WRAPPER.replace("export DYLD_FALLBACK_LIBRARY_PATH\n", ""),
                        WRAPPER + "touch /tmp/x\n",
                        WRAPPER.replace('"$@"', '"$@" --extra')):
            self.write(CONFIG, wrapper)
            with self.assertRaisesRegex(gate.GateError, "linker wrapper"):
                gate.check_cargo_config(PIN, self.root)


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        (self.base / "contracts/i05-v3").mkdir(parents=True)
        (self.base / "contracts/i05-v3/vectors.json").write_bytes(b"{}")
        (self.base / "contracts/PROVENANCE.md").write_text("provenance\n")
        self.patch = mock.patch.object(gate, "CONTRACTS", {"contracts/i05-v3/vectors.json": hashlib.sha256(b"{}").hexdigest()})
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.directory.cleanup()

    def test_registered_contracts_pass(self):
        self.assertEqual(gate.check_contracts(self.base), 1)

    # HE-002S DESIGN section 3: the two published EFFECT_GATE programs join the 13 contract files at their digests.
    # HE-003A2 (DESIGN section 2, Q-A2-1 (a)): the two seccomp-v4 programs join them (17); the v3 ones stay pinned.
    # HE-004A (DESIGN section 2, Q-HE4A-4 (a)): the two OBSERVER programs join them (19).
    # HE-003A3 (DESIGN section 2): the I05 v4 README and vectors join them (21).
    # HE-004B1 (DESIGN-B section 2): edge record v4's ten HE-004 rows join them (31).
    # HE-004D1 (DESIGN-D1 section 2, G-D1-9): edge record v5's four native-profile rows join them (35).
    def test_the_table_pins_the_effect_gate_programs(self):
        self.patch.stop()
        try:
            self.assertEqual(len(gate.CONTRACTS), 35)
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/native-profile-")}, {
                "contracts/native-profile-v4/qualification.schema.json":
                    "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
                "contracts/native-profile-v4/vectors.json":
                    "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
                "contracts/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
                "contracts/native-profile-v3/qualification.schema.json":
                    "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith(("contracts/i06-", "contracts/admission-v3/"))}, {
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
                    "1096b3cc71c4fe6b5a17ed61e8bf8c17ee17fcf52b192503534d60aed9ce4741"})
            self.assertEqual(gate.CONTRACTS["contracts/i05-v4/README.md"],
                             "b0af1f8784c7e9bcdd3793a1002d1000e222a13e5a7613b50b04ce5a116ed04d")
            self.assertEqual(gate.CONTRACTS["contracts/i05-v4/vectors.json"],
                             "f314610f7ee3feb08533cb535f0a4c19fc991384b852b99a50a1646b0739b1e9")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v3/OBSERVER.aarch64.bpf"],
                             "d31c841042de456bb784e8412f61429be7700aea2ffa508af2637283ebcb3707")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v3/OBSERVER.x86_64.bpf"],
                             "e793aae5ad04a7c82a67d3f102b837064e645a585b83ace0586169a1746eb25a")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v3/EFFECT_GATE.aarch64.bpf"],
                             "0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v3/EFFECT_GATE.x86_64.bpf"],
                             "ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v4/EFFECT_GATE.aarch64.bpf"],
                             "8de80a2b597b84d9f5ace818e76ef15d4b15a5b02013bb479ca4fdf73df3d044")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v4/EFFECT_GATE.x86_64.bpf"],
                             "4e516f1682098c90edd568f8f214d3de01b404a2c144104596fc4e3262f6e7a3")
        finally:
            self.patch.start()

    def test_changed_extra_missing_and_linked_contracts_fail(self):
        (self.base / "contracts/i05-v3/vectors.json").write_bytes(b"{ }")
        with self.assertRaisesRegex(gate.GateError, "differs from its registered bytes"):
            gate.check_contracts(self.base)
        (self.base / "contracts/i05-v3/vectors.json").write_bytes(b"{}")
        (self.base / "contracts/i05-v3/extra.json").write_bytes(b"{}")
        with self.assertRaisesRegex(gate.GateError, "exactly the registered files"):
            gate.check_contracts(self.base)
        (self.base / "contracts/i05-v3/extra.json").unlink()
        (self.base / "contracts/i05-v3/vectors.json").unlink()
        with self.assertRaisesRegex(gate.GateError, "exactly the registered files"):
            gate.check_contracts(self.base)
        (self.base / "contracts/real.json").write_bytes(b"{}")
        os.symlink("../real.json", self.base / "contracts/i05-v3/vectors.json")
        with self.assertRaisesRegex(gate.GateError, "exactly the registered files|differs from its registered bytes"):
            gate.check_contracts(self.base)


class Tree(unittest.TestCase):
    """A temporary tree written from a dict of relative paths to texts."""

    TREE: dict = {}

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        for rel, text in self.TREE.items():
            self.write(rel, text)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, rel, text):
        path = self.base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def refused(self, check, rel, text, message):
        self.write(rel, text)
        with self.assertRaisesRegex(gate.GateError, message):
            check(self.base)
        if rel in self.TREE:
            self.write(rel, self.TREE[rel])
        else:
            (self.base / rel).unlink()


CHANNEL = "crates/gate-sys/src/channel.rs"


class ChannelModuleTests(Tree):
    """HE-003A DESIGN section 8: gate-sys's channel module is the third file allowed `unsafe`, declares exactly its
    twelve foreign symbols, and with the openat module the only linked source that names std::os::fd items."""

    TREE = FOREIGN_TREE

    def test_unsafe_is_also_allowed_in_gate_sys_channel(self):
        self.assertEqual(gate.check_unsafe(self.base), 17)
        for rel in ("crates/gate-sys/src/channel/raw.rs", "crates/effect-gate/src/channel.rs",
                    "crates/effect-gate/src/substrate.rs", "crates/gate-sys/src/peer_wire.rs"):
            self.refused(gate.check_unsafe, rel, "fn f() { unsafe { g() } }\n", "contains unsafe outside .*channel.rs")

    def test_the_channel_module_declares_exactly_its_twelve_symbols(self):
        self.assertEqual(gate.check_foreign_items(self.base), 15)
        self.assertEqual(len(gate.FOREIGN_ITEMS[CHANNEL]), 12)
        message = "channel.rs declares the foreign items .* not exactly"
        for text in (FOREIGN_TREE[CHANNEL].replace("    fn ppoll(", "    fn poll("),
                     FOREIGN_TREE[CHANNEL].replace("    fn listen(fd: c_int, backlog: c_int) -> c_int;\n", ""),
                     FOREIGN_TREE[CHANNEL] + "unsafe extern \"C\" { fn accept4(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[CHANNEL] + "unsafe extern \"C\" { fn accept(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[CHANNEL] + "unsafe extern \"C\" { fn readlinkat(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[CHANNEL] + "unsafe extern \"C\" { fn pidfd_open(p: c_int) -> c_int; }\n"):
            self.refused(gate.check_foreign_items, CHANNEL, text, message)
        self.refused(gate.check_foreign_items, CHANNEL, FOREIGN_TREE[CHANNEL] + "// $x\n", "channel.rs: defines a macro")
        # The channel's symbols anywhere else refuse.
        self.refused(gate.check_foreign_items, "crates/gate-sys/src/peer_wire.rs", CHANNEL_DECLARATIONS,
                     "peer_wire.rs declares the foreign items .* not exactly \\[\\]")
        (self.base / CHANNEL).unlink()
        with self.assertRaisesRegex(gate.GateError, "channel.rs is missing"):
            gate.check_foreign_items(self.base)

    def test_std_os_fd_items_in_the_openat_and_channel_modules_only(self):
        with_fd = (FOREIGN_TREE[CHANNEL] + "use std::fs::File;\nuse std::os::fd::AsRawFd;\nuse std::os::fd::FromRawFd;\n"
                   "use std::os::fd::OwnedFd;\n")
        self.write(CHANNEL, with_fd)
        self.assertEqual(gate.check_linked_sources(self.base), 15)
        message = "std::os::fd item outside crates/gate-sys/src/openat.rs and crates/gate-sys/src/channel.rs"
        for rel in ("crates/gate-sys/src/peer_wire.rs", "crates/effect-gate/src/substrate.rs",
                    "crates/effect-gate/src/linux_os.rs"):
            self.refused(gate.check_linked_sources, rel, "use std::os::fd::OwnedFd;\n", message)
        self.refused(gate.check_linked_sources, CHANNEL, with_fd + "use std::os::unix::net::UnixListener;\n",
                     "std::os item other than")


STARTUP_CHANNEL = ('pub fn sockcreate() { let _ = Dir::at("/proc/thread-self/attr"); }\n'
                   'pub fn peer(pid: i32) { let _ = Dir::at(&format!("/proc/{}", pid)); }\n')


class StartUpExceptionTests(Tree):
    """HE-003A DESIGN section 8: the start-up lint's exceptions are a per-file list of exact expressions, each removed
    once: the seal module's status read, and the channel module's two openings."""

    TREE = {"crates/gate-sys/src/seal.rs": 'pub fn own_status() { let _ = Dir::at("/proc/self")?.file_ro("status")?; }\n',
            CHANNEL: STARTUP_CHANNEL,
            "crates/gate-sys/src/peer_wire.rs": "pub fn parse() {}\n"}

    def test_each_expression_once_in_its_file(self):
        self.assertEqual(gate.check_sources(self.base), 3)
        self.write(CHANNEL, 'fn f(pid: i32) { Dir :: at ( "/proc/thread-self/attr" ) ; Dir::at( & format ! ( '
                            '"/proc/{}" , pid ) ); }\n')
        self.assertEqual(gate.check_sources(self.base), 3)
        message = "crates/gate-sys/src/channel.rs uses /proc .start-up lint"
        for text in (STARTUP_CHANNEL + 'let _ = Dir::at("/proc/thread-self/attr");\n',
                     STARTUP_CHANNEL + 'let _ = Dir::at(&format!("/proc/{}", pid));\n',
                     STARTUP_CHANNEL + 'let _ = Dir::at("/proc/self")?.file_ro("status");\n',
                     STARTUP_CHANNEL + '// the sockcreate file is /proc/thread-self/attr/sockcreate\n',
                     'let _ = Dir::at("/proc/thread-self/attr/sockcreate");\n',
                     'let _ = Dir::at(&format!("/proc/{}", other));\n',
                     'let _ = Dir::at(&format!("/proc/{}/", pid));\n',
                     'let _ = Dir::at(r"/proc/thread-self/attr");\n'):
            self.refused(gate.check_sources, CHANNEL, text, message)
        # The channel's expressions are excepted in the channel module only, and the seal's in the seal module only.
        self.refused(gate.check_sources, "crates/gate-sys/src/seal.rs", self.TREE["crates/gate-sys/src/seal.rs"]
                     + STARTUP_CHANNEL, "seal.rs uses /proc .start-up lint")
        for rel in ("crates/gate-sys/src/peer_wire.rs", "crates/effect-gate/src/linux_os.rs",
                    "crates/effect-gate/tests/substrate.rs"):
            self.refused(gate.check_sources, rel, STARTUP_CHANNEL, "uses /proc .start-up lint")


STARTUP_ROOTS = ('pub fn open_after_seal(_s: &Sealed) -> io::Result<KernelRoots> {\n'
                 '    let cgroup = KernelRoot::open_kernel_root("/sys/fs/cgroup")?;\n'
                 '    let proc_root = KernelRoot::open_kernel_root("/proc")?;\n    x(cgroup, proc_root)\n}\n')


class StartUpRootTests(Tree):
    """HE-003A3 (DESIGN sections 5 and 6, D2-5): linux_os.rs's two root opens are the start-up lint's exceptions there,
    each excepted once; any other /proc or /sys there, or the same expressions elsewhere, still refuse."""

    TREE = {"crates/effect-gate/src/linux_os.rs": STARTUP_ROOTS, "crates/gate-sys/src/peer_wire.rs": "pub fn parse() {}\n"}

    def test_each_root_open_once_in_linux_os(self):
        self.assertEqual(gate.check_sources(self.base), 2)
        rel = "crates/effect-gate/src/linux_os.rs"
        self.write(rel, STARTUP_ROOTS.replace('KernelRoot::open_kernel_root("/proc")',
                                              'KernelRoot :: open_kernel_root ( "/proc" )'))
        self.assertEqual(gate.check_sources(self.base), 2)
        for text, token in ((STARTUP_ROOTS + 'fn again() { let _ = KernelRoot::open_kernel_root("/proc"); }\n', "/proc"),
                            (STARTUP_ROOTS + 'fn again() { let _ = KernelRoot::open_kernel_root("/sys/fs/cgroup"); }\n', "/sys"),
                            (STARTUP_ROOTS.replace('"/proc")', '"/proc/self")'), "/proc"),
                            (STARTUP_ROOTS.replace('"/sys/fs/cgroup")', '"/sys/fs/cgroup/planeon.slice")'), "/sys"),
                            (STARTUP_ROOTS.replace('KernelRoot::open_kernel_root("/proc")', 'KernelRoot::open_kernel_root(r"/proc")'), "/proc"),
                            (STARTUP_ROOTS.replace('KernelRoot::open_kernel_root("/proc")', 'Dir::at("/proc")'), "/proc"),
                            (STARTUP_ROOTS + "// the leaf under /sys/fs/cgroup\n", "/sys")):
            self.refused(gate.check_sources, rel, text, "linux_os.rs uses %s .start-up lint" % token)
        for other in ("crates/gate-sys/src/peer_wire.rs", "crates/effect-gate/src/observation.rs",
                      "crates/effect-gate/tests/observation.rs", "crates/gate-sys/src/channel.rs"):
            self.refused(gate.check_sources, other, STARTUP_ROOTS, "uses /(sys|proc) .start-up lint")


DEBUG_TREE = {
    **LINKED_TREE,
    "crates/gate-sys/src/openat.rs": LINKED_TREE["crates/gate-sys/src/openat.rs"]
                                     + "pub struct Dir { handle: File }\nimpl fmt::Debug for Dir { fn fmt() {} }\n"
                                     + "#[derive(Copy, Clone, Debug, PartialEq, Eq)]\npub enum FileMode { Existing }\n",
    "crates/effect-gate/src/substrate.rs": "#[derive(Copy, Clone, Debug)]\n#[must_use]\n"
                                           "pub enum Watch { Listener(Listen), Conn(ConnId), PidFd(ConnId) }\n"
                                           "#[derive(Debug)]\npub struct Held { conn: String, file_name: String }\n"
                                           "#[derive(Clone)]\nstruct Slot { conn: Conn, file: File }\n"
                                           "#[derive(Debug)]\npub(crate) enum SetupError { Poller(io::Error), "
                                           "Listener { side: Listen, error: ListenError } }\n"
                                           "#[derive(Debug)]\nstruct Unit;\n#[derive(Debug)]\nstruct Conn(u8);\n",
    "crates/broker/src/main.rs": "#[derive(Debug)]\nstruct S { f: std::fs::File }\nfn main() {}\n",
}


class DebugDeriveTests(Tree):
    """HE-003A DESIGN section 8: no derive(Debug), also under cfg_attr, on a struct or enum of the linked crates whose
    field types mention File, Dir, FileStores, Conn, Listener, Poller, PidFd or ProcDir; field and variant names are not
    types, manual impls pass, and the binary crates are not linked."""

    TREE = DEBUG_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_debug_derives(self.base), 12)

    def test_hazardous_field_types_refuse(self):
        rel = "crates/effect-gate/src/extra.rs"
        for text, hazard in (("#[derive(Debug)]\nstruct S { file: File }", "File"),
                             ("#[derive(Clone, Debug)]\npub(crate) struct S { stores: Option<FileStores> }", "FileStores"),
                             ("#[derive(Debug)]\nstruct S(Dir);", "Dir"),
                             ("#[cfg_attr(test, derive(Debug))]\nstruct S { c: Conn }", "Conn"),
                             ("#[derive(Debug)]\n#[must_use]\npub struct S { p: Poller }", "Poller"),
                             ("#[derive(Debug)]\nenum E { A(PidFd), B }", "PidFd"),
                             ("#[derive(Debug)]\nenum E { A { l: Listener } }", "Listener"),
                             ("#[derive(Debug)]\nstruct S { d: gate_sys::channel::ProcDir }", "ProcDir"),
                             ("#[derive(Debug)]\nstruct S<T> { v: Vec<(T, std::fs::File)> }", "File"),
                             ("#[derive(Debug)]\n/* a comment */ pub struct S { f: Option<Box<File>> }", "File")):
            self.refused(gate.check_debug_derives, rel, text + "\n", "derives Debug on .* mention %s .Debug check" % hazard)
        for text in ("#[derive(Debug)]\nfn f() {}", "#[derive(Debug)]\nstruct S { a: u8 ", "#[derive(Debug)]"):
            self.refused(gate.check_debug_derives, rel, text + "\n", "cannot read")

    def test_names_impls_comments_and_other_crates_pass(self):
        self.write("crates/effect-gate/src/extra.rs", "#[derive(Debug)]\nenum E { File, Dir }\n"
                   "/* #[derive(Debug)] struct S { f: File } */\nconst A: &str = \"#[derive(Debug)] struct S { f: File }\";\n"
                   "impl fmt::Debug for FileStores { fn fmt() {} }\n")
        self.assertEqual(gate.check_debug_derives(self.base), 13)


WORKSPACE_TREE = {
    "Cargo.toml": '[workspace]\nmembers = ["crates/effect-gate", "crates/gate-sys", "crates/i05-protocol", "crates/gate",'
                  ' "crates/gate-tls"]\n\n[workspace.package]\nedition = "2024"\n',
    "crates/gate-tls/Cargo.toml": '[package]\nname = "gate-tls"\nedition.workspace = true\n',
    "crates/effect-gate/Cargo.toml": '[package]\nname = "effect-gate"\nedition.workspace = true\n',
    "crates/gate-sys/Cargo.toml": '[package]\nname = "gate-sys"\nedition.workspace = true\n',
    "crates/i05-protocol/Cargo.toml": '[package]\nname = "i05-protocol"\nedition.workspace = true\n',
    "crates/gate/Cargo.toml": '[package]\nname = "planeon-gate"\nedition.workspace = true\n',
}
WORKSPACE = {"effect-gate": {"gate-sys", "i05-protocol"}, "gate-sys": set(), "i05-protocol": set(), "planeon-gate": set(),
             "gate-tls": {"effect-gate", "i05-protocol"}}


class WorkspaceShapeTests(Tree):
    """HE-002C PR review round 3, R3-2 (1)-(4), taken by HE-003A (DESIGN section 8)."""

    TREE = WORKSPACE_TREE

    def check(self, workspace=None):
        return lambda base: gate.check_workspace_shape(base, WORKSPACE if workspace is None else workspace)

    def test_the_workspace_passes(self):
        self.assertEqual(gate.check_workspace_shape(self.base, WORKSPACE), 5)

    def test_members_live_under_crates(self):
        for member in ("other/x", "crates/a/b", "crates/../x", "crates", "./crates/gate"):
            self.refused(self.check(), "Cargo.toml", WORKSPACE_TREE["Cargo.toml"].replace("crates/gate\"", member + "\""),
                         "is not crates/<name>")

    def test_crates_is_not_a_symlink(self):
        real = self.base / "real"
        (self.base / "crates").rename(real)
        (self.base / "crates").symlink_to(real)
        with self.assertRaisesRegex(gate.GateError, "crates is a symlink"):
            gate.check_workspace_shape(self.base, WORKSPACE)

    def test_the_edition_is_2024_and_inherited(self):
        self.refused(self.check(), "Cargo.toml", WORKSPACE_TREE["Cargo.toml"].replace('"2024"', '"2021"'),
                     "workspace edition is not 2024")
        for text in ('[package]\nname = "gate-sys"\nedition = "2024"\n', '[package]\nname = "gate-sys"\n'):
            self.refused(self.check(), "crates/gate-sys/Cargo.toml", text, "does not inherit the workspace edition")

    def test_no_target_table_overrides_the_edition(self):
        # HE-003A PR review round 1, R1-1: a target table's own edition would undo the inherited 2024.
        manifest = WORKSPACE_TREE["crates/gate-sys/Cargo.toml"]
        for kind, text in (("lib", '\n[lib]\nedition = "2021"\n'), ("lib", '\n[lib]\nedition.workspace = true\n'),
                           ("bin", '\n[[bin]]\nname = "a"\n\n[[bin]]\nname = "b"\nedition = "2021"\n'),
                           ("test", '\n[[test]]\nname = "t"\nedition = "2021"\n'),
                           ("bench", '\n[[bench]]\nname = "b"\nedition = "2021"\n'),
                           ("example", '\n[[example]]\nname = "e"\nedition = "2021"\n')):
            self.refused(self.check(), "crates/gate-sys/Cargo.toml", manifest + text,
                         "crates/gate-sys gives a %s target its own edition" % kind)
        self.write("crates/gate-sys/Cargo.toml", manifest + '\n[lib]\nname = "gate_sys"\n\n[[test]]\nname = "t"\n')
        self.assertEqual(gate.check_workspace_shape(self.base, WORKSPACE), 5)

    def test_effect_gate_links_exactly_the_linked_crates(self):
        # HE-003B DESIGN section 2.6: the union of effect-gate's and gate-tls's closures; HE-003D DESIGN section 5: and
        # planeon-gate's (the binary is linked now). A crate outside the linked set in any closure refuses.
        self.write("crates/broker/Cargo.toml", '[package]\nname = "planeon-broker"\nedition.workspace = true\n')
        message = "the crates effect-gate, gate-tls and planeon-gate link"
        for workspace in ({**WORKSPACE, "effect-gate": {"gate-sys", "i05-protocol", "planeon-broker"}},
                          {**WORKSPACE, "effect-gate": {"gate-sys"}, "gate-tls": {"effect-gate"}},
                          {**WORKSPACE, "gate-sys": {"host-common"}},
                          {**WORKSPACE, "gate-tls": {"effect-gate", "planeon-broker"}},
                          {**WORKSPACE, "planeon-gate": {"gate-tls", "host-common"}}):
            with self.assertRaisesRegex(gate.GateError, message):
                gate.check_workspace_shape(self.base, {**workspace, "planeon-broker": set(), "host-common": set()})
        without = {name: deps for name, deps in WORKSPACE.items() if name != "gate-tls"}
        with self.assertRaisesRegex(gate.GateError, message):
            gate.check_workspace_shape(self.base, without)
        # The binary depending on the linked crates is the HE-003D shape.
        self.assertEqual(gate.check_workspace_shape(self.base, {**WORKSPACE, "planeon-gate": {"effect-gate", "gate-tls"}}), 5)

    def test_planeon_observer_links_exactly_its_crate_and_gate_sys(self):
        # HE-004A DESIGN-A section 6 (D2-4): OBSERVER_LINKED_CRATES is planeon-observer's closure (a dev-dependency is
        # not in check_workspace's result). HE-004B1 DESIGN-B section 3 (Q-HE4B-6 (a)): i05-protocol joins it, so the
        # HE-004A shape (gate-sys alone) now refuses too.
        # HE-004D1 (G-D1-1): observer-sys joins it, so the HE-004C shape refuses too.
        self.write("Cargo.toml", WORKSPACE_TREE["Cargo.toml"].replace('"crates/gate-tls"]',
                                                                      '"crates/gate-tls", "crates/observer", "crates/observer-sys"]'))
        self.write("crates/observer/Cargo.toml", '[package]\nname = "planeon-observer"\nedition.workspace = true\n')
        self.write("crates/observer-sys/Cargo.toml", '[package]\nname = "observer-sys"\nedition.workspace = true\n')
        self.assertEqual(gate.OBSERVER_LINKED_CRATES, ("crates/observer", "crates/gate-sys", "crates/i05-protocol",
                                                       "crates/observer-sys"))
        good = {**WORKSPACE, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys"}, "observer-sys": set()}
        self.assertEqual(gate.check_workspace_shape(self.base, good), 7)
        self.assertEqual(gate.check_workspace_shape(self.base, {**good, "planeon-observer": {"i05-protocol", "observer-sys"},
                                                                "i05-protocol": {"gate-sys"}}), 7)
        for dependencies in (set(), {"gate-sys"}, {"i05-protocol"}, {"gate-sys", "i05-protocol"},
                             {"gate-sys", "i05-protocol", "observer-sys", "effect-gate"},
                             {"effect-gate"}, {"gate-sys", "i05-protocol", "observer-sys", "planeon-broker"}):
            with self.assertRaisesRegex(gate.GateError, "planeon-observer links .*, not .* .workspace shape"):
                gate.check_workspace_shape(self.base, {**good, "planeon-observer": dependencies, "planeon-broker": set()})
        without = {name: dependencies for name, dependencies in good.items() if name != "planeon-observer"}
        with self.assertRaisesRegex(gate.GateError, "no planeon-observer crate in the workspace"):
            gate.check_workspace_shape(self.base, without)


TCP = "crates/gate-sys/src/tcp.rs"


class TcpModuleTests(Tree):
    """HE-003B DESIGN section 3.1: gate-sys's tcp module is the fourth file allowed `unsafe`, declares exactly its
    foreign symbols (HE-003C DESIGN sections 5 and 6: ten, with connect and getsockopt), and may name the std::os::fd
    items."""

    TREE = FOREIGN_TREE

    def test_the_tcp_module_declares_exactly_its_ten_symbols(self):
        self.assertEqual(gate.check_foreign_items(self.base), 15)
        self.assertEqual(gate.FOREIGN_ITEMS[TCP], {"socket", "setsockopt", "bind", "listen", "connect", "getsockopt",
                                                    "recv", "send", "shutdown", "syscall"})
        message = "tcp.rs declares the foreign items .* not exactly"
        for text in (FOREIGN_TREE[TCP].replace("    fn shutdown(fd: c_int, how: c_int) -> c_int;\n", ""),
                     FOREIGN_TREE[TCP].replace("fn recv(", "fn recvfrom("),
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn accept(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn accept4(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn ioctl(f: c_int, ...) -> c_int; }\n",
                     # HE-003C: connect and getsockopt are required, and the client needs no other call.
                     FOREIGN_TREE[TCP].replace("    fn connect(fd: c_int, address: *const c_void, length: c_uint) -> c_int;\n",
                                               ""),
                     FOREIGN_TREE[TCP].replace("fn getsockopt(", "fn getpeername("),
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn connectx(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn fcntl(f: c_int, c: c_int, ...) -> c_int; }\n"):
            self.refused(gate.check_foreign_items, TCP, text, message)
        (self.base / TCP).unlink()
        with self.assertRaisesRegex(gate.GateError, "tcp.rs is missing"):
            gate.check_foreign_items(self.base)

    def test_unsafe_and_fd_items_are_allowed_in_tcp(self):
        self.assertEqual(gate.check_unsafe(self.base), 17)
        self.write(TCP, FOREIGN_TREE[TCP] + "use std::os::fd::AsRawFd;\nuse std::os::fd::OwnedFd;\n"
                        "fn f() { unsafe { g() } }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 15)
        self.assertEqual(gate.check_unsafe(self.base), 17)
        self.refused(gate.check_unsafe, "crates/gate-tls/src/i04.rs", "fn f() { unsafe { g() } }\n",
                     "contains unsafe outside")


GOOD_TLS = """//! The configuration.
use std::sync::Arc;
pub fn server_config() {
    let config = ServerConfig::builder_with_details(provider, time)
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    if config.ticketer.enabled() { return; }
}
"""


GOOD_CLIENT = """//! The client configuration.
pub fn client_config() {
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider()).build();
    let mut config = ClientConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&TLS13])
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(chain, key);
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
}
"""
GOOD_EXCHANGE = "pub fn stage() { let _ = UpstreamResponse { http_status: 200 }; }\n"
# HE-004C (G3): check_tls's group O, the observer's client profile (its tls.rs, the one source of this fixture's group).
GOOD_OBSERVER_TLS = """//! The observer's client configuration.
pub fn client_config() {
    let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider()).build();
    let mut config = ClientConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&TLS13])
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(chain, key);
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
}
"""


class TlsTests(Tree):
    """HE-003B DESIGN sections 2.6 and 20 (D1-5, D2-1): the TLS deny-list over gate-tls's sources and the
    exactly-once settings; HE-003C DESIGN section 5: the client's tokens and settings in the same global list, its
    authentication and verifier once in tls_client.rs, and UpstreamResponse constructed in exchange.rs only."""

    TREE = {"crates/gate-tls/src/lib.rs": "#![forbid(unsafe_code)]\npub mod tls;\n",
            "crates/gate-tls/src/tls.rs": GOOD_TLS,
            "crates/gate-tls/src/tls_client.rs": GOOD_CLIENT,
            "crates/gate-tls/src/exchange.rs": GOOD_EXCHANGE,
            "crates/gate-tls/tests/tls_server.rs": "// tests may build a Ticketer, a KeyLogFile, ServerConfig::builder()\n",
            # HE-004C (G3): the observer's group O, one source.
            "crates/observer/src/tls.rs": GOOD_OBSERVER_TLS}

    def test_the_closed_configuration_passes(self):
        self.assertEqual(gate.check_tls(self.base), 5)

    def test_every_refused_token(self):
        tls = "crates/gate-tls/src/tls.rs"
        for line in ("let log = KeyLogFile::new();", "// SSLKEYLOGFILE", "struct K; impl KeyLog for K {}",
                     "config.key_log = x;", "use rustls::pki_types::pem::PemObject;", "let _ = pem :: from_slice;",
                     "let _ = CertificateDer::from_pem_slice(b);", "provider.install_default();",
                     "let _ = CryptoProvider::get_default();", "let _ = ServerConfig::builder();",
                     "let _ = ServerConfig::builder_with_protocol_versions(&[&TLS13]);",
                     "let _ = WebPkiClientVerifier :: builder (roots);", "use rustls::server::danger;",
                     "verifier.allow_unauthenticated();", "builder.with_no_client_auth();", "let _ = NoClientAuth;",
                     "let _ = ServerSessionMemoryCache::new(1);", "let _ = Ticketer::new();", "config.ticketer = t;",
                     "config.ticketer= t;", "config.enable_secret_extraction = true;",
                     "let _ = connection.dangerous_extract_secrets();"):
            self.refused(gate.check_tls, tls, GOOD_TLS + line + "\n", "names .* .TLS deny-list")
        # The deny-list is not applied to the tests.
        self.assertEqual(gate.check_tls(self.base), 5)

    def test_the_settings_are_set_exactly_once(self):
        tls = "crates/gate-tls/src/tls.rs"
        message = "does not set %s exactly once"
        for name, line in (("max_early_data_size", "    config.max_early_data_size = 0;\n"),
                           ("send_tls13_tickets", "    config.send_tls13_tickets = 0;\n"),
                           ("send_half_rtt_data", "    config.send_half_rtt_data = false;\n"),
                           ("session_storage", "    config.session_storage = Arc::new(NoServerSessionStorage {});\n")):
            self.refused(gate.check_tls, tls, GOOD_TLS.replace(line, ""), message % name)
            self.refused(gate.check_tls, tls, GOOD_TLS.replace(line, "    // " + line.strip() + "\n"), message % name)
            self.refused(gate.check_tls, tls, GOOD_TLS + line, message % name)
            self.refused(gate.check_tls, "crates/gate-tls/src/i04.rs", line, message % name)
        self.refused(gate.check_tls, tls, GOOD_TLS.replace("max_early_data_size = 0", "max_early_data_size = 16384"),
                     message % "max_early_data_size")
        self.refused(gate.check_tls, tls, GOOD_TLS.replace("send_tls13_tickets = 0", "send_tls13_tickets = 2"),
                     message % "send_tls13_tickets")
        # Whitespace variants of the settings are accepted; the lower-case ticketer read is not a refused token.
        self.write(tls, GOOD_TLS.replace("config.send_tls13_tickets = 0;", "config.send_tls13_tickets=0;"))
        self.assertEqual(gate.check_tls(self.base), 5)

    def test_the_resolver_is_named_exactly_once(self):
        tls = "crates/gate-tls/src/tls.rs"
        self.refused(gate.check_tls, tls, GOOD_TLS.replace("SingleCertAndKey::from(certified)", "certified"),
                     "SingleCertAndKey::from. exactly once")
        self.refused(gate.check_tls, tls, GOOD_TLS + "fn again() { let _ = with_cert_resolver(x); }\n",
                     "with_cert_resolver. exactly once")

    def test_every_refused_client_token(self):
        # HE-003C (Q-HE3C-5 (b)): one global list, so the client hazards refuse in any gate-tls source, comments
        # included, and the server's tokens refuse in the client's sources too.
        for rel in ("crates/gate-tls/src/tls_client.rs", "crates/gate-tls/src/upstream.rs", "crates/gate-tls/src/tls.rs"):
            text = self.TREE.get(rel, "")
            for line in ("config.resumption = Resumption::in_memory_sessions(8);", "let _ = Resumption :: store(s);",
                         "let _ = ClientSessionMemoryCache::new(8);", "let r = r.tls12_resumption(t);",
                         "let b = b.with_ech(mode);", "let _: Option<EchMode> = None;",
                         "let c = b.with_client_cert_resolver(r);", "let _ = config.send_ticket_request;",
                         "// with_ech is not called", "let _ = ClientConfig::builder();", "let b = b.dangerous();",
                         "let c = b.with_no_client_auth();", "config.key_log = k;",
                         "let _ = ClientConfig::builder_with_protocol_versions(&[&TLS13]);",
                         "let _ = WebPkiServerVerifier::builder(roots);"):
                self.refused(gate.check_tls, rel, text + line + "\n", "names .* .TLS deny-list")
        self.assertEqual(gate.check_tls(self.base), 5)

    def test_the_client_settings_are_set_exactly_once(self):
        client = "crates/gate-tls/src/tls_client.rs"
        message = "does not set %s exactly once"
        for name, line in (("resumption", "    config.resumption = Resumption::disabled();\n"),
                           ("enable_early_data", "    config.enable_early_data = false;\n"),
                           ("enable_sni", "    config.enable_sni = false;\n")):
            self.refused(gate.check_tls, client, GOOD_CLIENT.replace(line, ""), message % name)
            self.refused(gate.check_tls, client, GOOD_CLIENT.replace(line, "    // " + line.strip() + "\n"), message % name)
            self.refused(gate.check_tls, client, GOOD_CLIENT + line, message % name)
            self.refused(gate.check_tls, "crates/gate-tls/src/upstream.rs", line, message % name)
        for old, new, name in (("enable_early_data = false", "enable_early_data = true", "enable_early_data"),
                               ("enable_sni = false", "enable_sni = true", "enable_sni"),
                               ("Resumption::disabled()", "Resumption::default()", "resumption")):
            self.refused(gate.check_tls, client, GOOD_CLIENT.replace(old, new), message % name)
        # Whitespace variants pass; the type name Resumption is not the setting.
        self.write(client, GOOD_CLIENT.replace("config.enable_sni = false;", "config.enable_sni=false;")
                   + "fn kind() -> Resumption { Resumption::disabled() }\n")
        self.assertEqual(gate.check_tls(self.base), 5)

    def test_client_auth_and_the_verifier_are_named_once_in_tls_client(self):
        client = "crates/gate-tls/src/tls_client.rs"
        for name, call in (("with_client_auth_cert", ".with_client_auth_cert(chain, key)"),
                           ("with_webpki_verifier", ".with_webpki_verifier(verifier)")):
            message = "mention %s exactly once, in tls_client.rs" % name
            self.refused(gate.check_tls, client, GOOD_CLIENT.replace(call, ""), message)
            self.refused(gate.check_tls, client, GOOD_CLIENT + "fn again() { x%s; }\n" % call, message)
            self.refused(gate.check_tls, "crates/gate-tls/src/upstream.rs", "fn other() { x%s; }\n" % call, message)
            self.refused(gate.check_tls, client, GOOD_CLIENT.replace(call, "/* %s */" % call), message)
        (self.base / client).rename(self.base / "crates/gate-tls/src/client.rs")
        with self.assertRaisesRegex(gate.GateError, "no tls_client.rs"):
            gate.check_tls(self.base)

    def test_only_exchange_names_upstream_response(self):
        # HE-003C DESIGN section 5, widened by HE-003D DESIGN section 5 (HE-003C PR R1-1, D1-2): outside exchange.rs no
        # gate-tls source and no source of the binary names UpstreamResponse at all (read without comments).
        message = "names UpstreamResponse outside crates/gate-tls/src/exchange.rs"
        for rel, text in (("crates/gate-tls/src/upstream.rs", "fn f() { let _ = UpstreamResponse { http_status: 200 }; }\n"),
                          ("crates/gate-tls/src/upstream.rs", "fn f() { let _ = effect_gate::UpstreamResponse{ x }; }\n"),
                          ("crates/gate-tls/src/i04.rs", "fn f() { let _ = UpstreamResponse\n    { x }; }\n"),
                          # The bypass forms of R1-1: a use, a renamed or grouped import, an alias, a where-impl, a
                          # clone-and-mutate, a type in a signature.
                          ("crates/gate-tls/src/upstream.rs", "use effect_gate::UpstreamResponse;\n"),
                          ("crates/gate-tls/src/upstream.rs", "use effect_gate::UpstreamResponse as Resp;\nfn f() { Resp { x }; }\n"),
                          ("crates/gate-tls/src/upstream.rs", "use effect_gate::{Event, UpstreamResponse as R};\n"),
                          ("crates/gate-tls/src/i04.rs", "type Resp = effect_gate::UpstreamResponse;\n"),
                          ("crates/gate-tls/src/i04.rs", "impl<T> Build for T where T: Into<UpstreamResponse> {}\n"),
                          ("crates/gate-tls/src/i04.rs", "fn f(r: &UpstreamResponse) { let mut c = r.clone(); c.http_status = 1; }\n"),
                          ("crates/gate/src/main.rs", "fn main() { let _: Option<effect_gate::UpstreamResponse> = None; }\n")):
            self.refused(gate.check_tls, rel, text, message)
        # A comment, a literal, the tests and effect-gate's sources are not mentions in gate-tls or the binary.
        self.write("crates/gate-tls/src/upstream.rs", "// UpstreamResponse { .. }\nconst A: &str = \"UpstreamResponse { }\";\n")
        self.write("crates/gate-tls/tests/upstream.rs", "let _ = UpstreamResponse { http_status: 200 };\n")
        self.write("crates/effect-gate/src/gate.rs", "pub struct UpstreamResponse { pub http_status: i64 }\n")
        self.assertEqual(gate.check_tls(self.base), 6)

    def test_the_binary_and_macros_and_root_certificates(self):
        # HE-003D DESIGN section 5 (C7, D1-2): the deny-list and the exactly-once rules cover the binary's sources;
        # with_root_certificates joins the list; neither crate defines a macro_rules macro.
        main = "crates/gate/src/main.rs"
        self.write(main, "fn main() {}\n")
        self.assertEqual(gate.check_tls(self.base), 6)
        for text in ("fn main() { let _ = KeyLogFile::new(); }\n", "// SSLKEYLOGFILE\nfn main() {}\n",
                     "fn main() { let _ = rustls::ClientConfig::builder(); }\n",
                     "fn main() { b.with_root_certificates(roots); }\n"):
            self.refused(gate.check_tls, main, text, "main.rs names .* .TLS deny-list")
        self.refused(gate.check_tls, "crates/gate-tls/src/tls_client.rs", GOOD_CLIENT + "fn r() { b.with_root_certificates(x); }\n",
                     "names with_root_certificates")
        self.refused(gate.check_tls, main, "fn main() { config.enable_sni = false; }\n", "does not set enable_sni exactly once")
        self.refused(gate.check_tls, main, "fn main() { let f = rustls::ConfigBuilder::with_client_auth_cert; }\n",
                     "mention with_client_auth_cert exactly once")
        for rel in (main, "crates/gate-tls/src/upstream.rs"):
            self.refused(gate.check_tls, rel, "macro_rules! m { () => {} }\nfn main() {}\n", "defines a macro with macro_rules")
        # A mention in a comment is not counted.
        self.write(main, "// with_client_auth_cert, with_webpki_verifier, macro_rules\nfn main() {}\n")
        self.assertEqual(gate.check_tls(self.base), 6)


SECRET_TREE = {**DEBUG_TREE, "crates/gate-tls/src/tls.rs": "#[derive(Debug)]\npub enum TlsSetupError { Key(rustls::Error) }\n"
                                                          "impl fmt::Debug for TlsServerInputs { fn fmt() {} }\n"}


class SecretDebugTests(Tree):
    """HE-003B DESIGN section 2.6 (D1-4): no derive(Debug) on a secret type or on an item whose field types mention one,
    nor on one holding the I04 listener's opaque types."""

    TREE = SECRET_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_debug_derives(self.base), 13)

    def test_secret_names_and_fields_refuse(self):
        rel = "crates/gate-tls/src/extra.rs"
        for text in ("#[derive(Debug)]\npub struct TlsServerInputs { key: Vec<u8> }",
                     "#[derive(Clone, Debug)]\nstruct ServerConnection(u8);",
                     "#[cfg_attr(test, derive(Debug))]\nstruct CertifiedKey;"):
            self.refused(gate.check_debug_derives, rel, text + "\n", "a secret type .Debug check")
        for text, hazard in (("#[derive(Debug)]\nstruct S { config: Arc<ServerConfig> }", "ServerConfig"),
                             ("#[derive(Debug)]\nstruct S { inputs: Option<TlsServerInputs> }", "TlsServerInputs"),
                             ("#[derive(Debug)]\nenum E { K(PrivateKeyDer<'static>) }", "PrivateKeyDer"),
                             ("#[derive(Debug)]\nstruct S { k: PrivatePkcs8KeyDer<'static> }", "PrivatePkcs8KeyDer"),
                             ("#[derive(Debug)]\nstruct S { tls: ServerConnection }", "ServerConnection"),
                             ("#[derive(Debug)]\nstruct S { c: TcpConn }", "TcpConn"),
                             ("#[derive(Debug)]\nstruct S { l: gate_sys::tcp::TcpListener }", "TcpListener"),
                             ("#[derive(Debug)]\nstruct S { n: Rc<RefCell<NetTable>> }", "NetTable")):
            self.refused(gate.check_debug_derives, rel, text + "\n", "mention %s .Debug check" % hazard)

    def test_credential_holders_refuse(self):
        # HE-003D DESIGN section 3.4 (D1-7): the credential read's helper and key holder are secret types.
        rel = "crates/gate-tls/src/extra.rs"
        for text in ("#[derive(Debug)]\npub struct KeyBytes(Zeroizing<Vec<u8>>);",
                     "#[derive(Clone, Debug)]\npub struct CredentialFile { size: usize }"):
            self.refused(gate.check_debug_derives, rel, text + "\n", "a secret type .Debug check")
        for text, hazard in (("#[derive(Debug)]\nstruct S { key: KeyBytes }", "KeyBytes"),
                             ("#[derive(Debug)]\nenum E { F(CredentialFile) }", "CredentialFile")):
            self.refused(gate.check_debug_derives, rel, text + "\n", "mention %s .Debug check" % hazard)

    def test_client_secret_names_and_fields_refuse(self):
        # HE-003C DESIGN section 5: the client's configuration, connection and identity, and the connector.
        rel = "crates/gate-tls/src/extra.rs"
        for text in ("#[derive(Debug)]\npub struct TlsClientIdentity { key: Vec<u8> }",
                     "#[derive(Clone, Debug)]\nstruct ClientConnection(u8);",
                     "#[cfg_attr(test, derive(Debug))]\nstruct ClientConfig;"):
            self.refused(gate.check_debug_derives, rel, text + "\n", "a secret type .Debug check")
        for text, hazard in (("#[derive(Debug)]\nstruct S { config: Arc<ClientConfig> }", "ClientConfig"),
                             ("#[derive(Debug)]\nstruct Open { tls: Option<ClientConnection> }", "ClientConnection"),
                             ("#[derive(Debug)]\nenum E { I(TlsClientIdentity) }", "TlsClientIdentity"),
                             ("#[derive(Debug)]\nstruct S { net: effect_gate::linux_net::LinuxConnector }",
                              "LinuxConnector")):
            self.refused(gate.check_debug_derives, rel, text + "\n", "mention %s .Debug check" % hazard)


GOOD_MAIN = """//! The gate binary (a comment may name NetTable, std::thread and println!).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use effect_gate::status;
#[cfg(target_os = "linux")]
use effect_gate::{seal_stage1, seal_stage2, GateConfig, Sealed};
#[cfg(target_os = "linux")]
use gate_tls::signed_config::{self, LoadError};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let stage1 = match seal_stage1() {
        Ok(stage1) => stage1,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    let document = match signed_config::load() {
        Ok(document) => document,
        Err(LoadError::Read) => return ExitCode::from(status::CONFIG_READ),
        Err(LoadError::Signature(_)) => return ExitCode::from(status::CONFIG_SIGNATURE),
    };
    let config = match GateConfig::parse(&document) {
        Ok(config) => config,
        Err(_) => return ExitCode::from(status::CONFIG_CHECK),
    };
    let sealed = match seal_stage2(stage1) {
        Ok(sealed) => sealed,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    ExitCode::from(serve(&sealed, config))
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    ExitCode::from(status::NOT_LINUX)
}

#[cfg(target_os = "linux")]
fn serve(sealed: &Sealed, config: GateConfig) -> u8 {
    use effect_gate::file_store::fstat_device;
    use effect_gate::linux_net::{LinuxConnector, LinuxStreams, NetTable};
    use effect_gate::linux_os::{KernelRoots, LinuxKernelReads, LinuxOs};
    use effect_gate::{ExpectedPeers, FileStores, KernelObserver, ListenerPlan, Owner, PolicyGate, Stores, Substrate};
    use gate_tls::{client_config, credentials, server_config, Exchange, I04Server, UpstreamClient};
    let net = NetTable::new();
    if NetTable::listen_i04(&net, sealed, &config.endpoint).is_err() {
        return status::SOCKETS;
    }
    let _ = LinuxConnector::new(sealed, net);
    0
}
"""
GOOD_GATE_CONFIG = "//! Portable checks.\nuse crate::net::InetAddress;\npub fn parse() {}\n"
GOOD_SIGNED_CONFIG = "//! The read between the stages.\nuse gate_sys::Dir;\npub fn load() { let _ = Dir::at(\"/etc/planeon/effect-gate\"); }\n"
SEAL_TREE = {**LINKED_TREE, gate.GATE_MAIN: GOOD_MAIN, gate.GATE_CONFIG: GOOD_GATE_CONFIG, gate.SIGNED_CONFIG: GOOD_SIGNED_CONFIG}


class SealOrderTests(Tree):
    """HE-003D DESIGN section 5 (O2; D1-3, D2-2): the seal-order grammar over the binary's main.rs, and the socket and
    thread names refused before the second stage there and in the configuration's two modules."""

    TREE = SEAL_TREE

    def test_the_main_passes(self):
        found = gate.check_seal_order(self.base)
        self.assertEqual(found, "Err, ExitCode::from, GateConfig::parse, Ok, signed_config::load, status::seal "
                                "(and the tuple-variant patterns LoadError::Signature)")

    def test_a_call_between_the_stages_refuses(self):
        main = gate.GATE_MAIN
        before = "    let sealed = match seal_stage2(stage1) {"
        message = "seal-order grammar"
        for extra in ("    let _ = config.validate();\n",                 # a method call
                      "    let f = |x: u8| x;\n",                          # a closure
                      "    println!(\"x\");\n",                            # a macro
                      "    let _ = listen();\n",                           # another call
                      "    let _ = GateConfig::parse(&document)?;\n",      # the ? operator
                      "    let _ = Wrapper::Thing(document);\n",           # a constructor outside a pattern
                      "    let _ = status::seal(&e);\n",                   # status::seal outside ExitCode::from
                      "    let _ = [0u8; 4];\n",                           # brackets
                      "    loop {}\n",                                     # another keyword
                      "    let _ = signed_config :: load ();\n    let _ = gate_tls::credentials::time_provider();\n"):
            self.refused(gate.check_seal_order, main, GOOD_MAIN.replace(before, extra + before), message)
        # Spaces and comments between the tokens do not hide a call.
        self.refused(gate.check_seal_order, main, GOOD_MAIN.replace(before, "    let _ = setup /* x */ ();\n" + before),
                     "main calls setup")

    def test_the_second_stage_statement_is_exact(self):
        # PR review round 1, R1-1: nothing in the argument of seal_stage2 (evaluated before the second stage) and
        # nothing else in either arm.
        main = gate.GATE_MAIN
        argument = "seal_stage2(stage1)"
        for replacement in ("seal_stage2({ let _ = early(); stage1 })",
                            "seal_stage2({ let _n = effect_gate::linux_net::NetTable::new(); stage1 })",
                            "seal_stage2(make(stage1))", "seal_stage2(match stage1 { s => s })", "seal_stage2(&stage1)",
                            "seal_stage2(stage1.clone())", "seal_stage2(other)", "seal_stage2(stage1, extra)"):
            self.refused(gate.check_seal_order, main, GOOD_MAIN.replace(argument, replacement), "seal-order grammar")
        ok_arm, err_arm = "        Ok(sealed) => sealed,\n", "        Err(error) => return ExitCode::from(status::seal(&error)),\n    };\n    ExitCode::from(serve"
        for old, new in ((ok_arm, "        Ok(sealed) => { let _ = early(); sealed }\n"),
                         (ok_arm, "        Ok(sealed) => other,\n"),
                         (ok_arm, "        Ok(sealed) => sealed,\n        _ => unreachable(),\n"),
                         (err_arm, "        Err(error) => { let _ = early(); return ExitCode::from(status::seal(&error)) }\n    };\n    ExitCode::from(serve"),
                         (err_arm, "        Err(error) => return ExitCode::from(status::seal(&other)),\n    };\n    ExitCode::from(serve"),
                         (err_arm, "        Err(error) => return ExitCode::from(status::CONFIG_READ),\n    };\n    ExitCode::from(serve"),
                         (err_arm, "        Err(error) => return ExitCode::from(status::seal(&error)),\n    }\n    .into();\n    ExitCode::from(serve")):
            self.assertEqual(GOOD_MAIN.count(old), 1, old)
            self.refused(gate.check_seal_order, main, GOOD_MAIN.replace(old, new), "seal-order grammar")
        # Whitespace and comments inside the statement are tolerated.
        spaced = GOOD_MAIN.replace("    let sealed = match seal_stage2(stage1) {",
                                   "    let sealed = match /* stage 2 */ seal_stage2 ( stage1 )\n    {")
        self.write(main, spaced)
        self.assertIn("signed_config::load", gate.check_seal_order(self.base))

    def test_main_rs_holds_only_its_pinned_imports_items_and_attributes(self):
        # PR review round 1, R1-2: code defined in main.rs cannot run between the stages under an allowed name.
        main = gate.GATE_MAIN
        use = "use gate_tls::signed_config::{self, LoadError};\n"
        shadow = ("#[cfg(target_os = \"linux\")]\nmod signed_config {\n    pub enum LoadError { Read, Signature(u8) }\n"
                  "    pub fn load() -> Result<Vec<u8>, LoadError> { Err(LoadError::Read) }\n}\n")
        for text, message in (
                (GOOD_MAIN.replace(use, "use signed_config::LoadError;\n") + shadow, "pinned set"),            # P1
                (GOOD_MAIN + shadow, "defines a mod item"),
                (GOOD_MAIN.replace("use effect_gate::{seal_stage1, seal_stage2, GateConfig, Sealed};",
                                   "use effect_gate::{seal_stage1, seal_stage2, Sealed};")
                 + "struct GateConfig;\nimpl GateConfig { fn parse(_: &[u8]) -> Result<u8, ()> { Err(()) } }\n", "pinned set"),  # P2
                (GOOD_MAIN.replace(use, "use gate_tls::credentials as signed_config;\nuse gate_tls::signed_config::LoadError;\n"),
                 "renames an import"),                                                                           # P3
                (GOOD_MAIN.replace(use, "use gate_tls::signed_config::*;\n"), "imports a glob"),
                (GOOD_MAIN + "use gate_tls::http1::frame;\n", "pinned set"),
                (GOOD_MAIN.replace("    use effect_gate::linux_os::{KernelRoots, LinuxKernelReads, LinuxOs};\n", ""), "pinned set"),
                # HE-003A3 (D2-2): the observation's three imports are pinned too.
                (GOOD_MAIN.replace("{KernelRoots, LinuxKernelReads, LinuxOs}", "{LinuxKernelReads, LinuxOs}"), "pinned set"),
                (GOOD_MAIN.replace("FileStores, KernelObserver, ListenerPlan", "FileStores, ListenerPlan"), "pinned set"),
                (GOOD_MAIN + "fn early() {}\n", "functions other than"),
                (GOOD_MAIN.replace("    let net = NetTable::new();", "    fn inner() {}\n    let net = NetTable::new();"),
                 "functions other than")):
            self.refused(gate.check_seal_order, main, text, message)
        for item in ("struct S;", "enum E { A }", "union U { a: u8 }", "trait T {}", "type T = u8;", "impl S {}",
                     "const C: u8 = 0;", "static S: u8 = 0;", "macro_rules! m { () => {} }", "macro m() {}",
                     "extern \"C\" { fn f(); }", "mod m {}"):
            self.refused(gate.check_seal_order, main, GOOD_MAIN + item + "\n", "defines a .* item")
        for text in (GOOD_MAIN.replace('#[cfg(target_os = "linux")]\nfn main()', '#[cfg(any())]\n#[cfg(target_os = "linux")]\nfn main()', 1),  # P4
                     GOOD_MAIN.replace('#[cfg(target_os = "linux")]\nfn main()', '#[inline(never)]\n#[cfg(target_os = "linux")]\nfn main()', 1),
                     GOOD_MAIN.replace('#[cfg(target_os = "linux")]\nfn serve', '#[cfg(target_os = "linux")]\n#[inline]\nfn serve', 1),
                     GOOD_MAIN.replace("#![forbid(unsafe_code)]", "#![forbid(unsafe_code)]\n#![allow(dead_code)]")):
            self.refused(gate.check_seal_order, main, text, "attribute")

    def test_the_name_scan_on_its_own(self):
        # PR review round 2, R2-3: with the pinned imports and the grammar satisfied (a path that is not called), only
        # the before-seal name scan refuses: one between the stages (Q23), one inside the stage-1 arm (Q24).
        main = gate.GATE_MAIN
        for old, new in (("    let config = match GateConfig::parse(&document) {",
                          "    let _n = effect_gate::linux_net::NetTable::new;\n    let config = match GateConfig::parse(&document) {"),
                         ("        Ok(stage1) => stage1,", "        Ok(stage1) => { let _p = effect_gate::linux_os::LinuxOs::new; stage1 }"),
                         ("    let config = match GateConfig::parse(&document) {",
                          "    let _t = std :: thread :: yield_now;\n    let config = match GateConfig::parse(&document) {")):
            self.assertEqual(GOOD_MAIN.count(old), 1, old)
            self.refused(gate.check_seal_order, main, GOOD_MAIN.replace(old, new), "main.rs names .* before the seal")

    def test_the_main_shape(self):
        main = gate.GATE_MAIN
        for text, message in (
                (GOOD_MAIN.replace("    let stage1 = match seal_stage1() {", "    let early = 1;\n    let stage1 = match seal_stage1() {"),
                 "does not start with"),
                (GOOD_MAIN + "fn again() { let _ = seal_stage2(x); }\n", "exactly once each"),
                (GOOD_MAIN.replace("seal_stage2(stage1)", "seal_stage2(stage1)").replace(
                    "#[cfg(not(target_os = \"linux\"))]\nfn main() -> ExitCode {\n    ExitCode::from(status::NOT_LINUX)\n}",
                    "#[cfg(not(target_os = \"linux\"))]\nfn main() -> ExitCode {\n    run()\n}"), "exactly one"),
                (GOOD_MAIN.replace("#[cfg(target_os = \"linux\")]\nfn main()", "fn main()"), "exactly one"),
                (GOOD_MAIN.replace("#[cfg(target_os = \"linux\")]\nfn main()", "#[cfg(target_os = \"linux\")]\nfn main()", 1)
                 + "#[cfg(target_os = \"linux\")]\nfn main() -> ExitCode { ExitCode::from(1) }\n", "exactly one")):
            self.refused(gate.check_seal_order, main, text, message)
        (self.base / gate.SIGNED_CONFIG).unlink()
        with self.assertRaisesRegex(gate.GateError, "signed_config.rs is missing"):
            gate.check_seal_order(self.base)

    def test_socket_and_thread_names_before_the_second_stage(self):
        main = gate.GATE_MAIN
        for line in ("use effect_gate::linux_net::NetTable;", "use effect_gate::linux_os::LinuxOs;",
                     "use effect_gate::linux_net::LinuxConnector;", "use gate_sys::channel::Poller;",
                     "use std::thread;", "fn f() { let _ = std :: net :: TcpListener::bind; }",
                     "fn f() { let _ = thread::current(); }", "fn f() { gate_tls::x::listen_tcp(); }",
                     "fn f() { connect_upstream(); }"):
            # The pinned imports (R1-2) refuse these first; the name scan stands behind them.
            self.refused(gate.check_seal_order, main, GOOD_MAIN.replace("use effect_gate::status;", line + "\nuse effect_gate::status;"),
                         "main.rs('s imports are not exactly the pinned set| names .* before the seal| defines)")
        for rel, base_text in ((gate.GATE_CONFIG, GOOD_GATE_CONFIG), (gate.SIGNED_CONFIG, GOOD_SIGNED_CONFIG)):
            for line in ("use gate_sys::inet::parse_authority;", "fn f() { let _ = Poller::new(); }",
                         "fn f() { std::thread::spawn(g); }", "use effect_gate::linux_net::NetTable;"):
                self.refused(gate.check_seal_order, rel, base_text + line + "\n", "names .* before the seal")
        # signed_config.rs may import gate-sys's read-only opener once, and only that (departure A2, accepted).
        self.refused(gate.check_seal_order, gate.SIGNED_CONFIG, GOOD_SIGNED_CONFIG + "use gate_sys::Dir;\n", "names gate_sys")
        self.refused(gate.check_seal_order, gate.GATE_CONFIG, GOOD_GATE_CONFIG + "use gate_sys::Dir;\n", "names gate_sys")
        without = GOOD_SIGNED_CONFIG.replace("use gate_sys::Dir;\n", "")
        for line in ("pub use gate_sys::Dir;", "pub(crate) use gate_sys::Dir;", "use gate_sys::{Dir};",
                     "use gate_sys::Dir as D;", "use gate_sys::openat::Dir;", "use ::gate_sys::Dir;",
                     "use gate_sys::{Dir, FileMode};", "use gate_sys::*;", "use gate_sys;",
                     "#[cfg(all())] use gate_sys::Dir;", "fn f() { let _ = gate_sys::Dir::at(p); }",
                     "fn f() { let _ = gate_sys::inet::parse_authority(p); }"):
            self.refused(gate.check_seal_order, gate.SIGNED_CONFIG, without + line + "\n", "signed_config.rs names gate_sys")
            self.refused(gate.check_seal_order, gate.SIGNED_CONFIG, GOOD_SIGNED_CONFIG + line + "\n",
                         "signed_config.rs names gate_sys")
        # Whitespace inside the excepted statement and a comment beside it are read through.
        self.write(gate.SIGNED_CONFIG, without + "use gate_sys :: Dir ; // the opener\n")
        self.assertIn("signed_config::load", gate.check_seal_order(self.base))

    def test_kernel_roots_are_refused_before_the_second_stage(self):
        # HE-003A3 (DESIGN section 5, D2-2): KernelRoots joins BEFORE_SEAL_REFUSED; serve (after stage 2) may name it.
        main = gate.GATE_MAIN
        old = "    let config = match GateConfig::parse(&document) {"
        self.refused(gate.check_seal_order, main, GOOD_MAIN.replace(
            old, "    let _r = effect_gate::linux_os::KernelRoots::open_after_seal;\n" + old), "main.rs names KernelRoots before")
        for rel, base_text in ((gate.GATE_CONFIG, GOOD_GATE_CONFIG), (gate.SIGNED_CONFIG, GOOD_SIGNED_CONFIG)):
            self.refused(gate.check_seal_order, rel, base_text + "fn f() { let _ = KernelRoots :: open_after_seal; }\n",
                         "names KernelRoots before the seal")
        self.write(main, GOOD_MAIN.replace("    let _ = LinuxConnector::new(sealed, net);",
                                           "    let _ = LinuxConnector::new(sealed, net);\n    let _k = KernelRoots::open_after_seal(sealed);"))
        self.assertIn("signed_config::load", gate.check_seal_order(self.base))


# HE-004C (G4): the observer's socket module, mapping gate-sys's socket items into client.rs's portable types.
OBSERVER_LINUX_NET_TEXT = ("use gate_sys::channel;\nuse gate_sys::tcp::{self, TcpConn};\n"
                           "pub struct LinuxWire { poller: channel::Poller, conns: Vec<TcpConn> }\n"
                           "pub fn new(_sealed: &Sealed) -> Result<LinuxWire, i32> { x() }\n"
                           "fn connect(a: &InetAddress) -> Result<TcpConn, i32> { tcp::connect_tcp(a).map(|c| c.0) }\n")
SOCKET_TREE = {**LINKED_TREE,
               "crates/effect-gate/src/linux_os.rs": "use gate_sys::channel::{Conn, Poller};\nfn f() { gate_sys::channel::accept(x); }\n",
               "crates/effect-gate/src/linux_net.rs": "use gate_sys::tcp::{TcpConn, TcpListener};\n"
                                                      "fn f() { gate_sys::tcp::listen_tcp(a, 16); }\n",
               "crates/gate-sys/src/tcp.rs": "use crate::channel::Watched;\npub fn listen_tcp() {}\n",
               "crates/gate-tls/src/credentials.rs": "use gate_sys::Dir;\nuse gate_sys::{FileMode, inet::InetAddress};\n",
               # HE-004C (G4): the observer's socket module.
               gate.OBSERVER_LINUX_NET: OBSERVER_LINUX_NET_TEXT}


class SocketModuleTests(Tree):
    """HE-003D DESIGN section 5 (D1-3, D2-6): gate-sys's channel and tcp modules are reached only from effect-gate's
    linux_os.rs and linux_net.rs (which re-export nothing) and from gate-sys, by use tree or qualified path; no linked
    source names std::thread or thread::."""

    TREE = SOCKET_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_socket_modules(self.base), 16)

    def test_the_bypass_forms_refuse(self):
        message = "socket-module check"
        for rel in ("crates/gate-tls/src/upstream.rs", gate.GATE_MAIN, "crates/effect-gate/src/substrate.rs"):
            prefix = LINKED_TREE.get(rel, "")
            for text in ("use gate_sys::tcp::connect_tcp;", "use gate_sys::{channel, Dir};", "use gate_sys::{self, tcp::TcpConn};",
                         "use gate_sys::*;", "use gate_sys as g;", "use gate_sys::{self as g};", "use gate_sys::channel as c;",
                         "use ::gate_sys::tcp;", "type T = gate_sys::tcp::TcpConn;",
                         "fn f<T>() where T: gate_sys :: tcp :: Owned {}", "fn f() { gate_sys::\n    channel::socket(); }",
                         "fn f() { gate_sys::/* x */tcp::connect_tcp(a); }"):
                self.refused(gate.check_socket_modules, rel, prefix + text + "\n", message)
        self.refused(gate.check_socket_modules, "crates/effect-gate/src/linux_net.rs",
                     SOCKET_TREE["crates/effect-gate/src/linux_net.rs"] + "pub use gate_sys::tcp::TcpConn;\n", "re-exports")
        self.refused(gate.check_socket_modules, "crates/effect-gate/src/linux_os.rs",
                     SOCKET_TREE["crates/effect-gate/src/linux_os.rs"] + "pub(crate) use gate_sys::channel::Conn;\n", "re-exports")
        # A comment or a literal is not a path.
        self.write("crates/gate-tls/src/upstream.rs", "// gate_sys::tcp\nconst A: &str = \"gate_sys::channel\";\n")
        self.assertEqual(gate.check_socket_modules(self.base), 17)

    def test_threads_refuse_in_every_linked_crate(self):
        for rel in ("crates/gate-sys/src/channel.rs", "crates/i05-protocol/src/json.rs", gate.GATE_MAIN,
                    "crates/effect-gate/src/linux_os.rs"):
            for text in ("use std::thread;", "fn f() { std::thread::spawn(g); }", "fn f() { thread :: sleep(d); }"):
                self.refused(gate.check_socket_modules, rel, LINKED_TREE.get(rel, SOCKET_TREE.get(rel, "")) + text + "\n",
                             "names std::thread or thread::")
        self.write("crates/effect-gate/src/linux_os.rs", SOCKET_TREE["crates/effect-gate/src/linux_os.rs"]
                   + "// one thread::\nconst T: &str = \"thread-self\";\nfn threads() {}\n")
        self.assertEqual(gate.check_socket_modules(self.base), 16)


class SocketItemTests(Tree):
    """PR review round 1, R1-3: linux_os.rs and linux_net.rs hand out no gate-sys socket item through a pub type alias,
    const, static or fn signature (P18), except the data types the current code returns; no linked source or the
    binary defines a macro (P13, P14)."""

    TREE = {**SOCKET_TREE,
            "crates/effect-gate/src/linux_net.rs": "use gate_sys::channel::Watched;\nuse gate_sys::tcp::{TcpConn, TcpListenError, TcpListener};\n"
                                                   "pub fn listen_i04(net: &N, _s: &Sealed, a: &A) -> Result<SourceId, TcpListenError> { x() }\n"
                                                   "pub(crate) fn watched(&self) -> Option<Watched<'_>> { None }\n"
                                                   "fn private(l: TcpListener) -> TcpConn { y() }\n",
            "crates/effect-gate/src/linux_os.rs": "use gate_sys::channel::{Conn, ListenError, Poller};\n"
                                                  "pub enum SetupError { Listener { error: ListenError } }\n"
                                                  "pub fn new(_s: &Sealed) -> Result<u8, SetupError> { z() }\n"}

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_socket_modules(self.base), 16)
        self.assertEqual(gate.check_macros(self.base), 16)

    def test_pub_items_naming_socket_items_refuse(self):
        message = "pub item naming gate-sys's socket items"
        for rel in ("crates/effect-gate/src/linux_os.rs", "crates/effect-gate/src/linux_net.rs"):
            base = self.TREE[rel]
            for line in ("pub type Wire = gate_sys::channel::Poller;",                      # P18
                         "pub(crate) type Wire = gate_sys :: tcp :: TcpConn;",
                         "pub const L: fn(&A, u16) -> u8 = gate_sys::tcp::listen_tcp;",
                         "pub static S: Option<gate_sys::channel::Conn> = None;",
                         "pub fn take(&mut self) -> gate_sys::tcp::TcpListener { x() }",
                         "pub(super) fn f<T>(t: T) where T: Into<gate_sys::channel::Poller> { }",
                         "pub unsafe fn g() -> gate_sys::channel::PidFd { x() }"):
                self.refused(gate.check_socket_modules, rel, base + line + "\n", message)
        os_rs = "crates/effect-gate/src/linux_os.rs"
        for text in (self.TREE[os_rs] + "pub type Wire = Poller;\n",
                     self.TREE[os_rs] + "pub(crate) fn poller(&self) -> &Poller { &self.p }\n",
                     "use gate_sys::channel;\npub type Wire = channel::Poller;\n",
                     "use gate_sys::tcp::{self as t};\npub fn f() -> t::TcpConn { x() }\n",
                     "use gate_sys::tcp::TcpConn as TcpListenError;\npub fn f() -> TcpListenError { x() }\n"):
            self.refused(gate.check_socket_modules, os_rs, text, message)
        self.refused(gate.check_socket_modules, os_rs, "use gate_sys::channel::*;\n", "glob of gate-sys's socket module")

    def test_aliases_fields_and_fn_pointers_refuse(self):
        # PR review round 2, R2-1 (the reviewer's Q6, Q7, Q9, Q15 and their kin).
        os_rs = "crates/effect-gate/src/linux_os.rs"
        base = self.TREE[os_rs]
        for text, message in (
                ("type P = Poller;\npub type Wire = P;", "defines a private type alias"),                    # Q6
                ("type P = gate_sys::channel::Poller;\npub type Wire = P;", "defines a private type alias"),  # Q7
                ("type Local = u8;", "defines a private type alias"),
                ("pub struct Leak { pub poller: Poller }", "pub field naming gate-sys's socket items"),      # Q9
                ("pub struct Leak2 { n: u8, pub(crate) c: Option<gate_sys::tcp::TcpConn> }", "pub field naming"),
                ("pub struct Tuple(pub Conn);", "pub field naming"),
                ("pub struct F { pub f: fn(&A, u16) -> u8, pub g: u8 }", "pub field of a fn-pointer type"),
                ("pub struct E { pub f: extern \"C\" fn() }", "pub field of a fn-pointer type"),
                ("fn lt(a: &A, b: u16) -> bool { g(a, b) }\npub static LT: fn(&A, u16) -> bool = lt;", "pub static of a fn-pointer"),  # Q15
                ("pub const L: Option<fn()> = None;", "pub const of a fn-pointer")):
            self.refused(gate.check_socket_modules, os_rs, base + text + "\n", message)
        # Private fields, data-type fields, plain pub aliases and consts, and unit structs pass.
        self.write(os_rs, base + "pub struct Held { poller: Poller, pub n: u8, pub e: ListenError, f: fn() }\n"
                   "pub type Shared = Rc<RefCell<u8>>;\npub const BACKLOG: u16 = 16;\nstruct Unit;\n"
                   "pub struct Pair(u8, Poller);\nfn private() -> fn() { f }\n")
        self.assertEqual(gate.check_socket_modules(self.base), 16)

    def test_fn_traits_fn_pointers_and_pub_enum_variants_refuse(self):
        # HE-003D PR review round 2 confirmation, N1 (HE-003A2 DESIGN section 6, Q-A2-9 (a), D1-3, D2-1).
        os_rs, net_rs = "crates/effect-gate/src/linux_os.rs", "crates/effect-gate/src/linux_net.rs"
        lt = "fn lt(a: &InetAddress, p: u16) -> bool { gate_sys::tcp::listen_tcp(a, p).is_ok() }\n"
        for rel, text, message in (
                # The reviewer's Q25-Q30.
                (net_rs, lt + "pub type Hook = fn(&InetAddress, u16) -> bool;\npub static LT: Hook = lt;", "pub type of a fn-pointer"),
                (net_rs, lt + "pub static LT2: &(dyn Fn(&InetAddress, u16) -> bool + Sync) = &lt;", "pub static of an Fn-trait"),
                (net_rs, lt + "pub struct Leak { pub hook: &'static (dyn Fn(&InetAddress, u16) -> bool + Sync) }", "pub field of an Fn-trait"),
                (os_rs, "pub enum Leak { P(Poller) }", "pub enum variant naming gate-sys's socket items \\['Poller'\\]"),
                (net_rs, lt + "pub enum H { F(fn(&InetAddress, u16) -> bool) }\npub const X: H = H::F(lt);", "pub enum variant of a fn-pointer"),
                (net_rs, lt + "pub type Hook = fn(&InetAddress, u16) -> bool;\npub struct S { pub hook: Hook }", "pub type of a fn-pointer"),
                # D2-1's three.
                (os_rs, "pub enum H { F(fn() -> bool) }", "pub enum variant of a fn-pointer"),
                (os_rs, "pub enum N { V { f: Box<dyn FnMut()> } }", "pub enum variant of an Fn-trait"),
                # FnMut, FnOnce, higher-ranked and bounded forms; aliases, consts, statics, braced and tuple fields.
                (os_rs, "pub type Cb = Box<dyn FnOnce(u8) + Send>;", "pub type of an Fn-trait"),
                (os_rs, "pub static S: Mutex<Option<Box<dyn FnMut() + Send>>> = Mutex::new(None);", "pub static of an Fn-trait"),
                (os_rs, "pub static H: &(dyn for<'a> Fn(&'a u8) + Sync) = &h;", "pub static of an Fn-trait"),
                (os_rs, "pub const C: &dyn Fn() = &f;", "pub const of an Fn-trait"),
                (os_rs, "pub(crate) const E: extern \"C\" fn() = f;", "pub const of a fn-pointer"),
                (os_rs, "pub struct T(pub &'static (dyn Send + Fn()));", "pub field of an Fn-trait"),
                (os_rs, "pub struct T(u8, pub(crate) Option<fn(u8)>);", "pub field of a fn-pointer"),
                # A tuple field spelled `pub fn(..)` reads as a pub fn item, which the reader cannot close: refused too.
                (os_rs, "pub struct T(u8, pub(crate) fn(u8));", "cannot read"),
                (os_rs, "pub struct I { pub f: Box<dyn 'static + FnOnce()> }", "pub field of an Fn-trait"),
                # Enum variants: tuple and named-field, socket items through every import form, visibility forms.
                (os_rs, "pub enum W { P { poller: Poller } }", "pub enum variant naming gate-sys's socket items"),
                (os_rs, "pub(crate) enum W { A(u8), B(Option<Conn>) }", "pub enum variant naming gate-sys's socket items"),
                (os_rs, "pub(super) enum W { A(gate_sys::channel::PidFd) }", "pub enum variant naming gate-sys's socket items"),
                (net_rs, "pub enum W { C(Box<TcpConn>) }", "pub enum variant naming gate-sys's socket items"),
                (os_rs, "pub enum W {\n    #[allow(dead_code)]\n    A { f: extern \"C\" fn() },\n}", "pub enum variant of a fn-pointer"),
                (os_rs, "pub enum W { A(Box<dyn Send + FnOnce() -> u8>) }", "pub enum variant of an Fn-trait"),
                # PR review round 1, R1-1: path-qualified, parenthesised, higher-ranked and nested-bound spellings.
                (os_rs, "pub type Cb = Box<dyn std::ops::Fn(u8) + Send>;", "pub type of an Fn-trait"),
                (os_rs, "pub struct Zq { pub f: Box<dyn core::ops::FnMut()> }", "pub field of an Fn-trait"),
                (os_rs, "pub enum Qq { A(Box<dyn ::core::ops::FnOnce()>) }", "pub enum variant of an Fn-trait"),
                (os_rs, "pub static PS: &(dyn (Fn()) + Sync) = &f;", "pub static of an Fn-trait"),
                (os_rs, "pub static HR: &(dyn for<'a> std::ops::Fn(&'a u8) + Sync) = &h;", "pub static of an Fn-trait"),
                (os_rs, "pub const HP: &dyn (for<'a> core::ops::FnMut(&'a u8)) = &h;", "pub const of an Fn-trait"),
                (os_rs, "pub struct Ts(pub Box<dyn Foo<Vec<u8>> + Fn()>);", "pub field of an Fn-trait"),
                (os_rs, "pub type Ip = Option<impl ::std::ops::FnOnce(u8)>;", "pub type of an Fn-trait"),
                # PR review round 1, R1-2: angle brackets in a discriminant do not merge the next variant.
                (os_rs, "#[repr(u8)]\npub enum Ev { A = 1 << 2, B(Poller) }", "pub enum variant naming gate-sys's socket items"),
                (os_rs, "#[repr(u8)]\npub enum Ev { A = 8 >> 1, B(Poller) }", "pub enum variant naming gate-sys's socket items"),
                (os_rs, "#[repr(u8)]\npub enum Ev { A = (2 >= 1) as u8, B { p: Poller } }",
                 "pub enum variant naming gate-sys's socket items"),
                (os_rs, "pub enum Ub { A(Vec<u8), B(u8) }", "unbalanced angle brackets"),
                (os_rs, "pub enum Ub { A { f: u8> } }", "unbalanced angle brackets")):
            self.refused(gate.check_socket_modules, rel, self.TREE[rel] + text + "\n", message)
        # The unchanged files' shapes pass: a pub enum whose variant names equal socket types (SetupError's Poller and
        # Listener) with data-type fields, a private enum holding socket items (linux_net.rs's Stream), unit variants and
        # discriminants, and fn pointers or Fn traits in private items and in a private fn's parameters.
        self.write(os_rs, self.TREE[os_rs].replace(
            "pub enum SetupError { Listener { error: ListenError } }",
            "pub enum SetupError { Poller(io::Error), Listener { side: Listen, error: ListenError } }")
            + "pub enum Kind { Poller, Conn = 2, Plain(u8), Named { listener: u8 } }\n"
            # R1-2: a balanced generic variant and a shift discriminant pass.
            "#[repr(u8)]\npub enum Gen { A(HashMap<u8, Vec<u16>>) = 1 << 2, B { m: Option<Box<u8>> } = 8 >> 1 }\n"
            "fn port_request(&self, request: impl FnOnce(&Poller, Watched<'_>) -> io::Result<()>) -> bool { r() }\n"
            "struct Hidden { f: Box<dyn Fn()>, g: fn() }\n")
        self.write(net_rs, self.TREE[net_rs] + "enum Stream {\n    Listener(TcpListener),\n    Conn(TcpConn),\n}\n")
        self.assertEqual(gate.check_socket_modules(self.base), 16)
        # Comments are not code; the reader refuses an enum it cannot read.
        self.write(os_rs, self.TREE[os_rs] + "// pub enum Leak { P(Poller) }\n")
        self.assertEqual(gate.check_socket_modules(self.base), 16)
        self.refused(gate.check_socket_modules, os_rs, self.TREE[os_rs] + "pub enum Broken { A(u8)\n", "cannot read")

    def test_macros_refuse_in_every_linked_crate(self):
        p13 = ("macro_rules! wire { ($m:ident) => { gate_sys::$m::listen_tcp }; }\n"
               "#[allow(unused_imports)]\npub(crate) use wire;\n")
        p14 = "macro_rules! via { ($c:ident) => { $c::tcp::listen_tcp }; }\npub(crate) use via;\n"
        for rel in ("crates/effect-gate/src/substrate.rs", "crates/gate-sys/src/peer_wire.rs", "crates/i05-protocol/src/json.rs",
                    "crates/gate-tls/src/upstream.rs", gate.GATE_MAIN):
            prefix = LINKED_TREE.get(rel, "")
            for text, name in ((p13, "macro_rules"), (p14, "macro_rules"), ("pub macro wire($m:ident) { gate_sys::$m }", "a macro item"),
                               ("macro wire() {}", "a macro item"), ("#[macro_export]\nconst X: u8 = 0;", "#\\[macro_export\\]")):
                self.refused(gate.check_macros, rel, prefix + text + "\n", "defines %s .macro rule" % name)
        # Comments, literals and the tests are not definitions.
        self.write("crates/effect-gate/src/substrate.rs", "// no macro_rules here\nconst S: &str = \"macro_rules! m\";\n")
        self.write("crates/effect-gate/tests/m.rs", "macro_rules! m { () => {} }\n")
        self.assertEqual(gate.check_macros(self.base), 17)


class StructAngleTests(Tree):
    """HE-003A3 (STRUCT-ANGLE and the struct-body defect, owner decision Q-HE4A-5 (a); DESIGN section 6, D1-5, D2-3,
    D3-3): struct_fields skips the generic list and any where-clause with the context-aware bracket scanner, nests
    angles in type position (generic arguments, qualified paths, for<'a>; `>>` two closers, `->` no bracket) and treats
    array lengths and `{ }` blocks as expressions, so no private first field can swallow a pub hazard field."""

    TREE = {**SOCKET_TREE, "crates/effect-gate/src/linux_os.rs": "use gate_sys::channel::{Conn, ListenError, Poller};\n"}

    def fields(self, text):
        code = gate.rust_code(text)
        match = gate.STRUCT_ITEM.search(code)
        return [field.split(":")[0].split()[-1] if ":" in field else field.strip()
                for field in gate.struct_fields(code, match.end())]

    def test_each_form_reads_the_right_fields(self):
        for text, names in (
                ("pub struct S { a: HashMap<K, V>, pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: [u8; 1 << 2], pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: [u8; { 3 > 2 } as usize], pub p: Poller }", ["a", "p"]),
                ("pub struct S<F: Fn(u8)> { pub p: Poller }", ["p"]),
                ("pub struct S<F: Fn(u8) -> (u8, u8)> { pub p: Poller }", ["p"]),
                ("pub struct S { a: <u8 as Tr<u8, u8>>::A, pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: for<'a> fn(&'a u8), pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: Box<dyn for<'a> Fn(&'a u8)>, pub p: Poller }", ["a", "p"]),
                ("pub struct S<const N: usize = { 1 << 2 }> { pub p: Poller }", ["p"]),
                ("pub struct S<const N: usize = { 3 > 2 }> { pub p: Poller }", ["p"]),
                ("pub struct S<T> where T: Tr<{ 1 }> { pub p: Poller }", ["p"]),
                ("pub struct S<T> where [u8; { 2 }]: Sized, T: Copy { pub p: Poller }", ["p"]),
                ("pub struct S<T>(pub Poller, T) where T: Copy;", ["pub Poller", "T"]),
                ("pub struct S<T> where T: Copy;", []),
                ("pub struct S;", []),
                ("pub struct S { a: Vec<Vec<u8>>, pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: [u8; N >> 1], pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: [u8; A[0] >> 1], pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: [u8; { size_of::<Vec<u8>>() }], pub p: Poller }", ["a", "p"]),
                ("pub struct S<T = Vec<u8>> { a: T, pub p: Poller }", ["a", "p"]),
                ("pub struct S<T = [u8; N >> 1]> { a: T, pub p: Poller }", ["a", "p"]),
                ("pub struct S { a: fn(u8) -> u8, b: Box<dyn Iterator<Item = u8>>, pub p: Poller }", ["a", "b", "p"]),
                ("pub struct S { #[allow(dead_code)] a: u8, pub(crate) p: Poller, }", ["a", "p"])):
            self.assertEqual(self.fields(text), names, text)

    def test_a_private_first_field_never_hides_a_pub_hazard(self):
        os_rs = "crates/effect-gate/src/linux_os.rs"
        base = self.TREE[os_rs]
        for text in ("pub struct S { a: HashMap<K, V>, pub p: Poller }",
                     "pub struct S { a: [u8; 1 << 2], pub p: Poller }",
                     "pub struct S { a: [u8; { 3 > 2 } as usize], pub p: Poller }",
                     "pub struct S<F: Fn(u8)> { pub p: Poller }",
                     "pub struct S<F: Fn(u8) -> (u8, u8)> { pub p: Poller }",
                     "pub struct S { a: <u8 as Tr<u8, u8>>::A, pub p: Poller }",
                     "pub struct S { a: for<'a> fn(&'a u8), pub p: Poller }",
                     "pub struct S { a: Box<dyn for<'a> Fn(&'a u8)>, pub p: Poller }",
                     "pub struct S<const N: usize = { 1 << 2 }> { pub p: Poller }",
                     "pub struct S<T> where T: Tr<{ 1 }> { pub p: Poller }",
                     "pub struct S<T>(pub Poller, T) where T: Copy;",
                     "pub struct S { a: Vec<Vec<u8>>, pub p: Poller }",
                     "pub struct S { a: [u8; N >> 1], pub p: Poller }",
                     "pub struct S { a: [u8; A[0] >> 1], pub p: Poller }",
                     "pub struct S { a: [u8; { size_of::<Vec<u8>>() }], pub p: Poller }",
                     "pub struct S<T = Vec<u8>> { a: T, pub p: Poller }",
                     "pub struct S<T = [u8; N >> 1]> { a: T, pub p: Poller }"):
            self.refused(gate.check_socket_modules, os_rs, base + text + "\n", "pub field naming gate-sys's socket items")
        self.write(os_rs, base + "pub struct S<T> where T: Copy;\npub struct Q<T = [u8; N >> 1]> { a: T, p: Poller }\n")
        self.assertEqual(gate.check_socket_modules(self.base), 16)

    def test_an_unreadable_struct_or_a_field_default_refuses(self):
        os_rs = "crates/effect-gate/src/linux_os.rs"
        for text, message in (("pub struct S { a: bool = X < Y, pub p: Poller }", "a field default"),
                              ("pub struct S { a: u8 = 1 }", "a field default"),
                              ("pub struct S { a: u8>, pub p: Poller }", "cannot read"),
                              ("pub struct S<T { a: T }", "cannot read"),
                              ("pub struct S { a: (u8, pub p: Poller }", "cannot read"),
                              ("pub struct S<T> = T;", "cannot read"),
                              ("pub struct S<T>(T) x;", "cannot read")):
            self.refused(gate.check_socket_modules, os_rs, self.TREE[os_rs] + text + "\n", message)


OBSERVATION_TREE = {
    **LINKED_TREE,
    "crates/effect-gate/src/lib.rs": "#![forbid(unsafe_code)]\npub mod fake_kernel;\npub mod observation;\n"
                                     "pub use observation::{KernelObserver, KernelReads, Unobserved, WorkerObserver};\n",
    gate.OBSERVATION_RS: "pub trait WorkerObserver { fn observe(&mut self, pid: i64, start: i64) -> Observation; }\n"
                         "pub trait KernelReads { type Pidfd; fn poll_zero(&mut self, p: &Self::Pidfd) -> u8; }\n"
                         "pub struct Unobserved;\nimpl WorkerObserver for Unobserved { fn observe() {} }\n"
                         "pub struct KernelObserver<K> { reads: K }\n"
                         "impl<K: KernelReads> KernelObserver<K> { pub fn new(reads: K) -> KernelObserver<K> { x() } }\n"
                         "impl<K: KernelReads> WorkerObserver for KernelObserver<K> { fn observe() {} }\n",
    gate.FAKE_KERNEL: "use crate::observation::{KernelFail, KernelReads};\n"
                      "/// A FakeKernel names KernelObserver only in a comment.\n"
                      "#[derive(Clone, Debug, Default)]\npub struct FakeKernel { processes: Rc<RefCell<Vec<u8>>> }\n"
                      "impl FakeKernel {\n    fn read(&self, render: impl FnOnce(&FakeKernel) -> Result<u8, u8>) -> u8 { x() }\n}\n"
                      "impl KernelReads for FakeKernel {\n    type Pidfd = Rc<(i32, u64)>;\n    fn poll_zero() {}\n}\n"
                      "pub fn convert_v3_config(config: &Value) -> Result<(Value, FakeKernel), String> { x() }\n",
    gate.LINUX_OS: "use gate_sys::channel::PidFd;\nuse gate_sys::openat::{read_bounded, FixedPath, KernelRoot};\n"
                   "pub struct KernelRoots { cgroup: KernelRoot, proc_root: KernelRoot }\n"
                   "impl KernelRoots {\n    pub fn open_after_seal(_sealed: &Sealed) -> io::Result<KernelRoots> {\n"
                   "        let cgroup = KernelRoot::open_kernel_root(\"/sys/fs/cgroup\")?;\n"
                   "        let proc_root = KernelRoot::open_kernel_root(\"/proc\")?;\n"
                   "        Ok(KernelRoots { cgroup, proc_root })\n    }\n}\n"
                   "pub struct LinuxKernelReads {\n    cgroup: KernelRoot,\n    proc_root: KernelRoot,\n}\n"
                   "fn read_fixed(root: &KernelRoot, path: io::Result<FixedPath>) -> u8 { root.open_fixed(&path?) }\n"
                   "impl KernelReads for LinuxKernelReads {\n    type Pidfd = PidFd;\n"
                   "    fn read_leaf_procs(&mut self) -> u8 {\n        read_fixed(&self.cgroup, FixedPath::from_constant("
                   "\"planeon.slice/planeon-capacity-broker.service/probe-worker/cgroup.procs\"))\n    }\n"
                   "    fn read_stat(&mut self, pid: i32) -> u8 { read_fixed(&self.proc_root, FixedPath::pid_stat(pid)) }\n}\n"
                   "fn borrowed(x: &'static str) {}\n",
    gate.OPENAT: LINKED_TREE["crates/gate-sys/src/openat.rs"]
                 + "pub fn from_constant(path: &'static str) -> io::Result<FixedPath> { x() }\n"
                   "pub fn pid_stat(pid: i32) -> io::Result<FixedPath> { x() }\n"
                   "pub fn open_kernel_root(absolute: &str) -> io::Result<KernelRoot> { x() }\n"
                   "pub fn open_fixed(&self, path: &FixedPath) -> io::Result<File> { x() }\n",
    gate.GATE_MAIN: "#![forbid(unsafe_code)]\nfn main() {}\nfn serve(sealed: &Sealed) -> u8 {\n"
                    "    let Ok(kernel) = KernelRoots::open_after_seal(sealed) else { return status::OBSERVER_ROOTS };\n    0\n}\n",
    "crates/effect-gate/src/gate.rs": "pub struct Gate { observer: Box<dyn WorkerObserver> }\n"
                                      "const C01: &str = \"a static list is refused (convert_v3_config)\";\n"
                                      "// fake_kernel::FakeKernel in a comment\n"
                                      "#[cfg(test)]\nmod tests {\n    use super::*;\n"
                                      "    fn g() { let _ = crate::fake_kernel::convert_v3_config(&v); }\n}\n",
}


class ObservationRuleTests(Tree):
    """HE-003A3 DESIGN sections 4-6 (D2-1, D2-5, D3-1, D3-2, D3-4): the observation's caller rules (exact call forms),
    implementation pairs, the fake kernel's confinement and shape, the alias refusal, LinuxKernelReads's fields and
    linux_os.rs's lack of static state."""

    TREE = OBSERVATION_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observation(self.base), 15)

    def test_the_callers_are_pinned_by_exact_call_forms(self):
        os_rs, openat = self.TREE[gate.LINUX_OS], self.TREE[gate.OPENAT]
        cgroup = 'KernelRoot::open_kernel_root("/sys/fs/cgroup")'
        leaf = '"planeon.slice/planeon-capacity-broker.service/probe-worker/cgroup.procs"'
        for rel, text, message in (
                # open_kernel_root: a third call, a call elsewhere, a function item, a renamed path, outside the opener.
                (gate.LINUX_OS, os_rs + 'fn f() { let _ = KernelRoot::open_kernel_root("/proc"); }\n', "pinned calls"),
                ("crates/effect-gate/src/substrate.rs", 'fn f() { let _ = KernelRoot::open_kernel_root("/proc"); }\n',
                 "substrate.rs names open_kernel_root"),
                (gate.LINUX_OS, os_rs + "fn f() { let _ = KernelRoot::open_kernel_root; }\n", "pinned calls"),
                (gate.LINUX_OS, os_rs.replace(cgroup, 'Root::open_kernel_root("/sys/fs/cgroup")'), "pinned calls"),
                (gate.LINUX_OS, os_rs.replace(cgroup, "x()") + "fn f() { let _ = %s; }\n" % cgroup,
                 "outside KernelRoots::open_after_seal"),
                (gate.LINUX_OS, os_rs.replace('open_kernel_root("/proc")', 'open_kernel_root("/proc/1")'), "pinned calls"),
                (gate.GATE_MAIN, self.TREE[gate.GATE_MAIN] + "fn f() { let _ = gate_sys::openat::KernelRoot::open_kernel_root(\"/proc\"); }\n",
                 "main.rs names open_kernel_root"),
                # open_after_seal: twice in main, elsewhere, another argument, no definition.
                (gate.GATE_MAIN, self.TREE[gate.GATE_MAIN] + "fn g(sealed: &Sealed) { let _ = KernelRoots::open_after_seal(sealed); }\n",
                 "main.rs does not name open_after_seal exactly"),
                ("crates/effect-gate/src/substrate.rs", "fn f(s: &Sealed) { let _ = KernelRoots::open_after_seal(s); }\n",
                 "substrate.rs names open_after_seal"),
                (gate.GATE_MAIN, self.TREE[gate.GATE_MAIN].replace("open_after_seal(sealed)", "open_after_seal(&other)"),
                 "main.rs does not name open_after_seal exactly"),
                (gate.LINUX_OS, os_rs.replace("pub fn open_after_seal(", "pub fn open_roots("), "as its definition"),
                # FixedPath's constructors: another literal, a second call, elsewhere; open_fixed by path or elsewhere.
                (gate.LINUX_OS, os_rs.replace(leaf, '"planeon.slice/other/cgroup.procs"'), "from_constant exactly as its pinned"),
                (gate.LINUX_OS, os_rs + "fn f() { let _ = FixedPath::from_constant(%s); }\n" % leaf, "from_constant exactly"),
                ("crates/effect-gate/src/observation.rs", self.TREE[gate.OBSERVATION_RS] + "fn f() { FixedPath::pid_stat(1); }\n",
                 "observation.rs names pid_stat"),
                (gate.LINUX_OS, os_rs + "fn f() { let _ = FixedPath::pid_stat(2); }\n", "pid_stat exactly"),
                (gate.LINUX_OS, os_rs.replace("root.open_fixed(&path?)", "KernelRoot::open_fixed(root, &path?)"),
                 "names open_fixed other than as a method call"),
                ("crates/gate-sys/src/channel.rs", "fn f(r: &KernelRoot, p: &FixedPath) { let _ = r.open_fixed(p); }\n",
                 "channel.rs names open_fixed"),
                (gate.OPENAT, openat + "pub fn from_constant2() { let _ = from_constant; }\n", "from_constant exactly once, as its definition"),
                (gate.OPENAT, openat.replace("pub fn pid_stat(", "pub fn stat_of("), "pid_stat exactly once, as its definition")):
            self.refused(gate.check_observation, rel, text, message)

    def test_the_implementations_are_the_pinned_pairs(self):
        message = "not one of the observation's pinned"
        for rel, text in (
                (gate.FAKE_KERNEL, self.TREE[gate.FAKE_KERNEL] + "impl KernelReads for () { type Pidfd = u8; }\n"),
                (gate.OBSERVATION_RS, self.TREE[gate.OBSERVATION_RS] + "impl<T> KernelReads for T { type Pidfd = u8; }\n"),
                (gate.OBSERVATION_RS, self.TREE[gate.OBSERVATION_RS] + "impl KernelReads for i32 {}\n"),
                ("crates/effect-gate/src/substrate.rs", "struct Counter;\nimpl WorkerObserver for Counter {}\n"),
                ("crates/effect-gate/src/substrate.rs", "impl crate::observation::WorkerObserver for X {}\n"),
                ("crates/effect-gate/src/substrate.rs", "impl KernelReads for LinuxKernelReads {}\n"),
                (gate.OBSERVATION_RS, self.TREE[gate.OBSERVATION_RS] + "impl WorkerObserver for KernelObserver<u8> {}\n"),
                (gate.OBSERVATION_RS, self.TREE[gate.OBSERVATION_RS].replace(
                    "impl<K: KernelReads> WorkerObserver for KernelObserver<K>",
                    "impl<K> WorkerObserver for KernelObserver<K> where K: KernelReads")),
                (gate.OBSERVATION_RS, self.TREE[gate.OBSERVATION_RS] + "impl<T: WorkerObserver> WorkerObserver for Box<T> {}\n"),
                ("crates/effect-gate/src/gate.rs", self.TREE["crates/effect-gate/src/gate.rs"].replace(
                    "    use super::*;\n", "    use super::*;\n    struct Count;\n    impl WorkerObserver for Count {}\n")),
                ("crates/effect-gate/src/substrate.rs", "fn f() { struct L; impl KernelReads for L {} }\n"),
                ("crates/effect-gate/src/substrate.rs", "unsafe impl KernelReads for Z {}\n")):
            self.refused(gate.check_observation, rel, text, message)
        for rel, text in ((gate.OBSERVATION_RS, self.TREE[gate.OBSERVATION_RS].replace(
                              "impl WorkerObserver for Unobserved { fn observe() {} }\n", "")),
                          (gate.OBSERVATION_RS, self.TREE[gate.OBSERVATION_RS] + "impl WorkerObserver for Unobserved {}\n")):
            self.refused(gate.check_observation, rel, text, "not each exactly once")
        # Renamed traits are aliases; impl Trait in a parameter is a type, not an implementation.
        self.refused(gate.check_observation, "crates/effect-gate/src/substrate.rs",
                     "use crate::observation::WorkerObserver as W;\nimpl W for X {}\n", "renames or aliases")
        self.write("crates/effect-gate/src/substrate.rs",
                   "fn f(o: impl WorkerObserver, r: &dyn KernelReads<Pidfd = u8>) -> impl FnOnce() -> u8 { x() }\n")
        self.assertEqual(gate.check_observation(self.base), 16)

    def test_the_fake_kernel_is_confined(self):
        message = "names the fake kernel outside a strict"
        gate_rs = self.TREE["crates/effect-gate/src/gate.rs"]
        for rel, text in (
                ("crates/effect-gate/src/gate.rs", gate_rs + "use crate::fake_kernel::FakeKernel;\n"),
                ("crates/effect-gate/src/policy_gate.rs", "fn f() { let _ = crate::fake_kernel::convert_v3_config; }\n"),
                (gate.EFFECT_GATE_LIB, self.TREE[gate.EFFECT_GATE_LIB] + "pub use fake_kernel::FakeKernel;\n"),
                (gate.EFFECT_GATE_LIB, self.TREE[gate.EFFECT_GATE_LIB] + "pub use crate::fake_kernel as k;\n"),
                ("crates/effect-gate/src/gate.rs", gate_rs.replace("#[cfg(test)]\nmod tests {", "#[cfg(any(test, unix))]\nmod tests {")),
                ("crates/effect-gate/src/gate.rs", gate_rs.replace("#[cfg(test)]\nmod tests {", "#[cfg(test)] mod tests {")),
                ("crates/effect-gate/src/gate.rs", gate_rs.replace("#[cfg(test)]\nmod tests {", "#[cfg(test)]\nmod other {")),
                ("crates/effect-gate/src/gate.rs", gate_rs.replace("#[cfg(test)]\nmod tests {", "#[allow(unused)]\n#[cfg(test)]\nmod tests {")),
                ("crates/effect-gate/src/gate.rs", gate_rs.replace("#[cfg(test)]\nmod tests {", "#[cfg(test)]\n#[allow(unused)]\nmod tests {")),
                ("crates/effect-gate/src/gate.rs", gate_rs.replace("#[cfg(test)]\nmod tests {", "#[cfg(not(test))]\nmod tests {")),
                (gate.GATE_MAIN, self.TREE[gate.GATE_MAIN] + "fn f() { let _ = effect_gate::fake_kernel::FakeKernel::default(); }\n"),
                ("crates/gate-tls/src/upstream.rs", "fn f() -> effect_gate::fake_kernel::FakeKernel { x() }\n")):
            self.refused(gate.check_observation, rel, text, message)
        self.refused(gate.check_observation, gate.EFFECT_GATE_LIB, self.TREE[gate.EFFECT_GATE_LIB] + "pub mod fake_kernel;\n",
                     "pub mod fake_kernel; exactly once")
        fake = self.TREE[gate.FAKE_KERNEL]
        for text, shape in ((fake + "pub use crate::observation::KernelReads;\n", "re-exports"),
                            (fake + "struct Wrapper(FakeKernel);\n", "a struct other than FakeKernel"),
                            (fake + "pub enum Kind { A }\n", "defines another type"),
                            (fake + "pub trait Hook {}\n", "defines another type"),
                            (fake + "impl Default for Unit {}\n", "an impl other than"),
                            (fake + "impl FakeKernel { fn again() {} }\n", "an impl other than"),
                            (fake + "fn f() { let _: Option<u8> = None; type Local = u8; }\n", "a type item other than"),
                            (fake.replace("    type Pidfd = Rc<(i32, u64)>;\n", ""), "exactly one type Pidfd"),
                            (fake.replace("    type Pidfd = Rc<(i32, u64)>;\n", "    type Pidfd = u8;\n    type Pidfd = u16;\n"),
                             "exactly one type Pidfd"),
                            (fake + "pub fn observer(k: FakeKernel) -> KernelObserver<FakeKernel> { x() }\n", "names an observer"),
                            (fake + "pub fn boxed(k: FakeKernel) -> Box<dyn WorkerObserver> { x() }\n", "names an observer")):
            self.refused(gate.check_observation, gate.FAKE_KERNEL, text, shape)
        self.refused(gate.check_observation, gate.FAKE_KERNEL, fake + "pub type Fake = FakeKernel;\n", "renames or aliases")

    def test_the_cgroup_root_open_is_the_linked_tripwire_s_one_fs_exception(self):
        # HE-003A3 (R96): the exact `KernelRoot::open_kernel_root("/sys/fs/cgroup")` once in linux_os.rs; another
        # `fs` word there, or the same expression in another file, still refuses.
        self.assertEqual(gate.check_linked_sources(self.base), 15)
        os_rs = self.TREE[gate.LINUX_OS]
        message = "names a std fs item other than its allowed ones"
        for rel, text in ((gate.LINUX_OS, os_rs + 'fn f() { let _ = KernelRoot::open_kernel_root("/sys/fs/cgroup"); }\n'),
                          (gate.LINUX_OS, os_rs + "fn f() { let _ = std::fs::read(p); }\n"),
                          (gate.LINUX_OS, os_rs + "// under /sys/fs\n"),
                          ("crates/effect-gate/src/substrate.rs",
                           'fn f() { let _ = KernelRoot::open_kernel_root("/sys/fs/cgroup"); }\n')):
            self.refused(gate.check_linked_sources, rel, text, message)

    def test_aliases_fields_and_state(self):
        os_rs = self.TREE[gate.LINUX_OS]
        for rel, text, message in (
                (gate.LINUX_OS, os_rs.replace("use gate_sys::openat::{read_bounded, FixedPath, KernelRoot};",
                                              "use gate_sys::openat::{read_bounded, FixedPath, KernelRoot as Root};"), "renames or aliases"),
                ("crates/effect-gate/src/substrate.rs", "type Roots = crate::linux_os::KernelRoots;\n", "renames or aliases"),
                ("crates/effect-gate/src/substrate.rs", "type FixedPath = u8;\n", "renames or aliases"),
                ("crates/gate-tls/src/upstream.rs", "use effect_gate::KernelObserver as O;\n", "renames or aliases"),
                (gate.LINUX_OS, os_rs.replace("    proc_root: KernelRoot,\n}", "    proc_root: KernelRoot,\n    cache: Vec<u8>,\n}"),
                 "not exactly two private KernelRoots"),
                (gate.LINUX_OS, os_rs.replace("    proc_root: KernelRoot,\n}", "}"), "not exactly two private KernelRoots"),
                (gate.LINUX_OS, os_rs.replace("    cgroup: KernelRoot,\n    proc_root", "    pub cgroup: KernelRoot,\n    proc_root"),
                 "not exactly two private KernelRoots"),
                (gate.LINUX_OS, os_rs.replace("    proc_root: KernelRoot,\n}", "    proc_root: Option<KernelRoot>,\n}"),
                 "not exactly two private KernelRoots"),
                (gate.LINUX_OS, os_rs + "static LAST: u8 = 0;\n", "names static"),
                (gate.LINUX_OS, os_rs + "thread_local! { static C: u8 = 0; }\n", "names (static|thread_local)"),
                (gate.LINUX_OS, os_rs + "fn f() { let _ = std::sync::OnceLock::<u8>::new(); }\n", "a lazy or once cell"),
                (gate.LINUX_OS, os_rs + "fn f() { let _ = std::cell::LazyCell::new(g); }\n", "a lazy or once cell")):
            self.refused(gate.check_observation, rel, text, message)


WIRING_MAIN = """#![forbid(unsafe_code)]
fn main() {}
fn serve(sealed: &Sealed, config: GateConfig) -> u8 {
    use effect_gate::linux_os::{KernelRoots, LinuxKernelReads, LinuxOs};
    use effect_gate::{KernelObserver, PolicyGate, Substrate};
    let Ok(os) = LinuxOs::with_net(sealed, &i05, &i07, net.clone(), config.writer_executable) else {
        return status::SOCKETS;
    };
    // the roots, before the stores
    let Ok(kernel) = KernelRoots::open_after_seal(sealed) else { return status::OBSERVER_ROOTS };
    let stores = match FileStores::open_bound(a, b, c, d, e, None) { Ok(stores) => stores, Err(_) => return status::STORES };
    let gate = match PolicyGate::create(&config.gate, &config.kinds, stores) { Ok(gate) => gate, Err(_) => return status::GATE };
    let gate = gate.with_observer(Box::new(KernelObserver::new(LinuxKernelReads::new(kernel))));
    let mut substrate = match Substrate::new(gate, os, i04, upstream, ExpectedPeers::r10(), config.lifetimes) {
        Ok(substrate) => substrate,
        Err(_) => return status::SUBSTRATE,
    };
    status::loop_exit(&substrate.run())
}
"""


class ObserverWiringTests(Tree):
    """HE-003A3 DESIGN section 5 (D1-3, D2-2): serve's two pinned statements, each exactly once and in order: the
    kernel roots after LinuxOs::with_net and before FileStores::open_bound, the Linux observer on the PolicyGate after
    it and before Substrate::new, which takes that gate."""

    TREE = {gate.GATE_MAIN: WIRING_MAIN}

    def test_the_wiring_passes(self):
        self.assertEqual(gate.check_observer_wiring(self.base), 2)
        self.write(gate.GATE_MAIN, WIRING_MAIN.replace("let Ok(kernel) = KernelRoots::open_after_seal(sealed) else",
                                                       "let Ok ( kernel ) = KernelRoots :: open_after_seal ( sealed )\n        else"))
        self.assertEqual(gate.check_observer_wiring(self.base), 2)

    def test_every_departure_refuses(self):
        roots = "    let Ok(kernel) = KernelRoots::open_after_seal(sealed) else { return status::OBSERVER_ROOTS };\n"
        observer = "    let gate = gate.with_observer(Box::new(KernelObserver::new(LinuxKernelReads::new(kernel))));\n"
        stores = "    let stores = match FileStores::open_bound("
        for text, message in (
                (WIRING_MAIN.replace(roots, ""), "exactly one"),
                (WIRING_MAIN.replace(observer, ""), "exactly one"),
                (WIRING_MAIN.replace(roots, "").replace("    let gate = match", roots + "    let gate = match"), "out of order"),
                (WIRING_MAIN.replace(observer, "").replace("    status::loop_exit", observer + "    status::loop_exit"),
                 "out of order"),
                (WIRING_MAIN.replace(roots, roots + roots), "exactly one"),
                (WIRING_MAIN.replace(observer, observer.replace("KernelObserver::new(LinuxKernelReads::new(kernel))", "Unobserved")),
                 "exactly one"),
                (WIRING_MAIN.replace(roots, roots.replace("OBSERVER_ROOTS", "SOCKETS")), "exactly one"),
                (WIRING_MAIN.replace(observer, observer + "    let gate = gate.with_observer(Box::new(Unobserved));\n"),
                 "with_observer outside"),
                (WIRING_MAIN.replace(observer, observer + "    let gate = wrap(gate);\n"), "rebinds gate"),
                (WIRING_MAIN.replace("Substrate::new(gate,", "Substrate::new(other,"), "exactly one"),
                (WIRING_MAIN + "fn extra() { let _ = KernelRoots::open_after_seal; }\n", "KernelRoots outside")):
            self.refused(gate.check_observer_wiring, gate.GATE_MAIN, text, message)


class ObserverWiringRebindTests(Tree):
    """HE-003A3 PR review round 1, R1-2 (carried to HE-004B1): serve binds gate in no other let pattern, assigns it nowhere,
    and after the observer's attach names it only in gate.apiserver_address() and Substrate::new(gate, ..)."""

    TREE = {gate.GATE_MAIN: WIRING_MAIN}
    OBSERVER = "    let gate = gate.with_observer(Box::new(KernelObserver::new(LinuxKernelReads::new(kernel))));\n"

    def after(self, extra):
        return WIRING_MAIN.replace(self.OBSERVER, self.OBSERVER + extra)

    def test_later_binding_forms_refuse(self):
        before = "    let gate = match PolicyGate"
        for text, message in (
                (self.after("    let (gate, _x) = (gate, 1);\n"), "binds gate in the pattern `let \\(gate, _x\\)`"),
                (self.after("    let mut gate = gate;\n"), "binds gate in the pattern `let mut gate`"),
                (self.after("    let Some(gate) = maybe(gate) else { return 1 };\n"), "binds gate in the pattern"),
                (self.after("    let Wrap { gate, .. } = wrap(gate);\n"), "binds gate in the pattern"),
                (self.after("    let ref gate = gate;\n"), "binds gate in the pattern"),
                (self.after("    gate = other_gate();\n"), "assigns to gate"),
                (self.after("    let gate = gate;\n"), "rebinds gate"),
                (self.after("    let gate: PolicyGate = gate;\n"), "rebinds gate"),
                (self.after("    let wrapped = Wrapper { gate };\n"), "names gate after the observer's attach"),
                (self.after("    drop(gate);\n"), "names gate after the observer's attach"),
                (self.after("    let _ = gate.into_policy();\n"), "names gate after the observer's attach"),
                (self.after("    let f = move || gate;\n"), "names gate after the observer's attach"),
                (WIRING_MAIN.replace(before, "    let (gate, _r) = (x, 1);\n" + before), "binds gate in the pattern"),
                (WIRING_MAIN.replace(before, "    gate = x;\n" + before), "assigns to gate")):
            self.refused(gate.check_observer_wiring, gate.GATE_MAIN, text, message)

    def test_the_allowed_uses_pass(self):
        # gate.apiserver_address() between the attach and Substrate::new(gate, ..); before the attach a match arm, a
        # comparison and a name holding the word are neither bindings nor assignments.
        text = self.after("    let upstream = UpstreamClient::new(connector, gate . apiserver_address ( ), effect);\n")
        text = text.replace("Ok(gate) => gate", "Ok(gate) if gate == gate => gate").replace(
            "    let stores", "    let gate_count = 1;\n    let stores")
        self.write(gate.GATE_MAIN, text)
        self.assertEqual(gate.check_observer_wiring(self.base), 2)


class ObservationPathTests(Tree):
    """HE-003A3 PR review round 1, R1-3 (carried to HE-004B1): the observers are pinned by path: observation.rs defines no
    module outside its strict test module, Unobserved and KernelObserver exactly once each at its top level, and its
    pinned impls at its top level."""

    TREE = OBSERVATION_TREE

    def test_a_nested_or_second_observer_type_refuses(self):
        observation = self.TREE[gate.OBSERVATION_RS]
        unobserved = "pub struct Unobserved;\nimpl WorkerObserver for Unobserved { fn observe() {} }\n"
        for text, message in (
                # The review's probe: the pinned impl moved into a nested module with its own Unobserved, re-exported.
                (observation.replace(unobserved, "pub struct Unobserved;\nmod inner {\n    pub struct Unobserved;\n"
                                     "    impl WorkerObserver for Unobserved { fn observe() {} }\n}\npub use inner::Unobserved;\n"),
                 "defines a module outside its strict test module"),
                (observation + "pub mod shadow;\n", "defines a module outside its strict test module"),
                (observation + "fn f() { struct KernelObserver<K> { k: K } }\n", "KernelObserver exactly once at its top level"),
                (observation + "pub type Unobserved = u8;\n", "Unobserved exactly once at its top level"),
                (observation.replace("pub struct Unobserved;\n", "fn f() { pub struct Unobserved; }\n"),
                 "Unobserved exactly once at its top level"),
                (observation.replace(unobserved, "pub struct Unobserved;\nfn hidden() {\n"
                                     "    impl WorkerObserver for Unobserved { fn observe() {} }\n}\n"),
                 "holds `impl WorkerObserver for Unobserved` below its top level"),
                (observation.replace("pub struct KernelObserver<K> { reads: K }\n", ""), "KernelObserver exactly once")):
            self.refused(gate.check_observation, gate.OBSERVATION_RS, text, message)
        # A strict in-source test module may hold its own helpers, even one named like an observer.
        self.write(gate.OBSERVATION_RS, observation + "#[cfg(test)]\nmod tests {\n    struct Unobserved;\n    fn t() {}\n}\n")
        self.assertEqual(gate.check_observation(self.base), 15)


class DebugKernelRootTests(Tree):
    """HE-003A3 (D2-7): KernelRoot joins the Debug hazards, so no struct holding it derives Debug."""

    TREE = DEBUG_TREE

    def test_a_struct_holding_a_kernel_root_derives_no_debug(self):
        for text in ("#[derive(Debug)]\npub struct KernelRoots { cgroup: KernelRoot, proc_root: KernelRoot }\n",
                     "#[derive(Debug)]\npub struct LinuxKernelReads { cgroup: Option<KernelRoot> }\n"):
            self.refused(gate.check_debug_derives, "crates/effect-gate/src/linux_os.rs", text, "mention KernelRoot")


class PreMainAndPrintTests(Tree):
    """HE-003D DESIGN sections 4 and 5 (D1-3, D1-10, D2-6): no code before main and nothing printed, in every linked
    crate and the binary (read without comments)."""

    TREE = LINKED_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_pre_main(self.base), 11)
        self.assertEqual(gate.check_prints(self.base), 11)

    def test_code_before_main_refuses(self):
        for rel in (gate.GATE_MAIN, "crates/effect-gate/src/file_store.rs", "crates/gate-tls/src/lib.rs"):
            for text, name in (("#[unsafe(link_section = \".init_array\")]\nstatic I: fn() = f;", "link_section"),
                               ("#[used]\nstatic K: u8 = 0;", "#\\[used\\]"), ("# [ used ]\nstatic K: u8 = 0;", "#\\[used\\]"),
                               ("const S: &str = init_array;", "init_array"), ("#[unsafe(no_mangle)]\nfn f() {}", "no_mangle"),
                               ("#[unsafe(export_name = \"main\")]\nfn f() {}", "export_name")):
                self.refused(gate.check_pre_main, rel, LINKED_TREE[rel] + text + "\n", name + " .code before main")
        self.write(gate.GATE_MAIN, LINKED_TREE[gate.GATE_MAIN] + "// no link_section, #[used] or no_mangle here\n")
        self.assertEqual(gate.check_pre_main(self.base), 11)

    def test_printing_refuses(self):
        for rel in (gate.GATE_MAIN, "crates/gate-sys/src/openat.rs", "crates/i05-protocol/src/json.rs"):
            for text, name in (("fn f() { print!(\"x\"); }", "print!"), ("fn f() { println !(\"x\"); }", "println!"),
                               ("fn f() { eprint!(\"x\"); }", "eprint!"), ("fn f() { eprintln!(\"x\"); }", "eprintln!"),
                               ("fn f() { dbg!(x); }", "dbg!"), ("fn f() { let o = std::io::stdout; }", "stdout or stderr"),
                               ("fn f() { let e = std::io::stderr; e(); }", "stdout or stderr"),
                               ("fn f(_: std::io::Stderr) {}", "stdout or stderr")):
                self.refused(gate.check_prints, rel, LINKED_TREE[rel] + text + "\n", re.escape(name) + " .print rule")
        self.write(gate.GATE_MAIN, LINKED_TREE[gate.GATE_MAIN] + "// a panic message may reach stderr\n"
                   "const S: &str = \"stdout\";\nfn f() { let _ = format!(\"x\"); let reprint = 1; }\n")
        self.assertEqual(gate.check_prints(self.base), 11)


class LinkedBinaryTests(Tree):
    """HE-003D DESIGN section 5 (O4): the binary's crate is linked, with its crate-root attribute and exactly one exit
    import, removed once before the refused-path scan."""

    TREE = LINKED_TREE

    def test_the_exit_import_is_allowed_once_in_main(self):
        main = gate.GATE_MAIN
        good = LINKED_TREE[main] + "use std::process::ExitCode;\nfn run() -> ExitCode { ExitCode::from(2) }\n"
        self.write(main, good)
        self.assertEqual(gate.check_linked_sources(self.base), 11)
        self.write(main, LINKED_TREE[main] + "use std :: process ::\n    ExitCode ;\n")
        self.assertEqual(gate.check_linked_sources(self.base), 11)
        for text in (good + "use std::process::ExitCode;\n", good + "fn f() { std::process::exit(1); }\n",
                     good + "use std::process::Command;\n", good + "fn f() { let _ = std::env::args_os(); }\n",
                     LINKED_TREE[main] + "use std::process;\n", LINKED_TREE[main] + "use std::process::{ExitCode};\n"):
            self.refused(gate.check_linked_sources, main, text, "linked-source tripwire")
        self.refused(gate.check_linked_sources, "crates/effect-gate/src/file_store.rs",
                     LINKED_TREE["crates/effect-gate/src/file_store.rs"] + "use std::process::ExitCode;\n", "std::process")
        self.refused(gate.check_linked_sources, main, good.replace("#![forbid(unsafe_code)]\n", ""), "lacks #!\\[forbid")
        # The binary is a linked crate for the Debug, foreign-item and post-seal rules too.
        self.refused(gate.check_debug_derives, main, LINKED_TREE[main] + "#[derive(Debug)]\nstruct S { f: File }\n", "Debug check")
        self.refused(gate.check_foreign_items, main, LINKED_TREE[main] + "unsafe extern \"C\" { fn system(c: *const u8) -> i32; }\n",
                     "declares the foreign items")
        self.refused(gate.check_post_seal_sources, main, LINKED_TREE[main] + "fn f(x: &File) { x.set_len(0); }\n", "post-seal")


class SignerKeyTests(Tree):
    """HE-003D DESIGN section 3.1 (Q-HE3D-7 (d)): the compiled-in key file is 0 or 32 bytes."""

    def test_zero_or_thirty_two_bytes(self):
        path = self.base / gate.SIGNER_KEY
        with self.assertRaisesRegex(gate.GateError, "config-signer.pub is missing"):
            gate.check_signer_key(self.base)
        path.parent.mkdir(parents=True)
        for size in (0, 32):
            path.write_bytes(b"\x42" * size)
            self.assertEqual(gate.check_signer_key(self.base), size)
        for size in (1, 31, 33, 64):
            path.write_bytes(b"\x42" * size)
            with self.assertRaisesRegex(gate.GateError, "holds %d bytes, not 0 or 32" % size):
                gate.check_signer_key(self.base)


# Symbol names as the composed planeon-gate holds them (v0 mangling, and legacy for gate-tls), and ring's C core.
CRATE_NAMES = {"_RNvNtCskpwDPCNkCDi_8gate_tls13signed_config9read_file",
               "_RINvCsajaTMy3G2oH_6subtle9black_boxhECsjLitWopGBcO_6rustls",
               "_ZN8gate_tls11credentials4fill17h0123456789abcdefE",
               "ring_core_0_17_14__CRYPTO_memcmp"}


class GateSymbolTests(unittest.TestCase):
    """HE-003D DESIGN section 5 (O3, C8): planeon-gate's symbol table has no membarrier, and every musl wrapper of a
    killed call it holds is in the reviewed list; owner decision Q-HE3D-B1 (a): it holds gate-tls, rustls and ring
    symbols (the composed gate)."""

    def test_the_inventory(self):
        present = set(gate.WRAPPER_JUSTIFICATIONS) | {"read", "openat", "socket", "epoll_pwait", "main"} | CRATE_NAMES
        self.assertEqual(gate.check_gate_symbols(present), sorted(gate.WRAPPER_JUSTIFICATIONS))
        self.assertEqual(gate.check_gate_symbols({"read", "__membarrier_init"} | CRATE_NAMES), [])
        self.assertTrue(set(gate.WRAPPER_JUSTIFICATIONS) <= set(gate.KILLED_WRAPPERS))
        self.assertEqual(len(gate.KILLED_WRAPPERS), len(set(gate.KILLED_WRAPPERS)))
        for name in gate.MEMBARRIER:
            with self.assertRaisesRegex(gate.GateError, "links .*membarrier.* .membarrier check"):
                gate.check_gate_symbols({"read", name} | CRATE_NAMES)
        for name in ("ioctl", "execve", "socketpair", "uname", "fork", "accept", "readdir"):
            with self.assertRaisesRegex(gate.GateError, "without a reviewed justification"):
                gate.check_gate_symbols(present | {name})

    def test_readlinkat_left_the_killed_wrappers(self):
        # HE-003A2 (DESIGN section 2, D1-13): re-derived over contracts/seccomp-v4/, readlinkat is argument-filtered on
        # both targets (allowed with a non-negative dirfd), so the gate may hold musl's wrapper; readlink stays (x86_64
        # kills its call 89 unconditionally), and so does realpath, which calls it.
        self.assertNotIn("readlinkat", gate.KILLED_WRAPPERS)
        self.assertEqual(len(gate.KILLED_WRAPPERS), 98)
        self.assertTrue({"readlink", "realpath", "getcwd"} <= set(gate.KILLED_WRAPPERS))
        present = set(gate.WRAPPER_JUSTIFICATIONS) | {"readlinkat"} | CRATE_NAMES
        self.assertEqual(gate.check_gate_symbols(present), sorted(gate.WRAPPER_JUSTIFICATIONS))

    def test_the_composed_gate_is_linked(self):
        # Each crate missing refuses; a crate whose name only starts like gate-tls's or rustls's does not count.
        for crate, missing in (("gate_tls", {"_RNvNtCskpwDPCNkCDi_8gate_tls13signed_config9read_file",
                                             "_ZN8gate_tls11credentials4fill17h0123456789abcdefE"}),
                               ("rustls", {"_RINvCsajaTMy3G2oH_6subtle9black_boxhECsjLitWopGBcO_6rustls"}),
                               ("ring", {"ring_core_0_17_14__CRYPTO_memcmp"})):
            with self.assertRaisesRegex(gate.GateError, "holds no %s symbol: the composed gate is not linked" % crate):
                gate.check_gate_symbols((CRATE_NAMES - missing) | {"read"})
        lookalikes = {"_RNvCs1QWHNFWaGd2_16rustls_pki_types5parse", "_RNvCsx_9gate_tlsx4f", "_ZN10gate_tls_x1fE",
                      "ring_core_0_17_13__CRYPTO_memcmp", "rustls", "gate_tls"}
        for crate in ("gate_tls", "rustls", "ring"):
            with self.assertRaisesRegex(gate.GateError, "holds no"):
                gate.check_gate_symbols({name for name in CRATE_NAMES if crate not in name} | lookalikes)
        self.assertEqual(gate.check_gate_symbols(CRATE_NAMES), [])


STORE_MAIN = ("#![forbid(unsafe_code)]\nuse effect_gate::{FileStores, PolicyGate};\n"
              "fn serve() {\n    let stores = FileStores::open_bound(a, b, c, d, &probe, None);\n"
              "    let (gate, _) = PolicyGate::open(&x, &k, stores);\n    let g = PolicyGate::create(&x, &k, s);\n}\n"
              "// FileStores::open( in a comment is not code\n")


class StoreOpeningTests(Tree):
    """HE-003D departure A1 (accepted): the binary opens its stores only with FileStores::open_bound."""

    TREE = {gate.GATE_MAIN: STORE_MAIN}

    def test_the_binding_opening_passes(self):
        self.assertEqual(gate.check_gate_stores(self.base), 1)
        self.write(gate.GATE_MAIN, STORE_MAIN.replace("FileStores::open_bound(", "FileStores :: open_bound ("))
        self.assertEqual(gate.check_gate_stores(self.base), 1)

    def test_other_openings_refuse(self):
        main = gate.GATE_MAIN
        for text in (STORE_MAIN + "fn f() { let _ = FileStores::open(a, b, c, &p, None); }\n",
                     STORE_MAIN + "fn f() { let _ = effect_gate::FileStores :: open (a, b, c, &p, None); }\n",
                     STORE_MAIN + "fn f() { let o = FileStores::open; }\n",
                     STORE_MAIN + "fn f() { let _ = <FileStores>::open(a); }\n",
                     STORE_MAIN + "fn f() { let _ = <effect_gate::PolicyGate>::open(a); }\n",
                     STORE_MAIN + "fn f() { let _ = Stores::open(a); }\n",
                     STORE_MAIN + "fn f() { let _ = file_store::FileStores::open(a); }\n"):
            self.refused(gate.check_gate_stores, main, text, "names ::open other than PolicyGate::open")
        for text in (STORE_MAIN + "use effect_gate::FileStores as PolicyGate;\n",
                     STORE_MAIN + "use effect_gate::{FileStores as S};\n",
                     STORE_MAIN + "use effect_gate::file_store::FileStores as PolicyGate;\n",
                     STORE_MAIN + "type Stores = effect_gate::FileStores;\n",
                     STORE_MAIN + "type PolicyGate = effect_gate::FileStores;\n"):
            self.refused(gate.check_gate_stores, main, text, "renames or aliases FileStores or PolicyGate")
        for text, count in ((STORE_MAIN.replace("FileStores::open_bound(a, b, c, d, &probe, None)", "x()"), 0),
                            (STORE_MAIN + "fn g() { let _ = FileStores::open_bound(a, b, c, d, &p, None); }\n", 2)):
            self.refused(gate.check_gate_stores, main, text, "calls FileStores::open_bound %d times" % count)
        self.write("crates/gate/src/other.rs", "fn f() { let _ = FileStores::open(a); }\n")
        with self.assertRaisesRegex(gate.GateError, "other.rs names ::open"):
            gate.check_gate_stores(self.base)

    def test_no_linked_source_calls_the_unbound_opening(self):
        # PR review round 1, R1-4: a library wrapper (P10) cannot hand the binary an unbound opening.
        store = "crates/effect-gate/src/file_store.rs"
        definition = ("impl FileStores {\n    pub fn open(j: &str) -> Result<FileStores, OpenError> { FileStores::opening(j, None) }\n"
                      "    pub fn open_bound(j: &str, d: &str) -> Result<FileStores, OpenError> { FileStores::opening(j, Some(d)) }\n}\n"
                      "/// [`FileStores::open`] in a comment.\n")
        self.write(store, definition)
        self.assertEqual(gate.check_gate_stores(self.base), 1)
        for rel, text in ((store, definition + "pub fn unbound(j: &str) -> Result<FileStores, OpenError> { FileStores::open(j) }\n"),
                          (store, definition.replace("FileStores::opening(j, Some(d))", "Self::open(j)")),
                          (store, definition + "fn f() { let _ = <FileStores>::open; }\n"),
                          ("crates/effect-gate/src/policy_gate.rs", "fn f() { let _ = crate::file_store::FileStores :: open(j); }\n"),
                          ("crates/gate-tls/src/credentials.rs", "fn f() { let _ = effect_gate::FileStores::open(j); }\n")):
            self.refused(gate.check_gate_stores, rel, text, "calls FileStores::open, the unbound opening")
        # The tests may open unbound stores.
        self.write("crates/effect-gate/tests/stores.rs", "fn f() { let _ = FileStores::open(j); }\n")
        self.assertEqual(gate.check_gate_stores(self.base), 1)


READ_LINK_OPENAT = ("#![allow(unsafe_code)]\n/// [`Dir::read_link`]: one link by name, the one readlinkat call.\n"
                    "pub fn read_link(&self, name: &str, buffer: &mut [u8]) -> io::Result<usize> {\n"
                    "    let count = unsafe { readlinkat(self.fd(), name.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };\n"
                    "    x(count)\n}\n")
READ_LINK_CHANNEL = ("#![allow(unsafe_code)]\n/// Through [`Dir::read_link`].\n"
                     "pub fn exe(&self, buffer: &mut [u8]) -> io::Result<usize> {\n    self.dir.read_link(\"exe\", buffer)\n}\n")


class OpenatReadLinkTests(Tree):
    """HE-003A2 DESIGN section 3 (Q-A2-2 (a), D1-6, D1-9, D2-2): the openat module declares exactly openat and readlinkat
    (readlinkat refused in any other linked source), and the word read_link occurs exactly twice in the linked sources:
    its definition in openat.rs and the one call read_link("exe", ..) in channel.rs."""

    TREE = {**FOREIGN_TREE, gate.OPENAT: FOREIGN_TREE[gate.OPENAT] + READ_LINK_OPENAT.split("\n", 1)[1],
            gate.CHANNEL: FOREIGN_TREE[gate.CHANNEL] + READ_LINK_CHANNEL.split("\n", 1)[1]}

    def test_the_openat_module_declares_exactly_its_two_symbols(self):
        self.assertEqual(gate.FOREIGN_ITEMS[gate.OPENAT], {"openat", "readlinkat"})
        self.assertEqual(gate.check_foreign_items(self.base), 15)
        message = "openat.rs declares the foreign items .* not exactly"
        openat = self.TREE[gate.OPENAT]
        readlinkat = "    fn readlinkat(dirfd: c_int, path: *const c_char, buffer: *mut c_char, size: usize) -> isize;\n"
        self.assertIn(readlinkat, openat)
        for text in (openat.replace(readlinkat, ""), openat.replace("fn readlinkat(", "fn readlink("),
                     openat + "unsafe extern \"C\" { fn syscall(number: c_long, ...) -> c_long; }\n",
                     openat + "unsafe extern \"C\" { fn realpath(p: *const c_char, r: *mut c_char) -> *mut c_char; }\n"):
            self.refused(gate.check_foreign_items, gate.OPENAT, text, message)
        # readlinkat anywhere else refuses: another gate-sys module, effect-gate, gate-tls, the binary.
        for rel in ("crates/gate-sys/src/peer_wire.rs", "crates/gate-sys/src/seal.rs", "crates/effect-gate/src/linux_os.rs",
                    "crates/gate-tls/src/credentials.rs", gate.GATE_MAIN):
            self.refused(gate.check_foreign_items, rel, self.TREE.get(rel, "") + "unsafe extern \"C\" {\n" + readlinkat + "}\n",
                         "declares the foreign items .*readlinkat.* not exactly")

    def test_read_link_is_defined_once_and_called_once_with_exe(self):
        self.assertEqual(gate.check_read_link(self.base), 2)
        channel, openat = self.TREE[gate.CHANNEL], self.TREE[gate.OPENAT]
        for rel, text, message in (
                # A second call, in channel.rs or anywhere else.
                (gate.CHANNEL, channel + "pub fn cwd(&self, b: &mut [u8]) -> io::Result<usize> { self.dir.read_link(\"exe\", b) }\n",
                 "channel.rs does not name read_link exactly once"),
                ("crates/effect-gate/src/linux_os.rs", "fn f(d: &Dir, b: &mut [u8]) { let _ = d.read_link(\"exe\", b); }\n",
                 "linux_os.rs names read_link"),
                ("crates/gate-sys/src/peer_wire.rs", "fn f(d: &Dir, b: &mut [u8]) { let _ = d.read_link(\"cwd\", b); }\n",
                 "peer_wire.rs names read_link"),
                ("crates/gate-tls/src/signed_config.rs", "fn f(d: &Dir, b: &mut [u8]) { let _ = Dir::read_link(d, \"exe\", b); }\n",
                 "signed_config.rs names read_link"),
                (gate.GATE_MAIN, "#![forbid(unsafe_code)]\nfn main() { let _ = gate_sys::Dir::read_link; }\n", "main.rs names read_link"),
                # Another link name, a non-literal name, a reference without a call (a fn item), a call by path.
                (gate.CHANNEL, channel.replace("read_link(\"exe\", buffer)", "read_link(\"cwd\", buffer)"),
                 "as the call read_link"),
                (gate.CHANNEL, channel.replace("read_link(\"exe\", buffer)", "read_link(NAME, buffer)"), "as the call read_link"),
                (gate.CHANNEL, channel.replace("self.dir.read_link(\"exe\", buffer)", "{ let f = Dir::read_link; f(&self.dir, \"exe\", buffer) }"),
                 "as the call read_link"),
                (gate.CHANNEL, channel.replace("self.dir.read_link(\"exe\", buffer)", "x(\"exe\", buffer)"), "as the call read_link"),
                # The definition missing, renamed through a use, or defined twice.
                (gate.OPENAT, openat.replace("pub fn read_link(", "pub fn link_of("), "as its definition"),
                (gate.OPENAT, openat + "pub fn other() { let _ = Dir::read_link; }\n", "as its definition"),
                ("crates/effect-gate/src/substrate.rs", "use gate_sys::Dir;\nfn f() { let _ = <Dir>::read_link; }\n",
                 "substrate.rs names read_link"),
                ("crates/effect-gate/src/file_store.rs", "fn f() { let _ = std::fs::read_link(p); }\n", "file_store.rs names read_link")):
            self.refused(gate.check_read_link, rel, text, message)
        # Comments are not code, and the tests may call it.
        self.write("crates/effect-gate/src/linux_os.rs", "// read_link(\"exe\", b) through ProcDir::exe\n/* Dir::read_link */\n")
        self.write("crates/gate-sys/tests/read_link.rs", "fn f(d: &Dir, b: &mut [u8]) { let _ = d.read_link(\"cwd\", b); }\n")
        self.write("crates/effect-gate/tests/writer_exe.rs", "fn f(d: &Dir, b: &mut [u8]) { let _ = d.read_link(\"x\", b); }\n")
        self.assertEqual(gate.check_read_link(self.base), 2)
        # A literal holding the word counts (literals are kept), so it refuses outside the two places.
        self.refused(gate.check_read_link, "crates/i05-protocol/src/json.rs", "const S: &str = \"read_link\";\n",
                     "json.rs names read_link")

    def test_readlinkat_occurs_twice_in_openat_as_declaration_and_one_call(self):
        # PR review round 1, R1-3: no second wrapper of readlinkat under another name.
        openat = self.TREE[gate.OPENAT]
        call = "    let count = unsafe { readlinkat(self.fd(), name.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };\n"
        self.assertIn(call, openat)
        message = "openat.rs does not name readlinkat exactly twice"
        for text in (
                openat + "pub fn link_text(&self, name: &str, b: &mut [u8]) -> isize {\n"
                         "    unsafe { readlinkat(self.fd(), name.as_ptr(), b.as_mut_ptr().cast(), b.len()) }\n}\n",
                openat.replace(call, "    let count = x(name, buffer);\n")
                + "pub fn sub(&self) -> isize { unsafe { readlinkat(0, p(), q(), 1) } }\n",
                openat.replace(call, "    let count = x(name, buffer);\n"),
                openat.replace("    fn readlinkat(", "    fn readlinkat_(") + "fn f() { let _ = readlinkat; }\n",
                openat + "const NAME: &str = \"readlinkat\";\n",
                openat.replace(call, "    let f = readlinkat;\n    let count = unsafe { f(1, p(), q(), 1) };\n"),
                openat.replace(call, call + call)):
            self.refused(gate.check_read_link, gate.OPENAT, text, message)
        for rel in ("crates/gate-sys/src/peer_wire.rs", "crates/effect-gate/src/linux_os.rs", gate.GATE_MAIN):
            self.refused(gate.check_read_link, rel, self.TREE.get(rel, "") + "fn f() { let _ = readlinkat; }\n",
                         "names readlinkat; only openat.rs")
        # Comments are not code.
        self.write("crates/effect-gate/src/linux_os.rs", "// gate-sys's readlinkat on the kept directory\n")
        self.write(gate.OPENAT, openat + "// readlinkat(AT_FDCWD, ..) is never called\n")
        self.assertEqual(gate.check_read_link(self.base), 2)


GOOD_OBSERVER_MAIN = """//! The observer binary (a comment may name std::thread, println! and NetTable).
#![forbid(unsafe_code)]

use std::process::ExitCode;

use planeon_observer::status;
#[cfg(target_os = "linux")]
use planeon_observer::{seal_stage1, seal_stage2, Sealed};

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let stage1 = match seal_stage1() {
        Ok(stage1) => stage1,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    let sealed = match seal_stage2(stage1) {
        Ok(sealed) => sealed,
        Err(error) => return ExitCode::from(status::seal(&error)),
    };
    ExitCode::from(serve(&sealed))
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    ExitCode::from(status::NOT_LINUX)
}

#[cfg(target_os = "linux")]
fn serve(sealed: &Sealed) -> u8 {
    use planeon_observer::capture::CaptureEngine;
    use planeon_observer::capture_schema::CaptureSchema;
    use planeon_observer::config::{self, ObserverConfig};
    use planeon_observer::credentials;
    use planeon_observer::enrolled::{self, Enrolled};
    use planeon_observer::linux_capture::LinuxCapture;
    use planeon_observer::linux_net::LinuxWire;
    use planeon_observer::observe;
    use planeon_observer::signed_config;
    use planeon_observer::snapshot::Closure;
    use planeon_observer::tls::{client_config, time_provider};
    use planeon_observer::utc;

    let document = match signed_config::load() {
        Ok(document) => document,
        Err(error) => return status::config_load(&error),
    };
    let Ok((config, record_ref)) = ObserverConfig::parse_with_record(&document) else { return status::CONFIG_CHECK };
    drop(document);
    if let Err(error) = config::check_lifetime(&config, utc::wall_seconds()) {
        return status::lifetime(&error);
    }
    let Ok((serving_ca, identity)) = credentials::observer_inputs(&config.credentials) else { return status::CREDENTIALS };
    let Ok(tls) = client_config(identity, serving_ca, time_provider()) else { return status::TLS_SETUP };
    let Ok((schema, record_schema)) = CaptureSchema::embedded() else { return status::CAPTURE_SCHEMA };
    let record = match enrolled::load_record(&record_ref) {
        Ok(record) => record,
        Err(error) => return status::capture_setup(&error),
    };
    let enrolled = match Enrolled::new(record, &record_schema, utc::wall_seconds()) {
        Ok(enrolled) => enrolled,
        Err(error) => return status::capture_setup(&error),
    };
    drop(record_schema);
    let Ok(wire) = LinuxWire::new(sealed) else { return status::SOCKETS };
    let capture = match LinuxCapture::new(sealed) {
        Ok(capture) => capture,
        Err(error) => return status::capture_setup(&error),
    };
    let Ok(closure) = Closure::embedded() else { return status::CLOSURE };
    let captures = Box::new(CaptureEngine::new(capture, enrolled, schema));
    status::observation(&observe::run(wire, config, tls, closure, captures))
}
"""
OBSERVER_SEAL = "crates/observer/src/seal.rs"
OBSERVER_TREE = {**FOREIGN_TREE, gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN,
                 "crates/effect-gate/src/linux_os.rs": SOCKET_TREE["crates/effect-gate/src/linux_os.rs"],
                 "crates/effect-gate/src/linux_net.rs": SOCKET_TREE["crates/effect-gate/src/linux_net.rs"],
                 # HE-004C (G4): the observer's socket module.
                 gate.OBSERVER_LINUX_NET: OBSERVER_LINUX_NET_TEXT,
                 gate.OBSERVER_LIB: "#![forbid(unsafe_code)]\npub mod seal;\npub mod status;\n",
                 OBSERVER_SEAL: "use std::io;\npub fn seal_stage1() -> io::Result<()> { Ok(()) }\n",
                 "crates/observer/src/status.rs": "pub const NOT_YET_SERVING: u8 = 10;\n",
                 # gate-sys's own definitions of what the observer may not call stay allowed in gate-sys (D2-2).
                 "crates/gate-sys/src/openat.rs": FOREIGN_TREE["crates/gate-sys/src/openat.rs"]
                                                  + "pub enum FileMode { Existing }\npub fn file() {}\n"
                                                  + "pub fn sync(h: &File) { let _ = h.sync_all(); }\n"}


class ObserverSealOrderTests(Tree):
    """HE-004A DESIGN-A sections 5 and 6 (D2-3): the seal-order grammar, parameterised, over the observer's main.rs: stage
    1 first and exact, nothing between the stages, the exact stage-2 statement, the pinned tail closing main, its own
    imports and functions; the gate's rules unchanged."""

    TREE = OBSERVER_TREE

    def test_the_observer_main_passes(self):
        self.assertEqual(gate.check_seal_order(self.base, gate.OBSERVER_SEAL_SITE),
                         "Err, ExitCode::from, Ok, status::seal (and the tuple-variant patterns none)")
        self.assertEqual(gate.OBSERVER_SEAL_SITE["before"], ())
        self.assertEqual(set(gate.OBSERVER_SEAL_CALLS), set(gate.SEAL_CALLS) - {"signed_config::load", "GateConfig::parse"})
        # Whitespace and comments inside the statements are tolerated.
        spaced = (GOOD_OBSERVER_MAIN.replace("    let sealed = match seal_stage2(stage1) {",
                                             "    let sealed = match /* two */ seal_stage2 ( stage1 )\n    {")
                  .replace("    ExitCode::from(serve(&sealed))\n", "    ExitCode :: from ( serve ( & sealed ) ) // end\n"))
        self.write(gate.OBSERVER_MAIN, spaced)
        self.assertIn("status::seal", gate.check_seal_order(self.base, gate.OBSERVER_SEAL_SITE))

    def test_nothing_runs_between_the_stages(self):
        before = "    let sealed = match seal_stage2(stage1) {"
        for extra in ("    let _x = 1;\n", "    let _ = early();\n", "    let _ = Ok::<u8, u8>(1);\n",
                      "    let _e = ExitCode::from(status::NOT_LINUX);\n", "    {}\n"):
            self.refused(lambda base: gate.check_seal_order(base, gate.OBSERVER_SEAL_SITE), gate.OBSERVER_MAIN,
                         GOOD_OBSERVER_MAIN.replace(before, extra + before),
                         "runs something between the seal's stages|seal-order grammar")
        # The same insertions in a statement-free form also refuse; the gate's site still allows its configuration.
        self.refused(lambda base: gate.check_seal_order(base, gate.OBSERVER_SEAL_SITE), gate.OBSERVER_MAIN,
                     GOOD_OBSERVER_MAIN.replace(before, "    let _d = signed_config::load();\n" + before),
                     "seal-order grammar")

    def test_the_first_stage_is_exact(self):
        ok_arm = "        Ok(stage1) => stage1,\n        Err(error) => return ExitCode::from(status::seal(&error)),\n    };\n    let sealed"
        self.assertEqual(GOOD_OBSERVER_MAIN.count(ok_arm), 1)
        for new in ("        Ok(stage1) => { let _ = early(); stage1 }\n        Err(error) => return ExitCode::from(status::seal(&error)),\n    };\n    let sealed",
                    "        Ok(stage1) => other,\n        Err(error) => return ExitCode::from(status::seal(&error)),\n    };\n    let sealed",
                    "        Ok(stage1) => stage1,\n        Err(error) => return ExitCode::from(status::NOT_LINUX),\n    };\n    let sealed",
                    "        Ok(stage1) => stage1,\n        Err(error) => return ExitCode::from(status::seal(&other)),\n    };\n    let sealed",
                    "        Ok(stage1) => stage1,\n        _ => return ExitCode::from(1),\n    };\n    let sealed"):
            self.refused(lambda base: gate.check_seal_order(base, gate.OBSERVER_SEAL_SITE), gate.OBSERVER_MAIN,
                         GOOD_OBSERVER_MAIN.replace(ok_arm, new), "first stage is not exactly|seal-order grammar")

    def test_the_tail_is_pinned(self):
        # HE-004C (G5): the tail is exactly `ExitCode::from(serve(&<the stage-2 binding>))`, closing main; HE-004A's
        # not-yet-serving tail now refuses too.
        tail = "    ExitCode::from(serve(&sealed))\n}\n\n#[cfg(not"
        self.assertEqual(GOOD_OBSERVER_MAIN.count(tail), 1)
        for new in ("    ExitCode::from(0)\n}\n\n#[cfg(not", "    ExitCode::SUCCESS\n}\n\n#[cfg(not",
                    "    let _ = serve(&sealed);\n    ExitCode::from(serve(&sealed))\n}\n\n#[cfg(not",
                    "    ExitCode::from(serve(&sealed));\n}\n\n#[cfg(not",
                    "    return ExitCode::from(serve(&sealed));\n}\n\n#[cfg(not",
                    "    {\n        ExitCode::from(serve(&sealed))\n    }\n}\n\n#[cfg(not",
                    "    loop {}\n}\n\n#[cfg(not",
                    "    ExitCode::from(status::NOT_YET_SERVING)\n}\n\n#[cfg(not",
                    "    ExitCode::from(serve(&stage1))\n}\n\n#[cfg(not",
                    "    ExitCode::from(serve(&sealed, 1))\n}\n\n#[cfg(not",
                    "    ExitCode::from(serve(sealed))\n}\n\n#[cfg(not"):
            self.refused(lambda base: gate.check_seal_order(base, gate.OBSERVER_SEAL_SITE), gate.OBSERVER_MAIN,
                         GOOD_OBSERVER_MAIN.replace(tail, new), "seal-order grammar")

    def test_the_observer_imports_items_and_stage_two(self):
        site = lambda base: gate.check_seal_order(base, gate.OBSERVER_SEAL_SITE)
        uses = "#[cfg(target_os = \"linux\")]\nuse planeon_observer::{seal_stage1, seal_stage2, Sealed};\n"
        for text, message in (
                (GOOD_OBSERVER_MAIN.replace(uses, uses + "use planeon_observer::Sealed;\n"), "pinned set"),
                (GOOD_OBSERVER_MAIN.replace(uses, uses + "use effect_gate::status as gate_status;\n"), "renames an import"),
                (GOOD_OBSERVER_MAIN.replace(uses, "use planeon_observer::*;\n"), "imports a glob"),
                # HE-004C (G5): serve's in-body imports are pinned too; fn serve is the third function, and only it.
                (GOOD_OBSERVER_MAIN.replace("    use planeon_observer::utc;\n", ""), "pinned set"),
                (GOOD_OBSERVER_MAIN.replace("    use planeon_observer::utc;\n", "    use planeon_observer::utc;\n"
                                            "    use planeon_observer::client;\n"), "pinned set"),
                (GOOD_OBSERVER_MAIN + "fn other() {}\n", "functions other than fn main"),
                (GOOD_OBSERVER_MAIN + "fn serve() {}\n", "functions other than fn main"),
                (GOOD_OBSERVER_MAIN + "mod seal {}\n", "defines a mod item"),
                (GOOD_OBSERVER_MAIN + "const C: u8 = 0;\n", "defines a const item"),
                (GOOD_OBSERVER_MAIN.replace("seal_stage2(stage1)", "seal_stage2(other)"), "argument or arms"),
                (GOOD_OBSERVER_MAIN.replace("        Ok(sealed) => sealed,", "        Ok(sealed) => { early(); sealed }"),
                 "second stage is not exactly"),
                (GOOD_OBSERVER_MAIN.replace("#![forbid(unsafe_code)]", "#![forbid(unsafe_code)]\n#![allow(dead_code)]"),
                 "attribute"),
                (GOOD_MAIN, "seal-order grammar")):   # the gate's main is not the observer's
            self.refused(site, gate.OBSERVER_MAIN, text, message)
        (self.base / gate.OBSERVER_MAIN).unlink()
        with self.assertRaisesRegex(gate.GateError, "crates/observer/src/main.rs is missing"):
            gate.check_seal_order(self.base, gate.OBSERVER_SEAL_SITE)

    def test_the_gate_site_is_unchanged(self):
        # The default site is the gate's: its configuration calls and serve stay allowed there, and the observer's main
        # would not satisfy it.
        self.write(gate.GATE_MAIN, GOOD_MAIN)
        self.write(gate.GATE_CONFIG, GOOD_GATE_CONFIG)
        self.write(gate.SIGNED_CONFIG, GOOD_SIGNED_CONFIG)
        self.assertIn("signed_config::load", gate.check_seal_order(self.base))
        self.assertEqual(gate.check_seal_order(self.base), gate.check_seal_order(self.base, gate.GATE_SEAL_SITE))
        self.refused(gate.check_seal_order, gate.GATE_MAIN, GOOD_OBSERVER_MAIN.replace("planeon_observer", "effect_gate"),
                     "seal-order grammar")


class ObserverLinkedCrateTests(Tree):
    """HE-004A DESIGN-A section 6 (D2-4): crates/observer joins every linked-crate scan, its roots forbid unsafe_code,
    and main.rs has the one exit import; its post-seal list (crates/observer only, D2-2)."""

    TREE = OBSERVER_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.SCANNED_CRATES, gate.LINKED_CRATES + ("crates/observer", "crates/observer-sys"))
        self.assertEqual(gate.OBSERVER_LINKED_CRATES, ("crates/observer", "crates/gate-sys", "crates/i05-protocol",
                                                       "crates/observer-sys"))
        # 13 sources of the gate's linked crates, 5 of the observer's (HE-004C: its socket module) and 2 of observer-sys's
        # (HE-004D1).
        for check in (gate.check_linked_sources, gate.check_foreign_items, gate.check_debug_derives, gate.check_socket_modules,
                      gate.check_macros, gate.check_pre_main, gate.check_prints):
            self.assertEqual(check(self.base), 20, check.__name__)
        # HE-004B1: the observer's (5 with HE-004C's socket module) and i05-protocol's 2; HE-004D1: observer-sys's 2.
        self.assertEqual(gate.check_observer_post_seal(self.base), 9)
        self.assertEqual(gate.check_post_seal_sources(self.base), 13, "the gate's post-seal crates do not include the observer")
        self.assertEqual(gate.CRATE_ROOTS[gate.OBSERVER_LIB], "#![forbid(unsafe_code)]")
        self.assertEqual(gate.CRATE_ROOTS[gate.OBSERVER_MAIN], "#![forbid(unsafe_code)]")

    def test_every_linked_crate_scan_reads_the_observer(self):
        seal = self.TREE[OBSERVER_SEAL]
        for check, text, message in (
                (gate.check_linked_sources, "fn f() { let _ = std::env::args_os(); }", "linked-source tripwire"),
                (gate.check_linked_sources, "use std::process::ExitCode;", "linked-source tripwire"),
                (gate.check_linked_sources, "fn f(_: &Path) {}", "linked-source tripwire"),
                (gate.check_linked_sources, "use std::net::TcpStream;", "linked-source tripwire"),
                (gate.check_foreign_items, "unsafe extern \"C\" { fn ioctl(fd: i32, r: u64, ...) -> i32; }",
                 "declares the foreign items"),
                (gate.check_debug_derives, "#[derive(Debug)]\npub struct S { f: File }", "Debug check"),
                (gate.check_socket_modules, "use gate_sys::channel::Poller;", "socket-module check"),
                (gate.check_socket_modules, "fn f() { std::thread::spawn(g); }", "names std::thread"),
                (gate.check_read_link, "fn f(d: &Dir, b: &mut [u8]) { let _ = d.read_link(\"exe\", b); }",
                 "seal.rs names read_link"),
                (gate.check_macros, "macro_rules! m { () => {} }", "macro rule"),
                (gate.check_pre_main, "#[unsafe(no_mangle)]\nfn f() {}", "code before main"),
                (gate.check_prints, "fn f() { println!(\"x\"); }", "print rule"),
                (gate.check_unsafe, "fn f() { unsafe { g() } }", "contains unsafe outside")):
            self.refused(check, OBSERVER_SEAL, seal + text + "\n", message)
        for rel in (gate.OBSERVER_LIB, gate.OBSERVER_MAIN):
            self.refused(gate.check_linked_sources, rel, self.TREE[rel].replace("#![forbid(unsafe_code)]", "#![deny(unsafe_code)]"),
                         "lacks #!\\[forbid")

    def test_the_observer_exit_import_once_in_main(self):
        main = gate.OBSERVER_MAIN
        self.assertEqual(gate.check_linked_sources(self.base), 20)
        for text in (GOOD_OBSERVER_MAIN + "use std::process::ExitCode;\n",
                     GOOD_OBSERVER_MAIN + "fn f() { std::process::exit(1); }\n",
                     GOOD_OBSERVER_MAIN + "fn f() { let _ = std::env::args_os(); }\n"):
            self.refused(gate.check_linked_sources, main, text, "linked-source tripwire")
        self.refused(gate.check_linked_sources, gate.OBSERVER_LIB, self.TREE[gate.OBSERVER_LIB] + "use std::process::ExitCode;\n",
                     "std::process")

    def test_the_observer_post_seal_list(self):
        seal = self.TREE[OBSERVER_SEAL]
        message = "seal.rs names .* .observer post-seal check"
        for text in ("fn f(d: &Dir) { let _ = d.file(\"x\", m); }", "fn f() { let _ = FileMode::Existing; }",
                     "fn f(d: &Dir) { let _ = d.sync(); }", "fn f(f: &File) { let _ = f.sync_all(); }",
                     "fn f(f: &File) { let _ = f.sync_data(); }", "fn f(f: &File) { let _ = f.lock_shared(); }",
                     "fn f(f: &File) { let _ = f.try_lock(); }", "fn f(f: &File) { let _ = f.try_lock_shared(); }",
                     "fn f(f: &File) { let _ = f.unlock(); }", "fn f(f: &File) { let _ = f.lock(); }",
                     "fn f(m: &Mutex<u8>) { let _ = m .lock (); }", "fn f(f: &File) { let _ = f.write_at(b, 0); }",
                     "fn f(f: &File) { let _ = f.write_all_at(b, 0); }",
                     # PR review round 1, R1-1: path calls, function items, a turbofish and imports.
                     "fn f(d: &Dir) { let _ = Dir::sync(d); }", "fn f(d: &Dir) { let _ = gate_sys::Dir :: sync (d); }",
                     "fn f(d: &Dir) { let s = Dir::sync; let _ = s(d); }", "fn f(f: &File) { let _ = File::lock(f); }",
                     "fn f(m: &Mutex<u8>) { let _ = Mutex::lock(m); }", "fn f(d: &Dir) { let _ = <Dir>::file(d, n, m); }",
                     "fn f(d: &Dir) { let _ = [Dir::file]; }", "fn f(f: &File) { let _ = File::write_at::<>(f, b, 0); }",
                     "fn f(f: &File) { let _ = std::fs::File::sync_all(f); }", "use x::{a, unlock};",
                     "use std::sync::Mutex; fn f(m: &Mutex<u8>) { let _ = m.lock(); }",
                     # R1-4: no destructor of the observer's own runs under the filter.
                     "impl Drop for Plan { fn drop(&mut self) {} }", "impl core::ops::Drop for Sealed { fn drop(&mut self) {} }",
                     # The gate's list applies too.
                     "fn f(s: &S) { let _ = s.set_nonblocking(true); }", "fn f() { membarrier(0, 0); }",
                     "fn f(f: &File) { let _ = f.is_terminal(); }", "fn f() { let _ = std::fs::read_dir(p); }"):
            self.refused(gate.check_observer_post_seal, OBSERVER_SEAL, seal + text + "\n", message)
        # Other crates are outside this rule: gate-sys defines file, FileMode and sync (calling sync_all), the gate's crates
        # may sync; words that are not these calls pass in the observer.
        self.write("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                   + "fn f(d: &Dir) { let _ = d.file(n, FileMode::Existing); let _ = d.sync(); }\n")
        self.write(OBSERVER_SEAL, seal + "fn f(blocked: bool, clocks: u8) -> bool { let synced = blocked; synced }\n")
        self.assertEqual(gate.check_observer_post_seal(self.base), 9)
        # R1-1: a module path segment, comments and literals pass; drop() is not the Drop trait.
        self.write(OBSERVER_SEAL, seal + "use std::sync::atomic::AtomicU8;\n// Dir::sync, File::lock and impl Drop are refused\n"
                   "fn g(x: u8) -> &'static str { drop(x); \"file lock sync Drop\" }\n")
        self.assertEqual(gate.check_observer_post_seal(self.base), 9)
        for rel in list(OBSERVER_TREE):
            if rel.startswith("crates/observer/"):
                (self.base / rel).unlink()
        with self.assertRaisesRegex(gate.GateError, "crates/observer has no sources .observer post-seal check"):
            gate.check_observer_post_seal(self.base)

    def test_i05_protocol_joins_the_observer_post_seal_list(self):
        # HE-004B1 DESIGN-B section 6 (owner decision Q-HE4B-6 (a)): i05-protocol's sources join the rule, with json.rs's
        # one memory-only `impl Drop for Value` excepted once; gate-sys stays outside.
        self.assertEqual(gate.OBSERVER_POST_SEAL_CRATES, ("crates/observer", "crates/i05-protocol", "crates/observer-sys"))
        json_rs = self.TREE[gate.I05_JSON]
        drop = "impl Drop for Value {\n    fn drop(&mut self) { let mut pending = Vec::new(); pending.clear(); }\n}\n"
        self.write(gate.I05_JSON, json_rs + drop)
        self.assertEqual(gate.check_observer_post_seal(self.base), 9)
        self.write(gate.I05_JSON, json_rs + "impl  Drop\n    for Value { fn drop(&mut self) {} }\n")
        self.assertEqual(gate.check_observer_post_seal(self.base), 9)
        message = "names .* .observer post-seal check"
        for rel, text in ((gate.I05_JSON, json_rs + drop + drop),
                          (gate.I05_JSON, json_rs + "impl Drop for Doc { fn drop(&mut self) {} }\n"),
                          (gate.I05_JSON, json_rs + "impl core::ops::Drop for Value { fn drop(&mut self) {} }\n"),
                          ("crates/i05-protocol/src/lib.rs", LINKED_TREE["crates/i05-protocol/src/lib.rs"] + drop),
                          ("crates/i05-protocol/src/frame.rs", drop),
                          (gate.I05_JSON, json_rs + "fn f(m: &Mutex<u8>) { let _ = m.lock(); }\n"),
                          (gate.I05_JSON, json_rs + "fn f(d: &Dir) { let _ = d.sync(); }\n"),
                          (gate.I05_JSON, json_rs + "fn f(h: &File) { let _ = h.sync_all(); }\n"),
                          ("crates/i05-protocol/src/frame.rs", "fn f(file: u8) -> u8 { file }\n"),
                          (gate.I05_JSON, json_rs + "fn f(s: &S) { let _ = s.set_nonblocking(true); }\n")):
            self.refused(gate.check_observer_post_seal, rel, text, message)
        # Comments and literals pass; gate-sys's own definitions stay outside (OBSERVER_TREE's openat.rs).
        self.write(gate.I05_JSON, json_rs + "// impl Drop for Doc, file, lock and sync in a comment\nconst T: &str = \"Drop file\";\n")
        self.assertEqual(gate.check_observer_post_seal(self.base), 9)


class ObserverBinaryTests(unittest.TestCase):
    """HE-004A DESIGN-A section 6 (D1-1; D1-10, D2-5): planeon-observer links no membarrier and holds its architecture's
    OBSERVER program bytes exactly once; no wrapper inventory (owner decision Q-HE4A-B2 (a))."""

    PROGRAM = bytes(range(8)) * 3

    def test_the_program_once_and_no_membarrier(self):
        raw = b"\x7fELF" + b"\0" * 64 + self.PROGRAM + b"\0" * 16
        self.assertEqual(gate.check_observer_binary({"main", "read", "__membarrier_init"}, raw, self.PROGRAM), 24)
        for name in gate.MEMBARRIER:
            with self.assertRaisesRegex(gate.GateError, "links .*membarrier.* .membarrier check"):
                gate.check_observer_binary({"read", name}, raw, self.PROGRAM)
        for count in (0, 2, 3):
            with self.assertRaisesRegex(gate.GateError, "holds its OBSERVER program %d times, not exactly once" % count):
                gate.check_observer_binary({"read"}, b"\0" * 8 + self.PROGRAM * count + b"\0", self.PROGRAM)
        # A truncated copy is not the program.
        with self.assertRaisesRegex(gate.GateError, "0 times"):
            gate.check_observer_binary({"read"}, self.PROGRAM[:-1], self.PROGRAM)
        with self.assertRaisesRegex(gate.GateError, "an empty OBSERVER program"):
            gate.check_observer_binary({"read"}, raw, b"")

    def test_each_target_names_its_pinned_program(self):
        self.assertEqual(set(gate.OBSERVER_PROGRAMS), set(gate.MACHINE))
        self.assertEqual(gate.OBSERVER_PROGRAMS["x86_64-unknown-linux-musl"], "contracts/seccomp-v3/OBSERVER.x86_64.bpf")
        self.assertEqual(gate.OBSERVER_PROGRAMS["aarch64-unknown-linux-musl"], "contracts/seccomp-v3/OBSERVER.aarch64.bpf")
        self.assertTrue(set(gate.OBSERVER_PROGRAMS.values()) <= set(gate.CONTRACTS))
        self.assertFalse(hasattr(gate, "OBSERVER_WRAPPER_JUSTIFICATIONS"), "no observer wrapper inventory in HE-004A")


LOGIC_TREE = {
    **OBSERVER_TREE,
    "crates/observer/src/inputs.rs": "use std::collections::{BTreeMap, BTreeSet, VecDeque};\nuse std::fmt::{self, Write};\n"
                                     "use i05_protocol::json::{JStr, Value};\n"
                                     "pub fn n(items: &[Value]) -> usize { let wide = items.len() as u64; usize::try_from(wide).unwrap_or(0) }\n"
                                     "// HashMap, std::fs::read, unwrap() and panic! in a comment\n"
                                     "const NOTE: &str = \"std::process HashSet expect( super::x\";\n",
    "crates/observer/src/rbac.rs": "use crate::inputs::{self, n};\nuse crate::contracts;\n"
                                   "pub fn f() -> std::cmp::Ordering { std::cmp::Ordering::Less }\n"
                                   "pub fn g(x: &[u8]) -> Option<&str> { std :: str :: from_utf8(x).ok() }\n",
    "crates/observer/src/snapshot.rs": "use i05_protocol::sha256::{self, Sha256};\nuse crate::rbac;\n"
                                       "pub fn h() -> Vec<u8> { Vec::<u8>::new() }\npub fn k(x: u8) -> u8 { <u8 as Clone>::clone(&x) }\n"
                                       "pub fn m() -> self::rbac::X { x() }\n"
                                       "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() { assert_eq!(1, 1); let _ = Some(1).unwrap(); }\n}\n",
    "crates/observer/src/operational.rs": "use i05_protocol::contracts::I07_V3_POLICY_KINDS;\n"
                                          "pub fn kinds() -> &'static [u8] { I07_V3_POLICY_KINDS }\n"
                                          "pub fn e(r: Result<u8, u8>) -> u8 { r.unwrap_or_else(|e| e) }\n",
    "crates/observer/src/admission.rs": "use std::fmt;\npub fn z(v: Vec<u8>) -> impl std::iter::Iterator<Item = u8> { v.into_iter() }\n"
                                        "pub fn expected(x: Result<u8, u8>) -> bool { x.expect_err(\"e\") == 1 }\n"
                                        "pub fn w() -> ::std::string::String { String::new() }\n",
    # HE-004D1 (G-D1-10): the capture checks' three logic modules.
    "crates/observer/src/capture_schema.rs": "use i05_protocol::json::{self, Value};\nuse i05_protocol::schema::Schema;\n"
                                             "pub fn embedded() -> &'static [u8] { crate::contracts::NATIVE_PROFILE_V4_SCHEMA }\n",
    "crates/observer/src/capture_check.rs": "use std::collections::BTreeMap;\nuse crate::capture_schema::CaptureSchema;\n"
                                            "use crate::kernel_text;\npub fn f(x: &[u8]) -> Option<&str> { std::str::from_utf8(x).ok() }\n",
    "crates/observer/src/kernel_text.rs": "use std::collections::BTreeMap;\n"
                                          "pub fn hex(b: &[u8]) -> String { i05_protocol::sha256::hex(b) }\n",
}


class ObserverLogicTests(Tree):
    """HE-004B1 DESIGN-B section 6 (D1-7, D2-5, D3-2): the observer logic modules' path-root whitelist, its refused forms
    and words, and the no-panic tripwire outside strict #[cfg(test)] blocks."""

    TREE = LOGIC_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.OBSERVER_LOGIC_NAMES, ("inputs", "rbac", "snapshot", "operational", "admission"))
        self.assertEqual(gate.check_observer_logic(self.base), 8)

    def test_each_module_is_required(self):
        for rel in gate.OBSERVER_LOGIC:
            (self.base / rel).unlink()
            with self.assertRaisesRegex(gate.GateError, "is missing .observer logic rules"):
                gate.check_observer_logic(self.base)
            self.write(rel, self.TREE[rel])

    def test_paths_outside_the_whitelist_refuse(self):
        rel = "crates/observer/src/rbac.rs"
        good = self.TREE[rel]
        for text, message in (
                # Use declarations: std modules outside the list, other crates' modules, the seal and status, super::,
                # foreign self::, a glob, a rename.
                ("use std::collections::HashMap;\n", "imports std::collections::HashMap"),
                ("use std::collections;\n", "imports std::collections,"),
                ("use std::sync::Arc;\n", "imports std::sync::Arc"),
                ("use std::time::Instant;\n", "imports std::time::Instant"),
                ("use std::io::Read;\n", "imports std::io::Read"),
                ("use core::cell::Cell;\n", "imports core::cell::Cell"),
                ("use alloc::rc::Rc;\n", "imports alloc::rc::Rc"),
                ("use crate::seal::Sealed;\n", "imports crate::seal::Sealed"),
                ("use crate::status;\n", "imports crate::status"),
                ("use super::inputs::Inputs;\n", "imports super::inputs::Inputs"),
                ("use self::helper::X;\n", "imports self::helper::X"),
                ("use gate_sys::Dir;\n", "imports gate_sys::Dir"),
                ("use ::gate_sys::Dir;\n", "imports gate_sys::Dir"),
                ("use planeon_observer::seal;\n", "imports planeon_observer::seal"),
                ("use i05_protocol::schema::Schema;\n", "imports i05_protocol::schema::Schema"),
                ("use i05_protocol::Value;\n", "imports i05_protocol::Value"),
                ("use i05_protocol::{json, regex};\n", "imports i05_protocol::regex"),
                ("use crate::*;\n", "imports a glob"),
                ("use i05_protocol::json::*;\n", "imports a glob"),
                ("use crate::inputs as other;\n", "renames an import"),
                ("use std::fmt as f;\n", "renames an import"),
                ("fn f() { use std::time::Instant; }\n", "imports std::time::Instant"),
                # Code paths, spaced or with a leading `::`, and the refused words.
                ("fn f() { let _ = std::time::Instant::now(); }\n", "names std::time::Instant::now"),
                ("fn f() { let _ = ::std::env::args(); }\n", "names ::std::env::args"),
                ("fn f() { let _ = std :: thread :: current(); }\n", "names std::thread::current"),
                ("fn f() { crate::seal::seal_stage1(); }\n", "names crate::seal::seal_stage1"),
                ("fn f() { super::x(); }\n", "names super::x"),
                ("fn f() { self::g(); }\n", "names self::g"),
                ("fn f() { gate_sys::Dir::at(p); }\n", "names gate_sys::Dir::at"),
                ("fn f() { let _ = i05_protocol::schema::Schema::from_json(b); }\n", "names i05_protocol::schema"),
                ("fn f() { let _ = ::other::thing(); }\n", "names ::other::thing"),
                ("fn f() { let _: std::collections::BTreeMap<u8, u8> = x(); let _ = HashSet::<u8>::new(); }\n", "HashMap, HashSet or RandomState"),
                ("fn f() { let _ = RandomState::new(); }\n", "HashMap, HashSet or RandomState"),
                ("const X: &[u8] = include_bytes!(\"../../../contracts/i06-v1/README.md\");\n", "include_bytes! or include_str!"),
                ("const X: &str = include_str! (\"x\");\n", "include_bytes! or include_str!")):
            self.refused(gate.check_observer_logic, rel, good + text, message)

    def test_the_no_panic_tripwire(self):
        rel = "crates/observer/src/operational.rs"
        good = self.TREE[rel]
        for text, name in (("fn f(x: Option<u8>) -> u8 { x.unwrap() }\n", "unwrap"), ("fn f(x: Option<u8>) -> u8 { x.expect (\"y\") }\n", "expect"),
                           ("fn f() { panic!(\"x\") }\n", "panic!"), ("fn f() -> u8 { unreachable!() }\n", "unreachable!"),
                           ("fn f() -> u8 { todo!() }\n", "todo!"), ("fn f() -> u8 { unimplemented!() }\n", "unimplemented!"),
                           ("fn f(x: u8) { assert!(x > 0); }\n", "assert!"), ("fn f(x: u8) { assert_eq!(x, 0); }\n", "assert_eq!"),
                           ("fn f(x: u8) { assert_ne!(x, 0); }\n", "assert_ne!"), ("fn f(x: u8) { debug_assert!(x > 0); }\n", "debug_assert!"),
                           ("fn f(x: u8) { debug_assert_eq!(x, 0); }\n", "debug_assert!"), ("fn f(x: u8) { debug_assert_ne!(x, 0); }\n", "debug_assert!"),
                           ("fn f(x: Option<u8>) -> u8 { Option::unwrap(x) }\n", "unwrap")):
            self.refused(gate.check_observer_logic, rel, good + text, "names %s.* outside a strict #\\[cfg\\(test\\)\\] mod tests block" % re.escape(name))
        # Only a strict in-source test module is exempt (the HE-003A3 form).
        panicking = "    #[test]\n    fn t() { let _ = Some(1).unwrap(); }\n}\n"
        for opening in ("#[cfg(test)] mod tests {\n", "#[cfg(any(test, unix))]\nmod tests {\n", "#[cfg(test)]\nmod other {\n",
                        "#[allow(unused)]\n#[cfg(test)]\nmod tests {\n"):
            self.refused(gate.check_observer_logic, rel, good + opening + panicking, "no-panic tripwire")
        self.write(rel, good + "#[cfg(test)]\nmod tests {\n" + panicking)
        self.assertEqual(gate.check_observer_logic(self.base), 8)


INCLUDE_TREE = {
    **OBSERVER_TREE,
    gate.OBSERVER_CONTRACTS: "pub const A: &[u8] = include_bytes!(\"../../../contracts/i06-v1/identity-closure.json\");\n"
                             "pub const B: &str = include_str! ( \"../../../contracts/i06-v2/README.md\" );\n"
                             "// include_bytes!(\"../../../tools/gate.py\") in a comment\n",
    OBSERVER_SEAL: "pub static X: &[u8; 1904] = include_bytes!(\"../../../contracts/seccomp-v3/OBSERVER.x86_64.bpf\");\n"
                   "pub static A: &[u8; 1816] = include_bytes!(\"../../../contracts/seccomp-v3/OBSERVER.aarch64.bpf\");\n",
}


class ObserverIncludeTests(Tree):
    """HE-004B1 DESIGN-B section 6 (D2-5): the observer's embedded contracts live in contracts.rs, each include one plain
    literal naming a registered contract file; seal.rs embeds only its two OBSERVER programs."""

    TREE = INCLUDE_TREE

    def test_the_tree_passes(self):
        self.assertEqual((gate.OBSERVER_CONTRACTS, gate.OBSERVER_SEAL_RS), ("crates/observer/src/contracts.rs", OBSERVER_SEAL))
        self.assertEqual(gate.check_observer_includes(self.base), 4)

    def test_other_forms_paths_and_files_refuse(self):
        contracts = self.TREE[gate.OBSERVER_CONTRACTS]
        for rel, text, message in (
                (gate.OBSERVER_CONTRACTS, contracts + "pub const C: &[u8] = include_bytes!(\"../../../contracts/i06-v1/upstream-facts-v1.37.1.json\");\n",
                 "not a registered contract file"),
                (gate.OBSERVER_CONTRACTS, contracts + "pub const C: &[u8] = include_bytes!(\"../../../tools/gate.py\");\n",
                 "not a registered contract file"),
                (gate.OBSERVER_CONTRACTS, contracts + "pub const C: &[u8] = include_bytes!(\"../../../../host-enforcement/contracts/i06-v2/README.md\");\n",
                 "not a registered contract file"),
                (gate.OBSERVER_CONTRACTS, contracts + "pub const C: &[u8] = include_bytes!(concat!(\"../../../contracts/\", \"i06-v2/README.md\"));\n",
                 "not one plain path literal"),
                (gate.OBSERVER_CONTRACTS, contracts + "pub const C: &[u8] = include_bytes!(r\"../../../contracts/i06-v2/README.md\");\n",
                 "not one plain path literal"),
                (gate.OBSERVER_CONTRACTS, contracts + "pub const C: &[u8] = include_bytes!(\"..\\x2f..\\x2f..\\x2fcontracts/i06-v2/README.md\");\n",
                 "not one plain path literal"),
                ("crates/observer/src/status.rs", self.TREE["crates/observer/src/status.rs"]
                 + "pub const C: &[u8] = include_bytes!(\"../../../contracts/i06-v2/README.md\");\n", "only crates/observer/src/contracts.rs embeds"),
                ("crates/observer/src/rbac.rs", "pub const C: &str = include_str!(\"../../../contracts/i06-v2/README.md\");\n",
                 "only crates/observer/src/contracts.rs embeds"),
                (OBSERVER_SEAL, self.TREE[OBSERVER_SEAL] + "pub static C: &[u8] = include_bytes!(\"../../../contracts/i06-v2/README.md\");\n",
                 "not an OBSERVER program"),
                (OBSERVER_SEAL, self.TREE[OBSERVER_SEAL] + "pub static C: &[u8] = include_bytes!(\"../../../contracts/seccomp-v4/EFFECT_GATE.x86_64.bpf\");\n",
                 "not an OBSERVER program")):
            self.refused(gate.check_observer_includes, rel, text, message)
        (self.base / gate.OBSERVER_CONTRACTS).unlink()
        with self.assertRaisesRegex(gate.GateError, "contracts.rs is missing .observer contracts rule"):
            gate.check_observer_includes(self.base)


def fake_sha(name):
    return hashlib.sha256(name.encode()).hexdigest()


class VendorTests(unittest.TestCase):
    """HE-003B DESIGN sections 2.2, 2.6, 17 and 19: check_vendor over a fixture vendor tree and table."""

    CRATES = {
        ("ring", "0.17.14", "LINKED", "FULL"): {
            "Cargo.toml": b'[package]\nname = "ring"\nversion = "0.17.14"\nbuild = "build.rs"\n', "build.rs": b"fn main() {}\n",
            "LICENSE": b"ISC\n", "src/lib.rs": b"pub fn f() {}\n", "crypto/a.c": b"int a;\n", "include/a.h": b"int a;\n",
            "pregenerated/x.o": b"\x7fELF\xff\xfe"},
        ("cc", "1.8.0", "BUILD_HOST", "FULL"): {
            "Cargo.toml": b'[package]\nname = "cc"\nversion = "1.8.0"\n', "LICENSE-MIT": b"MIT\n", "src/lib.rs": b"//\n",
            "src/detect_compiler_family.c": b"probe\n", "src/detect_cpp_stdlib.cpp": b"probe\n"},
        ("libc", "0.2.190", "LINKED", "FULL"): {
            "Cargo.toml": b'[package]\nname = "libc"\nversion = "0.2.190"\n', "build.rs": b"fn main() {}\n",
            "LICENSE-MIT": b"MIT\n", "src/lib.rs": b"//\n"},
        ("rustls", "0.23.46", "LINKED", "FULL"): {
            "Cargo.toml": b'[package]\nname = "rustls"\nversion = "0.23.46"\nbuild = "build.rs"\n', "build.rs": b"fn main() {}\n",
            "LICENSE-MIT": b"MIT\n", "src/lib.rs": b"//\n"},
        ("windows-sys", "0.52.0", "LOCK_ONLY", "STUB"): {
            "Cargo.toml": b'[package]\nname = "windows-sys"\nversion = "0.52.0"\nreadme = "readme.md"\n',
            "license-mit": b"MIT\n", "readme.md": b"# windows-sys\n", "src/lib.rs": b""},
    }

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        self.probes = mock.patch.object(gate, "CC_PROBES", {"src/detect_compiler_family.c": hashlib.sha256(b"probe\n").hexdigest(),
                                                            "src/detect_cpp_stdlib.cpp": hashlib.sha256(b"probe\n").hexdigest()})
        self.probes.start()
        self.rows = {}
        for (name, version, role, form), files in self.CRATES.items():
            root = self.base / "vendor" / ("%s-%s" % (name, version))
            for rel, data in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(data)
            self.rows[name] = {"name": name, "version": version, "role": role, "form": form, "sha256": fake_sha(name),
                               "outcome": "ACCEPTED_OR", "canonical": "MIT", "dependencies": []}
            self.rebuild(name)

    def tearDown(self):
        self.probes.stop()
        self.directory.cleanup()

    def root(self, name):
        row = self.rows[name]
        return self.base / "vendor" / ("%s-%s" % (row["name"], row["version"]))

    def rebuild(self, name, stale=()):
        """Rewrites the crate's checksum file and recomputes its row, keeping the fields in `stale`."""
        row, root = self.rows[name], self.root(name)
        checksum = root / ".cargo-checksum.json"
        if checksum.exists():
            checksum.unlink()
        files = {path.relative_to(root).as_posix(): path.read_bytes() for path in sorted(root.rglob("*")) if path.is_file()}
        checksum.write_text(json.dumps({"files": {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()},
                                        "package": row["sha256"]}))
        files[".cargo-checksum.json"] = checksum.read_bytes()
        files = dict(sorted(files.items()))
        digests = {rel: hashlib.sha256(data).hexdigest() for rel, data in files.items()}
        fresh = {"fileCount": len(files), "treeDigest": gate.sha256(gate.canonical(digests)),
                 "buildScript": "build.rs" in files, "suffixes": {}, "nonUtf8": [], "nativeFiles": [],
                 "licenseFiles": [{"path": rel, "sha256": digests[rel]} for rel in files if rel.lower().startswith("licen")]}
        for rel, data in files.items():
            suffix = Path(rel).suffix
            fresh["suffixes"][suffix] = fresh["suffixes"].get(suffix, 0) + 1
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                fresh["nonUtf8"].append({"path": rel, "sha256": digests[rel]})
            if suffix in gate.NATIVE_SUFFIXES:
                fresh["nativeFiles"].append({"path": rel, "sha256": digests[rel]})
        if row["form"] == "STUB" and "stub" not in row:
            row["stub"] = {"emptyLibrary": "src/lib.rs", "dropped": [],
                           "kept": [{"path": rel, "sha256": digests[rel]} for rel in files
                                    if rel not in ("src/lib.rs", ".cargo-checksum.json")]}
        for key, value in fresh.items():
            if key not in stale:
                row[key] = value

    def table(self):
        table = {"schemaVersion": "planeon.internal.he-vendor-table/v1", "acceptedOutcomes": list(gate.ACCEPTED),
                 "rows": [self.rows[name] for name in sorted(self.rows)]}
        raw = gate.canonical(table) + b"\n"
        return raw, gate.sha256(raw)

    def check(self):
        raw, digest = self.table()
        return gate.check_vendor(self.base, raw, digest)

    def refused(self, message):
        with self.assertRaisesRegex(gate.GateError, message):
            self.check()

    def test_the_fixture_passes(self):
        rows, files = self.check()
        self.assertEqual((len(rows), files), (5, 29))
        self.assertEqual(len(gate.VENDOR_TABLE_SHA256), 64)

    def test_the_table_digest_is_pinned(self):
        raw, _ = self.table()
        with self.assertRaisesRegex(gate.GateError, "not the reviewed table"):
            gate.check_vendor(self.base, raw, "0" * 64)

    def test_the_directory_set_is_exact(self):
        (self.base / "vendor/extra-1.0.0").mkdir()
        self.refused("exactly one directory per vendor row")
        (self.base / "vendor/extra-1.0.0").rmdir()
        (self.base / "vendor/README").write_text("x\n")
        self.refused("exactly one directory per vendor row")

    def test_links_executables_names_and_case(self):
        os.symlink("lib.rs", self.root("libc") / "src/alias.rs")
        self.refused("symlink")
        (self.root("libc") / "src/alias.rs").unlink()
        os.chmod(self.root("libc") / "build.rs", 0o755)
        self.refused("executable")
        os.chmod(self.root("libc") / "build.rs", 0o644)
        (self.root("libc") / "src/a\tb.rs").write_text("//\n")
        self.rebuild("libc")
        self.refused("printable ASCII")
        # Paths that differ in case only cannot be made on the build host's case-insensitive file system; the
        # verifier's head-tree rule refuses them as well.

    def test_the_checksum_file_and_the_tree(self):
        checksum = self.root("rustls") / ".cargo-checksum.json"
        document = json.loads(checksum.read_text())
        checksum.write_text(json.dumps({**document, "package": "0" * 64}))
        self.refused("checksum package is not the approved sha256")
        checksum.write_text(json.dumps(document))
        (self.root("rustls") / "src/more.rs").write_text("//\n")
        self.refused("does not list exactly its files")
        self.rebuild("rustls", stale=("treeDigest", "fileCount"))
        self.refused("files differ from its vendor row")

    def test_build_scripts_are_role_aware(self):
        (self.root("cc") / "build.rs").write_text("fn main() {}\n")
        self.rebuild("cc")
        self.refused("with a build script are")
        (self.root("cc") / "build.rs").unlink()
        self.rebuild("cc")
        (self.root("libc") / "build.rs").unlink()
        self.rebuild("libc", stale=("buildScript",))
        self.refused("build script differs from its vendor row")

    def test_an_unlisted_non_utf8_file_and_a_new_suffix(self):
        (self.root("rustls") / "src/key.bin").write_bytes(b"\xff\x00\xfe")
        self.rebuild("rustls", stale=("nonUtf8",))
        self.refused("non-UTF-8 files differ")
        (self.root("rustls") / "src/key.bin").unlink()
        (self.root("rustls") / "notes.xyz").write_text("x\n")
        self.rebuild("rustls", stale=("suffixes",))
        self.refused("suffix inventory differs")

    def test_c_family_files_only_in_ring_and_the_two_cc_probes(self):
        (self.root("libc") / "src/shim.c").write_text("int x;\n")
        self.rebuild("libc")
        self.refused("libc-0.2.190 holds a C-family")
        (self.root("libc") / "src/shim.c").unlink()
        self.rebuild("libc")
        for rel in ("src/other.c", "tools/gen.pl", "src/x.S"):
            (self.root("cc") / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root("cc") / rel).write_text("x\n")
            self.rebuild("cc")
            self.refused("cc holds C-family files other than its two compiler probes")
            (self.root("cc") / rel).unlink()
            self.rebuild("cc")
        (self.root("cc") / "src/detect_cpp_stdlib.cpp").write_text("changed\n")
        self.rebuild("cc")
        self.refused("cc holds C-family files other than its two compiler probes")

    def test_a_stub_holds_exactly_its_kept_files(self):
        (self.root("windows-sys") / "src/extra.rs").write_text("//\n")
        self.rebuild("windows-sys")
        self.refused("is not exactly its stub")
        (self.root("windows-sys") / "src/extra.rs").unlink()
        (self.root("windows-sys") / "src/lib.rs").write_text("pub fn f() {}\n")
        self.rebuild("windows-sys")
        self.refused("is not exactly its stub")


class VendorExclusionTests(unittest.TestCase):
    """HE-003B DESIGN section 2.1: the source scans skip vendor/ (pinned by check_vendor), never crates/."""

    def test_vendor_is_skipped_and_crates_are_not(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for rel, text in (("crates/a/src/main.rs", "fn main() {}\n"),
                              ("vendor/libc-0.2.190/src/lib.rs", "unsafe extern \"C\" {} // /proc env::var vars\n")):
                (base / rel).parent.mkdir(parents=True, exist_ok=True)
                (base / rel).write_text(text)
            self.assertEqual(gate.check_sources(base), 1)
            self.assertEqual(gate.check_unsafe(base), 1)
            nested = base / "crates/a/src/vendor/mod.rs"
            nested.parent.mkdir()
            nested.write_text("fn f() { let _ = env::var(\"x\"); }\n")
            with self.assertRaisesRegex(gate.GateError, "crates/a/src/vendor/mod.rs uses env::var"):
                gate.check_sources(base)


GATE_TLS_MANIFEST = ('[package]\nname = "gate-tls"\n\n[dependencies]\na = { path = "../a" }\n'
                     'rustls = { version = "=0.23.46", default-features = false, features = ["ring", "std"] }\n'
                     'getrandom = { version = "=0.2.17", default-features = false, features = ["linux_disable_fallback"] }\n'
                     'zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }\n'
                     'ring = "=0.17.14"\n')
VENDOR_ROWS = [{"name": "rustls", "version": "0.23.46", "sha256": fake_sha("rustls"), "dependencies": ["ring"]},
               {"name": "ring", "version": "0.17.14", "sha256": fake_sha("ring"), "dependencies": []}]


class RegistryLineTests(unittest.TestCase):
    """HE-003B DESIGN sections 2.4, 2.6 and 20: gate-tls's exact registry lines, no other registry line, no [patch] or
    [replace], and a lock whose registry packages are exactly the vendor table's, with checksums and edges."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        (self.base / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/a", "crates/gate-tls"]\n')
        for name in ("a", "gate-tls"):
            (self.base / "crates" / name / "src").mkdir(parents=True)
        (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n')
        self.manifest(GATE_TLS_MANIFEST)
        self.lock()

    def tearDown(self):
        self.directory.cleanup()

    def manifest(self, text):
        (self.base / "crates/gate-tls/Cargo.toml").write_text(text)

    def lock(self, rows=VENDOR_ROWS, extra=""):
        text = 'version = 4\n\n[[package]]\nname = "a"\nversion = "0.1.0"\n\n[[package]]\nname = "gate-tls"\nversion = "0.1.0"\n\n'
        for row in rows:
            text += ('[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\ndependencies = [%s]\n\n'
                     % (row["name"], row["version"], gate.REGISTRY, row["sha256"], ", ".join('"%s"' % d for d in row["dependencies"])))
        (self.base / "Cargo.lock").write_text(text + extra)

    def test_the_pinned_lines_and_the_lock_pass(self):
        self.assertEqual(gate.check_workspace(self.base, VENDOR_ROWS), {"a": set(), "gate-tls": {"a"}})

    def test_registry_lines_are_exact(self):
        for old, new in (('"=0.23.46"', '"0.23.46"'), ('features = ["ring", "std"]', 'features = ["ring", "std", "tls12"]'),
                         ('getrandom = { version = "=0.2.17", default-features = false',
                          'getrandom = { version = "=0.2.17", default-features = true'),
                         ('zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }',
                          'zeroize = "=1.9.1"')):
            self.manifest(GATE_TLS_MANIFEST.replace(old, new))
            with self.assertRaisesRegex(gate.GateError, "not its pinned line"):
                gate.check_workspace(self.base, VENDOR_ROWS)
        # HE-003D (Q-HE3D-6 (a)): ring is pinned exactly as `ring = "=0.17.14"`; any other form of the line refuses.
        for line in ('ring = "0.17.14"', 'ring = "=0.17.13"', 'ring = { version = "=0.17.14" }',
                     'ring = { version = "=0.17.14", default-features = false }'):
            self.manifest(GATE_TLS_MANIFEST.replace('ring = "=0.17.14"', line))
            with self.assertRaisesRegex(gate.GateError, "the registry dependency ring of crates/gate-tls is not its pinned line"):
                gate.check_workspace(self.base, VENDOR_ROWS)
        for text in (GATE_TLS_MANIFEST.replace('ring = "=0.17.14"\n', "") + "\n[dev-dependencies]\nring = \"=0.17.14\"\n",
                     GATE_TLS_MANIFEST + "untrusted = \"=0.9.0\"\n"):
            self.manifest(text)
            with self.assertRaisesRegex(gate.GateError, "dependency outside the workspace"):
                gate.check_workspace(self.base, VENDOR_ROWS)
        self.manifest(GATE_TLS_MANIFEST)
        (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n\n[dependencies]\n'
                                                      'rustls = { version = "=0.23.46", default-features = false, features = ["ring", "std"] }\n')
        with self.assertRaisesRegex(gate.GateError, "dependency outside the workspace"):
            gate.check_workspace(self.base, VENDOR_ROWS)

    def test_no_patch_or_replace(self):
        for table in ("[patch.crates-io]\nring = { path = \"x\" }\n", "[replace]\n\"ring:0.17.14\" = { path = \"x\" }\n"):
            (self.base / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/a", "crates/gate-tls"]\n\n' + table)
            with self.assertRaisesRegex(gate.GateError, "patch. or .replace"):
                gate.check_workspace(self.base, VENDOR_ROWS)

    def test_the_lock_is_the_vendor_table(self):
        self.lock(rows=VENDOR_ROWS[:1])
        with self.assertRaisesRegex(gate.GateError, "outside the vendor table"):
            gate.check_workspace(self.base, VENDOR_ROWS)
        self.lock(rows=[{**VENDOR_ROWS[0], "sha256": "0" * 64}, VENDOR_ROWS[1]])
        with self.assertRaisesRegex(gate.GateError, "checksum of rustls"):
            gate.check_workspace(self.base, VENDOR_ROWS)
        self.lock(rows=[{**VENDOR_ROWS[0], "dependencies": ["ring", "log"]}, VENDOR_ROWS[1]])
        with self.assertRaisesRegex(gate.GateError, "dependencies of rustls"):
            gate.check_workspace(self.base, VENDOR_ROWS)
        self.lock(extra='[[package]]\nname = "log"\nversion = "0.4.0"\nsource = "%s"\nchecksum = "00"\n' % gate.REGISTRY)
        with self.assertRaisesRegex(gate.GateError, "outside the vendor table"):
            gate.check_workspace(self.base, VENDOR_ROWS)
        self.lock(extra='[[package]]\nname = "x"\nversion = "1.0.0"\nsource = "git+https://example.invalid/x"\n')
        with self.assertRaisesRegex(gate.GateError, "registry or git"):
            gate.check_workspace(self.base, VENDOR_ROWS)


PATCH_ROWS = ([{"name": name, "version": version, "role": "LINKED", "sha256": fake_sha(name),
                "dependencies": ["cc"] if name == "ring" else []} for name, version in gate.PATCH_CRATES]
              + [{"name": "cc", "version": "1.8.0", "role": "BUILD_HOST", "sha256": fake_sha("cc"), "dependencies": []}])
PATCH_MANIFEST = ("\n[patch.crates-io]\n" + "".join('%s = { path = "vendor/%s-%s" }\n' % (name, name, version)
                                                     for name, version in gate.PATCH_CRATES))


class PatchTableTests(unittest.TestCase):
    """HE-003D DESIGN sections 2 and 5: the [patch] table is exactly the 11 LINKED vendored crates' vendor/ paths, and
    in Cargo.lock they are path packages with their vendor rows' versions and edges; the other vendor rows stay registry
    packages with their checksums."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        for name in ("a", "gate-tls"):
            (self.base / "crates" / name / "src").mkdir(parents=True)
        (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n')
        (self.base / "crates/gate-tls/Cargo.toml").write_text(GATE_TLS_MANIFEST)
        self.workspace()
        self.lock()

    def tearDown(self):
        self.directory.cleanup()

    def workspace(self, table=PATCH_MANIFEST):
        (self.base / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/a", "crates/gate-tls"]\n' + table)

    def lock(self, patched=None, registry=None, extra=""):
        text = 'version = 4\n\n[[package]]\nname = "a"\nversion = "0.1.0"\n\n[[package]]\nname = "gate-tls"\nversion = "0.1.0"\n\n'
        for row in PATCH_ROWS[:-1] if patched is None else patched:
            text += ('[[package]]\nname = "%s"\nversion = "%s"\ndependencies = [%s]\n\n'
                     % (row["name"], row["version"], ", ".join('"%s"' % d for d in row["dependencies"])))
        for row in PATCH_ROWS[-1:] if registry is None else registry:
            text += ('[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\n\n'
                     % (row["name"], row["version"], gate.REGISTRY, row["sha256"]))
        (self.base / "Cargo.lock").write_text(text + extra)

    def check(self):
        return gate.check_workspace(self.base, PATCH_ROWS)

    def test_the_table_and_the_lock_pass(self):
        self.assertEqual(self.check(), {"a": set(), "gate-tls": {"a"}})
        self.assertEqual(len(gate.PATCH_CRATES), 11)

    def test_the_patch_table_is_exact(self):
        message = "patch. or .replace"
        first = '%s = { path = "vendor/%s-%s" }\n' % (gate.PATCH_CRATES[0][0], gate.PATCH_CRATES[0][0], gate.PATCH_CRATES[0][1])
        for table in ("", PATCH_MANIFEST.replace(first, ""), PATCH_MANIFEST + 'cc = { path = "vendor/cc-1.8.0" }\n',
                      PATCH_MANIFEST.replace('"vendor/ring-0.17.14"', '"vendor/ring-0.17.13"'),
                      PATCH_MANIFEST.replace('"vendor/ring-0.17.14"', '"/abs/vendor/ring-0.17.14"'),
                      PATCH_MANIFEST.replace('ring = { path = "vendor/ring-0.17.14" }',
                                             'ring = { git = "https://example.invalid/ring" }'),
                      PATCH_MANIFEST.replace('ring = { path = "vendor/ring-0.17.14" }',
                                             'ring = { path = "vendor/ring-0.17.14", version = "0.17.14" }'),
                      PATCH_MANIFEST + '\n[patch."https://example.invalid/index"]\nx = { path = "x" }\n',
                      PATCH_MANIFEST + '\n[replace]\n"ring:0.17.14" = { path = "x" }\n'):
            self.workspace(table)
            with self.assertRaisesRegex(gate.GateError, message):
                self.check()
        # Without LINKED rows (no vendored crate to patch) any [patch] refuses, as before HE-003D.
        self.workspace()
        with self.assertRaisesRegex(gate.GateError, message):
            gate.check_workspace(self.base, PATCH_ROWS[-1:])

    def test_the_linked_rows_are_the_patch_crates(self):
        rows = [dict(row, role="BUILD_HOST") if row["name"] == "subtle" else row for row in PATCH_ROWS]
        with self.assertRaisesRegex(gate.GateError, "LINKED crates are not the .patch. table's"):
            gate.check_workspace(self.base, rows)

    def test_the_patched_packages_are_path_packages(self):
        ring = next(row for row in PATCH_ROWS if row["name"] == "ring")
        others = [row for row in PATCH_ROWS[:-1] if row["name"] != "ring"]
        self.lock(patched=others)
        with self.assertRaisesRegex(gate.GateError, "exactly the patched vendored crates as path packages"):
            self.check()
        self.lock(patched=others, registry=PATCH_ROWS[-1:] + [ring])
        with self.assertRaisesRegex(gate.GateError, "exactly the patched vendored crates as path packages"):
            self.check()
        self.lock(patched=others + [dict(ring, dependencies=["cc", "spin"])])
        with self.assertRaisesRegex(gate.GateError, "dependencies of the patched ring"):
            self.check()
        self.lock(patched=others + [dict(ring, version="0.17.13")])
        with self.assertRaisesRegex(gate.GateError, "exactly the (workspace crates|patched vendored crates)"):
            self.check()
        self.lock(extra='[[package]]\nname = "zeroize"\nversion = "1.9.1"\nchecksum = "%s"\n' % fake_sha("zeroize"))
        with self.assertRaisesRegex(gate.GateError, "exactly the (workspace crates|patched vendored crates)"):
            self.check()

    def test_the_other_rows_stay_registry_packages(self):
        self.lock(registry=[])
        with self.assertRaisesRegex(gate.GateError, "outside the vendor table"):
            self.check()
        self.lock(registry=[dict(PATCH_ROWS[-1], sha256="0" * 64)])
        with self.assertRaisesRegex(gate.GateError, "checksum of cc"):
            self.check()


class SbomVendorTests(unittest.TestCase):
    """HE-003B DESIGN section 2.7: a binary's SBOM lists the LINKED vendor rows its lock closure reaches."""

    LOCK = [{"name": "planeon-gate", "version": "0.1.0", "dependencies": ["gate-tls", "host-common"]},
            {"name": "planeon-broker", "version": "0.1.0", "dependencies": ["host-common"]},
            {"name": "host-common", "version": "0.1.0"}, {"name": "gate-tls", "version": "0.1.0", "dependencies": ["rustls"]},
            {"name": "rustls", "version": "0.23.46", "dependencies": ["ring"]},
            {"name": "ring", "version": "0.17.14", "dependencies": ["cc 1.8.0", "windows-sys"]},
            {"name": "cc", "version": "1.8.0"}, {"name": "windows-sys", "version": "0.52.0"}]
    ROWS = [{"name": name, "version": version, "role": role, "sha256": fake_sha(name), "canonical": "MIT",
             "outcome": "ACCEPTED_OR"}
            for name, version, role in (("rustls", "0.23.46", "LINKED"), ("ring", "0.17.14", "LINKED"),
                                        ("cc", "1.8.0", "BUILD_HOST"), ("windows-sys", "0.52.0", "LOCK_ONLY"))]

    def test_only_linked_rows_in_the_closure(self):
        closure = gate.lock_closure(self.LOCK, "planeon-gate")
        self.assertEqual(closure, {"planeon-gate", "host-common", "gate-tls", "rustls", "ring", "cc", "windows-sys"})
        components = gate.vendor_components(self.ROWS, closure)
        self.assertEqual([component["name"] for component in components], ["rustls", "ring"])
        self.assertEqual(components[1]["properties"][0]["value"], "host-enforcement/vendor/ring-0.17.14")
        self.assertEqual(gate.vendor_components(self.ROWS, gate.lock_closure(self.LOCK, "planeon-broker")), [])

    def test_a_binary_without_vendored_crates_keeps_its_sbom(self):
        before = gate.sbom("planeon-broker", X86, "ab" * 32, [], {"planeon-broker", "host-common"})
        after = gate.sbom("planeon-broker", X86, "ab" * 32, [], {"planeon-broker", "host-common"}, [])
        self.assertEqual(before, after)
        with_vendor = gate.sbom("planeon-gate", X86, "ab" * 32, [], {"planeon-gate"},
                                gate.vendor_components(self.ROWS, gate.lock_closure(self.LOCK, "planeon-gate")))
        names = [component["name"] for component in json.loads(with_vendor)["components"]]
        self.assertEqual(sorted(names), ["planeon-gate", "ring", "rustls"])


# ------------------------------------------------------------------------------------------ HE-004C (DESIGN-C section 15)

REGISTRY_TEXT = ('rustls = { version = "=0.23.46", default-features = false, features = ["ring", "std"] }\n'
                 'getrandom = { version = "=0.2.17", default-features = false, features = ["linux_disable_fallback"] }\n'
                 'zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }\n'
                 'ring = "=0.17.14"\n')
OBSERVER_MANIFEST = ('[package]\nname = "planeon-observer"\n\n[dependencies]\na = { path = "../a" }\n' + REGISTRY_TEXT
                     + '\n[dev-dependencies]\ngate-tls = { path = "../gate-tls" }\n')


class ObserverRegistryLineTests(unittest.TestCase):
    """HE-004C DESIGN-C sections 3 and 15 (G1, Q-HE4-5 (a)): crates/observer's registry lines are gate-tls's four, each
    exactly; its gate-tls dev-dependency is a path edge that check_workspace leaves out of the closure; any other form
    refuses."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        (self.base / "Cargo.toml").write_text('[workspace]\nmembers = ["crates/a", "crates/gate-tls", "crates/observer"]\n')
        for name in ("a", "gate-tls", "observer"):
            (self.base / "crates" / name / "src").mkdir(parents=True)
        (self.base / "crates/a/Cargo.toml").write_text('[package]\nname = "a"\n')
        (self.base / "crates/gate-tls/Cargo.toml").write_text(GATE_TLS_MANIFEST)
        self.manifest(OBSERVER_MANIFEST)
        text = 'version = 4\n\n'
        for name in ("a", "gate-tls", "planeon-observer"):
            text += '[[package]]\nname = "%s"\nversion = "0.1.0"\n\n' % name
        for row in VENDOR_ROWS:
            text += ('[[package]]\nname = "%s"\nversion = "%s"\nsource = "%s"\nchecksum = "%s"\ndependencies = [%s]\n\n'
                     % (row["name"], row["version"], gate.REGISTRY, row["sha256"], ", ".join('"%s"' % d for d in row["dependencies"])))
        (self.base / "Cargo.lock").write_text(text)

    def tearDown(self):
        self.directory.cleanup()

    def manifest(self, text):
        (self.base / "crates/observer/Cargo.toml").write_text(text)

    def test_the_observer_lines_pass_and_the_dev_edge_stays_outside(self):
        self.assertEqual(gate.REGISTRY_LINES["crates/observer"], gate.REGISTRY_LINES["crates/gate-tls"])
        self.assertEqual(set(gate.REGISTRY_LINES), {"crates/gate-tls", "crates/observer"})
        self.assertEqual(gate.check_workspace(self.base, VENDOR_ROWS),
                         {"a": set(), "gate-tls": {"a"}, "planeon-observer": {"a"}})

    def test_the_observer_lines_are_exact(self):
        for old, new, name in (('"=0.23.46"', '"0.23.46"', "rustls"),
                               ('features = ["ring", "std"]', 'features = ["ring", "std", "tls12"]', "rustls"),
                               ('default-features = false, features = ["linux_disable_fallback"]',
                                'default-features = true, features = ["linux_disable_fallback"]', "getrandom"),
                               ('zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }',
                                'zeroize = "=1.9.1"', "zeroize"),
                               ('ring = "=0.17.14"', 'ring = { version = "=0.17.14" }', "ring")):
            self.manifest(OBSERVER_MANIFEST.replace(old, new))
            with self.assertRaisesRegex(gate.GateError, "the registry dependency %s of crates/observer is not its pinned line"
                                        % name):
                gate.check_workspace(self.base, VENDOR_ROWS)
        for text in (OBSERVER_MANIFEST + 'untrusted = "=0.9.0"\n',
                     OBSERVER_MANIFEST.replace('gate-tls = { path = "../gate-tls" }', 'gate-tls = { path = "../gate-tls", version = "0.1.0" }'),
                     OBSERVER_MANIFEST.replace('ring = "=0.17.14"\n', "") + 'ring = "=0.17.14"\n'):
            self.manifest(text)
            with self.assertRaisesRegex(gate.GateError, "dependency outside the workspace"):
                gate.check_workspace(self.base, VENDOR_ROWS)


class ObserverClosureTests(Tree):
    """HE-004C DESIGN-C section 15 (G2): OBSERVER_LINKED_CRATES is unchanged by the client; a fifth workspace path
    dependency of planeon-observer still refuses (the gate-tls dev-dependency is not in check_workspace's result)."""

    TREE = {**WORKSPACE_TREE,
            "Cargo.toml": WORKSPACE_TREE["Cargo.toml"].replace('"crates/gate-tls"]',
                                                               '"crates/gate-tls", "crates/observer", "crates/observer-sys"]'),
            "crates/observer/Cargo.toml": '[package]\nname = "planeon-observer"\nedition.workspace = true\n',
            # HE-004D1 (G-D1-1): observer-sys joins the closure.
            "crates/observer-sys/Cargo.toml": '[package]\nname = "observer-sys"\nedition.workspace = true\n'}

    def test_a_fifth_workspace_path_dependency_refuses(self):
        self.assertEqual(gate.OBSERVER_LINKED_CRATES, ("crates/observer", "crates/gate-sys", "crates/i05-protocol",
                                                       "crates/observer-sys"))
        good = {**WORKSPACE, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys"}, "observer-sys": set()}
        self.assertEqual(gate.check_workspace_shape(self.base, good), 7)
        for extra in ("gate-tls", "effect-gate", "planeon-gate"):
            with self.assertRaisesRegex(gate.GateError, "planeon-observer links .*, not .* .workspace shape"):
                gate.check_workspace_shape(self.base, {**good, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys",
                                                                                    extra}})


OBSERVER_TLS_TREE = {"crates/gate-tls/src/lib.rs": "#![forbid(unsafe_code)]\npub mod tls;\n",
                     "crates/gate-tls/src/tls.rs": GOOD_TLS,
                     "crates/gate-tls/src/tls_client.rs": GOOD_CLIENT,
                     "crates/gate-tls/src/exchange.rs": GOOD_EXCHANGE,
                     gate.OBSERVER_TLS: GOOD_OBSERVER_TLS,
                     "crates/observer/src/client.rs": "//! The driver.\npub fn drive() {}\n",
                     "crates/observer/tests/c_support/mod.rs": "// tests build a ServerConfig, with_single_cert, macro_rules\n"}


class ObserverTlsTests(Tree):
    """HE-004C DESIGN-C section 15 (G3, D1-14 (b)): check_tls reads two groups; group O, crates/observer, holds none of the
    deny-list nor the server-side tokens (raw text, comments included), sets its three client settings exactly once,
    names the client authentication and the webpki verifier once each in its tls.rs and defines no macro_rules; the
    counts are per group."""

    TREE = OBSERVER_TLS_TREE

    def test_the_two_groups_pass(self):
        self.assertEqual(gate.check_observer_tls(self.base), 2)
        self.assertEqual(gate.check_tls(self.base), 6)

    def test_group_o_refuses_the_deny_list_and_the_server_side(self):
        client = "crates/observer/src/client.rs"
        for rel in (gate.OBSERVER_TLS, client):
            base = self.TREE[rel]
            for line in ("let _ = ClientConfig::builder();", "let b = b.dangerous();", "config.key_log = k;",
                         "let _ = Resumption::store(s);", "let c = b.with_client_cert_resolver(r);",
                         "let _ = ClientSessionMemoryCache::new(8);", "let b = b.with_ech(mode);",
                         "fn r() { b.with_root_certificates(x); }", "let _ = CryptoProvider::get_default();",
                         "// SSLKEYLOGFILE",
                         # The server-side list (the observer is client-only).
                         "let _: Option<ServerConfig> = None;", "let s = ServerConnection::new(c);",
                         "let v = WebPkiClientVerifier::builder_with_provider(r, p);", "let b = b.with_cert_resolver(r);",
                         "let b = b.with_single_cert(c, k);", "config.max_early_data_size = 0;",
                         "config.send_tls13_tickets = 0;", "config.send_half_rtt_data = false;",
                         "config.session_storage = s;", "let _ = NoServerSessionStorage {};",
                         "let _ = SingleCertAndKey::from(k);", "impl ResolvesServerCert for R {}",
                         "// a ServerConfig named in a comment"):
                self.refused(gate.check_tls, rel, base + line + "\n", "names .* .TLS deny-list, group O")
        # The tests are outside the rule; the gate's group may hold its server settings.
        self.assertEqual(gate.check_tls(self.base), 6)

    def test_group_o_sets_each_client_setting_exactly_once(self):
        tls = gate.OBSERVER_TLS
        message = "crates/observer does not set %s exactly once, as the closed setting .TLS deny-list, group O"
        for name, line in (("resumption", "    config.resumption = Resumption::disabled();\n"),
                           ("enable_early_data", "    config.enable_early_data = false;\n"),
                           ("enable_sni", "    config.enable_sni = false;\n")):
            self.refused(gate.check_tls, tls, GOOD_OBSERVER_TLS.replace(line, ""), message % name)
            self.refused(gate.check_tls, tls, GOOD_OBSERVER_TLS.replace(line, "    // " + line.strip() + "\n"), message % name)
            self.refused(gate.check_tls, tls, GOOD_OBSERVER_TLS + line, message % name)
            self.refused(gate.check_tls, "crates/observer/src/client.rs", self.TREE["crates/observer/src/client.rs"] + line,
                         message % name)
        for old, new, name in (("enable_early_data = false", "enable_early_data = true", "enable_early_data"),
                               ("enable_sni = false", "enable_sni = true", "enable_sni"),
                               ("Resumption::disabled()", "Resumption::default()", "resumption")):
            self.refused(gate.check_tls, tls, GOOD_OBSERVER_TLS.replace(old, new), message % name)
        # The groups count apart: the gate's client settings missing still refuses in group G.
        self.refused(gate.check_tls, "crates/gate-tls/src/tls_client.rs",
                     GOOD_CLIENT.replace("    config.enable_sni = false;\n", ""), "gate-tls does not set enable_sni exactly once")
        self.write(tls, GOOD_OBSERVER_TLS.replace("config.enable_sni = false;", "config.enable_sni=false;"))
        self.assertEqual(gate.check_tls(self.base), 6)

    def test_group_o_names_the_authentication_and_the_verifier_once_in_tls_rs(self):
        tls, client = gate.OBSERVER_TLS, "crates/observer/src/client.rs"
        for name, call in (("with_client_auth_cert", ".with_client_auth_cert(chain, key)"),
                           ("with_webpki_verifier", ".with_webpki_verifier(verifier)")):
            message = "crates/observer does not mention %s exactly once, in tls.rs .TLS deny-list, group O" % name
            self.refused(gate.check_tls, tls, GOOD_OBSERVER_TLS.replace(call, ""), message)
            self.refused(gate.check_tls, tls, GOOD_OBSERVER_TLS + "fn again() { x%s; }\n" % call, message)
            self.refused(gate.check_tls, client, self.TREE[client] + "fn other() { x%s; }\n" % call, message)
            self.refused(gate.check_tls, tls, GOOD_OBSERVER_TLS.replace(call, "/* %s */" % call), message)
        (self.base / tls).rename(self.base / "crates/observer/src/profile.rs")
        with self.assertRaisesRegex(gate.GateError, "crates/observer has no tls.rs .TLS deny-list, group O"):
            gate.check_tls(self.base)

    def test_group_o_defines_no_macro_and_has_sources(self):
        self.refused(gate.check_tls, "crates/observer/src/client.rs", "macro_rules! m { () => {} }\n",
                     "defines a macro with macro_rules .TLS deny-list, group O")
        for rel in (gate.OBSERVER_TLS, "crates/observer/src/client.rs"):
            (self.base / rel).unlink()
        with self.assertRaisesRegex(gate.GateError, "crates/observer has no sources .TLS deny-list, group O"):
            gate.check_tls(self.base)


class ObserverSocketModuleTests(Tree):
    """HE-004C DESIGN-C section 15 (G4, D1-14 (a)): the observer's linux_net.rs is the one crates/observer source that may
    reach gate-sys's channel and tcp modules, re-exports nothing and names their items in no pub signature, field or
    alias; every other observer source still refuses them."""

    TREE = SOCKET_TREE

    def test_the_observer_socket_module_passes(self):
        self.assertIn(gate.OBSERVER_LINUX_NET, gate.SOCKET_FILES)
        self.assertEqual(gate.OBSERVER_LINUX_NET, "crates/observer/src/linux_net.rs")
        self.assertEqual(gate.check_socket_modules(self.base), 16)

    def test_every_other_observer_source_refuses_the_socket_modules(self):
        for rel in ("crates/observer/src/client.rs", "crates/observer/src/observe.rs", gate.OBSERVER_MAIN,
                    "crates/observer/src/lib.rs"):
            prefix = SOCKET_TREE.get(rel, "")
            for text in ("use gate_sys::tcp::TcpConn;", "use gate_sys::channel::{Poller, Ready};", "use gate_sys::{self, tcp};",
                         "use gate_sys::*;", "fn f() { gate_sys :: tcp :: connect_tcp(a); }",
                         "type R = gate_sys::channel::Ready;"):
                self.refused(gate.check_socket_modules, rel, prefix + text + "\n", "socket-module check")

    def test_the_observer_socket_module_hands_out_nothing(self):
        rel = gate.OBSERVER_LINUX_NET
        for text, message in (("pub use gate_sys::tcp::TcpConn;", "re-exports"),
                              ("pub(crate) use gate_sys::channel::Poller;", "re-exports"),
                              ("pub fn raw(w: &LinuxWire) -> &TcpConn { x() }", "pub item naming gate-sys's socket items"),
                              ("pub fn poller(w: &LinuxWire) -> &channel::Poller { x() }", "pub item naming gate-sys's socket items"),
                              ("pub struct Leak { pub conn: TcpConn }", "pub field naming gate-sys's socket items"),
                              ("type Conn = TcpConn;", "private type alias"),
                              ("pub enum Held { C(channel::Ready) }", "pub enum variant naming")):
            self.refused(gate.check_socket_modules, rel, OBSERVER_LINUX_NET_TEXT + text + "\n", message)
        (self.base / rel).unlink()
        with self.assertRaisesRegex(gate.GateError, "crates/observer/src/linux_net.rs is missing .socket-module check"):
            gate.check_socket_modules(self.base)


# HE-004D1 (G-D1-8): twelve steps, one call each.
SERVE_STEPS = (
    "    let document = match signed_config::load() {\n        Ok(document) => document,\n"
    "        Err(error) => return status::config_load(&error),\n    };\n",
    "    let Ok((config, record_ref)) = ObserverConfig::parse_with_record(&document) else { return status::CONFIG_CHECK };\n"
    "    drop(document);\n",
    "    if let Err(error) = config::check_lifetime(&config, utc::wall_seconds()) {\n        return status::lifetime(&error);\n    }\n",
    "    let Ok((serving_ca, identity)) = credentials::observer_inputs(&config.credentials) else { return status::CREDENTIALS };\n",
    "    let Ok(tls) = client_config(identity, serving_ca, time_provider()) else { return status::TLS_SETUP };\n",
    "    let Ok((schema, record_schema)) = CaptureSchema::embedded() else { return status::CAPTURE_SCHEMA };\n",
    "    let record = match enrolled::load_record(&record_ref) {\n        Ok(record) => record,\n"
    "        Err(error) => return status::capture_setup(&error),\n    };\n",
    "    let enrolled = match Enrolled::new(record, &record_schema, utc::wall_seconds()) {\n        Ok(enrolled) => enrolled,\n"
    "        Err(error) => return status::capture_setup(&error),\n    };\n    drop(record_schema);\n",
    "    let Ok(wire) = LinuxWire::new(sealed) else { return status::SOCKETS };\n",
    "    let capture = match LinuxCapture::new(sealed) {\n        Ok(capture) => capture,\n"
    "        Err(error) => return status::capture_setup(&error),\n    };\n",
    "    let Ok(closure) = Closure::embedded() else { return status::CLOSURE };\n",
    "    let captures = Box::new(CaptureEngine::new(capture, enrolled, schema));\n"
    "    status::observation(&observe::run(wire, config, tls, closure, captures))\n",
)


class ObserverServeTests(Tree):
    """HE-004C DESIGN-C sections 14 and 15 (G5's wiring rule, D1-1): serve calls the configuration's load, parse and
    lifetime, the credentials, the TLS configuration, the wire, the embedded closure and the epoch each exactly once, in
    that order; missing, swapped and doubled calls refuse, and comments, use declarations and spaced paths are read
    through."""

    TREE = {gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN}

    def test_the_wiring_passes(self):
        self.assertEqual("".join(SERVE_STEPS) in GOOD_OBSERVER_MAIN, True)
        self.assertEqual(gate.check_observer_serve(self.base), 12)
        self.assertEqual([name for _, name in gate.OBSERVER_WIRING],
                         ["signed_config::load(", "ObserverConfig::parse_with_record(", "config::check_lifetime(",
                          "credentials::observer_inputs(", "client_config(", "CaptureSchema::embedded(",
                          "enrolled::load_record(", "Enrolled::new(", "LinuxWire::new(", "LinuxCapture::new(",
                          "Closure::embedded(", "observe::run("])
        # Spaced paths, comments naming the calls and the in-body use declarations are read through.
        spaced = (GOOD_OBSERVER_MAIN.replace("signed_config::load()", "signed_config :: load ()")
                  .replace("Closure::embedded()", "Closure ::embedded ( )")
                  .replace("    use planeon_observer::utc;\n", "    use planeon_observer::utc;\n    // observe::run( again in a comment\n"))
        self.write(gate.OBSERVER_MAIN, spaced)
        self.assertEqual(gate.check_observer_serve(self.base), 12)

    def test_each_call_missing_refuses(self):
        body = "".join(SERVE_STEPS)
        for index, (_, name) in enumerate(gate.OBSERVER_WIRING):
            steps = list(SERVE_STEPS)
            del steps[index]
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace(body, "".join(steps)),
                         "serve does not call %s exactly once" % re.escape(name))

    def test_each_adjacent_pair_swapped_refuses(self):
        body = "".join(SERVE_STEPS)
        for index in range(len(SERVE_STEPS) - 1):
            steps = list(SERVE_STEPS)
            steps[index], steps[index + 1] = steps[index + 1], steps[index]
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace(body, "".join(steps)),
                         "serve does not call .* in this order .observer wiring order")

    def test_each_call_doubled_refuses(self):
        body = "".join(SERVE_STEPS)
        for index, (_, name) in enumerate(gate.OBSERVER_WIRING):
            steps = list(SERVE_STEPS)
            steps.insert(index, SERVE_STEPS[index])
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace(body, "".join(steps)),
                         "serve does not call %s exactly once" % re.escape(name))

    def test_bypass_forms_refuse(self):
        for old, new in (("observe::run(", "planeon_observer::observe::run("), ("client_config(identity", "tls::client_config(identity"),
                         ("config::check_lifetime(&config", "planeon_observer::config::check_lifetime(&config"),
                         ("LinuxWire::new(sealed)", "<LinuxWire>::new(sealed)"),
                         ("Closure::embedded()", "embedded_closure()")):
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace(old, new, 1),
                         "exactly once|in this order")
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace("fn serve(", "fn other("),
                     "does not hold exactly one fn serve")
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN + "fn serve(s: &Sealed) -> u8 { 0 }\n",
                     "does not hold exactly one fn serve")


class ObserverKeyIncludeTests(Tree):
    """HE-004C DESIGN-C sections 11 and 15 (G6, Q-HE4C-3 (i)): the observer's signed_config.rs holds exactly one include,
    include_bytes!("../config-signer.pub"), and nothing else is admitted; both signer key files are 0 or 32 bytes."""

    TREE = {**INCLUDE_TREE,
            gate.OBSERVER_SIGNED_CONFIG: "pub const COMPILED_KEY: &[u8] = include_bytes!(\"../config-signer.pub\");\n"}

    def test_the_key_include_passes(self):
        self.assertEqual((gate.OBSERVER_SIGNED_CONFIG, gate.OBSERVER_KEY_INCLUDE),
                         ("crates/observer/src/signed_config.rs", "../config-signer.pub"))
        self.assertEqual(gate.check_observer_includes(self.base), 4)

    def test_other_key_forms_refuse(self):
        rel = gate.OBSERVER_SIGNED_CONFIG
        good = self.TREE[rel]
        for text, message in (
                ("pub const K: &[u8] = include_str!(\"../config-signer.pub\");\n", "something other than exactly include_bytes"),
                ("pub const K: &[u8] = include_bytes!(\"../../gate-tls/config-signer.pub\");\n", "something other than exactly"),
                (good + "pub const S: &[u8] = include_bytes!(\"../config-signer.pub\");\n", "something other than exactly"),
                (good + "pub const C: &[u8] = include_bytes!(\"../../../contracts/i06-v2/README.md\");\n",
                 "something other than exactly"),
                ("pub const K: &[u8] = include_bytes!(concat!(\"../\", \"config-signer.pub\"));\n", "not one plain path literal")):
            self.refused(gate.check_observer_includes, rel, text, message)
        self.refused(gate.check_observer_includes, "crates/observer/src/config.rs", good,
                     "only crates/observer/src/contracts.rs embeds")

    def test_both_signer_keys_are_zero_or_thirty_two_bytes(self):
        self.assertEqual(gate.SIGNER_KEYS, ("crates/gate-tls/config-signer.pub", "crates/observer/config-signer.pub"))
        for rel in gate.SIGNER_KEYS:
            path = self.base / rel
            with self.assertRaisesRegex(gate.GateError, "%s is missing .signer key" % re.escape(rel)):
                gate.check_signer_key(self.base, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            for size in (0, 32):
                path.write_bytes(b"\x42" * size)
                self.assertEqual(gate.check_signer_key(self.base, rel), size)
            for size in (1, 31, 33, 64):
                path.write_bytes(b"\x42" * size)
                with self.assertRaisesRegex(gate.GateError, "%s holds %d bytes, not 0 or 32" % (re.escape(rel), size)):
                    gate.check_signer_key(self.base, rel)
            path.write_bytes(b"")


GOOD_CONTRACTS_MODULE = (
    "//! The contract data (a comment may name fn, static and mod).\n"
    "/// The identity closure.\n"
    "pub const IDENTITY_CLOSURE: &[u8] = include_bytes!(\"../../../contracts/i06-v1/identity-closure.json\");\n"
    "/// Its registered sha256.\n"
    "pub const IDENTITY_CLOSURE_SHA256: &str = \"0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb\";\n"
    "pub const I07_V3_POLICY_KINDS_SHA256: &str =\n    \"4e427204b89959cb855d8641c3fa6f95d358b0b6a6a7730bfc7776adc4a173c0\";\n")


class ContractsPinTests(Tree):
    """HE-004C DESIGN-C section 15 (G7; HE-004B1 PR review R1-3): contracts.rs holds only pub consts of a registered
    contract file's bytes and of registered pins, with doc comments; a fn, a use, a static, another type, an unpinned
    value, an attribute or a mod refuses."""

    TREE = {gate.OBSERVER_CONTRACTS: GOOD_CONTRACTS_MODULE}

    def test_the_module_passes(self):
        self.assertEqual(gate.check_observer_contracts_module(self.base), 3)
        self.write(gate.OBSERVER_CONTRACTS, GOOD_CONTRACTS_MODULE.replace(": &[u8] = include_bytes!(", " :&[ u8 ]=include_bytes! ("))
        self.assertEqual(gate.check_observer_contracts_module(self.base), 3)

    def test_other_items_refuse(self):
        rel = gate.OBSERVER_CONTRACTS
        message = "contracts pin"
        for text in ("pub fn closure() -> &'static [u8] { IDENTITY_CLOSURE }",
                     "pub use crate::inputs::Resource;", "use std::fmt;",
                     "pub static S: &[u8] = include_bytes!(\"../../../contracts/i06-v1/README.md\");",
                     "pub const N: &[u16] = &[];", "pub const T: &'static str = \"x\";", "pub const U: usize = 3;",
                     "pub const P: &str = \"" + "a" * 64 + "\";",
                     "pub const Q: &str = \"0a9b82ff\";",
                     "#[doc = \"x\"]", "#[allow(dead_code)]\npub const V: &str = \"0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb\";",
                     "mod inner {}", "const PRIVATE: &str = \"0a9b82ffa2d63bf48a8850574cdf3ece02bf1913f33a72cbb96ed30a40f1f3bb\";",
                     "pub const B: &[u8] = include_bytes!(\"../../../tools/gate.py\");",
                     "pub const C: &[u8] = include_str!(\"../../../contracts/i06-v1/README.md\");"):
            self.refused(gate.check_observer_contracts_module, rel, GOOD_CONTRACTS_MODULE + text + "\n", message)
        (self.base / rel).unlink()
        with self.assertRaisesRegex(gate.GateError, "contracts.rs is missing .contracts pin"):
            gate.check_observer_contracts_module(self.base)


class ObserverNoPanicTests(Tree):
    """HE-004C DESIGN-C section 15 (G8, D1-14 (c)): the no-panic tripwire covers every HE-004C module and the changed
    main.rs and status.rs: no panicking macro or call outside strict #[cfg(test)] mod tests blocks; each file required."""

    TREE = {rel: "//! unwrap(), expect( and panic! in a comment pass.\npub fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }\n"
            for rel in gate.OBSERVER_NO_PANIC + gate.OBSERVER_SYS_NO_PANIC}

    def test_the_tree_passes(self):
        self.assertEqual(len(gate.OBSERVER_C_MODULES), 13)
        self.assertEqual(gate.check_observer_no_panic(self.base), 21)

    def test_each_source_is_required(self):
        for rel in gate.OBSERVER_NO_PANIC:
            (self.base / rel).unlink()
            with self.assertRaisesRegex(gate.GateError, "%s is missing .observer no-panic tripwire" % re.escape(rel)):
                gate.check_observer_no_panic(self.base)
            self.write(rel, self.TREE[rel])

    def test_panics_refuse_outside_strict_test_blocks(self):
        for rel in ("crates/observer/src/client.rs", "crates/observer/src/linux_net.rs", gate.OBSERVER_MAIN,
                    gate.OBSERVER_STATUS):
            good = self.TREE[rel]
            for text in ("fn g(x: Option<u8>) -> u8 { x.unwrap() }", "fn g(x: Option<u8>) -> u8 { x.expect(\"some\") }",
                         "fn g() { panic!(\"x\"); }", "fn g() { unreachable!() }", "fn g() { todo!() }",
                         "fn g() { assert!(true); }", "fn g() { assert_eq!(1, 1); }", "fn g() { debug_assert!(true); }",
                         "fn g() -> u8 { Some(1) . unwrap ( ) }"):
                self.refused(gate.check_observer_no_panic, rel, good + text + "\n", "observer no-panic tripwire")
            self.refused(gate.check_observer_no_panic, rel, good + "#[cfg(test)] mod tests {\n    fn t() { panic!(); }\n}\n",
                         "observer no-panic tripwire")
            self.write(rel, good + "#[cfg(test)]\nmod tests {\n    fn t() { assert_eq!(1, 1); Some(1).unwrap(); }\n}\n")
            self.assertEqual(gate.check_observer_no_panic(self.base), 21)
            self.write(rel, good)


class ObserverSymbolTests(unittest.TestCase):
    """HE-004C DESIGN-C section 15 (G9, D1-6, D2-8; Q-HE4C-12 (a)): planeon-observer's .symtab holds a rustls symbol
    naming ClientConnection (or the recorded substitute of the client handshake modules) and a planeon_observer client,
    http, watch or observe symbol, each read by its own path down to its first crate root; each missing refuses, and a
    generic instantiation of another crate's item never counts. The v0 names are as the shipped builds hold them."""

    CLIENT = ("_ZN6rustls6client11client_conn16ClientConnection3new17h0123456789abcdefE",
              "_RNvMs_NtNtCs1a2b3c4d5e6_6rustls6client11client_connNtB4_16ClientConnection3new")
    SUBSTITUTE = ("_RNvNtNtCsjLitWopGBcO_6rustls6client2hs27emit_client_hello_for_retry",
                  "_RNvNtNtCsjLitWopGBcO_6rustls6client5tls1319handle_server_hello",
                  "_RNvXs_NtNtCsjLitWopGBcO_6rustls6client2hsNtB4_17ExpectServerHelloINtNtB8_12common_state5StateNtNtB6_"
                  "11client_conn20ClientConnectionDataE6handle",
                  "_RNvYNtNtNtCsjLitWopGBcO_6rustls6client5tls1314ExpectFinishedINtNtB8_12common_state5StateNtNtB6_11client_"
                  "conn20ClientConnectionDataE19into_owned",
                  "_ZN6rustls6client5tls1325ExpectCertificateVerify6handle17h0123456789abcdefE")
    MODULE = ("_RINvNtCs5pXa2Z9YbGW_16planeon_observer7observe3runNtNtB4_9linux_net9LinuxWireECsizgaKzn5tVV_16planeon_observer",
              "_RNvMs1_NtCs5pXa2Z9YbGW_16planeon_observer6clientINtB5_6ClientNtNtB7_9linux_net9LinuxWireE4pollCsizgaKzn5tVV_"
              "16planeon_observer",
              "_RNvMs_NtCs5pXa2Z9YbGW_16planeon_observer4httpNtB4_6Framer4push",
              "_RNvNtCs5pXa2Z9YbGW_16planeon_observer5watch8classify",
              "_ZN16planeon_observer7observe3run17h0123456789abcdefE")
    # Instantiations rooted in another crate, names that merely mention the paths, and other paths: none counts.
    NOT_CLIENT = ("_RINvNtCsifRdLFh1usa_4core3ptr9drop_glueNtNtNtCsjLitWopGBcO_6rustls6client2hs17ExpectServerHelloEBH_",
                  "_RINvNtCsifRdLFh1usa_4core3ptr9drop_glueNtNtNtCsjLitWopGBcO_6rustls6client11client_conn16ClientConnectionE",
                  "_RNvNtNtCsjLitWopGBcO_6rustls6server2hs4read",
                  "_RNvXs_NtNtCsjLitWopGBcO_6rustls6client11client_connNtB4_20ClientConnectionData4drop",
                  "_ZN7myrustls6client2hs4read17h0123456789abcdefE", "_ZN6rustls6common5Codec4read17hE")
    NOT_MODULE = ("_RINvMs10_NtNtNtCskCQYDStZNxl_5alloc11collections5btree4nodeINtB7_16BalancingContextyNtNtCs5pXa2Z9YbGW_"
                  "16planeon_observer6client4LinkE25merge_tracking_child_edgeNtNtBd_5alloc6GlobalECsizgaKzn5tVV_16planeon_observer",
                  "_RNvNtCs5pXa2Z9YbGW_16planeon_observer4main", "_RNvNtCs5pXa2Z9YbGW_16planeon_observer4seal5stage",
                  "_RNvNtCs5pXa2Z9YbGW_16planeon_observer9linux_net4wait", "_ZN16planeon_observer5serve17hE",
                  "_ZN8planeon_7observe3run17hE", "main")

    def test_symbol_paths(self):
        self.assertEqual(gate.symbol_path(self.SUBSTITUTE[0])[0], ("rustls", "client", "hs", "emit_client_hello_for_retry"))
        self.assertEqual(gate.symbol_path(self.MODULE[1])[0], ("planeon_observer", "client"))
        self.assertEqual(gate.symbol_path(self.NOT_MODULE[0])[0][:2], ("alloc", "collections"))
        self.assertEqual(gate.symbol_path(self.CLIENT[0])[0][:4], ("rustls", "client", "client_conn", "ClientConnection"))
        self.assertEqual(gate.symbol_path("main"), ((), ""))
        self.assertEqual(gate.symbol_path("_RNvXsZ"), ((), ""))

    def test_the_symbols_pass(self):
        for client in self.CLIENT:
            for module in self.MODULE:
                self.assertEqual(gate.check_observer_symbols({"main", client, module}), ("ClientConnection", module))
        for substitute in self.SUBSTITUTE:
            self.assertEqual(gate.check_observer_symbols({substitute, self.MODULE[0]}), ("substitute", self.MODULE[0]))

    def test_each_symbol_missing_refuses(self):
        for names in ({"main", self.MODULE[0]}, set(self.NOT_CLIENT) | {self.MODULE[1]}):
            with self.assertRaisesRegex(gate.GateError, "no rustls ClientConnection symbol and no recorded substitute"):
                gate.check_observer_symbols(names)
        for names in ({self.CLIENT[0]}, set(self.NOT_MODULE) | {self.SUBSTITUTE[0]}):
            with self.assertRaisesRegex(gate.GateError, "no planeon_observer client, http, watch or observe symbol"):
                gate.check_observer_symbols(names)


class ObserverDebugTests(Tree):
    """HE-004C DESIGN-C section 15 (G10): the observer's identity, key holder and credential helper are secret types, and
    its wire joins the Debug hazards."""

    TREE = SECRET_TREE

    def test_the_observer_types_refuse(self):
        rel = "crates/observer/src/extra.rs"
        for text in ("#[derive(Debug)]\npub struct ObserverIdentity { key: Vec<u8> }",
                     "#[derive(Clone, Debug)]\npub struct ObserverKeyBytes(Zeroizing<Vec<u8>>);",
                     "#[cfg_attr(test, derive(Debug))]\npub struct ObserverCredential { size: usize }"):
            self.refused(gate.check_debug_derives, rel, text + "\n", "a secret type .Debug check")
        for text, hazard in (("#[derive(Debug)]\nstruct S { identity: ObserverIdentity }", "ObserverIdentity"),
                             ("#[derive(Debug)]\nenum E { K(ObserverKeyBytes) }", "ObserverKeyBytes"),
                             ("#[derive(Debug)]\nstruct S { opened: Option<ObserverCredential> }", "ObserverCredential"),
                             ("#[derive(Debug)]\nstruct Epoch { client: Client<LinuxWire> }", "LinuxWire")):
            self.refused(gate.check_debug_derives, rel, text + "\n", "mention %s .Debug check" % hazard)


# --- HE-004D1 (DESIGN-D1 rev 4 section 19): observer-sys, the capture wiring and the exempt span ---------------------

OBSERVER_SYS_LIB_TEXT = "//! Kernel reads.\n#![deny(unsafe_code)]\npub mod dirent;\npub mod kernel;\n"
OBSERVER_SYS_DIRENT = "crates/observer-sys/src/dirent.rs"
OBSERVER_SYS_DIRENT_TEXT = "pub const DT_DIR: u8 = 4;\npub fn entries(buffer: &[u8]) -> usize { buffer.len() }\n"
KERNEL = gate.OBSERVER_SYS_KERNEL
KERNEL_TEXT = """//! The kernel reads (a comment may name syscall(257, x) and SYS_WRITE).
#![allow(unsafe_code)]

use std::ffi::CStr;
use std::ffi::c_long;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

#[cfg(target_arch = "x86_64")]
mod numbers {
    use std::ffi::c_long;

    pub const SYS_OPENAT: c_long = 257;
    pub const SYS_GETDENTS64: c_long = 217;
    pub const SYS_READLINKAT: c_long = 267;
    pub const SYS_FSTATFS: c_long = 138;
    pub const SYS_IOCTL: c_long = 16;
    pub const SYS_BPF: c_long = 321;
    pub const O_DIRECTORY: c_long = 0o200000;
    pub const O_NOFOLLOW: c_long = 0o400000;
}

#[cfg(target_arch = "aarch64")]
mod numbers {
    use std::ffi::c_long;

    pub const SYS_OPENAT: c_long = 56;
    pub const SYS_GETDENTS64: c_long = 61;
    pub const SYS_READLINKAT: c_long = 78;
    pub const SYS_FSTATFS: c_long = 44;
    pub const SYS_IOCTL: c_long = 29;
    pub const SYS_BPF: c_long = 280;
    pub const O_DIRECTORY: c_long = 0o40000;
    pub const O_NOFOLLOW: c_long = 0o100000;
}

use numbers::*;

const O_RDONLY: c_long = 0;
const O_CLOEXEC: c_long = 0o2000000;
const O_NONBLOCK: c_long = 0o4000;
const O_PATH: c_long = 0o10000000;
const ZERO: c_long = 0;
const ROOT_PATH_FLAGS: c_long = O_PATH | O_DIRECTORY | O_CLOEXEC;
const DIR_FLAGS: c_long = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW;
const READ_FLAGS: c_long = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
const TARGET_FLAGS: c_long = O_PATH | O_CLOEXEC;
const _: () = assert!(ROOT_PATH_FLAGS & 0x400643 == 0);
const _: () = assert!(DIR_FLAGS & 0x400643 == 0);
const _: () = assert!(READ_FLAGS & 0x400643 == 0);
const _: () = assert!(TARGET_FLAGS & 0x400643 == 0);
const PROC_ROOT: &str = "/proc";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const FS_IOC_MEASURE_VERITY: c_long = 0xC004_6686;
const BPF_OBJ_GET: c_long = 7;
const BPF_OBJ_GET_INFO_BY_FD: c_long = 15;
const BPF_PROG_QUERY: c_long = 16;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

fn raw(handle: &File) -> c_long {
    c_long::from(handle.as_raw_fd())
}

fn open_dir(dirfd: c_long, path: &CStr) -> c_long {
    // SAFETY: a fixture.
    unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), DIR_FLAGS, ZERO, ZERO, ZERO) }
}

fn open_read(dirfd: c_long, path: &CStr) -> c_long {
    // SAFETY: a fixture.
    unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), READ_FLAGS, ZERO, ZERO, ZERO) }
}

fn listing(handle: &File, buffer: &mut [u8], length: c_long) -> c_long {
    // SAFETY: a fixture.
    unsafe { syscall(SYS_GETDENTS64, raw(handle), buffer.as_mut_ptr(), length, ZERO, ZERO, ZERO) }
}

fn magic(handle: &File, reply: *mut u8) -> c_long {
    // SAFETY: a fixture.
    unsafe { syscall(SYS_FSTATFS, raw(handle), reply, ZERO, ZERO, ZERO, ZERO) }
}

fn verity(handle: &File, reply: *mut u8) -> c_long {
    // SAFETY: a fixture.
    unsafe { syscall(SYS_IOCTL, raw(handle), FS_IOC_MEASURE_VERITY, reply, ZERO, ZERO, ZERO) }
}

fn programs(attr: *mut u8, size: c_long) -> [c_long; 3] {
    // SAFETY: a fixture.
    unsafe {
        [syscall(SYS_BPF, BPF_OBJ_GET, attr, size, ZERO, ZERO, ZERO),
         syscall(SYS_BPF, BPF_OBJ_GET_INFO_BY_FD, attr, size, ZERO, ZERO, ZERO),
         syscall(SYS_BPF, BPF_PROG_QUERY, attr, size, ZERO, ZERO, ZERO)]
    }
}

fn link_at(dir: &File, name: &CStr, buffer: &mut [u8]) -> c_long {
    let size = buffer.len() as c_long;
    // SAFETY: a fixture.
    unsafe { syscall(SYS_READLINKAT, raw(dir), name.as_ptr(), buffer.as_mut_ptr(), size, ZERO, ZERO) }
}

fn name(text: &'static str) -> &'static CStr {
    c"x"
}

pub enum CgroupFile {
    Procs,
    Events,
    Stat,
    MemoryMax,
    PidsMax,
    PidsCurrent,
    CpuMax,
}

impl CgroupFile {
    fn name(self) -> &'static str {
        match self {
            CgroupFile::Procs => "cgroup.procs",
            CgroupFile::Events => "cgroup.events",
            CgroupFile::Stat => "cgroup.stat",
            CgroupFile::MemoryMax => "memory.max",
            CgroupFile::PidsMax => "pids.max",
            CgroupFile::PidsCurrent => "pids.current",
            CgroupFile::CpuMax => "cpu.max",
        }
    }
}

pub enum ProcLink {
    Exe,
    NsUser,
    NsMnt,
    NsPid,
    NsNet,
}

impl ProcLink {
    fn name(self) -> &'static str {
        match self {
            ProcLink::Exe => "exe",
            ProcLink::NsUser => "ns/user",
            ProcLink::NsMnt => "ns/mnt",
            ProcLink::NsPid => "ns/pid",
            ProcLink::NsNet => "ns/net",
        }
    }
}

pub struct Roots {
    proc_root: File,
}

impl Roots {
    #[inline(never)]
    pub fn open() -> c_long {
        open_dir(-100, c"x")
    }

    pub fn own_pid(&self) -> c_long {
        let mut buffer = [0u8; 32];
        link_at(&self.proc_root, &name("self"), &mut buffer)
    }
}

pub struct ProcDir {
    handle: File,
}

impl ProcDir {
    pub fn link_text(&self, which: ProcLink, buffer: &mut [u8]) -> c_long {
        link_at(&self.handle, &name(which.name()), buffer)
    }

    pub fn identity(&self) -> u64 {
        self.handle.metadata().map(|facts| facts.ino()).unwrap_or(0)
    }
}
"""
LINUX_CAPTURE = gate.OBSERVER_LINUX_CAPTURE
LINUX_CAPTURE_TEXT = """//! The Linux kernel view over observer_sys (a comment may name LinuxCapture::new and open_after_seal).
use observer_sys::kernel::{self, ProcDir, Roots};

use crate::seal::Sealed;

pub struct LinuxCapture {
    roots: Roots,
}

impl LinuxCapture {
    #[inline(never)]
    pub fn new(_sealed: &Sealed) -> Result<LinuxCapture, SetupError> {
        Ok(LinuxCapture { roots: Roots::open() })
    }
}

impl KernelView for LinuxCapture {
    type Proc = ProcDir;

    fn observer_pid(&mut self) -> i64 {
        self.roots.own_pid()
    }

    fn proc_link(&mut self, process: &ProcDir) -> i64 {
        process.link_text(kernel::ProcLink::Exe, &mut [])
    }
}
"""
CAPTURE_RS = "crates/observer/src/capture.rs"
CAPTURE_TEXT = "//! The engine.\npub trait KernelView { type Proc; }\npub fn fill() {}\n"
D1_TREE = {**FOREIGN_TREE, gate.OBSERVER_SYS_LIB: OBSERVER_SYS_LIB_TEXT, OBSERVER_SYS_DIRENT: OBSERVER_SYS_DIRENT_TEXT,
           KERNEL: KERNEL_TEXT, LINUX_CAPTURE: LINUX_CAPTURE_TEXT, CAPTURE_RS: CAPTURE_TEXT,
           gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN}


class ObserverSysWorkspaceTests(Tree):
    """HE-004D1 G-D1-1: observer-sys joins planeon-observer's closure and the scanned crates, its root denies unsafe_code
    and its manifest names no dependency; planeon-gate's closure is unchanged."""

    TREE = {**WORKSPACE_TREE,
            "Cargo.toml": WORKSPACE_TREE["Cargo.toml"].replace('"crates/gate-tls"]',
                                                               '"crates/gate-tls", "crates/observer", "crates/observer-sys"]'),
            "crates/observer/Cargo.toml": '[package]\nname = "planeon-observer"\nedition.workspace = true\n',
            "crates/observer-sys/Cargo.toml": '[package]\nname = "observer-sys"\nedition.workspace = true\n'}
    GOOD = {**WORKSPACE, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys"}, "observer-sys": set()}

    def test_the_closure_and_the_lists(self):
        self.assertEqual(gate.check_workspace_shape(self.base, self.GOOD), 7)
        self.assertEqual(gate.SCANNED_CRATES[-1], "crates/observer-sys")
        self.assertEqual(gate.CRATE_ROOTS[gate.OBSERVER_SYS_LIB], "#![deny(unsafe_code)]")
        self.assertIn("crates/observer-sys", gate.OBSERVER_POST_SEAL_CRATES)

    def test_a_dependency_of_observer_sys_refuses(self):
        rel = "crates/observer-sys/Cargo.toml"
        for extra in ('\n[dependencies]\ngate-sys = { path = "../gate-sys" }\n', '\n[dev-dependencies]\nx = { path = "../x" }\n',
                      '\n[build-dependencies]\ncc = "1"\n', '\n[target.\'cfg(unix)\'.dependencies]\nlibc = "0.2"\n'):
            self.refused(lambda base: gate.check_workspace_shape(base, self.GOOD), rel, self.TREE[rel] + extra,
                         "observer-sys has a dependency")

    def test_planeon_gate_linking_observer_sys_and_a_fifth_observer_dependency_refuse(self):
        with self.assertRaisesRegex(gate.GateError, "the crates effect-gate, gate-tls and planeon-gate link"):
            gate.check_workspace_shape(self.base, {**self.GOOD, "planeon-gate": {"observer-sys"}})
        with self.assertRaisesRegex(gate.GateError, "planeon-observer links .*, not .* .workspace shape"):
            gate.check_workspace_shape(self.base, {**self.GOOD, "planeon-observer": self.GOOD["planeon-observer"] | {"effect-gate"}})
        with self.assertRaisesRegex(gate.GateError, "planeon-observer links .*, not .* .workspace shape"):
            gate.check_workspace_shape(self.base, {**self.GOOD, "planeon-observer": {"gate-sys", "i05-protocol"}})

    def test_the_root_must_deny_unsafe_code(self):
        tree = {**LINKED_TREE}
        for rel, text in tree.items():
            self.write(rel, text)
        self.assertEqual(gate.check_linked_sources(self.base), 11)
        for text in ("//! Kernel reads.\n#![allow(unsafe_code)]\n", "//! Kernel reads.\n"):
            self.refused(gate.check_linked_sources, gate.OBSERVER_SYS_LIB, text, "lacks #!\\[deny")


class ObserverSysUnsafeTests(Tree):
    """HE-004D1 G-D1-2: kernel.rs is the one observer-sys file allowed unsafe and std::os::fd items, it declares exactly
    syscall, and MetadataExt is allowed in observer-sys (and gate-sys) only."""

    TREE = D1_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.FOREIGN_ITEMS[KERNEL], {"syscall"})
        self.assertIn(KERNEL, gate.UNSAFE_FILES)
        self.assertIn(KERNEL, gate.FD_FILES)
        self.assertEqual(gate.check_foreign_items(self.base), 18)
        self.assertEqual(gate.check_unsafe(self.base), 20)
        self.assertEqual(gate.check_linked_sources(self.base), 18)

    def test_unsafe_outside_kernel_rs_refuses(self):
        for rel in (gate.OBSERVER_SYS_LIB, OBSERVER_SYS_DIRENT, "crates/observer-sys/tests/dirent.rs", LINUX_CAPTURE):
            self.refused(gate.check_unsafe, rel, self.TREE.get(rel, "") + "fn f() { unsafe { g() } }\n",
                         "contains unsafe outside")

    def test_a_second_foreign_item_refuses(self):
        for text in (KERNEL_TEXT.replace("    fn syscall(number: c_long, ...) -> c_long;\n",
                                         "    fn syscall(number: c_long, ...) -> c_long;\n"
                                         "    fn openat(d: c_int, p: *const c_char, f: c_int, ...) -> c_int;\n"),
                     KERNEL_TEXT + "unsafe extern \"C\" { fn ioctl(fd: c_int, r: c_ulong, ...) -> c_int; }\n",
                     KERNEL_TEXT.replace("fn syscall(", "fn syscall6(")):
            self.refused(gate.check_foreign_items, KERNEL, text, "kernel.rs declares the foreign items .* not exactly")
        self.refused(gate.check_foreign_items, OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT
                     + "unsafe extern \"C\" { fn syscall(number: c_long, ...) -> c_long; }\n", "dirent.rs declares the foreign items")

    def test_metadata_ext_and_fd_items(self):
        message = "names a std fs item other than its allowed ones"
        for rel in (CAPTURE_RS, LINUX_CAPTURE):
            self.refused(gate.check_linked_sources, rel, self.TREE[rel] + "use std::os::unix::fs::MetadataExt;\n", message)
        self.write(OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT + "use std::os::unix::fs::MetadataExt;\n")
        self.assertEqual(gate.check_linked_sources(self.base), 18)
        self.write(OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT)
        self.refused(gate.check_linked_sources, OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT + "use std::os::fd::OwnedFd;\n",
                     "std::os::fd item outside")
        self.refused(gate.check_linked_sources, OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT + "use std::os::unix::fs::FileExt;\n",
                     message)


class ObserverSysCallTests(Tree):
    """HE-004D1 G-D1-3 (D1-6): the syscall item's one route, its six numbers, seven arguments and the checked positions."""

    TREE = D1_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_sys_calls(self.base), 9)
        self.assertEqual(gate.SYS_NUMBERS["x86_64"]["SYS_BPF"], 321)
        self.assertEqual(gate.SYS_NUMBERS["aarch64"]["SYS_OPENAT"], 56)
        # Spacing, a trailing comma and comments are read through.
        self.write(KERNEL, KERNEL_TEXT.replace("syscall(SYS_FSTATFS, raw(handle), reply, ZERO, ZERO, ZERO, ZERO)",
                                               "syscall ( SYS_FSTATFS , raw(handle) , /* the reply */ reply, ZERO, ZERO, "
                                               "ZERO, ZERO, )"))
        self.assertEqual(gate.check_observer_sys_calls(self.base), 9)

    def test_numbers_and_arguments_refuse(self):
        message = "observer-sys calls, G-D1-3"
        fstatfs = "syscall(SYS_FSTATFS, raw(handle), reply, ZERO, ZERO, ZERO, ZERO)"
        ioctl = "syscall(SYS_IOCTL, raw(handle), FS_IOC_MEASURE_VERITY, reply, ZERO, ZERO, ZERO)"
        query = "syscall(SYS_BPF, BPF_PROG_QUERY, attr, size, ZERO, ZERO, ZERO)"
        opening = "syscall(SYS_OPENAT, dirfd, path.as_ptr(), READ_FLAGS, ZERO, ZERO, ZERO)"
        for text in (
                KERNEL_TEXT.replace(fstatfs, "syscall(138, raw(handle), reply, ZERO, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace("    pub const SYS_BPF: c_long = 321;\n",
                                    "    pub const SYS_BPF: c_long = 321;\n    pub const SYS_WRITE: c_long = 1;\n")
                .replace(fstatfs, "syscall(SYS_WRITE, raw(handle), reply, ZERO, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace("SYS_OPENAT: c_long = 257;", "SYS_OPENAT: c_long = 258;"),
                KERNEL_TEXT.replace("SYS_BPF: c_long = 280;", "SYS_BPF: c_long = 0x118;"),
                KERNEL_TEXT.replace(fstatfs, "syscall(SYS_FSTATFS, raw(handle), reply, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace(fstatfs, "syscall(SYS_FSTATFS, raw(handle), reply, ZERO, ZERO, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace("const BPF_PROG_QUERY: c_long = 16;\n",
                                    "const BPF_PROG_QUERY: c_long = 16;\nconst BPF_PROG_LOAD: c_long = 5;\n")
                .replace(query, "syscall(SYS_BPF, BPF_PROG_LOAD, attr, size, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace("const BPF_PROG_QUERY: c_long = 16;\n",
                                    "const BPF_PROG_QUERY: c_long = 16;\nconst FS_IOC_GETFLAGS: c_long = 0x80086601;\n")
                .replace(ioctl, "syscall(SYS_IOCTL, raw(handle), FS_IOC_GETFLAGS, reply, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace(ioctl, "syscall(SYS_IOCTL, raw(handle), FS_IOC_MEASURE_VERITY + 0, reply, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace(ioctl, "syscall(SYS_IOCTL, raw(handle), 0xC0046686, reply, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace(query, "syscall(SYS_BPF, BPF_PROG_QUERY | 0, attr, size, ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace(opening, "syscall(SYS_OPENAT, dirfd, READ_FLAGS, path.as_ptr(), ZERO, ZERO, ZERO)"),
                KERNEL_TEXT.replace("const BPF_OBJ_GET: c_long = 7;", "const BPF_OBJ_GET: c_long = 6;"),
                KERNEL_TEXT.replace("const FS_IOC_MEASURE_VERITY: c_long = 0xC004_6686;",
                                    "const FS_IOC_MEASURE_VERITY: c_long = 0x4004_6686;"),
                KERNEL_TEXT.replace("#[cfg(target_arch = \"aarch64\")]\nmod numbers", "#[cfg(target_arch = \"riscv64\")]\nmod numbers")):
            self.refused(gate.check_observer_sys_calls, KERNEL, text, message)

    def test_other_routes_to_the_item_refuse(self):
        message = "observer-sys calls, G-D1-3"
        tail = "fn routes() {}\n"
        for extra in ("fn f() -> c_long { let raw = syscall; 0 }\n",
                      "use self::syscall as raw;\n",
                      "fn f() { let call: unsafe extern \"C\" fn(c_long, ...) -> c_long = syscall; }\n",
                      "fn f() -> c_long { unsafe { self::syscall(SYS_BPF, BPF_OBJ_GET, 0, 0, ZERO, ZERO, ZERO) } }\n",
                      "fn f() -> c_long { let SYS_OPENAT = 2; 0 }\n",
                      "fn f() -> c_long { const SYS_BPF: c_long = 321; 0 }\n",
                      "static SYS_IOCTL2: c_long = 16;\n",
                      "unsafe extern \"C\" {\n    fn syscall(number: c_long, ...) -> c_long;\n}\n"):
            self.refused(gate.check_observer_sys_calls, KERNEL, KERNEL_TEXT + extra + tail, message)
        for rel in (CAPTURE_RS, LINUX_CAPTURE, OBSERVER_SYS_DIRENT):
            for extra in ("fn f() -> i64 { syscall(1, 2) }\n", "const SYS_OPENAT: i64 = 257;\n"):
                self.refused(gate.check_observer_sys_calls, rel, self.TREE[rel] + extra, "names syscall or a SYS_ constant")


class ObserverReadOnlyTests(Tree):
    """HE-004D1 G-D1-4 (NP-3): read-only flag sets with their asserts, exactly seven cgroup file names, no freeze, no
    write in observer-sys."""

    TREE = D1_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_read_only(self.base), 2)

    def test_write_flags_missing_asserts_and_other_sets_refuse(self):
        message = "G-D1-4"
        for flag in ("O_RDWR", "O_WRONLY", "O_CREAT", "O_TRUNC", "O_APPEND", "O_TMPFILE", "0o2", "2"):
            self.refused(gate.check_observer_read_only, KERNEL,
                         KERNEL_TEXT.replace("O_NOFOLLOW | O_NONBLOCK;", "O_NOFOLLOW | O_NONBLOCK | %s;" % flag), message)
        for text in (KERNEL_TEXT.replace("const _: () = assert!(READ_FLAGS & 0x400643 == 0);\n", ""),
                     KERNEL_TEXT.replace("assert!(DIR_FLAGS & 0x400643 == 0)", "assert!(DIR_FLAGS & 0x400603 == 0)"),
                     KERNEL_TEXT.replace("const TARGET_FLAGS: c_long = O_PATH | O_CLOEXEC;\n",
                                         "const TARGET_FLAGS: c_long = O_PATH | O_CLOEXEC;\nconst TARGET_FLAGS2: c_long = O_PATH;\n")
                     .replace("path.as_ptr(), READ_FLAGS,", "path.as_ptr(), TARGET_FLAGS2,"),
                     KERNEL_TEXT.replace("path.as_ptr(), READ_FLAGS,", "path.as_ptr(), O_RDONLY,"),
                     KERNEL_TEXT.replace("fn open_read(dirfd: c_long, path: &CStr) -> c_long {",
                                         "fn open_read(dirfd: c_long, path: &CStr) -> c_long {\n    let READ_FLAGS = 2;")):
            self.refused(gate.check_observer_read_only, KERNEL, text, message)

    def test_cgroup_names_freeze_and_write_refuse(self):
        message = "G-D1-4"
        for text in (KERNEL_TEXT.replace('            CgroupFile::CpuMax => "cpu.max",\n',
                                         '            CgroupFile::CpuMax => "cpu.max",\n'
                                         '            CgroupFile::Subtree => "cgroup.subtree_control",\n'),
                     KERNEL_TEXT.replace('            CgroupFile::CpuMax => "cpu.max",\n', ""),
                     KERNEL_TEXT.replace('"pids.max"', '"pids.current"'),
                     KERNEL_TEXT + 'const KILL: &str = "cgroup.kill";\n'):
            self.refused(gate.check_observer_read_only, KERNEL, text, message)
        for rel, extra in ((KERNEL, 'const FREEZE: &str = "cgroup.freeze";\n'), (CAPTURE_RS, "// the broker's freeze\n"),
                           (LINUX_CAPTURE, "fn freeze() {}\n"), (OBSERVER_SYS_DIRENT, "/* cgroup.freeze */\n")):
            self.refused(gate.check_observer_read_only, rel, self.TREE[rel] + extra, "names freeze")
        for extra in ("use std::io::Write;\n", "fn f(h: &mut File) { let _ = h.write(b\"x\"); }\n",
                      "fn f(h: &mut File) { let _ = h.write_all(b\"x\"); }\n"):
            self.refused(gate.check_observer_read_only, OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT + extra,
                         "names write, Write or write_all")
        # A comment saying the kernel writes, and a write in crates/observer, are outside this rule.
        self.write(OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT + "// the kernel will write and then writes\n")
        self.write(CAPTURE_RS, CAPTURE_TEXT + "fn f(out: &mut String) { let _ = out.write_str(\"x\"); }\n")
        self.assertEqual(gate.check_observer_read_only(self.base), 2)


class ObserverRootConstantTests(Tree):
    """HE-004D1 G-D1-5 (R3-1, R4-1): five exact private root constants, each excepted once in its own file from the
    start-up lint and the linked-source fs scan; every other form still refuses."""

    ENROLLED = gate.OBSERVER_ENROLLED
    CHECK = gate.OBSERVER_CAPTURE_CHECK
    ENROLLED_TEXT = ('const CGROUP_ROOT: &str = "/sys/fs/cgroup";\n'
                     '/// The pins.\nconst PIN_ROOT: &str = "/sys/fs/bpf/planeon";\npub fn f() {}\n')
    CHECK_TEXT = '#[allow(dead_code)]\n    const CGROUP_ROOT: &str = "/sys/fs/cgroup";\npub fn g() {}\n'
    TREE = {**D1_TREE, gate.OBSERVER_ENROLLED: ENROLLED_TEXT, gate.OBSERVER_CAPTURE_CHECK: CHECK_TEXT}

    def test_the_tree_passes(self):
        self.assertEqual([expression for _, expressions in gate.FS_SCAN_EXCEPTIONS.items() for expression, _ in expressions],
                         ['const PROC_ROOT: &str = "/proc";', 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";',
                          'const CGROUP_ROOT: &str = "/sys/fs/cgroup";', 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";',
                          'const CGROUP_ROOT: &str = "/sys/fs/cgroup";'])
        self.assertEqual(gate.check_sources(self.base), 22)
        self.assertEqual(gate.check_linked_sources(self.base), 20)
        # A rustfmt-wrapped expression is removed once (both scans).
        self.write(self.ENROLLED, self.ENROLLED_TEXT.replace('const PIN_ROOT: &str = "/sys/fs/bpf/planeon";',
                                                             'const PIN_ROOT: &str =\n    "/sys/fs/bpf/planeon";'))
        self.assertEqual(gate.check_sources(self.base), 22)
        self.assertEqual(gate.check_linked_sources(self.base), 20)

    def forms(self, rel, text, old):
        """Each refused form of `old` (one of `rel`'s expressions) in `text`."""
        value = old.split('"')[1]
        return (text.replace(old, "pub " + old), text.replace(old, "pub(crate) " + old),
                text.replace(old, "#[allow(dead_code)] " + old),
                text + old + "\n",
                text.replace(old, old.replace('"%s"' % value, 'r"%s"' % value)),
                text.replace(old, old.replace('"%s"' % value, 'concat!("%s")' % value)),
                text.replace(old, old.replace("= ", "= /* the root */ ")),
                text.replace(old, old.replace(value, value + "/x")),
                "// " + old + "\n" + text.replace(old, "const OTHER: u8 = 0;"),
                text + "// " + old + "\n",
                "/*\n" + old + "\n*/\n" + text)

    def test_other_forms_refuse_in_the_start_up_lint(self):
        for rel, text, old in ((KERNEL, KERNEL_TEXT, 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";'),
                               (KERNEL, KERNEL_TEXT, 'const PROC_ROOT: &str = "/proc";'),
                               (self.ENROLLED, self.ENROLLED_TEXT, 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";'),
                               (self.CHECK, self.CHECK_TEXT, 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";')):
            for form in self.forms(rel, text, old):
                self.refused(gate.check_sources, rel, form, "uses /(proc|sys) .start-up lint")
        for rel in (CAPTURE_RS, LINUX_CAPTURE, "crates/observer/tests/observer_capture.rs", gate.OBSERVER_SYS_LIB):
            self.refused(gate.check_sources, rel, self.TREE.get(rel, "") + 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";\n',
                         "uses /sys .start-up lint")
        self.refused(gate.check_sources, self.ENROLLED, self.ENROLLED_TEXT + 'const PROC_ROOT: &str = "/proc";\n',
                     "uses /proc .start-up lint")

    def test_other_forms_refuse_in_the_fs_scan(self):
        message = "names a std fs item other than its allowed ones"
        for rel, text, old in ((KERNEL, KERNEL_TEXT, 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";'),
                               (self.ENROLLED, self.ENROLLED_TEXT, 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";'),
                               (self.CHECK, self.CHECK_TEXT, 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";')):
            for form in self.forms(rel, text, old):
                self.refused(gate.check_linked_sources, rel, form, message)
            self.refused(gate.check_linked_sources, rel, text + 'fn f() { let _ = "/sys/fs/cgroup/planeon.slice"; }\n', message)
            self.refused(gate.check_linked_sources, rel, text + "// a fs-verity digest\n", message)
        for rel in (CAPTURE_RS, LINUX_CAPTURE, gate.OBSERVER_SYS_LIB):
            self.refused(gate.check_linked_sources, rel, self.TREE[rel] + 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";\n',
                         message)
        # R96's one cgroup2-root open in linux_os.rs still passes beside them.
        self.write(gate.LINUX_OS, 'fn f() { let _ = KernelRoot::open_kernel_root("/sys/fs/cgroup"); }\n')
        self.assertEqual(gate.check_linked_sources(self.base), 21)


class ObserverCaptureCallerTests(Tree):
    """HE-004D1 G-D1-6 (D1-12, R2-1): observer_sys only in linux_capture.rs, which re-exports nothing and names no
    observer-sys type in a public item; LinuxCapture::new(sealed) once, in serve; the capture roots refused before the
    seal; and the OBSERVATION_CALLERS rule unchanged over D1's real sources."""

    TREE = D1_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_capture_callers(self.base), 4)
        self.assertIn(r"\bobserver_sys\b", gate.BEFORE_SEAL_REFUSED)
        self.assertIn(r"\bLinuxCapture\b", gate.BEFORE_SEAL_REFUSED)

    def test_observer_sys_outside_linux_capture_and_public_items_refuse(self):
        rule = "G-D1-6"
        for rel in (CAPTURE_RS, gate.OBSERVER_LIB, gate.OBSERVER_MAIN):
            self.refused(gate.check_observer_capture_callers, rel, self.TREE[rel] + "// observer_sys in a comment\n",
                         "names observer_sys")
        for text in (LINUX_CAPTURE_TEXT + "pub use observer_sys::kernel::Roots;\n",
                     LINUX_CAPTURE_TEXT + "pub(crate) use observer_sys::kernel;\n",
                     LINUX_CAPTURE_TEXT + "pub fn dir(c: &LinuxCapture) -> ProcDir { x() }\n",
                     LINUX_CAPTURE_TEXT + "pub fn dir(c: &LinuxCapture) -> kernel::ProcDir { x() }\n",
                     LINUX_CAPTURE_TEXT + "pub type Dir = observer_sys::kernel::ProcDir;\n",
                     LINUX_CAPTURE_TEXT + "pub struct Held { pub roots: Roots }\n",
                     LINUX_CAPTURE_TEXT + "pub enum Held { R(Roots) }\n",
                     LINUX_CAPTURE_TEXT.replace("    roots: Roots,\n}", "    pub roots: Roots,\n}")):
            self.refused(gate.check_observer_capture_callers, LINUX_CAPTURE, text, rule)

    def test_the_constructor_s_one_call(self):
        rule = "G-D1-6"
        call = "    let capture = match LinuxCapture::new(sealed) {"
        for text in (GOOD_OBSERVER_MAIN.replace(call, call.replace("(sealed)", "(&sealed)")),
                     GOOD_OBSERVER_MAIN.replace(call, call.replace("(sealed)", "(other)")),
                     GOOD_OBSERVER_MAIN.replace(call, "    let _again = LinuxCapture::new(sealed);\n" + call),
                     GOOD_OBSERVER_MAIN.replace(call, "    let make = LinuxCapture::new;\n" + call),
                     GOOD_OBSERVER_MAIN + "fn other(sealed: &Sealed) { let _ = LinuxCapture::new(sealed); }\n"):
            self.refused(gate.check_observer_capture_callers, gate.OBSERVER_MAIN, text, rule)
        for rel in (CAPTURE_RS, LINUX_CAPTURE):
            for extra in ("fn f(s: &Sealed) { let _ = LinuxCapture::new(s); }\n", "fn f() { let _ = LinuxCapture :: new; }\n",
                          "impl LinuxCapture { fn other() {} }\n", "use crate::linux_capture::LinuxCapture as Capture;\n",
                          "type Capture = LinuxCapture;\n"):
                self.refused(gate.check_observer_capture_callers, rel, self.TREE[rel] + extra, rule)
        self.refused(gate.check_observer_capture_callers, CAPTURE_RS, CAPTURE_TEXT + "pub struct LinuxCapture;\n", rule)
        self.refused(gate.check_observer_capture_callers, LINUX_CAPTURE,
                     LINUX_CAPTURE_TEXT.replace("pub fn new(_sealed", "pub fn open(_sealed"), rule)

    def test_the_capture_roots_before_the_seal_refuse(self):
        uses = tuple(sorted(gate.OBSERVER_MAIN_USES + ((("planeon_observer", "linux_capture", "LinuxCapture"), None),)))
        text = GOOD_OBSERVER_MAIN.replace("use planeon_observer::status;\n",
                                          "use planeon_observer::status;\nuse planeon_observer::linux_capture::LinuxCapture;\n")
        self.write(gate.OBSERVER_MAIN, text)
        with mock.patch.dict(gate.OBSERVER_SEAL_SITE, {"uses": uses}):
            with self.assertRaisesRegex(gate.GateError, "names LinuxCapture before the seal"):
                gate.check_seal_order(self.base, gate.OBSERVER_SEAL_SITE)
        self.write(gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN)
        uses = tuple(sorted(gate.OBSERVER_MAIN_USES + ((("observer_sys", "kernel", "Roots"), None),)))
        self.write(gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace("use planeon_observer::status;\n",
                                                                  "use planeon_observer::status;\nuse observer_sys::kernel::Roots;\n"))
        with mock.patch.dict(gate.OBSERVER_SEAL_SITE, {"uses": uses}):
            with self.assertRaisesRegex(gate.GateError, "names observer_sys before the seal"):
                gate.check_seal_order(self.base, gate.OBSERVER_SEAL_SITE)

    def test_observation_callers_over_d1_s_real_sources(self):
        # R2-1: the existing OBSERVATION_CALLERS rule passes over a tree holding D1's observer and observer-sys sources (as
        # built), and fails when any of them names open_after_seal.
        names = ["crates/observer/src/%s.rs" % name for name in
                 ("capture", "capture_check", "capture_schema", "enrolled", "kernel_text", "linux_capture", "lib", "main",
                  "status", "config", "contracts", "observe")] + [gate.OBSERVER_SYS_LIB, OBSERVER_SYS_DIRENT, KERNEL]
        real = {rel: (gate.HE / rel).read_text(encoding="utf-8") for rel in names}
        for rel, text in real.items():
            self.write(rel, text)
        for rel, text in OBSERVATION_TREE.items():
            if not rel.startswith(("crates/observer/", "crates/observer-sys/")):
                self.write(rel, text)
        self.assertGreater(gate.check_observation(self.base), len(names))
        for rel, text in real.items():
            self.refused(gate.check_observation, rel, text + "\nfn open_after_seal() {}\n", "names open_after_seal")
            self.write(rel, text)


class ObserverLinkTests(Tree):
    """HE-004D1 G-D1-7 (R2-6): link_text reads ProcLink's five names, own_pid the proc root's self link, and both are
    called only in linux_capture.rs."""

    TREE = D1_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_links(self.base), 2)

    def test_other_links_and_callers_refuse(self):
        rule = "G-D1-7"
        for text in (KERNEL_TEXT.replace("    NsNet,\n}", "    NsNet,\n    Cwd,\n}")
                     .replace('            ProcLink::NsNet => "ns/net",\n',
                              '            ProcLink::NsNet => "ns/net",\n            ProcLink::Cwd => "cwd",\n'),
                     KERNEL_TEXT.replace('ProcLink::NsNet => "ns/net"', 'ProcLink::NsNet => "root"'),
                     KERNEL_TEXT.replace('&name("self")', '&name("thread-self")'),
                     KERNEL_TEXT.replace("    pub fn own_pid(&self) -> c_long {",
                                         "    pub fn parent(&self) -> c_long {\n        let mut b = [0u8; 8];\n"
                                         "        link_at(&self.proc_root, &name(\"cwd\"), &mut b)\n    }\n\n"
                                         "    pub fn own_pid(&self) -> c_long {"),
                     KERNEL_TEXT + "pub fn link_text() {}\n",
                     KERNEL_TEXT + "fn f(d: &ProcDir) -> c_long { d.link_text(ProcLink::Exe, &mut []) }\n",
                     KERNEL_TEXT.replace("link_at(&self.handle, &name(which.name()), buffer)",
                                         "link_at(&self.handle, &name(\"cwd\"), buffer)")):
            self.refused(gate.check_observer_links, KERNEL, text, rule)
        for rel in (CAPTURE_RS, gate.OBSERVER_MAIN, OBSERVER_SYS_DIRENT):
            for extra in ("fn f(r: &Roots) -> i64 { r.own_pid() }\n", "fn f(d: &ProcDir) -> i64 { d.link_text(x, b) }\n"):
                self.refused(gate.check_observer_links, rel, self.TREE[rel] + extra, "only .* calls it")
        self.refused(gate.check_observer_links, LINUX_CAPTURE, LINUX_CAPTURE_TEXT + "fn f() { let read = ProcDir::link_text; }\n",
                     "other than as a method call")


NATIVE_CONTRACTS = (GOOD_CONTRACTS_MODULE
                    + "pub const NATIVE_PROFILE_V4_SCHEMA: &[u8] =\n"
                      "    include_bytes!(\"../../../contracts/native-profile-v4/qualification.schema.json\");\n"
                      "pub const NATIVE_PROFILE_V4_SCHEMA_SHA256: &str =\n"
                      "    \"c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10\";\n")
NATIVE_SCHEMA_RS = "crates/observer/src/capture_schema.rs"
NATIVE_SCHEMA_TEXT = ("impl CaptureSchema {\n    pub fn embedded() -> Loaded {\n"
                      "        CaptureSchema::from_bytes(crate::contracts::NATIVE_PROFILE_V4_SCHEMA)\n    }\n\n"
                      "    pub fn from_bytes(bytes: &[u8]) -> Loaded { load(bytes) }\n}\n")


class ObserverNativeProfileTests(Tree):
    """HE-004D1 G-D1-9 (R2-5): the four native-profile files are pinned (35), contracts.rs holds the schema's two items,
    and the schema has one use site, in CaptureSchema::embedded."""

    TREE = {gate.OBSERVER_CONTRACTS: NATIVE_CONTRACTS, NATIVE_SCHEMA_RS: NATIVE_SCHEMA_TEXT, CAPTURE_RS: CAPTURE_TEXT}

    def test_the_tree_passes(self):
        self.assertEqual(len(gate.CONTRACTS), 35)
        self.assertEqual(gate.check_native_profile_use(self.base), 2)
        self.assertEqual(gate.check_observer_contracts_module(self.base), 5)

    def test_a_second_use_refuses(self):
        rule = "G-D1-9"
        use = "crate::contracts::NATIVE_PROFILE_V4_SCHEMA"
        for rel, text in ((NATIVE_SCHEMA_RS, NATIVE_SCHEMA_TEXT.replace("load(bytes)", "load(%s)" % use)),
                          (NATIVE_SCHEMA_RS, NATIVE_SCHEMA_TEXT.replace("from_bytes(%s)" % use, "from_bytes(%s); %s" % (use, use))),
                          (NATIVE_SCHEMA_RS, NATIVE_SCHEMA_TEXT.replace(use, "&[]")),
                          (NATIVE_SCHEMA_RS, NATIVE_SCHEMA_TEXT.replace("fn embedded", "fn embedded_v4")),
                          (CAPTURE_RS, CAPTURE_TEXT + "fn f() -> usize { %s.len() }\n" % use),
                          (gate.OBSERVER_CONTRACTS, NATIVE_CONTRACTS.replace("NATIVE_PROFILE_V4_SCHEMA:", "NATIVE_PROFILE_SCHEMA:"))):
            self.refused(gate.check_native_profile_use, rel, text, rule)
        # contracts.rs's static form is not admitted (the fallback of R2-5 was not needed).
        self.refused(gate.check_observer_contracts_module, gate.OBSERVER_CONTRACTS,
                     NATIVE_CONTRACTS.replace("pub const NATIVE_PROFILE_V4_SCHEMA: &[u8] =",
                                              "pub static NATIVE_PROFILE_V4_SCHEMA: &[u8; 93041] ="), "contracts pin")


class ObserverD1LogicTests(Tree):
    """HE-004D1 G-D1-10: the capture checks' three logic modules take B1's rule with their own whitelist."""

    TREE = LOGIC_TREE

    def test_the_whitelist_and_its_refusals(self):
        self.assertEqual(gate.D1_LOGIC_NAMES, ("capture_schema", "capture_check", "kernel_text"))
        self.assertIn("observer_sys", gate.CRATE_PATH_ROOTS)
        self.assertEqual(gate.check_observer_logic(self.base), 8)
        rel = "crates/observer/src/capture_check.rs"
        good = self.TREE[rel]
        for text, message in (("use std::fs::File;\n", "imports std::fs::File"),
                              ("use crate::enrolled::Enrolled;\n", "imports crate::enrolled::Enrolled"),
                              ("use crate::capture::Slot;\n", "imports crate::capture::Slot"),
                              ("use observer_sys::kernel;\n", "imports observer_sys::kernel"),
                              ("fn f() { let _ = observer_sys::kernel::Roots::open(); }\n", "names observer_sys::kernel"),
                              ("fn f() { gate_sys::Dir::at(p); }\n", "names gate_sys::Dir::at"),
                              ("fn f() { let _ = std::time::Instant::now(); }\n", "names std::time::Instant::now"),
                              ("fn f() { let _: HashMap<u8, u8> = x(); }\n", "HashMap, HashSet or RandomState"),
                              ("const X: &[u8] = include_bytes!(\"x\");\n", "include_bytes! or include_str!"),
                              ("fn f(x: Option<u8>) -> u8 { x.unwrap() }\n", "no-panic tripwire"),
                              ("fn f(x: u8) { assert!(x > 0); }\n", "no-panic tripwire")):
            self.refused(gate.check_observer_logic, rel, good + text, message)
        # i05_protocol::schema is D1's, not B1's.
        self.write("crates/observer/src/kernel_text.rs", self.TREE["crates/observer/src/kernel_text.rs"]
                   + "use i05_protocol::schema::Schema;\nuse crate::capture_check;\n")
        self.assertEqual(gate.check_observer_logic(self.base), 8)
        self.refused(gate.check_observer_logic, "crates/observer/src/inputs.rs", self.TREE["crates/observer/src/inputs.rs"]
                     + "use crate::kernel_text;\n", "imports crate::kernel_text")


class ObserverD1NoPanicTests(Tree):
    """HE-004D1 G-D1-11: the no-panic tripwire over enrolled.rs, capture.rs, linux_capture.rs and observer-sys's three
    sources, where only item-level compile-time asserts are removed."""

    TREE = {rel: "//! unwrap() in a comment passes.\npub fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }\n"
            for rel in gate.OBSERVER_NO_PANIC + gate.OBSERVER_SYS_NO_PANIC}

    def test_each_new_source_refuses_a_panic(self):
        self.assertEqual(gate.check_observer_no_panic(self.base), 21)
        for rel in ("crates/observer/src/enrolled.rs", CAPTURE_RS, LINUX_CAPTURE) + gate.OBSERVER_SYS_NO_PANIC:
            for text in ("fn g(x: Option<u8>) -> u8 { x.unwrap() }", "fn g(x: Option<u8>) -> u8 { x.expect(\"y\") }",
                         "fn g() { panic!(\"x\"); }", "fn g() { assert!(true); }"):
                self.refused(gate.check_observer_no_panic, rel, self.TREE[rel] + text + "\n", "observer no-panic tripwire")
            (self.base / rel).unlink()
            with self.assertRaisesRegex(gate.GateError, "is missing .observer no-panic tripwire"):
                gate.check_observer_no_panic(self.base)
            self.write(rel, self.TREE[rel])

    def test_only_item_level_compile_time_asserts_pass_in_observer_sys(self):
        good = self.TREE[KERNEL]
        self.write(KERNEL, good + "const _: () = assert!(A & 0x400643 == 0);\nconst _: () =\n    assert!(f(B) == (1, 2));\n"
                   "const _ : ( ) = assert ! ( size_of::<u64>() == 8 ) ;\n")
        self.assertEqual(gate.check_observer_no_panic(self.base), 21)
        for text in ("fn g() { const _: () = assert!(true); }", "const _: () = { assert!(true) };",
                     "const X: () = assert!(true);", "static _S: () = assert!(true);", "fn g() { debug_assert!(true); }"):
            self.refused(gate.check_observer_no_panic, KERNEL, good + text + "\n", "observer no-panic tripwire")
        # The exception is observer-sys's only: the same assert in the observer's crate refuses.
        self.refused(gate.check_observer_no_panic, CAPTURE_RS, self.TREE[CAPTURE_RS] + "const _: () = assert!(true);\n",
                     "observer no-panic tripwire")


class ObserverSysPostSealTests(Tree):
    """HE-004D1 G-D1-12: observer-sys joins the observer post-seal rule (Drop, read_dir and the observer's words)."""

    TREE = D1_TREE

    def test_post_seal_words_refuse_in_observer_sys(self):
        self.assertEqual(gate.check_observer_post_seal(self.base), 9)
        for rel in (KERNEL, OBSERVER_SYS_DIRENT, gate.OBSERVER_SYS_LIB):
            for text in ("impl Drop for Opened { fn drop(&mut self) {} }", "fn f() { let _ = std::fs::read_dir(p); }",
                         "fn f(h: &File) { let _ = h.sync_all(); }", "fn f(d: &Dir) { let _ = d.file(n, m); }",
                         "fn f(h: &File) { let _ = h.lock(); }", "fn f(h: &File) { let _ = h.set_len(0); }"):
                self.refused(gate.check_observer_post_seal, rel, self.TREE[rel] + text + "\n", "observer post-seal check")


class ObserverSysDebugTests(Tree):
    """HE-004D1 G-D1-13: observer-sys's handles and the Linux capture view join the Debug hazards."""

    TREE = SECRET_TREE

    def test_the_handles_refuse(self):
        rel = "crates/observer-sys/src/extra.rs"
        for hazard in ("Roots", "ProcDir", "CgroupDir", "Opened", "ProgFd", "LinuxCapture"):
            for text in ("#[derive(Debug)]\nstruct S { held: %s }" % hazard, "#[derive(Debug)]\nenum E { A(Option<%s>) }" % hazard):
                self.refused(gate.check_debug_derives, rel, text + "\n", "mention %s .Debug check" % hazard)
        self.refused(gate.check_debug_derives, "crates/observer/src/extra.rs",
                     "#[derive(Clone, Debug)]\npub struct View { capture: LinuxCapture }\n", "mention LinuxCapture")


class ObserverCaptureSymbolTests(unittest.TestCase):
    """HE-004D1 G-D1-14 (D1-7): planeon-observer's .symtab holds Roots::open's and LinuxCapture::new's symbols, each by its
    whole item path (legacy or v0); another function, a closure inside them or a mention does not count."""

    ROOTS = ("_ZN12observer_sys6kernel5Roots4open17h0123456789abcdefE",
             "_RNvMs_NtCs1a2b3c4d5e6_12observer_sys6kernelNtB4_5Roots4open",
             "_RNvMNtCs1a2b3c4d5e6_12observer_sys6kernelNtNtCs1a2b3c4d5e6_12observer_sys6kernel5Roots4open")
    NEW = ("_ZN16planeon_observer13linux_capture12LinuxCapture3new17h0123456789abcdefE",
           "_RNvMs0_NtCs5pXa2Z9YbGW_16planeon_observer13linux_captureNtB5_12LinuxCapture3new")
    OTHERS = ("_RNvMs_NtCs1a2b3c4d5e6_12observer_sys6kernelNtB4_5Roots9processes",
              "_RNCNvMs_NtCs1a2b3c4d5e6_12observer_sys6kernelNtB6_5Roots4open0B8_",
              "_RINvNtCsifRdLFh1usa_4core3ptr9drop_glueNtNtCs1a2b3c4d5e6_12observer_sys6kernel5RootsEB8_",
              "_ZN12observer_sys6kernel5Roots4open4help17h0123456789abcdefE",
              "_RNvMs0_NtCs5pXa2Z9YbGW_16planeon_observer13linux_captureNtB5_12LinuxCapture12observer_pid",
              "_RNvNtCs5pXa2Z9YbGW_16planeon_observer13linux_capture3new",
              "_ZN6myobserver_sys6kernel5Roots4open17h0123456789abcdefE", "observer_sys_kernel_Roots_open", "_RNvB99_3new")

    def test_item_paths(self):
        for name in self.ROOTS:
            self.assertEqual(gate.item_path(name), ("observer_sys", "kernel", "Roots", "open"), name)
        for name in self.NEW:
            self.assertEqual(gate.item_path(name), ("planeon_observer", "linux_capture", "LinuxCapture", "new"), name)
        self.assertEqual(gate.v0_path(ObserverSymbolTests.MODULE[2]), ("planeon_observer", "http", "Framer", "push"))
        self.assertEqual(gate.v0_path(ObserverSymbolTests.MODULE[1]), ())
        self.assertEqual(gate.v0_path("main"), ())

    def test_the_symbols_pass_and_each_missing_refuses(self):
        for roots in self.ROOTS:
            for new in self.NEW:
                self.assertEqual(gate.check_capture_symbols({"main", roots, new} | set(self.OTHERS)), [roots, new])
        for names in ({self.NEW[0]} | set(self.OTHERS), {self.NEW[1], self.OTHERS[0], self.OTHERS[1]}):
            with self.assertRaisesRegex(gate.GateError, "no observer_sys::kernel::Roots::open symbol"):
                gate.check_capture_symbols(names)
        with self.assertRaisesRegex(gate.GateError, "no planeon_observer::linux_capture::LinuxCapture::new symbol"):
            gate.check_capture_symbols({self.ROOTS[1]} | set(self.OTHERS))


class ObserverExemptSpanTests(unittest.TestCase):
    """HE-004D1 G-D1-16 (owner decision Q-HE4D1-D3 (a)): planeon-observer's host-path scan exempts exactly one span, the
    pinned v4 schema's bytes, which must occur exactly once; every other needle and every other binary as before."""

    def setUp(self):
        self.schema = gate.binary_exempt("planeon-observer", gate.HE)

    def test_the_exempt_bytes(self):
        self.assertEqual(gate.HOST_PATHS, (b"/Users/", b"/opt/planeon/", b"/private/tmp/", b"/private/var/"))
        self.assertEqual(gate.EXEMPT_SPANS, {"planeon-observer": "contracts/native-profile-v4/qualification.schema.json"})
        self.assertEqual(hashlib.sha256(self.schema).hexdigest(), gate.CONTRACTS[gate.EXEMPT_SPANS["planeon-observer"]])
        self.assertGreater(self.schema.count(b"/opt/planeon/"), 0)
        self.assertTrue(self.schema.startswith(b"{") and self.schema.endswith(b"}\n"))
        for binary in gate.BINARIES:
            if binary != "planeon-observer":
                self.assertEqual(gate.binary_exempt(binary, gate.HE), b"")
        with mock.patch.dict(gate.CONTRACTS, {gate.EXEMPT_SPANS["planeon-observer"]: "0" * 64}):
            with self.assertRaisesRegex(gate.GateError, "differs from its registered bytes"):
                gate.binary_exempt("planeon-observer", gate.HE)

    def test_the_schema_once_passes(self):
        raw = build_elf(payload=b"\0" * 7 + self.schema + b"\0" * 5)
        offset = gate.check_binary(raw, X86, "static-pie", MARKERS, exempt=self.schema)
        self.assertEqual(raw[offset:offset + len(self.schema)], self.schema)
        self.assertEqual(gate.check_binary(build_elf(), X86, "static-pie", MARKERS), -1)

    def test_other_cases_fail(self):
        changed = self.schema.replace(b"/opt/planeon/", b"/opt/planeoN/", 1)
        for payload, message in ((self.schema + self.schema, "occurs 2 times, not exactly once"),
                                 (changed, "occurs 0 times, not exactly once"),
                                 (b"", "occurs 0 times, not exactly once"),
                                 (self.schema + b"\0/opt/planeon/run\0", "a build-host path"),
                                 (b"/private/tmp/x\0" + self.schema, "a build-host path")):
            with self.assertRaisesRegex(gate.GateError, message):
                gate.check_binary(build_elf(payload=payload), X86, "static-pie", MARKERS, exempt=self.schema)
        # The same fixture as planeon-gate (no exemption) fails on the schema's own paths.
        with self.assertRaisesRegex(gate.GateError, "a build-host path"):
            gate.check_binary(build_elf(payload=self.schema), X86, "static-pie", MARKERS,
                              exempt=gate.binary_exempt("planeon-gate", gate.HE))
        # A host path given as an extra needle (the build root) still fails outside the span.
        with self.assertRaisesRegex(gate.GateError, "a build-host path"):
            gate.check_binary(build_elf(payload=self.schema + b"/build/root/x"), X86, "static-pie", MARKERS,
                              gate.HOST_PATHS + (b"/build/root",), self.schema)


class ObserverServeV1ParseTests(Tree):
    """HE-004D1 G-D1-8: serve's imports gain the capture setup's, and the v1 parse no longer passes in serve."""

    TREE = OBSERVER_TREE

    def test_the_v1_parse_and_a_missing_import_refuse(self):
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN,
                     GOOD_OBSERVER_MAIN.replace("ObserverConfig::parse_with_record(", "ObserverConfig::parse("), "v1")
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN,
                     GOOD_OBSERVER_MAIN.replace("    drop(document);\n", "    let _ = ObserverConfig::parse(&document);\n"), "v1")
        for use in ("    use planeon_observer::capture::CaptureEngine;\n", "    use planeon_observer::linux_capture::LinuxCapture;\n",
                    "    use planeon_observer::enrolled::{self, Enrolled};\n"):
            self.refused(lambda base: gate.check_seal_order(base, gate.OBSERVER_SEAL_SITE), gate.OBSERVER_MAIN,
                         GOOD_OBSERVER_MAIN.replace(use, ""), "imports are not exactly the pinned set")


class ObserverWordListTests(Tree):
    """HE-004D1 DESIGN-D1 section 19's word lists: one refusing fixture per list, each in a D1 source."""

    TREE = {**D1_TREE, **OBSERVER_TLS_TREE}

    def test_one_refusal_per_list(self):
        # (a) anywhere, tests included: the start-up lint.
        self.refused(gate.check_sources, "crates/observer/tests/observer_capture.rs", "// see /proc/self/status\n",
                     "uses /proc .start-up lint")
        # (b) the non-test sources, comments included: the linked-source tripwire.
        self.refused(gate.check_linked_sources, OBSERVER_SYS_DIRENT, OBSERVER_SYS_DIRENT_TEXT + "// std::path::Path\n",
                     "linked-source tripwire")
        # (c) the code: the print rule.
        self.refused(gate.check_prints, KERNEL, KERNEL_TEXT + "fn f() { eprintln!(\"x\"); }\n", "print rule")
        # (d) crates/observer's sources, comments included: group O of the TLS deny-list.
        self.refused(gate.check_observer_tls, CAPTURE_RS, CAPTURE_TEXT + "// nothing dangerous here\n", "danger")
        # (e) the code, comments and literal contents removed: the observer post-seal words.
        self.refused(gate.check_observer_post_seal, LINUX_CAPTURE, LINUX_CAPTURE_TEXT + "fn f(file: u8) -> u8 { file }\n",
                     "observer post-seal check")


class ObserverSysConstAssertBraceTests(Tree):
    """HE-004D1 PR review round 1, R1-1 (G-D1-11, S8): only a brace-free `const _: () = assert!(..);` at item level is
    removed before observer-sys's no-panic scan; a form whose argument holds a block stays, so its `assert!` and any
    panic inside it refuse."""

    TREE = {rel: "//! unwrap() in a comment passes.\npub fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }\n"
            for rel in gate.OBSERVER_NO_PANIC + gate.OBSERVER_SYS_NO_PANIC}

    def test_only_brace_free_forms_are_removed(self):
        good = self.TREE[KERNEL]
        self.write(KERNEL, good + "const _: () = assert!(DIR_FLAGS & 0x400643 == 0);\n"
                   "const _: () = assert!(size_of::<u64>() == 8 && offset_of!(Info, id) == 4);\n")
        self.assertEqual(gate.check_observer_no_panic(self.base), 21)
        self.assertEqual(len(gate.const_asserts("const _: () = assert!(A == 0);\nconst _: () = assert!({ true });\n")), 1)
        for rel, text in (
                (KERNEL, "const _: () = assert!({ impl Roots { pub fn probe(&self) -> u8 { panic!(\"x\") } } true });"),
                (KERNEL, "const _: () = assert!({ impl RelPath { pub fn first(&self) -> u8 { None::<u8>.unwrap() } } true });"),
                (OBSERVER_SYS_DIRENT, "const _: () = assert!({ impl Drop for Entry { fn drop(&mut self) {} } true });"),
                (KERNEL, "const _: () = assert!({ true });"),
                (gate.OBSERVER_SYS_LIB, "const _: () = assert!(match 1 { _ => true });")):
            self.refused(gate.check_observer_no_panic, rel, self.TREE[rel] + text + "\n", "observer no-panic tripwire")

    def test_the_head_s_forms_are_brace_free(self):
        code = gate.PATH_SPACE.sub("::", gate.rust_code((gate.HE / gate.OBSERVER_SYS_KERNEL).read_text(encoding="utf-8")))
        found = len(gate.CONST_ASSERT.findall(code))
        self.assertGreater(found, 0)
        self.assertEqual(len(gate.const_asserts(code)), found)


class ObserverSysPinnedNameTests(Tree):
    """HE-004D1 PR review round 1, R1-2 (G-D1-3, G-D1-4, G-D1-7): kernel.rs renames nothing in a use declaration, holds
    no item inside a function body, names each flag set, the verity request and each BPF command exactly where the pins
    put them, and names `name` and `link_at` on the link-read path only as pinned; the reviewer's three probes refuse."""

    TREE = D1_TREE
    RULE = "observer-sys pinned names, R1-2"

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_sys_names(self.base), 15)
        self.assertEqual(gate.LINK_PATH_NAMES, {"link_text": (1, 1, 0), "own_pid": (1, 0, 0), "link_at": (0, 0, 1)})
        # A second call passing a set or a command keeps the count exact.
        self.write(KERNEL, KERNEL_TEXT + "fn again(dirfd: c_long, path: &CStr) -> c_long {\n    // SAFETY: a fixture.\n"
                   "    unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), TARGET_FLAGS, ZERO, ZERO, ZERO) }\n}\n")
        self.assertEqual(gate.check_observer_sys_names(self.base), 16)

    def test_the_reviewer_s_three_probes_refuse(self):
        # Probe 1: a block-level rename of DIR_FLAGS to a set holding O_RDWR, feeding an openat call.
        probe1 = KERNEL_TEXT + ("const WIDE: c_long = 0o2;\nfn wide_open(dirfd: c_long, path: &CStr) -> c_long {\n"
                                "    use self::WIDE as DIR_FLAGS;\n    // SAFETY: a probe.\n"
                                "    unsafe { syscall(SYS_OPENAT, dirfd, path.as_ptr(), DIR_FLAGS, ZERO, ZERO, ZERO) }\n}\n")
        # Probe 2: a block-level rename of BPF_PROG_QUERY to command 5, feeding a bpf call.
        probe2 = KERNEL_TEXT + ("const OTHER: c_long = 5;\nfn query(attr: *mut u8, size: c_long) -> c_long {\n"
                                "    use self::OTHER as BPF_PROG_QUERY;\n    // SAFETY: a probe.\n"
                                "    unsafe { syscall(SYS_BPF, BPF_PROG_QUERY, attr, size, ZERO, ZERO, ZERO) }\n}\n")
        # Probe 3: a nested fn `name` inside link_text, making it read fd/3.
        probe3 = KERNEL_TEXT.replace("        link_at(&self.handle, &name(which.name()), buffer)",
                                     "        fn name(_text: &'static str) -> &'static CStr {\n            c\"fd/3\"\n        }\n"
                                     "        link_at(&self.handle, &name(which.name()), buffer)")
        self.assertNotEqual(probe3, KERNEL_TEXT)
        for text in (probe1, probe2, probe3):
            self.refused(gate.check_observer_sys_names, KERNEL, text, self.RULE)
        # Each probe's own message: the rename, and the item inside a body.
        self.refused(gate.check_observer_sys_names, KERNEL, probe1, "renames self::WIDE as DIR_FLAGS")
        self.refused(gate.check_observer_sys_names, KERNEL, probe3, "holds an item \\(fn\\) inside fn link_text's body")

    def test_other_rebindings_refuse(self):
        link_text = "        link_at(&self.handle, &name(which.name()), buffer)"
        link_at = "    let size = buffer.len() as c_long;\n"
        for text in (
                KERNEL_TEXT + "use std::io as stdio;\n",
                KERNEL_TEXT + "fn f() -> c_long {\n    use self::BPF_OBJ_GET;\n    0\n}\n",
                KERNEL_TEXT + "fn f() -> c_long {\n    const LOCAL: c_long = 2;\n    LOCAL\n}\n",
                KERNEL_TEXT + "fn f() -> c_long {\n    static LOCAL: c_long = 2;\n    LOCAL\n}\n",
                KERNEL_TEXT + "fn f() -> u8 {\n    struct Local;\n    0\n}\n",
                KERNEL_TEXT + "fn f() -> u8 {\n    impl Roots { fn more(&self) -> u8 { 0 } }\n    0\n}\n",
                KERNEL_TEXT + "fn f() -> u8 {\n    mod inner {}\n    0\n}\n",
                KERNEL_TEXT + "const ALIAS: c_long = READ_FLAGS;\n",
                KERNEL_TEXT + "const ALIAS: c_long = BPF_OBJ_GET;\n",
                KERNEL_TEXT + "fn f() -> c_long { FS_IOC_MEASURE_VERITY }\n",
                KERNEL_TEXT.replace(link_text, "        let name = |_text: &str| c\"fd/3\";\n" + link_text),
                KERNEL_TEXT.replace(link_text, "        let link_at = |_d: &File, _n: &CStr, _b: &mut [u8]| 0;\n" + link_text),
                KERNEL_TEXT.replace(link_at, link_at + "    let name: &CStr = c\"fd/3\";\n"),
                KERNEL_TEXT.replace(link_at, link_at + "    let raw = |_handle: &File| -100;\n"),
                KERNEL_TEXT.replace("        let mut buffer = [0u8; 32];\n",
                                    "        let mut buffer = [0u8; 32];\n        let name = |_text: &str| c\"thread-self\";\n"),
                KERNEL_TEXT.replace("    pub fn link_text(&self, which: ProcLink, buffer: &mut [u8]) -> c_long {",
                                    "    pub fn link_text(&self, which: ProcLink, buffer: &mut [u8], name: fn(&str) -> &CStr) -> c_long {")):
            self.refused(gate.check_observer_sys_names, KERNEL, text, self.RULE)
        # The `const` of a raw pointer type is not an item.
        self.write(KERNEL, KERNEL_TEXT + "fn pointer(value: &u8) -> *const u8 {\n    let pointer: *const u8 = value;\n"
                   "    pointer\n}\n")
        self.assertEqual(gate.check_observer_sys_names(self.base), 16)



class ObserverLinkPinTests(Tree):
    """HE-004D1 PR review round 2, R2-1 (G-D1-7): kernel.rs's link_text, own_pid and link_at equal their pinned
    signatures and bodies, whitespace and comments aside; the reviewer's two probes (a rebound `which`, a retyped
    `which`), a changed body, a changed parameter type, an added parameter, a changed visibility, a generic parameter and
    a second definition refuse. Run on the real kernel.rs."""

    RULE = "link-read path pinned, R2-1"
    PROBE = "struct Probe;\nimpl Probe {\n    fn name(self) -> &'static str {\n        \"fd/3\"\n    }\n}\n"
    LINK_TEXT = "    pub fn link_text(&self, which: ProcLink, buffer: &mut [u8]) -> io::Result<usize> {\n"
    LINK_CALL = "        link_at(&self.handle, &name(which.name())?, buffer)\n"
    OWN_PID = "    pub fn own_pid(&self) -> io::Result<i32> {\n"
    LINK_AT = "\nfn link_at(dir: &File, name: &CStr, buffer: &mut [u8]) -> io::Result<usize> {\n"

    def setUp(self):
        super().setUp()
        self.real = (gate.HE / KERNEL).read_text(encoding="utf-8")
        for anchor in (self.LINK_TEXT, self.LINK_CALL, self.OWN_PID, self.LINK_AT, ".min(LINK_BUFFER)", 'name("self")'):
            self.assertEqual(self.real.count(anchor), 1, anchor)
        self.write(KERNEL, self.real)

    def probe(self, old, new, extra=""):
        text = self.real.replace(old, new) + extra
        self.assertNotEqual(text, self.real)
        return text

    def test_the_real_tree_passes(self):
        self.assertEqual(gate.check_observer_link_pins(self.base), 3)
        self.assertEqual(list(gate.LINK_PATH_PINS), ["link_text", "own_pid", "link_at"])
        # Whitespace and comments do not count.
        self.write(KERNEL, self.probe(self.LINK_CALL, "        // a comment\n        link_at(\n            &self.handle,"
                                      " /* a block comment */ &name(which.name())?,\n            buffer,\n        )\n"
                                      .replace(",\n        )", "\n        )")))
        self.assertEqual(gate.check_observer_link_pins(self.base), 3)
        # Top-level text outside the three functions does not count either.
        self.write(KERNEL, self.real + self.PROBE)
        self.assertEqual(gate.check_observer_link_pins(self.base), 3)

    def test_the_reviewer_s_two_probes_refuse(self):
        # Probe 1: `which` rebound to a type whose name() returns "fd/3".
        rebound = self.probe(self.LINK_CALL, "        let which = Probe;\n" + self.LINK_CALL, self.PROBE)
        # Probe 2: the parameter `which` retyped to that type.
        retyped = self.probe(self.LINK_TEXT, self.LINK_TEXT.replace("which: ProcLink", "which: Probe"), self.PROBE)
        for text in (rebound, retyped):
            self.refused(gate.check_observer_link_pins, KERNEL, text, "fn link_text differs from its pinned signature")

    def test_a_changed_body_refuses(self):
        self.refused(gate.check_observer_link_pins, KERNEL, self.probe(".min(LINK_BUFFER)", ".min(LINK_BUFFER + 1)"),
                     "fn link_text differs")
        self.refused(gate.check_observer_link_pins, KERNEL, self.probe('name("self")', 'name("thread-self")'),
                     "fn own_pid differs")
        self.refused(gate.check_observer_link_pins, KERNEL, self.probe(self.LINK_CALL, self.LINK_CALL.replace(
            "&self.handle", "&self.proc_root")), "fn link_text differs")

    def test_a_changed_parameter_type_refuses(self):
        self.refused(gate.check_observer_link_pins, KERNEL, self.probe(self.LINK_AT, self.LINK_AT.replace(
            "name: &CStr", "name: &CString")), "fn link_at differs")

    def test_an_added_parameter_refuses(self):
        self.refused(gate.check_observer_link_pins, KERNEL, self.probe(self.OWN_PID, self.OWN_PID.replace(
            "(&self)", "(&self, _extra: u8)")), "fn own_pid differs")
        self.refused(gate.check_observer_link_pins, KERNEL, self.probe(self.LINK_TEXT, self.LINK_TEXT.replace(
            "buffer: &mut [u8])", "buffer: &mut [u8], _name: &CStr)")), "fn link_text differs")

    def test_other_signature_edits_refuse(self):
        for text, function in (
                (self.probe(self.LINK_AT, self.LINK_AT.replace("\nfn link_at(", "\npub fn link_at(")), "link_at"),
                (self.probe(self.LINK_TEXT, self.LINK_TEXT.replace("fn link_text(", "fn link_text<P>(")), "link_text"),
                (self.probe(self.OWN_PID, self.OWN_PID.replace("io::Result<i32>", "io::Result<i64>")), "own_pid")):
            self.refused(gate.check_observer_link_pins, KERNEL, text, "fn %s differs" % function)
        # A second definition of a pinned function refuses as well.
        self.refused(gate.check_observer_link_pins, KERNEL,
                     self.real + "struct Other;\nimpl Other {\n    pub fn own_pid(&self) -> i32 {\n        0\n    }\n}\n",
                     "not exactly one fn own_pid")
        self.refused(gate.check_observer_link_pins, KERNEL, self.probe(self.LINK_AT, "\nfn link_at_moved(dir: &File, "
                     "name: &CStr, buffer: &mut [u8]) -> io::Result<usize> {\n"), "not exactly one fn link_at")


class ObserverSysRenameScopeTests(Tree):
    """HE-004D1 PR review round 2, R2-2: the no-rename rule covers every observer-sys source, so a renaming `pub use` in
    lib.rs (or a renaming use in dirent.rs or a new module) refuses."""

    TREE = D1_TREE
    RULE = "observer-sys pinned names, R1-2"

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_sys_names(self.base), 15)
        # A re-export without a rename keeps passing.
        self.write(gate.OBSERVER_SYS_LIB, OBSERVER_SYS_LIB_TEXT + "pub use kernel::Roots;\n")
        self.assertEqual(gate.check_observer_sys_names(self.base), 15)

    def test_a_renaming_use_outside_kernel_rs_refuses(self):
        self.refused(gate.check_observer_sys_names, gate.OBSERVER_SYS_LIB,
                     OBSERVER_SYS_LIB_TEXT + "pub use kernel::Roots as Handles;\n",
                     "%s renames kernel::Roots as Handles" % gate.OBSERVER_SYS_LIB)
        self.refused(gate.check_observer_sys_names, gate.OBSERVER_SYS_LIB,
                     OBSERVER_SYS_LIB_TEXT + "pub use kernel::{Roots as Handles, ProcLink};\n", "renames kernel::Roots as Handles")
        self.refused(gate.check_observer_sys_names, OBSERVER_SYS_DIRENT, "use std::io as stdio;\n" + OBSERVER_SYS_DIRENT_TEXT,
                     "%s renames std::io as stdio" % OBSERVER_SYS_DIRENT)
        self.refused(gate.check_observer_sys_names, "crates/observer-sys/src/extra.rs", "pub use crate::kernel::Roots as R;\n",
                     self.RULE)


class ObserverSysPinTests(Tree):
    """HE-004D1 PR review round 3, R3-1 (monitor decision (a)): observer-sys's kernel.rs is pinned whole by sha256. The
    real file passes; a one-byte change, a missing file and a symlink refuse; the reviewer's four R3-1 edits, each outside
    the three R2-1 functions (which still pass their pins), refuse by the pin alone. Run on the real kernel.rs."""

    RULE = "observer-sys pin, R3-1"
    FREE_NAME = '    CString::new(text).map_err(|_| refusal("a name holds NUL"))\n'
    PROC_LINK = "impl ProcLink {\n    fn name(self) -> &'static str {\n"
    FD3 = "    fn name(self) -> &'static str {\n        \"fd/3\"\n    }\n}\n"

    def setUp(self):
        super().setUp()
        self.real = (gate.HE / KERNEL).read_bytes()
        self.text = self.real.decode("utf-8")
        for anchor in (self.FREE_NAME, self.PROC_LINK):
            self.assertEqual(self.text.count(anchor), 1, anchor)
        self.write_bytes(self.real)

    def write_bytes(self, data):
        path = self.base / KERNEL
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def refuses(self, data, message="differs from its pinned bytes"):
        self.write_bytes(data)
        with self.assertRaisesRegex(gate.GateError, message):
            gate.check_observer_sys_pins(self.base)
        self.write_bytes(self.real)

    def test_the_real_file_passes(self):
        self.assertEqual(set(gate.OBSERVER_SYS_PINS), {KERNEL})
        self.assertEqual(gate.OBSERVER_SYS_PINS[KERNEL], gate.sha256(self.real))
        self.assertEqual(gate.check_observer_sys_pins(self.base), 1)

    def test_a_one_byte_change_refuses(self):
        middle = len(self.real) // 2
        self.refuses(self.real[:middle] + bytes([self.real[middle] ^ 1]) + self.real[middle + 1:])
        self.refuses(self.real + b"\n")
        self.refuses(self.real[:-1])
        self.refuses(self.real.replace(b"\n", b"\r\n", 1))

    def test_a_missing_file_or_a_symlink_refuses(self):
        (self.base / KERNEL).unlink()
        with self.assertRaisesRegex(gate.GateError, "missing or a symlink"):
            gate.check_observer_sys_pins(self.base)
        (self.base / "real.rs").write_bytes(self.real)
        (self.base / KERNEL).symlink_to(self.base / "real.rs")
        with self.assertRaisesRegex(gate.GateError, "missing or a symlink"):
            gate.check_observer_sys_pins(self.base)

    def test_the_reviewer_s_four_edits_refuse(self):
        label = self.text.replace(self.PROC_LINK, self.PROC_LINK.replace("fn name(", "fn label("))
        edits = (
            # (a) The free fn name maps "exe" to "fd/3".
            self.text.replace(self.FREE_NAME, self.FREE_NAME.replace(
                "CString::new(text)", 'CString::new(if text == "exe" { "fd/3" } else { text })')),
            # (b) ProcLink's inherent name() renamed, a name() returning "fd/3" in a path-qualified impl.
            label + "impl crate::kernel::ProcLink {\n" + self.FD3,
            # (c) The same through a type alias.
            label + "type Which = ProcLink;\nimpl Which {\n" + self.FD3,
            # (d) The same through a trait impl.
            label + "trait Named {\n    fn name(self) -> &'static str;\n}\nimpl Named for ProcLink {\n" + self.FD3)
        for text in edits:
            self.assertNotEqual(text, self.text)
            self.write_bytes(text.encode("utf-8"))
            # The R2-1 pins still pass: the edit is outside link_text, own_pid and link_at.
            self.assertEqual(gate.check_observer_link_pins(self.base), 3)
            self.refuses(text.encode("utf-8"), "%s differs from its pinned bytes \\(%s\\)" % (KERNEL, self.RULE))

class OutputPrefixTests(unittest.TestCase):
    def test_every_line_carries_the_prefix(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            gate.say("packet=0000\noffline-acceptance argv: [\"x\"]\n\nlast")
            gate.say("")
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 5)
        self.assertTrue(all(line.startswith(gate.PREFIX) for line in lines))

    def test_failures_are_reported_with_the_prefix(self):
        output = io.StringIO()
        with mock.patch.object(gate, "self_test", side_effect=gate.GateError("first\nsecond")), \
                contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 1)
        lines = output.getvalue().splitlines()
        self.assertEqual(lines, [gate.PREFIX + "FAILED: GateError: first", gate.PREFIX + "second"])


if __name__ == "__main__":
    unittest.main()
