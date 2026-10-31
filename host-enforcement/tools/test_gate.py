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
    # HE-005A0: role-seal's root joins the scanned crates (CRATE_ROOTS), so every tree built on this one holds one more
    # linked and workspace source.
    "crates/role-seal/src/lib.rs": "//! The role-neutral seal.\n#![forbid(unsafe_code)]\n",
    # HE-005A: the broker's library and binary roots and its one socket file join the scanned crates (CRATE_ROOTS,
    # SOCKET_FILES), so every tree built on this one holds three more linked sources and two more workspace sources (its
    # main.rs was one already). The unlinked binary crate of the tests below is containment's.
    "crates/broker/src/lib.rs": "//! The capacity broker.\n#![forbid(unsafe_code)]\npub mod linux_listen;\n",
    "crates/broker/src/main.rs": "#![forbid(unsafe_code)]\nfn main() {}\n",
    "crates/broker/src/linux_listen.rs": "use gate_sys::channel;\n"
                                         "pub struct LinuxI02 { listener: Option<channel::Listener> }\n"
                                         "pub fn new(_sealed: &Sealed) -> LinuxI02 { x() }\n",
    # HE-005C (the frozen seam note section 1): broker-sys joins the scanned crates and CRATE_ROOTS, so every tree
    # built on this one holds one more linked and workspace source, its crate root.
    "crates/broker-sys/src/lib.rs": "//! The broker's raw calls.\n#![deny(unsafe_code)]\n",
    "target/debug/build/out.rs": "unsafe fn generated() {}\n",
}
# The unlinked binary crate (HE-005A: the broker is linked now): outside every linked-crate scan.
UNLINKED_MAIN = "crates/containment/src/main.rs"


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
        self.assertEqual(gate.check_linked_sources(self.base), 16)
        self.assertEqual(gate.check_unsafe(self.base), 17)
        self.assertEqual(gate.check_included_code(self.base), 17)

    def test_forbidden_names_in_linked_sources(self):
        for text in ("use std::process::Command;", "let _ = std::env::args_os();", "use std::net::TcpStream;",
                     "use std::path::Path;", "fn f(_: &Path) {}", "fn f(_: PathBuf) {}", "let _ = DirBuilder::new();",
                     "let _ = OpenOptions::new();", "let _ = File::open(x);", "let _ = File::create(x);",
                     "let _ = File::options();", "Err(TryLockError::WouldBlock) => {}", "fn f(_: Metadata) {}"):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", "linked-source tripwire")
            self.refused("crates/gate-sys/src/openat.rs", LINKED_TREE["crates/gate-sys/src/openat.rs"] + text + "\n",
                         "linked-source tripwire")
        # Tests and other crates are outside the linked-source tripwire (the start-up lint and the unsafe rule still apply).
        self.write(UNLINKED_MAIN, "use std::path::Path;\nfn main() {}\n")
        self.assertEqual(gate.check_linked_sources(self.base), 16)

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
        self.assertEqual(gate.check_linked_sources(self.base), 16)

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
        self.assertEqual(gate.check_linked_sources(self.base), 16)

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
        self.assertEqual(gate.check_linked_sources(self.base), 16)

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
        self.assertEqual(gate.check_linked_sources(self.base), 16)

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
        self.assertEqual(gate.check_unsafe(self.base), 17)

    # HE-002S DESIGN section 6: gate-sys's seal.rs is the second file that may contain the word unsafe.
    def test_unsafe_is_also_allowed_in_gate_sys_seal(self):
        self.write("crates/gate-sys/src/seal.rs", "#![allow(unsafe_code)]\nfn f() -> i32 { unsafe { prctl(38, 1) } }\n")
        self.assertEqual(gate.check_unsafe(self.base), 18)
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
        self.assertEqual(gate.check_included_code(self.base), 17)

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
        self.write(UNLINKED_MAIN, "fn main() { let asm = 1; let _ = asm; }\n")
        self.assertEqual(gate.check_included_code(self.base), 18)
        self.assertEqual(gate.check_linked_sources(self.base), 16)

    # HE-002S DESIGN section 5 (D7): std APIs that reach a call the EFFECT_GATE filter kills, in effect-gate, gate-sys
    # and (PR review round 1, R1-2) i05-protocol, whose code runs after the seal too; is_terminal joins the list.
    def test_post_seal_std_apis(self):
        # HE-005A: the broker's three sources join the gate's eight; HE-005C (Q-U4-1 (a)): broker-sys's root, twelve.
        self.assertEqual(gate.check_post_seal_sources(self.base), 12)
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
        self.write(UNLINKED_MAIN, "fn main() { let _ = std::io::stdin().is_terminal(); }\n")
        self.write("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                   + "fn g(f: &File) { let _ = f.try_clone(); let _ = copy_from_slice; let _ = terminal; }\n")
        self.assertEqual(gate.check_post_seal_sources(self.base), 12)
        # HE-005A: the broker's code runs after its seal, so the list refuses there too.
        self.refused("crates/broker/src/linux_listen.rs", LINKED_TREE["crates/broker/src/linux_listen.rs"]
                     + "fn f(s: &S) { let _ = s.set_nonblocking(true); }\n", r"set_nonblocking .*\(post-seal check\)",
                     check=gate.check_post_seal_sources)

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
        self.assertEqual(gate.check_linked_sources(self.base), 16)

    def test_nested_globs_and_std_aliases(self):
        for text, message in (("use std::collections::*;", "nested glob of std"),
                              ("use std :: io :: prelude :: * ;", "nested glob of std"),
                              ("use std::os::unix::prelude::*;", "std::os item other than"),
                              ("use {std as s};", "renames std"), ("pub use { std  as  s };", "renames std")):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", message)
        self.write("crates/i05-protocol/src/json.rs", "mod tests { use super::*; }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 16)

    def test_raw_identifiers_and_inline_assembly(self):
        for rel in ("crates/i05-protocol/src/json.rs", "crates/broker/src/main.rs", "crates/effect-gate/tests/files.rs"):
            for text, message in (("let _ = std::r#process::Command::new(x);", "uses a raw identifier"),
                                  ("use r#std as s;", "uses a raw identifier"),
                                  ('#[r#path = "x.inc"] mod m;', "uses a raw identifier"),
                                  ('core::arch::global_asm!("");', "uses inline assembly"),
                                  ('fn f() { asm ! ("nop") }', "uses inline assembly")):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", message, check=gate.check_included_code)
        self.write("crates/broker/src/main.rs", 'fn main() { let _ = r#"raw string"#; let asm = 1; }\n')
        self.assertEqual(gate.check_included_code(self.base), 17)

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
        self.assertEqual(gate.check_included_code(self.base), 17)

    # HE-002C PR review round 1, R1-1: the forms that passed the first tripwire.

    def test_grouped_std_imports(self):
        for text in ("use std::{process::Command};", "use std :: {net::TcpStream};", "pub use ::std::{env};",
                     "use std::*;", "pub use std :: * ;"):
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "top-level group or glob of std")
        self.write("crates/i05-protocol/src/json.rs", "use std::collections::{BTreeMap, BTreeSet};\n")
        self.assertEqual(gate.check_linked_sources(self.base), 16)

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
        self.assertEqual(gate.check_linked_sources(self.base), 16)

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
        self.assertEqual(gate.check_included_code(self.base), 17)

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
        self.assertEqual(gate.check_included_code(self.base), 17)

    def test_non_rs_files_under_src(self):
        for rel in ("crates/gate-sys/src/extra.inc", "crates/gate/src/extra.txt", "crates/effect-gate/src/sub/x.rs.txt"):
            self.refused(rel, "#![allow(unsafe_code)]\nunsafe fn f() {}\n", "not a .rs file", check=gate.check_included_code)
        os.symlink("../tests", self.base / "crates/effect-gate/src/linked")
        with self.assertRaisesRegex(gate.GateError, "symlink under crates/"):
            gate.check_included_code(self.base)
        (self.base / "crates/effect-gate/src/linked").unlink()
        self.write("crates/effect-gate/tests/data.json", "{}\n")
        self.assertEqual(gate.check_included_code(self.base), 17)


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
    # HE-005C (the frozen seam note section 1; G-HE5C-7): broker-sys's audited module, the sixth, with its one foreign
    # item in G-D1-3's form (FOREIGN_ITEMS requires the file).
    "crates/broker-sys/src/raw.rs": "#![allow(unsafe_code)]\nunsafe extern \"C\" {\n"
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
        self.assertEqual(gate.check_foreign_items(self.base), 21)
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
        self.write(UNLINKED_MAIN, "unsafe extern \"C\" { fn system(c: *const u8) -> i32; }\nfn main() {}\n")
        self.assertEqual(gate.check_foreign_items(self.base), 21)

    def test_extern_items_are_private_and_not_safe(self):
        seal = "crates/gate-sys/src/seal.rs"
        for old, new, message in (("    fn prctl(", "    pub fn prctl(", "public foreign item"),
                                  ("    fn prctl(", "    pub(crate) fn prctl(", "public foreign item"),
                                  ("    fn getresuid(", "    safe fn getresuid(", "safe foreign item"),
                                  ("    fn capget(", "    pub safe fn capget(", "public foreign item")):
            self.refused(seal, FOREIGN_TREE[seal].replace(old, new), message)
        # A comment inside the block is not read; the word unsafe before extern is not the word safe.
        self.write(seal, FOREIGN_TREE[seal].replace("    fn prctl(", "    // not pub, not safe\n    fn prctl("))
        self.assertEqual(gate.check_foreign_items(self.base), 21)

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
        self.assertEqual(gate.check_foreign_items(self.base), 21)

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
        self.assertEqual(gate.check_foreign_items(self.base), 21)

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
    # HE-004D2 (DESIGN-D2 section 2, G-D2-1): edge record v6's five HE-004D2 rows join them (40), and unit B1's six of edge
    # record v7 (46). HE-004-I01a unit U1 (DESIGN-I01A section 3): edge record v8's two seccomp-v5 OBSERVER rows (48);
    # unit U6 (DESIGN-I01A section 10): its two I06 v4 rows (50). HE-004-I01A2, unit U7 (DESIGN-I01A sections 3 and 7):
    # edge record v9's two I01 wire rows (52). HE-004-I01B1 (DESIGN-I01B rev 3 section 2, G-I01B-2): edge record v10's
    # four rows, the I01 digest contract's three files and the proxy-contract vectors beside the wire's two (56).
    # HE-004-I01B4 (DESIGN-I01B4 rev 2 sections 1.2 and 5, G-I01B-2): edge record v11's seven rows, the contract v2's three
    # files, admission v4's three and profile v2's vectors, beside the held v1 and admission v3 files (63).
    # HE-005A (DESIGN-HE005 revision 5 sections 2 and 4): edge record v11's four seccomp-v3 BROKER and WORKER programs (67).
    # HE-005B (DESIGN-HE005 revision 5 section 4, G-HE5B-4): edge record v12's two broker handoff rows 80 and 81 (69).
    def test_the_table_pins_the_effect_gate_programs(self):
        self.patch.stop()
        try:
            self.assertEqual(len(gate.CONTRACTS), 69)
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/broker-handoff-v1/")}, {
                "contracts/broker-handoff-v1/channel.schema.json":
                    "e7e9558fb50b7ba804222065734d1d4fb4694327bb2427a34ef8dffc945d56f9",
                "contracts/broker-handoff-v1/vectors.json":
                    "80d8da953c41ef544ecf0cd4a0f62b98316b018bfbdc39c550c320f68ab603c4"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith(("contracts/seccomp-v3/BROKER", "contracts/seccomp-v3/WORKER"))}, {
                "contracts/seccomp-v3/BROKER.aarch64.bpf": "bc9c5a3797277ca753b5168e8e55132e1878fed2a726de361fd7d80e0fababf8",
                "contracts/seccomp-v3/BROKER.x86_64.bpf": "95221bd0db753aa22ead2eb49eeac8dae3d24c3dad72811de86c9392f4894dcc",
                "contracts/seccomp-v3/WORKER.aarch64.bpf": "cc04a4710495d3794b0d295613a2f2bd330524a328cb6963a819565bac2acb40",
                "contracts/seccomp-v3/WORKER.x86_64.bpf": "5616c9099324e441674f8e589b6c705ae95f6a4a697f10e761565d0735689d45"})
            self.assertEqual(sorted(gate.BROKER_PROGRAMS.values()), ["contracts/seccomp-v3/BROKER.aarch64.bpf",
                                                                     "contracts/seccomp-v3/BROKER.x86_64.bpf"])
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/i01-v1/")}, {
                "contracts/i01-v1/channel.schema.json": "fb69b77201d9b6275a19667a5f5770537f382ddb11309095733628c8430bdc0e",
                "contracts/i01-v1/vectors.json": "1bfb46776636f800e38ab6a8f94a0989aa38513fb4a28ef18e61e732a115c124",
                "contracts/i01-v1/proxy-contract-vectors.json":
                    "edf32ddf992e06e8786fd331affdb4d2ecd5538ca874d52c37439386793a8eb7"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/i01-digests-v1/")}, {
                "contracts/i01-digests-v1/definitions.json":
                    "086692065cfc9da101f770fa39c50af2e2650a169595526e9860fc805478c2aa",
                "contracts/i01-digests-v1/vectors.json":
                    "bd9f04bd04fcccc584bcab341ec649bcead567fe349c57e30958eaaf2ea64f84",
                "contracts/i01-digests-v1/README.md": "e393dd11c75f527829bb6522c5643cb593b6dc67e2788f5e280ce9de0f4166ae"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/i01-digests-v2/")}, {
                "contracts/i01-digests-v2/definitions.json":
                    "fef08fddfb94e06eeff5bc4bdaf37246f9142fd072dd6427f629350c8d5cb2f2",
                "contracts/i01-digests-v2/vectors.json":
                    "68eab4709431f73ce6f977aad7e5a087dccf9b5635c4ce04b8c08387bdce2594",
                "contracts/i01-digests-v2/README.md": "fbb28445c5ec35bbf65bec5d852bd94de8b7c4acf8d2c239ee234e00c10d6090"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/admission-v4/")}, {
                "contracts/admission-v4/README.md": "f7794aa857aa50800f05b651f7b0a56eda7407f67855bc2f0437b27b3fe297fa",
                "contracts/admission-v4/vectors.json": "5706b1a8df5cabd978caa219400b40a9c4ef6cbdbca8ea2f7c6f69b69474301c",
                "contracts/admission-v4/admission-manifests/planeon-a2.json":
                    "92c21612304cb704d13b506c1ae885d62a47c01f0ed0d284affe563aa1868e32"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/i01-v2/")}, {
                "contracts/i01-v2/proxy-profile-v2-vectors.json":
                    "011a650bcd2a11f2eaeba531693f3e7ee9c30c1f6ede2d5ecf87919f206affcc"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/i06-v4/")}, {
                "contracts/i06-v4/criteria.json": "10aa3a8fe08a930e3a4a13f7a11b38404cd82bd1a12164a40ef13141af37d09a",
                "contracts/i06-v4/vectors.json": "27aba3bf7296a08b90adef1663d6498fda9ae98499707d0c0950aa6c4ba14eb7"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/native-profile-")}, {
                "contracts/native-profile-v4/qualification.schema.json":
                    "c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10",
                "contracts/native-profile-v4/vectors.json":
                    "dede64ab3202a9e28094f062b5dad868c13ca02423e2380af8666ecf2e7a86e6",
                "contracts/native-profile-v4/README.md": "a4205a5388dc83827bb39670bcc9477b030f29829128abf19f7578321c170174",
                "contracts/native-profile-v3/qualification.schema.json":
                    "ae5cbb6aa39f4edfa2d9919f25e55bad9ab214a99ca927c5afe7e2d943946ac5",
                "contracts/native-profile-v1/qualification.schema.json":
                    "bef248bfa82b234124c014f98e40c5791bced3171bb118b7ed1bb7b8daaf95c3",
                "contracts/native-profile-v2/qualification.schema.json":
                    "55bd641fd229f21e04ec00813bcfe600890584e982e290a210720ac5cb160ab0",
                "contracts/native-profile-v5/qualification.schema.json":
                    "70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113",
                "contracts/native-profile-v5/vectors.json": "b630c362b20bfa7b362bb2ee28734a403303a0dc54b2d627c11a332b226333a1",
                "contracts/native-profile-v5/README.md": "76b584ca769f0afdd5142fcf3f96e3b5b2d053a172d5713f970dc77594e77692",
                "contracts/native-profile-v1/vectors.json": "cd1be009b721bb596887335184a33ab8e1f24aed8215477b63e28f058110748f",
                "contracts/native-profile-v2/vectors.json": "6d58d1f36b7bce5739b94dd89512d358b96878c70e1de7cf8f399050b881b396",
                "contracts/native-profile-v3/vectors.json": "14af47a69c972039294be8659c31332acd5326bfb0a3a38384a2c6bf9d11fe6d"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith("contracts/i06-v3/")}, {
                "contracts/i06-v3/vectors.json": "4752b648abdd82d21ea622a1b26c721143577478c0a2491204e0d584c1d6f081",
                "contracts/i06-v3/criteria.json": "752533c57b5f93e4c4158a9c17b52eb88d236a3632ab0b66b669e8f8041f57c7",
                "contracts/i06-v3/README.md": "9ee406f43060f266a7b5dd2679aa8352f0815584c45e33d0ab193ea7f90c0c77"})
            self.assertEqual({path: digest for path, digest in gate.CONTRACTS.items()
                              if path.startswith(("contracts/i06-v1/", "contracts/i06-v2/", "contracts/admission-v3/"))}, {
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
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v5/OBSERVER.aarch64.bpf"],
                             "887bf07824d7c1e6ec6db991473935d31500e0c78fac345058972a0f777ad184")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v5/OBSERVER.x86_64.bpf"],
                             "a20d2a956393b3af72799eaad5fa2c4a3cd82f38bf3842c0dea7c42012e525b9")
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
        self.assertEqual(gate.check_unsafe(self.base), 22)
        for rel in ("crates/gate-sys/src/channel/raw.rs", "crates/effect-gate/src/channel.rs",
                    "crates/effect-gate/src/substrate.rs", "crates/gate-sys/src/peer_wire.rs"):
            self.refused(gate.check_unsafe, rel, "fn f() { unsafe { g() } }\n", "contains unsafe outside .*channel.rs")

    def test_the_channel_module_declares_exactly_its_twelve_symbols(self):
        self.assertEqual(gate.check_foreign_items(self.base), 21)
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
        self.assertEqual(gate.check_linked_sources(self.base), 21)
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
    UNLINKED_MAIN: "#[derive(Debug)]\nstruct S { f: std::fs::File }\nfn main() {}\n",
}


class DebugDeriveTests(Tree):
    """HE-003A DESIGN section 8: no derive(Debug), also under cfg_attr, on a struct or enum of the linked crates whose
    field types mention File, Dir, FileStores, Conn, Listener, Poller, PidFd or ProcDir; field and variant names are not
    types, manual impls pass, and the binary crates are not linked."""

    TREE = DEBUG_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_debug_derives(self.base), 17)

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
        self.assertEqual(gate.check_debug_derives(self.base), 18)


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
        # HE-005A0: role-seal joins it (its one dependency gate-sys), so the HE-004D1 shape refuses too.
        self.write("Cargo.toml", WORKSPACE_TREE["Cargo.toml"].replace(
            '"crates/gate-tls"]', '"crates/gate-tls", "crates/observer", "crates/observer-sys", "crates/role-seal"]'))
        self.write("crates/observer/Cargo.toml", '[package]\nname = "planeon-observer"\nedition.workspace = true\n')
        self.write("crates/observer-sys/Cargo.toml", '[package]\nname = "observer-sys"\nedition.workspace = true\n')
        self.write("crates/role-seal/Cargo.toml", '[package]\nname = "role-seal"\nedition.workspace = true\n')
        self.assertEqual(gate.OBSERVER_LINKED_CRATES, ("crates/observer", "crates/gate-sys", "crates/i05-protocol",
                                                       "crates/observer-sys", "crates/role-seal"))
        good = {**WORKSPACE, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys", "role-seal"},
                "observer-sys": set(), "role-seal": {"gate-sys"}}
        self.assertEqual(gate.check_workspace_shape(self.base, good), 8)
        self.assertEqual(gate.check_workspace_shape(self.base, {**good, "planeon-observer": {"i05-protocol", "observer-sys",
                                                                                             "role-seal"},
                                                                "i05-protocol": {"gate-sys"}}), 8)
        for dependencies in (set(), {"gate-sys"}, {"i05-protocol"}, {"gate-sys", "i05-protocol"},
                             {"gate-sys", "i05-protocol", "observer-sys"},
                             {"gate-sys", "i05-protocol", "observer-sys", "role-seal", "effect-gate"},
                             {"effect-gate"}, {"gate-sys", "i05-protocol", "observer-sys", "role-seal", "planeon-broker"}):
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
        self.assertEqual(gate.check_foreign_items(self.base), 21)
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
        self.assertEqual(gate.check_unsafe(self.base), 22)
        self.write(TCP, FOREIGN_TREE[TCP] + "use std::os::fd::AsRawFd;\nuse std::os::fd::OwnedFd;\n"
                        "fn f() { unsafe { g() } }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 21)
        self.assertEqual(gate.check_unsafe(self.base), 22)
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
        self.assertEqual(gate.check_debug_derives(self.base), 18)

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


# HE-004-I01a (DESIGN-I01A section 4): the observer's I01 listener file, the second observer socket file: gate-sys's
# listener and peer in private fields, a pub(crate) API naming only the data type Watched among gate-sys's items.
OBSERVER_LINUX_LISTEN_TEXT = ("use gate_sys::channel::{self, ListenStep};\n"
                              "pub(crate) struct I01Socket { listener: channel::Listener, held: Option<channel::Conn> }\n"
                              "pub(crate) fn watched(s: &I01Socket) -> channel::Watched<'_> { channel::Watched::Listener(&s.listener) }\n"
                              "fn step(s: ListenStep) -> u8 { 0 }\n")
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
               gate.OBSERVER_LINUX_NET: OBSERVER_LINUX_NET_TEXT,
               # HE-004-I01a: its I01 listener file.
               gate.OBSERVER_LINUX_LISTEN: OBSERVER_LINUX_LISTEN_TEXT}


class SocketModuleTests(Tree):
    """HE-003D DESIGN section 5 (D1-3, D2-6): gate-sys's channel and tcp modules are reached only from effect-gate's
    linux_os.rs and linux_net.rs (which re-export nothing) and from gate-sys, by use tree or qualified path; no linked
    source names std::thread or thread::."""

    TREE = SOCKET_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_socket_modules(self.base), 22)

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
        self.assertEqual(gate.check_socket_modules(self.base), 23)

    def test_threads_refuse_in_every_linked_crate(self):
        for rel in ("crates/gate-sys/src/channel.rs", "crates/i05-protocol/src/json.rs", gate.GATE_MAIN,
                    "crates/effect-gate/src/linux_os.rs"):
            for text in ("use std::thread;", "fn f() { std::thread::spawn(g); }", "fn f() { thread :: sleep(d); }"):
                self.refused(gate.check_socket_modules, rel, LINKED_TREE.get(rel, SOCKET_TREE.get(rel, "")) + text + "\n",
                             "names std::thread or thread::")
        self.write("crates/effect-gate/src/linux_os.rs", SOCKET_TREE["crates/effect-gate/src/linux_os.rs"]
                   + "// one thread::\nconst T: &str = \"thread-self\";\nfn threads() {}\n")
        self.assertEqual(gate.check_socket_modules(self.base), 22)


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
        self.assertEqual(gate.check_socket_modules(self.base), 22)
        self.assertEqual(gate.check_macros(self.base), 22)

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

    def test_items_through_a_crate_or_module_alias_refuse(self):
        # HE-004-I01A2 (HE-004-I01a PR review round 1, R1-3): the use paths are read with the source's aliases followed,
        # so a socket item imported or named through a rename of gate_sys or of a socket module refuses in a pub item as
        # its direct form does, in every socket file (effect-gate's two, the observer's two and, from HE-005A, the
        # broker's one).
        message = "pub item naming gate-sys's socket items"
        for rel in ("crates/effect-gate/src/linux_os.rs", "crates/effect-gate/src/linux_net.rs", gate.OBSERVER_LINUX_NET,
                    gate.OBSERVER_LINUX_LISTEN, gate.BROKER_LINUX_LISTEN):
            for text in ("use gate_sys as gs;\nuse gs::channel::{Conn};\npub fn f() -> Conn { x() }\n",
                         "use gate_sys::{self as gs};\nuse gs::{channel::{Poller as P}};\npub type Wire = P;\n",
                         "use gate_sys as gs;\npub fn f() -> gs::channel::Poller { x() }\n",
                         "use gate_sys as gs;\npub fn f() -> gs :: tcp :: TcpConn { x() }\n",
                         "use gate_sys as gs;\nuse gs::channel as c;\nuse c::PidFd;\npub static S: Option<PidFd> = None;\n",
                         "use gate_sys as gs;\nuse gs::tcp::{self as t};\npub fn f() -> t::TcpConn { x() }\n",
                         "use gate_sys as g1;\nuse g1 as g2;\nuse g2::channel::Conn;\npub struct Leak { pub c: Conn }\n"):
                self.refused(gate.check_socket_modules, rel, text, message + "|pub field naming")
            self.refused(gate.check_socket_modules, rel, "use gate_sys as gs;\nuse gs::channel::*;\n",
                         "glob of gate-sys's socket module")
        # A private use through an alias, and the data types through one, pass in effect-gate's files.
        os_rs = "crates/effect-gate/src/linux_os.rs"
        self.write(os_rs, "use gate_sys as gs;\nuse gs::channel::{ListenError, Poller};\nfn private(p: Poller) {}\n"
                   "pub fn new(_s: &Sealed) -> Result<u8, ListenError> { z() }\n")
        self.assertEqual(gate.check_socket_modules(self.base), 22)

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
        self.assertEqual(gate.check_socket_modules(self.base), 22)

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
        self.assertEqual(gate.check_socket_modules(self.base), 22)
        # Comments are not code; the reader refuses an enum it cannot read.
        self.write(os_rs, self.TREE[os_rs] + "// pub enum Leak { P(Poller) }\n")
        self.assertEqual(gate.check_socket_modules(self.base), 22)
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
        self.assertEqual(gate.check_macros(self.base), 23)


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
        self.assertEqual(gate.check_socket_modules(self.base), 22)

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
        self.assertEqual(gate.check_observation(self.base), 20)

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
        self.assertEqual(gate.check_observation(self.base), 21)

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
        self.assertEqual(gate.check_linked_sources(self.base), 20)
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
        self.assertEqual(gate.check_observation(self.base), 20)


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
        self.assertEqual(gate.check_pre_main(self.base), 16)
        self.assertEqual(gate.check_prints(self.base), 16)

    def test_code_before_main_refuses(self):
        for rel in (gate.GATE_MAIN, "crates/effect-gate/src/file_store.rs", "crates/gate-tls/src/lib.rs"):
            for text, name in (("#[unsafe(link_section = \".init_array\")]\nstatic I: fn() = f;", "link_section"),
                               ("#[used]\nstatic K: u8 = 0;", "#\\[used\\]"), ("# [ used ]\nstatic K: u8 = 0;", "#\\[used\\]"),
                               ("const S: &str = init_array;", "init_array"), ("#[unsafe(no_mangle)]\nfn f() {}", "no_mangle"),
                               ("#[unsafe(export_name = \"main\")]\nfn f() {}", "export_name")):
                self.refused(gate.check_pre_main, rel, LINKED_TREE[rel] + text + "\n", name + " .code before main")
        self.write(gate.GATE_MAIN, LINKED_TREE[gate.GATE_MAIN] + "// no link_section, #[used] or no_mangle here\n")
        self.assertEqual(gate.check_pre_main(self.base), 16)

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
        self.assertEqual(gate.check_prints(self.base), 16)


class LinkedBinaryTests(Tree):
    """HE-003D DESIGN section 5 (O4): the binary's crate is linked, with its crate-root attribute and exactly one exit
    import, removed once before the refused-path scan."""

    TREE = LINKED_TREE

    def test_the_exit_import_is_allowed_once_in_main(self):
        main = gate.GATE_MAIN
        good = LINKED_TREE[main] + "use std::process::ExitCode;\nfn run() -> ExitCode { ExitCode::from(2) }\n"
        self.write(main, good)
        self.assertEqual(gate.check_linked_sources(self.base), 16)
        self.write(main, LINKED_TREE[main] + "use std :: process ::\n    ExitCode ;\n")
        self.assertEqual(gate.check_linked_sources(self.base), 16)
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
        self.assertEqual(gate.check_foreign_items(self.base), 21)
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
    use planeon_observer::i01_request::I01Binding;
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
    let Ok((config, record_ref)) = ObserverConfig::parse_v3(&document) else { return status::CONFIG_CHECK };
    drop(document);
    if let Err(error) = config::check_lifetime(&config, utc::wall_seconds()) {
        return status::lifetime(&error);
    }
    let Some(binding) = I01Binding::from_config(config.binding()) else { return status::CONFIG_CHECK };
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
    let server = match enrolled.server_identity() {
        Ok(server) => server,
        Err(error) => return status::capture_setup(&error),
    };
    let wire = match LinuxWire::new(sealed) {
        Ok(wire) => wire,
        Err(error) => return status::wire_setup(&error),
    };
    let capture = match LinuxCapture::new(sealed) {
        Ok(capture) => capture,
        Err(error) => return status::capture_setup(&error),
    };
    let Ok(closure) = Closure::embedded() else { return status::CLOSURE };
    let captures = Box::new(CaptureEngine::new(capture, enrolled, schema));
    status::observation(&observe::run(wire, config, tls, closure, captures, server, binding))
}
"""
OBSERVER_SEAL = "crates/observer/src/seal.rs"
OBSERVER_TREE = {**FOREIGN_TREE, gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN,
                 "crates/effect-gate/src/linux_os.rs": SOCKET_TREE["crates/effect-gate/src/linux_os.rs"],
                 "crates/effect-gate/src/linux_net.rs": SOCKET_TREE["crates/effect-gate/src/linux_net.rs"],
                 # HE-004C (G4): the observer's socket module; HE-004-I01a: its I01 listener file.
                 gate.OBSERVER_LINUX_NET: OBSERVER_LINUX_NET_TEXT,
                 gate.OBSERVER_LINUX_LISTEN: OBSERVER_LINUX_LISTEN_TEXT,
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
        self.assertEqual(gate.SCANNED_CRATES, gate.LINKED_CRATES + ("crates/observer", "crates/observer-sys",
                                                                    "crates/role-seal", "crates/broker",
                                                                    "crates/broker-sys"))
        self.assertEqual(gate.OBSERVER_LINKED_CRATES, ("crates/observer", "crates/gate-sys", "crates/i05-protocol",
                                                       "crates/observer-sys", "crates/role-seal"))
        # 13 sources of the gate's linked crates, 6 of the observer's (HE-004C: its socket module; HE-004-I01a: its I01
        # listener file), 2 of observer-sys's (HE-004D1), role-seal's 1 (HE-005A0), the broker's 3 (HE-005A) and
        # broker-sys's 2 (HE-005C).
        for check in (gate.check_linked_sources, gate.check_foreign_items, gate.check_debug_derives, gate.check_socket_modules,
                      gate.check_macros, gate.check_pre_main, gate.check_prints):
            self.assertEqual(check(self.base), 27, check.__name__)
        # HE-004B1: the observer's (5 with HE-004C's socket module, 6 with HE-004-I01a's listener file) and i05-protocol's
        # 2; HE-004D1: observer-sys's 2; HE-005A0: role-seal's 1. The gate's list: its 13 and, from HE-005A, the broker's 3;
        # HE-005C (Q-U4-1 (a)): broker-sys's 2.
        self.assertEqual(gate.check_observer_post_seal(self.base), 11)
        self.assertEqual(gate.check_post_seal_sources(self.base), 18, "the gate's post-seal crates do not include the observer")
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

    def test_role_seal_joins_every_linked_crate_scan(self):
        # HE-005A0 (DESIGN-HE005 section 4, A0): the coverage the observer's seal code had moves with it to role-seal:
        # every linked-crate scan, the observer post-seal list and its crate root; and the print rule refuses printing a
        # Stage1 there (MON-HE005A0-U1).
        root = self.TREE[gate.ROLE_SEAL_LIB]
        for check, text, message in (
                (gate.check_linked_sources, "fn f() { let _ = std::env::args_os(); }", "linked-source tripwire"),
                (gate.check_linked_sources, "use std::net::TcpStream;", "linked-source tripwire"),
                (gate.check_foreign_items, "unsafe extern \"C\" { fn prctl(o: i32, ...) -> i32; }", "declares the foreign items"),
                (gate.check_debug_derives, "#[derive(Debug)]\npub struct S { f: File }", "Debug check"),
                (gate.check_socket_modules, "use gate_sys::channel::Poller;", "socket-module check"),
                (gate.check_socket_modules, "fn f() { std::thread::spawn(g); }", "names std::thread"),
                (gate.check_read_link, "fn f(d: &Dir, b: &mut [u8]) { let _ = d.read_link(\"exe\", b); }",
                 "role-seal/src/lib.rs names read_link"),
                (gate.check_macros, "macro_rules! m { () => {} }", "macro rule"),
                (gate.check_pre_main, "#[unsafe(no_mangle)]\nfn f() {}", "code before main"),
                (gate.check_prints, "fn f() { println!(\"x\"); }", "print rule"),
                (gate.check_prints, "fn show(stage1: &Stage1) { eprintln!(\"{stage1:?}\"); }", "print rule"),
                (gate.check_prints, "fn show(stage1: &Stage1) { let _ = writeln!(std::io::stderr(), \"{stage1:?}\"); }",
                 "print rule"),
                (gate.check_unsafe, "fn f() { unsafe { g() } }", "contains unsafe outside"),
                (gate.check_observer_post_seal, "impl Drop for Sealed { fn drop(&mut self) {} }", "observer post-seal check"),
                (gate.check_observer_post_seal, "fn f(d: &Dir) { let _ = d.sync(); }", "observer post-seal check"),
                (gate.check_observer_post_seal, "fn f() { membarrier(0, 0); }", "observer post-seal check")):
            self.refused(check, gate.ROLE_SEAL_LIB, root + text + "\n", message)
        self.refused(gate.check_linked_sources, gate.ROLE_SEAL_LIB, root.replace("#![forbid(unsafe_code)]", "#![deny(unsafe_code)]"),
                     "lacks #!\\[forbid")
        self.assertEqual(gate.CRATE_ROOTS[gate.ROLE_SEAL_LIB], "#![forbid(unsafe_code)]")
        self.assertEqual(gate.check_observer_post_seal(self.base), 11)

    def test_the_observer_exit_import_once_in_main(self):
        main = gate.OBSERVER_MAIN
        self.assertEqual(gate.check_linked_sources(self.base), 27)
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
        self.assertEqual(gate.check_observer_post_seal(self.base), 11)
        # R1-1: a module path segment, comments and literals pass; drop() is not the Drop trait.
        self.write(OBSERVER_SEAL, seal + "use std::sync::atomic::AtomicU8;\n// Dir::sync, File::lock and impl Drop are refused\n"
                   "fn g(x: u8) -> &'static str { drop(x); \"file lock sync Drop\" }\n")
        self.assertEqual(gate.check_observer_post_seal(self.base), 11)
        for rel in list(OBSERVER_TREE):
            if rel.startswith("crates/observer/"):
                (self.base / rel).unlink()
        with self.assertRaisesRegex(gate.GateError, "crates/observer has no sources .observer post-seal check"):
            gate.check_observer_post_seal(self.base)

    def test_i05_protocol_joins_the_observer_post_seal_list(self):
        # HE-004B1 DESIGN-B section 6 (owner decision Q-HE4B-6 (a)): i05-protocol's sources join the rule, with json.rs's
        # one memory-only `impl Drop for Value` excepted once; gate-sys stays outside.
        self.assertEqual(gate.OBSERVER_POST_SEAL_CRATES, ("crates/observer", "crates/i05-protocol", "crates/observer-sys",
                                                          "crates/role-seal"))
        json_rs = self.TREE[gate.I05_JSON]
        drop = "impl Drop for Value {\n    fn drop(&mut self) { let mut pending = Vec::new(); pending.clear(); }\n}\n"
        self.write(gate.I05_JSON, json_rs + drop)
        self.assertEqual(gate.check_observer_post_seal(self.base), 11)
        self.write(gate.I05_JSON, json_rs + "impl  Drop\n    for Value { fn drop(&mut self) {} }\n")
        self.assertEqual(gate.check_observer_post_seal(self.base), 11)
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
        self.assertEqual(gate.check_observer_post_seal(self.base), 11)


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
        # HE-004-I01a (DESIGN-I01A section 3): the seccomp-v5 programs; the v3 ones stay pinned but are no longer embedded.
        self.assertEqual(gate.OBSERVER_PROGRAMS["x86_64-unknown-linux-musl"], "contracts/seccomp-v5/OBSERVER.x86_64.bpf")
        self.assertEqual(gate.OBSERVER_PROGRAMS["aarch64-unknown-linux-musl"], "contracts/seccomp-v5/OBSERVER.aarch64.bpf")
        self.assertIn("contracts/seccomp-v3/OBSERVER.x86_64.bpf", gate.CONTRACTS)
        self.assertIn("contracts/seccomp-v3/OBSERVER.aarch64.bpf", gate.CONTRACTS)
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
    # HE-004D2 (G-D2-4): every D2 logic module built so far.
    **{rel: "use crate::capture_check::Refusal;\nuse crate::kernel_text;\npub fn d() -> u8 { 0 }\n" for rel in gate.D2_LOGIC},
    # HE-004-I01a: the I01 logic modules built so far (the request checks; the role pin from unit U6).
    **{rel: "use i05_protocol::json::Value;\nuse crate::snapshot;\npub fn i(v: &Value) -> bool { v.is_null() }\n"
       for rel in gate.I01_LOGIC},
}
# HE-004D2 (G-D2-4): the logic modules, B1's five, D1's three and the D2 modules built so far; HE-004-I01a's.
LOGIC_COUNT = 8 + len(gate.D2_LOGIC_BUILT) + len(gate.I01_LOGIC_BUILT)


class ObserverLogicTests(Tree):
    """HE-004B1 DESIGN-B section 6 (D1-7, D2-5, D3-2): the observer logic modules' path-root whitelist, its refused forms
    and words, and the no-panic tripwire outside strict #[cfg(test)] blocks."""

    TREE = LOGIC_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.OBSERVER_LOGIC_NAMES, ("inputs", "rbac", "snapshot", "operational", "admission"))
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)

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

    def test_the_answer_logic_s_whitelist(self):
        # HE-004-I01B3 (DESIGN-I01B3 rev 4 sections 3 and 8; Q-1e (a); I3D-9 (e)): i01_answer takes I01_LOGIC_PATHS plus
        # exactly crate::kernel_text::utc_text and utc_seconds; the clock, the client and kernel_text's other items refuse.
        rel = gate.I01_ANSWER
        self.assertIn((rel, gate.I01_ANSWER_PATHS), gate.LOGIC_MODULES)
        self.assertEqual(gate.I01_ANSWER_PATHS, gate.I01_LOGIC_PATHS + (("crate", "kernel_text", "utc_text"),
                                                                       ("crate", "kernel_text", "utc_seconds")))
        self.assertNotIn("i01_answer", gate.I01_LOGIC_NAMES)
        good = self.TREE[rel]
        self.write(rel, good + "use crate::kernel_text::{utc_seconds, utc_text};\n"
                               "pub fn t(s: u64) -> Option<String> { crate::kernel_text::utc_text(s) }\n")
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)
        for text, message in (("pub fn n() -> u64 { crate::utc::wall_seconds() }\n", "names crate::utc::wall_seconds"),
                              ("use std::time::SystemTime;\n", "imports std::time::SystemTime"),
                              ("pub fn c(x: &crate::client::Client) {}\n", "names crate::client::Client"),
                              ("use crate::kernel_text::utc_millis;\n", "imports crate::kernel_text::utc_millis"),
                              ("pub fn m(t: &str) -> Option<u64> { crate::kernel_text::utc_millis(t) }\n",
                               "names crate::kernel_text::utc_millis")):
            self.refused(gate.check_observer_logic, rel, good + text, re.escape(rel) + " " + message)
        # No other module's whitelist widens: kernel_text's two items stay outside i01_digest's and i01_request's.
        for other in ("crates/observer/src/i01_digest.rs", "crates/observer/src/i01_request.rs"):
            self.refused(gate.check_observer_logic, other, self.TREE[other] + "use crate::kernel_text::utc_text;\n",
                         "imports crate::kernel_text::utc_text")

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
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)


INCLUDE_TREE = {
    **OBSERVER_TREE,
    gate.OBSERVER_CONTRACTS: "pub const A: &[u8] = include_bytes!(\"../../../contracts/i06-v1/identity-closure.json\");\n"
                             "pub const B: &str = include_str! ( \"../../../contracts/i06-v2/README.md\" );\n"
                             "// include_bytes!(\"../../../tools/gate.py\") in a comment\n",
    OBSERVER_SEAL: "pub static X: &[u8; 2024] = include_bytes!(\"../../../contracts/seccomp-v5/OBSERVER.x86_64.bpf\");\n"
                   "pub static A: &[u8; 1936] = include_bytes!(\"../../../contracts/seccomp-v5/OBSERVER.aarch64.bpf\");\n",
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
                 "not an OBSERVER program"),
                # HE-004-I01a (DESIGN-I01A section 3): the seccomp-v3 OBSERVER programs are pinned but no longer embedded.
                (OBSERVER_SEAL, self.TREE[OBSERVER_SEAL] + "pub static C: &[u8] = include_bytes!(\"../../../contracts/seccomp-v3/OBSERVER.x86_64.bpf\");\n",
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
        self.assertEqual(set(gate.REGISTRY_LINES), {"crates/gate-tls", "crates/observer", "crates/broker"})
        # HE-005C (Q-HE5C-2 (a)): the broker's two lines, ring and getrandom, are gate-tls's (and the observer's).
        self.assertEqual(gate.REGISTRY_LINES["crates/broker"],
                         {name: gate.REGISTRY_LINES["crates/gate-tls"][name] for name in ("getrandom", "ring")})
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
            "Cargo.toml": WORKSPACE_TREE["Cargo.toml"].replace(
                '"crates/gate-tls"]', '"crates/gate-tls", "crates/observer", "crates/observer-sys", "crates/role-seal"]'),
            "crates/observer/Cargo.toml": '[package]\nname = "planeon-observer"\nedition.workspace = true\n',
            # HE-004D1 (G-D1-1): observer-sys joins the closure.
            "crates/observer-sys/Cargo.toml": '[package]\nname = "observer-sys"\nedition.workspace = true\n',
            # HE-005A0: role-seal joins the closure.
            "crates/role-seal/Cargo.toml": '[package]\nname = "role-seal"\nedition.workspace = true\n'}

    def test_a_fifth_workspace_path_dependency_refuses(self):
        self.assertEqual(gate.OBSERVER_LINKED_CRATES, ("crates/observer", "crates/gate-sys", "crates/i05-protocol",
                                                       "crates/observer-sys", "crates/role-seal"))
        good = {**WORKSPACE, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys", "role-seal"},
                "observer-sys": set(), "role-seal": {"gate-sys"}}
        self.assertEqual(gate.check_workspace_shape(self.base, good), 8)
        for extra in ("gate-tls", "effect-gate", "planeon-gate"):
            with self.assertRaisesRegex(gate.GateError, "planeon-observer links .*, not .* .workspace shape"):
                gate.check_workspace_shape(self.base, {**good, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys",
                                                                                    "role-seal", extra}})
        # role-seal reaching another workspace crate widens the closure too.
        with self.assertRaisesRegex(gate.GateError, "planeon-observer links .*, not .* .workspace shape"):
            gate.check_workspace_shape(self.base, {**good, "role-seal": {"gate-sys", "effect-gate"}})


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
        # HE-004-I01a (DESIGN-I01A section 4): the I01 listener file is the observer's second socket file.
        self.assertIn(gate.OBSERVER_LINUX_LISTEN, gate.SOCKET_FILES)
        self.assertEqual(gate.OBSERVER_LINUX_LISTEN, "crates/observer/src/linux_listen.rs")
        self.assertEqual(gate.check_socket_modules(self.base), 22)

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

    def test_the_listener_file_hands_out_only_the_watched_view(self):
        # HE-004-I01a (DESIGN-I01A section 4, review r3 I3-1): I01Socket's pub(crate) API names gate-sys's Watched and
        # nothing else of its socket modules; the R1-3 rule reads the listener file as it reads linux_net.rs.
        rel = gate.OBSERVER_LINUX_LISTEN
        for text, message in (("pub(crate) fn raw(s: &I01Socket) -> &channel::Listener { x() }", "pub item naming gate-sys's socket items"),
                              ("pub(crate) fn step(e: &ListenError) -> ListenStep { x() }", "pub item naming gate-sys's socket items"),
                              ("pub(crate) use gate_sys::channel::Conn;", "re-exports"),
                              ("pub(crate) struct Leak { pub(crate) conn: channel::Conn }", "pub field naming gate-sys's socket items"),
                              ("type Held = channel::Conn;", "private type alias")):
            self.refused(gate.check_socket_modules, rel, OBSERVER_LINUX_LISTEN_TEXT + text + "\n", message)
        self.write(rel, OBSERVER_LINUX_LISTEN_TEXT + "pub(crate) fn peer(s: &I01Socket) -> Option<channel::Watched<'_>> { None }\n")
        self.assertEqual(gate.check_socket_modules(self.base), 22)
        (self.base / rel).unlink()
        with self.assertRaisesRegex(gate.GateError, "crates/observer/src/linux_listen.rs is missing .socket-module check"):
            gate.check_socket_modules(self.base)


# HE-004D1 (G-D1-8): twelve steps, one call each; HE-004-I01a: thirteen, the server identity after Enrolled::new.
# HE-004-I01B2 (DESIGN-I01B2 rev 3 section 5; I2D-9): fourteen, configuration v3's parse and the binding's one
# constructor fourth; the wire step is SERVE_STEPS[10].
SERVE_STEPS = (
    "    let document = match signed_config::load() {\n        Ok(document) => document,\n"
    "        Err(error) => return status::config_load(&error),\n    };\n",
    "    let Ok((config, record_ref)) = ObserverConfig::parse_v3(&document) else { return status::CONFIG_CHECK };\n"
    "    drop(document);\n",
    "    if let Err(error) = config::check_lifetime(&config, utc::wall_seconds()) {\n        return status::lifetime(&error);\n    }\n",
    "    let Some(binding) = I01Binding::from_config(config.binding()) else { return status::CONFIG_CHECK };\n",
    "    let Ok((serving_ca, identity)) = credentials::observer_inputs(&config.credentials) else { return status::CREDENTIALS };\n",
    "    let Ok(tls) = client_config(identity, serving_ca, time_provider()) else { return status::TLS_SETUP };\n",
    "    let Ok((schema, record_schema)) = CaptureSchema::embedded() else { return status::CAPTURE_SCHEMA };\n",
    "    let record = match enrolled::load_record(&record_ref) {\n        Ok(record) => record,\n"
    "        Err(error) => return status::capture_setup(&error),\n    };\n",
    "    let enrolled = match Enrolled::new(record, &record_schema, utc::wall_seconds()) {\n        Ok(enrolled) => enrolled,\n"
    "        Err(error) => return status::capture_setup(&error),\n    };\n    drop(record_schema);\n",
    "    let server = match enrolled.server_identity() {\n        Ok(server) => server,\n"
    "        Err(error) => return status::capture_setup(&error),\n    };\n",
    # HE-004-I01A2 (R1-5): main.rs's form, the wire's refusal mapped through status::wire_setup (24, 31-34).
    "    let wire = match LinuxWire::new(sealed) {\n        Ok(wire) => wire,\n"
    "        Err(error) => return status::wire_setup(&error),\n    };\n",
    "    let capture = match LinuxCapture::new(sealed) {\n        Ok(capture) => capture,\n"
    "        Err(error) => return status::capture_setup(&error),\n    };\n",
    "    let Ok(closure) = Closure::embedded() else { return status::CLOSURE };\n",
    "    let captures = Box::new(CaptureEngine::new(capture, enrolled, schema));\n"
    "    status::observation(&observe::run(wire, config, tls, closure, captures, server, binding))\n",
)


class ObserverServeTests(Tree):
    """HE-004C DESIGN-C sections 14 and 15 (G5's wiring rule, D1-1): serve calls the configuration's load, parse and
    lifetime, the credentials, the TLS configuration, the wire, the embedded closure and the epoch each exactly once, in
    that order; missing, swapped and doubled calls refuse, and comments, use declarations and spaced paths are read
    through."""

    TREE = {gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN}

    def test_the_wiring_passes(self):
        self.assertEqual("".join(SERVE_STEPS) in GOOD_OBSERVER_MAIN, True)
        self.assertEqual(gate.check_observer_serve(self.base), 14)
        # HE-004-I01B2 (I2D-9): configuration v3's parse in place of the v2 parse, the binding's constructor fourth.
        self.assertEqual([name for _, name in gate.OBSERVER_WIRING],
                         ["signed_config::load(", "ObserverConfig::parse_v3(", "config::check_lifetime(",
                          "I01Binding::from_config(", "credentials::observer_inputs(", "client_config(",
                          "CaptureSchema::embedded(", "enrolled::load_record(", "Enrolled::new(", "enrolled.server_identity(",
                          "LinuxWire::new(", "LinuxCapture::new(",
                          "Closure::embedded(", "observe::run("])
        # Spaced paths, comments naming the calls and the in-body use declarations are read through.
        spaced = (GOOD_OBSERVER_MAIN.replace("signed_config::load()", "signed_config :: load ()")
                  .replace("Closure::embedded()", "Closure ::embedded ( )")
                  .replace("    use planeon_observer::utc;\n", "    use planeon_observer::utc;\n    // observe::run( again in a comment\n"))
        self.write(gate.OBSERVER_MAIN, spaced)
        self.assertEqual(gate.check_observer_serve(self.base), 14)

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

    def test_the_server_identity_is_the_thirteenth_call(self):
        # HE-004-I01a (DESIGN-I01A sections 6 and 12): enrolled.server_identity() right after Enrolled::new, before the
        # record moves into the capture engine; another receiver or a path spelling is not the call.
        step = "    let server = match enrolled.server_identity() {\n"
        for text in (GOOD_OBSERVER_MAIN.replace(step, "    let server = match record.server_identity() {\n"),
                     GOOD_OBSERVER_MAIN.replace(step, "    let server = match Enrolled::server_identity(&enrolled) {\n"),
                     GOOD_OBSERVER_MAIN.replace(step, step.replace("enrolled.", "enrolled . ") + "    let _again = enrolled.server_identity();\n")):
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, text, "enrolled.server_identity. exactly once|in this order")
        self.write(gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace(step, step.replace("enrolled.", "enrolled . ")))
        self.assertEqual(gate.check_observer_serve(self.base), 14)

    def test_the_wire_s_refusal_maps_through_wire_setup(self):
        # HE-004-I01A2 (HE-004-I01a PR review round 1, R1-5): main.rs's match maps LinuxWire::new's refusal through
        # status::wire_setup (24, 31-34); one status for every setup refusal, another mapping or a lost arm refuses.
        # HE-004-I01B2 (I2D-9): the wire step is the eleventh of fourteen.
        good = SERVE_STEPS[10]
        self.assertIn("status::wire_setup(&error)", good)
        self.assertEqual(GOOD_OBSERVER_MAIN.count(good), 1)
        self.assertEqual(len(gate.WIRE_SETUP_MATCH.findall(GOOD_OBSERVER_MAIN)), 1)
        for new in ("    let Ok(wire) = LinuxWire::new(sealed) else { return status::SOCKETS };\n",
                    good.replace("return status::wire_setup(&error)", "return status::SOCKETS"),
                    good.replace("status::wire_setup(&error)", "status::capture_setup(&error)"),
                    good.replace("status::wire_setup(&error)", "status::wire_setup(&other)"),
                    good.replace("Err(error) => return", "_ => return"),
                    good.replace("Ok(wire) => wire,", "Ok(wire) => { early(); wire }"),
                    good.replace("let wire = match", "let other = match")):
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace(good, new),
                         "map LinuxWire::new's refusal exactly once|exactly once|in this order")
        # Spacing, comments and a final arm without its comma are read through.
        spaced = ("    let wire = match LinuxWire :: new ( sealed ) { // the wire\n        Ok ( wire ) => wire,\n"
                  "        Err(error) => return status :: wire_setup ( & error )\n    };\n")
        self.write(gate.OBSERVER_MAIN, GOOD_OBSERVER_MAIN.replace(good, spaced))
        self.assertEqual(gate.check_observer_serve(self.base), 14)

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
        self.assertEqual(gate.SIGNER_KEYS, ("crates/gate-tls/config-signer.pub", "crates/observer/config-signer.pub",
                                            "crates/broker/config-signer.pub"))
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


# HE-004C's 13 modules, main.rs and status.rs, D1's three and observer-sys's three; HE-004-I01a's as their units add them.
NO_PANIC_COUNT = 22 + len(gate.I01_NO_PANIC_BUILT)   # HE-005A0: role-seal's lib.rs, the 22nd


class ObserverNoPanicTests(Tree):
    """HE-004C DESIGN-C section 15 (G8, D1-14 (c)): the no-panic tripwire covers every HE-004C module and the changed
    main.rs and status.rs: no panicking macro or call outside strict #[cfg(test)] mod tests blocks; each file required."""

    TREE = {rel: "//! unwrap(), expect( and panic! in a comment pass.\npub fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }\n"
            for rel in gate.OBSERVER_NO_PANIC + gate.OBSERVER_SYS_NO_PANIC}

    def test_the_tree_passes(self):
        self.assertEqual(len(gate.OBSERVER_C_MODULES), 13)
        self.assertEqual(gate.check_observer_no_panic(self.base), NO_PANIC_COUNT)

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
            self.assertEqual(gate.check_observer_no_panic(self.base), NO_PANIC_COUNT)
            self.write(rel, good)

    def test_role_seal_joins_the_no_panic_list(self):
        # HE-005A0: role-seal's one source, outside its strict test block (a panic message could format a Stage1).
        rel = gate.ROLE_SEAL_LIB
        self.assertEqual(gate.OBSERVER_NO_PANIC[-1], rel)
        good = self.TREE[rel]
        for text in ("fn g(x: Option<u8>) -> u8 { x.unwrap() }", "fn g(r: Result<u8, Stage1>) -> u8 { r.expect(\"x\") }",
                     "fn g() { panic!(\"x\"); }", "fn g() { assert_eq!(1, 1); }"):
            self.refused(gate.check_observer_no_panic, rel, good + text + "\n", "observer no-panic tripwire")
        self.write(rel, good + "#[cfg(test)]\nmod tests {\n    fn t() { assert_eq!(1, 1); Some(1).unwrap(); }\n}\n")
        self.assertEqual(gate.check_observer_no_panic(self.base), NO_PANIC_COUNT)
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
                             ("#[derive(Debug)]\nstruct Epoch { client: Client<LinuxWire> }", "LinuxWire"),
                             # HE-004-I01a (G-I01-6, R4-6): the I01 listener with its held peer.
                             ("#[derive(Debug)]\nstruct Held { socket: Option<I01Socket> }", "I01Socket")):
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

    # HE-005A0: role-seal joins the closure too (and SCANNED_CRATES after observer-sys).
    TREE = {**WORKSPACE_TREE,
            "Cargo.toml": WORKSPACE_TREE["Cargo.toml"].replace(
                '"crates/gate-tls"]', '"crates/gate-tls", "crates/observer", "crates/observer-sys", "crates/role-seal"]'),
            "crates/observer/Cargo.toml": '[package]\nname = "planeon-observer"\nedition.workspace = true\n',
            "crates/observer-sys/Cargo.toml": '[package]\nname = "observer-sys"\nedition.workspace = true\n',
            "crates/role-seal/Cargo.toml": '[package]\nname = "role-seal"\nedition.workspace = true\n'}
    GOOD = {**WORKSPACE, "planeon-observer": {"gate-sys", "i05-protocol", "observer-sys", "role-seal"}, "observer-sys": set(),
            "role-seal": {"gate-sys"}}

    def test_the_closure_and_the_lists(self):
        self.assertEqual(gate.check_workspace_shape(self.base, self.GOOD), 8)
        self.assertEqual(gate.SCANNED_CRATES[-3:], ("crates/role-seal", "crates/broker", "crates/broker-sys"))
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
            gate.check_workspace_shape(self.base, {**self.GOOD, "planeon-observer": {"gate-sys", "i05-protocol", "role-seal"}})

    def test_the_root_must_deny_unsafe_code(self):
        tree = {**LINKED_TREE}
        for rel, text in tree.items():
            self.write(rel, text)
        self.assertEqual(gate.check_linked_sources(self.base), 16)
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
        self.assertEqual(gate.check_foreign_items(self.base), 24)
        self.assertEqual(gate.check_unsafe(self.base), 25)
        self.assertEqual(gate.check_linked_sources(self.base), 24)

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
        self.assertEqual(gate.check_linked_sources(self.base), 24)
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
        # HE-004D2 (G-D2-9): record_check.rs's two expressions follow D1's five.
        self.assertEqual([expression for _, expressions in gate.FS_SCAN_EXCEPTIONS.items() for expression, _ in expressions],
                         ['const PROC_ROOT: &str = "/proc";', 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";',
                          'const CGROUP_ROOT: &str = "/sys/fs/cgroup";', 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";',
                          'const CGROUP_ROOT: &str = "/sys/fs/cgroup";', 'const CGROUP_ROOT: &str = "/sys/fs/cgroup";',
                          'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";',
                          # HE-005C (the frozen seam note section 1): leaf.rs's LEAF_PATH, merged last.
                          'const LEAF_PATH: &str = "/sys/fs/cgroup/planeon.slice/planeon-capacity-broker.service/probe-worker";'])
        self.assertEqual(gate.check_sources(self.base), 27)
        self.assertEqual(gate.check_linked_sources(self.base), 26)
        # A rustfmt-wrapped expression is removed once (both scans).
        self.write(self.ENROLLED, self.ENROLLED_TEXT.replace('const PIN_ROOT: &str = "/sys/fs/bpf/planeon";',
                                                             'const PIN_ROOT: &str =\n    "/sys/fs/bpf/planeon";'))
        self.assertEqual(gate.check_sources(self.base), 27)
        self.assertEqual(gate.check_linked_sources(self.base), 26)

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
        self.assertEqual(gate.check_linked_sources(self.base), 27)


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
                      "    \"c3e91c087ebc6a13e8a96a066f80710ac968c8def434d1d1b97415811715ed10\";\n"
                      # HE-004D2 (G-D2-3): the v5 capture schema beside it.
                      "pub const NATIVE_PROFILE_V5_SCHEMA: &[u8] =\n"
                      "    include_bytes!(\"../../../contracts/native-profile-v5/qualification.schema.json\");\n"
                      "pub const NATIVE_PROFILE_V5_SCHEMA_SHA256: &str =\n"
                      "    \"70bda12463cee83301bc10fa6285023dc0e07b281a87ca70d44ec746cf262113\";\n")
NATIVE_SCHEMA_RS = "crates/observer/src/capture_schema.rs"
NATIVE_SCHEMA_TEXT = ("impl CaptureSchema {\n    pub fn embedded() -> Loaded {\n"
                      "        let record = RecordSchema::from_bytes(crate::contracts::NATIVE_PROFILE_V4_SCHEMA);\n"
                      "        CaptureSchema::from_bytes(crate::contracts::NATIVE_PROFILE_V5_SCHEMA)\n    }\n\n"
                      "    pub fn from_bytes(bytes: &[u8]) -> Loaded { load(bytes) }\n}\n")


class ObserverNativeProfileTests(Tree):
    """HE-004D1 G-D1-9 (R2-5): the four native-profile files are pinned (35), contracts.rs holds the schema's two items,
    and the schema has one use site, in CaptureSchema::embedded."""

    TREE = {gate.OBSERVER_CONTRACTS: NATIVE_CONTRACTS, NATIVE_SCHEMA_RS: NATIVE_SCHEMA_TEXT, CAPTURE_RS: CAPTURE_TEXT}

    def test_the_tree_passes(self):
        # HE-004D2 (G-D2-1, G-D2-3): edge records v6 and v7 make 46; the v5 schema's two items and its one use join.
        # HE-004-I01a unit U1: edge record v8's two seccomp-v5 programs make 48; unit U6's two I06 v4 files 50; unit U7's
        # two I01 wire files (HE-004-I01A2, edge record v9) 52; HE-004-I01B1's four (edge record v10, none embedded) 56;
        # HE-004-I01B4's seven (edge record v11, none embedded) 63; HE-005A's four seccomp-v3 programs (edge record v11,
        # BROKER embedded by the broker's seal) 67; HE-005B's two broker handoff files (edge record v12) 69.
        self.assertEqual(len(gate.CONTRACTS), 69)
        self.assertEqual(gate.check_native_profile_use(self.base), 4)
        self.assertEqual(gate.check_observer_contracts_module(self.base), 7)

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
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)
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
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)
        self.refused(gate.check_observer_logic, "crates/observer/src/inputs.rs", self.TREE["crates/observer/src/inputs.rs"]
                     + "use crate::kernel_text;\n", "imports crate::kernel_text")

    def test_no_logic_module_reaches_role_seal(self):
        # HE-005A0 (MON-HE005A0-U1): role_seal is a crate root, so a logic module naming it names a rooted path outside
        # every whitelist, in a use declaration or in the code; the same name as a local path segment still passes.
        self.assertIn("role_seal", gate.CRATE_PATH_ROOTS)
        for rel in ("crates/observer/src/inputs.rs", "crates/observer/src/capture_check.rs"):
            good = self.TREE[rel]
            for text, message in (("use role_seal::filter_length;\n", "imports role_seal::filter_length"),
                                  ("use role_seal::{self};\n", "imports role_seal::self"),
                                  ("fn f(p: &[u8]) -> Option<u16> { role_seal::filter_length(p) }\n",
                                   "names role_seal::filter_length"),
                                  ("fn f() -> u32 { ::role_seal::CAP_LAST_CAP }\n", "names ::role_seal::CAP_LAST_CAP")):
                self.refused(gate.check_observer_logic, rel, good + text, message)
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)


class ObserverD1NoPanicTests(Tree):
    """HE-004D1 G-D1-11: the no-panic tripwire over enrolled.rs, capture.rs, linux_capture.rs and observer-sys's three
    sources, where only item-level compile-time asserts are removed."""

    TREE = {rel: "//! unwrap() in a comment passes.\npub fn f(x: Option<u8>) -> u8 { x.unwrap_or(0) }\n"
            for rel in gate.OBSERVER_NO_PANIC + gate.OBSERVER_SYS_NO_PANIC}

    def test_each_new_source_refuses_a_panic(self):
        self.assertEqual(gate.check_observer_no_panic(self.base), NO_PANIC_COUNT)
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
        self.assertEqual(gate.check_observer_no_panic(self.base), NO_PANIC_COUNT)
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
        self.assertEqual(gate.check_observer_post_seal(self.base), 10)
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
    """HE-004D1 G-D1-8: serve's imports gain the capture setup's, and the v1 parse no longer passes in serve.
    HE-004-I01B2 (DIB section 3.3; I2D-9): nor the v2 parse, and serve's imports gain I01Binding."""

    TREE = OBSERVER_TREE

    def test_the_v1_parse_and_a_missing_import_refuse(self):
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN,
                     GOOD_OBSERVER_MAIN.replace("ObserverConfig::parse_v3(", "ObserverConfig::parse("), "v1")
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN,
                     GOOD_OBSERVER_MAIN.replace("    drop(document);\n", "    let _ = ObserverConfig::parse(&document);\n"), "v1")
        for use in ("    use planeon_observer::capture::CaptureEngine;\n", "    use planeon_observer::linux_capture::LinuxCapture;\n",
                    "    use planeon_observer::enrolled::{self, Enrolled};\n", "    use planeon_observer::i01_request::I01Binding;\n"):
            self.refused(lambda base: gate.check_seal_order(base, gate.OBSERVER_SEAL_SITE), gate.OBSERVER_MAIN,
                         GOOD_OBSERVER_MAIN.replace(use, ""), "imports are not exactly the pinned set")

    def test_the_v2_parse_refuses(self):
        # HE-004-I01B2: parse_with_record( in serve refuses, in place of parse_v3( or beside it (DIB section 7.2's wiring
        # case).
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN,
                     GOOD_OBSERVER_MAIN.replace("ObserverConfig::parse_v3(", "ObserverConfig::parse_with_record("), "v2")
        self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN,
                     GOOD_OBSERVER_MAIN.replace("    drop(document);\n",
                                                "    let _ = ObserverConfig::parse_with_record(&document);\n    drop(document);\n"),
                     "v2 ObserverConfig::parse_with_record")
        self.assertEqual(gate.check_observer_serve(self.base), 14)


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
        self.assertEqual(gate.check_observer_no_panic(self.base), NO_PANIC_COUNT)
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
        # HE-004D2 (G-D2-10, R4-1): the other three pinned files, as they are.
        for rel in gate.OBSERVER_SYS_PINS:
            if rel != KERNEL:
                path = self.base / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((gate.HE / rel).read_bytes())

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
        # HE-004D2 (G-D2-10, R4-1): kernel.rs's pin is unchanged and three files join it.
        self.assertEqual(set(gate.OBSERVER_SYS_PINS), {KERNEL, gate.OBSERVER_SYS_LIB, OBSERVER_SYS_DIRENT,
                                                       "crates/observer-sys/Cargo.toml"})
        self.assertEqual(gate.OBSERVER_SYS_PINS[KERNEL], gate.sha256(self.real))
        self.assertEqual(gate.OBSERVER_SYS_PINS[KERNEL], "0b3d0151c9eaf1f44dd56436795aefd8cb7140ce9f4d16fe5f4eaf7130e61d43")
        self.assertEqual(gate.check_observer_sys_pins(self.base), 4)

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


# --- HE-004D2 (DESIGN-D2 rev 2 section 12) --------------------------------------------------------------------------------

D2_V6_CONTRACTS = ("contracts/native-profile-v1/qualification.schema.json", "contracts/native-profile-v2/qualification.schema.json",
                   "contracts/i06-v3/vectors.json", "contracts/i06-v3/criteria.json", "contracts/i06-v3/README.md")
D2_V7_CONTRACTS = ("contracts/native-profile-v5/qualification.schema.json", "contracts/native-profile-v5/vectors.json",
                   "contracts/native-profile-v5/README.md", "contracts/native-profile-v1/vectors.json",
                   "contracts/native-profile-v2/vectors.json", "contracts/native-profile-v3/vectors.json")
# HE-004-I01A2, HE-004-I01a's unit U7 (DESIGN-I01A sections 3 and 7): edge record v9's two I01 wire rows.
I01_V9_CONTRACTS = ("contracts/i01-v1/channel.schema.json", "contracts/i01-v1/vectors.json")
# HE-004-I01B1 (DESIGN-I01B rev 3 section 2, G-I01B-2): edge record v10's four rows 69-72.
I01B_V10_CONTRACTS = ("contracts/i01-digests-v1/definitions.json", "contracts/i01-digests-v1/vectors.json",
                      "contracts/i01-digests-v1/README.md", "contracts/i01-v1/proxy-contract-vectors.json")
# HE-004-I01B4 (DESIGN-I01B4 rev 2 sections 1.1 and 5, G-I01B-2): edge record v11's seven rows 73-79.
I01B_V11_CONTRACTS = ("contracts/i01-digests-v2/definitions.json", "contracts/i01-digests-v2/vectors.json",
                      "contracts/i01-digests-v2/README.md", "contracts/admission-v4/README.md",
                      "contracts/admission-v4/vectors.json", "contracts/admission-v4/admission-manifests/planeon-a2.json",
                      "contracts/i01-v2/proxy-profile-v2-vectors.json")
# HE-005A: edge record v11's four seccomp-v3 rows for HE-005 (artifacts 17, 18, 29 and 30).
HE005A_V11_CONTRACTS = ("contracts/seccomp-v3/BROKER.aarch64.bpf", "contracts/seccomp-v3/BROKER.x86_64.bpf",
                        "contracts/seccomp-v3/WORKER.aarch64.bpf", "contracts/seccomp-v3/WORKER.x86_64.bpf")
# HE-005B (G-HE5B-4): edge record v12's two broker handoff rows 80 and 81.
HE005B_V12_CONTRACTS = ("contracts/broker-handoff-v1/channel.schema.json", "contracts/broker-handoff-v1/vectors.json")


class D2ContractCountTests(unittest.TestCase):
    """HE-004D2 G-D2-1: edge record v6's five HE-004D2 rows and edge record v7's six make 46 registered files; over a copy
    of the real contracts/ tree, a missing one of the eleven, a changed one, and an unregistered file refuse. HE-004-I01A2:
    edge record v9's two I01 wire rows are checked the same way (52 files), and the readiness document, which edge record
    v9 leaves unregistered (Q-EV9-1b (a)), refuses if held. HE-004-I01B1: edge record v10's four rows are checked the same
    way (56 files); the proxy-contract vectors are registered now (row 72), so the digest contract's reference model,
    which no record registers, is the unregistered file held beside them. HE-004-I01B4: edge record v11's seven rows are
    checked the same way (63 files), and the contract v2's model, which no record registers, is the unregistered file held
    beside the contract v2's own."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.base = Path(self.directory.name)
        for rel in list(gate.CONTRACTS) + ["contracts/PROVENANCE.md"]:
            path = self.base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((gate.HE / rel).read_bytes())

    def tearDown(self):
        self.directory.cleanup()

    def test_the_forty_six_files_pass(self):
        # HE-004-I01a unit U1 (DESIGN-I01A section 3): edge record v8's two seccomp-v5 programs make 48; unit U6
        # (section 10): its two I06 v4 files make 50; unit U7 (HE-004-I01A2, sections 3 and 7): edge record v9's two
        # I01 wire files make 52; HE-004-I01B1 (DESIGN-I01B rev 3 section 2, G-I01B-2): edge record v10's four make 56;
        # HE-004-I01B4 (DESIGN-I01B4 rev 2 section 1.2, G-I01B-2): edge record v11's seven make 63; HE-005A (DESIGN-HE005
        # revision 5 section 2): its four seccomp-v3 BROKER and WORKER rows make 67; HE-005B (section 4, G-HE5B-4): edge
        # record v12's two broker handoff rows make 69.
        self.assertEqual(len(gate.CONTRACTS), 69)
        self.assertTrue(set(D2_V6_CONTRACTS + D2_V7_CONTRACTS + I01_V9_CONTRACTS + I01B_V10_CONTRACTS
                            + I01B_V11_CONTRACTS + HE005A_V11_CONTRACTS + HE005B_V12_CONTRACTS) <= set(gate.CONTRACTS))
        self.assertEqual(gate.check_contracts(self.base), 69)

    def test_a_missing_changed_or_unregistered_file_refuses(self):
        for rel in (D2_V6_CONTRACTS + D2_V7_CONTRACTS + I01_V9_CONTRACTS + I01B_V10_CONTRACTS + I01B_V11_CONTRACTS
                    + HE005A_V11_CONTRACTS + HE005B_V12_CONTRACTS):
            path = self.base / rel
            data = path.read_bytes()
            path.unlink()
            with self.assertRaisesRegex(gate.GateError, "exactly the registered files"):
                gate.check_contracts(self.base)
            path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            with self.assertRaisesRegex(gate.GateError, "differs from its registered bytes: %s" % re.escape(rel)):
                gate.check_contracts(self.base)
            path.write_bytes(data)
        for rel in ("contracts/native-profile-v6/qualification.schema.json", "contracts/native-profile-v5/extra.json",
                    "contracts/i06-v5/vectors.json", "contracts/i06-v4/README.md",
                    # HE-004-I01A2: the unregistered readiness document. HE-004-I01B1: edge record v10 registers the
                    # proxy-contract vectors (row 72), so the digest contract's reference model, which no record
                    # registers, takes their place as the unregistered file beside the contract's own.
                    "contracts/i01-v1/POLICY_OBSERVATION_READINESS.md",
                    "contracts/i01-digests-v1/policy_observation_digests.py",
                    # HE-004-I01B4: the contract v2's model, which no record registers (edge record v11's notes), in
                    # the same place beside the contract v2's own files.
                    "contracts/i01-digests-v2/policy_observation_digests_v2.py",
                    # HE-005A: a third role's program, which no record registers, beside the four.
                    "contracts/seccomp-v3/WRITER.x86_64.bpf",
                    # HE-005B: the readiness guide, which edge record v12 leaves unregistered (not a consumer
                    # artefact), beside the two broker handoff files.
                    "contracts/broker-handoff-v1/BROKER_HANDOFF_READINESS.md"):
            path = self.base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"{}")
            with self.assertRaisesRegex(gate.GateError, "exactly the registered files"):
                gate.check_contracts(self.base)
            path.unlink()
        self.assertEqual(gate.check_contracts(self.base), 69)


class D2EmbeddedContractTests(Tree):
    """HE-004D2 G-D2-2: contracts.rs embeds only OBSERVER_EMBEDDED_CONTRACTS (I06 v1's three files, the v4 schema and,
    from unit B1, the v5 schema); embedding any other registered file (a predecessor schema, a vector set, a README, I06
    v3's files) refuses, and an unregistered file refuses as before."""

    TREE = {gate.OBSERVER_CONTRACTS: NATIVE_CONTRACTS}
    RULE = "G-D2-2"

    def test_the_real_module_and_the_fixture_pass(self):
        self.assertEqual(gate.OBSERVER_EMBEDDED_CONTRACTS,
                         ("contracts/i06-v1/identity-closure.json", "contracts/i06-v1/writer-inventory.json",
                          "contracts/i06-v1/upstream-bootstrap-rbac-v1.37.1.json",
                          "contracts/native-profile-v4/qualification.schema.json",
                          "contracts/native-profile-v5/qualification.schema.json"))
        self.assertTrue(set(gate.OBSERVER_EMBEDDED_CONTRACTS) <= set(gate.CONTRACTS))
        self.assertEqual(gate.check_observer_contracts_module(self.base), 7)
        self.write(gate.OBSERVER_CONTRACTS, (gate.HE / gate.OBSERVER_CONTRACTS).read_text(encoding="utf-8"))
        self.assertEqual(gate.check_observer_contracts_module(self.base), 11)

    def test_other_registered_files_refuse(self):
        for rel in ("contracts/native-profile-v1/qualification.schema.json",
                    "contracts/native-profile-v2/qualification.schema.json",
                    "contracts/native-profile-v3/qualification.schema.json", "contracts/native-profile-v4/vectors.json",
                    "contracts/native-profile-v4/README.md", "contracts/native-profile-v5/vectors.json",
                    "contracts/native-profile-v5/README.md", "contracts/native-profile-v1/vectors.json",
                    "contracts/native-profile-v2/vectors.json", "contracts/native-profile-v3/vectors.json",
                    "contracts/i06-v3/criteria.json", "contracts/i06-v3/vectors.json", "contracts/i06-v2/README.md",
                    "contracts/i06-v1/README.md", "contracts/i07-v3/policy-kinds.json", "contracts/i06-v4/criteria.json",
                    "contracts/i06-v4/vectors.json"):
            self.assertIn(rel, gate.CONTRACTS)
            text = NATIVE_CONTRACTS + "pub const OTHER: &[u8] = include_bytes!(\"../../../%s\");\n" % rel
            self.refused(gate.check_observer_contracts_module, gate.OBSERVER_CONTRACTS, text, self.RULE)
        for rel in ("contracts/native-profile-v6/vectors.json", "contracts/i06-v5/vectors.json"):
            text = NATIVE_CONTRACTS + "pub const OTHER: &[u8] = include_bytes!(\"../../../%s\");\n" % rel
            self.refused(gate.check_observer_contracts_module, gate.OBSERVER_CONTRACTS, text,
                         "not a registered contract file")


class D2SchemaConstantTests(Tree):
    """HE-004D2 G-D2-3 (G-D1-9 generalised): each of NATIVE_PROFILE_SCHEMAS is defined once in contracts.rs and named once
    in capture_schema.rs, inside CaptureSchema::embedded, and nowhere else; the old single-constant cases hold for v5."""

    TREE = {gate.OBSERVER_CONTRACTS: NATIVE_CONTRACTS, NATIVE_SCHEMA_RS: NATIVE_SCHEMA_TEXT, CAPTURE_RS: CAPTURE_TEXT,
            gate.OBSERVER_RECORD_CHECK: "pub fn f() {}\n"}
    RULE = "G-D2-3"

    def test_both_constants_once(self):
        self.assertEqual(gate.NATIVE_PROFILE_SCHEMAS, ("NATIVE_PROFILE_V4_SCHEMA", "NATIVE_PROFILE_V5_SCHEMA"))
        self.assertEqual(gate.check_native_profile_use(self.base), 4)
        # The real sources: contracts.rs and capture_schema.rs as built.
        for rel in (gate.OBSERVER_CONTRACTS, NATIVE_SCHEMA_RS):
            self.write(rel, (gate.HE / rel).read_text(encoding="utf-8"))
        self.assertEqual(gate.check_native_profile_use(self.base), 4)

    def test_other_uses_of_the_v5_constant_refuse(self):
        use = "crate::contracts::NATIVE_PROFILE_V5_SCHEMA"
        for rel, text in ((NATIVE_SCHEMA_RS, NATIVE_SCHEMA_TEXT.replace("load(bytes)", "load(%s)" % use)),
                          (NATIVE_SCHEMA_RS, NATIVE_SCHEMA_TEXT.replace("from_bytes(%s)" % use, "from_bytes(%s); %s" % (use, use))),
                          (NATIVE_SCHEMA_RS, NATIVE_SCHEMA_TEXT.replace(use, "&[]")),
                          (gate.OBSERVER_RECORD_CHECK, "pub fn f() -> usize { %s.len() }\n" % use),
                          (CAPTURE_RS, CAPTURE_TEXT + "fn f() -> &'static [u8] { %s }\n" % use),
                          (gate.OBSERVER_CONTRACTS, NATIVE_CONTRACTS.replace("NATIVE_PROFILE_V5_SCHEMA:", "NATIVE_PROFILE_SCHEMA_V5:"))):
            self.refused(gate.check_native_profile_use, rel, text, "NATIVE_PROFILE_V5_SCHEMA.*" + self.RULE)
        # A second use of the v4 constant still refuses, as G-D1-9.
        self.refused(gate.check_native_profile_use, gate.OBSERVER_RECORD_CHECK, "pub fn f() -> usize { crate::contracts::NATIVE_PROFILE_V4_SCHEMA.len() }\n",
                     "NATIVE_PROFILE_V4_SCHEMA.*G-D1-9")


class D2ConstructorHomePinTests(Tree):
    """HE-004D2 owner decision Q-D2-END (a): linux_net.rs and linux_capture.rs are pinned whole; for each, a one-byte
    change, an added byte, a removed byte, an appended alias or default (round 4's probes), a missing file and a symlink
    refuse; the real files pass. Run on the real files."""

    def setUp(self):
        super().setUp()
        self.real = {rel: (gate.HE / rel).read_bytes() for rel in gate.OBSERVER_HOME_PINS}
        for rel, data in self.real.items():
            self.write_bytes(rel, data)

    def write_bytes(self, rel, data):
        path = self.base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        path.write_bytes(data)

    def refuses(self, rel, data, message="%s differs from its pinned bytes"):
        self.write_bytes(rel, data)
        with self.assertRaisesRegex(gate.GateError, (message % re.escape(rel)) + ".*Q-D2-END"):
            gate.check_observer_home_pins(self.base)
        self.write_bytes(rel, self.real[rel])

    def test_the_real_files_pass(self):
        # HE-004-I01a (G-I01-6): linux_listen.rs joins the pins and linux_net.rs is re-pinned. HE-004-I01B5 (DESIGN-I01B5
        # rev 5 section 1): both re-pinned at I01B5's bytes (the one send path), keeping this test's intent.
        self.assertEqual(gate.OBSERVER_HOME_PINS, {
            "crates/observer/src/linux_capture.rs": "77e50074e81eefc782ba287fad874ba83c3a5c01225ee6a1d5c69407b0be1862",
            "crates/observer/src/linux_net.rs": "d0ba15d46f21c43195f9c50e2b0440f36bce58555842f960c3e4f215750b20e4",
            "crates/observer/src/linux_listen.rs": "f64acf69dbe1870356ce5aaa7b576e837859bc09371a8af29ef4cc16ee535d2b"})
        self.assertEqual(gate.check_observer_home_pins(self.base), 3)

    def test_each_file_refuses_a_change_missing_or_a_symlink(self):
        for rel, alias in (("crates/observer/src/linux_net.rs", b"pub type W<T: Into<[u8; 1]> = LinuxWire> = T;\n"),
                           ("crates/observer/src/linux_capture.rs", b"pub struct H<T = LinuxCapture>(T);\n"),
                           ("crates/observer/src/linux_listen.rs", b"pub(crate) struct H<T = I01Socket>(T);\n")):
            data = self.real[rel]
            middle = len(data) // 2
            self.refuses(rel, data[:middle] + bytes([data[middle] ^ 1]) + data[middle + 1:])
            self.refuses(rel, data + b"\n")
            self.refuses(rel, data[:-1])
            self.refuses(rel, data + alias)
            (self.base / rel).unlink()
            with self.assertRaisesRegex(gate.GateError, "%s is missing or a symlink" % re.escape(rel)):
                gate.check_observer_home_pins(self.base)
            (self.base / "real.bin").write_bytes(data)
            (self.base / rel).symlink_to(self.base / "real.bin")
            with self.assertRaisesRegex(gate.GateError, "%s is missing or a symlink" % re.escape(rel)):
                gate.check_observer_home_pins(self.base)
            (self.base / rel).unlink()
            self.write_bytes(rel, data)
        self.assertEqual(gate.check_observer_home_pins(self.base), 3)


class D2ObserverSysPinTests(Tree):
    """HE-004D2 G-D2-10 (HE-004D1 PR review round 4, R4-1): observer-sys's lib.rs, dirent.rs and Cargo.toml are pinned
    whole beside kernel.rs; for each, a one-byte change, an added byte, a missing file and a symlink refuse; R4-1's own
    probe, an inline `pub mod kernel { }` in lib.rs, refuses; the real files pass. Run on the real files."""

    RULE = "observer-sys pin, R3-1"
    NEW = (gate.OBSERVER_SYS_LIB, OBSERVER_SYS_DIRENT, "crates/observer-sys/Cargo.toml")

    def setUp(self):
        super().setUp()
        self.real = {rel: (gate.HE / rel).read_bytes() for rel in gate.OBSERVER_SYS_PINS}
        for rel, data in self.real.items():
            self.put(rel, data)

    def put(self, rel, data):
        path = self.base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        path.write_bytes(data)

    def refuses(self, rel, data, message="%s differs from its pinned bytes"):
        self.put(rel, data)
        with self.assertRaisesRegex(gate.GateError, message % re.escape(rel) if "%s" in message else message):
            gate.check_observer_sys_pins(self.base)
        self.put(rel, self.real[rel])

    def test_the_real_files_pass(self):
        self.assertEqual(gate.OBSERVER_SYS_PINS, {
            "crates/observer-sys/src/kernel.rs": "0b3d0151c9eaf1f44dd56436795aefd8cb7140ce9f4d16fe5f4eaf7130e61d43",
            "crates/observer-sys/src/lib.rs": "e718fc32fc13a28b4bfc58d6917cd9ac88479e2f5779ab9d351fdc5723f19029",
            "crates/observer-sys/src/dirent.rs": "133b05b3b231757078efd6c62259dcdafcd3b60f0f9fbae0ba0c0653c15ef510",
            "crates/observer-sys/Cargo.toml": "4d1299774cccfd74a5a8f7e353c47afde7c6014cc7eb04deadad3d05e5d6fcc4"})
        self.assertEqual({rel: len(data) for rel, data in self.real.items() if rel in self.NEW},
                         {gate.OBSERVER_SYS_LIB: 895, OBSERVER_SYS_DIRENT: 3264, "crates/observer-sys/Cargo.toml": 410})
        self.assertEqual(gate.check_observer_sys_pins(self.base), 4)

    def test_each_new_file_refuses_a_change(self):
        for rel in self.NEW:
            data = self.real[rel]
            middle = len(data) // 2
            self.refuses(rel, data[:middle] + bytes([data[middle] ^ 1]) + data[middle + 1:])
            self.refuses(rel, data + b"\n")
            self.refuses(rel, data[:-1])

    def test_each_new_file_missing_or_a_symlink_refuses(self):
        for rel in self.NEW:
            (self.base / rel).unlink()
            with self.assertRaisesRegex(gate.GateError, "%s is missing or a symlink" % re.escape(rel)):
                gate.check_observer_sys_pins(self.base)
            (self.base / "real.bin").write_bytes(self.real[rel])
            (self.base / rel).symlink_to(self.base / "real.bin")
            with self.assertRaisesRegex(gate.GateError, "%s is missing or a symlink" % re.escape(rel)):
                gate.check_observer_sys_pins(self.base)
            (self.base / rel).unlink()
            self.put(rel, self.real[rel])
        self.assertEqual(gate.check_observer_sys_pins(self.base), 4)

    def test_the_r4_1_probes_refuse(self):
        lib = self.real[gate.OBSERVER_SYS_LIB]
        self.refuses(gate.OBSERVER_SYS_LIB, lib + b"pub mod kernel { }\n")
        self.refuses(gate.OBSERVER_SYS_LIB, lib + b"pub mod extra;\n")
        self.refuses("crates/observer-sys/Cargo.toml", self.real["crates/observer-sys/Cargo.toml"]
                     + b"\n[dependencies]\nlibc = \"0.2\"\n")


class D2QualifiedConstructorTests(Tree):
    """HE-004D2 G-D2-11 (HE-004D1 PR review round 1, R1-5): serve constructs LinuxWire and LinuxCapture exactly once each,
    counting `<T>::new`, `< T >::new` and (HE-004D2 PR review round 1, R1-7) `T::<>::new`, `<(T)>::new` and `<T<>>::new`,
    and names each type only once; only main.rs's serve calls LinuxCapture::new in any of these forms."""

    TREE = D1_TREE
    CLOSURE = "    let Ok(closure) = Closure::embedded() else { return status::CLOSURE };\n"

    def test_the_fixture_passes(self):
        self.assertEqual([name for _, name in gate.QUALIFIED_CONSTRUCTORS], ["LinuxWire", "LinuxCapture"])
        self.assertEqual(gate.check_observer_serve(self.base), 14)
        self.assertEqual(gate.check_observer_capture_callers(self.base), 4)

    def test_a_second_qualified_construction_in_serve_refuses(self):
        for extra, name in (("    let _again = <LinuxCapture>::new(sealed);\n", "LinuxCapture"),
                            ("    let _again = < LinuxCapture > :: new(sealed);\n", "LinuxCapture"),
                            ("    let _again = <LinuxWire>::new(sealed);\n", "LinuxWire"),
                            ("    let _again = < LinuxWire >::new(sealed);\n", "LinuxWire")):
            text = GOOD_OBSERVER_MAIN.replace(self.CLOSURE, extra + self.CLOSURE)
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, text,
                         "serve constructs %s other than exactly once.*G-D2-11" % name)
            if name == "LinuxCapture":
                self.refused(gate.check_observer_capture_callers, gate.OBSERVER_MAIN, text, "G-D1-6")

    def test_the_pr_review_round1_spellings_refuse(self):
        # HE-004D2 PR review round 1, R1-7: empty generic arguments and a parenthesised type, spaces allowed; and any
        # second naming of either type in serve.
        for extra, name in (("    let _again = LinuxWire::<>::new(sealed);\n", "LinuxWire"),
                            ("    let _again = <(LinuxWire)>::new(sealed);\n", "LinuxWire"),
                            ("    let _again = LinuxWire :: < > :: new(sealed);\n", "LinuxWire"),
                            ("    let _again = LinuxCapture::<>::new(sealed);\n", "LinuxCapture"),
                            ("    let _again = <(LinuxCapture)>::new(sealed);\n", "LinuxCapture"),
                            ("    let _again = <LinuxCapture<>>::new(sealed);\n", "LinuxCapture")):
            text = GOOD_OBSERVER_MAIN.replace(self.CLOSURE, extra + self.CLOSURE)
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, text,
                         "serve constructs %s other than exactly once.*G-D2-11" % name)
            if name == "LinuxCapture":
                self.refused(gate.check_observer_capture_callers, gate.OBSERVER_MAIN, text, "G-D1-6")
        for name in ("LinuxWire", "LinuxCapture"):
            text = GOOD_OBSERVER_MAIN.replace(self.CLOSURE, "    let _kept: Option<%s> = None;\n" % name + self.CLOSURE)
            self.refused(gate.check_observer_serve, gate.OBSERVER_MAIN, text, "serve names %s other than once.*R1-7" % name)
        for rel in (CAPTURE_RS, LINUX_CAPTURE):
            for extra in ("fn f(s: &Sealed) { let _ = LinuxCapture::<>::new(s); }\n",
                          "fn f(s: &Sealed) { let _ = <(LinuxCapture)>::new(s); }\n",
                          "fn f(s: &Sealed) { let _ = <LinuxCapture<>>::new(s); }\n"):
                self.refused(gate.check_observer_capture_callers, rel, self.TREE[rel] + extra,
                             "names LinuxCapture::new; only main.rs's serve calls it")

    def test_a_linux_wire_alias_refuses(self):
        # HE-004D2 PR review round 2, R2-1: an alias of LinuxWire outside main.rs, paired with a second construction
        # through it in serve; a renaming import; a parenthesised aliased type.
        main = GOOD_OBSERVER_MAIN.replace(self.CLOSURE, "    let Ok(_again) = planeon_observer::linux_net::W::new(sealed) "
                                          "else { return status::SOCKETS };\n" + self.CLOSURE)
        self.write(gate.OBSERVER_MAIN, main)
        for rel, extra in (("crates/observer/src/linux_net.rs", "pub type W = LinuxWire;\n"),
                           (gate.OBSERVER_LIB, "pub type W = linux_net::LinuxWire;\n"),
                           (gate.OBSERVER_LIB, "pub use linux_net::LinuxWire as W;\n"),
                           (CAPTURE_RS, "type W = (crate::linux_net::LinuxWire);\n")):
            self.refused(gate.check_observer_capture_callers, rel, self.TREE.get(rel, "") + extra,
                         "renames or aliases LinuxWire .*G-D1-6")
        self.write(gate.OBSERVER_MAIN, self.TREE[gate.OBSERVER_MAIN])
        self.assertEqual(gate.check_observer_capture_callers(self.base), 4)

    def test_the_round3_alias_and_naming_forms_refuse(self):
        # HE-004D2 PR review round 3, R3-1: a type item naming either type in any form (split across lines, a tab, a
        # defaulted parameter, a where clause, a projection), in its own file or elsewhere; the type named outside its
        # own file and main.rs's serve (a struct default, a size_of outside serve).
        net = "crates/observer/src/linux_net.rs"
        for rel, text in ((net, "pub type W = (\n    LinuxWire\n);\n"), (net, "pub type W = (\tLinuxWire);\n"),
                          (net, "pub type W<T = LinuxWire> = T;\n"), (net, "pub type W where u8: Copy = LinuxWire;\n"),
                          (net, "pub type W = <[LinuxWire; 1] as IntoIterator>::Item;\n"),
                          (gate.OBSERVER_LIB, self.TREE[gate.OBSERVER_LIB] + "pub type W<T = linux_net::LinuxWire> = T;\n"),
                          (LINUX_CAPTURE, self.TREE[LINUX_CAPTURE] + "pub type C = (\n    LinuxCapture\n);\n"),
                          (LINUX_CAPTURE, self.TREE[LINUX_CAPTURE] + "pub type C<T = LinuxCapture> = T;\n")):
            name = "LinuxCapture" if rel == LINUX_CAPTURE else "LinuxWire"
            self.refused(gate.check_observer_capture_callers, rel, text, "renames or aliases %s .*G-D1-6" % name)
        for rel, extra, name in ((CAPTURE_RS, "pub struct H<T = crate::linux_net::LinuxWire>(T);\n", "LinuxWire"),
                                 (gate.OBSERVER_LIB, "pub struct H<T = linux_net::LinuxWire>(T);\n", "LinuxWire"),
                                 (CAPTURE_RS, "pub struct H<T = crate::linux_capture::LinuxCapture>(T);\n", "LinuxCapture"),
                                 (gate.OBSERVER_MAIN, "fn width() -> usize {\n    std::mem::size_of::<LinuxWire>()\n}\n",
                                  "LinuxWire")):
            self.refused(gate.check_observer_capture_callers, rel, self.TREE[rel] + extra,
                         "names %s outside .*main.rs's serve .*R3-1" % name)

    def test_the_round4_type_items_refuse(self):
        # HE-004D2 PR review round 4, R4-1: a `;` inside an array type or a block does not end a type item early, in the
        # home files where naming the type is allowed.
        net = "crates/observer/src/linux_net.rs"
        capture = self.TREE[LINUX_CAPTURE]
        for rel, text, name in ((net, "pub type W where [u8; 1]: Copy = LinuxWire;\n", "LinuxWire"),
                                (net, "pub type W<T: Into<[u8; 1]> = LinuxWire> = T;\n", "LinuxWire"),
                                (net, "pub type W = <[u8; 1] as crate::capture::Pick<LinuxWire>>::Out;\n", "LinuxWire"),
                                (LINUX_CAPTURE, capture + "pub type C where [u8; 1]: Copy = LinuxCapture;\n", "LinuxCapture"),
                                (LINUX_CAPTURE, capture + "pub type C<T: Into<[u8; 1]> = LinuxCapture> = T;\n", "LinuxCapture"),
                                (LINUX_CAPTURE, capture + "pub type C = <[u8; { 1 }] as crate::capture::Pick<LinuxCapture>>::Out;\n",
                                 "LinuxCapture")):
            self.refused(gate.check_observer_capture_callers, rel, text, "renames or aliases %s .*G-D1-6" % name)
        self.refused(gate.check_observer_capture_callers, net, "pub type W = [u8; 1]", "a type item the alias rule cannot read")

    def test_a_qualified_call_elsewhere_refuses(self):
        for rel in (CAPTURE_RS, LINUX_CAPTURE):
            for extra in ("fn f(s: &Sealed) { let _ = < LinuxCapture >::new(s); }\n",
                          "fn f(s: &Sealed) { let _ = <LinuxCapture>::new(s); }\n"):
                self.refused(gate.check_observer_capture_callers, rel, self.TREE[rel] + extra,
                             "names LinuxCapture::new; only main.rs's serve calls it")


RECORD_CHECK = "crates/observer/src/record_check.rs"


class D2LogicTests(Tree):
    """HE-004D2 G-D2-4: each D2 logic module takes B1's logic rule with D1's whitelist plus the four D2 modules: crate::capture,
    crate::observe, crate::enrolled, gate-sys, observer-sys, i05-protocol's regex and std::net refuse, as do a HashMap, an
    unwrap( and an include_str!; B1's and D1's modules may not name a D2 module."""

    TREE = LOGIC_TREE

    def test_the_group_and_its_refusals(self):
        self.assertEqual(gate.D2_LOGIC_NAMES, ("record_check", "qualification", "i06_evidence", "composition"))
        self.assertEqual(gate.D2_LOGIC_BUILT, ("record_check", "i06_evidence", "qualification", "composition"))
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)
        good = self.TREE[RECORD_CHECK]
        for text, message in (
                ("use crate::capture::CaptureEngine;\n", "imports crate::capture::CaptureEngine"),
                ("use crate::observe::Epoch;\n", "imports crate::observe::Epoch"),
                ("use crate::enrolled::Enrolled;\n", "imports crate::enrolled::Enrolled"),
                ("fn f() { crate::capture::fill(); }\n", "names crate::capture::fill"),
                ("fn f() { gate_sys::Dir::at(p); }\n", "names gate_sys::Dir::at"),
                ("fn f() { let _ = observer_sys::kernel::Roots::open(); }\n", "names observer_sys::kernel"),
                ("use i05_protocol::regex::Regex;\n", "imports i05_protocol::regex::Regex"),
                ("use std::net::IpAddr;\n", "imports std::net::IpAddr"),
                ("fn f() -> bool { std :: net :: Ipv4Addr::LOCALHOST.is_loopback() }\n", "names std::net::Ipv4Addr"),
                ("use super::capture_check;\n", "imports super::capture_check"),
                ("use crate::capture_check as checks;\n", "renames an import"),
                ("use crate::capture_check::*;\n", "imports a glob"),
                ("fn f() { let _: HashMap<u8, u8> = x(); }\n", "HashMap, HashSet or RandomState"),
                ("const X: &str = include_str!(\"x\");\n", "include_bytes! or include_str!"),
                ("fn f(x: Option<u8>) -> u8 { x.unwrap() }\n", "no-panic tripwire"),
                ("fn f(x: Option<u8>) -> u8 { x.expect(\"y\") }\n", "no-panic tripwire"),
                ("fn f(x: u8) { assert!(x > 0); }\n", "no-panic tripwire")):
            self.refused(gate.check_observer_logic, RECORD_CHECK, good + text, message)
        # D1's modules and the other D2 modules are on D2's whitelist; a strict test block may panic.
        self.write(RECORD_CHECK, good + "use crate::capture_schema::RecordSchema;\nuse crate::qualification;\n"
                   "use i05_protocol::schema::Schema;\nfn g() -> u8 { self::composition::x() }\n"
                   "#[cfg(test)]\nmod tests {\n    fn t() { Some(1).unwrap(); }\n}\n")
        self.assertEqual(gate.check_observer_logic(self.base), LOGIC_COUNT)
        # B1's and D1's modules may not name a D2 module.
        for rel in ("crates/observer/src/inputs.rs", "crates/observer/src/capture_check.rs"):
            self.refused(gate.check_observer_logic, rel, self.TREE[rel] + "use crate::record_check;\n", "imports crate::record_check")


D2_ISOLATION_RECORD = ("//! A record_check fixture (IpText and qualification in a comment pass).\n"
                       "pub struct RecordAccepted {\n    record: u8,\n}\n\n"
                       "impl RecordAccepted {\n    pub fn record(&self) -> u8 {\n        self.record\n    }\n}\n\n"
                       "#[derive(Debug, PartialEq, Eq)]\npub struct IpText;\n\nenum Walk {\n    Node,\n}\n\n"
                       "pub enum Production {\n    Unavailable(&'static str),\n}\n\n"
                       "pub fn check_record() -> &'static str {\n    let _ = Walk::Node;\n    \"composition qualification\"\n}\n\n"
                       "#[cfg(test)]\nmod tests {\n    struct Local;\n}\n")
D2_ISOLATION_TREE = {
    gate.OBSERVER_LIB: "#![forbid(unsafe_code)]\n// record_check and composition in a comment\npub mod capture;\npub mod capture_check;\n"
                       "pub mod observe;\n" + "".join("pub mod %s;\n" % name for name in gate.D2_LOGIC_BUILT),
    RECORD_CHECK: D2_ISOLATION_RECORD,
    # Every other D2 module built so far, as a type-free stub.
    **{"crates/observer/src/%s.rs" % name: "pub fn %s_entry() {}\n" % name for name in gate.D2_LOGIC_BUILT if name != "record_check"},
    "crates/observer/src/observe.rs": "//! record_check and RecordAccepted in a comment.\n"
                                      "pub fn run() -> &'static str { \"qualification IpText\" }\n",
    "crates/observer/src/capture_check.rs": "pub enum Refusal {\n    Missing,\n}\npub struct CheckedRecord;\n",
    CAPTURE_RS: CAPTURE_TEXT,
    gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN,
}


class D2ChildModuleTests(Tree):
    """HE-004D2 PR review round 1, R1-6: the observer's src/ holds no directory and no logic module declares a module
    outside a strict test block, so no child module's file reaches a logic module's private items through `super::`. The
    reviewer's form refuses: `mod bridge;` in i06_evidence.rs, and i06_evidence/bridge.rs adding a method to a non-D2 type
    and re-flagging a token."""

    TREE = LOGIC_TREE
    RULE = "R1-6"

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_child_modules(self.base), len(gate.LOGIC_MODULES))
        self.write(RECORD_CHECK, self.TREE[RECORD_CHECK] + "#[cfg(test)]\nmod tests {\n    mod inner {}\n}\n")
        self.assertEqual(gate.check_observer_child_modules(self.base), len(gate.LOGIC_MODULES))

    def test_a_module_in_a_logic_file_refuses(self):
        for rel, _ in gate.LOGIC_MODULES:
            for extra in ("mod bridge;\n", "pub(crate) mod bridge;\n", "mod bridge {\n    pub fn f() {}\n}\n",
                          "#[cfg(not(test))]\nmod tests {\n}\n"):
                self.refused(gate.check_observer_child_modules, rel, self.TREE[rel] + extra, "declares a module .*" + self.RULE)

    def test_a_directory_under_src_refuses(self):
        self.write("crates/observer/src/i06_evidence/bridge.rs",
                   "impl CheckedRecord {\n    pub fn bridge_whitespace(&self, point: u32) -> bool {\n"
                   "        super::whitespace(point)\n    }\n}\n\npub fn launder() -> bool {\n"
                   "    let mut token = match super::check_evidence(true) {\n        Ok(token) => token,\n"
                   "        Err(_) => return false,\n    };\n    token.fixture = false;\n    token.fixture()\n}\n")
        with self.assertRaisesRegex(gate.GateError, "src/i06_evidence is a directory under crates/observer/src.*" + self.RULE):
            gate.check_observer_child_modules(self.base)


class D2IsolationTests(Tree):
    """HE-004D2 G-D2-5 (D2-4): the D2 modules' names occur outside them only as lib.rs's pub mod lines; the D2 type set is
    derived from the D2 files and none of its names occurs in another observer source; every D2 impl is `impl <own type>
    {`; no D2 file re-exports another item; the D2 files present are exactly those that take the logic rule. The words in
    a comment or a string pass."""

    TREE = D2_ISOLATION_TREE
    RULE = "G-D2-5"

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_observer_d2_isolation(self.base), 4)

    def test_the_module_names_outside_lib_rs_refuse(self):
        for rel, extra in (("crates/observer/src/observe.rs", "pub fn f() -> u8 { qualification::check_qualification() }\n"),
                           ("crates/observer/src/observe.rs", "pub fn f() -> u8 { crate::record_check::check_record() }\n"),
                           (CAPTURE_RS, "use crate::composition as c;\n"),
                           (gate.OBSERVER_MAIN, "use planeon_observer::i06_evidence;\n"),
                           (gate.OBSERVER_LIB, "pub use record_check::check_record;\n"),
                           # A pub mod line for a D2 module not built yet.
                           *[(gate.OBSERVER_LIB, "pub mod %s;\n" % name) for name in gate.D2_LOGIC_NAMES
                             if name not in gate.D2_LOGIC_BUILT][:1]):
            self.refused(gate.check_observer_d2_isolation, rel, self.TREE[rel] + extra, "names the D2 module .*" + self.RULE)
        lib = self.TREE[gate.OBSERVER_LIB]
        for text in (lib.replace("pub mod record_check;\n", ""), lib + "pub mod record_check;\n",
                     lib.replace("pub mod record_check;\n", "pub(crate) mod record_check;\n")):
            self.refused(gate.check_observer_d2_isolation, gate.OBSERVER_LIB, text, "does not declare `pub mod record_check;`")

    def test_the_d2_type_names_elsewhere_refuse(self):
        for rel, extra in ((gate.OBSERVER_MAIN, "fn f(p: Production) {}\n"), (CAPTURE_RS, "pub fn f() -> IpText { x() }\n"),
                           ("crates/observer/src/observe.rs", "type Accepted = RecordAccepted;\n"),
                           ("crates/observer/src/observe.rs", "fn f() { let _ = Walk::Node; }\n")):
            self.refused(gate.check_observer_d2_isolation, rel, self.TREE[rel] + extra, "a type the D2 module .*" + self.RULE)
        # A new D2 type passes, and naming it elsewhere refuses.
        self.write(RECORD_CHECK, D2_ISOLATION_RECORD + "struct Matcher;\n\nimpl Matcher {\n    fn new() -> u8 {\n        0\n    }\n}\n")
        self.assertEqual(gate.check_observer_d2_isolation(self.base), 5)
        self.refused(gate.check_observer_d2_isolation, CAPTURE_RS, CAPTURE_TEXT + "pub fn f(m: &Matcher) {}\n", "names Matcher")
        # A D2 type that an observer source defines or names (D1's Refusal, a helper trait named in observe.rs) refuses.
        self.refused(gate.check_observer_d2_isolation, RECORD_CHECK, D2_ISOLATION_RECORD + "pub enum Refusal {}\n", "names Refusal")
        self.write(RECORD_CHECK, D2_ISOLATION_RECORD + "trait Helper {}\n")
        self.refused(gate.check_observer_d2_isolation, "crates/observer/src/observe.rs",
                     self.TREE["crates/observer/src/observe.rs"] + "fn f(h: &dyn Helper) {}\n", "names Helper")
        self.write(RECORD_CHECK, D2_ISOLATION_RECORD)
        # Two D2 files defining one name refuse (the set stays unambiguous).
        self.refused(gate.check_observer_d2_isolation, "crates/observer/src/composition.rs", "pub struct IpText;\n",
                     "defines IpText, which crates/observer/src/composition.rs defines too")

    def test_impl_headers_and_re_exports_refuse(self):
        for extra in ("impl CheckedRecord {\n    pub fn more(&self) {}\n}\n", "impl CaptureCycle for RecordAccepted {}\n",
                      "impl<T> Walk {}\n", "impl<T: Clone> Helper for T {}\ntrait Helper {}\n", "impl IpText for u8 {}\n",
                      "impl std::fmt::Display for IpText {}\n", "pub fn f() { impl CheckedRecord {} }\n"):
            self.refused(gate.check_observer_d2_isolation, RECORD_CHECK, D2_ISOLATION_RECORD + extra, "impl header .*" + self.RULE)
        self.refused(gate.check_observer_d2_isolation, RECORD_CHECK, D2_ISOLATION_RECORD + "pub use crate::capture_check::Refusal;\n",
                     "re-exports crate::capture_check::Refusal")
        self.refused(gate.check_observer_d2_isolation, RECORD_CHECK, D2_ISOLATION_RECORD + "pub(crate) use crate::observe::run;\n",
                     "re-exports crate::observe::run")

    def test_the_present_d2_files_are_the_built_ones(self):
        self.assertEqual(sorted(gate.D2_LOGIC_BUILT), sorted(gate.D2_LOGIC_NAMES))
        # A D2 file present before its unit builds it (it would escape the logic rule) refuses.
        with mock.patch.object(gate, "D2_LOGIC_BUILT", ("record_check", "i06_evidence", "qualification")):
            with self.assertRaisesRegex(gate.GateError, "not exactly those that take the logic rule"):
                gate.check_observer_d2_isolation(self.base)
        # A built D2 file missing refuses.
        for rel in ("crates/observer/src/composition.rs", RECORD_CHECK):
            (self.base / rel).unlink()
            with self.assertRaisesRegex(gate.GateError, "not exactly those that take the logic rule"):
                gate.check_observer_d2_isolation(self.base)
            self.write(rel, self.TREE[rel])
        self.assertEqual(gate.check_observer_d2_isolation(self.base), 4)


class D2InterpreterTreeTests(Tree):
    """HE-004D2 G-D2-6: /opt/planeon/ occurs in crates/observer's sources only as record_check.rs's one exact, line-anchored
    INTERPRETER_TREE constant; a second occurrence, the literal elsewhere, a pub form, a raw string and a comment refuse."""

    EXPRESSION = 'const INTERPRETER_TREE: &str = "/opt/planeon/python/";'
    TREE = {RECORD_CHECK: "pub fn f() {}\n" + EXPRESSION + "\n", CAPTURE_RS: CAPTURE_TEXT}

    def test_the_one_expression_passes(self):
        self.assertEqual(gate.INTERPRETER_TREE[0], self.EXPRESSION)
        self.assertEqual(gate.check_observer_interpreter_tree(self.base), 1)
        self.write(RECORD_CHECK, "pub fn f() {}\n    const INTERPRETER_TREE: &str =\n        \"/opt/planeon/python/\";\n")
        self.assertEqual(gate.check_observer_interpreter_tree(self.base), 1)

    def test_other_forms_refuse(self):
        good = self.TREE[RECORD_CHECK]
        message = "G-D2-6"
        for text in (good + 'const BIN: &str = "/opt/planeon/bin/";\n', good + "// see /opt/planeon/python/ above\n",
                     good + self.EXPRESSION + "\n", good.replace(self.EXPRESSION, "pub " + self.EXPRESSION),
                     good.replace(self.EXPRESSION, "pub(crate) " + self.EXPRESSION),
                     good.replace('"/opt/planeon/python/"', 'r"/opt/planeon/python/"'),
                     good.replace("/opt/planeon/python/", "/opt/planeon/python/3.12/"),
                     good.replace(self.EXPRESSION, "const OTHER: u8 = 0;")):
            self.refused(gate.check_observer_interpreter_tree, RECORD_CHECK, text, message)
        self.refused(gate.check_observer_interpreter_tree, CAPTURE_RS, CAPTURE_TEXT + self.EXPRESSION + "\n", message)
        (self.base / RECORD_CHECK).unlink()
        with self.assertRaisesRegex(gate.GateError, "record_check.rs is missing"):
            gate.check_observer_interpreter_tree(self.base)


class D2RootConstantTests(Tree):
    """HE-004D2 G-D2-9: record_check.rs's CGROUP_ROOT and PIN_ROOT are excepted once each from the start-up lint and the
    linked-source fs scan, under G-D1-5's anchored patterns; a second /sys literal, the expression in another file, a pub
    form and fs in a comment refuse."""

    TEXT = ('const CGROUP_ROOT: &str = "/sys/fs/cgroup";\n/// The pins.\nconst PIN_ROOT: &str = "/sys/fs/bpf/planeon";\n'
            "pub fn f() {}\n")
    TREE = {**D1_TREE, RECORD_CHECK: TEXT}

    def test_the_tree_passes(self):
        self.assertEqual([expression for expression, _ in gate.D2_ROOT_CONSTANTS[RECORD_CHECK]],
                         ['const CGROUP_ROOT: &str = "/sys/fs/cgroup";', 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";'])
        self.assertIn(RECORD_CHECK, gate.STARTUP_EXCEPTIONS)
        self.assertIn(RECORD_CHECK, gate.FS_SCAN_EXCEPTIONS)
        self.assertGreater(gate.check_sources(self.base), 0)
        self.assertGreater(gate.check_linked_sources(self.base), 0)

    def test_other_forms_refuse(self):
        for old in ('const CGROUP_ROOT: &str = "/sys/fs/cgroup";', 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";'):
            for text in (self.TEXT.replace(old, "pub " + old), self.TEXT + old + "\n",
                         self.TEXT.replace(old, old.replace('= "', '= r"'))):
                self.refused(gate.check_sources, RECORD_CHECK, text, "uses /sys .start-up lint")
                self.refused(gate.check_linked_sources, RECORD_CHECK, text, "names a std fs item")
        for text in (self.TEXT + 'fn f() { let _ = "/sys/fs/cgroup/planeon.slice"; }\n',):
            self.refused(gate.check_sources, RECORD_CHECK, text, "uses /sys .start-up lint")
        self.refused(gate.check_linked_sources, RECORD_CHECK, self.TEXT + "// a fs-verity digest\n", "names a std fs item")
        self.refused(gate.check_sources, CAPTURE_RS, CAPTURE_TEXT + 'const PIN_ROOT: &str = "/sys/fs/bpf/planeon";\n',
                     "uses /sys .start-up lint")


class D2SymbolTests(unittest.TestCase):
    """HE-004D2 G-D2-7 (D2-4): no planeon-observer symbol has a path in a D2 module, by item path (legacy, v0, an inherent
    impl) or by its first crate root (a trait impl, a closure); a symbol that only mentions a D2 name passes."""

    REFUSED = ("_ZN16planeon_observer13qualification19check_qualification17h0123456789abcdefE",
               "_RNvNtCs5pXa2Z9YbGW_16planeon_observer13qualification19check_qualification",
               "_RNvMNtCs5pXa2Z9YbGW_16planeon_observer12record_checkNtB2_6IpText9canonical",
               "_RNvXs_NtCs5pXa2Z9YbGW_16planeon_observer12record_checkNtB4_6IpTextNtNtCsifRdLFh1usa_4core3fmt5Debug3fmt",
               "_RNCNvNtCs5pXa2Z9YbGW_16planeon_observer12i06_evidence14check_evidence0B5_",
               "_ZN16planeon_observer11composition13compose_fixture17h0123456789abcdefE")
    PASSED = ("_RNvNtCs5pXa2Z9YbGW_16planeon_observer7capture13qualification",
              "_RINvNtCsifRdLFh1usa_4core3ptr13drop_in_placeNtNtCs5pXa2Z9YbGW_16planeon_observer12record_check6IpTextEB4_",
              "_ZN4core3ptr61drop_in_place$LT$planeon_observer..record_check..RecordAccepted$GT$17h0123456789abcdefE",
              "_ZN16planeon_observer7capture11composition17h0123456789abcdefE",
              "_ZN18planeon_observer_x12record_check1f17h0123456789abcdefE", "record_check", "main")

    def test_d2_symbols_refuse_and_mentions_pass(self):
        self.assertEqual(gate.check_d2_absent(set(self.PASSED)), len(self.PASSED))
        for name in self.REFUSED:
            with self.assertRaisesRegex(gate.GateError, "a symbol of the D2 module .*G-D2-7"):
                gate.check_d2_absent(set(self.PASSED) | {name})


EVIDENCE_RS = "crates/observer/src/i06_evidence.rs"
TOKEN_TEXT = ("//! An i06_evidence fixture (`EvidenceAccepted {` and `Self {` in a comment pass).\n"
              "#[derive(Debug, PartialEq, Eq)]\npub struct EvidenceAccepted {\n    record_digest: String,\n"
              "    evidence_digest: String,\n    fixture: bool,\n}\n\n"
              "impl EvidenceAccepted {\n    pub fn record_digest(&self) -> &str {\n        &self.record_digest\n    }\n\n"
              "    pub fn fixture(&self) -> bool {\n        self.fixture\n    }\n}\n\n"
              "pub enum EvidenceRefusal {\n    Rule(&'static str),\n}\n\n"
              "pub fn check_evidence(flag: bool) -> Result<EvidenceAccepted, EvidenceRefusal> {\n"
              "    let record_digest = String::from(\"Self { }\");\n    if flag {\n        return Err(EvidenceRefusal::Rule(\"x\"));\n    }\n"
              "    Ok(EvidenceAccepted { record_digest, evidence_digest: String::new(), fixture: flag })\n}\n")


QUALIFICATION_RS = "crates/observer/src/qualification.rs"
QUALIFICATION_TOKEN_TEXT = ("//! A qualification fixture (B2).\n#[derive(Debug, PartialEq, Eq)]\npub struct QualificationAccepted {\n"
                            "    record_digest: String,\n    valid_from: u64,\n    expires_at: u64,\n    fixture: bool,\n}\n\n"
                            "impl QualificationAccepted {\n    pub fn valid_from(&self) -> u64 {\n        self.valid_from\n    }\n\n"
                            "    pub fn fixture(&self) -> bool {\n        self.fixture\n    }\n}\n\n"
                            "pub fn check_qualification(flag: bool) -> Result<QualificationAccepted, u8> {\n"
                            "    Ok(QualificationAccepted { record_digest: String::new(), valid_from: 0, expires_at: 0, "
                            "fixture: flag })\n}\n")


COMPOSITION_RS = "crates/observer/src/composition.rs"
COMPOSITION_TOKEN_TEXT = ("//! A composition fixture (B3).\nuse crate::i06_evidence::EvidenceAccepted;\n"
                          "use crate::qualification::QualificationAccepted;\n\n#[derive(Debug, PartialEq, Eq)]\n"
                          "pub struct Composed {\n    record_digest: String,\n    valid_from: u64,\n}\n\n"
                          "impl Composed {\n    pub fn valid_from(&self) -> u64 {\n        self.valid_from\n    }\n}\n\n"
                          "pub enum Production {\n    Unavailable(&'static str),\n}\n\n"
                          "pub fn compose_fixture(evidence: EvidenceAccepted, qualification: QualificationAccepted) "
                          "-> Result<Composed, u8> {\n    let _ = evidence;\n"
                          "    Ok(Composed { record_digest: String::new(), valid_from: qualification.valid_from() })\n}\n\n"
                          "pub fn compose_production(evidence: &EvidenceAccepted, qualification: &QualificationAccepted)\n"
                          "                          -> Result<Production, u8> {\n"
                          "    if evidence.fixture() || qualification.fixture() {\n        return Err(0);\n    }\n"
                          "    Ok(Production::Unavailable(\"W02-PROD Composed compose_fixture\"))\n}\n")


class D2TokenTests(Tree):
    """HE-004D2 G-D2-8 (D2-1; design review round 2, R2-1): the evidence token (A3), the qualification token (B2) and the
    composition (B3), whose production entry names none of compose_fixture, Composed, check_qualification and
    check_evidence. One literal, in the minting function (check_evidence, check_qualification, compose_fixture); private
    fields of the closed types; no Clone, Copy, Default, Hash or serde derive (also under cfg_attr); one impl of `&self`
    getters returning neither the token nor Self, each returning its own field; the token named only in its struct, impl
    header, the minting signature and the literal; outside the impl, a field reached only by its getter call; no `Self {`
    or `Self(` in a token file. Each of the reviewers' forms refuses; the real getters pass."""

    TREE = {EVIDENCE_RS: TOKEN_TEXT, CAPTURE_RS: CAPTURE_TEXT, QUALIFICATION_RS: QUALIFICATION_TOKEN_TEXT,
            COMPOSITION_RS: COMPOSITION_TOKEN_TEXT}
    RULE = "G-D2-8"
    IMPL_END = "        self.fixture\n    }\n}\n"

    def method(self, text):
        return TOKEN_TEXT.replace(self.IMPL_END, "        self.fixture\n    }\n\n" + text + "}\n")

    def test_the_fixture_and_the_built_tokens(self):
        self.assertEqual(gate.D2_TOKENS_BUILT, ("EvidenceAccepted", "QualificationAccepted", "Composed"))
        self.assertEqual(gate.D2_TOKENS["EvidenceAccepted"], (EVIDENCE_RS, "check_evidence"))
        self.assertEqual(gate.D2_TOKENS["QualificationAccepted"], (QUALIFICATION_RS, "check_qualification"))
        self.assertEqual(gate.D2_TOKENS["Composed"], (COMPOSITION_RS, "compose_fixture"))
        self.assertEqual(gate.check_observer_tokens(self.base), 3)
        # A strict test block may name Self; a `pub(crate)` getter passes.
        self.write(EVIDENCE_RS, TOKEN_TEXT.replace("    pub fn fixture(&self)", "    pub(crate) fn fixture(&self)")
                   + "#[cfg(test)]\nmod tests {\n    struct Local;\n    impl Local {\n        fn new() -> Local {\n"
                     "            Self {}\n        }\n    }\n}\n")
        self.assertEqual(gate.check_observer_tokens(self.base), 3)

    def test_the_composition_s_forms_refuse(self):
        # B3: the production entry naming the fixture entry, the composed token or either check; no production entry;
        # a second Composed literal; a re-flag of the composition's window.
        entry = "    Ok(Production::Unavailable(\"W02-PROD Composed compose_fixture\"))\n"
        for text, message in (("    let _ = compose_fixture;\n", "compose_production names compose_fixture"),
                              # Composed there is also a fifth naming of the token, which the name count refuses first.
                              ("    let _: Option<Composed> = None;\n", "names Composed other than"),
                              ("    crate::qualification::check_qualification(true);\n",
                               "compose_production names check_qualification"),
                              ("    crate::i06_evidence::check_evidence(true);\n", "compose_production names check_evidence")):
            self.refused(gate.check_observer_tokens, COMPOSITION_RS, COMPOSITION_TOKEN_TEXT.replace(entry, text + entry), message)
        self.refused(gate.check_observer_tokens, COMPOSITION_RS,
                     COMPOSITION_TOKEN_TEXT.replace("pub fn compose_production(", "pub fn production("),
                     "fn compose_production .*not exactly one such function")
        for text in (COMPOSITION_TOKEN_TEXT + "fn forge() -> u8 {\n    let _ = Composed { record_digest: String::new(), "
                     "valid_from: 0 };\n    0\n}\n",
                     COMPOSITION_TOKEN_TEXT + "pub fn widen(mut held: Held) {\n    held.valid_from = 0;\n}\n",
                     COMPOSITION_TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]", "#[derive(Debug, Default)]")):
            self.refused(gate.check_observer_tokens, COMPOSITION_RS, text, self.RULE)

    def test_the_qualification_token_s_forms_refuse(self):
        # B2: its file missing, a second literal, a field outside the closed types, the re-flag, a free re-flag function.
        (self.base / QUALIFICATION_RS).unlink()
        with self.assertRaisesRegex(gate.GateError, "qualification.rs is missing .*" + self.RULE):
            gate.check_observer_tokens(self.base)
        self.write(QUALIFICATION_RS, QUALIFICATION_TOKEN_TEXT)
        method = lambda text: QUALIFICATION_TOKEN_TEXT.replace("        self.fixture\n    }\n}\n",
                                                               "        self.fixture\n    }\n\n" + text + "}\n")
        for text in (QUALIFICATION_TOKEN_TEXT + "fn forge() -> u8 {\n    let _ = QualificationAccepted { record_digest: "
                     "String::new(), valid_from: 0, expires_at: 0, fixture: false };\n    0\n}\n",
                     QUALIFICATION_TOKEN_TEXT.replace("    expires_at: u64,\n", "    expires_at: u128,\n"),
                     QUALIFICATION_TOKEN_TEXT.replace("    valid_from: u64,\n", "    pub valid_from: u64,\n"),
                     QUALIFICATION_TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]", "#[derive(Debug, Clone)]"),
                     method("    pub fn as_production(self) -> Self {\n        Self { fixture: false, ..self }\n    }\n"),
                     method("    pub fn widen(&mut self) {\n        self.expires_at += 60;\n    }\n"),
                     QUALIFICATION_TOKEN_TEXT + "pub fn reflag(mut token: QualificationAccepted) -> QualificationAccepted {\n"
                                                "    token.fixture = false;\n    token\n}\n",
                     QUALIFICATION_TOKEN_TEXT + "pub fn extend(held: &mut Held) {\n    held.expires_at = u64::MAX;\n}\n"):
            self.refused(gate.check_observer_tokens, QUALIFICATION_RS, text, self.RULE)
        self.refused(gate.check_observer_tokens, CAPTURE_RS, CAPTURE_TEXT + "fn f() { let _ = QualificationAccepted { }; }\n",
                     "writes the QualificationAccepted literal")

    def test_a_second_literal_refuses(self):
        self.refused(gate.check_observer_tokens, EVIDENCE_RS, TOKEN_TEXT + "fn forge() -> u8 {\n    let _ = EvidenceAccepted {"
                     " record_digest: String::new(), evidence_digest: String::new(), fixture: false };\n    0\n}\n", self.RULE)
        self.refused(gate.check_observer_tokens, CAPTURE_RS, CAPTURE_TEXT + "fn f() { let _ = EvidenceAccepted { }; }\n",
                     "writes the EvidenceAccepted literal")

    def test_fields_and_derives_refuse(self):
        for text in (TOKEN_TEXT.replace("    fixture: bool,\n", "    pub fixture: bool,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    pub(crate) fixture: bool,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: std::cell::Cell<bool>,\n")
                     .replace("        self.fixture\n", "        self.fixture.get()\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: Cell<bool>,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: RefCell<bool>,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: AtomicBool,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: Mutex<bool>,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: RwLock<bool>,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: OnceCell<bool>,\n"),
                     TOKEN_TEXT.replace("    fixture: bool,\n", "    fixture: Box<bool>,\n"),
                     TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]", "#[derive(Debug, Clone)]"),
                     TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]", "#[derive(Copy, Debug)]"),
                     TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]", "#[derive(Default)]"),
                     TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]", "#[derive(Debug, Hash)]"),
                     TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]", "#[derive(Debug)]\n#[derive(serde::Deserialize)]"),
                     TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]\n", "#[derive(Debug, PartialEq, Eq)]\n"
                                        "#[cfg_attr(not(test), derive(Clone))]\n"),
                     TOKEN_TEXT.replace("#[derive(Debug, PartialEq, Eq)]\npub struct", "#[cfg_attr(not(test), derive(Clone, Debug))]\npub struct")):
            self.refused(gate.check_observer_tokens, EVIDENCE_RS, text, self.RULE)

    def test_the_reviewers_minting_and_re_flag_forms_refuse(self):
        for text in (
                # A minting method, the re-flag through a functional update, a by-value method returning Self.
                self.method("    pub fn forge(record_digest: String) -> Self {\n        Self { record_digest, evidence_digest: "
                            "String::new(), fixture: false }\n    }\n"),
                self.method("    pub fn as_production(self) -> Self {\n        Self { fixture: false, ..self }\n    }\n"),
                self.method("    pub fn keep(self) -> Self {\n        self\n    }\n"),
                # A getter returning the token, an associated function, a `&mut self` setter, an item in the impl.
                self.method("    pub fn again(&self) -> EvidenceAccepted {\n        x()\n    }\n"),
                self.method("    pub fn make() -> u8 {\n        0\n    }\n"),
                self.method("    pub fn set(&mut self, flag: bool) {\n        self.fixture = flag;\n    }\n"),
                self.method("    const KEPT: u8 = 0;\n"),
                # A tuple-style Self( anywhere in the token file.
                TOKEN_TEXT + "pub struct Pair(u8);\n\nimpl Pair {\n    pub fn new() -> Pair {\n        Self(0)\n    }\n}\n",
                # A free re-flag function, and a swap of the flag.
                TOKEN_TEXT + "pub fn reflag(mut token: EvidenceAccepted) -> EvidenceAccepted {\n    token.fixture = false;\n"
                             "    token\n}\n",
                TOKEN_TEXT + "pub fn swap(token: &mut Held, other: &mut bool) {\n    std::mem::swap(&mut token.fixture, other);\n}\n",
                TOKEN_TEXT + "pub fn bump(held: &mut Held) {\n    held.record_digest += \"x\";\n}\n",
                TOKEN_TEXT.replace("Result<EvidenceAccepted, EvidenceRefusal>", "Result<Box<EvidenceAccepted>, EvidenceRefusal>")
                .replace("    Ok(EvidenceAccepted {", "    let _: Option<EvidenceAccepted> = None;\n    Ok(EvidenceAccepted {")):
            self.refused(gate.check_observer_tokens, EVIDENCE_RS, text, self.RULE)

    def test_the_pr_review_round1_forms_refuse(self):
        # HE-004D2 PR review round 1, R1-1: a function in the token's file obtains a token from the minting function (its
        # type inferred, so the token's name count stays four) and reaches a field other than by its getter call: compound
        # assignments, a parenthesised place, a borrow of one, a method call on the field, a rebinding, a raw identifier,
        # a plain read. A getter answering other than its own field refuses too. Getter calls pass.
        evidence = lambda statement: TOKEN_TEXT + (
            "pub fn launder() -> bool {\n    let mut token = match check_evidence(true) {\n        Ok(token) => token,\n"
            "        Err(_) => return false,\n    };\n    %s\n    token.fixture()\n}\n" % statement)
        qualification = lambda statement: QUALIFICATION_TOKEN_TEXT + (
            "pub fn launder() -> u64 {\n    let mut token = match check_qualification(true) {\n        Ok(token) => token,\n"
            "        Err(_) => return 0,\n    };\n    %s\n    token.valid_from()\n}\n" % statement)
        self.write(EVIDENCE_RS, evidence("let _ = (token.record_digest(), token . fixture ());"))
        self.write(QUALIFICATION_RS, qualification("let _ = token.fixture();"))
        self.assertEqual(gate.check_observer_tokens(self.base), 3)
        self.write(QUALIFICATION_RS, QUALIFICATION_TOKEN_TEXT)
        for statement in ("token.fixture ^= true;", "(token.fixture) = false;", "std::mem::swap(&mut (token.fixture), &mut false);",
                          "token.fixture.clone_from(&false);", "token.record_digest.push_str(\"x\");",
                          "let held = &mut token;\n    held.fixture ^= true;", "token.r#fixture = false;",
                          "let flag = token.fixture;\n    let _ = flag;"):
            self.refused(gate.check_observer_tokens, EVIDENCE_RS, evidence(statement), "uses the EvidenceAccepted field")
        for statement in ("token.expires_at *= 2;", "token.valid_from <<= 1;", "token.expires_at >>= 1;",
                          "token.valid_from /= 1;", "token.expires_at %= 7;", "token.valid_from = token.valid_from() + 1;"):
            self.refused(gate.check_observer_tokens, QUALIFICATION_RS, qualification(statement),
                         "uses the QualificationAccepted field")
        # A lying getter, a getter reading another field, a getter whose name is no field.
        for text in (TOKEN_TEXT.replace(self.IMPL_END, "        false\n    }\n}\n"),
                     TOKEN_TEXT.replace(self.IMPL_END, "        self.record_digest.is_empty()\n    }\n}\n"),
                     TOKEN_TEXT.replace("    pub fn fixture(&self) -> bool {", "    pub fn production(&self) -> bool {")):
            self.refused(gate.check_observer_tokens, EVIDENCE_RS, text, "whose body is not")

    def test_self_literals_refuse_in_every_token_file(self):
        # qualification.rs (PredecessorSchemas built with Self { .. }) and composition.rs are token files as well.
        for rel in (QUALIFICATION_RS, "crates/observer/src/composition.rs"):
            kept = self.TREE.get(rel, "")
            self.refused(gate.check_observer_tokens, rel, kept + "pub struct PredecessorSchemas {\n    v1: u8,\n}\n\n"
                         "impl PredecessorSchemas {\n    pub fn from_bytes() -> PredecessorSchemas {\n        Self { v1: 0 }\n"
                         "    }\n}\n", "writes `Self\\{`")
            self.refused(gate.check_observer_tokens, rel, kept + "pub struct Pair(u8);\npub fn pair() -> Pair {\n    Self (0)\n}\n",
                         "writes `Self\\(`")
            self.write(rel, kept + "pub struct PredecessorSchemas {\n    v1: u8,\n}\n\nimpl PredecessorSchemas {\n"
                            "    pub fn from_bytes() -> PredecessorSchemas {\n        PredecessorSchemas { v1: 0 }\n    }\n}\n")
            self.assertEqual(gate.check_observer_tokens(self.base), 3)
            if rel in self.TREE:
                self.write(rel, kept)
            else:
                (self.base / rel).unlink()


# --- HE-004-I01a (DESIGN-I01A rev 6 section 12): the observer's I01 listener --------------------------------------------

I01_CLIENT_TEXT = ("//! The transport (a comment may name self.wire.wait(, W::wait, peer_send and Wire::wait).\n"
                   "pub trait PeerOps {\n    fn accept_peer(&mut self) -> u8;\n}\n"
                   "pub trait PeerService {\n    fn serve_peer_step(&mut self, ops: &mut dyn PeerOps) -> u8;\n}\n"
                   "pub struct Client<W: Wire> { wire: W, service: Option<Box<dyn PeerService>> }\n"
                   "impl<W: Wire + PeerOps> Client<W> {\n"
                   "    fn wait_serving(&mut self, until: u8) -> u8 {\n"
                   "        let woken = self.wire.wait(&[], until);\n"
                   "        if let Some(service) = self.service.as_deref_mut() {\n"
                   "            service.serve_peer_step(&mut self.wire);\n"
                   "        }\n"
                   "        woken\n"
                   "    }\n"
                   "    pub fn pause(&mut self) -> u8 {\n        self.wait_serving(1)\n    }\n"
                   "}\n")
I01_NET_TEXT = ("use gate_sys::channel;\nuse crate::linux_listen::I01Socket;\n"
                "pub struct LinuxWire { poller: channel::Poller, i01: I01Socket }\n"
                "impl LinuxWire {\n"
                "    pub fn new(sealed: &Sealed) -> Result<LinuxWire, u8> {\n"
                "        let i01 = I01Socket::open(sealed).map_err(|_| 31)?;\n"
                "        Ok(LinuxWire { poller: poller(), i01 })\n"
                "    }\n"
                "}\n"
                "impl Wire for LinuxWire {\n"
                "    fn wait(&mut self) -> u8 {\n"
                "        self.poller.wait(0, &mut ready);\n"
                "        0\n"
                "    }\n"
                "    fn send(&mut self, conn: u8) -> u8 {\n        self.conns.get(&conn).send(b)\n    }\n"
                "}\n")
I01_LISTEN_TEXT = ("use gate_sys::channel::{self, ListenStep};\n"
                   "const I01_PATH: &str = \"/run/planeon/live-proxy/policy-observer.sock\";\n"
                   "pub(crate) struct I01Socket { listener: channel::Listener }\n"
                   "impl I01Socket {\n"
                   "    pub(crate) fn open(_sealed: &Sealed) -> Result<I01Socket, u8> {\n"
                   "        channel::listen_seqpacket_plain(I01_PATH).map(|listener| I01Socket { listener }).map_err(|_| 31)\n"
                   "    }\n"
                   "}\n")
I01_OBSERVE = "crates/observer/src/observe.rs"
I01_TREE = {gate.OBSERVER_CLIENT: I01_CLIENT_TEXT, gate.OBSERVER_LINUX_NET: I01_NET_TEXT,
            gate.OBSERVER_LINUX_LISTEN: I01_LISTEN_TEXT,
            gate.OBSERVER_LIB: "#![forbid(unsafe_code)]\npub mod client;\npub mod i01_admission_render;\npub mod i01_answer;\n"
                              "pub mod i01_digest;\npub mod i01_gate;\npub mod i01_request;\npub mod i01_service;\n"
                              "pub mod linux_listen;\npub mod linux_net;\n",
            I01_OBSERVE: "pub fn run() -> u8 { 0 }\n",
            # Unit U4: the two i01_ sources.
            gate.I01_FILES[0]: "use crate::client::{PeerOps, PeerService};\npub struct I01Service;\n",
            gate.I01_FILES[1]: "pub fn check(bytes: &[u8]) -> bool { bytes.is_empty() }\n",
            # HE-004-I01B1 (DESIGN-I01B1 rev 2 section 4, I1D-4): the digest port's three logic modules.
            gate.I01_FILES[2]: "pub fn digest(bytes: &[u8]) -> usize { bytes.len() }\n",
            gate.I01_FILES[3]: "pub fn render() -> u8 { 0 }\n",
            gate.I01_FILES[4]: "pub const GATE_BOUND_MS: u64 = 90_000;\n",
            # HE-004-I01B3 (DESIGN-I01B3 rev 4 section 6, I3D-10): the answer logic.
            gate.I01_FILES[5]: "pub fn answer() -> u8 { 0 }\n"}
# The I01 fixture's sources: client.rs, linux_net.rs, linux_listen.rs, lib.rs, observe.rs and the six i01_ sources.
I01_TREE_COUNT = 11


class I01ListenerRuleTests(Tree):
    """HE-004-I01a G-I01-1, -2, -4, -5 and -6 (DESIGN-I01A section 12) over a small observer tree: the fixture passes and
    each departure refuses; then the five rules over the real sources."""

    TREE = I01_TREE

    def test_the_fixture_passes(self):
        self.assertEqual(gate.I01_PATH, "/run/planeon/live-proxy/policy-observer.sock")
        # HE-004-I01B1 (G-I01B-7 (a)): the service and its request checks, then the digest port's three modules;
        # HE-004-I01B3: then the answer logic.
        self.assertEqual(gate.I01_FILES, ("crates/observer/src/i01_service.rs", "crates/observer/src/i01_request.rs",
                                          "crates/observer/src/i01_digest.rs", "crates/observer/src/i01_admission_render.rs",
                                          "crates/observer/src/i01_gate.rs", "crates/observer/src/i01_answer.rs"))
        self.assertEqual(gate.check_observer_never_unlinks(self.base), I01_TREE_COUNT)
        self.assertEqual(gate.check_observer_wait_point(self.base), 3)
        self.assertEqual(gate.check_observer_i01_path(self.base), 1)
        self.assertEqual(gate.check_observer_no_send(self.base), I01_TREE_COUNT)
        self.assertEqual(gate.check_observer_i01_socket(self.base), I01_TREE_COUNT)

    def test_g_i01_1_no_path_is_removed_or_renamed(self):
        good = self.TREE[I01_OBSERVE]
        for text in ("fn f(d: &Dir) { d.unlink(n); }", "fn f() { let _ = remove_file(p); }", "fn f() { remove_dir(p); }",
                     "fn f() { remove_dir_all(p); }", "fn f() { rename(a, b); }", "fn f() { hard_link(a, b); }",
                     "use x::unlink;"):
            self.refused(gate.check_observer_never_unlinks, I01_OBSERVE, good + text + "\n", "G-I01-1")
        # Comments, literals and a strict test block pass.
        self.write(I01_OBSERVE, good + "// unlink and rename in a comment\nconst T: &str = \"remove_file\";\n"
                   "#[cfg(test)]\nmod tests {\n    fn t() { remove_dir_all(p); }\n}\n")
        self.assertEqual(gate.check_observer_never_unlinks(self.base), I01_TREE_COUNT)

    def test_g_i01_2_one_wire_wait_and_one_step(self):
        client, net = gate.OBSERVER_CLIENT, gate.OBSERVER_LINUX_NET
        good = self.TREE[client]
        anchor = "    pub fn pause(&mut self) -> u8 {\n        self.wait_serving(1)\n    }\n"
        for extra in ("    fn other(&mut self) -> u8 { self.wire.wait(&[], 2) }\n",
                      "    fn other(&mut self) -> u8 { W::wait(&mut self.wire, &[], 2) }\n",
                      "    fn other(&mut self) -> u8 { Wire :: wait(&mut self.wire, &[], 2) }\n",
                      "    fn other(&mut self) -> u8 { <W as Wire>::wait(&mut self.wire, &[], 2) }\n",
                      "    fn other(&mut self) -> u8 { let f = W::wait; f(&mut self.wire, &[], 2) }\n",
                      "    fn other(&mut self) -> u8 { self.wire . wait (&[], 2) }\n",
                      "    fn other(&mut self, s: &mut S) { s.serve_peer_step(&mut self.wire); }\n",
                      "    fn other(&mut self, s: &mut S) { PeerService::serve_peer_step(s, &mut self.wire); }\n",
                      "    fn other(&mut self, s: &mut S) { <S as PeerService>::serve_peer_step(s, &mut self.wire); }\n",
                      "    fn other(&mut self) { let _f = S::serve_peer_step; }\n"):
            self.refused(gate.check_observer_wait_point, client, good.replace(anchor, anchor + extra), "G-I01-2")
        # The wire wait moved out of wait_serving, the step called twice, a wait in another file, the poller's wait
        # replaced.
        moved = good.replace("        let woken = self.wire.wait(&[], until);\n", "        let woken = until;\n").replace(
            anchor, anchor + "    fn other(&mut self) -> u8 { self.wire.wait(&[], 2) }\n")
        self.refused(gate.check_observer_wait_point, client, moved, "G-I01-2")
        step = "            service.serve_peer_step(&mut self.wire);\n"
        self.refused(gate.check_observer_wait_point, client, good.replace(step, step + step), "G-I01-2")
        self.refused(gate.check_observer_wait_point, I01_OBSERVE,
                     self.TREE[I01_OBSERVE] + "fn f<W: Wire>(w: &mut W) { w.wait(&[], 1); }\n", "G-I01-2")
        self.refused(gate.check_observer_wait_point, net,
                     self.TREE[net].replace("self.poller.wait(0, &mut ready)", "self.other.wait(0, &mut ready)"), "G-I01-2")
        # A strict test block passes.
        self.write(client, good + "#[cfg(test)]\nmod tests {\n    fn t(w: &mut W) { w.wait(&[], 1); }\n}\n")
        self.assertEqual(gate.check_observer_wait_point(self.base), 3)

    def test_g_i01_4_the_path_lives_only_in_the_listener_file(self):
        listen = gate.OBSERVER_LINUX_LISTEN
        good = self.TREE[listen]
        other = self.TREE[I01_OBSERVE]
        for rel, text in ((I01_OBSERVE, other + "// /run/planeon/live-proxy/policy-observer.sock\n"),
                          (I01_OBSERVE, other + "const P: &str = \"policy-observer.sock\";\n"),
                          (listen, good + "// policy-observer.sock again\n"),
                          (listen, good.replace("const I01_PATH", "pub const I01_PATH")),
                          (listen, good.replace("\"/run/planeon/live-proxy/policy-observer.sock\"",
                                                "concat!(\"/run/planeon/live-proxy/\", \"policy-observer.sock\")"))):
            self.refused(gate.check_observer_i01_path, rel, text, "G-I01-4")
        (self.base / listen).unlink()
        with self.assertRaisesRegex(gate.GateError, "linux_listen.rs is missing .the I01 path, G-I01-4"):
            gate.check_observer_i01_path(self.base)

    def test_g_i01_5_nothing_leaves_i01a(self):
        net, listen, client, lib = gate.OBSERVER_LINUX_NET, gate.OBSERVER_LINUX_LISTEN, gate.OBSERVER_CLIENT, gate.OBSERVER_LIB
        # HE-004-I01B5 (DESIGN-I01B5 rev 5 section 6.3; F6.5): the "no peer_send" and "no channel::send path" clauses
        # became G-I01B-5 (a) and (c)'s exact counts; their rows keep their intent there (I01b5SendTests: P5-1, P5-2,
        # P5-4 and the three channel::send spellings), and G-I01-5 itself passes them now.
        for rel, text in ((I01_OBSERVE, "fn f(o: &mut dyn PeerOps) { o.peer_send(1, b); }"),
                          (net, "fn f(c: &Conn) { let _ = channel::send(c, b); }"),
                          (listen, "fn f(c: &Conn) { let _ = gate_sys :: channel :: send(c, b); }"),
                          (listen, "fn f(c: &Conn) { let _ = ::gate_sys::channel::send(c, b); }")):
            self.write(rel, self.TREE[rel] + text + "\n")
            self.assertEqual(gate.check_observer_no_send(self.base), I01_TREE_COUNT)
            self.write(rel, self.TREE[rel])
        for rel in (net, listen):
            for text in ("use gate_sys::channel::send;", "use gate_sys::channel::{Conn, send};",
                         "use gate_sys::channel::send as s;", "use gate_sys::channel as ch;", "use gate_sys::{channel as ch};",
                         "use gate_sys::channel::{self as ch};"):
                self.refused(gate.check_observer_no_send, rel, self.TREE[rel] + text + "\n", "G-I01-5")
        # PeerOps: exactly `pub trait PeerOps {`, once, in client.rs.
        good = self.TREE[client]
        for text in (good.replace("pub trait PeerOps {", "pub trait PeerOps: Wire {"),
                     good.replace("pub trait PeerOps {", "pub trait PeerOps where Self: Wire {"),
                     good.replace("pub trait PeerOps {", "pub(crate) trait PeerOps {"),
                     good + "pub trait PeerOps {\n}\n"):
            self.refused(gate.check_observer_no_send, client, text, "G-I01-5")
        self.refused(gate.check_observer_no_send, I01_OBSERVE, self.TREE[I01_OBSERVE] + "trait PeerOps {}\n", "G-I01-5")
        # The i01_ sources: exactly the built ones (unit U4's two; HE-004-I01B1's digest port adds three), declared in
        # lib.rs, naming none of Wire, connect, ConnId and Client; no response, observation or answer module; and none
        # before its unit builds it.
        service, request = gate.I01_FILES[:2]
        self.assertEqual(gate.I01_FILES_BUILT, gate.I01_FILES)
        for word in ("Wire", "connect", "ConnId", "Client"):
            self.refused(gate.check_observer_no_send, service, self.TREE[service] + "fn f(w: &dyn %s) {}\n" % word, "G-I01-5")
            self.refused(gate.check_observer_no_send, request, self.TREE[request] + "fn %s() {}\n" % word, "G-I01-5")
            for rel in gate.I01_FILES[2:]:
                self.refused(gate.check_observer_no_send, rel, self.TREE[rel] + "fn %s() {}\n" % word, "G-I01-5")
        # HE-004-I01B1 (DESIGN-I01B rev 3 section 8.5, I1D-4): src/i01_digest.rs, refused here before, is now built and
        # allowed; HE-004-I01B3 (DESIGN-I01B3 rev 4 section 6, I3D-10): so is i01_answer.rs, whose refusal row becomes an
        # allowance, keeping its intent: an i01_ source no packet has built (a response or observation module) refuses.
        for rel in ("crates/observer/src/i01_digest.rs", "crates/observer/src/i01_answer.rs"):
            self.write(rel, "pub fn answer() {}\n")
            self.assertEqual(gate.check_observer_no_send(self.base), I01_TREE_COUNT)
            self.write(rel, self.TREE[rel])
        for rel in ("crates/observer/src/i01_response.rs", "crates/observer/src/i01_observation.rs"):
            self.refused(gate.check_observer_no_send, rel, "pub fn answer() {}\n", "G-I01-5")
        self.refused(gate.check_observer_no_send, lib, self.TREE[lib] + "mod i01_observation;\n", "G-I01-5")
        self.refused(gate.check_observer_no_send, lib, self.TREE[lib].replace("pub mod i01_request;\n", ""), "G-I01-5")
        (self.base / request).unlink()
        with self.assertRaisesRegex(gate.GateError, "G-I01-5"):
            gate.check_observer_no_send(self.base)
        self.write(request, self.TREE[request])
        with mock.patch.object(gate, "I01_FILES_BUILT", ()):
            with self.assertRaisesRegex(gate.GateError, "the i01_ sources present .* are not exactly none"):
                gate.check_observer_no_send(self.base)
        self.assertEqual(gate.check_observer_no_send(self.base), I01_TREE_COUNT)

    def test_g_i01_5_the_alias_forms_refuse(self):
        # HE-004-I01A2 (HE-004-I01a PR review round 1, R1-3; Q-U7-2 (a)): the reviewer's probe and its kin, in both socket
        # files: each import of send or rename of the channel module through a crate alias, braced or not, refuses as
        # its direct form does, and so does a crate alias, a glob of gate_sys or an extern crate by itself.
        net, listen = gate.OBSERVER_LINUX_NET, gate.OBSERVER_LINUX_LISTEN
        call = "fn f(x: &Conn) { let _ = c::send(x, b); }"
        for rel in (net, listen):
            for text, message in (
                    ("use gate_sys as gs;\nuse gs::channel::{send};\nfn f(x: &Conn) { let _ = send(x, b); }",
                     "imports gate-sys's channel send"),                                       # the reviewer's probe
                    ("use gate_sys as gs;\nuse gs::channel::send;", "imports gate-sys's channel send"),
                    ("use gate_sys as gs;\nuse gs::channel::{Conn, send as s};", "imports gate-sys's channel send"),
                    ("use gate_sys::{self as gs};\nuse gs::{channel::{send}};", "imports gate-sys's channel send"),
                    ("use gate_sys as gs;\nuse self::gs::channel::send;", "imports gate-sys's channel send"),
                    ("use gate_sys as gs;\nuse gs::channel;\nuse channel::send;", "imports gate-sys's channel send"),
                    ("use gate_sys as g1;\nuse g1 as g2;\nuse g2::channel::send;", "imports gate-sys's channel send"),
                    ("use gate_sys as gs;\nuse gs::channel as c;\n" + call, "channel send through c"),
                    ("use gate_sys::channel as c;\n" + call, "channel send through c"),
                    ("use gate_sys as gs;\nuse gs::{channel::{self as c}};\n" + call, "channel send through c"),
                    ("use gate_sys as gs;\nuse gs::channel as c;", "renames gate-sys's channel module"),
                    ("use gate_sys as gs;\nuse gs::{channel as c};", "renames gate-sys's channel module"),
                    # HE-004-I01B5: the path itself is G-I01B-5 (c)'s count now; the crate alias still refuses here.
                    ("use gate_sys as gs;\nfn f(x: &Conn) { let _ = gs::channel::send(x, b); }", "renames gate_sys"),
                    ("use gate_sys as gs;", "renames gate_sys"),
                    ("use gate_sys::{self as gs};", "renames gate_sys"),
                    ("use ::gate_sys as gs;", "renames gate_sys"),
                    ("use gate_sys::*;", "imports a glob of gate_sys"),
                    ("extern crate gate_sys as gs;", "declares an extern crate")):
                self.refused(gate.check_observer_no_send, rel, self.TREE[rel] + text + "\n", message + ".*G-I01-5")
        # The aliases the real files hold are unchanged: plain `channel` and `{self, ListenStep}` imports pass.
        self.assertEqual(gate.resolved_uses([(("gate_sys", "channel", "self"), None), (("gate_sys", "channel", "ListenStep"), None)]),
                         [(("gate_sys", "channel", "self"), None), (("gate_sys", "channel", "ListenStep"), None)])
        self.assertEqual(gate.resolved_uses([(("gate_sys",), "gs"), (("gs", "channel"), "c"), (("c", "send"), None)]),
                         [(("gate_sys",), "gs"), (("gate_sys", "channel"), "c"), (("gate_sys", "channel", "send"), None)])
        self.assertEqual(gate.gate_sys_aliases([(("gate_sys",), "gs"), (("gate_sys", "self"), "g2"), (("gate_sys", "tcp"), "t")]),
                         {"gs", "g2"})
        self.assertEqual(gate.check_observer_no_send(self.base), I01_TREE_COUNT)

    def test_g_i01_6_the_socket_s_homes_and_its_one_construction(self):
        net, listen = gate.OBSERVER_LINUX_NET, gate.OBSERVER_LINUX_LISTEN
        call = "        let i01 = I01Socket::open(sealed).map_err(|_| 31)?;\n"
        good = self.TREE[net]
        for text in (good + "fn again(s: &Sealed) { let _ = I01Socket::open(s); }\n",
                     good.replace(call, call + "        let _again = <I01Socket>::open(sealed);\n"),
                     good.replace(call, call + "        let _again = I01Socket::<>::open(sealed);\n"),
                     good.replace(call, call + "        let _again = <(I01Socket)>::open(sealed);\n"),
                     good.replace(call, call + "        let _again = I01Socket :: open(sealed);\n"),
                     good.replace(call, "        let i01 = make(sealed)?;\n"),
                     good + "pub type Socket = I01Socket;\n",
                     good.replace("use crate::linux_listen::I01Socket;", "use crate::linux_listen::I01Socket as Socket;")):
            self.refused(gate.check_observer_i01_socket, net, text, "G-I01-6")
        for text in (self.TREE[listen] + "impl I01Socket {\n    fn reopen(s: &Sealed) -> Result<Self, u8> { Self::open(s) }\n}\n",
                     self.TREE[listen] + "pub(crate) type Socket<T = I01Socket> = T;\n"):
            self.refused(gate.check_observer_i01_socket, listen, text, "G-I01-6")
        for text in ("fn f(s: &crate::linux_listen::I01Socket) {}\n", "pub struct H<T = I01Socket>(T);\n"):
            self.refused(gate.check_observer_i01_socket, I01_OBSERVE, self.TREE[I01_OBSERVE] + text, "G-I01-6")
        self.assertIn("I01Socket", gate.DEBUG_HAZARDS)
        self.assertEqual(gate.check_observer_i01_socket(self.base), I01_TREE_COUNT)

    def test_the_real_sources_pass(self):
        # Over the observer's real sources (as built): the five rules hold.
        for check in (gate.check_observer_never_unlinks, gate.check_observer_no_send, gate.check_observer_i01_socket):
            self.assertGreater(check(gate.HE), 30, check.__name__)
        self.assertEqual(gate.check_observer_wait_point(gate.HE), 3)
        self.assertEqual(gate.check_observer_i01_path(gate.HE), 1)


# HE-004-I01a unit U6 (DESIGN-I01A sections 10 and 12): the role pin's call in a small check_snapshot.
ROLE_PIN_OBSERVE = (
    "use crate::observer_rbac::{self, RbacLists};\n"
    "impl Epoch {\n"
    "    // Closure::check and observer_rbac::check_observer_snapshot( in a comment are no anchors.\n"
    "    fn check_snapshot(&mut self, inputs: Inputs) -> Result<u8, Stop> {\n"
    "        let produced = match produce_snapshot(&inputs, &namespace) {\n"
    "            Ok(produced) => produced,\n"
    "            Err(_) => return Err(self.stop(ObserverExit::Rbac, \"B1 {refused}\")),\n"
    "        };\n"
    "        if self.closure.check(&produced.snapshot, &namespace).is_err() {\n"
    "            return Err(self.stop(ObserverExit::Rbac, \"the closure check refused\"));\n"
    "        }\n"
    "        let cluster_roles = match inputs.items(Resource::ClusterRoles) {\n"
    "            Ok(items) => items,\n"
    "            Err(error) => return Err(self.input_exit(&error)),\n"
    "        };\n"
    "        let cluster_role_bindings = inputs.items(Resource::ClusterRoleBindings).unwrap_or(&[]);\n"
    "        let role_bindings = inputs.items(Resource::RoleBindings).unwrap_or(&[]);\n"
    "        if observer_rbac::check_observer_snapshot(&produced.snapshot,\n"
    "                                                  RbacLists { cluster_roles, cluster_role_bindings, role_bindings })\n"
    "            .is_err()\n"
    "        {\n"
    "            return Err(self.stop(ObserverExit::Rbac, \"I06 v4's role pin refused\"));\n"
    "        }\n"
    "        let dropped = produced.dropped_non_resource_rules;\n"
    "        drop(produced);\n"
    "        for check in [check_or02, check_or05, check_or06] {\n"
    "            check(&inputs)?;\n"
    "        }\n"
    "        Ok(dropped)\n"
    "    }\n"
    "}\n")
ROLE_PIN_CALL_TEXT = "        if observer_rbac::check_observer_snapshot(&produced.snapshot,\n"
ROLE_PIN_LAST_LET = "        let role_bindings = inputs.items(Resource::RoleBindings).unwrap_or(&[]);\n"
ROLE_PIN_DROPS = "        let dropped = produced.dropped_non_resource_rules;\n        drop(produced);\n"


class RolePinCallTests(Tree):
    """HE-004-I01a G-I01-3 (DESIGN-I01A sections 10 and 12): observe.rs calls observer_rbac::check_observer_snapshot
    once, in the statement after the closure check's with only `let`s between, followed by `let dropped` and then
    drop(produced); each departure refuses; then the real observe.rs."""

    TREE = {"crates/observer/src/observe.rs": ROLE_PIN_OBSERVE}
    RULE = "G-I01-3"

    def test_the_fixture_passes(self):
        self.assertEqual(gate.OBSERVER_OBSERVE, "crates/observer/src/observe.rs")
        self.assertEqual(gate.check_observer_role_pin(self.base), 3)
        # Spacing around `::`, a strict test block's own call and a second block elsewhere pass.
        good = ROLE_PIN_OBSERVE
        self.write(gate.OBSERVER_OBSERVE, good.replace("observer_rbac::check_observer_snapshot(&produced",
                                                       "observer_rbac :: check_observer_snapshot (&produced")
                   + "#[cfg(test)]\nmod tests {\n    fn t() { observer_rbac::check_observer_snapshot(&s, l); }\n}\n")
        self.assertEqual(gate.check_observer_role_pin(self.base), 3)
        # No list let at all is still only lets (none) between.
        self.write(gate.OBSERVER_OBSERVE, good.replace(ROLE_PIN_LAST_LET, ""))
        self.assertEqual(gate.check_observer_role_pin(self.base), 2)

    def test_departures_refuse(self):
        good, rel = ROLE_PIN_OBSERVE, gate.OBSERVER_OBSERVE
        closure = "        if self.closure.check(&produced.snapshot, &namespace).is_err() {\n"
        for text in (
                # The call missing, twice, or spelled as an imported name.
                good.replace("observer_rbac::check_observer_snapshot(&produced", "observer_rbac::other(&produced"),
                good + "fn again(s: &Value, l: RbacLists) { let _ = observer_rbac::check_observer_snapshot(s, l); }\n",
                good.replace("observer_rbac::check_observer_snapshot(&produced", "check_observer_snapshot(&produced")
                + "use crate::observer_rbac::check_observer_snapshot;\n",
                good + "fn f() { let g = check_observer_snapshot; }\n",
                # A statement other than `let` between, or the call before the closure check.
                good.replace(ROLE_PIN_LAST_LET, ROLE_PIN_LAST_LET + "        self.trace(1);\n"),
                good.replace(ROLE_PIN_LAST_LET, ROLE_PIN_LAST_LET + "        if role_bindings.is_empty() {\n            self.note();\n        }\n"),
                good.replace(closure, "        let early = observer_rbac::check_observer_snapshot(&produced.snapshot, l);\n" + closure)
                .replace(ROLE_PIN_CALL_TEXT, "        if observer_rbac::other(&produced.snapshot,\n"),
                # The two drops missing, swapped or not right after the call.
                good.replace(ROLE_PIN_DROPS, "        drop(produced);\n"),
                good.replace(ROLE_PIN_DROPS, "        drop(produced);\n        let dropped = 0;\n"),
                good.replace(ROLE_PIN_DROPS, "        self.trace(2);\n" + ROLE_PIN_DROPS),
                # The closure check twice, or only in a comment.
                good + "fn g(&self) -> bool { self.closure.check(&s, &n).is_ok() }\n",
                good.replace(closure, "        // self.closure.check(&produced.snapshot, &namespace)\n        if false {\n"),
                # The call in another block than the closure check's.
                good.replace(closure, "        {\n" + closure).replace(ROLE_PIN_LAST_LET, ROLE_PIN_LAST_LET + "        }\n")):
            self.assertNotEqual(text, good)
            self.refused(gate.check_observer_role_pin, rel, text, self.RULE)
        (self.base / rel).unlink()
        with self.assertRaisesRegex(gate.GateError, "observe.rs is missing .the role pin's call, G-I01-3"):
            gate.check_observer_role_pin(self.base)

    def test_the_real_observe_rs_passes(self):
        self.assertEqual(gate.check_observer_role_pin(gate.HE), 3)


ROLE_PIN_RBAC_TEXT = (gate.HE / "crates/observer/src/observer_rbac.rs").read_text(encoding="utf-8")
ROLE_PIN_VECTORS_TEXT = (gate.HE / "contracts/i06-v4/vectors.json").read_text(encoding="utf-8")


class RolePinConstantTests(Tree):
    """HE-004-I01a DESIGN-I01A section 10 (Q-I01A-4 (a)): the role pin's compiled rule data matches the I06 v4 vectors'
    objectsPositive; a changed rule, name, pair or count refuses, as do constants the check cannot read plainly, and a
    changed positive."""

    TREE = {"crates/observer/src/observer_rbac.rs": ROLE_PIN_RBAC_TEXT, "contracts/i06-v4/vectors.json": ROLE_PIN_VECTORS_TEXT}
    RULE = "the role pin's constants"

    def test_the_real_constants_pass(self):
        self.assertEqual(gate.OBSERVER_RBAC, "crates/observer/src/observer_rbac.rs")
        self.assertEqual(gate.I06_V4_VECTORS, "contracts/i06-v4/vectors.json")
        self.assertEqual(gate.check_observer_role_constants(self.base), 14)
        self.assertEqual(gate.check_observer_role_constants(gate.HE), 14)

    def test_changed_constants_refuse(self):
        good, rel = ROLE_PIN_RBAC_TEXT, gate.OBSERVER_RBAC
        last = re.search(r"    ContractRule \{ api_groups: &\[\], resources: &\[\],.*?\},\n", good, re.S).group(0)
        for old, new in (
                ('"serviceaccounts", "secrets"]', '"serviceaccounts", "secret"]'),
                ('"serviceaccounts", "secrets"]', '"serviceaccounts"]'),
                ('verbs: &["get"]', 'verbs: &["get", "list"]'),
                ('verbs: &["get"], resource_names: &[]', 'verbs: &["get"], resource_names: &["x"]'),
                ('resources: &["networkpolicies"], non_resource_urls: &[]',
                 'resources: &["networkpolicies"], non_resource_urls: &["/metrics"]'),
                ('api_groups: &["networking.k8s.io"]', 'api_groups: &["networking.k8s.io", ""]'),
                ('pub const ROLE_NAME: &str = "planeon:policy-observer";', 'pub const ROLE_NAME: &str = "planeon-policy-observer";'),
                ('pub const BINDING_NAME: &str = "planeon:policy-observer";',
                 'pub const BINDING_NAME: &str = "planeon:policy-observers";'),
                ('pub const OBSERVER_USER: &str = "planeon:policy-observer";', 'pub const OBSERVER_USER: &str = "planeon:observer";'),
                ('pub const RBAC_API_VERSION: &str = "rbac.authorization.k8s.io/v1";',
                 'pub const RBAC_API_VERSION: &str = "rbac.authorization.k8s.io/v1beta1";'),
                ('("kind", "ClusterRole")', '("kind", "Role")'),
                ('("kind", "User")', '("kind", "Group")'),
                # Forms the check cannot read plainly: a computed text, a constant list, a missing field, an escape.
                ('pub const ROLE_NAME: &str = "planeon:policy-observer";', 'pub const ROLE_NAME: &str = OBSERVER_USER;'),
                ('verbs: &["get"]', 'verbs: GET'),
                (', resource_names: &[] },\n];', ' },\n];'),
                ('"/version"', '"/vers\\u{69}on"'),
                ('pub const OBSERVER_RULES: [ContractRule; 8]', 'pub const OBSERVER_RULES: [ContractRule; 9]'),
                ("pub const SUBJECT: [(&str, &str); 3] =", "pub const SUBJECT: [(&str, &str); 4] =")):
            self.assertIn(old, good)
            self.refused(gate.check_observer_role_constants, rel, good.replace(old, new, 1), self.RULE)
        # Seven rules, declared and held, against the contract's eight; a second definition of a constant.
        self.refused(gate.check_observer_role_constants, rel,
                     good.replace(last, "").replace("[ContractRule; 8]", "[ContractRule; 7]"), self.RULE)
        self.refused(gate.check_observer_role_constants, rel,
                     good + 'pub const ROLE_NAME: &str = "planeon:policy-observer";\n', self.RULE)

    def test_a_changed_positive_refuses(self):
        rel = "contracts/i06-v4/vectors.json"
        vectors = json.loads(ROLE_PIN_VECTORS_TEXT)
        for change in (lambda positive: positive["clusterRoles"][0]["rules"][0]["verbs"].append("get"),
                       lambda positive: positive["clusterRoles"][0]["rules"].pop(),
                       lambda positive: positive["clusterRoles"][0]["metadata"].update(name="other"),
                       lambda positive: positive["clusterRoleBindings"][0]["subjects"].append(
                           {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "x"}),
                       lambda positive: positive["clusterRoleBindings"][0]["roleRef"].update(apiGroup="")):
            changed = json.loads(ROLE_PIN_VECTORS_TEXT)
            change(changed["objectsPositive"])
            self.assertNotEqual(changed, vectors)
            self.refused(gate.check_observer_role_constants, rel, json.dumps(changed), self.RULE)
        self.refused(gate.check_observer_role_constants, rel, "[]", self.RULE)


# --- HE-004-I01B1 (DESIGN-I01B rev 3 sections 2 and 6, DESIGN-I01B1 rev 2 section 4) -------------------------------------

class I01bContractFileTests(Tree):
    """HE-004-I01B1 G-I01B-2 over a tree holding copies of edge record v10's four files, PROVENANCE.md and contracts.rs:
    the tree and the real host-enforcement pass; a changed byte, a wrong mode (an execute bit), a symlink, a missing
    file, an embedded file (an include_bytes! or include_str! literal in a crate source, or the file in
    OBSERVER_EMBEDDED_CONTRACTS), a missing, changed or doubled PROVENANCE.md line and a CONTRACTS digest other than the
    row's each refuse. HE-004-I01B4 (DESIGN-I01B4 rev 2 section 5): the tree also holds edge record v11's seven files,
    and every case runs over the eleven, each refusal naming its record (v10 or v11) and row."""

    RULE = "G-I01B-2"
    COPIED = I01B_V10_CONTRACTS + I01B_V11_CONTRACTS + ("contracts/PROVENANCE.md", gate.OBSERVER_CONTRACTS)
    # HE-004-I01B4: each of the eleven files with the edge record its refusals name.
    RECORDS = tuple((rel, "v10") for rel in I01B_V10_CONTRACTS) + tuple((rel, "v11") for rel in I01B_V11_CONTRACTS)

    def setUp(self):
        super().setUp()
        for rel in self.COPIED:
            path = self.base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((gate.HE / rel).read_bytes())
            path.chmod(0o644)

    def refuses(self, message):
        with self.assertRaisesRegex(gate.GateError, "%s .*%s" % (message, self.RULE)):
            gate.check_i01b_contracts(self.base)

    def test_the_tree_and_the_real_files_pass(self):
        # HE-005A: edge record v11's four seccomp-v3 rows join the 63 (outside the I01b rows this rule reads). HE-005B:
        # edge record v12's two broker handoff rows make 69 (also outside them).
        self.assertEqual(len(gate.CONTRACTS), 69)
        self.assertEqual(tuple(gate.I01B_EDGE_V10_ROWS), I01B_V10_CONTRACTS)
        self.assertEqual([row[0] for row in gate.I01B_EDGE_V10_ROWS.values()], [69, 70, 71, 72])
        self.assertEqual([row[1] for row in gate.I01B_EDGE_V10_ROWS.values()],
                         ["architecture/policy-observation-digests/definitions.json",
                          "architecture/policy-observation-digests/vectors.json",
                          "architecture/policy-observation-digests/README.md",
                          "architecture/proxy-contract-inputs/vectors.json"])
        self.assertEqual(tuple(gate.I01B_EDGE_V11_ROWS), I01B_V11_CONTRACTS)
        self.assertEqual([row[0] for row in gate.I01B_EDGE_V11_ROWS.values()], [73, 74, 75, 76, 77, 78, 79])
        self.assertEqual([row[1] for row in gate.I01B_EDGE_V11_ROWS.values()],
                         ["architecture/policy-observation-digests-v2/definitions.json",
                          "architecture/policy-observation-digests-v2/vectors.json",
                          "architecture/policy-observation-digests-v2/README.md",
                          "architecture/admission-semantics-v4/README.md",
                          "architecture/admission-semantics-v4/vectors.json",
                          "architecture/admission-semantics-v4/admission-manifests/planeon-a2.json",
                          "architecture/proxy-profile-v2/vectors.json"])
        for rel, (_, _, digest) in list(gate.I01B_EDGE_V10_ROWS.items()) + list(gate.I01B_EDGE_V11_ROWS.items()):
            self.assertEqual(gate.CONTRACTS[rel], digest)
            self.assertEqual(hashlib.sha256((gate.HE / rel).read_bytes()).hexdigest(), digest)
            self.assertNotIn(rel, gate.OBSERVER_EMBEDDED_CONTRACTS)
        self.assertEqual(len(gate.OBSERVER_EMBEDDED_CONTRACTS), 5)
        self.assertEqual(gate.check_i01b_contracts(self.base), 11)
        self.assertEqual(gate.check_i01b_contracts(gate.HE), 11)

    def test_a_changed_byte_refuses(self):
        for rel, record in self.RECORDS:
            path = self.base / rel
            data = path.read_bytes()
            for changed in (data[:-1] + bytes([data[-1] ^ 1]), bytes([data[0] ^ 1]) + data[1:], data + b"\n", data[:-1]):
                path.write_bytes(changed)
                self.refuses("%s differs from edge record %s's row" % (re.escape(rel), record))
            path.write_bytes(data)
        self.assertEqual(gate.check_i01b_contracts(self.base), 11)

    def test_a_wrong_mode_a_symlink_or_a_missing_file_refuses(self):
        for rel in I01B_V10_CONTRACTS + I01B_V11_CONTRACTS:
            path = self.base / rel
            for mode in (0o755, 0o744, 0o654, 0o645):
                path.chmod(mode)
                self.refuses("%s is not mode 100644" % re.escape(rel))
            path.chmod(0o644)
            data = path.read_bytes()
            twin = self.base / "twin"
            twin.write_bytes(data)
            path.unlink()
            path.symlink_to(twin)
            self.refuses("%s is missing or a symlink" % re.escape(rel))
            path.unlink()
            twin.unlink()
            self.refuses("%s is missing or a symlink" % re.escape(rel))
            path.write_bytes(data)
            path.chmod(0o644)
        self.assertEqual(gate.check_i01b_contracts(self.base), 11)

    def test_an_embedded_file_refuses(self):
        contracts_rs = self.base / gate.OBSERVER_CONTRACTS
        good = contracts_rs.read_text(encoding="utf-8")
        for rel in I01B_V10_CONTRACTS + I01B_V11_CONTRACTS:
            literal = "../../../" + rel
            contracts_rs.write_text(good + "pub const DIGESTS: &[u8] = include_bytes!(\"%s\");\n" % literal,
                                    encoding="utf-8")
            self.refuses("%s embeds %s" % (re.escape(gate.OBSERVER_CONTRACTS), re.escape(rel)))
            contracts_rs.write_text(good, encoding="utf-8")
            for source, text in (("crates/observer/src/i01_digest.rs",
                                  "const RAW: &str = include_str!( \"%s\" );\n" % literal),
                                 ("crates/effect-gate/src/lib.rs", "const RAW: &[u8] = include_bytes!(\"%s\");\n" % literal),
                                 ("crates/observer/src/nested/deeper.rs",
                                  "const RAW: &[u8] = include_bytes!(\"../%s\");\n" % literal)):
                self.refused(gate.check_i01b_contracts, source, text, self.RULE)
            with mock.patch.object(gate, "OBSERVER_EMBEDDED_CONTRACTS", gate.OBSERVER_EMBEDDED_CONTRACTS + (rel,)):
                self.refuses("%s is embedded" % re.escape(rel))
        self.assertEqual(gate.check_i01b_contracts(self.base), 11)

    def test_the_provenance_line_is_required(self):
        path = self.base / "contracts/PROVENANCE.md"
        good = path.read_text(encoding="utf-8")
        for rel, (_, provider, digest) in list(gate.I01B_EDGE_V10_ROWS.items()) + list(gate.I01B_EDGE_V11_ROWS.items()):
            lines = [line for line in good.splitlines() if line.startswith("- `%s` from " % rel)]
            self.assertEqual(len(lines), 1, rel)
            line = lines[0]
            for text in (good.replace(line + "\n", ""), good.replace(line, line.replace(digest, "0" * 64)),
                         good.replace(line, line.replace(provider, provider + ".old")),
                         good.replace(line, line.replace(" bytes", "0 bytes")),
                         good.replace(line, line.replace("`%s`" % rel, "`%s.json`" % rel)),
                         good + line + "\n"):
                path.write_text(text, encoding="utf-8")
                self.refuses("%s has not exactly one PROVENANCE.md line" % re.escape(rel))
            path.write_text(good, encoding="utf-8")
        path.unlink()
        self.refuses("contracts/PROVENANCE.md is missing or a symlink")
        path.write_text(good, encoding="utf-8")
        self.assertEqual(gate.check_i01b_contracts(self.base), 11)

    def test_a_digest_other_than_the_row_refuses(self):
        for record, rows in (("v10", gate.I01B_EDGE_V10_ROWS), ("v11", gate.I01B_EDGE_V11_ROWS)):
            for rel, (row, _, _) in rows.items():
                message = "%s is not registered at edge record %s's row %d sha256" % (re.escape(rel), record, row)
                with mock.patch.dict(gate.CONTRACTS, {rel: "0" * 64}):
                    self.refuses(message)
                with mock.patch.dict(gate.CONTRACTS):
                    del gate.CONTRACTS[rel]
                    self.refuses(message)
        self.assertEqual(gate.check_i01b_contracts(self.base), 11)


# --- HE-004-I01B4 (DESIGN-I01B4 rev 2 section 5; the section review's I4D-1 and I4D-2) ------------------------------------

I01B4_READER = gate.I01B4_ROW79_READER
I01B4_LITERAL = "../../../contracts/i01-v2/proxy-profile-v2-vectors.json"
I01B4_INCLUDE = 'const PROXY_VECTORS: &[u8] = include_bytes!("%s");\n' % I01B4_LITERAL
I01B4_SCOPE_TREE = {
    # The digest replay, row 79's one reader; the file name in a comment is not read.
    I01B4_READER: ("//! The digest replay (proxy-profile-v2-vectors.json in a comment passes).\n" + I01B4_INCLUDE
                   + "#[test]\nfn row_79s_positive_is_the_complete_positives_profile_but_ten_members() {}\n"),
    "crates/observer/src/lib.rs": "pub mod i01_digest;\n",
    "crates/observer/src/i01_digest.rs":
        'pub const SCHEMA_VERSION: &str = "planeon.internal.policy-observation-digests/v2";\n',
    # Names that exist at a5d07979 and pass: the word precondition inside a longer name, in a const and in a test fn.
    "crates/effect-gate/src/gate.rs": ("pub const LOOP_MODEL_PRECONDITION: u8 = 30;\n// proxy-profile-v2-vectors.json\n"
                                       "#[cfg(test)]\nmod tests {\n    #[test]\n"
                                       "    fn events_outside_the_preconditions_change_nothing() {}\n}\n"),
    # A native-profile v2 reader: clause (c2)'s exemption, and no proxyprofilev2 for clause (c1).
    "crates/observer/tests/observer_native_profile_v2.rs":
        'const NATIVE_PROFILE_V2: &str = "contracts/native-profile-v2/vectors.json";\n',
}


class I01b4ReplayScopeTests(Tree):
    """HE-004-I01B4 G-I01B4-1, the absence clause (DESIGN-I01B4 rev 2 section 5; Q-I01B4-5; I4D-1, I4D-2), over a tree
    holding row 79's file, the digest replay's one include and names that exist at a5d07979: the tree and the real
    host-enforcement pass. Each of these refuses:
    - (a) CONTRACTS registering a profile.schema.json, or any path at profile v2's schema sha256; a file of that name
      under contracts/; a file under contracts/ with the schema's bytes (the constant patched to the planted file's
      digest, since R10 holds no copy of the schema);
    - (b) row 79's file included by an observer src file or by another test; the digest replay's include removed or
      doubled, or the file read at run time there; a concat! form in another test;
    - (c) fn validate_profile, fn precondition and mod proxy_profile_v2, each planted in a src and a tests file;
    - a const fn read as the fn it qualifies (PR review round 1, R1-1): const fn validate_profile, pub const fn
      precondition and pub const unsafe fn validate_profile (clause (c)), and const fn preconditions (clause (c1));
    - I4D-1's five forms: (1) a test crate root named after profile v2 (tests/profile_v2_check.rs, and a directory so
      named); (2) fn preconditions; (3) fn r#precondition; (4) struct ProxyProfileV2 with an impl; (5) macro_rules!
      validate_profile;
    - (c3) one of row 79's negative texts, or the schema's sha256, in another source; the digest replay may hold
      them."""

    RULE = "G-I01B4-1"
    TREE = I01B4_SCOPE_TREE

    def setUp(self):
        super().setUp()
        path = self.base / gate.I01B4_ROW79
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((gate.HE / gate.I01B4_ROW79).read_bytes())

    def refuses(self, rel, text, message):
        self.refused(gate.check_i01b4_replay_scope, rel, text, "%s.*%s" % (message, self.RULE))

    def declares(self, rel, text, item, clause):
        self.refused(gate.check_i01b4_replay_scope, rel, text,
                     re.escape("%s declares %s, a profile v2 validator's name (the replay scope, G-I01B4-1, clause %s)"
                               % (rel, item, clause)))

    def test_the_tree_and_the_real_files_pass(self):
        self.assertEqual(gate.check_i01b4_replay_scope(self.base), 5)
        crates = gate.HE / "crates"
        sources = len(list(crates.glob("*/src/**/*.rs"))) + len(list(crates.glob("*/tests/**/*.rs")))
        self.assertEqual(gate.check_i01b4_replay_scope(gate.HE), sources)
        vectors = json.loads((gate.HE / gate.I01B4_ROW79).read_text(encoding="utf-8"))
        self.assertEqual(len({row["expect"] for row in vectors["negative"]}), gate.I01B4_ROW79_TEXTS)
        self.assertEqual(gate.I01B4_ROW79_TEXTS, 28)

    def test_profile_v2_s_schema_refuses_by_name_or_bytes(self):
        for rel in ("contracts/i01-v2/profile.schema.json", "contracts/proxy-profile-v2/Profile.Schema.JSON"):
            with mock.patch.dict(gate.CONTRACTS, {rel: "0" * 64}):
                with self.assertRaisesRegex(gate.GateError, "CONTRACTS registers %s, profile v2's schema by name .*%s"
                                            % (re.escape(rel), self.RULE)):
                    gate.check_i01b4_replay_scope(self.base)
        with mock.patch.dict(gate.CONTRACTS, {"contracts/i01-v2/schema.json": gate.PROFILE_V2_SCHEMA_SHA256}):
            with self.assertRaisesRegex(gate.GateError, "CONTRACTS registers contracts/i01-v2/schema.json at profile v2's "
                                        "schema sha256 .*%s" % self.RULE):
                gate.check_i01b4_replay_scope(self.base)
        for rel in ("contracts/i01-v2/profile.schema.json", "contracts/other/profile.schema.json"):
            self.refuses(rel, "{}", "%s is profile v2's schema by name" % re.escape(rel))
        # By bytes: R10 holds no copy of the schema, so the constant is patched to the planted file's digest.
        text = '{"title": "a schema under another name"}\n'
        with mock.patch.object(gate, "PROFILE_V2_SCHEMA_SHA256", hashlib.sha256(text.encode()).hexdigest()):
            self.refuses("contracts/i01-v2/renamed.json", text, "contracts/i01-v2/renamed.json holds profile v2's schema bytes")
        self.assertEqual(gate.check_i01b4_replay_scope(self.base), 5)

    def test_row_79_s_file_has_one_reader(self):
        include = 'const RAW: &[u8] = include_bytes!("%s");\n' % I01B4_LITERAL
        for rel in ("crates/observer/src/i01_digest.rs", "crates/observer/tests/observer_i01_pv_replay.rs",
                    "crates/observer/tests/nested/deeper.rs"):
            text = include.replace("../../../", "../../../../") if "nested" in rel else include
            self.refuses(rel, text, "%s includes %s, which only" % (re.escape(rel), re.escape(gate.I01B4_ROW79)))
        # The digest replay's include removed, doubled, or the file read at run time beside it.
        once = re.escape("%s does not include %s exactly once" % (I01B4_READER, gate.I01B4_ROW79))
        self.refuses(I01B4_READER, "fn other() {}\n", once)
        self.refuses(I01B4_READER, I01B4_INCLUDE + I01B4_INCLUDE.replace("PROXY_VECTORS", "AGAIN"), once)
        self.refuses(I01B4_READER, I01B4_INCLUDE + 'fn read() { let _ = std::fs::read("%s"); }\n' % I01B4_LITERAL,
                     "names proxy-profile-v2-vectors.json other than in its include literal")
        # A concat! form, or the name in any literal, in another test.
        self.refuses("crates/observer/tests/observer_other.rs",
                     'const RAW: &[u8] = include_bytes!(concat!("../../../contracts/i01-v2/", '
                     '"proxy-profile-v2-vectors.json"));\n',
                     "crates/observer/tests/observer_other.rs names proxy-profile-v2-vectors.json")
        self.assertEqual(gate.check_i01b4_replay_scope(self.base), 5)

    def test_a_profile_v2_validator_s_name_refuses(self):
        # Clause (c), each in a src and a tests file.
        for item, text in (("fn validate_profile", "pub fn validate_profile() {}\n"),
                           ("fn precondition", "fn precondition() {}\n"),
                           ("mod proxy_profile_v2", "mod proxy_profile_v2 {}\n")):
            for rel in ("crates/observer/src/planted.rs", "crates/effect-gate/tests/planted.rs"):
                self.declares(rel, text, item, "(c)")
        # I4D-1's forms (2)-(5): clause (c1) (form (3)'s r# stripped meets clause (c) first).
        rel = "crates/observer/tests/planted.rs"
        self.declares(rel, "fn preconditions() {}\n", "fn preconditions", "(c1)")
        self.declares(rel, "fn r#precondition() {}\n", "fn precondition", "(c)")
        self.declares(rel, "pub struct ProxyProfileV2;\nimpl ProxyProfileV2 {\n    pub fn validate(&self) {}\n}\n",
                      "struct ProxyProfileV2", "(c1)")
        self.declares(rel, "macro_rules! validate_profile {\n    () => {};\n}\n", "macro_rules validate_profile", "(c1)")
        self.declares("crates/observer/src/planted.rs", "pub enum PRE_CONDITIONS { A }\n", "enum PRE_CONDITIONS", "(c1)")
        # I4D-1's form (1): a test crate root named after profile v2 needs no mod line; clause (c2) reads its path.
        validate = "use i05_protocol::json::Value;\n\nfn validate(profile: &Value) -> Vec<String> {\n    Vec::new()\n}\n"
        for rel in ("crates/observer/tests/profile_v2_check.rs", "crates/observer/tests/proxy-profile-v2/main.rs",
                    "crates/observer/src/ProfileV2.rs"):
            self.refused(gate.check_i01b4_replay_scope, rel, validate,
                         re.escape("%s is named after profile v2 (the replay scope, G-I01B4-1, clause (c2))" % rel))
        self.assertEqual(gate.check_i01b4_replay_scope(self.base), 5)

    def test_a_const_fn_is_read_as_the_fn_it_qualifies(self):
        # PR review round 1, R1-1: `const` before `fn`, `unsafe`, `extern` or `async` is a qualifier, not the item.
        for rel in ("crates/observer/src/planted.rs", "crates/effect-gate/tests/planted.rs"):
            self.declares(rel, "const fn validate_profile() -> bool {\n    true\n}\n", "fn validate_profile", "(c)")
            self.declares(rel, "pub const fn precondition() -> bool {\n    true\n}\n", "fn precondition", "(c)")
            self.declares(rel, "pub const unsafe fn validate_profile() -> bool {\n    true\n}\n", "fn validate_profile",
                          "(c)")
            self.declares(rel, "const fn preconditions() -> bool {\n    true\n}\n", "fn preconditions", "(c1)")
        # A const item is still read as a const.
        self.declares("crates/observer/src/planted.rs", "pub const PRECONDITION: bool = true;\n", "const PRECONDITION",
                      "(c1)")
        self.assertEqual(gate.check_i01b4_replay_scope(self.base), 5)

    def test_row_79_s_texts_or_the_schema_digest_elsewhere_refuse(self):
        vectors = json.loads((gate.HE / gate.I01B4_ROW79).read_text(encoding="utf-8"))
        texts = sorted({row["expect"] for row in vectors["negative"]})
        for text in (texts[0], texts[5], texts[-1]):
            for rel in ("crates/observer/tests/observer_i01_pv_replay.rs", "crates/observer/src/i01_digest.rs"):
                self.refuses(rel, "const TEXT: &str = %s;\n" % json.dumps(text),
                             re.escape("%s holds row 79's negative text %r" % (rel, text)))
        self.refuses("crates/observer/src/i01_digest.rs", 'const SCHEMA: &str = "%s";\n' % gate.PROFILE_V2_SCHEMA_SHA256,
                     "crates/observer/src/i01_digest.rs holds profile v2's schema sha256")
        # The digest replay may hold them.
        self.write(I01B4_READER, I01B4_SCOPE_TREE[I01B4_READER] + "const TEXT: &str = %s;\nconst SCHEMA: &str = \"%s\";\n"
                   % (json.dumps(texts[0]), gate.PROFILE_V2_SCHEMA_SHA256))
        self.assertEqual(gate.check_i01b4_replay_scope(self.base), 5)


I01B1_LIB = ("#![forbid(unsafe_code)]\n// i01_digest and i01_gate in a comment\npub mod capture;\npub mod i01_admission_render;\n"
             "pub mod i01_answer;\npub mod i01_digest;\npub mod i01_gate;\npub mod observe;\n")
# HE-004-I01B3 (DESIGN-I01B3 rev 4 section 6): G-I01B-1's I01B3 form adds the fourth unreachable module, its type set
# (Derived, CaptureFacts, ChainMode), named in no I01B1 file; it names the I01B1 types, which is allowed.
I01B3_ANSWER = ("//! An i01_answer fixture (`impl DigestKey {`, i01_digest and DigestKey in a comment pass).\n"
                "use crate::i01_digest::DigestKey;\n\n#[derive(Debug)]\npub struct Derived {\n    key: DigestKey,\n}\n\n"
                "impl Derived {\n    pub fn key(&self) -> DigestKey {\n        self.key\n    }\n}\n\n"
                "pub struct CaptureFacts {\n    pub completed: bool,\n}\n\nenum ChainMode {\n    Skip,\n}\n\n"
                "pub fn derive(key: DigestKey) -> Option<Derived> {\n    Some(Derived { key })\n}\n")
I01B1_DIGEST = ("//! An i01_digest fixture (`impl Other for DigestKey` and LatestSet in a comment pass).\n"
                "pub enum DigestKey {\n    Rbac,\n}\n\nimpl DigestKey {\n    pub fn name(self) -> &'static str {\n"
                "        \"rbac\"\n    }\n}\n\npub struct SealedAdmission {\n    pub namespace: String,\n}\n\n"
                "pub struct Rendered;\n\n#[cfg(test)]\nmod tests {\n    struct Local;\n}\n")
I01B1_ISOLATION_TREE = {
    gate.OBSERVER_LIB: I01B1_LIB,
    "crates/observer/src/i01_digest.rs": I01B1_DIGEST,
    "crates/observer/src/i01_admission_render.rs": "use crate::i01_digest::{Rendered, SealedAdmission};\n"
                                                   "pub fn render(_sealed: &SealedAdmission) -> Option<Rendered> {\n"
                                                   "    None\n}\n",
    "crates/observer/src/i01_gate.rs": "use crate::i01_digest::DigestKey;\npub struct LatestSet {\n    pub mono_age_ms: u64,\n}\n"
                                       "pub fn capture_gate(key: DigestKey) -> &'static str {\n    key.name()\n}\n",
    gate.I01_ANSWER: I01B3_ANSWER,
    # HE-004-I01B5 (G-I01B-1's I01B5 form, DESIGN-I01B5 rev 5 section 6.1): i01_answer's five listed places, each once.
    "crates/observer/src/observe.rs": "//! i01_digest, DigestKey and LatestSet in a comment.\n"
                                      "pub fn run() -> &'static str { \"i01_gate Rendered\" }\n"
                                      "pub fn view(k: u8) -> u8 {\n    let _ = crate::i01_answer::derive(k);\n    0\n}\n",
    gate.OBSERVER_CLIENT: "pub struct SnapshotView {\n    pub derived: Option<crate::i01_answer::Derived>,\n}\n",
    gate.OBSERVER_SERVICE: "pub fn respond() {\n    let facts = crate::i01_answer::CaptureFacts { completed: true };\n"
                           "    let _ = crate::i01_answer::answer(&facts);\n"
                           "    let _ = crate::i01_answer::self_check(&facts);\n}\n",
    CAPTURE_RS: CAPTURE_TEXT,
    gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN,
}


# HE-004-I01B3 G-I01B-1 (e), the direction clause (DESIGN-I01B3 rev 4 sections 6 and 8; I3D-4, I3E-4, I3F-7): the three
# union-only rows, each refused by (e) alone among G-I01B-1's own functions (module_isolation's (a)-(d), and (e)); the
# build's mutation proof reads this table. Each row: (label, sub-clause, ((file, anchor, replacement), ..)).
I01B3_DIGEST_ANCHOR = "pub struct Rendered;\n"
I01B3_GATE_ANCHOR = "pub fn capture_gate(key: DigestKey) -> &'static str {\n"
I01B3_ANSWER_ANCHOR = "pub fn derive(key: DigestKey) -> Option<Derived> {\n"
I01B3_DIRECTION_ROWS = (
    ("e-1 a re-export of i01_answer in an I01B1 file", "(e)",
     (("crates/observer/src/i01_digest.rs", I01B3_DIGEST_ANCHOR,
       I01B3_DIGEST_ANCHOR + "pub use crate::i01_answer::derive;\n"),)),
    ("e-2 Derived named in an I01B1 file", "(e)",
     (("crates/observer/src/i01_gate.rs", I01B3_GATE_ANCHOR,
       "pub fn peek(derived: &crate::i01_answer::Derived) -> u8 {\n    0\n}\n" + I01B3_GATE_ANCHOR),)),
    ("e-3 an impl on an I01B1 type inside i01_answer.rs", "(e)",
     ((gate.I01_ANSWER, I01B3_ANSWER_ANCHOR,
       "impl DigestKey {\n    pub fn answer_all(self) -> u8 {\n        0\n    }\n}\n\n" + I01B3_ANSWER_ANCHOR),)),
)
# G-I01B-1's own sub-clause functions, by the label the proof disables them under.
I01B3_DIRECTION_FUNCTIONS = {"(a)-(d)": "module_isolation", "(e)": "i01b_direction"}
# HE-004-I01B5 G-I01B-1's I01B5 form (DESIGN-I01B5 rev 5 sections 6.1 and 8; B3-5): N2-9's forms, a second self_check(
# call and a listed place missing, each refused at (a)-(d) (module_isolation with its listed places); the build's
# mutation proof reads this table. Each row: (label, sub-clause, stated set, ((file, anchor, replacement), ..)).
I01B5_ISOLATION_ROWS = (
    ("N2-9 a second crate::i01_answer::derive( in observe.rs", "(a)-(d)", None,
     (("crates/observer/src/observe.rs", "    0\n}\n", "    let _ = crate::i01_answer::derive(k);\n    0\n}\n"),)),
    ("N2-9 use crate::i01_answer::Derived; in client.rs", "(a)-(d)", None,
     ((gate.OBSERVER_CLIENT, "pub struct SnapshotView {\n", "use crate::i01_answer::Derived;\npub struct SnapshotView {\n"),)),
    ("N2-9 pub use crate::i01_answer::Derived; in lib.rs", "(a)-(d)", None,
     ((gate.OBSERVER_LIB, "pub mod observe;\n", "pub mod observe;\npub use crate::i01_answer::Derived;\n"),)),
    ("a second self_check( call in i01_service.rs", "(a)-(d)", None,
     ((gate.OBSERVER_SERVICE, "    let _ = crate::i01_answer::self_check(&facts);\n",
       "    let _ = crate::i01_answer::self_check(&facts);\n    let _ = crate::i01_answer::self_check(&facts);\n"),)),
    ("a listed place missing (self_check( spelled as answer()", "(a)-(d)", None,
     ((gate.OBSERVER_SERVICE, "crate::i01_answer::self_check(", "crate::i01_answer::answer("),)),
)


def i01b3_isolation_tree(changes=()):
    """I01B1_ISOLATION_TREE (with i01_answer.rs) with each (file, anchor, replacement) applied once."""
    texts = dict(I01B1_ISOLATION_TREE)
    for rel, old, new in changes:
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


class I01b1IsolationTests(Tree):
    """HE-004-I01B1 G-I01B-1 (DESIGN-I01B1 rev 2 section 4, I1D-5), in D2IsolationTests' style, in its I01B3 form from
    HE-004-I01B3 (DESIGN-I01B3 rev 4 section 6; I3D-4, I3E-4), each I01B1 case kept: (a) a module name outside its file
    (a `crate::i01_digest::` call in observe.rs, `use planeon_observer::i01_gate;` in main.rs, `pub use i01_digest::x;`
    in lib.rs) refuses, and so does a pub mod line removed, doubled or written `pub(crate) mod`; (b) a type of the union
    set named in another observer source refuses; (c) an impl header other than `impl <a type of the set> {` refuses (a
    trait impl, a generic impl, an impl inside a fn); (d) a `pub use` or `pub(crate) use` of another module's item in one
    of the four refuses. The I01B3 rows: DIB section 7.6's N2-9 forms, round 3's X1-1 and X1-2, and a planted
    `use crate::i01_answer::Derived;` and `crate::i01_answer::derive(` in observe.rs, each refused at (a); and (e)'s
    three union-only rows, each refused by (e) alone. The fixture and the real sources pass. G-D2-5's own cases are
    unchanged (D2IsolationTests): the construction is shared (module_isolation)."""

    TREE = I01B1_ISOLATION_TREE
    RULE = "G-I01B-1"

    def test_the_tree_and_the_real_sources_pass(self):
        self.assertEqual(gate.I01B1_MODULES, ("i01_digest", "i01_admission_render", "i01_gate"))
        self.assertEqual(gate.I01B3_MODULES, ("i01_digest", "i01_admission_render", "i01_gate", "i01_answer"))
        # The fixture's seven type names (the I01B1 files' four, i01_answer's three).
        self.assertEqual(gate.check_i01b_isolation(self.base), 7)
        self.assertEqual(gate.i01b_direction(self.base, self.RULE), 3)
        # The real sources: the eleven type names i01_digest and i01_gate define and i01_answer's three, each named only
        # in the four files.
        self.assertEqual(gate.check_i01b_isolation(gate.HE), 14)

    def test_a_module_name_outside_its_file_refuses(self):
        for rel, extra in (("crates/observer/src/observe.rs", "pub fn f() -> u8 { crate::i01_digest::f() }\n"),
                           (gate.OBSERVER_MAIN, "use planeon_observer::i01_gate;\n"),
                           (gate.OBSERVER_LIB, "pub use i01_digest::x;\n"),
                           (CAPTURE_RS, "use crate::i01_admission_render as r;\n")):
            self.refused(gate.check_i01b_isolation, rel, self.TREE[rel] + extra, "names the I01B3 module .*" + self.RULE)
        lib = self.TREE[gate.OBSERVER_LIB]
        for name in ("i01_digest", "i01_answer"):
            for text in (lib.replace("pub mod %s;\n" % name, ""), lib + "pub mod %s;\n" % name,
                         lib.replace("pub mod %s;\n" % name, "pub(crate) mod %s;\n" % name)):
                self.refused(gate.check_i01b_isolation, gate.OBSERVER_LIB, text, "does not declare `pub mod %s;`" % name)

    def test_the_answer_module_is_named_nowhere_else(self):
        # DIB section 7.6's N2-9 (in I01B3 no other source may name i01_answer), round 3's X1-1 and X1-2, and the section's
        # planted forms in observe.rs: each refused at (a).
        observe, service = "crates/observer/src/observe.rs", "crates/observer/src/i01_service.rs"
        for rel, extra in ((observe, "pub fn f() { let _ = crate::i01_answer::derive(k); }\n"),
                           (observe, "pub fn f() { let _ = crate::i01_answer::answer(d, c, f, 0, None); }\n"),
                           (observe, "use crate::i01_answer::Derived;\n"),
                           (gate.OBSERVER_MAIN, "use planeon_observer::i01_answer::Derived;\n"),
                           (gate.OBSERVER_LIB, "pub use crate::i01_answer::Derived;\n"),
                           (observe, "pub fn f() { let mint = crate::i01_answer::derive;\n    let _ = mint(k); }\n"),
                           (service, "pub fn g() { let _ = crate::i01_answer::capture_gate(k); }\n")):
            self.refused(gate.check_i01b_isolation, rel, self.TREE.get(rel, "") + extra,
                         "%s names the I01B3 module i01_answer .*%s" % (re.escape(rel), self.RULE))
        # X1-2's other half, the re-export inside i01_answer.rs, passes (d): it names one of the four modules' paths.
        self.write(gate.I01_ANSWER, I01B3_ANSWER + "pub use crate::i01_gate::capture_gate;\n")
        self.assertEqual(gate.check_i01b_isolation(self.base), 7)

    def test_a_type_of_the_set_elsewhere_refuses(self):
        for rel, extra in ((gate.OBSERVER_MAIN, "fn f(key: DigestKey) {}\n"),
                           (CAPTURE_RS, "pub fn f() -> LatestSet { x() }\n"),
                           ("crates/observer/src/observe.rs", "type R = Rendered;\n"),
                           ("crates/observer/src/observe.rs", "pub struct SealedAdmission;\n"),
                           ("crates/observer/src/observe.rs", "pub fn f(facts: CaptureFacts) {}\n"),
                           (CAPTURE_RS, "fn f() -> ChainMode { x() }\n")):
            self.refused(gate.check_i01b_isolation, rel, self.TREE[rel] + extra, "a type the I01B3 module .*" + self.RULE)
        # Two of the four defining one name refuse.
        self.refused(gate.check_i01b_isolation, "crates/observer/src/i01_gate.rs",
                     self.TREE["crates/observer/src/i01_gate.rs"] + "pub struct Rendered;\n", "defines Rendered, which")
        self.refused(gate.check_i01b_isolation, gate.I01_ANSWER, I01B3_ANSWER + "pub struct LatestSet;\n",
                     "defines LatestSet, which")

    def test_impl_headers_and_re_exports_refuse(self):
        rel = "crates/observer/src/i01_digest.rs"
        for extra in ("impl std::fmt::Display for DigestKey {}\n", "impl Clone for Rendered {}\n", "impl<T> DigestKey {}\n",
                      "pub fn f() { impl Refusal {} }\n", "impl CaptureEngine {}\n"):
            self.refused(gate.check_i01b_isolation, rel, I01B1_DIGEST + extra, "impl header .*" + self.RULE)
        gate_rs = "crates/observer/src/i01_gate.rs"
        for extra, message in (("pub use crate::capture::KernelView;\n", "re-exports crate::capture::KernelView"),
                               ("pub(crate) use crate::observe::run;\n", "re-exports crate::observe::run")):
            self.refused(gate.check_i01b_isolation, gate_rs, self.TREE[gate_rs] + extra, message + ".*" + self.RULE)
        # A re-export of the set's own item passes.
        self.write(gate_rs, self.TREE[gate_rs] + "pub use crate::i01_digest::Rendered;\n")
        self.assertEqual(gate.check_i01b_isolation(self.base), 7)

    def test_the_direction_clause_refuses_the_three_union_only_rows(self):
        # (e) [I3D-4, I3E-4]: each row passes module_isolation's union (a)-(d) and is refused by (e) alone.
        for label, clause, changes in I01B3_DIRECTION_ROWS:
            self.assertEqual(clause, "(e)")
            for rel, text in i01b3_isolation_tree(changes).items():
                self.write(rel, text)
            self.assertEqual(gate.module_isolation(self.base, gate.I01B3_MODULES, gate.I01B3_MODULES, "I01B3", self.RULE,
                                                   gate.I01B5_ANSWER_PLACES), 7, label)
            with self.assertRaisesRegex(gate.GateError, re.escape("(I01B5 isolation, G-I01B-1 (e))")):
                gate.check_i01b_isolation(self.base)
            for rel, text in i01b3_isolation_tree().items():
                self.write(rel, text)
        # (e) refuses nothing legitimate: i01_answer naming the I01B1 types passes.
        self.assertEqual(gate.check_i01b_isolation(self.base), 7)

    def test_the_i01b5_form_allows_the_five_listed_places_once_each(self):
        # HE-004-I01B5 (DESIGN-I01B5 rev 5 sections 6.1 and 8; B3-5): the five places, each written crate::i01_answer::…
        # and each once; the compiled spelling (the real sources) passes. N2-9's forms, a use or pub use declaration, a
        # second self_check( call, another spelling or a place missing refuses; without the listed places the I01B3 form
        # refuses the fixture.
        observe, service = "crates/observer/src/observe.rs", gate.OBSERVER_SERVICE
        self.assertEqual(sorted(gate.I01B5_ANSWER_PLACES), sorted([observe, gate.OBSERVER_CLIENT, service]))
        self.assertEqual(sum(len(places) for places in gate.I01B5_ANSWER_PLACES.values()), 5)
        self.assertEqual(gate.check_i01b_isolation(gate.HE), 14)
        good = self.TREE[service]
        for rel, text in ((service, good.replace("}\n", "    let _ = crate::i01_answer::self_check(&facts);\n}\n")),
                          (service, good + "use crate::i01_answer::self_check;\n"),
                          (gate.OBSERVER_CLIENT, "pub use crate::i01_answer::Derived;\n" + self.TREE[gate.OBSERVER_CLIENT]),
                          (observe, self.TREE[observe] + "pub fn g(k: u8) { let _ = crate::i01_answer::derive(k); }\n")):
            self.refused(gate.check_i01b_isolation, rel, text, "names the I01B3 module i01_answer .*" + self.RULE)
        for rel, old, new in ((service, "crate::i01_answer::self_check(", "crate::i01_answer::answer("),
                              (service, "crate::i01_answer::answer(", "i01_answer::answer("),
                              (gate.OBSERVER_CLIENT, "crate::i01_answer::Derived", "u8"),
                              (observe, "crate::i01_answer::derive(k)", "k")):
            self.refused(gate.check_i01b_isolation, rel, self.TREE[rel].replace(old, new),
                         "does not name the I01B3 module at its listed place .*" + self.RULE)
        with self.assertRaisesRegex(gate.GateError, "names the I01B3 module i01_answer"):
            gate.module_isolation(self.base, gate.I01B3_MODULES, gate.I01B3_MODULES, "I01B3", self.RULE)
        for label, clause, _, changes in I01B5_ISOLATION_ROWS:
            self.assertEqual(clause, "(a)-(d)")
            for rel, text in i01b3_isolation_tree(changes).items():
                self.write(rel, text)
            with self.assertRaisesRegex(gate.GateError, re.escape("(I01B5 isolation, G-I01B-1)"), msg=label):
                gate.check_i01b_isolation(self.base)
            for rel, text in i01b3_isolation_tree().items():
                self.write(rel, text)

    def test_the_present_modules_are_the_four(self):
        for rel in ("crates/observer/src/i01_gate.rs", "crates/observer/src/i01_admission_render.rs", gate.I01_ANSWER):
            (self.base / rel).unlink()
            with self.assertRaisesRegex(gate.GateError, "the I01B3 modules present .* not exactly those"):
                gate.check_i01b_isolation(self.base)
            self.write(rel, self.TREE[rel])
        self.assertEqual(gate.check_i01b_isolation(self.base), 7)


# HE-004-I01B1's I01b1SymbolTests (G-I01B-1's symbol-table corroboration) retired with check_i01b1_absent in
# HE-004-I01B5 (Q-I01B3-8 (a); DESIGN-I01B5 rev 5 sections 6.1 and 8); G-D2-7's self-tests stay.


I01_SOURCE_LIB = "#![forbid(unsafe_code)]\n" + "".join(
    ('#[cfg(target_os = "linux")]\npub mod %s;\n' if name.startswith("linux_") else "pub mod %s;\n") % name
    for name in gate.OBSERVER_LIB_MODULES)
I01_SOURCE_TREE = {
    gate.OBSERVER_LIB: I01_SOURCE_LIB,
    **{rel: "pub fn f() -> u8 { 0 }\n" for rel in gate.I01_FILES},
    gate.OBSERVER_CLIENT: "pub fn c() {}\n",
    "crates/observer/src/observe.rs": "pub fn run() {}\n\n#[cfg(test)]\nmod tests {\n    mod inner {}\n}\n",
}


class I01SourceRuleTests(Tree):
    """HE-004-I01B1 G-I01B-7 (DESIGN-I01B rev 3 section 7.5, the I01B1 set): P7-1 an extra i01_ source, P7-2 an extra
    pub mod line, P7-3 a module not named i01_*, P7-4 a module declared in client.rs or under src/client/, each refuse;
    a guarded module declared inline in lib.rs refuses (file form), and so does an I01B1 module off the logic or
    no-panic list; P7-5's I01B1 half, the five i01_ sources, passes, and so do the real sources."""

    TREE = I01_SOURCE_TREE
    RULE = "G-I01B-7"

    def test_p7_5_the_five_and_the_real_sources_pass(self):
        # HE-004-I01B3 (DESIGN-I01B3 rev 4 section 6; DIB section 7.5's P7-5): I01B1's five, then I01B3's six.
        self.assertEqual(len(gate.OBSERVER_LIB_MODULES), 39)
        self.assertEqual(len(gate.I01_FILES_BUILT), 6)
        self.assertEqual(gate.check_i01b_sources(self.base), 6)
        self.assertEqual(gate.check_i01b_sources(gate.HE), 6)
        lib = self.TREE[gate.OBSERVER_LIB]
        (self.base / gate.I01_ANSWER).unlink()
        self.write(gate.OBSERVER_LIB, lib.replace("pub mod i01_answer;\n", ""))
        with mock.patch.object(gate, "I01_FILES_BUILT", gate.I01_FILES[:5]), \
                mock.patch.object(gate, "OBSERVER_LIB_MODULES", gate.OBSERVER_LIB_MODULES[:-1]):
            self.assertEqual(gate.check_i01b_sources(self.base), 5)
        # The I01B1 set over the I01B3 tree, or the I01B3 set without i01_answer.rs, refuses.
        with self.assertRaisesRegex(gate.GateError, "the i01_ sources present .* are not exactly .*" + self.RULE):
            gate.check_i01b_sources(self.base)
        self.write(gate.I01_ANSWER, self.TREE[gate.I01_ANSWER])
        self.write(gate.OBSERVER_LIB, lib)
        self.assertEqual(gate.check_i01b_sources(self.base), 6)

    def test_p7_1_to_p7_4_refuse(self):
        lib = self.TREE[gate.OBSERVER_LIB]
        self.refused(gate.check_i01b_sources, "crates/observer/src/i01_extra.rs", "pub fn f() {}\n",
                     "the i01_ sources present .* are not exactly .*" + self.RULE)
        self.refused(gate.check_i01b_sources, gate.OBSERVER_LIB, lib + "pub mod i01_extra;\n",
                     "lib.rs declares the modules .*, not exactly OBSERVER_LIB_MODULES")
        self.write("crates/observer/src/answer.rs", "pub fn answer() {}\n")
        self.refused(gate.check_i01b_sources, gate.OBSERVER_LIB, lib + "pub mod answer;\n",
                     "lib.rs declares the modules .*, not exactly OBSERVER_LIB_MODULES")
        (self.base / "crates/observer/src/answer.rs").unlink()
        self.refused(gate.check_i01b_sources, gate.OBSERVER_CLIENT, self.TREE[gate.OBSERVER_CLIENT] + "mod i01_x;\n",
                     "client.rs declares a module; only lib.rs does .*" + self.RULE)
        self.refused(gate.check_i01b_sources, "crates/observer/src/client/i01_x.rs", "pub fn x() {}\n",
                     "the i01_ sources present .* are not exactly")
        self.assertEqual(gate.check_i01b_sources(self.base), 6)

    def test_file_form_and_the_lists(self):
        lib = self.TREE[gate.OBSERVER_LIB]
        for text in (lib.replace("pub mod config;\n", "pub mod config { }\n"), lib.replace("pub mod client;\n", ""),
                     lib + "pub mod client;\n"):
            self.refused(gate.check_i01b_sources, gate.OBSERVER_LIB, text, "not exactly OBSERVER_LIB_MODULES")
        self.refused(gate.check_i01b_sources, "crates/observer/src/observe.rs", "pub mod nested {}\n",
                     "observe.rs declares a module")
        for listed in ("I01_LOGIC_BUILT", "I01_NO_PANIC_BUILT"):
            with mock.patch.object(gate, listed, tuple(name for name in getattr(gate, listed) if name != "i01_gate")):
                with self.assertRaisesRegex(gate.GateError, "i01_gate miss the logic or the no-panic rule"):
                    gate.check_i01b_sources(self.base)
            # HE-004-I01B3 (G-I01B-7 (d)): i01_answer off either list refuses too.
            with mock.patch.object(gate, listed, tuple(name for name in getattr(gate, listed) if name != "i01_answer")):
                with self.assertRaisesRegex(gate.GateError, "i01_answer miss the logic or the no-panic rule"):
                    gate.check_i01b_sources(self.base)
        self.assertEqual(gate.check_i01b_sources(self.base), 6)


class I01bConstantTests(Tree):
    """HE-004-I01B1 G-I01B-8 (DESIGN-I01B rev 3 section 6, B2-7) over copies of the real i01_gate.rs, observe.rs,
    capture.rs, i01_digest.rs, i01_admission_render.rs and definitions.json: the copies and the real tree pass; one
    refusal per constant (each value changed, each literal pin's citation removed, a second definition) and for the
    contract's bound; an extra key-prefixed text or a changed pinned text refuses."""

    RULE = "G-I01B-8"
    COPIED = (gate.I01_GATE_RS, "crates/observer/src/observe.rs", "crates/observer/src/capture.rs",
              "crates/observer/src/i01_digest.rs", "crates/observer/src/i01_admission_render.rs", gate.I01B_DEFINITIONS)

    def setUp(self):
        super().setUp()
        self.real = {rel: (gate.HE / rel).read_text(encoding="utf-8") for rel in self.COPIED}
        for rel, text in self.real.items():
            self.write(rel, text)

    def changed(self, rel, old, new, message, check=None):
        text = self.real[rel]
        self.assertEqual(text.count(old), 1, old)
        self.write(rel, text.replace(old, new))
        with self.assertRaisesRegex(gate.GateError, message + ".*" + self.RULE):
            (check or gate.check_i01b_constants)(self.base)
        self.write(rel, text)

    def test_the_copies_and_the_real_tree_pass(self):
        self.assertEqual(gate.check_i01b_constants(self.base), 7)
        self.assertEqual(gate.check_i01b_constants(gate.HE), 7)
        self.assertEqual(gate.check_i01b_refusal_texts(self.base), 90)
        self.assertEqual(gate.check_i01b_refusal_texts(gate.HE), 90)

    def test_one_refusal_per_constant(self):
        gate_rs = gate.I01_GATE_RS
        self.changed(gate_rs, "GATE_BOUND_MS: u64 = 90_000;", "GATE_BOUND_MS: u64 = 90_001;", "GATE_BOUND_MS is not")
        self.changed("crates/observer/src/observe.rs", "CYCLE: Duration = Duration::from_secs(60);",
                     "CYCLE: Duration = Duration::from_secs(61);", "CYCLE is not")
        self.changed("crates/observer/src/capture.rs", "SCRAPE_TO_SET: Duration = Duration::from_secs(5);",
                     "SCRAPE_TO_SET: Duration = Duration::from_secs(6);", "SCRAPE_TO_SET is not")
        self.changed("crates/observer/src/capture.rs", "SET_BUDGET: Duration = Duration::from_secs(25);",
                     "SET_BUDGET: Duration = Duration::from_secs(24);", "SET_BUDGET is not")
        for name, old, new in (("ANSWER_LIMIT", "usize = 65_536;", "usize = 65_535;"),
                               ("FRESHNESS_WINDOW_SECONDS", "FRESHNESS_WINDOW_SECONDS: u64 = 5;",
                                "FRESHNESS_WINDOW_SECONDS: u64 = 6;"),
                               ("EXCHANGE_DEADLINE_SECONDS", "EXCHANGE_DEADLINE_SECONDS: u64 = 2;",
                                "EXCHANGE_DEADLINE_SECONDS: u64 = 3;")):
            self.changed(gate_rs, old, new, "does not pin %s" % name)
        for name, citation in (("ANSWER_LIMIT", "validate_policy_observation.py:86-88"),
                               ("FRESHNESS_WINDOW_SECONDS", "validate_policy_observation.py:128"),
                               ("EXCHANGE_DEADLINE_SECONDS", "Q-I01B-21 (a)")):
            self.changed(gate_rs, citation, "a citation elsewhere", "does not pin %s" % name)
        self.changed(gate_rs, "pub const ANSWER_LIMIT: usize = 65_536;",
                     "pub const ANSWER_LIMIT: usize = 65_536;\nconst ANSWER_LIMIT: usize = 1;",
                     "does not define ANSWER_LIMIT exactly once")
        self.changed(gate_rs, "pub const GATE_BOUND_MS: u64 = 90_000;", "pub(crate) const GATE_BOUND_MS: u64 = 90_000;",
                     "does not define GATE_BOUND_MS exactly once")
        self.changed(gate.I01B_DEFINITIONS, '"boundMs": 90000', '"boundMs": 90001', "captureGate.boundMs is not")

    def test_the_texts(self):
        texts = gate.check_i01b_refusal_texts
        self.changed(gate.I01_GATE_RS, "pub const LIFECYCLE_SLOT",
                     "const FORGED: &str = \"rbac: a text the contract does not pin\";\npub const LIFECYCLE_SLOT",
                     "refusal texts are not exactly .*extra", texts)
        self.changed("crates/observer/src/i01_digest.rs", '"admissionPolicy: rendered hash differs"',
                     '"admissionPolicy: rendered hashes differ"', "refusal texts are not exactly .*missing", texts)
        # A pinned text written in a comment only is not written.
        self.changed("crates/observer/src/i01_digest.rs", '"networkEnforcementDigest: no network policy agent"',
                     '"" // "networkEnforcementDigest: no network policy agent"', "missing", texts)


class I01bGuardedPinTests(Tree):
    """HE-004-I01B1 R-B3-PIN (DESIGN-I01B1 rev 2 section 1; I1D-3, I1D-10), over copies of the six guarded files and the
    two crates' lib.rs, in D2ConstructorHomePinTests' form: for each of the six, a changed, added and removed byte, the
    appended probes (B3-12's trait-item and generic-default forms in the two effect-gate files, X6-4's type alias in all
    six), a missing file, a symlink to identical bytes and a rename refuse; HE-004-I01B3 (DESIGN-I01B3 rev 4 section 1):
    i01_answer.rs's absence became the seventh pin, so its absence cases became presence cases (the loop's cases, and an
    empty file, a directory or a dangling symlink in its place); a casefolded sibling of a guarded name refuses (on a
    case-sensitive file system; on a case-insensitive one the sibling of i01_answer.rs is that file, changed); an inline module in
    place of a guarded one (I1D-3's probes, `pub mod config { }` and `pub mod linux_os { }`), a doubled declaration and
    an inline `mod client {` elsewhere refuse; the copies and the real tree pass."""

    RULE = "R-B3-PIN"
    LIBS = (gate.OBSERVER_LIB, gate.EFFECT_GATE_LIB)
    LEAK = b"pub trait Leak { fn leak(&self) -> &Conn; }\n"
    HOLDER = b"pub struct Holder<T = Conn> { pub inner: T }\n"
    ALIAS = b"pub type Leaked = crate::los::Conn;\n"

    def setUp(self):
        super().setUp()
        self.real = {rel: (gate.HE / rel).read_bytes() for rel in tuple(gate.I01B_GUARDED_PINS) + self.LIBS}
        for rel, data in self.real.items():
            self.write_bytes(rel, data)

    def write_bytes(self, rel, data):
        path = self.base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        path.write_bytes(data)

    def refuses(self, message):
        with self.assertRaisesRegex(gate.GateError, message + ".*" + self.RULE):
            gate.check_i01b_guarded_pins(self.base)

    def test_the_copies_and_the_real_tree_pass(self):
        self.assertEqual(gate.I01B_GUARDED_PINS, {
            "crates/effect-gate/src/linux_os.rs": "88e70bf599f0b3cb733aa018c0ea08da6b973ccd21aea8b1b15e3d1cfa7475a6",
            "crates/effect-gate/src/linux_net.rs": "d452aa507f1325028ce4dd62c77d5dfa808a5e18a77dc1cb1e5036db209e6fbd",
            "crates/observer/src/config.rs": "173b7adf575c946e55fb3384467bcb37377f0505a41d36d21308c04c458624da",
            # HE-004-I01B5 (DESIGN-I01B5 rev 5 section 1; Q-4): these three re-pinned at I01B5's bytes.
            "crates/observer/src/i01_request.rs": "7d3b6951a5082fddf7313a7a94a4bb96b2eccf63003d1e605dcb2549c316d7af",
            "crates/observer/src/i01_service.rs": "11b921cfa316eca65ff3259e992f2330734d3e8423bc9a10514db469f608e298",
            "crates/observer/src/client.rs": "9c496052b5c05cf59fe21867f689aa68d74b30671d37ad77e52837e3f9b45c35",
            # HE-004-I01B3 (DESIGN-I01B3 rev 4 section 1; Q-4): the absence became the pin, at I01B3's bytes.
            "crates/observer/src/i01_answer.rs": "3ee5fb683bc6bcbc13a39db985782038915f4851d825a75f02c26f0409764736"})
        self.assertEqual(gate.I01B_ABSENT, ())
        self.assertIn("i01_answer", gate.I01B_FILE_FORM[gate.OBSERVER_LIB])
        # linux_listen.rs and linux_net.rs stay in OBSERVER_HOME_PINS (re-pinned there by HE-004-I01B5).
        self.assertIn("crates/observer/src/linux_listen.rs", gate.OBSERVER_HOME_PINS)
        self.assertIn("crates/observer/src/linux_net.rs", gate.OBSERVER_HOME_PINS)
        self.assertEqual(gate.check_i01b_guarded_pins(self.base), 7)
        self.assertEqual(gate.check_i01b_guarded_pins(gate.HE), 7)

    def test_each_pinned_file_refuses_a_change_a_probe_missing_a_symlink_or_a_rename(self):
        for rel in gate.I01B_GUARDED_PINS:
            data = self.real[rel]
            middle = len(data) // 2
            probes = [self.ALIAS] + ([self.LEAK, self.HOLDER] if rel.startswith("crates/effect-gate/") else [])
            for changed in [data[:middle] + bytes([data[middle] ^ 1]) + data[middle + 1:], data + b"\n", data[:-1]] + [
                    data + probe for probe in probes]:
                self.write_bytes(rel, changed)
                self.refuses("%s differs from its pinned bytes" % re.escape(rel))
                self.write_bytes(rel, data)
            path = self.base / rel
            path.unlink()
            self.refuses("%s is missing or a symlink" % re.escape(rel))
            (self.base / "real.bin").write_bytes(data)
            path.symlink_to(self.base / "real.bin")
            self.refuses("%s is missing or a symlink" % re.escape(rel))
            path.unlink()
            moved = path.with_name("moved_" + path.name)
            moved.write_bytes(data)
            self.refuses("%s is missing or a symlink" % re.escape(rel))
            moved.unlink()
            self.write_bytes(rel, data)
        self.assertEqual(gate.check_i01b_guarded_pins(self.base), 7)

    def test_the_answer_module_is_pinned(self):
        # HE-004-I01B3 (DESIGN-I01B3 rev 4 section 1): the absence cases become presence cases. Beside the loop above (a
        # changed, added and removed byte, the probes, a missing file, a symlink to identical bytes, a rename), an empty
        # file, a directory and a dangling symlink in its place refuse.
        rel = gate.I01_ANSWER
        answer, data = self.base / rel, self.real[rel]
        answer.write_bytes(b"")
        self.refuses("i01_answer.rs differs from its pinned bytes")
        answer.unlink()
        answer.mkdir()
        self.refuses("i01_answer.rs is missing or a symlink")
        answer.rmdir()
        answer.symlink_to(self.base / "nowhere.rs")
        self.refuses("i01_answer.rs is missing or a symlink")
        answer.unlink()
        self.write_bytes(rel, data)
        self.assertEqual(gate.check_i01b_guarded_pins(self.base), 7)

    def test_a_casefolded_sibling_refuses(self):
        probe = self.base / "case-probe"
        probe.write_bytes(b"")
        sensitive = not (self.base / "CASE-PROBE").exists()
        probe.unlink()
        # HE-004-I01B3: i01_answer.rs is pinned, so on a case-insensitive file system the sibling is that file, changed.
        sibling = self.base / "crates/observer/src/I01_answer.rs"
        sibling.write_bytes(b"")
        self.refuses("I01_answer.rs casefolds to the guarded name i01_answer.rs" if sensitive
                     else "i01_answer.rs differs from its pinned bytes")
        sibling.unlink()
        self.write_bytes(gate.I01_ANSWER, self.real[gate.I01_ANSWER])
        if sensitive:
            for rel in ("crates/effect-gate/src/Linux_os.rs", "crates/observer/src/CONFIG.rs",
                        "crates/observer/src/Linux_Net.rs"):
                (self.base / rel).write_bytes(b"pub fn f() {}\n")
                self.refuses("%s casefolds to the guarded name" % re.escape(rel))
                (self.base / rel).unlink()
        self.assertEqual(gate.check_i01b_guarded_pins(self.base), 7)

    def test_the_casefold_clause_on_a_listing(self):
        # PR review round 1, R1-4: the clause read over a directory listing (casefold_siblings, which the check calls with
        # each guarded directory's entries), so its refusal runs on any file system, case-insensitive ones included.
        rule = "guarded pin, R-B3-PIN"
        guarded = list(gate.I01B_GUARDED_PINS) + list(gate.I01B_ABSENT) + [gate.OBSERVER_LINUX_NET, gate.OBSERVER_LINUX_LISTEN]
        names = {}
        for rel in guarded:
            names.setdefault(rel.rsplit("/", 1)[0], set()).add(rel.rsplit("/", 1)[1])
        self.assertEqual(names, {"crates/effect-gate/src": {"linux_os.rs", "linux_net.rs"},
                                 "crates/observer/src": {"config.rs", "i01_request.rs", "i01_service.rs", "client.rs",
                                                         "i01_answer.rs", "linux_listen.rs", "linux_net.rs"}})
        gate.casefold_siblings("crates/effect-gate/src", ["lib.rs", "linux_os.rs", "linux_net.rs", "peers.rs"],
                               names["crates/effect-gate/src"], rule)
        gate.casefold_siblings("crates/observer/src", ["client.rs", "config.rs", "i01_digest.rs", "observe.rs"],
                               names["crates/observer/src"], rule)
        for directory, entries, sibling in (("crates/effect-gate/src", ["linux_os.rs", "Linux_os.rs"], "Linux_os.rs"),
                                            ("crates/effect-gate/src", ["LINUX_NET.RS"], "LINUX_NET.RS"),
                                            ("crates/observer/src", ["I01_answer.rs"], "I01_answer.rs"),
                                            ("crates/observer/src", ["config.rs", "Config.rs"], "Config.rs"),
                                            ("crates/observer/src", ["Linux_Listen.rs"], "Linux_Listen.rs"),
                                            ("crates/observer/src", ["CLIENT.rs", "client.rs"], "CLIENT.rs")):
            with self.assertRaisesRegex(gate.GateError, "%s/%s casefolds to the guarded name .*%s"
                                        % (re.escape(directory), re.escape(sibling), self.RULE)):
                gate.casefold_siblings(directory, entries, names[directory], rule)

    def test_an_inline_module_in_place_of_a_guarded_one_refuses(self):
        for lib, old, new, message in (
                (gate.OBSERVER_LIB, b"pub mod config;\n", b"pub mod config { }\n", "does not declare `pub mod config;`"),
                (gate.EFFECT_GATE_LIB, b"pub mod linux_os;\n", b"pub mod linux_os { }\n",
                 "does not declare `pub mod linux_os;`"),
                (gate.OBSERVER_LIB, b"pub mod client;\n", b"pub mod client;\npub mod client;\n",
                 "does not declare `pub mod client;`"),
                (gate.OBSERVER_LIB, b"pub mod i01_service;\n", b"", "does not declare `pub mod i01_service;`"),
                # HE-004-I01B3 (DESIGN-I01B3 rev 4 section 1, I1D-3's file form): i01_answer as an inline module, twice,
                # or not declared.
                (gate.OBSERVER_LIB, b"pub mod i01_answer;\n", b"pub mod i01_answer { }\n",
                 "does not declare `pub mod i01_answer;`"),
                (gate.OBSERVER_LIB, b"pub mod i01_answer;\n", b"pub mod i01_answer;\npub mod i01_answer;\n",
                 "does not declare `pub mod i01_answer;`"),
                (gate.OBSERVER_LIB, b"pub mod i01_answer;\n", b"", "does not declare `pub mod i01_answer;`")):
            data = self.real[lib]
            self.assertEqual(data.count(old), 1, old)
            self.write_bytes(lib, data.replace(old, new))
            self.refuses(message)
            self.write_bytes(lib, data)
        self.write_bytes("crates/observer/src/observe.rs", b"mod client {\n    pub fn f() {}\n}\n")
        self.refuses("observe.rs holds an inline `mod client {`")
        self.write_bytes("crates/observer/src/observe.rs", b"mod i01_answer {\n    pub fn derive() {}\n}\n")
        self.refuses("observe.rs holds an inline `mod i01_answer {`")
        (self.base / "crates/observer/src/observe.rs").unlink()
        self.assertEqual(gate.check_i01b_guarded_pins(self.base), 7)


# HE-004-I01B2 (DESIGN-I01B2 rev 3 section 7; DIB sections 7.1 and 7.2): G-I01B-3's and G-I01B-4's fixture: main.rs's
# serve (GOOD_OBSERVER_MAIN), config.rs's private binding with its accessor and parse_v3, i01_request.rs's closed
# binding, and the two sources that carry it.
I01B2_CONFIG_TEXT = """//! A config.rs fixture (`ObserverConfig {`, `Self {`, `.binding`, `parse_v3` and `type C = ObserverConfig;` in a comment pass).
use i05_protocol::json::{Object, Value};

#[derive(Clone, Debug)]
pub struct ObserverConfig {
    pub namespace: String,
    binding: Value,
    pub sealed: Option<SealedValues>,
}

impl ObserverConfig {
    pub fn parse_v3(document: &[u8]) -> Result<(ObserverConfig, FileRef), ConfigError> {
        let value = canonical_value(document)?;
        let root = closed(Some(&value), "the document", &MEMBERS_V3)?;
        let mut config = ObserverConfig::members(root)?;
        let record = file_ref(root.get("qualificationRecord"), "qualificationRecord")?;
        binding_namespaces(root.get("binding"), &config.namespace)?;
        let sealed = sealed_values(root.get("sealedAdmission"))?;
        let binding = match root.get("binding") {
            Some(member) => member.clone(),
            None => return schema("the document holds no binding member".to_string()),
        };
        config.sealed = Some(sealed);
        config.binding = binding;
        Ok((config, record))
    }

    fn members(root: &Object) -> Result<ObserverConfig, ConfigError> {
        let namespace = text(root, "qualificationNamespace", "the document")?;
        Ok(ObserverConfig { namespace: namespace.to_string(), binding: Value::Null, sealed: None })
    }

    pub fn binding(&self) -> &Value {
        &self.binding
    }
}
"""
I01B2_REQUEST_TEXT = """//! An i01_request.rs fixture (`I01Binding {`, `Self {` and `impl Clone for I01Binding` in a comment pass).
use i05_protocol::json::{self, Value};
use i05_protocol::sha256;

/// HE-008's binding.
#[derive(Debug, PartialEq, Eq)]
pub struct I01Binding {
    signed_digest: String,
    signed_nonce: String,
}

impl I01Binding {
    pub fn from_config(binding: &Value) -> Option<I01Binding> {
        let encoded = json::canonical(binding).ok()?;
        let signed_nonce = binding.get("scope")?.get("runNonce")?.as_str()?.to_string();
        let signed_digest = sha256::prefixed(&encoded);
        Some(I01Binding { signed_digest, signed_nonce })
    }

    pub fn signed_digest(&self) -> &str {
        &self.signed_digest
    }

    pub fn signed_nonce(&self) -> &str {
        &self.signed_nonce
    }
}

pub fn binding_gate(request: &I01Request, binding: Option<&I01Binding>) -> Result<(), RequestRefusal> {
    match binding {
        Some(bound) if bound.signed_digest() == request.binding_digest && bound.signed_nonce() == request.run_nonce => Ok(()),
        _ => Err(RequestRefusal::Binding),
    }
}

pub fn check_request(bytes: &[u8], truncated: bool, chain: &mut Chain, binding: Option<&I01Binding>)
                     -> Result<I01Request, RequestRefusal> {
    let value = frame(bytes, truncated)?;
    let checked = request_schema(&value)?;
    chain.check(&checked)?;
    binding_gate(&checked, binding)?;
    Ok(checked)
}
"""
I01B2_SERVICE_TEXT = """//! An i01_service.rs fixture.
use crate::i01_request::{check_request, Chain, I01Binding};

pub struct I01Service {
    binding: I01Binding,
}

impl I01Service {
    pub fn new(binding: I01Binding) -> I01Service {
        I01Service { binding }
    }

    pub fn request(&self, bytes: &[u8], chain: &mut Chain) -> bool {
        check_request(bytes, false, chain, Some(&self.binding)).is_ok()
    }
}
"""
I01B2_OBSERVE_TEXT = """//! An observe.rs fixture (`I01Binding::from_config(` and `ObserverConfig::parse_v3(` in a comment pass).
use crate::config::ObserverConfig;
use crate::i01_request::I01Binding;
use crate::i01_service::I01Service;

pub fn run(config: ObserverConfig, binding: I01Binding) -> I01Service {
    let _ = config;
    I01Service::new(binding)
}
"""
I01B2_LIB_TEXT = "#![forbid(unsafe_code)]\npub mod config;\npub mod i01_request;\npub mod i01_service;\npub mod observe;\n"
I01B2_SERVICE = "crates/observer/src/i01_service.rs"
I01B2_OBSERVE = "crates/observer/src/observe.rs"
I01B2_TREE = {gate.OBSERVER_MAIN: GOOD_OBSERVER_MAIN, gate.OBSERVER_LIB: I01B2_LIB_TEXT, gate.I01B2_CONFIG: I01B2_CONFIG_TEXT,
              gate.I01B2_REQUEST: I01B2_REQUEST_TEXT, I01B2_SERVICE: I01B2_SERVICE_TEXT, I01B2_OBSERVE: I01B2_OBSERVE_TEXT}
# The fixture's anchors the plantings change, each once in its file.
I01B2_LOAD_OK = "        Ok(document) => document,\n"
I01B2_LOAD_ERR = "        Err(error) => return status::config_load(&error),\n"
I01B2_PARSE = "    let Ok((config, record_ref)) = ObserverConfig::parse_v3(&document) else { return status::CONFIG_CHECK };\n"
I01B2_FROM = "    let Some(binding) = I01Binding::from_config(config.binding()) else { return status::CONFIG_CHECK };\n"
I01B2_RUN = "    status::observation(&observe::run(wire, config, tls, closure, captures, server, binding))\n"
I01B2_USE = "use i05_protocol::json::{Object, Value};\n"
I01B2_LET = "        let binding = match root.get(\"binding\") {\n"
I01B2_ASSIGN = "        config.binding = binding;\n"
I01B2_ACCESSOR = "    pub fn binding(&self) -> &Value {\n"
I01B2_OBSERVE_USE = "use crate::i01_service::I01Service;\n"
I01B2_LIB_LAST = "pub mod observe;\n"
# The monitor's ruling on round 2 (and I2E-4): every NEW-n and H-n form is a self-test row, one sub-clause each, refused
# with that sub-clause's message, and passing the gate with only that sub-clause disabled (the build's mutation proof,
# which reads this table). Each row: (label, sub-clause, ((file, anchor, replacement), ..)). A row's spelling keeps every
# other sub-clause's places, so that only its own sub-clause refuses it (BUILD.md records where it departs from the
# record's wording; the record's own spellings are test_the_review_records_own_spellings_refuse's).
I01B2_CLAUSE_FUNCTIONS = {"(b1)": "constructor_b1_load_pin", "(b2)": "constructor_b2_document",
                          "(b3)": "constructor_b3_config", "(b4)": "constructor_b4_outermost",
                          "(b5)": "constructor_b5_parse_pin", "(b6)": "constructor_b6_parse_v3",
                          "(c1)": "constructor_c1_alias", "(c2)": "constructor_c2_dot_form",
                          "(c3)": "constructor_c3_bound_once", "(c4)": "constructor_c4_no_self"}
_MAIN, _CONFIG = gate.OBSERVER_MAIN, gate.I01B2_CONFIG
I01B2_ROWS = (
    # (b1) the pinned load statement [I2E-1]: an unsigned literal in either arm (the arm keeps document's three words).
    ("H1", "(b1)", ((_MAIN, I01B2_LOAD_OK, "        Ok(document) => { let _ = document; b\"{}\".to_vec() }\n"),)),
    ("H1b", "(b1)", ((_MAIN, I01B2_LOAD_ERR, "        Err(_) => b\"{}\".to_vec(),\n"),)),
    # (b2) document 5 times [I2E-2 (i)].
    ("NEW-3b", "(b2)", ((_MAIN, I01B2_PARSE, "    let document = b\"{}\".to_vec();\n" + I01B2_PARSE),)),
    ("H2", "(b2)", ((_MAIN, I01B2_PARSE, "    let mut document = document;\n    document.clear();\n"
                                         "    document.extend_from_slice(b\"{}\");\n" + I01B2_PARSE),)),
    ("H2b", "(b2)", ((_MAIN, I01B2_PARSE, "    let mut document = document;\n    document = b\"{}\".to_vec();\n" + I01B2_PARSE),)),
    ("H2c", "(b2)", ((_MAIN, I01B2_PARSE, "    let document = match Ok::<Vec<u8>, u8>(document) {\n"
                                          "        Ok(mut document) => { document.clear(); document.extend_from_slice(b\"{}\"); "
                                          "document }\n        Err(_) => return status::CONFIG_CHECK,\n    };\n"
                                          + I01B2_PARSE),)),
    ("H3c", "(b2)", ((_MAIN, I01B2_PARSE, "    let Some(document) = Some(b\"{}\".to_vec()) else { return 0 };\n" + I01B2_PARSE),)),
    ("H8-document", "(b2)", ((_MAIN, I01B2_PARSE, "    let r#document = b\"{}\".to_vec();\n" + I01B2_PARSE),)),
    # (b3) config 5 times at its places [I2E-2 (ii)].
    ("NEW-4b", "(b3)", ((_MAIN, I01B2_FROM, "    let config = observe::Wrap(config);\n" + I01B2_FROM),)),
    ("H3", "(b3)", ((_MAIN, I01B2_FROM, "    let (config, _) = (observe::Wrap(config), ());\n" + I01B2_FROM),)),
    ("H3b", "(b3)", ((_MAIN, I01B2_FROM, "    let observe::Held { config } = observe::hold(config);\n" + I01B2_FROM),)),
    ("H3d", "(b3)", ((_MAIN, I01B2_RUN, "    { let config = observe::other(); status::observation(&observe::run(wire, config, "
                                        "tls, closure, captures, server, binding)) }\n"),)),
    ("H8-config", "(b3)", ((_MAIN, I01B2_FROM, "    let r#config = config;\n" + I01B2_FROM),)),
    # (b4) both pinned statements outermost, in order [I2E-2 (iii)].
    ("H10", "(b4)", ((_MAIN, I01B2_PARSE, "    { " + I01B2_PARSE.strip() + " }\n"),)),
    # (b5) the pinned parse statement [I2D-4 (1)].
    ("NEW-3a", "(b5)", ((_MAIN, I01B2_PARSE, "    let Ok((config, record_ref)) = ObserverConfig::parse_v3(if document.is_empty() "
                                             "{ b\"{}\" } else { b\"{}\" }) else { return status::CONFIG_CHECK };\n"),)),
    ("H7c", "(b5)", ((_MAIN, "ObserverConfig::parse_v3(&document)", "<ObserverConfig>::parse_v3(&document)"),)),
    # (b6) parse_v3 twice in the crate [I2E-2 (iv)].
    ("NEW-4a", "(b6)", ((I01B2_OBSERVE, I01B2_OBSERVE_USE,
                         I01B2_OBSERVE_USE + "pub fn reparse(d: &[u8]) -> bool { ObserverConfig::parse_v3(d).is_ok() }\n"),)),
    ("H7", "(b6)", ((I01B2_OBSERVE, I01B2_OBSERVE_USE,
                     I01B2_OBSERVE_USE + "static P: fn(&[u8]) -> Result<(ObserverConfig, FileRef), ConfigError> = "
                                         "ObserverConfig::parse_v3;\n"),)),
    ("H7b", "(b6)", ((I01B2_OBSERVE, I01B2_OBSERVE_USE,
                      I01B2_OBSERVE_USE + "pub trait Again { fn again(d: &[u8]) -> bool { ObserverConfig::parse_v3(d).is_ok() } }\n"),)),
    ("H7d", "(b6)", ((I01B2_OBSERVE, I01B2_OBSERVE_USE, I01B2_OBSERVE_USE + "use crate::config::ObserverConfig::parse_v3 as p;\n"),)),
    ("H8-parse_v3", "(b6)", ((I01B2_OBSERVE, I01B2_OBSERVE_USE,
                              I01B2_OBSERVE_USE + "pub fn reparse(d: &[u8]) -> bool { ObserverConfig::r#parse_v3(d).is_ok() }\n"),)),
    # (c1) no rename or type item naming ObserverConfig [I2D-1; I2E-5].
    ("X4-7 (NEW-1)", "(c1)", ((_CONFIG, I01B2_USE, I01B2_USE + "type C = ObserverConfig;\n"),
                              (_CONFIG, I01B2_ASSIGN, I01B2_ASSIGN + "        let config = C { binding: forged(), ..config };\n"))),
    ("X4-8 (NEW-1b)", "(c1)", ((_CONFIG, I01B2_USE, I01B2_USE + "use self::ObserverConfig as Oc;\n"),
                               (_CONFIG, I01B2_ASSIGN, I01B2_ASSIGN + "        let Oc { binding: slot, .. } = &mut config;\n"
                                                                     "        *slot = forged();\n"))),
    ("H5", "(c1)", ((gate.OBSERVER_LIB, I01B2_LIB_LAST, I01B2_LIB_LAST + "pub use crate::config::ObserverConfig as X;\n"),
                    (_CONFIG, I01B2_ASSIGN, I01B2_ASSIGN + "        let config = crate::X { binding: forged(), ..config };\n"))),
    ("H6", "(c1)", ((_CONFIG, I01B2_USE, I01B2_USE + "trait Tr { type Out; }\nimpl Tr for u8 { type Out = ObserverConfig; }\n"
                                                     "type A = <u8 as Tr>::Out;\n"),
                    (_CONFIG, I01B2_ASSIGN, I01B2_ASSIGN + "        let config = A { binding: forged(), ..config };\n"))),
    ("H8-ObserverConfig", "(c1)", ((_CONFIG, I01B2_USE, I01B2_USE + "type C = r#ObserverConfig;\n"),
                                   (_CONFIG, I01B2_ASSIGN, I01B2_ASSIGN + "        let config = C { binding: forged(), ..config };\n"))),
    # (c2) the dot form read as G-D2-8 reads it [I2D-13].
    ("NEW-10", "(c2)", ((_CONFIG, I01B2_ASSIGN, I01B2_ASSIGN + "        config . r#binding = forged();\n"),)),
    ("H9", "(c2)", ((_CONFIG, I01B2_LET, "        let _seen = config.binding();\n" + I01B2_LET),)),
    ("H8-binding", "(c2)", ((_CONFIG, I01B2_ACCESSOR, "    fn rebind(config: &mut ObserverConfig, value: Value) {\n"
                                                      "        config.r#binding = value;\n    }\n\n" + I01B2_ACCESSOR),)),
    # (c3) I2D-3's clause [I2E-3].
    ("NEW-2", "(c3)", ((_CONFIG, I01B2_ASSIGN, "        let binding = forged();\n" + I01B2_ASSIGN),)),
    ("H4", "(c3)", ((_CONFIG, I01B2_LET, I01B2_LET.replace("let binding", "let mut binding")),
                    (_CONFIG, I01B2_ASSIGN, "        binding = forged();\n" + I01B2_ASSIGN))),
    ("H4b", "(c3)", ((_CONFIG, I01B2_ASSIGN, "        let set = |binding: Value| config.binding = binding;\n        set(forged());\n"),)),
    ("H4c", "(c3)", ((_CONFIG, I01B2_ASSIGN, "        match forged() {\n            binding => config.binding = binding,\n        }\n"),)),
    ("H4d", "(c3)", ((_CONFIG, I01B2_ASSIGN, "        for binding in [forged()] {\n            config.binding = binding;\n        }\n"),)),
    # (c4) no word Self in config.rs [I2E-7].
    ("X4-Self", "(c4)", ((_CONFIG, I01B2_ACCESSOR, "    fn rebuilt(self, binding: Value) -> Self {\n        Self { binding, ..self }\n"
                                                   "    }\n\n" + I01B2_ACCESSOR),)),
)


def i01b2_tree(changes=()):
    """I01B2_TREE with each (file, anchor, replacement) applied; each anchor must occur once in its file."""
    texts = dict(I01B2_TREE)
    for rel, old, new in changes:
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


class I01BindingRuleTests(Tree):
    """HE-004-I01B2 G-I01B-3 and G-I01B-4 (DESIGN-I01B2 rev 3 section 7; DIB sections 7.1 and 7.2), over the fixture
    (main.rs's serve, config.rs's accessor and parse_v3, i01_request.rs's closed binding): the fixture and the real
    sources pass; DIB section 7.1's rows P3-1..P3-7, SR-2, N2-1 and N2-1b and round 3's X3-1..X3-4 refuse under
    G-I01B-3; section 7.2's rows P4-1..P4-6, N2-2 and N2-2b, its two positives and two wiring cases, and round 3's X4-1,
    X4-2, X4-3, X4-3b, X4-4, X4-5 and X4-6 under G-I01B-4; and the 35 NEW-n and H-n rows, one sub-clause each, each
    refused with its own sub-clause's message (I2E-4)."""

    TREE = I01B2_TREE

    def plant(self, changes):
        for rel, text in i01b2_tree(changes).items():
            self.write(rel, text)

    def refuses(self, check, changes, message):
        self.plant(changes)
        try:
            with self.assertRaisesRegex(gate.GateError, message):
                check(self.base)
        finally:
            self.plant(())

    def test_the_fixture_and_the_real_sources_pass(self):
        self.assertEqual(gate.check_i01b_binding(self.base), 6)
        self.assertEqual(gate.check_i01b_constructor(self.base), 14)
        self.assertEqual(gate.check_observer_serve(self.base), 14)
        self.assertEqual(gate.check_i01b_binding(gate.HE), 6)
        self.assertEqual(gate.check_i01b_constructor(gate.HE), 14)

    def test_g_i01b_3_section_7_1_rows_refuse(self):
        binding, constructor = gate.check_i01b_binding, gate.check_i01b_constructor
        request, service, observe = gate.I01B2_REQUEST, I01B2_SERVICE, I01B2_OBSERVE
        service_use = "use crate::i01_request::{check_request, Chain, I01Binding};\n"
        derive = "#[derive(Debug, PartialEq, Eq)]\npub struct I01Binding"
        getter = "    pub fn signed_digest(&self) -> &str {\n"
        literal = "        Some(I01Binding { signed_digest, signed_nonce })\n"
        last = "    Ok(checked)\n}\n"
        other_file = "i01_service.rs writes the I01Binding literal; only"
        # P3-1, P3-2: a literal outside its module, also split-path and spaced.
        for planted in ("fn forge(d: String, n: String) -> Option<I01Binding> { Some(I01Binding { signed_digest: d, "
                        "signed_nonce: n }) }\n",
                        "fn forge() -> Option<I01Binding> { Some(crate::i01_request::I01Binding { signed_digest: "
                        "String::new(), signed_nonce: String::new() }) }\n",
                        "fn forge() -> Option<I01Binding> { Some(i01_request :: I01Binding { ..todo() }) }\n"):
            self.refuses(binding, ((service, service_use, service_use + planted),), other_file)
        # P3-3: `Self {` in an impl elsewhere.
        self.refuses(binding, ((service, service_use, service_use + "impl I01Binding { fn forge() -> Self { Self { "
                                                                    "signed_digest: String::new(), signed_nonce: "
                                                                    "String::new() } } }\n"),),
                     "i01_service.rs holds an impl naming I01Binding other than")
        # P3-4: a second constructor in the impl, written `Self {`, and as a free fn.
        self.refuses(binding, ((request, getter, "    pub fn forge(d: String, n: String) -> I01Binding {\n        I01Binding "
                                                 "{ signed_digest: d, signed_nonce: n }\n    }\n\n" + getter),),
                     "holds a fn other than from_config and its two getters")
        self.refuses(binding, ((request, literal, literal.replace("I01Binding {", "Self {")),), "writes `Self\\{`")
        self.refuses(binding, ((request, last, last + "pub fn forge(d: String, n: String) -> Option<I01Binding> {\n    "
                                                      "Some(I01Binding { signed_digest: d, signed_nonce: n })\n}\n"),),
                     "writes the I01Binding literal other than once, in fn from_config")
        # P3-5 and SR-2: Default, cfg_attr, Clone, Copy; the trait impls in two files.
        for new, message in (("#[derive(Debug, Default, PartialEq, Eq)]\npub struct I01Binding", "derives Default on I01Binding"),
                             ("#[cfg_attr(test, derive(Default))]\n" + derive, "an attribute other than its one derive"),
                             ("#[derive(Clone, Debug, PartialEq, Eq)]\npub struct I01Binding", "derives Clone on I01Binding"),
                             ("#[derive(Copy, Clone, Debug, PartialEq, Eq)]\npub struct I01Binding", "derives Clone on I01Binding")):
            self.refuses(binding, ((request, derive, new),), message)
        self.refuses(binding, ((service, service_use, service_use + "impl Clone for I01Binding { fn clone(&self) -> "
                                                                    "I01Binding { todo() } }\n"),),
                     "i01_service.rs holds an impl naming I01Binding other than")
        self.refuses(binding, ((observe, I01B2_OBSERVE_USE, I01B2_OBSERVE_USE + "impl Copy for I01Binding {}\n"),),
                     "observe.rs holds an impl naming I01Binding other than")
        # P3-6: pub fields and a write.
        for visibility in ("pub ", "pub(crate) "):
            self.refuses(binding, ((request, "    signed_digest: String,\n", "    %ssigned_digest: String,\n" % visibility),),
                         "a field of I01Binding with a visibility")
        self.refuses(binding, ((observe, I01B2_OBSERVE_USE, I01B2_OBSERVE_USE + "pub fn forge(b: &mut I01Binding) { "
                                                                                "b.signed_digest = String::new(); }\n"),),
                     "observe.rs uses the I01Binding field signed_digest other than through its getter")
        # P3-7: an alias.
        for planted in ("use crate::i01_request::I01Binding as B;\n", "type B = I01Binding;\n"):
            self.refuses(binding, ((observe, I01B2_OBSERVE_USE, I01B2_OBSERVE_USE + planted),), "renames or aliases I01Binding")
        # N2-1: the empty-turbofish literal, as a free fn, inside another impl, spaced, and in i01_service.rs.
        forge = "pub fn forge(d: String, n: String) -> Option<I01Binding> { Some(I01Binding::<> { signed_digest: d, " \
                "signed_nonce: n }) }\n"
        own = "writes the I01Binding literal other than once, in fn from_config"
        self.refuses(binding, ((request, last, last + forge),), own)
        self.refuses(binding, ((request, last, last + "pub struct Chain;\nimpl Chain {\n    " + forge + "}\n"),), own)
        self.refuses(binding, ((request, last, last + forge.replace("I01Binding::<> {", "I01Binding :: < > {")),), own)
        self.refuses(binding, ((service, service_use, service_use + forge),), other_file)
        # N2-1b: destructuring outside the module.
        self.refuses(binding, ((service, service_use, service_use + "fn peek(b: I01Binding) -> String { let I01Binding { "
                                                                    "signed_digest, .. } = b; signed_digest }\n"),),
                     other_file)
        # G-I01B-4 does not refuse these G-I01B-3 forms that name no from_config (they are G-I01B-3's).
        self.plant(((request, derive, "#[derive(Clone, Debug, PartialEq, Eq)]\npub struct I01Binding"),))
        self.assertEqual(constructor(self.base), 14)
        self.plant(())

    def test_g_i01b_3_round_3_rows_refuse(self):
        binding, request = gate.check_i01b_binding, gate.I01B2_REQUEST
        literal = "        Some(I01Binding { signed_digest, signed_nonce })\n"
        from_config = ("    pub fn from_config(binding: &Value) -> Option<I01Binding> {\n"
                       "        let encoded = json::canonical(binding).ok()?;\n"
                       "        let signed_nonce = binding.get(\"scope\")?.get(\"runNonce\")?.as_str()?.to_string();\n"
                       "        let signed_digest = sha256::prefixed(&encoded);\n" + literal + "    }\n")
        # X3-1: a minting closure; the name still occurs six times, so only the exact signature refuses it (B3-11 (a)).
        minting = ("    pub fn from_config(binding: &Value) -> Option<impl Fn(String, String) -> I01Binding> {\n"
                   "        let _ = binding;\n        Some(|signed_digest, signed_nonce| I01Binding { signed_digest, "
                   "signed_nonce })\n    }\n")
        self.refuses(binding, ((request, from_config, minting),),
                     re.escape("does not hold `pub fn from_config(binding: &Value) -> Option<I01Binding>` exactly once"))
        # X3-2: a const literal.
        self.refuses(binding, ((request, "    Ok(checked)\n}\n", "    Ok(checked)\n}\nconst FORGED: I01Binding = I01Binding "
                                                               "{ signed_digest: String::new(), signed_nonce: String::new() };\n"),),
                     "writes the I01Binding literal other than once, in fn from_config")
        # X3-3: a nested fn inside from_config's body.
        self.refuses(binding, ((request, literal, "        fn mint(d: String, n: String) -> Option<I01Binding> { "
                                                  "Some(I01Binding { signed_digest: d, signed_nonce: n }) }\n"
                                                  "        mint(signed_digest, signed_nonce)\n"),),
                     "holds a fn other than from_config and its two getters")
        # X3-4: destructuring inside i01_request.rs.
        self.refuses(binding, ((request, "    match binding {\n", "    if let Some(I01Binding { signed_digest, .. }) = binding "
                                                               "{ let _ = signed_digest; }\n    match binding {\n"),),
                     "writes the I01Binding literal other than once, in fn from_config")

    def test_g_i01b_4_section_7_2_rows_refuse(self):
        binding, constructor = gate.check_i01b_binding, gate.check_i01b_constructor
        observe, anchor = I01B2_OBSERVE, I01B2_OBSERVE_USE
        count = "from_config occurs 3 times, not exactly twice"
        # P4-1, P4-2, P4-3's wrapper, P4-5's two qualified spellings, P4-6's non-strict cfg(test) fn.
        for planted in ("pub fn twice(doc: &Value) { let _ = I01Binding::from_config(doc); }\n",
                        "pub fn reference() { let make = I01Binding::from_config; let _ = make; }\n",
                        "pub fn again(c: &Value) -> Option<I01Binding> { I01Binding::from_config(c) }\n",
                        "pub fn qualified(doc: &Value) { let _ = <I01Binding>::from_config(doc); }\n",
                        "pub fn qualified(doc: &Value) { let _ = I01Binding::<>::from_config(doc); }\n",
                        "#[cfg(test)]\nfn helper(doc: &Value) { let _ = I01Binding::from_config(doc); }\n"):
            self.refuses(constructor, ((observe, anchor, anchor + planted),), count)
        # P4-3's From impl (G-I01B-3 (iii)); P4-4's alias call (G-I01B-3 (v) and (a)).
        self.refuses(binding, ((observe, anchor, anchor + "impl From<&Value> for I01Binding { fn from(v: &Value) -> "
                                                          "I01Binding { todo() } }\n"),),
                     "observe.rs holds an impl naming I01Binding other than")
        alias = "use crate::i01_request::I01Binding as B;\npub fn alias(doc: &Value) { let _ = B::from_config(doc); }\n"
        self.refuses(binding, ((observe, anchor, anchor + alias),), "renames or aliases I01Binding")
        self.refuses(constructor, ((observe, anchor, anchor + alias),), count)
        # N2-2: a recursive serve.
        self.refuses(constructor, ((gate.OBSERVER_MAIN, I01B2_RUN, "    if retry { return serve(sealed); }\n" + I01B2_RUN),),
                     re.escape("main.rs matches `serve(` 3 times, not its definition and the tail's call"))
        # N2-2b: an accessor handing out another value, a pub field (c), and a second dot write outside parse_v3 (c2).
        config = gate.I01B2_CONFIG
        for old, new in (("        &self.binding\n", "        &self.other\n"), ("    binding: Value,\n", "    pub binding: Value,\n")):
            self.refuses(constructor, ((config, old, new),), "ObserverConfig's binding accessor or field is not as pinned")
        self.refuses(constructor, ((config, I01B2_ACCESSOR, "    fn reset(config: &mut ObserverConfig, v: Value) {\n"
                                                            "        config.binding = v;\n    }\n\n" + I01B2_ACCESSOR),),
                     re.escape("G-I01B-4 (c2)"))

    def test_g_i01b_4_positives_and_wiring_cases(self):
        constructor = gate.check_i01b_constructor
        # Positive: a call inside a strict #[cfg(test)] mod tests block passes (the fixture's pass is the other one).
        self.plant(((I01B2_OBSERVE, I01B2_OBSERVE_USE, I01B2_OBSERVE_USE + "#[cfg(test)]\nmod tests {\n    use super::*;\n"
                                                                          "    fn twice(doc: &Value) { let _ = "
                                                                          "I01Binding::from_config(doc); }\n}\n"),))
        self.assertEqual(constructor(self.base), 14)
        self.assertEqual(gate.check_i01b_binding(self.base), 6)
        self.plant(())
        # Wiring: the statement before check_lifetime( (the wiring order's), or wrapped in loop { .. } ((a)).
        lifetime = "    if let Err(error) = config::check_lifetime(&config, utc::wall_seconds()) {\n"
        self.refuses(gate.check_observer_serve, ((gate.OBSERVER_MAIN, I01B2_FROM, ""),
                                                 (gate.OBSERVER_MAIN, lifetime, I01B2_FROM + lifetime)),
                     "serve does not call .* in this order")
        self.refuses(constructor, ((gate.OBSERVER_MAIN, I01B2_FROM, "    loop {\n    " + I01B2_FROM + "        break;\n    }\n"),),
                     re.escape("as a statement of its outermost block (one constructor call, G-I01B-4 (a))"))
        # Wiring: parse_with_record( in serve.
        self.refuses(gate.check_observer_serve, ((gate.OBSERVER_MAIN, "ObserverConfig::parse_v3(", "ObserverConfig::parse_with_record("),),
                     "v2 ObserverConfig::parse_with_record")

    def test_g_i01b_4_round_3_rows_refuse(self):
        constructor, config = gate.check_i01b_constructor, gate.I01B2_CONFIG
        word = "main.rs names the word serve 3 times"
        # X4-1, X4-2, X4-3 (B3-3's word count) and X4-3b (B2-10's pattern).
        for planted, message in (("    let again = serve;\n    if retry { return again(sealed); }\n", word),
                                 ("    if retry { return serve::<>(sealed); }\n", word),
                                 ("    if retry { return (serve)(sealed); }\n", word),
                                 ("    if retry { return self::serve(sealed); }\n", re.escape("main.rs matches `serve(` 3 times"))):
            self.refuses(constructor, ((gate.OBSERVER_MAIN, I01B2_RUN, planted + I01B2_RUN),), message)
        # X4-4 and X4-6 (Self: (c4)); X4-5 (the restated literal pattern: (c)).
        self.refuses(constructor, ((config, I01B2_ACCESSOR, "    fn rebind(self, binding: Value) -> Self {\n        Self { "
                                                            "binding, ..self }\n    }\n\n" + I01B2_ACCESSOR),),
                     re.escape("G-I01B-4 (c4)"))
        self.refuses(constructor, ((config, I01B2_ASSIGN, I01B2_ASSIGN + "        let config = ObserverConfig::<> { binding: "
                                                                         "forged(), ..config };\n"),),
                     "writes the ObserverConfig literal or pattern other than once, in fn members")
        self.refuses(constructor, ((config, I01B2_ASSIGN, I01B2_ASSIGN + "        let Self { binding: slot, .. } = &mut config;\n"
                                                                         "        *slot = forged();\n"),),
                     re.escape("G-I01B-4 (c4)"))

    def rows_of(self, clause):
        rows = [row for row in I01B2_ROWS if row[1] == clause]
        self.assertTrue(rows, clause)
        for label, _, changes in rows:
            with self.subTest(row=label):
                self.refuses(gate.check_i01b_constructor, changes, re.escape("G-I01B-4 %s" % clause))
        return len(rows)

    def test_the_35_rows_are_named_once_and_name_their_sub_clauses(self):
        labels = [label for label, _, _ in I01B2_ROWS]
        self.assertEqual((len(I01B2_ROWS), len(set(labels))), (35, 35))
        counts = {clause: sum(row[1] == clause for row in I01B2_ROWS) for clause in I01B2_CLAUSE_FUNCTIONS}
        self.assertEqual(counts, {"(b1)": 2, "(b2)": 6, "(b3)": 5, "(b4)": 1, "(b5)": 2, "(b6)": 5,
                                  "(c1)": 5, "(c2)": 3, "(c3)": 5, "(c4)": 1})
        for function in I01B2_CLAUSE_FUNCTIONS.values():
            self.assertTrue(callable(getattr(gate, function)), function)

    def test_b1_the_pinned_load_statement(self):
        self.assertEqual(self.rows_of("(b1)"), 2)

    def test_b2_document_five_times(self):
        self.assertEqual(self.rows_of("(b2)"), 6)

    def test_b3_config_five_times(self):
        self.assertEqual(self.rows_of("(b3)"), 5)

    def test_b4_outermost_and_in_order(self):
        self.assertEqual(self.rows_of("(b4)"), 1)

    def test_b5_the_pinned_parse_statement(self):
        self.assertEqual(self.rows_of("(b5)"), 2)

    def test_b6_parse_v3_twice(self):
        self.assertEqual(self.rows_of("(b6)"), 5)

    def test_c1_no_alias_or_type_item(self):
        self.assertEqual(self.rows_of("(c1)"), 5)

    def test_c2_the_dot_form(self):
        self.assertEqual(self.rows_of("(c2)"), 3)

    def test_c3_bound_once(self):
        self.assertEqual(self.rows_of("(c3)"), 5)

    def test_c4_no_self(self):
        self.assertEqual(self.rows_of("(c4)"), 1)

    def test_the_review_records_own_spellings_refuse(self):
        # The records' spellings where a row's spelling departs from them (each also breaks another place, so it can
        # name more than one sub-clause): refused by G-I01B-4 all the same.
        main, observe = gate.OBSERVER_MAIN, I01B2_OBSERVE
        load = "    let document = match signed_config::load() {\n"
        for changes in (
                ((main, I01B2_LOAD_OK, "        Ok(_) => b\"{}\".to_vec(),\n"),),
                ((main, load, load.replace("let document", "let mut document")),
                 (main, I01B2_PARSE, "    document.clear();\n    document.extend_from_slice(b\"{}\");\n" + I01B2_PARSE)),
                ((main, load, load.replace("let document", "let mut document")),
                 (main, I01B2_PARSE, "    document = b\"{}\".to_vec();\n" + I01B2_PARSE)),
                ((main, I01B2_LOAD_OK, "        Ok(mut document) => { document.clear(); document.extend_from_slice(b\"{}\"); "
                                       "document }\n"),),
                ((main, "ObserverConfig::parse_v3(&document)", "ObserverConfig::parse_v3(b\"{}\")"),),
                ((main, I01B2_PARSE, "    let (config, record_ref) = { " + I01B2_PARSE.strip() + " (config, record_ref) };\n"),),
                ((observe, I01B2_OBSERVE_USE, I01B2_OBSERVE_USE + "pub fn reparse(d: &[u8]) -> Option<ObserverConfig> { "
                                                                  "ObserverConfig::parse_v3(d).ok().map(|(config, _)| config) }\n"),
                 (main, I01B2_FROM, "    let config = observe::reparse(b\"{}\").unwrap_or(config);\n" + I01B2_FROM))):
            self.refuses(gate.check_i01b_constructor, changes, "G-I01B-4")


ALIAS_TREE = {
    gate.EFFECT_GATE_LIB: "#![forbid(unsafe_code)]\n#[cfg(target_os = \"linux\")]\npub mod linux_net;\n"
                          "#[cfg(target_os = \"linux\")]\npub mod linux_os;\npub mod peers;\n",
    gate.LINUX_OS: "use gate_sys::channel::Conn;\nuse crate::linux_net::SharedNet;\npub struct Slot;\n",
    "crates/effect-gate/src/linux_net.rs": "use gate_sys::tcp::TcpConn;\npub struct SharedNet;\n",
    "crates/effect-gate/src/peers.rs": "pub fn peers() {}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n}\n",
    gate.OBSERVER_LIB: "#![forbid(unsafe_code)]\npub mod i01_admission_render;\npub mod i01_digest;\npub mod i01_gate;\n"
                       "#[cfg(target_os = \"linux\")]\npub mod linux_listen;\n#[cfg(target_os = \"linux\")]\npub mod linux_net;\n"
                       "pub mod observe;\n",
    gate.OBSERVER_LINUX_NET: "use gate_sys::channel;\nuse crate::linux_listen::I01Socket;\npub struct LinuxWire;\n",
    gate.OBSERVER_LINUX_LISTEN: "use gate_sys::channel::{self, ListenStep};\npub(crate) struct I01Socket;\n",
    "crates/observer/src/observe.rs": "pub fn run() {}\n",
    gate.OBSERVER_MAIN: "fn serve() {\n    use planeon_observer::linux_net::LinuxWire;\n}\n",
    # HE-004-I01B1's three modules (DESIGN-I01B1 rev 2 section 2, I1D-2: the fixture with I01B1's changes).
    "crates/observer/src/i01_digest.rs": "pub fn digest() {}\n",
    "crates/observer/src/i01_admission_render.rs": "use crate::i01_digest::digest;\npub fn render() {}\n",
    "crates/observer/src/i01_gate.rs": "pub fn gate() {}\n",
}
# The I1D-11 matrix: (alias spelling x placement x socket file) 10 x 2 x 4, X6-1..X6-4 (the alias with its use site in
# the socket file) 4 x 2 x 4, and the four scope-root renames x 2 placements x 2 crates: 80 + 32 + 16 = 128 cases (PR
# review round 1, R1-7: the tenth spelling is the unrenamed module import).
ALIAS_SPELLINGS = ("use crate::{m} as a;\n", "use crate::{m}::{{self as a}};\n", "use crate::{{{m}::{{self as a}}}};\n",
                   "use {m} as a;\n", "use self::{m} as a;\n", "pub(crate) use super::{m} as a;\n",
                   "mod inner {{\n    pub(crate) use super::{m} as a;\n}}\n", "pub use crate::{m}::Item;\n",
                   "use crate::{m}::*;\n", "use crate::{m};\n")
ALIAS_USE_SITES = ("pub fn leak(slot: &Slot) -> &crate::a::Conn {{ slot.conn() }}\n",
                   "pub fn leak(slot: &Slot) -> &super::a::Conn {{ slot.conn() }}\n",
                   "pub fn tcp(slot: &Slot) -> Option<&crate::a::TcpConn> {{ slot.tcp() }}\n",
                   "pub type Leaked = crate::a::Conn;\n")
SCOPE_ROOT_RENAMES = ("use crate as r;\n", "use crate::{self as r};\n", "use self as r;\n", "use super as r;\n")
ALIAS_FILES = ((gate.EFFECT_GATE_LIB, "crates/effect-gate/src/peers.rs", gate.LINUX_OS, "linux_os"),
               (gate.EFFECT_GATE_LIB, "crates/effect-gate/src/peers.rs", "crates/effect-gate/src/linux_net.rs", "linux_net"),
               (gate.OBSERVER_LIB, "crates/observer/src/observe.rs", gate.OBSERVER_LINUX_NET, "linux_net"),
               (gate.OBSERVER_LIB, "crates/observer/src/observe.rs", gate.OBSERVER_LINUX_LISTEN, "linux_listen"))
ALIAS_CASES = 128
# PR review round 1, R1-2: scope-root globs, refused in every module but a crate's lib.rs top level.
SCOPE_ROOT_GLOBS = ("use crate::*;\n", "pub use crate::*;\n", "pub(crate) use crate::*;\n", "use self::*;\n",
                    "use super::*;\n", "pub use super::*;\n")


class SocketModuleAliasTests(Tree):
    """HE-004-I01B1 B3-1, G-I01B-6 (e) (DESIGN-I01B1 rev 2 sections 2 and 6, I1D-1, I1D-2, I1D-11): the matrix of alias
    declarations (ten spellings: a rename of the module, its trailing self braced and nested, the 2018 relative and
    self:: forms, a pub(crate) super:: form, the same inside an inline module, a pub use of an item through it, a glob
    through it and the unrenamed import, R1-7), each in lib.rs and in another module of the crate, for each of the four
    socket files; X6-1..X6-4 with their use sites; and the four scope-root renames in both crates: 128 cases, each
    refusing. Scope-root globs (R1-2) refuse in every module but a crate's lib.rs top level. The must-pass: the fixture
    with I01B1's changes and today's three item imports (effect-gate linux_os.rs:39, observer linux_net.rs:35,
    main.rs:63), and the real sources."""

    TREE = ALIAS_TREE
    RULE = "G-I01B-6 \\(e\\)"

    def test_the_fixture_and_the_real_sources_pass(self):
        self.assertEqual(gate.check_socket_module_aliases(self.base), len(self.TREE))
        real = sum(1 for crate in gate.SOCKET_CRATE_MODULES for _ in (gate.HE / crate / "src").rglob("*.rs"))
        self.assertEqual(gate.check_socket_module_aliases(gate.HE), real)

    def test_the_alias_matrix_refuses(self):
        cases = 0
        for lib, other, socket, module in ALIAS_FILES:
            for placement in (lib, other):
                for spelling in ALIAS_SPELLINGS:
                    self.refused(gate.check_socket_module_aliases, placement,
                                 self.TREE[placement] + spelling.format(m=module), "socket module .*" + self.RULE)
                    cases += 1
                for site in ALIAS_USE_SITES:
                    self.write(socket, self.TREE[socket] + site.format())
                    self.refused(gate.check_socket_module_aliases, placement,
                                 self.TREE[placement] + ALIAS_SPELLINGS[0].format(m=module), "socket module .*" + self.RULE)
                    self.write(socket, self.TREE[socket])
                    cases += 1
        for lib, other in ((gate.EFFECT_GATE_LIB, "crates/effect-gate/src/peers.rs"),
                           (gate.OBSERVER_LIB, "crates/observer/src/observe.rs")):
            for placement in (lib, other):
                for rename in SCOPE_ROOT_RENAMES:
                    self.refused(gate.check_socket_module_aliases, placement, self.TREE[placement] + rename,
                                 "imports or renames a scope root .*" + self.RULE)
                    cases += 1
        self.assertEqual(cases, ALIAS_CASES)
        # A use site alone (X6-4 without the alias) is the pins' case, not this rule's.
        self.write(gate.LINUX_OS, self.TREE[gate.LINUX_OS] + ALIAS_USE_SITES[3].format())
        self.assertEqual(gate.check_socket_module_aliases(self.base), len(self.TREE))

    def test_scope_root_globs_refuse_outside_a_crate_root(self):
        # PR review round 1, R1-2: in a module other than the crate root, a glob of a scope root (any visibility) refuses,
        # in both crates; so does one inside an inline module of lib.rs, and main.rs's glob of the library's root.
        refusals = 0
        for lib, other in ((gate.EFFECT_GATE_LIB, "crates/effect-gate/src/peers.rs"),
                           (gate.OBSERVER_LIB, "crates/observer/src/observe.rs")):
            for glob in SCOPE_ROOT_GLOBS:
                self.refused(gate.check_socket_module_aliases, other, self.TREE[other] + glob,
                             "globs a scope root outside its crate root .*" + self.RULE)
                refusals += 1
            self.refused(gate.check_socket_module_aliases, lib, self.TREE[lib] + "mod inner {\n    pub use crate::*;\n}\n",
                         "globs a scope root outside its crate root .*" + self.RULE)
            refusals += 1
            # At the top level of the crate root a glob of the root names nothing new, and passes.
            self.write(lib, self.TREE[lib] + "pub use crate::*;\n")
            self.assertEqual(gate.check_socket_module_aliases(self.base), len(self.TREE))
            self.write(lib, self.TREE[lib])
        self.refused(gate.check_socket_module_aliases, gate.OBSERVER_MAIN, self.TREE[gate.OBSERVER_MAIN]
                     + "use planeon_observer::*;\n", "globs a scope root outside its crate root .*" + self.RULE)
        refusals += 1
        self.assertEqual(refusals, 2 * len(SCOPE_ROOT_GLOBS) + 3)
        # A strict test block's glob of super (peers.rs's fixture) is blanked, and the fixture passes.
        self.assertIn("use super::*;", self.TREE["crates/effect-gate/src/peers.rs"])
        self.assertEqual(gate.check_socket_module_aliases(self.base), len(self.TREE))

    def test_item_imports_pass_and_their_other_forms_refuse(self):
        main = gate.OBSERVER_MAIN
        for text in ("fn serve() {\n    use planeon_observer::linux_net::{LinuxWire, Other as O};\n}\n",
                     "fn serve() {\n    use crate::linux_net::LinuxWire as W;\n}\n"):
            self.write(main, text)
            self.assertEqual(gate.check_socket_module_aliases(self.base), len(self.TREE))
        for text, message in (("fn serve() {\n    use planeon_observer::linux_net;\n}\n", "imports the socket module"),
                              ("fn serve() {\n    use planeon_observer::linux_net::{self};\n}\n", "imports the socket module"),
                              ("use planeon_observer as po;\n", "scope root"),
                              ("pub use planeon_observer::linux_listen::I01Socket;\n", "re-exports")):
            self.refused(gate.check_socket_module_aliases, main, text, message + ".*" + self.RULE)
        # The same item import made pub refuses; a test block's glob of super passes (blanked).
        self.refused(gate.check_socket_module_aliases, gate.LINUX_OS,
                     self.TREE[gate.LINUX_OS].replace("use crate::linux_net::SharedNet;", "pub use crate::linux_net::SharedNet;"),
                     "re-exports .*" + self.RULE)
        self.refused(gate.check_socket_module_aliases, gate.OBSERVER_LINUX_NET, self.TREE[gate.OBSERVER_LINUX_NET]
                     + "use crate::linux_listen::{1 + 1};\n", "cannot read .*" + self.RULE)


# --- HE-004-I01B3 (DESIGN-I01B3 rev 4 sections 4, 5 and 8): G-I01B-9 and G-I01B-8's I01B3 checks -------------------------

# The fixture: copies of the real i01_answer.rs, i01_digest.rs (the (t5) methods' home) and the contract v2's
# definitions.json, and small observe.rs, client.rs and i01_service.rs, the other sources the rows plant into.
I01B3_ANSWER_TEXT = (gate.HE / gate.I01_ANSWER).read_text(encoding="utf-8")
I01B3_OBSERVE = "crates/observer/src/observe.rs"
I01B3_SERVICE = "crates/observer/src/i01_service.rs"
I01B3_OBSERVE_RUN = "pub fn run() -> u8 {\n    0\n}\n"
I01B3_CLIENT_TEXT = "pub fn c() {}\n"
I01B3_ANSWER_TREE = {
    gate.I01_ANSWER: I01B3_ANSWER_TEXT,
    gate.I01B1_DIGEST_RS: (gate.HE / gate.I01B1_DIGEST_RS).read_text(encoding="utf-8"),
    gate.I01B_DEFINITIONS: (gate.HE / gate.I01B_DEFINITIONS).read_text(encoding="utf-8"),
    I01B3_OBSERVE: ("//! An observe.rs fixture (`Derived {`, `impl Clone for Derived`, `type D = Derived;` and `static` in "
                    "a comment pass).\n" + I01B3_OBSERVE_RUN),
    gate.OBSERVER_CLIENT: I01B3_CLIENT_TEXT,
    I01B3_SERVICE: "pub struct I01Service;\n",
}
# The real file's anchors the plantings use, each once in it.
I01B3_STRUCT = re.search(r"pub struct Derived \{\n.*?\n\}\n", I01B3_ANSWER_TEXT, re.S).group(0)
I01B3_TAIL = re.search(r"    Ok\(Derived \{\n.*?\n    \}\)\n", I01B3_ANSWER_TEXT, re.S).group(0)
I01B3_DERIVE_FN = re.search(r"pub fn derive\(.*?\n    \}\)\n\}\n", I01B3_ANSWER_TEXT, re.S).group(0)
I01B3_TOP = "// ------------------------------------------------------------------------------------------------ the answer list\n"
I01B3_IN_ANSWER = "    // 8. The bound.\n"
I01B3_DERIVE_LET = "    let generation_hex = generation.to_string();\n"
I01B3_GETTER = "    pub fn binding_member(&self) -> &Value {\n        &self.binding_member\n    }\n"
I01B3_STRUCT_ATTR = "#[derive(Debug)]\npub struct Derived {\n"
I01B3_FIELD = "    bound_digest: String,\n"
I01B3_NAMESPACE_DOC = ("/// VPO's observed namespace against the binding's (harness-onion scripts/validate_policy_observation.py:109 "
                       "at\n/// f9882c1a).\n")
I01B3_NAMESPACE_PIN = 'pub const OBSERVED_NAMESPACE_TEXT: &str = "observed namespace";\n'
I01B3_KEY_UID = 'pub const KEY_UID: &str = "uid";\n'
I01B3_LIST_LET = "    let mut list: Vec<&'static str> = Vec::new();\n"
I01B3_LIST_TAIL = "    list\n}\n"
I01B3_LIST_PUSH = "                list.push(text);\n"
I01B3_X9_1 = ("impl Clone for Derived where Derived: Sized {\n    fn clone(&self) -> Self where Self: Sized {\n        forged()\n"
              "    }\n}\n\n")
I01B3_NEW_1 = ("    impl CaptureFacts {\n        pub fn mint(policy_values: Vec<u8>) -> Option<Derived> {\n"
               "            Some(Derived { policy_values, ..forged() })\n        }\n    }\n"
               "    CaptureFacts::mint(policy_values).ok_or(INVALID_OBSERVATION_TEXT)\n")
_ANSWER = gate.I01_ANSWER
# DESIGN-I01B3 rev 4 sections 4 and 8 [I3D-3, I3D-10, I3E-1, I3E-5, I3F-5, I3F-6]: G-I01B-9's rows, each with its named
# sub-clause (the first of the set section 4 states, and the first of the actual set to refuse, the sub-clauses running
# (i) to (vii)), section 4's stated set, and its plantings ((file, anchor, replacement), ..). The build's mutation proof
# reads this table, records each row's actual refusing set and runs the single-clause or each-alone proof.
I01B3_DERIVED_ROWS = (
    # DIB section 7.6 (N2-8: module_isolation (b) also refuses it, outside G-I01B-9).
    ("N2-8", "(ii)", ("(ii)",),
     ((I01B3_OBSERVE, I01B3_OBSERVE_RUN, I01B3_OBSERVE_RUN + "pub fn forge() -> u8 {\n    let _ = crate::i01_answer::Derived { "
                                         "..forged() };\n    0\n}\n"),
      (gate.OBSERVER_CLIENT, I01B3_CLIENT_TEXT, I01B3_CLIENT_TEXT + "pub fn forge() {\n    let _ = Derived::<> { ..forged() };\n}\n"))),
    ("N2-8b", "(ii)", ("(ii)", "(vi)"),
     ((_ANSWER, I01B3_TOP, "fn expected(binding: &Value) -> Option<Derived> {\n    Some(Derived { ..forged(binding) })\n}\n\n"
                           + I01B3_TOP),)),
    # Round 3's X9 forms; X9-1 re-planted with where clauses [I3E-5], in both files.
    ("X9-1 in i01_answer.rs", "(iii)", ("(iii)", "(vi)"), ((_ANSWER, I01B3_TOP, I01B3_X9_1 + I01B3_TOP),)),
    ("X9-1 in observe.rs", "(iii)", ("(iii)",), ((I01B3_OBSERVE, I01B3_OBSERVE_RUN, I01B3_OBSERVE_RUN + I01B3_X9_1),)),
    ("X9-2", "(i)", ("(i)",), ((_ANSWER, I01B3_STRUCT_ATTR, I01B3_STRUCT_ATTR.replace("Debug", "Debug, Clone")),)),
    ("X9-3", "(i)", ("(i)",), ((_ANSWER, I01B3_FIELD, "    pub bound_digest: String,\n"),)),
    ("X9-4", "(ii)", ("(ii)", "(vi)"),
     ((_ANSWER, I01B3_IN_ANSWER, "    let _forged = Derived::<> { ..forged() };\n" + I01B3_IN_ANSWER),)),
    # Round 1's forms [I3D-3].
    ("(1) cfg_attr Default", "(i)", ("(i)",),
     ((_ANSWER, I01B3_STRUCT_ATTR, "#[cfg_attr(not(test), derive(Default))]\n" + I01B3_STRUCT_ATTR),)),
    ("(2) a field write on an owned value in answer", "(iv)", ("(iv)",),
     ((_ANSWER, I01B3_IN_ANSWER, "    let mut owned = rebuilt();\n    owned.boot_id = forged();\n" + I01B3_IN_ANSWER),)),
    ("(3a) the tuple definition, its getters kept", "(i)", ("(i)",),
     ((_ANSWER, I01B3_STRUCT, "pub struct Derived(Value, String);\n"),)),
    ("(3b) a Derived( call, the brace struct kept", "(ii)", ("(ii)", "(vi)"),
     ((_ANSWER, I01B3_IN_ANSWER, "    let _forged = Derived(forged());\n" + I01B3_IN_ANSWER),)),
    # I3D-3's rows.
    ("a field write in derive before the tail, the tail kept", "(iv)", ("(iv)",),
     ((_ANSWER, I01B3_DERIVE_LET, "    let mut other = template();\n    other.bound_nonce = forged();\n" + I01B3_DERIVE_LET),)),
    ("a field write through &mut Derived in a helper", "(iv)", ("(iv)", "(vi)"),
     ((_ANSWER, I01B3_TOP, "fn adjust(derived: &mut Derived, value: Value) {\n    derived.binding_member = value;\n}\n\n"
                           + I01B3_TOP),)),
    ("a &mut self getter", "(iii)", ("(iii)",),
     ((_ANSWER, I01B3_GETTER, "    pub fn binding_member(&mut self) -> &mut Value {\n        &mut self.binding_member\n    }\n"),)),
    ("a getter reading another field", "(iii)", ("(iii)",),
     ((_ANSWER, I01B3_GETTER, I01B3_GETTER.replace("&self.binding_member", "&self.enrolled_record")),)),
    # Round 2's [I3E-1].
    ("NEW-1", "(ii)", ("(ii)", "(vi)", "(vii)"), ((_ANSWER, I01B3_TAIL, I01B3_NEW_1),)),
    ("NEW-2", "(ii)", ("(ii)",),
     ((_ANSWER, I01B3_TAIL, "    let make = |policy_values| Derived { policy_values, ..forged() };\n"
                            "    Ok(make(policy_values))\n"),)),
    ("NEW-3", "(ii)", ("(ii)", "(vi)"),
     ((_ANSWER, I01B3_TAIL, "    fn make(policy_values: Vec<u8>) -> Derived {\n        Derived { policy_values, ..forged() }\n"
                            "    }\n    Ok(make(policy_values))\n"),)),
    ("NEW-10", "(i)", ("(i)", "(vi)"),
     ((_ANSWER, "pub struct Derived {\n", "pub struct Derived<T = Value> {\n"),
      (_ANSWER, I01B3_IN_ANSWER, "    let _forged = Derived::<Value> { ..forged() };\n" + I01B3_IN_ANSWER))),
    ("(vi) alone: a top-level helper naming Derived", "(vi)", ("(vi)",),
     ((_ANSWER, I01B3_TOP, "fn peek(derived: &Derived) -> &str {\n    derived.boot_id()\n}\n\n" + I01B3_TOP),)),
    ("(vii) alone: a nested impl in derive's body, a let after it", "(vii)", ("(vii)",),
     ((_ANSWER, I01B3_DERIVE_LET, "    impl CaptureFacts {\n        fn mint(&self) -> bool {\n            self.completed\n"
                                  "        }\n    }\n" + I01B3_DERIVE_LET),)),
    # Round 3's [I3F-6].
    ("H6", "(ii)", ("(ii)",), ((_ANSWER, I01B3_TAIL, "    Ok((|| Derived { policy_values, ..forged() })())\n"),)),
    ("H7", "(vi)", ("(vi)",), ((_ANSWER, I01B3_DERIVE_FN, "impl CaptureFacts {\n" + I01B3_DERIVE_FN + "}\n"),)),
)
I01B3_DERIVED_FUNCTIONS = {"(i)": "derived_i_struct", "(ii)": "derived_ii_literal", "(iii)": "derived_iii_impls",
                           "(iv)": "derived_iv_fields", "(v)": "derived_v_names", "(vi)": "derived_vi_name_count",
                           "(vii)": "derived_vii_top_level"}
# DESIGN-I01B3 rev 4 sections 5 and 8 [I3E-3, I3F-1..3], and PR review rounds 1 and 2 (R1-1, R1-2: U6; R2-1..R2-3: U7):
# G-I01B-8's I01B3 rows, (t1)-(t10), each with its named check (the first of its actual set to refuse, the checks
# running (t1), (t6), (t2), (t9), (t3), (t4), (t8), (t5), (t7), (t10), and (t11) since HE-004-I01B5), no stated set
# (section 4 states sets for G-I01B-9 only), and its plantings. HE-004-I01B5's rows are I01B5_TEXT_ROWS.
I01B3_TEXT_ROWS = (
    ("(t1) a changed VPO text", "(t1)", None,
     ((_ANSWER, I01B3_NAMESPACE_PIN, I01B3_NAMESPACE_PIN.replace('"observed namespace"', '"observed namespaces"')),)),
    ("(t1) a missing citation", "(t1)", None,
     ((_ANSWER, I01B3_NAMESPACE_DOC, I01B3_NAMESPACE_DOC.replace("scripts/validate_policy_observation.py:109 at", "VPO at")),)),
    ("(t1) a key const holding an invented value", "(t1)", None,
     ((_ANSWER, I01B3_KEY_UID, I01B3_KEY_UID.replace('"uid"', '"uuid"')),)),
    ("(t2) an unlisted R10 text", "(t2)", None,
     ((_ANSWER, I01B3_TOP, '/// R10-defined, MODEL_DEFINED R201.\npub const FORGED_TEXT: &str = "forged refusal";\n\n'
                           + I01B3_TOP),)),
    ("(t2) a second const with a text's value", "(t2)", None,
     ((_ANSWER, I01B3_TOP, 'pub const AGAIN_TEXT: &str = "observed namespace";\n\n' + I01B3_TOP),)),
    ("(t2) a key const equal to a text", "(t2)", None,
     ((_ANSWER, I01B3_TOP, 'pub const KEY_FORGED: &str = "observed namespace";\n\n' + I01B3_TOP),)),
    ("(t2) a fn-local const", "(t2)", None,
     ((_ANSWER, I01B3_IN_ANSWER, 'pub const MADE_UP_TEXT: &str = "made up";\n' + I01B3_IN_ANSWER),)),
    ("(t2) a &'static str const outside the lists", "(t2)", None,
     ((_ANSWER, I01B3_TOP, "pub const OTHER: &'static str = KEY_SCOPE;\n\n" + I01B3_TOP),)),
    ("(t2) a pinned line inside a block comment, the name redefined", "(t2)", None,
     ((_ANSWER, I01B3_NAMESPACE_DOC + I01B3_NAMESPACE_PIN,
       "/*\n" + I01B3_NAMESPACE_DOC + I01B3_NAMESPACE_PIN + "*/\npub static OBSERVED_NAMESPACE_TEXT: &str = KEY_NAMESPACE;\n"),)),
    ("(t3) a bare Err literal", "(t3)", None,
     ((_ANSWER, I01B3_IN_ANSWER, '    if wall_ms == 0 {\n        return Err("observed namespace");\n    }\n' + I01B3_IN_ANSWER),)),
    ("(t3) a raw string", "(t3)", None, ((_ANSWER, I01B3_IN_ANSWER, '    let _raw = r"observed namespace";\n' + I01B3_IN_ANSWER),)),
    ("(t3) a raw string with hashes", "(t3)", None,
     ((_ANSWER, I01B3_IN_ANSWER, '    let _raw = r#"observed namespace"#;\n' + I01B3_IN_ANSWER),)),
    ("(t3) a byte string", "(t3)", None,
     ((_ANSWER, I01B3_IN_ANSWER, '    let _bytes = b"observed namespace";\n' + I01B3_IN_ANSWER),)),
    ("(t3) a raw byte string", "(t3)", None,
     ((_ANSWER, I01B3_IN_ANSWER, '    let _bytes = br"observed namespace";\n' + I01B3_IN_ANSWER),)),
    ("(t3) a C string", "(t3)", None, ((_ANSWER, I01B3_IN_ANSWER, '    let _c = c"observed namespace";\n' + I01B3_IN_ANSWER),)),
    ("(t3) a raw C string", "(t3)", None,
     ((_ANSWER, I01B3_IN_ANSWER, '    let _c = cr"observed namespace";\n' + I01B3_IN_ANSWER),)),
    ("(t4) stringify!", "(t4)", None, ((_ANSWER, I01B3_IN_ANSWER, "    let _made = stringify!(made up);\n" + I01B3_IN_ANSWER),)),
    ("(t4) file!()", "(t4)", None, ((_ANSWER, I01B3_IN_ANSWER, "    let _made = file!();\n" + I01B3_IN_ANSWER),)),
    ("(t4) module_path!()", "(t4)", None, ((_ANSWER, I01B3_IN_ANSWER, "    let _made = module_path!();\n" + I01B3_IN_ANSWER),)),
    ("(t5) Default::default()", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(Default::default());\n    }\n" + I01B3_IN_ANSWER),)),
    ("(t5) a slice of a pinned const", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(&OBSERVED_NAMESPACE_TEXT[9..]);\n    }\n"
                                 + I01B3_IN_ANSWER),)),
    ("(t5) an I01B1 non-refusal text, LIFECYCLE_SLOT", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(i01_gate::LIFECYCLE_SLOT);\n    }\n"
                                 + I01B3_IN_ANSWER),)),
    ("(t5) an I01B1 non-refusal text, DigestKey::name()", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(DigestKey::Rbac.name());\n    }\n"
                                 + I01B3_IN_ANSWER),)),
    # U3's (t5) row: since R1-2 (a), (t2) reads the array's `[&str; 1]` as a type naming str and refuses it first.
    ("(t2) a const array of key consts", "(t2)", None,
     ((_ANSWER, I01B3_TOP, "const KEYS: [&str; 1] = [KEY_SCOPE];\n\n" + I01B3_TOP),
      (_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(KEYS[0]);\n    }\n" + I01B3_IN_ANSWER))),
    ("(t5) a KEY_ const through the rule function", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    require(wall_ms != 1, KEY_SCOPE)?;\n" + I01B3_IN_ANSWER),)),
    ("(t5) a KEY_ const through map_err", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    let _ = json::canonical(derived.binding_member()).map_err(|_| KEY_SCOPE)?;\n"
                                 + I01B3_IN_ANSWER),)),
    ("(t5) a KEY_ const through ok_or_else(move ||)", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    let _ = utc_text(now).ok_or_else(move || KEY_SCOPE)?;\n" + I01B3_IN_ANSWER),)),
    ("(t5) a KEY_ const as a braced argument", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err({ KEY_SCOPE });\n    }\n" + I01B3_IN_ANSWER),)),
    ("(t6) a key-prefixed literal", "(t6)", None,
     ((_ANSWER, I01B3_TOP, 'pub const KEY_FORGED: &str = "rbac: differs from the signed value";\n\n' + I01B3_TOP),)),
    ("(t7) a static aliasing a key const", "(t7)", None,
     ((_ANSWER, I01B3_TOP, "pub static ALIAS: &str = KEY_SCOPE;\n\n" + I01B3_TOP),)),
    ("(t7) a fn-local static shadowing a pinned name", "(t7)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    static OBSERVED_NAMESPACE_TEXT: &str = KEY_SCOPE;\n" + I01B3_IN_ANSWER),)),
    # PR review round 1's hunted forms H8-1 .. H8-10 (R1-1, R1-2; U6), in the spellings of the record's findings.
    ("H8-1 Err turbofish", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err::<Vec<u8>, &'static str>(KEY_SCOPE);\n    }\n"
                                 + I01B3_IN_ANSWER),)),
    ("H8-2 ok_or turbofish", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    let _ = utc_text(now).ok_or::<&'static str>(KEY_SCOPE)?;\n" + I01B3_IN_ANSWER),)),
    ("H8-3 map_err turbofish", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    let _ = json::canonical(derived.binding_member())\n"
                                 "        .map_err::<&'static str, _>(|_| KEY_SCOPE)?;\n" + I01B3_IN_ANSWER),)),
    ("H8-4 Err as a function value", "(t8)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    Some(KEY_SCOPE).filter(..).map_or(Ok(()), Err)?;\n" + I01B3_IN_ANSWER),)),
    ("H8-5 the rule helper as a function value", "(t8)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    let rule = require;\n    rule(.., KEY_SCOPE)?;\n" + I01B3_IN_ANSWER),)),
    ("H8-6 a fn item as map_err's argument", "(t5)", None,
     ((_ANSWER, I01B3_TOP, "fn scope_text(_: json::Error) -> &'static str {\n    KEY_SCOPE\n}\n\n" + I01B3_TOP),
      (_ANSWER, I01B3_IN_ANSWER, "    let _ = json::canonical(derived.binding_member()).map_err(scope_text)?;\n"
                                 + I01B3_IN_ANSWER))),
    ("H8-7 refusals' list via Vec::push", "(t5)", None,
     ((_ANSWER, I01B3_LIST_LET, I01B3_LIST_LET + "    Vec::push(&mut list, KEY_SCOPE);\n"),)),
    ("H8-8 refusals' list via extend", "(t5)", None,
     ((_ANSWER, I01B3_LIST_LET, I01B3_LIST_LET + "    list.extend([KEY_SCOPE]);\n"),)),
    ("H8-9 a lower-case const typed &(str)", "(t2)", None,
     ((_ANSWER, I01B3_TOP, "const scope_text: &(str) = KEY_SCOPE;\n\n" + I01B3_TOP),
      (_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(scope_text);\n    }\n" + I01B3_IN_ANSWER))),
    ("H8-10 a lower-case const typed through a type alias of str", "(t9)", None,
     ((_ANSWER, I01B3_TOP, "type Text = str;\nconst scope_text: &Text = KEY_SCOPE;\n\n" + I01B3_TOP),
      (_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(scope_text);\n    }\n" + I01B3_IN_ANSWER))),
    # PR review round 2's forms N-10 (both spellings), M-1 (both spellings) and M-2 (R2-1..R2-3; U7), each planted from
    # the round-2 record's huntedForms text.
    ("N-10 a const fn as ok_or_else's argument", "(t5)", None,
     ((_ANSWER, I01B3_TOP, "const fn scope_text() -> &'static str { KEY_SCOPE }\n\n" + I01B3_TOP),
      (_ANSWER, I01B3_IN_ANSWER, "    let _ = utc_text(now).ok_or_else(scope_text)?;\n" + I01B3_IN_ANSWER))),
    ("N-10b a pub const fn as ok_or_else's argument", "(t5)", None,
     ((_ANSWER, I01B3_TOP, "pub const fn scope_text() -> &'static str { KEY_SCOPE }\n\n" + I01B3_TOP),
      (_ANSWER, I01B3_IN_ANSWER, "    let _ = utc_text(now).ok_or_else(scope_text)?;\n" + I01B3_IN_ANSWER))),
    ("M-1 an early return of vec! from refusals", "(t10)", None,
     ((_ANSWER, I01B3_LIST_LET, I01B3_LIST_LET + "    if facts.expired { return vec![KEY_SCOPE]; }\n"),)),
    ("M-1b an early return of Vec::from from refusals", "(t10)", None,
     ((_ANSWER, I01B3_LIST_LET, I01B3_LIST_LET + "    if facts.expired { return Vec::from([KEY_SCOPE]); }\n"),)),
    ("M-2 a module fn push given refusals' list", "(t5)", None,
     ((_ANSWER, I01B3_TOP, "fn push(into: &mut Vec<&'static str>, text: &'static str) { into.extend([text, KEY_SCOPE]); }\n\n"
                           + I01B3_TOP),
      (_ANSWER, I01B3_LIST_PUSH, "                push(&mut list, text);\n"))),
)
I01B3_TEXT_FUNCTIONS = {"(t1)": "answer_texts_t1_pins", "(t2)": "answer_texts_t2_set",
                        "(t3)": "answer_texts_t3_no_other_string", "(t4)": "answer_texts_t4_routes",
                        "(t5)": "answer_texts_t5_positions", "(t6)": "answer_texts_t6_key_prefixed",
                        "(t7)": "answer_texts_t7_no_static", "(t8)": "answer_texts_t8_calls_only",
                        "(t9)": "answer_texts_t9_no_str_alias", "(t10)": "answer_texts_t10_refusals_no_return"}


def i01b3_answer_tree(changes=()):
    """I01B3_ANSWER_TREE with each (file, anchor, replacement) applied in order; each anchor must occur once."""
    texts = dict(I01B3_ANSWER_TREE)
    for rel, old, new in changes:
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


class I01b3AnswerTreeTests(Tree):
    """The shared fixture of HE-004-I01B3's G-I01B-9 and G-I01B-8 rows (a copy of the real i01_answer.rs, i01_digest.rs
    and definitions.json, with small observe.rs, client.rs and i01_service.rs)."""

    TREE = I01B3_ANSWER_TREE

    def plant(self, changes):
        for rel, text in i01b3_answer_tree(changes).items():
            self.write(rel, text)

    def refuses_each(self, rows, check, rule):
        for label, clause, _, changes in rows:
            self.plant(changes)
            try:
                with self.assertRaisesRegex(gate.GateError, re.escape("(%s %s)" % (rule, clause)), msg=label):
                    check(self.base)
            finally:
                self.plant(())


class AnswerModuleRuleTests(I01b3AnswerTreeTests):
    """HE-004-I01B3 G-I01B-9, `Derived` closed (DESIGN-I01B3 rev 4 sections 4 and 8; DIB section 7.6): the fixture and the
    real sources pass, and each of I01B3_DERIVED_ROWS (DIB section 7.6's N2-8 and N2-8b, round 3's X9-1 in both files and
    X9-2..X9-4, round 1's forms (1), (2), (3a) and (3b), I3D-3's four rows, round 2's NEW-1, NEW-2, NEW-3 and NEW-10 with
    the (vi)-alone and (vii)-alone rows, and round 3's H6 and H7) refuses with its own sub-clause's message."""

    def test_the_fixture_and_the_real_sources_pass(self):
        self.assertEqual(len(gate.DERIVED_FIELDS), 13)
        self.assertEqual(gate.check_i01b_derived(self.base), 7)
        self.assertEqual(gate.check_i01b_derived(gate.HE), 7)

    def test_the_rows_and_their_stated_sets(self):
        self.assertEqual(len(I01B3_DERIVED_ROWS), 23)
        self.assertEqual(sorted(I01B3_DERIVED_FUNCTIONS), ["(i)", "(ii)", "(iii)", "(iv)", "(v)", "(vi)", "(vii)"])
        for label, clause, stated, _ in I01B3_DERIVED_ROWS:
            self.assertEqual(stated[0], clause, label)
            self.assertTrue(set(stated) <= set(I01B3_DERIVED_FUNCTIONS), label)
            self.assertTrue(callable(getattr(gate, I01B3_DERIVED_FUNCTIONS[clause])), label)

    def test_each_row_refuses_with_its_own_sub_clause_s_message(self):
        self.refuses_each(I01B3_DERIVED_ROWS, gate.check_i01b_derived, "Derived closed, G-I01B-9")


class I01b3TextTests(I01b3AnswerTreeTests):
    """HE-004-I01B3 G-I01B-8's I01B3 checks (DESIGN-I01B3 rev 4 sections 5 and 8; I3E-3, I3F-1..3): the fixture and the
    real sources pass, pinned_constant reads a text in its `&str` form, and each of I01B3_TEXT_ROWS ((t1) a changed VPO
    text, a missing citation, a key const holding an invented value; (t2) an unlisted R10 text, a second const with a
    text's value, a key const equal to a text, a fn-local const, a `&'static str` const outside the lists, a pinned line
    inside a block comment with the name redefined; (t3) a bare literal and raw, byte and C strings; (t4) stringify!,
    file!() and module_path!(); (t5) Default::default(), a slice of a pinned const, an I01B1 non-refusal text, and a
    KEY_ const through the rule function, map_err, ok_or_else(move ||) and a braced argument; (t6) a key-prefixed
    literal; (t7) a static aliasing a key const and a fn-local static shadowing a pinned name; U3's const array of key
    consts, (t2)'s since R1-2 (a); and PR review round 1's H8-1 .. H8-10: (t5) the Err, ok_or and map_err turbofish, a fn
    item as map_err's argument and refusals' list via Vec::push and extend; (t8) Err and the rule helper as function
    values; (t2) a lower-case const typed &(str); (t9) one typed through a type alias of str; and PR review round 2's
    N-10 and N-10b, a const fn and a pub const fn as ok_or_else's argument, (t5); M-1 and M-1b, an early return of
    vec! and Vec::from from refusals, (t10); M-2, a module fn push given refusals' list, (t5)) refuses with its own
    check's message."""

    def test_the_fixture_and_the_real_sources_pass(self):
        self.assertEqual((len(gate.I01B3_TEXT_PINS), len(gate.I01B3_KEY_CONSTS)), (17, 37))
        self.assertEqual(gate.check_i01b3_texts(self.base), 54)
        self.assertEqual(gate.check_i01b3_texts(gate.HE), 54)
        self.assertEqual(gate.answer_texts_t5_positions(self.base, "G-I01B-8"),
                         gate.answer_texts_t5_positions(gate.HE, "G-I01B-8"))
        # The 17 texts: the 14 VPO labels and generic text, cited by line, and the three R10 texts, cited to MODEL_DEFINED.
        self.assertEqual(sum(citation.startswith("scripts/validate_policy_observation.py:")
                             for _, _, citation in gate.I01B3_TEXT_PINS), 14)
        self.assertEqual([name for name, _, citation in gate.I01B3_TEXT_PINS if citation == gate.R10_CITATION],
                         list(gate.I01B3_R10_TEXTS))

    def test_pinned_constant_reads_a_text(self):
        value, _, _ = gate.pinned_constant(self.base, gate.I01_ANSWER, "KEY_UID", "&str", gate.STR_FORM, "a rule")
        self.assertEqual(value, "uid")
        # The &str form: no escape, quote, tab, non-ASCII letter or DEL.
        for value in ("u\\x41", 'u\\"', "u\tid", "ué", "u\x7f"):
            self.plant(((gate.I01_ANSWER, I01B3_KEY_UID, 'pub const KEY_UID: &str = "%s";\n' % value),))
            with self.assertRaisesRegex(gate.GateError, "does not define KEY_UID exactly once"):
                gate.pinned_constant(self.base, gate.I01_ANSWER, "KEY_UID", "&str", gate.STR_FORM, "a rule")
        self.plant(())

    def test_the_rows(self):
        self.assertEqual(len(I01B3_TEXT_ROWS), 46)
        self.assertEqual(sorted({clause for _, clause, _, _ in I01B3_TEXT_ROWS}), sorted(I01B3_TEXT_FUNCTIONS))
        self.assertEqual([label.split()[0] for label, _, _, _ in I01B3_TEXT_ROWS[-15:-5]],
                         ["H8-%d" % number for number in range(1, 11)])
        self.assertEqual([label.split()[0] for label, _, _, _ in I01B3_TEXT_ROWS[-5:]],
                         ["N-10", "N-10b", "M-1", "M-1b", "M-2"])

    def test_each_row_refuses_with_its_own_check_s_message(self):
        self.refuses_each(I01B3_TEXT_ROWS, gate.check_i01b3_texts, "constants and texts, G-I01B-8")

    def test_the_record_s_hunted_spellings_refuse_too(self):
        # PR review round 1's huntedForms spell H8-1, H8-2 and H8-4 with KEY_X; the rows plant its findings' spellings.
        for text, clause in (("        return Err::<_, _>(KEY_X);\n", "(t5)"),
                             ("        let _ = utc_text(now).ok_or::<_>(KEY_X)?;\n", "(t5)"),
                             ("        Some(KEY_X).map_or(Ok(()), Err)?;\n", "(t8)")):
            self.plant(((gate.I01_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n" + text + "    }\n" + I01B3_IN_ANSWER),))
            try:
                with self.assertRaisesRegex(gate.GateError, re.escape("(constants and texts, G-I01B-8 %s)" % clause),
                                            msg=text):
                    gate.check_i01b3_texts(self.base)
            finally:
                self.plant(())

    def test_call_opening_reads_an_optional_turbofish(self):
        # R1-1 (a): the `(` past whitespace and a balanced turbofish; none when the word is not called.
        for code in ("Err(x)", "Err (x)", "Err::<_, _>(x)", "Err::<Vec<Vec<u8>>, &'static str>(x)",
                     "Err::<fn(u8) -> u8, ()>(x)", "Err:: < u8 > (x)"):
            self.assertEqual(code[gate.call_opening(code, 3):], "(x)", code)
        for code in ("Err)", "Err, y", "Err::new(x)", "Err::<u8; (x)", "Err::<u8 { (x)", "Err::<u8"):
            self.assertIsNone(gate.call_opening(code, 3), code)

    def test_refusals_list_is_named_only_at_its_receivers(self):
        # R1-1 (c), tightened by R2-3: inside fn refusals the list is named only at its declaration, its tail and the
        # .push( and .contains( receivers. Its .extend( and .insert( (even with a binding), Vec::push(&mut list, ..), a
        # helper taking &mut list, any other naming, a second declaration or another tail refuse, each with (t5)'s
        # message; .extend( and .insert( outside refusals stay legal, as the real file's traversal and objects use them.
        _, _, code = gate.answer_source(gate.HE, "G-I01B-8")
        self.assertIsNone(gate.refusals_list_names(code, "G-I01B-8"))
        self.assertIn(".extend(", code)
        self.assertIn(".insert(", code)
        for old, new in ((I01B3_LIST_LET, I01B3_LIST_LET + "    list.insert(0, text_of_nothing);\n"),
                         (I01B3_LIST_LET, I01B3_LIST_LET + "    let more = Vec::new();\n    list.extend(more);\n"),
                         (I01B3_LIST_LET, I01B3_LIST_LET + "    Vec::push(&mut list, text_of_nothing);\n"),
                         (I01B3_LIST_LET, I01B3_LIST_LET + "    list.push(text_of_nothing);\n    list[0] = KEY_SCOPE;\n"),
                         (I01B3_LIST_LET, I01B3_LIST_LET + "    grow(&mut list);\n"),
                         (I01B3_LIST_LET, I01B3_LIST_LET + "    let list = vec![KEY_SCOPE];\n"),
                         (I01B3_LIST_LET, I01B3_LIST_LET + I01B3_LIST_LET),
                         (I01B3_LIST_TAIL, "    vec![KEY_SCOPE]\n}\n")):
            self.plant(((gate.I01_ANSWER, old, new),))
            try:
                with self.assertRaisesRegex(gate.GateError, re.escape("(constants and texts, G-I01B-8 (t5))"), msg=new):
                    gate.check_i01b3_texts(self.base)
            finally:
                self.plant(())
        # Its .contains( and .push( with a binding pass, as the real refusals writes and reads it.
        self.plant(((gate.I01_ANSWER, I01B3_LIST_LET, I01B3_LIST_LET + "    if !list.contains(&KEY_SCOPE) {\n"
                                                                       "        list.push(text_of_nothing);\n    }\n"),))
        self.assertEqual(gate.check_i01b3_texts(self.base), 54)
        self.plant(())


# HE-004-I01B5 U1 (DESIGN-I01B5 rev 5 sections 6.6, 6.7 and 8): R1-1's two G-I01B-4 clauses (I01B2's HUNT-22 carry,
# closed gate-side; config.rs's bytes and pin unchanged) and the carries from HE-004-I01B3 (R3-1's row, round 3's NOTE
# rows). Each row: (label, named sub-clause, stated set or None, ((file, anchor, replacement), ..)). The build's mutation
# proof reads these tables, records each row's actual refusing set and runs the single-clause or each-alone proof.
I01B5_CONSTRUCTOR_FUNCTIONS = {"(a)": "constructor_a_from_config", "(b)": "constructor_b_wiring", **I01B2_CLAUSE_FUNCTIONS,
                               "(c)": "constructor_c_accessor", "(c5)": "constructor_c5_binding_fields"}
I01B5_LITERAL = "binding: Value::Null, sealed: None"
I01B5_NAMESPACE_LET = '        let namespace = text(root, "qualificationNamespace", "the document")?;\n'
I01B5_CONSTRUCTOR_ROWS = (
    # (c) tightened [R1-1]: `binding: Value::Null` only as the literal's own top-level initialiser (I01B2 PR review
    # round 1's HUNT-22 and HUNT-24).
    ("HUNT-22 (c): the own binding forged, a W { binding: Value::Null } nested in another field", "(c)", ("(c)",),
     ((_CONFIG, I01B5_LITERAL, "binding: forged(), sealed: crate::wrap::seal(crate::wrap::W { binding: Value::Null })"),)),
    ("HUNT-24 (c): binding: Value::Null.forged()", "(c)", ("(c)",),
     ((_CONFIG, I01B5_LITERAL, "binding: Value::Null.forged(), sealed: None"),)),
    ("R1-1 (c): the shorthand binding", "(c)", ("(c)",),
     ((_CONFIG, I01B5_NAMESPACE_LET, I01B5_NAMESPACE_LET + "        let binding = forged();\n"),
      (_CONFIG, I01B5_LITERAL, "binding, sealed: None"))),
    # (c5) I2E-7 as a gate check [R1-1; HUNT-22; I5D-10].
    ("HUNT-22 (c5): struct W { binding: Value }", "(c5)", ("(c5)",),
     ((_CONFIG, I01B2_USE, I01B2_USE + "\nstruct W {\n    binding: Value,\n}\n"),)),
    ("I5D-10 (c5): an enum variant's binding field", "(c5)", ("(c5)",),
     ((_CONFIG, I01B2_USE, I01B2_USE + "\nenum Hidden {\n    Carry { binding: Value },\n}\n"),)),
    ("(c5): a union's binding field", "(c5)", ("(c5)",),
     ((_CONFIG, I01B2_USE, I01B2_USE + "\nunion Raw {\n    binding: std::mem::ManuallyDrop<Value>,\n}\n"),)),
    # HUNT-22 whole: both clauses refuse it, each alone.
    ("HUNT-22 whole: W declared, its literal nested, the own binding forged", "(c)", ("(c)", "(c5)"),
     ((_CONFIG, I01B2_USE, I01B2_USE + "\nstruct W {\n    binding: Value,\n}\n"),
      (_CONFIG, I01B5_LITERAL, "binding: forged(), sealed: seal(W { binding: Value::Null })"))),
)
I01B5_STEP_TWO_LINE = "    if let Some(&refusal) = refusals(derived, facts).first() {\n"
I01B5_TEXT_FUNCTIONS = {**I01B3_TEXT_FUNCTIONS, "(t11)": "answer_texts_t11_step_two"}
I01B5_TEXT_ROWS = (
    # R3-1 [HE-004-I01B3 PR review round 3, carried]: a key text fed in at the answer list's consumer, without a local.
    ("R3-1 S1 .first().or(Some(&KEY_SCOPE))", "(t11)", None,
     ((_ANSWER, I01B5_STEP_TWO_LINE, "    if let Some(&refusal) = refusals(derived, facts).first().or(Some(&KEY_SCOPE)) {\n"),)),
    ("R3-1 S2 .iter().chain(&[KEY_SCOPE]).next()", "(t11)", None,
     ((_ANSWER, I01B5_STEP_TWO_LINE,
       "    if let Some(&refusal) = refusals(derived, facts).iter().chain(&[KEY_SCOPE]).next() {\n"),)),
    ("(t11) a second refusals( call", "(t11)", None,
     ((_ANSWER, I01B5_STEP_TWO_LINE, "    let _again = refusals(derived, facts);\n" + I01B5_STEP_TWO_LINE),)),
    ("(t11) refusals as a fn item", "(t11)", None,
     ((_ANSWER, I01B5_STEP_TWO_LINE, "    let _list = refusals;\n" + I01B5_STEP_TWO_LINE),)),
    # Round 3's NOTE [R2-1's two changes]: a row that only the item reading refuses, and one that only ok_or_else's
    # closure-only rule refuses (N-10 and N-10b are refused by each).
    ("R2-1 item reading alone: a const fn at Err(", "(t5)", None,
     ((_ANSWER, I01B3_TOP, "const fn scope_text() -> &'static str { KEY_SCOPE }\n\n" + I01B3_TOP),
      (_ANSWER, I01B3_IN_ANSWER, "    if wall_ms == 1 {\n        return Err(scope_text);\n    }\n" + I01B3_IN_ANSWER))),
    ("R2-1 closure-only alone: a local closure as ok_or_else's argument", "(t5)", None,
     ((_ANSWER, I01B3_IN_ANSWER, "    let pick = || KEY_SCOPE;\n    let _ = utc_text(now).ok_or_else(pick)?;\n"
                                 + I01B3_IN_ANSWER),)),
)
# R2-1's two changes, each undone alone (the proof's and the self-test's isolation): the item reading emptied, and
# ok_or_else taken out of the closure-only words.
I01B5_R2_1_UNDO = {"item reading": ("answer_item_names", lambda code: set()),
                   "closure-only": ("I01B3_CLOSURE_ONLY", ("map_err",))}
I01B5_R2_1_ROWS = {"R2-1 item reading alone: a const fn at Err(": "item reading",
                   "R2-1 closure-only alone: a local closure as ok_or_else's argument": "closure-only"}
# R2-4 [HE-004-I01B3 PR review round 3, carried]: const generic parameters, after `<` and after `,`, that (t2) skips.
I01B5_GENERIC_CONSTS = ("pub fn pick<const N: usize>(texts: [&'static str; N]) -> &'static str {\n    texts[0]\n}\n\n",
                        "pub fn pick<T: Copy, const N: usize>(texts: [&'static str; N], _t: T) -> &'static str {\n"
                        "    texts[0]\n}\n\n")


class I01b5ConstructorTests(Tree):
    """HE-004-I01B5 U1, R1-1 (DESIGN-I01B5 rev 5 sections 6.6 and 8; I01B2's HUNT-22 carry, gate-side only): G-I01B-4
    (c), tightened so that `binding: Value::Null` counts only as the ObserverConfig literal's own top-level initialiser,
    and (c5), I2E-7's "no other binding field in config.rs" over every struct, enum and union body [I5D-10]. Both accept
    the fixture and today's config.rs (bytes and pin unchanged); each of I01B5_CONSTRUCTOR_ROWS (HUNT-22's nested
    literal, HUNT-24's longer initialiser and a shorthand under (c); HUNT-22's struct W, an enum variant's field and a
    union's field under (c5); HUNT-22 whole under both) refuses with its own sub-clause's message."""

    TREE = I01B2_TREE

    def plant(self, changes):
        for rel, text in i01b2_tree(changes).items():
            self.write(rel, text)

    def test_both_clauses_accept_the_fixture_and_today_s_config_rs(self):
        rule = "one constructor call, G-I01B-4"
        for base in (self.base, gate.HE):
            codes = gate.observer_code(base, rule)
            self.assertIsNone(gate.constructor_c_accessor(codes, rule))
            self.assertIsNone(gate.constructor_c5_binding_fields(codes, rule))
        self.assertEqual(gate.check_i01b_constructor(gate.HE), 14)
        self.assertEqual(hashlib.sha256((gate.HE / gate.I01B2_CONFIG).read_bytes()).hexdigest(),
                         gate.I01B_GUARDED_PINS[gate.I01B2_CONFIG])
        # Today's literal: exactly one top-level binding field, `binding: Value::Null`.
        code = gate.observer_code(gate.HE, rule)[gate.I01B2_CONFIG]
        literal = [found for found in gate.OBSERVER_CONFIG_LITERAL.finditer(code)][-1]
        fields = gate.literal_fields(code, literal.end() - 1)
        self.assertEqual([field for field in fields if field.startswith("binding")], ["binding: Value::Null"])

    def test_the_rows_and_their_stated_sets(self):
        self.assertEqual(len(I01B5_CONSTRUCTOR_ROWS), 7)
        self.assertEqual(len(I01B5_CONSTRUCTOR_FUNCTIONS), 14)
        for label, clause, stated, _ in I01B5_CONSTRUCTOR_ROWS:
            self.assertEqual(stated[0], clause, label)
            self.assertTrue(set(stated) <= set(I01B5_CONSTRUCTOR_FUNCTIONS), label)
        for function in I01B5_CONSTRUCTOR_FUNCTIONS.values():
            self.assertTrue(callable(getattr(gate, function)), function)

    def test_each_row_refuses_with_its_own_sub_clause_s_message(self):
        for label, clause, _, changes in I01B5_CONSTRUCTOR_ROWS:
            self.plant(changes)
            try:
                with self.assertRaisesRegex(gate.GateError, re.escape("(one constructor call, G-I01B-4 %s" % clause),
                                            msg=label):
                    gate.check_i01b_constructor(self.base)
            finally:
                self.plant(())

    def test_the_literal_s_top_level_fields(self):
        code = "x = S { a: f(b, c), binding: W { binding: Value::Null }, d: [1, 2], e }"
        self.assertEqual(gate.literal_fields(code, code.index("{")),
                         ["a: f(b, c)", "binding: W { binding: Value::Null }", "d: [1, 2]", "e"])


class I01b5TextTests(I01b3AnswerTreeTests):
    """HE-004-I01B5 U1, the carries from HE-004-I01B3 (DESIGN-I01B5 rev 5 sections 6.7 and 8): (t11), R3-1's row,
    reads answer's step 2 exactly and refuses S1, S2, a second refusals( call and a fn-item reference; R2-1's two
    changes each have a row that only it refuses (the item reading, the closure-only rule); and (t2) skips a const
    generic parameter (R2-4), which without the skip it refuses (fail-closed)."""

    def test_the_fixture_and_the_real_sources_pass(self):
        self.assertEqual(I01B3_ANSWER_TEXT.count(I01B5_STEP_TWO_LINE), 1)
        self.assertEqual(gate.check_i01b3_texts(self.base), 54)
        self.assertEqual(gate.check_i01b3_texts(gate.HE), 54)
        self.assertIsNone(gate.answer_texts_t11_step_two(gate.HE, "constants and texts, G-I01B-8"))

    def test_the_rows(self):
        self.assertEqual(len(I01B5_TEXT_ROWS), 6)
        self.assertEqual(sorted(I01B5_TEXT_FUNCTIONS), sorted(list(I01B3_TEXT_FUNCTIONS) + ["(t11)"]))
        for _, clause, _, _ in I01B5_TEXT_ROWS:
            self.assertTrue(callable(getattr(gate, I01B5_TEXT_FUNCTIONS[clause])), clause)

    def test_each_row_refuses_with_its_own_check_s_message(self):
        self.refuses_each(I01B5_TEXT_ROWS, gate.check_i01b3_texts, "constants and texts, G-I01B-8")

    def test_r2_1_s_two_changes_each_have_a_row_only_it_refuses(self):
        rows = {label: changes for label, _, _, changes in I01B5_TEXT_ROWS}
        for label, own in I01B5_R2_1_ROWS.items():
            self.plant(rows[label])
            try:
                for change, (name, undone) in I01B5_R2_1_UNDO.items():
                    with mock.patch.object(gate, name, undone):
                        if change == own:
                            self.assertEqual(gate.check_i01b3_texts(self.base), 54, label)
                        else:
                            with self.assertRaisesRegex(gate.GateError, re.escape("(constants and texts, G-I01B-8 (t5))"),
                                                        msg=label):
                                gate.check_i01b3_texts(self.base)
            finally:
                self.plant(())

    def test_r2_4_a_const_generic_parameter_is_skipped(self):
        for planted in I01B5_GENERIC_CONSTS:
            self.plant(((gate.I01_ANSWER, I01B3_TOP, planted + I01B3_TOP),))
            try:
                self.assertEqual(gate.check_i01b3_texts(self.base), 54, planted)
                with mock.patch.object(gate, "generic_parameter", lambda code, position: False):
                    with self.assertRaisesRegex(gate.GateError, re.escape("(constants and texts, G-I01B-8 (t2))"),
                                                msg=planted):
                        gate.check_i01b3_texts(self.base)
            finally:
                self.plant(())
        for code, expected in (("fn f<const N: usize>()", True), ("fn f<T, const N: usize>()", True),
                               ("fn f<F: Fn(u8) -> u8, const N: usize>()", True), ("pub const X: &str = KEY;", False),
                               ("{ const X: u8 = 1; }", False), ("f(a, const X: u8)", False), ("a < b; const X: u8", False)):
            self.assertEqual(gate.generic_parameter(code, code.index("const")), expected, code)


# HE-004-I01B5 U4 (DESIGN-I01B5 rev 5 sections 6 and 8): the rules over a fixture of the real observer sources (and
# effect-gate's lib.rs and two socket files), each row planted by (file, anchor, replacement) on the real bytes. Each
# row: (label, named sub-clause, stated set or None, changes[, the message it is refused with, when that is another
# rule's]). The build's mutation proof reads these tables (I01B5_PROOF_RULES), records each row's actual refusing set and
# runs the single-clause or each-alone proof.
I01B5_TREE = {**{path.relative_to(gate.HE).as_posix(): path.read_text(encoding="utf-8")
                 for path in sorted((gate.HE / gate.OBSERVER_CRATE / "src").rglob("*.rs"))},
              **{rel: (gate.HE / rel).read_text(encoding="utf-8")
                 for rel in (gate.EFFECT_GATE_LIB, gate.LINUX_OS, "crates/effect-gate/src/linux_net.rs")},
              # HE-005A: the broker's real sources, its linux_listen.rs the fifth socket file the socket-module rule
              # requires.
              **{path.relative_to(gate.HE).as_posix(): path.read_text(encoding="utf-8")
                 for path in sorted((gate.HE / gate.BROKER_CRATE / "src").rglob("*.rs"))}}
_OBS, _CLI, _SRV = gate.OBSERVER_OBSERVE, gate.OBSERVER_CLIENT, gate.OBSERVER_SERVICE
_NET, _LST, _EGN = gate.OBSERVER_LINUX_NET, gate.OBSERVER_LINUX_LISTEN, "crates/effect-gate/src/linux_net.rs"
I01B5_SELF_CHECK_TEXT = re.search(r"        let observation = match ::std::str.*?\n        \};\n", I01B5_TREE[_SRV], re.S).group(0)
I01B5_SEND_TEXT = re.search(r"        match ops\.peer_send\(.*?\n        \}\n", I01B5_TREE[_SRV], re.S).group(0)
I01B5_ANSWER_LINE = ("        let bytes = match crate::i01_answer::answer(derived, &checked, &facts, wall_ms, "
                     "session.last_observed) {\n")
I01B5_RESPOND_TAIL = "            PeerSent::Failed(_) => return Some(Closed::NotServed),\n        }\n        None\n"
I01B5_RESPOND_CALL_LINE = ("        let closed = if self.ready(&session, now) { self.respond(ops, &mut session, wall_ms, now) } "
                           "else { None };\n")
I01B5_FRESHNESS_LINES = ("        if now >= after(received, I01_EXCHANGE_DEADLINE) || now >= session.outer {\n"
                         "            return Some(Closed::NotServed);\n        }\n")
I01B5_CLOCK_LINE = "        let wall_ms = match wall_ms { Some(ms) => ms, None => return Some(Closed::Window) };\n"
I01B5_WOKE = "        session.woke = now;\n"
I01B5_END = "        ops.peer_close(peer);\n"
I01B5_SERVICE_TAIL = "        None\n    }\n}\n\nimpl PeerService for I01Service {\n"
I01B5_DRAINS_DOC = "    /// The poll count of each drain so far (the tests' reading).\n"
I01B5_PASSED_LINE = "                let passed = self.request_round.take()\n"
I01B5_PUSH_PASSED = "                self.client.push_availability(Availability { phase: self.phase, established, fresh,\n"
I01B5_SEND_FUNCTIONS = {"(a)": "send_a_peer_send", "(b)": "send_b_send_answer", "(c)": "send_c_channel_send",
                        "(d)": "send_d_use_paths", "(e)": "send_e_peer_ops", "(f)": "send_f_respond",
                        "(g)": "send_g_readable", "(h)": "send_h_deadlines_call", "(i)": "send_i_chain"}
I01B5_SEND_ROWS = (
    # (a) [DIB 7.3 P5-1; I5D-7].
    ("P5-1 a second ops.peer_send call", "(a)", None,
     ((_SRV, I01B5_END, I01B5_END + "        let _ = ops.peer_send(peer, &[]);\n"),)),
    ("P5-1 UFCS PeerOps::peer_send(ops, ..)", "(a)", None,
     ((_SRV, I01B5_END, I01B5_END + "        let _ = PeerOps::peer_send(ops, peer, &[]);\n"),)),
    ("P5-1 the call moved to i01_answer.rs", "(a)", None,
     ((gate.I01_ANSWER, "pub fn self_check(", "pub fn send(ops: &mut dyn PeerOps, peer: PeerId, bytes: &[u8]) -> PeerSent "
       "{\n    ops.peer_send(peer, bytes)\n}\n\npub fn self_check("),
      (_SRV, "        match ops.peer_send(session.peer, &bytes) {\n",
       "        match crate::i01_answer::send(ops, session.peer, &bytes) {\n"))),
    ("I5D-7 a default peer_send body", "(a)", None,
     ((_CLI, "    fn peer_send(&mut self, peer: PeerId, bytes: &[u8]) -> PeerSent;\n",
       "    fn peer_send(&mut self, peer: PeerId, bytes: &[u8]) -> PeerSent {\n        let _ = (peer, bytes);\n"
       "        PeerSent::Sent\n    }\n"),)),
    # (b) [DIB 7.3's extra; I5D-7].
    ("extra: a second send_answer call in another LinuxWire method", "(b)", None,
     ((_NET, "impl PeerOps for LinuxWire {\n", "impl LinuxWire {\n    fn again(&self, peer: PeerId) -> PeerSent {\n"
       "        self.i01.send_answer(peer, b\"\")\n    }\n}\n\nimpl PeerOps for LinuxWire {\n"),)),
    ("I5D-7 a loop in send_answer", "(b)", None,
     ((_LST, "        match channel::send(&held.conn, bytes) {\n",
       "        match loop { break channel::send(&held.conn, bytes); } {\n"),)),
    ("I5D-7 changed bytes in send_answer", "(b)", None,
     ((_LST, "        match channel::send(&held.conn, bytes) {\n", "        match channel::send(&held.conn, &bytes[1..]) {\n"),)),
    # (c) [DIB 7.3 P5-2, P5-4; G-I01-5's three channel::send spellings, kept as rows here].
    ("P5-2 a second channel::send( in linux_net.rs", "(c)", None,
     ((_NET, "use crate::linux_listen::I01Socket;\n", "use crate::linux_listen::I01Socket;\n\n"
       "fn leak(c: &channel::Conn) {\n    let _ = channel::send(c, b\"x\");\n}\n"),)),
    ("P5-4 a fn-item reference", "(c)", None,
     ((_LST, "    /// Closes the held peer and everything kept for it (the close also takes it off the poller).\n",
       "    pub(crate) fn sender(&self) {\n        let _s = channel::send;\n    }\n\n"
       "    /// Closes the held peer and everything kept for it (the close also takes it off the poller).\n"),)),
    ("G-I01-5's spelling gate_sys :: channel :: send(", "(c)", None,
     ((_LST, "    /// Closes the held peer and everything kept for it (the close also takes it off the poller).\n",
       "    pub(crate) fn again(&self, c: &channel::Conn) {\n        let _ = gate_sys :: channel :: send(c, b\"x\");\n"
       "    }\n\n    /// Closes the held peer and everything kept for it (the close also takes it off the poller).\n"),)),
    ("G-I01-5's spelling ::gate_sys::channel::send(", "(c)", None,
     ((_LST, "    /// Closes the held peer and everything kept for it (the close also takes it off the poller).\n",
       "    pub(crate) fn again(&self, c: &channel::Conn) {\n        let _ = ::gate_sys::channel::send(c, b\"x\");\n"
       "    }\n\n    /// Closes the held peer and everything kept for it (the close also takes it off the poller).\n"),)),
    # (d) [DIB 7.3 P5-3, P5-5; the backstops].
    ("P5-3 a renamed channel", "(d)", None,
     ((_LST, "use gate_sys::channel::{self, ListenStep};\n", "use gate_sys::channel::{self, ListenStep};\n"
       "use gate_sys::channel as c;\n\nfn leak(x: &c::Conn) {\n    let _ = c::send(x, b\"x\");\n}\n"),)),
    # DIB 7.3 names (d) (and G-I01B-6 (d)); its `use super::channel::send;` is also a channel::send path, which (c),
    # run first, counts: the set is {(c), (d)}, each refusing alone.
    ("P5-5 a nested module", "(c)", ("(c)", "(d)"),
     ((_LST, "use gate_sys::channel::{self, ListenStep};\n", "use gate_sys::channel::{self, ListenStep};\n"
       "mod inner {\n    use super::channel::send;\n}\n"),)),
    ("(d) a glob import", "(d)", None,
     ((_LST, "use gate_sys::channel::{self, ListenStep};\n", "use gate_sys::channel::{self, ListenStep};\n"
       "use gate_sys::peer_wire::*;\n"),)),
    # (e) [DIB 7.3's extra; X5-1..X5-3; I5D-9].
    ("extra: a push taking PeerOps", "(e)", None,
     ((_CLI, "    fn peer_capture_view(&mut self, gate: CaptureGate);\n",
       "    fn peer_capture_view(&mut self, gate: CaptureGate, ops: &mut dyn PeerOps);\n"),)),
    ("X5-1 pub type Ops = dyn PeerOps;, a push taking it", "(e)", None,
     ((_CLI, "pub trait PeerService {\n", "pub type Ops = dyn PeerOps;\n\npub trait PeerService {\n"),
      (_CLI, "    fn peer_capture_view(&mut self, gate: CaptureGate);\n",
       "    fn peer_capture_view(&mut self, gate: CaptureGate, ops: &mut Ops);\n"))),
    ("X5-2 use self::PeerOps as P;, a push taking it", "(e)", None,
     ((_CLI, "pub trait PeerService {\n", "use self::PeerOps as P;\n\npub trait PeerService {\n"),
      (_CLI, "    fn peer_capture_view(&mut self, gate: CaptureGate);\n",
       "    fn peer_capture_view(&mut self, gate: CaptureGate, ops: &mut dyn P);\n"))),
    ("X5-3 pub trait Ops2: PeerOps {} with a blanket impl, a push taking it", "(e)", None,
     ((_CLI, "pub trait PeerService {\n", "pub trait Ops2: PeerOps {}\n\nimpl<T: PeerOps> Ops2 for T {}\n\n"
       "pub trait PeerService {\n"),
      (_CLI, "    fn peer_capture_view(&mut self, gate: CaptureGate);\n",
       "    fn peer_capture_view(&mut self, gate: CaptureGate, ops: &mut dyn Ops2);\n"))),
    ("I5D-9 trait X where Self: PeerOps", "(e)", None,
     ((_CLI, "pub trait PeerService {\n", "pub trait Hidden where Self: PeerOps {}\n\npub trait PeerService {\n"),)),
    # (f) [DIB 7.3 N2-3, N2-3b, N2-5, N2-5b and its extra; X5-4, X5-5; I5D-13 (ii); I5E-5, I5F-6].
    ("N2-3 the Ok arm yields other bytes", "(f)", None,
     ((_SRV, "            Ok(bytes) => bytes,\n", "            Ok(_) => self.buffer.clone(),\n"),)),
    ("N2-3 the bytes extended", "(f)", None,
     ((_SRV, "            Ok(bytes) => bytes,\n", "            Ok(mut bytes) => {\n                bytes.push(b' ');\n"
       "                bytes\n            }\n"),)),
    ("N2-3b PeerSent::Sent => {} (the chain not advanced)", "(f)", None,
     ((_SRV, "            PeerSent::Sent => session.sent(&checked, &bytes, observation, wall_ms),\n",
       "            PeerSent::Sent => {}\n"),)),
    ("N2-3b PeerSent::Failed(_) => {} (no close)", "(f)", None,
     ((_SRV, I01B5_RESPOND_TAIL, "            PeerSent::Failed(_) => {}\n        }\n        None\n"),)),
    ("extra: a statement between the answer and the self-check", "(f)", None,
     ((_SRV, I01B5_SELF_CHECK_TEXT, "        let _between = 0;\n" + I01B5_SELF_CHECK_TEXT),)),
    ("N2-5 the statements in a loop inside respond", "(f)", None,
     ((_SRV, I01B5_ANSWER_LINE, "        loop {\n" + I01B5_ANSWER_LINE),
      (_SRV, I01B5_RESPOND_TAIL, "            PeerSent::Failed(_) => return Some(Closed::NotServed),\n        }\n"
       "        break;\n        }\n        None\n"))),
    ("N2-5b a second respond call", "(f)", None,
     ((_SRV, I01B5_RESPOND_CALL_LINE, I01B5_RESPOND_CALL_LINE
       + "        let _again = self.respond(ops, &mut session, wall_ms, now);\n"),)),
    ("X5-4 a second trait Kick reached through PeerService, kick calling respond", "(f)", None,
     ((_CLI, "pub trait PeerService {\n", "pub trait Kick {\n    fn kick(&mut self, ops: &mut dyn PeerOps);\n}\n\n"
       "pub trait PeerService {\n    fn kicker(&mut self) -> Option<&mut dyn Kick>;\n"),
      (_SRV, "impl PeerService for I01Service {\n", "impl crate::client::Kick for I01Service {\n"
       "    fn kick(&mut self, ops: &mut dyn PeerOps) {\n        let Some(mut session) = self.session.take() else { return };\n"
       "        let _ = self.respond(ops, &mut session, None, Instant::now());\n    }\n}\n\n"
       "impl PeerService for I01Service {\n"))),
    ("X5-5 let r = Self::respond;", "(f)", None,
     ((_SRV, I01B5_RESPOND_CALL_LINE, "        let _r = Self::respond;\n" + I01B5_RESPOND_CALL_LINE),)),
    ("I5D-13 (ii) the self-check statement altered (no previous)", "(f)", None,
     ((_SRV, "wall_ms / 1000, session.previous.as_ref()) {", "wall_ms / 1000, None) {"),)),
    ("I5D-13 (ii) the self-check statement moved after the send", "(f)", None,
     ((_SRV, I01B5_SELF_CHECK_TEXT + I01B5_SEND_TEXT, I01B5_SEND_TEXT + I01B5_SELF_CHECK_TEXT),)),
    ("I5E-5 a use .. as json rename reaching the self-check", "(f)", None,
     ((_SRV, "use i05_protocol::json::Value;\n", "use i05_protocol::json::Value;\nuse crate::i01_request as json;\n"),
      (_SRV, "::i05_protocol::json::parse(text)", "json::parse(text)"))),
    ("I5F-6 a std rename reaching the self-check", "(f)", None,
     ((_SRV, "use i05_protocol::json::Value;\n", "use i05_protocol::json::Value;\nuse crate::i01_request as std;\n"),
      (_SRV, "::std::str::from_utf8(&bytes)", "std::str::from_utf8(&bytes)"))),
    # (g) [F6.10].
    ("(g) a write interest on the I01 listener", "(g)", None,
     ((_NET, "                self.poller.add(self.i01.watched_listener(), LISTENER_TOKEN, readable)\n",
       "                self.poller.add(self.i01.watched_listener(), LISTENER_TOKEN, channel::Interest { readable: true, "
       "writable: true })\n"),)),
    ("(g) readable rebound", "(g)", None,
     ((_NET, "    fn watch_i01(&mut self, peers: PeerWatch, woken: &mut Woken) {\n"
       "        let readable = channel::Interest { readable: true, writable: false };\n",
       "    fn watch_i01(&mut self, peers: PeerWatch, woken: &mut Woken) {\n"
       "        let readable = channel::Interest { readable: true, writable: peers.listener };\n"),)),
    # (h) [DIB 7.3 N2-4].
    ("N2-4 serve_peer_deadlines from a Client push", "(h)", None,
     ((_CLI, "    /// The attached service's pending request's receipt (the epoch's request-round trigger).\n",
       "    pub fn kick(&mut self) {\n        if let Some(service) = self.service.as_deref_mut() {\n"
       "            service.serve_peer_deadlines(&mut self.wire, None, self.wire.now());\n        }\n    }\n\n"
       "    /// The attached service's pending request's receipt (the epoch's request-round trigger).\n"),)),
    ("N2-4 PeerService::serve_peer_deadlines(..)", "(h)", None,
     ((_CLI, "    /// The attached service's pending request's receipt (the epoch's request-round trigger).\n",
       "    pub fn kick(&mut self, s: &mut dyn PeerService) {\n"
       "        PeerService::serve_peer_deadlines(s, &mut self.wire, None, self.wire.now());\n    }\n\n"
       "    /// The attached service's pending request's receipt (the epoch's request-round trigger).\n"),)),
    # (i) [I5D-8, I5E-4, I5F-5; E1-E5].
    ("I5D-8 let f = Chain::answered;", "(i)", None,
     ((_SRV, I01B5_END, I01B5_END + "        let _f = Chain::answered;\n"),)),
    ("I5D-8 a second .sent( call", "(i)", None,
     ((_SRV, I01B5_SERVICE_TAIL, "        session.sent(&checked, &bytes, observation, wall_ms);\n" + I01B5_SERVICE_TAIL),)),
    ("E1 session.chain = Chain::default();", "(i)", None,
     ((_SRV, I01B5_WOKE, I01B5_WOKE + "        session.chain = Chain::default();\n"),)),
    ("E2 std::mem::take(&mut session.chain)", "(i)", None,
     ((_SRV, I01B5_WOKE, I01B5_WOKE + "        let _ = std::mem::take(&mut session.chain);\n"),)),
    ("E3 session.previous = None;", "(i)", None,
     ((_SRV, I01B5_WOKE, I01B5_WOKE + "        session.previous = None;\n"),)),
    ("E4 session.previous.take();", "(i)", None,
     ((_SRV, I01B5_WOKE, I01B5_WOKE + "        session.previous.take();\n"),)),
    ("E5 std::mem::take(&mut session.last_observed)", "(i)", None,
     ((_SRV, I01B5_WOKE, I01B5_WOKE + "        let _ = std::mem::take(&mut session.last_observed);\n"),)),
)
I01B5_STATEMENT_FUNCTIONS = {"(s1)": "statements_s1_check_snapshot", "(s2)": "statements_s2_snapshot_literal",
                             "(s3)": "statements_s3_capture_push", "(s4)": "statements_s4_passed",
                             "(s5)": "statements_s5_round_start", "(s6)": "statements_s6_from_view",
                             "(s7)": "statements_s7_clock", "(s8)": "statements_s8_facts", "(s9)": "statements_s9_order"}
I01B5_FACTS_ROWS = (("completed: gate.scheduled.is_some(),", "completed: true,"),          # D-2
                    ("expired: gate.expired,", "expired: false,"),
                    ("scheduled_after_now: gate.scheduled > Some(now),", "scheduled_after_now: false,"),
                    ("slots: gate.slots.clone(),", "slots: Vec::new(),"),
                    ("mono_age_ms: gate.scheduled.filter(|at| *at <= now).map_or(0, |at| ms(now - at)),", "mono_age_ms: 0,"),
                    ("wall_age_ms: wall_ms as i64 - gate.set_started_ms as i64,", "wall_age_ms: 0,"),
                    ("record_digest: gate.record_digest.clone(),", "record_digest: String::new(),"))
I01B5_STATEMENT_ROWS = (
    # (s1) [B3-6 (1): D-1; I5E-2: A1; rev 5 and MON-I01B5-STOPS (ii)-(iv) as source forms; I5D-3].
    ("D-1 the quota Value from the binding's values", "(s1)", None,
     ((_OBS, '        let quota = object([("hard", Some(quota_side(&quotas.pairs, |pair| pair.hard))),\n',
       '        let quota = self.config.binding().clone();\n'
       '        let _unused = object([("hard", Some(quota_side(&quotas.pairs, |pair| pair.hard))),\n'),)),
    ("ADM-4 after the derive", "(s1)", None,
     ((_OBS, "        let (record, digest) = self.adm4(samples, window).map_err(Stop::Exit)?;\n", ""),
      (_OBS, "        drop(inputs);\n",
       "        let (record, digest) = self.adm4(samples, window).map_err(Stop::Exit)?;\n        drop(inputs);\n"))),
    ("A1 a statement between ADM-4's and the configuration Value", "(s1)", None,
     ((_OBS, "        let (record, digest) = self.adm4(samples, window).map_err(Stop::Exit)?;\n",
       "        let (record, digest) = self.adm4(samples, window).map_err(Stop::Exit)?;\n"
       "        let digest = String::from(\"sha256:00\");\n"),)),
    ("rev 5 (iv) a fourth sealedAdmission member", "(s1)", None,
     ((_OBS, '("ipFamily", Some(Value::str(&sealed.ip_family))),',
       '("ipFamily", Some(Value::str(&sealed.ip_family))), ("namespace", Some(Value::str(&self.config.namespace))),'),)),
    ("rev 5 (iv) a namespace member in place of ipFamily", "(s1)", None,
     ((_OBS, '("ipFamily", Some(Value::str(&sealed.ip_family))),',
       '("namespace", Some(Value::str(&sealed.ip_family))),'),)),
    ("rev 5 (ii)/(iii) the loaded hash taken from config", "(s1)", None,
     ((_OBS, "&record.loaded_hash().map_or(Value::Null, Value::str)", "&Value::str(&self.config.pinned_manifest_hash)"),)),
    ("the no-engine branch with another text", "(s1)", None,
     ((_OBS, "None => Err(NO_CAPTURE_ENGINE_TEXT),", "None => Err(\"no capture engine\"),"),)),
    ("I5D-12 the object helper adding a member", "(s1)", None,
     ((_OBS, "            built.insert(JStr::new(name), member);\n", "            built.insert(JStr::new(name), member);\n"
       "            built.insert(JStr::new(\"namespace\"), Value::Null);\n"),)),
    ("I5D-12 the quota helper reading one side for both", "(s1)", None,
     ((_OBS, "Value::Int(Int::from_u64(side(pair)))", "Value::Int(Int::from_u64(pair.hard))"),)),
    # (s2) [I5D-11].
    ("a changed SnapshotView initialiser", "(s2)", None,
     ((_OBS, "SnapshotView { phase: self.phase, mark, fresh_stamp: stamp, derived }",
       "SnapshotView { phase: self.phase, mark, fresh_stamp: self.client.now(), derived }"),)),
    # (s3) [I5D-4, I5E-3: the push reading a local].
    ("I5E-3 the expiry push reading a forged local", "(s3)", None,
     ((_OBS, "            captures.expire();\n", "            captures.expire();\n            let forged = forged_cycle();\n"),
      (_OBS, "            if let Some(captures) = self.captures.as_deref() {\n",
       "            if let Some(captures) = Some(&forged) {\n"))),
    # (s4) [I5E-3: a local round; Passed with started from another clock].
    ("I5E-3 a local round before Passed", "(s4)", None,
     ((_OBS, I01B5_PASSED_LINE, "                let mut round = self.request_round;\n"
       "                let passed = round.take()\n"),)),
    ("Passed with started from another clock", "(s4)", None,
     ((_OBS, "started: round.started", "started: self.client.now()"),)),
    # (s5) [I5F-2 (1)].
    ("I5F-2 (1) the round started from another clock", "(s5)", None,
     ((_OBS, "        let started = self.client.now();\n        self.request_round = Some(RequestRound {",
       "        let started = self.last_round_start.unwrap_or(self.client.now());\n"
       "        self.request_round = Some(RequestRound {"),)),
    # (s6) [I5D-4; I5E-7].
    ("I5E-7 a slot name swapped in from_view", "(s6)", None,
     ((_CLI, "CAPTURE_LIFECYCLE_SLOT.to_string()", "CAPTURE_BACKEND_SLOT_PREFIX.to_string()"),)),
    ("a CaptureGate slot true for a non-Taken variant", "(s6)", None,
     ((_CLI, "        let taken = |slot: &Slot| matches!(slot, Slot::Taken { .. });\n",
       "        let taken = |slot: &Slot| !matches!(slot, Slot::Free);\n"),)),
    # (s7) [I5E-6: a second clock reading; I5F-4: step 2 removed].
    ("I5E-6 a second clock reading", "(s7)", None, ((_SRV, I01B5_CLOCK_LINE, I01B5_CLOCK_LINE + I01B5_CLOCK_LINE),)),
    ("I5F-4 step 2 removed", "(s7)", None, ((_SRV, I01B5_FRESHNESS_LINES, ""),)),
    # (s8) [B3-6 (2), I3D-12: D-2 and each initialiser changed].
) + tuple(("B3-6 (2) %s" % ("D-2 completed: true" if new == "completed: true," else "the initialiser " + new), "(s8)",
           None, ((_SRV, "            %s\n" % old, "            %s\n" % new),)) for old, new in I01B5_FACTS_ROWS) + (
    # (s9) [I5F-4: the order swapped].
    ("I5F-4 the order swapped", "(s9)", None,
     ((_SRV, I01B5_RESPOND_CALL_LINE, ""),
      (_SRV, "        let closed = if !inside {\n", I01B5_RESPOND_CALL_LINE + "        let closed = if !inside {\n"))),
)
I01B5_FOLD_FUNCTIONS = {"I5F-1 (1)": "fold_1_snapshot_names", "I5F-1 (3)": "fold_1_snapshot_call",
                        "I5F-1 (4)": "fold_1_adm4_arm", "I5F-2 (2)": "fold_2_round_literals",
                        "I5F-2 (3)": "fold_2_request_round", "I5F-2 (4)": "fold_2_passed_names",
                        "I5F-3 (1)": "fold_3_capture_counts", "I5F-3 (2)": "fold_3_captures",
                        "I5F-3 (3)": "fold_3_capture_literals", "I5F-7": "fold_7_respond_clock",
                        "R1-1 (1)": "fold_r1_1_assignments", "R1-1 (2)": "fold_r1_1_borrows",
                        "R1-1 (3)": "fold_r1_1_exchanges"}
# PR review round 1's probes (R1-1, MON-I01B5-R1), planted at the head of fn start.
I01B5_START_LINE = "        let deadline = after(self.client.now(), OR07_BUDGET);\n"
I01B5_FOLD_ROWS = (
    ("A2 a shadowed inputs before the four statements", "I5F-1 (1)", None,
     ((_OBS, "        let quotas = match inputs.items(Resource::ResourceQuotas) {\n",
       "        let inputs = forged_inputs();\n        let quotas = match inputs.items(Resource::ResourceQuotas) {\n"),)),
    ("A3 a shadowed resource_version", "I5F-1 (1)", None,
     ((_OBS, "        let inputs = match Inputs::new(pairs) {\n",
       "        let resource_version = \"1\";\n        let inputs = match Inputs::new(pairs) {\n"),)),
    ("A4 a shadowed quotas between the quota statements", "I5F-1 (1)", None,
     ((_OBS, "        let quotas = match quotas {\n", "        let quotas = forged_quotas();\n        let quotas = match quotas {\n"),)),
    ("I5F-1 (3) a forged text at the call", "I5F-1 (3)", None,
     ((_OBS, "&resource_text, mark, stamp)?;", "\"1\", mark, stamp)?;"),)),
    ("I5F-1 (4) a config digest in adm4's Match arm", "I5F-1 (4)", None,
     ((_OBS, "                let digest = record.digest();\n",
       "                let digest = self.config.pinned_manifest_hash.clone();\n"),)),
    ("C5 a write to self.request_round before Passed", "I5F-2 (2)", None,
     ((_OBS, I01B5_PASSED_LINE, "                self.request_round = Some(RequestRound { started: self.client.now(), "
       "deadline: now, mark: Some(mark) });\n" + I01B5_PASSED_LINE),)),
    ("C6 the round's started rewritten", "I5F-2 (3)", None,
     ((_OBS, I01B5_PASSED_LINE, "                if let Some(round) = self.request_round.as_mut() { round.started = "
       "self.client.now(); }\n" + I01B5_PASSED_LINE),)),
    ("C7 a shadowed passed and a second Passed literal", "I5F-2 (2)", None,
     ((_OBS, I01B5_PUSH_PASSED, "                let passed = Some(Passed { started: self.client.now(), mark, stamp: now "
       "});\n" + I01B5_PUSH_PASSED),)),
    ("C2 a third push over a CaptureView literal", "I5F-3 (1)", None,
     ((_OBS, I01B5_DRAINS_DOC, "    fn forge(&mut self) {\n        self.client.push_capture_view(CaptureGate::from_view("
       "&CaptureView { sequence: 0 }, false));\n    }\n\n" + I01B5_DRAINS_DOC),)),
    ("C3 a replaced engine", "I5F-3 (2)", None,
     ((_OBS, "        self.drain_due = true;\n",
       "        self.drain_due = true;\n        self.captures = Some(Box::new(ForgedCycle::all_taken()));\n"),)),
    ("a CaptureGate literal in observe.rs", "I5F-3 (3)", None,
     ((_OBS, I01B5_DRAINS_DOC, "    fn forge(&self) -> Option<CaptureGate> {\n        Some(CaptureGate { scheduled: None, "
       "set_started_ms: 0, slots: Vec::new(), record_digest: String::new(), expired: false })\n    }\n\n"
       + I01B5_DRAINS_DOC),)),
    ("G1 a second wall_ms binding after the clock statement", "I5F-7", None,
     ((_SRV, I01B5_CLOCK_LINE, I01B5_CLOCK_LINE + "        let wall_ms = wall_ms.saturating_sub(4_000);\n"),)),
    ("G2 a let now before the CaptureFacts literal", "I5F-7", None,
     ((_SRV, "        let facts = crate::i01_answer::CaptureFacts {\n",
       "        let now = std::time::Instant::now();\n        let facts = crate::i01_answer::CaptureFacts {\n"),)),
    ("R-P6 the pinned manifest hash rewritten", "R1-1 (1)", None,
     ((_OBS, I01B5_START_LINE, "        self.config.pinned_manifest_hash = String::new();\n" + I01B5_START_LINE),)),
    ("R-P7 the sealed values dropped", "R1-1 (1)", None,
     ((_OBS, I01B5_START_LINE, "        self.config.sealed = None;\n" + I01B5_START_LINE),)),
    ("R-P8 the closure replaced", "R1-1 (1)", None,
     ((_OBS, I01B5_START_LINE, "        self.closure = Closure::embedded().unwrap();\n" + I01B5_START_LINE),)),
    ("R-P9 the configuration swapped", "R1-1 (3)", None,
     ((_OBS, I01B5_START_LINE, "        let mut other = self.config.clone();\n        std::mem::swap(&mut self.config, "
       "&mut other);\n" + I01B5_START_LINE),)),
)
I01B5_SNAPSHOT_FUNCTIONS = {"(i)": "snapshot_view_i_struct", "(ii)": "snapshot_view_ii_literal",
                            "(iii)": "snapshot_view_iii_impls", "(v)": "snapshot_view_v_names", "(vi)": "snapshot_view_vi_places"}
I01B5_SNAPSHOT_ROWS = (
    ("#[derive(Clone)]", "(i)", None,
     ((_CLI, "#[derive(Debug)]\npub struct SnapshotView {\n", "#[derive(Clone, Debug)]\npub struct SnapshotView {\n"),)),
    ("a second literal", "(ii)", None,
     ((_OBS, I01B5_DRAINS_DOC, "    fn forge_view(&self) -> SnapshotView {\n        SnapshotView { phase: 0, mark: 0, "
       "fresh_stamp: self.client.now(), derived: Err(NO_CAPTURE_ENGINE_TEXT) }\n    }\n\n" + I01B5_DRAINS_DOC),)),
    ("a PartialEq impl", "(iii)", None,
     ((_CLI, "#[derive(Debug)]\npub struct SnapshotView {\n", "impl PartialEq for SnapshotView {\n    fn eq(&self, _other: "
       "&Self) -> bool {\n        true\n    }\n}\n\n#[derive(Debug)]\npub struct SnapshotView {\n"),)),
    ("a type alias", "(v)", None,
     ((_CLI, "#[derive(Debug)]\npub struct SnapshotView {\n",
       "pub type View = SnapshotView;\n\n#[derive(Debug)]\npub struct SnapshotView {\n"),)),
    ("SnapshotView named in another file", "(vi)", None,
     (("crates/observer/src/utc.rs", "pub fn wall_millis() -> Option<u64> {\n",
       "pub fn phase(view: &crate::client::SnapshotView) -> u64 {\n    view.phase\n}\n\npub fn wall_millis() -> Option<u64> "
       "{\n"),)),
)
I01B5_LITERAL_ROWS = (
    (_OBS, "pub const REQUEST_ROUND_SPACING: Duration = Duration::from_secs(1);\n",
     "pub const REQUEST_ROUND_SPACING: Duration = Duration::from_secs(2);\n"),
    (_OBS, "pub const REQUEST_ROUND_DEADLINE: Duration = Duration::from_secs(2);\n",
     "pub const REQUEST_ROUND_DEADLINE: Duration = Duration::from_secs(3);\n"),
    (_OBS, "pub const NO_CAPTURE_ENGINE_TEXT: &str = \"no capture engine\";\n",
     "pub const NO_CAPTURE_ENGINE_TEXT: &str = \"no engine\";\n"),
    (_SRV, "pub const I01_EXCHANGE_DEADLINE: Duration = Duration::from_secs(2);\n",
     "pub const I01_EXCHANGE_DEADLINE: Duration = Duration::from_secs(3);\n"),
    (_CLI, "\"role/BROKER\", \"role/WORKER\"", "\"role/WORKER\", \"role/BROKER\""),
    (_CLI, "pub const CAPTURE_LIFECYCLE_SLOT: &str = \"lifecycle\";\n", "pub const CAPTURE_LIFECYCLE_SLOT: &str = \"cycle\";\n"),
    (_CLI, "/// R10-defined (I5E-7): the lifecycle slot's name, i01_gate.rs:37-45's `LIFECYCLE_SLOT`.\n",
     "/// The lifecycle slot's name.\n"),
)
# G-I01B-6 (a) and (c) (section 6.3; DIB 7.4's P6-1..P6-10, N2-6, N2-7, each with the clause that refuses it): the
# reading over the four socket files, run as G-I01-5, the socket-item rule, G-I01B-6 (e) and G-I01B-7 (c) run them.
# (a) and (c) are disabled by reading the paths and texts as they are (own_scope_path's and own_scope_strip's identity).
I01B5_OWN_SCOPE_FUNCTIONS = {"(a)": ("own_scope_path", lambda path, own: path),
                             "(c)": ("own_scope_strip", lambda text, own: text),
                             "(e)": ("check_socket_module_aliases", lambda base: 0),
                             "G-I01B-7 (c)": ("check_i01b_sources", lambda base: 0)}
_LISTEN_USE, _NET_USE = "use gate_sys::channel::{self, ListenStep};\n", "use crate::linux_listen::I01Socket;\n"
_OS_USE, _EG_USE = "use crate::linux_net::SharedNet;\n", "use crate::seal::Sealed;\n"
_SEND_IMPORT, _RENAME = "imports gate-sys's channel send", "renames gate-sys's channel module"
_ITEM, _ALIAS = "has a pub item naming gate-sys's socket items", "G-I01B-6 \\(e\\)"
I01B5_OWN_SCOPE_ROWS = (
    ("P6-1 use crate::linux_listen::channel::{send};", "(a)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use crate::linux_listen::channel::{send};\n"),), _SEND_IMPORT),
    ("P6-1 use crate::linux_net::channel::{send}; (linux_net.rs)", "(a)", None,
     ((_NET, _NET_USE, _NET_USE + "use crate::linux_net::channel::{send};\n"),), _SEND_IMPORT),
    ("P6-2 use crate::linux_listen::channel as c;", "(a)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use crate::linux_listen::channel as c;\n"),), _RENAME),
    ("P6-3 use super::linux_listen::channel::{send};", "(a)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use super::linux_listen::channel::{send};\n"),), _SEND_IMPORT),
    ("P6-4 use self::channel::send;", "(a)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use self::channel::send;\n"),), _SEND_IMPORT),
    ("P6-5 use crate::linux_os::Conn as K; pub fn f() -> K (linux_os.rs)", "(a)", None,
     ((gate.LINUX_OS, _OS_USE, _OS_USE + "use crate::linux_os::Conn as K;\n\npub fn leak(k: K) -> K {\n    k\n}\n"),),
     _ITEM),
    ("P6-5 use crate::linux_net::TcpConn as K; (effect-gate linux_net.rs)", "(a)", None,
     ((_EGN, _EG_USE, _EG_USE + "use crate::linux_net::TcpConn as K;\n\npub fn leak(k: K) -> K {\n    k\n}\n"),), _ITEM),
    ("P6-6 use super::linux_os::Conn as K;", "(a)", None,
     ((gate.LINUX_OS, _OS_USE, _OS_USE + "use super::linux_os::Conn as K;\n\npub fn leak(k: K) -> K {\n    k\n}\n"),),
     _ITEM),
    ("P6-7 use crate::linux_listen as me; use me::channel::send;", "(e)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use crate::linux_listen as me;\nuse me::channel::send;\n"),), _ALIAS),
    ("P6-8 -> &self::Conn (linux_os.rs)", "(c)", None,
     ((gate.LINUX_OS, _OS_USE, _OS_USE + "\npub fn leak(conn: &self::Conn) -> &self::Conn {\n    conn\n}\n"),), _ITEM),
    ("P6-8 -> &'static crate::linux_os::Conn", "(c)", None,
     ((gate.LINUX_OS, _OS_USE, _OS_USE + "\npub fn leak() -> &'static crate::linux_os::Conn {\n    todo()\n}\n"),), _ITEM),
    ("P6-8 pub type T = self::channel::Conn; (linux_listen.rs)", "(c)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "\npub type T = self::channel::Conn;\n"),), _ITEM),
    ("P6-8 -> &super::linux_net::TcpConn (effect-gate linux_net.rs)", "(c)", None,
     ((_EGN, _EG_USE, _EG_USE + "\npub fn leak(conn: &super::linux_net::TcpConn) -> &super::linux_net::TcpConn {\n"
       "    conn\n}\n"),), _ITEM),
    ("P6-9 use crate as r; use r::linux_listen::channel::send;", "(e)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use crate as r;\nuse r::linux_listen::channel::send;\n"),), _ALIAS),
    ("P6-10 mod m { use super::channel::send; } (linux_listen.rs)", "G-I01B-7 (c)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "mod m {\n    use super::channel::send;\n}\n"),), "declares a module"),
    ("N2-6 use crate::linux_os; then -> &linux_os::Conn", "(e)", None,
     ((gate.LINUX_OS, _OS_USE, _OS_USE + "use crate::linux_os;\n\npub fn leak(conn: &linux_os::Conn) -> &linux_os::Conn {\n"
       "    conn\n}\n"),), _ALIAS),
    ("N2-6 use super::linux_net; then -> &linux_net::TcpConn", "(e)", None,
     ((_EGN, _EG_USE, _EG_USE + "use super::linux_net;\n"),), _ALIAS),
    ("N2-6 use crate::linux_listen; (linux_listen.rs)", "(e)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use crate::linux_listen;\n"),), _ALIAS),
    ("N2-6 use crate::linux_net; (linux_net.rs)", "(e)", None,
     ((_NET, _NET_USE, _NET_USE + "use crate::linux_net;\n"),), _ALIAS),
    ("N2-6 use crate::linux_os::{self};", "(e)", None,
     ((gate.LINUX_OS, _OS_USE, _OS_USE + "use crate::linux_os::{self};\n"),), _ALIAS),
    ("N2-6 use crate::linux_os::{self as m};", "(e)", None,
     ((gate.LINUX_OS, _OS_USE, _OS_USE + "use crate::linux_os::{self as m};\n"),), _ALIAS),
    ("N2-7 use crate::*; (linux_listen.rs)", "(e)", None,
     ((_LST, _LISTEN_USE, _LISTEN_USE + "use crate::*;\n"),), _ALIAS),
    ("N2-7 use super::*; (linux_net.rs)", "(e)", None, ((_NET, _NET_USE, _NET_USE + "use super::*;\n"),), _ALIAS),
    ("N2-7 use self::*; (effect-gate linux_net.rs)", "(e)", None, ((_EGN, _EG_USE, _EG_USE + "use self::*;\n"),), _ALIAS),
)


def i01b5_tree(changes=()):
    """I01B5_TREE with each (file, anchor, replacement) applied once, in order."""
    texts = dict(I01B5_TREE)
    for rel, old, new in changes:
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old[:80]))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


def i01b6_checks(base):
    """G-I01B-6's reading over the four socket files, as the gate runs it: G-I01-5 (the observer's two), the socket-item
    rule (all four, check_socket_modules), G-I01B-6 (e) and G-I01B-7 (c). The number of checks run."""
    gate.check_observer_no_send(base)
    gate.check_socket_modules(base)
    gate.check_socket_module_aliases(base)
    gate.check_i01b_sources(base)
    return 4


# Each tag is the start of a sub-clause's own message mark (its rule and clause; the citations that follow vary).
I01B5_SEND_TAG, I01B5_STATEMENT_TAG = "(one send path, G-I01B-5 %s", "(pinned statements, B3-6 %s"
I01B5_FOLD_TAG, I01B5_SNAPSHOT_TAG = "(round 3's folds, %s", "(SnapshotView closed, B3-7 %s"
I01B5_PROOF_RULES = (
    ("G-I01B-5", "check_i01b5_send", I01B5_SEND_FUNCTIONS, I01B5_SEND_ROWS, i01b5_tree, I01B5_SEND_TAG),
    ("B3-6", "check_i01b5_statements", I01B5_STATEMENT_FUNCTIONS, I01B5_STATEMENT_ROWS, i01b5_tree, I01B5_STATEMENT_TAG),
    ("I5F", "check_i01b5_folds", I01B5_FOLD_FUNCTIONS, I01B5_FOLD_ROWS, i01b5_tree, I01B5_FOLD_TAG),
    ("B3-7", "check_i01b5_snapshot_view", I01B5_SNAPSHOT_FUNCTIONS, I01B5_SNAPSHOT_ROWS, i01b5_tree, I01B5_SNAPSHOT_TAG),
    ("G-I01B-6", i01b6_checks, I01B5_OWN_SCOPE_FUNCTIONS, I01B5_OWN_SCOPE_ROWS, i01b5_tree, "%s"),
)


def patched_functions(functions, enabled):
    """mock patches that disable every clause function of `functions` but `enabled` (a plain name becomes a no-op; a
    (name, replacement) pair takes its replacement)."""
    patches = []
    for clause, function in functions.items():
        if clause == enabled:
            continue
        name, replacement = function if isinstance(function, tuple) else (function, lambda *args, **kwargs: 0)
        patches.append(mock.patch.object(gate, name, replacement))
    return patches


class I01b5RuleTests(Tree):
    """HE-004-I01B5 U4 (DESIGN-I01B5 rev 5 sections 6 and 8) over the real observer sources: G-I01B-5's nine clauses,
    the nine pinned statements, round 3's ten folds with PR review round 1's three R1-1 clauses (R-P6..R-P9 among the
    fold rows), SnapshotView closed and the seven new literal pins accept today's sources; each row of I01B5_SEND_ROWS, I01B5_STATEMENT_ROWS, I01B5_FOLD_ROWS and I01B5_SNAPSHOT_ROWS is refused by
    its rule, and with every other clause of the rule disabled, by its own named sub-clause's message; each literal pin
    refuses a changed value or citation; and G-I01B-6's rows (P6-1..P6-10, N2-6, N2-7) are refused by the clause the
    table names, with the message DIB 7.4 gives."""

    TREE = I01B5_TREE

    def plant(self, changes):
        for rel, text in i01b5_tree(changes).items():
            self.write(rel, text)

    def test_the_real_sources_and_the_fixture_pass(self):
        for base in (self.base, gate.HE):
            self.assertEqual(gate.check_i01b5_send(base), 9)
            self.assertEqual(gate.check_i01b5_statements(base), 9)
            self.assertEqual(gate.check_i01b5_folds(base), 13)
            self.assertEqual(gate.check_i01b5_snapshot_view(base), 5)
            self.assertEqual(gate.check_i01b5_constants(base), 7)
            self.assertEqual(i01b6_checks(base), 4)
        self.assertEqual(gate.check_observer_no_send(self.base), gate.check_observer_no_send(gate.HE))

    def test_the_tables(self):
        self.assertEqual(len(I01B5_SEND_ROWS), 43)
        self.assertEqual(len(I01B5_STATEMENT_ROWS), 26)
        self.assertEqual(len(I01B5_FOLD_ROWS), 17)
        self.assertEqual(len(I01B5_SNAPSHOT_ROWS), 5)
        self.assertEqual(len(I01B5_OWN_SCOPE_ROWS), 24)
        for name, check, functions, rows, builder, tag in I01B5_PROOF_RULES:
            self.assertTrue(callable(check) or callable(getattr(gate, check)), name)
            for function in functions.values():
                self.assertTrue(callable(getattr(gate, function[0] if isinstance(function, tuple) else function)), function)
            for row in rows:
                self.assertIn(row[1], functions, row[0])
                builder(row[3])

    def refuses_each(self, check, functions, rows, tag):
        for row in rows:
            label, clause, _, changes = row[:4]
            message = row[4] if len(row) > 4 else re.escape(tag % clause)
            self.plant(changes)
            try:
                with self.assertRaisesRegex(gate.GateError, message, msg=label):
                    check(self.base)
                patches = patched_functions(functions, clause)
                for patch in patches:
                    patch.start()
                try:
                    with self.assertRaisesRegex(gate.GateError, message, msg=label):
                        check(self.base)
                finally:
                    for patch in patches:
                        patch.stop()
            finally:
                self.plant(())

    def test_g_i01b_5_rows(self):
        self.refuses_each(gate.check_i01b5_send, I01B5_SEND_FUNCTIONS, I01B5_SEND_ROWS, I01B5_SEND_TAG)

    def test_pinned_statement_rows(self):
        self.refuses_each(gate.check_i01b5_statements, I01B5_STATEMENT_FUNCTIONS, I01B5_STATEMENT_ROWS,
                          I01B5_STATEMENT_TAG)

    def test_fold_rows(self):
        self.refuses_each(gate.check_i01b5_folds, I01B5_FOLD_FUNCTIONS, I01B5_FOLD_ROWS, I01B5_FOLD_TAG)

    def test_snapshot_view_rows(self):
        self.refuses_each(gate.check_i01b5_snapshot_view, I01B5_SNAPSHOT_FUNCTIONS, I01B5_SNAPSHOT_ROWS,
                          I01B5_SNAPSHOT_TAG)

    def test_g_i01b_6_rows(self):
        self.refuses_each(i01b6_checks, I01B5_OWN_SCOPE_FUNCTIONS, I01B5_OWN_SCOPE_ROWS, "%s")
        # P6-10 in effect-gate's two files: (d), no nested module, is held there by the whole-file pins (F6.8).
        for rel, anchor in ((gate.LINUX_OS, _OS_USE), (_EGN, _EG_USE)):
            self.plant(((rel, anchor, anchor + "mod m {\n    use super::channel::send;\n}\n"),))
            try:
                with self.assertRaisesRegex(gate.GateError, "differs from its pinned bytes .*R-B3-PIN"):
                    gate.check_i01b_guarded_pins(self.base)
            finally:
                self.plant(())

    def test_the_own_scope_reading_units(self):
        self.assertEqual(gate.own_scope_path(("crate", "linux_listen", "channel", "send"), "linux_listen"),
                         ("channel", "send"))
        self.assertEqual(gate.own_scope_path(("super", "linux_os", "Conn"), "linux_os"), ("Conn",))
        self.assertEqual(gate.own_scope_path(("self", "channel"), None), ("channel",))
        self.assertEqual(gate.own_scope_path(("crate", "linux_os"), "linux_os"), ("crate", "linux_os"))
        self.assertEqual(gate.own_scope_path(("crate", "linux_net", "SharedNet"), "linux_os"),
                         ("crate", "linux_net", "SharedNet"))
        self.assertEqual(gate.resolved_uses([(("gate_sys", "channel", "self"), None),
                                             (("crate", "linux_listen", "channel", "send"), None)], "linux_listen"),
                         [(("gate_sys", "channel", "self"), None), (("gate_sys", "channel", "send"), None)])
        self.assertEqual(gate.own_scope_strip("pub fn f() -> &crate::linux_os::Conn { self::g(super::linux_os::x) }",
                                              "linux_os"), "pub fn f() -> &Conn { g(x) }")
        self.assertEqual(gate.own_scope_strip("-> &crate::linux_net::SharedNet", "linux_os"),
                         "-> &crate::linux_net::SharedNet")
        # Today's four import heads are unchanged by the reading: each file's own paths resolve as before.
        for rel in gate.SOCKET_FILES:
            raw = (gate.HE / rel).read_text(encoding="utf-8")
            uses = gate.source_uses(rel, raw)
            self.assertEqual(gate.resolved_uses(uses, Path(rel).stem), gate.resolved_uses(uses), rel)

    def test_each_literal_pin_refuses_a_change(self):
        for rel, old, new in I01B5_LITERAL_ROWS:
            self.plant(((rel, old, new),))
            try:
                with self.assertRaisesRegex(gate.GateError, re.escape("(I01B5 literal pins, G-I01B-8)")):
                    gate.check_i01b5_constants(self.base)
            finally:
                self.plant(())

    def test_the_pinned_patterns(self):
        pattern = gate.pinned_pattern('let x = f("a", b) ;')
        self.assertTrue(pattern.fullmatch('let x=f( "" ,b);'))
        self.assertFalse(pattern.fullmatch('letx = f("", b);'))
        self.assertTrue(gate.pinned_pattern('f("a")', literals=True).fullmatch('f( "a" )'))
        self.assertFalse(gate.pinned_pattern('f("a")', literals=True).fullmatch('f("b")'))
        self.assertTrue(gate.named_at("a b a", "a", (("a", 2),)))
        self.assertFalse(gate.named_at("a b a c", "c", ()))


ROLE_SEAL_MANIFEST = "crates/role-seal/Cargo.toml"


class RoleSealRuleTests(Tree):
    """HE-005A0 (DESIGN-HE005 section 4, A0, D6; MON-HE005A-PLAN; MON-HE005A0-U1, exception 4): check_role_seal over a
    fixture copy of role-seal's real lib.rs and manifest. (a) Only lib.rs; (b) the public item set, so the SealOps engine
    stays crate-private (the item-set rule's own failing rows plant a public engine); (c) no program bytes, embedded file
    or fixture name outside the strict test block; (d) gate-sys by path, the one dependency. Each row names the clause
    whose message refuses it."""

    TREE = {gate.ROLE_SEAL_LIB: (gate.HE / gate.ROLE_SEAL_LIB).read_text(encoding="utf-8"),
            ROLE_SEAL_MANIFEST: (gate.HE / ROLE_SEAL_MANIFEST).read_text(encoding="utf-8")}
    TESTS = "#[cfg(test)]\nmod tests {"

    def planted(self, text):
        """The real lib.rs with `text` planted at its top level, right before its strict test block."""
        real = self.TREE[gate.ROLE_SEAL_LIB]
        at = real.index(self.TESTS)
        return real[:at] + text + "\n\n" + real[at:]

    def test_the_real_copy_passes(self):
        self.assertEqual(gate.check_role_seal(self.base), 18)
        # HE-005A: (e) reads lib.rs (this tree holds no broker source), (f) finds no type item and (g) one fn whose return
        # type names u8, LinuxOps's own_status, with no byte literal.
        self.assertEqual([clause(self.base) for _, clause in gate.ROLE_SEAL_CLAUSES], [1, 18, 6, 1, 1, 0, 1])
        self.assertEqual(len(gate.ROLE_SEAL_PUBLIC), 18)
        self.assertEqual(self.TREE[gate.ROLE_SEAL_LIB].count(self.TESTS), 1)
        # The seven fixture items sit inside the strict test block, where clause (c) does not read.
        tests = self.TREE[gate.ROLE_SEAL_LIB][self.TREE[gate.ROLE_SEAL_LIB].index(self.TESTS):]
        for name in gate.ROLE_SEAL_FIXTURE_NAMES:
            self.assertRegex(tests, r"\b%s\b" % name)

    def test_a_only_lib_rs(self):
        message = "role-seal/src holds .* not exactly lib.rs .role-seal rule \\(a\\)"
        for rel in ("crates/role-seal/src/engine.rs", "crates/role-seal/src/seal/mod.rs"):
            self.refused(gate.check_role_seal, rel, "pub fn run() {}\n", message)
        (self.base / gate.ROLE_SEAL_LIB).unlink()
        with self.assertRaisesRegex(gate.GateError, message):
            gate.check_role_seal(self.base)

    def test_b_d6_refuses_a_public_engine(self):
        # MON-HE005A-PLAN: D6's private engine is proven by the item-set rule's own failing rows.
        real = self.TREE[gate.ROLE_SEAL_LIB]
        engine = "pub fn seal_with<O: SealOps>(ops: &mut O, spec: RoleSpec) -> Result<Stage1, SealError> {\n" \
                 "    run_stage1(ops, spec).map(|plan| Stage1 { plan })\n}"
        rows = (
            (real.replace("pub(crate) fn run_stage1<O: SealOps>", "pub fn run_stage1<O: SealOps>", 1),
             "not listed [('fn', 'run_stage1')]"),
            (real.replace("pub(crate) fn run_stage2<O: SealOps>", "pub fn run_stage2<O: SealOps>", 1),
             "not listed [('fn', 'run_stage2')]"),
            (real.replace("pub(crate) trait SealOps {", "pub trait SealOps {", 1), "not listed [('trait', 'SealOps')]"),
            (real.replace("pub(crate) fn plan(spec: RoleSpec)", "pub fn plan(spec: RoleSpec)", 1),
             "not listed [('fn', 'plan')]"),
            (real.replace("\nstruct LinuxOps;", "\npub struct LinuxOps;", 1), "not listed [('struct', 'LinuxOps')]"),
            (real.replace("pub(crate) struct Plan {", "pub struct Plan {", 1), "not listed [('struct', 'Plan')]"),
            (self.planted(engine), "not listed [('fn', 'seal_with')]"),
            (self.planted("pub use self::run_stage1 as stage;"), "not listed [('use', 'self')]"),
            (real.replace("pub struct Stage1 {\n    plan: Plan,", "pub struct Stage1 {\n    pub plan: Plan,", 1),
             "pub fields are not exactly the listed ones: not listed [('Stage1', 'plan')]"),
            (self.planted("impl Stage1 {\n    pub fn new(plan: Plan) -> Stage1 {\n        Stage1 { plan }\n    }\n}"),
             "pub methods are not exactly the listed ones: not listed [('Stage1', 'new')]"),
            (real.replace("pub fn filter_length(", "fn filter_length(", 1), "missing [('fn', 'filter_length')]"),
            (self.planted("fn hidden() {\n    pub fn inner() {}\n}"), "a pub the item-set rule cannot place"),
            (self.planted("mod engine {\n    pub use super::run_stage1;\n}"), "a pub the item-set rule cannot place"),
            (self.planted("#[cfg(test)] mod other {\n    pub fn run() {}\n}"), "a pub the item-set rule cannot place"))
        for text, fragment in rows:
            self.assertNotEqual(text, real, fragment)
            self.refused(gate.check_role_seal, gate.ROLE_SEAL_LIB, text,
                         re.escape(fragment) + ".*" + re.escape("(role-seal rule (b), D6)"))

    def test_c_no_program_bytes_or_fixture_outside_the_tests(self):
        rows = (("static P: &[u8; 8] = include_bytes!(\"../p.bpf\");", "embeds a file with include_bytes! or include_str!"),
                ("const P: &str = include_str!(\"../p.txt\");", "embeds a file with include_bytes! or include_str!"),
                ("static P: &[u8; 8] = &[0; 8];", "holds program bytes: P's type names u8"),
                ("const P: &[u8] = &[0x20, 0, 0, 0];", "holds program bytes: P's type names u8"),
                ("pub(crate) static PROGRAM: [u8; 4] = [6, 0, 0, 0];", "holds program bytes: PROGRAM's type names u8"),
                ("fn spec() -> u16 {\n    RoleSpec { bounding: 0, kept: 0, program: &[], instructions: 0 }.instructions\n}",
                 "builds a RoleSpec outside its tests"),
                ("const CAP_NET_ADMIN: u32 = 12;", "names the tests' fixture CAP_NET_ADMIN"),
                ("const CAP_BPF: u32 = 39;", "names the tests' fixture CAP_BPF"),
                ("const KEPT: u64 = 1 << 12 | 1 << 39;", "names the tests' fixture KEPT"),
                ("fn f() -> usize { PROGRAM_X86_64.len() }", "names the tests' fixture PROGRAM_X86_64"),
                ("const PROGRAM_AARCH64: usize = 1936;", "names the tests' fixture PROGRAM_AARCH64"),
                ("enum Arch {\n    X86_64,\n}", "names the tests' fixture Arch"),
                # A test block in another form is not the strict one, so its fixture is read.
                ("#[cfg(test)] mod fixture {\n    const KEPT: u64 = 0;\n}", "names the tests' fixture KEPT"))
        for text, fragment in rows:
            self.refused(gate.check_role_seal, gate.ROLE_SEAL_LIB, self.planted(text),
                         re.escape(fragment) + ".*" + re.escape("(role-seal rule (c), exception 4)"))

    def test_d_gate_sys_by_path_alone(self):
        good = self.TREE[ROLE_SEAL_MANIFEST]
        line = 'gate-sys = { path = "../gate-sys" }\n'
        self.assertEqual(good.count(line), 1)
        rows = (good + 'i05-protocol = { path = "../i05-protocol" }\n', good + 'ring = "=0.17.14"\n',
                good.replace(line, 'gate-sys = { path = "../gate-sys", features = ["x"] }\n'),
                good.replace(line, ""), good + '\n[dev-dependencies]\ni05-protocol = { path = "../i05-protocol" }\n',
                good + '\n[build-dependencies]\ncc = "1"\n', good + '\n[target.\'cfg(unix)\'.dependencies]\nlibc = "0.2"\n')
        for text in rows:
            self.refused(gate.check_role_seal, ROLE_SEAL_MANIFEST, text,
                         re.escape("Cargo.toml's dependencies are not exactly gate-sys by path (role-seal rule (d))"))


# --- HE-005A (DESIGN-HE005 revision 5 section 4, HE-005A; MON-HE005A-PLAN2, MON-HE005A0-U4, MON-HE005A0-PUSH,
# MON-HE005A-LAUNCH) ---------------------------------------------------------------------------------------------------
# The real sources the HE-005A rules read: role-seal's lib.rs and manifest, the observer's and the broker's sources, the
# broker's manifest, and effect-gate's lib.rs and two socket files (the socket-module rule requires every socket file).
# Each blocking obligation's rows are (label, the named sub-clause, changes); a change is (file, anchor, replacement),
# an empty anchor appending. The build's mutation proof reads HE005A_PROOF_RULES, records each row's actual refusing
# set and runs the single-clause or each-alone proof.
HE005A_TREE = {**{path.relative_to(gate.HE).as_posix(): path.read_text(encoding="utf-8")
                  for crate in (gate.OBSERVER_CRATE, gate.BROKER_CRATE, gate.BROKER_SYS_CRATE)
                  for path in sorted((gate.HE / crate / "src").rglob("*.rs"))},
               **{rel: (gate.HE / rel).read_text(encoding="utf-8")
                  for rel in (gate.ROLE_SEAL_LIB, ROLE_SEAL_MANIFEST, "crates/broker/Cargo.toml", gate.EFFECT_GATE_LIB,
                              gate.LINUX_OS, "crates/effect-gate/src/linux_net.rs")}}
_RSL, _BSEAL, _BSTATUS = gate.ROLE_SEAL_LIB, gate.BROKER_SEAL_RS, gate.BROKER_STATUS
_BLIB, _BMAIN, _BLISTEN = gate.BROKER_LIB, gate.BROKER_MAIN, gate.BROKER_LINUX_LISTEN
_OSEAL, _OCLIENT, _OSTATUS = gate.OBSERVER_SEAL_RS, gate.OBSERVER_CLIENT, gate.OBSERVER_STATUS
_RS_TESTS = "#[cfg(test)]\nmod tests {"
_STAGE1_DEF = "#[derive(Debug)]\n#[must_use]\npub struct Stage1 {\n    plan: Plan,\n}"
_SEALED_DEF = "#[derive(Debug)]\n#[must_use]\npub struct Sealed {\n    _sealed: (),\n}"
_STAGE1_SIGNATURE = "pub fn seal_stage1(spec: RoleSpec) -> Result<Stage1, SealError> {"
_STAGE2_SIGNATURE = "pub fn seal_stage2(stage1: Stage1) -> Result<Sealed, SealError> {"
_STAGE1_BODY = "    run_stage1(&mut LinuxOps, spec).map(|plan| Stage1 { plan })"
_BROKER_STAGE1 = "    role_seal::seal_stage1(spec(RUNNING_ARCH)).map_err(SealError::Seal)"
_BROKER_STAGE2 = "    role_seal::seal_stage2(stage1).map_err(SealError::Seal)"
_BROKER_X86 = 'include_bytes!("../../../contracts/seccomp-v3/BROKER.x86_64.bpf")'
_BROKER_ARM = 'include_bytes!("../../../contracts/seccomp-v3/BROKER.aarch64.bpf")'


def he005a_tree(changes=()):
    """HE005A_TREE with each (file, anchor, replacement) applied once, in order; an empty anchor appends."""
    texts = dict(HE005A_TREE)
    for rel, old, new in changes:
        if not old:
            texts[rel] = texts[rel] + new
            continue
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old[:80]))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


def role_seal_planted(text):
    """A change planting `text` at role-seal's top level, right before its strict test block."""
    return (_RSL, _RS_TESTS, text + "\n\n" + _RS_TESTS)


# Clause (e) of check_role_seal (MON-HE005A0-U4): formatting a token, or unwrapping an error carrying one.
HE005A_E_ROWS = (
    ("e1 format! of a Stage1", "(e)", (role_seal_planted('fn show(stage1: &Stage1) -> String {\n    format!("{stage1:?}")\n}'),)),
    ("e2 write! of a Sealed", "(e)",
     (role_seal_planted('fn show(sealed: &Sealed, out: &mut String) {\n    let _ = write!(out, "{:?}", sealed);\n}'),)),
    ("e3 writeln! of a Sealed", "(e)",
     (role_seal_planted('fn show(sealed: &Sealed, out: &mut String) {\n    let _ = writeln!(out, "{sealed:?}");\n}'),)),
    ("e4 format_args! with {:#?}", "(e)",
     (role_seal_planted('fn show(stage1: &Stage1) -> usize {\n    format_args!("{:#?}", stage1).as_str().map_or(0, str::len)\n}'),)),
    ("e5 a Display impl calling Debug::fmt", "(e)",
     (role_seal_planted("struct Shown<'a>(&'a Stage1);\nimpl core::fmt::Display for Shown<'_> {\n"
                        "    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {\n"
                        "        core::fmt::Debug::fmt(self.0, f)\n    }\n}"),)),
    ("e6 unwrap_err on a result carrying a Stage1 (A0's gap)", "(e)",
     (role_seal_planted("fn token(result: Result<u8, Stage1>) -> Stage1 {\n    result.unwrap_err()\n}"),)),
    ("e7 expect_err on a result carrying a Sealed (A0's gap)", "(e)",
     (role_seal_planted('fn token(result: Result<u8, Sealed>) -> Sealed {\n    result.expect_err("a token")\n}'),)),
    ("e8 a Debug specifier in a literal", "(e)", (role_seal_planted('const SHOWN: &str = "{:?}";'),)),
    ("e9 an alternate hex Debug specifier", "(e)", (role_seal_planted('const SHOWN: &str = "{stage1:#x?}";'),)),
    ("e10 format! in the broker's seal.rs", "(e)",
     ((_BSEAL, "", '\nfn show(stage1: &Stage1) -> String {\n    format!("{stage1:?}")\n}\n'),)),
    ("e11 unwrap_err in the broker's lib.rs", "(e)",
     ((_BLIB, "", "\nfn token(result: Result<u8, Stage1>) -> Stage1 {\n    result.unwrap_err()\n}\n"),)),
    ("e12 a Debug specifier in the broker's status.rs", "(e)", ((_BSTATUS, "", '\nconst SHOWN: &str = "{:?}";\n'),)),
)
# Clause (f) (R1-2): bytes behind a type alias or a renamed u8.
HE005A_F_ROWS = (
    ("f1 bytes behind a type alias (probe E-1)", "(f)", (role_seal_planted("type Bytes = [u8; 8];\nstatic S: Bytes = [0; 8];"),)),
    ("f2 a slice alias", "(f)", (role_seal_planted("type Program = &'static [u8];"),)),
    ("f3 u8 aliased by its primitive path", "(f)",
     (role_seal_planted("type Byte = core::primitive::u8;\nstatic S: [Byte; 8] = [0; 8];"),)),
    ("f4 u8 renamed in a use", "(f)", (role_seal_planted("use core::primitive::u8 as Byte;\nstatic S: [Byte; 8] = [0; 8];"),)),
    ("f5 u8 renamed in a grouped use", "(f)", (role_seal_planted("use std::primitive::{u16, u8 as B};\nconst P: &[B] = &[6, 0];"),)),
    ("f6 an associated type naming u8", "(f)",
     (role_seal_planted("trait Source {\n    type Unit;\n}\nimpl Source for Plan {\n    type Unit = u8;\n}"),)),
)
# Clause (g) (R1-3): a fn returning a byte-array literal.
HE005A_G_ROWS = (
    ("g1 a byte-array literal (probe E-2)", "(g)",
     (role_seal_planted("fn program() -> &'static [u8] {\n    &[0x20, 0, 0, 0, 4, 0, 0, 0]\n}"),)),
    ("g2 an owned byte array", "(g)", (role_seal_planted("fn program() -> [u8; 8] {\n    [6, 0, 0, 0, 0, 0, 0xFF, 0x7F]\n}"),)),
    ("g3 a byte string", "(g)",
     (role_seal_planted('fn program() -> Vec<u8> {\n    b"\\x06\\0\\0\\0\\0\\0\\xff\\x7f".to_vec()\n}'),)),
    ("g4 an optional slice", "(g)",
     (role_seal_planted("fn program() -> Option<&'static [u8]> {\n    Some(&[6, 0, 0, 0, 0, 0, 0xFF, 0x7F])\n}"),)),
    ("g5 a generic fn with a where-clause", "(g)",
     (role_seal_planted("fn program<T>() -> &'static [u8]\nwhere\n    T: Copy,\n{\n    &[6, 0, 0, 0]\n}"),)),
    ("g6 a method", "(g)", (role_seal_planted("impl Plan {\n    fn bytes(&self) -> &'static [u8] {\n        &[6, 0, 0, 0]\n    }\n}"),)),
)
# R1-1: the tokens closed (check_seal_tokens).
HE005A_TOKEN_ROWS = (
    ("t1 a unit-struct Sealed", "(i)", ((_RSL, _SEALED_DEF, "#[derive(Debug)]\n#[must_use]\npub struct Sealed;"),)),
    ("t2 a Default derive", "(i)", ((_RSL, _STAGE1_DEF, _STAGE1_DEF.replace("derive(Debug)", "derive(Debug, Default)")),)),
    ("t3 a Clone derive on Sealed", "(i)", ((_RSL, _SEALED_DEF, _SEALED_DEF.replace("derive(Debug)", "derive(Clone, Debug)")),)),
    ("t4 a cfg_attr derive", "(i)", ((_RSL, _SEALED_DEF, "#[cfg_attr(test, derive(Default))]\n" + _SEALED_DEF),)),
    ("t5 a visible field", "(i)", ((_RSL, _STAGE1_DEF, _STAGE1_DEF.replace("    plan: Plan,", "    pub(crate) plan: Plan,")),)),
    ("t6 a tuple Sealed", "(i)", ((_RSL, _SEALED_DEF, "#[derive(Debug)]\n#[must_use]\npub struct Sealed(());"),)),
    ("t7 a second Stage1 literal", "(ii)",
     (role_seal_planted("fn forge(plan: Plan) -> Option<Stage1> {\n    Some(Stage1 { plan })\n}"),)),
    ("t8 a Self literal", "(ii)",
     (role_seal_planted("impl Plan {\n    fn again(&self) -> Self {\n        Self { spec: self.spec, length: self.length }\n    }\n}"),)),
    ("t9 the Stage1 literal outside its stage", "(ii)",
     ((_RSL, _STAGE1_BODY, "    run_stage1(&mut LinuxOps, spec).map(wrap)"),
      role_seal_planted("fn wrap(plan: Plan) -> Stage1 {\n    Stage1 { plan }\n}"))),
    ("t10 a Sealed literal in the observer", "(ii)",
     ((_OSEAL, "", "\nfn forge() -> role_seal::Sealed {\n    role_seal::Sealed { _sealed: () }\n}\n"),)),
    ("t11 a Stage1 literal in the broker", "(ii)", ((_BSEAL, "", "\nfn forge(plan: u8) -> Stage1 {\n    Stage1 { plan }\n}\n"),)),
    ("t12 stage 1 generic over SealOps", "(iii)",
     ((_RSL, _STAGE1_SIGNATURE + "\n" + _STAGE1_BODY,
       "pub fn seal_stage1<O: SealOps>(ops: &mut O, spec: RoleSpec) -> Result<Stage1, SealError> {\n"
       "    run_stage1(ops, spec).map(|plan| Stage1 { plan })"),)),
    ("t13 stage 2 taking a reference", "(iii)",
     ((_RSL, _STAGE2_SIGNATURE, "pub fn seal_stage2(stage1: &Stage1) -> Result<Sealed, SealError> {"),)),
    ("t14 a second call of stage 1 inside role-seal", "(iii)",
     (role_seal_planted("fn again(spec: RoleSpec) -> bool {\n    seal_stage1(spec).is_ok()\n}"),)),
    ("t15 a Default impl for Sealed", "(iv)",
     (role_seal_planted("impl Default for Sealed {\n    fn default() -> Sealed {\n        loop {}\n    }\n}"),)),
    ("t16 From for Stage1", "(iv)",
     (role_seal_planted("impl From<Plan> for Stage1 {\n    fn from(_plan: Plan) -> Stage1 {\n        loop {}\n    }\n}"),)),
    ("t17 an inherent impl of Stage1", "(iv)",
     (role_seal_planted("impl Stage1 {\n    fn length(&self) -> u16 {\n        self.plan.length\n    }\n}"),)),
    ("t18 Clone for Sealed in the observer", "(iv)",
     ((_OSEAL, "", "\nimpl Clone for role_seal::Sealed {\n    fn clone(&self) -> role_seal::Sealed {\n        loop {}\n    }\n}\n"),)),
    ("t19 a trait impl in the broker", "(iv)", ((_BLIB, "", "\npub trait Token {}\nimpl Token for Sealed {}\n"),)),
    ("t20 an alias of Sealed in role-seal", "(v)", (role_seal_planted("type Token = Sealed;"),)),
    ("t21 a rename of Stage1 in role-seal", "(v)", (role_seal_planted("use crate::Stage1 as First;"),)),
    ("t22 a rename in the broker", "(v)", ((_BSEAL, "", "\npub use role_seal::Stage1 as First;\n"),)),
    ("t23 an alias in the observer", "(v)", ((_OSEAL, "", "\ntype Done = role_seal::Sealed;\n"),)),
)
# R1-5: the calls of role-seal's stages (check_role_seal_stage_calls).
HE005A_STAGE_ROWS = (
    ("s1 a stage imported in an observer module", "(a)", ((_OCLIENT, "", "\nuse role_seal::seal_stage1;\n"),)),
    ("s2 role_seal renamed", "(a)", ((_OCLIENT, "", "\nuse role_seal as rs;\n"),)),
    ("s3 role_seal renamed through self", "(a)", ((_OCLIENT, "", "\nuse role_seal::{self as rs};\n"),)),
    ("s4 a glob of role_seal", "(a)", ((_BLIB, "", "\nuse role_seal::*;\n"),)),
    ("s5 a stage renamed and re-exported", "(a)", ((_BLIB, "", "\npub use role_seal::{seal_stage2 as raw_stage2};\n"),)),
    ("s6 a stage imported in the role's own seal.rs", "(a)", ((_BSEAL, "", "\nuse role_seal::seal_stage1 as stage_one;\n"),)),
    ("s7 an alias chain to a stage", "(a)", ((_OCLIENT, "", "\nuse role_seal as rs;\nuse rs::seal_stage2;\n"),)),
    ("s8 a stage called from an observer module", "(b)",
     ((_OCLIENT, "", "\nfn again() -> bool {\n    role_seal::seal_stage1(spec()).is_ok()\n}\n"),)),
    ("s9 a stage as a fn item in the broker's status.rs", "(b)",
     ((_BSTATUS, "", "\nfn stage() {\n    let _ = ::role_seal::seal_stage2;\n}\n"),)),
    ("s10 a spaced stage path in the broker's main.rs", "(b)",
     ((_BMAIN, "", "\nfn again() {\n    let _ = role_seal :: seal_stage1;\n}\n"),)),
    ("s11 a second call in the broker's seal.rs", "(c)",
     ((_BSEAL, "", "\nfn again() -> bool {\n    role_seal::seal_stage1(spec(Arch::X86_64)).is_ok()\n}\n"),)),
    ("s12 the call moved out of the wrapper", "(c)",
     ((_BSEAL, _BROKER_STAGE1, "    raw(spec(RUNNING_ARCH)).map_err(SealError::Seal)"),
      (_BSEAL, "", "\nfn raw(spec: role_seal::RoleSpec) -> Result<Stage1, role_seal::SealError> {\n"
                   "    role_seal::seal_stage1(spec)\n}\n"))),
    ("s13 a stage as a fn item in the observer's seal.rs", "(c)",
     ((_OSEAL, "    role_seal::seal_stage2(stage1)", "    (role_seal::seal_stage2)(stage1)"),)),
    ("s14 the broker's wrapper without its stage", "(c)",
     ((_BSEAL, _BROKER_STAGE2, "    Err(SealError::Start(StartCheck::Status))"),)),
    # HE-005A PR review round 1, R1-1 (MON-HE005A-R1): the reviewer's four probe forms, each through a seal.rs that
    # re-exports the role_seal crate, and the re-export forms alone.
    ("s15 a crate-relative call in the broker's lib.rs (probe p1)", "(b)",
     ((_BSEAL, "", "\npub(crate) use role_seal;\n"),
      (_BLIB, "", "\nfn forged() -> bool {\n    crate::seal::role_seal::seal_stage1(seal::spec(seal::Arch::X86_64)).is_ok()\n}\n"))),
    ("s16 super::seal::role_seal:: in the broker's status.rs (probe p1b)", "(b)",
     ((_BSEAL, "", "\npub use role_seal;\n"),
      (_BSTATUS, "", "\nfn forged() {\n    let _ = super::seal::role_seal::seal_stage2;\n}\n"))),
    ("s17 an alias of the re-export, then rs::seal_stage1 (probe p1c)", "(a)",
     ((_BSEAL, "", "\npub(crate) use role_seal::{self};\n"),
      (_BLIB, "", "\nuse crate::seal::role_seal as rs;\nfn forged() -> bool {\n"
                  "    rs::seal_stage1(seal::spec(seal::Arch::X86_64)).is_ok()\n}\n"))),
    ("s18 the observer's client.rs through its seal.rs (probe p2)", "(b)",
     ((_OSEAL, "", "\npub(crate) use role_seal;\n"),
      (_OCLIENT, "", "\nfn forged(spec: role_seal::RoleSpec) -> bool {\n    crate::seal::role_seal::seal_stage1(spec).is_ok()\n}\n"))),
    ("s19 pub(crate) use role_seal; in the broker's seal.rs", "(a)", ((_BSEAL, "", "\npub(crate) use role_seal;\n"),)),
    ("s20 pub use role_seal; in the observer's seal.rs", "(a)", ((_OSEAL, "", "\npub use role_seal;\n"),)),
    ("s21 pub(crate) use role_seal::{self}; in the broker's seal.rs", "(a)",
     ((_BSEAL, "", "\npub(crate) use role_seal::{self};\n"),)),
    ("s22 a private, rooted and renamed re-export in the observer's seal.rs", "(a)",
     ((_OSEAL, "", "\nuse ::role_seal as seal_crate;\n"),)),
    ("s23 an item imported through another path in the broker's lib.rs", "(a)",
     ((_BLIB, "", "\nuse crate::seal::role_seal::RoleSpec;\n"),)),
    ("s24 a second stage path after a segment in the observer's seal.rs", "(c)",
     ((_OSEAL, "", "\nfn again() {\n    let _ = self::role_seal::seal_stage2;\n}\n"),)),
)
# R1-2's broker form (check_broker_bytes): bytes outside seal.rs.
HE005A_BYTES_ROWS = (
    ("b1 a status table as a byte array", ((_BSTATUS, "", "\npub const STAGES: [u8; 2] = [NOT_LINUX, NOT_YET_SERVING];\n"),)),
    ("b2 program bytes in lib.rs", ((_BLIB, "", "\npub static PROGRAM: &[u8] = &[6, 0, 0, 0, 0, 0, 0xFF, 0x7F];\n"),)),
    ("b3 bytes behind a type alias", ((_BLISTEN, "", "\ntype Frame = [u8; 16];\nstatic EMPTY: Frame = [0; 16];\n"),)),
    ("b4 u8 renamed", ((_BLIB, "", "\nuse core::primitive::u8 as Byte;\nstatic PROGRAM: [Byte; 8] = [0; 8];\n"),)),
    ("b5 a byte string in main.rs", ((_BMAIN, "", '\nstatic FRAME: &[u8; 4] = b"\\x06\\0\\0\\0";\n'),)),
)
# HE-005A U5 (MON-HE005A-U5, MON-HE005A-U5-1): the broker rules' rows, shared by BrokerRuleTests and the mutation proof
# (HE005A_PROOF_RULES), each check its own one clause. A row is (label, clause, changes) or, where the self-test matches
# a row's own message, (label, clause, changes, message); the proof reads the first three.
_BSTAGE2 = "    let sealed = match seal_stage2(stage1) {"
_BTAIL = "    ExitCode::from(serve(&sealed, config))\n}"
_BSERVE_USE = "    use planeon_broker::serve_unanswered;\n"
_FILTER_ARM = "        SealStep::Filter => 66,"
_TWO_ARMS = "        SealStep::UserIds => 41,\n        SealStep::GroupIds => 42,"
# The broker's seal-order site (check_seal_order with BROKER_SEAL_SITE; Q-HE5A-1 (a)).
HE005A_SITE_ROWS = (
    ("m1 a statement between the stages", "(site)", ((_BMAIN, _BSTAGE2, "    let _x = 1;\n" + _BSTAGE2),),
     "runs something between the seal's stages|seal-order grammar"),
    ("m2 a call between the stages", "(site)", ((_BMAIN, _BSTAGE2, "    let _ = early();\n" + _BSTAGE2),),
     "seal-order grammar"),
    ("m3 another tail", "(site)", ((_BMAIN, _BTAIL, "    ExitCode::from(status::LISTENER)\n}"),), "seal-order grammar"),
    ("m4 a pinned import dropped", "(site)", ((_BMAIN, _BSERVE_USE, ""),), "pinned set"),
    ("m5 an import added", "(site)", ((_BMAIN, _BSERVE_USE, _BSERVE_USE + "    use planeon_broker::seal;\n"),),
     "pinned set"),
    ("m6 another fn", "(site)", ((_BMAIN, "", "\nfn other() {}\n"),), "functions other than"),
    ("m7 a const item", "(site)", ((_BMAIN, "", "\nconst C: u8 = 0;\n"),), "defines a const item"),
    ("m8 code in the stage-2 arm", "(site)", ((_BMAIN, "Ok(sealed) => sealed,", "Ok(sealed) => { early(); sealed }"),),
     "second stage is not exactly"),
)
# The broker's include rule (check_broker_includes): its change rows; the missing seal.rs stays BrokerRuleTests' own.
HE005A_INCLUDE_ROWS = (
    ("i1 a WORKER program embedded", "(includes)",
     ((_BSEAL, "", '\npub static W: &[u8; 1496] = include_bytes!("../../../contracts/seccomp-v3/WORKER.x86_64.bpf");\n'),)),
    ("i2 the OBSERVER program in BROKER's place", "(includes)",
     ((_BSEAL, _BROKER_X86, 'include_bytes!("../../../contracts/seccomp-v5/OBSERVER.x86_64.bpf")'),)),
    ("i3 a concat! path", "(includes)",
     ((_BSEAL, _BROKER_ARM, 'include_bytes!(concat!("../../../contracts/seccomp-v3/", "BROKER.aarch64.bpf"))'),)),
    ("i4 include_str! of a program", "(includes)",
     ((_BSEAL, _BROKER_ARM, _BROKER_ARM.replace("include_bytes", "include_str")),)),
    ("i5 a program embedded in lib.rs", "(includes)",
     ((_BLIB, "", '\npub static P: &[u8] = include_bytes!("../../../contracts/seccomp-v3/BROKER.x86_64.bpf");\n'),)),
    ("i6 include_str! in status.rs", "(includes)",
     ((_BSTATUS, "", '\nconst P: &str = include_str!("../../../contracts/seccomp-v3/WORKER.aarch64.bpf");\n'),)),
)
# The status-table text rule (check_broker_status_table; Q-HE5A-2 (a)).
HE005A_TABLE_ROWS = (
    ("q1 the broker's Filter status moved", "(table)", ((_BSTATUS, _FILTER_ARM, "        SealStep::Filter => 67,"),)),
    ("q2 the observer's Filter status moved", "(table)", ((_OSTATUS, _FILTER_ARM, "        SealStep::Filter => 67,"),)),
    ("q3 NOT_YET_SERVING moved", "(table)",
     ((_BSTATUS, "pub const NOT_YET_SERVING: u8 = 10;", "pub const NOT_YET_SERVING: u8 = 11;"),)),
    ("q4 NOT_LINUX moved", "(table)", ((_BSTATUS, "pub const NOT_LINUX: u8 = 2;", "pub const NOT_LINUX: u8 = 3;"),)),
    ("q5 two arms swapped", "(table)",
     ((_BSTATUS, _TWO_ARMS, "        SealStep::GroupIds => 42,\n        SealStep::UserIds => 41,"),)),
    ("q6 the parameter renamed", "(table)",
     ((_BSTATUS, "pub fn seal_step(step: SealStep) -> u8 {", "pub fn seal_step(stage: SealStep) -> u8 {"),)),
)
# The channel home: the socket-module rule (check_socket_modules) and its alias rule (check_socket_module_aliases).
HE005A_MODULE_ROWS = (
    ("c1 a channel import in status.rs", "(modules)", ((_BSTATUS, "", "\nuse gate_sys::channel::Poller;\n"),),
     "socket-module check"),
    ("c2 a channel path in seal.rs", "(modules)", ((_BSEAL, "", "\nfn f() { let _ = gate_sys::channel::accept; }\n"),),
     "socket-module check"),
    ("c3 a re-export from linux_listen.rs", "(modules)", ((_BLISTEN, "", "\npub use gate_sys::channel::Conn;\n"),),
     "re-exports"),
    ("c4 a pub fn handing out the listener", "(modules)",
     ((_BLISTEN, "", "\npub fn raw(i: &LinuxI02) -> &channel::Listener { x() }\n"),),
     "pub item naming gate-sys's socket items"),
    ("c5 a thread in linux_listen.rs", "(modules)", ((_BLISTEN, "", "\nfn f() { std::thread::spawn(g); }\n"),),
     "names std::thread"),
)
HE005A_ALIAS_ROWS = (
    ("c6 lib.rs re-exporting through linux_listen", "(aliases)", ((_BLIB, "", "\npub use linux_listen::LinuxI02;\n"),),
     "re-exports a path through a socket module"),
    ("c7 main.rs importing linux_listen", "(aliases)", ((_BMAIN, "", "\nuse planeon_broker::linux_listen;\n"),),
     "imports the socket module linux_listen itself"),
    ("c8 a rename of the library root", "(aliases)", ((_BMAIN, "", "\nuse planeon_broker as b;\n"),),
     "imports or renames a scope root"),
)
# HE-005A PR review round 1, R1-4 (folded under MON-HE005A-R1): the broker's never-unlink rule (check_broker_never_unlinks,
# G-I01-1's I01_REMOVALS form), one clause: the reviewer's probe p4 and the rule's other removal words.
HE005A_UNLINK_ROWS = (
    ("u1 an unlink call in linux_listen.rs (probe p4)", "(unlink)",
     ((_BLISTEN, "", "\nfn clear() {\n    unlink(I02_PATH);\n}\n"),)),
    ("u2 remove_file of the I02 path", "(unlink)",
     ((_BLISTEN, "", "\nfn clear() {\n    let _ = std::fs::remove_file(I02_PATH);\n}\n"),)),
    ("u3 remove_dir in lib.rs", "(unlink)", ((_BLIB, "", "\nfn clear(dir: &str) {\n    let _ = std::fs::remove_dir(dir);\n}\n"),)),
    ("u4 remove_dir_all in main.rs", "(unlink)",
     ((_BMAIN, "", "\nfn clear(dir: &str) {\n    let _ = std::fs::remove_dir_all(dir);\n}\n"),)),
    ("u5 rename in seal.rs", "(unlink)",
     ((_BSEAL, "", "\nfn moved(from: &str, to: &str) {\n    let _ = std::fs::rename(from, to);\n}\n"),)),
    ("u6 hard_link in status.rs", "(unlink)",
     ((_BSTATUS, "", "\nfn linked(from: &str, to: &str) {\n    let _ = std::fs::hard_link(from, to);\n}\n"),)),
)
# HE-005A PR review round 1, R1-5 (folded under MON-HE005A-R1): the broker's serve (check_broker_serve, G5's form), its
# clauses (a) the calls named once each, in order, and (b) the exact body: the reviewer's probe p5, and forms that skip,
# repeat or wrap the listener seam.
_BSERVE_CALL = "    status::listener(&serve_unanswered(&mut LinuxI02::new(sealed)))"
HE005A_SERVE_ROWS = (
    ("w1 no listener, NOT_YET_SERVING after the seal (probe p5)", "(a)",
     ((_BMAIN, _BSERVE_CALL, "    let _ = sealed;\n    status::NOT_YET_SERVING"),)),
    ("w2 the listener built but never served", "(a)",
     ((_BMAIN, _BSERVE_CALL, "    let _ = LinuxI02::new(sealed);\n    status::LISTENER"),)),
    ("w3 the seam run twice", "(a)",
     ((_BMAIN, _BSERVE_CALL, "    let _ = serve_unanswered(&mut LinuxI02::new(sealed));\n" + _BSERVE_CALL),)),
    ("w4 the call wrapped in a loop", "(b)",
     ((_BMAIN, _BSERVE_CALL, "    loop {\n        status::listener(&serve_unanswered(&mut LinuxI02::new(sealed)));\n    }"),)),
    ("w5 the status discarded and another returned", "(b)",
     ((_BMAIN, _BSERVE_CALL, "    let _ = status::listener(&serve_unanswered(&mut LinuxI02::new(sealed)));\n"
                             "    status::NOT_YET_SERVING"),)),
    ("w6 the call inside a branch", "(b)",
     ((_BMAIN, _BSERVE_CALL, "    if ready() {\n        status::listener(&serve_unanswered(&mut LinuxI02::new(sealed)))\n"
                             "    } else {\n        status::NOT_LINUX\n    }"),)),
)
ROLE_SEAL_TAGS = {"(e)": "(role-seal rule (e), clause (e))", "(f)": "(role-seal rule (f), R1-2)",
                  "(g)": "(role-seal rule (g), R1-3)"}
SEAL_TOKEN_FUNCTIONS = {"(i)": "tokens_i_definition", "(ii)": "tokens_ii_construction",
                        "(iii)": "tokens_iii_signatures", "(iv)": "tokens_iv_impls", "(v)": "tokens_v_names"}
STAGE_CALL_FUNCTIONS = {"(a)": "stage_calls_a_uses", "(b)": "stage_calls_b_elsewhere", "(c)": "stage_calls_c_sites"}
SERVE_FUNCTIONS = {"(a)": "serve_a_calls_once", "(b)": "serve_b_body_exact", "(c)": "serve_c_isolation"}


def role_seal_patches(enabled=None, disabled=()):
    """check_role_seal's clauses are function objects in ROLE_SEAL_CLAUSES, so one patch of the table: with `enabled`
    every other clause a no-op, and every clause of `disabled` a no-op."""
    clauses = tuple((name, clause if (enabled is None or "(%s)" % name == enabled) and "(%s)" % name not in disabled
                     else (lambda base: 0)) for name, clause in gate.ROLE_SEAL_CLAUSES)
    return [mock.patch.object(gate, "ROLE_SEAL_CLAUSES", clauses)]


def named_patches(functions):
    """For a check that calls its clause functions by name: patches making every clause but `enabled`, and every clause
    of `disabled`, a no-op."""
    def patches(enabled=None, disabled=()):
        return [mock.patch.object(gate, name, lambda *args, **kwargs: 0) for clause, name in functions.items()
                if (enabled is not None and clause != enabled) or clause in disabled]
    return patches


# (rule, check, its clauses, rows, the named clause's message, any clause's message, the patches).
HE005A_PROOF_RULES = (
    ("clause (e), R1-2, R1-3", gate.check_role_seal, tuple("(%s)" % name for name, _ in gate.ROLE_SEAL_CLAUSES),
     HE005A_E_ROWS + HE005A_F_ROWS + HE005A_G_ROWS, lambda clause: ROLE_SEAL_TAGS[clause], r"\(role-seal rule \([a-g]\)",
     role_seal_patches),
    ("R1-1", gate.check_seal_tokens, tuple(SEAL_TOKEN_FUNCTIONS), HE005A_TOKEN_ROWS,
     lambda clause: "(seal tokens closed, R1-1 %s)" % clause, r"\(seal tokens closed, R1-1 \(", named_patches(SEAL_TOKEN_FUNCTIONS)),
    ("R1-5", gate.check_role_seal_stage_calls, tuple(STAGE_CALL_FUNCTIONS), HE005A_STAGE_ROWS,
     lambda clause: "(role-seal stage calls, R1-5 %s)" % clause, r"\(role-seal stage calls, R1-5 \(",
     named_patches(STAGE_CALL_FUNCTIONS)),
    # HE-005A U5 (MON-HE005A-U5, MON-HE005A-U5-1): R1-2's broker form and the broker rules. None of these checks has
    # clause functions of its own (check_seal_order's check_main_shape and check_socket_modules' check_socket_items are
    # helpers called between inline clauses), so each is its own one clause: a by-name wrapper, switched off by a name
    # patch.
    ("R1-2 broker form", lambda base: gate.check_broker_bytes(base), ("(bytes)",),
     tuple((label, "(bytes)", changes) for label, changes in HE005A_BYTES_ROWS), lambda clause: "(broker bytes, R1-2)",
     re.escape("(broker bytes, R1-2)"), named_patches({"(bytes)": "check_broker_bytes"})),
    ("broker seal site", lambda base: gate.check_seal_order(base, gate.BROKER_SEAL_SITE), ("(site)",),
     tuple(row[:3] for row in HE005A_SITE_ROWS), lambda clause: "(seal-order grammar)",
     re.escape("(seal-order grammar)"), named_patches({"(site)": "check_seal_order"})),
    ("broker includes", lambda base: gate.check_broker_includes(base), ("(includes)",), HE005A_INCLUDE_ROWS,
     lambda clause: "(broker includes)", re.escape("(broker includes)"),
     named_patches({"(includes)": "check_broker_includes"})),
    ("broker status table", lambda base: gate.check_broker_status_table(base), ("(table)",), HE005A_TABLE_ROWS,
     lambda clause: "(broker status table, Q-HE5A-2)", re.escape("(broker status table, Q-HE5A-2)"),
     named_patches({"(table)": "check_broker_status_table"})),
    ("channel home", lambda base: gate.check_socket_modules(base), ("(modules)",),
     tuple(row[:3] for row in HE005A_MODULE_ROWS), lambda clause: "(socket-module check)",
     re.escape("(socket-module check)"), named_patches({"(modules)": "check_socket_modules"})),
    ("channel home aliases", lambda base: gate.check_socket_module_aliases(base), ("(aliases)",),
     tuple(row[:3] for row in HE005A_ALIAS_ROWS), lambda clause: "(socket-module aliases, G-I01B-6 (e))",
     re.escape("(socket-module aliases, G-I01B-6 (e))"), named_patches({"(aliases)": "check_socket_module_aliases"})),
    # HE-005A PR review round 1 (MON-HE005A-R1): R1-4's never-unlink rule, one clause, and R1-5's serve rule, whose two
    # clauses are its own functions.
    ("broker never unlinks", lambda base: gate.check_broker_never_unlinks(base), ("(unlink)",), HE005A_UNLINK_ROWS,
     lambda clause: "(broker never unlinks, R1-4)", re.escape("(broker never unlinks, R1-4)"),
     named_patches({"(unlink)": "check_broker_never_unlinks"})),
    ("broker serve", gate.check_broker_serve, tuple(SERVE_FUNCTIONS), HE005A_SERVE_ROWS,
     lambda clause: "(broker serve, R1-5 %s)" % clause, r"\(broker serve, R1-5 \(", named_patches(SERVE_FUNCTIONS)),
)


class He005aObligationTests(Tree):
    """HE-005A's blocking obligations over copies of the real sources (HE005A_TREE): check_role_seal's clauses (e)
    (MON-HE005A0-U4), (f) (R1-2) and (g) (R1-3), check_seal_tokens (R1-1) and check_role_seal_stage_calls (R1-5) accept
    today's sources; each row is refused by its rule, and with every other clause of the rule disabled, by its own named
    clause's message; and check_broker_bytes refuses R1-2's broker rows."""

    TREE = HE005A_TREE

    def plant(self, changes):
        for rel, text in he005a_tree(changes).items():
            self.write(rel, text)

    def test_the_real_sources_and_the_fixture_pass(self):
        for base in (self.base, gate.HE):
            self.assertEqual(gate.check_role_seal(base), 18)
            self.assertEqual(gate.check_seal_tokens(base), 5)
            self.assertEqual(gate.check_role_seal_stage_calls(base), 2)
            # HE-005B: the four logic modules are broker sources outside seal.rs too (4 + 4); HE-005C: the
            # configuration's two and the lifecycle's fourteen (24).
            self.assertEqual(gate.check_broker_bytes(base), 24)
        # (e) reads role-seal's lib.rs and the broker's five sources (HE-005B: and its four logic modules, so ten;
        # HE-005C: and the configuration's two and the lifecycle's fourteen, so 26); (g) finds LinuxOps's own_status.
        self.assertEqual([clause(self.base) for _, clause in gate.ROLE_SEAL_CLAUSES], [1, 18, 6, 1, 26, 0, 1])
        self.assertEqual(gate.ROLE_SEAL_SITES, (gate.OBSERVER_SEAL_RS, gate.BROKER_SEAL_RS))

    def test_the_tables(self):
        self.assertEqual((len(HE005A_E_ROWS), len(HE005A_F_ROWS), len(HE005A_G_ROWS)), (12, 6, 6))
        self.assertEqual((len(HE005A_TOKEN_ROWS), len(HE005A_STAGE_ROWS), len(HE005A_BYTES_ROWS)), (23, 24, 5))
        self.assertEqual(tuple(len(rows) for rows in (HE005A_SITE_ROWS, HE005A_INCLUDE_ROWS, HE005A_TABLE_ROWS,
                                                      HE005A_MODULE_ROWS, HE005A_ALIAS_ROWS)), (8, 6, 6, 5, 3))
        self.assertEqual((len(HE005A_UNLINK_ROWS), len(HE005A_SERVE_ROWS)), (6, 6))
        self.assertEqual(sum(len(rule[3]) for rule in HE005A_PROOF_RULES), 116)
        for name, check, clauses, rows, tag, any_tag, patches in HE005A_PROOF_RULES:
            self.assertTrue(callable(check), name)
            for row in rows:
                self.assertIn(row[1], clauses, row[0])
                he005a_tree(row[2])
        for function in (list(SEAL_TOKEN_FUNCTIONS.values()) + list(STAGE_CALL_FUNCTIONS.values())
                         + list(SERVE_FUNCTIONS.values())):
            self.assertTrue(callable(getattr(gate, function)), function)
        for row in HE005A_BYTES_ROWS:
            he005a_tree(row[1])

    def refuses_each(self, check, rows, tag, any_tag, patches):
        for label, clause, changes in rows:
            self.plant(changes)
            try:
                with self.assertRaisesRegex(gate.GateError, any_tag, msg=label):
                    check(self.base)
                active = patches(enabled=clause)
                for patch in active:
                    patch.start()
                try:
                    with self.assertRaisesRegex(gate.GateError, re.escape(tag(clause)), msg=label):
                        check(self.base)
                finally:
                    for patch in active:
                        patch.stop()
            finally:
                self.plant(())

    def test_clause_e_f_and_g_rows(self):
        _, check, _, rows, tag, any_tag, patches = HE005A_PROOF_RULES[0]
        self.refuses_each(check, rows, tag, any_tag, patches)

    def test_r1_1_rows(self):
        _, check, _, rows, tag, any_tag, patches = HE005A_PROOF_RULES[1]
        self.refuses_each(check, rows, tag, any_tag, patches)

    def test_r1_5_rows(self):
        _, check, _, rows, tag, any_tag, patches = HE005A_PROOF_RULES[2]
        self.refuses_each(check, rows, tag, any_tag, patches)

    def test_r1_2_broker_rows(self):
        for label, changes in HE005A_BYTES_ROWS:
            self.plant(changes)
            try:
                with self.assertRaisesRegex(gate.GateError, re.escape("(broker bytes, R1-2)"), msg=label):
                    gate.check_broker_bytes(self.base)
            finally:
                self.plant(())

    def test_r1_4_and_r1_5_folds(self):
        # HE-005A PR review round 1 (MON-HE005A-R1): the broker's never-unlink rule (R1-4) and serve rule (R1-5) accept
        # today's sources, refuse each row with only its own clause on, and pass a comment, a literal and spacing.
        for base in (self.base, gate.HE):
            # HE-005B: and the four logic modules; HE-005C: and the configuration's and lifecycle's sixteen.
            self.assertEqual(gate.check_broker_never_unlinks(base), 25)
            self.assertEqual(gate.check_broker_serve(base), 6)  # HE-005C (G-HE5C-11): six named calls
        rules = {rule[0]: rule for rule in HE005A_PROOF_RULES}
        for name in ("broker never unlinks", "broker serve"):
            _, check, _, rows, tag, any_tag, patches = rules[name]
            self.refuses_each(check, rows, tag, any_tag, patches)
        for changes, check in (
                (((_BLISTEN, "", "\n// HE-008's unit unlinks a stale socket, never the broker\n"),), gate.check_broker_never_unlinks),
                (((_BLISTEN, "", '\nconst NOTE: &str = "never unlink, rename or remove_file";\n'),),
                 gate.check_broker_never_unlinks),
                (((_BMAIN, _BSERVE_CALL, "    // the one seam\n    status::listener( & serve_unanswered ( &mut LinuxI02::new(sealed) ) )"),),
                 gate.check_broker_serve)):
            self.plant(changes)
            try:
                check(self.base)
            finally:
                self.plant(())

    def test_forms_the_rules_pass(self):
        # Comments, a Display-only literal, a fn taking bytes, a fn returning bytes it was given, the strict test block
        # (which formats Stage1 and builds its fixture), a type item without u8, and the broker's u8 status constants.
        for changes, checks in (
                ((role_seal_planted('// format!("{:?}", stage1), unwrap_err, impl Default for Sealed\n'
                                    'const SHOWN: &str = "{}";\ntype Count = u64;\n'
                                    "fn count(program: &[u8]) -> usize {\n    program[..].len()\n}\n"
                                    "fn same(program: &'static [u8]) -> &'static [u8] {\n    program\n}"),),
                 (gate.check_role_seal, gate.check_seal_tokens)),
                (((_BSTATUS, "", "\n// pub const STAGES: [u8; 2] = [2, 10];\npub const EXTRA: u8 = 99;\n"),),
                 (gate.check_broker_bytes, gate.check_role_seal))):
            self.plant(changes)
            try:
                for check in checks:
                    check(self.base)
            finally:
                self.plant(())

    def test_the_reading_helpers(self):
        self.assertEqual(gate.return_type("<O: SealOps>(ops: &mut O) -> io::Result<Vec<u8>> where O: Copy "),
                         " io::Result<Vec<u8>> ")
        self.assertEqual(gate.return_type("(program: &[u8]) "), "")
        self.assertEqual(gate.return_type("(f: impl Fn(u8) -> u8) -> u16 "), " u16 ")
        self.assertEqual(gate.masked_literals('a("{", \'}\') {'), 'a("_", \'_\') {')
        self.assertEqual(gate.resolved_uses([(("role_seal",), "rs"), (("rs", "seal_stage1"), None)], root="role_seal"),
                         [(("role_seal",), "rs"), (("role_seal", "seal_stage1"), None)])
        self.assertEqual(gate.resolved_uses([(("role_seal",), "rs"), (("rs", "x"), None)]),
                         [(("role_seal",), "rs"), (("rs", "x"), None)], "gate_sys by default")


class BrokerRuleTests(Tree):
    """HE-005A's other rules over copies of the real sources: the broker's include rule, its no-panic list, its status
    table against the observer's (Q-HE5A-2 (a)), its seal-order site (Q-HE5A-1 (a)) and its one socket file."""

    TREE = HE005A_TREE

    def plant(self, changes):
        for rel, text in he005a_tree(changes).items():
            self.write(rel, text)

    def refuses(self, check, changes, message):
        self.plant(changes)
        try:
            with self.assertRaisesRegex(gate.GateError, message, msg=repr(changes)[:120]):
                check(self.base)
        finally:
            self.plant(())

    def test_the_real_sources_and_the_fixture_pass(self):
        for base in (self.base, gate.HE):
            # HE-005B (G-HE5B-4, G-HE5B-2): i02.rs's one schema beside seal.rs's two programs; four more no-panic files.
            # HE-005C (G-HE5C-8): spawn.rs's two WORKER programs and signed_config.rs's key; the configuration's,
            # the lifecycle's and broker-sys's eighteen more no-panic files.
            self.assertEqual(gate.check_broker_includes(base), 6)
            self.assertEqual(gate.check_broker_no_panic(base), 27)
            self.assertEqual(gate.check_broker_status_table(base), 22)
            self.assertEqual(gate.check_seal_order(base, gate.BROKER_SEAL_SITE),
                             "BrokerConfig::parse, Err, ExitCode::from, Ok, signed_config::load, status::seal (and the "
                             "tuple-variant patterns LoadError::Signature)")
        self.assertGreater(gate.check_socket_modules(self.base), 0)
        self.assertGreater(gate.check_socket_module_aliases(self.base), 0)
        self.assertEqual(gate.BROKER_SEAL_SITE["calls"], gate.BROKER_SEAL_CALLS)  # HE-005C (G-HE5C-13)
        self.assertTrue(gate.BROKER_SEAL_SITE["configured"])
        self.assertIn(gate.BROKER_LINUX_LISTEN, gate.SOCKET_FILES)
        self.assertEqual(gate.SOCKET_CRATE_MODULES[gate.BROKER_CRATE], ("linux_listen",))
        self.assertIn(gate.BROKER_CRATE, gate.POST_SEAL_CRATES)
        self.assertEqual((gate.CRATE_ROOTS[gate.BROKER_LIB], gate.CRATE_ROOTS[gate.BROKER_MAIN]),
                         ("#![forbid(unsafe_code)]", "#![forbid(unsafe_code)]"))

    def test_the_include_rule(self):
        message = re.escape("(broker includes)")
        for _, _, changes in HE005A_INCLUDE_ROWS:
            self.refuses(gate.check_broker_includes, changes, message)
        (self.base / _BSEAL).unlink()
        with self.assertRaisesRegex(gate.GateError, "seal.rs is missing .broker includes"):
            gate.check_broker_includes(self.base)

    def test_the_no_panic_list(self):
        message = r"outside a strict #\[cfg\(test\)\] mod tests block .broker no-panic tripwire"
        for changes in (((_BLISTEN, "", "\nfn first(v: &[u8]) -> u8 {\n    *v.first().unwrap()\n}\n"),),
                        ((_BLIB, "", '\nfn f(x: Option<u8>) -> u8 {\n    x.expect("x")\n}\n'),),
                        ((_BSEAL, "", "\nconst _: () = assert!({ INSTRUCTIONS_X86_64 } == 326);\n"),),
                        ((_BSTATUS, "", "\nfn f(x: u8) {\n    assert!(x < 200);\n}\n"),),
                        ((_BMAIN, "", "\nfn f() {\n    panic!();\n}\n"),)):
            self.refuses(gate.check_broker_no_panic, changes, message)
        self.plant(((_BLIB, "", "\n// unwrap() and panic! in a comment\n"),))
        self.assertEqual(gate.check_broker_no_panic(self.base), 27)

    def test_the_status_table_is_the_observers(self):
        message = re.escape("(broker status table, Q-HE5A-2)")
        for _, _, changes in HE005A_TABLE_ROWS:
            self.refuses(gate.check_broker_status_table, changes, message)
        # Comments and spacing are not text the rule compares.
        self.plant(((_BSTATUS, _FILTER_ARM, "        SealStep::Filter  =>  66, // the install"),))
        self.assertEqual(gate.check_broker_status_table(self.base), 22)

    def test_the_seal_order_site(self):
        site = lambda base: gate.check_seal_order(base, gate.BROKER_SEAL_SITE)
        for _, _, changes, message in HE005A_SITE_ROWS:
            self.refuses(site, changes, message)

    def test_the_one_socket_file(self):
        for check, rows in ((gate.check_socket_modules, HE005A_MODULE_ROWS),
                            (gate.check_socket_module_aliases, HE005A_ALIAS_ROWS)):
            for _, _, changes, message in rows:
                self.refuses(check, changes, message)


class BrokerLinkedTests(Tree):
    """HE-005A: the broker's crate is linked (its main.rs's one exit import, its roots' attribute) and joins the gate's
    post-seal list; containment stays the unlinked binary."""

    TREE = LINKED_TREE

    def test_the_broker_is_scanned(self):
        main = gate.BROKER_MAIN
        good = LINKED_TREE[main] + "use std::process::ExitCode;\n"
        self.write(main, good)
        self.assertEqual(gate.check_linked_sources(self.base), 16)
        for text in (good + "use std::process::ExitCode;\n", good + "fn f() { std::process::exit(1); }\n",
                     LINKED_TREE[main] + "fn f() { let _ = std::env::args_os(); }\n"):
            self.refused(gate.check_linked_sources, main, text, "linked-source tripwire")
        self.refused(gate.check_linked_sources, gate.BROKER_LIB, LINKED_TREE[gate.BROKER_LIB] + "use std::process::ExitCode;\n",
                     "std::process")
        self.refused(gate.check_linked_sources, gate.BROKER_LIB, "pub mod linux_listen;\n", "lacks #!\\[forbid")
        self.refused(gate.check_debug_derives, gate.BROKER_LIB, LINKED_TREE[gate.BROKER_LIB]
                     + "#[derive(Debug)]\npub struct Held { listener: Listener }\n", "Debug check")
        self.refused(gate.check_foreign_items, gate.BROKER_LINUX_LISTEN, LINKED_TREE[gate.BROKER_LINUX_LISTEN]
                     + "unsafe extern \"C\" { fn setresuid(r: u32, e: u32, s: u32) -> i32; }\n", "declares the foreign items")
        self.refused(gate.check_prints, gate.BROKER_LIB, LINKED_TREE[gate.BROKER_LIB] + "fn f() { eprintln!(\"x\"); }\n",
                     "print rule")
        self.write(UNLINKED_MAIN, "use std::process::Command;\nfn main() { let _ = Command::new(\"x\"); }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 16)


class BrokerClosureTests(Tree):
    """HE-005A (H5D-12): planeon-broker links exactly BROKER_LINKED_CRATES (itself, role-seal and gate-sys): host-common,
    i05-protocol (HE-005B's) or any other workspace crate in its closure refuses. HE-005B (G-HE5B-3; Q-HE5B-6 (a)):
    i05-protocol joins the set, unchanged, so A's three crates (i05-protocol missing) refuse, as does host-common,
    effect-gate or any other workspace crate, directly or through role-seal. HE-005C (G-HE5C-7; the frozen seam note
    section 1): broker-sys joins the set, so B's four crates (broker-sys missing) refuse too."""

    TREE = {**WORKSPACE_TREE,
            "Cargo.toml": WORKSPACE_TREE["Cargo.toml"].replace('"crates/gate-tls"]', '"crates/gate-tls", "crates/broker", '
                                                                                   '"crates/role-seal", "crates/broker-sys"]'),
            "crates/broker/Cargo.toml": '[package]\nname = "planeon-broker"\nedition.workspace = true\n',
            "crates/role-seal/Cargo.toml": '[package]\nname = "role-seal"\nedition.workspace = true\n',
            "crates/broker-sys/Cargo.toml": '[package]\nname = "broker-sys"\nedition.workspace = true\n'}
    GOOD = {**WORKSPACE, "planeon-broker": {"gate-sys", "role-seal", "i05-protocol", "broker-sys"},
            "role-seal": {"gate-sys"}, "broker-sys": set()}

    def test_the_closure_is_exact(self):
        self.assertEqual(gate.BROKER_LINKED_CRATES, ("crates/broker", "crates/role-seal", "crates/gate-sys",
                                                     "crates/i05-protocol", "crates/broker-sys"))
        self.assertEqual(gate.check_workspace_shape(self.base, self.GOOD), 8)
        self.assertEqual(gate.check_workspace_shape(self.base, {**self.GOOD, "planeon-broker": {"role-seal", "i05-protocol",
                                                                                          "broker-sys"}}), 8)
        for dependencies in (set(), {"gate-sys"}, {"gate-sys", "role-seal"}, {"gate-sys", "i05-protocol"},
                             {"gate-sys", "role-seal", "i05-protocol"},
                             {"gate-sys", "role-seal", "i05-protocol", "broker-sys", "host-common"},
                             {"gate-sys", "role-seal", "i05-protocol", "broker-sys", "effect-gate"}):
            with self.assertRaisesRegex(gate.GateError, "planeon-broker links .*, not .* .workspace shape"):
                gate.check_workspace_shape(self.base, {**self.GOOD, "planeon-broker": dependencies, "host-common": set()})
        with self.assertRaisesRegex(gate.GateError, "planeon-broker links .*, not .* .workspace shape"):
            gate.check_workspace_shape(self.base, {**self.GOOD, "role-seal": {"gate-sys", "effect-gate"}})
        with self.assertRaisesRegex(gate.GateError, "planeon-broker links .*, not .* .workspace shape"):
            gate.check_workspace_shape(self.base, {**self.GOOD, "broker-sys": {"effect-gate"}})
        without = {name: dependencies for name, dependencies in self.GOOD.items() if name != "planeon-broker"}
        with self.assertRaisesRegex(gate.GateError, "no planeon-broker crate in the workspace"):
            gate.check_workspace_shape(self.base, without)


class BrokerBinaryTests(unittest.TestCase):
    """HE-005A (DESIGN-HE005 sections 3.5 and 4): each built planeon-broker holds its BROKER program once, no membarrier
    and none of section 3.5's symbols."""

    PROGRAM = bytes(range(16)) * 2

    def test_the_program_once_and_no_refused_symbol(self):
        raw = b"\x7fELF" + b"\0" * 64 + self.PROGRAM + b"\0" * 16
        self.assertEqual(gate.check_broker_binary({"main", "read", "__membarrier_init", "setresuid_x"}, raw, self.PROGRAM), 32)
        for name in gate.MEMBARRIER:
            with self.assertRaisesRegex(gate.GateError, "links .*membarrier.* .membarrier check"):
                gate.check_broker_binary({"read", name}, raw, self.PROGRAM)
        for name in gate.BROKER_ABSENT_SYMBOLS:
            with self.assertRaisesRegex(gate.GateError, "links \\['%s'\\] .DESIGN-HE005 section 3.5 symbol check" % name):
                gate.check_broker_binary({"read", name}, raw, self.PROGRAM)
        for count in (0, 2, 3):
            with self.assertRaisesRegex(gate.GateError, "holds its BROKER program %d times, not exactly once" % count):
                gate.check_broker_binary({"read"}, b"\0" * 8 + self.PROGRAM * count + b"\0", self.PROGRAM)
        with self.assertRaisesRegex(gate.GateError, "an empty BROKER program"):
            gate.check_broker_binary({"read"}, raw, b"")

    def test_each_target_names_its_pinned_program(self):
        self.assertEqual(set(gate.BROKER_PROGRAMS), set(gate.MACHINE))
        self.assertTrue(set(gate.BROKER_PROGRAMS.values()) <= set(gate.CONTRACTS))
        self.assertEqual(gate.BROKER_ABSENT_SYMBOLS, ("__synccall", "setresuid", "setresgid", "setuid", "setgid",
                                                      "pthread_create", "fork", "posix_spawn"))
        self.assertIn("planeon-broker", gate.BINARIES)


# --- HE-005B (DESIGN-HE005 revision 5 section 4, HE-005B; MON-HE005B-PLAN; the build brief's conditions 1 and 2) -------
# The real sources the HE-005B rules read: HE005A_TREE (the observer's and the broker's sources, the manifests A's rules
# read) and the differential test. A change is (file, anchor, replacement) as in he005a_tree, or (file, None, None),
# which removes the file. The build's mutation proof reads HE005B_PROOF_RULES with each rule's own tree builder.
HE005B_TREE = {**HE005A_TREE, gate.HE005B_DIFFERENTIAL: (gate.HE / gate.HE005B_DIFFERENTIAL).read_text(encoding="utf-8")}
_BI02, _BI03, _BI05, _BPEER = gate.HE005B_FILES
_BDIFF = gate.HE005B_DIFFERENTIAL
_I02_INCLUDE = 'include_bytes!("../../../contracts/broker-handoff-v1/channel.schema.json")'
_I02_DEPTH_FLOAT = ("    if json::depth(&value) > MAX_DEPTH {\n        return Err(FrameError::F01);\n    }\n"
                    "    if json::contains_float(&value) {\n        return Err(FrameError::F03);\n    }\n")
_I02_FLOAT_CONTROL = ("    if json::contains_float(&value) {\n        return Err(FrameError::F03);\n    }\n"
                      "    if json::contains_control(&value) {\n        return Err(FrameError::F04);\n    }\n")
_I02_COMPARE = "    if encoded != raw {\n        return Err(FrameError::F06);\n    }\n"
_I02_SCHEMA_STEP = "    if !schema.is_valid(&value) {\n        return Err(FrameError::F00);\n    }\n"
_I03_USE = "use crate::i02::{decode_datagram, Dispatch, Schemas, MAX_CONTROL_BYTES};"
_I05_USE = "use crate::i02::{BindRefusal, Verb, ZERO_DIGEST};"
_GQ_DEF = "#[derive(Debug)]\n#[must_use]\npub struct GateQualified {\n    pid: i64,\n    start_ticks: u64,\n}"
_GQ_MINT = ("pub fn qualify_gate(observed: &GateObservation, gate_executable_path: &str) -> Result<GateQualified, "
            "GateRefusal> {")


def he005b_tree(changes=()):
    """HE005B_TREE with each (file, anchor, replacement) applied once, in order (an empty anchor appends), and each
    (file, None, None) removing the file."""
    texts = dict(HE005B_TREE)
    for rel, old, new in changes:
        if old is None:
            del texts[rel]
            continue
        if not old:
            texts[rel] = texts[rel] + new
            continue
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old[:80]))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


# G-HE5B-1, the isolation (check_broker_isolation): the names (a), the type set (b), the impls (c), the uses (d).
HE005B_ISOLATION_ROWS = (
    ("n1 lib.rs declaring i02 without pub", "(a)", ((_BLIB, "pub mod i02;\n", "mod i02;\n"),)),
    ("n2 main.rs reaching i02 through the library root", "(a)",
     ((_BMAIN, "", "\nfn probe() {\n    let _ = planeon_broker::i02::decode;\n}\n"),)),
    ("n3 seal.rs importing i03", "(a)", ((_BSEAL, "", "\nuse crate::i03::start;\n"),)),
    ("n4 lib.rs re-exporting from i02", "(a)", ((_BLIB, "", "\npub use i02::decode;\n"),)),
    ("n5 status.rs naming gate_peer's refusal", "(a)",
     ((_BSTATUS, "", "\nfn probe(_: &crate::gate_peer::GateRefusal) {}\n"),)),
    ("n6 the i03 module file removed", "(a)", ((_BI03, None, None),)),
    ("n7 linux_listen.rs naming a type of i02", "(b)", ((_BLISTEN, "", "\nfn probe(_: &Transcript) {}\n"),)),
    ("n8 main.rs naming the I05 client's type", "(b)", ((_BMAIN, "", "\nfn probe(_: I05Client) {}\n"),)),
    ("n9 a Default impl in i02.rs", "(c)",
     ((_BI02, "", "\nimpl Default for Kind {\n    fn default() -> Kind {\n        Kind::Started\n    }\n}\n"),)),
    ("n10 a Display impl in i05_client.rs", "(c)",
     ((_BI05, "", "\nimpl core::fmt::Display for Operation {\n    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> "
                  "core::fmt::Result {\n        f.write_str(self.wire())\n    }\n}\n"),)),
    ("n11 a re-export in i03.rs", "(d)", ((_BI03, "", "\npub use crate::i02::Dispatch;\n"),)),
    ("n12 an item renamed in i05_client.rs", "(d)",
     ((_BI05, _I05_USE, "use crate::i02::{BindRefusal, Verb as Action, ZERO_DIGEST};"),)),
    ("n13 a glob in gate_peer.rs", "(d)", ((_BPEER, "", "\nuse crate::i02::*;\n"),)),
    ("n14 a module alias in i03.rs", "(d)", ((_BI03, _I03_USE, "use crate::i02 as wire;\n" + _I03_USE),)),
)
# G-HE5B-2, pure (check_broker_pure): the names (a), the decode order and limits (b), the differential test (c).
HE005B_PURE_ROWS = (
    ("p1 std::fs in i02.rs", "(a)", ((_BI02, "", "\nfn probe() -> bool {\n    std::fs::metadata(\"x\").is_ok()\n}\n"),)),
    ("p2 std::net in i05_client.rs", "(a)", ((_BI05, "", "\nfn probe() {\n    let _ = std::net::TcpStream::connect;\n}\n"),)),
    ("p3 std::os in gate_peer.rs", "(a)", ((_BPEER, "", "\nuse std::os::fd::OwnedFd;\n"),)),
    ("p4 std::io in i03.rs", "(a)", ((_BI03, "", "\nuse std::io::Read;\n"),)),
    ("p5 std::process in i02.rs", "(a)", ((_BI02, "", "\nfn probe() -> u32 {\n    std::process::id()\n}\n"),)),
    ("p6 std::thread in gate_peer.rs", "(a)", ((_BPEER, "", "\nfn probe() {\n    let _ = std::thread::current();\n}\n"),)),
    ("p7 gate_sys in i05_client.rs", "(a)", ((_BI05, "", "\nuse gate_sys::channel::Conn;\n"),)),
    ("p8 role_seal in i03.rs", "(a)", ((_BI03, "", "\nuse role_seal::RoleSpec;\n"),)),
    ("p9 a foreign item in gate_peer.rs", "(a)", ((_BPEER, "", "\nextern \"C\" {\n    fn getpid() -> i32;\n}\n"),)),
    ("p10 unsafe in i02.rs", "(a)",
     ((_BI02, "", "\nfn probe(value: &u8) -> u8 {\n    unsafe { *(value as *const u8) }\n}\n"),)),
    ("o1 two steps swapped: float before depth", "(b)",
     ((_BI02, _I02_DEPTH_FLOAT, _I02_DEPTH_FLOAT[_I02_DEPTH_FLOAT.index("    if json::contains_float"):]
       + _I02_DEPTH_FLOAT[:_I02_DEPTH_FLOAT.index("    if json::contains_float")]),)),
    ("o2 two steps swapped: control before float", "(b)",
     ((_BI02, _I02_FLOAT_CONTROL, _I02_FLOAT_CONTROL[_I02_FLOAT_CONTROL.index("    if json::contains_control"):]
       + _I02_FLOAT_CONTROL[:_I02_FLOAT_CONTROL.index("    if json::contains_control")]),)),
    ("o3 the canonical comparison dropped", "(b)", ((_BI02, _I02_COMPARE, "    let _ = &encoded;\n"),)),
    ("o4 the schema step dropped", "(b)", ((_BI02, _I02_SCHEMA_STEP, "    let _ = schema;\n"),)),
    ("o5 a duplicate key mapped to F06", "(b)",
     ((_BI02, "        ParseError::Duplicate => FrameError::F05,", "        ParseError::Duplicate => FrameError::F06,"),)),
    ("o6 the 16 KiB kind limit raised", "(b)",
     ((_BI02, "pub const MAX_CONTROL_BYTES: usize = 16_384;", "pub const MAX_CONTROL_BYTES: usize = 32_768;"),)),
    ("o7 the kind limit compared with the datagram bound", "(b)",
     ((_BI02, "    if control && canonical_length > MAX_CONTROL_BYTES {",
       "    if control && canonical_length > MAX_DATAGRAM_BYTES {"),)),
    ("o8 the kind limit not run by decode", "(b)", ((_BI02, "    check_control_size(&value, raw.len())?;\n", ""),)),
    ("o9 the datagram bound raised", "(b)",
     ((_BI02, "pub const MAX_DATAGRAM_BYTES: usize = 65_536;", "pub const MAX_DATAGRAM_BYTES: usize = 131_072;"),)),
    ("d1 the differential test removed", "(c)", ((_BDIFF, None, None),)),
    ("d2 a named form removed (float)", "(c)",
     ((_BDIFF, '    ("float", FrameError::F03),\n', ""),
      (_BDIFF, '        "float" => canonical(&with(frame, &["sequence"], Value::Float(1.0))),\n', ""),
      (_BDIFF, '"duplicate key", "float",\n', '"duplicate key",\n'))),
    ("d3 the digest-mismatch form removed", "(c)",
     ((_BDIFF, 'const DIGEST_MISMATCH: &str = "digest mismatch";', 'const DIGEST_MISMATCH: &str = "chain";'),
      (_BDIFF, '    assert_eq!(DIGEST_MISMATCH, "digest mismatch");', '    assert_eq!(DIGEST_MISMATCH, "chain");'))),
    # HE-005B PR review round 1, R1-3 and R1-4 (Q-HE5B-R1-2 (a)): the observer logic-module words (d) and path
    # whitelist (e), with the reviewer's three escape forms (a hashed collection, a clock, a crate:: path into the
    # broker's own I/O code), each where the reviewer's static probe planted it.
    ("q1 a HashSet type in i02.rs, not imported", "(d)",
     ((_BI02, "", "\nfn probe(set: &HashSet<u8>) -> usize {\n    set.len()\n}\n"),)),
    ("q2 std::collections::HashSet imported in i02.rs (probe)", "(d)", ((_BI02, "", "\nuse std::collections::HashSet;\n"),)),
    ("q3 RandomState imported in gate_peer.rs", "(d)",
     ((_BPEER, "", "\nuse std::collections::hash_map::RandomState;\n"),)),
    ("q4 Instant::now in i05_client.rs (probe)", "(e)",
     ((_BI05, "", "\nfn probe() -> std::time::Instant {\n    std::time::Instant::now()\n}\n"),)),
    ("q5 SystemTime::now, imported, in i03.rs (probe)", "(e)",
     ((_BI03, "", "\nuse std::time::SystemTime;\nfn probe() -> SystemTime {\n    SystemTime::now()\n}\n"),)),
    ("q6 crate::seal_stage1 in i03.rs (probe)", "(e)", ((_BI03, "", "\nfn probe() {\n    let _ = crate::seal_stage1;\n}\n"),)),
    ("q7 crate::linux_listen::LinuxI02::new in i02.rs (probe)", "(e)",
     ((_BI02, "", "\nfn probe() {\n    let _ = crate::linux_listen::LinuxI02::new;\n}\n"),)),
    ("q8 crate::serve_unanswered in gate_peer.rs (probe)", "(e)",
     ((_BPEER, "", "\nfn probe() {\n    let _ = crate::serve_unanswered;\n}\n"),)),
    ("q9 a super:: path in i03.rs", "(e)", ((_BI03, "", "\nfn probe() -> u8 {\n    super::status::LISTENER\n}\n"),)),
    ("q10 an import renamed in i05_client.rs", "(e)", ((_BI05, "", "\nuse std::collections::BTreeSet as Set;\n"),)),
    ("q11 a glob import in gate_peer.rs", "(e)", ((_BPEER, "", "\nuse std::collections::*;\n"),)),
    ("q12 i05-protocol's regex in i02.rs", "(e)", ((_BI02, "", "\nuse i05_protocol::regex::Regex;\n"),)),
)
# G-HE5B-4, the include rule (check_broker_includes, one clause): i02.rs's schema and the vectors.
HE005B_INCLUDE_ROWS = (
    ("k1 the schema embedded twice in i02.rs", "(includes)",
     ((_BI02, "", "\npub fn again() -> Result<Schemas, SchemaError> {\n    Schemas::from_json(%s)\n}\n" % _I02_INCLUDE),)),
    ("k2 include_str! of the schema", "(includes)", ((_BI02, _I02_INCLUDE, _I02_INCLUDE.replace("include_bytes", "include_str")),)),
    ("k3 the vectors in the schema's place", "(includes)",
     ((_BI02, _I02_INCLUDE, _I02_INCLUDE.replace("channel.schema.json", "vectors.json")),)),
    ("k4 the schema embedded in i05_client.rs", "(includes)", ((_BI05, "", "\nconst SCHEMA: &[u8] = %s;\n" % _I02_INCLUDE),)),
    ("k5 another contract in the schema's place", "(includes)",
     ((_BI02, _I02_INCLUDE, 'include_bytes!("../../../contracts/i05-v3/channel.schema.json")'),)),
    ("k6 a vectors.json path in i03.rs", "(includes)",
     ((_BI03, "", '\nconst VECTORS: &str = "../../../contracts/broker-handoff-v1/vectors.json";\n'),)),
    ("k7 i02.rs removed", "(includes)", ((_BI02, None, None),)),
    ("k8 the schema embedded in gate_peer.rs", "(includes)", ((_BPEER, "", "\nstatic SCHEMA: &[u8] = %s;\n" % _I02_INCLUDE),)),
    ("k9 a concat! path in i02.rs", "(includes)",
     ((_BI02, _I02_INCLUDE, 'include_bytes!(concat!("../../../contracts/broker-handoff-v1/", "channel.schema.json"))'),)),
)
# G-HE5B-5, the token (check_he005b_token): condition 2's forgery forms, each its clause's.
HE005B_TOKEN_ROWS = (
    ("g1 a pub field", "(i)", ((_BPEER, _GQ_DEF, _GQ_DEF.replace("    pid: i64,", "    pub pid: i64,")),)),
    ("g2 a pub(crate) field", "(i)", ((_BPEER, _GQ_DEF, _GQ_DEF.replace("    start_ticks: u64,", "    pub(crate) start_ticks: u64,")),)),
    ("g3 a unit struct", "(i)", ((_BPEER, _GQ_DEF, "#[derive(Debug)]\n#[must_use]\npub struct GateQualified;"),)),
    ("g4 a tuple struct", "(i)", ((_BPEER, _GQ_DEF, "#[derive(Debug)]\n#[must_use]\npub struct GateQualified(i64, u64);"),)),
    ("g5 a Default derive", "(i)", ((_BPEER, _GQ_DEF, _GQ_DEF.replace("derive(Debug)", "derive(Debug, Default)")),)),
    ("g6 a Clone derive", "(i)", ((_BPEER, _GQ_DEF, _GQ_DEF.replace("derive(Debug)", "derive(Clone, Debug)")),)),
    ("g7 a Copy derive", "(i)", ((_BPEER, _GQ_DEF, _GQ_DEF.replace("derive(Debug)", "derive(Clone, Copy, Debug)")),)),
    ("g8 a field of a type outside the closed list", "(i)",
     ((_BPEER, _GQ_DEF, _GQ_DEF.replace("    start_ticks: u64,", "    start_ticks: core::cell::Cell<u64>,")),)),
    ("g9 a second literal", "(ii)",
     ((_BPEER, "", "\nfn forge() -> GateQualified {\n    GateQualified { pid: 1, start_ticks: 1 }\n}\n"),)),
    ("g10 a Self literal", "(ii)",
     ((_BPEER, "", "\nimpl PeerCredentials {\n    fn zero() -> Self {\n        Self { pid: 0, uid: 0, gid: 0 }\n    }\n}\n"),)),
    ("g11 a struct literal in another module", "(ii)",
     ((_BI02, "", "\nfn forge() -> crate::gate_peer::GateQualified {\n"
                  "    crate::gate_peer::GateQualified { pid: 1, start_ticks: 1 }\n}\n"),)),
    ("g12 a minting function generic over a trait", "(iii)",
     ((_BPEER, _GQ_MINT, _GQ_MINT.replace("qualify_gate(", "qualify_gate<O: Into<GateObservation>>(")),)),
    ("g13 a From impl", "(iv)",
     ((_BPEER, "", "\nimpl From<u64> for GateQualified {\n    fn from(_ticks: u64) -> GateQualified {\n        loop {}\n"
                   "    }\n}\n"),)),
    ("g14 a Default impl", "(iv)",
     ((_BPEER, "", "\nimpl Default for GateQualified {\n    fn default() -> GateQualified {\n        loop {}\n    }\n}\n"),)),
    ("g15 an inherent impl", "(iv)",
     ((_BPEER, "", "\nimpl GateQualified {\n    fn pid(&self) -> i64 {\n        self.pid\n    }\n}\n"),)),
    ("g16 pub use .. as G", "(v)", ((_BI02, "", "\npub use crate::gate_peer::GateQualified as G;\n"),)),
    ("g17 a glob re-export", "(v)", ((_BI03, "", "\npub use crate::gate_peer::*;\n"),)),
    ("g18 a type alias", "(v)", ((_BI05, "", "\ntype Qualified = crate::gate_peer::GateQualified;\n"),)),
    ("g19 a re-export in lib.rs", "(v)", ((_BLIB, "", "\npub use gate_peer::GateQualified;\n"),)),
)
HE005B_ISOLATION_FUNCTIONS = {"(a)": "isolation_a_names", "(b)": "isolation_b_types", "(c)": "isolation_c_impls",
                              "(d)": "isolation_d_uses"}
HE005B_PURE_FUNCTIONS = {"(a)": "pure_a_names", "(b)": "pure_b_decode_order", "(c)": "pure_c_presence",
                         "(d)": "pure_d_words", "(e)": "pure_e_paths"}
HE005B_TOKEN_FUNCTIONS = {"(i)": "gate_token_i_definition", "(ii)": "gate_token_ii_literal",
                          "(iii)": "gate_token_iii_signature", "(iv)": "gate_token_iv_impls", "(v)": "gate_token_v_names"}

# G-HE5B-3, the closure (check_workspace_shape's broker block, gate.py's `if "planeon-broker" in names:`; Q-HE5B-6 (a),
# the block's proof rows): a workspace fixture whose broker, role-seal and host-common manifests are read for their path
# dependencies beside WORKSPACE's.
HE005B_CLOSURE_TREE = {
    **WORKSPACE_TREE,
    "Cargo.toml": WORKSPACE_TREE["Cargo.toml"].replace(
        '"crates/gate-tls"]', '"crates/gate-tls", "crates/broker", "crates/role-seal", "crates/host-common", '
                              '"crates/broker-sys"]'),
    "crates/broker/Cargo.toml": ('[package]\nname = "planeon-broker"\nedition.workspace = true\n\n[dependencies]\n'
                                 'gate-sys = { path = "../gate-sys" }\nrole-seal = { path = "../role-seal" }\n'
                                 'i05-protocol = { path = "../i05-protocol" }\nbroker-sys = { path = "../broker-sys" }\n'),
    # HE-005C (G-HE5C-7): broker-sys, std only, no dependency.
    "crates/broker-sys/Cargo.toml": '[package]\nname = "broker-sys"\nedition.workspace = true\n',
    "crates/role-seal/Cargo.toml": ('[package]\nname = "role-seal"\nedition.workspace = true\n\n[dependencies]\n'
                                    'gate-sys = { path = "../gate-sys" }\n'),
    "crates/host-common/Cargo.toml": '[package]\nname = "host-common"\nedition.workspace = true\n',
}
_CLOSURE_I05 = 'i05-protocol = { path = "../i05-protocol" }\n'


def he005b_closure_tree(changes=()):
    """HE005B_CLOSURE_TREE with each (file, anchor, replacement) applied once (an empty anchor appends)."""
    texts = dict(HE005B_CLOSURE_TREE)
    for rel, old, new in changes:
        if not old:
            texts[rel] = texts[rel] + new
            continue
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old[:80]))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


def he005b_closure_check(base):
    """check_workspace_shape over the fixture, its workspace WORKSPACE's with the three manifests' path dependencies."""
    workspace = {name: set(dependencies) for name, dependencies in WORKSPACE.items()}
    for rel in ("crates/broker/Cargo.toml", "crates/role-seal/Cargo.toml", "crates/host-common/Cargo.toml",
                "crates/broker-sys/Cargo.toml"):
        table = gate.tomllib.loads((base / rel).read_text(encoding="utf-8"))
        workspace[table["package"]["name"]] = set(table.get("dependencies", {}))
    return gate.check_workspace_shape(base, workspace)


HE005B_CLOSURE_ROWS = (
    ("l1 A's three crates (i05-protocol dropped)", "(closure)", (("crates/broker/Cargo.toml", _CLOSURE_I05, ""),)),
    ("l2 host-common added", "(closure)",
     (("crates/broker/Cargo.toml", "", 'host-common = { path = "../host-common" }\n'),)),
    ("l3 effect-gate added", "(closure)",
     (("crates/broker/Cargo.toml", "", 'effect-gate = { path = "../effect-gate" }\n'),)),
    ("l4 effect-gate reached through role-seal", "(closure)",
     (("crates/role-seal/Cargo.toml", "", 'effect-gate = { path = "../effect-gate" }\n'),)),
    ("l5 role-seal dropped", "(closure)",
     (("crates/broker/Cargo.toml", 'role-seal = { path = "../role-seal" }\n', ""),)),
)

# (rule, check, its clauses, rows, the named clause's message, any clause's message, the patches, the tree builder).
HE005B_PROOF_RULES = (
    ("G-HE5B-1 isolation", gate.check_broker_isolation, tuple(HE005B_ISOLATION_FUNCTIONS), HE005B_ISOLATION_ROWS,
     lambda clause: "(HE-005B isolation, G-HE5B-1 %s)" % clause, r"\(HE-005B isolation, G-HE5B-1 \(",
     named_patches(HE005B_ISOLATION_FUNCTIONS), he005b_tree),
    ("G-HE5B-2 pure", gate.check_broker_pure, tuple(HE005B_PURE_FUNCTIONS), HE005B_PURE_ROWS,
     lambda clause: "(HE-005B pure, G-HE5B-2 %s)" % clause, r"\(HE-005B pure, G-HE5B-2 \(",
     named_patches(HE005B_PURE_FUNCTIONS), he005b_tree),
    ("G-HE5B-3 closure", he005b_closure_check, ("(closure)",), HE005B_CLOSURE_ROWS, lambda clause: "(workspace shape)",
     re.escape("(workspace shape)"), named_patches({"(closure)": "check_workspace_shape"}), he005b_closure_tree),
    ("G-HE5B-4 includes", lambda base: gate.check_broker_includes(base), ("(includes)",), HE005B_INCLUDE_ROWS,
     lambda clause: "(broker includes)", re.escape("(broker includes)"),
     named_patches({"(includes)": "check_broker_includes"}), he005b_tree),
    ("G-HE5B-5 token", gate.check_he005b_token, tuple(HE005B_TOKEN_FUNCTIONS), HE005B_TOKEN_ROWS,
     lambda clause: "(gate-qualification token, G-HE5B-5 %s)" % clause, r"\(gate-qualification token, G-HE5B-5 \(",
     named_patches(HE005B_TOKEN_FUNCTIONS), he005b_tree),
)


class He005bRuleTests(Tree):
    """HE-005B's rules G-HE5B-1, -2, -4 and -5 over copies of the real sources (HE005B_TREE): each accepts today's
    sources; each row is refused by its rule and, with every other clause of the rule disabled, by its own named
    clause's message; and comments, literals and strict test blocks pass."""

    TREE = HE005B_TREE

    def plant(self, changes):
        texts = he005b_tree(changes)
        for rel in HE005B_TREE:
            if rel not in texts and (self.base / rel).exists():
                (self.base / rel).unlink()
        for rel, text in texts.items():
            self.write(rel, text)

    def test_the_real_sources_and_the_fixture_pass(self):
        for base in (self.base, gate.HE):
            self.assertEqual(gate.check_broker_isolation(base), 28)
            self.assertEqual(gate.check_broker_pure(base), 4)
            self.assertEqual(gate.check_broker_includes(base), 6)  # HE-005C: and the WORKER programs and the key
            self.assertEqual(gate.check_he005b_token(base), 5)
            self.assertEqual(gate.check_broker_no_panic(base), 27)
        self.assertEqual(gate.HE005B_FILES, ("crates/broker/src/i02.rs", "crates/broker/src/i03.rs",
                                             "crates/broker/src/i05_client.rs", "crates/broker/src/gate_peer.rs"))
        self.assertTrue(set(gate.HE005B_FILES) <= set(gate.BROKER_NO_PANIC))
        self.assertEqual(gate.BROKER_EMBEDS, {gate.BROKER_SEAL_RS: tuple(sorted(gate.BROKER_PROGRAMS.values())),
                                              gate.BROKER_I02: ("contracts/broker-handoff-v1/channel.schema.json",),
                                              gate.BROKER_SPAWN: tuple(sorted(gate.BROKER_WORKER_PROGRAMS.values())),
                                              gate.BROKER_SIGNED_CONFIG: (gate.BROKER_SIGNER_KEY,)})

    def test_the_tables(self):
        self.assertEqual(tuple(len(rows) for rows in (HE005B_ISOLATION_ROWS, HE005B_PURE_ROWS, HE005B_CLOSURE_ROWS,
                                                      HE005B_INCLUDE_ROWS, HE005B_TOKEN_ROWS)), (14, 34, 5, 9, 19))
        self.assertEqual(sum(len(rule[3]) for rule in HE005B_PROOF_RULES), 81)
        for name, check, clauses, rows, tag, any_tag, patches, tree in HE005B_PROOF_RULES:
            self.assertTrue(callable(check), name)
            for row in rows:
                self.assertIn(row[1], clauses, row[0])
                tree(row[2])
        for function in (list(HE005B_ISOLATION_FUNCTIONS.values()) + list(HE005B_PURE_FUNCTIONS.values())
                         + list(HE005B_TOKEN_FUNCTIONS.values())):
            self.assertTrue(callable(getattr(gate, function)), function)

    def refuses_each(self, check, rows, tag, any_tag, patches):
        for label, clause, changes in rows:
            self.plant(changes)
            try:
                with self.assertRaisesRegex(gate.GateError, any_tag, msg=label):
                    check(self.base)
                active = patches(enabled=clause)
                for patch in active:
                    patch.start()
                try:
                    with self.assertRaisesRegex(gate.GateError, re.escape(tag(clause)), msg=label):
                        check(self.base)
                finally:
                    for patch in active:
                        patch.stop()
            finally:
                self.plant(())

    def test_each_rule_refuses_its_rows(self):
        for name, check, _, rows, tag, any_tag, patches, tree in HE005B_PROOF_RULES:
            if tree is he005b_tree:
                self.refuses_each(check, rows, tag, any_tag, patches)

    def test_forms_the_rules_pass(self):
        # Comments and literals naming the modules, std::fs, the token or vectors.json are not code; a strict test block
        # in a module may hold an extern block ((a) sets it aside; since round 1, (e) reads every path of the file, as
        # check_observer_logic does, so a gate_sys path there would refuse); lib.rs's own module comment names them.
        for changes in (
                ((_BMAIN, "", "\n// planeon_broker::i02 and Transcript are HE-005B's, unreachable here\n"),),
                ((_BI02, "", '\n// std::fs::read and unsafe stay out of i02\nconst NOTE: &str = "i03 std::fs GateQualified";\n'),),
                ((_BPEER, "", "\n#[cfg(test)]\nmod tests {\n    extern \"C\" {\n        fn getpid() -> i32;\n    }\n}\n"),),
                ((_BLIB, "", "\n// pub use gate_peer::GateQualified as G; include_bytes!(\"vectors.json\")\n"),)):
            self.plant(changes)
            try:
                for check in (gate.check_broker_isolation, gate.check_broker_pure, gate.check_broker_includes,
                              gate.check_he005b_token):
                    check(self.base)
            finally:
                self.plant(())


class He005bClosureTests(Tree):
    """HE-005B G-HE5B-3 (Q-HE5B-6 (a)): the broker closure block's rows over a workspace fixture whose manifests carry the
    path dependencies: the exact four-crate closure passes; A's three crates, an added crate and a crate reached through
    role-seal refuse, with the block switched off passing each."""

    TREE = HE005B_CLOSURE_TREE

    def test_the_closure_rows(self):
        self.assertEqual(he005b_closure_check(self.base), 9)  # HE-005C: broker-sys is the ninth member
        name, check, clauses, rows, tag, any_tag, patches, tree = HE005B_PROOF_RULES[2]
        for label, clause, changes in rows:
            for rel, text in tree(changes).items():
                self.write(rel, text)
            try:
                with self.assertRaisesRegex(gate.GateError, "planeon-broker links .*, not .* .workspace shape", msg=label):
                    check(self.base)
                active = patches(disabled=(clause,))
                for patch in active:
                    patch.start()
                try:
                    check(self.base)
                finally:
                    for patch in active:
                        patch.stop()
            finally:
                for rel, text in tree(()).items():
                    self.write(rel, text)


class He005bSymbolTests(unittest.TestCase):
    """HE-005B G-HE5B-6 (check_d2_absent's form): no planeon-broker symbol has a path in one of the four modules, by item
    path (legacy, v0, an inherent impl) or by its first crate root (a trait impl, a closure); a symbol that only
    mentions a module's name passes."""

    REFUSED = ("_ZN14planeon_broker3i0215decode_datagram17h0123456789abcdefE",
               "_RNvNtCs5pXa2Z9YbGW_14planeon_broker3i035start",
               "_RNvMNtCs5pXa2Z9YbGW_14planeon_broker10i05_clientNtB2_9I05Client4open",
               "_RNvXs_NtCs5pXa2Z9YbGW_14planeon_broker9gate_peerNtB4_13GateQualifiedNtNtCsifRdLFh1usa_4core3fmt5Debug3fmt",
               "_RNCNvNtCs5pXa2Z9YbGW_14planeon_broker9gate_peer12qualify_gate0B5_")
    PASSED = ("_RNvNtCs5pXa2Z9YbGW_14planeon_broker4seal11seal_stage1",
              "_RINvNtCsifRdLFh1usa_4core3ptr13drop_in_placeNtNtCs5pXa2Z9YbGW_14planeon_broker3i0210TranscriptEB4_",
              "_ZN4core3ptr52drop_in_place$LT$planeon_broker..i02..Transcript$GT$17h0123456789abcdefE",
              "_ZN16planeon_observer3i0215decode_datagram17h0123456789abcdefE",
              "_ZN16planeon_broker_x3i021f17h0123456789abcdefE", "i02", "main")

    def test_he005b_symbols_refuse_and_mentions_pass(self):
        self.assertEqual(gate.check_he005b_absent(set(self.PASSED)), len(self.PASSED))
        for name in self.REFUSED:
            with self.assertRaisesRegex(gate.GateError, "a symbol of the HE-005B module .*G-HE5B-6"):
                gate.check_he005b_absent(set(self.PASSED) | {name})
        self.assertEqual(gate.HE005B_MODULES, ("i02", "i03", "i05_client", "gate_peer"))


# HE-GATE-001 (DESIGN rev 3): Fix A, CODE_PATH's colon form (HE-005B PR review round 2, R2-1 and R2-2), in both of its
# readers; Fix B, the observer's gate_sys crate check (HE-005A PR review round 2, R2-1). The old pattern, patched into
# gate.CODE_PATH, shows each Fix A refusal fails with the fix reverted.
HEGATE_OLD_CODE_PATH = re.compile(r"(?<![\w:])(::)?([A-Za-z_]\w*)((?:::[A-Za-z_]\w*)+)")
_HG_RBAC, _HG_LIB, _HG_TLS = "crates/observer/src/rbac.rs", gate.OBSERVER_LIB, gate.OBSERVER_TLS
_HG_CONFIG, _HG_CREDENTIALS = "crates/observer/src/config.rs", "crates/observer/src/credentials.rs"
_HG_NET, _HG_LISTEN = gate.OBSERVER_LINUX_NET, gate.OBSERVER_LINUX_LISTEN
# Fix A's forms, (text, the path its reader names): a parameter, a let, a field, a bound, a closure parameter, a static
# and a const, a struct-literal value, and the spaced leading `: ::path` (PATH_SPACE's `:::path`) and `:::path`. The
# observer forms name paths outside rbac.rs's whitelist; the broker forms name only paths that (e) alone refuses
# (std::time, std::sync, std::cell, crate::seal, crate::linux_listen), never one of (a)'s HE005B_REFUSED_NAMES.
HEGATE_OBSERVER_COLON_FORMS = (
    ("fn hg_parameter(t:std::time::SystemTime) -> bool { true }\n", "std::time::SystemTime"),
    ("fn hg_let() { let m:std::sync::Mutex<u8> = hg(); }\n", "std::sync::Mutex"),
    ("struct HgField { l:crate::client::Client }\n", "crate::client::Client"),
    ("fn hg_bound<T:std::marker::Send>(t: T) -> T { t }\n", "std::marker::Send"),
    ("fn hg_closure() { let c = |t:std::time::Instant| t; }\n", "std::time::Instant"),
    ("static HG_STATIC:std::sync::Mutex<u8> = hg();\n", "std::sync::Mutex"),
    ("const HG_CONST:crate::seal::Plan = hg();\n", "crate::seal::Plan"),
    ("fn hg_value() -> HgT { HgT { f:std::time::SystemTime::now() } }\n", "std::time::SystemTime::now"),
    ("fn hg_spaced(t: ::std::time::SystemTime) {}\n", "::std::time::SystemTime"),
    ("fn hg_colons(t:::std::time::SystemTime) {}\n", "::std::time::SystemTime"),
)
HEGATE_BROKER_COLON_FORMS = (
    ("fn hg_parameter(t:std::time::SystemTime) -> bool { true }\n", "std::time::SystemTime"),
    ("fn hg_let() { let m:std::sync::Mutex<u8> = hg(); }\n", "std::sync::Mutex"),
    ("struct HgField { l:crate::linux_listen::LinuxI02 }\n", "crate::linux_listen::LinuxI02"),
    ("fn hg_bound<T:crate::seal::Sealing>(t: T) -> T { t }\n", "crate::seal::Sealing"),
    ("fn hg_closure() { let c = |t:std::time::Instant| t; }\n", "std::time::Instant"),
    ("static HG_STATIC:std::cell::Cell<u8> = hg();\n", "std::cell::Cell"),
    ("const HG_CONST:crate::seal::Plan = hg();\n", "crate::seal::Plan"),
    ("fn hg_value() -> HgT { HgT { f:std::time::SystemTime::now() } }\n", "std::time::SystemTime::now"),
    ("fn hg_spaced(t: ::std::time::SystemTime) {}\n", "::std::time::SystemTime"),
    ("fn hg_colons(t:::std::time::SystemTime) {}\n", "::std::time::SystemTime"),
)
HEGATE_COLON_PASSES = ("fn hg_whitelisted(x:std::collections::BTreeMap<u8, u8>) -> usize { x.len() }\n",
                       "fn hg_unrooted(x:Foo::Bar) {}\n")
HEGATE_CODE_PATH_TEXTS = ("a::b::c", "Foo::<T>::bar::baz", "<std::time::Instant>::now()", "::std::time::Instant::now()")
HEGATE_OBSERVER_SOURCES = 41
# The proof (DESIGN rev 3 section 4, HG-D2-2): the trees of copies of the real sources each rule reads, in he005b_tree's
# form; Fix A's one clause, (colon), switched off by patching the old pattern into gate.CODE_PATH; Fix B's three clause
# functions switched off by name.
HEGATE_LOGIC_TREE = {rel: HE005B_TREE[rel] for rel, _ in gate.LOGIC_MODULES}
HEGATE_OBSERVER_TREE = {rel: text for rel, text in HE005B_TREE.items() if rel.startswith(gate.OBSERVER_CRATE + "/src/")}
HEGATE_FIX_B_FUNCTIONS = {"(i)": "observer_gate_sys_bare", "(ii)": "observer_gate_sys_after_head",
                          "(iii)": "observer_gate_sys_readable"}


def hegate_changed(texts, changes):
    """`texts` with each (file, anchor, replacement) applied once, in order (an empty anchor appends), and each
    (file, None, None) removing the file (he005b_tree's form)."""
    texts = dict(texts)
    for rel, old, new in changes:
        if old is None:
            del texts[rel]
            continue
        if not old:
            texts[rel] = texts[rel] + new
            continue
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old[:80]))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


def hegate_logic_tree(changes=()):
    """Copies of LOGIC_MODULES' real sources (check_observer_logic's input) with `changes`."""
    return hegate_changed(HEGATE_LOGIC_TREE, changes)


def hegate_observer_tree(changes=()):
    """Copies of crates/observer's real sources (check_observer_gate_sys_crate's input) with `changes`."""
    return hegate_changed(HEGATE_OBSERVER_TREE, changes)


def codepath_patches(enabled=None, disabled=()):
    """Fix A's one clause, (colon), in named_patches' result shape: a list holding mock.patch.object(gate, "CODE_PATH",
    the old compiled pattern) only when (colon) is disabled (another clause enabled alone, or (colon) in `disabled`)."""
    off = (enabled is not None and enabled != "(colon)") or "(colon)" in disabled
    return [mock.patch.object(gate, "CODE_PATH", HEGATE_OLD_CODE_PATH)] if off else []


HEGATE_COLON_ROW = "\nfn p(t:std::time::SystemTime) -> bool { true }\n"
HEGATE_OBSERVER_ROWS = (("HG1 a parameter type after a lone colon in rbac.rs", "(colon)",
                         ((_HG_RBAC, "", HEGATE_COLON_ROW),)),)
HEGATE_BROKER_ROWS = (("HG2 a parameter type after a lone colon in i03.rs", "(colon)",
                       ((_BI03, "", HEGATE_COLON_ROW),)),)
HEGATE_FIX_B_ROWS = (
    ("HG3 pub(crate) use gate_sys; in client.rs", "(i)", ((_OCLIENT, "", "\npub(crate) use gate_sys;\n"),)),
    ("HG4 use crate::wire::gate_sys::Dir; in client.rs", "(ii)",
     ((_OCLIENT, "", "\nuse crate::wire::gate_sys::Dir;\n"),)),
    ("HG5 use r#gate_sys; in config.rs", "(iii)", ((_HG_CONFIG, "", "\nuse r#gate_sys;\n"),)),
)
# (rule, check, its clauses, rows, the named clause's message, any clause's message, the patches, the tree builder):
# HE005B_PROOF_RULES' shape; the lane's mutation proof reads this table after that one, with the same row logic.
HEGATE_PROOF_RULES = (
    ("HE-GATE-001 Fix A (observer)", gate.check_observer_logic, ("(colon)",), HEGATE_OBSERVER_ROWS,
     lambda clause: "(observer logic rules)", re.escape("(observer logic rules)"), codepath_patches, hegate_logic_tree),
    ("HE-GATE-001 Fix A (broker)", gate.check_broker_pure, ("(colon)",), HEGATE_BROKER_ROWS,
     lambda clause: "(HE-005B pure, G-HE5B-2 (e))", re.escape("(HE-005B pure, G-HE5B-2 (e))"), codepath_patches,
     he005b_tree),
    ("HE-GATE-001 Fix B", gate.check_observer_gate_sys_crate, tuple(HEGATE_FIX_B_FUNCTIONS), HEGATE_FIX_B_ROWS,
     lambda clause: "(observer gate_sys crate, HE-GATE-001 %s)" % clause, r"\(observer gate_sys crate, HE-GATE-001 \(",
     named_patches(HEGATE_FIX_B_FUNCTIONS), hegate_observer_tree),
)


class HeGateTests(Tree):
    """HE-GATE-001 over copies of the real sources (HE005B_TREE). Fix A: each colon-adjacent form is refused by
    check_observer_logic in rbac.rs and by check_broker_pure's (e) in i03.rs, and passes with the old pattern patched
    into gate.CODE_PATH; whitelisted and unrooted forms pass under both; the old and new patterns match alike
    elsewhere. Fix B: check_observer_gate_sys_crate's clauses (i), (ii) and (iii) refuse their forms with their own
    messages, the real files and gate_sys's item imports pass, and its stated bounds stay refused by
    check_linked_sources. The proof table's rows HG1-HG5."""

    TREE = HE005B_TREE

    def colon_forms_refuse(self, check, rel, forms, tag, count):
        good = self.TREE[rel]
        for text, named in forms:
            self.write(rel, good + "\n" + text)
            try:
                with self.assertRaisesRegex(gate.GateError, re.escape("%s names %s, outside the " % (rel, named)) + ".*"
                                            + re.escape(tag), msg=text):
                    check(self.base)
                with mock.patch.object(gate, "CODE_PATH", HEGATE_OLD_CODE_PATH):
                    self.assertEqual(check(self.base), count, text)
            finally:
                self.write(rel, good)

    def test_fix_a_observer_logic_reads_the_colon_forms(self):
        self.colon_forms_refuse(gate.check_observer_logic, _HG_RBAC, HEGATE_OBSERVER_COLON_FORMS,
                                "(observer logic rules)", len(gate.LOGIC_MODULES))

    def test_fix_a_broker_pure_reads_the_colon_forms(self):
        self.colon_forms_refuse(gate.check_broker_pure, _BI03, HEGATE_BROKER_COLON_FORMS,
                                "(HE-005B pure, G-HE5B-2 (e))", len(gate.HE005B_FILES))

    def test_fix_a_whitelisted_and_unrooted_forms_pass(self):
        for check, rel, count in ((gate.check_observer_logic, _HG_RBAC, len(gate.LOGIC_MODULES)),
                                  (gate.check_broker_pure, _BI03, len(gate.HE005B_FILES))):
            good = self.TREE[rel]
            for text in HEGATE_COLON_PASSES:
                self.write(rel, good + "\n" + text)
                try:
                    self.assertEqual(check(self.base), count, text)
                    with mock.patch.object(gate, "CODE_PATH", HEGATE_OLD_CODE_PATH):
                        self.assertEqual(check(self.base), count, text)
                finally:
                    self.write(rel, good)

    def test_fix_a_code_path_matches_alike_elsewhere(self):
        for text in HEGATE_CODE_PATH_TEXTS:
            self.assertEqual([(found.span(), found.groups()) for found in gate.CODE_PATH.finditer(text)],
                             [(found.span(), found.groups()) for found in HEGATE_OLD_CODE_PATH.finditer(text)], text)

    def test_fix_b_the_real_files_pass(self):
        for base in (self.base, gate.HE):
            self.assertEqual(gate.check_observer_gate_sys_crate(base), HEGATE_OBSERVER_SOURCES)

    def test_fix_b_i_refuses_the_crate_itself_outside_the_socket_files(self):
        for rel, text in ((_OCLIENT, "pub(crate) use gate_sys;\n"), (_HG_CONFIG, "use gate_sys::{self};\n"),
                          (_HG_TLS, "use ::gate_sys as g;\n"), (_HG_CREDENTIALS, "use ::{gate_sys};\n"),
                          (_HG_CONFIG, "use gate_sys::{Dir, self};\n"), (_OCLIENT, "use gate_sys::{{self}};\n")):
            self.refused(gate.check_observer_gate_sys_crate, rel, self.TREE[rel] + "\n" + text,
                         re.escape("%s imports the gate_sys crate itself (observer gate_sys crate, HE-GATE-001 (i))"
                                   % rel))

    def test_fix_b_i_passes_a_private_import_in_a_socket_file(self):
        # Not refused by (i), and not a re-export: check_socket_modules refuses every `pub use` in a socket file.
        self.write(_HG_NET, self.TREE[_HG_NET] + "\nuse gate_sys;\n")
        self.assertEqual(gate.check_observer_gate_sys_crate(self.base), HEGATE_OBSERVER_SOURCES)

    def test_fix_b_ii_refuses_gate_sys_after_the_head(self):
        for rel, text, path in ((_OCLIENT, "use crate::wire::gate_sys::Dir;\n", "crate::wire::gate_sys::Dir"),
                                (_OCLIENT, "pub use self::gate_sys;\n", "self::gate_sys"),
                                (_OCLIENT, "use super::gate_sys;\n", "super::gate_sys"),
                                (_HG_LIB, "pub use crate::client::gate_sys;\n", "crate::client::gate_sys"),
                                (_HG_LISTEN, "use crate::client::gate_sys::channel::{send};\n",
                                 "crate::client::gate_sys::channel::send")):
            self.refused(gate.check_observer_gate_sys_crate, rel, self.TREE[rel] + "\n" + text,
                         re.escape("%s reaches gate_sys through another path, %s (observer gate_sys crate, HE-GATE-001 "
                                   "(ii))" % (rel, path)))

    def test_fix_b_iii_refuses_an_unreadable_declaration(self):
        self.refused(gate.check_observer_gate_sys_crate, _HG_CONFIG, self.TREE[_HG_CONFIG] + "\nuse r#gate_sys;\n",
                     re.escape("%s holds a use declaration the gate_sys crate rule cannot read (observer gate_sys "
                               "crate, HE-GATE-001 (iii))" % _HG_CONFIG))

    def test_fix_b_forms_that_pass(self):
        good = self.TREE[_OCLIENT]
        for text in ("pub(crate) use gate_sys::Dir;\n", "use gate_sys::inet::{self};\n",
                     'const HEGATE_NOTE: &str = "pub(crate) use gate_sys;";\n', "// pub(crate) use gate_sys;\n"):
            self.write(_OCLIENT, good + "\n" + text)
            try:
                self.assertEqual(gate.check_observer_gate_sys_crate(self.base), HEGATE_OBSERVER_SOURCES, text)
            finally:
                self.write(_OCLIENT, good)

    def test_fix_b_bounds_stay_refused(self):
        # HG-D1-5: extern crate gate_sys, at any visibility, is check_linked_sources' (LINKED_FORMS), over LINKED_TREE.
        for rel, text in LINKED_TREE.items():
            self.write("linked/" + rel, text)
        linked = self.base / "linked"
        gate.check_linked_sources(linked)
        self.write("linked/" + gate.OBSERVER_CLIENT, "pub(crate) extern crate gate_sys;\n")
        with self.assertRaisesRegex(gate.GateError, re.escape("%s declares an extern crate (linked-source tripwire)"
                                                              % gate.OBSERVER_CLIENT)):
            gate.check_linked_sources(linked)

    def test_the_proof_table(self):
        # DESIGN rev 3 section 4: three rules in HE005B_PROOF_RULES' shape, rows HG1-HG5; each row is refused by its
        # rule (any clause's message), by its own clause alone (the named clause's message), and passes with its clause
        # off.
        self.assertEqual([rule[0] for rule in HEGATE_PROOF_RULES],
                         ["HE-GATE-001 Fix A (observer)", "HE-GATE-001 Fix A (broker)", "HE-GATE-001 Fix B"])
        self.assertEqual([row[0][:3] for rule in HEGATE_PROOF_RULES for row in rule[3]],
                         ["HG1", "HG2", "HG3", "HG4", "HG5"])
        self.assertEqual((len(HEGATE_LOGIC_TREE), len(HEGATE_OBSERVER_TREE)),
                         (len(gate.LOGIC_MODULES), HEGATE_OBSERVER_SOURCES))
        self.assertEqual((codepath_patches(), codepath_patches(enabled="(colon)")), ([], []))
        self.assertEqual((len(codepath_patches(disabled=("(colon)",))), len(codepath_patches(enabled="(i)"))), (1, 1))
        for function in HEGATE_FIX_B_FUNCTIONS.values():
            self.assertTrue(callable(getattr(gate, function)), function)
        for name, check, clauses, rows, tag, any_tag, patches, tree in HEGATE_PROOF_RULES:
            self.assertTrue(callable(check), name)
            for label, clause, changes in rows:
                self.assertIn(clause, clauses, label)
                for rel, text in tree(changes).items():
                    self.write(rel, text)
                try:
                    with self.assertRaisesRegex(gate.GateError, any_tag, msg=label):
                        check(self.base)
                    for enabled, disabled in ((clause, ()), (None, (clause,))):
                        active = patches(enabled=enabled, disabled=disabled)
                        for patch in active:
                            patch.start()
                        try:
                            if disabled:
                                check(self.base)
                            else:
                                with self.assertRaisesRegex(gate.GateError, re.escape(tag(clause)), msg=label):
                                    check(self.base)
                        finally:
                            for patch in active:
                                patch.stop()
                finally:
                    for rel, text in tree(()).items():
                        self.write(rel, text)


# --- HE-005C (the broker's lifecycle; the frozen seam note DESIGN-HE005.SEAM-C rev 4 with MON-SEAM-E1..E3; the plan's
# G-HE5C-1..8 and delta C3's G-HE5C-9..13; the build brief U2-U5 and its addenda 1 and 2) ------------------------------
# The real sources the HE-005C rules read: every scanned crate's src (broker-sys's raw.rs included), the broker's tests,
# and HE005B_TREE's named files and differential test. A change is (file, anchor, replacement) as in he005b_tree, or
# (file, None, None), which removes the file. Rows change only these fixture copies, never a source.
HE005C_TREE = {**HE005B_TREE,
               **{path.relative_to(gate.HE).as_posix(): path.read_text(encoding="utf-8")
                  for crate in gate.SCANNED_CRATES for path in sorted((gate.HE / crate / "src").rglob("*.rs"))},
               **{path.relative_to(gate.HE).as_posix(): path.read_text(encoding="utf-8")
                  for path in sorted((gate.HE / gate.BROKER_CRATE / "tests").rglob("*.rs"))}}
_CRAW, _CSYSLIB = gate.BROKER_SYS_RAW, gate.BROKER_SYS_LIB
_CRUN, _CSPAWN, _CSEAMS, _COUT = gate.BROKER_RUN, gate.BROKER_SPAWN, gate.BROKER_SEAMS, gate.BROKER_OUTCOME
_CPROC, _CLEAF, _CNP9, _CW6 = gate.BROKER_PROC, gate.BROKER_LEAF, gate.BROKER_NP9, gate.BROKER_W6
_CSIGNED, _CCONFIG = gate.BROKER_SIGNED_CONFIG, gate.BROKER_CONFIG
_CHOLD, _CMOD = gate.BROKER_LIFECYCLE + "/hold.rs", gate.BROKER_LIFECYCLE + "/mod.rs"
_CTESTS = gate.BROKER_CRATE + "/tests/lifecycle.rs"


def he005c_tree(changes=()):
    """HE005C_TREE with each (file, anchor, replacement) applied once, in order (an empty anchor appends), and each
    (file, None, None) removing the file."""
    texts = dict(HE005C_TREE)
    for rel, old, new in changes:
        if old is None:
            del texts[rel]
            continue
        if not old:
            texts[rel] = texts[rel] + new
            continue
        if texts[rel].count(old) != 1:
            raise ValueError("%s: the anchor %r does not occur once" % (rel, old[:80]))
        texts[rel] = texts[rel].replace(old, new, 1)
    return texts


# G-HE5C-1..3, the span (check_child_span): pinned (1), its order (2), its calls and operations (3).
_UNBLOCK = ("        if raw.call(SYS_RT_SIGPROCMASK, [SIG_SETMASK, values.no_signals, 0, SIGSET_BYTES, 0, 0]) < 0 {\n"
            "            break 'steps;\n        }\n")
_SETRESGID = ("        if raw.call(SYS_SETRESGID, [values.worker_id, values.worker_id, values.worker_id, 0, 0, 0]) < 0 {\n"
              "            break 'steps;\n        }\n")
HE005C_SPAN_ROWS = (
    ("s1 #[inline(never)] dropped from clone_span", "(1)", ((_CRAW, "#[inline(never)]\nfn clone_span<", "fn clone_span<"),)),
    ("s2 a failed block-all reported as a failed clone3", "(1)",
     ((_CRAW, "        return Cloned::NotBlocked;\n", "        return Cloned::Failed;\n"),)),
    ("s3 setresgid before the unblock", "(2)", ((_CRAW, _UNBLOCK + _SETRESGID, _SETRESGID + _UNBLOCK),)),
    ("s4 SIGKILL in the reset list", "(2)",
     ((_CRAW, "    1, 2, 3, 4, 5, 6, 7, 8, 10,", "    1, 2, 3, 4, 5, 6, 7, 8, 9, 10,"),)),
    ("s5 the script duplicated to the channel's number", "(2)",
     ((_CRAW, "[values.script, WORKER_SCRIPT_FD, 0, 0, 0, 0]", "[values.script, WORKER_CHANNEL_FD, 0, 0, 0, 0]"),)),
    ("s6 the child path off clone3's return-0 branch", "(2)",
     ((_CRAW, "    if pid == 0 {\n        child_path(raw, values);", "    if pid >= 0 {\n        child_path(raw, values);"),)),
    ("s7 the exec descriptor renumbered", "(2)",
     ((_CRAW, "const WORKER_SCRIPT_FD: c_long = 4;", "const WORKER_SCRIPT_FD: c_long = 3;"),)),
    ("s8 arithmetic in an argument", "(3)",
     ((_CRAW, "[SIG_SETMASK, values.all_signals, 0, SIGSET_BYTES, 0, 0]",
       "[SIG_SETMASK, values.all_signals, 0, SIGSET_BYTES + 0, 0, 0]"),)),
    ("s9 another call in the span", "(3)",
     ((_CRAW, "    let pid = raw.call(SYS_CLONE3,", "    core::hint::black_box(0);\n    let pid = raw.call(SYS_CLONE3,"),)),
    ("s10 a bare number for a call", "(3)",
     ((_CRAW, "raw.call(SYS_PRCTL, [PR_SET_NO_NEW_PRIVS", "raw.call(157, [PR_SET_NO_NEW_PRIVS"),)),
    ("s11 a cast in the span", "(3)",
     ((_CRAW, "[values.clone_args, CLONE_ARGS_BYTES, 0, 0, 0, 0]", "[values.clone_args, CLONE_ARGS_BYTES as c_long, 0, 0, 0, 0]"),)),
    ("s12 an index into the reset list", "(3)",
     ((_CRAW, "[signal, values.default_action, 0, SIGSET_BYTES, 0, 0]",
       "[RESET_SIGNALS[0], values.default_action, 0, SIGSET_BYTES, 0, 0]"),)),
)
# G-HE5C-4, the measured exec across the seam (check_measured_exec): one site each (a), the raw half (b), the agent half (c).
HE005C_EXEC_ROWS = (
    ("x1 a second execveat site", "(a)",
     ((_CRAW, "", "\nfn again() -> io::Result<c_long> {\n    sys(SYS_EXECVEAT, [0, 0, 0, 0, 0, 0])\n}\n"),)),
    ("x2 a second clone3 site", "(a)",
     ((_CRAW, "", "\nfn again() -> io::Result<c_long> {\n    sys(SYS_CLONE3, [0, 0, 0, 0, 0, 0])\n}\n"),)),
    ("x3 the exec's descriptor from the channel", "(b)",
     ((_CRAW, "let script = plan.script.fd.as_raw_fd() as c_long;", "let script = plan.channel.fd.as_raw_fd() as c_long;"),)),
    ("x4 the script's value read twice", "(b)",
     ((_CRAW, "", "\nfn peek(values: &ChildValues) -> c_long {\n    values.script\n}\n"),)),
    ("x5 W5 measures a second open", "(c)",
     ((_CRUN, "    let (algorithm, digest) = spawn.measure(&script)",
       "    let other = spawn.open_script().map_err(|_| Step::W5Open)?;\n    let (algorithm, digest) = spawn.measure(&other)"),)),
    ("x6 the script rebound before W2", "(c)",
     ((_CRUN, "    let (child, expect) = match w2(", "    let script = script;\n    let (child, expect) = match w2("),)),
    ("x7 spawn.rs's measure through a binding", "(c)",
     ((_CSPAWN, "        broker_sys::measure_verity(script)\n",
       "        let measured = script;\n        broker_sys::measure_verity(measured)\n"),)),
    ("x8 the plan given another script", "(c)",
     ((_CSPAWN, "            child_end,\n            script,\n", "            child_end,\n            self.open_script()?,\n"),)),
)
# PR review round 1, R1-1's two planted forms (Q-HE5C-R1-1 (a)): (i) startup_run first calls a new private fn that runs
# W5, W1 and W2 before its call of startup with the stand-ins; (ii) step 2's Unavailable arm forges a GateTicket.
_CSTARTUP_CALL = "    startup(&mut handles.leaf_ops(), &mut spawn, &clock, qualifier, binder, config, standing)\n"
_CFORM_I = ((_CRUN, _CSTARTUP_CALL, "    early(&mut handles.leaf_ops(), &mut spawn, &clock, config, standing);\n"
                                    + _CSTARTUP_CALL),
            (_CRUN, "", "\nfn early<L: LeafOps, S: SpawnOps, K: Clock>(leaf: &mut L, spawn: &mut S, clock: &K, "
                        "config: &BrokerConfig, standing: &mut Standing<S::Child>) {\n"
                        "    if let Ok((script, (_parent_end, child_end))) = w5(spawn, config) {\n"
                        "        let _ = w1(leaf, clock, standing);\n"
                        "        let _ = w2(spawn, config.worker_uid(), child_end, script);\n    }\n}\n"))
_CFORM_II = ((_CRUN, "        GateAnswer::Unavailable => return Outcome::Unavailable,\n",
              "        GateAnswer::Unavailable => GateTicket { generation: 0 },\n"),)
# G-HE5C-5, W4's thaw (check_w4_thaw): exact (a), the pass and the ticket (b), the order and the thaw sites (c).
HE005C_THAW_ROWS = (
    ("t1 W4's thaw without BIND's ticket", "(a)",
     ((_CRUN, ", _passed: &W3Passed, _bound: &BindTicket)", ", _passed: &W3Passed)"),)),
    ("t2 W4 writes before its thaw", "(a)",
     ((_CRUN, "    leaf.write(LeafWrite::Thaw)\n}", "    let _ = leaf.write(LeafWrite::Freeze);\n    leaf.write(LeafWrite::Thaw)\n}"),)),
    ("t3 W3's pass made copyable", "(b)", ((_CRUN, "struct W3Passed {", "#[derive(Clone, Copy)]\nstruct W3Passed {"),)),
    ("t4 a pass forged outside W3", "(b)",
     ((_CRUN, "", "\nfn forged() -> W3Passed {\n    W3Passed { start_ticks: 0 }\n}\n"),)),
    ("t5 a BindTicket written in the run", "(b)",
     ((_CRUN, "    if w4_thaw(leaf, &passed, &bound).is_err() {",
       "    let bound = BindTicket { pid, start_ticks: passed.start_ticks };\n"
       "    if w4_thaw(leaf, &passed, &bound).is_err() {"),)),
    ("t6 a thaw before BIND", "(c)",
     ((_CRUN, "    let pid = spawn.child_pid(&child);\n",
       "    let _ = w4_thaw(leaf, &passed, &early_ticket());\n    let pid = spawn.child_pid(&child);\n"),)),
    ("t7 a thaw written in hold.rs", "(c)",
     ((_CHOLD, "", "\nfn thaw_early<L: LeafOps>(leaf: &mut L) -> io::Result<()> {\n    leaf.write(LeafWrite::Thaw)\n}\n"),)),
    ("t8 R1-1 (ii): step 2's Unavailable arm forges a GateTicket", "(b)", _CFORM_II),
    ("t9 R1-1 (i): startup_run runs W5, W1 and W2 before startup", "(c)", _CFORM_I),
    ("t10 a thaw written in startup (R1-2)", "(c)",
     ((_CRUN, "    let pid = spawn.child_pid(&child);\n",
       "    let _ = leaf.write(LeafWrite::Thaw);\n    let pid = spawn.child_pid(&child);\n"),)),
)
# G-HE5C-6, the control opener (check_control_opener): raw.rs's names (a), its site (b), every other file (c).
HE005C_OPENER_ROWS = (
    ("o1 cgroup.freeze named twice in raw.rs", "(a)",
     ((_CRAW, 'const CGROUP_KILL: &[u8] = b"cgroup.kill\\0";\n',
       'const CGROUP_KILL: &[u8] = b"cgroup.kill\\0";\nconst CGROUP_SECOND: &[u8] = b"cgroup.freeze\\0";\n'),)),
    ("o2 the thaw written to cgroup.kill", "(b)",
     ((_CRAW, 'LeafWrite::Thaw => (CGROUP_FREEZE, b"0"),', 'LeafWrite::Thaw => (CGROUP_KILL, b"0"),'),)),
    ("o3 O_CREAT in the control flags", "(b)",
     ((_CRAW, "const CONTROL_FLAGS: c_long = O_WRONLY | O_CLOEXEC | O_NOFOLLOW;",
       "const CONTROL_FLAGS: c_long = O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_CREAT;"),)),
    ("o4 O_WRONLY given O_RDWR's value", "(b)", ((_CRAW, "const O_WRONLY: c_long = 1;", "const O_WRONLY: c_long = 2;"),)),
    ("o5 a second opener with the control flags", "(b)",
     ((_CRAW, "", "\nfn reopen(leaf: c_long) -> io::Result<c_long> {\n    sys(SYS_OPENAT, [leaf, 0, CONTROL_FLAGS, 0, 0, 0])\n}\n"),)),
    ("o6 a lifecycle comment names cgroup.freeze", "(c)", ((_CLEAF, "", "\n// thaws by writing 0 to cgroup.freeze\n"),)),
    ("o7 a broker test names cgroup.kill", "(c)", ((_CTESTS, "", "\n// kills through cgroup.kill\n"),)),
    ("o8 broker-sys's lib.rs names cgroup.kill", "(c)", ((_CSYSLIB, "", '\npub const KILL: &str = "cgroup.kill";\n'),)),
    ("o9 an O_RDWR const in raw.rs (R1-2)", "(b)", ((_CRAW, "", "\nconst O_RDWR: c_long = 2;\n"),)),
)
# G-HE5C-7 and the seam note section 1: the lists (check_he005c_lists), and the existing lints over broker-sys and the
# lifecycle (the start-up lint, the unsafe tripwire, the foreign items, the linked sources and threads, the socket
# modules), each its own one clause.
HE005C_LIST_ROWS = (
    ("k-a proc.rs missing", "(lists)", ((_CPROC, None, None),)),
    ("k-b broker-sys's lib.rs missing", "(lists)", ((_CSYSLIB, None, None),)),
)
HE005C_STARTUP_ROWS = (
    ("k1 a second /proc path in raw.rs", "(sources)", ((_CRAW, "", '\nconst SELF: &str = "/proc/self";\n'),)),
    ("k2 a second process-directory open in proc.rs", "(sources)",
     ((_CPROC, "", '\nfn again(pid: i32) -> io::Result<Dir> {\n    Dir::at(&format!("/proc/{}", pid))\n}\n'),)),
    ("k3 the descriptor-directory path in leaf.rs", "(sources)",
     ((_CLEAF, "", '\nfn fds(pid: i32) -> String {\n    format!("/proc/{}/fd", pid)\n}\n'),)),
    ("k4 a second /sys path in leaf.rs", "(sources)", ((_CLEAF, "", '\nconst OTHER: &str = "/sys/fs/cgroup/other";\n'),)),
    ("k14 raw.rs's descriptor-directory path changed (R1-2)", "(sources)",
     ((_CRAW, 'format!("/proc/{}/fd", pid)', 'format!("/proc/{}/fdinfo", pid)'),)),
)
HE005C_UNSAFE_ROWS = (
    ("k5 unsafe in broker-sys's lib.rs", "(unsafe)", ((_CSYSLIB, "", "\nfn f() {\n    unsafe {}\n}\n"),)),
    ("k6 unsafe in the lifecycle", "(unsafe)", ((_CSPAWN, "", "\nfn f() {\n    unsafe {}\n}\n"),)),
)
HE005C_FOREIGN_ROWS = (
    ("k7 a second foreign item in raw.rs", "(foreign)",
     ((_CRAW, "    fn syscall(number: c_long, ...) -> c_long;\n",
       "    fn syscall(number: c_long, ...) -> c_long;\n    fn getpid() -> c_int;\n"),)),
    ("k8 an extern block in broker-sys's lib.rs", "(foreign)",
     ((_CSYSLIB, "", '\nextern "C" {\n    fn getpid() -> i32;\n}\n'),)),
)
HE005C_LINKED_ROWS = (
    ("k9 std::net in raw.rs", "(linked)",
     ((_CRAW, "", "\nfn peer() -> Option<std::net::TcpStream> {\n    None\n}\n"),)),
    ("k10 std::env in the lifecycle", "(linked)", ((_CRUN, "", "\nfn home() -> bool {\n    std::env::args().count() > 0\n}\n"),)),
)
HE005C_SOCKET_ROWS = (
    ("k11 raw.rs names a socket module", "(socket)", ((_CRAW, "", "\nuse gate_sys::channel;\n"),)),
    ("k12 a thread in raw.rs", "(socket)", ((_CRAW, "", "\nfn spin() {\n    let _ = std::thread::current();\n}\n"),)),
    ("k13 a thread in the lifecycle", "(socket)", ((_CRUN, "", "\nfn spin() {\n    let _ = std::thread::current();\n}\n"),)),
)
# G-HE5C-7 in G-D1-3's form (check_broker_sys_calls, Q-RAW-R1-3): syscall (a), the numbers (b), the positions (c),
# every other file (d).
_SYSCALL_CALL = "unsafe { syscall(number, first, second, third, fourth, fifth, sixth) }"
HE005C_CALLS_ROWS = (
    ("c1 a second syscall call", "(a)",
     ((_CRAW, "", "\nfn direct() -> c_long {\n    unsafe { syscall(SYS_WRITE, 0, 0, 0, 0, 0, 0) }\n}\n"),)),
    ("c2 syscall given a literal number", "(a)",
     ((_CRAW, _SYSCALL_CALL, "unsafe { syscall(1, first, second, third, fourth, fifth, sixth) }"),)),
    ("c3 a pinned number changed", "(b)",
     ((_CRAW, "    pub const SYS_SETRESUID: c_long = 117;", "    pub const SYS_SETRESUID: c_long = 105;"),)),
    ("c4 a number added", "(b)",
     ((_CRAW, "    pub const SYS_CLOSE_RANGE: c_long = 436;\n    pub const O_DIRECTORY: c_long = 0o200000;",
       "    pub const SYS_CLOSE_RANGE: c_long = 436;\n    pub const SYS_SETUID: c_long = 105;\n"
       "    pub const O_DIRECTORY: c_long = 0o200000;"),)),
    ("c5 a number for sys's call", "(c)", ((_CRAW, "sys(SYS_WRITE, [control.as_raw_fd()", "sys(1, [control.as_raw_fd()"),)),
    ("c6 a SYS_ name bound elsewhere", "(c)", ((_CRAW, "", "\nconst ALIAS: c_long = SYS_EXECVEAT;\n"),)),
    ("c7 a SYS_ name through Kernel.call", "(c)",
     ((_CRAW, "", "\nfn other() -> c_long {\n    Kernel.call(SYS_GETDENTS64, [0; 6])\n}\n"),)),
    ("c8 a SYS_ name in the lifecycle", "(d)", ((_CLEAF, "", "\nconst SYS_OPENAT: i64 = 257;\n"),)),
    ("c9 syscall named in broker-sys's lib.rs", "(d)", ((_CSYSLIB, "", "\nfn syscall() {}\n"),)),
    ("c10 an expression for sys's call number (R1-2)", "(c)",
     ((_CRAW, "sys(SYS_WRITE, [control.as_raw_fd()", "sys(SYS_WRITE + 0, [control.as_raw_fd()"),)),
)
# G-HE5C-7, the closure (G-HE5B-3's block over HE005B_CLOSURE_TREE).
HE005C_CLOSURE_ROWS = (
    ("l6 broker-sys dropped (B's four crates)", "(closure)",
     (("crates/broker/Cargo.toml", 'broker-sys = { path = "../broker-sys" }\n', ""),)),
    ("l7 broker-sys linking effect-gate", "(closure)",
     (("crates/broker-sys/Cargo.toml", "", '\n[dependencies]\neffect-gate = { path = "../effect-gate" }\n'),)),
)
# G-HE5C-8: the include rule with the WORKER programs and the key (check_broker_includes), the named byte items
# (check_broker_bytes), and R1-3's pin (check_role_programs).
HE005C_INCLUDE_ROWS = (
    ("i7 a WORKER program embedded in run.rs", "(includes)",
     ((_CRUN, "", '\nstatic W: &[u8; 1496] = include_bytes!("../../../../contracts/seccomp-v3/WORKER.x86_64.bpf");\n'),)),
    ("i8 the BROKER program in WORKER's place", "(includes)",
     ((_CSPAWN, 'include_bytes!("../../../../contracts/seccomp-v3/WORKER.aarch64.bpf")',
       'include_bytes!("../../../../contracts/seccomp-v3/BROKER.aarch64.bpf")'),)),
    ("i9 the observer's key in the broker's place", "(includes)",
     ((_CSIGNED, 'include_bytes!("../config-signer.pub")', 'include_bytes!("../../observer/config-signer.pub")'),)),
)
HE005C_BYTES_ROWS = (
    ("b6 a third byte item in spawn.rs", "(bytes)", ((_CSPAWN, "", '\nstatic EXTRA: &[u8; 4] = b"\\x06\\0\\0\\0";\n'),)),
    ("b7 a WORKER name in run.rs", "(bytes)", ((_CRUN, "", "\nstatic WORKER_X86_64: &[u8; 8] = &[0; 8];\n"),)),
    ("b8 the key retyped", "(bytes)",
     ((_CSIGNED, "pub const COMPILED_KEY: &[u8] = include_bytes!", "pub const COMPILED_KEY: &[u8; 32] = include_bytes!"),)),
)
HE005C_PROGRAM_ROWS = (
    ("r1 the broker's RoleSpec given a static", "(programs)",
     ((_BSEAL, "program: arch.program()", "program: PROGRAM_X86_64.as_slice()"),)),
    ("r2 the broker's arms swapped", "(programs)",
     ((_BSEAL, "Arch::X86_64 => PROGRAM_X86_64.as_slice(),", "Arch::X86_64 => PROGRAM_AARCH64.as_slice(),"),)),
    ("r3 the observer's RoleSpec given a static", "(programs)",
     ((_OSEAL, "program: RUNNING_ARCH.program(),", "program: PROGRAM_AARCH64.as_slice(),"),)),
    ("r4 a program static named in lib.rs", "(programs)",
     ((_BLIB, "", "\npub fn program_bytes() -> &'static [u8] {\n    crate::seal::PROGRAM_X86_64\n}\n"),)),
    ("r5 the broker's program arms fully swapped (R1-2)", "(programs)",
     ((_BSEAL, "            Arch::X86_64 => PROGRAM_X86_64.as_slice(),\n            Arch::Aarch64 => PROGRAM_AARCH64.as_slice(),",
       "            Arch::X86_64 => PROGRAM_AARCH64.as_slice(),\n            Arch::Aarch64 => PROGRAM_X86_64.as_slice(),"),)),
)
# G-HE5C-9, the markers' text half (check_he005c_markers): defined (a), called once (b), the WORKER statics (c).
HE005C_MARKER_ROWS = (
    ("g1 W4's thaw not #[inline(never)]", "(a)", ((_CRUN, "#[inline(never)]\nfn w4_thaw<", "fn w4_thaw<"),)),
    ("g2 NP-9's bracket inlined always", "(a)", ((_CNP9, "#[inline(never)]\npub fn bracket", "#[inline(always)]\npub fn bracket"),)),
    ("g3 the measure called twice", "(b)",
     ((_CSPAWN, "", "\nfn remeasure(script: &Script) -> io::Result<(u16, [u8; 32])> {\n    broker_sys::measure_verity(script)\n}\n"),)),
    ("g4 a marker renamed by its re-export", "(b)",
     ((_CSYSLIB, "pub use raw::measure_verity;", "pub use raw::measure_verity as measure;"),)),
    ("g5 the bracket called from W6", "(b)",
     ((_CW6, "", "\nfn early<L: LeafOps, K: Clock>(leaf: &mut L, clock: &K) {\n    let _ = super::np9::bracket(leaf, clock, 0);\n}\n"),)),
    ("g6 a WORKER static named outside the plan", "(c)", ((_CSPAWN, "", "\nfn worker_len() -> usize {\n    WORKER_X86_64.len()\n}\n"),)),
    ("g7 the WORKER arms swapped", "(c)",
     ((_CSPAWN, "Arch::X86_64 => WORKER_X86_64.as_slice(),", "Arch::X86_64 => WORKER_AARCH64.as_slice(),"),)),
    ("g8 a WORKER static made public", "(c)",
     ((_CSPAWN, "static WORKER_X86_64: &[u8; 1496]", "pub static WORKER_X86_64: &[u8; 1496]"),)),
)
# G-HE5C-10, the stand-ins (check_he005c_seams): (i)-(vii).
HE005C_SEAM_ROWS = (
    ("e1 a default body for qualify", "(i)",
     ((_CSEAMS, "    fn qualify(&mut self) -> GateAnswer;\n", "    fn qualify(&mut self) -> GateAnswer {\n        GateAnswer::Unavailable\n    }\n"),)),
    ("e2 a second method on Binder", "(i)", ((_CSEAMS, "pub trait Binder {\n", "pub trait Binder {\n    fn reset(&mut self) {}\n"),)),
    ("e3 a zero-sized gate ticket", "(ii)",
     ((_CSEAMS, "pub struct GateTicket {\n    pub generation: u64,\n}", "pub struct GateTicket {}"),)),
    ("e4 a single-valued bind answer", "(ii)", ((_CSEAMS, "    Bound(BindTicket),\n    Unavailable,\n", "    Unavailable,\n"),)),
    ("e5 the qualifier stand-in answering Qualified", "(iii)",
     ((_CSEAMS, "core::hint::black_box(crate::lifecycle::seams::GateAnswer::Unavailable)",
       "core::hint::black_box(crate::lifecycle::seams::GateAnswer::Qualified(GateTicket { generation: 1 }))"),)),
    ("e6 the binder stand-in without black_box", "(iii)",
     ((_CSEAMS, "core::hint::black_box(crate::lifecycle::seams::BindAnswer::Unavailable)",
       "crate::lifecycle::seams::BindAnswer::Unavailable"),)),
    ("e7 another qualifier", "(iv)",
     ((_CRUN, "", "\nstruct Always;\n\nimpl GateQualifier for Always {\n    fn qualify(&mut self) -> GateAnswer {\n"
                  "        GateAnswer::Unavailable\n    }\n}\n"),)),
    ("e8 a reference impl of Binder", "(iv)",
     ((_CSEAMS, "", "\nimpl<T: Binder> Binder for &mut T {\n    fn bind(&mut self, gate: &GateTicket, pid: i32, start_ticks: u64)"
                    " -> BindAnswer {\n        (**self).bind(gate, pid, start_ticks)\n    }\n}\n"),)),
    ("e9 a stand-in renamed", "(v)", ((_CMOD, "", "\npub use seams::QualifierStandIn as Qualifier;\n"),)),
    ("e10 the outcome aliased", "(v)", ((_CRUN, "", "\ntype Ended = Outcome;\n"),)),
    ("e11 a dyn qualifier", "(vi)", ((_CRUN, "", "\nfn erased(_qualifier: &mut dyn GateQualifier) {}\n"),)),
    ("e12 W6's bound changed", "(vii)", ((_CW6, "const W6_BOUND_MS: u64 = 10_000;", "const W6_BOUND_MS: u64 = 60_000;"),)),
)
# G-HE5C-11, serve (check_broker_serve): the order (a), the exact body (b), the lifecycle only through serve (c).
_CSTARTUP = "    startup_run(&leaf, &config, &mut standing, QualifierStandIn, BinderStandIn);\n"
HE005C_SERVE_ROWS = (
    ("v1 the startup run dropped", "(a)", ((_BMAIN, _CSTARTUP, ""),)),
    ("v2 the leaf opened twice", "(a)",
     ((_BMAIN, "    let leaf = open_leaf();\n", "    let leaf = open_leaf();\n    let _again = open_leaf();\n"),)),
    ("v3 the run's outcome bound", "(b)", ((_BMAIN, _CSTARTUP, "    let _outcome = " + _CSTARTUP[4:]),)),
    ("v4 lib.rs reaches the lifecycle", "(c)",
     ((_BLIB, "", "\npub fn membership() -> &'static [u8] {\n    lifecycle::leaf::membership()\n}\n"),)),
    ("v5 the run's entry named inside the lifecycle", "(c)",
     ((_CHOLD, "", "\nfn again() {\n    let _ = super::run::startup_run;\n}\n"),)),
    ("v6 seal.rs names the lifecycle", "(c)",
     ((_BSEAL, "", "\nfn leaf_path() -> &'static [u8] {\n    crate::lifecycle::leaf::membership()\n}\n"),)),
    ("v7 R1-1 (i): startup_run's body runs W5, W1 and W2 first", "(b)", _CFORM_I),
    ("v8 derive_hold no longer holds a failed open", "(b)",
     ((_CRUN, "        Err(_) => Some(Step::HoldRead),\n", "        Err(_) => None,\n"),)),
)
# G-HE5C-12, the key through black_box (check_broker_load): exact (a), the observer's parity (b).
_CLOAD = "load_from(PRODUCTION_DIR, core::hint::black_box(COMPILED_KEY))"
HE005C_LOAD_ROWS = (
    ("y1 the key without black_box", "(a)", ((_CSIGNED, _CLOAD, "load_from(PRODUCTION_DIR, COMPILED_KEY)"),)),
    ("y2 black_box around the load", "(a)",
     ((_CSIGNED, _CLOAD, "core::hint::black_box(load_from(PRODUCTION_DIR, COMPILED_KEY))"),)),
    ("y3 an alias of the key", "(a)", ((_CSIGNED, "", "\nconst KEY: &[u8] = COMPILED_KEY;\n"),)),
    ("y4 the document limit changed", "(b)",
     ((_CSIGNED, "pub const DOCUMENT_LIMIT: usize = 1 << 20;", "pub const DOCUMENT_LIMIT: usize = 1 << 21;"),)),
    ("y5 the observer's directory", "(b)", ((_CSIGNED, '"/etc/planeon/capacity-broker"', '"/etc/planeon/policy-observer"'),)),
    ("y6 a black_box in run.rs (R1-2)", "(a)",
     ((_CRUN, "", "\nfn opaque(value: u64) -> u64 {\n    core::hint::black_box(value)\n}\n"),)),
)
# G-HE5C-13, the configured seal site (check_seal_order with BROKER_SEAL_SITE).
HE005C_SITE_ROWS = (
    ("n1 the parse failure as a read failure", "(site)",
     ((_BMAIN, "Err(_) => return ExitCode::from(status::CONFIG_CHECK),", "Err(_) => return ExitCode::from(status::CONFIG_READ),"),)),
    ("n2 the document kept past the seal", "(site)", ((_BMAIN, "    drop(document);\n", ""),)),
    ("n3 serve without the configuration", "(site)",
     ((_BMAIN, "    ExitCode::from(serve(&sealed, config))\n", "    ExitCode::from(serve(&sealed, BrokerConfig::default()))\n"),)),
    ("n4 the signature failure as a read failure", "(site)",
     ((_BMAIN, "Err(LoadError::Signature(_)) => return ExitCode::from(status::CONFIG_SIGNATURE),",
       "Err(LoadError::Signature(_)) => return ExitCode::from(status::CONFIG_READ),"),)),
    ("n5 a second load between the stages", "(site)",
     ((_BMAIN, "    let config = match BrokerConfig::parse(&document) {",
       "    let _again = signed_config::load();\n    let config = match BrokerConfig::parse(&document) {"),)),
    ("n6 a Dir import in config.rs before the seal", "(site)", ((_CCONFIG, "", "\nuse gate_sys::Dir;\n"),)),
    ("n7 the parse reading another document", "(site)", ((_BMAIN, "BrokerConfig::parse(&document)", "BrokerConfig::parse(&stage1)"),)),
    ("n8 a statement between the parse and stage 2 (R1-2)", "(site)",
     ((_BMAIN, "    let sealed = match seal_stage2(stage1) {", "    let _x = 1;\n    let sealed = match seal_stage2(stage1) {"),)),
)
# MON-SEAM-E2, check_role_seal (e)'s one-file exception: a second format! in proc.rs, another format string there, and the
# expression in another broker file still refuse.
HE005C_E2_ROWS = (
    ("p1 a second format! in proc.rs", "(e)",
     ((_CPROC, "", '\nfn status_path(pid: i32) -> String {\n    format!("/proc/{}/status", pid)\n}\n'),)),
    ("p2 another format string in proc.rs", "(e)",
     ((_CPROC, 'Dir::at(&format!("/proc/{}", pid))', 'Dir::at(&format!("/proc/{}/", pid))'),)),
    ("p3 the process-directory open in leaf.rs", "(e)",
     ((_CLEAF, "", '\nfn peer(pid: i32) -> io::Result<Dir> {\n    Dir::at(&format!("/proc/{}", pid))\n}\n'),)),
    ("p4 a second identical process-directory open in proc.rs (R1-2)", "(e)",
     ((_CPROC, "", '\nfn again(pid: i32) -> io::Result<Dir> {\n    Dir::at(&format!("/proc/{}", pid))\n}\n'),)),
)
# MON-SEAM-E3, G-HE5B-1 (b)'s qualified-form exception: a bare name, any other form, or a listed form in another file
# still refuses.
HE005C_E3_ROWS = (
    ("q1 a bare ChannelEnd in spawn.rs", "(b)",
     ((_CSPAWN, "type ChannelEnd = broker_sys::ChannelEnd;", "type ChannelEnd = ChannelEnd;"),)),
    ("q2 another form of ChannelEnd in run.rs", "(b)",
     ((_CRUN, "child_end: S::ChannelEnd, script: S::Script)", "child_end: <S as SpawnOps>::ChannelEnd, script: S::Script)"),)),
    ("q3 spawn.rs's form in run.rs", "(b)", ((_CRUN, "", "\ntype End = broker_sys::ChannelEnd;\n"),)),
    ("q4 a bare Bind in run.rs", "(b)", ((_CRUN, "Entry::Failed(Step::Bind)", "Entry::Failed(Bind)"),)),
    ("q5 Step::Bind outside the lifecycle", "(b)", ((_BLIB, "", "\npub fn bind_step() -> u8 {\n    let _ = Step::Bind;\n    0\n}\n"),)),
    ("q6 Bind given a payload", "(b)", ((_COUT, "W3Descriptors, Bind, W4Thaw", "W3Descriptors, Bind(u8), W4Thaw"),)),
    ("q7 ops.rs's form in spawn.rs", "(b)", ((_CSPAWN, "", "\nfn end(_end: Self::ChannelEnd) {}\n"),)),
    ("q8 run.rs's form after another :: (R1-2)", "(b)", ((_CRUN, "", "\ntype Other = crate::x::S::ChannelEnd;\n"),)),
)
# LINKED-EXCEPTIONS-PROOF (the plan's Q-HE5C-5 (a)): each main's one exit import is the only std::process path the linked
# scan removes; another std::process import beside it refuses (He005cLinkedExceptionTests shows a loosened allowance
# would pass each row, so the rows test the exception's exactness).
HE005C_EXCEPTION_ROWS = tuple(
    ("le%d std::process::%s beside %s's ExitCode" % (index, name, rel.split("/")[1]), "(linked)",
     ((rel, "use std::process::ExitCode;\n", "use std::process::ExitCode;\nuse std::process::%s;\n" % name),))
    for index, (rel, name) in enumerate(((rel, name) for rel in (gate.GATE_MAIN, gate.OBSERVER_MAIN, gate.BROKER_MAIN)
                                         for name in ("exit", "Command")), 1))
SPAN_FUNCTIONS = {"(1)": "span_1_pinned", "(2)": "span_2_order", "(3)": "span_3_calls"}
EXEC_FUNCTIONS = {"(a)": "exec_a_once", "(b)": "exec_b_raw", "(c)": "exec_c_agent"}
THAW_FUNCTIONS = {"(a)": "thaw_a_exact", "(b)": "thaw_b_pass", "(c)": "thaw_c_order"}
OPENER_FUNCTIONS = {"(a)": "opener_a_names", "(b)": "opener_b_site", "(c)": "opener_c_elsewhere"}
CALLS_FUNCTIONS = {"(a)": "broker_sys_syscall", "(b)": "broker_sys_numbers", "(c)": "broker_sys_positions",
                   "(d)": "broker_sys_elsewhere"}
MARKER_FUNCTIONS = {"(a)": "markers_a_defined", "(b)": "markers_b_once", "(c)": "markers_c_worker"}
SEAM_FUNCTIONS = {"(i)": "seams_i_traits", "(ii)": "seams_ii_payloads", "(iii)": "seams_iii_standins",
                  "(iv)": "seams_iv_impls", "(v)": "seams_v_aliases", "(vi)": "seams_vi_dyn", "(vii)": "seams_vii_bound"}
LOAD_FUNCTIONS = {"(a)": "load_a_exact", "(b)": "load_b_parity"}


def he005c_single(name, check, clause, rows, tag, tree=he005c_tree):
    """A one-clause rule over a check with no clause functions of its own: a by-name wrapper, switched off by a name
    patch (HE005A_PROOF_RULES' form)."""
    return (name, lambda base: getattr(gate, check)(base), (clause,), rows, lambda _: tag, re.escape(tag),
            named_patches({clause: check}), tree)


# (rule, check, its clauses, rows, the named clause's message, any clause's message, the patches, the tree builder).
HE005C_PROOF_RULES = (
    ("G-HE5C-1..3 span", gate.check_child_span, tuple(SPAN_FUNCTIONS), HE005C_SPAN_ROWS,
     lambda clause: "(child-path span, G-HE5C-1..3 %s)" % clause, r"\(child-path span, G-HE5C-1\.\.3 \(",
     named_patches(SPAN_FUNCTIONS), he005c_tree),
    ("G-HE5C-4 measured exec", gate.check_measured_exec, tuple(EXEC_FUNCTIONS), HE005C_EXEC_ROWS,
     lambda clause: "(measured exec, G-HE5C-4 %s)" % clause, r"\(measured exec, G-HE5C-4 \(",
     named_patches(EXEC_FUNCTIONS), he005c_tree),
    ("G-HE5C-5 W4 thaw", gate.check_w4_thaw, tuple(THAW_FUNCTIONS), HE005C_THAW_ROWS,
     lambda clause: "(W4 thaw, G-HE5C-5 %s)" % clause, r"\(W4 thaw, G-HE5C-5 \(", named_patches(THAW_FUNCTIONS), he005c_tree),
    ("G-HE5C-6 control opener", gate.check_control_opener, tuple(OPENER_FUNCTIONS), HE005C_OPENER_ROWS,
     lambda clause: "(control opener, G-HE5C-6 %s)" % clause, r"\(control opener, G-HE5C-6 \(",
     named_patches(OPENER_FUNCTIONS), he005c_tree),
    he005c_single("G-HE5C-7 lists", "check_he005c_lists", "(lists)", HE005C_LIST_ROWS, "(broker-sys lists, G-HE5C-7)"),
    he005c_single("G-HE5C-7 start-up lint", "check_sources", "(sources)", HE005C_STARTUP_ROWS, "(start-up lint)"),
    he005c_single("G-HE5C-7 unsafe", "check_unsafe", "(unsafe)", HE005C_UNSAFE_ROWS, "contains unsafe outside"),
    he005c_single("G-HE5C-7 foreign items", "check_foreign_items", "(foreign)", HE005C_FOREIGN_ROWS, "(foreign-item check)"),
    he005c_single("G-HE5C-7 linked sources", "check_linked_sources", "(linked)", HE005C_LINKED_ROWS,
                  "(linked-source tripwire)"),
    he005c_single("G-HE5C-7 socket modules and threads", "check_socket_modules", "(socket)", HE005C_SOCKET_ROWS,
                  "(socket-module check)"),
    ("G-HE5C-7 calls", gate.check_broker_sys_calls, tuple(CALLS_FUNCTIONS), HE005C_CALLS_ROWS,
     lambda clause: "(broker-sys calls, G-HE5C-7 (G-D1-3's form, Q-RAW-R1-3) %s)" % clause,
     r"\(broker-sys calls, G-HE5C-7 \(G-D1-3's form, Q-RAW-R1-3\) \(", named_patches(CALLS_FUNCTIONS), he005c_tree),
    ("G-HE5C-7 closure", he005b_closure_check, ("(closure)",), HE005C_CLOSURE_ROWS, lambda clause: "(workspace shape)",
     re.escape("(workspace shape)"), named_patches({"(closure)": "check_workspace_shape"}), he005b_closure_tree),
    he005c_single("G-HE5C-8 includes", "check_broker_includes", "(includes)", HE005C_INCLUDE_ROWS, "(broker includes)"),
    he005c_single("G-HE5C-8 bytes", "check_broker_bytes", "(bytes)", HE005C_BYTES_ROWS, "(broker bytes, R1-2)"),
    he005c_single("R1-3 role programs", "check_role_programs", "(programs)", HE005C_PROGRAM_ROWS, "(role programs, R1-3)"),
    ("G-HE5C-9 markers", gate.check_he005c_markers, tuple(MARKER_FUNCTIONS), HE005C_MARKER_ROWS,
     lambda clause: "(broker markers, G-HE5C-9 %s)" % clause, r"\(broker markers, G-HE5C-9 \(",
     named_patches(MARKER_FUNCTIONS), he005c_tree),
    ("G-HE5C-10 stand-ins", gate.check_he005c_seams, tuple(SEAM_FUNCTIONS), HE005C_SEAM_ROWS,
     lambda clause: "(seam stand-ins, G-HE5C-10 %s)" % clause, r"\(seam stand-ins, G-HE5C-10 \(",
     named_patches(SEAM_FUNCTIONS), he005c_tree),
    ("G-HE5C-11 serve", gate.check_broker_serve, tuple(SERVE_FUNCTIONS), HE005C_SERVE_ROWS,
     lambda clause: "(broker serve, R1-5 %s)" % clause, r"\(broker serve, R1-5 \(", named_patches(SERVE_FUNCTIONS),
     he005c_tree),
    ("G-HE5C-12 key through black_box", gate.check_broker_load, tuple(LOAD_FUNCTIONS), HE005C_LOAD_ROWS,
     lambda clause: "(broker key through black_box, G-HE5C-12 %s)" % clause,
     r"\(broker key through black_box, G-HE5C-12 \(", named_patches(LOAD_FUNCTIONS), he005c_tree),
    ("G-HE5C-13 configured seal site", lambda base: gate.check_seal_order(base, gate.BROKER_SEAL_SITE), ("(site)",),
     HE005C_SITE_ROWS, lambda clause: "(seal-order grammar)", re.escape("(seal-order grammar)"),
     named_patches({"(site)": "check_seal_order"}), he005c_tree),
    ("MON-SEAM-E2 clause (e)", gate.check_role_seal, tuple("(%s)" % name for name, _ in gate.ROLE_SEAL_CLAUSES),
     HE005C_E2_ROWS, lambda clause: ROLE_SEAL_TAGS[clause], r"\(role-seal rule \([a-g]\)", role_seal_patches, he005c_tree),
    ("MON-SEAM-E3 G-HE5B-1 (b)", gate.check_broker_isolation, tuple(HE005B_ISOLATION_FUNCTIONS), HE005C_E3_ROWS,
     lambda clause: "(HE-005B isolation, G-HE5B-1 %s)" % clause, r"\(HE-005B isolation, G-HE5B-1 \(",
     named_patches(HE005B_ISOLATION_FUNCTIONS), he005c_tree),
    he005c_single("LINKED-EXCEPTIONS-PROOF", "check_linked_sources", "(linked)", HE005C_EXCEPTION_ROWS,
                  "(linked-source tripwire)"),
)


class He005cRuleTests(Tree):
    """HE-005C's rules over copies of the real sources (HE005C_TREE): each accepts today's sources; each row is refused by
    its rule, and with every other clause of the rule disabled, by its own named clause's message; forms the rules do
    not read pass; and G-HE5C-7's list memberships refuse when one is dropped."""

    TREE = HE005C_TREE

    def plant(self, changes):
        texts = he005c_tree(changes)
        for rel in HE005C_TREE:
            if rel not in texts and (self.base / rel).exists():
                (self.base / rel).unlink()
        for rel, text in texts.items():
            self.write(rel, text)

    def test_the_real_sources_and_the_fixture_pass(self):
        for base in (self.base, gate.HE):
            self.assertEqual(gate.check_child_span(base), 16)
            self.assertEqual(gate.check_measured_exec(base), 14)
            self.assertEqual(gate.check_w4_thaw(base), 5)
            self.assertEqual(gate.check_control_opener(base), 39)
            self.assertEqual(gate.check_he005c_lists(base), 11)  # Q-U4-1 (a): and POST_SEAL_CRATES
            self.assertEqual(gate.check_broker_sys_calls(base), 28)
            self.assertEqual(gate.check_role_programs(base), 2)
            self.assertEqual(gate.check_he005c_markers(base), 5)
            self.assertEqual(gate.check_he005c_seams(base), 7)
            self.assertEqual(gate.check_broker_load(base), 1307)
            self.assertEqual(gate.check_broker_bytes(base), 24)
            self.assertEqual(gate.check_broker_serve(base), 6)
            self.assertEqual(gate.check_broker_isolation(base), 28)
            self.assertEqual(gate.check_role_seal(base), 18)
        for check in (gate.check_sources, gate.check_unsafe, gate.check_foreign_items, gate.check_linked_sources,
                      gate.check_socket_modules):
            self.assertGreater(check(self.base), 0)
        self.assertEqual(gate.SPAN_PINS, {"clone_span": "f3487c636d0ac7b133617e9d2f6491ce8a71bf575ba5f75aa184ff3bc9091570",
                                          "child_path": "0a9684c3eb62eb4770692265882f11ae137521c83158ee108025b792a6209f0c"})
        self.assertEqual(gate.FOREIGN_ITEMS[gate.BROKER_SYS_RAW], {"syscall"})
        self.assertEqual(gate.CRATE_ROOTS[gate.BROKER_SYS_LIB], "#![deny(unsafe_code)]")

    def test_the_tables(self):
        self.assertEqual(tuple(len(rule[3]) for rule in HE005C_PROOF_RULES),
                         (12, 8, 10, 9, 2, 5, 2, 2, 2, 3, 10, 2, 3, 3, 5, 8, 12, 8, 6, 8, 4, 8, 6))
        # PR review round 1 (Q-HE5C-R1-1 (a)): R1-1's four rows (its two planted forms, derive_hold's pin) and
        # R1-2's nine, 125 -> 138.
        self.assertEqual(sum(len(rule[3]) for rule in HE005C_PROOF_RULES), 138)
        for name, check, clauses, rows, tag, any_tag, patches, tree in HE005C_PROOF_RULES:
            self.assertTrue(callable(check), name)
            for row in rows:
                self.assertIn(row[1], clauses, row[0])
                tree(row[2])
        for functions in (SPAN_FUNCTIONS, EXEC_FUNCTIONS, THAW_FUNCTIONS, OPENER_FUNCTIONS, CALLS_FUNCTIONS, MARKER_FUNCTIONS,
                          SEAM_FUNCTIONS, LOAD_FUNCTIONS, SERVE_FUNCTIONS):
            for function in functions.values():
                self.assertTrue(callable(getattr(gate, function)), function)

    def refuses_each(self, check, rows, tag, any_tag, patches):
        for label, clause, changes in rows:
            self.plant(changes)
            try:
                with self.assertRaisesRegex(gate.GateError, any_tag, msg=label):
                    check(self.base)
                active = patches(enabled=clause)
                for patch in active:
                    patch.start()
                try:
                    with self.assertRaisesRegex(gate.GateError, re.escape(tag(clause)), msg=label):
                        check(self.base)
                finally:
                    for patch in active:
                        patch.stop()
            finally:
                self.plant(())

    def test_each_rule_refuses_its_rows(self):
        for name, check, _, rows, tag, any_tag, patches, tree in HE005C_PROOF_RULES:
            if tree is he005c_tree:
                self.refuses_each(check, rows, tag, any_tag, patches)

    def test_forms_the_rules_pass(self):
        # Comments are not code (outside G-HE5C-6, which reads raw text), and spacing around `::` and between tokens is
        # not text the code rules compare.
        for check, changes in (
                (gate.check_w4_thaw, ((_CRUN, "", "\n// w4_thaw(leaf, &passed, &bound) and LeafWrite::Thaw, in a comment\n"),)),
                (gate.check_broker_sys_calls, ((_CLEAF, "", "\n// syscall(SYS_OPENAT, ...) is raw.rs's alone\n"),)),
                (gate.check_broker_serve, ((_BMAIN, _CSTARTUP, _CSTARTUP.replace("(&leaf, ", "( &leaf , ")),)),
                (gate.check_broker_isolation, ((_CRUN, "Entry::Failed(Step::Bind)", "Entry::Failed(Step :: Bind)"),)),
                (gate.check_he005c_seams, ((_CSEAMS, "", "\n// impl GateQualifier for Anything, dyn Binder: a comment\n"),))):
            self.plant(changes)
            try:
                self.assertGreater(check(self.base), 0)
            finally:
                self.plant(())

    def test_a_dropped_membership_refuses(self):
        message = re.escape("(broker-sys lists, G-HE5C-7)")
        for name, value in (
                ("SCANNED_CRATES", tuple(crate for crate in gate.SCANNED_CRATES if crate != gate.BROKER_SYS_CRATE)),
                ("BROKER_LINKED_CRATES", gate.BROKER_LINKED_CRATES[:-1]),
                ("POST_SEAL_CRATES", tuple(crate for crate in gate.POST_SEAL_CRATES if crate != gate.BROKER_SYS_CRATE)),
                ("UNSAFE_FILES", tuple(rel for rel in gate.UNSAFE_FILES if rel != gate.BROKER_SYS_RAW)),
                ("FD_FILES", tuple(rel for rel in gate.FD_FILES if rel != gate.BROKER_SYS_RAW)),
                ("FOREIGN_ITEMS", {**gate.FOREIGN_ITEMS, gate.BROKER_SYS_RAW: {"syscall", "getpid"}}),
                ("CRATE_ROOTS", {**gate.CRATE_ROOTS, gate.BROKER_SYS_LIB: "#![allow(unsafe_code)]"}),
                ("BROKER_NO_PANIC", tuple(rel for rel in gate.BROKER_NO_PANIC if rel != gate.BROKER_SYS_RAW)),
                ("STARTUP_EXCEPTIONS", {**gate.STARTUP_EXCEPTIONS, _CRUN: ((gate.PEER_DIR, gate.PEER_DIR_CALL),)}),
                ("LEAF_PATH", "/sys/fs/cgroup/planeon.slice/other.service/probe-worker")):
            with mock.patch.object(gate, name, value):
                with self.assertRaisesRegex(gate.GateError, message, msg=name):
                    gate.check_he005c_lists(self.base)

    def test_broker_sys_root_must_deny_unsafe_code(self):
        self.refused(gate.check_linked_sources, _CSYSLIB,
                     HE005C_TREE[_CSYSLIB].replace("#![deny(unsafe_code)]", "#![allow(unsafe_code)]"), "lacks #!\\[deny")


class He005cClosureTests(Tree):
    """HE-005C G-HE5C-7: broker-sys joins the broker closure block's fixture; dropping it, or broker-sys linking another
    crate, refuses, and with the block switched off each passes."""

    TREE = HE005B_CLOSURE_TREE

    def test_the_closure_rows(self):
        self.assertEqual(he005b_closure_check(self.base), 9)
        rule = {rule[0]: rule for rule in HE005C_PROOF_RULES}["G-HE5C-7 closure"]
        _, check, _, rows, _, any_tag, patches, tree = rule
        for label, clause, changes in rows:
            for rel, text in tree(changes).items():
                self.write(rel, text)
            try:
                with self.assertRaisesRegex(gate.GateError, "planeon-broker links .*, not .* .workspace shape", msg=label):
                    check(self.base)
                active = patches(disabled=(clause,))
                for patch in active:
                    patch.start()
                try:
                    check(self.base)
                finally:
                    for patch in active:
                        patch.stop()
            finally:
                for rel, text in tree(()).items():
                    self.write(rel, text)


class He005cLinkedExceptionTests(Tree):
    """LINKED-EXCEPTIONS-PROOF: each main's other std::process import refuses, and with each main's allowance loosened to
    remove one more std::process import, the same row passes, so the rows test the exception's exactness."""

    TREE = HE005C_TREE
    LOOSE = re.compile(r"\buse\s+std::process::\w+\s*;")

    def test_each_row_refuses_and_a_loosened_allowance_passes_it(self):
        self.assertGreater(gate.check_linked_sources(self.base), 0)
        loosened = {rel: expressions + (("a loosened allowance", self.LOOSE),)
                    for rel, expressions in gate.LINKED_EXCEPTIONS.items()}
        for label, _, changes in HE005C_EXCEPTION_ROWS:
            for rel, text in he005c_tree(changes).items():
                self.write(rel, text)
            try:
                with self.assertRaisesRegex(gate.GateError, "names std::process .linked-source tripwire", msg=label):
                    gate.check_linked_sources(self.base)
                with mock.patch.object(gate, "LINKED_EXCEPTIONS", loosened):
                    self.assertGreater(gate.check_linked_sources(self.base), 0, msg=label)
            finally:
                for rel, text in he005c_tree(()).items():
                    self.write(rel, text)


class He005cBinaryTests(unittest.TestCase):
    """HE-005C G-HE5C-9's binary half: each built planeon-broker holds its WORKER program once and, by whole item path
    (legacy, v0 or a v0 generic instance), a symbol of each marker, a ring_core symbol and one in the broker's
    configuration modules; a closure inside a marker or a name that only mentions it does not count."""

    PROGRAM = bytes(range(24)) * 2
    MARKERS = {"_RINvNtCs5pXa2Z9YbGW_10broker_sys3raw10clone_spanNtB4_6KernelEB4_",
               "_ZN10broker_sys3raw10child_path17h0123456789abcdefE",
               "_RNvNtCs5pXa2Z9YbGW_10broker_sys3raw14measure_verity",
               "_RINvNtNtCs5pXa2Z9YbGW_14planeon_broker9lifecycle3run7w4_thawNtNtB6_4leaf9LinuxLeafEB6_",
               "_ZN14planeon_broker9lifecycle3np97bracket17h0123456789abcdefE",
               "ring_core_0_17_14_x25519_sc_reduce",
               "_RNvNtCs5pXa2Z9YbGW_14planeon_broker13signed_config4load"}

    def test_the_markers(self):
        found = gate.check_broker_markers(self.MARKERS | {"main", "read"})
        self.assertEqual(len(found), 7)
        self.assertEqual([gate.marker_path(name) for name in found[:5]], list(gate.BROKER_MARKER_SYMBOLS))
        for wanted in gate.BROKER_MARKER_SYMBOLS:
            names = {name for name in self.MARKERS if gate.marker_path(name) != wanted}
            with self.assertRaisesRegex(gate.GateError, "holds no %s symbol" % re.escape("::".join(wanted))):
                gate.check_broker_markers(names)
        # A closure inside a marker and a symbol that only mentions one do not count.
        others = {name for name in self.MARKERS if gate.marker_path(name) != ("broker_sys", "raw", "clone_span")}
        for name in ("_RNCINvNtCs5pXa2Z9YbGW_10broker_sys3raw10clone_spanNtB6_6KernelE0B6_",
                     "_ZN4core3ptr10clone_span17h0123456789abcdefE"):
            with self.assertRaisesRegex(gate.GateError, "holds no broker_sys::raw::clone_span symbol"):
                gate.check_broker_markers(others | {name})
        with self.assertRaisesRegex(gate.GateError, "no ring_core_0_17_14_ symbol"):
            gate.check_broker_markers({name for name in self.MARKERS if not name.startswith("ring_core")})
        with self.assertRaisesRegex(gate.GateError, "no symbol in planeon_broker::signed_config or ::config"):
            gate.check_broker_markers({name for name in self.MARKERS if "signed_config" not in name})

    def test_the_worker_program_once(self):
        raw = b"\x7fELF" + b"\0" * 64 + self.PROGRAM + b"\0" * 16
        self.assertEqual(gate.check_broker_worker(raw, self.PROGRAM), 48)
        for count in (0, 2, 3):
            with self.assertRaisesRegex(gate.GateError, "holds its WORKER program %d times, not exactly once" % count):
                gate.check_broker_worker(b"\0" * 8 + self.PROGRAM * count + b"\0", self.PROGRAM)
        with self.assertRaisesRegex(gate.GateError, "an empty WORKER program"):
            gate.check_broker_worker(raw, b"")
        self.assertEqual(set(gate.BROKER_WORKER_PROGRAMS), set(gate.MACHINE))
        self.assertTrue(set(gate.BROKER_WORKER_PROGRAMS.values()) <= set(gate.CONTRACTS))


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
