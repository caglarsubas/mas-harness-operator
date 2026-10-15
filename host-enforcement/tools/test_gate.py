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
    "crates/gate/src/main.rs": "fn main() {}\n",
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
        self.assertEqual(gate.check_linked_sources(self.base), 7)
        self.assertEqual(gate.check_unsafe(self.base), 9)
        self.assertEqual(gate.check_included_code(self.base), 9)

    def test_forbidden_names_in_linked_sources(self):
        for text in ("use std::process::Command;", "let _ = std::env::args_os();", "use std::net::TcpStream;",
                     "use std::path::Path;", "fn f(_: &Path) {}", "fn f(_: PathBuf) {}", "let _ = DirBuilder::new();",
                     "let _ = OpenOptions::new();", "let _ = File::open(x);", "let _ = File::create(x);",
                     "let _ = File::options();", "Err(TryLockError::WouldBlock) => {}", "fn f(_: Metadata) {}"):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", "linked-source tripwire")
            self.refused("crates/gate-sys/src/openat.rs", LINKED_TREE["crates/gate-sys/src/openat.rs"] + text + "\n",
                         "linked-source tripwire")
        # Tests and other crates are outside the linked-source tripwire (the start-up lint and the unsafe rule still apply).
        self.write("crates/gate/src/main.rs", "use std::path::Path;\nfn main() {}\n")
        self.assertEqual(gate.check_linked_sources(self.base), 7)

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
        self.assertEqual(gate.check_linked_sources(self.base), 7)

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
        self.assertEqual(gate.check_linked_sources(self.base), 7)

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
        self.assertEqual(gate.check_linked_sources(self.base), 7)

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
        self.assertEqual(gate.check_linked_sources(self.base), 7)

    def test_crate_root_attributes(self):
        for rel in gate.CRATE_ROOTS:
            self.refused(rel, "pub mod x;\n", "lacks")
        self.refused("crates/gate-sys/src/lib.rs", "#![forbid(unsafe_code)]\npub mod openat;\n", "lacks")
        self.refused("crates/effect-gate/src/lib.rs", "#![deny(unsafe_code)]\npub mod file_store;\n", "lacks")

    def test_unsafe_is_confined_to_openat(self):
        for rel in ("crates/effect-gate/tests/files.rs", "crates/gate/src/main.rs", "crates/i05-protocol/src/json.rs",
                    "crates/gate-sys/src/lib.rs"):
            self.refused(rel, LINKED_TREE.get(rel, "") + "// no unsafe here\n", "contains unsafe outside",
                         check=gate.check_unsafe)
        self.write("crates/effect-gate/src/lib.rs", "#![forbid(unsafe_code)]\n// unsafe_code is a lint name\n")
        self.assertEqual(gate.check_unsafe(self.base), 9)

    # HE-002S DESIGN section 6: gate-sys's seal.rs is the second file that may contain the word unsafe.
    def test_unsafe_is_also_allowed_in_gate_sys_seal(self):
        self.write("crates/gate-sys/src/seal.rs", "#![allow(unsafe_code)]\nfn f() -> i32 { unsafe { prctl(38, 1) } }\n")
        self.assertEqual(gate.check_unsafe(self.base), 10)
        for rel in ("crates/effect-gate/src/seal.rs", "crates/gate-sys/src/seal/raw.rs", "crates/gate-sys/tests/seal.rs"):
            self.refused(rel, "fn f() { unsafe { g() } }\n", "contains unsafe outside crates/gate-sys/src/openat.rs and "
                         "crates/gate-sys/src/seal.rs", check=gate.check_unsafe)

    # HE-002C PR review round 3, R3-1: a renaming import of global_asm or naked_asm.
    def test_renamed_assembly_macros(self):
        for rel in ("crates/gate/src/main.rs", "crates/effect-gate/src/file_store.rs"):
            for text in ("use core::arch::global_asm as ga;\nga!(\".globl x\");", "use core::arch::{naked_asm as na};",
                         "use std::arch::global_asm as ga;",
                         "macro_rules! call { ($m:ident) => { core::arch::$m!(\"\"); } }\ncall!(global_asm);"):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", "uses inline assembly", check=gate.check_included_code)
        self.write("crates/gate/src/main.rs", "fn main() { let global_asmx = 1; let _ = global_asmx; }\n")
        self.assertEqual(gate.check_included_code(self.base), 9)

    # HE-002S PR review round 1, R1-4: a renaming import of asm (now possible in seal.rs too), and the word asm in a
    # linked source, where a macro could otherwise assemble the call from its arguments.
    def test_renamed_asm(self):
        for rel in ("crates/gate-sys/src/seal.rs", "crates/gate/src/main.rs", "crates/effect-gate/src/file_store.rs"):
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
        self.write("crates/gate/src/main.rs", "fn main() { let asm = 1; let _ = asm; }\n")
        self.assertEqual(gate.check_included_code(self.base), 9)
        self.assertEqual(gate.check_linked_sources(self.base), 7)

    # HE-002S DESIGN section 5 (D7): std APIs that reach a call the EFFECT_GATE filter kills, in effect-gate, gate-sys
    # and (PR review round 1, R1-2) i05-protocol, whose code runs after the seal too; is_terminal joins the list.
    def test_post_seal_std_apis(self):
        self.assertEqual(gate.check_post_seal_sources(self.base), 7)
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
        self.write("crates/gate/src/main.rs", "fn main() { let _ = std::io::stdin().is_terminal(); }\n")
        self.write("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                   + "fn g(f: &File) { let _ = f.try_clone(); let _ = copy_from_slice; let _ = terminal; }\n")
        self.assertEqual(gate.check_post_seal_sources(self.base), 7)

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
        self.assertEqual(gate.check_linked_sources(self.base), 7)

    def test_nested_globs_and_std_aliases(self):
        for text, message in (("use std::collections::*;", "nested glob of std"),
                              ("use std :: io :: prelude :: * ;", "nested glob of std"),
                              ("use std::os::unix::prelude::*;", "std::os item other than"),
                              ("use {std as s};", "renames std"), ("pub use { std  as  s };", "renames std")):
            self.refused("crates/i05-protocol/src/json.rs", text + "\n", message)
        self.write("crates/i05-protocol/src/json.rs", "mod tests { use super::*; }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 7)

    def test_raw_identifiers_and_inline_assembly(self):
        for rel in ("crates/i05-protocol/src/json.rs", "crates/gate/src/main.rs", "crates/effect-gate/tests/files.rs"):
            for text, message in (("let _ = std::r#process::Command::new(x);", "uses a raw identifier"),
                                  ("use r#std as s;", "uses a raw identifier"),
                                  ('#[r#path = "x.inc"] mod m;', "uses a raw identifier"),
                                  ('core::arch::global_asm!("");', "uses inline assembly"),
                                  ('fn f() { asm ! ("nop") }', "uses inline assembly")):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", message, check=gate.check_included_code)
        self.write("crates/gate/src/main.rs", 'fn main() { let _ = r#"raw string"#; let asm = 1; }\n')
        self.assertEqual(gate.check_included_code(self.base), 9)

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
        self.assertEqual(gate.check_included_code(self.base), 9)

    # HE-002C PR review round 1, R1-1: the forms that passed the first tripwire.

    def test_grouped_std_imports(self):
        for text in ("use std::{process::Command};", "use std :: {net::TcpStream};", "pub use ::std::{env};",
                     "use std::*;", "pub use std :: * ;"):
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "top-level group or glob of std")
        self.write("crates/i05-protocol/src/json.rs", "use std::collections::{BTreeMap, BTreeSet};\n")
        self.assertEqual(gate.check_linked_sources(self.base), 7)

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
        self.assertEqual(gate.check_linked_sources(self.base), 7)

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
        for rel in ("crates/gate-sys/src/lib.rs", "crates/gate/src/main.rs", "crates/effect-gate/tests/files.rs"):
            for text in ('#[path = "extra.inc"]\nmod extra;', '# [ path="extra.rs"] mod extra;', '#![path = "x"]',
                         '#[cfg_attr(all(), path = "extra.inc")]\nmod extra;'):
                self.refused(rel, LINKED_TREE[rel] + text + "\n", "has a path attribute", check=gate.check_included_code)
        self.write("crates/gate/src/main.rs", '#[cfg_attr(test, derive(Debug))]\nstruct S;\nfn main() { let path = "p"; }\n')
        self.assertEqual(gate.check_included_code(self.base), 9)

    def test_include_in_a_linked_crate(self):
        for text in ('include!("extra.txt");', 'std::include !("extra.txt");', "use core::include as inc;",
                     "use core::{include as inc};"):
            self.refused("crates/effect-gate/src/file_store.rs", LINKED_TREE["crates/effect-gate/src/file_store.rs"]
                         + text + "\n", "names include", check=gate.check_included_code)

    def test_include_in_a_binary_crate(self):
        self.refused("crates/gate/src/main.rs", 'include!("extra.txt");\nfn main() {}\n', "names include",
                     check=gate.check_included_code)
        self.write("crates/gate/src/main.rs", 'const A: &str = include_str!("a.txt");\n'
                                              'const B: &[u8] = include_bytes!("b.bin");\nfn main() {}\n')
        self.assertEqual(gate.check_included_code(self.base), 9)

    def test_non_rs_files_under_src(self):
        for rel in ("crates/gate-sys/src/extra.inc", "crates/gate/src/extra.txt", "crates/effect-gate/src/sub/x.rs.txt"):
            self.refused(rel, "#![allow(unsafe_code)]\nunsafe fn f() {}\n", "not a .rs file", check=gate.check_included_code)
        os.symlink("../tests", self.base / "crates/effect-gate/src/linked")
        with self.assertRaisesRegex(gate.GateError, "symlink under crates/"):
            gate.check_included_code(self.base)
        (self.base / "crates/effect-gate/src/linked").unlink()
        self.write("crates/effect-gate/tests/data.json", "{}\n")
        self.assertEqual(gate.check_included_code(self.base), 9)


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
                    "    fn recv(fd: c_int, b: *mut c_void, n: usize, flags: c_int) -> c_long;\n"
                    "    fn send(fd: c_int, b: *const c_void, n: usize, flags: c_int) -> c_long;\n"
                    "    fn shutdown(fd: c_int, how: c_int) -> c_int;\n"
                    "    fn syscall(number: c_long, ...) -> c_long;\n}\n")
FOREIGN_TREE = {
    **LINKED_TREE,
    "crates/gate-sys/src/openat.rs": "#![allow(unsafe_code)]\nunsafe extern \"C\" {\n    // the one call\n"
                                     "    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;\n}\n",
    "crates/gate-sys/src/seal.rs": "#![allow(unsafe_code)]\n" + SEAL_DECLARATIONS
                                   + "pub fn user_ids() -> [u32; 3] { [0; 3] }\n",
    # HE-003A: the channel module, the third file with its own allowlist (the linked tree's eighth source).
    "crates/gate-sys/src/channel.rs": "#![allow(unsafe_code)]\n" + CHANNEL_DECLARATIONS,
    # HE-003B: the tcp module, the fourth.
    "crates/gate-sys/src/tcp.rs": "#![allow(unsafe_code)]\n" + TCP_DECLARATIONS,
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
        self.assertEqual(gate.check_foreign_items(self.base), 10)
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
        self.write("crates/gate/src/main.rs", "unsafe extern \"C\" { fn system(c: *const u8) -> i32; }\nfn main() {}\n")
        self.assertEqual(gate.check_foreign_items(self.base), 10)

    def test_extern_items_are_private_and_not_safe(self):
        seal = "crates/gate-sys/src/seal.rs"
        for old, new, message in (("    fn prctl(", "    pub fn prctl(", "public foreign item"),
                                  ("    fn prctl(", "    pub(crate) fn prctl(", "public foreign item"),
                                  ("    fn getresuid(", "    safe fn getresuid(", "safe foreign item"),
                                  ("    fn capget(", "    pub safe fn capget(", "public foreign item")):
            self.refused(seal, FOREIGN_TREE[seal].replace(old, new), message)
        # A comment inside the block is not read; the word unsafe before extern is not the word safe.
        self.write(seal, FOREIGN_TREE[seal].replace("    fn prctl(", "    // not pub, not safe\n    fn prctl("))
        self.assertEqual(gate.check_foreign_items(self.base), 10)

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
        self.assertEqual(gate.check_foreign_items(self.base), 10)

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
        self.assertEqual(gate.check_foreign_items(self.base), 10)

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
    def test_the_table_pins_the_effect_gate_programs(self):
        self.patch.stop()
        try:
            self.assertEqual(len(gate.CONTRACTS), 15)
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v3/EFFECT_GATE.aarch64.bpf"],
                             "0ccbd7d090212fe52d366a2d68515670de40557cbc6fd07531653b404bb7105a")
            self.assertEqual(gate.CONTRACTS["contracts/seccomp-v3/EFFECT_GATE.x86_64.bpf"],
                             "ee85e9d225ad687aec82f83cb7d7c1be95f16df5f68eec5b56ee913d6cd86115")
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
        self.assertEqual(gate.check_unsafe(self.base), 12)
        for rel in ("crates/gate-sys/src/channel/raw.rs", "crates/effect-gate/src/channel.rs",
                    "crates/effect-gate/src/substrate.rs", "crates/gate-sys/src/peer_wire.rs"):
            self.refused(gate.check_unsafe, rel, "fn f() { unsafe { g() } }\n", "contains unsafe outside .*channel.rs")

    def test_the_channel_module_declares_exactly_its_twelve_symbols(self):
        self.assertEqual(gate.check_foreign_items(self.base), 10)
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
        self.assertEqual(gate.check_linked_sources(self.base), 10)
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
    "crates/gate/src/main.rs": "#[derive(Debug)]\nstruct S { f: std::fs::File }\nfn main() {}\n",
}


class DebugDeriveTests(Tree):
    """HE-003A DESIGN section 8: no derive(Debug), also under cfg_attr, on a struct or enum of the linked crates whose
    field types mention File, Dir, FileStores, Conn, Listener, Poller, PidFd or ProcDir; field and variant names are not
    types, manual impls pass, and the binary crates are not linked."""

    TREE = DEBUG_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_debug_derives(self.base), 8)

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
        self.assertEqual(gate.check_debug_derives(self.base), 9)


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
        # HE-003B DESIGN section 2.6: the union of effect-gate's and gate-tls's closures.
        for workspace in ({**WORKSPACE, "effect-gate": {"gate-sys", "i05-protocol", "planeon-gate"}},
                          {**WORKSPACE, "effect-gate": {"gate-sys"}, "gate-tls": {"effect-gate"}},
                          {**WORKSPACE, "gate-sys": {"planeon-gate"}},
                          {**WORKSPACE, "gate-tls": {"effect-gate", "planeon-gate"}}):
            with self.assertRaisesRegex(gate.GateError, "the crates effect-gate and gate-tls link"):
                gate.check_workspace_shape(self.base, workspace)
        without = {name: deps for name, deps in WORKSPACE.items() if name != "gate-tls"}
        with self.assertRaisesRegex(gate.GateError, "the crates effect-gate and gate-tls link"):
            gate.check_workspace_shape(self.base, without)


TCP = "crates/gate-sys/src/tcp.rs"


class TcpModuleTests(Tree):
    """HE-003B DESIGN section 3.1: gate-sys's tcp module is the fourth file allowed `unsafe`, declares exactly its eight
    foreign symbols, and may name the std::os::fd items."""

    TREE = FOREIGN_TREE

    def test_the_tcp_module_declares_exactly_its_eight_symbols(self):
        self.assertEqual(gate.check_foreign_items(self.base), 10)
        self.assertEqual(gate.FOREIGN_ITEMS[TCP], {"socket", "setsockopt", "bind", "listen", "recv", "send", "shutdown",
                                                    "syscall"})
        message = "tcp.rs declares the foreign items .* not exactly"
        for text in (FOREIGN_TREE[TCP].replace("    fn shutdown(fd: c_int, how: c_int) -> c_int;\n", ""),
                     FOREIGN_TREE[TCP].replace("fn recv(", "fn recvfrom("),
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn accept(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn accept4(f: c_int) -> c_int; }\n",
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn ioctl(f: c_int, ...) -> c_int; }\n",
                     FOREIGN_TREE[TCP] + "unsafe extern \"C\" { fn connect(f: c_int) -> c_int; }\n"):
            self.refused(gate.check_foreign_items, TCP, text, message)
        (self.base / TCP).unlink()
        with self.assertRaisesRegex(gate.GateError, "tcp.rs is missing"):
            gate.check_foreign_items(self.base)

    def test_unsafe_and_fd_items_are_allowed_in_tcp(self):
        self.assertEqual(gate.check_unsafe(self.base), 12)
        self.write(TCP, FOREIGN_TREE[TCP] + "use std::os::fd::AsRawFd;\nuse std::os::fd::OwnedFd;\n"
                        "fn f() { unsafe { g() } }\n")
        self.assertEqual(gate.check_linked_sources(self.base), 10)
        self.assertEqual(gate.check_unsafe(self.base), 12)
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


class TlsTests(Tree):
    """HE-003B DESIGN sections 2.6 and 20 (D1-5, D2-1): the TLS deny-list over gate-tls's sources and the
    exactly-once settings."""

    TREE = {"crates/gate-tls/src/lib.rs": "#![forbid(unsafe_code)]\npub mod tls;\n",
            "crates/gate-tls/src/tls.rs": GOOD_TLS,
            "crates/gate-tls/tests/tls_server.rs": "// tests may build a Ticketer, a KeyLogFile, ServerConfig::builder()\n"}

    def test_the_closed_configuration_passes(self):
        self.assertEqual(gate.check_tls(self.base), 2)

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
        self.assertEqual(gate.check_tls(self.base), 2)

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
        self.assertEqual(gate.check_tls(self.base), 2)

    def test_the_resolver_is_named_exactly_once(self):
        tls = "crates/gate-tls/src/tls.rs"
        self.refused(gate.check_tls, tls, GOOD_TLS.replace("SingleCertAndKey::from(certified)", "certified"),
                     "SingleCertAndKey::from. exactly once")
        self.refused(gate.check_tls, tls, GOOD_TLS + "fn again() { let _ = with_cert_resolver(x); }\n",
                     "with_cert_resolver. exactly once")


SECRET_TREE = {**DEBUG_TREE, "crates/gate-tls/src/tls.rs": "#[derive(Debug)]\npub enum TlsSetupError { Key(rustls::Error) }\n"
                                                          "impl fmt::Debug for TlsServerInputs { fn fmt() {} }\n"}


class SecretDebugTests(Tree):
    """HE-003B DESIGN section 2.6 (D1-4): no derive(Debug) on a secret type or on an item whose field types mention one,
    nor on one holding the I04 listener's opaque types."""

    TREE = SECRET_TREE

    def test_the_tree_passes(self):
        self.assertEqual(gate.check_debug_derives(self.base), 9)

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
                     'zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }\n')
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
        for text in (GATE_TLS_MANIFEST + "ring = \"=0.17.14\"\n",
                     GATE_TLS_MANIFEST + "\n[dev-dependencies]\nring = \"=0.17.14\"\n"):
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
