"""Self-test of gate.py (stdlib unittest): the ELF parser, the table checks and the output-prefix rule.

gate.py runs this suite in-process before its checks and re-emits the unittest stream under its prefix.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gate

X86, ARM = "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"
COMMENT = b"Linker: LLD 23.1.1\0rustc version 1.99.0 (b940084d7 2026-09-28)\0"


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
            gate.check_binary(raw, target, shape)

    def test_good_shapes_pass(self):
        gate.check_binary(build_elf(), X86, "static-pie")
        gate.check_binary(build_elf(machine=183, rela=(1027,)), ARM, "static-pie")
        gate.check_binary(build_elf(rela=()), X86, "static-pie")
        gate.check_binary(static_elf(), ARM, "static")

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
        self.assertRefused(build_elf(comment=b"Linker: LLD 23.1.1\0"), "rustc version 1.99.0")
        self.assertRefused(build_elf(comment=b"rustc version 1.98.0 (aaaaaaaaa 2026-08-01)\0Linker: LLD 23\0"), "rustc")
        self.assertRefused(build_elf(comment=b"rustc version 1.99.0 (b940084d7 2026-09-28)\0GCC: (GNU) 13\0"), "LLD")

    def test_host_paths(self):
        for needle in (b"/Users/someone/src", b"/opt/planeon/toolchains", b"/private/tmp/x", b"/private/var/folders"):
            self.assertRefused(build_elf(payload=needle), "build-host path")
        with self.assertRaisesRegex(gate.GateError, "build-host path"):
            gate.check_binary(build_elf(payload=b"/srv/checkout/x"), X86, "static-pie", (b"/srv/checkout",))

    def test_truncated_file_fails(self):
        raw = build_elf()
        with self.assertRaises(Exception):
            gate.check_binary(raw[:200], X86, "static-pie")


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
        self.assertEqual(gate.check_workspace(self.base), {"a", "b"})

    def test_build_scripts_and_proc_macros(self):
        (self.base / "crates/a/build.rs").write_text("fn main() {}\n")
        with self.assertRaisesRegex(gate.GateError, "build script"):
            gate.check_workspace(self.base)
        (self.base / "crates/a/build.rs").unlink()
        (self.base / "crates/b/Cargo.toml").write_text('[package]\nname = "b"\nbuild = "gen.rs"\n')
        with self.assertRaisesRegex(gate.GateError, "build script"):
            gate.check_workspace(self.base)
        (self.base / "crates/b/Cargo.toml").write_text('[package]\nname = "b"\n\n[lib]\nproc-macro = true\n')
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
        self.lock('[[package]]\nname = "a"\nversion = "0.1.0"\n\n[[package]]\nname = "b"\nversion = "0.1.0"\n'
                  'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "00"\n')
        with self.assertRaisesRegex(gate.GateError, "registry or git"):
            gate.check_workspace(self.base)

    def test_start_up_lint(self):
        self.assertEqual(gate.check_sources(self.base), 2)
        (self.base / "target/debug").mkdir(parents=True)
        (self.base / "target/debug/generated.rs").write_text("std::thread::available_parallelism()\n")
        self.assertEqual(gate.check_sources(self.base), 2)
        main = self.base / "crates/a/src/main.rs"
        for token in gate.FORBIDDEN_SOURCE:
            main.write_text("fn main() { let _ = %s; }\n" % token)
            with self.assertRaisesRegex(gate.GateError, "start-up lint"):
                gate.check_sources(self.base)


PIN = {"rustc": {"release": "1.99.0", "commit": "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4"},
       "cargo": "cargo 1.99.0 (5f94df478 2026-08-27)", "host": "aarch64-apple-darwin", "sysroot": "/sys-root",
       "targets": {X86: {"shape": "static-pie"}, ARM: {"shape": "static"}},
       "commandLineTools": {"clang": "Apple clang version 14.0.3 (clang-1403.0.22.14.1)", "sdk": "13.3"}}


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        tools = Path(self.directory.name)
        (tools / "usr/bin").mkdir(parents=True)
        (tools / "usr/bin/clang").write_text("")
        (tools / "SDKs/MacOSX.sdk").mkdir(parents=True)
        (tools / "SDKs/MacOSX.sdk/SDKSettings.json").write_text(json.dumps({"Version": "13.3"}))
        self.pin = json.loads(json.dumps(PIN))
        self.pin["commandLineTools"]["path"] = str(tools)
        self.answers = {
            "rustc -vV": "rustc 1.99.0 (b940084d7 2026-09-28)\nbinary: rustc\ncommit-hash: "
                         "b940084d7eb6a299eb4bfeb8e34901bc051e7ac4\nhost: aarch64-apple-darwin\nrelease: 1.99.0\n",
            "cargo -V": "cargo 1.99.0 (5f94df478 2026-08-27)\n", "rustc --print sysroot": "/sys-root\n",
            "rustc --print target-libdir --target " + X86: "/sys-root/lib/rustlib/%s/lib\n" % X86,
            "rustc --print target-libdir --target " + ARM: "/sys-root/lib/rustlib/%s/lib\n" % ARM,
            str(tools / "usr/bin/clang") + " --version": "Apple clang version 14.0.3 (clang-1403.0.22.14.1)\nTarget: x\n"}

    def tearDown(self):
        self.directory.cleanup()

    def check(self):
        output = io.StringIO()
        with mock.patch.object(gate, "run", lambda argv: self.answers[" ".join(argv)]), contextlib.redirect_stdout(output):
            gate.check_toolchain(self.pin)
        return output.getvalue()

    def test_pinned_toolchain_passes(self):
        self.assertNotIn("differ", self.check())

    def test_rustc_cargo_and_sysroot_mismatch_fail(self):
        for key, value in (("rustc -vV", self.answers["rustc -vV"].replace("b940084d7eb6", "0000084d7eb6")),
                           ("cargo -V", "cargo 1.99.1 (aaaaaaaaa 2026-09-01)\n"),
                           ("rustc --print sysroot", "/elsewhere\n"),
                           ("rustc --print target-libdir --target " + ARM, "/elsewhere/lib\n")):
            saved, self.answers[key] = self.answers[key], value
            with self.assertRaises(gate.GateError):
                self.check()
            self.answers[key] = saved

    def test_command_line_tools(self):
        self.pin["commandLineTools"]["sdk"] = "14.0"
        self.assertIn("differ from toolchain.json (printed, not failed)", self.check())
        os.unlink(Path(self.pin["commandLineTools"]["path"]) / "usr/bin/clang")
        with self.assertRaisesRegex(gate.GateError, "Command Line Tools are missing"):
            self.check()


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
