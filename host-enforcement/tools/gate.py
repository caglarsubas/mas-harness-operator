#!/usr/bin/env python3
"""HE-001 gate: toolchain pin, workspace and lock, closure table, crt objects, binaries, start-up lint and SBOM.

HE-002C adds three lexical tripwires over the workspace's Rust sources: no refused std path in the sources linked into
EFFECT_GATE (a list of refused modules and items, not an allowlist of std modules), the word `unsafe` only in gate-sys's
openat module, and no code included from a file the scans do not read. They match text, not Rust: the compiler's `#![forbid(unsafe_code)]` on the effect-gate and
i05-protocol roots enforces those crates' unsafe rule, and any form the tripwires do not refuse is code review's.

The owner-operated verifier runs it as `python3 -I -B host-enforcement/tools/gate.py` from the repository root, after
the two musl release builds. Stdlib only. Every line it prints starts with "he-gate: ", so no line starts with one of the
verifier's evidence prefixes. It fails closed on the first violation (exit 1).
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import subprocess
import sys
import tomllib
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
# harness-onion contract files R10 holds, byte-exact, registered in harness-onion's operator -> harness-engineering
# buildArtifact edge record (owner decision Q-HE2-A); provenance in contracts/PROVENANCE.md.
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
}
ACCEPTED = ("ACCEPTED_AND", "ACCEPTED_OR", "ALLOWED_EXCEPTION_EXPRESSION", "DEFAULT_ALLOWED")
MACHINE = {"x86_64-unknown-linux-musl": 62, "aarch64-unknown-linux-musl": 183}
RELATIVE = {"x86_64-unknown-linux-musl": 8, "aarch64-unknown-linux-musl": 1027}
FORBIDDEN_SOURCE = ("available_parallelism", "current_exe", "current_dir", "env::var", "var_os", "vars", "/proc", "/sys")
HOST_PATHS = (b"/Users/", b"/opt/planeon/", b"/private/tmp/", b"/private/var/")
# HE-002C DESIGN section 9: the crates EFFECT_GATE will link, checked over their non-test sources (src/).
LINKED_CRATES = ("crates/effect-gate", "crates/gate-sys", "crates/i05-protocol")
OPENAT = "crates/gate-sys/src/openat.rs"
CRATE_ROOTS = {"crates/i05-protocol/src/lib.rs": "#![forbid(unsafe_code)]",
               "crates/effect-gate/src/lib.rs": "#![forbid(unsafe_code)]",
               "crates/gate-sys/src/lib.rs": "#![deny(unsafe_code)]"}
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
                (re.compile(r"std::\$"), "completes a std path in a macro"))
# The std::os paths a linked source may name besides the fs items: the fd items, in the openat module only.
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
                 # Forms the other patterns cannot read: a raw identifier (r#process, r#path) and inline assembly.
                 (re.compile(r"\br#[A-Za-z_]"), "uses a raw identifier"),
                 (re.compile(r"\b(?:global_asm|naked_asm|asm)\s*!"), "uses inline assembly"))
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
    if (found, sdk) != (pin["commandLineTools"]["clang"], pin["commandLineTools"]["sdk"]):
        say("note: the Command Line Tools differ from toolchain.json (printed, not failed)")
    return sysroot


def check_linker(pin: dict, root: Path) -> None:
    """The repository-root cargo config links both musl targets through the wrapper, and the wrapper execs the pinned
    rust-lld with the pinned sysroot's lib/ on the dylib search path (so a pin change cannot miss the wrapper)."""
    config = tomllib.loads((root / ".cargo/config.toml").read_text(encoding="utf-8"))
    require(set(config) == {"net", "target"}, "the cargo config must hold only [net] and [target]")
    require(config.get("net") == {"offline": True}, "the cargo config must set [net] offline = true and nothing else")
    flags = ["-C", "link-self-contained=yes", "-C", "target-feature=+crt-static"]
    require(set(config.get("target", {})) == set(pin["targets"]), "the cargo config must name exactly the pinned targets")
    for target in pin["targets"]:
        require(config["target"][target] == {"linker": pin["linkerWrapper"], "rustflags": flags},
                "the cargo config for %s is not the wrapper with the static flags" % target)
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


def check_workspace(base: Path) -> dict:
    """The workspace members, each with its direct workspace (path) dependencies."""
    workspace = tomllib.loads((base / "Cargo.toml").read_text(encoding="utf-8"))
    names, paths = {}, {}
    manifests = []
    for member in workspace["workspace"]["members"]:
        manifest = tomllib.loads((base / member / "Cargo.toml").read_text(encoding="utf-8"))
        package = manifest["package"]
        require("build" not in package and not (base / member / "build.rs").exists(), "a build script in " + member)
        library = manifest.get("lib", {})
        require(not library.get("proc-macro") and not library.get("proc_macro"), "a proc-macro crate in " + member)
        require("build-dependencies" not in manifest and "target" not in manifest, "build or target dependencies in " + member)
        names[package["name"]] = set()
        paths[(base / member).resolve()] = package["name"]
        manifests.append((member, package["name"], manifest))
    for member, name, manifest in manifests:
        for table in ("dependencies", "dev-dependencies"):
            for dependency, spec in manifest.get(table, {}).items():
                require(type(spec) is dict and set(spec) == {"path"} and (base / member / spec["path"]).resolve() in paths
                        and paths[(base / member / spec["path"]).resolve()] == dependency,
                        "a dependency outside the workspace in " + member)
                if table == "dependencies":
                    names[name].add(dependency)
    packages = tomllib.loads((base / "Cargo.lock").read_text(encoding="utf-8"))["package"]
    require(sorted(package["name"] for package in packages) == sorted(names),
            "Cargo.lock does not list exactly the workspace crates")
    require(all("source" not in package and "checksum" not in package for package in packages),
            "Cargo.lock names a registry or git package")
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
    count = 0
    for path in sorted(base.rglob("*.rs")):
        if path.relative_to(base).parts[0] == "target":   # the build directory only
            continue
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_SOURCE:
            require(token not in text, "%s uses %s (start-up lint)" % (path.relative_to(base).as_posix(), token))
        count += 1
    return count


def workspace_sources(base: Path) -> list[Path]:
    """Every .rs file of the workspace outside the build directory (tests and binaries included)."""
    return [path for path in sorted(base.rglob("*.rs")) if path.relative_to(base).parts[0] != "target"]


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


def check_linked_sources(base: Path) -> int:
    """A lexical tripwire over the non-test sources of the crates EFFECT_GATE will link, with the whitespace around `::`
    removed first: none names a refused std path (LINKED_FORBIDDEN; the fd items outside the openat module; std fs items
    other than the allowed ones; std::os paths other than those), renames a std item, or uses a form that names std's
    modules without spelling their paths (LINKED_FORMS); and their crate-root attributes. Other std paths pass: it
    refuses a list, it is not an allowlist of std modules. It matches text, not Rust: the compiler's
    `#![forbid(unsafe_code)]` enforces the roots' rule, and any other form is code review's."""
    for root, attribute in CRATE_ROOTS.items():
        require(attribute in (base / root).read_text(encoding="utf-8").splitlines(), "%s lacks %s" % (root, attribute))
    count = 0
    for crate in LINKED_CRATES:
        for path in sorted((base / crate / "src").rglob("*.rs")):
            rel = path.relative_to(base).as_posix()
            text = PATH_SPACE.sub("::", path.read_text(encoding="utf-8"))
            for pattern in LINKED_FORBIDDEN:
                require(not re.search(pattern, text), "%s names %s (linked-source tripwire)" % (rel, pattern.replace("\\b", "")))
            require(rel == OPENAT or not FD_ITEMS.search(text), "%s names a std::os::fd item outside %s" % (rel, OPENAT))
            rest = text
            for item, allowed in FS_ITEMS:
                if allowed(rel):
                    rest = re.sub(re.escape(item) + r"(?!\w)", "", rest)
            require(not re.search(r"\bfs\b", rest),
                    "%s names a std fs item other than its allowed ones, one item per use line (linked-source tripwire)" % rel)
            if rel == OPENAT:
                rest = OPENAT_FD_PATH.sub("", rest)
            require(not re.search(r"std::os\b", rest),
                    "%s names a std::os item other than its allowed ones (linked-source tripwire)" % rel)
            for use in STD_USE.finditer(text):
                require(not re.search(r"\sas\s", use.group(0)), "%s renames a std item in a use statement" % rel)
            for pattern, form in LINKED_FORMS:
                require(not pattern.search(text), "%s %s (linked-source tripwire)" % (rel, form))
            count += 1
    return count


def check_unsafe(base: Path) -> int:
    """A lexical tripwire: the word unsafe appears in no workspace source but gate-sys's openat module (tests and
    binaries included)."""
    count = 0
    for path in workspace_sources(base):
        rel = path.relative_to(base).as_posix()
        if rel != OPENAT:
            require(not UNSAFE.search(path.read_text(encoding="utf-8")), "%s contains unsafe outside %s" % (rel, OPENAT))
        count += 1
    return count


def sbom(binary: str, target: str, digest: str, rows: list[dict], workspace: set) -> bytes:
    """workspace: the workspace crates in the binary's dependency closure."""
    components = [{"type": "library", "name": row["component"], "version": row["version"],
                   "licenses": [{"expression": row["canonical"]}], "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                   "properties": [{"name": "planeon:path", "value": row["path"]},
                                  {"name": "planeon:outcome", "value": row["outcome"]}]}
                  for row in rows if row["target"] == target and row["role"] == "LINKED"]
    components += [{"type": "library", "name": name, "version": VERSION, "licenses": [{"expression": "Apache-2.0"}],
                    "properties": [{"name": "planeon:path", "value": "host-enforcement (workspace crate)"}]}
                   for name in sorted(workspace)]
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
        check_linker(pin, ROOT)
        say("linker: the cargo config links both targets through %s, which execs the pinned rust-lld" % pin["linkerWrapper"])
        workspace = check_workspace(HE)
        say("workspace: %d crates, a lock without registry or git packages, no build script or proc-macro" % len(workspace))
        say("contracts: %d files match the registered harness-onion bytes" % check_contracts(HE))
        rows = load_table(TABLE.read_bytes(), TABLE_SHA256)
        check_tree(rows, sysroot, targets)
        say("closure: %d shipped files match the reviewed table %s" % (len(rows), TABLE_SHA256))
        for target in targets:
            for name in CRT_OBJECTS:
                check_crt_symbols(name, symbol_names((sysroot / "lib/rustlib" / target / "lib/self-contained" / name)
                                                     .read_bytes()))
        say("crt objects: compiler-rt's crtbegin and crtend on both targets")
        say("start-up lint: %d workspace sources without a forbidden API" % check_sources(HE))
        say("included code: %d workspace sources pass the lexical tripwire (no path attribute, include!, raw "
            "identifier or inline assembly; no manifest target path, build key or symlink), crates' src/ hold only .rs "
            "files" % check_included_code(HE))
        say("linked sources: %d sources of effect-gate, gate-sys and i05-protocol name no refused std path (lexical "
            "tripwire), crate roots forbid or deny unsafe_code" % check_linked_sources(HE))
        say("unsafe: the lexical tripwire finds the word only in %s among %d workspace sources"
            % (OPENAT, check_unsafe(HE)))
        markers = comment_markers(pin)
        host_paths = HOST_PATHS + tuple(path.encode() for path in (str(ROOT), str(Path.home())) if len(path) > 1)
        for target in targets:
            shape = pin["targets"][target]["shape"]
            for binary in BINARIES:
                raw = (HE / "target" / target / "release" / binary).read_bytes()
                check_binary(raw, target, shape, markers, host_paths)
                digest = sha256(raw)
                document = sbom(binary, target, digest, rows, linked(workspace, binary))
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
