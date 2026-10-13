#!/usr/bin/env python3
"""HE-001 gate: toolchain pin, workspace and lock, closure table, crt objects, binaries, start-up lint and SBOM.

The owner-operated verifier runs it as `python3 -I -B host-enforcement/tools/gate.py` from the repository root, after
the two musl release builds. Stdlib only. Every line it prints starts with "he-gate: ", so no line starts with one of the
verifier's evidence prefixes. It fails closed on the first violation (exit 1).
"""
from __future__ import annotations

import hashlib
import io
import json
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


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


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
