from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dispatcher", ROOT / "ci/run_make_target.py")
assert SPEC and SPEC.loader
dispatcher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dispatcher
SPEC.loader.exec_module(dispatcher)


def descriptor(packet: str = "OP-001", target: str = "proof", command: list[str] | None = None, variables: dict | None = None) -> dict:
    return {
        "packetId": packet,
        "schemaVersion": dispatcher.SCHEMA,
        "targets": [{"acceptedVariables": variables or {}, "argvTemplate": [command or ["python3", "-V"]], "name": target}],
    }


class DispatchTests(unittest.TestCase):
    def write(self, directory: Path, name: str, value: object) -> None:
        (directory / name).write_text(json.dumps(value), encoding="utf-8")

    def assert_refused(self, callback) -> None:
        with self.assertRaises(dispatcher.DescriptorError):
            callback()

    def test_valid_descriptor_loads(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.write(directory, "op-001.json", descriptor())
            rules = dispatcher.load_rules(directory)
            self.assertEqual([(rule.packet_id, rule.target) for rule in rules], [("OP-001", "proof")])

    def test_negative_descriptor_vectors(self) -> None:
        vectors = (
            ("wrong.json", descriptor()),
            ("op-001.json", descriptor(command=["sh", "-c", "true"])),
            ("op-001.json", descriptor(variables={"TOKEN": {"const": "x"}})),
            ("op-001.json", {**descriptor(), "extra": True}),
            ("op-001.json", {**descriptor(), "targets": []}),
        )
        for name, value in vectors:
            with self.subTest(name=name, value=value):
                with tempfile.TemporaryDirectory() as raw:
                    directory = Path(raw)
                    self.write(directory, name, value)
                    self.assert_refused(lambda: dispatcher.load_rules(directory))

    def test_duplicate_json_and_overlapping_handlers_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            (directory / "op-001.json").write_text('{"packetId":"OP-001","packetId":"OP-001","schemaVersion":"x","targets":[]}', encoding="utf-8")
            self.assert_refused(lambda: dispatcher.load_rules(directory))
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            value = descriptor()
            value["targets"].append(value["targets"][0].copy())
            self.write(directory, "op-001.json", value)
            self.assert_refused(lambda: dispatcher.load_rules(directory))

    def test_unknown_target_and_make_variable_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            self.write(directory, "op-001.json", descriptor())
            self.assert_refused(lambda: dispatcher.dispatch("unknown", {}, directory))
        self.assert_refused(lambda: dispatcher.supplied_variables({"MAKEOVERRIDES": "CLOUD=x", "CLOUD": "x"}))


if __name__ == "__main__":
    unittest.main()
