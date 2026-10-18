from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN = ROOT / "ci/zero_bill_scan.py"
# The scanned words are built at run time, so this file never matches the scan it tests.
NODE_PORT, LOAD_BALANCER, KEY = "Node" + "Port", "Load" + "Balancer", "api" + "_key"
CONTRACTS = ("host-enforcement/contracts/admission-v3/admission-manifests/planeon-a2.json",
             "host-enforcement/contracts/admission-v3/vectors.json")


class ZeroBillContractAllowlistTests(unittest.TestCase):
    """The pinned admission-v3 contract files are exempt from the service-type patterns only with their exact bytes at
    their exact paths (owner decision Q-HE4B1-ZB (a), 2026-10-18)."""

    def tree(self, files: dict[str, bytes]) -> Path:
        base = Path(tempfile.mkdtemp(prefix="zero-bill-"))
        self.addCleanup(shutil.rmtree, base)
        for name in ("Containerfile", "ci/targets/op-001.json"):
            (base / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, base / name)
        for name, data in files.items():
            (base / name).parent.mkdir(parents=True, exist_ok=True)
            (base / name).write_bytes(data)
        return base

    def scan(self, base: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-I", "-B", str(SCAN), str(base)], capture_output=True, text=True,
                              timeout=60)

    def test_the_pinned_bytes_at_their_paths_pass(self) -> None:
        result = self.scan(self.tree({name: (ROOT / name).read_bytes() for name in CONTRACTS}))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_changed_byte_is_refused(self) -> None:
        for changed in CONTRACTS:
            with self.subTest(changed=changed):
                files = {name: (ROOT / name).read_bytes() for name in CONTRACTS}
                files[changed] = files[changed].replace(b"}", b" }", 1)
                result = self.scan(self.tree(files))
                self.assertEqual(result.returncode, 1)
                self.assertIn(changed + " contains prohibited executable configuration: (?i)" + NODE_PORT, result.stderr)
                self.assertIn(changed + " contains prohibited executable configuration: (?i)" + LOAD_BALANCER,
                              result.stderr)

    def test_the_same_bytes_at_another_path_are_refused(self) -> None:
        moved = "host-enforcement/contracts/admission-v4/vectors.json"
        result = self.scan(self.tree({moved: (ROOT / CONTRACTS[1]).read_bytes()}))
        self.assertEqual(result.returncode, 1)
        self.assertIn(moved + " contains prohibited executable configuration: (?i)" + NODE_PORT, result.stderr)

    def test_the_exemption_covers_the_service_type_patterns_only(self) -> None:
        # A scan whose allowlist pins a file that names both service types and also carries a key assignment: the two
        # service-type patterns are skipped for it, the key pattern still refuses it.
        name = CONTRACTS[1]
        data = ('{"rule": "!has(object.spec.healthCheck%s) && type != %s"}\n%s: "x"\n'
                % (NODE_PORT, LOAD_BALANCER, KEY)).encode()
        digest = __import__("hashlib").sha256(data).hexdigest()
        base = self.tree({name: data})
        pinned = (ROOT / CONTRACTS[1]).read_bytes()
        script = SCAN.read_text(encoding="utf-8").replace(__import__("hashlib").sha256(pinned).hexdigest(), digest)
        self.assertEqual(script.count(digest), 1)
        scan = Path(tempfile.mkdtemp(prefix="zero-bill-scan-"))
        self.addCleanup(shutil.rmtree, scan)
        (scan / "zero_bill_scan.py").write_text(script, encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", str(scan / "zero_bill_scan.py"), str(base)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1)
        self.assertIn(name + " contains prohibited executable configuration: (?i)(api[_-]?key", result.stderr)
        self.assertNotIn(NODE_PORT, result.stderr)
        self.assertNotIn(LOAD_BALANCER, result.stderr)


if __name__ == "__main__":
    unittest.main()
