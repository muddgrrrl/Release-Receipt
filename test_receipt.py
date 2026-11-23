import hashlib
import json
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from receipt import InspectionError, expected_hash, inspect_bundles

SCRIPT = Path(__file__).with_name("receipt.py")


def thin(cpu):
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, 2, 0, 0, 0, 0)


def fat():
    arm = thin(0x0100000C)
    intel = thin(0x01000007)
    header = struct.pack(">12I", 0xCAFEBABE, 2, 0x0100000C, 0, 48, len(arm), 0,
                         0x01000007, 0, 48 + len(arm), len(intel), 0)
    return header + arm + intel


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "Example.zip"

    def make_zip(self, binary, extra_plist=None):
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("Example.app/Contents/Info.plist",
                             plistlib.dumps({"CFBundleExecutable": "Example"}))
            archive.writestr("Example.app/Contents/MacOS/Example", binary)
            if extra_plist:
                archive.writestr(extra_plist, b"ignored")

    def command(self, *flags):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.archive), *flags],
                              capture_output=True, text=True)

    def test_universal_and_checksum_manifest(self):
        self.make_zip(fat(), "../../Broken.app/Contents/Info.plist")
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        sums = self.root / "SHA256SUMS.txt"
        sums.write_text(f"{digest} *./{self.archive.name}\n", encoding="utf-8")
        result = self.command("--checksums", str(sums), "--require-universal", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["bundles"][0]["architectures"], ["arm64", "x86_64"])
        self.assertTrue(data["checksum_verified"])

    def test_mismatch_does_not_inspect_corrupt_archive(self):
        self.archive.write_bytes(b"not a zip")
        result = self.command("--expected", "0" * 64)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Checksum mismatch", result.stderr)

    def test_thin_app_fails_universal_check(self):
        self.make_zip(thin(0x0100000C))
        result = self.command("--require-universal")
        self.assertEqual(result.returncode, 3)
        self.assertIn("arm64", result.stdout)

    def test_rejects_out_of_bounds_architecture(self):
        broken = struct.pack(">7I", 0xCAFEBABE, 1, 0x0100000C, 0, 400, 40, 0)
        self.make_zip(broken)
        with self.assertRaises(InspectionError):
            inspect_bundles(self.archive)

    def test_invalid_plist_is_reported_without_traceback(self):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(".", b"")
            archive.writestr("Example.app/Contents/Info.plist", b"<?xml broken")
        result = self.command()
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid Info.plist", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_ambiguous_checksum_entries(self):
        sums = self.root / "SHA256SUMS.txt"
        sums.write_text(("a" * 64 + "  Example.zip\n") * 2, encoding="utf-8")
        with self.assertRaises(InspectionError):
            expected_hash(sums, "Example.zip")


if __name__ == "__main__":
    unittest.main()
