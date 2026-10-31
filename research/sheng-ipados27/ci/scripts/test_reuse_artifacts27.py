"""Small offline reuse guards; no native build, Mac signature or device test."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("reuse27_tested", Path(__file__).with_name("reuse_artifacts27.py"))
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)


class ReuseTests(unittest.TestCase):
    def test_fixed_run_and_source_contract(self):
        self.assertEqual(reuse.SOURCE_RUN, 41173083070)
        self.assertEqual(reuse.POLICY_SOURCE_RUN, 41166392969)
        self.assertEqual(reuse.PINS, reuse.helper("payload_stage27").PINS)
        self.assertEqual(reuse.PINNED_FILES["data.dbr"], "b8433fd0cc979fbc1584a256d5a677b005cffed7d6da620ed18f3e6e1ec50e72")
        self.assertEqual(reuse.PINNED_FILES["firmware/SILICIUM_UEFI.fd"], "5ea559e296eea36b168f0f6bf680b08142041cfdd0c75cd15c3acacc9b405fb7")

    def test_member_refuses_missing_and_escaped_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "artifact"
            root.mkdir()
            (root / "known.bin").write_bytes(b"known")
            (base / "outside.bin").write_bytes(b"outside")
            self.assertEqual(reuse.member(root, "known.bin"), root / "known.bin")
            for name in ("absent.bin", "../outside.bin"):
                with self.assertRaises(ValueError):
                    reuse.member(root, name)

    def test_changed_capture_refused_before_other_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "capture.bin"
            source.write_bytes(b"captured bytes")
            with patch.dict(reuse.PINNED_FILES, {"capture.bin": hashlib.sha256(source.read_bytes()).hexdigest()}, clear=True):
                reuse.verify_pins(root)
                source.write_bytes(b"replacement bytes")
                with self.assertRaisesRegex(ValueError, "Captured run file SHA-256 differs"):
                    reuse.verify_pins(root)

    def test_derived_header_bundle_keeps_exact_supplied_headers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Structural fixtures only; the real verifier first checks RSA and
            # the complete tables with data_stage27.root_plan.
            headers = [bytes([value]) * 544 for value in (3, 4)]
            for name, header in zip(("OS", "SystemOS"), headers):
                (root / name).mkdir()
                (root / name / "manifest.bin").write_bytes(header + b"fixture-table")
            result = root / "headers.bin"
            result.write_bytes(reuse.header_bundle(root))
            self.assertEqual(result.stat().st_size, 1152)
            checked = reuse.helper("payload_stage27").policy_bundle(result, root)
            self.assertTrue(checked["header_only"])
            result.write_bytes(result.read_bytes()[:-1] + b"!")
            with self.assertRaises(ValueError):
                reuse.helper("payload_stage27").policy_bundle(result, root)


if __name__ == "__main__":
    unittest.main()
