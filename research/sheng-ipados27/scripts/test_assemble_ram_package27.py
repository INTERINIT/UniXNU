"""Data/root mismatch controls and optional actual-input RAM-package plan.

The real-input control refuses every sparse-file open and every external
command except OpenSSL. It never publishes a package or contacts a device.
"""

import argparse
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("ram_assembler27_tests", Path(__file__).with_name("assemble_ram_package27.py"))
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)
REAL = None


class RamPackageControls(unittest.TestCase):
    def fixture(self):
        identity = {"boot_policy_bundle_sha256": "a" * 64, "data_seed_sha256": "b" * 64,
                    "data_volume_uuid": "11111111-1111-1111-1111-111111111111"}
        boot = {"root_policies_sha256": "a" * 64, "owner_anchor_sha256": "c" * 64,
                "data_seed_sha256": identity["data_seed_sha256"], "data_volume_uuid": identity["data_volume_uuid"]}
        return identity, {"owner_anchor_sha256": "c" * 64}, boot

    def test_different_Data_uuid_or_seed_cannot_reuse_installation(self):
        identity, root, boot = self.fixture()
        a.matching_install(identity, root, boot)
        for key in ("data_volume_uuid", "data_seed_sha256"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.matching_install(identity, root, dict(boot, **{key: "another Data"}))

    def test_different_root_policy_or_anchor_cannot_reuse_installation(self):
        identity, root, boot = self.fixture()
        for key in ("root_policies_sha256", "owner_anchor_sha256"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.matching_install(identity, root, dict(boot, **{key: "d" * 64}))

    def test_optional_actual_plan_never_opens_sparse_or_calls_device(self):
        if REAL is None:
            self.skipTest("Supply --real-result/--installed-package for actual-input validation")
        original_open, original_popen = Path.open, subprocess.Popen

        def no_sparse(path, *args, **kwargs):
            self.assertNotIn("sparse", path.name.lower(), "RAM-only assembly must not open sparse media")
            return original_open(path, *args, **kwargs)

        def only_openssl(command, *args, **kwargs):
            self.assertIn(Path(command[0]).name.lower(), ("openssl", "openssl.exe"), "No device or other external executable")
            return original_popen(command, *args, **kwargs)

        with mock.patch.object(Path, "open", no_sparse), mock.patch.object(subprocess, "Popen", only_openssl):
            plan = a.assemble(REAL)
        self.assertEqual(plan["status"], "ready_to_assemble")
        self.assertFalse(plan["userdata_media_opened"])
        self.assertFalse(plan["device_operations"])
        self.assertFalse(REAL.output.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--real-result", type=Path)
    parser.add_argument("--installed-package", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--openssl", type=Path)
    args, remaining = parser.parse_known_args()
    if args.real_result:
        if not (args.installed_package and args.output):
            parser.error("Supply --installed-package and a fresh --output")
        REAL = SimpleNamespace(result=args.real_result, installed_package=args.installed_package,
                               output=args.output, openssl=args.openssl, policies=None, assemble=False)
    unittest.main(argv=[__file__, *remaining])
