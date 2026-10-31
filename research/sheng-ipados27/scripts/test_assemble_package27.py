"""Host-only assembler refusal/metadata controls; never publishes a fake package.

Optional real inputs exercise OpenSSL and one complete read-only sparse pass.
No test invokes the assembler success/publication path or a device executable.
"""

import argparse
import contextlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("assemble_package27.py")
SPEC = importlib.util.spec_from_file_location("assembler27_tests", SOURCE)
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)
REAL = None
REAL_RESULT = None
ORIGINAL_RUN = subprocess.run
ORIGINAL_POPEN = subprocess.Popen


class AssembleControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="assemble27-controls-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("run", "Popen", "check_output"):
            self.stack.enter_context(mock.patch.object(subprocess, name, side_effect=AssertionError("No external command is allowed")))

    def test_missing_actual_boot_cannot_publish_assembled_status(self):
        output = self.root / "must-remain-absent"
        args = SimpleNamespace(target_serial="OFFLINE-FIXTURE", boot=self.root / "no-boot.img",
                               boot_report=self.root / "no-boot.json", userdata=self.root / "no-sparse.img",
                               userdata_report=self.root / "no-sparse.json", boot_policies=self.root / "no-bundle.bin",
                               policies=self.root / "no-policies", output=output, assemble=True)
        with mock.patch.object(a, "helper", side_effect=AssertionError("Missing boot must stop before importing builders")):
            with self.assertRaises(ValueError):
                a.assemble(args)
        self.assertFalse(output.exists())

    def test_pending_boot_receipt_is_refused_before_image_use(self):
        image, receipt = self.root / "not-a-real-boot", self.root / "pending.json"
        image.write_bytes(b"not a deployable input")
        receipt.write_text(json.dumps({"status": "pending"}))
        with self.assertRaises(ValueError):
            a.verify_boot(image, receipt, "a" * 64, "b" * 64, None)

    def test_unverified_original_sparse_report_is_refused(self):
        report = self.root / "unverified.json"
        report.write_text(json.dumps({"build": "24A446", "device": "sheng", "all_local_raw_blocks_verified": False}))
        with self.assertRaises(ValueError):
            a.verify_sparse(self.root / "absent.img", report, None, {}, None)

    def test_two_exact_544_byte_header_bundle_and_negative_controls(self):
        # Bounded metadata fixtures only, never accepted as authenticated OS policies.
        policies = {"OS": SimpleNamespace(blob=b"A" * 544 + b"table1"),
                    "SystemOS": SimpleNamespace(blob=b"B" * 544 + b"table2")}
        body = struct.pack("<8sQQQ", b"VROOTB01", 1, 2, 1152)
        body += struct.pack("<4Q", 64, 544, 608, 544) + b"A" * 544 + b"B" * 544
        path = self.root / "metadata-fixture.bin"
        path.write_bytes(body)
        self.assertEqual(a.boot_bundle(path, policies), a.sha(path))
        variants = [body[:-1], body + b"X", body[:64] + b"Z" + body[65:]]
        changed = bytearray(body)
        struct.pack_into("<Q", changed, 32, 65)
        variants.append(bytes(changed))
        for raw in variants:
            path.write_bytes(raw)
            with self.subTest(case=raw[:40]), self.assertRaises(ValueError):
                a.boot_bundle(path, policies)

    def test_same_volume_hardlink_preserves_source_and_conflicts(self):
        source, target = self.root / "source", self.root / "linked"
        source.write_bytes(b"own small host fixture")
        original = source.read_bytes()
        self.assertEqual(a.link_or_copy(source, target, large=True), "hardlink")
        self.assertTrue(source.samefile(target))
        with self.assertRaises(ValueError):
            a.link_or_copy(source, target, large=True)
        self.assertEqual(source.read_bytes(), original)

    def test_launchers_only_select_guard_modes_and_default_check(self):
        for mode in ("check", "install", "boot"):
            text = a.launcher(mode)
            self.assertIn("flash27.py\" " + mode + " --package", text)
            self.assertNotIn("fastboot", text.lower())
            self.assertNotIn("adb", text.lower())
        self.assertNotIn(" install ", a.launcher("check"))
        self.assertNotIn(" boot ", a.launcher("check"))
        with self.assertRaises(ValueError):
            a.launcher("userdata & anything")

    def test_optional_real_RSA_policy_and_complete_sparse_check(self):
        global REAL_RESULT
        if REAL is None:
            self.skipTest("No actual sparse/policy inputs supplied")

        def only_real_openssl(command, **kwargs):
            self.assertIn(Path(command[0]).name.lower(), ("openssl", "openssl.exe"))
            self.assertEqual(list(map(str, command[1:3])), ["dgst", "-sha256"])
            return ORIGINAL_RUN(command, **kwargs)

        def only_openssl_process(command, *args, **kwargs):
            self.assertIn(Path(command[0]).name.lower(), ("openssl", "openssl.exe"))
            return ORIGINAL_POPEN(command, *args, **kwargs)

        with mock.patch.object(subprocess, "run", side_effect=only_real_openssl), mock.patch.object(subprocess, "Popen", side_effect=only_openssl_process):
            builder, flash = a.helper("build_userdata27_windows"), a.helper("flash27")
            executable = builder.openssl_path(REAL.openssl)
            policies = a.full_policies(builder, REAL.real_policies, executable)
            report, actual, _ = a.verify_sparse(REAL.real_userdata, REAL.real_report, builder, policies, flash)
        self.assertEqual(actual["sha256"], report["sparse_sha256"])
        self.assertEqual(set(actual["actual_sparse_ranges_hash_verified"]), {"OS", "SystemOS", "OS.vroot", "SystemOS.vroot"})
        REAL_RESULT = {"actual_complete_sparse_SHA256": actual["sha256"], "actual_RSA_policy_envelopes_checked": 2,
                       "actual_window_and_table_ranges_checked": actual["actual_sparse_ranges_hash_verified"]}


def main():
    global REAL
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--real-userdata", type=Path)
    parser.add_argument("--real-report", type=Path)
    parser.add_argument("--real-policies", type=Path)
    parser.add_argument("--openssl", type=Path)
    args = parser.parse_args()
    require_all = (args.real_userdata, args.real_report, args.real_policies)
    if any(require_all):
        a.require(all(require_all), "Supply all three real sparse/report/policy inputs")
        REAL = args
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AssembleControls))
    print(json.dumps({"tests_run": result.testsRun, "passed": result.wasSuccessful(), "skipped": len(result.skipped),
                      "real_input_checks": REAL_RESULT, "assembled_package_published": False,
                      "device_operations": False, "hardware_tested": False}, indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
