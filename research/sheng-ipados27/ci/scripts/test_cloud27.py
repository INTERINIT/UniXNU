"""Offline control-flow checks for one combined host workflow, no build tools."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("cloud27_offline", Path(__file__).with_name("cloud27.py"))
cloud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cloud)


class CombinedRunTests(unittest.TestCase):
    def execute(self, failures):
        calls = []

        def action(name):
            def run():
                calls.append(name)
                if name in failures:
                    raise RuntimeError("offline control failure: " + name)
            return run

        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}):
            output = Path(temporary)
            report = cloud.package_phases({name: action(name) for name in ("data", "native", "gpu", "firmware", "payload")}, output)
            self.assertEqual(json.loads((output / "package-phases27.json").read_text()), report)
            for name in failures:
                if name in calls:
                    self.assertIn("RuntimeError", (output / ("package-" + name + "-failure.log")).read_text())
        return calls, report

    def test_data_failure_still_collects_gpu_and_firmware(self):
        calls, report = self.execute({"data"})
        self.assertEqual(calls, ["data", "gpu", "firmware"])
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["phases"]["native"]["dependencies"], ["data"])
        self.assertEqual(report["phases"]["payload"]["status"], "blocked")

    def test_each_independent_failure_blocks_payload_without_masking_others(self):
        for failed in ("native", "gpu", "firmware"):
            with self.subTest(failed=failed):
                calls, report = self.execute({failed})
                self.assertEqual(calls, ["data", "native", "gpu", "firmware"])
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["phases"][failed]["status"], "failed")
                self.assertEqual(report["phases"]["payload"]["dependencies"], [failed])

    def test_payload_runs_only_after_all_prerequisites_pass(self):
        calls, report = self.execute(set())
        self.assertEqual(calls, ["data", "native", "gpu", "firmware", "payload"])
        self.assertEqual(report["status"], "host_verified")
        self.assertFalse(report["hardware_tested"])
        self.assertFalse(report["device_operations"])
        _, failed = self.execute({"payload"})
        self.assertEqual(failed["status"], "failed")

    def test_interruption_never_starts_more_phases(self):
        def interrupted():
            raise KeyboardInterrupt()

        def forbidden():
            self.fail("Interruption started another phase")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(KeyboardInterrupt):
                cloud.package_phases({"data": interrupted, "gpu": forbidden}, Path(temporary))


if __name__ == "__main__":
    unittest.main()
