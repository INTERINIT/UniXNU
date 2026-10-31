"""Offline restore boundaries and phase reporting; no Actions are contacted."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("resume27_tested", Path(__file__).with_name("resume_package27.py"))
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


class ResumeTests(unittest.TestCase):
    def test_restore_selection_preserves_current_preparation_and_native(self):
        names = ["prepare.json", "host-preflight27.json", "package-phases27.json", "kernel.macho",
                 "gpu27.gpuaddon", "gpu27-stage-status.json", "owner-trust27.bundle", "firmware-stage27.json", "firmware/SILICIUM_UEFI.fd"]
        actual = resume.selected_artifacts({"files": {"package/" + name: {} for name in names}})
        self.assertEqual(set(actual), set(names[4:]))

    def test_conflicting_copy_is_preserved_and_source_mutation_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "source", root / "target"
            source.write_bytes(b"passed artifact")
            sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            expected = {"bytes": source.stat().st_size, "sha256": sha(source)}
            resume.copy_checked(source, target, expected, sha)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            target.write_bytes(b"preserve conflicting result")
            with self.assertRaisesRegex(ValueError, "Preserve a conflicting"):
                resume.copy_checked(source, target, expected, sha)
            self.assertEqual(target.read_bytes(), b"preserve conflicting result")
            source.write_bytes(b"changed capture")
            with self.assertRaisesRegex(ValueError, "changed before restore"):
                resume.copy_checked(source, target, expected, sha)

    def test_failed_native_never_becomes_a_passed_package(self):
        report = {"status": "failed", "phases": {name: {"status": status} for name, status in
                  (("data", "passed"), ("gpu", "passed"), ("firmware", "passed"), ("native", "failed"), ("payload", "blocked"))}}
        resume.mark_reuse(report, True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["phases"]["native"]["status"], "failed")
        self.assertTrue(report["phases"]["data"]["reused"])
        self.assertFalse(report["phases"]["firmware"]["fresh_build"])
        self.assertEqual(report["phases"]["gpu"]["source_run"], 41173083070)


if __name__ == "__main__":
    unittest.main()
