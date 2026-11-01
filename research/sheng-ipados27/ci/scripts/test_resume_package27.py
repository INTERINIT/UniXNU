"""Offline restore boundaries and phase reporting; no Actions are contacted."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


spec = importlib.util.spec_from_file_location("resume27_tested", Path(__file__).with_name("resume_package27.py"))
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


class ResumeTests(unittest.TestCase):
    def test_upstream_phase_flow_restores_only_data_and_builds_code_fresh(self):
        # This controls routing only; it cannot qualify synthetic seed bytes.
        cloud_spec = importlib.util.spec_from_file_location("upstream_cloud_control", Path(__file__).with_name("cloud27.py"))
        cloud_code = importlib.util.module_from_spec(cloud_spec)
        cloud_spec.loader.exec_module(cloud_code)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "work27/reuse-41173083070/result27"
            source.mkdir(parents=True)
            for name in resume.DATA_FILES:
                (source / name).write_bytes(("routing fixture: " + name).encode())
            (source / "gpu27.gpuaddon").write_bytes(b"old GPU must not be copied")
            (source / "firmware-stage27.json").write_bytes(b"old FD receipt must not be copied")
            main, device, output = root / "UniXNU", root / "UniXNU-sheng", root / "result27"
            profile = main / "profiles/os/ipados-27.0.1-24A446/profile.toml"
            profile.parent.mkdir(parents=True)
            profile.write_text('[os]\nname="ipados-27.0.1-24A446"\n')
            output.mkdir()
            ctx = SimpleNamespace(tree=root / "tree", work=root / "target")
            seed = {"packed_sha256": "routing-only", "volume_uuid": "12345678-1234-5678-ABCD-123456789ABC"}
            calls = []

            def checked_data(*arguments):
                calls.append("check_data")
                self.assertEqual(arguments[0], source)
                self.assertEqual(arguments[1], ctx.tree / "build/verified-root-24A446")
                return seed, {}

            def forbidden(*arguments):
                self.fail("Full legacy GPU/FD reuse must not run in the upstream stage")

            def data_reuse(actual):
                calls.append("data")
                for name in resume.DATA_FILES:
                    self.assertEqual((ctx.work / "data-seed" / name).read_bytes(), (source / name).read_bytes())
                return dict(seed)

            helpers = {
                "reuse_artifacts27": SimpleNamespace(PROFILE="ipados-27.0.1-24A446", check_data=checked_data,
                    member=lambda base, name: base / name, verify=forbidden, check_firmware=forbidden),
                "data_stage27": object(),
                "target27": SimpleNamespace(gpu=lambda *args: calls.append("gpu")),
                "firmware_stage27": SimpleNamespace(run=lambda *args, **kwargs: calls.append("firmware")),
                "payload_stage27": SimpleNamespace(run=lambda *args, **kwargs: calls.append("payload")),
            }
            cloud = SimpleNamespace(WORK=root / "work27", MAIN=main, DEVICE=device, ROOT=root, RESULT=output,
                PINS=cloud_code.PINS, helper=helpers.__getitem__, context=lambda: ctx,
                restore_policies=lambda actual: calls.append("policies"), data=data_reuse,
                native=lambda *args, **kwargs: calls.append("native"), sha=cloud_code.sha,
                package_phases=cloud_code.package_phases)
            report = resume.run_upstream(cloud, ctx)
            self.assertEqual(calls, ["policies", "check_data", "data", "native", "gpu", "firmware", "payload"])
            self.assertEqual(report["status"], "host_verified")
            self.assertTrue(report["phases"]["data"]["reused"])
            self.assertFalse(report["phases"]["data"]["fresh_build"])
            for name in ("native", "gpu", "firmware", "payload"):
                self.assertFalse(report["phases"][name]["reused"])
                self.assertTrue(report["phases"][name]["fresh_build"])
            self.assertFalse((output / "gpu27.gpuaddon").exists())
            self.assertFalse((output / "firmware-stage27.json").exists())
            self.assertEqual(json.loads((output / "package-phases27.json").read_text()), report)

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
