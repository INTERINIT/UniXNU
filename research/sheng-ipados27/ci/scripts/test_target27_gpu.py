"""Host regressions for the bounded iOS17-fixture/27-replay separation.

These tests do not execute Darwin code or qualify GPU hardware.
"""
import ast
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("target27_gpu_tested", SCRIPTS / "target27.py")
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
SOURCE = SCRIPTS.parents[3] / "scripts/check-turnip-darwin-host.py"
MAIN = SCRIPTS.parents[3]
DEVICE = MAIN.parent / "UniXNU-sheng"


def actual_parser(path):
    source = ast.parse(path.read_text(encoding="utf-8"))
    statements = []
    for node in source.body:
        if isinstance(node, ast.Assign) and any(isinstance(item, ast.Name) and item.id == "parser" for item in node.targets):
            statements.append(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute):
            owner = node.value.func.value
            if isinstance(owner, ast.Name) and owner.id == "parser" and node.value.func.attr == "add_argument":
                statements.append(node)
    namespace = {"argparse": argparse, "Path": Path, "__doc__": "Actual source CLI contract"}
    exec(compile(ast.Module(body=statements, type_ignores=[]), str(path), "exec"), namespace)
    return namespace["parser"]


class ReplayScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tree, self.output = self.root / "tree", self.root / "result"
        (self.tree / "scripts").mkdir(parents=True)
        self.output.mkdir()
        shutil.copy2(SOURCE, self.tree / "scripts/check-turnip-darwin-host.py")

    def test_all_other_check_statements_preserved(self):
        original = ast.parse(SOURCE.read_text(encoding="utf-8"))
        local = target.prepare_gpu_host_check(self.tree, self.output)
        derived = ast.parse(local.read_text(encoding="utf-8"))
        # Compare the entire program's AST after removing only the root-path
        # relocation and the one explicitly unqualified original-input check.
        def without_scope_statements(program):
            result = []
            for node in program.body:
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "ROOT" for t in node.targets):
                    continue
                code = ast.unparse(node)
                if isinstance(node, ast.With) and "prefix='quartzcore-driver-cache-'" in code:
                    continue
                if isinstance(node, ast.Expr) and code.startswith("print('NOT RUN: original iOS17 QuartzCore"):
                    continue
                result.append(ast.dump(node, include_attributes=False))
            return result
        self.assertEqual(without_scope_statements(original), without_scope_statements(derived))
        text = local.read_text(encoding="utf-8")
        self.assertIn("check-priming-cache-host.py", text)
        self.assertIn("HOSTSIM_STALL='17'", text)
        self.assertIn("24A446 UI AIR cache is not qualified", text)

    def test_changed_upstream_suite_refused(self):
        source = self.tree / "scripts/check-turnip-darwin-host.py"
        source.write_text(source.read_text(encoding="utf-8") + "\n# unreviewed change\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Host Turnip check changed"):
            target.prepare_gpu_host_check(self.tree, self.output)
        self.assertFalse((self.output / "check-turnip-host27-local.py").exists())

    def test_failed_suite_never_creates_pass_report_even_with_cached_smoke(self):
        host = self.tree / "build/turnip-darwin-host"
        host.mkdir(parents=True)
        (host / "plugin_smoke").write_bytes(b"left by earlier failed aggregate")
        (host / "plugin_watchdog.log").write_text("actual failing stall stdout/stderr")
        (self.output / "gpu27-host-checks.json").write_text('{"passed": ["stale run"]}')
        with patch.object(target, "run", side_effect=subprocess.CalledProcessError(1, "host-check")) as call:
            with self.assertRaises(subprocess.CalledProcessError):
                target.gpu_host_check(self.tree, self.output, {})
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.args[0][1], self.output / "check-turnip-host27-local.py")
        self.assertFalse((self.output / "gpu27-host-checks.json").exists())
        self.assertEqual((self.output / "host-turnip-plugin_watchdog.log").read_text(), "actual failing stall stdout/stderr")
        self.assertEqual(json.loads((self.output / "gpu27-host-check-failure.json").read_text())["status"], "failed")

    def test_failed_child_stdout_and_stderr_preserved(self):
        log = self.output / "failing-child.log"
        with self.assertRaises(subprocess.CalledProcessError):
            target.run([sys.executable, "-c", "import sys; print('real stdout'); print('real stderr', file=sys.stderr); sys.exit(9)"],
                       self.tree, log_path=log)
        self.assertIn("real stdout", log.read_text())
        self.assertIn("real stderr", log.read_text())

    def test_real_upstream_packers_can_replace_existing_results_safely(self):
        plugin = self.tree / "build/adreno-metal-plugin27"
        bundle = plugin / "NativeAdrenoMetal.bundle"
        bundle.mkdir(parents=True)
        # These are packing-contract bytes, not signed/qualified GPU programs.
        (bundle / "NativeAdrenoMetal").write_bytes(b"software packing fixture")
        (bundle / "libvulkan_freedreno.dylib").write_bytes(b"software Turnip fixture")
        (bundle / "Info.plist").write_bytes(b"packing fixture metadata")
        (plugin / "trust.json").write_text(json.dumps({"cdhash": "01" * 20, "turnip_cdhash": "02" * 20}))
        shutil.copy2(MAIN / "scripts/make-gpu-addon.py", self.tree / "scripts/make-gpu-addon.py")
        trust = self.root / "original-trust.bundle"
        import struct
        module = struct.pack("<I16sI", 2, bytes(16), 0)
        original = struct.pack("<III", 2, 12, 12 + len(module)) + module + module
        trust.write_bytes(original)
        (self.output / "gpu27.gpuaddon").write_bytes(b"earlier complete result")
        (self.output / "owner-trust27.bundle").write_bytes(b"earlier trust result")
        target.publish_gpu_artifacts(MAIN, self.tree, trust, self.output, os.environ)
        first = (self.output / "gpu27.gpuaddon").read_bytes()
        target.publish_gpu_artifacts(MAIN, self.tree, trust, self.output, os.environ)
        self.assertEqual((self.output / "gpu27.gpuaddon").read_bytes(), first)
        self.assertEqual(trust.read_bytes(), original)
        report = json.loads((self.output / "gpu27-artifacts.json").read_text())
        self.assertTrue(report["actual_packed_contents_equal_signed_bundle"])
        self.assertFalse(report["hardware_tested"])
        before = {name: (self.output / name).read_bytes() for name in ("gpu27.gpuaddon", "owner-trust27.bundle", "gpu27-trust.json")}
        with patch.object(target, "run", side_effect=subprocess.CalledProcessError(1, "packer")):
            with self.assertRaises(subprocess.CalledProcessError):
                target.publish_gpu_artifacts(MAIN, self.tree, trust, self.output, os.environ)
        self.assertEqual({name: (self.output / name).read_bytes() for name in before}, before)

    def test_actual_ios27_cli_and_rust_paths(self):
        for path in (MAIN / "scripts/build-turnip-darwin.py", MAIN / "scripts/build-adreno-metal-bridge.py"):
            self.assertEqual(actual_parser(path).parse_args(["--target", "ios27"]).target, "ios27")
        self.assertTrue(actual_parser(DEVICE / "scripts/build-adreno-compiler-host.py").parse_args(["--probe"]).probe)
        plugin = ast.parse((MAIN / "scripts/build-adreno-metal-plugin.py").read_text())
        namespace = {"sys": SimpleNamespace(argv=["build-adreno-metal-plugin.py", "--target", "ios27"]), "ROOT": self.tree}
        for node in plugin.body:
            if isinstance(node, ast.Assign) and any(isinstance(item, ast.Name) and item.id in
                                                   ("IOS27", "OUT", "TURNIP", "BRIDGE_TARGET") for item in node.targets):
                exec(compile(ast.Module(body=[node], type_ignores=[]), "actual-plugin-contract", "exec"), namespace)
        self.assertTrue(namespace["IOS27"])
        self.assertEqual(namespace["OUT"], self.tree / "build/adreno-metal-plugin27")
        self.assertEqual(namespace["TURNIP"], self.tree / "build/mesa-tu-ios27/src/freedreno/vulkan/libvulkan_freedreno.dylib")
        self.assertEqual(namespace["BRIDGE_TARGET"], "ios27")
        bridge = ast.parse((MAIN / "scripts/build-adreno-metal-bridge.py").read_text())
        namespace.update(args=SimpleNamespace(target="ios27"), os=SimpleNamespace(environ={}), runtime_id="fixture",
                         air=Path("runtime.air"), fc_air=Path("constant.air"), scanout_air=Path("scanout.air"))
        for node in bridge.body:
            if isinstance(node, ast.Assign) and any(isinstance(item, ast.Name) and item.id in ("triple", "cargo", "env") for item in node.targets):
                exec(compile(ast.Module(body=[node], type_ignores=[]), "actual-bridge-contract", "exec"), namespace)
            elif isinstance(node, ast.If) and ast.unparse(node.test) == "args.target == 'ios27'":
                exec(compile(ast.Module(body=[node], type_ignores=[]), "actual-bridge-contract", "exec"), namespace)
        self.assertEqual(namespace["triple"], "arm64e-apple-ios")
        self.assertEqual(namespace["cargo"], ["cargo", "+1.98.0", "-Z", "build-std=std,panic_unwind"])
        self.assertEqual(namespace["env"]["RUSTC_BOOTSTRAP"], "1")
        self.assertEqual(namespace["env"]["IPHONEOS_DEPLOYMENT_TARGET"], "27.0")


if __name__ == "__main__":
    unittest.main()
