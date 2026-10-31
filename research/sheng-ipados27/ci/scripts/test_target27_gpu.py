"""Host regressions for the bounded iOS17-fixture/27-replay separation.

These tests do not execute Darwin code or qualify GPU hardware.
"""
import ast
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("target27_gpu_tested", SCRIPTS / "target27.py")
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
SOURCE = SCRIPTS.parents[3] / "scripts/check-turnip-darwin-host.py"


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
        (self.output / "gpu27-host-checks.json").write_text('{"passed": ["stale run"]}')
        with patch.object(target, "run", side_effect=subprocess.CalledProcessError(1, "host-check")) as call:
            with self.assertRaises(subprocess.CalledProcessError):
                target.gpu_host_check(self.tree, self.output, {})
        self.assertEqual(call.call_count, 1)
        self.assertEqual(call.call_args.args[0][1], self.output / "check-turnip-host27-local.py")
        self.assertFalse((self.output / "gpu27-host-checks.json").exists())


if __name__ == "__main__":
    unittest.main()
