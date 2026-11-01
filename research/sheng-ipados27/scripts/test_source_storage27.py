"""Offline source-selection controls, with the actual pinned build recipe.

The recipe's source-list AST is evaluated without invoking compilers or creating
objects, archives, receipts or Mach-O files. Small outputs test only adaptation.
"""
import argparse
import ast
import copy
import importlib.util
import os
from pathlib import Path
import re
import tempfile
import sys
import unittest
from unittest.mock import patch


MAIN = Path(__file__).resolve().parents[3]
DEVICE = MAIN.parent / "UniXNU-sheng"
RESEARCH = Path(__file__).resolve().parents[1]
RECIPE = MAIN / "scripts/build-sheng-source-storage.py"
SPEC = importlib.util.spec_from_file_location("source_storage27_offline", RESEARCH / "ci/scripts/source_storage27.py")
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def selected_sources(text, *, bootstrap="0", legacy="1", adreno="1"):
    """Evaluate only the real recipe's nested resolver and source selection."""
    body = next(node.body for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == "main")
    resolver = next(node for node in body if isinstance(node, ast.FunctionDef) and node.name == "device_source")
    start = next(i for i, node in enumerate(body) if isinstance(node, ast.Assign)
                 and any(isinstance(name, ast.Name) and name.id == "sources" for name in node.targets))
    end = next(i for i, node in enumerate(body[start + 1:], start + 1) if isinstance(node, ast.Assign)
               and any(isinstance(name, ast.Tuple) and any(isinstance(part, ast.Name) and part.id == "objects" for part in name.elts)
                       for name in node.targets))
    # These are only names of the recipe's generated inputs. No file is emitted.
    generated = Path("UNCREATED-RECIPE-OUTPUT")
    namespace = {"os": os, "device": DEVICE, "tree": MAIN, "ROOT": MAIN,
                 "package_dirs": [DEVICE / "package"], "parser": argparse.ArgumentParser(),
                 "base": generated / "IOBlockStorageDevice.cpp", "boot_log_defaults": generated / "BootLogDefaults.c",
                 "anchor": generated / "RootAnchor.c", "flags": []}
    module = ast.Module(body=[resolver, *body[start:end]], type_ignores=[])
    with patch.dict(os.environ, {adapter.BOOTSTRAP_ENV: bootstrap, "UNIXNU_IOS_VERSION": "27.0",
                                 "XNU_NATIVE_LEGACY_DISPLAY": legacy, "XNU_NATIVE_ADRENO": adreno}):
        exec(compile(module, str(RECIPE), "exec"), namespace)
    return namespace["sources"], namespace["flags"]


class StorageBootstrapTests(unittest.TestCase):
    def test_normal_keeps_entire_original_source_selection(self):
        original = RECIPE.read_bytes()
        adapted = adapter.adapted_source(original)
        self.assertEqual(adapted.replace(adapter.NEW, adapter.OLD), original)
        self.assertEqual(selected_sources(original.decode()), selected_sources(adapted.decode()))
        self.assertEqual(sum(path.name == "BootDiagExport.c" for path in selected_sources(adapted.decode())[0]), 1)
        self.assertEqual(adapter.sha_bytes((DEVICE / "package/BootDiagExport.c").read_bytes()), adapter.DIAG_SHA256)

    def test_bootstrap_excludes_exactly_the_exporter(self):
        text = adapter.adapted_source(RECIPE.read_bytes()).decode()
        normal, normal_flags = selected_sources(text)
        bootstrap, bootstrap_flags = selected_sources(text, bootstrap="1", legacy="0", adreno="0")
        self.assertEqual(bootstrap, [path for path in normal if path.name != "BootDiagExport.c"])
        self.assertEqual(bootstrap_flags, normal_flags)
        self.assertTrue({"BootLog.c", "BootReset.c", "BootProcessProbe.c", "BootUiTraceProbe.c", "BootProcessWorker.c",
                         "BootWatchdogPolicy.c", "SourceStorage.cpp", "SourceRootPolicies.cpp", "SourceRootBinding.cpp",
                         "NativeUfs.cpp", "NativeRamBlock.cpp", "verified_root.c", "xnu_crypto.c"}
                        <= {path.name for path in bootstrap})

    def test_bad_or_nonbootstrap_flag_combinations_refused(self):
        text = adapter.adapted_source(RECIPE.read_bytes()).decode()
        for mode, legacy, adreno in (("bad", "0", "0"), ("1", "1", "0"), ("1", "0", "1")):
            with self.subTest(mode=mode, legacy=legacy, adreno=adreno), self.assertRaises(SystemExit):
                selected_sources(text, bootstrap=mode, legacy=legacy, adreno=adreno)

    def test_strict_source_and_idempotent_temporary_adaptation(self):
        original = RECIPE.read_bytes()
        with self.assertRaises(ValueError):
            adapter.adapted_source(original + b"\n")
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            (tree / "scripts").mkdir()
            path = tree / "scripts/build-sheng-source-storage.py"
            path.write_bytes(original)
            first = adapter.apply(tree)
            self.assertEqual(first, adapter.apply(tree))
            path.write_bytes(path.read_bytes().replace(b"sources = [base", b"sources = [anchor"))
            with self.assertRaises(ValueError):
                adapter.apply(tree)

    def test_environment_restored_even_when_build_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                with adapter.export_bootstrap_mode():
                    self.assertEqual(os.environ[adapter.BOOTSTRAP_ENV], "1")
                    raise RuntimeError("stop")
            self.assertNotIn(adapter.BOOTSTRAP_ENV, os.environ)
            adapter.require_normal_mode()
        with patch.dict(os.environ, {adapter.BOOTSTRAP_ENV: "0"}):
            with adapter.export_bootstrap_mode():
                with self.assertRaises(ValueError):
                    adapter.require_normal_mode()
            self.assertEqual(os.environ[adapter.BOOTSTRAP_ENV], "0")

    def test_existing_weak_diagnostic_interface_is_preserved(self):
        original = ast.parse(RECIPE.read_text())
        changed = ast.parse(adapter.adapted_source(RECIPE.read_bytes()).decode())
        weak = lambda module: next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "weak_defaults")
        self.assertEqual(ast.dump(weak(original)), ast.dump(weak(changed)))
        log = (DEVICE / "package/BootLog.c").read_text()
        for name in ("boot_diag_scan", "boot_diag_stream", "boot_diag_shot_tick"):
            self.assertRegex(log, r"extern[^\n]*\b" + name + r"\([^\n]*__attribute__\(\(weak_import\)\)")
        self.assertTrue(any(re.search(r'if\s*\([^\n]*&boot_diag_scan\s*&&\s*&boot_diag_stream', line)
                            for line in log.splitlines()), "Diagnostic calls retain both weak-import checks")

    def test_actual_catalog_and_target_restore_full_build_after_failure(self):
        # Failure injection checks the caller's finally block. It supplies no
        # pretend compile output and cannot pass as a successful native build.
        sys.path.insert(0, str(MAIN / "scripts"))
        from unixnu import feeds, kernel
        from unixnu.cli import parser
        from unixnu.config import Context, parse_config
        ctx = Context(parser().parse_args(["status", "-D", str(DEVICE), "--out", str(MAIN / "out"),
                                            "--os", "ipados-27.0.1-24A446"]))
        modules = feeds.resolve(ctx)
        ctx.config = parse_config((DEVICE / "configs/sheng_ipados27_defconfig").read_text())
        config = copy.deepcopy(ctx.config)
        specs, archives = ctx.component_specs, ctx.board["kernel"]["archives"]
        target_spec = importlib.util.spec_from_file_location("storage27_target_control", RESEARCH / "ci/scripts/target27.py")
        target = importlib.util.module_from_spec(target_spec)
        target_spec.loader.exec_module(target)

        def stop_bootstrap(actual_ctx, actual_modules):
            self.assertIs(actual_modules, modules)
            self.assertEqual(os.environ[adapter.BOOTSTRAP_ENV], "1")
            self.assertFalse(actual_ctx.config["XNU_NATIVE_LEGACY_DISPLAY"])
            self.assertFalse(actual_ctx.config["XNU_NATIVE_ADRENO"])
            self.assertTrue(actual_ctx.config["XNU_SOURCE_STORAGE"])
            self.assertTrue(actual_ctx.config["XNU_OWNER_DATA_MOUNT"])
            kernel.archive_plan(actual_ctx)
            raise RuntimeError("injected compile failure; no output")

        def stop_full(actual_ctx, actual_modules):
            adapter.require_normal_mode()
            self.assertTrue(actual_ctx.config["XNU_NATIVE_LEGACY_DISPLAY"])
            self.assertTrue(actual_ctx.config["XNU_NATIVE_ADRENO"])
            plan = kernel.archive_plan(actual_ctx)
            self.assertTrue(any(kind == "component" and item["id"] == "Adreno740" for kind, item in plan))
            self.assertIn(("script", "build-gop-legacy-display-27.py"), plan)
            raise RuntimeError("full compile not executed")

        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {}, clear=True):
            ctx.tree = Path(temporary)
            (ctx.tree / "scripts").mkdir()
            (ctx.tree / "scripts/build-sheng-source-storage.py").write_bytes(RECIPE.read_bytes())
            with patch.object(kernel, "build", side_effect=stop_bootstrap), self.assertRaisesRegex(RuntimeError, "injected compile failure"):
                target.native_bootstrap(ctx, modules, ctx.tree)
            self.assertEqual(ctx.config, config)
            self.assertIs(ctx.component_specs, specs)
            self.assertIs(ctx.board["kernel"]["archives"], archives)
            self.assertNotIn(adapter.BOOTSTRAP_ENV, os.environ)
            (ctx.tree / "kits/XnuPrelink/fixtures").mkdir(parents=True)
            with patch.object(kernel, "build", side_effect=stop_full), self.assertRaisesRegex(RuntimeError, "full compile not executed"):
                target.full_kernel(DEVICE, ctx, modules)
            self.assertFalse(any(ctx.tree.rglob("*.macho")))


if __name__ == "__main__":
    unittest.main()
