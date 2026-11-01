"""Offline native dependency and comparison-recipe checks; never compiles XNU."""
import importlib.util
import ast
import copy
import json
import os
from pathlib import Path
import shlex
import sys
import subprocess
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest import mock

MAIN = Path(__file__).resolve().parents[3]
RESEARCH = Path(__file__).resolve().parents[1]
DEVICE = MAIN.parent / "UniXNU-sheng"
sys.path.insert(0, str(MAIN / "scripts"))
spec = importlib.util.spec_from_file_location("reviewed_target27", RESEARCH / "ci/scripts/target27.py")
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)


def actual_plan():
    from unixnu.cli import parser
    from unixnu.config import Context
    from unixnu import feeds, kernel
    args = parser().parse_args(["status", "-D", str(DEVICE), "--out", str(MAIN / "out"),
                                "--os", "ipados-27.0.1-24A446"])
    ctx = Context(args)
    modules = feeds.resolve(ctx)
    original = kernel.archive_plan(ctx)
    ctx.component_specs, ctx.board["kernel"]["archives"] = target.bootstrap_recipe(ctx)
    bootstrap = kernel.archive_plan(ctx)
    display_tree = ctx.tree
    return ctx, modules, original, bootstrap, display_tree


class NativeRecipeTests(unittest.TestCase):
    def test_bootstrap_overrides_survive_actual_context_reread_and_restore(self):
        from unixnu import kernel
        from unixnu.config import Context, parse_config
        adapter = target.storage_adapter()
        identity = "94143051-A2CC-4A69-A7AC-A35798CB9782"
        original = ("# Keep original comments and line endings\r\n"
                    "CONFIG_XNU_NATIVE_LEGACY_DISPLAY=y\r\n"
                    "CONFIG_XNU_NATIVE_ADRENO=y\r\n"
                    "CONFIG_XNU_BUILD_ARCHIVES=y\r\n"
                    f'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="{identity}"\r\n').encode()
        for fail in (False, True):
            with self.subTest(build_fails=fail), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                ctx = Context.__new__(Context)
                ctx.tree = root / "tree"
                ctx.tree.mkdir()
                ctx.config_path = root / ".config"
                ctx.config_path.write_bytes(original)
                ctx.config = parse_config(original.decode())
                specs, recipe = ["normal specs"], ["normal recipe"]
                ctx.component_specs = specs
                ctx.board = {"kernel": {"archives": recipe, "prelink": {}}}
                output = root / "result"
                output.mkdir()

                def build(context, modules):
                    # The real xnu_env calls the new Context.need_config again.
                    for _ in range(2):
                        env = kernel.xnu_env(context)
                        for key in ("XNU_NATIVE_LEGACY_DISPLAY", "XNU_NATIVE_ADRENO", "XNU_BOOT_PROGRESS"):
                            self.assertEqual(env[key], "0")
                        self.assertEqual(env["XNU_OWNER_DATA_VOLUME_UUID"], identity)
                    self.assertEqual(os.environ[adapter.BOOTSTRAP_ENV], "1")
                    if fail:
                        raise RuntimeError("simulated native build failure")
                    native = context.tree / target.NATIVE_KERNEL
                    native.parent.mkdir(parents=True)
                    native.write_bytes(b"offline native output")

                wrapped = SimpleNamespace(apply=mock.Mock(), export_bootstrap_mode=adapter.export_bootstrap_mode,
                                          verify_archive_sources=mock.Mock(return_value={"bootstrap": True}))
                with mock.patch.object(target, "storage_adapter", return_value=wrapped), \
                        mock.patch.object(target, "bootstrap_recipe", return_value=(["bootstrap specs"], ["bootstrap recipe"])), \
                        mock.patch.object(kernel, "build", side_effect=build), \
                        mock.patch.dict(os.environ, {adapter.BOOTSTRAP_ENV: "0"}):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "simulated native"):
                            target.native_bootstrap(ctx, [], output)
                    else:
                        target.native_bootstrap(ctx, [], output)
                        self.assertEqual((output / "native-bootstrap.macho").read_bytes(), b"offline native output")
                    self.assertEqual(os.environ[adapter.BOOTSTRAP_ENV], "0")
                self.assertEqual(ctx.config_path.read_bytes(), original)
                self.assertEqual(ctx.need_config(), parse_config(original.decode()))
                self.assertEqual(ctx.config["XNU_OWNER_DATA_VOLUME_UUID"], identity)
                self.assertIs(ctx.component_specs, specs)
                self.assertIs(ctx.board["kernel"]["archives"], recipe)

    def test_new_board_keeps_existing_owner_policies_and_data_uuid(self):
        board = tomllib.loads((DEVICE / "board.toml").read_text(encoding="utf-8"))
        original = copy.deepcopy(board["kernel"]["archives"])
        config = {"XNU_OWNER_DATA_VOLUME_UUID": "12345678-1234-5678-ABCD-123456789ABC"}
        ctx = SimpleNamespace(tree=Path("uncreated research tree"), board=board, config=config)
        target.owner_policy_archives(ctx)
        storage = [shlex.split(item) for item in board["kernel"]["archives"]
                   if shlex.split(item)[0] == "build-sheng-source-storage.py"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0], ["build-sheng-source-storage.py", "--policy-dir",
                                     str(ctx.tree / "build/verified-root-24A446")])
        other = lambda values: [item for item in values if shlex.split(item)[0] != "build-sheng-source-storage.py"]
        self.assertEqual(other(original), other(board["kernel"]["archives"]))
        self.assertIs(ctx.config, config)
        self.assertEqual(config["XNU_OWNER_DATA_VOLUME_UUID"], "12345678-1234-5678-ABCD-123456789ABC")
        once = list(board["kernel"]["archives"])
        target.owner_policy_archives(ctx)
        self.assertEqual(board["kernel"]["archives"], once)

    def test_actual_catalog_full_and_bootstrap_dependency_plans(self):
        ctx, modules, full, bootstrap, tree = actual_plan()
        profile = MAIN / "profiles/os/ipados-27.0.1-24A446/profile.toml"
        original_profile = profile.read_bytes()
        reference_arguments = list(ctx.board["kernel"]["prelink"]["extra_args"])
        sealed = target.select_sealed_native_kernel(ctx)
        self.assertEqual(sealed, tree / target.NATIVE_KERNEL)
        self.assertEqual(ctx.board["kernel"]["prelink"]["kernel"], target.NATIVE_KERNEL)
        self.assertTrue(str(sealed).endswith("mach.development.bcm2837.unstripped"))
        self.assertEqual(ctx.board["kernel"]["prelink"]["extra_args"], reference_arguments)
        self.assertIn("build/xnu/fileset-reference/mach.release.bcm2837.unstripped.noctf", reference_arguments)
        self.assertEqual(profile.read_bytes(), original_profile)
        names = [item["id"] for kind, item in bootstrap if kind == "component"]
        self.assertEqual(names, ["ArmDTPlatform", "ArmCpu", "VirtioMmioBlock", "ShengUfs", "RamBlock"])
        self.assertNotIn("Adreno740", names)
        self.assertTrue(any(kind == "script" and item == "build-gop-legacy-display-27.py" for kind, item in full))
        self.assertEqual(modules[("refer", "IOHIDFamily")].source["commit"], "e31e90a24c27ad6cbe981650d12a1a4124065b03")
        self.assertEqual(modules[("refer", "xnu")].source["commit"], "ac9718fb1af618d5ce8678d0dc6e8a58f252216f")
        from unixnu import kernel
        environment = kernel.version_env(modules, ctx)
        self.assertEqual(environment["UNIXNU_XNU_ARCH"], "arm64e")
        self.assertEqual(environment["UNIXNU_IOS_VERSION"], "27.0")
        self.assertEqual(environment["UNIXNU_LIBPTHREAD_COMMIT"], "1f4f5265b319111142f1bf3a27d4484ef5a98314")
        self.assertEqual(environment["UNIXNU_IPSW_BUILD"], "24A446")
        self.assertEqual(tree.parents[4], MAIN)
        self.assertEqual(tree.parents[5] / "UniXNU-sheng", DEVICE)
        self.assertEqual(tree.parents[3] / "driver-sources/IOHIDFamily", MAIN / "out/driver-sources/IOHIDFamily")

    def test_reference_rewrite_and_cache_identity_follow_actual_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree, output = root / "tree", root / "result"
            source = tree / ".cache/xnu-work"
            source.mkdir(parents=True)
            output.mkdir()
            (source / "test-source.c").write_text("int version = 1;\n")
            ctx = SimpleNamespace(tree=tree)
            local, first, receipt = target.prepare_reference_builder(MAIN, ctx, output)
            text = local.read_text()
            compile(text, str(local), "exec")
            self.assertEqual(receipt["upstream_builder_sha256"], target.sha(MAIN / "scripts/build-fileset-release-reference.py"))
            self.assertIn("-miphoneos-version-min=27.0", text)
            self.assertIn("-Wl,-ios_version_min,27.0", text)
            self.assertNotIn("version-min=26.0", text)
            self.assertNotIn("-ios_version_min,26.0", text)
            self.assertNotIn("root = repo /", text)
            self.assertIn("extern int      proc_pid(struct proc *p);", text)
            self.assertNotIn("#include <sys/proc.h>", text)
            self.assertLess(text.index("exception.write_text"), text.index("    manifest ="))
            self.assertTrue(first.is_relative_to(tree / "build/xnu/fileset-reference"))
            self.assertEqual(first, target.prepare_reference_builder(MAIN, ctx, output)[1])
            (source / ".git").mkdir()
            (source / ".git/config").write_text("not a source input\n")
            self.assertEqual(first, target.prepare_reference_builder(MAIN, ctx, output)[1])
            (source / "test-source.c").write_text("int version = 2;\n")
            self.assertNotEqual(first, target.prepare_reference_builder(MAIN, ctx, output)[1])
            (source / "restored-header.h").write_text("#define RESTORED 1\n")
            self.assertEqual(target.source_identity(source)[1], 2)

    def test_reference_declaration_keeps_diagnostics_and_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "tree/.cache/xnu-work", root / "result"
            source.mkdir(parents=True)
            output.mkdir()
            fixture = '#ifdef MACH_BSD\nextern int      proc_selfpid(void);\nextern char *proc_name_address(struct proc *p);\n#endif\n/* proc_pid(get_bsdtask_info(task)) remains in the real diagnostic body */\n'
            exception = source / "osfmk/kern/exception.c"
            exception.parent.mkdir(parents=True)
            exception.write_text(fixture, encoding="utf-8")
            patch_text = (DEVICE / "patches/xnu-12377/source-storage-runtime.patch").read_text(encoding="utf-8")
            hook = "".join(line[1:] + "\n" for line in patch_text.splitlines() if line.startswith("+") and not line.startswith("+++"))
            storage = source / "bsd/kern/bsd_init.c"
            storage.parent.mkdir(parents=True)
            storage.write_text("\tvfsinit();\n" + hook, encoding="utf-8")
            spec = importlib.util.spec_from_file_location("reference_exports_test", RESEARCH / "ci/scripts/reference_exports27.py")
            exports = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(exports)
            for name, symbols in exports.UNAVAILABLE_EXPORTS.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("_retained_export\n" + "\n".join(symbols) + "\n", encoding="utf-8")
            local, _, _ = target.prepare_reference_builder(MAIN, SimpleNamespace(tree=root / "tree"), output)
            snapshot = next(node for node in ast.parse(local.read_text()).body if isinstance(node, ast.If))
            start = next(i for i, node in enumerate(snapshot.body) if isinstance(node, ast.Assign)
                         and any(isinstance(name, ast.Name) and name.id == "exception" for name in node.targets))
            end = next(i for i, node in enumerate(snapshot.body) if isinstance(node, ast.Assign)
                       and any(isinstance(name, ast.Name) and name.id == "manifest" for name in node.targets))
            code = compile(ast.Module(body=snapshot.body[start:end], type_ignores=[]), str(local), "exec")
            namespace = {"source": source, "output": output, "sys": sys, "subprocess": subprocess}
            exec(code, namespace)
            result = exception.read_text(encoding="utf-8")
            added = 'extern int      proc_pid(struct proc *p);\n'
            self.assertEqual(result.replace(added, ""), fixture)
            self.assertEqual(storage.read_text(encoding="utf-8"), "\tvfsinit();\n#if defined(XNU_SOURCE_STORAGE) && XNU_SOURCE_STORAGE\n" + hook + "#endif\n")
            for name in exports.UNAVAILABLE_EXPORTS:
                self.assertEqual((source / name).read_text(encoding="utf-8"), "_retained_export\n")
            with self.assertRaisesRegex(ValueError, "Review changed"):
                exec(code, namespace)

    def test_empty_reference_source_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "empty"):
                target.source_identity(Path(temporary))


if __name__ == "__main__":
    unittest.main()
