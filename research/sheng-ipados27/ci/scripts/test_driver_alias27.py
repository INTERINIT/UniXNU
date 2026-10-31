"""Three small host-only path controls; no driver compilation or device use."""
import importlib.util
from pathlib import Path
import tempfile
import tomllib
from types import SimpleNamespace
import unittest


SCRIPT = Path(__file__).with_name("driver_alias27.py")
spec = importlib.util.spec_from_file_location("tested_driver_alias27", SCRIPT)
alias_helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(alias_helper)


class DriverAliasControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="driver-alias27-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.main, self.device = self.base / "MAIN", self.base / "DEVICE"
        self.tree = self.main / "out/tree"
        self.a740, self.metal = self.main / "drivers/Adreno740", self.main / "drivers/AdrenoMetal"
        for directory in (self.device, self.tree / "drivers", self.a740, self.metal):
            directory.mkdir(parents=True)
        (self.a740 / "NativeAdrenoAccelerator.cpp").write_text('#include "../NativeMetal/OriginalAcceleratorABI.h"\n')
        self.header = b"original ABI path fixture; never compiled\n"
        (self.metal / "OriginalAcceleratorABI.h").write_bytes(self.header)
        try:
            (self.tree / "drivers/Adreno740").symlink_to(self.a740, target_is_directory=True)
            (self.tree / "drivers/AdrenoMetal").symlink_to(self.metal, target_is_directory=True)
            (self.tree / "drivers/NativeMetal").symlink_to(self.metal, target_is_directory=True)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("This Windows token cannot create symlinks")
            raise
        self.ctx = SimpleNamespace(root=self.main, device=self.device, tree=self.tree)
        self.physical = self.a740.parent / "NativeMetal"

    def test_official_alias_is_created_reused_and_reads_the_same_header(self):
        catalog = SCRIPT.parents[4] / "components.toml"
        metal = next(row for row in tomllib.loads(catalog.read_text(encoding="utf-8"))["component"]
                     if row["id"] == "AdrenoMetal")
        self.assertEqual(metal["legacy_name"], "NativeMetal")
        first = alias_helper.prepare(self.ctx, self.base / "receipt")
        self.assertEqual(first["action"], "created_symlink")
        self.assertTrue(self.physical.is_symlink())
        self.assertTrue((self.physical / "OriginalAcceleratorABI.h").samefile(self.metal / "OriginalAcceleratorABI.h"))
        self.assertEqual((self.physical / "OriginalAcceleratorABI.h").read_bytes(), self.header)
        self.assertEqual(alias_helper.prepare(self.ctx, self.base / "receipt")["action"], "reused")

    def test_existing_different_alias_is_not_overwritten(self):
        self.physical.mkdir()
        sentinel = self.physical / "keep"
        sentinel.write_bytes(b"preserve existing directory")
        with self.assertRaises(ValueError):
            alias_helper.prepare(self.ctx, self.base / "receipt")
        self.assertFalse(self.physical.is_symlink())
        self.assertEqual(sentinel.read_bytes(), b"preserve existing directory")

    def test_source_outside_main_and_device_cannot_create_an_alias(self):
        external = self.base / "outside/Adreno740"
        external.mkdir(parents=True)
        (external / "NativeAdrenoAccelerator.cpp").write_text("outside fixture")
        logical = self.tree / "drivers/Adreno740"
        logical.unlink()
        logical.symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            alias_helper.prepare(self.ctx, self.base / "receipt")
        self.assertFalse((external.parent / "NativeMetal").exists())
        self.assertFalse(self.physical.exists())


if __name__ == "__main__":
    unittest.main()
