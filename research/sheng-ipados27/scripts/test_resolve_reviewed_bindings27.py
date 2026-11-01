"""Read-only plan checks against actual archived27 kernels; no synthetic Mach-O."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("reviewed27_plan", SCRIPTS / "resolve_reviewed_bindings27.py")
resolver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolver)
ROOT = resolver.REPO.parents[1]
BASELINE = ROOT / "resources/run41186106830-public/result27/kernel.macho"
MAPPING = BASELINE.with_name("kernel.map.json")
CACHE = ROOT / "research/apple-small-inputs-24A446/kernelcache.decompressed"
FIX4 = ROOT / "diagnostics/metaclass-bindings-fix4/kernel-entry-probe.macho"
LEGACY = SCRIPTS.parent / "patches/prelink/diagnostic-bindings-41186106830.json"


@unittest.skipUnless(all(path.is_file() for path in (BASELINE, MAPPING, CACHE)), "Actual archived27 host inputs are unavailable")
class ReviewedPlanTests(unittest.TestCase):
    def test_actual_baseline_reproduces_prior58_and_only_reviewed_additions(self):
        before = BASELINE.stat()
        plan = resolver.resolve(BASELINE, MAPPING, CACHE)
        self.assertEqual(plan["summary"], {"bindings": 71, "already_correct": 0,
                                          "preserved_existing": 0, "unresolved": 0})
        by_site = {entry["site"]: entry for entry in plan["bindings"]}
        legacy = json.loads(LEGACY.read_text(encoding="utf-8"))
        self.assertEqual(plan["kernel_sha256"], legacy["kernel_sha256"])
        for old in legacy["bindings"]:
            new = by_site[old["site"]]
            self.assertEqual(new["native_symbol"], old["native_symbol"])
            self.assertEqual(int(new["expected_word"], 16), int(old["expected_word"], 16))
        for binding in plan["bindings"]:
            # Format8 stores only the target in low30 bits. Authentication,
            # diversity and the actual next-chain step must remain untouched.
            self.assertEqual((int(binding["expected_word"], 16) ^ int(binding["proposed_word"], 16)) & ~((1 << 30) - 1), 0)
        self.assertEqual(BASELINE.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(BASELINE.stat().st_size, before.st_size)
        self.assertFalse(plan["kernel_modified"])

    @unittest.skipUnless(FIX4.is_file(), "Actual fix4 diagnostic is unavailable")
    def test_actual_fix4_keeps_existing58_and_plans_only13_gaps(self):
        plan = resolver.resolve(FIX4, MAPPING, CACHE)
        self.assertEqual(plan["summary"], {"bindings": 13, "already_correct": 58,
                                          "preserved_existing": 0, "unresolved": 0})
        legacy = json.loads(LEGACY.read_text(encoding="utf-8"))
        self.assertEqual({entry["site"] for entry in plan["already_correct"]},
                         {entry["site"] for entry in legacy["bindings"]})
        names = {entry["native_symbol"] for entry in plan["bindings"]}
        self.assertIn("_throttle_lowpri_window", names)
        self.assertIn("_gIODTPHandleKey", names)
        self.assertNotIn("_PE_parse_boot_arg_str", names)

    def test_changed_apple_map_or_reviewed_function_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            altered = json.loads(MAPPING.read_text(encoding="utf-8"))
            altered["inputs"]["kernelcache_sha256"] = "0" * 64
            changed_map = root / "changed-map.json"
            changed_map.write_text(json.dumps(altered), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact Apple kernelcache"):
                resolver.resolve(BASELINE, changed_map, CACHE)
            fixture = json.loads(resolver.FIXTURE.read_text(encoding="utf-8"))
            fixture["functions"][-1]["original_sha256"] = "0" * 64
            changed_fixture = root / "changed-fixture.json"
            changed_fixture.write_text(json.dumps(fixture), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "original function bytes changed"):
                resolver.resolve(BASELINE, MAPPING, CACHE, changed_fixture)


if __name__ == "__main__":
    unittest.main()
