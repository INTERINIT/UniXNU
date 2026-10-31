"""Source-preservation controls; supply the exact pinned original header.

Usage: python test_gpu_watchdog27.py --source PATH/NativeTurnipSmoke.h
This is not a substitute for the real Mac C++/17-second stall controls.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("watchdog27_tested", Path(__file__).with_name("gpu_watchdog27.py"))
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)
ORIGINAL = None


class ClockPatchTests(unittest.TestCase):
    def test_actual_pinned_source_preserved_outside_exact_clock_changes(self):
        changed = watchdog.transform(ORIGINAL)
        self.assertEqual(watchdog.sha(ORIGINAL), watchdog.SOURCE_SHA256)
        self.assertEqual(watchdog.sha(changed), watchdog.PATCHED_SHA256)
        restored = changed.replace("#include <mach/mach_time.h>\n", "").replace(watchdog.CLOCK_SETUP, "").replace(
            watchdog.NEW_LOOP, watchdog.OLD_LOOP)
        self.assertEqual(restored, ORIGINAL)
        sampler = ORIGINAL[ORIGINAL.index("static void sample("):ORIGINAL.index("template <typename Marker, typename Reporter>")]
        self.assertIn(sampler, changed)
        with self.assertRaises(ValueError):
            watchdog.transform(ORIGINAL + "\n// independent edit\n")

    def test_apply_idempotence_and_independent_edit_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            component, output = root / "drivers/AdrenoMetal", root / "result"
            component.mkdir(parents=True)
            output.mkdir()
            source = component / "NativeTurnipSmoke.h"
            source.write_text(ORIGINAL, encoding="utf-8", newline="\n")
            responses = [watchdog.COMPONENT_PIN + "\n", ORIGINAL.encode()]
            with patch.object(watchdog.subprocess, "check_output", side_effect=responses * 2):
                first = watchdog.apply(root, output)
                second = watchdog.apply(root, output)
            self.assertEqual(first, second)
            self.assertEqual(watchdog.sha(source.read_text()), watchdog.PATCHED_SHA256)
            report = json.loads((output / "gpu27-watchdog-source.json").read_text())
            self.assertEqual(report["qualification_at_patch_application"], "not_run")
            self.assertTrue(report["original_sampler_unchanged"])
            source.write_text(source.read_text() + "\n// preserve this independent change\n")
            with patch.object(watchdog.subprocess, "check_output", side_effect=responses):
                with self.assertRaisesRegex(ValueError, "independently modified"):
                    watchdog.apply(root, output)

    def test_exact_shipping_loop_bodies_used_by_real_cpp_clock_control(self):
        fixture = watchdog.clock_fixture()
        self.assertEqual(fixture.count(watchdog.OLD_LOOP), 1)
        self.assertEqual(fixture.count(watchdog.NEW_LOOP), 1)
        self.assertIn("assert(samples == 0)", fixture)
        self.assertIn("firstSample >= 15000000000ull", fixture)
        # An independent elapsed-time oracle demonstrates the counter defect.
        def observed(wake, monotonic):
            now, tenths, next_checkpoint, samples = 0, 0, 0, []
            while now < 17000000000:
                now += wake
                due = now >= (15, 45, 90)[next_checkpoint] * 1000000000 if monotonic else tenths == (15, 45, 90)[next_checkpoint] * 10
                if due:
                    samples.append(now)
                    now += 300000000
                    next_checkpoint += 1
                    if next_checkpoint == 3:
                        break
                tenths += 1
            return samples
        self.assertEqual(observed(125000000, False), [])
        self.assertEqual(len(observed(125000000, True)), 1)
        self.assertLess(observed(10000000, False)[0], 2000000000)
        self.assertGreaterEqual(observed(10000000, True)[0], 15000000000)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args, remainder = parser.parse_known_args()
    ORIGINAL = args.source.read_text(encoding="utf-8")
    unittest.main(argv=[__file__, *remainder])
