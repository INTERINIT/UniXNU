"""Three local source-preparation controls; no download, compiler or device."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("ath12k_source_controls", Path(__file__).with_name("ath12k_sources27.py"))
h = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(h)
MAIN = Path(__file__).resolve().parents[4]
DEVICE = MAIN.parent / "UniXNU-sheng"
# Same official f6bf... gitlink already present in the17 reference, read only.
CANONICAL = DEVICE / "drivers/Ath12kWifi"
MODULE = CANONICAL if (CANONICAL / "tools/fetch-sources.sh").is_file() else MAIN.parents[2] / "sources/UniXNU-sheng/drivers/Ath12kWifi"


class SourceControls(unittest.TestCase):
    def test_real_module_default_plan_does_not_fetch_or_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "must-remain-absent"
            with patch.object(h, "fetch_commands", side_effect=AssertionError("No fetch in a plan")):
                report = h.prepare(MODULE, output)
            self.assertEqual(report["module_commit"], "f6bf561f92cc42761bdd417fce1d53fe1db9477c")
            self.assertEqual(report["status"], "planned")
            self.assertFalse(output.exists())

    def test_official_sparse_selection_fetches_the_fixed_source(self):
        commands = h.fetch_commands(Path("source-only-fixture"))
        clone = commands[0]
        self.assertEqual(clone[1], "clone")
        self.assertEqual(clone[clone.index("--depth") + 1], "1")
        self.assertIn("--filter=blob:none", clone)
        self.assertEqual(clone[clone.index("--branch") + 1], "v7.0.14")
        self.assertEqual(h.LINUX["commit"], "458c6079fc1d41d564c37679c8ace02cd83ee817")
        official = (MODULE / "tools/fetch-sources.sh").read_text(encoding="utf-8")
        self.assertIn(h.LINUX["url"], official)
        self.assertIn("--branch " + h.LINUX["ref"], official)
        self.assertTrue(all(pattern in official for pattern in h.LINUX["patterns"]))
        self.assertTrue(all(command[0] == "git" for command in commands))

    def test_other_existing_repository_is_preserved(self):
        before = h.git(DEVICE, "rev-parse", "HEAD")
        with self.assertRaisesRegex(ValueError, "different commit"):
            h.repository(DEVICE, h.LINUX["commit"], h.LINUX["url"])
        self.assertEqual(h.git(DEVICE, "rev-parse", "HEAD"), before)


if __name__ == "__main__":
    unittest.main()
