"""Offline controls of the actual pinned Adreno-fetch adapter; no network."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.request


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


adapter = module(Path(__file__).with_name("adreno_fetch27.py"), "adreno_adapter_tested")
MAIN = Path(__file__).resolve().parents[4]


class AdrenoFetchTests(unittest.TestCase):
    def fixture(self, root):
        tree = root / "tree"
        for name in ("scripts/fetch-adreno-inputs.py", "scripts/data/adreno-inputs.json"):
            path = tree / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((MAIN / name).read_bytes())
        script = adapter.prepare(tree, root / "result")
        return tree, script, module(script, "adreno_local_tested")

    def test_exact_https_api_origin_only_and_no_redirect_forwarding(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, local = self.fixture(Path(temporary))
            with patch.dict(os.environ, {"GH_TOKEN": "test-only-gh", "GITHUB_TOKEN": "test-only-fallback"}, clear=True):
                request = local.authenticated_request("https://api.github.com/repos/public/repo/git/blobs/abc")
                self.assertEqual(request.get_header("Authorization"), "Bearer test-only-gh")
                self.assertNotIn("Authorization", request.headers)
                for url in ("https://raw.githubusercontent.com/public/repo/commit/file", "https://github.com/public/repo",
                            "https://cgit.freedesktop.org/file", "http://api.github.com/repo", "https://api.github.com.evil.test/repo",
                            "https://api.github.com@evil.test/repo", "https://api.github.com:443/repo"):
                    self.assertIsNone(local.authenticated_request(url).get_header("Authorization"))
                for destination in ("https://raw.githubusercontent.com/redirect", "https://api.github.com/redirect", "https://evil.test/redirect"):
                    redirected = urllib.request.HTTPRedirectHandler().redirect_request(request, None, 302, "Found", {}, destination)
                    self.assertIsNone(redirected.get_header("Authorization"))
            with patch.dict(os.environ, {"GITHUB_TOKEN": "test-only-fallback"}, clear=True):
                self.assertEqual(local.authenticated_request("https://api.github.com/x").get_header("Authorization"), "Bearer test-only-fallback")
            with patch.dict(os.environ, {}, clear=True):
                self.assertIsNone(local.authenticated_request("https://api.github.com/x").get_header("Authorization"))

    def test_original_checks_preserved_and_git_blob_download_still_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree, script, local = self.fixture(root)
            original = (tree / "scripts/fetch-adreno-inputs.py").read_text()
            before = original[original.index("def fetch(item):"):original.index("if __name__ == '__main__':")]
            adapted = script.read_text()
            after = adapted[adapted.index("def fetch(item):"):adapted.index("if __name__ == '__main__':")]
            self.assertEqual(before.replace(adapter.REQUEST_LINE, "        request = authenticated_request(url)\n"), after)
            data = b"synthetic firmware input, never executable"
            expected = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            blob = hashlib.sha1(("blob " + str(len(data)) + "\0").encode() + data).hexdigest()
            path = root / "fetched.bin"
            with patch.object(local.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps({"content": base64.b64encode(data).decode()}).encode())):
                self.assertEqual(local.fetch((path, "https://api.github.com/repos/public/repo/git/blobs/" + blob, expected, blob, None)), len(data))
            self.assertEqual(path.read_bytes(), data)
            for metadata, identity, message in ((dict(expected, bytes=len(data) + 1), blob, "hash/size"),
                                                 (dict(expected, sha256="0" * 64), blob, "hash/size"),
                                                 (expected, "0" * 40, "Git blob")):
                with self.assertRaisesRegex(ValueError, message):
                    local.fetch((path, "https://api.github.com/test", metadata, identity, None))

    def test_source_and_manifest_drift_refused_before_generation_and_at_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree, script, _ = self.fixture(root)
            self.assertEqual(adapter.prepare(tree, root / "result"), script)
            source = tree / "scripts/fetch-adreno-inputs.py"
            original = source.read_bytes()
            source.write_bytes(original + b"\n# independent edit\n")
            with self.assertRaisesRegex(ValueError, "source differs"):
                adapter.prepare(tree, root / "source-drift")
            self.assertFalse((root / "source-drift").exists())
            source.write_bytes(original)
            manifest = tree / "scripts/data/adreno-inputs.json"
            manifest.write_bytes(manifest.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "manifest differs"):
                adapter.prepare(tree, root / "manifest-drift")
            self.assertFalse((root / "manifest-drift").exists())
            with self.assertRaisesRegex(ValueError, "manifest differs"):
                module(script, "adreno_changed_manifest_tested")


if __name__ == "__main__":
    unittest.main()
