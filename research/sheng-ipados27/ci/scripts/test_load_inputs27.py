"""Tiny encrypted ZIP controls; keys are ephemeral and never printed."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


spec = importlib.util.spec_from_file_location("inputs27_tested", Path(__file__).with_name("load_inputs27.py"))
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)


def fixture(extra=None, symlink=False, wrong_hash=False):
    files = {name: b"small resource fixture" for name in loader.VENDOR | loader.POLICIES}
    files[loader.PACKAGE + "data-seed.json"] = b"small captured metadata fixture"
    if extra:
        files[extra] = b"unsafe"
    manifest = {"format": "UX27IN01", "source_run": 41173083070,
                "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()}}
    if wrong_hash:
        manifest["files"][next(iter(files))]["sha256"] = "0" * 64
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(loader.MANIFEST, json.dumps(manifest))
        for name, data in files.items():
            if symlink and name == "resources/official-vendor/uefi.elf":
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, data)
            else:
                archive.writestr(name, data)
    key, nonce = os.urandom(32), os.urandom(12)
    blob = loader.MAGIC + nonce + AESGCM(key).encrypt(nonce, buffer.getvalue(), loader.MAGIC)
    return key, blob, files


class InputTests(unittest.TestCase):
    def exercise(self, key, blob, root):
        path = root.parent / "inputs.enc"
        path.write_bytes(blob)
        with patch.dict(os.environ, INPUTS27_KEY=base64.b64encode(key).decode()):
            return loader.load(path, root, hashlib.sha256(blob).hexdigest())

    def test_authenticated_exact_inputs_and_repeat(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "workspace"
            root.mkdir()
            key, blob, files = fixture()
            self.assertEqual(self.exercise(key, blob, root), len(files))
            self.assertEqual(self.exercise(key, blob, root), len(files))
            self.assertFalse((root / loader.MANIFEST).exists())
            for name, data in files.items():
                self.assertEqual((root / name).read_bytes(), data)

    def test_wrong_key_and_tampered_member_never_write(self):
        for wrong_key, wrong_hash in ((True, False), (False, True)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "workspace"
                root.mkdir()
                key, blob, _ = fixture(wrong_hash=wrong_hash)
                with self.assertRaises(ValueError):
                    self.exercise(os.urandom(32) if wrong_key else key, blob, root)
                self.assertEqual(list(root.iterdir()), [])

    def test_traversal_links_and_private_key_members_never_write(self):
        for extra, symlink in (("../escape", False), (loader.PACKAGE + "owner.pem", False), (None, True)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "workspace"
                root.mkdir()
                key, blob, _ = fixture(extra, symlink)
                with self.assertRaises(ValueError):
                    self.exercise(key, blob, root)
                self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
