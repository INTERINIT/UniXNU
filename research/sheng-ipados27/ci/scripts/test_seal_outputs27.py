import base64
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


spec = importlib.util.spec_from_file_location("seal27_tested", Path(__file__).with_name("seal_outputs27.py"))
seal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seal)


class SealedResultTests(unittest.TestCase):
    def test_result_roundtrip_and_authentication(self):
        key = bytes(range(32))
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"INPUTS27_KEY": base64.b64encode(key).decode()}):
            root = Path(temporary)
            (root / "result27").mkdir()
            (root / "result27/boot.img").write_bytes(b"private payload fixture")
            (root / "outside.key").write_bytes(b"excluded key fixture")
            report = seal.seal(root, root / "sealed")
            blob = (root / "sealed/outputs27.enc").read_bytes()
            self.assertEqual(blob[:8], b"UX27OUT1")
            self.assertNotIn(b"private payload fixture", blob)
            plain = AESGCM(key).decrypt(blob[8:20], blob[20:], b"UX27OUT1")
            with zipfile.ZipFile(io.BytesIO(plain)) as archive:
                self.assertEqual(archive.read("result27/boot.img"), b"private payload fixture")
                self.assertNotIn("outside.key", archive.namelist())
            self.assertEqual(report["files"], 1)
            with self.assertRaises(InvalidTag):
                AESGCM(key).decrypt(blob[8:20], blob[20:-1] + bytes([blob[-1] ^ 1]), b"UX27OUT1")
