"""Real small seal/unseal controls; no job, production key or device access."""
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
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def module(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location(name + "_tested", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


seal, unseal = module("seal_outputs27"), module("unseal_outputs27")


class OutputTests(unittest.TestCase):
    def test_actual_sealer_roundtrip_and_fresh_output_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / "work"
            files = {"result27/payload27/boot27-v3.img": b"encrypted boot fixture only",
                     "result27/data.dbr": b"packed seed fixture only",
                     "work27/UniXNU/out/sheng/os/config/logs/kernel.log": b"host log fixture"}
            for name, blob in files.items():
                target = work / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(blob)
            key = os.urandom(32)
            key_file = root / "local.key"
            key_file.write_bytes(key)
            with patch.dict(os.environ, INPUTS27_KEY=base64.b64encode(key).decode()):
                seal.seal(work, root / "sealed")
            args = (root / "sealed/outputs27.enc", root / "sealed/encrypted-output.json", key_file, root / "unpacked")
            result = unseal.unseal(*args)
            self.assertEqual(result["files"], len(files))
            for name, blob in files.items():
                self.assertEqual((root / "unpacked" / name).read_bytes(), blob)
            self.assertFalse((root / "unpacked/outputs27-manifest.json").exists())
            with self.assertRaisesRegex(ValueError, "fresh directory"):
                unseal.unseal(*args)

    def test_tag_and_unsafe_authenticated_path_fail_before_creation(self):
        for unsafe, corrupt in ((False, True), (True, False)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                key, nonce = os.urandom(32), os.urandom(12)
                key_file = root / "local.key"
                key_file.write_bytes(key)
                name, data = ("result27/../../escape" if unsafe else "result27/result.json"), b"fixture"
                manifest = {"format": "UX27OUT1", "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}}}
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    archive.writestr(name, data)
                    archive.writestr("outputs27-manifest.json", json.dumps(manifest))
                blob = unseal.MAGIC + nonce + AESGCM(key).encrypt(nonce, buffer.getvalue(), unseal.MAGIC)
                if corrupt:
                    blob = blob[:-1] + bytes([blob[-1] ^ 1])
                (root / "outputs.enc").write_bytes(blob)
                (root / "metadata.json").write_text(json.dumps({"format": "UX27OUT1", "encryption": "AES-256-GCM", "bytes": len(blob),
                    "sha256": hashlib.sha256(blob).hexdigest(), "files": 1}))
                with self.assertRaises(ValueError):
                    unseal.unseal(root / "outputs.enc", root / "metadata.json", key_file, root / "unpacked")
                self.assertFalse((root / "unpacked").exists())


if __name__ == "__main__":
    unittest.main()
