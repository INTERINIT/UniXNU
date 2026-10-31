"""Encrypt public-runner results, including the device-bound boot payload."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"UX27OUT1"


def seal(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    key = base64.b64decode(os.environ["INPUTS27_KEY"], validate=True)
    if len(key) != 32 or output.exists():
        raise ValueError("Require a 32-byte key and fresh output directory")
    files = []
    result = root / "result27"
    if result.is_dir():
        files += list(result.rglob("*"))
    files += list(root.glob("work27/UniXNU/out/sheng/**/logs/*.log"))
    files += list(root.glob("work27/UniXNU/out/sheng/**/data-seed/*.log"))
    buffer, manifest = io.BytesIO(), {}
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=5) as archive:
        for path in sorted(set(files)):
            if path.is_symlink() or not path.resolve().is_relative_to(root):
                raise ValueError("Refuse escaped or linked result")
            if not path.is_file():
                continue
            name = path.relative_to(root).as_posix()
            data = path.read_bytes()
            manifest[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            archive.writestr(name, data)
        archive.writestr("outputs27-manifest.json", json.dumps({"format": MAGIC.decode(), "files": manifest}, sort_keys=True))
    nonce = os.urandom(12)
    encrypted = MAGIC + nonce + AESGCM(key).encrypt(nonce, buffer.getvalue(), MAGIC)
    output.mkdir(parents=True)
    (output / "outputs27.enc").write_bytes(encrypted)
    report = {"file": "outputs27.enc", "bytes": len(encrypted), "sha256": hashlib.sha256(encrypted).hexdigest(),
              "format": MAGIC.decode(), "encryption": "AES-256-GCM", "files": len(manifest),
              "hardware_tested": False, "device_operations": False}
    (output / "encrypted-output.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(seal(args.root, args.output), indent=2))
