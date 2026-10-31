#!/usr/bin/env python3
"""Load one SHA-pinned AES256-GCM ZIP of fixed27 host inputs.

Wire format: UX27IN01 + nonce12 + ciphertext/tag; AAD is UX27IN01.
ZIP metadata inputs27-manifest.json is authenticated by GCM and the pinned
whole-bundle SHA. It is parsed in memory and never extracted. No key is logged.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"UX27IN01"
MANIFEST = "inputs27-manifest.json"
SOURCE_RUN = 41173083070
MAX_BUNDLE = 256 << 20
MAX_EXPANDED = 512 << 20
MAX_FILE = 128 << 20
VENDOR = {"resources/official-vendor/" + name for name in
          ("official-extraction-manifest.json", "provenance.json", "uefi.elf")}
POLICIES = {"resources/root-policies-24A446/" + name + "/" + part
            for name in ("OS", "SystemOS") for part in ("manifest.bin", "trusted-key.bin", "verification.json")}
PACKAGE = "work27/reuse-41173083070/result27/"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_name(name):
    require(isinstance(name, str) and name and "\\" not in name and not name.startswith("/"), "Unsafe ZIP member path")
    parts = name.split("/")
    require(all(part not in ("", ".", "..") and re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts),
            "Unsafe ZIP member path")
    require(not any(part.lower().endswith((".pem", ".key")) or part.lower() in ("id_rsa", "id_ed25519") for part in parts),
            "Private-key paths are not input resources")
    require(name in VENDOR or name in POLICIES or name.startswith(PACKAGE), "ZIP member is outside the fixed input trees")
    # This captured run never produced a boot/payload or carried its platform ID.
    relative = name[len(PACKAGE):] if name.startswith(PACKAGE) else ""
    require(not relative.startswith(("payload", "boot27", "kernel27")), "Completed boot/payload files are not allowed inputs")
    return name


def destination(root, name):
    target = root.joinpath(*name.split("/"))
    current = root
    for part in name.split("/"):
        current = current / part
        require(not current.is_symlink(), "An extraction destination is a symbolic link")
    require(target.resolve().is_relative_to(root), "Extraction destination escapes the workspace")
    return target


def read_manifest(archive):
    infos = archive.infolist()
    require(1 <= len(infos) <= 256, "Unexpected ZIP member count")
    names, files, manifest_info = set(), {}, None
    for info in infos:
        name = info.filename
        require(not info.is_dir(), "ZIP must contain files only; omit directory entries")
        require(name.casefold() not in names, "Duplicate or case-colliding ZIP paths")
        names.add(name.casefold())
        kind = stat.S_IFMT(info.external_attr >> 16)
        require(kind in (0, stat.S_IFREG) and not info.flag_bits & 1, "ZIP links/special/encrypted members are forbidden")
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and 0 <= info.file_size <= MAX_FILE, "ZIP compression/member size is outside bounds")
        if name == MANIFEST:
            require(info.file_size <= 1 << 20, "Input manifest is too large")
            manifest_info = info
        else:
            files[safe_name(name)] = info
    require(manifest_info is not None, "Authenticated input manifest is missing")
    manifest = json.loads(archive.read(manifest_info))
    require(manifest.get("format") == MAGIC.decode() and manifest.get("source_run") == SOURCE_RUN
            and isinstance(manifest.get("files"), dict), "Input manifest format/source run differs")
    expected = manifest["files"]
    require(set(expected) == set(files) and VENDOR | POLICIES <= set(expected)
            and any(name.startswith(PACKAGE) for name in expected), "Manifest must exactly cover the three fixed input groups")
    total = 0
    for name, entry in expected.items():
        safe_name(name)
        require(isinstance(entry, dict) and type(entry.get("bytes")) is int and 0 <= entry["bytes"] <= MAX_FILE
                and re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", ""))
                and files[name].file_size == entry["bytes"], "Input manifest file metadata differs")
        total += entry["bytes"]
    require(total <= MAX_EXPANDED, "Expanded input bundle exceeds the fixed limit")
    return files, expected


def verify_zip(archive, root):
    files, expected = read_manifest(archive)
    # Verify every member and every existing destination before creating files.
    for name, info in files.items():
        digest, size = hashlib.sha256(), 0
        with archive.open(info) as stream:
            while chunk := stream.read(1 << 20):
                size += len(chunk)
                require(size <= expected[name]["bytes"], "ZIP member expands beyond its declared bound")
                digest.update(chunk)
        require(size == expected[name]["bytes"] and digest.hexdigest() == expected[name]["sha256"], "Input ZIP member SHA-256 differs")
        target = destination(root, name)
        if target.exists():
            require(target.is_file() and sha(target) == expected[name]["sha256"], "Preserve a conflicting existing input")
    return files, expected


def load(bundle, root, expected_sha256):
    bundle, root = Path(bundle), Path(root).resolve()
    require(root.is_dir() and re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""), "Provide an existing workspace and pinned bundle SHA-256")
    require(bundle.is_file() and 36 <= bundle.stat().st_size <= MAX_BUNDLE, "Encrypted bundle size is outside bounds")
    require(sha(bundle) == expected_sha256, "Encrypted bundle SHA-256 differs")
    try:
        key = base64.b64decode(os.environ.get("INPUTS27_KEY", ""), validate=True)
    except (ValueError, TypeError):
        raise ValueError("INPUTS27_KEY must be strict base64 for a256-bit key") from None
    require(len(key) == 32, "INPUTS27_KEY must be strict base64 for a256-bit key")
    blob = bundle.read_bytes()
    require(len(blob) <= MAX_BUNDLE and hashlib.sha256(blob).hexdigest() == expected_sha256,
            "Encrypted bundle changed before decryption")
    require(blob[:8] == MAGIC, "Encrypted input format differs")
    try:
        plaintext = AESGCM(key).decrypt(blob[8:20], blob[20:], MAGIC)
    except InvalidTag:
        raise ValueError("Encrypted input authentication failed") from None
    del key
    with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
        files, expected = verify_zip(archive, root)
        for name, info in files.items():
            target = destination(root, name)
            if target.exists():
                continue  # Exact content was already checked, including reruns.
            target.parent.mkdir(parents=True, exist_ok=True)
            destination(root, name)  # Check newly materialized ancestors again.
            with target.open("xb") as output, archive.open(info) as source:
                shutil_copy(source, output)
            target.chmod(0o600)
            require(sha(target) == expected[name]["sha256"], "Extracted input bytes changed")
    return len(files)


def shutil_copy(source, output):
    while chunk := source.read(1 << 20):
        output.write(chunk)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    count = load(args.bundle, args.root, args.expected_sha256)
    print(f"Loaded {count} pinned host input files; no device operation.")
