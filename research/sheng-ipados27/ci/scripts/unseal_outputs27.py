#!/usr/bin/env python3
"""Authenticate and unpack UX27OUT1 results into a fresh local directory.

Matches seal_outputs27.py: magic8 + nonce12 + AES256-GCM ciphertext/tag,
with the same magic as AAD. The local key is raw32B, never logged/copied.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"UX27OUT1"
MANIFEST = "outputs27-manifest.json"
MAX_CIPHERTEXT = 512 << 20
MAX_EXPANDED = 2 << 30
MAX_FILE = 512 << 20
MAX_MEMBERS = 4096
WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", *["COM" + str(n) for n in range(1, 10)], *["LPT" + str(n) for n in range(1, 10)]}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def json_unique(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON metadata key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def output_name(name):
    require(isinstance(name, str) and name and "\\" not in name and not name.startswith("/"), "Unsafe output ZIP path")
    parts = name.split("/")
    require(all(part not in ("", ".", "..") and re.fullmatch(r"[A-Za-z0-9_.-]+", part)
                and not part.endswith(".") and part.split(".", 1)[0].upper() not in WINDOWS_DEVICES for part in parts),
            "Unsafe output ZIP path")
    result = len(parts) >= 2 and parts[0] == "result27"
    log = (len(parts) >= 6 and parts[:4] == ["work27", "UniXNU", "out", "sheng"]
           and parts[-2] in ("logs", "data-seed") and parts[-1].endswith(".log"))
    require(result or log, "Output member is outside the permitted result/log trees")
    return name


def destination(root, name):
    target = root.joinpath(*name.split("/"))
    current = root
    for part in name.split("/"):
        current = current / part
        require(not current.is_symlink(), "Output destination is a symbolic link")
    require(target.resolve().is_relative_to(root), "Output destination escapes its fresh directory")
    return target


def verify_zip(archive, expected_count):
    infos = archive.infolist()
    require(1 <= len(infos) <= MAX_MEMBERS, "Output ZIP member count is outside bounds")
    files, folded, manifest = {}, set(), None
    for info in infos:
        require(not info.is_dir(), "Output archive must contain files only")
        require(info.filename.casefold() not in folded, "Duplicate/case-colliding output ZIP member")
        folded.add(info.filename.casefold())
        require(stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG) and not info.flag_bits & 1,
                "Output archive contains a link/special/encrypted member")
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and 0 <= info.file_size <= MAX_FILE, "Output ZIP compression/member size is outside bounds")
        if info.filename == MANIFEST:
            require(info.file_size <= 8 << 20, "Output manifest is too large")
            manifest = json_unique(archive.read(info))
        else:
            files[output_name(info.filename)] = info
    require(isinstance(manifest, dict) and manifest.get("format") == MAGIC.decode()
            and isinstance(manifest.get("files"), dict), "Authenticated output manifest is missing/invalid")
    entries = manifest["files"]
    require(set(entries) == set(files) and len(files) == expected_count, "Output manifest/member set differs from metadata")
    # A file cannot also serve as a directory for another member.
    for name in files:
        parts = name.split("/")
        require(not any("/".join(parts[:n]).casefold() in folded for n in range(1, len(parts))), "Output file/directory paths collide")
    total = 0
    for name, entry in entries.items():
        require(isinstance(entry, dict) and type(entry.get("bytes")) is int and 0 <= entry["bytes"] <= MAX_FILE
                and files[name].file_size == entry["bytes"] and re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")),
                "Output manifest size/hash metadata differs")
        total += entry["bytes"]
    require(total <= MAX_EXPANDED, "Expanded outputs exceed2GiB; raw Data/root disks are not accepted")
    for name, info in files.items():
        size, digest = 0, hashlib.sha256()
        with archive.open(info) as stream:
            while chunk := stream.read(1 << 20):
                size += len(chunk)
                require(size <= entries[name]["bytes"], "Output member expands beyond declared bounds")
                digest.update(chunk)
        require(size == entries[name]["bytes"] and digest.hexdigest() == entries[name]["sha256"], "Output member SHA-256 differs")
    return files, entries, total


def unseal(bundle, metadata, key_file, output):
    bundle, metadata, key_file = map(Path, (bundle, metadata, key_file))
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), "Preserve existing output; provide a fresh directory")
    output = output.resolve()
    require(metadata.is_file() and metadata.stat().st_size <= 1 << 20, "Encrypted-output metadata is missing/oversized")
    record = json_unique(metadata.read_bytes())
    require(record.get("format") == MAGIC.decode() and record.get("encryption") == "AES-256-GCM"
            and type(record.get("bytes")) is int and 36 <= record["bytes"] <= MAX_CIPHERTEXT
            and re.fullmatch(r"[0-9a-f]{64}", record.get("sha256", ""))
            and type(record.get("files")) is int and 0 <= record["files"] < MAX_MEMBERS,
            "Encrypted-output metadata format/size/hash is invalid")
    require(bundle.is_file() and bundle.stat().st_size == record["bytes"], "Encrypted output size differs")
    blob = bundle.read_bytes()
    require(len(blob) == record["bytes"] and hashlib.sha256(blob).hexdigest() == record["sha256"]
            and blob[:8] == MAGIC, "Encrypted output magic/SHA-256 differs")
    require(key_file.is_file() and key_file.stat().st_size == 32, "Local key file must contain exactly32 raw bytes")
    key = key_file.read_bytes()
    require(len(key) == 32, "Local key file changed while reading")
    try:
        plaintext = AESGCM(key).decrypt(blob[8:20], blob[20:], MAGIC)
    except InvalidTag:
        raise ValueError("Encrypted output authentication failed") from None
    finally:
        del key
    with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
        files, entries, total = verify_zip(archive, record["files"])
        output.mkdir(parents=True, exist_ok=False)
        for name, info in files.items():
            target = destination(output, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            destination(output, name)
            with target.open("xb") as destination_stream, archive.open(info) as source:
                while chunk := source.read(1 << 20):
                    destination_stream.write(chunk)
            target.chmod(0o600)
            with target.open("rb") as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == entries[name]["sha256"], "Unpacked output changed")
    return {"status": "authenticated_outputs_unpacked", "files": len(files), "bytes": total,
            "bundle_sha256": record["sha256"], "device_operations": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(unseal(args.bundle, args.metadata, args.key_file, args.output), indent=2))
