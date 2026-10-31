"""Fetch only the pinned Apple IPSW's stored AEA root members, with resume.

No device access. Files become final only after ZIP CRC/size verification.
"""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import threading
import time
import urllib.request
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "resources/apple-24A446"
CHUNK = 16 << 20
WORKERS = 4


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


def main():
    metadata = json.loads((ROOT / "research/ipsw-24A446-metadata.json").read_text())
    if (metadata["version"], metadata["build"]) != ("27.0.1", "24A446"):
        raise ValueError("Wrong IPSW identity")
    spec = importlib.util.spec_from_file_location("inspect27", ROOT / "research/inspect_27_ipsw.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    OUT.mkdir(parents=True, exist_ok=True)
    stream = helper.BoundedRemote()
    if stream.size != metadata["ipsw_bytes"] or stream.http["headers"]["ETag"] != metadata["http"]["headers"]["ETag"]:
        raise ValueError("Apple IPSW entity changed")
    entries = []
    with zipfile.ZipFile(stream) as archive:
        for component in ("OS", "Cryptex1,SystemOS"):
            pin = metadata["components"][component]
            info = archive.getinfo(pin["path"])
            if info.compress_type != zipfile.ZIP_STORED or info.file_size != pin["bytes"] or f"{info.CRC:08x}" != pin["zip_crc32"]:
                raise ValueError("Root member metadata differs")
            stream.seek(info.header_offset)
            header = stream.read(30)
            if header[:4] != b"PK\x03\x04":
                raise ValueError("ZIP local header differs")
            name_len, extra_len = struct.unpack_from("<HH", header, 26)
            start = info.header_offset + 30 + name_len + extra_len
            entries.append((component, pin, start))
    required = sum(p["bytes"] for _, p, _ in entries if not (OUT / p["path"]).exists())
    if shutil.disk_usage(OUT).free < required + (10 << 30):
        raise ValueError("Need the download size plus 10 GiB free space")
    reports = {}
    for component, pin, remote_start in entries:
        target = OUT / pin["path"]
        if target.parent != OUT or target.suffix != ".aea":
            raise ValueError("Unexpected root member path")
        report_path = target.with_suffix(target.suffix + ".json")
        if target.exists():
            if not report_path.exists():
                raise ValueError("Preserve unrecorded final file")
            saved = json.loads(report_path.read_text())
            if target.stat().st_size != pin["bytes"] or saved["zip_crc32"] != pin["zip_crc32"]:
                raise ValueError("Existing root file differs")
            reports[component] = saved
            continue
        partial = target.with_suffix(target.suffix + ".partial")
        resume_path = target.with_suffix(target.suffix + ".resume.json")
        identity = {"member": pin["path"], "bytes": pin["bytes"], "crc": pin["zip_crc32"], "etag": metadata["http"]["headers"]["ETag"], "chunk_bytes": CHUNK}
        total = (pin["bytes"] + CHUNK - 1) // CHUNK
        state = {"identity": identity, "chunks": {}}
        if partial.exists() or resume_path.exists():
            if not partial.exists() or not resume_path.exists():
                raise ValueError("Partial download and resume metadata must both exist")
            state = json.loads(resume_path.read_text())
            if state["identity"] != identity or partial.stat().st_size != pin["bytes"]:
                raise ValueError("Partial download belongs to another source")
            # Check saved chunks before trusting the resume bitmap.
            with partial.open("rb") as handle:
                for key, digest in state["chunks"].items():
                    index = int(key)
                    handle.seek(index * CHUNK)
                    if hashlib.sha256(handle.read(min(CHUNK, pin["bytes"] - index * CHUNK))).hexdigest() != digest:
                        raise ValueError("Partial chunk changed: " + key)
        else:
            with partial.open("xb") as handle:
                handle.truncate(pin["bytes"])
            atomic_json(resume_path, state)
        print(component, "download", pin["bytes"], "bytes; resume chunks", len(state["chunks"]), flush=True)

        def fetch(index):
            offset = index * CHUNK
            length = min(CHUNK, pin["bytes"] - offset)
            first, last = remote_start + offset, remote_start + offset + length - 1
            for attempt in range(5):
                try:
                    request = urllib.request.Request(metadata["url"], headers={"Range": f"bytes={first}-{last}", "If-Range": identity["etag"]})
                    with urllib.request.urlopen(request, timeout=180) as response:
                        if response.status != 206 or response.headers.get("Content-Range") != f"bytes {first}-{last}/{stream.size}":
                            raise ValueError("CDN did not honor exact root byte range")
                        data = response.read(length + 1)
                    if len(data) != length:
                        raise OSError("Short root range")
                    with partial.open("r+b", buffering=0) as handle:
                        handle.seek(offset)
                        handle.write(data)
                    return index, hashlib.sha256(data).hexdigest()
                except (OSError, ValueError):
                    if attempt == 4:
                        raise
                    time.sleep(2 ** attempt)

        last_report = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
            tasks = [pool.submit(fetch, i) for i in range(total) if str(i) not in state["chunks"]]
            for future in concurrent.futures.as_completed(tasks):
                index, digest = future.result()
                state["chunks"][str(index)] = digest
                atomic_json(resume_path, state)
                if time.monotonic() - last_report >= 20 or len(state["chunks"]) == total:
                    print(component, f"{len(state['chunks'])}/{total} chunks", flush=True)
                    last_report = time.monotonic()
        digest, crc = hashlib.sha256(), 0
        with partial.open("rb") as handle:
            for data in iter(lambda: handle.read(CHUNK), b""):
                digest.update(data)
                crc = zlib.crc32(data, crc)
        if f"{crc:08x}" != pin["zip_crc32"]:
            raise ValueError("Root member ZIP CRC mismatch")
        partial.rename(target)
        saved = {"component": component, "member": pin["path"], "bytes": target.stat().st_size, "sha256": digest.hexdigest(), "zip_crc32": f"{crc:08x}", "apple_url": metadata["url"], "build": "24A446", "version": "27.0.1", "decrypted": False, "device_operations": False}
        atomic_json(report_path, saved)
        reports[component] = saved
        print(component, "ZIP size/CRC verified; SHA256", digest.hexdigest(), flush=True)
    atomic_json(OUT / "download-report.json", reports)


if __name__ == "__main__":
    main()
