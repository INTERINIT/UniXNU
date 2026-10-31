"""Meaningful small transport/crypto controls; never substitutes for Apple inputs."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import struct
import tempfile
from types import SimpleNamespace
import uuid
import zlib

import build_userdata27_windows as b


def rejected(function):
    try:
        function()
    except (ValueError, EOFError, struct.error):
        return
    raise AssertionError("Negative input was incorrectly accepted")


def udif_fixture(path):
    first = (b"first raw sector pattern" * 400)[:4096].ljust(4096, b"A")
    last = (b"compressed independent fixture" * 400)[:8192].ljust(8192, b"B")
    packed = zlib.compress(last)
    chunks = [(b.RAW, 0, 8, 0, len(first)), (b.ZERO_FILL, 8, 8, 0, 0), (b.ZLIB, 16, 16, len(first), len(packed))]
    table = bytearray(204)
    table[:4] = b"mish"
    struct.pack_into(">I", table, 200, len(chunks))
    for kind, sector, length, offset, stored in chunks:
        table.extend(struct.pack(">IIQQQQ", kind, 0, sector, length, offset, stored))
    metadata = plistlib.dumps({"resource-fork": {"blkx": [{"Name": "small transport fixture", "Data": bytes(table)}]}}, fmt=plistlib.FMT_BINARY)
    trailer = bytearray(512)
    trailer[:4] = b"koly"
    struct.pack_into(">QQ", trailer, 216, len(first) + len(packed), len(metadata))
    struct.pack_into(">Q", trailer, 492, 32)
    path.write_bytes(first + packed + metadata + trailer)
    return first + bytes(4096) + last


def sparse_chunks(blob):
    result, offset, logical = [], 28, 0
    count = struct.unpack_from("<I", blob, 20)[0]
    for _ in range(count):
        kind, _, blocks, length = struct.unpack_from("<2H2I", blob, offset)
        result.append((offset, kind, logical, blocks * b.BLOCK))
        logical += blocks * b.BLOCK
        offset += length
    return result


def self_test(executable):
    checks = []
    with tempfile.TemporaryDirectory(prefix="userdata27-fixture-") as directory:
        root = Path(directory)
        previous_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(executable.parent) + os.pathsep + previous_path
        try:
            # Sign fixtures using the upstream implementation and real OpenSSL.
            sources = (b.SOURCE / "kits/VerifiedRoot/tools/manifest.py",
                       b.WORK / "sources/UniXNU/kits/VerifiedRoot/tools/manifest.py")
            source = next((path for path in sources if path.is_file()), None)
            if source is None:
                raise ValueError("Initialize the pinned kits/VerifiedRoot submodule before this host check")
            spec = importlib.util.spec_from_file_location("fixture_manifest", source)
            manifest = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(manifest)
            private, public = root / "owner.pem", root / "owner-public.pem"
            b.run([executable, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072", "-out", private])
            b.run([executable, "pkey", "-in", private, "-pubout", "-out", public])
            os_data = bytearray((i * 19 + i // 4096) & 255 for i in range(6 * b.BLOCK + 512))
            os_data[32:36] = b"NXSB"
            os_data = bytes(os_data)
            os_path, system_path = root / "OS.dmg", root / "SystemOS.dmg"
            os_path.write_bytes(os_data)
            system_data = udif_fixture(system_path)
            images = {"OS": b.RawImage(os_path), "SystemOS": b.RawImage(system_path)}
            policy = {}
            for index, (name, data) in enumerate((("OS", os_data), ("SystemOS", system_data))):
                out = root / name
                manifest.make(io.BytesIO(data), len(data), private, public,
                              uuid.UUID(int=100 + index), 1, out)
                policy[name] = b.Policy((out / "manifest.bin").read_bytes(), (out / "trusted-key.bin").read_bytes(), executable)
                verifier = b.MediaVerifier(policy[name])
                reconstructed = bytearray()
                for zero, extent in images[name].extents():
                    chunk = bytes(extent) if zero else extent
                    verifier.feed(chunk, zero)
                    reconstructed.extend(chunk)
                verifier.finish()
                assert reconstructed == data
            checks.append("Real OpenSSL RSA3072-signed fixtures and every 4096-byte raw block verified")
            checks.append("Actual raw APFS fast path plus synthetic UDIF RAW/zero/zlib decoding reproduces independent bytes")
            corrupt = bytearray(policy["OS"].blob)
            corrupt[40] ^= 1
            rejected(lambda: b.Policy(bytes(corrupt), policy["OS"].anchor, executable))
            corrupt = bytearray(policy["OS"].blob)
            corrupt[-1] ^= 1
            rejected(lambda: b.Policy(bytes(corrupt), policy["OS"].anchor, executable))
            verifier = b.MediaVerifier(policy["OS"])
            rejected(lambda: verifier.feed(b"!" + os_data[1:4096]))
            verifier = b.MediaVerifier(policy["OS"])
            verifier.feed(os_data[:-1])
            rejected(verifier.finish)
            checks.append("Changed signed UUID, hash table, actual data block and truncated raw stream refused")

            header, windows, objects, used = b.layout(images, policy)
            capacity = 8 * b.MIB
            destination = root / "small.sparse"
            with destination.open("wb+") as stream:
                writer = b.SparseWriter(stream, capacity, b.BLOCK)
                writer.write(header)
                for row, data in zip(windows, (os_data, system_data)):
                    writer.zeros(row["offset"] - writer.position)
                    writer.write(data)
                for row, name in zip(objects, ("OS", "SystemOS")):
                    writer.zeros(row["offset"] - writer.position)
                    writer.write(policy[name].table)
                writer.zeros(capacity - writer.position)
                writer.finish()
            report, expanded = b.inspect_sparse(destination, capacity, expand=True, ranges=windows + objects)
            expected = bytearray(capacity)
            expected[:b.BLOCK] = header
            for row, data in zip(windows + objects, (os_data, system_data, policy["OS"].table, policy["SystemOS"].table)):
                expected[row["offset"]:row["offset"] + row["size"]] = data
            assert expanded == expected and used == 5 * b.MIB
            assert expanded[4064:4096] == hashlib.sha256(expanded[:4064]).digest()
            assert struct.unpack_from("<8sIIQ", expanded) == (b"SHNGROOT", 2, 4, used)
            assert [struct.unpack_from("<II", expanded, 24 + 128 * i + 48) for i in range(4)] == [(512, 1), (512, 1), (4096, 3), (4096, 3)]
            assert report["dont_care_chunks"] == 0 and expanded[used:] == bytes(capacity - used)
            checks.append("Complete independent sparse expansion equals SHNGROOTv2 windows, tables-only objects and a zeroed whole partition")

            original = destination.read_bytes()
            chunks = sparse_chunks(original)
            fill_offset = next(offset for offset, kind, _, _ in chunks if kind == b.SPARSE_FILL)
            bad = bytearray(original)
            struct.pack_into("<H", bad, fill_offset, 0xCAC3)
            changed = root / "bad.sparse"
            changed.write_bytes(bad)
            rejected(lambda: b.inspect_sparse(changed, capacity))
            bad = bytearray(original)
            bad[fill_offset + 12] = 1
            changed.write_bytes(bad)
            rejected(lambda: b.inspect_sparse(changed, capacity))
            changed.write_bytes(original[:-1])
            rejected(lambda: b.inspect_sparse(changed, capacity))
            bad = bytearray(original)
            first_offset, _, first_logical, _ = next(item for item in chunks if item[1] == b.SPARSE_RAW and item[2] <= windows[0]["offset"] < item[2] + item[3])
            bad[first_offset + 12 + windows[0]["offset"] - first_logical] ^= 1
            changed.write_bytes(bad)
            rejected(lambda: b.inspect_sparse(changed, capacity, ranges=windows + objects))
            checks.append("DONT_CARE, nonzero FILL, truncated sparse body and corrupted written window refused")
            with (root / "huge-fill.sparse").open("wb+") as stream:
                writer = b.SparseWriter(stream, 100 << 30)
                writer.zeros(100 << 30)
                writer.finish()
            huge_report, _ = b.inspect_sparse(root / "huge-fill.sparse", 100 << 30)
            assert (root / "huge-fill.sparse").stat().st_size == 44 and huge_report["zero_fill_bytes"] == 100 << 30
            rejected(lambda: b.SparseWriter(io.BytesIO(), b.BLOCK - 1))
            writer = b.SparseWriter(io.BytesIO(), b.BLOCK)
            rejected(lambda: writer.zeros(b.BLOCK + 1))
            checks.append("100GiB explicit zero coverage encodes in 44B without expansion; capacity misalignment and overrun refused")
            encrypted = root / "encrypted.dmg"
            encrypted.write_bytes(b"AEA1" + bytes(4096))
            rejected(lambda: b.RawImage(encrypted))
            checks.append("Still-encrypted AEA input refused instead of silently treating it as raw")
        finally:
            os.environ["PATH"] = previous_path
    report = {"checks": checks, "fixture_RSA_signatures_real": True, "small_v2_sparse_fixture_passed": True,
              "actual_Apple_root_media_tested": False, "Mac_CI_policy_reports_not_fabricated": True,
              "device_operations": False, "hardware_tested": False}
    out = b.ROOT / "reports/userdata27-assembler-selftest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
