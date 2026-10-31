"""Build a fully clearing SHNGROOTv2 Android sparse image on the PC only.

Requires actual 24A446 Apple images and the genuine CI VerifiedRoot policies.
No ADB, fastboot, partition write, image mounting, or device operation is used.
Default mode is --plan. Use --build explicitly to create the sparse file.
"""
import argparse
import base64
import bz2
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parent
SOURCE = Path(os.environ.get("UNIXNU_SOURCE", ROOT / "source/UniXNU"))
if not (SOURCE / "scripts/unixnu").is_dir() and (ROOT.parents[1] / "scripts/unixnu").is_dir():
    SOURCE = ROOT.parents[1]  # the research directory inside a UniXNU fork
sys.path[:0] = [str(WORK / "tools/python-deps"), str(SOURCE / "scripts")]
from unixnu.udif import Image, ZERO_FILL, IGNORE, RAW, ZLIB, BZIP2, LZFSE

BLOCK, MIB = 4096, 1 << 20
PARTITION_BYTES = 249497890816
SPARSE_MAGIC, SPARSE_RAW, SPARSE_FILL = 0xED26FF3A, 0xCAC1, 0xCAC2
PINNED = {
    "OS": ("2F8E6EED-68D5-4261-B8A3-12571BAA2DD4", "8a12cdad43f8f0d33dadcf01a800a560222baf40c05f71374c460ba57ba3a739"),
    "SystemOS": ("F914C62A-AD00-47C6-8281-5746291C339A", "d5b4873d35c85f96eaafaa31c59602b485afe33b5067eff1af67ba31204cdb4a"),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def align(value, boundary=MIB):
    return (value + boundary - 1) // boundary * boundary


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def openssl_path(explicit=None):
    choices = [explicit, shutil.which("openssl"), r"C:\Program Files\Git\mingw64\bin\openssl.exe",
               r"C:\Program Files\Git\usr\bin\openssl.exe"]
    found = next((Path(item) for item in choices if item and Path(item).is_file()), None)
    require(found, "Real OpenSSL RSA verification is required; specify --openssl")
    return found


def run(command):
    result = subprocess.run(list(map(str, command)), capture_output=True)
    require(result.returncode == 0, "Command failed: " + str(command[0]) + ": " + result.stderr.decode("utf-8", "replace")[-1200:])
    return result.stdout


def der(tag, data):
    length = len(data)
    encoded = bytes([length]) if length < 128 else bytes([0x80 | ((length.bit_length() + 7) // 8)]) + length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag]) + encoded + data


def rsa_verify(header, signature, anchor, executable):
    require(len(header) == 160 and len(signature) == 384 and len(anchor) == 395 and anchor[:8] == b"VROOTKEY"
            and anchor[-3:] == bytes.fromhex("010001") and anchor[8] & 128 and anchor[391] & 1,
            "Invalid complete RSA3072 owner anchor or signed header")
    public = der(0x30, der(2, b"\0" + anchor[8:392]) + der(2, anchor[392:]))
    pem = b"-----BEGIN RSA PUBLIC KEY-----\n" + base64.encodebytes(public) + b"-----END RSA PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="vroot-rsa-") as temporary:
        location = Path(temporary)
        (location / "public.pem").write_bytes(pem)
        (location / "header.bin").write_bytes(header)
        (location / "signature.bin").write_bytes(signature)
        run([executable, "dgst", "-sha256", "-verify", location / "public.pem", "-signature", location / "signature.bin", location / "header.bin"])


class Policy:
    """A real RSA-authenticated complete envelope; table objects exclude 544B."""
    def __init__(self, blob, anchor, executable):
        require(544 <= len(blob) <= 256 * MIB, "Policy envelope size is outside the supported bounds")
        values = struct.unpack_from("<8s4I2Q16s32s32s32sQ", blob)
        magic, version, header, block, flags, self.size, self.count, identity, image_hash, table_hash, key_hash, self.generation = values
        require((magic, version, header, block, flags) == (b"VROOT01\0", 1, 160, BLOCK, 0), "Wrong policy format")
        require(self.size > 0 and self.count == (self.size + BLOCK - 1) // BLOCK and self.generation == 1,
                "Invalid policy geometry or unsupported generation")
        require(len(blob) == 544 + 32 * self.count, "Policy table truncated or has trailing data")
        self.blob, self.anchor = blob, anchor
        self.table = memoryview(blob)[544:]
        self.uuid, self.image_sha = str(uuid.UUID(bytes=identity)).upper(), image_hash.hex()
        require(hashlib.sha256(self.table).digest() == table_hash, "Signed hash table digest mismatch")
        require(hashlib.sha256(anchor).digest() == key_hash, "Independent owner anchor digest mismatch")
        rsa_verify(blob[:160], blob[160:544], anchor, executable)

    @classmethod
    def load(cls, name, directory, image_size, image_path, executable):
        location = directory / name
        for filename in ("manifest.bin", "trusted-key.bin", "verification.json"):
            require((location / filename).is_file(), name + ": missing actual Mac CI " + filename)
        require((location / "manifest.bin").stat().st_size <= 256 * MIB, "Oversized policy input")
        policy = cls((location / "manifest.bin").read_bytes(), (location / "trusted-key.bin").read_bytes(), executable)
        expected_uuid, expected_sha = PINNED[name]
        require((policy.uuid, policy.image_sha, policy.size) == (expected_uuid, expected_sha, image_size), name + ": policy differs from the pinned actual media")
        report = json.loads((location / "verification.json").read_text(encoding="utf-8-sig"))
        require(report.get("real_c_signature_and_block_verification") is True and report.get("original_image_modified") is False
                and report.get("host_media_writable") is False, name + ": require genuine full C/RSA read-only Mac verification")
        require(report.get("image_sha256") == expected_sha and str(report.get("volume_uuid")).upper() == expected_uuid
                and report.get("image_bytes") == policy.size and report.get("blocks_verified") == policy.count
                and report.get("trusted_key_sha256") == hashlib.sha256(policy.anchor).hexdigest(), name + ": CI verification metadata differs")
        source_digest = report.get("source_file_sha256", report.get("source_compressed_sha256"))
        require(isinstance(source_digest, str) and len(source_digest) == 64, name + ": CI has no original decrypted image file digest")
        require(sha(image_path) == source_digest, name + ": local decrypted file differs from the actual Mac CI input")
        policy.report = report
        return policy


class RawImage:
    def __init__(self, path, max_decode=128 * MIB):
        self.path, self.max_decode = Path(path), max_decode
        require(self.path.is_file() and self.path.suffix not in (".aea", ".partial"), "Require a complete AEA-decrypted input: " + str(path))
        self.file_size = self.path.stat().st_size
        with self.path.open("rb") as stream:
            first = stream.read(4096)
            require(first[:4] != b"AEA1", "Input is still AEA encrypted")
            stream.seek(-512, 2)
            is_udif = stream.read(4) == b"koly"
        require(is_udif or first[32:36] == b"NXSB" or first[512:520] == b"EFI PART", "Expected genuine UDIF or raw APFS/GPT image")
        self.image = Image(self.path)
        self.size = self.image.size
        require(0 < self.size <= PARTITION_BYTES // 4 and self.size % 512 == 0, "Invalid virtual media size")
        self.chunks = self.image.chunks or [(0, self.size, RAW, 0, self.size)]
        cursor = 0
        for start, length, kind, offset, stored in self.chunks:
            require(start == cursor and length > 0 and length % 512 == 0, "UDIF chunks do not exactly cover ordered sectors")
            require(kind in (ZERO_FILL, IGNORE, RAW, ZLIB, BZIP2, LZFSE), "Unsupported UDIF encoding")
            if kind not in (ZERO_FILL, IGNORE):
                require(offset >= 0 and 0 < stored <= self.file_size - offset, "UDIF stored chunk exceeds input file")
                if kind == RAW:
                    require(stored == length, "Raw UDIF chunk has inconsistent length")
                else:
                    require(length <= max_decode and stored <= max_decode, "Compressed UDIF chunk exceeds bounded decoder budget; use Mac conversion")
            cursor += length
        require(cursor == self.size, "Virtual media is incomplete")

    def extents(self):
        with self.path.open("rb") as stream:
            for _, length, kind, offset, stored in self.chunks:
                if kind in (ZERO_FILL, IGNORE):
                    yield True, length
                    continue
                stream.seek(offset)
                if kind == RAW:
                    remaining = stored
                    while remaining:
                        data = stream.read(min(remaining, 8 * MIB))
                        require(data, "Short raw image read")
                        yield False, data
                        remaining -= len(data)
                    continue
                packed = stream.read(stored)
                require(len(packed) == stored, "Short compressed image read")
                if kind == ZLIB:
                    decoder = zlib.decompressobj()
                    data = decoder.decompress(packed, length + 1)
                    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, "Invalid zlib UDIF stream")
                elif kind == BZIP2:
                    decoder = bz2.BZ2Decompressor()
                    data = decoder.decompress(packed, max_length=length + 1)
                    require(decoder.eof and not decoder.unused_data, "Invalid bzip2 UDIF stream")
                else:
                    import lzfse
                    data = lzfse.decompress(packed)
                require(len(data) == length, "UDIF decoded chunk length differs")
                for at in range(0, length, 8 * MIB):
                    yield False, memoryview(data)[at:at + 8 * MIB]


class MediaVerifier:
    def __init__(self, policy):
        self.policy, self.pending, self.index, self.done = policy, bytearray(), 0, 0
        self.digest = hashlib.sha256()
        self.zero_hash = hashlib.sha256(bytes(BLOCK)).digest()

    def block(self, data, known_zero=False):
        require(self.index < self.policy.count, "More raw integrity blocks than the signed policy")
        actual = self.zero_hash if known_zero and len(data) == BLOCK else hashlib.sha256(data).digest()
        require(actual == self.policy.table[self.index * 32:(self.index + 1) * 32], "Actual raw block differs from policy at " + str(self.index))
        self.index += 1

    def feed(self, data, known_zero=False):
        self.digest.update(data)
        self.done += len(data)
        require(self.done <= self.policy.size, "Raw bytes exceed signed media geometry")
        view, at = memoryview(data), 0
        if self.pending:
            count = min(BLOCK - len(self.pending), len(view))
            self.pending.extend(view[:count])
            at += count
            if len(self.pending) == BLOCK:
                self.block(self.pending)
                self.pending.clear()
        while len(view) - at >= BLOCK:
            self.block(view[at:at + BLOCK], known_zero)
            at += BLOCK
        self.pending.extend(view[at:])

    def finish(self):
        if self.pending:
            self.block(self.pending)
            self.pending.clear()
        require(self.done == self.policy.size and self.index == self.policy.count
                and self.digest.hexdigest() == self.policy.image_sha, "Complete raw digest or signed block count differs")


class SparseWriter:
    def __init__(self, stream, logical_bytes, max_raw=16 * MIB):
        require(logical_bytes > 0 and logical_bytes % BLOCK == 0 and logical_bytes // BLOCK <= 0xFFFFFFFF, "Android sparse capacity overflow or alignment error")
        require(BLOCK <= max_raw <= 64 * MIB and max_raw % BLOCK == 0, "Invalid bounded RAW chunk size")
        self.stream, self.logical_bytes, self.max_raw = stream, logical_bytes, max_raw
        self.buffer, self.blocks, self.chunks, self.raw_bytes, self.fill_bytes = bytearray(), 0, 0, 0, 0
        stream.write(bytes(28))

    @property
    def position(self):
        return self.blocks * BLOCK + len(self.buffer)

    def flush(self):
        require(not len(self.buffer) % BLOCK, "RAW sparse flush must be block aligned")
        if not self.buffer:
            return
        if self.buffer.count(0) == len(self.buffer):
            self.fill(len(self.buffer) // BLOCK)
        else:
            self.stream.write(struct.pack("<2H2I", SPARSE_RAW, 0, len(self.buffer) // BLOCK, 12 + len(self.buffer)))
            self.stream.write(self.buffer)
            self.blocks += len(self.buffer) // BLOCK
            self.chunks += 1
            self.raw_bytes += len(self.buffer)
        self.buffer.clear()

    def fill(self, blocks):
        require(0 < blocks <= 0xFFFFFFFF and (self.blocks + blocks) * BLOCK <= self.logical_bytes, "FILL exceeds target partition")
        self.stream.write(struct.pack("<2H2I", SPARSE_FILL, 0, blocks, 16) + bytes(4))
        self.blocks += blocks
        self.chunks += 1
        self.fill_bytes += blocks * BLOCK

    def write(self, data):
        require(self.position + len(data) <= self.logical_bytes, "RAW write exceeds target partition")
        view, at = memoryview(data), 0
        while at < len(view):
            count = min(self.max_raw - len(self.buffer), len(view) - at)
            self.buffer.extend(view[at:at + count])
            at += count
            if len(self.buffer) == self.max_raw:
                self.flush()

    def zeros(self, count):
        require(count >= 0 and self.position + count <= self.logical_bytes, "Zero extent exceeds target partition")
        if self.buffer and count:
            needed = (-len(self.buffer)) % BLOCK
            taken = min(needed, count)
            self.buffer.extend(bytes(taken))
            count -= taken
            if len(self.buffer) % BLOCK:
                return
            self.flush()
        blocks, tail = divmod(count, BLOCK)
        if blocks:
            self.fill(blocks)
        self.buffer.extend(bytes(tail))

    def finish(self):
        require(self.position == self.logical_bytes, "Sparse output does not cover the whole partition")
        self.flush()
        self.stream.seek(0)
        self.stream.write(struct.pack("<I4H4I", SPARSE_MAGIC, 1, 0, 28, 12, BLOCK, self.logical_bytes // BLOCK, self.chunks, 0))
        self.stream.flush()


def inspect_sparse(path, capacity, expand=False, ranges=()):
    """Reparse actual chunks, refusing DONT_CARE, nonzero fill or omitted tails."""
    require(capacity > 0 and capacity % BLOCK == 0, "Unaligned sparse inspection capacity")
    require(not expand or capacity <= 32 * MIB, "Test expansion is deliberately small")
    expanded, digest, blocks, raw_bytes, fill_bytes = bytearray(), hashlib.sha256(), 0, 0, 0
    head = bytearray()
    checked = [{"row": row, "done": 0, "digest": hashlib.sha256()} for row in ranges]
    zero = bytes(8 * MIB)

    def record_data(start, data=None, zero_length=0):
        length = zero_length if data is None else len(data)
        if start < BLOCK:
            take = min(length, BLOCK - start)
            require(len(head) == start, "Sparse root header is not contiguous")
            head.extend(bytes(take) if data is None else data[:take])
        for item in checked:
            row = item["row"]
            first, last = max(start, row["offset"]), min(start + length, row["offset"] + row["size"])
            if first >= last:
                continue
            require(first == row["offset"] + item["done"], "Sparse range readback is not contiguous")
            count = last - first
            if data is None:
                left = count
                while left:
                    take = min(left, len(zero))
                    item["digest"].update(memoryview(zero)[:take])
                    left -= take
            else:
                item["digest"].update(memoryview(data)[first - start:last - start])
            item["done"] += count
    with path.open("rb") as source:
        header = source.read(28)
        require(len(header) == 28, "Truncated sparse header")
        magic, major, minor, file_header, chunk_header, block, total, count, checksum = struct.unpack("<I4H4I", header)
        require((magic, major, minor, file_header, chunk_header, block, total, checksum) ==
                (SPARSE_MAGIC, 1, 0, 28, 12, BLOCK, capacity // BLOCK, 0), "Sparse header differs from required geometry")
        digest.update(header)
        for _ in range(count):
            item = source.read(12)
            require(len(item) == 12, "Truncated sparse chunk")
            digest.update(item)
            kind, reserved, amount, stored = struct.unpack("<2H2I", item)
            require(not reserved and amount and amount <= total - blocks, "Sparse chunk block count overflow")
            length = amount * BLOCK
            if kind == SPARSE_RAW:
                require(stored == 12 + length and length <= 64 * MIB, "RAW chunk exceeds bounded transport geometry")
                remaining = length
                while remaining:
                    data = source.read(min(remaining, 8 * MIB))
                    require(data, "Sparse RAW data truncated")
                    digest.update(data)
                    record_data(blocks * BLOCK + length - remaining, data)
                    if expand:
                        expanded.extend(data)
                    remaining -= len(data)
                raw_bytes += length
            elif kind == SPARSE_FILL:
                pattern = source.read(4)
                require(stored == 16 and pattern == bytes(4), "Only explicit zero FILL is allowed")
                digest.update(pattern)
                record_data(blocks * BLOCK, zero_length=length)
                if expand:
                    require(capacity <= 32 * MIB, "Test expansion is deliberately small")
                    expanded.extend(bytes(length))
                fill_bytes += length
            else:
                raise ValueError("Forbidden sparse chunk type (including DONT_CARE): " + hex(kind))
            blocks += amount
        require(blocks == total and not source.read(1), "Sparse output omits partition tail or has trailing data")
    for item in checked:
        row = item["row"]
        require(item["done"] == row["size"] and item["digest"].hexdigest() == row["sha256"],
                "Actual sparse output range differs: " + row["name"])
    return {"sha256": digest.hexdigest(), "logical_bytes": capacity, "chunks": count, "raw_bytes": raw_bytes,
            "zero_fill_bytes": fill_bytes, "dont_care_chunks": 0, "every_partition_block_written": True,
            "actual_root_header_sha256": hashlib.sha256(head).hexdigest(),
            "actual_sparse_ranges_hash_verified": [item["row"]["name"] for item in checked]}, bytes(expanded)


def layout(images, policies):
    windows, objects, cursor = [], [], MIB
    for name in ("OS", "SystemOS"):
        windows.append({"name": name, "offset": cursor, "size": images[name].size, "sha256": policies[name].image_sha})
        cursor += align(images[name].size)
    for name in ("OS", "SystemOS"):
        data = policies[name].table
        objects.append({"name": name + ".vroot", "offset": cursor, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        cursor += align(len(data))
    require(len(windows) <= 4 and len(objects) <= 4, "Root entry limit exceeded")
    header = bytearray(BLOCK)
    struct.pack_into("<8sIIQ", header, 0, b"SHNGROOT", 2, len(windows) + len(objects), cursor)
    for index, row in enumerate(windows + objects):
        block, flags = (512, 1) if row in windows else (BLOCK, 3)
        struct.pack_into("<32sQQII32s40s", header, 24 + index * 128, row["name"].encode(), row["offset"], row["size"], block, flags, bytes.fromhex(row["sha256"]), bytes(40))
    header[4064:] = hashlib.sha256(header[:4064]).digest()
    return bytes(header), windows, objects, cursor


def boot_binding(path, policies):
    if path is None:
        return False
    data = path.read_bytes()
    require(len(data) >= 32 and struct.unpack_from("<8sQQQ", data) == (b"VROOTB01", 1, 2, len(data)), "Wrong boot policy bundle")
    cursor, actual = 64, []
    for index in range(2):
        offset, size = struct.unpack_from("<QQ", data, 32 + 16 * index)
        require(offset == cursor and size == 544 and offset + size <= len(data), "Require two bounded header-only boot policies")
        actual.append(data[offset:offset + size])
        cursor += size
    require(cursor == len(data) and sorted(actual) == sorted(policies[name].blob[:544] for name in policies), "Boot policy headers differ from root policy objects")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--build", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--profile", type=Path, default=SOURCE / "profiles/os/ipados-27.0.1-24A446/profile.toml")
    parser.add_argument("--os-dmg", type=Path)
    parser.add_argument("--systemos-dmg", type=Path)
    parser.add_argument("--policies", type=Path)
    parser.add_argument("--boot-policies", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "package/images/userdata27-full.sparse.img")
    parser.add_argument("--userdata-bytes", type=lambda text: int(text, 0), default=PARTITION_BYTES)
    parser.add_argument("--serial", help="Optional private lab metadata; not needed for host image generation")
    parser.add_argument("--max-raw-mib", type=int, default=16)
    parser.add_argument("--openssl", type=Path)
    args = parser.parse_args()
    if args.self_test:
        from test_userdata27_windows import self_test
        self_test(openssl_path(args.openssl))
        return
    require(args.userdata_bytes == PARTITION_BYTES, "This image expects the measured 249497890816-byte userdata capacity")
    require(1 <= args.max_raw_mib <= 64, "RAW transport bound must be 1..64 MiB")
    profile = tomllib.loads(args.profile.read_text(encoding="utf-8"))
    require(profile["os"]["name"] == "ipados-27.0.1-24A446" and profile["ipsw"]["build"] == "24A446", "Wrong OS profile")
    for name, prefix in (("OS", "os"), ("SystemOS", "systemos")):
        require((profile["root"][prefix + "_volume_uuid"].upper(), profile["root"][prefix + "_image_sha256"]) == PINNED[name], "Root pins changed")
    supplied = {"OS": args.os_dmg, "SystemOS": args.systemos_dmg}
    missing = [name + ": original decrypted input missing" for name, path in supplied.items() if path is None or not path.is_file()]
    if args.policies is None:
        missing.append("Mac C/RSA-verified policies directory missing")
    else:
        missing.extend(name + "/" + filename + " missing" for name in PINNED for filename in ("manifest.bin", "trusted-key.bin", "verification.json") if not (args.policies / name / filename).is_file())
    plan = {"build": "24A446", "device": "sheng", "serial": args.serial, "userdata_bytes_expected_not_live_checked": args.userdata_bytes,
            "root_format": "SHNGROOTv2", "sparse_format": "Android RAW/FILL only; every partition block written",
            "explicit_zero_fill_for_entire_unused_partition_tail": True, "partition_clear_applied_to_device": False,
            "DONT_CARE_allowed": False, "missing_inputs": missing,
            "input_readiness_only": not args.build, "device_operations": False, "hardware_tested": False}
    if not args.build:
        plan["decrypted_virtual_sizes"] = {name: RawImage(path).size if path and path.is_file() else None for name, path in supplied.items()}
        print(json.dumps(plan, indent=2))
        return
    require(not missing, "Cannot build without actual inputs: " + "; ".join(missing))
    executable = openssl_path(args.openssl)
    images = {name: RawImage(path) for name, path in supplied.items()}
    policies = {name: Policy.load(name, args.policies, images[name].size, supplied[name], executable) for name in PINNED}
    require(policies["OS"].anchor == policies["SystemOS"].anchor, "Both root policies must share the same actual owner anchor")
    bound = boot_binding(args.boot_policies, policies)
    header, windows, objects, root_bytes = layout(images, policies)
    require(root_bytes + 4 * MIB < args.userdata_bytes // 4, "Root front exceeds conservative protected store separation")
    target = args.output.resolve()
    partial = target.with_suffix(target.suffix + ".partial")
    report_path = target.with_suffix(target.suffix + ".json")
    require(not target.exists() and not partial.exists() and not report_path.exists(), "Preserve existing image/report/partial; choose a new output path")
    target.parent.mkdir(parents=True, exist_ok=True)
    zero = bytes(8 * MIB)
    with partial.open("xb+") as stream:
        writer = SparseWriter(stream, args.userdata_bytes, args.max_raw_mib * MIB)
        writer.write(header)
        for row in windows:
            name = row["name"]
            writer.zeros(row["offset"] - writer.position)
            verifier = MediaVerifier(policies[name])
            for is_zero, extent in images[name].extents():
                if is_zero:
                    remaining = extent
                    while remaining:
                        take = min(remaining, len(zero))
                        verifier.feed(memoryview(zero)[:take], True)
                        remaining -= take
                    writer.zeros(extent)
                else:
                    verifier.feed(extent)
                    writer.write(extent)
            verifier.finish()
            print("PASS local raw", name, verifier.done, verifier.digest.hexdigest(), flush=True)
        for row, name in zip(objects, PINNED):
            writer.zeros(row["offset"] - writer.position)
            writer.write(policies[name].table)
        writer.zeros(args.userdata_bytes - writer.position)
        writer.finish()
        os.fsync(stream.fileno())
    verified, _ = inspect_sparse(partial, args.userdata_bytes, ranges=windows + objects)
    require(verified["logical_bytes"] == args.userdata_bytes and verified["dont_care_chunks"] == 0, "Incomplete clear coverage")
    require(verified["actual_root_header_sha256"] == hashlib.sha256(header).hexdigest(), "Sparse root header readback differs")
    partial.rename(target)
    report = dict(plan, missing_inputs=[], input_readiness_only=False, sparse_image=str(target), sparse_file_bytes=target.stat().st_size,
                  sparse_sha256=verified["sha256"], sparse_validation=verified, root_image_bytes=root_bytes,
                  root_manifest_sha256=hashlib.sha256(header).hexdigest(), windows=windows, objects=objects,
                  signed_UUID_source="actual read-only Mac CI APFS verification, bound to identical complete local raw hashes",
                  owner_anchor_sha256=hashlib.sha256(policies["OS"].anchor).hexdigest(),
                  policy_signatures_verified_by="real OpenSSL RSA3072-PKCS1v1.5-SHA256",
                  all_local_raw_blocks_verified=True, boot_policy_headers_match_verified=bound,
                  live_partition_geometry_verified=False, requires_final_boot_package_and_live_device_checks=True,
                  logical_full_partition_SHA256_not_computed=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
