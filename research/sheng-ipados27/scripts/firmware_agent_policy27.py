#!/usr/bin/env python3
"""Sign and fully C/RSA-verify both 24A446 root media on a macOS build host.

Inputs are already AEA-decrypted original UDIF or raw APFS images. This script only attaches
them read-only without mounting. It never accesses a tablet, changes a device
partition, converts the original image, or skips a block verification.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
import sys
import tomllib
import uuid


def require(value, message):
    if not value:
        raise RuntimeError(message)


def command(*parts):
    return subprocess.check_output(list(map(str, parts)), stderr=subprocess.PIPE)


def plist(*parts):
    return plistlib.loads(command(*parts))


def file_sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def read_only(info):
    return (info.get("Writable") is False or info.get("ReadOnlyMedia") is True
            or info.get("ReadOnlyVolume") is True or info.get("WritableVolume") is False)


def authenticate_attachment(image, expected_uuid, expected_size):
    """Return only the raw device created by this exact read-only attachment."""
    attached = plist("hdiutil", "attach", "-nomount", "-readonly", "-noverify", "-noautofsck", "-plist", image)
    entities = attached.get("system-entities", [])
    devices = [entry["dev-entry"] for entry in entities if re.fullmatch(r"/dev/disk\d+", entry.get("dev-entry", ""))]
    # APFS may also expose a synthesized /dev/diskM whole container. Prefer
    # the actual image's GUID whole media, as the upstream 17 policy builder
    # does, and authenticate its bus/size before any raw read.
    guided = [entry["dev-entry"] for entry in entities
              if entry.get("content-hint") == "GUID_partition_scheme"
              and entry.get("dev-entry") in devices]
    device = None
    try:
        containers = plist("diskutil", "apfs", "list", "-plist").get("Containers", [])
        stores = {part.get("DeviceIdentifier") for container in containers
                  for part in container.get("PhysicalStores", [])}
        # A raw APFS image has no GPT. In that case the actual image whole
        # node is a PhysicalStore; a synthesized APFS whole container is not.
        raw_stores = [candidate for candidate in devices if Path(candidate).name in stores]
        candidates = []
        for candidate in guided or raw_stores or devices:
            item = plist("diskutil", "info", "-plist", candidate)
            if (item.get("BusProtocol") == "Disk Image" and read_only(item)
                    and item.get("DeviceNode") == candidate and item.get("TotalSize") == expected_size):
                candidates.append((candidate, item))
        require(len(candidates) == 1, "Cannot uniquely authenticate the exact-sized read-only image whole media")
        device, info = candidates[0]
        images = plist("hdiutil", "info", "-plist")["images"]
        exact = [item for item in images if Path(item["image-path"]).resolve() == image.resolve()
                 and item.get("writeable") is False
                 and device in [part.get("dev-entry") for part in item.get("system-entities", [])]]
        require(len(exact) == 1, "The new device is not uniquely tied to this read-only image")
        attached_ids = {Path(item["dev-entry"]).name for item in entities if "dev-entry" in item}
        volumes = []
        for container in containers:
            physical = {part.get("DeviceIdentifier") for part in container.get("PhysicalStores", [])}
            if physical.intersection(attached_ids):
                volumes.extend(container.get("Volumes", []))
        matching = []
        for volume in volumes:
            identifier = volume.get("DeviceIdentifier", "")
            require(re.fullmatch(r"disk\d+s\d+", identifier), "Unexpected APFS volume identifier")
            volume_info = plist("diskutil", "info", "-plist", "/dev/" + identifier)
            actual_uuid = volume_info.get("VolumeUUID", volume.get("APFSVolumeUUID", ""))
            if str(actual_uuid).upper() == str(expected_uuid).upper():
                require(read_only(volume_info), "The matching APFS volume must be read-only")
                matching.append({"device": volume_info.get("DeviceNode"), "volume_uuid": str(expected_uuid).upper(),
                                 "name": volume_info.get("VolumeName", volume.get("Name"))})
        require(len(matching) == 1, "Expected profile UUID is absent or ambiguous within this exact virtual media")
        raw = Path("/dev/r" + Path(device).name)
        require(stat.S_ISCHR(raw.stat().st_mode), "Virtual raw disk is not a character device")
        return device, raw, {"host_bus_protocol": "Disk Image", "host_media_writable": False,
                             "whole_device": device, "volume": matching[0]}
    except Exception:
        for created in ([device] if device else guided):
            subprocess.run(["hdiutil", "detach", created], check=False, capture_output=True)
        raise


class View(ctypes.Structure):
    _fields_ = [("hashes", ctypes.c_void_p), ("image_bytes", ctypes.c_uint64),
                ("block_count", ctypes.c_uint64), ("generation", ctypes.c_uint64),
                ("volume_uuid", ctypes.c_uint8 * 16), ("image_sha256", ctypes.c_uint8 * 32)]


def verify_volume(name, image, expected, output, host, native, manifest, generation):
    require(image.is_file() and image.suffix.lower() != ".aea", name + ": require an existing AEA-decrypted image")
    with image.open("rb") as source:
        beginning = source.read(4096)
        source.seek(-512, 2)
        udif = source.read(4) == b"koly"
    require(udif or beginning[32:36] == b"NXSB" or beginning[512:520] == b"EFI PART",
            name + ": expected original UDIF or raw APFS/GPT image")
    source_format = "AEA-decrypted original UDIF" if udif else "AEA-decrypted original raw APFS/GPT disk image"
    source_digest = file_sha(image)
    image_info = plist("hdiutil", "imageinfo", "-plist", image)
    image_size = image_info["Size Information"]["Total Bytes"]
    require(image_size > 0, "Empty virtual root image")
    output.mkdir(parents=True, exist_ok=True)
    output.joinpath("verification.json").unlink(missing_ok=True)
    expected_uuid = uuid.UUID(expected["uuid"])
    device, raw, attachment = authenticate_attachment(image, expected_uuid, image_size)
    try:
        keys = host / "keys"
        with raw.open("rb", buffering=1 << 20) as source:
            record = manifest.make(source, image_size, keys / "owner.pem", keys / "owner-public.pem",
                                   expected_uuid, generation, output)
        require(record["image_sha256"] == expected["sha256"],
                name + ": actual virtual raw media SHA-256 differs from the pinned OS profile")
        encoded_data = (output / "manifest.bin").read_bytes()
        anchor_data = (output / "trusted-key.bin").read_bytes()
        require(len(anchor_data) == 395, "Require the complete explicit RSA3072 owner anchor")
        encoded, anchor, view = ctypes.create_string_buffer(encoded_data), ctypes.create_string_buffer(anchor_data), View()
        require(native.vr_host_open(encoded, len(encoded_data), anchor, generation, ctypes.byref(view)) == 0,
                name + ": real C/RSA signature authentication failed")
        require(view.image_bytes == image_size and view.block_count == (image_size + 4095) // 4096
                and view.generation == generation and bytes(view.volume_uuid) == expected_uuid.bytes
                and bytes(view.image_sha256).hex() == expected["sha256"],
                name + ": authenticated native C view differs from actual media and profile")
        whole = hashlib.sha256()
        indices = [0, 1, view.block_count // 2, view.block_count - 1]
        samples, lengths = [], []
        with raw.open("rb", buffering=1 << 20) as source:
            for index in range(view.block_count):
                size = min(4096, image_size - index * 4096)
                block = source.read(size)
                require(len(block) == size, name + ": short raw block " + str(index))
                require(native.vr_host_block(ctypes.byref(view), index, block, len(block)) == 0,
                        name + ": actual C block authentication failed at " + str(index))
                whole.update(block)
                if index in indices:
                    samples.append(block.ljust(4096, b"\0"))
                    lengths.append(len(block))
                if (index + 1) % 262144 == 0:
                    print(name, "C-verified", index + 1, "/", view.block_count, "blocks", flush=True)
            require(not source.read(1), "Virtual media exceeds its authenticated exact bounds")
        require(whole.hexdigest() == expected["sha256"] == record["image_sha256"]
                and whole.digest() == bytes(view.image_sha256), name + ": complete second-pass raw digest differs")
        require(file_sha(image) == source_digest, name + ": original decrypted UDIF changed during verification")
        (output / "original-samples.bin").write_bytes(b"".join(samples))
        report = dict(image_bytes=image_size, blocks_verified=view.block_count, image_sha256=whole.hexdigest(),
                      volume_uuid=str(expected_uuid).upper(), generation=view.generation,
                      source_compressed_sha256=source_digest, source_format=source_format,
                      trusted_key_sha256=hashlib.sha256(anchor_data).hexdigest(),
                      actual_sample_indices=indices, actual_sample_lengths=lengths,
                      real_c_signature_and_block_verification=True, original_image_modified=False,
                      host_only=True, boot_root_authenticated=False, qemu_tested=False, hardware_tested=False,
                      **attachment)
        (output / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
        print("PASS", name, "RSA3072 and every", view.block_count, "raw block verified", flush=True)
        return report
    finally:
        subprocess.run(["hdiutil", "detach", device], check=True, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", type=Path, required=True, help="Resolved UniXNU target tree with pinned VerifiedRoot component")
    parser.add_argument("--os-dmg", type=Path, required=True)
    parser.add_argument("--systemos-dmg", type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--openssl-prefix", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--generation", type=int, default=1)
    args = parser.parse_args()
    require(platform.system() == "Darwin", "This complete image-policy build requires macOS hdiutil/diskutil/xcrun")
    require(args.generation > 0, "Positive policy generation required")
    tree = args.tree.resolve()
    profile_path = (args.profile or tree / "profiles/os/ipados-27.0.1-24A446/profile.toml").resolve()
    profile = tomllib.loads(profile_path.read_text())
    require(profile["os"]["name"] == "ipados-27.0.1-24A446" and profile["ipsw"]["build"] == "24A446",
            "Use the reviewed iPadOS 27.0.1 / 24A446 profile, not a renamed older policy")
    expected = {"OS": {"sha256": profile["root"]["os_image_sha256"], "uuid": profile["root"]["os_volume_uuid"]},
                "SystemOS": {"sha256": profile["root"]["systemos_image_sha256"], "uuid": profile["root"]["systemos_volume_uuid"]}}
    output = (args.output or tree / "build/verified-root-24A446").resolve()
    require(output.is_relative_to((tree / "build").resolve()), "Keep generated policies inside this target tree's build directory")
    kit = tree / "kits/VerifiedRoot"
    for name in ("tools/manifest.py", "tests/check.py", "tests/openssl_provider.c", "src/verified_root.c"):
        require((kit / name).is_file(), "Fetch the pinned VerifiedRoot component before building: " + name)
    prefix = args.openssl_prefix or Path(command("brew", "--prefix", "openssl@3").decode().strip())
    os.environ["PATH"] = str(prefix / "bin") + os.pathsep + os.environ["PATH"]
    host = tree / "build/verified-root-host"
    # Always build and exercise the real C parser and OpenSSL RSA provider,
    # including all upstream tamper/refusal tests. Preserve the same owner key
    # across both policies; never publish private files from host/keys/.
    subprocess.run([sys.executable, kit / "tests/check.py", "--output", host, "--openssl-prefix", prefix], check=True)
    checks = json.loads((host / "checks.json").read_text())
    require(checks["real_c_parser"] is True and checks["real_openssl_signature_verification"] is True,
            "Upstream real C/RSA host checks did not pass")
    loader = importlib.util.spec_from_file_location("policy27_manifest", kit / "tools/manifest.py")
    manifest = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(manifest)
    native = ctypes.CDLL(str(host / "verified-root.dylib"))
    native.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(View)]
    native.vr_host_open.restype = ctypes.c_int
    native.vr_host_block.argtypes = [ctypes.POINTER(View), ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
    native.vr_host_block.restype = ctypes.c_int
    reports = {name: verify_volume(name, path.resolve(), expected[name], output / name, host, native, manifest, args.generation)
               for name, path in (("OS", args.os_dmg), ("SystemOS", args.systemos_dmg))}
    anchors = [(output / name / "trusted-key.bin").read_bytes() for name in reports]
    require(anchors[0] == anchors[1] and len(anchors[0]) == 395, "Root policies must share one complete explicit owner anchor")
    summary = {"build": "24A446", "profile": str(profile_path), "profile_sha256": file_sha(profile_path),
               "components": reports, "same_owner_anchor": True, "host_only": True, "device_operations": False,
               "root_media_hash_semantics": "SHA-256 of complete virtual raw disk bytes, not AEA or UDIF file bytes",
               "private_keys_exported": False, "hardware_tested": False}
    (output / "policy27-build.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("PASS: both 24A446 policies fully authenticated; no device operation", flush=True)


if __name__ == "__main__":
    main()
