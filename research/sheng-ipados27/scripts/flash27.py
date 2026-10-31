"""Check, install userdata, or RAM-boot an assembled sheng 24A446 package.

Default check is entirely local. Installation replaces userdata only. Boot
never reflashes it. A concrete, paired package manifest is mandatory.
"""
import argparse
from collections import deque
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import zlib

CAPACITY = 249497890816
ROOT_BYTES = 15753805824
ROOT_SHA = "ebf57107c50274b8e05ce0c39a15901329e54e76d9ea351a4d637c3bd1639b07"
MAX_BOOT_BYTES = 256 * 1024 * 1024
REQUIRED_ARGS = {"sheng-gpu-power": "9", "sheng-gpu-metal": "1", "sheng-gpu-addon": "1",
                 "sheng-fb-gpu": "1", "sheng-data-persist": "2", "sheng-log-reserve": "1024"}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked_file(base, spec):
    require(isinstance(spec, dict) and isinstance(spec.get("path"), str), "Missing package file specification")
    path = (base / spec["path"]).resolve()
    require(path.is_relative_to(base) and path.is_file(), "Missing file or path outside package")
    require(path.stat().st_size == spec.get("bytes") and re.fullmatch(r"[0-9a-f]{64}", spec.get("sha256", "")),
            "File size or digest specification is invalid")
    print("Verifying SHA-256:", path.name, flush=True)
    require(sha(path) == spec["sha256"], "File SHA-256 mismatch: " + path.name)
    return path


def boot_header(path):
    require(path.stat().st_size <= MAX_BOOT_BYTES, "Boot image exceeds the reviewed host container cap")
    with path.open("rb") as stream:
        head = stream.read(4096)
        require(len(head) == 4096 and head[:8] == b"ANDROID!", "Invalid Android boot header")
        kernel, ramdisk, _, header_size = struct.unpack_from("<4I", head, 8)
        require(struct.unpack_from("<I", head, 40)[0] == 3 and header_size == 1580
                and head[24:40] == bytes(16) and 0 < kernel <= 16 * 1024 * 1024
                and 0 < ramdisk <= 192 * 1024 * 1024 and head[44:] == bytes(4096 - 44),
                "Require the reviewed nonempty v3 container")
        extent = 4096 + ((kernel + 4095) // 4096 + (ramdisk + 4095) // 4096) * 4096
        require(extent == path.stat().st_size, "Boot image is truncated or has unexpected trailing data")
        compressed = stream.read(kernel)
        require(len(compressed) == kernel and stream.read((-kernel) % 4096) == bytes((-kernel) % 4096),
                "Truncated compressed firmware or nonzero kernel padding")
        payload, remaining = hashlib.sha256(), ramdisk
        while remaining:
            data = stream.read(min(remaining, 8 * 1024 * 1024))
            require(data, "Truncated payload ramdisk")
            payload.update(data)
            remaining -= len(data)
        require(stream.read((-ramdisk) % 4096) == bytes((-ramdisk) % 4096) and not stream.read(1),
                "Nonzero ramdisk padding or unexpected trailing data")
    decoder = zlib.decompressobj(31)
    combined = decoder.decompress(compressed, 16 * 1024 * 1024 + 1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
            and len(combined) > 0x300000 and len(combined) <= 16 * 1024 * 1024
            and combined[56:60] == b"ARM\x64", "Missing bounded BootShim/FD or unexpected appended data")
    require(struct.unpack_from("<QQ", combined, 8) == (0xA7100000, len(combined)), "BootShim ARM64 load address/extent differs")
    return {"header_version": 3, "ramdisk_bytes": ramdisk,
            "payload_sha256": payload.hexdigest(), "kernel_gzip_sha256": hashlib.sha256(compressed).hexdigest(),
            "fd_sha256": hashlib.sha256(combined[-0x300000:]).hexdigest()}


def normal_arguments(boot):
    line = boot.get("normal_cmdline")
    require(isinstance(line, str) and line == " ".join(line.split()) and len(line.encode("ascii")) <= 900,
            "Missing canonical bounded normal boot command line")
    values = {}
    for token in line.split():
        require(re.fullmatch(r"[A-Za-z0-9_.-]+(?:=[A-Za-z0-9_.,/\-]+)?", token), "Unsupported normal argument")
        name, _, value = token.partition("=")
        require(name not in values and name != "sheng-data-reset", "Duplicate or Data-reset argument in normal Boot")
        values[name] = value
    require(all(values.get(name) == value for name, value in REQUIRED_ARGS.items()), "GPU/persistent-Data arguments differ")
    require(boot.get("kernel_args") == line and boot.get("autoboot") is False
            and boot.get("normal_boot_resets_data") is False, "Normal Boot must preserve Data and wait at the menu")
    return values


def sparse_header(path):
    with path.open("rb") as stream:
        head = stream.read(28)
        require(len(head) == 28, "Truncated sparse header")
        magic, major, minor, file_head, chunk_head, block, blocks, chunks, checksum = struct.unpack("<I4H4I", head)
        require((magic, major, minor, file_head, chunk_head, block, checksum) ==
                (0xED26FF3A, 1, 0, 28, 12, 4096, 0) and blocks * block == CAPACITY and chunks > 0,
                "Unexpected sparse format or full-partition geometry")
        cursor, manifest, raw, fill = 0, None, 0, 0
        for index in range(chunks):
            chunk = stream.read(12)
            require(len(chunk) == 12, "Truncated sparse chunk")
            kind, reserved, count, size = struct.unpack("<2H2I", chunk)
            length = count * block
            require(not reserved and count > 0 and cursor + length <= CAPACITY, "Sparse chunk exceeds the partition")
            if kind == 0xCAC1:
                require(size == 12 + length and length <= 32 * 1024 * 1024 and cursor + length <= ROOT_BYTES,
                        "Invalid RAW chunk or nonzero Data tail")
                if index == 0:
                    manifest = stream.read(4096)
                    stream.seek(length - 4096, 1)
                else:
                    stream.seek(length, 1)
                raw += length
            elif kind == 0xCAC2:
                require(size == 16 and stream.read(4) == bytes(4), "Only zero FILL chunks are permitted")
                fill += length
            else:
                raise ValueError("DONT_CARE and unknown sparse chunks are forbidden")
            cursor += length
        require(cursor == CAPACITY and stream.tell() == path.stat().st_size, "Sparse transport is incomplete or has trailing data")
    require(manifest is not None and len(manifest) == 4096 and manifest[:8] == b"SHNGROOT"
            and hashlib.sha256(manifest).hexdigest() == ROOT_SHA
            and hashlib.sha256(manifest[:4064]).digest() == manifest[4064:]
            and struct.unpack_from("<IIQ", manifest, 8) == (2, 4, ROOT_BYTES),
            "Wrong SHNGROOTv2 manifest or root geometry")
    return {"logical_bytes": cursor, "raw_bytes": raw, "zero_fill_bytes": fill, "dont_care_chunks": 0}


def load_package(base, mode):
    base = Path(base).resolve()
    require(mode in ("check", "install", "boot"), "Unknown package operation")
    require((base / "manifest.json").resolve().is_relative_to(base), "Manifest is outside package")
    document = json.loads((base / "manifest.json").read_text(encoding="utf-8-sig"))
    require(document.get("status") == "assembled" and document.get("device") == "sheng"
            and document.get("os_build") == "24A446" and document.get("os_version") == "27.0.1"
            and document.get("userdata_bytes") == CAPACITY, "Package is incomplete or targets another device/build")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", document.get("target_serial", "")), "Missing explicit local target serial")
    names = ["boot.img", "boot-report.json", "userdata-report.json"]
    if mode != "boot":
        names.append("userdata.sparse.img")
    files = {name: checked_file(base, document.get("files", {}).get(name)) for name in names}
    require(len(set(files.values())) == len(files), "Package file specifications alias each other")
    boot = json.loads(files["boot-report.json"].read_text(encoding="utf-8"))
    root = json.loads(files["userdata-report.json"].read_text(encoding="utf-8"))
    require(boot.get("status") == "host_verified" and boot.get("os_build") == "24A446"
            and boot.get("image_sha256") == document["files"]["boot.img"]["sha256"]
            and boot.get("image_bytes") == document["files"]["boot.img"]["bytes"]
            and boot.get("os_version") == "27.0.1" and boot.get("header_version") == 3
            and boot.get("appended_dtb") is False and boot.get("packed_boot_vroot_extracted_and_equal") is True
            and boot.get("gpu_signature_and_cdhash_verified") is True, "Boot verification receipt is not paired")
    normal_arguments(boot)
    sparse = document.get("files", {}).get("userdata.sparse.img", {})
    require(root.get("all_local_raw_blocks_verified") is True and root.get("boot_policy_headers_match_verified") is True
            and root.get("root_manifest_sha256") == ROOT_SHA
            and root.get("root_image_bytes") == ROOT_BYTES
            and root.get("userdata_bytes_expected_not_live_checked") == CAPACITY
            and root.get("sparse_sha256") == sparse.get("sha256")
            and re.fullmatch(r"[0-9a-f]{64}", sparse.get("sha256", ""))
            and root.get("sparse_file_bytes") == sparse.get("bytes")
            and root.get("boot_policy_bundle_sha256") == boot.get("root_policies_sha256")
            and root.get("owner_anchor_sha256") == boot.get("owner_anchor_sha256")
            and re.fullmatch(r"[0-9a-f]{64}", boot.get("owner_anchor_sha256", ""))
            and re.fullmatch(r"[0-9a-f]{64}", boot.get("root_policies_sha256", "")),
            "Actual boot policies are not paired with the verified userdata image")
    require(re.fullmatch(r"[0-9a-f]{64}", boot.get("data_seed_sha256", ""))
            and re.fullmatch(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", boot.get("data_volume_uuid", "")),
            "Missing actual persistent-Data seed identity")
    actual = boot_header(files["boot.img"])
    require(all(actual[key] == boot.get(key) for key in ("fd_sha256", "payload_sha256", "kernel_gzip_sha256")),
            "Actual boot firmware/payload bytes differ from the host receipt")
    if "userdata.sparse.img" in files:
        require(root.get("sparse_sha256") == document["files"]["userdata.sparse.img"]["sha256"], "Userdata receipt is not paired")
        sparse_header(files["userdata.sparse.img"])
    return document, files


def install_identity(manifest, files):
    boot = json.loads(files["boot-report.json"].read_text(encoding="utf-8"))
    return {"target_serial": manifest["target_serial"], "userdata_sha256": manifest["files"]["userdata.sparse.img"]["sha256"],
            "root_manifest_sha256": ROOT_SHA, "boot_policy_bundle_sha256": boot["root_policies_sha256"],
            "data_seed_sha256": boot["data_seed_sha256"], "data_volume_uuid": boot["data_volume_uuid"]}


def completed_install(state, identity):
    require(state.is_file() and not state.is_symlink(), "No completed local install receipt; install the paired package first")
    receipt = json.loads(state.read_text(encoding="utf-8"))
    require(receipt.get("status") == "completed" and receipt.get("flash_completed") is True
            and all(receipt.get(key) == value for key, value in identity.items()),
            "Installation is incomplete or belongs to other root/Data/target inputs")
    return receipt


def write_install_state(state, receipt, *, create=False):
    """Keep an exclusive intent before flashing, including interrupted attempts."""
    if create:
        with state.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        return
    temporary = state.with_name(state.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, state)


def invoke(tool, arguments, *, stream=False, timeout=45):
    if stream:
        tail = deque(maxlen=60)
        with subprocess.Popen([str(tool), *map(str, arguments)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace", bufsize=1) as process:
            for line in process.stdout:
                print(line.rstrip(), flush=True)
                tail.append(line.rstrip())
            code = process.wait()
        require(code == 0, "fastboot failed (%s):\n%s" % (code, "\n".join(tail)))
        return ""
    result = subprocess.run([str(tool), *map(str, arguments)], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    output = result.stdout + result.stderr
    require(result.returncode == 0, "fastboot failed (%s):\n%s" % (result.returncode, output))
    return output


def variable(tool, serial, name, *, timeout=45):
    output = invoke(tool, ["-s", serial, "getvar", name], timeout=timeout)
    match = re.search(r"(?:\(bootloader\)\s*)?" + re.escape(name) + r":\s*(\S+)", output, re.I)
    require(match is not None, "Missing fastboot variable: " + name)
    return match[1]


def wait_fastboot(tool, serial, *, timeout=120):
    """Wait for a responsive bootloader after USB re-enumeration."""
    deadline = time.monotonic() + timeout
    print("Waiting for bootloader FASTBOOT to reconnect (up to %s seconds)..." % timeout, flush=True)
    # A reboot command can finish before Windows removes the old USB entry.
    time.sleep(min(3, timeout))
    last_error = "target has not appeared in the USB list"
    while time.monotonic() < deadline:
        try:
            listing = invoke(tool, ["devices"], timeout=min(3, deadline - time.monotonic()))
            if re.search(r"^" + re.escape(serial) + r"\s+fastboot\s*$", listing, re.M):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                # Enumeration alone does not mean the new interface is ready.
                variable(tool, serial, "product", timeout=min(3, remaining))
                return
            last_error = "target has not appeared in the USB list"
        except (ValueError, subprocess.TimeoutExpired) as error:
            last_error = str(error)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(1, remaining))
    raise ValueError("FASTBOOT did not become responsive within %s seconds. "
                     "Once the tablet shows FASTBOOT, retry Boot.cmd; do not repeat Flash.cmd. "
                     "Last connection result: %s" % (timeout, last_error))


def device_check(tool, serial, boot_bytes):
    require(variable(tool, serial, "product") == "sheng", "Connected product is not sheng")
    require(variable(tool, serial, "unlocked").lower() in ("yes", "true", "1"), "Bootloader is locked or unknown")
    require(variable(tool, serial, "is-userspace").lower() in ("no", "false", "0"), "Use bootloader FASTBOOT")
    require(int(variable(tool, serial, "partition-size:userdata"), 0) == CAPACITY, "Live userdata geometry differs")
    require(int(variable(tool, serial, "max-download-size"), 0) >= boot_bytes, "Boot image exceeds the live download buffer")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "install", "boot"), nargs="?", default="check")
    parser.add_argument("--package", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--fastboot", type=Path)
    args = parser.parse_args()
    base = args.package.resolve()
    manifest, files = load_package(base, args.mode)
    if args.mode == "check":
        print("PASS: local paired package checks. No device operation.")
        return
    state = base / "install-state.json"
    identity = install_identity(manifest, files)
    if args.mode == "install":
        require(not state.exists() and not state.is_symlink(), "An installation attempt receipt exists; use boot after completion; inspect interrupted attempts before retrying")
    else:
        completed_install(state, identity)
    tool = args.fastboot or Path(r"D:\platform-tools\fastboot.exe")
    if not tool.is_file():
        found = shutil.which("fastboot.exe") or shutil.which("fastboot")
        require(found, "System fastboot was not found")
        tool = Path(found)
    print("Using fastboot:", tool, flush=True)
    print(invoke(tool, ["--version"]).strip(), flush=True)
    serial = manifest["target_serial"]
    device_check(tool, serial, files["boot.img"].stat().st_size)
    if args.mode == "install":
        receipt = dict(identity, status="flashing", flash_completed=False,
                       time=datetime.datetime.now().isoformat(), boot_success="not_tested")
        write_install_state(state, receipt, create=True)
        print("Replacing userdata with the verified 27 root and an explicitly zeroed Data/log tail.", flush=True)
        try:
            invoke(tool, ["-s", serial, "-S", "128M", "flash", "userdata", files["userdata.sparse.img"]], stream=True)
        except BaseException as error:
            receipt.update(status="failed", failure_type=type(error).__name__)
            write_install_state(state, receipt)
            raise
        receipt.update(status="completed", flash_completed=True)
        write_install_state(state, receipt)
    invoke(tool, ["-s", serial, "reboot", "bootloader"])
    wait_fastboot(tool, serial)
    device_check(tool, serial, files["boot.img"].stat().st_size)
    invoke(tool, ["-s", serial, "boot", files["boot.img"]], stream=True)
    print("RAM boot accepted. Observe the tablet; this alone does not prove iPadOS boot success.")
    print("For a fresh Data store only, select the menu's Initialize Data entry once. Normal boots must omit reset.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("STOP:", error, file=sys.stderr)
        raise SystemExit(2)
