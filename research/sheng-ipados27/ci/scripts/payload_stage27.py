#!/usr/bin/env python3
"""Draft host-only 24A446 payload/Android-v3 assembly adapter.

Import run(MAIN, DEVICE, RESULT, ROOT, ctx=ctx, uefi=checkout, execute=True)
only after the independent kernel, Data, GPU and firmware stages succeed.
Default execution is an input audit/plan. No device client is used here.
The macOS assembly path has not yet been executed or hardware-qualified.
"""
import argparse
from contextlib import contextmanager
import copy
import hashlib
import hmac
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import tomllib
import uuid
import zlib


SCRIPTS = Path(__file__).resolve().parent
PROFILE = "ipados-27.0.1-24A446"
PINS = {"UniXNU": "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16",
        "UniXNU-sheng": "f47b27ad97e97bee945f8af34a8430e3abcf918c"}
UEFI_PIN = "20ac23d5e0937106c2129303dfc931b3390ae660"
DARWIN_PIN = "3e3a8a969e1177995984d8ed98c9dcc44e318265"
FAT_WINDOW_SHA = "a970191cdb4077522f610d4c967be72eb4fcddde41cf98cb57d8c87dda09826a"
APPLE_KERNEL_SHA = "38e6d9fa5f789b8228f4617ef4c6d2a3fd8ab564abdc9b62920f1db53fc1780a"
MIB, PAGE = 1 << 20, 4096
MAX_BOOT_BYTES = 256 * MIB
MAX_PAYLOAD_MIB = 192
CONFIG = "EFI/UniXNU/unixnu.toml"
PAYLOADS = "EFI/UniXNU/Payloads/"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def helper(name):
    spec = importlib.util.spec_from_file_location("payload27_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_pin(directory, expected):
    actual = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
    require(actual == expected, "Unexpected source revision: " + str(directory))


def arguments(board):
    base = list(board["payload"]["kernel_args"])
    keys = [token.split("=", 1)[0] for token in base]
    require(len(keys) == len(set(keys)) and "sheng-data-reset" not in keys, "Duplicate/reset argument in base recipe")
    updates = {"sheng-data-persist": "2", "sheng-log-reserve": "1024", "sheng-gpu-power": "9",
               "sheng-gpu-metal": "1", "sheng-fb-gpu": "1", "sheng-gpu-addon": "1",
               "sheng-log": "1", "sheng-diag-export": "1", "sheng-autoreset": "0", "cpus": "8"}
    values = [token for token in base if token.split("=", 1)[0] not in updates]
    values += [name + "=" + value for name, value in updates.items()]
    require(all(re.fullmatch(r"[A-Za-z0-9_.\-]+(=[A-Za-z0-9_.,/\-]+)?", item) for item in values), "Unsupported argument spelling")
    line = " ".join(values)
    require(len(line.encode("ascii")) <= 900 and len((line + " sheng-data-reset=1").encode("ascii")) <= 1000,
            "Normal/install command line exceeds the reviewed 900/1000-byte bounds")
    return values


def menu(line):
    """No reset in normal Boot; one explicit Install confirmation adds reset=1."""
    require("sheng-data-reset" not in line and len(line.encode("ascii")) <= 900, "Unsafe or oversized normal boot line")
    common = 'type = "xnu"\npath = "Payloads/kernel.macho"\ninitrd = "Payloads/scratch-data.img"\nargs = ' + json.dumps(line) + '\n'
    return ('version = 1\n[boot]\ntimeout = -1\ndefault = "tools"\n[kits]\nautoload = false\n'
            '[[entry]]\nid = "xnu"\ntitle = "iPadOS 27.0.1 - GPU and persistent Data"\n' + common +
            '[[entry]]\nid = "install"\ntitle = "First install - initialize iPadOS Data"\n'
            'confirm = "ERASE iPadOS Data and initialize this fresh 24A446 seed?"\n'
            'confirm_titles = ["Erase iPadOS Data and boot"]\nconfirm_args = ["sheng-data-reset=1"]\n' + common +
            '[[entry]]\nid = "tools"\ntitle = "Tools"\ntype = "action"\naction = "tools"\n'
            '[[entry]]\nid = "exit"\ntitle = "Return to firmware"\ntype = "action"\naction = "exit"\n'
            '[[entry]]\nid = "reset"\ntitle = "Restart"\ntype = "action"\naction = "reset"\n'
            '[[entry]]\nid = "shutdown"\ntitle = "Power off"\ntype = "action"\naction = "shutdown"\n')


def policy_bundle(path, policy_root):
    data = Path(path).read_bytes()
    require(len(data) == 1152 and struct.unpack_from("<8sQQQ", data) == (b"VROOTB01", 1, 2, len(data)),
            "Require the two actual header-only 27 policies")
    headers, cursor = [], 64
    for index in range(2):
        offset, size = struct.unpack_from("<QQ", data, 32 + 16 * index)
        require(offset == cursor and size == 544 and size <= len(data) - offset, "Noncanonical policy bundle extent")
        headers.append(data[offset:offset + size])
        cursor += size
    require(cursor == len(data) and sorted(headers) == sorted((policy_root / name / "manifest.bin").read_bytes()[:544]
                                                             for name in ("OS", "SystemOS")),
            "Boot signed headers differ from the authenticated root tables")
    return {"sha256": digest(data), "bytes": len(data), "header_only": True, "policy_names": ["OS", "SystemOS"]}


def trust_modules(data):
    require(len(data) >= 4, "Truncated trust bundle")
    count = struct.unpack_from("<I", data)[0]
    require(1 <= count <= 16 and 4 + 4 * count <= len(data), "Invalid trust module count")
    offsets = list(struct.unpack_from("<" + "I" * count, data, 4)) + [len(data)]
    require(offsets[0] == 4 + 4 * count, "Trust bundle table gap")
    result = []
    for start, end in zip(offsets, offsets[1:]):
        require(start < end <= len(data) and end - start >= 24, "Trust module extent outside bundle")
        module = data[start:end]
        version, entries = struct.unpack_from("<I", module)[0], struct.unpack_from("<I", module, 20)[0]
        require(version == 2 and len(module) == 24 + 24 * entries, "Expected bounded version2 trust module")
        result.append(module)
    return result


def addon_files(data):
    require(24 <= len(data) <= 64 * MIB, "GPU addon outside loader bounds")
    magic, count, reserved, total = struct.unpack_from("<8sIIQ", data)
    require(magic == b"NGPUADD2" and 1 <= count <= 512 and reserved == 0 and total == len(data), "Invalid GPU addon header")
    cursor, expanded, files = 24, 0, {}
    for _ in range(count):
        require(cursor + 24 <= len(data), "Truncated addon entry")
        size, mode, raw_bytes, packed_bytes = struct.unpack_from("<IIQQ", data, cursor)
        cursor += 24
        require(1 < size <= 160 and raw_bytes <= 64 * MIB and packed_bytes <= len(data) - cursor,
                "Invalid addon path/content size")
        name_bytes = data[cursor:cursor + size]
        require(len(name_bytes) == size and name_bytes[-1] == 0 and b"\0" not in name_bytes[:-1], "Invalid addon path terminator")
        name = name_bytes[:-1].decode("utf-8")
        require(not name.startswith("/") and "\\" not in name and all(part not in ("", ".", "..") for part in name.split("/"))
                and name not in files and mode in (0o644, 0o755), "Unsafe or repeated addon entry")
        path_end = (cursor + size + 7) & ~7
        require(path_end <= len(data) and not any(data[cursor + size:path_end]), "Invalid addon path padding")
        cursor = path_end
        require(packed_bytes <= len(data) - cursor, "Addon content outside file")
        packed = data[cursor:cursor + packed_bytes]
        decoder = zlib.decompressobj()
        content = decoder.decompress(packed, raw_bytes + 1)
        require(len(content) == raw_bytes and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                "Addon decompression length/stream mismatch")
        expanded += len(content)
        require(expanded <= 64 * MIB, "Expanded addon exceeds loader bounds")
        content_end = cursor + packed_bytes
        cursor = (content_end + 7) & ~7
        require(cursor <= len(data) and not any(data[content_end:cursor]), "Invalid addon content padding")
        files[name] = (mode, content)
    require(cursor == len(data), "Trailing addon bytes")
    require("addons/NativeAdrenoMetal.publish" in files and "addons/NativeAdrenoMetal.bundle/NativeAdrenoMetal" in files
            and "addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib" in files, "GPU publish/plugin/Turnip is missing")
    require(all(name.startswith("addons/") for name in files), "The first27 addon must contain no probe daemon, jobs or wallpaper replacements")
    return files


def check_gpu(result):
    require(load(result / "gpu27-stage-status.json").get("status") == "passed",
            "GPU build and host checks did not complete successfully in this result set")
    trust = load(result / "gpu27-trust.json")
    original = (result / "ipsw-trust27.bundle").read_bytes()
    preparation = load(result / "prepare.json")
    require(preparation.get("source_pins") == PINS and preparation.get("kernelcache_sha256") == APPLE_KERNEL_SHA
            and preparation.get("original_trust_sha256") == digest(original), "Original27 trust provenance differs")
    modules = trust_modules((result / "owner-trust27.bundle").read_bytes())
    require(len(modules) == 3 and modules[:-1] == trust_modules(original), "Owner bundle changed original Apple trust modules")
    wanted = {bytes.fromhex(trust[key]) for key in ("cdhash", "turnip_cdhash")}
    require(len(wanted) == 2 and all(len(item) == 20 for item in wanted), "Expected distinct actual plugin/Turnip CDHashes")
    owner = modules[-1]
    require(struct.unpack_from("<I", owner, 20)[0] == 2
            and {owner[index:index + 20] for index in range(24, len(owner), 24)} == wanted
            and all(owner[index + 20:index + 24] == b"\x02\0\0\0" for index in range(24, len(owner), 24)),
            "Owner trust module must cover exactly the two27 binaries")
    files = addon_files((result / "gpu27.gpuaddon").read_bytes())
    for name in ("NativeAdrenoMetal", "libvulkan_freedreno.dylib"):
        data = files["addons/NativeAdrenoMetal.bundle/" + name][1]
        require(len(data) >= 32 and struct.unpack_from("<2I", data) == (0xfeedfacf, 0x100000c)
                and struct.unpack_from("<I", data, 8)[0] & 0xffffff == 2,
                "Require the actual arm64e27 GPU binary: " + name)
        commands, command_bytes = struct.unpack_from("<2I", data, 16)
        require(commands <= 4096 and 32 + command_bytes <= len(data), "GPU Mach-O command bounds differ")
        cursor, builds = 32, []
        for _ in range(commands):
            require(cursor + 8 <= 32 + command_bytes, "Truncated GPU Mach-O command")
            kind, size = struct.unpack_from("<2I", data, cursor)
            require(size >= 8 and cursor + size <= 32 + command_bytes, "GPU Mach-O command extent differs")
            if kind == 0x32:
                require(size >= 24, "Truncated GPU build version")
                builds.append(struct.unpack_from("<2I", data, cursor + 8))
            cursor += size
        require(cursor == 32 + command_bytes and len(builds) == 1 and builds[0][0] == 2
                and 0x1b0000 <= builds[0][1] < 0x1c0000, "GPU binary is not built for actual iOS27")
    host = load(result / "gpu27-host-checks.json")
    require(host.get("target") == "iPadOS27.0.1 / 24A446" and len(host.get("passed", [])) == 6,
            "Complete the real host transport/cache/watchdog checks before packaging")
    return files, trust


def gpu_signatures(files, trust, directory):
    for name, (mode, data) in files.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
    bundle = directory / "addons/NativeAdrenoMetal.bundle"
    for path, expected in ((bundle, trust["cdhash"]), (bundle / "libvulkan_freedreno.dylib", trust["turnip_cdhash"])):
        subprocess.run(["codesign", "--verify", "--strict", str(path)], check=True, capture_output=True)
        info = subprocess.run(["codesign", "--display", "--verbose=4", str(path)], text=True, capture_output=True, check=True).stderr
        match = re.search(r"^CDHash=([a-f0-9]{40})$", info, re.M)
        require(match and match[1] == expected and re.search(r"^Page size=4096$", info, re.M), "Actual GPU signature/CDHash differs")


def macho_symbol_bytes(data, symbol, length):
    """Read one file-backed symbol from bounded final Mach-O/fileset commands.

    Fileset member linkedit/segment offsets refer to the containing file. Never
    fall back to a native input address or infer a relocation from known bytes.
    """
    pending, seen, hits = [0], set(), set()
    while pending:
        base = pending.pop()
        require(base not in seen and len(seen) < 128 and base + 32 <= len(data), "Cyclic/excessive Mach-O fileset entry")
        seen.add(base)
        magic, cpu, _, kind, count, size = struct.unpack_from("<6I", data, base)
        require(magic == 0xfeedfacf and cpu == 0x100000c and count <= 4096 and base + 32 + size <= len(data),
                "Invalid bounded ARM64 Mach-O header")
        cursor, end, segments, tables, entries = base + 32, base + 32 + size, [], [], []
        for _ in range(count):
            require(cursor + 8 <= end, "Truncated Mach-O command")
            command, command_size = struct.unpack_from("<2I", data, cursor)
            require(command_size >= 8 and cursor + command_size <= end, "Mach-O command outside header")
            if command == 0x19:
                require(command_size >= 72, "Truncated segment64")
                address, virtual_size, offset, file_size = struct.unpack_from("<4Q", data, cursor + 24)
                require(file_size <= virtual_size and offset <= len(data) and file_size <= len(data) - offset,
                        "Mach-O segment outside final file")
                segments.append((address, virtual_size, offset, file_size))
            elif command == 2:
                require(command_size == 24, "Invalid symtab command size")
                tables.append(struct.unpack_from("<4I", data, cursor + 8))
            elif command == 0x80000035:
                require(kind == 12 and command_size >= 32, "Fileset entry outside an actual MH_FILESET")
                offset = struct.unpack_from("<Q", data, cursor + 16)[0]
                name_offset = struct.unpack_from("<I", data, cursor + 24)[0]
                require(32 <= name_offset < command_size and b"\0" in data[cursor + name_offset:cursor + command_size],
                        "Fileset entry identifier outside command")
                entries.append(offset)
            cursor += command_size
        require(cursor == end and len(tables) <= 1, "Ambiguous Mach-O command table")
        for symbols_offset, symbols_count, strings_offset, strings_size in tables:
            require(symbols_count <= len(data) // 16 and symbols_offset <= len(data)
                    and symbols_count * 16 <= len(data) - symbols_offset
                    and strings_offset <= len(data) and strings_size <= len(data) - strings_offset,
                    "Mach-O symbols/strings outside final file")
            strings_end = strings_offset + strings_size
            for index in range(symbols_count):
                name, symbol_type, _, _, address = struct.unpack_from("<IBBHQ", data, symbols_offset + index * 16)
                require(name < strings_size, "Mach-O symbol string index outside table")
                terminator = data.find(b"\0", strings_offset + name, strings_end)
                require(terminator >= 0, "Unterminated Mach-O symbol name")
                if symbol_type & 0xe0 or symbol_type & 0xe != 0xe:
                    continue
                if data[strings_offset + name:terminator] != symbol.encode("ascii"):
                    continue
                ranges = [(offset + address - start, length) for start, _, offset, file_size in segments
                          if start <= address and length <= file_size and address - start <= file_size - length]
                require(len(ranges) == 1, "Symbol is not uniquely file-backed in the actual final Mach-O")
                hits.add(ranges[0])
        pending.extend(entries)
    require(len(hits) == 1, "Expected exactly one actual final symbol extent: " + symbol)
    offset, size = hits.pop()
    return data[offset:offset + size]


def check_data_receipts(seed, native, stage, config, seed_digest, config_digest):
    """Bind existing successful Data/kernel receipts, without invented flags."""
    require(seed.get("os_build") == "24A446" and seed.get("seed17_reused") is False
            and seed.get("original_os_inputs_modified") is False and seed.get("root_capacity_qualified") is True
            and seed.get("data_stage_host_only") is True
            and seed.get("source_verification_level") == "verified raw-image policy plus mounted identity",
            "Require the fresh27 seed with real original-media verification")
    identity = str(uuid.UUID(seed["volume_uuid"])).upper()
    require(seed["volume_uuid"] == identity == config.get("XNU_OWNER_DATA_VOLUME_UUID"),
            "Data UUID differs from the actual kernel .config")
    update = stage.get("config_update", {})
    require(stage.get("target") == PROFILE and stage.get("host_execution_completed") is True
            and stage.get("device_operations") is False and stage.get("fresh_seed_reused_17") is False
            and stage.get("data_seed") == "data.dbr"
            and stage.get("data_seed_sha256") == seed_digest == seed.get("packed_sha256")
            and stage.get("allocation") == seed.get("allocation")
            and stage.get("root_image_bytes") == seed.get("allocation", {}).get("root_image_bytes")
            and stage.get("data_stage_request_sha256") == seed.get("data_stage_request_sha256")
            and update.get("written_to_actual_config") is True
            and update.get("XNU_OWNER_DATA_VOLUME_UUID") == identity
            and update.get("config_sha256") == config_digest,
            "Successful Data-stage seed/UUID/config receipt differs from the actual input")
    require(native.get("stage") == "kernel" and native.get("source_pins") == PINS
            and native.get("data_volume_uuid") == identity and native.get("config_sha256") == config_digest
            and native.get("data_seed_sha256") == seed_digest,
            "Kernel-stage Data/config receipt differs from the actual input")
    return identity


def check_prelink_record(record, kernel_digest, kernel_bytes):
    require(record.get("candidate_written") is True and record.get("candidate_sha256") == kernel_digest
            and record.get("candidate_bytes") == kernel_bytes
            and record.get("inputs", {}).get("kernelcache_sha256") == APPLE_KERNEL_SHA,
            "Actual prelinked kernel differs from its24A446 build record")


def check_generated_uuid(tree, identity):
    # Exact producer: build-xnu-4k-baseline.sh OWNER_DATA_HEADER and PY_DATA_UUID.
    text = (Path(tree) / "build/xnu/owner-data-volume.h").read_text()
    require(re.findall(r'^#define XNU_OWNER_DATA_VOLUME_UUID "([^"]+)"$', text, re.M) == [identity],
            "The actual generated kernel Data UUID header differs")


def check_inputs(main, device, result, root, ctx, uefi):
    main, device, result, root, uefi = [Path(path).resolve() for path in (main, device, result, root, uefi)]
    require(device == main.parent / "UniXNU-sheng" and Path(ctx.root).resolve() == main
            and Path(ctx.device).resolve() == device, "Prepared27 source/context paths differ")
    require(ctx.config_name == "sheng_ipados27_defconfig" and ctx.board["board"]["os_profile"] == PROFILE,
            "Do not reuse a17/26 context")
    for path, pin in ((main, PINS["UniXNU"]), (device, PINS["UniXNU-sheng"]), (uefi, UEFI_PIN),
                      (Path(ctx.tree) / "drivers/DarwinBoot", DARWIN_PIN)):
        check_pin(path, pin)
    require(sha(Path(ctx.tree) / "package/UniXNUPkg/Driver/UniXNURamDiskDxe/FatWindow.h") == FAT_WINDOW_SHA,
            "Require the bounded FAT reader built into this27 firmware")
    seed, native = load(result / "data-seed.json"), load(result / "native-stage27.json")
    seed_path, kernel = result / "data.dbr", result / "kernel.macho"
    from unixnu.config import parse_config
    actual_config = parse_config(Path(ctx.config_path).read_text())
    identity = check_data_receipts(seed, native, load(result / "data-stage27.json"), actual_config,
                                   sha(seed_path), sha(ctx.config_path))
    require(ctx.config.get("XNU_OWNER_DATA_VOLUME_UUID") == identity, "In-memory configuration UUID differs")
    prelink = load(result / "kernel.json")
    check_prelink_record(prelink, sha(kernel), kernel.stat().st_size)
    require(kernel.read_bytes()[:4] == b"\xcf\xfa\xed\xfe", "Kernel is not a real Mach-O")
    check_generated_uuid(ctx.tree, identity)
    profile = tomllib.loads((main / "profiles/os" / PROFILE / "profile.toml").read_text())
    data_stage = helper("data_stage27")
    policy_root, root_plan, _ = data_stage.find_policies(ctx, result, profile)
    anchor = macho_symbol_bytes(kernel.read_bytes(), "_verified_root_key", 395)
    require(anchor == (policy_root / "OS/trusted-key.bin").read_bytes(), "Final kernel carries another owner root anchor")
    require(seed.get("root_manifest_sha256") == root_plan["manifest_sha256"]
            and seed.get("source_root_layout_sha256") == data_stage.json_hash(root_plan)
            and seed.get("os_image_sha256") == profile["root"]["os_image_sha256"],
            "Data seed was made for another authenticated27 root layout")
    binding = policy_bundle(result / "root-policies.bin", policy_root)
    require(binding["sha256"] == native.get("root_policy_bundle_sha256"), "Kernel-linked policy bundle receipt differs")
    actual_bundle = Path(ctx.tree) / "build/sheng-source-storage/root-policies.bin"
    require(actual_bundle.read_bytes() == (result / "root-policies.bin").read_bytes(), "Actual linked policy handoff differs")
    packed = data_stage.helper("payload27_packed", Path(ctx.tree) / "drivers/DarwinBoot/Test/packed_ramdisk.py")
    data_stage.checked_seed(seed_path, seed, packed, seed["data_stage_request_sha256"], seed["allocation"]["logical_bytes"])
    require(seed["allocation"]["tail_reserve_mib"] == 1024 and seed["allocation"]["root_image_bytes"] == root_plan["image_bytes"],
            "Data allocation does not match both actual root policy tables and the1024MiB reserve")
    firmware = result / "firmware"
    manifest, pins = load(firmware / "firmware-manifest.json"), load(firmware / "firmware-source-pins.json")
    firmware_stage = helper("firmware_stage27")
    firmware_stage.check_manifest(manifest)
    receipt = load(result / "firmware-stage27.json")
    require(receipt.get("source_pins") == firmware_stage.PINS and receipt.get("draft_sha256") == sha(firmware_stage.SOURCE)
            and receipt.get("host_fv_and_bootshim_verified") is True and receipt.get("fd_sha256") == manifest["fd_sha256"],
            "Complete the actual new27 firmware stage before payload assembly")
    require(pins.get("main") == PINS["UniXNU"] and pins.get("device") == PINS["UniXNU-sheng"]
            and pins.get("DarwinBoot") == DARWIN_PIN and pins.get("uefi-sheng") == UEFI_PIN,
            "Firmware input source pins differ; no17 FD may be reused")
    require({"SILICIUM_UEFI.fd", "firmware-input.dtb", "firmware-source-pins.json", "fat-window-tests.txt", "ffs-proof.json"}
            <= set(manifest["files"]), "Firmware manifest omits required actual build evidence")
    for name, item in manifest["files"].items():
        require(Path(name).name == name and (firmware / name).stat().st_size == item["bytes"]
                and sha(firmware / name) == item["sha256"], "Firmware manifest file mismatch: " + name)
    require((firmware / "SILICIUM_UEFI.fd").stat().st_size == 0x300000
            and sha(firmware / "SILICIUM_UEFI.fd") == manifest["fd_sha256"], "Actual new27 FD differs")
    require((firmware / "BootShim-fixtures/shim.bin").is_file(), "The actual new firmware BootShim fixture is required")
    files, trust = check_gpu(result)
    power = (device / "package/GpuPowerProbe.cpp").read_text()
    display = (device / "package/LegacyDisplayProbe.cpp").read_text()
    builder = (device / "scripts/build-gop-legacy-display-27.py").read_text()
    require('("sheng-gpu-power"' in power and 'bootArg("sheng-gpu-metal", 0) == 1' in power
            and '"sheng-fb-gpu"' in display and "('GpuPowerProbe'," in builder,
            "Require the board power/Metal/presenter route; do not guess a second service bringup")
    patched_exec = Path(ctx.tree) / ".cache/xnu-work/bsd/kern/kern_exec.c"
    require(patched_exec.is_file() and '"sheng-gpu-addon"' in patched_exec.read_text(), "The actual XNU source lacks the addon mount switch")
    values = arguments(ctx.board)
    return {"main": main, "device": device, "result": result, "root": root, "uefi": uefi,
            "kernel": kernel, "data": seed_path, "seed": seed, "firmware": firmware, "policies": binding,
            "args": values, "addon_files": files, "gpu_trust": trust, "config_sha256": sha(ctx.config_path),
            "owner_anchor_sha256": digest(anchor),
            "kernel_build_qualification": {key: prelink.get(key) for key in
                                           ("mapping_complete", "allow_missing", "runtime_qualified", "loadable")}}


def extract_fat(image, directory):
    directory.mkdir()
    subprocess.run(["mcopy", "-s", "-i", str(image), "::/EFI", str(directory)], check=True, capture_output=True)
    return {str(path.relative_to(directory)).replace("\\", "/"): sha(path)
            for path in directory.rglob("*") if path.is_file()}


def payload_size_mib(content_bytes):
    # Match payload.build's strict95%-content guard, with1MiB allowance for ADT,
    # entry-probe growth, config and FAT metadata. The upstream addon recipe
    # documents192MiB as the working tablet ramdisk size;256MiB did not boot.
    size = max(176, math.ceil((content_bytes + MIB) / (0.95 * MIB)))
    require(size <= MAX_PAYLOAD_MIB, "Kernel/Data/GPU cannot fit the proven192MiB FAT payload cap")
    return size


def check_sealed_kernel(path, report):
    data = Path(path).read_bytes()
    code, size, field = int(report["code_file_offset"], 16), report["code_bytes"], int(report["hmac_file_offset"], 16)
    require(report.get("kernel_sha256") == digest(data) and report.get("runtime_selftests_executed") is False
            and 0 < size <= len(data) and 0 <= code <= len(data) - size and 0 <= field <= len(data) - 32,
            "The actual source-crypto seal report/extent differs")
    expected = hmac.digest(b"\0", data[code:code + size], "sha256")
    require(data[field:field + 32] == expected == bytes.fromhex(report["hmac_sha256"]),
            "The actual copied kernel POST HMAC differs from its code")
    return digest(data)


def prepare_fileset_kernel(ctx, source, output, line, owner_anchor_sha256):
    """Reseal an owned copy through the existing fileset-aware POST tool.

    The legacy entry/panic-screen patcher assumes an MH_EXECUTE-era entry
    padding/symbol layout. Keep it out of this experimental fileset package;
    native27 diagnostics and the reserved UFS log remain available.
    """
    with Path(source).open("rb") as stream:
        header = stream.read(32)
    require(len(header) == 32 and struct.unpack_from("<I", header, 12)[0] == 12, "Require the reviewed27 fileset candidate")
    from unixnu import kernel
    version = kernel.version_env({}, ctx)
    require(version.get("UNIXNU_XNU_ARCH") == "arm64e" and version.get("UNIXNU_IOS_VERSION") == "27.0",
            "Fileset POST tool must run with the actual27 arm64e target")
    source_digest = sha(source)
    destination = Path(output) / "kernel27-sealed.macho"
    require(not destination.exists(), "Preserve the previous sealed payload input")
    shutil.copy2(source, destination)
    tool = Path(ctx.tree) / "scripts/seal-source-crypto-kernel.py"
    with (Path(output) / "kernel27-source-post-seal.log").open("w", encoding="utf-8") as log:
        subprocess.run([sys.executable, str(tool), str(destination), "--kernel-args", line + " sheng-data-reset=1"],
                       env=dict(os.environ, **version), check=True, stdout=log, stderr=subprocess.STDOUT)
    report = load(destination.with_suffix(destination.suffix + ".crypto-hmac.json"))
    sealed_digest = check_sealed_kernel(destination, report)
    require(sha(source) == source_digest and digest(macho_symbol_bytes(destination.read_bytes(), "_verified_root_key", 395))
            == owner_anchor_sha256, "POST packaging changed the original candidate or its trusted owner anchor")
    return destination, {"source_candidate_sha256": source_digest, "payload_input_sha256": sealed_digest,
                         "seal_tool_sha256": sha(tool), "actual_post_hmac_rechecked": True,
                         "legacy_entry_probe_applied": False, "legacy_panic_screen_applied": False,
                         "runtime_selftests_executed": False, "original_candidate_unchanged": True}


@contextmanager
def payload_toolchain():
    from unixnu import kernel
    previous = os.environ.get("PATH")
    os.environ["PATH"] = kernel.toolchain_path(previous)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = previous


def convert_v3(legacy, payload, fd, shim):
    """Use the original gzip/FAT in v3; stock vendor_boot supplies its DTB.

    The official v0 intermediate appends a DTB after its gzip. The successful
    sheng v3 route carries only gzip(BootShim+FD), like the stock v4 firmware
    container, so remove that suffix without changing or recompressing gzip.
    """
    require(len(legacy) >= PAGE and legacy[:8] == b"ANDROID!", "Invalid official legacy container")
    kernel_size, _, ramdisk_size = struct.unpack_from("<3I", legacy, 8)
    require(struct.unpack_from("<2I", legacy, 36) == (PAGE, 0), "The intermediate must be official legacy-v0/4096")
    offset = PAGE + (kernel_size + PAGE - 1) // PAGE * PAGE
    require(0 < len(payload) <= MAX_PAYLOAD_MIB * MIB and struct.unpack_from("<I", legacy, 24)[0] == 0 and ramdisk_size == len(payload)
            and len(legacy) == offset + (ramdisk_size + PAGE - 1) // PAGE * PAGE
            and legacy[offset:offset + ramdisk_size] == payload, "Legacy FAT/extent differs")
    kernel = legacy[PAGE:PAGE + kernel_size]
    require(len(kernel) == kernel_size, "Truncated compressed firmware")
    decoder = zlib.decompressobj(31)
    combined = decoder.decompress(kernel, 4 * MIB + 1)
    require(decoder.eof and not decoder.unconsumed_tail and combined == shim + fd
            and combined[56:60] == b"ARM\x64" and struct.unpack_from("<Q", combined, 16)[0] == len(combined),
            "Original BootShim/FD/header did not round-trip")
    dtb = decoder.unused_data
    require(len(dtb) >= 40 and dtb[:4] == b"\xd0\x0d\xfe\xed" and struct.unpack_from(">I", dtb, 4)[0] == len(dtb),
            "Appended hardware DTB differs")
    kernel = kernel[:-len(dtb)]
    kernel_size = len(kernel)
    outer_cmdline = (legacy[64:576] + legacy[608:1632]).rstrip(b"\0")
    require(len(outer_cmdline) <= 1535 and b"\0" not in outer_cmdline, "Malformed outer boot command line")
    header = bytearray(PAGE)
    header[:8] = b"ANDROID!"
    struct.pack_into("<4I", header, 8, kernel_size, len(payload), struct.unpack_from("<I", legacy, 44)[0], 1580)
    struct.pack_into("<I", header, 40, 3)
    header[44:44 + len(outer_cmdline)] = outer_cmdline
    result = bytes(header) + kernel + bytes((-len(kernel)) % PAGE) + payload + bytes((-len(payload)) % PAGE)
    require(len(result) <= MAX_BOOT_BYTES, "Boot exceeds the conservative256MiB host packaging cap")
    offset = PAGE + (kernel_size + PAGE - 1) // PAGE * PAGE
    require(result[PAGE:PAGE + kernel_size] == kernel and result[offset:offset + len(payload)] == payload, "V3 rehouse changed payload bytes")
    decoder = zlib.decompressobj(31)
    require(decoder.decompress(result[PAGE:PAGE + kernel_size], 4 * MIB + 1) == shim + fd
            and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
            "Final v3 must contain exactly gzip(BootShim+FD), with no appended DTB")
    return result


def run(main, device, result, root, *, ctx, uefi, execute=False, unique_chip_id=None):
    """Audit first; explicit execute=True builds files on a macOS host only."""
    sys.path.insert(0, str(Path(main) / "scripts"))
    inputs = check_inputs(main, device, result, root, ctx, uefi)
    plan = {"draft": True, "target": PROFILE, "kernel_sha256": sha(inputs["kernel"]),
            "data_seed_sha256": sha(inputs["data"]), "data_volume_uuid": inputs["seed"]["volume_uuid"],
            "root_policy_bundle_sha256": inputs["policies"]["sha256"],
            "owner_anchor_sha256": inputs["owner_anchor_sha256"],
            "kernel_build_qualification": inputs["kernel_build_qualification"],
            "gpu_addon_sha256": sha(inputs["result"] / "gpu27.gpuaddon"),
            "owner_trust_sha256": sha(inputs["result"] / "owner-trust27.bundle"),
            "fd_sha256": sha(inputs["firmware"] / "SILICIUM_UEFI.fd"),
            "kernel_args": " ".join(inputs["args"]), "container_header_version": 3,
            "autoboot": False, "normal_boot_resets_data": False, "install_confirmation_arg": "sheng-data-reset=1",
            "device_operations": False, "host_execution_completed": False, "hardware_tested": False}
    if not execute:
        return plan
    require(platform.system() == "Darwin", "The actual payload adapter requires macOS/mtools/Xcode")
    with payload_toolchain():
        return assemble(inputs, plan, ctx, unique_chip_id)


def assemble(inputs, plan, ctx, unique_chip_id):
    """Actual Mac assembly; called only inside the reviewed toolchain scope."""
    require(unique_chip_id and re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", unique_chip_id), "Provide the private platform seed separately; never publish it")
    from unixnu import payload, bootimg
    out = inputs["result"] / "payload27"
    require(not out.exists(), "Preserve an earlier/incomplete payload attempt; select a fresh result directory")
    out.mkdir()
    work = copy.copy(ctx)
    work.work, work.logs, work.uefi = out / "work", out / "logs", inputs["uefi"]
    work.logs.mkdir()
    work.board, work.args = copy.deepcopy(ctx.board), copy.copy(ctx.args)
    work.board["payload"].update(kernel_args=inputs["args"], timeout=-1, tools=True, panic_screen=False, entry_probe_reset_delay=0,
                                 root_policies=str(inputs["result"] / "root-policies.bin"),
                                 install={"title": "First install", "confirm": "Erase iPadOS Data?",
                                          "confirm_titles": ["Erase iPadOS Data and boot"], "confirm_args": ["sheng-data-reset=1"]})
    work.board.setdefault("bootimg", {}).setdefault("image", {})["header_version"] = 0
    for name, value in {"kernel_arg": [], "owner_trust_cache": inputs["result"] / "owner-trust27.bundle", "trust_cache": None,
                        "data_ramdisk": inputs["data"], "skip_setup": False, "gpu_addon": inputs["result"] / "gpu27.gpuaddon",
                        "unique_chip_id": unique_chip_id}.items():
        setattr(work.args, name, value)
    content = sum(path.stat().st_size for path in (inputs["kernel"], inputs["data"], inputs["result"] / "gpu27.gpuaddon",
                  inputs["result"] / "owner-trust27.bundle", inputs["result"] / "root-policies.bin"))
    work.board["payload"]["size_mib"] = payload_size_mib(content)
    prepared_kernel, seal_receipt = prepare_fileset_kernel(work, inputs["kernel"], out, plan["kernel_args"],
                                                          inputs["owner_anchor_sha256"])
    with tempfile.TemporaryDirectory(prefix="payload27-verify-", dir=out) as temporary:
        temp = Path(temporary)
        gpu_signatures(inputs["addon_files"], inputs["gpu_trust"], temp / "gpu")
        image = payload.build(work, kernel=prepared_kernel)
        before = extract_fat(image, temp / "before")
        require(PAYLOADS + "kernel.macho.vroot" in before, "Official payload did not carry the actual vroot sidecar")
        config = temp / "unixnu.toml"
        config.write_text(menu(" ".join(inputs["args"])), encoding="utf-8", newline="\n")
        subprocess.run(["mcopy", "-o", "-i", str(image), str(config), "::/" + CONFIG], check=True, capture_output=True)
        after = extract_fat(image, temp / "after")
        require(before.keys() == after.keys() and all(before[name] == after[name] for name in before if name != CONFIG),
                "Changing the menu altered another payload file")
        payload_report = load(work.work / "payload/payload.json")
        require(after[PAYLOADS + "kernel.macho"] == payload_report["payload_kernel_sha256"]
                == payload_report["kernel_sha256"] == seal_receipt["payload_input_sha256"]
                and sha(inputs["kernel"]) == plan["kernel_sha256"], "Actual staged kernel provenance differs")
        expected = {"kernel.macho.vroot": inputs["result"] / "root-policies.bin", "kernel.macho.trustcache": inputs["result"] / "owner-trust27.bundle",
                    "kernel.macho.gpuaddon": inputs["result"] / "gpu27.gpuaddon", "scratch-data.img": inputs["data"]}
        require(all(after[PAYLOADS + name] == sha(path) for name, path in expected.items()), "Actual FAT sidecar SHA mismatch")
        legacy = bootimg.build(work, inputs["uefi"], inputs["firmware"] / "SILICIUM_UEFI.fd",
                               inputs["firmware"] / "firmware-input.dtb", ramdisk=image, output=out / "intermediate-v0.img")
        raw = convert_v3(legacy.read_bytes(), image.read_bytes(), (inputs["firmware"] / "SILICIUM_UEFI.fd").read_bytes(),
                         (inputs["firmware"] / "BootShim-fixtures/shim.bin").read_bytes())
        final = out / "boot27-v3.img"
        final.write_bytes(raw)
        kernel_bytes, ramdisk_bytes = struct.unpack_from("<2I", raw, 8)
        offset = PAGE + (kernel_bytes + PAGE - 1) // PAGE * PAGE
        final_fat = temp / "final-fat.img"
        final_fat.write_bytes(final.read_bytes()[offset:offset + ramdisk_bytes])
        final_inventory = extract_fat(final_fat, temp / "final")
        require(final_inventory == after and (temp / "final" / (PAYLOADS + "kernel.macho.vroot")).read_bytes()
                == (inputs["result"] / "root-policies.bin").read_bytes(), "Packed boot did not preserve the actual extracted signed policy payload")
        plan.update(host_execution_completed=True, status="host_verified", device="sheng", os_version="27.0.1", os_build="24A446",
                    image_sha256=sha(final), image_bytes=final.stat().st_size,
                    root_policies_sha256=final_inventory[PAYLOADS + "kernel.macho.vroot"],
                    image={"file": final.name, "bytes": final.stat().st_size, "sha256": sha(final)}, header_version=3,
                    normal_cmdline=plan["kernel_args"], gpu_flags=[token for token in inputs["args"]
                                                               if token.startswith(("sheng-gpu-", "sheng-fb-gpu="))],
                    boot_file=final.name,
                    boot_sha256=sha(final), boot_bytes=final.stat().st_size, payload_sha256=sha(final_fat),
                    payload_files=final_inventory, packed_boot_vroot_extracted_and_equal=True,
                    config_sha256=inputs["config_sha256"], gpu_signature_and_cdhash_verified=True)
        plan["kernel_packaging"] = seal_receipt
        plan.update(appended_dtb=False, hardware_dtb_source="unchanged stock vendor_boot",
                    kernel_gzip_sha256=digest(raw[PAGE:PAGE + kernel_bytes]))
        (out / "payload-stage27.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        (out / "boot27.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        shutil.copy2(config, out / "unixnu.toml")
    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    raise SystemExit("Import payload_stage27.run with explicit prepared27 paths/context; default execute=False audits only.")
