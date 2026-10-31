"""Host-only root-layout planning and fresh persistent-Data preparation for 24A446.

Entry point: data(main_checkout, ctx, result_directory, desired_gib=8).
No device client or flashing command is used. No 16 GB raw root is copied.
The APFS creation/mount path has not yet been exercised on a macOS runner.
"""
import hashlib
import hmac
import importlib.util
import json
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

BUILD = "24A446"
PROFILE = "ipados-27.0.1-24A446"
USERDATA_BYTES = 249497890816
MIB, GIB, PAGE = 1 << 20, 1 << 30, 4096
POLICY_HEADER, POLICY_SIGNATURE = 160, 384
POLICY_TABLE_OFFSET = POLICY_HEADER + POLICY_SIGNATURE
SCRIPTS = Path(__file__).resolve().parent


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def json_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def helper(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rsa_header_valid(header, signature, anchor):
    """Recheck the cached public RSA3072/PKCS1v1.5/SHA256 envelope strictly.

    The previous policy phase already ran the real C/RSA provider and every
    actual raw block. This public-key-only cache check never signs anything.
    """
    if len(anchor) != 395 or anchor[:8] != b"VROOTKEY" or anchor[-3:] != b"\x01\0\x01" or len(signature) != 384:
        return False
    modulus = int.from_bytes(anchor[8:392], "big")
    value = int.from_bytes(signature, "big")
    if modulus.bit_length() != 3072 or not modulus & 1 or not 0 < value < modulus:
        return False
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(header).digest()
    expected = b"\0\x01" + b"\xff" * (384 - len(digest_info) - 3) + b"\0" + digest_info
    return hmac.compare_digest(pow(value, 65537, modulus).to_bytes(384, "big"), expected)


def checked_policy(directory, expected_digest, expected_uuid):
    report_path = directory / "verification.json"
    manifest_path = directory / "manifest.bin"
    anchor_path = directory / "trusted-key.bin"
    report = json.loads(report_path.read_text())
    require(report.get("real_c_signature_and_block_verification") is True and report.get("original_image_modified") is False,
            directory.name + ": missing complete prior raw-image C verification")
    anchor = anchor_path.read_bytes()
    require(len(anchor) == 395 and hashlib.sha256(anchor).hexdigest() == report.get("trusted_key_sha256"),
            directory.name + ": cached public anchor differs")
    with manifest_path.open("rb") as stream:
        header, signature = stream.read(POLICY_HEADER), stream.read(POLICY_SIGNATURE)
        require(len(header) == POLICY_HEADER, directory.name + ": truncated policy")
        fields = struct.unpack("<8s4I2Q16s32s32s32sQ", header)
        magic, version, header_bytes, block, reserved, image_bytes, count, identity, digest, table_digest, key_digest, generation = fields
        require((magic, version, header_bytes, block, reserved) == (b"VROOT01\0", 1, 160, PAGE, 0),
                directory.name + ": unsupported policy format")
        require(image_bytes > 0 and count == (image_bytes + PAGE - 1) // PAGE and generation > 0,
                directory.name + ": invalid signed raw geometry")
        require(image_bytes == report.get("image_bytes") and count == report.get("blocks_verified") and generation == report.get("generation"),
                directory.name + ": signed header differs from the complete verification report")
        require(digest.hex() == expected_digest == report.get("image_sha256") and
                str(uuid.UUID(bytes=identity)).upper() == expected_uuid == str(report.get("volume_uuid", "")).upper(),
                directory.name + ": cached policy is for another OS image or UUID")
        require(key_digest == hashlib.sha256(anchor).digest() and rsa_header_valid(header, signature, anchor),
                directory.name + ": cached header RSA authentication failed")
        table_hash, table_bytes = hashlib.sha256(), 0
        while part := stream.read(MIB):
            table_hash.update(part)
            table_bytes += len(part)
        require(table_bytes == count * 32 and table_hash.digest() == table_digest,
                directory.name + ": cached policy table is incomplete or modified")
    return {"name": directory.name, "image_bytes": image_bytes, "image_sha256": expected_digest,
            "volume_uuid": expected_uuid, "generation": generation, "table_bytes": table_bytes,
            "table_sha256": table_digest.hex(), "manifest_sha256": sha(manifest_path),
            "verification_report_sha256": sha(report_path), "trusted_key_sha256": report["trusted_key_sha256"],
            "source_compressed_sha256": report.get("source_compressed_sha256"),
            "source_format": report.get("source_format"), "prior_full_c_block_verification": True,
            "cached_header_rsa_and_table_rechecked": True}


def root_plan(profile, policy_root):
    """Create only SHNGROOTv2 metadata and its exact manifest block."""
    require(profile["os"]["name"] == PROFILE and profile["ipsw"]["build"] == BUILD and profile["ipsw"]["version"] == "27.0.1",
            "Require the reviewed 27.0.1/24A446 profile")
    policies = {}
    for name, stem in (("OS", "os"), ("SystemOS", "systemos")):
        policies[name] = checked_policy(policy_root / name, profile["root"][stem + "_image_sha256"],
                                        str(uuid.UUID(profile["root"][stem + "_volume_uuid"])).upper())
    require(policies["OS"]["trusted_key_sha256"] == policies["SystemOS"]["trusted_key_sha256"],
            "Both policies must use the same public owner anchor")
    cursor, windows, objects = MIB, [], []
    for name, component in (("OS", "OS"), ("SystemOS", "Cryptex1,SystemOS")):
        item = policies[name]
        require(item["image_bytes"] % 512 == 0, "Raw window is not sector aligned")
        windows.append({"name": name, "component": component, "offset": cursor, "size": item["image_bytes"],
                        "sha256": item["image_sha256"]})
        cursor += (item["image_bytes"] + MIB - 1) // MIB * MIB
    for name in ("OS", "SystemOS"):
        item = policies[name]
        objects.append({"name": name + ".vroot", "offset": cursor, "size": item["table_bytes"], "sha256": item["table_sha256"],
                        "source_policy": name, "source_member": "manifest.bin", "source_offset": POLICY_TABLE_OFFSET})
        cursor += (item["table_bytes"] + MIB - 1) // MIB * MIB
    require(cursor < USERDATA_BYTES - (4 * MIB + GIB), "The complete root leaves insufficient guarded Data space")
    header = bytearray(PAGE)
    struct.pack_into("<8sIIQ", header, 0, b"SHNGROOT", 2, len(windows) + len(objects), cursor)
    for index, (row, block, flags) in enumerate([(row, 512, 1) for row in windows] + [(row, PAGE, 3) for row in objects]):
        struct.pack_into("<32sQQII32s40s", header, 24 + 128 * index, row["name"].encode(), row["offset"], row["size"],
                         block, flags, bytes.fromhex(row["sha256"]), bytes(40))
    header[4064:] = hashlib.sha256(header[:4064]).digest()
    plan = {"image_bytes": cursor, "manifest_sha256": hashlib.sha256(header).hexdigest(), "manifest_version": 2,
            "userdata_bytes": USERDATA_BYTES, "windows": windows, "objects": objects, "policies": policies,
            "image_sha256": None, "status": "layout_planned_no_raw_root_copied", "hardware_tested": False,
            "device_operations": False, "all_offsets_relative_to_userdata": True,
            "warning": "This is a complete new userdata layout, not a root17-preserving section update."}
    return plan, bytes(header)


def find_policies(ctx, result, profile):
    candidates = [Path(result) / "root-policies", Path(ctx.tree) / ("build/verified-root-" + BUILD)]
    present = [path for path in candidates if (path / "OS/verification.json").is_file() and (path / "SystemOS/verification.json").is_file()]
    require(present, "Restore the fully verified 24A446 policy cache before the Data stage")
    checked = [(path, *root_plan(profile, path)) for path in present]
    require(all(header == checked[0][2] for _, _, header in checked), "Policy cache copies disagree; preserve them for review")
    return checked[0]


def write_config_uuid(ctx, identity):
    identity = str(uuid.UUID(identity)).upper()
    config_path = Path(ctx.config_path).resolve()
    require(config_path.is_relative_to(Path(ctx.work).resolve()) and config_path.is_file(),
            "Resolved target configuration is absent or outside this context")
    text = config_path.read_text()
    pattern = r'^CONFIG_XNU_OWNER_DATA_VOLUME_UUID="[^"\n]*"$'
    require(len(re.findall(pattern, text, re.M)) == 1, "Expected exactly one real Data UUID config assignment")
    updated = re.sub(pattern, 'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="' + identity + '"', text, flags=re.M)
    if updated != text:
        temporary = config_path.with_name(config_path.name + ".data27.tmp")
        require(not temporary.exists(), "Preserve existing temporary Data configuration")
        temporary.write_text(updated)
        temporary.replace(config_path)
    from unixnu.config import parse_config
    parsed = parse_config(config_path.read_text())
    require(parsed.get("XNU_OWNER_DATA_VOLUME_UUID") == identity, "Data UUID did not persist in the actual config file")
    ctx.config = parsed
    return {"written_to_actual_config": True, "config_sha256": sha(config_path), "XNU_OWNER_DATA_VOLUME_UUID": identity}


def checked_seed(path, metadata, packed, request_key, logical):
    require(metadata.get("data_stage_request_sha256") == request_key and metadata.get("os_build") == BUILD,
            "Preserve cached Data from another recipe, source or allocation")
    require(metadata.get("seed17_reused") is False and metadata.get("original_os_inputs_modified") is False,
            "Cached Data is not the fresh reviewed recipe")
    require(path.is_file() and sha(path) == metadata.get("packed_sha256"), "Cached packed Data SHA-256 mismatch")
    info, header = packed.inspect(path)
    require(info["packed"] and info["bytes"] == logical and header[32:36] == b"NXSB", "Cached APFS Data extent/format differs")
    require(info == metadata.get("packed") and str(uuid.UUID(metadata["volume_uuid"])).upper() == metadata["volume_uuid"],
            "Cached packed identity or generated VolumeUUID differs")
    return info


def data(main, ctx, result, *, desired_gib=8):
    """Use the already-prepared main Context, then persist its new Data UUID."""
    require(platform.system() == "Darwin", "Data creation requires a macOS host; no device operation is available")
    main, result = Path(main).resolve(), Path(result).resolve()
    require(ctx.board["board"]["os_profile"] == PROFILE and ctx.board["ipsw"]["build"] == BUILD,
            "Context targets another OS")
    spec = ctx.board["userdata"]
    require(spec.get("lba_bytes", PAGE) == PAGE and (spec["last_lba"] - spec["first_lba"] + 1) * PAGE == USERDATA_BYTES,
            "Board userdata geometry differs from the measured sheng device")
    profile_path = main / "profiles/os" / PROFILE / "profile.toml"
    profile = tomllib.loads(profile_path.read_text())
    policy_root, plan, header = find_policies(ctx, result, profile)
    result.mkdir(parents=True, exist_ok=True)
    plan_path, header_path = result / "source-root-layout.json", result / "source-root-manifest.bin"
    if header_path.exists():
        require(header_path.read_bytes() == header, "Preserve an existing different root manifest plan")
    header_path.write_bytes(header)
    plan_path.write_text(json.dumps(plan, indent=2) + "\n")
    seed_script = SCRIPTS / "seed27.py"
    packing_path = Path(ctx.tree) / "drivers/DarwinBoot/Test/packed_ramdisk.py"
    grow_tool = Path(ctx.tree) / "scripts/seed-data-grow.py"
    require(seed_script.is_file() and packing_path.is_file() and grow_tool.is_file(), "Fetch the pinned seed/packing/growth helpers")
    seed = helper("stage27_fresh_seed", seed_script)
    packed = helper("stage27_packed_ramdisk", packing_path)
    allocation = seed.choose_size(USERDATA_BYTES, plan["image_bytes"], desired_gib, 1024, 1)
    request = {"recipe": 1, "target": PROFILE, "profile_sha256": sha(profile_path), "root_plan_sha256": json_hash(plan),
               "seed_script_sha256": sha(seed_script), "packing_helper_sha256": sha(packing_path), "grow_helper_sha256": sha(grow_tool),
               "desired_gib": desired_gib, "allocation": allocation}
    request_key = json_hash(request)
    destination, metadata_path = result / "data.dbr", result / "data-seed.json"
    if destination.exists() or metadata_path.exists():
        require(destination.is_file() and metadata_path.is_file(), "Preserve an incomplete cached Data result")
        metadata = json.loads(metadata_path.read_text())
        checked_seed(destination, metadata, packed, request_key, allocation["logical_bytes"])
    else:
        from unixnu.ipsw import Ipsw
        source = Ipsw(ctx)
        # The policy cache deliberately excludes large plain images. Fetch only
        # OS again when necessary, then prove it is byte-identical to the file
        # whose every raw block passed the previous complete C/RSA phase.
        image = source.disk_image("OS").resolve()
        require(image.is_file() and image.is_relative_to(source.cache.resolve()), "OS image escaped the selected IPSW cache")
        image_digest = sha(image)
        require(image_digest == plan["policies"]["OS"]["source_compressed_sha256"],
                "Newly fetched original OS file differs from the fully verified policy source")
        encrypted = image.with_suffix(image.suffix + ".aea")
        if encrypted.exists():
            require(encrypted.resolve().is_relative_to(source.cache.resolve()), "Encrypted input cleanup escaped the cache")
            encrypted.unlink()
        policy_tools = helper("stage27_policy_attachment", SCRIPTS / "policy27.py")
        stage_work = result / "data-stage-work"
        stage_work.mkdir(exist_ok=True)
        seed_output = stage_work / "fresh-seed"
        request_path = stage_work / "request.json"
        if request_path.exists():
            require(json.loads(request_path.read_text()) == request, "Preserve earlier pending Data recipe")
        else:
            request_path.write_text(json.dumps(request, indent=2) + "\n")
        if not (seed_output / "data-seed.json").is_file():
            require(not seed_output.exists(), "Preserve the incomplete seed output before another APFS creation attempt")
            with tempfile.TemporaryDirectory(prefix="data27-os-", dir=stage_work) as temporary:
                mount = Path(temporary) / "os"
                mount.mkdir()
                device, _, attachment = policy_tools.authenticate_attachment(image, profile["root"]["os_volume_uuid"],
                                                                            plan["policies"]["OS"]["image_bytes"])
                try:
                    require(re.fullmatch(r"/dev/disk[0-9]+s[0-9]+", attachment["volume"].get("device", "")),
                            "Expected one authenticated virtual APFS volume device")
                    subprocess.run(["diskutil", "mount", "readOnly", "-mountPoint", str(mount), attachment["volume"]["device"]],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    command = ["sudo", "-n", sys.executable, str(seed_script), "--os-mount", str(mount), "--profile", str(profile_path),
                               "--verified-os-report", str(policy_root / "OS/verification.json"), "--root-report", str(plan_path),
                               "--packed-module", str(packing_path), "--grow-tool", str(grow_tool), "--output-dir", str(seed_output),
                               "--userdata-bytes", str(USERDATA_BYTES), "--desired-gib", str(desired_gib), "--reserve-mib", "1024", "--margin-gib", "1"]
                    with (result / "data-seed-stage.log").open("w") as log:
                        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
                finally:
                    subprocess.run(["hdiutil", "detach", device], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            require(sha(image) == image_digest, "Original plain OS changed during fresh Data preparation")
        metadata = json.loads((seed_output / "data-seed.json").read_text())
        metadata.update(data_stage_request_sha256=request_key, data_stage_recipe=1,
                        source_root_layout_sha256=json_hash(plan), source_os_file_sha256=image_digest,
                        root_capacity_qualified=True, data_stage_host_only=True, host_seed_creation_completed=True,
                        device_operations=False)
        checked_seed(seed_output / "data.dbr", metadata, packed, request_key, allocation["logical_bytes"])
        shutil.copy2(seed_output / "data.dbr", destination)
        metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    config = write_config_uuid(ctx, metadata["volume_uuid"])
    report = {"target": PROFILE, "root_layout": plan_path.name, "root_manifest": header_path.name,
              "root_image_bytes": plan["image_bytes"], "data_seed": destination.name, "data_seed_sha256": sha(destination),
              "allocation": allocation, "config_update": config, "data_stage_request_sha256": request_key,
              "device_operations": False, "hardware_tested": False, "host_execution_completed": True,
              "verified_policy_directory": str(policy_root),
              "root_raw_image_copied": False, "fresh_seed_reused_17": False,
              "first_install": "Initialize once with sheng-data-reset=1 or 2; normal Boot must omit reset."}
    (result / "data-stage27.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: host Data stage, root plan and actual configuration UUID update complete; no device operation.", flush=True)
    return report


if __name__ == "__main__":
    raise SystemExit("Import data_stage27.data(main, ctx, result) from the prepared host pipeline.")
