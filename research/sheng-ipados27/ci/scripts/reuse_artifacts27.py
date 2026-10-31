#!/usr/bin/env python3
"""Offline reuse contract for the passed phases of package run41173083070.

This reads downloaded files and creates only a small manifest/policy-header
bundle. It does not rebuild native code, create a boot image, run codesign,
contact Actions or access a tablet. Complete native/payload remain required.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import types


SCRIPTS = Path(__file__).resolve().parent
SOURCE_RUN = 41173083070
POLICY_SOURCE_RUN = 41166392969
RESEARCH_REVISION = "48d8d2b88cc2c926d3ad3af6f20f6787d0cdae3f"
PROFILE = "ipados-27.0.1-24A446"
PINS = {"UniXNU": "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16",
        "UniXNU-sheng": "f47b27ad97e97bee945f8af34a8430e3abcf918c"}
PACKER_SHA = "efb5fac21ae94dcb1aecd47da2b73a7112b487e43692ac6396858552d27a0e48"
PINNED_FILES = {
    "data.dbr": "b8433fd0cc979fbc1584a256d5a677b005cffed7d6da620ed18f3e6e1ec50e72",
    "gpu27.gpuaddon": "df489e5fde60c2bd7bd5991b4aa508ce288e41e5e637a738c7ba337e029e69e6",
    "owner-trust27.bundle": "e0207dae366e0894e669808bde985af518a9b862924df12686eff27930957552",
    "ipsw-trust27.bundle": "dc655bcb2ddfaea214f9ec83659b3fc8d8b658bafac2b5a004fb4179a25c89bf",
    "source-root-manifest.bin": "ebf57107c50274b8e05ce0c39a15901329e54e76d9ea351a4d637c3bd1639b07",
    "firmware/SILICIUM_UEFI.fd": "5ea559e296eea36b168f0f6bf680b08142041cfdd0c75cd15c3acacc9b405fb7",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def helper(name):
    spec = importlib.util.spec_from_file_location("reuse27_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def member(root, name):
    root = Path(root).resolve()
    path = root / name
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root), "Missing/escaped reuse file: " + name)
    return path


def verify_pins(root):
    for name, expected in PINNED_FILES.items():
        require(sha(member(root, name)) == expected, "Captured run file SHA-256 differs: " + name)


def packed_module(path):
    # Python universally normalizes source newlines. Record the actual Windows
    # file SHA separately; the LF-normalized source must equal the Mac producer.
    source = Path(path).read_text(encoding="utf-8")
    require(hashlib.sha256(source.encode()).hexdigest() == PACKER_SHA, "The actual Data packing helper source differs")
    module = types.ModuleType("reuse27_packed_ramdisk")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def check_data(root, policies, profile, packing_path, data):
    seed, stage = load(member(root, "data-seed.json")), load(member(root, "data-stage27.json"))
    require(seed.get("os_build") == "24A446" and seed.get("os_version") == "27.0.1"
            and seed.get("data_stage_host_only") is True and seed.get("root_capacity_qualified") is True
            and seed.get("seed17_reused") is False and seed.get("original_os_inputs_modified") is False
            and seed.get("source_verification_level") == "verified raw-image policy plus mounted identity",
            "Data is not the actual passed27 original-media recipe")
    require(stage.get("target") == PROFILE and stage.get("host_execution_completed") is True
            and stage.get("device_operations") is False and stage.get("fresh_seed_reused_17") is False
            and stage.get("data_seed_sha256") == seed.get("packed_sha256") == PINNED_FILES["data.dbr"]
            and stage.get("data_stage_request_sha256") == seed.get("data_stage_request_sha256")
            and stage.get("allocation") == seed.get("allocation")
            and stage.get("config_update", {}).get("written_to_actual_config") is True
            and stage["config_update"].get("XNU_OWNER_DATA_VOLUME_UUID") == seed.get("volume_uuid"),
            "The actual successful Data stage receipt differs")
    identity = seed.get("apfs_identity_verification", {})
    require(identity.get("volume_uuid") == seed["volume_uuid"] and identity.get("logical_bytes") == 8 << 30
            and identity.get("read_only") is True and identity.get("physical_store_bound_to_seed") is True,
            "Require the prior Mac read-only APFS identity/physical-store evidence")
    packing = packed_module(packing_path)
    require(seed.get("packing_helper_sha256") == PACKER_SHA, "The successful Data stage used another packing implementation")
    data.checked_seed(member(root, "data.dbr"), seed, packing, seed["data_stage_request_sha256"], 8 << 30)
    plan, header = data.root_plan(profile, policies)
    require(plan == load(member(root, "source-root-layout.json")) and header == member(root, "source-root-manifest.bin").read_bytes(),
            "Both authenticated policy tables must reproduce this exact Data root layout")
    require(seed.get("root_manifest_sha256") == plan["manifest_sha256"]
            and seed.get("source_root_layout_sha256") == data.json_hash(plan)
            and stage.get("root_image_bytes") == plan["image_bytes"] and seed["allocation"]["tail_reserve_mib"] == 1024,
            "Data allocation/report is for another root layout")
    return seed, plan


def header_bundle(policies):
    headers = []
    for name in ("OS", "SystemOS"):
        with member(policies, name + "/manifest.bin").open("rb") as stream:
            headers.append(stream.read(544))
    return struct.pack("<8sQQQ4Q", b"VROOTB01", 1, 2, 1152, 64, 544, 608, 544) + b"".join(headers)


def check_firmware(root, firmware_helper):
    fw = root / "firmware"
    manifest, receipt = load(member(fw, "firmware-manifest.json")), load(member(root, "firmware-stage27.json"))
    firmware_helper.check_manifest(manifest)
    require(receipt.get("source_pins") == firmware_helper.PINS and receipt.get("fd_sha256") == manifest["fd_sha256"]
            == PINNED_FILES["firmware/SILICIUM_UEFI.fd"] and receipt.get("host_fv_and_bootshim_verified") is True,
            "Require the actual passed firmware phase")
    pins = load(member(fw, "firmware-source-pins.json"))
    require(pins.get("main") == PINS["UniXNU"] and pins.get("device") == PINS["UniXNU-sheng"]
            and pins.get("DarwinBoot") == firmware_helper.PINS["DARWIN_PIN"]
            and pins.get("uefi-sheng") == firmware_helper.PINS["UEFI_PIN"] and pins.get("SHENG_VENDOR_HW") == 0,
            "Passed firmware source/board inputs differ")
    for name, entry in manifest["files"].items():
        require(Path(name).name == name and member(fw, name).stat().st_size == entry["bytes"]
                and sha(fw / name) == entry["sha256"], "Firmware manifest mismatch: " + name)
    shim = load(member(fw, "BootShim-fixtures/report.json"))
    require(shim.get("fd_sha256") == manifest["fd_sha256"] and len(shim.get("qemu", [])) == 2
            and all(item.get("passed") is True for item in shim["qemu"]) and shim.get("qemu_skipped") is False
            and sha(member(fw, "BootShim-fixtures/shim.bin")) == shim.get("shim_sha256"),
            "Exact FD/BootShim copy and already-in-place controls must match")
    return receipt


def verify(artifact_root, policy_root, profile_path, packing_path, output):
    root, policies, output = [Path(value).resolve() for value in (artifact_root, policy_root, output)]
    require(not output.exists(), "Preserve an existing reuse contract; choose a fresh output directory")
    verify_pins(root)
    preparation = load(member(root, "prepare.json"))
    require(preparation.get("source_pins") == PINS and preparation.get("research_revision") == RESEARCH_REVISION,
            "Captured package source pins/research revision differ")
    phases = load(member(root, "package-phases27.json"))["phases"]
    require(all(phases.get(name, {}).get("status") == "passed" for name in ("data", "gpu", "firmware"))
            and phases.get("native", {}).get("status") == "failed" and phases.get("payload", {}).get("status") == "blocked",
            "This contract only reuses the three actually passed phases, never the failed native/payload")
    import tomllib
    profile = tomllib.loads(Path(profile_path).read_text(encoding="utf-8"))
    data, payload, firmware = helper("data_stage27"), helper("payload_stage27"), helper("firmware_stage27")
    seed, plan = check_data(root, policies, profile, packing_path, data)
    files, _ = payload.check_gpu(root)
    recorded = load(member(root, "gpu27-artifacts.json"))
    require(recorded.get("addon_sha256") == PINNED_FILES["gpu27.gpuaddon"]
            and recorded.get("owner_trust_sha256") == PINNED_FILES["owner-trust27.bundle"]
            and recorded.get("files") == {name: {"mode": mode, "bytes": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
                                           for name, (mode, blob) in files.items()}, "Actual addon files differ from the passed GPU artifact receipt")
    clock = load(member(root, "gpu27-watchdog-clock-control.json"))
    watchdog = member(root, "host-turnip-plugin_watchdog.log").read_text(encoding="utf-8")
    require(clock.get("status") == "passed" and "watchdog samples: 1" in watchdog
            and re.search(r"^watchdog: W 6004 .* v", watchdog, re.M), "Captured real clock/stalled-stack controls differ")
    fw_receipt = check_firmware(root, firmware)
    output.mkdir(parents=True)
    bundle = output / "reuse-root-policy-headers.bin"
    bundle.write_bytes(header_bundle(policies))
    binding = payload.policy_bundle(bundle, policies)
    sources = {"package": {"source_run": SOURCE_RUN, "root": str(root)},
               "policies": {"source_run": POLICY_SOURCE_RUN, "root": str(policies)}}
    inventory = {}
    for label, base in (("package", root), ("policies", policies)):
        selected = (list((root / "firmware").rglob("*")) + [path for path in root.iterdir() if path.is_file()
                    and not path.name.startswith("package-native-")]) if label == "package" else [
                        policies / name / part for name in ("OS", "SystemOS")
                        for part in ("manifest.bin", "trusted-key.bin", "verification.json")]
        for path in selected:
            if path.is_file():
                relative = path.relative_to(base).as_posix()
                safe = member(base, relative)
                inventory[label + "/" + relative] = {"bytes": safe.stat().st_size, "sha256": sha(safe)}
    contract = {"status": "offline_reuse_inputs_verified", "source_run": SOURCE_RUN,
                "source_pins": PINS, "research_revision": RESEARCH_REVISION, "sources": sources, "files": inventory,
                "target": PROFILE, "data_volume_uuid": seed["volume_uuid"], "data_seed_sha256": PINNED_FILES["data.dbr"],
                "owner_anchor_sha256": plan["policies"]["OS"]["trusted_key_sha256"],
                "derived_policy_headers": {"file": bundle.name, **binding, "native_link_binding_verified": False},
                "firmware_draft_sha256_from_passed_run": fw_receipt["draft_sha256"],
                "current_windows_checks": ["actual file hashes", "packed seed identity", "policy RSA/header/full-table hashes",
                                           "addon bounds/arm64e27 identities/owner-trust preservation", "firmware manifest/BootShim bytes"],
                "mac_codesign_executed_here": False, "prior_mac_gpu_and_firmware_phases_passed": True,
                "remaining": ["fresh native kernel with this exact Data UUID and owner anchor",
                              "fresh source/UEFI preparation at the pinned revisions; keep reused FD unchanged",
                              "new Mac codesign check and actual final boot FAT/header/sidecar verification"],
                "complete_boot_built": False, "device_operations": False, "hardware_tested": False}
    destination = output / "reuse-inputs27.json"
    destination.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    return contract


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--policy-root", type=Path, required=True, help="Original fully verified policy artifact; not present in the failed package artifact")
    parser.add_argument("--profile", type=Path, default=SCRIPTS.parents[3] / "profiles/os" / PROFILE / "profile.toml")
    parser.add_argument("--packed-module", type=Path, default=SCRIPTS.parents[3] / "drivers/DarwinBoot/Test/packed_ramdisk.py")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(args.artifact_root, args.policy_root, args.profile, args.packed_module, args.output)
    print(json.dumps({key: report[key] for key in ("status", "source_run", "data_volume_uuid", "complete_boot_built", "hardware_tested")}, indent=2))
