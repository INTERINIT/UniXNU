#!/usr/bin/env python3
"""Draft: create a fresh iPadOS 27 Data seed on a macOS build host only.

Never contacts a tablet. No ADB/fastboot commands or imported iPadOS 17 seed.
The mounted source OS must already have passed the selected profile's image
verification. The real generated VolumeUUID must be injected into the kernel
configuration BEFORE compiling that kernel. This draft has not run on macOS.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid

GIB, MIB, BLOCK = 1 << 30, 1 << 20, 4096
EXPECTED_BUILD, EXPECTED_VERSION = "24A446", "27.0.1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def overlay_bytes(logical):
    require(logical > 0 and logical % BLOCK == 0, "Data size is not page aligned")
    pages = logical // BLOCK
    bitmap = (pages + 32767) // 32768
    return (1 + bitmap + pages) * BLOCK


def choose_size(userdata, root_bytes, desired_gib, reserve_mib, margin_gib):
    require(userdata > 0 and userdata % BLOCK == 0, "Invalid userdata capacity")
    require(root_bytes > 0 and root_bytes % BLOCK == 0, "Invalid root image size")
    require(8 <= desired_gib <= 1024 and 0 <= reserve_mib <= 16384 and 0 <= margin_gib <= 16, "Invalid size/reserve/margin")
    root_guard = 4 * MIB
    available = userdata - root_bytes - root_guard - reserve_mib * MIB - margin_gib * GIB
    candidate = min(desired_gib, max(0, available // GIB))
    while candidate and overlay_bytes(candidate * GIB) > available:
        candidate -= 1
    require(candidate >= 8, "Root, guard, reserve and margin leave less than 8 GiB for Data")
    logical = candidate * GIB
    end = userdata - reserve_mib * MIB
    start = end - overlay_bytes(logical)
    require(start >= root_bytes + root_guard + margin_gib * GIB, "Data overlaps root or margin")
    return {"gib": candidate, "logical_bytes": logical, "overlay_bytes": overlay_bytes(logical),
            "start_relative_bytes": start, "end_relative_bytes": end,
            "root_image_bytes": root_bytes, "root_guard_bytes": root_guard,
            "tail_reserve_mib": reserve_mib, "additional_margin_gib": margin_gib,
            "userdata_bytes": userdata, "requested_maximum_gib": desired_gib}


def run(*command):
    print("RUN", *map(str, command), flush=True)
    return subprocess.check_output(list(map(str, command)), text=True)


def plist_command(*command):
    return plistlib.loads(subprocess.check_output(list(map(str, command))))


def read_only(info):
    # diskutil uses Writable/WritableVolume on recent macOS APFS volumes.
    # Keep the same positive read-only evidence accepted by policy27.py;
    # an absent flag alone must never count as read-only.
    return (info.get("Writable") is False or info.get("WritableVolume") is False
            or info.get("ReadOnlyMedia") is True or info.get("ReadOnlyVolume") is True
            or info.get("MediaReadOnly") is True)


def within(base, relative):
    result = base / relative
    require(result.resolve().is_relative_to(base.resolve()), "A Data path follows a symlink outside the new mount: " + relative)
    return result


def merge_pref(mount, home, name, values, mode=0o600):
    path = within(mount, home + "/Library/Preferences/" + name + ".plist")
    path.parent.mkdir(parents=True, exist_ok=True)
    require(not path.is_symlink(), "Refuse a symlink preference file")
    current = plistlib.loads(path.read_bytes()) if path.exists() else {}
    require(isinstance(current, dict), "Preference is not a dictionary: " + name)
    current.update(values)
    path.write_bytes(plistlib.dumps(current, fmt=plistlib.FMT_BINARY))
    path.chmod(mode)
    owner = 501 if home == "mobile" else 0
    os.chown(path, owner, owner)


def copy_var(source, target):
    """Copy symlinks as links and retain the actual source POSIX metadata."""
    shutil.copytree(source, target, symlinks=True, dirs_exist_ok=True,
                    ignore=lambda current, names: {"staged_system_apps"} if Path(current) == source else set())
    for current, directories, files in os.walk(source, followlinks=False):
        if Path(current) == source:
            directories[:] = [name for name in directories if name != "staged_system_apps"]
        for original in [Path(current), *(Path(current) / name for name in directories + files)]:
            copied = target / original.relative_to(source)
            details = original.lstat()
            os.chown(copied, details.st_uid, details.st_gid, follow_symlinks=False)
            if not stat.S_ISLNK(details.st_mode):
                copied.chmod(stat.S_IMODE(details.st_mode))


def fresh_preferences(mount, build):
    directories = ("db/dslocal/nodes/Default/users", "db/dslocal/nodes/Default/groups", "db/dslocal/nodes/Default/config",
                   "containers/Bundle", "containers/Data/System", "containers/Data/Application", "containers/Shared/SystemGroup",
                   "containers/Temp", "PersonaVolumes", "preboot", "root", "tmp", "run", "Library", "keybags/backup",
                   "mobile", "mobile/Library/Preferences", "mobile/Library/Caches", "mobile/Library/Logs", "mobile/Containers",
                   "mobile/Documents", "mobile/Media", "mobile/tmp")
    for relative in directories:
        path = within(mount, relative)
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700 if relative == "root" else 0o755)
        owner = 501 if relative == "mobile" or relative.startswith("mobile/") else 0
        os.chown(path, owner, owner)
    within(mount, "tmp").chmod(0o1777)
    # Keep migration marked complete. The 27 kernel must provide its existing
    # owner-staged-apps=1 read-only view of OS/private/var/staged_system_apps.
    merge_pref(mount, "mobile", "com.apple.migration", {"LastSystemVersion": build,
               "DMUserDataDisposition": {"SyntheticDidUpgrade": False, "buildVersion": build}})
    merge_pref(mount, "mobile", "com.apple.purplebuddy", {"SetupDone": True, "SetupFinishedAllSteps": True,
               "SetupVersion": 11, "daemonizeNeedsToRun": False})
    merge_pref(mount, "mobile", "com.apple.purplebuddy.notbackedup", {name: False for name in (
        "ShouldRunDiagnosticsMiniBuddy", "ShouldRunHSA2MiniBuddy", "ShouldRunKeychainSyncMiniBuddy", "ShouldRunMesaMiniBuddy",
        "ShouldRunPaymentMiniBuddy", "ShouldRunStandardMiniBuddy", "SilentICDPUpgrade")})
    merge_pref(mount, "mobile", "com.apple.managedconfiguration.notbackedup", {"LockdownActivationIndicatesCloudConfigurationAvailable": False})
    merge_pref(mount, "mobile", "com.apple.springboard", {"BKNoWatchdogs": True,
               "FBLaunchWatchdogExceptions": {"com.apple.purplebuddy": 100.0}, "MCForceShowCloudConfigurationUI": False,
               "SBDisableAutoDim": True, "SBDontDimOrLockOnAC": True, "SBDisableIdleSleep": True})
    for home in ("mobile", "root"):
        for name in ("backboardd", ".GlobalPreferences"):
            merge_pref(mount, home, name, {"CAEnableDeepFramebuffer": False, "CAEnableFramebufferCompression": False,
                       "CAEnableIOSurfaceCompression": False}, 0o644)


def physical_device(attachment):
    devices = [e.get("dev-entry", "") for e in attachment["system-entities"]]
    candidates = [d for d in devices if re.fullmatch(r"/dev/disk[0-9]+", d)]
    require(candidates, "hdiutil returned no whole-disk device")
    return candidates[0]


def inspect_packed(module, path, logical):
    report, header = module.inspect(path)
    require(report["packed"] and report["bytes"] == logical, "Packed seed size/format differs")
    require(header[32:36] == b"NXSB", "Packed seed has no APFS container header; inspect sparse-hole support")
    block = int.from_bytes(header[36:40], "little")
    blocks = int.from_bytes(header[40:48], "little")
    require(block == BLOCK and logical - 64 * MIB <= blocks * block <= logical, "APFS container size differs")
    return report


def verify_grown_uuid(module, packed, work, expected_uuid):
    logical, extents = module.regions(packed.read_bytes())
    raw = work / "grown-verification.raw"
    with raw.open("xb") as stream:
        stream.truncate(logical)
        for offset, data in extents:
            stream.seek(offset)
            stream.write(data)
    attached = plist_command("hdiutil", "attach", "-readonly", "-nomount", "-nobrowse", "-imagekey", "diskimage-class=CRawDiskImage", "-plist", raw)
    physical = physical_device(attached)
    try:
        listing = plist_command("diskutil", "apfs", "list", "-plist")
        containers = [entry for entry in listing["Containers"] if any(
            store["DeviceIdentifier"] == physical.removeprefix("/dev/") for store in entry.get("PhysicalStores", []))]
        require(len(containers) == 1, "Cannot identify the grown seed's APFS container")
        volumes = containers[0].get("Volumes", [])
        require(len(volumes) == 1 and str(uuid.UUID(volumes[0]["APFSVolumeUUID"])).upper() == expected_uuid,
                "Data VolumeUUID changed while growing or the wrong image was attached")
    finally:
        run("hdiutil", "detach", physical)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os-mount", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--initial-only", action="store_true", help="Create only the fresh 8 GiB seed; defer root-layout capacity qualification")
    parser.add_argument("--verified-os-report", type=Path)
    parser.add_argument("--root-report", type=Path)
    parser.add_argument("--packed-module", type=Path, required=True)
    parser.add_argument("--grow-tool", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--userdata-bytes", type=int, required=True)
    parser.add_argument("--desired-gib", type=int, default=215, help="Maximum desired size; reduce if actual root/reserve/margin needs room")
    parser.add_argument("--reserve-mib", type=int, default=1024)
    parser.add_argument("--margin-gib", type=int, default=1)
    parser.add_argument("--expected-launchd-sha256")
    args = parser.parse_args()
    require(platform.system() == "Darwin", "macOS hdiutil/diskutil are required; no seed was created")
    require(os.geteuid() == 0, "Run this host-only script with sudo to preserve original POSIX ownership in the fresh seed")
    profile = tomllib.loads(args.profile.read_text())
    root = json.loads(args.root_report.read_text()) if args.root_report else {}
    verified = json.loads(args.verified_os_report.read_text()) if args.verified_os_report else None
    require(profile["ipsw"]["build"] == EXPECTED_BUILD and profile["ipsw"]["version"] == EXPECTED_VERSION, "This draft requires reviewed 27.0.1/24A446 inputs")
    expected = profile["root"]
    if verified is not None:
        require(verified.get("real_c_signature_and_block_verification") is True and
                verified.get("image_sha256") == expected["os_image_sha256"] and
                verified.get("volume_uuid", "").upper() == expected["os_volume_uuid"], "OS policy report does not verify the selected 27 image")
    if args.initial_only:
        allocation = {"gib": 8, "logical_bytes": 8 * GIB, "userdata_bytes": args.userdata_bytes,
                      "tail_reserve_mib": args.reserve_mib, "root_capacity_qualification": "deferred; actual complete 27 root layout is still required"}
    else:
        require(args.root_report is not None and verified is not None and args.grow_tool is not None,
                "Growth requires root report, verified OS report and pinned grow helper")
        by_name = {row["name"]: row for row in root["windows"]}
        require(all(by_name.get(name, {}).get("sha256") == expected[key] for name, key in (
            ("OS", "os_image_sha256"), ("SystemOS", "systemos_image_sha256"))), "Root layout is not made from the selected 27 OS/SystemOS")
        require(by_name["OS"]["size"] == verified["image_bytes"], "Root OS size differs from the actual verified raw image")
        require({"OS.vroot", "SystemOS.vroot"}.issubset({row["name"] for row in root.get("objects", [])}),
                "Root size must include both policy-table objects selected by the 27 source-storage config")
        require(root.get("userdata_bytes") == args.userdata_bytes, "Root report/device capacity differ")
        allocation = choose_size(args.userdata_bytes, root["image_bytes"], args.desired_gib, args.reserve_mib, args.margin_gib)
    source = args.os_mount.resolve()
    info = plist_command("diskutil", "info", "-plist", source)
    mount_evidence = {key: info[key] for key in (
        "DeviceNode", "VolumeUUID", "MountPoint", "BusProtocol", "Writable", "WritableVolume",
        "ReadOnlyMedia", "ReadOnlyVolume", "MediaReadOnly") if key in info}
    print("SOURCE_MOUNT", json.dumps(mount_evidence, sort_keys=True), flush=True)
    require(read_only(info), "Original OS mount is not read-only")
    require(str(uuid.UUID(info["VolumeUUID"])).upper() == expected["os_volume_uuid"], "Mounted original OS UUID differs")
    version = plistlib.loads((source / "System/Library/CoreServices/SystemVersion.plist").read_bytes())
    require(version.get("ProductBuildVersion") == EXPECTED_BUILD and version.get("ProductVersion") == EXPECTED_VERSION,
            "Mounted OS SystemVersion is not 27.0.1/24A446")
    launchd_hash = sha(source / "sbin/launchd")
    if args.expected_launchd_sha256:
        require(launchd_hash == args.expected_launchd_sha256, "Original launchd SHA-256 differs")
    var = (source / "private/var").resolve()
    require(var.is_dir() and var.is_relative_to(source), "OS/private/var is absent or outside the verified mount")
    require((var / "staged_system_apps").is_dir(), "Expected 27 staged system apps are absent; review this OS resource before making a seed")
    out = args.output_dir.resolve()
    require(not out.exists() and not out.is_relative_to(source), "Refuse to overwrite an existing output or write inside OS mount")
    require(args.packed_module.is_file(), "Pinned packing helper is missing")
    require(args.grow_tool is None or args.grow_tool.is_file(), "Pinned growth helper is missing")
    spec = importlib.util.spec_from_file_location("reviewed_packed_ramdisk", args.packed_module)
    packed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packed)
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="fresh27-", dir=out) as temporary:
        work = Path(temporary)
        raw, mount = work / "fresh-data-8g.cdr", work / "mount"
        run("hdiutil", "create", "-size", "8g", "-layout", "NONE", "-fs", "APFS", "-volname", "OwnerData27", "-type", "UDTO", raw)
        require(raw.stat().st_size == 8 * GIB, "Unexpected initial Data image extent")
        mount.mkdir()
        attached = plist_command("hdiutil", "attach", "-nobrowse", "-owners", "on", "-mountpoint", mount, "-plist", raw)
        physical = physical_device(attached)
        try:
            mounted = plist_command("diskutil", "info", "-plist", mount)
            volume_uuid = str(uuid.UUID(mounted["VolumeUUID"])).upper()
            copy_var(var, mount)
            fresh_preferences(mount, EXPECTED_BUILD)
        finally:
            run("hdiutil", "detach", physical)
        base = out / "fresh27-base-8g.dbr"
        packed.pack(raw, base)
        base_info = inspect_packed(packed, base, 8 * GIB)
        final = out / "data.dbr"
        if allocation["gib"] == 8:
            shutil.copyfile(base, final)
        else:
            # The helper itself creates another sparse raw host file, never a tablet block device.
            (args.grow_tool.resolve().parents[1] / "build").mkdir(exist_ok=True)
            growth_log = run(sys.executable, args.grow_tool, "--gib", allocation["gib"], "--reserve-mib", args.reserve_mib, base, final)
            (out / "grow.log").write_text(growth_log)
        final_info = inspect_packed(packed, final, allocation["logical_bytes"])
        verify_grown_uuid(packed, final, work, volume_uuid)
    report = {"draft_host_generator": True, "hardware_tested": False, "device_operations": False,
              "os_build": EXPECTED_BUILD, "os_version": EXPECTED_VERSION, "volume_uuid": volume_uuid,
              "logical_data_gib": allocation["gib"],
              "kernel_config_required": {"XNU_OWNER_DATA_VOLUME_UUID": volume_uuid}, "allocation": allocation,
              "base": base_info, "packed": final_info, "packed_sha256": sha(final),
              "original_launchd_sha256": launchd_hash, "os_image_sha256": expected["os_image_sha256"],
              "root_manifest_sha256": root.get("manifest_sha256"), "seed17_reused": False, "initial_only": args.initial_only,
              "source_verification_level": "verified raw-image policy plus mounted identity" if verified is not None else
                  "mounted read-only OS UUID, SystemVersion and recorded launchd hash only; CI must separately verify original OS raw-image SHA",
              "source_mount_readonly_evidence": mount_evidence,
              "original_os_inputs_modified": False, "setup_marked_complete": True, "migration_marked_build": EXPECTED_BUILD,
              "staged_apps": "excluded from seed; requires owner-staged-apps=1 read-only OS view in matched 27 kernel",
              "gpu_preferences": "deep framebuffer and surface/framebuffer compression disabled; this does not enable GPU hardware",
              "normal_boot_required": ["sheng-data-persist=2", "sheng-log-reserve=" + str(args.reserve_mib)],
              "first_install_required": "initialize once with sheng-data-reset=1 or 2; subsequent normal boots MUST omit reset",
              "packing_helper_sha256": sha(args.packed_module), "grow_helper_sha256": sha(args.grow_tool) if args.grow_tool else None}
    (out / "data-seed.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
