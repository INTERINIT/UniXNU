"""Resume native/payload using the verified successful phases of one fixed run.

Called by cloud27 on the explicitly dispatched Mac host. No device operation.
The downloaded receipts remain immutable; new phase metadata labels reuse.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


SOURCE_RUN = 41173083070
REPOSITORY = "INTERINIT/sheng-ipados27-build-20261031"
ARTIFACT = "sheng-ipados27-host-result"
DATA_FILES = ("data.dbr", "data-seed.json", "data-stage27.json", "source-root-layout.json", "source-root-manifest.bin")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def selected_artifacts(contract):
    selected = []
    for key in contract["files"]:
        if not key.startswith("package/"):
            continue
        name = key.removeprefix("package/")
        if (name.startswith(("firmware/", "gpu27-", "host-turnip-", "bridge-build-"))
                or name in ("firmware-stage27.json", "gpu27.gpuaddon", "owner-trust27.bundle", "Cargo.lock", "Cargo.toml", "build-ios27.log")):
            selected.append(name)
    return sorted(selected)


def copy_checked(source, destination, expected, sha):
    source, destination = Path(source), Path(destination)
    require(source.is_file() and source.stat().st_size == expected["bytes"] and sha(source) == expected["sha256"],
            "Captured artifact changed before restore: " + source.name)
    if destination.exists():
        require(destination.is_file() and not destination.is_symlink() and sha(destination) == expected["sha256"],
                "Preserve a conflicting restored artifact: " + str(destination))
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    require(sha(destination) == expected["sha256"], "Restored artifact bytes changed: " + str(destination))


def mark_reuse(report, source_prepared):
    for name in ("data", "gpu", "firmware"):
        phase = report["phases"].get(name)
        if phase and phase["status"] == "passed":
            phase.update(reused=True, fresh_build=False, source_run=SOURCE_RUN)
            if name == "firmware":
                phase["fresh_source_preparation"] = source_prepared
    for name in ("native", "payload"):
        if name in report["phases"]:
            report["phases"][name].update(reused=False, fresh_build=True)
    return report


def prepare_firmware_sources(cloud):
    """Prepare source dependencies only; never rebuild/replace the passed FD."""
    firmware = cloud.helper("firmware_stage27")
    ctx = cloud.context()
    uefi = cloud.DEVICE / "uefi-sheng"
    required = [uefi / name for name in ("BootShim/BootShim.S", "Resources/Configs/sheng.toml", "Resources/Scripts/mkbootimg.py")]
    fat = ctx.tree / "package/UniXNUPkg/Driver/UniXNURamDiskDxe/FatWindow.h"
    ready = all(path.is_file() for path in required) and fat.is_file()
    if ready:
        actual = subprocess.check_output(["git", "-C", str(uefi), "rev-parse", "HEAD"], text=True).strip()
        ready = (actual == firmware.PINS["UEFI_PIN"] and cloud.sha(fat) ==
                 "a970191cdb4077522f610d4c967be72eb4fcddde41cf98cb57d8c87dda09826a")
    if ready:
        return False
    output = cloud.RESULT / "firmware-reuse-source-prep"
    require(not output.exists(), "Preserve previous incomplete firmware reuse preparation")
    cloud.run(sys.executable, firmware.SOURCE, "--unixnu", cloud.MAIN, "--device", cloud.DEVICE,
              "--out-root", ctx.out_root, "--output", output, "--patch-root", firmware.PATCH_ROOT,
              "--stage", "prepare", "--jobs", "4")
    require(all(path.is_file() for path in required) and cloud.sha(fat) ==
            "a970191cdb4077522f610d4c967be72eb4fcddde41cf98cb57d8c87dda09826a", "Firmware source preparation did not supply the exact payload dependencies")
    return True


def run(cloud, ctx):
    reuse = cloud.helper("reuse_artifacts27")
    require(reuse.SOURCE_RUN == SOURCE_RUN and cloud.PINS == reuse.PINS, "Resume source/run contract differs")
    downloaded = cloud.WORK / ("reuse-" + str(SOURCE_RUN))
    if not downloaded.exists():
        downloaded.mkdir()
        cloud.run("gh", "run", "download", str(SOURCE_RUN), "--repo", REPOSITORY,
                  "--name", ARTIFACT, "--dir", downloaded)
    source = downloaded / "result27"
    require(source.is_dir(), "The fixed passed-phase artifact was not completely restored")
    cloud.restore_policies(ctx)
    contract = reuse.verify(source, ctx.tree / "build/verified-root-24A446",
                            cloud.MAIN / "profiles/os" / reuse.PROFILE / "profile.toml",
                            ctx.tree / "drivers/DarwinBoot/Test/packed_ramdisk.py", cloud.RESULT / "reuse-audit27")
    # Keep current prepare/research revision and host-preflight receipts.
    current_prepare = json.loads((cloud.RESULT / "prepare.json").read_text())
    captured_prepare = json.loads((source / "prepare.json").read_text())
    require(current_prepare["source_pins"] == captured_prepare["source_pins"]
            and current_prepare["kernelcache_sha256"] == captured_prepare["kernelcache_sha256"]
            and current_prepare["original_trust_sha256"] == captured_prepare["original_trust_sha256"]
            and cloud.sha(cloud.RESULT / "ipsw-trust27.bundle") == reuse.PINNED_FILES["ipsw-trust27.bundle"],
            "Current source preparation/original trust differs from the reusable GPU inputs")
    for name in DATA_FILES:
        copy_checked(source / name, ctx.work / "data-seed" / name, contract["files"]["package/" + name], cloud.sha)
    for name in selected_artifacts(contract):
        copy_checked(source / name, cloud.RESULT / name, contract["files"]["package/" + name], cloud.sha)
    shutil.copy2(source / "prepare.json", cloud.RESULT / "reuse-source-prepare27.json")
    state = {"source_prepared": False}

    def data_reuse():
        # Existing data() checks the unchanged request84a1..., restores the real
        # UUID into actual.config and re-emits its current config-hash receipt.
        state["seed"] = cloud.data(cloud.context())
        require(state["seed"]["packed_sha256"] == reuse.PINNED_FILES["data.dbr"]
                and state["seed"]["volume_uuid"] == contract["data_volume_uuid"], "Reuse unexpectedly changed the successful seed")

    def gpu_reuse():
        cloud.helper("payload_stage27").check_gpu(cloud.RESULT)

    def firmware_reuse():
        receipt = cloud.RESULT / "firmware-stage27.json"
        before = cloud.sha(receipt)
        state["source_prepared"] = prepare_firmware_sources(cloud)
        require(cloud.sha(receipt) == before, "Source preparation changed the passed firmware receipt")
        reuse.check_firmware(cloud.RESULT, cloud.helper("firmware_stage27"))

    report = cloud.package_phases({
        "data": data_reuse,
        "native": lambda: cloud.native("kernel", cloud.context(), seed=state["seed"]),
        "gpu": gpu_reuse,
        "firmware": firmware_reuse,
        "payload": lambda: cloud.helper("payload_stage27").run(
            cloud.MAIN, cloud.DEVICE, cloud.RESULT, cloud.ROOT, ctx=cloud.context(), uefi=cloud.DEVICE / "uefi-sheng",
            execute=True, unique_chip_id=os.environ.get("UNIXNU_UNIQUE_CHIP_ID")),
    }, cloud.RESULT)
    mark_reuse(report, state["source_prepared"])
    (cloud.RESULT / "package-phases27.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "host_verified":
        raise RuntimeError("Resumed native/payload failed; reused artifacts were not reclassified as fresh builds")
    return report
