"""Check fixed build inputs and Mac tools before the single combined build."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


RESEARCH = Path(__file__).resolve().parents[2]
VENDOR_SHA = "a846d86dc6fc471a879ec02f8c8d87ee28dc1329e819f03629662fe0409ff520"
SCRIPTS = ("cloud27", "data_stage27", "seed27", "policy27", "target27", "source_storage27", "reference_exports27", "adreno_fetch27", "ath12k_sources27", "driver_alias27", "gpu_watchdog27", "firmware_stage27", "payload_stage27", "reuse_artifacts27", "resume_package27", "load_inputs27", "seal_outputs27", "host_preflight27")
TOOLS = ("git", "gh", "brew", "xcrun", "xcodebuild", "clang", "clang++", "make", "cmake", "ninja", "unifdef",
         "llvm-nm", "llvm-objcopy", "ld.lld", "mformat", "mcopy", "dtc", "fdtget", "fdtput", "iasl",
         "qemu-system-aarch64", "openssl", "glslc", "spirv-val", "rustup", "hdiutil", "diskutil", "codesign")


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def static_inputs(root):
    require(sys.version_info >= (3, 11), "Python 3.11 or newer is required for the offline checks")
    files = {}
    for name in SCRIPTS:
        path = RESEARCH / "ci/scripts" / (name + ".py")
        ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        files["ci/scripts/" + path.name] = sha(path)
    for name in ("ramdisk-fat-window27.patch", "logger-ram27.patch"):
        path = RESEARCH / "patches/firmware" / name
        require(path.is_file(), "Missing firmware patch: " + name)
        files["patches/firmware/" + name] = sha(path)
    monotonic = RESEARCH / "patches/gpu/watchdog-monotonic.patch"
    require(monotonic.is_file(), "Missing actual watchdog source patch")
    files["patches/gpu/watchdog-monotonic.patch"] = sha(monotonic)
    pin = json.loads((RESEARCH / "evidence/root-policies-24A446.json").read_text(encoding="utf-8"))
    require(pin["run_id"] == 41166392969 and len(pin["files"]) == 6, "Unexpected policy source run")
    vendor = root / "resources/official-vendor/uefi.elf"
    require(vendor.is_file() and vendor.stat().st_size == 2944824 and sha(vendor) == VENDOR_SHA,
            "The exact private vendor input is missing or altered")
    provenance = json.loads(vendor.with_name("provenance.json").read_text(encoding="utf-8"))
    require(provenance["output_sha256"] == VENDOR_SHA and provenance["output_bytes"] == vendor.stat().st_size,
            "Vendor provenance differs")
    return {"code_sha256": files, "vendor_sha256": VENDOR_SHA, "policy_source_run": pin["run_id"]}


def command(parts, *, input_text=None):
    result = subprocess.run(list(map(str, parts)), input=input_text, capture_output=True, text=True, check=False)
    require(result.returncode == 0, "Host preflight command failed: " + str(parts[0]) + "\n" + result.stdout[-3000:] + result.stderr[-3000:])
    return result.stdout.strip()


def mac_tools(root):
    require(platform.system() == "Darwin", "Actual host-tool qualification requires macOS")
    require(sys.version_info >= (3, 13), "Use the workflow's Python 3.13")
    developer = Path(os.environ.get("DEVELOPER_DIR", ""))
    require(developer.is_dir() and (developer / "usr/bin/xcodebuild").is_file(), "Selected full Xcode directory is missing")
    prefixes = [command(["brew", "--prefix", name]) for name in ("llvm", "lld", "openssl@3", "rustup")]
    path_prefixes = [*(str(Path(prefix) / "bin") for prefix in prefixes), str(Path.home() / ".cargo/bin")]
    os.environ["PATH"] = os.pathsep.join([*path_prefixes, os.environ["PATH"]])
    paths = {name: shutil.which(name) for name in TOOLS}
    require(all(paths.values()), "Missing host tools: " + ", ".join(name for name, path in paths.items() if not path))
    sdk = Path(command(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"]))
    sdk_version = command(["xcrun", "--sdk", "iphoneos", "--show-sdk-version"])
    require(sdk.is_dir() and int(sdk_version.split(".")[0]) >= 26, "The reviewed arm64e route needs iPhoneOS SDK 26 or newer")
    # Exercise the actual compiler, SDK and arm64e/minimum-27 flags before any
    # large Apple member download or source-kernel build.
    probe = '#include <stdint.h>\n#include <mach/mach_time.h>\n#import <Foundation/Foundation.h>\n#import <Metal/Metal.h>\n'
    command(["xcrun", "--sdk", "iphoneos", "clang++", "-target", "arm64e-apple-ios27.0", "-isysroot", sdk,
             "-std=c++17", "-fblocks", "-fobjc-arc", "-fsyntax-only", "-x", "objective-c++", "-"], input_text=probe)
    require(re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", os.environ.get("UNIXNU_UNIQUE_CHIP_ID", "")),
            "The private platform seed secret is absent or malformed")
    pin = json.loads((RESEARCH / "evidence/root-policies-24A446.json").read_text(encoding="utf-8"))
    supplied = root / "resources/root-policies-24A446"
    if supplied.exists():
        require(all((supplied / name).is_file() and (supplied / name).stat().st_size == item["bytes"]
                    and sha(supplied / name) == item["sha256"] for name, item in pin["files"].items()),
                "Supplied policies differ from the immutable successful policy artifact")
        policy_access = "authenticated_local_copy"
    else:
        document = json.loads(command(["gh", "api", "repos/" + pin["repository"] + "/actions/runs/" + str(pin["run_id"]) + "/artifacts"]))
        artifacts = [item for item in document["artifacts"] if item["name"] == pin["artifact"] and item.get("expired") is False]
        require(len(artifacts) == 1, "The pinned successful policy artifact is absent, expired or ambiguous")
        policy_access = "passed"
    github_path = os.environ.get("GITHUB_PATH")
    if github_path:
        with Path(github_path).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(path_prefixes) + "\n")
    return {"tools": paths, "path_prefixes": path_prefixes,
            "xcode": command(["xcodebuild", "-version"]), "iphoneos_sdk": sdk_version,
            "arm64e_ios27_sdk_syntax_probe": "passed", "policy_artifact_read_access": policy_access,
            "private_platform_seed_present": True, "disk_free_bytes": shutil.disk_usage(root).free}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Private build checkout, including resources/")
    parser.add_argument("--offline", action="store_true", help="Only fixed local code/input checks; no Mac or network probes")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = {"status": "in_progress", "mode": "offline" if args.offline else "mac_host",
              "device_operations": False, "hardware_tested": False}
    try:
        report["inputs"] = static_inputs(args.root.resolve())
        if not args.offline:
            report["host"] = mac_tools(args.root.resolve())
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", error_type=type(error).__name__, reason=str(error))
        raise
    finally:
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
