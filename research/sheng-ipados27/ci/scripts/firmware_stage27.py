#!/usr/bin/env python3
"""Host-only adapter for the pinned27 firmware draft.

cloud27 integration: firmware_stage27.run(MAIN, DEVICE, RESULT, ROOT, ctx=ctx).
Install the ordinary firmware dependencies plus acpica and qemu on macOS.
The code/patch paths come from this research checkout; private vendor inputs
come only from ROOT/resources/official-vendor. No17 FD is accepted as input.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


RESEARCH = Path(__file__).resolve().parents[2]
SOURCE = RESEARCH / "scripts/firmware27_draft.py"
PATCH_ROOT = RESEARCH / "patches/firmware"
PINS = {
    "MAIN_PIN": "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16",
    "DEVICE_PIN": "f47b27ad97e97bee945f8af34a8430e3abcf918c",
    "DARWIN_PIN": "3e3a8a969e1177995984d8ed98c9dcc44e318265",
    "UEFI_PIN": "20ac23d5e0937106c2129303dfc931b3390ae660",
    "PROFILE": "ipados-27.0.1-24A446",
}
VENDOR_SHA = "a846d86dc6fc471a879ec02f8c8d87ee28dc1329e819f03629662fe0409ff520"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reviewed_source():
    """Read constants without importing or executing the draft."""
    require(SOURCE.is_file() and PATCH_ROOT.is_dir(), "Canonical firmware source/patches are missing")
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in PINS:
                found[name] = ast.literal_eval(node.value)
    require(found == PINS, "Firmware draft source pins differ; refuse an older recipe")
    return tree


def command(main, device, result, root, *, out_root=None, jobs=4):
    """Return the actual draft CLI without fetching, building or writing files."""
    require(type(jobs) is int and jobs > 0, "Positive integer jobs required")
    main, device, result, root = (Path(path).resolve() for path in (main, device, result, root))
    require(main.name == "UniXNU" and device == main.parent / "UniXNU-sheng", "Use the prepared27 source siblings")
    vendor = root / "resources/official-vendor"
    output = result / "firmware"
    return list(map(str, [
        sys.executable, SOURCE,
        "--unixnu", main, "--device", device,
        "--out-root", Path(out_root).resolve() if out_root is not None else main / "out",
        "--output", output, "--patch-root", PATCH_ROOT,
        "--stage", "build", "--vendor-file", vendor / "uefi.elf",
        "--vendor-provenance", vendor / "provenance.json", "--jobs", jobs,
    ]))


def check_manifest(manifest):
    require(manifest.get("DarwinBoot_commit") == PINS["DARWIN_PIN"], "Do not reuse an older DarwinBoot FD")
    require(manifest.get("host_fv_and_bootshim_verified") is True, "Actual FV and both BootShim checks are required")
    require(manifest.get("official_empty_control_verified") is True, "The official empty-ramdisk container control is required")
    require(manifest.get("kernel_or_payload_built") is False and manifest.get("device_operations") is False
            and manifest.get("hardware_tested") is False, "Firmware phase must stay host-only")


def run(main, device, result, root, *, ctx=None, jobs=4):
    """Build/inspect the new FD on a Mac; return its dedicated output directory."""
    require(sys.platform == "darwin", "Firmware compilation requires the reviewed macOS host")
    reviewed_source()
    main, device, result, root = (Path(path).resolve() for path in (main, device, result, root))
    out_root = main / "out"
    if ctx is not None:
        require(Path(ctx.root).resolve() == main and Path(ctx.device).resolve() == device,
                "The prepared context does not belong to these27 sources")
        require(ctx.config_name == "sheng_ipados27_defconfig"
                and ctx.board["board"]["os_profile"] == PINS["PROFILE"], "Require the prepared27 context")
        out_root = Path(ctx.out_root).resolve()
    for path, key in ((main, "MAIN_PIN"), (device, "DEVICE_PIN")):
        actual = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
        require(actual == PINS[key], "Preserve the checkout at an unexpected source revision")
    vendor = root / "resources/official-vendor"
    image, provenance = vendor / "uefi.elf", vendor / "provenance.json"
    require(image.is_file() and image.stat().st_size == 2944824 and sha(image) == VENDOR_SHA,
            "Supply the exact private official-vendor resource; no community-padded substitute")
    require(provenance.is_file(), "The private official-vendor provenance is required")
    argv = command(main, device, result, root, out_root=out_root, jobs=jobs)
    env = dict(os.environ, NOBOOT="1")
    # No --download-vendor fallback, device ID or17 firmware artifact is passed.
    subprocess.run(argv, cwd=root, env=env, check=True)
    output = result / "firmware"
    manifest = json.loads((output / "firmware-manifest.json").read_text(encoding="utf-8"))
    check_manifest(manifest)
    fd = output / "SILICIUM_UEFI.fd"
    require(fd.is_file() and fd.stat().st_size == 0x300000 and sha(fd) == manifest["fd_sha256"],
            "Actual newly built FD differs from its checked firmware manifest")
    receipt = {
        "source_pins": PINS, "draft_sha256": sha(SOURCE), "fd_sha256": sha(fd),
        "fd_bytes": fd.stat().st_size, "output_subdirectory": "firmware",
        "vendor_sha256": VENDOR_SHA, "host_fv_and_bootshim_verified": True,
        "official_empty_control_verified": True,
        "stock_boot_header_compared": manifest["stock_boot_header_compared"],
        "device_operations": False, "hardware_tested": False,
    }
    (result / "firmware-stage27.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return output


def self_test():
    """Check adapter arguments against the real draft parser without running it."""
    tree = reviewed_source()
    entry = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    setup = []
    for node in entry.body:
        if isinstance(node, ast.Assign) and any(isinstance(item, ast.Name) and item.id == "args" for item in node.targets):
            break
        setup.append(node)
    namespace = {"argparse": argparse, "Path": Path, "__file__": str(SOURCE), "__doc__": __doc__}
    exec(compile(ast.Module(body=setup, type_ignores=[]), str(SOURCE), "exec"), namespace)
    base = Path("adapter-input-fixture").resolve()
    argv = command(base / "work27/UniXNU", base / "work27/UniXNU-sheng", base / "result27", base)
    parsed = namespace["parser"].parse_args(argv[2:])
    require(parsed.stage == "build" and parsed.download_vendor is False, "The adapter must build without a vendor download fallback")
    require(parsed.patch_root == PATCH_ROOT and parsed.vendor_file == base / "resources/official-vendor/uefi.elf",
            "Code/patch inputs and private binary inputs must remain separate")
    require(parsed.output == base / "result27/firmware" and parsed.out_root == base / "work27/UniXNU/out",
            "Dedicated firmware output or resolver layout changed")
    valid = {"DarwinBoot_commit": PINS["DARWIN_PIN"], "host_fv_and_bootshim_verified": True,
             "official_empty_control_verified": True, "kernel_or_payload_built": False,
             "device_operations": False, "hardware_tested": False}
    check_manifest(valid)
    rejected = False
    try:
        check_manifest(dict(valid, DarwinBoot_commit="older17-reference"))
    except ValueError:
        rejected = True
    require(rejected, "Older17 firmware metadata must be refused")
    return {"actual_draft_cli_parsed": True, "fixed27_source_pins_checked": True,
            "private_vendor_path_checked": True, "older_firmware_rejected": True,
            "firmware_build_executed": False, "device_operations": False, "hardware_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--unixnu", type=Path)
    parser.add_argument("--device", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--execute", action="store_true", help="Run host build; default only prints the command")
    args = parser.parse_args()
    if args.self_test:
        print(json.dumps(self_test(), indent=2))
        return
    require(all((args.unixnu, args.device, args.result, args.root)), "Provide --unixnu, --device, --result and --root")
    if args.execute:
        run(args.unixnu, args.device, args.result, args.root)
    else:
        reviewed_source()
        print(json.dumps(command(args.unixnu, args.device, args.result, args.root)))


if __name__ == "__main__":
    main()
