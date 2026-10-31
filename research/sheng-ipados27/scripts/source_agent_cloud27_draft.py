"""Mac-only build orchestration DRAFT for the reviewed iPadOS 27 source pair.

Prerequisites: the parent CI supplies the SoC overlay, authenticated OS and
SystemOS policies, vendor firmware, a fresh Data seed and its real UUID, and
the unchanged 24A446 trust bundle. Never invokes hardware or userdata flashing.
This draft is syntax-checked only; each real build remains to be qualified.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

MAIN_REV = "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16"
DEVICE_REV = "f47b27ad97e97bee945f8af34a8430e3abcf918c"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command, cwd, env=None):
    print("RUN", json.dumps(list(map(str, command))), flush=True)
    subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True)


def context(main, device, seed_report):
    sys.path.insert(0, str(main / "scripts"))
    from unixnu.cli import parser, prepare
    from unixnu.config import Context
    from unixnu import feeds
    args = parser().parse_args(["build", "kernel", "-D", str(device), "-j", "4"])
    ctx = Context(args)
    modules = prepare(ctx, ("kernel",))
    # kernel REFERENCES does not fetch IOHIDFamily, although the 27 board uses it.
    feeds.fetch(ctx, modules, only={"IOHIDFamily"})
    uuid = seed_report["volume_uuid"]
    ctx.config["XNU_OWNER_DATA_VOLUME_UUID"] = uuid
    expected = (main.parent / "UniXNU-sheng").resolve()
    if device.resolve() != expected:
        raise ValueError("27 display builder expects sibling UniXNU / UniXNU-sheng directories")
    hid = ctx.tree / "refer/IOHIDFamily"
    destination = main / "out/driver-sources/IOHIDFamily"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.resolve() != hid.resolve():
        raise ValueError("Preserve conflicting fixed HID source directory")
    if not destination.exists():
        destination.symlink_to(hid.resolve(), target_is_directory=True)
    for name in ("OS", "SystemOS"):
        directory = ctx.tree / "build/verified-root-24A446" / name
        for file in ("manifest.bin", "trusted-key.bin", "verification.json"):
            if not (directory / file).is_file():
                raise ValueError("Parent policy preparation must create " + str(directory / file))
    return ctx, modules


def native_bootstrap(ctx, modules, output):
    """Real source kernel for the source-driver export audit, without display/GPU."""
    from unixnu import kernel
    config, specs, recipe = copy.deepcopy(ctx.config), ctx.component_specs, ctx.board["kernel"]["archives"]
    try:
        ctx.config["XNU_NATIVE_LEGACY_DISPLAY"] = False
        ctx.config["XNU_NATIVE_ADRENO"] = False
        ctx.config["XNU_BOOT_PROGRESS"] = False
        keep = {"ArmDTPlatform", "ArmCpu", "ShengUfs", "RamBlock"}
        ctx.component_specs = [s for s in specs if s["id"] in keep or not s.get("build") or s.get("build_stage", "kernel") != "kernel"]
        ctx.board["kernel"]["archives"] = [
            "build-corecrypto-14.py", "build-corecrypto-14.py --namespace",
            "component:ArmDTPlatform", "component:ArmCpu", "build-libpthread-kernel.py",
            "component:ShengUfs", "component:RamBlock",
        ]
        kernel.build(ctx, modules)
        native = ctx.tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf"
        if not native.is_file():
            raise ValueError("Native bootstrap produced no real Mach-O")
        shutil.copy2(native, output / "native-bootstrap.macho")
        (output / "native-bootstrap.json").write_text(json.dumps({"sha256": sha(native), "purpose": "source-driver export audit only", "hardware_tested": False}, indent=2))
    finally:
        ctx.config, ctx.component_specs, ctx.board["kernel"]["archives"] = config, specs, recipe


def release_reference(main, ctx, output):
    """Parameterize the upstream comparison builder's stale 26 output path."""
    source = main / "scripts/build-fileset-release-reference.py"
    text = source.read_text()
    old = "root = repo / 'out/sheng/ipados-26.5.2-23F84/sheng_ipados26/tree'"
    if text.count(old) != 1:
        raise ValueError("Reference builder changed; review its input path")
    text = text.replace(old, "root = Path(" + repr(str(ctx.tree)) + ")")
    text = text.replace("version-min=26.0", "version-min=27.0").replace("-ios_version_min,26.0", "-ios_version_min,27.0")
    local = output / "build-release-reference27-local.py"
    local.write_text(text)
    run([sys.executable, local, "--lto"], main)
    directory = ctx.tree / "build/xnu/fileset-reference"
    result = directory / "lto-obj/RELEASE_ARM64_BCM2837/mach.release.bcm2837.unstripped.noctf"
    if not result.is_file():
        raise ValueError("RELEASE comparison kernel absent")
    shutil.copy2(result, directory / result.name)
    (output / "release-reference.json").write_text(json.dumps({"upstream_builder_sha256": sha(source), "local_builder_sha256": sha(local), "reference_sha256": sha(result)}, indent=2))


def symbols(path):
    raw = subprocess.check_output(["xcrun", "nm", str(path)], text=True)
    return {parts[2]: int(parts[0], 16) for line in raw.splitlines()
            if len(parts := line.split()) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]) and parts[1].lower() != "u"}


def full_kernel(device, ctx, modules):
    from unixnu import kernel
    for iteration in range(3):
        kernel.build(ctx, modules)
        kernel.prelink(ctx)
        native = ctx.tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped"
        linked, final = symbols(native), symbols(ctx.work / "kernel/kernel.macho")
        name = "_native_legacy_display_allocate"
        if name not in linked or name not in final:
            raise ValueError("Native display symbol absent; do not guess its slide")
        value = hex((final[name] - linked[name]) % (1 << 64))
        stamp = ctx.tree / "build/native-legacy-display/native-slide"
        if stamp.is_file() and stamp.read_text().strip() == value:
            run([sys.executable, device / "scripts/check-legacy27-binds.py", ctx.work / "kernel/kernel.macho"], device)
            return
        stamp.write_text(value + "\n")
    raise ValueError("Display binding slide did not converge in three real links")


def gpu(main, ctx, trust, output):
    tree = ctx.tree
    env = dict(os.environ)
    env["PATH"] = "/opt/homebrew/opt/llvm/bin:" + str(Path.home() / ".cargo/bin") + ":" + env["PATH"]
    pin = json.loads((tree / "scripts/data/gpu-metal-vulkan-inputs.json").read_text())["translator"]
    translator = tree / ".cache/gpu-reference/metal2vulkan"
    if not translator.exists():
        run(["git", "init", translator], main)
        run(["git", "-C", translator, "remote", "add", "origin", pin["repository"]], main)
        run(["git", "-C", translator, "fetch", "--depth=1", "origin", pin["commit"]], main)
        run(["git", "-C", translator, "checkout", "--detach", "FETCH_HEAD"], main)
    actual = subprocess.check_output(["git", "-C", str(translator), "rev-parse", "HEAD"], text=True).strip()
    if actual != pin["commit"]:
        raise ValueError("Translator source pin differs")
    run(["rustup", "toolchain", "install", "1.98.0", "--profile", "minimal"], main, env)
    run(["rustup", "component", "add", "--toolchain", "1.98.0", "rust-src"], main, env)
    for name, extra in (
        ("build-adreno-compiler-host.py", ["--probe"]),
        ("build-turnip-darwin.py", ["--target", "host"]),
        ("build-turnip-darwin.py", ["--target", "ios27"]),
        ("build-adreno-metal-plugin.py", ["--target", "ios27"]),
    ):
        run([sys.executable, tree / "scripts" / name, *extra], tree, env)
    plugin = tree / "build/adreno-metal-plugin27"
    addon = output / "gpu27.gpuaddon"
    env["ADRENO_PLUGIN_DIR"] = str(plugin)
    run([sys.executable, tree / "scripts/make-gpu-addon.py", "--publish", "--no-daemon", addon], tree, env)
    hashes = json.loads((plugin / "trust.json").read_text())
    run([sys.executable, main / "scripts/trust-append-module.py", trust, output / "owner-trust27.bundle", hashes["cdhash"], hashes["turnip_cdhash"]], main, env)
    shutil.copy2(plugin / "trust.json", output / "gpu27-trust.json")
    bridge = tree / "build/adreno-metal-bridge"
    for name in ("Cargo.lock", "Cargo.toml", "build-ios27.log"):
        shutil.copy2(bridge / name, output / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unixnu", type=Path, required=True)
    parser.add_argument("--device", type=Path, required=True)
    parser.add_argument("--seed-report", type=Path, required=True)
    parser.add_argument("--ipsw-trust", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stage", choices=("bootstrap", "reference", "kernel", "gpu", "all"), default="all")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise ValueError("This draft uses the reviewed macOS/Xcode archive route")
    main, device, output = args.unixnu.resolve(), args.device.resolve(), args.output.resolve()
    for directory, expected in ((main, MAIN_REV), (device, DEVICE_REV)):
        actual = subprocess.check_output(["git", "-C", str(directory), "rev-parse", "HEAD"], text=True).strip()
        if actual != expected:
            raise ValueError("Source revision differs: " + str(directory))
    output.mkdir(parents=True, exist_ok=True)
    ctx, modules = context(main, device, json.loads(args.seed_report.read_text()))
    for name, action in (
        ("bootstrap", lambda: native_bootstrap(ctx, modules, output)),
        ("reference", lambda: release_reference(main, ctx, output)),
        ("kernel", lambda: full_kernel(device, ctx, modules)),
        ("gpu", lambda: gpu(main, ctx, args.ipsw_trust.resolve(), output)),
    ):
        if args.stage in (name, "all"):
            action()
    print("Build stage finished. No hardware operation was performed.")


if __name__ == "__main__":
    main()
