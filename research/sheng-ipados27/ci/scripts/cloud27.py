"""Pinned iPadOS27 source/asset pipeline. No device operations in any stage."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback

CODE = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("UNIXNU_RESEARCH_BUILD_ROOT", CODE)).resolve()
WORK = ROOT / "work27"
MAIN = WORK / "UniXNU"
DEVICE = WORK / "UniXNU-sheng"
RESULT = ROOT / "result27"
PINS = {"UniXNU": "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16", "UniXNU-sheng": "f47b27ad97e97bee945f8af34a8430e3abcf918c"}
CONFIG = "sheng_ipados27_defconfig"
PROFILE = "ipados-27.0.1-24A446"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(*parts, cwd=None):
    print("RUN", json.dumps(list(map(str, parts))), flush=True)
    subprocess.run(list(map(str, parts)), cwd=cwd or ROOT, check=True)


def clone(name):
    path = WORK / name
    if not path.exists():
        run("git", "init", path)
        run("git", "-C", path, "remote", "add", "origin", f"https://github.com/UniXNU/{name}.git")
        run("git", "-C", path, "fetch", "--depth=1", "origin", PINS[name])
        run("git", "-C", path, "checkout", "--detach", "FETCH_HEAD")
    actual = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    if actual != PINS[name]:
        raise ValueError("Preserve cached source at a different revision: " + name)


def cli(*parts):
    run(sys.executable, MAIN / "unixnu", *parts, "-D", DEVICE, "--out", MAIN / "out", "--os", PROFILE, cwd=MAIN)


def context():
    sys.path.insert(0, str(MAIN / "scripts"))
    from unixnu.cli import parser
    from unixnu.config import Context
    return Context(parser().parse_args(["build", "kernel", "-D", str(DEVICE), "--out", str(MAIN / "out"),
                                       "--os", PROFILE, "-j", "4"]))


def prepare():
    WORK.mkdir(exist_ok=True)
    RESULT.mkdir(exist_ok=True)
    for name in PINS:
        clone(name)
    cli("defconfig", CONFIG)
    ctx = context()
    target = ctx.profile_roots["soc"] / "patches/xnu-12377"
    target.mkdir(exist_ok=True)
    for name in ("series", "native-smp-secondary.patch", "sheng-platform-power.patch"):
        source = CODE / "patches/sm8550-xnu12377" / name
        destination = target / name
        if destination.exists() and sha(destination) != sha(source):
            raise ValueError("Unexpected SoC patch overlay: " + name)
        shutil.copy2(source, destination)
    run("git", "-C", DEVICE, "submodule", "update", "--init", "--recursive", "--depth=1", "--jobs=4")
    cli("fetch")
    cli("tree")
    ctx = context()
    verified_root = (ctx.tree / "kits/VerifiedRoot").resolve()
    actual_verified = subprocess.check_output(["git", "-C", str(verified_root), "rev-parse", "HEAD"], text=True).strip()
    if actual_verified != "ed368a8d4451f8670228f9025f1b45479509c789" or not any("vr_open_header" in path.read_text() for path in verified_root.rglob("*.h")):
        raise ValueError("Require the reviewed header-only-policy VerifiedRoot gitlink")
    status = subprocess.check_output([sys.executable, str(MAIN / "unixnu"), "status", "-D", str(DEVICE), "--json"], text=True)
    (RESULT / "resolved-status.json").write_text(status)
    record = json.loads(status)
    if record["board"]["board"]["os_profile"] != "ipados-27.0.1-24A446":
        raise ValueError("Resolved OS differs")
    # These upstream tools fetch and hash-check firmware inputs only.
    run(sys.executable, ctx.tree / "scripts/fetch-adreno-inputs.py", cwd=ctx.tree)
    run(sys.executable, DEVICE / "scripts/extract-files.py", "--device", DEVICE)
    from unixnu import ipsw
    source = ipsw.Ipsw(ctx)
    kernelcache = ipsw.kernelcache(ctx, source)
    if sha(kernelcache) != "38e6d9fa5f789b8228f4617ef4c6d2a3fd8ab564abdc9b62920f1db53fc1780a":
        raise ValueError("Actual Apple kernelcache differs from 24A446 pin")
    modules = []
    for name in ("StaticTrustCache", "Cryptex1,SystemTrustCache"):
        data = source.extract(name).read_bytes()
        data = ipsw.im4p_payload(data) if data[0] == 0x30 else data
        if len(data) < 24 or struct.unpack_from("<I", data)[0] != 2:
            raise ValueError("Expected original version-2 trust module: " + name)
        count = struct.unpack_from("<I", data, 20)[0]
        if len(data) != 24 + 24 * count:
            raise ValueError("Original trust module bounds differ")
        modules.append(data)
    trust = struct.pack("<III", 2, 12, 12 + len(modules[0])) + b"".join(modules)
    (RESULT / "ipsw-trust27.bundle").write_bytes(trust)
    research_revision = subprocess.check_output(["git", "-C", str(CODE), "rev-parse", "HEAD"], text=True).strip()
    report = {"source_pins": PINS, "research_revision": research_revision, "target": "iPadOS27.0.1 / 24A446 / iPad17,3 j820ap", "kernelcache_sha256": sha(kernelcache), "original_trust_sha256": hashlib.sha256(trust).hexdigest(), "verified_root_commit": actual_verified, "soc_overlay_audit": json.loads((CODE / "patches/sm8550-xnu12377/audit.json").read_text()), "device_operations": False, "hardware_tested": False}
    (RESULT / "prepare.json").write_text(json.dumps(report, indent=2))
    return ctx


def policies(ctx):
    from unixnu import ipsw
    source = ipsw.Ipsw(ctx)
    images = {}
    for name, component in (("OS", "OS"), ("SystemOS", "Cryptex1,SystemOS")):
        image = source.disk_image(component)
        images[name] = image
        # Remove only this job's downloaded encrypted member after authenticated
        # decryption; Windows keeps the original member separately for reference.
        encrypted = image.with_suffix(image.suffix + ".aea")
        if encrypted.exists():
            if not encrypted.resolve().is_relative_to(source.cache.resolve()):
                raise ValueError("Encrypted cleanup escaped the IPSW cache")
            encrypted.unlink()
    run(sys.executable, CODE / "scripts/policy27.py", "--tree", ctx.tree, "--profile", MAIN / "profiles/os/ipados-27.0.1-24A446/profile.toml", "--os-dmg", images["OS"], "--systemos-dmg", images["SystemOS"])
    policy_root = ctx.tree / "build/verified-root-24A446"
    destination = RESULT / "root-policies"
    destination.mkdir(exist_ok=True)
    for name in ("OS", "SystemOS"):
        (destination / name).mkdir(exist_ok=True)
        for member in ("manifest.bin", "trusted-key.bin", "verification.json"):
            shutil.copy2(policy_root / name / member, destination / name / member)
    shutil.copy2(policy_root / "policy27-build.json", destination)
    return images


def helper(name):
    spec = importlib.util.spec_from_file_location(name, CODE / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def restore_policies(ctx):
    # Policies are immutable inputs, not an assumption about an opportunistic
    # source cache. Restore the actual successful run, then check every byte.
    pin = json.loads((CODE.parent / "evidence/root-policies-24A446.json").read_text())
    destination = ctx.tree / "build/verified-root-24A446"

    def check(directory):
        return all((directory / name).is_file()
                   and (directory / name).stat().st_size == item["bytes"]
                   and sha(directory / name) == item["sha256"]
                   for name, item in pin["files"].items())

    if check(destination):
        return
    if destination.exists() and any(destination.rglob("manifest.bin")):
        raise ValueError("Preserve root policies that differ from the selected immutable run")
    supplied = ROOT / "resources/root-policies-24A446"
    if check(supplied):
        source = supplied
        temporary = None
    else:
        temporary = tempfile.TemporaryDirectory(prefix="policy-import27-", dir=WORK)
        download = Path(temporary.name)
        run("gh", "run", "download", str(pin["run_id"]), "--repo", pin["repository"],
            "--name", pin["artifact"], "--dir", download)
        source = download / pin["path"]
    try:
        if not check(source):
            raise ValueError("Downloaded policy artifact differs from its recorded exact file hashes")
        for name in pin["files"]:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, target)
        if not check(destination):
            raise ValueError("Policy restore changed bytes")
    finally:
        if temporary is not None:
            temporary.cleanup()


def data(ctx):
    # Cache the seed beside this exact target, rather than in the ephemeral
    # result directory. Each invocation restores its real UUID after defconfig.
    restore_policies(ctx)
    cached = ctx.work / "data-seed"
    helper("data_stage27").data(MAIN, ctx, cached, desired_gib=8)
    for name in ("data.dbr", "data-seed.json", "data-stage27.json", "source-root-layout.json", "source-root-manifest.bin"):
        shutil.copy2(cached / name, RESULT / name)
    return json.loads((cached / "data-seed.json").read_text())


def native(stage, ctx, seed=None):
    seed = data(ctx) if seed is None else seed
    target = helper("target27")
    ctx, modules = target.context(MAIN, DEVICE, seed)
    target.native_bootstrap(ctx, modules, RESULT)
    if stage == "kernel":
        target.release_reference(MAIN, ctx, RESULT)
        target.full_kernel(DEVICE, ctx, modules)
        for name in ("kernel.macho", "kernel.json", "kernel.map.json"):
            path = ctx.work / "kernel" / name
            if path.is_file():
                shutil.copy2(path, RESULT / name)
        policy_bundle = ctx.tree / "build/sheng-source-storage/root-policies.bin"
        shutil.copy2(policy_bundle, RESULT / "root-policies.bin")
        for name in ("OS", "SystemOS"):
            location = RESULT / "root-policies" / name
            location.mkdir(parents=True, exist_ok=True)
            for member in ("manifest.bin", "trusted-key.bin", "verification.json"):
                shutil.copy2(ctx.tree / "build/verified-root-24A446" / name / member, location / member)
    (RESULT / "native-stage27.json").write_text(json.dumps({
        "stage": stage, "source_pins": PINS,
        "data_volume_uuid": seed["volume_uuid"],
        "data_seed_sha256": seed["packed_sha256"],
        "config_sha256": sha(ctx.config_path),
        "root_policy_bundle_sha256": sha(RESULT / "root-policies.bin") if stage == "kernel" else None,
        "device_operations": False, "hardware_tested": False,
    }, indent=2) + "\n")


def package_phases(actions, result):
    """Collect independent phase failures in one run; never mask its conclusion."""
    result = Path(result)
    result.mkdir(parents=True, exist_ok=True)
    phases = {}
    dependencies = {"data": (), "native": ("data",), "gpu": (), "firmware": (),
                    "payload": ("data", "native", "gpu", "firmware")}
    for name, required in dependencies.items():
        blocked = [item for item in required if phases[item]["status"] != "passed"]
        if blocked:
            phases[name] = {"status": "blocked", "dependencies": blocked}
        else:
            started = time.monotonic()
            print("PACKAGE PHASE:", name, flush=True)
            try:
                actions[name]()
            except (Exception, SystemExit) as error:
                trace = traceback.format_exc()
                private_seed = os.environ.get("UNIXNU_UNIQUE_CHIP_ID")
                if private_seed:
                    trace = trace.replace(private_seed, "[private platform seed]")
                log = "package-" + name + "-failure.log"
                (result / log).write_text(trace, encoding="utf-8")
                phases[name] = {"status": "failed", "error_type": type(error).__name__, "traceback": log}
                print("PACKAGE PHASE FAILED:", name, type(error).__name__, flush=True)
            else:
                phases[name] = {"status": "passed"}
            phases[name]["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report = {"status": "in_progress", "phases": phases, "device_operations": False, "hardware_tested": False}
        (result / "package-phases27.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["status"] = "host_verified" if all(item["status"] == "passed" for item in phases.values()) else "failed"
    (result / "package-phases27.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("## sheng 24A446 host build\n\n| Phase | Result |\n| --- | --- |\n")
            for name, item in phases.items():
                stream.write("| " + name + " | " + item["status"] + " |\n")
            stream.write("\nNo tablet operation. Hardware qualification remains untested.\n")
    return report


def complete_package(ctx):
    # One runner owns the seed/config/kernel/anchor chain. Independent phases
    # still run after an unrelated failure so one workflow yields all evidence.
    state = {}

    def create_data():
        state["seed"] = data(context())
        # This one-use Mac download is excluded from all caches. The original
        # encrypted/plain inputs remain on the Windows workstation. Native,
        # GPU, firmware and payload steps use the completed seed and policies.
        if platform.system() != "Darwin":
            raise ValueError("Complete package execution requires the Mac host")
        cache = (MAIN / "out/ipsw/24A446").resolve()
        plain = cache / "043-68950-668.dmg"
        cleanup = {"temporary_input": plain.name, "status": "not_present", "device_operations": False}
        if plain.exists():
            expected = "8a12cdad43f8f0d33dadcf01a800a560222baf40c05f71374c460ba57ba3a739"
            if (plain.is_symlink() or not plain.resolve().is_relative_to(cache)
                    or plain.stat().st_size != 9613344768
                    or state["seed"].get("source_os_file_sha256") != expected or sha(plain) != expected):
                raise ValueError("Preserve a temporary OS input that differs from the authenticated Data source")
            try:
                plain.unlink()
                cleanup.update(status="removed_after_read_only_seed_creation", bytes_freed=9613344768, sha256=expected)
            except OSError as error:
                cleanup.update(status="retained", reason=type(error).__name__)
        (RESULT / "temporary-os-cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n", encoding="utf-8")

    report = package_phases({
        "data": create_data,
        "native": lambda: native("kernel", context(), seed=state["seed"]),
        "gpu": lambda: helper("target27").gpu(MAIN, context(), RESULT / "ipsw-trust27.bundle", RESULT),
        "firmware": lambda: helper("firmware_stage27").run(MAIN, DEVICE, RESULT, ROOT, ctx=context()),
        "payload": lambda: helper("payload_stage27").run(
            MAIN, DEVICE, RESULT, ROOT, ctx=context(), uefi=DEVICE / "uefi-sheng",
            execute=True, unique_chip_id=os.environ.get("UNIXNU_UNIQUE_CHIP_ID")),
    }, RESULT)
    if report["status"] != "host_verified":
        raise RuntimeError("Package phases failed or were blocked; inspect package-phases27.json and the saved logs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "policies", "data", "bootstrap", "kernel", "gpu", "firmware", "package"))
    args = parser.parse_args()
    os.environ["NOBOOT"] = "1"
    ctx = prepare()
    if args.stage == "policies":
        policies(ctx)
    elif args.stage == "data":
        data(ctx)
    elif args.stage in ("bootstrap", "kernel"):
        native(args.stage, ctx)
    elif args.stage == "gpu":
        helper("target27").gpu(MAIN, ctx, RESULT / "ipsw-trust27.bundle", RESULT)
    elif args.stage == "firmware":
        helper("firmware_stage27").run(MAIN, DEVICE, RESULT, ROOT, ctx=ctx)
    elif args.stage == "package":
        complete_package(ctx)
    print("PASS: requested host phase completed; no hardware operation.", flush=True)


if __name__ == "__main__":
    main()
