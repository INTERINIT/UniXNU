"""Pinned iPadOS27 source/asset pipeline. No device operations in any stage."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tomllib

CODE = Path(__file__).resolve().parents[1]
ROOT = Path(os.environ.get("UNIXNU_RESEARCH_BUILD_ROOT", CODE)).resolve()
WORK = ROOT / "work27"
MAIN = WORK / "UniXNU"
DEVICE = WORK / "UniXNU-sheng"
RESULT = ROOT / "result27"
PINS = {"UniXNU": "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16", "UniXNU-sheng": "f47b27ad97e97bee945f8af34a8430e3abcf918c"}
CONFIG = "sheng_ipados27_defconfig"


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
    run(sys.executable, MAIN / "unixnu", *parts, "-D", DEVICE, cwd=MAIN)


def context():
    sys.path.insert(0, str(MAIN / "scripts"))
    from unixnu.cli import parser
    from unixnu.config import Context
    return Context(parser().parse_args(["build", "kernel", "-D", str(DEVICE), "-j", "4"]))


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "policies", "gpu"))
    args = parser.parse_args()
    os.environ["NOBOOT"] = "1"
    ctx = prepare()
    if args.stage == "policies":
        policies(ctx)
    elif args.stage == "gpu":
        spec = importlib.util.spec_from_file_location("target27", CODE / "scripts/target27.py")
        target = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(target)
        target.gpu(MAIN, ctx, RESULT / "ipsw-trust27.bundle", RESULT)
    print("PASS: requested host phase completed; no hardware operation.", flush=True)


if __name__ == "__main__":
    main()
