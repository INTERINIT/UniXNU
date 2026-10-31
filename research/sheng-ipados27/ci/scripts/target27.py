"""Mac-only build orchestration DRAFT for the reviewed iPadOS 27 source pair.

Prerequisites: the parent CI supplies the SoC overlay, authenticated OS and
SystemOS policies, vendor firmware, a fresh Data seed and its real UUID, and
the unchanged 24A446 trust bundle. Never invokes hardware or userdata flashing.
This draft is syntax-checked only; each real build remains to be qualified.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import uuid as uuidlib
import tempfile

MAIN_REV = "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16"
DEVICE_REV = "f47b27ad97e97bee945f8af34a8430e3abcf918c"
HOST_CHECK_SHA256 = "7ab580b33aa544a0e8931679884d2aa717e5663d6d9ff52ee5cda90c128862c0"
QUARTZCORE17_CONTROL = """with tempfile.TemporaryDirectory(prefix='quartzcore-driver-cache-', dir=out) as temporary:
    subprocess.run([sys.executable, ROOT / 'scripts/check-quartzcore-turnip-cache-host.py',
                    '--output', Path(temporary) / 'control'], check=True, timeout=660)
"""


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(command, cwd, env=None, log_path=None):
    print("RUN", json.dumps(list(map(str, command))), flush=True)
    if log_path is None:
        subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True)
    else:
        try:
            with Path(log_path).open("w", encoding="utf-8") as stream:
                subprocess.run(list(map(str, command)), cwd=cwd, env=env, check=True,
                               stdout=stream, stderr=subprocess.STDOUT)
        finally:
            print(Path(log_path).read_text(encoding="utf-8", errors="replace")[-40000:], end="", flush=True)


def context(main, device, seed_report):
    sys.path.insert(0, str(main / "scripts"))
    from unixnu.cli import parser, prepare
    from unixnu.config import Context
    from unixnu import feeds, tree
    args = parser().parse_args(["build", "kernel", "-D", str(device), "--out", str(main / "out"),
                                "--os", "ipados-27.0.1-24A446", "-j", "4"])
    ctx = Context(args)
    if (ctx.config_name != "sheng_ipados27_defconfig" or
            ctx.board.get("os", {}).get("name") != "ipados-27.0.1-24A446" or
            ctx.board.get("ipsw", {}).get("build") != "24A446"):
        raise ValueError("Select the reviewed sheng_ipados27_defconfig and 24A446 profile first")
    uuid = str(uuidlib.UUID(seed_report["volume_uuid"])).upper()
    if ctx.need_config().get("XNU_OWNER_DATA_VOLUME_UUID", "").upper() != uuid:
        raise ValueError("Persist the actual Data seed UUID in the resolved configuration before the kernel build")
    modules = prepare(ctx, ("kernel",))
    # kernel REFERENCES does not fetch IOHIDFamily, although the 27 board uses it.
    feeds.fetch(ctx, modules, only={"IOHIDFamily"})
    # fetch fills module.path after prepare's first assembly. A clean tree needs
    # its new refer link before the source HID builder can inspect that path.
    tree.assemble(ctx, modules)
    ctx.config["XNU_OWNER_DATA_VOLUME_UUID"] = uuid
    expected = (main.parent / "UniXNU-sheng").resolve()
    if device.resolve() != expected:
        raise ValueError("27 display builder expects sibling UniXNU / UniXNU-sheng directories")
    hid = ctx.tree / "refer/IOHIDFamily"
    destination = main / "out/driver-sources/IOHIDFamily"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not hid.is_dir():
        raise ValueError("Pinned IOHIDFamily source was not assembled")
    if (destination.exists() or destination.is_symlink()) and destination.resolve() != hid.resolve():
        raise ValueError("Preserve conflicting fixed HID source directory")
    if not destination.exists() and not destination.is_symlink():
        destination.symlink_to(hid.resolve(), target_is_directory=True)
    for name in ("OS", "SystemOS"):
        directory = ctx.tree / "build/verified-root-24A446" / name
        for file in ("manifest.bin", "trusted-key.bin", "verification.json"):
            if not (directory / file).is_file():
                raise ValueError("Parent policy preparation must create " + str(directory / file))
    return ctx, modules


def bootstrap_recipe(ctx):
    """Retain the actual catalog dependency closure before invoking a build."""
    # ShengUfs also needs VirtioMmioBlock even when source storage does not link
    # that archive. The planner must see the same declared dependencies.
    by_id = {spec["id"]: spec for spec in ctx.component_specs}
    keep = set()

    def retain(identifier):
        if identifier in keep:
            return
        if identifier not in by_id:
            raise ValueError("Bootstrap dependency is not selected: " + identifier)
        keep.add(identifier)
        for dependency in by_id[identifier].get("dependencies", []):
            retain(dependency)

    for identifier in ("ArmDTPlatform", "ArmCpu", "ShengUfs", "RamBlock"):
        retain(identifier)
    specs = [s for s in ctx.component_specs if s["id"] in keep or not s.get("build") or s.get("build_stage", "kernel") != "kernel"]
    recipe = [
        "build-corecrypto-14.py", "build-corecrypto-14.py --namespace",
        "component:ArmDTPlatform", "component:ArmCpu", "build-libpthread-kernel.py",
        "component:ShengUfs", "component:RamBlock",
    ]
    return specs, recipe


def storage_adapter():
    path = Path(__file__).with_name("source_storage27.py")
    spec = importlib.util.spec_from_file_location("target27_source_storage", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_bootstrap(ctx, modules, output):
    """Real source kernel for the source-driver export audit, without display/GPU."""
    from unixnu import kernel
    config, specs, recipe = copy.deepcopy(ctx.config), ctx.component_specs, ctx.board["kernel"]["archives"]
    try:
        ctx.config["XNU_NATIVE_LEGACY_DISPLAY"] = False
        ctx.config["XNU_NATIVE_ADRENO"] = False
        ctx.config["XNU_BOOT_PROGRESS"] = False
        ctx.component_specs, ctx.board["kernel"]["archives"] = bootstrap_recipe(ctx)
        adapter = storage_adapter()
        adapter.apply(ctx.tree, output)
        with adapter.export_bootstrap_mode():
            kernel.build(ctx, modules)
        storage = adapter.verify_archive_sources(ctx.tree, bootstrap=True)
        native = ctx.tree / "build/xnu/ios-obj/DEVELOPMENT_ARM64_BCM2837/mach.development.bcm2837.unstripped.noctf"
        if not native.is_file():
            raise ValueError("Native bootstrap produced no real Mach-O")
        shutil.copy2(native, output / "native-bootstrap.macho")
        (output / "native-bootstrap.json").write_text(json.dumps({"sha256": sha(native), "purpose": "source-driver export audit only", "source_storage": storage, "hardware_tested": False}, indent=2))
    finally:
        ctx.config, ctx.component_specs, ctx.board["kernel"]["archives"] = config, specs, recipe


def source_identity(directory):
    """Hash the actual patched source, including restored/untracked headers."""
    if not directory.is_dir():
        raise ValueError("Build the native bootstrap before the RELEASE comparison source snapshot")
    entries = []
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            entries.append([relative.as_posix(), "symlink", os.readlink(path)])
        elif path.is_file():
            entries.append([relative.as_posix(), "file", stat.S_IMODE(path.stat().st_mode), sha(path)])
    if not entries:
        raise ValueError("The RELEASE comparison source snapshot is empty")
    encoded = json.dumps(entries, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest(), len(entries)


def prepare_reference_builder(main, ctx, output):
    """Use an isolated source/object cache for this exact patched source."""
    source = main / "scripts/build-fileset-release-reference.py"
    text = source.read_text()
    old = "root = repo / 'out/sheng/ipados-26.5.2-23F84/sheng_ipados26/tree'"
    old_output = "output = root / 'build/xnu/fileset-reference'"
    if text.count(old) != 1 or text.count(old_output) != 1:
        raise ValueError("Reference builder changed; review its input/output paths")
    text = text.replace(old, "root = Path(" + repr(str(ctx.tree)) + ")")
    if text.count("version-min=26.0") != 2 or text.count("-ios_version_min,26.0") != 1:
        raise ValueError("Reference deployment options changed; review all target flags")
    text = text.replace("version-min=26.0", "version-min=27.0").replace("-ios_version_min,26.0", "-ios_version_min,27.0")
    # The 27 exception diagnostics also run in RELEASE; upstream exception.c
    # used proc_pid only in DEVELOPMENT/DEBUG and did not include its header.
    # Repair only the isolated reference copy, before its source manifest.
    manifest_marker = "    manifest = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()\n"
    if text.count(manifest_marker) != 1:
        raise ValueError("Reference source-manifest step changed; review header adaptation")
    header_fix = '''    exception = source / 'osfmk/kern/exception.c'
    exception_text = exception.read_text(encoding='utf-8')
    marker = '#include <sys/code_signing.h> /* for developer mode state */\\n'
    if (exception_text.count(marker) != 1 or '#include <sys/proc.h>' in exception_text or
            'proc_pid(get_bsdtask_info(task))' not in exception_text):
        raise ValueError('Review changed RELEASE exception diagnostic includes')
    exception_text = exception_text.replace(marker, marker + '#ifdef MACH_BSD\\n#include <sys/types.h>\\n#include <sys/proc.h>\\n#endif\\n', 1)
    exception.write_text(exception_text, encoding='utf-8', newline='\\n')
    # This comparison links no SourceStorage archive. Respect the existing
    # feature switch for its optional startup hook; full native is unchanged.
    storage = source / 'bsd/kern/bsd_init.c'
    storage_text = storage.read_text(encoding='utf-8')
    hook = ('\\t/* Optional source storage runtime registers after the IOKit bootstrap. */\\n'
            '\\textern void native_source_storage_start(void) __attribute__((weak_import));\\n'
            '\\tif (&native_source_storage_start)\\n'
            '\\t\\tnative_source_storage_start();\\n')
    storage.write_text(storage_text.replace(hook, '#if defined(XNU_SOURCE_STORAGE) && XNU_SOURCE_STORAGE\\n' + hook + '#endif\\n', 1),
                       encoding='utf-8', newline='\\n')
'''
    text = text.replace(manifest_marker, header_fix + manifest_marker)
    fingerprint, count = source_identity(ctx.tree / ".cache/xnu-work")
    recipe = hashlib.sha256(text.encode()).hexdigest()
    identity = hashlib.sha256((fingerprint + ":" + recipe + ":" +
                               os.environ.get("DEVELOPER_DIR", "")).encode()).hexdigest()
    directory = ctx.tree / "build/xnu/fileset-reference" / ("source-" + identity)
    text = text.replace(old_output, "output = Path(" + repr(str(directory)) + ")")
    local = output / "build-release-reference27-local.py"
    local.write_text(text, encoding="utf-8", newline="\n")
    return local, directory, {"upstream_builder_sha256": sha(source), "local_builder_sha256": sha(local),
                              "patched_source_sha256": fingerprint, "patched_source_entries": count,
                              "reference_identity": identity}


def release_reference(main, ctx, output):
    """Build the comparison only after the actual native source/archive pass."""
    from unixnu import kernel
    work = ctx.tree / ".cache/xnu-work"
    revision = subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()
    if revision != ctx.board["os"]["xnu_revision"]:
        raise ValueError("RELEASE comparison source does not have the selected Apple XNU base revision")
    local, directory, receipt = prepare_reference_builder(main, ctx, output)
    env = dict(os.environ, PATH=kernel.toolchain_path())
    try:
        run([sys.executable, local, "--lto"], main, env)
    finally:
        log = directory / "lto-build.log"
        if log.is_file():
            shutil.copy2(log, output / "release-reference-build.log")
            print(log.read_text(encoding="utf-8", errors="replace")[-40000:], end="", flush=True)
    result = directory / "lto-obj/RELEASE_ARM64_BCM2837/mach.release.bcm2837.unstripped.noctf"
    if not result.is_file():
        raise ValueError("RELEASE comparison kernel absent")
    shutil.copy2(result, ctx.tree / "build/xnu/fileset-reference" / result.name)
    receipt["reference_sha256"] = sha(result)
    (output / "release-reference.json").write_text(json.dumps(receipt, indent=2) + "\n")


def symbols(path):
    raw = subprocess.check_output(["xcrun", "nm", str(path)], text=True)
    return {parts[2]: int(parts[0], 16) for line in raw.splitlines()
            if len(parts := line.split()) == 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]) and parts[1].lower() != "u"}


def full_kernel(device, ctx, modules):
    from unixnu import kernel
    adapter = storage_adapter()
    adapter.require_normal_mode()
    adapter.apply(ctx.tree)
    for iteration in range(3):
        kernel.build(ctx, modules)
        adapter.verify_archive_sources(ctx.tree, bootstrap=False)
        kernel.prelink(ctx)
        # Measure the same native image the profile passed to emit_prelink.
        native = ctx.tree / ctx.board["kernel"]["prelink"]["kernel"]
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


def prepare_gpu_host_check(tree, output):
    """Keep the real transport tests separate from the iOS17 AIR fixture.

    The upstream aggregate also requires a specific iOS17.7 QuartzCore library.
    That original-input qualification is not a prerequisite for recording the
    synthetic first submission, and passing it would not qualify 24A446 UI AIR.
    Preserve the pinned script and every other check in an explicit local copy.
    """
    source = tree / "scripts/check-turnip-darwin-host.py"
    text = source.read_text(encoding="utf-8")
    if hashlib.sha256(text.encode()).hexdigest() != HOST_CHECK_SHA256:
        raise ValueError("Host Turnip check changed; review the 27 qualification scope")
    root = "ROOT = Path(__file__).resolve().parents[1]"
    if text.count(root) != 1 or text.count(QUARTZCORE17_CONTROL) != 1:
        raise ValueError("Expected exactly one root and iOS17 QuartzCore control")
    text = text.replace(root, "ROOT = Path(" + repr(str(tree)) + ")")
    text = text.replace(QUARTZCORE17_CONTROL,
                        "print('NOT RUN: original iOS17 QuartzCore AIR cache control; "
                        "the 24A446 UI AIR cache is not qualified by this replay build')\n")
    destination = output / "check-turnip-host27-local.py"
    destination.write_text(text, encoding="utf-8", newline="\n")
    return destination


def prepare_gpu_watchdog(tree, output, env):
    path = Path(__file__).with_name("gpu_watchdog27.py")
    spec = importlib.util.spec_from_file_location("target27_watchdog_clock", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.apply(tree, output)
    module.qualify_clock(output, env)
    return report


def export_gpu_logs(tree, output):
    # Preserve failing-process evidence as well as successful logs. No output
    # from a failed suite may be reclassified as a qualification report.
    for directory, prefix in (("turnip-darwin-host", "host-turnip-"), ("adreno-metal-bridge", "bridge-")):
        for path in (tree / "build" / directory).glob("*.log"):
            shutil.copy2(path, output / (prefix + path.name))
    for pattern in ("mesa-*.log", "bison-*.log"):
        for path in (tree / ".cache").glob(pattern):
            shutil.copy2(path, output / ("compiler-" + path.name))


def gpu_host_check(tree, output, env):
    report_path = output / "gpu27-host-checks.json"
    report_path.unlink(missing_ok=True)
    local = prepare_gpu_host_check(tree, output)
    # Run even when a previous failed aggregate left plugin_smoke in the cache.
    # Its existence alone is not evidence that the watchdog/controls passed.
    failure = output / "gpu27-host-check-failure.json"
    failure.unlink(missing_ok=True)
    try:
        run([sys.executable, local], tree, env, log_path=output / "gpu27-host-check.stdout.log")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        failure.write_text(json.dumps({"status": "failed", "error_type": type(error).__name__,
                                       "returncode": getattr(error, "returncode", None),
                                       "host_qualified": False, "hardware_tested": False,
                                       "local_check_sha256": sha(local)}, indent=2) + "\n")
        raise
    finally:
        export_gpu_logs(tree, output)
    host = tree / "build/turnip-darwin-host"
    inputs = {
        "host_turnip": tree / "build/mesa-tu/src/freedreno/vulkan/libvulkan_freedreno.dylib",
        "host_bridge": tree / "build/adreno-metal-bridge/host/libadreno_metal_bridge.a",
        "software_peer": host / "libhostiokit.dylib",
        "plugin_smoke": host / "plugin_smoke",
        "shipping_watchdog_header": tree / "drivers/AdrenoMetal/NativeTurnipSmoke.h",
    }
    report = {
        "target": "iPadOS27.0.1 / 24A446",
        "upstream_check_sha256": HOST_CHECK_SHA256,
        "local_check_sha256": sha(local),
        "passed": ["Vulkan host transport", "eight deferred-BO controls",
                   "Turnip pipeline cache controls", "priming cache controls",
                   "plugin fill/compute/render command transport", "17-second watchdog control"],
        "not_run": [{"check": "original iOS17.7 QuartzCore AIR cache",
                     "reason": "Requires the separate exact 606f913a... iOS17 original library fixture"}],
        "target27_original_ui_air_cache_qualified": False,
        "hardware_tested": False, "shader_execution_verified": False,
        "inputs": {name: {"bytes": path.stat().st_size, "sha256": sha(path)} for name, path in inputs.items()},
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n")


def gpu_build(main, ctx, trust, output):
    tree = ctx.tree
    env = dict(os.environ)
    env["PATH"] = "/opt/homebrew/opt/llvm/bin:" + str(Path.home() / ".cargo/bin") + ":" + env["PATH"]
    prepare_gpu_watchdog(tree, output, env)
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
    for index, (name, extra) in enumerate((
        ("build-adreno-compiler-host.py", ["--probe"]),
        ("build-turnip-darwin.py", ["--target", "host"]),
        ("build-adreno-metal-bridge.py", ["--target", "host"]),
        ("build-turnip-darwin.py", ["--target", "ios27"]),
    )):
        run([sys.executable, tree / "scripts" / name, *extra], tree, env,
            log_path=output / (f"gpu27-build-{index}-" + name.removesuffix(".py") + ".log"))
    gpu_host_check(tree, output, env)
    run([sys.executable, tree / "scripts/build-adreno-metal-plugin.py", "--target", "ios27"], tree, env,
        log_path=output / "gpu27-build-plugin-ios27.log")
    publish_gpu_artifacts(main, tree, trust, output, env)
    bridge = tree / "build/adreno-metal-bridge"
    for name in ("Cargo.lock", "Cargo.toml", "build-ios27.log"):
        shutil.copy2(bridge / name, output / name)


def publish_gpu_artifacts(main, tree, trust, output, env):
    """Use the real packers with fresh files; verify before replacing results."""
    plugin = tree / "build/adreno-metal-plugin27"
    hashes = json.loads((plugin / "trust.json").read_text())
    if any(not re.fullmatch(r"[0-9a-f]{40}", hashes.get(key, "")) for key in ("cdhash", "turnip_cdhash")):
        raise ValueError("Plugin build did not record two actual CDHashes")
    parser_spec = importlib.util.spec_from_file_location("gpu27_payload_format", Path(__file__).with_name("payload_stage27.py"))
    parser = importlib.util.module_from_spec(parser_spec)
    parser_spec.loader.exec_module(parser)
    original_trust = trust.read_bytes()
    original_modules = parser.trust_modules(original_trust)
    env = dict(env)
    env["ADRENO_PLUGIN_DIR"] = str(plugin)
    with tempfile.TemporaryDirectory(prefix=".gpu27-publish-", dir=output) as temporary:
        pending = Path(temporary)
        addon, owner = pending / "gpu27.gpuaddon", pending / "owner-trust27.bundle"
        run([sys.executable, tree / "scripts/make-gpu-addon.py", "--publish", "--no-daemon", addon], tree, env,
            log_path=output / "gpu27-pack-addon.log")
        run([sys.executable, main / "scripts/trust-append-module.py", trust, owner, hashes["cdhash"], hashes["turnip_cdhash"]], main, env,
            log_path=output / "gpu27-pack-trust.log")
        files = parser.addon_files(addon.read_bytes())
        bundle = plugin / "NativeAdrenoMetal.bundle"
        expected = {"addons/NativeAdrenoMetal.bundle/" + path.relative_to(bundle).as_posix():
                    (0o755 if path.name in ("NativeAdrenoMetal", "libvulkan_freedreno.dylib") else 0o644, path.read_bytes())
                    for path in bundle.rglob("*") if path.is_file()}
        expected["addons/NativeAdrenoMetal.publish"] = (0o644, b"1\n")
        if files != expected:
            raise ValueError("The actual addon differs from the signed27 plugin bundle or contains extra jobs")
        modules = parser.trust_modules(owner.read_bytes())
        wanted = {bytes.fromhex(hashes[key]) for key in ("cdhash", "turnip_cdhash")}
        last = modules[-1]
        if (len(wanted) != 2 or len(modules) != len(original_modules) + 1 or modules[:-1] != original_modules
                or len(last) != 72 or {last[index:index + 20] for index in (24, 48)} != wanted
                or any(last[index + 20:index + 24] != b"\x02\0\0\0" for index in (24, 48))):
            raise ValueError("Owner trust must preserve the original modules and append exactly the two signed27 CDHashes")
        if trust.read_bytes() != original_trust:
            raise ValueError("The original IPSW trust bundle changed during packing")
        shutil.copy2(plugin / "trust.json", pending / "gpu27-trust.json")
        artifact_report = {"addon_sha256": sha(addon), "owner_trust_sha256": sha(owner),
                           "original_trust_sha256": hashlib.sha256(original_trust).hexdigest(),
                           "plugin_cdhash": hashes["cdhash"], "turnip_cdhash": hashes["turnip_cdhash"],
                           "files": {name: {"mode": mode, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                     for name, (mode, data) in files.items()},
                           "actual_packed_contents_equal_signed_bundle": True, "probe_daemon_staged": False,
                           "hardware_tested": False}
        (pending / "gpu27-artifacts.json").write_text(json.dumps(artifact_report, indent=2) + "\n")
        for path in pending.iterdir():
            path.replace(output / path.name)


def gpu(main, ctx, trust, output):
    status = {"status": "in_progress", "stage": "GPU host build and transport qualification",
              "hardware_tested": False, "shader_execution_verified": False}
    receipt = output / "gpu27-stage-status.json"
    (output / "gpu27-host-checks.json").unlink(missing_ok=True)
    receipt.write_text(json.dumps(status, indent=2) + "\n")
    try:
        gpu_build(main, ctx, trust, output)
        status["status"] = "passed"
    finally:
        if status["status"] != "passed":
            status["status"] = "failed"
        export_gpu_logs(ctx.tree, output)
        receipt.write_text(json.dumps(status, indent=2) + "\n")


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
