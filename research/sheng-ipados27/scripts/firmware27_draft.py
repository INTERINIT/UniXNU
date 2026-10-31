#!/usr/bin/env python3
"""Host-only iPadOS27 UEFI draft; never boots or writes a connected device.

Prerequisite: cloud27 prepare has populated the fixed UniXNU/UniXNU-sheng pair
and the xnu-12377 SoC overlay. This script never checks out/reset those repos.
Use on a fresh macOS runner with brew cmake ninja llvm lld dtc acpica mtools
qemu. Builds firmware and empty container controls; no kernel, root volume,
Data or iPadOS payload is built here.
"""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


MAIN_PIN = "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16"
DEVICE_PIN = "f47b27ad97e97bee945f8af34a8430e3abcf918c"
DARWIN_PIN = "3e3a8a969e1177995984d8ed98c9dcc44e318265"
UEFI_PIN = "20ac23d5e0937106c2129303dfc931b3390ae660"
EXTRACT_PIN = "dac91b26733ca21cb204e41614c1b8c81cc50860"
MU_PIN = "cfb93724a06ff86ff5ba971413368a7809ee42a5"
PROFILE = "ipados-27.0.1-24A446"
PATCH_SHA = {
    "ramdisk-fat-window27.patch": "667e38c3637da5ab6c08d27881132acfd7f4f6a2163582972d0bb6d97e2d8d0c",
    "logger-ram27.patch": "9aee04f08645c13f74f6ed1b4a851c9e8ea6f8bbe38c4d9f84a8b22d5b441cc7",
}
VENDOR_UEFI_SHA = "a846d86dc6fc471a879ec02f8c8d87ee28dc1329e819f03629662fe0409ff520"
VENDOR_ROM_MD5 = "31450b6677d9e46edc4937c3f797c51d"
BOOTSHIM_CHECK_SHA = "f2ef7ac8500e42944ccfd56d8022af1745a974e4f62b944699e2597f0726e4bb"
STOCK_HEADER_READ = """    stock = ROOT / '.cache/firmware/sheng/porting-inputs'
    stock_boot = next(stock.rglob('boot.img'))
    with stock_boot.open('rb') as stream:
        stock_header = stream.read(44)
    if stock_header[:8] != b'ANDROID!':
        raise SystemExit('Unexpected stock boot image magic')
"""
OPTIONAL_STOCK_HEADER_READ = """    stock = ROOT / '.cache/firmware/sheng/porting-inputs'
    stock_candidates = sorted(stock.rglob('boot.img'))
    stock_boot_header_version = None
    if stock_candidates:
        if len(stock_candidates) != 1:
            raise SystemExit('Ambiguous original stock boot image inputs')
        with stock_candidates[0].open('rb') as stream:
            stock_header = stream.read(44)
        if len(stock_header) != 44 or stock_header[:8] != b'ANDROID!':
            raise SystemExit('Unexpected stock boot image header')
        stock_boot_header_version = struct.unpack_from('<I', stock_header, 40)[0]
"""


def prepare_bootshim_check(source, tree, output):
    """Keep the real upstream fixtures; make only stock-header reporting optional.

    The fixed upstream script reads stock boot.img only after all QEMU and
    container round-trip checks, to report its header version. A UEFI-only
    build has the genuine uefi.elf but not that separate Android image.
    """
    text = source.read_text(encoding="utf-8")
    require(hashlib.sha256(text.encode()).hexdigest() == BOOTSHIM_CHECK_SHA,
            "BootShim checker source changed; review the stock-input scope")
    root = "ROOT = Path(__file__).resolve().parents[1]"
    version = "'stock_boot_header_version': struct.unpack_from('<I', stock_header, 40)[0],"
    limitation = "'Legacy v0 recipe follows debian-sheng; stock firmware uses v4'"
    require(text.count(root) == text.count(STOCK_HEADER_READ) == text.count(version) == text.count(limitation) == 1,
            "Require the exact reviewed BootShim reporting context")
    updated = text.replace(root, "ROOT = Path(" + repr(str(tree)) + ")")
    updated = updated.replace(STOCK_HEADER_READ, OPTIONAL_STOCK_HEADER_READ)
    updated = updated.replace(version, "'stock_boot_header_version': stock_boot_header_version,\n"
                              "              'stock_boot_header_compared': stock_boot_header_version is not None,")
    updated = updated.replace(limitation, "'Legacy v0 control; stock header comparison is unavailable when the original boot image is absent'")
    target = output / "package-sheng-boot27-local.py"
    target.write_text(updated, encoding="utf-8", newline="\n")
    patch = "".join(difflib.unified_diff(text.splitlines(keepends=True), updated.splitlines(keepends=True),
                                      fromfile="a/scripts/package-sheng-boot.py", tofile="b/package-sheng-boot27-local.py"))
    (output / "bootshim-checker27-local.patch").write_text(patch, encoding="utf-8", newline="\n")
    report = {"upstream_checker_sha256": BOOTSHIM_CHECK_SHA, "local_checker_sha256": sha(target),
              "change": "Optional report-only stock boot header; explicit null when absent",
              "original_device_script_modified": False, "QEMU_or_roundtrip_checks_removed": False,
              "stock_image_generated_or_substituted": False, "device_operations": False}
    (output / "bootshim-checker27-adaptation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return target


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(*parts, cwd=None, capture=False):
    command = list(map(str, parts))
    # Defense against adding a device command while integrating this draft.
    require(not any(Path(part).stem.lower() in ("adb", "fastboot", "edl", "fh_loader")
                    for part in command), "Device commands are forbidden")
    print("RUN", json.dumps(command), flush=True)
    return subprocess.run(command, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def git(path, *parts):
    return run("git", "-C", path, *parts, capture=True).strip()


def assert_pin(path, commit):
    require(git(path, "rev-parse", "HEAD") == commit, "Preserve checkout at unexpected revision: " + str(path))


def clone_aux(path, url, commit):
    """Create only an absent auxiliary checkout; never reset an existing one."""
    require(not path.is_symlink(), "Auxiliary checkout must be a physical directory")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        run("git", "init", path)
        run("git", "-C", path, "remote", "add", "origin", url)
        run("git", "-C", path, "fetch", "--depth=1", "origin", commit)
        run("git", "-C", path, "checkout", "--detach", "FETCH_HEAD")
    assert_pin(path, commit)


class Pipeline:
    def __init__(self, args):
        self.args = args
        self.main = args.unixnu.resolve()
        self.device = args.device.resolve()
        self.uefi = self.device / "uefi-sheng"
        self.mu = self.uefi / "Mu_Basecore"
        self.output = args.output.resolve()
        self.aux = self.main.parent / "firmware27-host-tools"
        self.extractor = self.aux / "uefiextract-build/uefiextract"
        self.patch_root = args.patch_root.resolve()

    def guard(self):
        assert_pin(self.main, MAIN_PIN)
        assert_pin(self.device, DEVICE_PIN)
        require(self.main != self.device and not self.device.is_relative_to(self.main), "Expected independent source siblings")
        import tomllib
        board = tomllib.loads((self.device / "board.toml").read_text())
        require(board["board"]["os_profile"] == PROFILE, "This recipe accepts only the reviewed 27 profile")
        require(board["kernel"]["defconfig"] == "sheng_ipados27_defconfig", "Refuse a 17/26 defconfig")
        require(str(board["firmware"].get("defines", {}).get("SHENG_VENDOR_HW", "0")) == "0", "Vendor hardware must remain disabled")

    def common(self):
        # Explicit paths/OS/target beat inherited local build options.
        return ["-D", self.device, "--os", PROFILE, "--uefi", self.uefi,
                "--edk2", self.mu, "--local-module", f"refer:edk2={self.mu}",
                "--out", self.args.out_root.resolve(), "--target", "DEBUG", "-j", str(self.args.jobs)]

    def cli(self, *parts):
        self.guard()
        return run(sys.executable, self.main / "unixnu", *parts, *self.common(), cwd=self.main)

    def context(self):
        self.guard()
        sys.path.insert(0, str(self.main / "scripts"))
        from unixnu.cli import parser
        from unixnu.config import Context
        ctx = Context(parser().parse_args(list(map(str, ["build", "firmware", *self.common()]))))
        require(ctx.config_name == "sheng_ipados27_defconfig", "Output state selected another defconfig")
        return ctx

    def link(self, target, link):
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            require(link.is_symlink() and link.resolve() == target.resolve(), "Preserve conflicting link: " + str(link))
        else:
            link.symlink_to(target.resolve(), target_is_directory=target.is_dir())

    def patch(self, repo, name):
        path = self.patch_root / name
        require(sha(path) == PATCH_SHA[name], "Patch differs from reviewed draft: " + name)
        reverse = subprocess.run(["git", "-C", str(repo), "apply", "--reverse", "--check", str(path)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if reverse.returncode != 0:
            run("git", "-C", repo, "apply", "--check", path)
            run("git", "-C", repo, "apply", path)

    def prepare(self):
        self.guard()
        self.output.mkdir(parents=True, exist_ok=True)
        clone_aux(self.uefi, "https://github.com/UniXNU/uefi-sheng.git", UEFI_PIN)
        clone_aux(self.aux / "UEFITool", "https://github.com/LongSoft/UEFITool.git", EXTRACT_PIN)
        # These gitlink revisions, rather than moving release branches, supply
        # Mu logger, QR and BaseTools implementations used by the successful17 FD.
        selected = ["Mu_Basecore", "Common/Mu", "Common/Mu_OEM_Sample", "Silicium-ACPI",
                    "Silicon/Silicium/OpensslPkg/Library/OpensslLib/openssl"]
        run("git", "-C", self.uefi, "submodule", "update", "--init", "--depth=1", "--jobs=4", "--", *selected)
        for item in selected:
            expected = git(self.uefi, "rev-parse", "HEAD:" + item)
            assert_pin(self.uefi / item, expected)
        assert_pin(self.mu, MU_PIN)
        run("git", "-C", self.mu, "submodule", "update", "--init", "--depth=1", "--jobs=4", "--",
            "BaseTools/Source/C/BrotliCompress/brotli", "MdeModulePkg/Library/BrotliCustomDecompressLib/brotli",
            "MdePkg/Library/BaseFdtLib/libfdt", "MdePkg/Library/MipiSysTLib/mipisyst", "SecurityPkg/DeviceSecurity/SpdmLib/libspdm")
        self.patch(self.main, "ramdisk-fat-window27.patch")
        self.patch(self.uefi, "logger-ram27.patch")
        dsc = (self.uefi / "Platforms/Xiaomi/shengPkg/sheng.dsc").read_text()
        require(re.findall(r"^\s*SHENG_VENDOR_HW\s*=\s*(\d+)\s*$", dsc, re.M) == ["0"], "Require working SHENG_VENDOR_HW=0 panel path")
        self.cli("tree")
        ctx = self.context()
        self.link(self.uefi, ctx.tree / "uefi-sheng")
        assert_pin(ctx.tree / "drivers/DarwinBoot", DARWIN_PIN)
        require((ctx.tree / "package").resolve() == (self.main / "package").resolve(), "Firmware package override differs")
        require(sha(ctx.tree / "package/UniXNUPkg/Driver/UniXNURamDiskDxe/FatWindow.h") ==
                "a970191cdb4077522f610d4c967be72eb4fcddde41cf98cb57d8c87dda09826a", "FAT header differs")
        # Compile the exact helper embedded in this FD, with the successful17
        # malformed/prefixed-FAT controls and address/undefined sanitizers.
        tests = self.output / "fat-tests"
        tests.mkdir(exist_ok=True)
        for name in ("RealFatBpb.h", "test_fat_window.c"):
            shutil.copy2(self.patch_root / "fat-tests" / name, tests / name)
        shutil.copy2(ctx.tree / "package/UniXNUPkg/Driver/UniXNURamDiskDxe/FatWindow.h", tests / "FatWindow.h")
        run("cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-O1",
            tests / "test_fat_window.c", "-o", tests / "test-fat-window")
        result = run(tests / "test-fat-window", capture=True)
        require("bounds PASS" in result, "FAT controls did not complete")
        (self.output / "fat-window-tests.txt").write_text(result)
        run(sys.executable, ctx.tree / "scripts/fetch-sheng-dts.py", cwd=ctx.tree)
        report = {"main": MAIN_PIN, "device": DEVICE_PIN, "DarwinBoot": DARWIN_PIN,
                  "uefi-sheng": UEFI_PIN, "Mu_Basecore": MU_PIN, "UEFIExtract": EXTRACT_PIN,
                  "patches": PATCH_SHA, "logger": {"ram_bytes": 4 << 20, "file_logger": False,
                  "nvram_locator": False, "starts_in": "DXE core"}, "SHENG_VENDOR_HW": 0,
                  "main_reset_or_checkout_performed": False, "device_operations": False, "hardware_tested": False}
        (self.output / "firmware-source-pins.json").write_text(json.dumps(report, indent=2) + "\n")
        return ctx

    def vendor(self, ctx):
        self.guard()
        cache = self.device / ".cache/firmware/sheng"
        cache.mkdir(parents=True, exist_ok=True)
        image = cache / "porting-inputs/uefi.elf"
        manifest = cache / "porting-inputs.json"
        if self.args.vendor_file:
            supplied = self.args.vendor_file.resolve()
            require(supplied.stat().st_size == 2944824 and sha(supplied) == VENDOR_UEFI_SHA,
                    "Supplied vendor file must exactly match the successful official-ROM member")
            require(self.args.vendor_provenance, "Supply provenance with an explicit vendor file")
            provenance = json.loads(self.args.vendor_provenance.read_text())
            require(provenance["output_bytes"] == 2944824 and provenance["output_sha256"] == VENDOR_UEFI_SHA
                    and provenance["official_archive_md5"] == VENDOR_ROM_MD5
                    and provenance["official_manifest_sha256"] == "67426db3496c076439ac35385fd8419e036ff1ae26ffa193dac495a80e31a8d5",
                    "Vendor provenance differs from the reviewed official-member evidence")
            require(not image.exists() or sha(image) == VENDOR_UEFI_SHA, "Preserve conflicting cached UEFI")
            image.parent.mkdir(exist_ok=True)
            if not image.exists():
                shutil.copy2(supplied, image)
            if not manifest.exists():
                manifest.write_text(json.dumps({"archive_md5": VENDOR_ROM_MD5,
                    "source_kind": "Exact SHA256 match to recorded official-ROM member; imported from supplied file",
                    "source_provenance": provenance, "selected": [{"file": "uefi.elf", "bytes": 2944824,
                    "sha256": VENDOR_UEFI_SHA}]}, indent=2) + "\n")
            shutil.copy2(self.args.vendor_provenance, self.output / "vendor-provenance.json")
        if not (image.is_file() and sha(image) == VENDOR_UEFI_SHA and manifest.is_file()):
            require(self.args.download_vendor, "Provide the verified official vendor cache or pass --download-vendor (large official fastboot ROM)")
            require(not image.exists(), "Preserve unexpected cached UEFI before downloading another input")
            # These are exactly the official-ROM range downloader and extractor
            # used by successful logger run41072611463, at the fixed device pin.
            run(sys.executable, self.device / "scripts/download-sheng-firmware.py", "--connections", "16", cwd=self.device)
            run(sys.executable, self.device / "scripts/extract-sheng-firmware.py", "--delete-archive", cwd=self.device)
        require(image.stat().st_size == 2944824 and sha(image) == VENDOR_UEFI_SHA, "UEFI differs from successful official-ROM input")
        saved = json.loads(manifest.read_text())
        require(saved.get("archive_md5") == VENDOR_ROM_MD5, "Require the successful official-ROM extraction manifest")
        require(any(item["file"] == "uefi.elf" and item["sha256"] == VENDOR_UEFI_SHA for item in saved["selected"]), "Vendor manifest differs")
        run("cmake", "-S", self.aux / "UEFITool/UEFIExtract", "-B", self.extractor.parent)
        run("cmake", "--build", self.extractor.parent, "-j" + str(self.args.jobs))
        self.link(self.extractor, self.device / "build/tools/uefiextract/uefiextract")
        self.link(self.extractor, ctx.tree / "build/tools/uefiextract/uefiextract")
        (self.uefi / "Binaries").mkdir(exist_ok=True)
        run(sys.executable, self.device / "scripts/import-sheng-uefi.py", cwd=self.device)
        vendor = json.loads((cache / "uefi-binaries/manifest.json").read_text())
        require(vendor["source_sha256"] == VENDOR_UEFI_SHA and vendor["modules"], "Imported vendor manifest differs")
        require(all((self.uefi / "Binaries/sheng" / item["inf"]).is_file() for item in vendor["modules"]), "Incomplete vendor module import")
        shutil.copy2(manifest, self.output / "vendor-source.json")
        shutil.copy2(cache / "uefi-binaries/manifest.json", self.output / "vendor-modules.json")

    def build(self, ctx):
        self.guard()
        assert_pin(ctx.tree / "drivers/DarwinBoot", DARWIN_PIN)
        # Same official stages as official_uefi_minimal.py. Do not replace the
        # firmware driver, reset metadata or BaseTools source on speculative grounds.
        self.cli("build", "package", "firmware")
        self.guard()
        assert_pin(ctx.tree / "drivers/DarwinBoot", DARWIN_PIN)
        fd = self.uefi / "Build/shengPkg/DEBUG_CLANGPDB/FV/SILICIUM_UEFI.fd"
        require(fd.is_file() and fd.stat().st_size == 0x300000, "Unexpected FD size")
        (self.device / "build/sheng").mkdir(parents=True, exist_ok=True)
        run(sys.executable, self.device / "scripts/check-sheng-fv.py", cwd=self.device)
        # The original stock boot.img was used only for a report field, not
        # for shim execution or image generation. Preserve every actual check
        # in a hash-guarded local copy and report an absent stock header as null.
        checker = prepare_bootshim_check(ctx.tree / "scripts/package-sheng-boot.py", ctx.tree, self.output)
        run(sys.executable, checker, cwd=ctx.tree)
        report = json.loads((ctx.tree / "build/sheng/boot/report.json").read_text())
        require(len(report["qemu"]) == 2 and all(item["passed"] for item in report["qemu"]), "Both BootShim cases must pass")
        require(report["fd_sha256"] == sha(fd) and report["qemu_skipped"] is False,
                "BootShim check must exercise this exact newly built FD path")
        # Separately use the unmodified official bootimg driver with an empty
        # ramdisk. This is a host v0 container control, not a hardware claim.
        control = self.output / "empty-control/boot-uefi-empty.img"
        self.cli("bootimg", "--dtb", ctx.tree / "build/sheng/sheng.dtb", "--ramdisk", "none", "-o", control)
        empty = json.loads((control.parent / "boot.json").read_text())
        require(empty["ramdisk_bytes"] == 0 and empty["fd_sha256"] == sha(fd)
                and empty["image_sha256"] == sha(control), "Official empty control differs from this new FD")
        proofs = {}
        dump = fd.with_name(fd.name + ".dump")
        for name, inf in (("AdvancedLogDxe", self.main / "package/UniXNUPkg/Driver/AdvancedLogDxe/AdvancedLogDxe.inf"),
                          ("DarwinBoot", ctx.tree / "drivers/DarwinBoot/DarwinBootPkg/Driver/DarwinBoot.inf")):
            match = re.search(r"^\s*FILE_GUID\s*=\s*([\da-f-]+)", inf.read_text(), re.I | re.M)
            require(match, "Cannot derive FFS GUID: " + name)
            guid = match.group(1).lower()
            found = [item for item in dump.rglob("info.txt") if "file guid: " + guid in item.read_text().lower()]
            require(len(found) == 1, "Require exactly one actual FFS: " + name)
            proofs[name] = found[0].read_text()
        shutil.copy2(fd, self.output / "SILICIUM_UEFI.fd")
        shutil.copy2(ctx.tree / "build/sheng/sheng.dtb", self.output / "firmware-input.dtb")
        shutil.copy2(self.device / "build/sheng/fv-check.json", self.output / "fv-check.json")
        (self.output / "ffs-proof.json").write_text(json.dumps(proofs, indent=2) + "\n")
        fixtures = self.output / "BootShim-fixtures"
        fixtures.mkdir(exist_ok=True)
        for name in ("report.json", "copy.uart.log", "already-in-place.uart.log", "shim.bin"):
            shutil.copy2(ctx.tree / "build/sheng/boot" / name, fixtures / name)
        changes = {"main": git(self.main, "diff", "--", "package"),
                   "uefi": git(self.uefi, "diff", "--", "Platforms/Xiaomi/shengPkg")}
        (self.output / "source-diffs.json").write_text(json.dumps(changes, indent=2) + "\n")
        files = {path.name: {"bytes": path.stat().st_size, "sha256": sha(path)}
                 for path in self.output.iterdir() if path.is_file() and path.name != "firmware-manifest.json"}
        (self.output / "firmware-manifest.json").write_text(json.dumps({
            "fd_sha256": sha(fd), "DarwinBoot_commit": DARWIN_PIN, "files": files,
            "host_fv_and_bootshim_verified": True, "kernel_or_payload_built": False,
            "official_empty_control_verified": True,
            "empty_control_sha256": sha(control), "empty_control_header_version": empty["header_version"],
            "stock_boot_header_compared": report["stock_boot_header_compared"],
            "stock_boot_header_version": report["stock_boot_header_version"],
            "device_operations": False, "hardware_tested": False}, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unixnu", type=Path, required=True)
    parser.add_argument("--device", type=Path, required=True)
    parser.add_argument("--out-root", type=Path, required=True, help="Existing27 resolver output root from cloud27 prepare")
    parser.add_argument("--output", type=Path, required=True, help="Dedicated new firmware output directory")
    parser.add_argument("--patch-root", type=Path, default=Path(__file__).resolve().parents[1] / "patches/firmware")
    parser.add_argument("--stage", choices=("prepare", "vendor", "build"), default="prepare")
    parser.add_argument("--download-vendor", action="store_true", help="Allow full pinned official fastboot ROM when verified UEFI cache is absent")
    parser.add_argument("--vendor-file", type=Path, help="Exact official uefi.elf; requires matching provenance")
    parser.add_argument("--vendor-provenance", type=Path, help="Reviewed provenance JSON shipped beside the supplied ELF")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    require(sys.platform == "darwin", "This reviewed draft is for macOS cloud hosts only")
    require(args.jobs > 0, "Positive jobs required")
    os.environ["NOBOOT"] = "1"
    # Use brewed LLVM/LLD, as the actual successful17 workflow did.
    prefixes = [run("brew", "--prefix", name, capture=True).strip() for name in ("llvm", "lld")]
    os.environ["PATH"] = os.pathsep.join([str(Path(prefix) / "bin") for prefix in prefixes] + [os.environ["PATH"]])
    pipeline = Pipeline(args)
    ctx = pipeline.prepare()
    if args.stage in ("vendor", "build"):
        pipeline.vendor(ctx)
    if args.stage == "build":
        pipeline.build(ctx)
    print("PASS: requested host firmware stage completed; hardware is untested.", flush=True)


if __name__ == "__main__":
    main()
