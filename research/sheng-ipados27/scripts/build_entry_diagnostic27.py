"""Build a RAM-only entry diagnostic from the existing paired27 package.

The retained kernel must occupy one unchanged contiguous file range in the
actual FAT payload. Only that same-length range changes. No device tool runs.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys


REPO = Path(__file__).resolve().parents[3]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(arguments, log, env):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True, env=env)
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    result.check_returncode()


def apply_bindings(kernel, record_path):
    """Replace only reviewed chain targets, preserving PAC and chain metadata."""
    sys.path.insert(0, str(REPO / "kits/XnuPrelink"))
    from kc_image import Image
    from fileset_emit import chain_word, decode
    record = load(record_path)
    data = bytearray(kernel.read_bytes())
    if digest(data) != record["kernel_sha256"]:
        raise ValueError("The reviewed binding is for another exact emitted kernel")
    image = Image(data)
    native = Image(data, image.entries["com.apple.kernel"][1])
    names = {}
    for address, symbols in native.symbols().items():
        for symbol in symbols:
            names.setdefault(symbol, set()).add(address)
    fixups = image.fixups()
    applied = []
    for entry in record["bindings"]:
        site = int(entry["site"], 16)
        at = image.offset(site, 8)
        previous = struct.unpack_from("<Q", data, at)[0]
        target, auth, key, diversity, addrdiv, step = decode(previous)
        old_names = (names[entry["expected_target_symbol"]] if "expected_target_symbol" in entry
                     else {int(entry["expected_target"], 16)})
        new_names = names[entry["native_symbol"]]
        if (previous != int(entry["expected_word"], 16) or site not in fixups or
                len(old_names) != 1 or image.base + target != next(iter(old_names)) or len(new_names) != 1):
            raise ValueError("The actual chained import differs from its reviewed evidence")
        replacement = next(iter(new_names))
        word = chain_word(auth, key, diversity, addrdiv, replacement - image.base, step)
        struct.pack_into("<Q", data, at, word)
        changed = Image(data).fixups()[site]
        if changed[0] != replacement or changed[1:] != fixups[site][1:]:
            raise ValueError("The rebound import changed PAC metadata or resolved to another target")
        applied.append(dict(entry, native_address=hex(replacement), word=hex(word)))
    kernel.write_bytes(data)
    return applied


def build(package, source, output, llvm, reset_delay=0, reset_after=None, panic_screen=False, uefi=None, bindings=None):
    manifest = load(package / "manifest.json")
    report = load(package / "boot-report.json")
    original = source.read_bytes()
    boot = (package / "boot.img").read_bytes()
    if digest(original) != report["kernel_sha256"] or digest(boot) != report["boot_sha256"]:
        raise ValueError("Require the unchanged kernel and its actual paired boot image")
    at = boot.find(original)
    if at < 0 or boot.find(original, at + 1) >= 0:
        raise ValueError("Require one exact contiguous kernel range; fragmented payloads need the FAT builder")
    output.mkdir(parents=True, exist_ok=False)
    kernel = output / "kernel-entry-probe.macho"
    kernel.write_bytes(original)
    rebound = apply_bindings(kernel, bindings) if bindings else []
    env = dict(os.environ, UNIXNU_XNU_ARCH="arm64e", UNIXNU_IOS_VERSION="27.0")
    if llvm:
        env["PATH"] = str(llvm) + os.pathsep + env.get("PATH", "")
    if uefi:
        env["UNIXNU_UEFI"] = str(uefi)
    probe_args = ["--reset-delay", str(reset_delay)] if reset_delay else ["--no-reset"]
    if reset_after:
        if not reset_delay:
            raise ValueError("A named reset checkpoint requires a nonzero delay")
        probe_args += ["--reset-after", reset_after]
    if panic_screen:
        probe_args += ["--panic-screen"]
    run([sys.executable, REPO / "scripts/patch-xnu-entry-probe.py", kernel, *probe_args],
        output / "entry-probe-build.log", env)
    run([sys.executable, REPO / "scripts/seal-source-crypto-kernel.py", kernel,
         "--kernel-args", report["normal_cmdline"]], output / "post-seal-build.log", env)
    patched = kernel.read_bytes()
    seal = load(kernel.with_suffix(kernel.suffix + ".crypto-hmac.json"))
    code, size, field = int(seal["code_file_offset"], 16), seal["code_bytes"], int(seal["hmac_file_offset"], 16)
    if len(patched) != len(original) or patched[field:field + 32] != hmac.digest(b"\0", patched[code:code + size], "sha256"):
        raise ValueError("Diagnostic length or actual source-provider POST seal differs")
    final = boot[:at] + patched + boot[at + len(original):]
    kernel_size, ramdisk_size = struct.unpack_from("<2I", final, 8)
    payload_at = 4096 + ((kernel_size + 4095) // 4096) * 4096
    if not payload_at <= at < at + len(patched) <= payload_at + ramdisk_size:
        raise ValueError("The changed bytes must be entirely within the payload ramdisk")
    (output / "boot.img").write_bytes(final)
    kernel_hash, boot_hash = digest(patched), digest(final)
    report.update(kernel_sha256=kernel_hash, boot_sha256=boot_hash, image_sha256=boot_hash,
                  payload_sha256=digest(final[payload_at:payload_at + ramdisk_size]))
    report["image"]["sha256"] = boot_hash
    report["payload_files"]["EFI/UniXNU/Payloads/kernel.macho"] = kernel_hash
    report["kernel_packaging"].update(payload_input_sha256=kernel_hash, legacy_entry_probe_applied=True,
                                     legacy_panic_screen_applied=panic_screen, actual_post_hmac_rechecked=True)
    report["entry_diagnostic"] = {"entry_blue": True, "before_MMU_magenta": True,
                                  "automatic_reset": bool(reset_delay), "post_MMU_reset_delay_seconds": reset_delay,
                                  "reset_after_function": reset_after,
                                  "panic_renderer": panic_screen,
                                  "reviewed_bindings_applied": rebound,
                                  "source_boot_sha256": digest(boot), "source_kernel_sha256": digest(original)}
    write(output / "boot-report.json", report)
    for name in ("flash27.py", "userdata-report.json", "install-state.json", "Boot.cmd"):
        shutil.copy2(package / name, output / name)
    # Boot mode uses the existing install identity and never opens sparse media.
    # Do not add a Flash launcher or copy the15GB transport into this diagnostic.
    manifest["files"] = dict(manifest["files"])
    for name in ("boot.img", "boot-report.json", "flash27.py", "userdata-report.json", "Boot.cmd"):
        data = (output / name).read_bytes()
        manifest["files"][name] = {"path": name, "bytes": len(data), "sha256": digest(data)}
    manifest["boot_sha256"] = boot_hash
    manifest["ram_boot_diagnostic_only"] = True
    write(output / "manifest.json", manifest)
    result = {"status": "diagnostic_built", "boot_sha256": boot_hash, "kernel_sha256": kernel_hash,
              "kernel_file_bytes": len(patched), "kernel_payload_offset": hex(at),
              "boot_bytes": len(final), "firmware_and_all_other_payload_bytes_unchanged": True,
              "GPU_and_CPU_arguments_unchanged": True, "data_reset_added": False,
              "post_MMU_reset_delay_seconds": reset_delay,
              "reset_after_function": reset_after,
              "panic_renderer": panic_screen,
              "reviewed_bindings_applied": rebound,
              "userdata_written": False, "device_operations": False, "hardware_tested": False}
    write(output / "entry-diagnostic.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--llvm-dir", type=Path)
    parser.add_argument("--post-mmu-reset-delay", type=int, default=0, help="Timed CPU reset checkpoint after MMU enable; zero disables it")
    parser.add_argument("--reset-after", help="Move the reset checkpoint after this call in arm_init")
    parser.add_argument("--panic-screen", action="store_true", help="Capture panic text on the kernel framebuffer")
    parser.add_argument("--uefi", type=Path, help="Mu-Silicium source containing the panic renderer font")
    parser.add_argument("--bindings", type=Path, help="Source-backed chained import bindings for this exact kernel")
    args = parser.parse_args()
    print(json.dumps(build(args.package.resolve(), args.kernel.resolve(), args.output.resolve(), args.llvm_dir,
                           args.post_mmu_reset_delay, args.reset_after, args.panic_screen, args.uefi, args.bindings), indent=2))


if __name__ == "__main__":
    main()
