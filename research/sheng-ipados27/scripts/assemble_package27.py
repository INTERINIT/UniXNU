"""Verify and assemble an actual27 package on the host, without device clients.

Default is a verification plan. --assemble publishes a manifest only after
actual boot/policy/sparse checks. It never runs Check/Flash/Boot launchers.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parent
PREFIX = "EFI/UniXNU/Payloads/"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def helper(name):
    spec = importlib.util.spec_from_file_location("assemble27_" + name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def stamp(path):
    info = Path(path).stat()
    return info.st_size, info.st_mtime_ns


def full_policies(builder, directory, openssl):
    """Authenticate complete tables with the real existing OpenSSL Policy class."""
    policies = {}
    for name, (identity, digest) in builder.PINNED.items():
        location = Path(directory) / name
        blob = location / "manifest.bin"
        require(blob.is_file() and 544 <= blob.stat().st_size <= 256 * 1024 * 1024, "Missing/bounded complete policy: " + name)
        policy = builder.Policy(blob.read_bytes(), (location / "trusted-key.bin").read_bytes(), openssl)
        require(policy.uuid == identity and policy.image_sha == digest, "Policy differs from exact public27 OS pins: " + name)
        report = load(location / "verification.json")
        require(report.get("real_c_signature_and_block_verification") is True and report.get("original_image_modified") is False
                and report.get("host_media_writable") is False and report.get("image_sha256") == digest
                and report.get("volume_uuid") == identity and report.get("image_bytes") == policy.size
                and report.get("blocks_verified") == policy.count and report.get("generation") == policy.generation
                and report.get("trusted_key_sha256") == hashlib.sha256(policy.anchor).hexdigest(),
                "Complete actual Mac C/RSA verification receipt differs: " + name)
        policies[name] = policy
    require(policies["OS"].anchor == policies["SystemOS"].anchor, "The two authenticated policies use different owner anchors")
    return policies


def boot_bundle(path, policies):
    data = Path(path).read_bytes()
    require(len(data) == 1152 and struct.unpack_from("<8sQQQ", data) == (b"VROOTB01", 1, 2, 1152), "Require the actual two-header policy bundle")
    cursor, headers = 64, []
    for index in range(2):
        offset, length = struct.unpack_from("<QQ", data, 32 + 16 * index)
        require(offset == cursor and length == 544 and offset + length <= len(data), "Invalid/bounded policy header extent")
        headers.append(data[offset:offset + length])
        cursor += length
    require(cursor == len(data) and sorted(headers) == sorted(policy.blob[:544] for policy in policies.values()),
            "The actual boot headers differ from the RSA-authenticated complete root policies")
    return hashlib.sha256(data).hexdigest()


def verify_boot(path, receipt_path, bundle_sha, anchor_sha, flash):
    path, receipt_path = Path(path), Path(receipt_path)
    require(path.is_file() and receipt_path.is_file(), "Actual boot27 image and receipt must exist before assembly")
    receipt = load(receipt_path)
    require(receipt.get("status") == "host_verified" and receipt.get("host_execution_completed") is True
            and receipt.get("device") == "sheng" and receipt.get("os_build") == "24A446"
            and receipt.get("os_version") == "27.0.1" and receipt.get("header_version") == 3
            and receipt.get("container_header_version") == 3
            and receipt.get("appended_dtb") is False and receipt.get("hardware_tested") is False
            and receipt.get("device_operations") is False, "Not a completed actual27 host payload receipt")
    require(receipt.get("packed_boot_vroot_extracted_and_equal") is True
            and receipt.get("gpu_signature_and_cdhash_verified") is True, "Actual packed vroot/GPU verification is missing")
    flash.normal_arguments(receipt)
    image_sha = sha(path)
    image = receipt.get("image", {})
    require(receipt.get("image_sha256") == receipt.get("boot_sha256") == image.get("sha256") == image_sha
            and receipt.get("image_bytes") == receipt.get("boot_bytes") == image.get("bytes") == path.stat().st_size,
            "Boot file and actual-image receipts differ")
    actual = flash.boot_header(path)
    require(all(actual[key] == receipt.get(key) for key in ("fd_sha256", "payload_sha256", "kernel_gzip_sha256")),
            "Actual FD/gzip/ramdisk bytes differ from the payload receipt")
    require(receipt.get("root_policies_sha256") == receipt.get("root_policy_bundle_sha256") == bundle_sha
            and receipt.get("owner_anchor_sha256") == anchor_sha, "Boot root policy/actual-kernel owner anchor differs")
    inventory = receipt.get("payload_files", {})
    for name, expected in (("kernel.macho.vroot", bundle_sha), ("kernel.macho.trustcache", receipt.get("owner_trust_sha256")),
                           ("kernel.macho.gpuaddon", receipt.get("gpu_addon_sha256")), ("scratch-data.img", receipt.get("data_seed_sha256"))):
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected)
                and inventory.get(PREFIX + name) == expected, "Packed payload sidecar receipt differs: " + name)
    require(re.fullmatch(r"[0-9a-f]{64}", receipt.get("kernel_sha256", ""))
            and re.fullmatch(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", receipt.get("data_volume_uuid", "")),
            "Actual kernel/Data identity receipt is absent")
    return receipt, image_sha


def verify_sparse(path, report_path, builder, policies, flash):
    """Read the existing sparse transport; never materialize or rebuild raw media."""
    path, report_path = Path(path), Path(report_path)
    report = load(report_path)
    require(report.get("build") == "24A446" and report.get("device") == "sheng"
            and report.get("all_local_raw_blocks_verified") is True and report.get("input_readiness_only") is False
            and report.get("device_operations") is False and report.get("missing_inputs") == [],
            "Original sparse receipt is not a completed actual-root verification")
    require(report.get("userdata_bytes_expected_not_live_checked") == flash.CAPACITY == builder.PARTITION_BYTES
            and report.get("sparse_file_bytes") == path.stat().st_size, "Actual sparse capacity/file extent differs")
    images = {name: SimpleNamespace(size=policy.size) for name, policy in policies.items()}
    header, windows, objects, root_bytes = builder.layout(images, policies)
    require(root_bytes == flash.ROOT_BYTES == report.get("root_image_bytes")
            and hashlib.sha256(header).hexdigest() == flash.ROOT_SHA == report.get("root_manifest_sha256")
            and windows == report.get("windows") and objects == report.get("objects"),
            "Signed raw geometry/table digests do not match the original SHNGROOTv2 receipt")
    require(report.get("owner_anchor_sha256") == hashlib.sha256(policies["OS"].anchor).hexdigest(), "Sparse source report carries another owner anchor")
    before = stamp(path)
    print("Verifying the complete existing sparse file, OS windows and policy tables...", flush=True)
    actual, _ = builder.inspect_sparse(path, flash.CAPACITY, ranges=windows + objects)
    require(stamp(path) == before and actual["sha256"] == report.get("sparse_sha256")
            and actual["actual_root_header_sha256"] == flash.ROOT_SHA and actual["dont_care_chunks"] == 0,
            "Actual sparse SHA/layout changed since its complete block verification")
    flash.sparse_header(path)
    return report, actual, before


def launcher(mode):
    require(mode in ("check", "install", "boot"), "Invalid launcher mode")
    # No target, partition name or command from input metadata enters cmd.exe.
    return ("@echo off\r\nsetlocal\r\ncd /d \"%~dp0\"\r\n"
            "if exist \"tools\\python\\python.exe\" goto bundled\r\n"
            "where py >nul 2>nul\r\nif not errorlevel 1 goto py\r\n"
            f"python \"%~dp0flash27.py\" {mode} --package \"%~dp0.\"\r\nexit /b %errorlevel%\r\n"
            ":py\r\n" + f"py -3 \"%~dp0flash27.py\" {mode} --package \"%~dp0.\"\r\nexit /b %errorlevel%\r\n"
            ":bundled\r\n" + f"\"%~dp0tools\\python\\python.exe\" \"%~dp0flash27.py\" {mode} --package \"%~dp0.\"\r\nexit /b %errorlevel%\r\n")


def link_or_copy(source, target, *, large=False, allow_large_copy=False):
    require(not target.exists() and not target.is_symlink(), "Staging destination already exists")
    if large:
        try:
            os.link(source, target)
            return "hardlink"
        except OSError:
            require(allow_large_copy, "A same-volume hardlink is unavailable; choose that volume or explicitly allow the large copy")
    with Path(source).open("rb") as incoming, target.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 8 * 1024 * 1024)
    return "copy"


def assemble(args):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.target_serial), "An explicit private target serial is required")
    boot, boot_report, sparse, sparse_report, bundle, policy_dir = [Path(value).resolve() for value in
            (args.boot, args.boot_report, args.userdata, args.userdata_report, args.boot_policies, args.policies)]
    # Fail before crypto or large reads when the real cloud result is absent.
    require(boot.is_file() and boot_report.is_file(), "Actual cloud-built boot27 image/receipt are missing; no package can be assembled")
    builder, flash = helper("build_userdata27_windows"), helper("flash27")
    executable = builder.openssl_path(args.openssl)
    require(executable.name.lower() in ("openssl", "openssl.exe"), "Only a real OpenSSL executable is allowed")
    policies = full_policies(builder, policy_dir, executable)
    bundle_sha = boot_bundle(bundle, policies)
    anchor_sha = hashlib.sha256(policies["OS"].anchor).hexdigest()
    receipt, image_sha = verify_boot(boot, boot_report, bundle_sha, anchor_sha, flash)
    original, actual_sparse, sparse_stamp = verify_sparse(sparse, sparse_report, builder, policies, flash)
    bound = dict(original, boot_policy_headers_match_verified=True, boot_policy_bundle_sha256=bundle_sha,
                 assembled_from_original_sparse_report_sha256=sha(sparse_report), final_boot_package_paired=True,
                 actual_sparse_whole_file_SHA256_rechecked=True, sparse_rebuilt=False)
    plan = {"status": "ready_to_assemble", "os_build": "24A446", "os_version": "27.0.1",
            "boot_sha256": image_sha, "sparse_sha256": actual_sparse["sha256"], "root_policy_bundle_sha256": bundle_sha,
            "owner_anchor_sha256": anchor_sha, "device_operations": False, "hardware_tested": False}
    if not args.assemble:
        return plan
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    require(not (output / "install-state.json").exists() and not (output / "install-state.json").is_symlink(),
            "Preserve an installed package and its persistent-Data receipt")
    manifest_path = output / "manifest.json"
    require(not manifest_path.is_symlink(), "Preserve an unexpected manifest link")
    require(not manifest_path.exists() or load(manifest_path).get("status") != "assembled", "Preserve the existing assembled package")
    lock = output / ".assemble27.lock"
    with lock.open("x", encoding="utf-8") as stream:
        stream.write("host-only assembly in progress\n")
    try:
        with tempfile.TemporaryDirectory(prefix=".assemble27-", dir=output) as temporary:
            stage = Path(temporary).resolve()
            require(stage.parent == output and stage.name.startswith(".assemble27-"), "Staging cleanup must remain inside package")
            link_or_copy(boot, stage / "boot.img")
            link_or_copy(boot_report, stage / "boot-report.json")
            storage_mode = link_or_copy(sparse, stage / "userdata.sparse.img", large=True, allow_large_copy=args.copy_large)
            (stage / "userdata-report.json").write_text(json.dumps(bound, indent=2) + "\n", encoding="utf-8")
            link_or_copy(SCRIPTS / "flash27.py", stage / "flash27.py")
            for name, mode in (("Check.cmd", "check"), ("Flash.cmd", "install"), ("Boot.cmd", "boot")):
                (stage / name).write_bytes(launcher(mode).encode("ascii"))
            files = {path.name: {"path": path.name, "bytes": path.stat().st_size,
                     "sha256": actual_sparse["sha256"] if path.name == "userdata.sparse.img" else sha(path)}
                     for path in stage.iterdir() if path.is_file()}
            document = dict(plan, status="assembled", device="sheng", userdata_bytes=flash.CAPACITY,
                            target_serial=args.target_serial, files=files, sparse_storage_mode=storage_mode,
                            no_device_operation_performed=True)
            (stage / "manifest.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            # The large sparse file was just checked above. Recheck boot/report
            # bindings here without rereading15GB a second time on a hardlink.
            flash.load_package(stage, "boot")
            require(stamp(sparse) == sparse_stamp, "Sparse source changed after its full SHA verification")
            if storage_mode == "hardlink":
                require(os.path.samefile(sparse, stage / "userdata.sparse.img"), "Sparse hardlink does not refer to the verified file")
            else:
                require(sha(stage / "userdata.sparse.img") == actual_sparse["sha256"], "Large copy differs from the verified source")
            for name, spec in files.items():
                target = output / name
                if target.exists() or target.is_symlink():
                    require(target.is_file() and not target.is_symlink() and target.stat().st_size == spec["bytes"]
                            and (os.path.samefile(target, stage / name) or sha(target) == spec["sha256"]),
                            "Preserve different existing package file: " + name)
            for name in files:
                target = output / name
                if not target.exists():
                    os.link(stage / name, target)  # exclusive publication; never replaces a file
            pending = output / ".manifest27.pending"
            with pending.open("x", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(pending, manifest_path)  # the only assembled manifest is published last
        return document
    finally:
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("boot", "boot-report", "userdata", "userdata-report", "boot-policies", "policies", "output"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--target-serial", required=True, help="Private local target identity; never hardcoded or published")
    parser.add_argument("--openssl", type=Path)
    parser.add_argument("--assemble", action="store_true", help="Publish a host package after all actual checks; default is a plan")
    parser.add_argument("--copy-large", action="store_true", help="Explicitly allow a15GB copy when a hardlink is unavailable")
    args = parser.parse_args()
    result = assemble(args)
    print(json.dumps({key: value for key, value in result.items() if key != "target_serial"}, indent=2))


if __name__ == "__main__":
    main()
