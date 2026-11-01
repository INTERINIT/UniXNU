"""Verify and publish a RAM-boot-only27 package for an existing installation.

Default is a read-only plan; --assemble writes a fresh output directory.
The existing sparse transport is never opened, copied or linked. No device
client is invoked, and the completed installation receipt is copied verbatim.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile


SCRIPTS = Path(__file__).resolve().parent


def helper():
    path = SCRIPTS / "assemble_package27.py"
    spec = importlib.util.spec_from_file_location("ram27_existing_assembler", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def matching_install(identity, old_root, boot):
    """A new executable may change; the installed root/Data identity may not."""
    wanted = {
        "boot_policy_bundle_sha256": boot.get("root_policies_sha256"),
        "data_seed_sha256": boot.get("data_seed_sha256"),
        "data_volume_uuid": boot.get("data_volume_uuid"),
    }
    if any(identity.get(key) != value for key, value in wanted.items()):
        raise ValueError("New boot belongs to another installed root policy or Data identity")
    if old_root.get("owner_anchor_sha256") != boot.get("owner_anchor_sha256"):
        raise ValueError("New boot has another installed root owner anchor")


def assemble(args):
    a = helper()
    result, installed, output = [Path(path).resolve() for path in
                                 (args.result, args.installed_package, args.output)]
    a.require(not output.exists() and not output.is_symlink(), "Use a fresh RAM-package output directory")
    a.require(not output.is_relative_to(installed) and not installed.is_relative_to(output)
              and not output.is_relative_to(result) and not result.is_relative_to(output),
              "Keep the RAM package separate from the installed baseline and source result")
    boot, boot_report = result / "payload27/boot27-v3.img", result / "payload27/boot27.json"
    a.require(boot.is_file() and boot_report.is_file(), "The actual completed payload image/receipt is missing")
    flash, builder = a.helper("flash27"), a.helper("build_userdata27_windows")
    old_manifest, old_files = flash.load_package(installed, "boot")
    identity = flash.install_identity(old_manifest, old_files)
    state = installed / "install-state.json"
    flash.completed_install(state, identity)
    state_bytes = state.read_bytes()
    root = a.load(old_files["userdata-report.json"])
    executable = builder.openssl_path(args.openssl)
    policy_root = Path(args.policies).resolve() if args.policies else result / "root-policies"
    policies = a.full_policies(builder, policy_root, executable)
    bundle_sha = a.boot_bundle(result / "root-policies.bin", policies)
    anchor_sha = hashlib.sha256(policies["OS"].anchor).hexdigest()
    receipt, image_sha = a.verify_boot(boot, boot_report, bundle_sha, anchor_sha, flash)
    matching_install(identity, root, receipt)
    kernel = result / "kernel.macho"
    a.require(kernel.is_file() and a.sha(kernel) == receipt["kernel_sha256"],
              "Actual source kernel differs from the completed boot receipt")
    launcher = flash.checked_file(installed, old_manifest["files"].get("Boot.cmd"))
    sources = {"boot.img": boot, "boot-report.json": boot_report,
               "flash27.py": SCRIPTS / "flash27.py", "Boot.cmd": launcher,
               "userdata-report.json": old_files["userdata-report.json"], "install-state.json": state}
    expected = {name: {"path": name, "bytes": path.stat().st_size, "sha256": a.sha(path)}
                for name, path in sources.items()}
    a.require(expected["install-state.json"]["sha256"] == hashlib.sha256(state_bytes).hexdigest(),
              "The original installation receipt changed during validation")
    plan = {"status": "ready_to_assemble", "package_kind": "ram_boot_only",
            "boot_sha256": image_sha, "root_policy_bundle_sha256": bundle_sha,
            "owner_anchor_sha256": anchor_sha, "data_volume_uuid": receipt["data_volume_uuid"],
            "data_seed_sha256": receipt["data_seed_sha256"],
            "source_kernel_sha256": receipt["kernel_sha256"],
            "installed_manifest_sha256": a.sha(installed / "manifest.json"),
            "unchanged_install_state_sha256": expected["install-state.json"]["sha256"],
            "userdata_media_opened": False, "userdata_media_copied": False,
            "userdata_media_linked": False, "device_operations": False, "hardware_tested": False}
    if not args.assemble:
        return plan
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()  # Exclusive: never overwrite a package or its install state.
    with tempfile.TemporaryDirectory(prefix=".ram27-", dir=output) as temporary:
        stage = Path(temporary)
        for name, source in sources.items():
            shutil.copy2(source, stage / name)
            a.require((stage / name).stat().st_size == expected[name]["bytes"]
                      and a.sha(stage / name) == expected[name]["sha256"], "Copied RAM-package input changed: " + name)
        a.require((stage / "install-state.json").read_bytes() == state_bytes == state.read_bytes(),
                  "Preserve the original completed installation receipt byte for byte")
        manifest = copy.deepcopy(old_manifest)
        # The absent sparse entry identifies the already installed medium; boot
        # mode checks this metadata but never opens that transport file.
        manifest["files"] = {"userdata.sparse.img": copy.deepcopy(old_manifest["files"]["userdata.sparse.img"]),
                             **expected}
        manifest.update(boot_sha256=image_sha, root_policy_bundle_sha256=bundle_sha,
                        owner_anchor_sha256=anchor_sha, ram_boot_only=True,
                        userdata_transport_included=False, sparse_storage_mode="existing_install_identity_only",
                        candidate_pending_hardware_test=True, device_operations=False, hardware_tested=False,
                        kernel_build_qualification=receipt.get("kernel_build_qualification", {}))
        (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        paired, files = flash.load_package(stage, "boot")
        flash.completed_install(stage / "install-state.json", flash.install_identity(paired, files))
        plan.update(status="host_verified", installed_receipt_copied_verbatim=True,
                    boot_only_package_checked=True)
        (stage / "ram-package27.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        (stage / "启动说明.txt").write_text(
            "此目录只提供 Boot.cmd 临时内存启动，不包含 userdata 镜像或刷写入口。\n"
            "已保留原根卷与 Data 身份。进入菜单后选择正常 iPadOS 启动项，不要选择 First install 或重置 Data。\n"
            "这是电脑端验证完成的候选包，仍需实机测试。校验记录见 ram-package27.json。\n",
            encoding="utf-8")
        # Publish the manifest last; a partial host copy cannot look complete.
        for path in stage.iterdir():
            if path.name != "manifest.json":
                os.link(path, output / path.name)
        os.link(stage / "manifest.json", output / "manifest.json")
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", type=Path, required=True, help="Actual decrypted result27 directory")
    parser.add_argument("--installed-package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="Fresh directory separate from the existing installation")
    parser.add_argument("--policies", type=Path, help="Full actual policies; defaults to RESULT/root-policies")
    parser.add_argument("--openssl", type=Path)
    parser.add_argument("--assemble", action="store_true")
    args = parser.parse_args()
    print(json.dumps(assemble(args), indent=2))  # No private serial is printed.


if __name__ == "__main__":
    main()
