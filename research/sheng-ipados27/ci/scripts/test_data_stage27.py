"""Offline contracts against the exact pinned packing and configuration APIs.

Synthetic DBR/NXSB fixtures exercise format and orchestration contracts only.
They are not real APFS filesystems or macOS/hardware qualification.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parents[3]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed = load("tested_seed27", SCRIPTS / "seed27.py")
stage = load("tested_data_stage27", SCRIPTS / "data_stage27.py")
packed_path = ROOT / "drivers/DarwinBoot/Test/packed_ramdisk.py"
packed = load("tested_pinned_packed_ramdisk", packed_path)
grow = load("tested_pinned_data_grow", ROOT / "scripts/seed-data-grow.py")
IDENTITY = "2A5E9027-D9E1-40F9-983C-41BD3F1994F5"
ROOT_BYTES = 15753805824


def fixture(path, logical=8 << 30, container_bytes=None):
    # A bounded format fixture, not a mountable APFS filesystem.
    page = bytearray(4096)
    page[32:36] = b"NXSB"
    struct.pack_into("<IQ", page, 36, 4096, (container_bytes or logical) // 4096)
    tail = b"tail" + bytes(4092)
    blob = struct.pack("<8sIIQQ", b"DBRDISK1", 1, 4096, logical, 2)
    blob += struct.pack("<QQQQ", 0, 4096, logical - 4096, 4096) + page + tail
    path.write_bytes(blob)
    return page, tail


def metadata(path, logical, request_key="c" * 64):
    return {"os_build": "24A446", "os_version": "27.0.1", "data_stage_request_sha256": request_key,
            "seed17_reused": False, "original_os_inputs_modified": False, "initial_only": False,
            "root_capacity_qualified": True, "data_stage_host_only": True, "host_seed_creation_completed": True,
            "device_operations": False, "source_verification_level": "verified raw-image policy plus mounted identity",
            "packed_sha256": stage.sha(path), "packed": packed.inspect(path)[0], "volume_uuid": IDENTITY,
            "kernel_config_required": {"XNU_OWNER_DATA_VOLUME_UUID": IDENTITY}, "logical_data_gib": logical >> 30,
            "allocation": {"logical_bytes": logical}, "apfs_identity_verification": {
                "volume_uuid": IDENTITY, "logical_bytes": logical, "read_only": True, "physical_store_bound_to_seed": True}}


class SeedContracts(unittest.TestCase):
    def test_readonly_requires_explicit_boolean_evidence(self):
        for key, value in (("Writable", False), ("WritableVolume", False), ("ReadOnlyMedia", True),
                           ("ReadOnlyVolume", True), ("MediaReadOnly", True)):
            self.assertTrue(seed.read_only({key: value}))
        for info in ({}, {"Writable": True}, {"WritableVolume": 0}, {"ReadOnlyVolume": 1}, {"ReadOnlyVolume": False}):
            self.assertFalse(seed.read_only(info))

    def test_pinned_pack_small_roundtrip_and_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw, encoded = root / "input.raw", root / "packed.dbr"
            original = b"A" * 4096 + bytes(4096) + b"B" * 4096
            raw.write_bytes(original)
            report = packed.pack(raw, encoded)
            inspected, header = packed.inspect(encoded)
            self.assertEqual(inspected, report)
            self.assertEqual(set(report), {"bytes", "sha256", "encoded_bytes", "encoded_sha256", "packed"})
            logical, extents = packed.regions(encoded.read_bytes())
            rebuilt = bytearray(logical)
            for offset, content in extents:
                rebuilt[offset:offset + len(content)] = content
            self.assertEqual(rebuilt, original)
            self.assertEqual(header, original[:4096])
            self.assertEqual(report["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual(report["encoded_sha256"], stage.sha(encoded))

    def test_large_identity_is_not_the_encoded_hash_or_dense_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.dbr"
            for gib in (8, 215):
                logical = gib << 30
                head, tail = fixture(path, logical)
                report = seed.inspect_packed(packed, path, logical)
                identity = hashlib.sha256(b"SHNGSEED2" + struct.pack("<Q", logical))
                identity.update(struct.pack("<Q", 0) + head)
                identity.update(struct.pack("<Q", logical // 4096 - 1) + tail)
                self.assertEqual(report["sha256"], identity.hexdigest())
                self.assertEqual(report["encoded_sha256"], stage.sha(path))
                self.assertNotEqual(report["sha256"], report["encoded_sha256"])
                self.assertLess(path.stat().st_size, 16384)

    def test_container_geometry_is_checked_in_seed_and_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "wrong-container.dbr"
            logical = 8 << 30
            fixture(path, logical, container_bytes=7 << 30)
            with self.assertRaises(ValueError):
                seed.inspect_packed(packed, path, logical)
            with self.assertRaises(ValueError):
                stage.checked_seed(path, metadata(path, logical), packed, "c" * 64, logical)

    def test_cache_rejects_other_recipes_partial_receipts_and_uuid_mixups(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "seed.dbr"
            logical = 8 << 30
            fixture(path, logical)
            valid = metadata(path, logical)
            stage.checked_seed(path, valid, packed, "c" * 64, logical)
            changes = (("os_build", "21H461"), ("os_version", "17.7.11"), ("seed17_reused", True),
                       ("initial_only", True), ("root_capacity_qualified", False), ("host_seed_creation_completed", False),
                       ("source_verification_level", "mounted identity only"), ("data_stage_request_sha256", "d" * 64),
                       ("packed_sha256", "0" * 64), ("kernel_config_required", {"XNU_OWNER_DATA_VOLUME_UUID": "0" * 36}),
                       ("apfs_identity_verification", {}), ("logical_data_gib", None), ("logical_data_gib", True))
            for key, value in changes:
                bad = copy.deepcopy(valid)
                bad[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    stage.checked_seed(path, bad, packed, "c" * 64, logical)

    def test_real_root_capacity_and_native_store_arithmetic(self):
        for desired in (8, 215, 1024):
            allocation = seed.choose_size(stage.USERDATA_BYTES, ROOT_BYTES, desired, 1024, 1)
            pages = allocation["logical_bytes"] // 4096
            self.assertEqual(allocation["overlay_bytes"], grow.store_blocks(pages) * 4096)
            self.assertGreaterEqual(allocation["start_relative_bytes"], ROOT_BYTES + (4 << 20) + (1 << 30))
            self.assertEqual(allocation["end_relative_bytes"], stage.USERDATA_BYTES - (1024 << 20))
        self.assertEqual(seed.choose_size(stage.USERDATA_BYTES, ROOT_BYTES, 8, 1024, 1)["gib"], 8)
        with self.assertRaises(ValueError):
            seed.choose_size(stage.USERDATA_BYTES, stage.USERDATA_BYTES - (1 << 30), 8, 1024, 1)

    def test_config_uuid_is_written_and_restored_after_defconfig(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            config = work / ".config"
            baseline = 'CONFIG_XNU_OWNER_DATA_VOLUME_UUID="00000000-0000-0000-0000-000000000000"\nCONFIG_KEEP=y\n'
            ctx = types.SimpleNamespace(work=work, config_path=config, config={})
            for _ in range(2):
                config.write_text(baseline)
                record = stage.write_config_uuid(ctx, IDENTITY.lower())
                self.assertEqual(ctx.config["XNU_OWNER_DATA_VOLUME_UUID"], IDENTITY)
                self.assertTrue(ctx.config["KEEP"])
                self.assertEqual(record["config_sha256"], stage.sha(config))
                self.assertTrue(record["written_to_actual_config"])
            config.write_text(baseline + baseline)
            with self.assertRaises(ValueError):
                stage.write_config_uuid(ctx, IDENTITY)

    def test_equal_raw_root_tables_do_not_allow_other_signed_policy_copies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result, tree = root / "result", root / "tree"
            for directory in (result / "root-policies", tree / "build/verified-root-24A446"):
                for name in ("OS", "SystemOS"):
                    (directory / name).mkdir(parents=True)
                    (directory / name / "verification.json").write_text("{}")
            first = {"policies": {name: {"manifest_sha256": "a" * 64, "trusted_key_sha256": "b" * 64}
                                  for name in ("OS", "SystemOS")}}
            ctx = types.SimpleNamespace(tree=tree)
            with patch.object(stage, "root_plan", side_effect=[(first, b"same table manifest"), (copy.deepcopy(first), b"same table manifest")]):
                selected, _, _ = stage.find_policies(ctx, result, {})
                self.assertEqual(selected, result / "root-policies")
            for key in ("manifest_sha256", "trusted_key_sha256"):
                other = copy.deepcopy(first)
                other["policies"]["OS"][key] = "c" * 64
                with patch.object(stage, "root_plan", side_effect=[(first, b"same table manifest"), (other, b"same table manifest")]), \
                        self.assertRaises(ValueError):
                    stage.find_policies(ctx, result, {})

    def cache_context(self, root):
        main, work = root / "main", root / "work"
        tree = work / "tree"
        profile = main / "profiles/os" / stage.PROFILE / "profile.toml"
        profile.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "profiles/os" / stage.PROFILE / "profile.toml", profile)
        packing = tree / "drivers/DarwinBoot/Test/packed_ramdisk.py"
        packing.parent.mkdir(parents=True)
        shutil.copy2(packed_path, packing)
        growth = tree / "scripts/seed-data-grow.py"
        growth.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/seed-data-grow.py", growth)
        config = work / ".config"
        config.write_text('CONFIG_XNU_OWNER_DATA_VOLUME_UUID="00000000-0000-0000-0000-000000000000"\nCONFIG_KEEP=y\n')
        ctx = types.SimpleNamespace(work=work, tree=tree, config_path=config, config={}, board={
            "board": {"os_profile": stage.PROFILE}, "ipsw": {"build": "24A446"},
            "userdata": {"first_lba": 0, "last_lba": stage.USERDATA_BYTES // 4096 - 1, "lba_bytes": 4096}})
        return main, ctx, profile, packing, growth

    def test_completed_cache_restores_real_config_without_an_os_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            main, ctx, profile, packing, growth = self.cache_context(root)
            result = root / "data"
            result.mkdir()
            path = result / "data.dbr"
            fixture(path)
            plan = {"image_bytes": ROOT_BYTES, "manifest_sha256": "a" * 64}
            allocation = seed.choose_size(stage.USERDATA_BYTES, ROOT_BYTES, 8, 1024, 1)
            request = {"recipe": 1, "target": stage.PROFILE, "profile_sha256": stage.sha(profile),
                       "root_plan_sha256": stage.json_hash(plan), "seed_script_sha256": stage.sha(SCRIPTS / "seed27.py"),
                       "packing_helper_sha256": stage.sha(packing), "grow_helper_sha256": stage.sha(growth),
                       "desired_gib": 8, "allocation": allocation}
            record = metadata(path, 8 << 30, stage.json_hash(request))
            record["allocation"] = allocation
            (result / "data-seed.json").write_text(json.dumps(record))
            digest = stage.sha(path)
            with patch.object(stage.platform, "system", return_value="Darwin"), \
                    patch.object(stage, "find_policies", return_value=(root / "policies", plan, bytes(4096))), \
                    patch.object(stage.subprocess, "run", side_effect=AssertionError("Cache hit must not run a host/device command")):
                for _ in range(2):
                    ctx.config_path.write_text('CONFIG_XNU_OWNER_DATA_VOLUME_UUID="00000000-0000-0000-0000-000000000000"\n')
                    report = stage.data(main, ctx, result)
                    self.assertEqual(ctx.config["XNU_OWNER_DATA_VOLUME_UUID"], IDENTITY)
                    self.assertEqual(report["config_update"]["config_sha256"], stage.sha(ctx.config_path))
                    self.assertEqual(report["allocation"], record["allocation"])
                bad = dict(record, data_stage_request_sha256="0" * 64)
                (result / "data-seed.json").write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    stage.data(main, ctx, result)
            self.assertEqual(stage.sha(path), digest)

    def test_changed_pending_recipe_keeps_earlier_work_and_reaches_new_seed_attempt(self):
        from unixnu import ipsw
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            main, ctx, _, _, _ = self.cache_context(root)
            result, image_cache = root / "data", root / "images"
            legacy = result / "data-stage-work/request.json"
            legacy.parent.mkdir(parents=True)
            legacy.write_text('{"old_failed_recipe": true}')
            image_cache.mkdir()
            image = image_cache / "original.dmg"
            image.write_bytes(b"bounded verified-source fixture")
            source = types.SimpleNamespace(cache=image_cache, disk_image=lambda _: image)
            plan = {"image_bytes": ROOT_BYTES, "policies": {"OS": {
                "source_compressed_sha256": stage.sha(image), "image_bytes": 9613344768}}}
            attachment = {"volume": {"device": "/dev/disk5s1"}}
            tools = types.SimpleNamespace(authenticate_attachment=lambda *args: ("/dev/disk4", None, attachment))
            actual_helper, actual_sha = stage.helper, stage.sha

            def helper(name, path):
                return tools if path.name == "policy27.py" else actual_helper(name, path)

            def command(argv, **kwargs):
                if argv[0] == "sudo":
                    raise subprocess.CalledProcessError(1, argv)
                self.assertIn(argv[:2], (["diskutil", "mount"], ["hdiutil", "detach"]))
                return subprocess.CompletedProcess(argv, 0)

            with patch.object(stage.platform, "system", return_value="Darwin"), \
                    patch.object(stage, "find_policies", return_value=(root / "policies", plan, bytes(4096))), \
                    patch.object(ipsw, "Ipsw", return_value=source), patch.object(stage, "helper", side_effect=helper), \
                    patch.object(stage.subprocess, "run", side_effect=command):
                for version in ("a", "b"):
                    with patch.object(stage, "sha", side_effect=lambda path: version * 64 if Path(path) == SCRIPTS / "seed27.py" else actual_sha(path)):
                        with self.assertRaises(subprocess.CalledProcessError):
                            stage.data(main, ctx, result)
            requests = list((result / "data-stage-work").glob("*/request.json"))
            self.assertEqual(len(requests), 2)
            self.assertTrue(all(len(path.parent.name) == 64 for path in requests))
            self.assertEqual(json.loads(legacy.read_text()), {"old_failed_recipe": True})
            self.assertFalse((result / "data.dbr").exists())

    def test_fresh_preferences_use_27_build_and_mobile_parent_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            mount = Path(temporary)
            with patch.object(seed.os, "chown", create=True) as owner:
                seed.fresh_preferences(mount, "24A446")
            assigned = {call.args[0].relative_to(mount).as_posix(): call.args[1:] for call in owner.call_args_list}
            self.assertEqual(assigned["mobile"], (501, 501))
            self.assertEqual(assigned["mobile/Library"], (501, 501))
            preferences = mount / "mobile/Library/Preferences"
            migration = plistlib.loads((preferences / "com.apple.migration.plist").read_bytes())
            self.assertEqual(migration["LastSystemVersion"], "24A446")
            setup = plistlib.loads((preferences / "com.apple.purplebuddy.plist").read_bytes())
            self.assertTrue(setup["SetupDone"])
            display = plistlib.loads((preferences / "backboardd.plist").read_bytes())
            self.assertEqual(display, {"CAEnableDeepFramebuffer": False, "CAEnableFramebufferCompression": False,
                                       "CAEnableIOSurfaceCompression": False})

    def attachment(self):
        # Synthesized APFS whole is deliberately before the physical image.
        return {"system-entities": [{"dev-entry": "/dev/disk5"}, {"dev-entry": "/dev/disk5s1"},
                                    {"dev-entry": "/dev/disk4"}]}

    def disk_plists(self, raw, *, wrong_image=False, wrong_size=False, readonly=True, wrong_uuid=False):
        def answer(*command):
            if command == ("diskutil", "apfs", "list", "-plist"):
                return {"Containers": [
                    {"PhysicalStores": [{"DeviceIdentifier": "disk0s2"}]},
                    {"PhysicalStores": [{"DeviceIdentifier": "disk4"}], "Volumes": [{
                        "DeviceIdentifier": "disk5s1", "APFSVolumeUUID": str("00000000-0000-0000-0000-000000000000" if wrong_uuid else IDENTITY)}]}]}
            if command[:4] == ("diskutil", "info", "-plist", "/dev/disk4"):
                return {"DeviceNode": "/dev/disk4", "BusProtocol": "Disk Image", "TotalSize": 1 if wrong_size else 16384}
            if command == ("hdiutil", "info", "-plist"):
                return {"images": [{"image-path": str(raw.with_name("other.raw") if wrong_image else raw),
                                    "writeable": not readonly, **self.attachment()}]}
            if command[:2] == ("hdiutil", "attach"):
                return self.attachment()
            raise AssertionError(command)
        return answer

    def test_physical_store_is_selected_by_binding_not_enumeration_order(self):
        raw = Path("bounded-test-image.raw").resolve()
        with patch.object(seed, "plist_command", side_effect=self.disk_plists(raw)):
            self.assertEqual(seed.physical_device(self.attachment(), raw, 16384, readonly=True), "/dev/disk4")
        for changes in ({"wrong_image": True}, {"wrong_size": True}, {"readonly": False}):
            with patch.object(seed, "plist_command", side_effect=self.disk_plists(raw, **changes)), self.assertRaises(ValueError):
                seed.physical_device(self.attachment(), raw, 16384, readonly=True)

    def test_postpack_uuid_verification_binds_and_always_detaches(self):
        for wrong in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                path = work / "small.dbr"
                fixture(path, 16384)
                raw = work / "grown-verification.raw"
                with patch.object(seed, "plist_command", side_effect=self.disk_plists(raw, wrong_uuid=wrong)), \
                        patch.object(seed, "run") as detach:
                    if wrong:
                        with self.assertRaises(ValueError):
                            seed.verify_grown_uuid(packed, path, work, IDENTITY)
                    else:
                        receipt = seed.verify_grown_uuid(packed, path, work, IDENTITY)
                        self.assertEqual(receipt, {"volume_uuid": IDENTITY, "logical_bytes": 16384,
                                                 "read_only": True, "physical_store_bound_to_seed": True})
                    detach.assert_called_once_with("hdiutil", "detach", "/dev/disk4")

    def test_mount_must_be_one_of_the_new_virtual_nodes(self):
        mount = Path("test-mount").resolve()
        valid = {"DeviceNode": "/dev/disk5s1", "MountPoint": str(mount), "VolumeUUID": IDENTITY}
        with patch.object(seed, "plist_command", return_value=valid):
            self.assertEqual(seed.mounted_uuid(self.attachment(), mount), IDENTITY)
        for change in ({"DeviceNode": "/dev/disk0s1"}, {"MountPoint": str(mount.parent)}):
            with patch.object(seed, "plist_command", return_value=dict(valid, **change)), self.assertRaises(ValueError):
                seed.mounted_uuid(self.attachment(), mount)

    def test_failed_binding_cleanup_uses_only_returned_virtual_nodes(self):
        with patch.object(seed.subprocess, "run") as command:
            seed.detach_created(self.attachment(), None)
        self.assertEqual([call.args[0] for call in command.call_args_list],
                         [["hdiutil", "detach", "/dev/disk4"], ["hdiutil", "detach", "/dev/disk5"]])


if __name__ == "__main__":
    unittest.main()
