"""Small host regressions; these do not run the Mac payload assembly path."""
import gzip
import copy
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zlib


spec = importlib.util.spec_from_file_location("payload27_tested", Path(__file__).with_name("payload_stage27.py"))
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


def addon(entries):
    body = b""
    for name, content in entries:
        name = name.encode() + b"\0"
        packed = zlib.compress(content)
        body += struct.pack("<IIQQ", len(name), 0o644, len(content), len(packed))
        body += name + bytes(-len(name) % 8) + packed + bytes(-len(packed) % 8)
    return b"NGPUADD2" + struct.pack("<IIQ", len(entries), 0, 24 + len(body)) + body


class PayloadTests(unittest.TestCase):
    def test_actual_data_receipt_schema_without_extra_completion_flag(self):
        identity, seed_hash, config_hash = "2A5E9027-D9E1-40F9-983C-41BD3F1994F5", "a" * 64, "b" * 64
        allocation = {"logical_bytes": 8 << 30, "root_image_bytes": 16 << 30, "tail_reserve_mib": 1024}
        seed = {"os_build": "24A446", "seed17_reused": False, "original_os_inputs_modified": False,
                "root_capacity_qualified": True, "data_stage_host_only": True,
                "source_verification_level": "verified raw-image policy plus mounted identity",
                "volume_uuid": identity, "packed_sha256": seed_hash, "allocation": allocation,
                "data_stage_request_sha256": "c" * 64}
        stage = {"target": payload.PROFILE, "host_execution_completed": True, "device_operations": False,
                 "fresh_seed_reused_17": False, "data_seed": "data.dbr", "data_seed_sha256": seed_hash,
                 "root_image_bytes": allocation["root_image_bytes"], "allocation": allocation,
                 "data_stage_request_sha256": seed["data_stage_request_sha256"],
                 "config_update": {"written_to_actual_config": True, "XNU_OWNER_DATA_VOLUME_UUID": identity,
                                   "config_sha256": config_hash}}
        native = {"stage": "kernel", "source_pins": payload.PINS, "data_volume_uuid": identity,
                  "config_sha256": config_hash, "data_seed_sha256": seed_hash}
        config = {"XNU_OWNER_DATA_VOLUME_UUID": identity}
        self.assertEqual(payload.check_data_receipts(seed, native, stage, config, seed_hash, config_hash), identity)
        for field, value in (("host_execution_completed", False), ("data_seed_sha256", "d" * 64),
                             ("config_update", {"written_to_actual_config": True,
                                                "XNU_OWNER_DATA_VOLUME_UUID": identity, "config_sha256": "e" * 64})):
            bad = copy.deepcopy(stage)
            bad[field] = value
            with self.assertRaises(ValueError):
                payload.check_data_receipts(seed, native, bad, config, seed_hash, config_hash)
        weak = dict(seed, source_verification_level="mounted identity only")
        with self.assertRaises(ValueError):
            payload.check_data_receipts(weak, native, stage, config, seed_hash, config_hash)

    def test_generated_data_uuid_matches_actual_upstream_producer(self):
        baseline = Path(__file__).resolve().parents[4] / "scripts/build-xnu-4k-baseline.sh"
        text = baseline.read_text(encoding="utf-8")
        self.assertIn("OWNER_DATA_HEADER=$ROOT/build/xnu/owner-data-volume.h", text)
        producer = text.split("<<'PY_DATA_UUID'\n", 1)[1].split("\nPY_DATA_UUID", 1)[0]
        identity = "2A5E9027-D9E1-40F9-983C-41BD3F1994F5"
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            header = tree / "build/xnu/owner-data-volume.h"
            subprocess.run([sys.executable, "-c", producer, str(header), "1", "1", identity,
                            "F914C62A-AD00-47C6-8281-5746291C339A", "2F8E6EED-68D5-4261-B8A3-12571BAA2DD4", "1"], check=True)
            payload.check_generated_uuid(tree, identity)
            with self.assertRaises(ValueError):
                payload.check_generated_uuid(tree, "00000000-0000-0000-0000-000000000000")

    def test_actual_prelink_schema_keeps_runtime_qualification_separate(self):
        record = {"candidate_written": True, "candidate_sha256": "a" * 64, "candidate_bytes": 1234,
                  "inputs": {"kernelcache_sha256": payload.APPLE_KERNEL_SHA}, "mapping_complete": False,
                  "allow_missing": True, "runtime_qualified": False, "loadable": False}
        payload.check_prelink_record(record, "a" * 64, 1234)
        with self.assertRaises(ValueError):
            payload.check_prelink_record(dict(record, candidate_written=False), "a" * 64, 1234)
        with self.assertRaises(ValueError):
            payload.check_prelink_record(record, "b" * 64, 1234)

    def test_only_explicit_install_choice_resets_data(self):
        values = payload.arguments({"payload": {"kernel_args": ["-v", "native-source-storage=1"]}})
        config = tomllib.loads(payload.menu(" ".join(values)))
        self.assertEqual(config["boot"], {"timeout": -1, "default": "tools"})
        normal, install = config["entry"][:2]
        self.assertNotIn("sheng-data-reset", normal["args"])
        self.assertNotIn("confirm", normal)
        self.assertEqual(install["args"], normal["args"])
        self.assertEqual(install["confirm_args"], ["sheng-data-reset=1"])
        self.assertEqual(len(install["confirm_titles"]), 1)
        self.assertIn("sheng-data-persist=2", normal["args"])
        self.assertIn("sheng-log-reserve=1024", normal["args"])
        self.assertIn("sheng-autoreset=0", normal["args"])
        self.assertIn("sheng-log=1", normal["args"])
        self.assertIn("sheng-diag-export=1", normal["args"])
        with self.assertRaises(ValueError):
            payload.arguments({"payload": {"kernel_args": ["sheng-data-reset=0"]}})
        with self.assertRaises(ValueError):
            payload.menu("x" * 901)

    def test_v3_preserves_gzip_and_fat_using_stock_vendor_dtb(self):
        fd, shim, fat = b"new27-firmware" * 23, bytearray(64), b"bounded-fat-payload" * 79
        shim[56:60] = b"ARM\x64"
        struct.pack_into("<Q", shim, 16, len(shim) + len(fd))
        dtb = bytearray(40)
        dtb[:4] = b"\xd0\x0d\xfe\xed"
        struct.pack_into(">I", dtb, 4, len(dtb))
        kernel = gzip.compress(bytes(shim) + fd, mtime=0) + dtb
        header = bytearray(4096)
        header[:8] = b"ANDROID!"
        struct.pack_into("<3I", header, 8, len(kernel), 0x8000, len(fat))
        struct.pack_into("<2I", header, 36, 4096, 0)
        old = bytes(header) + kernel + bytes(-len(kernel) % 4096) + fat + bytes(-len(fat) % 4096)
        new = payload.convert_v3(old, fat, fd, bytes(shim))
        self.assertEqual(struct.unpack_from("<I", new, 20)[0], 1580)
        self.assertEqual(struct.unpack_from("<I", new, 40)[0], 3)
        new_kernel, new_ramdisk = struct.unpack_from("<2I", new, 8)
        decoder = zlib.decompressobj(31)
        self.assertEqual(decoder.decompress(new[4096:4096 + new_kernel]), bytes(shim) + fd)
        self.assertTrue(decoder.eof)
        self.assertEqual(decoder.unused_data, b"")
        self.assertEqual(new[4096:4096 + new_kernel], kernel[:-len(dtb)])
        offset = 4096 + (new_kernel + 4095) // 4096 * 4096
        self.assertEqual(new[offset:offset + new_ramdisk], fat)
        with self.assertRaises(ValueError):
            payload.convert_v3(old, fat, fd + b"wrong", bytes(shim))
        with self.assertRaises(ValueError):
            payload.convert_v3(old[:4200], fat, fd, bytes(shim))

    def test_actual_signed_header_binding_and_extent_refusals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            headers = [bytes([index]) * 544 for index in (1, 2)]
            for name, header in zip(("OS", "SystemOS"), headers):
                (root / name).mkdir()
                (root / name / "manifest.bin").write_bytes(header + b"actual-table")
            bundle = struct.pack("<8sQQQ4Q", b"VROOTB01", 1, 2, 1152, 64, 544, 608, 544) + b"".join(headers)
            path = root / "root-policies.bin"
            path.write_bytes(bundle)
            self.assertTrue(payload.policy_bundle(path, root)["header_only"])
            bad = bytearray(bundle)
            struct.pack_into("<Q", bad, 48, 607)
            path.write_bytes(bad)
            with self.assertRaises(ValueError):
                payload.policy_bundle(path, root)
            path.write_bytes(bundle[:-1] + b"!")
            with self.assertRaises(ValueError):
                payload.policy_bundle(path, root)

    def test_addon_stream_bounds_traversal_and_no_daemon(self):
        entries = [("addons/NativeAdrenoMetal.publish", b"publish\n"),
                   ("addons/NativeAdrenoMetal.bundle/NativeAdrenoMetal", b"binary"),
                   ("addons/NativeAdrenoMetal.bundle/libvulkan_freedreno.dylib", b"turnip")]
        data = addon(entries)
        self.assertEqual(len(payload.addon_files(data)), 3)
        for bad in (data[:-1], addon(entries + [("addons/../escape", b"x")]),
                    addon(entries + [("bin/adrenoprobed", b"x")]), addon(entries + [entries[0]])):
            with self.assertRaises(ValueError):
                payload.addon_files(bad)

    def test_actual_final_symbol_file_mapping_and_bounds(self):
        anchor = bytes(index % 251 for index in range(395))
        strings = b"\0_verified_root_key\0"
        data = bytearray(784 + len(strings))
        struct.pack_into("<8I", data, 0, 0xfeedfacf, 0x100000c, 2, 2, 2, 96, 0, 0)
        struct.pack_into("<2I16s4Q4I", data, 32, 0x19, 72, b"__CONST", 0x1000, 512, 256, 512, 1, 1, 0, 0)
        struct.pack_into("<6I", data, 104, 2, 24, 768, 1, 784, len(strings))
        data[256:256 + len(anchor)] = anchor
        struct.pack_into("<IBBHQ", data, 768, 1, 0xf, 1, 0, 0x1000)
        data[784:] = strings
        self.assertEqual(payload.macho_symbol_bytes(bytes(data), "_verified_root_key", 395), anchor)
        # The actual emitter relocates member segment/linkedit file offsets to
        # absolute collection offsets, while keeping the symbol's relocated VA.
        nested = bytearray(128 + len(data))
        nested[128:] = data
        struct.pack_into("<8I", nested, 0, 0xfeedfacf, 0x100000c, 2, 12, 1, 56, 0, 0)
        struct.pack_into("<IIQQII", nested, 32, 0x80000035, 56, 0x1000, 128, 32, 0)
        nested[64:81] = b"com.apple.kernel\0"
        struct.pack_into("<Q", nested, 128 + 32 + 40, 128 + 256)
        struct.pack_into("<I", nested, 128 + 104 + 8, 128 + 768)
        struct.pack_into("<I", nested, 128 + 104 + 16, 128 + 784)
        self.assertEqual(payload.macho_symbol_bytes(bytes(nested), "_verified_root_key", 395), anchor)
        struct.pack_into("<Q", nested, 32 + 16, 0)
        with self.assertRaises(ValueError):
            payload.macho_symbol_bytes(bytes(nested), "_verified_root_key", 395)
        overlap = bytearray(data)
        overlap.extend(bytes(1400 - len(overlap)))
        overlap[176:200] = overlap[104:128]
        overlap[104:176] = overlap[32:104]
        struct.pack_into("<2I", overlap, 16, 3, 168)
        struct.pack_into("<Q", overlap, 104 + 40, 512)
        with self.assertRaisesRegex(ValueError, "not uniquely file-backed"):
            payload.macho_symbol_bytes(bytes(overlap), "_verified_root_key", 395)
        with self.assertRaises(ValueError):
            payload.macho_symbol_bytes(bytes(data), "_another_key", 395)
        struct.pack_into("<I", data, 768, len(strings))
        with self.assertRaises(ValueError):
            payload.macho_symbol_bytes(bytes(data), "_verified_root_key", 395)


if __name__ == "__main__":
    unittest.main()
