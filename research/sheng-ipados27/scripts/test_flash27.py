"""Offline flash27 controls. Fixtures never represent a bootable iPadOS package.

Every subprocess entry is forbidden. Simulated install/boot flows replace the
Python invoke function in memory; no executable or connected device is used.
An optional real sparse file is opened read-only by the actual sparse parser.
"""

import argparse
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


SOURCE = Path(__file__).with_name("flash27.py")
SPEC = importlib.util.spec_from_file_location("offline_flash27", SOURCE)
f = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f)
REAL_GEOMETRY = (f.CAPACITY, f.ROOT_BYTES, f.ROOT_SHA)
REAL_USERDATA = None
BLOCK = 4096
LAB_SERIAL = "OFFLINE-FIXTURE"


class SimulatedClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def hashed(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def sparse_fixture(path, capacity, root_bytes, header, *, kind=0xCAC2, fill=b"\0" * 4, tail_raw=False):
    raw = header + b"fixture-root-block".ljust(root_bytes - BLOCK, b"R")
    chunks = 3 if tail_raw else 2
    data = struct.pack("<I4H4I", 0xED26FF3A, 1, 0, 28, 12, BLOCK, capacity // BLOCK, chunks, 0)
    data += struct.pack("<2H2I", 0xCAC1, 0, len(raw) // BLOCK, 12 + len(raw)) + raw
    left = (capacity - root_bytes) // BLOCK
    if tail_raw:
        data += struct.pack("<2H2I", 0xCAC1, 0, 1, 12 + BLOCK) + bytes(BLOCK)
        left -= 1
    data += struct.pack("<2H2I", kind, 0, left, 16 if kind == 0xCAC2 else 12)
    if kind == 0xCAC2:
        data += fill
    path.write_bytes(data)


def boot_fixture(path, *, extra_dtb=False, load_address=0xA7100000):
    # Own host fixture only: this is not an original or deployable FD.
    shim = bytearray(128)
    fd = b"offline-FD-fixture".ljust(0x300000, b"F")
    struct.pack_into("<QQ", shim, 8, load_address, len(shim) + len(fd))
    shim[56:60] = b"ARM\x64"
    kernel = gzip.compress(bytes(shim) + fd, mtime=0)
    if extra_dtb:
        kernel += b"\xd0\x0d\xfe\xed" + b"fixture-appended-DTB"
    payload = b"offline-ramdisk-fixture" * 100
    head = bytearray(BLOCK)
    head[:8] = b"ANDROID!"
    struct.pack_into("<4I", head, 8, len(kernel), len(payload), 0, 1580)
    struct.pack_into("<I", head, 40, 3)
    path.write_bytes(bytes(head) + kernel + bytes((-len(kernel)) % BLOCK)
                     + payload + bytes((-len(payload)) % BLOCK))
    return {"fd_sha256": hashlib.sha256(fd).hexdigest(), "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "kernel_gzip_sha256": hashlib.sha256(kernel).hexdigest()}


class OfflineFlashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="flash27-offline-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for name in ("run", "Popen", "check_output"):
            self.stack.enter_context(mock.patch.object(f.subprocess, name, side_effect=AssertionError("No external command is permitted")))
        header = bytearray(BLOCK)
        header[:8] = b"SHNGROOT"
        struct.pack_into("<IIQ", header, 8, 2, 4, 2 * BLOCK)
        header[4064:] = hashlib.sha256(header[:4064]).digest()
        self.header = bytes(header)
        for name, value in (("CAPACITY", 16 * BLOCK), ("ROOT_BYTES", 2 * BLOCK),
                            ("ROOT_SHA", hashlib.sha256(header).hexdigest())):
            self.stack.enter_context(mock.patch.object(f, name, value))
        sparse_fixture(self.base / "userdata.sparse.img", f.CAPACITY, f.ROOT_BYTES, self.header)
        hashes = boot_fixture(self.base / "boot.img")
        line = "-v " + " ".join(name + "=" + value for name, value in f.REQUIRED_ARGS.items())
        self.boot = dict(hashes, status="host_verified", os_build="24A446", os_version="27.0.1",
                         header_version=3, appended_dtb=False, packed_boot_vroot_extracted_and_equal=True,
                         gpu_signature_and_cdhash_verified=True, image_sha256=hashed(self.base / "boot.img"),
                         image_bytes=(self.base / "boot.img").stat().st_size, root_policies_sha256="a" * 64,
                         owner_anchor_sha256="b" * 64, data_seed_sha256="c" * 64,
                         data_volume_uuid="11111111-2222-3333-4444-555555555555", kernel_args=line,
                         normal_cmdline=line, autoboot=False, normal_boot_resets_data=False)
        sparse = self.base / "userdata.sparse.img"
        self.root = dict(all_local_raw_blocks_verified=True, boot_policy_headers_match_verified=True,
                         root_manifest_sha256=f.ROOT_SHA, root_image_bytes=f.ROOT_BYTES,
                         userdata_bytes_expected_not_live_checked=f.CAPACITY, sparse_sha256=hashed(sparse),
                         sparse_file_bytes=sparse.stat().st_size, boot_policy_bundle_sha256="a" * 64,
                         owner_anchor_sha256="b" * 64)
        self.manifest = dict(status="assembled", device="sheng", os_build="24A446", os_version="27.0.1",
                             userdata_bytes=f.CAPACITY, target_serial=LAB_SERIAL, files={})
        self.refresh()

    def refresh(self):
        write_json(self.base / "boot-report.json", self.boot)
        write_json(self.base / "userdata-report.json", self.root)
        for name in ("boot.img", "boot-report.json", "userdata-report.json", "userdata.sparse.img"):
            path = self.base / name
            self.manifest["files"][name] = {"path": name, "bytes": path.stat().st_size, "sha256": hashed(path)}
        write_json(self.base / "manifest.json", self.manifest)

    def load(self, mode="check"):
        with contextlib.redirect_stdout(io.StringIO()):
            return f.load_package(self.base, mode)

    def call_main(self, *arguments):
        with mock.patch.object(sys, "argv", [str(SOURCE), *arguments, "--package", str(self.base)]), contextlib.redirect_stdout(io.StringIO()):
            return f.main()

    def complete_receipt(self):
        manifest, files = self.load("boot")
        identity = f.install_identity(manifest, files)
        f.write_install_state(self.base / "install-state.json", dict(identity, status="completed", flash_completed=True), create=True)
        return identity

    def test_default_check_never_calls_a_subprocess(self):
        self.call_main()

    def test_missing_or_pending_package_stops_locally(self):
        self.manifest["status"] = "pending_actual_boot_and_kernel"
        self.refresh()
        with self.assertRaises(ValueError):
            self.call_main("install")
        (self.base / "manifest.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.call_main()

    def test_package_file_path_cannot_escape(self):
        self.manifest["files"]["boot.img"]["path"] = "../outside.img"
        write_json(self.base / "manifest.json", self.manifest)
        with self.assertRaises(ValueError):
            self.load()

    def test_required_gpu_and_data_flags_and_no_reset(self):
        f.normal_arguments(self.boot)
        for name in f.REQUIRED_ARGS:
            changed = copy.deepcopy(self.boot)
            changed["normal_cmdline"] = changed["kernel_args"] = changed["normal_cmdline"].replace(name + "=" + f.REQUIRED_ARGS[name], name + "=0")
            with self.subTest(flag=name), self.assertRaises(ValueError):
                f.normal_arguments(changed)
        for suffix in (" sheng-data-reset=1", " sheng-data-reset=0", " sheng-gpu-power=9"):
            changed = dict(self.boot, normal_cmdline=self.boot["normal_cmdline"] + suffix,
                           kernel_args=self.boot["kernel_args"] + suffix)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                f.normal_arguments(changed)
        for field in ("autoboot", "normal_boot_resets_data"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                f.normal_arguments(dict(self.boot, **{field: True}))

    def test_policy_anchor_and_sparse_bindings_even_in_boot_mode(self):
        original = copy.deepcopy(self.root)
        for field in ("sparse_sha256", "boot_policy_bundle_sha256", "owner_anchor_sha256"):
            self.root = dict(original, **{field: "d" * 64})
            self.refresh()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load("boot")

    def test_actual_fd_payload_and_gzip_are_bound_to_report(self):
        original = copy.deepcopy(self.boot)
        for field in ("fd_sha256", "payload_sha256", "kernel_gzip_sha256"):
            self.boot = dict(original, **{field: "d" * 64})
            self.refresh()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load("boot")

    def test_v3_extra_dtb_truncation_and_load_address_rejected(self):
        path = self.base / "bad-boot.img"
        boot_fixture(path, extra_dtb=True)
        with self.assertRaises(ValueError):
            f.boot_header(path)
        boot_fixture(path, load_address=0xA7000000)
        with self.assertRaises(ValueError):
            f.boot_header(path)
        boot_fixture(path)
        good = path.read_bytes()
        path.write_bytes(good[:-1])
        with self.assertRaises(ValueError):
            f.boot_header(path)
        corrupt = bytearray(good)
        corrupt[44] = 1
        path.write_bytes(corrupt)
        with self.assertRaises(ValueError):
            f.boot_header(path)

    def test_sparse_dontcare_nonzero_fill_tail_raw_and_truncation_rejected(self):
        path = self.base / "bad.sparse"
        for kwargs in ({"kind": 0xCAC3}, {"fill": b"BAD!"}, {"tail_raw": True}):
            sparse_fixture(path, f.CAPACITY, f.ROOT_BYTES, self.header, **kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                f.sparse_header(path)
        good = (self.base / "userdata.sparse.img").read_bytes()
        for data in (good[:-1], good + b"X"):
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                f.sparse_header(path)

    def test_install_receipt_creation_is_exclusive(self):
        state = self.base / "install-state.json"
        f.write_install_state(state, {"status": "flashing"}, create=True)
        before = state.read_bytes()
        with self.assertRaises(FileExistsError):
            f.write_install_state(state, {"status": "another"}, create=True)
        self.assertEqual(state.read_bytes(), before)

    def test_boot_rejects_missing_incomplete_or_other_data_receipt_before_tool(self):
        with mock.patch.object(f, "invoke", side_effect=AssertionError("No device call allowed before receipt")):
            with self.assertRaises(ValueError):
                self.call_main("boot")
            identity = self.complete_receipt()
            state = self.base / "install-state.json"
            for update in ({"status": "failed"}, {"data_seed_sha256": "d" * 64}, {"target_serial": "OTHER-FIXTURE"}):
                receipt = dict(identity, status="completed", flash_completed=True)
                receipt.update(update)
                write_json(state, receipt)
                with self.subTest(update=update), self.assertRaises(ValueError):
                    self.call_main("boot")

    def test_simulated_install_only_flashes_userdata_once(self):
        tool = self.base / "dummy-tool-never-executed"
        tool.write_bytes(b"")
        commands = []
        state = self.base / "install-state.json"

        def simulated_invoke(_tool, arguments, **_kwargs):
            args = list(map(str, arguments))
            commands.append(args)
            if "flash" in args:
                self.assertEqual(json.loads(state.read_text())["status"], "flashing")
                self.assertEqual(args[args.index("flash") + 1], "userdata")
            if args[-2:] == ["getvar", "product"]:
                return "(bootloader) product: sheng\n"
            return LAB_SERIAL + "\tfastboot\n" if args == ["devices"] else "offline simulation"

        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f, "device_check"), mock.patch.object(f.time, "sleep"):
            self.call_main("install", "--fastboot", str(tool))
        self.assertEqual(sum("flash" in args for args in commands), 1)
        self.assertEqual(sum("boot" in args for args in commands), 1)
        self.assertFalse(any(word in ("erase", "format", "flash:raw") for args in commands for word in args))
        self.assertEqual(json.loads(state.read_text())["status"], "completed")
        with mock.patch.object(f, "invoke", side_effect=AssertionError("Repeated install reached a tool")):
            with self.assertRaises(ValueError):
                self.call_main("install", "--fastboot", str(tool))

    def test_interrupted_flash_keeps_receipt_and_blocks_repeat(self):
        tool = self.base / "dummy-tool-never-executed"
        tool.write_bytes(b"")

        def simulated_failure(_tool, arguments, **_kwargs):
            if "flash" in arguments:
                raise ValueError("simulated transport failure")
            return "offline simulation"

        with mock.patch.object(f, "invoke", side_effect=simulated_failure), mock.patch.object(f, "device_check"):
            with self.assertRaises(ValueError):
                self.call_main("install", "--fastboot", str(tool))
        receipt = json.loads((self.base / "install-state.json").read_text())
        self.assertEqual(receipt["status"], "failed")
        self.assertFalse(receipt["flash_completed"])
        with mock.patch.object(f, "invoke", side_effect=AssertionError("Repeat reached a tool")):
            with self.assertRaises(ValueError):
                self.call_main("install", "--fastboot", str(tool))

    def test_simulated_boot_never_reflashes_userdata(self):
        self.complete_receipt()
        (self.base / "userdata.sparse.img").unlink()
        tool = self.base / "dummy-tool-never-executed"
        tool.write_bytes(b"")
        commands = []

        def simulated_invoke(_tool, arguments, **_kwargs):
            args = list(map(str, arguments))
            commands.append(args)
            if args[-2:] == ["getvar", "product"]:
                return "(bootloader) product: sheng\n"
            return LAB_SERIAL + "\tfastboot\n" if args == ["devices"] else "offline simulation"

        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f, "device_check"), mock.patch.object(f.time, "sleep"):
            self.call_main("boot", "--fastboot", str(tool))
        self.assertFalse(any("flash" in args or "erase" in args or "format" in args for args in commands))
        self.assertEqual(sum("boot" in args for args in commands), 1)

    def test_reconnect_ignores_stale_enumeration_until_protocol_responds(self):
        clock = SimulatedClock()
        probes = []
        replies = iter((LAB_SERIAL + "\tfastboot\n", f.subprocess.TimeoutExpired("offline-probe", 3),
                        "", LAB_SERIAL + "\tfastboot\n", "(bootloader) product: sheng\n"))

        def simulated_invoke(_tool, arguments, **kwargs):
            self.assertGreaterEqual(clock.now, 3)
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 3)
            probes.append(list(arguments))
            reply = next(replies)
            if isinstance(reply, Exception):
                clock.sleep(kwargs["timeout"])
                raise reply
            return reply

        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f.time, "monotonic", clock.monotonic), mock.patch.object(f.time, "sleep", clock.sleep):
            f.wait_fastboot("never-executed", LAB_SERIAL)
        self.assertEqual(sum("getvar" in args for args in probes), 2)
        self.assertEqual(sum(args == ["devices"] for args in probes), 3)

    def test_reconnect_retries_transient_transport_failures(self):
        clock = SimulatedClock()
        replies = iter((ValueError("USB temporarily unavailable"), LAB_SERIAL + "\tfastboot\n",
                        ValueError("interface not ready"), LAB_SERIAL + "\tfastboot\n", "product: sheng\n"))

        def simulated_invoke(_tool, _arguments, **_kwargs):
            reply = next(replies)
            if isinstance(reply, Exception):
                raise reply
            return reply

        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f.time, "monotonic", clock.monotonic), mock.patch.object(f.time, "sleep", clock.sleep):
            f.wait_fastboot("never-executed", LAB_SERIAL)
        self.assertGreaterEqual(clock.now, 5)

    def test_reconnect_allows_a_slow_driver_without_requiring_disconnect(self):
        clock = SimulatedClock()

        def simulated_invoke(_tool, arguments, **_kwargs):
            if list(arguments) == ["devices"]:
                return "OTHER-TABLET\tfastboot\n" if clock.now < 65 else LAB_SERIAL + "\tfastboot\n"
            return "product: sheng\n"

        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f.time, "monotonic", clock.monotonic), mock.patch.object(f.time, "sleep", clock.sleep):
            f.wait_fastboot("never-executed", LAB_SERIAL)
        self.assertEqual(clock.now, 65)

    def test_reconnect_deadline_bounds_repeated_probe_timeouts(self):
        clock = SimulatedClock()

        def simulated_invoke(_tool, _arguments, **kwargs):
            clock.sleep(kwargs["timeout"])
            raise f.subprocess.TimeoutExpired("offline-probe", kwargs["timeout"])

        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f.time, "monotonic", clock.monotonic), mock.patch.object(f.time, "sleep", clock.sleep):
            with self.assertRaisesRegex(ValueError, r"retry Boot\.cmd; do not repeat Flash\.cmd"):
                f.wait_fastboot("never-executed", LAB_SERIAL, timeout=10)
        self.assertEqual(clock.now, 10)

    def test_reconnect_failure_after_flash_can_resume_with_boot(self):
        tool = self.base / "dummy-tool-never-executed"
        tool.write_bytes(b"")
        commands = []

        def simulated_invoke(_tool, arguments, **_kwargs):
            commands.append(list(map(str, arguments)))
            return "offline simulation"

        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f, "device_check"), mock.patch.object(f, "wait_fastboot", side_effect=ValueError("simulated reconnect timeout")):
            with self.assertRaises(ValueError):
                self.call_main("install", "--fastboot", str(tool))
        self.assertEqual(sum("flash" in args for args in commands), 1)
        self.assertFalse(any("boot" in args for args in commands))
        state = self.base / "install-state.json"
        receipt = state.read_bytes()
        self.assertTrue(json.loads(receipt)["flash_completed"])
        commands.clear()
        with mock.patch.object(f, "invoke", side_effect=simulated_invoke), mock.patch.object(f, "device_check"), mock.patch.object(f, "wait_fastboot"):
            self.call_main("boot", "--fastboot", str(tool))
        self.assertEqual(sum("boot" in args for args in commands), 1)
        self.assertFalse(any("flash" in args for args in commands))
        self.assertEqual(state.read_bytes(), receipt)

    def test_optional_real_sparse_is_checked_read_only(self):
        if REAL_USERDATA is None:
            self.skipTest("No real sparse image was supplied")
        with mock.patch.object(f, "CAPACITY", REAL_GEOMETRY[0]), mock.patch.object(f, "ROOT_BYTES", REAL_GEOMETRY[1]), mock.patch.object(f, "ROOT_SHA", REAL_GEOMETRY[2]):
            result = f.sparse_header(REAL_USERDATA)
        self.assertEqual(result["logical_bytes"], REAL_GEOMETRY[0])
        self.assertEqual(result["raw_bytes"] + result["zero_fill_bytes"], REAL_GEOMETRY[0])
        self.assertEqual(result["dont_care_chunks"], 0)


def main():
    global REAL_USERDATA
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--real-userdata", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    REAL_USERDATA = args.real_userdata.resolve() if args.real_userdata else None
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OfflineFlashTests))
    report = {"tests_run": result.testsRun, "passed": result.wasSuccessful(), "skipped": len(result.skipped),
              "flash_script_sha256": hashed(SOURCE), "test_script_sha256": hashed(Path(__file__)),
              "actual_userdata_sparse_parser_checked": REAL_USERDATA is not None and result.wasSuccessful(),
              "actual_userdata_whole_file_SHA256_recomputed": False, "all_external_subprocesses_forbidden": True,
              "install_and_boot_tests_are_in_memory_simulations_only": True, "device_operations": False, "hardware_tested": False}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.output, report)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
