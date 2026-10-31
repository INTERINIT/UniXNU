"""Regress fileset nm output parsing without running a compiler or device tool."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[3] / "scripts/patch-xnu-entry-probe.py"
SPEC = importlib.util.spec_from_file_location("entry_probe27", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class SymbolTests(unittest.TestCase):
    def test_fileset_headers_and_undefined_names_are_skipped(self):
        output = ("Symbols from com.apple.kernel:\n"
                  "fffffff00aefb05c S _start_first_cpu\n"
                  "                 U _not_defined\n"
                  "Symbols from com.apple.driver.Example:\n"
                  "fffffff00b69d83c S _panic\n")
        with mock.patch.object(probe.subprocess, "run", return_value=SimpleNamespace(stdout=output)):
            symbols = probe.kernel_symbols("offline-only.macho")
        self.assertEqual(symbols, {0xfffffff00aefb05c: "_start_first_cpu", 0xfffffff00b69d83c: "_panic"})

    def test_plain_nm_and_first_alias_are_preserved(self):
        output = "0000000000000100 T _first\n0000000000000100 T _alias\n0000000000000200 s _data\n"
        with mock.patch.object(probe.subprocess, "run", return_value=SimpleNamespace(stdout=output)):
            symbols = probe.kernel_symbols("offline-only.macho")
        self.assertEqual(symbols, {0x100: "_first", 0x200: "_data"})


if __name__ == "__main__":
    unittest.main()
