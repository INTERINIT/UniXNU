"""Isolate the optional diagnostic exporter during the native export bootstrap.

No diagnostic data or function implementation is replaced. The normal source
recipe still includes the exact original BootDiagExport.c translation unit.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path


SOURCE_SHA256 = "3e814261da9d98b6658f09041d171c32d9b06e4bdd0ae0996a464ce3a237a4b6"
DIAG_SHA256 = "4eac327136e4deefc4519c4af2a111af98a5fd0c2be18086f703185a7d19eafa"
BOOTSTRAP_ENV = "UNIXNU_SHENG_EXPORT_BOOTSTRAP"
OLD = b"        sources.append(device_source('BootDiagExport.c'))\n"
NEW = b"""        # This optional exporter reads GPU/display/input rings absent from the
        # source-kernel export bootstrap. Normal builds retain the original TU.
        export_bootstrap = os.environ.get('UNIXNU_SHENG_EXPORT_BOOTSTRAP', '0')
        if export_bootstrap not in ('0', '1'):
            parser.error('UNIXNU_SHENG_EXPORT_BOOTSTRAP must be 0 or 1')
        if export_bootstrap == '1' and (os.environ.get('XNU_NATIVE_LEGACY_DISPLAY') != '0' or
                                        os.environ.get('XNU_NATIVE_ADRENO') != '0'):
            parser.error('The export bootstrap requires Legacy display and Adreno explicitly disabled')
        if export_bootstrap != '1':
            sources.append(device_source('BootDiagExport.c'))
"""


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def adapted_source(original):
    """Refuse source drift, including an unexpected second export selection."""
    if sha_bytes(original) != SOURCE_SHA256 or original.count(OLD) != 1:
        raise ValueError("Review changed pinned source-storage recipe before the bootstrap adaptation")
    return original.replace(OLD, NEW)


def apply(tree, output=None):
    path = Path(tree) / "scripts/build-sheng-source-storage.py"
    original = path.read_bytes()
    # Reconstruct the known original for idempotence without accepting an
    # arbitrary script merely because it contains the new environment flag.
    if original.count(NEW) == 1:
        upstream = original.replace(NEW, OLD)
        expected = adapted_source(upstream)
        if expected != original:
            raise ValueError("Unexpected source-storage bootstrap adaptation")
    else:
        upstream = original
        expected = adapted_source(upstream)
        path.write_bytes(expected)
    report = {"upstream_sha256": SOURCE_SHA256, "adapted_sha256": sha_bytes(expected),
              "environment_flag": BOOTSTRAP_ENV, "default_compiles_original_diagnostics": True,
              "fake_hardware_definitions_added": False, "device_operations": False}
    if output is not None:
        (Path(output) / "source-storage27-adapter.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


@contextmanager
def export_bootstrap_mode():
    previous = os.environ.get(BOOTSTRAP_ENV)
    os.environ[BOOTSTRAP_ENV] = "1"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(BOOTSTRAP_ENV, None)
        else:
            os.environ[BOOTSTRAP_ENV] = previous


def require_normal_mode():
    if os.environ.get(BOOTSTRAP_ENV, "0") != "0":
        raise ValueError("Restore normal diagnostic compilation before the full kernel build")


def verify_archive_sources(tree, *, bootstrap):
    """Check an actual compiler receipt; this helper never creates one."""
    report_path = Path(tree) / "build/sheng-source-storage/report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    archive = Path(tree) / "build/sheng-source-storage/libShengSourceStorage.a"
    if (Path(report["archive"]).resolve() != archive.resolve() or
            sha_bytes(archive.read_bytes()) != report["archive_sha256"]):
        raise ValueError("Actual source-storage archive differs from its compiler receipt")
    entries = [(Path(name), digest) for name, digest in report["sources"].items()
               if Path(name).name == "BootDiagExport.c"]
    if bootstrap:
        if entries:
            raise ValueError("The export bootstrap unexpectedly compiled the GPU/input diagnostic exporter")
    elif len(entries) != 1 or entries[0][1] != DIAG_SHA256 or sha_bytes(entries[0][0].read_bytes()) != DIAG_SHA256:
        raise ValueError("The full source-storage build must compile the exact original BootDiagExport.c")
    return {"bootstrap": bootstrap, "diagnostic_export_compiled": bool(entries),
            "actual_archive_sha256": report["archive_sha256"],
            "actual_source_receipt_sha256": sha_bytes(report_path.read_bytes()),
            "original_diagnostic_source_sha256": DIAG_SHA256,
            "runtime_qualified": False, "device_operations": False}
