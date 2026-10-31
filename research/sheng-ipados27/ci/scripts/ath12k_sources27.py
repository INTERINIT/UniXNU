"""Fetch the public Linux sources required by the full27 WiFi archive.

Follows Ath12kWifi/tools/fetch-sources.sh's shallow, filtered, sparse layout,
freezing its v7.0.14 source at the peeled commit. No driver source is patched,
and no compiler, kernel or device command is run. Default is a local plan.
FreeBSD is not used by build-ath12k-wifi.py and is not downloaded here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


MODULE_PIN = "f6bf561f92cc42761bdd417fce1d53fe1db9477c"
LINUX = {
    "url": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
    "ref": "v7.0.14", "commit": "458c6079fc1d41d564c37679c8ace02cd83ee817",
    "patterns": ("/drivers/net/wireless/ath/", "/drivers/bus/mhi/", "/include/", "/net/qrtr/",
                 "/drivers/soc/qcom/qmi_interface.c", "/drivers/soc/qcom/qmi_encdec.c"),
}


def git(path, *arguments):
    return subprocess.check_output(["git", "-C", str(path), *map(str, arguments)], text=True).strip()


def repository(path, commit, origin=None):
    path = Path(path)
    if not path.is_dir() or Path(git(path, "rev-parse", "--show-toplevel")).resolve() != path.resolve():
        raise ValueError("Source path is not its own Git checkout: " + str(path))
    if git(path, "rev-parse", "HEAD") != commit:
        raise ValueError("Preserve source checkout at a different commit: " + str(path))
    if origin is not None and git(path, "remote", "get-url", "origin") != origin:
        raise ValueError("Preserve source checkout from a different repository: " + str(path))


def file_sha(path):
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan(module):
    module = Path(module).resolve()
    repository(module, MODULE_PIN)
    return {"status": "planned", "module_commit": MODULE_PIN,
            "linux": {**LINUX, "patterns": list(LINUX["patterns"])},
            "official_fetch_recipe_sha256": file_sha(module / "tools/fetch-sources.sh"),
            "source_only": True, "kernel_or_objects_compiled": False, "device_operations": False,
            "freebsd_downloaded": False,
            "source_pin_provenance": "2026-10-31 git.kernel.org ls-remote v7.0.14 peeled tag"}


def fetch_commands(path):
    return [
        ["git", "clone", "--quiet", "--depth", "1", "--branch", LINUX["ref"],
         "--filter=blob:none", "--sparse", LINUX["url"], str(path)],
        ["git", "-C", str(path), "sparse-checkout", "set", "--no-cone", *LINUX["patterns"]],
    ]


def prepare(module, output, *, execute=False):
    module = Path(module).resolve()
    report = plan(module)
    if not execute:
        return report
    deps = module / "deps"
    if deps.is_symlink():
        raise ValueError("Preserve linked dependency directory: " + str(deps))
    deps.mkdir(exist_ok=True)
    destination = deps / "linux"
    if not destination.exists() and not destination.is_symlink():
        for command in fetch_commands(destination):
            subprocess.run(command, check=True)
    # Existing sources are checked in place, never reset, cleaned or replaced.
    repository(destination, LINUX["commit"], LINUX["url"])
    for name in ("drivers/net/wireless/ath/ath12k/core.c", "drivers/bus/mhi/host/boot.c", "include/linux/mhi.h"):
        if not (destination / name).is_file():
            raise FileNotFoundError("Linux source needed by the consumer is missing: " + name)
    report.update(status="sources_ready", actual_linux_commit=git(destination, "rev-parse", "HEAD"))
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "ath12k-sources27.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def run(device, result, *, execute=False):
    return prepare(Path(device).resolve() / "drivers/Ath12kWifi", result, execute=execute)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true", help="Fetch source only; default prints a local plan")
    args = parser.parse_args()
    print(json.dumps(run(args.device, args.output, execute=args.execute), indent=2))
