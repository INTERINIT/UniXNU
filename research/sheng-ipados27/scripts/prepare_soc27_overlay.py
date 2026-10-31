"""Generate and context-check the two missing SM8550 xnu-12377 hunks.

Only writes the new iPadOS27 patch/research directories. No device operations.
"""
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request

ROOT = Path(r"D:\iOS6sp\iPadOS27")
MAIN = ROOT / "source/UniXNU"
DEVICE = ROOT / "source/UniXNU-sheng"
OUT = ROOT / "patches/sm8550-xnu12377"
CHECK = ROOT / "research/soc27-context-check"
XNU = "ac9718fb1af618d5ce8678d0dc6e8a58f252216f"
FILES = ("osfmk/arm64/start.s", "bsd/kern/bsd_init.c")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def apply(path, check=False):
    cmd = ["git", "apply", "--check"] if check else ["git", "apply"]
    cmd += ["--include=" + name for name in FILES]
    cmd.append(str(path))
    subprocess.run(cmd, cwd=CHECK, check=True, capture_output=True, text=True)


def main():
    if CHECK.exists():
        raise ValueError("Preserve an existing context check; inspect before rerunning")
    OUT.mkdir(parents=True, exist_ok=True)
    CHECK.mkdir(parents=True)
    original = {}
    for name in FILES:
        url = f"https://raw.githubusercontent.com/apple-oss-distributions/xnu/{XNU}/{name}"
        with urllib.request.urlopen(url, timeout=45) as response:
            raw = response.read()
        raw.decode("utf-8")
        original[name] = raw
        path = CHECK / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    changes = {
        FILES[0]: ("#if HAS_CLUSTER\n\tand\t\tx0, x15, #0xFFFF", "#if HAS_CLUSTER || defined(BCM2837)\n\tand\t\tx0, x15, #0xFFFF"),
        FILES[1]: ('\tbsd_bufferinit();\n\n\t/*\n\t * Initialize the calendar.', '\tbsd_bufferinit();\n\n#if defined(XNU_SHENG_PMGR) && XNU_SHENG_PMGR\n\textern void sheng_pmgr_run(void);\n\tsheng_pmgr_run();\n#endif\n\n\t/*\n\t * Initialize the calendar.'),
    }
    patch_names = ("native-smp-secondary.patch", "sheng-platform-power.patch")
    for name, filename in zip(FILES, patch_names):
        old, new = changes[name]
        source = original[name].decode("utf-8")
        if source.count(old) != 1:
            raise ValueError("Original source context differs: " + name)
        changed = source.replace(old, new, 1)
        patch = "".join(difflib.unified_diff(source.splitlines(keepends=True), changed.splitlines(keepends=True), fromfile="a/" + name, tofile="b/" + name))
        (OUT / filename).write_text(patch, encoding="utf-8", newline="\n")
    (OUT / "series").write_text("native-smp-secondary.patch\nsheng-platform-power.patch\n", encoding="utf-8", newline="\n")

    # All original arch changes to the two affected source files go first.
    series = MAIN / "profiles/arch/arm64e/patches/xnu/series"
    arch = []
    for entry in series.read_text().splitlines():
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        patch = (series.parent / entry).resolve()
        apply(patch)
        arch.append(str(patch.relative_to(MAIN)))
    before_overlay = {name: sha((CHECK / name).read_bytes()) for name in FILES}
    for filename in patch_names:
        apply(OUT / filename, check=True)
        apply(OUT / filename)
    after_overlay = {name: sha((CHECK / name).read_bytes()) for name in FILES}
    # Verify the next OS series still applies, including the PMGR hook context.
    os_series = MAIN / "profiles/os/ipados-27.0.1-24A446/patches/xnu/series"
    os_patches = []
    for entry in os_series.read_text().splitlines():
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        if not entry.startswith("arch:"):
            raise ValueError("Unexpected OS patch scope")
        patch = (MAIN / "profiles/arch/arm64e" / entry.removeprefix("arch:")).resolve()
        apply(patch)
        os_patches.append(str(patch.relative_to(MAIN)))
    device_series = DEVICE / "patches/xnu-12377/series"
    for entry in device_series.read_text().splitlines():
        entry = entry.strip()
        if entry and not entry.startswith("#"):
            apply(device_series.parent / entry)
    report = {
        "upstream_xnu_commit": XNU,
        "upstream_xnu_tag": "xnu-12377.121.6",
        "upstream_apple_files_sha256": {name: sha(raw) for name, raw in original.items()},
        "main_commit": "793d6bddf7ea90678e3a61e2b2bd4350e5fdce16",
        "device_commit": "f47b27ad97e97bee945f8af34a8430e3abcf918c",
        "soc_commit": "23b2049fcd9e30356161def84231334fb55ecca9",
        "arch_series": arch, "os_series": os_patches,
        "before_overlay_sha256": before_overlay, "after_overlay_sha256": after_overlay,
        "patch_sha256": {name: sha((OUT / name).read_bytes()) for name in patch_names},
        "ordered_context_checks_passed": True,
        "scope": "Affected start.s and bsd_init.c contexts through arch, local SoC, OS and device series; other source paths were excluded",
        "max_cpu_hunk_omitted": "arch bcm2837-machine-config.patch already adds MAX_CPUS=8 and MAX_CPU_CLUSTERS=2",
        "kernel_compiled": False, "hardware_tested": False, "device_operations": False,
    }
    (OUT / "audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
