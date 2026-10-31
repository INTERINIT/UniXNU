"""Copy verified iPadOS17 boot references; never access the tablet."""
import hashlib
import json
from pathlib import Path
import shutil

WORK = Path(r"D:\iOS6sp")
OUT = WORK / "iPadOS27/reference17"
OUT.mkdir(parents=True, exist_ok=True)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


images = (
    ("iPadOS17-Start/boot.img", "ipados17-cpu-ram.img", "3ce19f77bccd134ec41f30e020fb7923fae408aba20599275b50e2077b96c576"),
    ("iPadOS17-DataGPU/images/data-persist.img", "ipados17-cpu-data2.img", "1fe810c7fc7aa1002a73eb9b2f966a3aa03afd868feafa02ce20430cbb82c85e"),
)
records = []
for relative, name, expected in images:
    source, target = WORK / relative, OUT / name
    if digest(source) != expected:
        raise ValueError("Reference source differs: " + str(source))
    if target.exists() and digest(target) != expected:
        raise ValueError("Preserve unexpected existing reference: " + str(target))
    if not target.exists():
        shutil.copy2(source, target)
    if digest(target) != expected:
        raise ValueError("Reference copy verification failed")
    records.append({"original_path": str(source), "preserved_path": str(target), "bytes": target.stat().st_size, "sha256": expected})

for relative, name in (
    ("iPadOS17-Start/manifest.json", "ram-manifest-original.json"),
    ("iPadOS17-DataGPU/data-persist.json", "data2-manifest-original.json"),
    ("iPadOS17-DataGPU/reports/data-persist-hardware.json", "data2-hardware-evidence.json"),
    ("package17/reports/kernel-build.json", "kernel-build-original.json"),
    ("iPadOS17-DataGPU/boot_next.py", "boot_next-original.py"),
    ("iPadOS17-DataGPU/boot_guard.py", "boot_guard-original.py"),
):
    source, target = WORK / relative, OUT / name
    if target.exists() and digest(target) != digest(source):
        raise ValueError("Preserve previous evidence copy rather than overwrite: " + name)
    if not target.exists():
        shutil.copy2(source, target)

report = {
    "images": records,
    "device_operations": False,
    "existing_17_directories_deleted_or_modified": False,
    "runtime_Data_overlay_backed_up": False,
    "runtime_Data_overlay_note": "Settings readback was verified on the tablet; this preserves boot resources and evidence, not a dump of live user data.",
    "user_plan": "Keep PC references; device userdata may later be replaced with independently built iPadOS27 root and persistent Data.",
    "root_image_original_path": str(WORK / "package17/images/userdata-root.img"),
    "root_image_original_sha256": "fd43ee7035ce185ce4215ac93fdc006fd784a54b3b7442e21457c226cbe03093",
    "root_image_copied": False,
}
(OUT / "reference-index.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
