"""Export an allowlisted, sanitized research snapshot into the user's fork."""
import json
from pathlib import Path
import re
import shutil

WORK = Path(__file__).resolve().parents[1]
REPO = WORK / "source/UniXNU"
DEST = REPO / "research/sheng-ipados27"
DEST.mkdir(parents=True, exist_ok=True)
private_identifiers = set()
local_manifest = WORK.parent / "iPadOS17-Start/manifest.json"
if local_manifest.is_file():
    private_identifiers.add(json.loads(local_manifest.read_text())["device_serial"])


def write(source, relative):
    data = source.read_text(encoding="utf-8-sig")
    for identifier in private_identifiers:
        data = data.replace(identifier, "DEVICE_SERIAL_REDACTED")
    data = data.replace("b714917c", "UPSTREAM_EXAMPLE_SERIAL")
    data = re.sub(r"C:[/\\]Users[/\\][^/\\\s\"']+", "USER_HOME", data)
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}", data):
        raise ValueError("Credential material in allowlisted file: " + str(source))
    target = DEST / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data.replace("\r\n", "\n"), encoding="utf-8", newline="\n")


scripts = (
    "fetch_root_members.py", "preserve17.py", "firmware_agent_policy27.py",
    "reference_agent_seed27.py", "source_agent_cloud27_draft.py", "firmware27_draft.py",
    "build_userdata27_windows.py", "test_userdata27_windows.py", "prepare_soc27_overlay.py",
)
for name in scripts:
    write(WORK / "scripts" / name, Path("scripts") / name)
for path in (WORK / "patches").rglob("*"):
    if path.is_file() and path.suffix.lower() in (".patch", ".json", ".txt", ".c", ".h") or path.is_file() and path.name == "series":
        write(path, Path("patches") / path.relative_to(WORK / "patches"))
for name in ("official-source-audit.txt", "firmware-audit.txt", "ipados17-reference-audit.txt", "root27-layout-options.txt", "publication-review.txt", "inspect_27_ipsw.py", "ipsw-24A446-metadata.json"):
    write(WORK / "research" / name, Path("evidence") / name)
for name in ("userdata27-assembler-selftest.json",):
    write(WORK / "reports" / name, Path("evidence") / name)
for path in (WORK / "ci/scripts").glob("*.py"):
    write(path, Path("ci/scripts") / path.name)
write(WORK / "ci/.github/workflows/ipados27.yml", Path("ci/workflow-template.yml"))
for path in (WORK / "ci/patches").rglob("*"):
    if path.is_file():
        write(path, Path("ci/patches") / path.relative_to(WORK / "ci/patches"))
write(WORK / "resources/run41166231424-prepare/result27/prepare.json", Path("evidence/prepare-host.json"))
print(json.dumps({"destination": str(DEST), "text_files": len([p for p in DEST.rglob('*') if p.is_file()]), "binaries_copied": False, "private_keys_copied": False}))
