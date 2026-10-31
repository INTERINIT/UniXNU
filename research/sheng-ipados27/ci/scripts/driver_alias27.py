"""Restore the catalog's NativeMetal compatibility name beside real sources.

The resolved build tree already supplies this official alias. The pinned A740
builder additionally resolves its C++ source before locating the same header,
so it needs the compatibility directory beside the physical driver checkout.
No source, ABI header, component selection, or build recipe is changed.
"""
import json
import os
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def prepare(ctx, output):
    """Prepare only the known physical alias; write a receipt under output."""
    roots = tuple(Path(path).resolve() for path in (ctx.root, ctx.device))
    tree = Path(ctx.tree)
    source = (tree / "drivers/Adreno740/NativeAdrenoAccelerator.cpp").resolve()
    metal = (tree / "drivers/AdrenoMetal").resolve()
    header = metal / "OriginalAcceleratorABI.h"
    require(source.is_file() and header.is_file(), "The selected A740 source or original Metal ABI header is missing")
    alias = source.parent.parent / "NativeMetal"
    require(all(any(path.is_relative_to(root) for root in roots) for path in (source, metal, alias.parent)),
            "Physical driver inputs must stay inside MAIN/DEVICE worktrees")
    if os.path.lexists(alias):
        require(alias.is_dir() and alias.resolve() == metal,
                "Preserve the existing different physical NativeMetal path")
        action = "reused"
    else:
        alias.symlink_to(metal, target_is_directory=True)
        action = "created_symlink"
    report = {"status": "verified", "catalog_legacy_name": "NativeMetal", "component": "AdrenoMetal",
              "physical_alias": str(alias), "canonical_module": str(metal), "accelerator_source": str(source),
              "action": action, "original_abi_header": str(header), "source_or_abi_modified": False,
              "device_operations": False, "hardware_tested": False}
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "driver-alias27.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    raise SystemExit("Import driver_alias27.prepare(ctx, output) from the prepared host pipeline.")
