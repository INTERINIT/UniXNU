"""Resolve reviewed imports against one actual emitted kernel, without changing it.

The original Apple chains identify consumers and targets. Retained entry headers
give the collection relocation; the emitted native symbol table gives the new
destination. Existing correct or different native bindings are left alone.
The output is consumed by build_entry_diagnostic27.apply_bindings().
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


REPO = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).resolve().parents[1] / "patches/prelink/fileset-24A446-runtime-symbols.json"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def resolve(kernel, mapping, kernelcache, fixture=FIXTURE):
    """Return an exact plan; no kernel, cache, map or fixture is written."""
    sys.path.insert(0, str(REPO / "kits/XnuPrelink"))
    from kc_image import Image
    from fileset_emit import chain_word, decode

    paths = {"kernel": Path(kernel), "map": Path(mapping), "kernelcache": Path(kernelcache), "fixture": Path(fixture)}
    blobs = {name: path.read_bytes() for name, path in paths.items()}
    recorded, reviewed = json.loads(blobs["map"]), json.loads(blobs["fixture"])
    cache_sha = sha(blobs["kernelcache"])
    entry = reviewed["inputs"]["entry"]
    if (reviewed["inputs"]["kernelcache_sha256"] != cache_sha or
            recorded.get("inputs", {}).get("kernelcache_sha256") != cache_sha or
            recorded.get("inputs", {}).get("entry") != entry):
        raise ValueError("Reviewed fixture/map do not describe this exact Apple kernelcache")
    original, emitted = Image(blobs["kernelcache"]), Image(blobs["kernel"])
    old_kernel = Image(original.data, original.entries[entry][1])
    native = Image(emitted.data, emitted.entries[entry][1])
    slide = emitted.base - original.base
    names = {}
    native_symbols = native.symbols()
    for address, symbols in native_symbols.items():
        for name in symbols:
            names.setdefault(name, set()).add(address)

    targets = {}
    for kind in ("functions", "data"):
        for record in reviewed.get(kind, []):
            address = int(record["original"], 16)
            if not record.get("evidence"):
                raise ValueError("Reviewed binding requires recorded source evidence")
            if record.get("addend", 0):
                raise ValueError("The existing diagnostic applier accepts named symbols without addends")
            if kind == "functions":
                body = old_kernel.read(address, record["original_size"])
                if sha(body) != record["original_sha256"]:
                    raise ValueError("Reviewed original function bytes changed: " + record["original"])
            if address in targets and targets[address][1] != record:
                raise ValueError("Conflicting reviewed identities for " + record["original"])
            targets[address] = (kind, record)

    retained = {name: Image(original.data, position) for name, (_, position) in original.entries.items()
                if name != entry and name in emitted.entries}
    old_fixups, new_fixups = original.fixups(), emitted.fixups()
    bindings, correct, preserved, unresolved = [], [], [], []
    for old_site, original_pointer in old_fixups.items():
        original_target = original_pointer[0]
        if original_target not in targets:
            continue
        owners = [name for name, image in retained.items() if image.section(old_site)]
        if not owners:
            continue
        if len(owners) != 1:
            raise ValueError("Original retained import has ambiguous component ownership")
        owner = owners[0]
        if emitted.entries[owner][0] - original.entries[owner][0] != slide:
            raise ValueError("Retained component has a different collection relocation: " + owner)
        site = old_site + slide
        if site not in new_fixups:
            unresolved.append({"original_site": hex(old_site), "component": owner,
                               "reason": "Original import has no actual emitted chain site"})
            continue
        kind, record = targets[original_target]
        symbol = record["native_symbol"]
        details = {"site": hex(site), "original_site": hex(old_site), "component": owner,
                   "reviewed_original": hex(original_target), "native_symbol": symbol}
        found = names.get(symbol, set())
        if len(found) != 1:
            unresolved.append(dict(details, reason="Native symbol is absent or has multiple addresses"))
            continue
        destination = next(iter(found))
        current = new_fixups[site]
        if current[1:] != original_pointer[1:]:
            unresolved.append(dict(details, reason="Actual import PAC metadata differs from the original consumer"))
            continue
        if current[0] == destination:
            correct.append(dict(details, native_address=hex(destination)))
            continue
        map_record = recorded.get(kind, {}).get(hex(original_target))
        stubbed = kind == "functions" and "_unixnu_fileset_unmapped" in native_symbols.get(current[0], [])
        stale = current[0] == original_target + slide and map_record is None
        if not (stubbed or stale):
            preserved.append(dict(details, actual_target=hex(current[0]), map_record=map_record,
                                  reason="Preserve a different existing binding; no automatic replacement"))
            continue
        raw = struct.unpack("<Q", emitted.read(site, 8))[0]
        _, auth, key, diversity, addrdiv, step = decode(raw)
        proposed = chain_word(auth, key, diversity, addrdiv, destination - emitted.base, step)
        proposed_fields = decode(proposed)
        if proposed_fields[0] + emitted.base != destination or proposed_fields[1:] != decode(raw)[1:]:
            raise ValueError("Proposed binding would change actual PAC or next-chain metadata")
        bindings.append(dict(details, expected_word=hex(raw), expected_target=hex(current[0]),
                             native_address=hex(destination), proposed_word=hex(proposed),
                             evidence=record["evidence"], mapping_state="reporting_stub" if stubbed else "unmapped_original_data",
                             actual_chain_metadata={"auth": auth, "key": key, "diversity": diversity,
                                                    "address_diversity": addrdiv, "next_step": step}))

    return {"format": "reviewed-chain-binding-plan-v1", "kernel_sha256": sha(blobs["kernel"]),
            "scope": "Only the supplied reviewed identities; not a complete kernel mapping or hardware qualification.",
            "inputs": {name: {"file": paths[name].name, "sha256": sha(data)} for name, data in blobs.items()},
            "entry": entry, "collection_slide": hex(slide), "bindings": sorted(bindings, key=lambda item: int(item["site"], 16)),
            "already_correct": correct, "preserved_existing": preserved, "unresolved": unresolved,
            "summary": {"bindings": len(bindings), "already_correct": len(correct),
                        "preserved_existing": len(preserved), "unresolved": len(unresolved)},
            "kernel_modified": False, "device_operations": False, "hardware_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--kernelcache", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.resolve() in {path.resolve() for path in (args.kernel, args.map, args.kernelcache, args.fixture)}:
        raise ValueError("The output plan must not replace a kernel or input file")
    result = resolve(args.kernel, args.map, args.kernelcache, args.fixture)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
