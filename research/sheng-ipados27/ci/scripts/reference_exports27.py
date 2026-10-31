"""Remove unavailable Apple-platform exports from the isolated RELEASE reference.

BCM2837 omits these implementation units. Apple's ARM64 RELEASE export list
nevertheless names them, while DEVELOPMENT links without that export list.
Apply this only to the private reference source copy before its source manifest.
No implementation, undefined-symbol policy, link flag, or full-native source is
changed; every other export remains a RELEASE/LTO retention root.
"""
import argparse
import hashlib
import json
from pathlib import Path


XNU_PIN = "ac9718fb1af618d5ce8678d0dc6e8a58f252216f"
# Exact raw linker names matched to run41182726395's 67 export-only failures.
UNAVAILABLE_EXPORTS = {
    'config/Private.arm64.exports': (
        '_pmap_iommu_init',
        '_pmap_iommu_iovmalloc',
        '_pmap_iommu_map',
        '_pmap_iommu_unmap',
        '_pmap_iommu_iovmfree',
        '_pmap_iommu_ioctl',
        '_pmap_iommu_alloc_contiguous_pages',
        '_pmap_acquire_iommu_scratch_area',
        '_pmap_alloc_iommu_page',
        '_pmap_free_iommu_page',
        '_pmap_create_aligned_buffer',
        '_pmap_destroy_aligned_buffer',
        '_pmap_ref_iommu_table',
        '_pmap_register_iommu_mapping',
        '_pmap_release_iommu_scratch_area',
        '_pmap_unregister_iommu_mapping',
        '_nvme_ppl_get_desc',
        '_sart_get_desc',
        '_t8020dart_get_desc',
        '_t8020dart_vo_tte',
        '_t6000dart_get_desc',
        '_t6000dart_vo_tte',
        '_t8110dart_get_desc',
        '_t8110dart_max_translation_levels',
        '_t8110dart_vo_tte',
        '_t8110dart_vo_tt_index',
        '_sptm_gen3dart_init',
        '_sptm_gen3dart_map_table',
        '_sptm_gen3dart_unmap_table',
        '_sptm_gen3dart_map',
        '_sptm_gen3dart_unmap',
        '_sptm_gen3dart_powerdown',
        '_sptm_gen3dart_powerup',
        '_sptm_gen3dart_disable_translation',
        '_sptm_gen3dart_enable_translation',
        '_sptm_gen3dart_clear_err',
        '_sptm_gen3dart_clear_perf_interrupts',
        '_sptm_gen3dart_clear_all_interrupts',
        '_sptm_gen3dart_disable_all_interrupts',
        '_sptm_gen3dart_clear_exception',
        '_sptm_gen3dart_query_tlb',
        '_sptm_gen3dart_set_smmu_window',
        '_sptm_gen3dart_read_smmu_stt_index',
        '_sptm_gen3dart_clamp_tlimits',
        '_sptm_gen3dart_test_translation',
        '_uat_get_desc',
        '__ZN26IOUnifiedAddressTranslator10gMetaClassE',
        '__ZN26IOUnifiedAddressTranslator10superClassE',
        '__ZN26IOUnifiedAddressTranslator17getPageTableEntryEy',
        '__ZN26IOUnifiedAddressTranslator18setClientContextIDEjb',
        '__ZN26IOUnifiedAddressTranslator21removeClientContextIDEv',
        '__ZN26IOUnifiedAddressTranslator19isPageFaultExpectedEyj',
        '__ZN26IOUnifiedAddressTranslator7getModeEv',
        '__ZN26IOUnifiedAddressTranslator29getFirmwareAddressSpaceHandleEv',
        '__ZN26IOUnifiedAddressTranslator22registerTaskForServiceEP4taskP9IOService',
        '__ZN26IOUnifiedAddressTranslator23createMappingInApertureEjP18IOMemoryDescriptorjym',
        '__ZN26IOUnifiedAddressTranslator23getTotalPageTableMemoryEv',
        '__ZN26IOUnifiedAddressTranslator3mapEP11IOMemoryMapj',
        '__ZN26IOUnifiedAddressTranslator5doMapEP18IOMemoryDescriptoryyj',
        '__ZN26IOUnifiedAddressTranslator5unmapEP11IOMemoryMap',
        '__ZN26IOUnifiedAddressTranslator7doUnmapEP18IOMemoryDescriptoryy',
        '__ZN26IOUnifiedAddressTranslator8taskDiedEv',
        '__ZN26IOUnifiedAddressTranslator12commitUnmapsEv',
        '__ZN26IOUnifiedAddressTranslator14prepareFWUnmapEyy',
        '__ZTV26IOUnifiedAddressTranslator',
    ),
    'config/Private.exports': (
        '_pmap_has_iofilter_protected_write',
        '_pmap_cs_configuration',
    ),
}


def adapt_text(text, names):
    """Delete only complete named export lines, preserving all other bytes."""
    omitted = set(names)
    return "".join(line for line in text.splitlines(keepends=True)
                   if line.rstrip("\r\n") not in omitted)


def apply(source, output=None):
    """Adapt an explicitly supplied isolated reference source directory."""
    source = Path(source)
    files = []
    for relative, names in UNAVAILABLE_EXPORTS.items():
        path = source / relative
        before = path.read_bytes()
        after = adapt_text(before.decode("utf-8"), names).encode("utf-8")
        if after != before:
            path.write_bytes(after)
        files.append({"path": relative,
                      "removed": [name for name in names if name in before.decode("utf-8").splitlines()],
                      "before_sha256": hashlib.sha256(before).hexdigest(),
                      "after_sha256": hashlib.sha256(after).hexdigest()})
    report = {"kind": "isolated-release-reference-platform-exports", "xnu_pin": XNU_PIN,
              "files": files, "ordinary_undefined_symbols_remain_errors": True,
              "release_lto_export_roots_preserved": True, "device_operations": False}
    if output is not None:
        Path(output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path,
                        help="private RELEASE reference source copy; not .cache/xnu-work")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = apply(args.source, args.report)
    print("RELEASE reference platform exports removed:",
          sum(len(item["removed"]) for item in report["files"]))


if __name__ == "__main__":
    main()
