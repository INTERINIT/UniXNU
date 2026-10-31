# sheng iPadOS 27 research

This branch tracks the work to boot iPadOS 27.0.1 (24A446) on Xiaomi Pad 6S Pro
(`sheng`, SM8550). It preserves the working iPadOS 17 case as a reference.
The first iPadOS 27 hardware candidate is intended to include the matching
Metal/GPU stack and a new persistent Data volume.

**A complete experimental package has been assembled and checked on Windows.
No iPadOS 27 boot, GPU rendering or persistent Data has been verified on our
tablet yet. The emitted kernel still has incomplete mappings.**

2026-10-31: public Actions run
[41186106830](https://github.com/INTERINIT/UniXNU/actions/runs/41186106830)
completed successfully from `e1e938ee5354913d958282d158b3582dea9cdf08`.
Native kernel and payload were built in that run; Data, GPU and firmware reused
the passed outputs of run 41173083070. The actual boot, complete root policies
and existing sparse media were paired into the Windows package, and its local
`check` command passed. No device operation was performed.

The current kernel report records 60 unresolved pointer references and 53
function references redirected to the diagnostic panic fallback. It retains
`mapping_complete=false`, `allow_missing=true`, `runtime_qualified=false` and
`loadable=false`; host build success does not establish hardware bootability.
See `evidence/integrated-run-41186106830.json`. Builds remain manually dispatched;
the package is undergoing manual hardware diagnosis.

The first hardware test on 2026-10-31 reached the green loader handoff bar and
stopped with the firmware menu still visible. A RAM-only diagnostic kernel
then produced the blue entry and magenta pre-MMU bars. This confirms native
kernel entry. Two timed reset checkpoints subsequently confirmed MMU enable
and return from `arm_vm_init`. A visible panic renderer then identified a
missing sandbox boot-argument import. Binding it to the real
`PE_parse_boot_arg_str` moved hardware startup into IOKit service matching,
where an IOCPU virtual import was the next reported gap. The reviewed IOCPU
get/set/serialization identities are recorded alongside the sandbox fix.
The next observed VFS registration fault came from seven unbound vnode
operation descriptors, which have been redirected to the canonical native
objects. Startup then reached HID initialization and a required OSArray cast
using an overwritten original metaclass pointer slot. Four reviewed metaclass
pointer variables now correct35 retained imports in the next RAM candidate.
These changes bind the variables themselves, preserving the consumer's second
load of the metaclass object and the existing type checks.
Full OS startup is still unconfirmed. Root media and Data were not reflashed
during diagnostics. See
`evidence/hardware-entry-20261031.json`.

`scripts/build_entry_diagnostic27.py` builds these diagnostics locally with
LLVM, the existing package and its exact source kernel. It reuses the shared
entry-probe tool and reseals the source-provider POST HMAC. The source and
original package stay unchanged. `--post-mmu-reset-delay 6` adds a deliberate
timed reset checkpoint after MMU enable; the default only draws the two bars.
The generated directory provides `Boot.cmd` and no flash launcher. Select the
first normal system entry; the original payload's First install entry is still
present and must not be selected for diagnostics.

`--panic-screen --uefi <Mu-Silicium>` adds the visible panic renderer.
`--bindings patches/prelink/diagnostic-bindings-41186106830.json` rebinds the
reviewed imports in the exact original candidate while preserving each chain's
authentication metadata. The corresponding source-backed records in
`patches/prelink/fileset-24A446-runtime-symbols.json` are also copied into the
resolved prelink fixtures for future cloud builds. No cloud retry is required
to test these local RAM-only candidates.

## Source baseline

| Input | Revision |
| --- | --- |
| UniXNU `feat/ipados27-gpu-parity` | `793d6bddf7ea90678e3a61e2b2bd4350e5fdce16` |
| UniXNU-sheng, same branch | `f47b27ad97e97bee945f8af34a8430e3abcf918c` |
| SM8550 common | `23b2049fcd9e30356161def84231334fb55ecca9` plus the recorded xnu-12377 overlay |
| DarwinBoot | `3e3a8a969e1177995984d8ed98c9dcc44e318265` |
| UEFI-sheng `sheng` | `20ac23d5e0937106c2129303dfc931b3390ae660` |
| Apple public XNU | `ac9718fb1af618d5ce8678d0dc6e8a58f252216f` (`12377.121.6`) |

The OS is iPadOS 27 userland. Its experimental source kernel uses the public
Darwin 25.5 XNU base with the branch's additional Darwin 26 interfaces. It is
not Apple's unpublished native Darwin 26 source kernel. The original 24A446
kernelcache is an arm64e fileset with SHA-256
`38e6d9fa5f789b8228f4617ef4c6d2a3fd8ab564abdc9b62920f1db53fc1780a`.

The 27 route was selected because this branch contains its matching display,
HID and GPU ABI work. The audited 26.5.2 profile does not provide an equivalent
complete GPU/display recipe. The 26 profile and 17's arm64 private bindings
must not be substituted for the 27 bindings.

## Recorded results

- iPadOS 17: user-confirmed touch, Home Screen icons and Dock, and Chinese/Dark
  preferences surviving an identical-image reboot. GPU acceleration and actual
  online CPU count were not measured.
- iPadOS 27: Apple CDN/BuildManifest identity and small components validated;
  decoded kernelcache matches the selected profile; Windows AEA decryption of
  both OS and SystemOS produced the exact pinned raw APFS hashes. Both images
  passed real C/RSA signature and every-4K-block authentication on macOS.
- SoC overlay: affected Apple `start.s` and `bsd_init.c` patch contexts checked
  in arch/SoC/OS/device order. The later combined run also compiled and linked
  the native kernel with the recorded overlay.
- Host prepare and policy phases passed in the private build runner. The new
  firmware subsequently passed package/FD compilation, FV checks, both real
  BootShim QEMU cases, and official empty-container round-trip checks. Source
  kernel and complete boot were subsequently produced by run 41186106830.
- Small userdata transport tests passed real RSA verification, v2 layout,
  zero-fill, tamper and truncation controls. They do not qualify Apple images
  or hardware boot.
- The Windows assembler produced a 15,349,546,184-byte sparse image spanning
  the full 249,497,890,816-byte target geometry with RAW/FILL chunks only.
  Readback verified both volumes and policy-table objects. Actual final boot
  policy headers were matched to the full signed tables during assembly.
  Hardware deployment has not been attempted.

## Layout

| Directory | Purpose |
| --- | --- |
| `scripts/` | Reviewed host tools and explicitly unqualified build drafts |
| `patches/sm8550-xnu12377/` | Missing SoC patch series, hashes and applicability evidence |
| `patches/firmware/` | Read-only FAT subwindow fix, RAM logger integration and C tests |
| `ci/` | Build scripts used by the private artifact runner |
| `evidence/` | Sanitized source, resource and host-check records |

The FAT-window implementation is also applied to the shared
`package/UniXNUPkg/Driver/UniXNURamDiskDxe` code in this branch, so it can be
reviewed as an ordinary source diff. Board/SoC changes remain an explicitly
recorded overlay until they are split into their owning repositories for an
upstream submission. No pull request has been submitted yet.

## Host checks

From the UniXNU checkout:

```sh
clang -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -I package/UniXNUPkg/Driver/UniXNURamDiskDxe \
  -I research/sheng-ipados27/patches/firmware/fat-tests \
  research/sheng-ipados27/patches/firmware/fat-tests/test_fat_window.c \
  -o /tmp/sheng-fat-window-test
/tmp/sheng-fat-window-test
python3 research/sheng-ipados27/scripts/build_userdata27_windows.py --self-test
```

The macOS orchestration requires Xcode 26.6, pinned sources, genuine Apple root
media, vendor firmware, and real policy/ABI checks. Use scripts/dispatch27.ps1 to resolve a published full source SHA before
dispatching a host stage. See the build scripts and evidence for current gaps. Do not run the upstream `cycle27.sh` against a
connected device: it contains an author's hardware-run sequence. Our build
orchestration never invokes device commands.

## Storage and publication

Source, patches, scripts and sanitized findings belong on this branch. Store
large original inputs and build products outside Git and identify them by
source URL, build, size and SHA-256. Never commit device identifiers, tokens,
owner private signing keys, original firmware blobs, IPSWs or live Data.

The preserved 17 boot resources remain on the local workstation; the reference
reports are available here. They are not a backup of the tablet's live Data.
Replacing userdata with 27 is authorized for this case and replaces the old
on-device 17 root/Data. Each new seed needs its actual UUID in the matching
kernel. Initialize new Data once, then omit reset arguments on normal boots.
