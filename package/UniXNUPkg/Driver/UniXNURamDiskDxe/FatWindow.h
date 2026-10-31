/* Locate a bounded FAT volume inside an Android concatenated initrd.
 * Read-only: this helper never alters the supplied bytes.
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef UNIXNU_FAT_WINDOW_H
#define UNIXNU_FAT_WINDOW_H

typedef struct {
  UINT64 Offset;
  UINT64 Bytes;
} FAT_WINDOW;

static UINT32 FatLe16 (const UINT8 *P) {
  return (UINT32)P[0] | ((UINT32)P[1] << 8);
}

static UINT32 FatLe32 (const UINT8 *P) {
  return FatLe16 (P) | (FatLe16 (P + 2) << 16);
}

static BOOLEAN FatVolumeBytes (const UINT8 *P, UINT64 Available, UINT64 *Bytes) {
  UINT32 Sectors, FatSectors, Reserved, RootEntries, ClusterSectors, FatCount;
  UINT64 Metadata, Clusters, Capacity, VolumeBytes;
  if (Available < 512 || (P[0] != 0xEB && P[0] != 0xE9) || P[510] != 0x55 || P[511] != 0xAA) return FALSE;
  /* The UniXNU generated payload uses 512-byte sectors. Do not guess other
     formats, MBR partitions, or an unbounded size from random vendor data. */
  if (FatLe16 (P + 11) != 512) return FALSE;
  ClusterSectors = P[13]; Reserved = FatLe16 (P + 14); FatCount = P[16];
  RootEntries = FatLe16 (P + 17);
  if (!ClusterSectors || ClusterSectors > 128 || (ClusterSectors & (ClusterSectors - 1)) || !Reserved || !FatCount || FatCount > 2) return FALSE;
  Sectors = FatLe16 (P + 19);
  if (Sectors && FatLe32 (P + 32)) return FALSE;
  if (!Sectors) Sectors = FatLe32 (P + 32);
  FatSectors = FatLe16 (P + 22);
  if (!FatSectors) FatSectors = FatLe32 (P + 36);
  if (!Sectors || !FatSectors) return FALSE;
  Metadata = Reserved + (UINT64)FatCount * FatSectors + ((UINT64)RootEntries * 32 + 511) / 512;
  if (Metadata >= Sectors) return FALSE;
  Clusters = (Sectors - Metadata) / ClusterSectors;
  if (!Clusters) return FALSE;
  if (!FatLe16 (P + 22)) {
    UINT32 RootCluster = FatLe32 (P + 44) & 0x0FFFFFFF;
    if (RootEntries || Clusters < 65525 || RootCluster < 2 || RootCluster > Clusters + 1) return FALSE;
    Capacity = (UINT64)FatSectors * 512 / 4;
  } else {
    if (!RootEntries || Clusters >= 65525) return FALSE;
    Capacity = Clusters < 4085 ? (UINT64)FatSectors * 512 * 2 / 3 : (UINT64)FatSectors * 512 / 2;
  }
  if (Capacity < Clusters + 2) return FALSE;
  VolumeBytes = (UINT64)Sectors * 512;
  if (VolumeBytes > Available) return FALSE;
  *Bytes = VolumeBytes;
  return TRUE;
}

static BOOLEAN FatFindWindow (const UINT8 *Data, UINT64 Length, FAT_WINDOW *Window) {
  UINT64 Offset, Last, Bytes;
  /* Payloads are downloaded through a < 1 GiB fastboot buffer. Prefix search
     is bounded separately; the measured vendor prefix is about 31.5 MiB.
     Vendor/generic concatenation need not start the FAT on a sector boundary. */
  if (!Data || !Window || Length < 512 || Length > (1ULL << 30)) return FALSE;
  Last = Length - 512;
  if (Last > (128ULL << 20)) Last = 128ULL << 20;
  for (Offset = 0; Offset <= Last; Offset++) {
    if (Data[Offset] != 0xEB && Data[Offset] != 0xE9) continue;
    if (FatVolumeBytes (Data + Offset, Length - Offset, &Bytes)) {
      Window->Offset = Offset;
      Window->Bytes = Bytes;
      return TRUE;
    }
  }
  return FALSE;
}

#endif
