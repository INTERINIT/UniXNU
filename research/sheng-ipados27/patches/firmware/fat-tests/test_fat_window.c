#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int BOOLEAN;
#define TRUE 1
#define FALSE 0
#include "FatWindow.h"
#include "RealFatBpb.h"

static void le16 (UINT8 *p, UINT32 n) {p[0]=(UINT8)n;p[1]=(UINT8)(n>>8);}
static void le32 (UINT8 *p, UINT32 n) {le16(p,n);le16(p+2,n>>16);}
int main (void) {
  const UINT64 Size=8ULL<<20, Prefix=33053692, Tail=173;
  UINT8 *p=calloc(1,(size_t)(Prefix+Size+Tail));
  UINT8 sector[512];
  FAT_WINDOW w;
  UINT64 volume;
  assert(p);
  assert(FatVolumeBytes(RealFullBpb,201326592,&volume)&&volume==201326592);
  assert(FatVolumeBytes(RealSmallBpb,8388608,&volume)&&volume==8388608);
  memset(sector,0,sizeof(sector));
  sector[0]=0xEB;le16(sector+11,512);sector[13]=2;le16(sector+14,1);
  sector[16]=2;le16(sector+17,512);le16(sector+19,16384);le16(sector+22,32);
  sector[510]=0x55;sector[511]=0xAA;
  memcpy(p,sector,512);
  assert(FatFindWindow(p,Size,&w)&&w.Offset==0&&w.Bytes==Size);
  memset(p,0,512);memcpy(p+Prefix,sector,512);
  assert(FatFindWindow(p,Prefix+Size+Tail,&w)&&w.Offset==Prefix&&w.Bytes==Size);
  assert(!FatFindWindow(p,Prefix+Size-1,&w));
  assert(!FatFindWindow(p,511,&w));
  assert(!FatFindWindow(NULL,512,&w));
  assert(!FatFindWindow(p,(1ULL<<30)+1,&w));
  p[Prefix+13]=3;assert(!FatFindWindow(p,Prefix+Size,&w));p[Prefix+13]=2;
  le16(p+Prefix+22,1);assert(!FatFindWindow(p,Prefix+Size,&w));le16(p+Prefix+22,32);
  le32(p+Prefix+32,0xFFFFFFFF);assert(!FatFindWindow(p,Prefix+Size,&w));le32(p+Prefix+32,0);
  assert(!FatFindWindow(p,Prefix,&w));
  memset(sector,0,sizeof(sector));sector[0]=0xEB;le16(sector+11,512);
  sector[13]=1;le16(sector+14,32);sector[16]=2;
  le32(sector+32,131072);le32(sector+36,1024);le32(sector+44,2);
  sector[510]=0x55;sector[511]=0xAA;
  assert(FatVolumeBytes(sector,64ULL<<20,&volume)&&volume==(64ULL<<20));
  le32(sector+44,1);assert(!FatVolumeBytes(sector,64ULL<<20,&volume));
  free(p);
  puts("FAT window: raw, unaligned vendor prefix, bootconfig tail, truncation, invalid geometry, capacity and bounds PASS");
  return 0;
}
