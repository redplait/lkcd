#ifdef __KERNEL__
#include <linux/sizes.h>
#else
#include "arm64thunk.h"
#define SZ_128M				0x08000000
#endif

const unsigned char s_bit_c[4] = {
#ifndef CONFIG_ARM64
0xF3, 0x0F, 0x1E, 0xFA }; // endbr64
#else
0x5F, 0x24, 0x03, 0xD5 };
const unsigned int b_op = 0x14000000;
#endif

int arm64_make_thunk(unsigned char *thunk, unsigned char *off)
{
  int i;
  // ripped from arm64/net/bpf_jit.c function is_long_jump 
  long offset = (long)off - (long)thunk - 4;
  if ( offset < -SZ_128M || offset >= SZ_128M )
    return -1;
  for ( i = 0; i < sizeof(s_bit_c); ++i )
    thunk[i] = s_bit_c[i];
#ifndef CONFIG_ARM64
  offset = (long)off - (long)thunk - 9;
  *(unsigned char *)(thunk + 4) = 0xe9; // jmp imm32
  *(unsigned int *)(thunk + 5) = (unsigned int)off;
#else
  *(unsigned int *)(thunk + 4) = b_op | ((offset >> 2) & 0x03ffffff);
#endif
  return 0;
}

int func_has_bti(void *addr)
{
  unsigned char *b = (unsigned char *)addr;
#ifndef CONFIG_ARM64
  return (b[0] == 0xF3) &&
         (b[1] == 0x0F) &&
         (b[2] == 0x1E) &&
         (b[3] == 0xFA)
#else
  return (b[0] == 0x5f) &&
         (b[1] == 0x24) &&
         (b[2] == 0x3 ) &&
         (b[3] == 0xd5)
#endif
   ;
}
