#include "arm64thunk.h"

const unsigned char s_bit_c[4] = { 0x5F, 0x24, 0x03, 0xD5 };
const unsigned int b_op = 0x14000000;

#ifndef __KERNEL__
#define SZ_128M				0x08000000
#else
#include <linux/sizes.h>
#endif

int arm64_make_thunk(unsigned char *thunk, unsigned char *off)
{
  int i;
  // ripped from arm64/net/bpf_jit.c function is_long_jump 
  long offset = (long)off - (long)thunk;
  if ( offset < -SZ_128M || offset >= SZ_128M )
    return -1;
  for ( i = 0; i < sizeof(s_bit_c); ++i )
    thunk[i] = s_bit_c[i];
  *(unsigned int *)(thunk + 4) = b_op | ((offset >> 2) & 0x00ffffff);
  return 0;
}