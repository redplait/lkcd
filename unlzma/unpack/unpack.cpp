// unpack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <stdlib.h>
#include "../unlzma.h"

FILE *s_fp = NULL;

void my_err(char *x)
{
  fprintf(stderr, "error: %s\n", x);
}

long ida_fill(void *buf, unsigned long size)
{
  size_t res = fread(buf, 1, size, s_fp);
  return res;
}

int main(int argc, char **argv)
{
  if ( argc != 2 )
  {
    fprintf(stderr, "%s: where is compressed file?\n", argv[0]);
    return 6;
  }
  s_fp = fopen(argv[1], "rb");
  if ( NULL == s_fp )
  {
    fprintf(stderr, "cannot open %s\n", argv[1]);
    return -1;
  }
  // read 4 last bytes from file - it`s size of unpacked data
  fseek(s_fp, -4, SEEK_END);
  int unpacked = 0;
  fread(&unpacked, 4, 1, s_fp);
  unpacked = _byteswap_ulong(unpacked);
  printf("unpacked size %d\n", unpacked);
  int size = ftell(s_fp);
  fseek(s_fp, 0, SEEK_SET);
  // alloc memory
  unsigned char *buf = (unsigned char *)malloc(unpacked);
  int res = __decompress(NULL, size, &ida_fill, NULL, buf, 0, &my_err);
  printf("res %d", res);
}

