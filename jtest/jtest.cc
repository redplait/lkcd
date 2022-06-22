#include <stdio.h>
#include <stdlib.h>
#include "ujit.h"

unsigned char test_body[] = {
  0xB7, 0, 0, 0, 0, 0, 0, 0,
  0x95, 0, 0, 0, 0, 0, 0, 0
};

unsigned char fault_body[] = {
 0xBF, 0x16, 0, 0, 0, 0, 0, 0,
 0x69, 0x67, 0xB0, 0, 0, 0, 0, 0,
 0xB4, 0x08, 0, 0, 0, 0, 0, 0,
 0x44, 0x08, 0, 0, 2, 0, 0, 0,
 0xB7, 0, 0, 0, 1, 0, 0, 0,
 0x55, 0x08, 1, 0, 2, 0, 0, 0,
 0xB7, 0, 0, 0, 0, 0, 0, 0,
 0x95, 0, 0, 0, 0, 0, 0, 0,
};

char *read_file(const char *fname, size_t &fsize)
{
  FILE *fp = fopen(fname, "rb");
  if ( !fp )
    return NULL;
  fseek(fp, 0, SEEK_END);
  fsize = ftell(fp);
  if ( !fsize )
  {
    fclose(fp);
    return NULL;
  }
  char *buf = (char *)malloc(fsize);
  if ( !buf )
  {
    fclose(fp);
    return NULL;
  }
  fread(buf, fsize, 1, fp);
  fclose(fp);
  return buf;
}

int main(int argc, char **argv)
{
  if ( !ujit_open("./libjsw64.so") )
  {
    printf("cannot open libjsw64.so\n");
    return -1;
  }
  if ( argc > 1 )
  {
    size_t fsize = 0;
    char *buf = read_file(argv[1], fsize);
    if ( !buf )
      printf("cannot open %s\n", argv[1]);
    else {
      ujit(0, (unsigned char *)buf, fsize / 8, 32);
      free(buf);
    }
  } else 
    ujit(0, fault_body, sizeof(fault_body) / 8, 32);
  return 0;
}