#include <stdio.h>
#include "ujit.h"

unsigned char test_body[] = {
  0xB7, 0, 0, 0, 0, 0, 0, 0,
  0x95, 0, 0, 0, 0, 0, 0, 0
};

int main()
{
  if ( !ujit_open("./libjsw64.so") )
  {
    printf("cannot open libjsw64.so\n");
    return -1;
  }
  ujit(0, test_body, 2, 32);
  return 0;
}