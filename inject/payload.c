#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

void inject(void *addr)
{
  printf("[+] greeting from injected, addr %p\n", addr);
//  if ( munmap(addr, 0x1000) ) printf("munmap failed, errno %d (%s)\n", errno, strerror(errno));
}