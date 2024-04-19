#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/genetlink.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include "lk.h"

// kernel base and end
unsigned long g_kstart = 0;
unsigned long g_kend = 0;

int is_inside_kernel(unsigned long a)
{
  return (a >= g_kstart) && (a < g_kend);
}

int read_kernel_area(int fd)
{
  union ksym_params kparm;
  int err;
  // kernel start and end
  strcpy(kparm.name, "startup_64");
  err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
  if ( err )
  {
    printf("IOCTL_RKSYM startup_64 failed, error %d\n", err);
    return err;
  }
  g_kstart = kparm.addr;
  strcpy(kparm.name, "__end_of_kernel_reserve");
  err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
  if ( err )
  {
    printf("IOCTL_RKSYM end_of_kernel failed, error %d\n", err);
    return err;
  }
  g_kend = kparm.addr;
  return 0;
}

const char hexes[] = "0123456789ABCDEF";

void HexDump(unsigned char *From, int Len)
{
 int i;
 int j,k;
 char buffer[256];
 char *ptr;

 for(i=0;i<Len;)
     {
          ptr = buffer;
          sprintf(ptr, "%08X ",i);
          ptr += 9;
          for(j=0;j<16 && i<Len;j++,i++)
          {
             *ptr++ = j && !(j%4)?(!(j%8)?'|':'-'):' ';
             *ptr++ = hexes[From[i] >> 4];
             *ptr++ = hexes[From[i] & 0xF];
          }
          for(k=16-j;k!=0;k--)
          {
            ptr[0] = ptr[1] = ptr[2] = ' ';
            ptr += 3;

          }
          ptr[0] = ptr[1] = ' ';
          ptr += 2;
          for(;j!=0;j--)
          {
               if(From[i-j]>=0x20)
                    *ptr = From[i-j];
               else
                    *ptr = '.';
               ptr++;
          }
          *ptr = 0;
          printf("%s\n", buffer);
     }
     printf("\n");
}
