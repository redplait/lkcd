#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "lk.h"
#include "shared.h"

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