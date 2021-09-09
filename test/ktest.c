#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "shared.h"
#include <getopt.h>
#include "drvname.h"

int main(int argc, char **argv)
{
  int opt_i = 0,
      opt_u = 0; 
  int fd;
  int err;
  unsigned long what = 0;
  // read options
   while (1)
   {
     int c = getopt(argc, argv, "st");
     if (c == -1)
	break;

     switch (c)
     {
        case 'i':
          opt_i = 1;
         break;
        case 'u':
          opt_u = 1;
         break;
     }
   }
  // open device
  fd = open(DRV_FILENAME, 0);
  if ( -1 == fd )
  {
    printf("cannot open device, error %d\n", errno);
    exit(errno);
  }
  if ( opt_i )
    what = 1;
  err = ioctl(fd, IOCTL_TEST_KPROBE, (int *)&what);
  if ( err )
  {
    printf("IOCTL_TEST_KPROBE failed, error %d\n", err);
  } 
  close(fd);
}