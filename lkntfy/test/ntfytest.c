#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "shared.h"

const char *fname = "/home/redp/test.file";

int main()
{
  int fd, test_fd;
  size_t size = strlen(fname) + 1 + sizeof(unsigned int);
  char *buf;
  int err;
  fd = open("/dev/lkntfy", 0);
  if ( -1 == fd )
  {
    printf("cannot open device, error %d\n", errno);
    exit(errno);
  }
  buf = (char *)malloc(size);
  *(unsigned int *)buf = 0x1ffe; // see man fanotify for masks FAN_XXX
  strcpy(buf + sizeof(unsigned int), fname);
  err = ioctl(fd, IOCTL_ADDFILE, (int *)buf);
  if ( err )
  {
    printf("IOCTL_ADDFILE test failed, error %d (%s)\n", err, strerror(err));
  } else {
    printf("press any key\n");
    getc(stdin);
    err = ioctl(fd, IOCTL_DELFILE, (int *)(buf + sizeof(unsigned int)));
    if ( err )
     printf("IOCTL_DELFILE test failed, error %d (%s)\n", err, strerror(err));
  }
  free(buf);
  close(fd);
}