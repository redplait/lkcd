#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <elfio/elfio_dump.hpp>
#include "ksyms.h"
#include "../shared.h"
#include "kmods.h"
#include "lk.h"

void dump_kmem(int fd, a64 addr, int cnt, sa64 delta)
{
  for ( int i = 0; i < cnt; i++, addr += sizeof(void *) )
  {
     char *ptr = (char *)addr;
     unsigned char *v = (unsigned char *)&ptr;
     int err = ioctl(fd, IOCTL_READ_PTR, (int *)&ptr);
     if ( err )
     {
        printf("read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
        continue;
     }
     printf("%lX: ", addr);
     for ( int j = 0; j < sizeof(void *); j++ )
       printf("%2.2X ", v[j]);
     if ( !ptr )
     {
       printf("\n");
       continue;
     }
     printf("%p", ptr);
     if ( is_inside_kernel((a64)ptr) )
     {
       size_t off = 0;
       const char *name = lower_name_by_addr_with_off((a64)ptr - delta, &off);
       if ( name )
       {
         if ( off )
           printf(" %s+%lX", name, off);
         else
           printf(" %s", name);
       } else {
         printf(" [kernel]");
       }
     } else
     {
        const char *mname = find_kmod((unsigned long)ptr);
        if ( mname )
          printf(" [%s]", mname);
     }
     printf("\n");
  }
}

int main(int argc, char **argv)
{
  if ( argc < 2 )
  {
    printf("Usage: %s addr len ...\n", argv[0]);
    exit(6);
  }
  // open device
  int fd = open("/dev/lkcd", 0);
  if ( -1 == fd )
  {
     printf("cannot open device, error %d\n", errno);
     return 1;
  }
  int err = read_kernel_area(fd);
  if ( err )
  {
    close(fd);
    printf("cannot read_kernel_area, error %d\n", err);
    return err;
  }
  err = init_kmods();
  if ( err )
  {
     close(fd);
     printf("init_kmods failed, error %d\n", err);
     return err;
  }
  err = read_system_map();
  if ( err )
  {
    close(fd);
    printf("cannot read system map, error %d\n", err);
    return err;
  }
  // read delta
  auto symbol_a = get_addr("group_balance_cpu");
  if ( !symbol_a )
  {
    close(fd);
    printf("cannot find group_balance_cpu\n");
    return 1;
  }
  union ksym_params kparm;
  strcpy(kparm.name, "group_balance_cpu");
  err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
  if ( err )
  {
    printf("IOCTL_RKSYM test failed, error %d\n", err);
    close(fd);
    return err;
  }
  sa64 delta = (char *)kparm.addr - (char *)symbol_a;
  printf("delta: %lX\n", delta);
  // process args
  for ( int i = 1; i < argc; )
  {
    char *end = 0;
    int size = 1;
    a64 addr = strtoul(argv[i], &end, 16);
    if ( !addr )
    {
      printf("what address you mean at %s\n", argv[i]);
      break;
    }
    i++;
    if ( i < argc )
    {
      size = atoi(argv[i]);
      i++;
    }
    if ( !size )
      size = 0;
    dump_kmem(fd, addr, size, delta);
  }
  close(fd);
}