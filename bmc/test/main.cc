#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <poll.h>

// those stupid morons even can't make their shitcode compilable
// https://github.com/libbpf/libbpf/issues/249
// on my ubuntu with g++ v12 it gives
// /usr/include/bpf/bpf.h:252:6: error: use of enum ‘bpf_stats_type’ without previous declaration
//  252 | enum bpf_stats_type; /* defined in up-to-date linux/bpf.h */
// so this is rip from uapi includes
enum bpf_stats_type {
    /* enabled run_time_ns and run_cnt */
    BPF_STATS_RUN_TIME = 0,
};

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

#include "../shared.h"

int main(int argc, char **argv)
{
  int fd = bpf_create_map_name(BPF_MAP_TYPE_HASH, "bmchannel", sizeof(pid_t), sizeof(proc_dead), 1024, 0);
  if ( fd < 0 ) {
    printf("create_map failed, error %d (%s)\n", errno, strerror(errno));
    return 0;
  }
  printf("map fd %d\n", fd);
  int drv_fd = open("/dev/bmc", 0);
  if ( -1 == drv_fd ) {
    printf("open bmc failed, error %d (%s)\n", errno, strerror(errno));
    return 0;
  }
  // pass fd to driver sharing bpf map
  unsigned long lfd = fd;
  int err = ioctl(drv_fd, IOCTL_FROM_FD, &lfd);
  if ( err ) {
    printf("IOCTL_FROM_FD failed, error %d (%s)\n", errno, strerror(errno));
    return 0;
  }
  // construct poll with 2 handles
  pollfd poller[2];
  poller[0].fd = drv_fd;
  poller[1].fd = fileno(stdin);
  poller[0].events = poller[1].events = POLLIN | POLLRDNORM;
  poller[0].revents = poller[1].revents = 0;
  pid_t key = 0, next_key;
  while(1) {
    int res = poll(poller, 2, 1000);
    if ( -1 == res ) {
      printf("poll failed, error %d (%s)\n", errno, strerror(errno));
      break;
    }
    if ( res ) {
     // check what we have
     if ( poller[0].revents ) {
       int res_key = 0;
       if ( !key ) {
         res_key = bpf_map_get_next_key(fd, &key, &key);
         if ( res_key ) // wtf - no prev and next key
           continue;
       }
       while(1)
       {
         res_key = bpf_map_get_next_key(fd, &key, &next_key);
         proc_dead value;
         res = bpf_map_lookup_elem(fd, &key, &value);
         if ( !res ) {
           printf("key %d exit_code %d clock %ld\n", key, value.exit_code, value.timestamp);
           bpf_map_delete_elem(fd, &key);
         } else
           break;
         if ( res_key ) {
           key = 0;
           break;
         }
         key = next_key;
       }
     } else if ( poller[1].revents )
       break;
    } else {
     printf("timed out\n");
    }
  }
}