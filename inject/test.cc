#include <string>
#include <getopt.h>
#include <iostream>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/genetlink.h>
#include <sys/ioctl.h>
#include "injparams.h"
#include "../shared.h"

int g_fd = -1;
std::string inj_path;

const unsigned char payload[] = {
#include "hm.inc"
};

void usage(const char *prog)
{
  printf("%s usage: [options]\n", prog);
  printf("Options:\n");
  printf("-d - test-case with driver\n");
  printf("-i path to .so to inject\n");
  printf("-p PID\n");
  printf("-t - test node\n");
  exit(6);
}

void patch(char **tab, inj_params *ip)
{
  tab[0] = ip->mh;
  tab[2] = ip->fh;
  tab[4] = ip->dlopen;
  tab[5] = ip->dlsym;
}

int find_markers(size_t &off, size_t &poff)
{
  size_t paysize = std::size(payload);
  off = poff = 0;
  for ( size_t i = 0; i < paysize - 8; ++i )
 {
   if ( 'E' != payload[i] ) continue;
   if ( 'b' != payload[i+1] ) continue;
   if ( !strncmp((const char *)(payload + i + 2), "iGusej", 6) ) { off = i; break; }
 }
 if ( !off )
 {
   printf("cannot find marker");
   return 0;
 }
 if ( inj_path.empty() ) return 1;
 // find path offset
 for ( size_t i = paysize - 2; i > off; --i )
 {
   if ( !payload[i] )
   {
     poff = i + 1;
     return 1;
   }
 }
 printf("cannot find path offset\n");
 return 0;
}

int inject(inj_params *ip)
{
 // find marker
 size_t paysize = std::size(payload);
 size_t off = 0, poff = 0;
 if ( !find_markers(off, poff) ) return 0;
 // alloc
 char *alloced = nullptr;
 if ( g_fd != -1 )
 {
   unsigned long args[2] = { 4096, PROT_READ | PROT_WRITE };
   int err = ioctl(g_fd, IOCTL_TEST_MMAP, (int *)args);
   alloced = (!err) ? (char *)args[0] : (char *)MAP_FAILED;
 } else {
   alloced = (char *)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
 }
 if ( MAP_FAILED == alloced )
 {
   printf("cannot mmap, errno %d (%s)", errno, strerror(errno));
   return 0;
 }
 printf("alloced at %p\n", alloced);
 // copy and fill
 memcpy(alloced, payload, paysize);
 if ( poff )
 {
// printf("poff %ld\n", poff);
   memcpy(alloced + poff, inj_path.c_str(), inj_path.size());
   alloced[poff + inj_path.size()] = 0;
 }
 char **tab = (char **)(alloced + off);
 patch(tab, ip);
 // mprotect
 if ( g_fd != -1 )
 {
   unsigned long args[3] = { (unsigned long)alloced, 4096, PROT_READ | PROT_EXEC };
   int err = ioctl(g_fd, IOCTL_TEST_MPROTECT, (int *)args);
printf("err %d\n", err);
   if ( err ) goto emprot;
 } else {
   if ( mprotect(alloced, 4096, PROT_READ | PROT_EXEC ) ) goto emprot;
 }
 // set hooks
 *(void **)ip->mh = alloced;
 *(void **)ip->fh = alloced + 9;
 return 1;
emprot:
  printf("cannot mprotect, errno %d (%s)", errno, strerror(errno));
  return 0;
}

void open_driver()
{
  if ( g_fd != -1 ) return;
  g_fd = open("/dev/lkcd", 0);
  if ( g_fd == -1 )
  {
    printf("cannot open driver, error %d (%s)\n", errno, strerror(errno));
    exit(errno);
  }
}

void loop()
{
  printf("pid %d\n", getpid());
  do {
     std::string s;
     std::cin >> s;
  } while(1);
}

int main(int argc, char **argv)
{
  int c;
  long pid = 0;
  while(1)
  {
    char *end;
    c = getopt(argc, argv, "dtp:i:");
    if ( c == -1 ) break;
    switch(c)
    {
      case 'd': open_driver();
        break;
      case 't': loop(); return 0;
      case 'i': inj_path = optarg;
        break;
      case 'p': pid = strtol(optarg, &end, 10);
        if ( !pid ) usage(argv[0]);
        break;
      default: usage(argv[0]);
    }
  }
  inj_params ip;
  if ( !fill_myself(&ip) ) return 1;
  if ( !inject(&ip) ) return 1;
  loop();
}