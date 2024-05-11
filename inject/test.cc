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
#ifdef __aarch64__
#include <sys/auxv.h>
#endif
#include "injparams.h"
#include "../shared.h"

int g_fd = -1;
std::string inj_path;

#ifdef __aarch64__
const unsigned char nobti[] = {
#include "a64_nobti.ainc"
};
const size_t nobti_size = sizeof(nobti);
#endif

const unsigned char payload[] = {
#ifdef __aarch64__
#include "a64.ainc"
#else
#include "hm.inc"
#endif
};
const size_t paysize = sizeof(payload);

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

int find_markers(inj_params *ip, size_t &off, size_t &poff)
{
  off = poff = 0;
  for ( size_t i = 0; i < ip->stub_size - 8; ++i )
 {
   if ( 'E' != ip->stub[i] ) continue;
   if ( 'b' != ip->stub[i+1] ) continue;
   if ( !strncmp((const char *)(ip->stub + i + 2), "iGusej", 6) ) { off = i; break; }
 }
 if ( !off )
 {
   printf("cannot find marker");
   return 0;
 }
 if ( inj_path.empty() ) return 1;
 // find path offset
 for ( size_t i = ip->stub_size - 2; i > off; --i )
 {
   if ( !ip->stub[i] )
   {
     poff = i + 1;
     return 1;
   }
 }
 printf("cannot find path offset\n");
 return 0;
}

void fill_buffer(char *alloced, size_t off, size_t poff, inj_params *ip)
{
 // copy and fill
 memcpy(alloced, ip->stub, ip->stub_size);
 if ( poff )
 {
// printf("poff %ld\n", poff);
   memcpy(alloced + poff, inj_path.c_str(), inj_path.size());
   alloced[poff + inj_path.size()] = 0;
 }
 char **tab = (char **)(alloced + off);
 patch(tab, ip);
}

int inject(inj_params *ip)
{
 // find marker
 size_t off = 0, poff = 0;
 if ( !find_markers(ip, off, poff) ) return 0;
 const size_t dtab_size = 6 * sizeof(unsigned long);
 const char *tab = (const char *)(ip->stub + off);
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
 fill_buffer(alloced, off, poff, ip);
 // mprotect
 if ( g_fd != -1 )
 {
   unsigned long args[3] = { (unsigned long)alloced, 4096, PROT_READ | PROT_EXEC };
   int err = ioctl(g_fd, IOCTL_TEST_MPROTECT, (int *)args);
printf("mprot err %d\n", err);
   if ( err ) goto emprot;
 } else {
   if ( mprotect(alloced, 4096, PROT_READ | PROT_EXEC ) ) goto emprot;
 }
 // set hooks
 *(void **)ip->mh = alloced;
 *(void **)ip->fh = alloced + tab[dtab_size];
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

int inject2(pid_t pid, char *params)
{
  open_driver();
  int err = ioctl(g_fd, IOCTL_INJECT, params);
  if ( err )
  {
   printf("IOCTL_INJECT failed, errno %d (%s)\n", errno, strerror(errno));
   return 0;
  }
  // wait for status
  while(1)
  {
    unsigned long wp[3] = { pid, 0, 0 };
    err = ioctl(g_fd, IOCTL_INJECT, wp);
    if ( err )
    {
      printf("wait IOCTL_INJECT failed, errno %d (%s)\n", errno, strerror(errno));
      return 0;
    }
    if ( wp[0] == 1 ) { printf("wait\n"); sleep(1); continue; }
    if ( wp[0] == 2 ) printf("injected at %p\n", (void *)wp[2]);
    else printf("state %ld error %ld\n", wp[0], -wp[1]);
    return (int)wp[1];
  }
}

void loop()
{
  printf("pid %d\n", getpid());
  do {
     void *alloced = malloc(10);
     std::string s;
     std::cin >> s;
     if ( alloced ) free(alloced);
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
  ip.stub = payload;
  ip.stub_size = paysize;
#ifdef __aarch64__
  auto hw2 = getauxval(AT_HWCAP2);
  // ripped from arch/arm64/include/uapi/asm/hwcap.h
#define HWCAP2_BTI              (1 << 17)
  if ( !(hw2 & HWCAP2_BTI) ) {
    ip.stub = nobti;
    ip.stub_size = nobti_size;
  }
#endif
  if ( pid )
  {
    if ( !fill_params(pid, &ip) ) return 1;
    // find marker
    size_t off = 0, poff = 0;
    if ( !find_markers(&ip, off, poff) ) return 1;
    // calc size
    size_t res = ip.stub_size;
    if ( !inj_path.empty() )
      res = poff + inj_path.size() + 1;
    const size_t param_size = 3 * sizeof(unsigned long);
    char *buf = (char *)malloc(res + param_size);
    if ( !buf )
    {
      printf("cannot alloc buffer len %lX\n", res);
      return 1;
    }
    unsigned long *p = (unsigned long *)buf;
    p[0] = pid;
    p[1] = res;
    p[2] = off;
    fill_buffer(buf + param_size, off, poff, &ip);
    HexDump((unsigned char *)buf, (int)(res + param_size));
    inject2(pid, buf);
    free(buf);
  } else {
    if ( !fill_myself(&ip) ) return 1;
    if ( !inject(&ip) ) return 1;
    loop();
  }
}