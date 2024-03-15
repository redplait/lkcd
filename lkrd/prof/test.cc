#include <stdlib.h>
#include <stdio.h>
#include "eread.h"
#include "lditer.h"

extern "C" void _mcleanup (void);
extern "C" void mcount(void);
extern "C" void monstartup (char *, char *);
const char *target = "libprelf.so";

int
main(int argc, char *argv[])
{
  printf("int %d long %d\n", sizeof(int), sizeof(long));
  int need_mstop = 0;
  char prefix[50] = { 0 };
  if ( argc > 1 )
  {
    for ( int i = 1; i < argc; i++ )
    {
      struct prof_data pd;
      if ( process_elf(argv[i], &pd) <= 0 )
      {
        if ( pd.flags ) printf("flags: %lX\n", pd.flags);
        if ( pd.flags1 ) printf("flags1: %lX\n", pd.flags1);
        continue;
      }
      printf("%s:\n", argv[i]);
      // dump res
      if ( pd.flags ) printf("flags: %lX\n", pd.flags);
      if ( pd.flags1 ) printf("flags1: %lX\n", pd.flags1);
      if ( pd.m_mcount ) printf("mcount %lX\n", pd.m_mcount);
      if ( pd.m_func_enter ) printf("func_enter %lX\n", pd.m_func_enter);
      if ( pd.m_func_exit ) printf("fubc_exit %lX\n", pd.m_func_exit);
      if ( cmp_sonames(argv[i], target) )
      {
        printf("[+] %s loaded", target);
        ld_data ld;
        ld.name = target;
        if ( ld_iter(&ld) )
        {
          printf(" at %p, x_start %p x_size %lX\n", ld.base, ld.x_start, ld.x_size);
          sprintf(prefix, "gmon.%lX", ld.base);
          if ( pd.m_mcount )
          {
            // this library was compiled with -pg option - so we can just call monstartup with right address range
            need_mstop = 1;
            monstartup(ld.base, ld.x_start + ld.x_size);
          } else if ( pd.m_func_enter )
          {
            // -finstrument-functions - patch __cyg_profile_func_enter to ncount and call monstartup
            void **iat = (void **)(ld.base + pd.m_func_enter);
            printf("[+] patch func_enter at %p\n", iat);
            void *real_m = (void *)&mcount;
            *iat = real_m;
            need_mstop = 1;
            monstartup(ld.base, ld.x_start + ld.x_size);
          } else {
            printf("[-] your library is not profileable\n");
          }
        } else
         printf(" ld_iter failed\n");
      }
    }
    if ( need_mstop ) {
     setenv("GMON_OUT_PREFIX", prefix, 1);
     _mcleanup();
    }
  } else
   ld_iter();
}