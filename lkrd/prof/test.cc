#include <stdlib.h>
#include <stdio.h>
#include "eread.h"
#include "lditer.h"

const char *target = "libprelf.so";

int
main(int argc, char *argv[])
{
  printf("int %d long %d\n", sizeof(int), sizeof(long));
  if ( argc > 1 )
  {
    for ( int i = 1; i < argc; i++ )
    {
      struct prof_data pd;
      if ( process_elf(argv[i], &pd) <= 0 ) continue;
      printf("%s:\n", argv[i]);
      // dump res
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
        } else
         printf(" ld_iter failed\n");
      }
    }
  } else
   ld_iter();
}