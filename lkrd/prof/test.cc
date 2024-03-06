#include <stdlib.h>
#include <stdio.h>
#include "eread.h"

void ld_iter();

int
main(int argc, char *argv[])
{
  printf("int %d long %d\n", sizeof(int), sizeof(long));
  if ( argc > 1 )
  {
    for ( int i = 1; i < argc; i++ )
    {
      ELFIO::elfio rdr;
      if ( !rdr.load( argv[i] ) )
      {
        printf( "File %s is not found or it is not an ELF file\n", argv[i] );
        continue;
      }
      printf("%s:\n", argv[i]);
      elf_dread ed(&rdr);
      ed.process();
      // dump res
      auto v = ed.get_mcount();
      if ( v ) printf("mcount %lX\n", v);
      v = ed.get_func_enter();
      if ( v ) printf("func_enter %lX\n", v);
    }
  } else
   ld_iter();
}