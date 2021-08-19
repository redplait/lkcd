#include <iostream>
#include "ksyms.h"
#include <elfio/elfio_dump.hpp>

using namespace ELFIO;

int main(int argc, char **argv)
{
   if ( argc < 2 )
   {
     printf("%s usage: image [symbols]\n", argv[0]);
     return 1;
   }
   elfio reader;
   if ( !reader.load( argv[1] ) ) 
   {
      printf( "File %s is not found or it is not an ELF file\n", argv[1] );
      return 1;
   }
   if ( argc == 3 )
   {
     int err = read_ksyms(argv[2]);
     if ( err )
     {
       printf("cannot read %s, error %d\n", argv[2], err);
       return err;
     }
     // make some tests
     auto a1 = get_addr("__x86_indirect_thunk_rax");
     printf("__x86_indirect_thunk_rax: %p\n", (void *)a1);
   }
   // enum sections
   Elf_Half n = reader.sections.size();
   Elf64_Addr text_start = 0;
   Elf_Xword text_size = 0;
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( sec->get_name() == ".text" )
     {
       text_start = sec->get_address();
       text_size  = sec->get_size();
       break;
     }
   }
   if ( !text_start )
   {
     printf("cannot find .text\n");
     return 1;
   }
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( sec->get_name() == ".data" )
     {
       a64 *curr = (a64 *)sec->get_data();
       a64 *end  = (a64 *)((char *)curr + sec->get_size());
       size_t count = 0;
       for ( ; curr < end; curr++ )
       {
         if ( *curr >= (a64)text_start &&
               *curr < (a64)(text_start + text_size)
            )
          count++;
       }
       printf("found %d\n", count);
       break;
     }
   }
}
