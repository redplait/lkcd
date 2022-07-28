#include <iostream>
#include "ldso.h"

int main(int argc, char **argv)
{
  if ( argc != 2 )
  {
    fprintf(stderr, "Usage: %s path\n", argv[0]);
    return 6;
  }
  ELFIO::elfio rdr;
  if ( !rdr.load( argv[1] ) ) 
  {
     printf( "File %s is not found or it is not an ELF file\n", argv[1] );
     return 1;
  }
  ldso ld(&rdr);
  if ( ld.process() )
    ld.dump();
}
