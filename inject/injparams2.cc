#include <fstream>
#include <string.h>
#include <stdlib.h>
#include "injparams.h"
#include "elfio/elfio.hpp"

int fill_params(long pid, inj_params *res)
{
  std::string libc;
  if ( !find_libc(&libc) )
  {
    printf("cannot find libc\n");
    return 0;
  }
  // check if it is symlink
  char *real = realpath(libc.c_str(), NULL);
  if ( real != NULL )
  {
    libc = real;
    free(real);
  }
  // open /proc/pid/maps
  std::string path = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream f;
  unsigned long base = 0;
  f.open(path);
  if ( !f.is_open() )
  {
    printf("cannot open %s, errno %d (%s)\n", path.c_str(), errno, strerror(errno));
    return 0;
  } else {
    std::string s;
    auto lsize = libc.size();
    while( std::getline(f, s) )
    {
      auto size = s.size();
      if ( size < lsize ) continue;
      if ( strncmp(s.c_str() + size - lsize, libc.c_str(), lsize) ) continue;
      char *end;
      base = strtoull(s.c_str(), &end, 16);
      break;
    }
  }
  if ( !base )
  {
    printf("cannot find base for %s\n", libc.c_str());
    return 0;
  }
  printf("%s base %lX\n", libc.c_str(), base);
  // ok, lets read symbol table
  using namespace ELFIO;
  elfio reader;
  if ( !reader.load(libc.c_str()) )
  {
    printf("cannot load %s\n", libc.c_str());
    return 0;
  }
  int has_syms = 0;
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i )
  {
    section* sec = reader.sections[i];
    if ( SHT_DYNSYM != sec->get_type() ) continue;
    symbol_section_accessor symbols( reader, sec );
    Elf_Xword sym_no = symbols.get_symbols_num();
    if ( sym_no > 0 )
    {
      has_syms = 1;
      for ( Elf_Xword i = 0; i < sym_no; ++i )
      {
        std::string   name;
        Elf64_Addr    value   = 0;
        Elf_Xword     size    = 0;
        unsigned char bind    = 0;
        unsigned char type    = 0;
        Elf_Half      section = 0;
        unsigned char other   = 0;
        symbols.get_symbol( i, name, value, size, bind, type, section, other );
#define ASGN(f)  { res->f = (char *)base + value; continue; }
        if ( !strcmp(name.c_str(), "__libc_dlopen_mode") ) ASGN(dlopen)
        if ( !strcmp(name.c_str(), "__libc_dlsym") ) ASGN(dlsym)
        if ( !strcmp(name.c_str(), "__malloc_hook") ) ASGN(mh)
        if ( !strcmp(name.c_str(), "__free_hook") ) ASGN(fh)
      }
    }
  }
  if ( !has_syms )
  {
    printf("cannot find symbols in %s\n", libc.c_str());
    return 0;
  }
  // validate
  if ( !res->mh ) { printf("cannot find malloc_hook\n"); return 0; }
  if ( !res->fh ) { printf("cannot find free_hook\n"); return 0; }
  if ( !res->dlopen ) { printf("cannot find dlopen\n"); return 0; }
  if ( !res->dlsym ) { printf("cannot find dlsym\n"); return 0; }
  return 1;
}