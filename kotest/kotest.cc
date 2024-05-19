#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <map>
#include "elfio/elfio.hpp"

using namespace ELFIO;

// globals
int g_hexdump = 0,
    g_debug = 0,
    g_verbose = 0;

struct asymbol
{
  std::string name;
  Elf64_Addr addr;
  Elf_Xword size;
  Elf_Half section;
  unsigned char bind = 0,
                type = 0,
                other = 0;
  unsigned long xref = 0, rref = 0;
};

struct areloc
{
  int sec_idx;
  Elf64_Addr addr;
  struct asymbol *sym;
  unsigned type;
};

struct asection
{
  char discard = 0;
  char mitigate = 0;
  section *s;
  std::map<Elf64_Addr, asymbol *> syms;
};

class kotest
{
  public:
   ~kotest();
   int open(const char *);
  protected:
   std::vector<asymbol *> syms;
   std::vector<asection *> sects;
   section *sym_sec = nullptr;
   elfio reader;
};

// fixme: names of disacardable section was borrowed from
// https://elixir.bootlin.com/linux/v6.8.10/source/include/linux/init.h
static int is_discardable(const char *sname)
{
  if ( !strcmp(sname, ".init.text") ) return 1;
  if ( !strcmp(sname, ".init.data") ) return 1;
  if ( !strcmp(sname, ".init.rodata") ) return 1;
  return 0;
}

kotest::~kotest()
{
  for ( auto s: syms )
    if ( s ) delete s;
  for ( auto s: sects )
    if ( s ) delete s;
}

int kotest::open(const char *fname)
{
  if ( !reader.load(fname) )
  {
    printf("cannot load %s\n", fname);
    return 0;
  }
  int num_disc = 0;
  Elf_Half n = reader.sections.size();
  if ( !n )
  {
    printf("%ss: no sections\n", fname);
    return 0;
  }
  auto et = reader.get_type();
  if ( g_debug )
    printf("%s: type %X\n", fname, et);
  if ( et != ET_REL )
  {
    printf("%s: not relocatable, type %X\n", fname, et);
    return 0;
  }
  sects.resize(n);
  for ( Elf_Half i = 0; i < n; ++i )
  {
    section* sec = reader.sections[i];
    if ( sec->get_type() == SHT_SYMTAB ) { sym_sec = sec; continue; }
    auto s_fl = sec->get_flags();
    if ( s_fl & 6 /* ALLOC | READ */ )
    {
      sects[i] = new asection;
      sects[i]->discard = is_discardable(sec->get_name().c_str());
      if ( sects[i]->discard ) num_disc++;
      sects[i]->s = sec;
    }
  }
  if ( !sym_sec )
  {
    printf("%s: cannot find symbols\n", fname);
    return 0;
  }
  if ( !num_disc )
  {
    printf("%s: not discardable sections\n", fname);
    return 0;
  }
  if ( g_verbose )
   printf("%s has %d discardable sections\n", fname, num_disc);
  // read symtab
  symbol_section_accessor symbols( reader, sym_sec );
  Elf_Xword sym_no = symbols.get_symbols_num();
  if ( !sym_no )
  {
    printf("%s: no symbols\n", fname);
    return 0;
  }
  syms.resize(sym_no);
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
    if ( type == STT_SECTION || type == STT_FILE ) continue;
    if ( section >= sects.size() )
    {
      printf("warning: symbol %d (%s) has too big section index %d\n", i, name.c_str(), section);
      continue;
    }
    if ( !sects[ section ] ) continue;
    auto s = sects[ section ];
    if ( g_debug )
    {
      printf("[%d] %s type %d sec %d (%s) addr %lX, size %X\n", i, name.c_str(), type,
       section, s->s->get_name().c_str(), value, size);
    }
    // add this symbol
    asymbol *as = new asymbol;
    as->name = name;
    as->addr = value;
    as->size = size;
    as->section = section;
    as->bind = bind;
    as->type = type;
    syms[i] = as;
    auto added = s->syms.find(value);
    if ( added == s->syms.end() )
      s->syms[value] = as;
  }
  return 1;
}

void usage(const char *prog)
{
  printf("%s usage: [options] lkm ...\n", prog);
  printf("Options:\n");
  printf("-d - debug moder\n");
  printf("-h - hexdump\n");
  printf("-v - verbose node\n");
  exit(6);
}

int main(int argc, char **argv)
{
  int c;
  while(1)
  {
    char *end;
    c = getopt(argc, argv, "dhv");
    if ( c == -1 ) break;
    switch(c)
    {
      case 'd': g_debug = 1;
        break;
      case 'h': g_hexdump = 1;
        break;
      case 'v': g_verbose = 1;
        break;
      default: usage(argv[0]);
    }
  }
  if (optind == argc) usage(argv[0]);
  for ( int i = optind; i < argc; i++ )
  {
    kotest kt;
    if ( !kt.open(argv[i]) ) continue;
  }
}