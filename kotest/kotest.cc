#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <map>
#include <list>
#include <set>
#include "elfio/elfio.hpp"

using namespace ELFIO;

// from hd.cc
extern void HexDump(unsigned char *From, int Len);

// globals
int g_hexdump = 0,
    g_with_bss = 0,
    g_debug = 0,
    g_verbose = 0;

struct asymbol
{
  std::string name;
  Elf64_Addr addr;
  Elf_Xword idx = 0;
  Elf_Xword size = 0;
  Elf_Half section;
  unsigned char bind = 0,
                type = 0,
                other = 0,
                art = 0;  // is symbol artificial - no name, only addr - offset in section
  unsigned long xref = 0, // number of refs from ordinary sections
                rref = 0; // number of refs from discardable sections
};

struct areloc
{
  int sec_idx;
  Elf64_Addr addr;
  struct asymbol *sym = nullptr;
  unsigned type;
};

struct art_symbol {
  asymbol sym;
  areloc track;
};

struct asection
{
  short discard:1,
        allowed:1,
        is_bss:1;
  Elf_Half s; // section index
  std::map<Elf64_Addr, asymbol *> syms;
  asymbol *nearest(Elf64_Addr addr)
  {
    if ( syms.empty() ) return nullptr;
    auto fiter = syms.upper_bound(addr);
    if ( fiter == syms.begin() ) return nullptr; // addr < most left known symbol in section
    fiter--;
    if ( fiter == syms.end() ) return nullptr; // no previous symbol
    if ( addr >= fiter->second->addr && (fiter->second->addr + fiter->second->size) > addr ) return fiter->second;
    return nullptr;
  }
};

class kotest
{
  public:
   ~kotest();
   int open(const char *);
   void process_relocs(int);
   void dump_symbols(int show_refs = 0) const;
   size_t s_moved_size = 0;
  protected:
   void fix_add(unsigned rtype, Elf_Sxword &add);
   void hdump(asymbol *sym);
   art_symbol *add_art(asection *, Elf_Sxword add);
   int fix_art(asection *);
   size_t calc_loss(asection *);
   void process_relocs(int, section *);
#define SNAME(i) reader.sections[i]->get_name().c_str()
   inline asection *by_sym(asymbol *sym)
   {
     if ( sym->section >= n_sec ) return nullptr;
     return sects[sym->section];
   }
   std::vector<asymbol *> syms;
   std::vector<asection *> sects;
   // pls don't change container type for artificial symbols
   // std::list don't move objects while resizing so addresses will remain the same and can be used as value in asection::syms
   std::list<art_symbol> m_arts;
   Elf_Half n_sec;
   elfio reader;
};

// fixme: names of disacardable section was borrowed from
// https://elixir.bootlin.com/linux/v6.8.10/source/include/linux/init.h
static int is_discardable(const char *sname)
{
  if ( !strcmp(sname, ".init.text") ) return 1;
  if ( !strcmp(sname, ".init.data") ) return 1;
  if ( !strcmp(sname, ".init.rodata") ) return 1;
  // from https://elixir.bootlin.com/linux/v6.8.10/source/kernel/module/main.c#L2118
  if ( !strcmp(sname, ".init_array") ) return 1;
  // aarch64 specific - processing in scs_patch <- module_finalize
  if ( !strcmp(sname, ".init.eh_frame") ) return 1;
  // emulate module_init_section function from kernel/module/main.c
  return 0 == strncmp(sname, ".init", 5);
}

static int is_allowed(const char *sname)
{
  // it's legal to have ref from .gnu.linkonce.this_module to init_module function
  if ( !strcmp(sname, ".gnu.linkonce.this_module") ) return 1;
  // apply_alternatives called from module_finalize <- post_relocation <- load_module before do_init_module
  if ( !strcmp(sname, ".altinstructions") ) return 1;
  // under risc-v this section called .alternative and processing in apply_module_alternatives <- module_finalize
  if ( !strcmp(sname, ".alternative") ) return 1;
  // apply_retpolines called from the same module_finalize
  if ( !strcmp(sname, ".retpoline_sites") ) return 1;
  // apply_returns called from the same module_finalize
  if ( !strcmp(sname, ".return_sites") ) return 1;
  // powerpc specific sections - do_feature_fixups & do_lwsync_fixups called from module_finalize
  if ( !strcmp(sname, "__ftr_fixup" ) ||
       !strcmp(sname, "__mmu_ftr_fixup") ||
       !strcmp(sname, "__fw_ftr_fixup") ||
       !strcmp(sname, "__lwsync_fixup") )
    return 1;
  // s390 specific sections - processing in nospec_revert <- from module_finalize
  if ( !strcmp(sname, ".s390_indirect") ||
       !strcmp(sname, ".s390_return") )
    return 1;
  return 0;
}

// set of sections which could well be in discardable memory
static std::set<std::string> s_can_move = {
 ".ctors",
 ".altinstructions",
 ".alternative",
 ".retpoline_sites", ".return_sites",
 // powerpc specific
 "__ftr_fixup", "__mmu_ftr_fixup", "__fw_ftr_fixup", "__lwsync_fixup",
 // s390 specific
 ".s390_indirect", ".s390_return"
};

inline int can_move(const std::string &name)
{
 auto si = s_can_move.find(name);
 return si != s_can_move.end();
}

void kotest::hdump(asymbol *sym)
{
  // check section
  if ( !sects[sym->section] ) return;
  section *s = reader.sections[sym->section];
  if ( !(s->get_flags() && 4) ) return; // bss?
  auto ssize = s->get_size();
  if ( !ssize ) return; // empty
  if ( sym->addr >= ssize ) return; // out of content
  int len = sym->size;
  // check real symbol size
  if ( !len )
  {
    // try next symbol
    auto niter = sects[sym->section]->syms.upper_bound(sym->addr);
    if ( niter != sects[sym->section]->syms.end() )
      len = niter->second->addr - sym->addr;
    else // till end of section
      len = ssize - sym->addr;
  }
  // dump header
  auto data = s->get_data();
  if ( !sym->art && !sym->name.empty() )
    printf("%s!%s size %X:\n", s->get_name().c_str(), sym->name.c_str(), len);
  else
    printf("%s+%lX size %X\n", s->get_name().c_str(), sym->addr, len);
  if ( data )
    HexDump( (unsigned char *)(data + sym->addr), len );
}

size_t kotest::calc_loss(asection *as)
{
  size_t res = 0;
  for ( auto si = as->syms.begin(); si != as->syms.end(); ++si )
  {
    if ( !si->second->rref ) continue;
    if ( si->second->xref ) continue;
    // we have symbol with refs only from discardable sections
    if ( g_hexdump )
     hdump(si->second);
    if ( g_verbose )
    {
      printf("%s + %lX", SNAME(si->second->section), si->first);
      if ( si->second->art )
      {
        art_symbol *ars = (art_symbol *)si->second;
        printf(" rref %ld xref %ld add size %ld", si->second->rref, si->second->xref, si->second->size);
        // we have track where this artificail symbol was reffered - it can be symbol or section + offset
        if ( ars->track.sym )
          printf(" <- %s", ars->track.sym->name.c_str());
        else
          printf(" <- %s + %lX", SNAME(ars->track.sec_idx), ars->track.addr);
        putc('\n', stdout);
      } else
      printf(" (%s) rref %ld xref %ld add size %ld\n", si->second->name.c_str(),
        si->second->rref, si->second->xref, si->second->size);
    }
    res += si->second->size;
  }
  return res;
}

int kotest::fix_art(asection *as)
{
  int res = 0;
  section *s = reader.sections[as->s];
  auto iter = as->syms.begin();
  asymbol *prev = iter->second;
  auto debug = [s](const asymbol *prev, int res) {
    if ( !res ) printf("Artificial symbols in %s:\n", s->get_name().c_str());
    printf(" %lX size %ld xref %ld rref %ld\n", prev->addr, prev->size, prev->xref, prev->rref);
  };
  for ( ++iter; iter != as->syms.end(); ++iter )
  {
    if ( prev->art )
    {
      prev->size = iter->second->addr - prev->addr;
      if ( g_debug ) debug(prev, res);
      res++;
    }
    prev = iter->second;
  }
  // last one
  if ( prev->art )
  {
    // find size of section
    auto end = s->get_size();
    if ( end > prev->addr )
    {
      prev->size = end - prev->addr;
      if ( g_debug ) debug(prev, res);
      res++;
    }
  }
  return res;
}

art_symbol *kotest::add_art(asection *as, Elf_Sxword add)
{
  // check that section is not discardable
  if ( as->discard ) return nullptr;
  art_symbol sym, *res;
  sym.sym.art = 1;
  sym.sym.section = as->s;
  sym.sym.addr = add;
  m_arts.push_back(sym);
  res = &m_arts.back();
  as->syms[add] = &res->sym;
  return res;
}

kotest::~kotest()
{
  for ( auto s: syms )
    if ( s ) delete s;
  for ( auto s: sects )
    if ( s ) delete s;
}

void kotest::fix_add(unsigned rtype, Elf_Sxword &add)
{
  auto mach = reader.get_machine();
  if ( mach == EM_386 || mach == EM_486 || mach == EM_X86_64 )
  {
    if ( rtype == 2 || // pc32
         rtype == 4    // plt32
       )
      add += 4;
  }
}

void kotest::process_relocs(int sidx, section *s)
{
  auto s_name = s->get_name();
  auto inf = s->get_info();
  if ( inf >= n_sec )
  {
    printf("reloc section %s info %d is too big\n", s_name.c_str(), inf);
    return;
  }
  auto dest = sects[inf];
  if ( !dest )
  {
    if ( g_verbose )
      printf("reloc section %s info %d not exists\n", s_name.c_str(), inf);
    return;
  }
  relocation_section_accessor ac(reader, s);
  int num = ac.get_entries_num();
  if ( g_debug )
    printf("reloc section %d %s has %d entries, dest %d (%s) discard %d\n", sidx, s_name.c_str(), num, inf,
      SNAME(dest->s), dest->discard);
  for ( int i = 0; i < num; ++i )
  {
    Elf64_Addr offset = 0;
    Elf_Word sym_idx = 0;
    unsigned rtype = 0;
    Elf_Sxword add = 0;
    ac.get_entry(i, offset, sym_idx, rtype, add);
    asymbol *sym = nullptr;
    if ( sym_idx < syms.size() ) sym = syms[sym_idx];
    // skip refs to external (PLT?)
    if ( sym && sym->section == SHN_UNDEF ) continue;
    // skip refs to absolute symbols
    if ( sym && sym->section == SHN_ABS ) continue;
    // fix add. depends from current arch & rtype
    fix_add(rtype, add);
    // try to find symbol in dest section
    if ( g_debug ) {
      if ( sym )
      {
        if ( sym->type == STT_SECTION )
         printf(" [%d] off %lX rtype %d section %s + %lX\n", i, offset, rtype, sym->name.c_str(), add);
        else
          printf(" [%d] off %lX rtype %d sym %s + %lX\n", i, offset, rtype, sym->name.c_str(), add);
      } else
        printf(" [%d] off %lX rtype %d sym_idx %d add %lX\n", i, offset, rtype, sym_idx, add);
    }
    if ( !sym ) {
      printf("no symbol for reloc %d in %s, sym_idx %d offset %lX\n", i, SNAME(dest->s), sym_idx, offset);
      continue;
    }
    auto process = [=](asymbol *sym, asection *src) {
      if ( dest->discard ) sym->rref++;
      else {
        sym->xref++;
        if ( src && src->discard && !dest->allowed )
        {
          auto pretty = dest->nearest(offset);
          if ( pretty )
            printf("Warning: %s!%s refs to symbol %s in discardable section %s\n", SNAME(dest->s), pretty->name.c_str(),
              sym->name.c_str(), SNAME(src->s));
          else
            printf("Warning: %s+%lX refs to symbol %s in discardable section %s\n", SNAME(dest->s), offset,
              sym->name.c_str(), SNAME(src->s));
        }
      }
    };
    // for just symbol refs just inc ref count
    if ( sym->type != STT_SECTION )
    {
      process(sym, by_sym(sym));
      continue;
    }
    // we have ref to section + add
    auto src = by_sym(sym);
    if ( !src ) {
      printf("cannot find section with index %d for reloc %d, sym_idx %d offset %lX\n", sym->section, i, sym_idx, offset);
      continue;
    }
    auto fiter = src->syms.find(add);
    if ( fiter != src->syms.end() )
    {
      process(fiter->second, src);
      continue;
    }
    // try prev
    auto prev = src->nearest(add);
    if ( prev && !prev->art ) {
      process(prev, src);
      continue;
    }
    // gcc gives here stupid warning: comparison of integer expressions of different signedness
    // you can ignore it bcs if we found prev - both prev->addr & add must be > 0
    if ( prev && prev->addr == add ) {
      // some already inserted artificial symbol
      if ( dest->discard ) prev->rref++;
      else prev->xref++;
      continue; // no sense to report about ref to each artificial symbol - report will be dumped below on inserting
    }
    // printf("need add art to section %s + %lX\n", SNAME(src->s), add);
    // check add
    if ( add < 0 )
    {
      printf("Reloc %d type %d in section %s + %lX has negative offset %ld to section %s\n", i, rtype, SNAME(inf), offset,
        add, SNAME(src->s));
      // check symbol at section + 0
      fiter = src->syms.find(0);
      if ( fiter != src->syms.end() )
        process(fiter->second, src);
      continue;
    }
    art_symbol *art = add_art(src, add);
    if ( art && g_verbose )
    { // for verbose mode store track where it referred to for first time
      art->track.sec_idx = inf;
      art->track.addr = offset;
      art->track.type = rtype;
      art->track.sym = dest->nearest(offset);
    }
    if ( dest->discard ) {
      if ( art ) art->sym.rref++;
      continue;
    }
    if ( art ) {
      if ( dest->discard ) art->sym.rref++;
      else art->sym.xref++;
      continue;
    }
    // we here bcs art was not added - src is discardable
    // check it's referred from normal section
    if ( !dest->discard && !dest->allowed) {
      auto pretty = dest->nearest(offset);
      if ( pretty )
        printf("Warning: %s!%s refs to symbol in discardable section %s + %lX\n", SNAME(dest->s), pretty->name.c_str(),
          SNAME(src->s), add);
      else
        printf("Warning: %s+%lX refs to symbol in discardable section %s + %lX\n", SNAME(dest->s), offset,
          SNAME(src->s), add);
    }
  }
}

void kotest::process_relocs(int ds)
{
  for ( int i = 0; i < n_sec; ++i )
  {
    section *s = reader.sections[i];
    if ( s->get_type() == SHT_RELA || s->get_type() == SHT_REL )
     process_relocs(i, s);
  }
  // fix sizes of artificial symbols
  for ( int i = 0; i < n_sec; ++i )
  {
    asection *s = sects[i];
    if ( !s || s->syms.empty() ) continue;
    // skip bss
    if ( s->is_bss && !g_with_bss ) continue;
    fix_art(s);
  }
  if ( ds ) dump_symbols(1);
  // and calculate size of symbols reffered from discardable sections only
  size_t gain = 0;
  for ( int i = 0; i < n_sec; ++i )
  {
    asection *s = sects[i];
    if ( !s || s->syms.empty() || s->discard ) continue;
    // skip bss
    if ( s->is_bss && !g_with_bss ) continue;
    gain += calc_loss(s);
  }
  if ( gain ) printf("Total possibly gain %ld bytes\n", gain);
}

void kotest::dump_symbols(int show_refs) const
{
  for ( auto s: sects )
  {
    if ( !s ) continue;
    if ( s->syms.empty() ) continue;
    if ( s->is_bss && !g_with_bss ) continue;
    printf("Symbols in %s:\n", SNAME(s->s));
    for ( auto sym: s->syms )
    {
      if ( sym.second->art )
        printf(" Off %lX art size %ld", sym.first, sym.second->size);
      else
        printf(" Off %lX %s (idx %ld) type %d size %ld", sym.first, sym.second->name.c_str(), sym.second->idx,
          sym.second->type, sym.second->size);
      if ( show_refs )
      {
        if ( sym.second->art ) printf(" %p", sym.second);
        printf(" rref %ld xref %ld\n", sym.second->rref, sym.second->xref);
      } else
        putc('\n', stdout);
    }
  }
}

int kotest::open(const char *fname)
{
  if ( !reader.load(fname) )
  {
    printf("cannot load %s\n", fname);
    return 0;
  }
  int num_disc = 0;
  n_sec = reader.sections.size();
  if ( !n_sec )
  {
    printf("%ss: no sections\n", fname);
    return 0;
  }
  auto et = reader.get_type();
  if ( g_debug )
    printf("%s: type %X sections %d\n", fname, et, n_sec);
  if ( et != ET_REL )
  {
    printf("%s: not relocatable, type %X\n", fname, et);
    return 0;
  }
  sects.resize(n_sec);
  section *sym_sec = nullptr;
  for ( Elf_Half i = 0; i < n_sec; ++i )
  {
    section* sec = reader.sections[i];
    if ( sec->get_type() == SHT_SYMTAB ) { sym_sec = sec; continue; }
    auto s_fl = sec->get_flags();
    if ( s_fl & 6 /* ALLOC | READ */ )
    {
      sects[i] = new asection;
      sects[i]->s = i;
      sects[i]->discard = is_discardable(sec->get_name().c_str());
      sects[i]->allowed = is_allowed(sec->get_name().c_str());
      sects[i]->is_bss = (sec->get_type() == SHT_NOBITS);
      if ( sects[i]->discard ) num_disc++;
      if ( can_move(sec->get_name()) ) {
        if ( g_verbose )
          printf("Section %s can be placed in discardable memory, size %lX\n", sec->get_name().c_str(), sec->get_size());
        s_moved_size += sec->get_size();
      }
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
  if ( g_debug ) {
    for ( Elf_Half i = 0; i < n_sec; ++i )
    {
      asection *ds = sects[i];
      if ( ds )
      {
        section* sec = reader.sections[ds->s];
        printf("Section %d (%s) type %X flags %lX size %ld discard %d\n", i, SNAME(i),
         sec->get_type(), sec->get_flags(), sec->get_size(), ds->discard ? 1 : 0);
      }
    }
  }
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
    Elf_Half      _section = 0;
    unsigned char other   = 0;
    symbols.get_symbol( i, name, value, size, bind, type, _section, other );
    if ( type == STT_FILE ) continue; // ignore file symbols
    if ( _section != SHN_ABS && _section >= sects.size() )
    {
      printf("warning: symbol %ld (%s) has too big section index %d\n", i, name.c_str(), _section);
      continue;
    }
    asection *ss = nullptr;
    // https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-79797.html#scrolltoc
    if ( _section != SHN_UNDEF && _section != SHN_ABS )
    {
      if ( !sects[ _section ] ) continue;
      ss = sects[ _section ];
    }
    if ( ss && type == STT_SECTION && name.empty() )
      name = reader.sections[_section]->get_name();
    if ( g_debug )
    {
      if ( _section == SHN_UNDEF )
       printf("[%ld] %s UND\n", i, name.c_str());
      else if ( _section == SHN_ABS )
       printf("[%ld] %s ABS\n", i, name.c_str());
      else {
        if ( size )
          printf("[%ld] %s type %d sec %d (%s) addr %lX, size %lX\n", i, name.c_str(), type,
           _section, SNAME(_section), value, size);
        else
          printf("[%ld] %s type %d sec %d (%s) addr %lX\n", i, name.c_str(), type,
           _section, SNAME(_section), value);
      }
    }
    // add this symbol
    asymbol *as = new asymbol;
    as->name = name;
    as->addr = value;
    as->idx = sym_no;
    as->size = size;
    as->section = _section;
    as->bind = bind;
    as->type = type;
    syms[i] = as;
    if ( ss && type != STT_SECTION && _section != SHN_ABS )
    {
      auto added = ss->syms.find(value);
      if ( added == ss->syms.end() )
        ss->syms[value] = as;
    }
  }
  return 1;
}

void usage(const char *prog)
{
  printf("%s usage: [options] lkm ...\n", prog);
  printf("Options:\n");
  printf("-b - with .bss section (NOBITS)\n");
  printf("-d - debug moder\n");
  printf("-h - hexdump\n");
  printf("-v - verbose node\n");
  exit(6);
}

int main(int argc, char **argv)
{
  int ds = 0, c;
  while(1)
  {
    c = getopt(argc, argv, "Sbdhv");
    if ( c == -1 ) break;
    switch(c)
    {
      case 'S': ds = 1;
        break;
      case 'b': g_with_bss = 1;
        break;
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
    printf("%s:\n", argv[i]);
    if ( ds ) kt.dump_symbols();
    kt.process_relocs(ds);
    if ( kt.s_moved_size ) printf("Size of moveable sections %ld\n", kt.s_moved_size);
  }
}