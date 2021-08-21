#include <stdio.h>
#include <fstream>
#include <string>
#include <list>
#include <map>
#include <set>
#include <algorithm>
#ifdef HAS_ELFIO
#include "elfio/elfio_dump.hpp"
#endif /* HAS_ELFIO */
#include "ksyms.h"

#ifdef _MSC_VER
typedef unsigned __int64 a64;
#else
typedef unsigned long a64;
#endif

struct one_sym
{
  std::string name;
  a64 addr;
  char letter;
};

struct one_addr
{
  a64 addr;
  one_sym *sym;
};

struct namesComparer : public std::binary_function<const char *, const char *, bool>
{
  bool operator()(const char *a, const char *b) const
  {
    return strcmp(a, b) < 0;
  }
};

class ksym_holder
{
  public:
    ksym_holder()
    {
      m_addresses = NULL;
    }
   ~ksym_holder()
    {
      if ( m_addresses != NULL )
        delete[] m_addresses;
    }
    int read_ksyms(const char *name);
#ifdef HAS_ELFIO
    int read_syms(const ELFIO::elfio& reader, ELFIO::symbol_section_accessor &);
#endif /* HAS_ELFIO */
    const char *name_by_addr(a64);
    const char *lower_name_by_addr(a64);
    a64 get_addr(const char *name)
    {
      auto c = m_names.find(name);
      if ( c != m_names.end() ) 
        return c->second->addr;
      return 0;
    }
  protected:
    std::list<one_sym> m_syms;
    std::map<const char *, one_sym *, namesComparer> m_names;
    size_t m_asize;
    one_addr *m_addresses;

    void make_addresses();
};

const char *ksym_holder::name_by_addr(a64 addr)
{
  if ( NULL == m_addresses )
    return NULL;
  const one_addr *found = std::lower_bound(m_addresses, m_addresses + m_asize, addr, [](const one_addr &l, a64 off) -> 
      bool { return l.addr < off; }
  );
  if ( found ==  m_addresses + m_asize)
    return NULL;
  if ( found->addr != addr )
    return NULL;
  return found->sym->name.c_str();
}

const char *ksym_holder::lower_name_by_addr(a64 addr)
{
  if ( NULL == m_addresses )
    return NULL;
  const one_addr *found = std::lower_bound(m_addresses, m_addresses + m_asize, addr, [](const one_addr &l, a64 off) -> 
      bool { return l.addr < off; }
  );
  if ( found ==  m_addresses + m_asize)
    return NULL;
  return found->sym->name.c_str();
}

void ksym_holder::make_addresses()
{
  auto count = m_syms.size();
  if ( !count )
    return;
  m_addresses = new one_addr[count];
  std::set<a64> inserted;
  for ( auto &c: m_syms )
  {
    auto was = inserted.find(c.addr);
    if ( was != inserted.end() )
      continue;
    m_addresses[m_asize].addr = c.addr;
    m_addresses[m_asize].sym = &c;
    m_asize++;
    inserted.insert(c.addr);
  }
  if ( !m_asize )
    return;
  // sort them
  std::sort(m_addresses, m_addresses + m_asize, [](const one_addr &l, const one_addr &r) -> bool { return l.addr < r.addr; });
}

int ksym_holder::read_ksyms(const char *name)
{
  std::ifstream f;
  f.open(name);
  if ( !f.is_open() )
    return errno;
  std::string line;
  while( std::getline(f, line) )
  {
     one_sym tmp;
     const char *s = line.c_str();
     char *next;
#ifdef _MSC_VER
     tmp.addr = _strtoui64(s, &next, 16);
#else
     tmp.addr = strtoul(s, &next, 16);
#endif /* _MSC_VER */
     next++;
     tmp.letter = *next;
     next += 2;
     tmp.name = next;
     m_syms.push_back(tmp);
     auto was = m_names.find(next);
     if ( was != m_names.end() )
       continue;
     auto &back = m_syms.back();
     m_names[back.name.c_str()] = &back;
  }
  if ( m_syms.empty() )
    return 0;
  make_addresses();
  return 0;
}

#ifdef HAS_ELFIO

using namespace ELFIO;

int ksym_holder::read_syms(const elfio& reader, symbol_section_accessor &symbols)
{
  Elf_Xword sym_no = symbols.get_symbols_num();
  if ( !sym_no )
    return 1;
  for ( Elf_Xword i = 0; i < sym_no; ++i ) 
  {
    std::string   name;
    Elf64_Addr    value   = 0;
    Elf_Xword     size    = 0;
    unsigned char bind    = 0;
    unsigned char type    = 0;
    Elf_Half      section_idx = 0;
    unsigned char other   = 0;
    symbols.get_symbol( i, name, value, size, bind, type, section_idx, other );
    one_sym tmp;
    // skip all empty names
    if (name.empty())
      continue;
    // skip all symbols started with $
    if (name.at(0) == '$')
      continue;
    tmp.addr = value;
    tmp.name = name;
    // letter - see https://sourceware.org/binutils/docs/binutils/nm.html
    section* sec = reader.sections[section_idx];
    if (NULL == sec)
      continue;
    if (type == STT_FILE || type == STT_SECTION )
      continue;
    if (name.empty())
      continue;
    // check if symbol in .bss
    if ( sec->get_type() & SHT_NOBITS )
    {
      if ( bind == STB_GLOBAL )
        tmp.letter = 'B';
      else
        tmp.letter = 'b';
    } else {
      auto sflags = sec->get_flags();
      // symbol in executable section?
      if ( sflags & SHF_EXECINSTR )
      {
        if ( bind == STB_GLOBAL )
          tmp.letter = 'T';
        else
          tmp.letter = 't';
        // symbol in writable section?
      } else if ( sflags & SHF_WRITE )
      {
        if ( bind == STB_GLOBAL )
          tmp.letter = 'D';
        else
          tmp.letter = 'd';
      } else {
        if ( bind == STB_GLOBAL )
          tmp.letter = 'R';
        else
          tmp.letter = 'r';
      }
    }
    m_syms.push_back(tmp);
    auto was = m_names.find(name.c_str());
    if ( was != m_names.end() )
      continue;
    auto &back = m_syms.back();
    m_names[back.name.c_str()] = &back;
  }
  if ( m_syms.empty() )
    return 0;
  make_addresses();
  return 0;
}
#endif /* HAS_ELFIO */

static ksym_holder s_ksyms;

// plain C interface
int read_ksyms(const char *name)
{
  return s_ksyms.read_ksyms(name);
}

a64 get_addr(const char *name)
{
  return s_ksyms.get_addr(name);
}

const char *name_by_addr(a64 addr)
{
  return s_ksyms.name_by_addr(addr);
}

const char *lower_name_by_addr(a64 addr)
{
  return s_ksyms.lower_name_by_addr(addr);
}

#ifdef HAS_ELFIO
int read_syms(const ELFIO::elfio& reader, ELFIO::symbol_section_accessor &ssa)
{
  return s_ksyms.read_syms(reader, ssa);
}
#endif /* HAS_ELFIO */
