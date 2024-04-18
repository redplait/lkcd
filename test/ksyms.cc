#include <stdio.h>
#include <fstream>
#include <string>
#include <list>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <cstring>
#include <regex>
#include <sys/utsname.h>
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
    int read_kallsyms(const char *name);
#ifdef HAS_ELFIO
    int read_syms(const ELFIO::elfio& reader, ELFIO::symbol_section_accessor &);
#endif /* HAS_ELFIO */
    const char *name_by_addr(a64);
    const char *lower_name_by_addr(a64);
    const char *lower_name_by_addr_with_off(a64, size_t *);
    a64 get_addr(const char *name)
    {
      auto c = m_names.find(name);
      if ( c != m_names.end() ) 
        return c->second->addr;
      return 0;
    }
    struct addr_sym *get_in_range(a64 start, a64 end, size_t *count);
    struct addr_sym *start_with(const char *prefix, a64 start, a64 end, size_t *count);
    size_t fill_bpf_protos(std::list<one_bpf_proto> &out_res);
  protected:
    std::list<one_sym> m_syms;
    std::map<const char *, one_sym *, namesComparer> m_names;
    size_t m_asize;
    one_addr *m_addresses;

    void make_addresses();
    void process_string(std::string &s);
};

size_t ksym_holder::fill_bpf_protos(std::list<one_bpf_proto> &out_res)
{
  size_t res = 0;
  std::regex bpf_regex("^bpf_.*_proto$");
  for ( const auto name: m_names )
  {
    if ( !std::regex_search(name.first, bpf_regex) )
      continue;
    // try to find function from proto
    size_t len = strlen(name.first);
    std::string fname(name.first, name.first + len - 6);
    auto fiter = m_names.find(fname.c_str());
    if ( fiter == m_names.end() )
      continue;
    one_bpf_proto tmp;
    tmp.proto.name = name.first;
    tmp.proto.addr = name.second->addr;
    tmp.func.name = fiter->first;
    tmp.func.addr = fiter->second->addr;
    out_res.push_back(tmp);
    res++;
  }
  return res;
}

const char *ksym_holder::name_by_addr(a64 addr)
{
  if ( NULL == m_addresses )
    return NULL;
  const one_addr *found = std::lower_bound(m_addresses, m_addresses + m_asize, addr, [](const one_addr &l, a64 off) -> 
      bool { return l.addr < off; }
  );
  if ( found == m_addresses + m_asize)
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
  if ( found == m_addresses + m_asize)
    return NULL;
  if ( found->addr == addr )
    found->sym->name.c_str();
  if ( found == m_addresses )
    return NULL;
  found--;
  return found->sym->name.c_str();
}

const char *ksym_holder::lower_name_by_addr_with_off(a64 addr, size_t *off)
{
  if ( NULL == m_addresses )
    return NULL;
  const one_addr *found = std::lower_bound(m_addresses, m_addresses + m_asize, addr, [](const one_addr &l, a64 off) -> 
      bool { return l.addr < off; }
  );
  if ( found == m_addresses + m_asize)
    return NULL;
  if ( found->addr == addr )
  {
    *off = 0;
    return found->sym->name.c_str();
  }
  if ( found == m_addresses )
    return NULL;
  found--;
  *off = addr - found->addr;
  return found->sym->name.c_str();
}

struct addr_sym *ksym_holder::get_in_range(a64 start, a64 end_a, size_t *count)
{
  *count = 0;
  if ( NULL == m_addresses )
    return NULL;
  auto end = m_addresses + m_asize;
  one_addr *found = std::lower_bound(m_addresses, end, start, [](const one_addr &l, a64 off) -> 
      bool { return l.addr < off; }
  );
  if ( found == end )
    return NULL;
  if ( found->addr < start )
    found++;
  // calc count
  for ( one_addr *curr = found; curr < end; curr++ )
   if ( curr->addr >= end_a )
   {
     end = curr;
     break;
   }
  *count = end - found;
  if ( !*count )
    return NULL;
  // alloc mem
  auto res = (addr_sym *)malloc(sizeof(addr_sym) * *count);
  if ( NULL == res )
    return res;
  std::transform(found, end, res, [](one_addr &c) -> addr_sym { return { c.sym->name.c_str(), c.addr}; });
  return res;
}

struct addr_sym *ksym_holder::start_with(const char *prefix, a64 start_addr, a64 end_addr, size_t *count)
{
  *count = 0;
  if ( NULL == m_addresses )
    return NULL;
  auto plen = strlen(prefix);
  auto from = m_addresses;
  auto end = m_addresses + m_asize;
  if ( start_addr )
  {
    from = std::lower_bound(m_addresses, end, start_addr, [](const one_addr &l, a64 off) -> 
      bool { return l.addr < off; }
    );
    if ( from == end )
      return NULL;
    if ( from->addr < start_addr )
      from++;
  }
  std::vector<const one_addr *> tmp;
  for ( ; from < end; from++ )
  {
    if ( end_addr && from->addr > end_addr )
      break;
    if ( strncmp(from->sym->name.c_str(), prefix, plen) )
      continue;
    tmp.push_back(from);
  }
  if ( tmp.empty() )
    return NULL;
  *count = tmp.size();
  auto res = (addr_sym *)malloc(sizeof(addr_sym) * *count);
  if ( NULL == res )
    return res;
  std::transform(tmp.begin(), tmp.end(), res, [](const one_addr *c) -> addr_sym { return { c->sym->name.c_str(), c->addr}; });
  return res;
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

void ksym_holder::process_string(std::string &line)
{
  const char *s = line.c_str();
  char *next;
  one_sym tmp;
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
  if ( was != m_names.end() ) return;
  auto &back = m_syms.back();
  m_names[back.name.c_str()] = &back;
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
     process_string(line);
  }
  if ( m_syms.empty() )
    return 0;
  make_addresses();
  return 0;
}

int ksym_holder::read_kallsyms(const char *name)
{
  std::ifstream f;
  f.open(name);
  if ( !f.is_open() )
    return errno;
  std::string line;
  while( std::getline(f, line) )
  {
    // unlike Symbols kallsyms can have [module_name] at end of string
    if ( line.back() == ']' )
    {
      line.pop_back();
      while( !line.empty() )
      {
        if ( line.back() == '[' )
        {
          line.pop_back();
          // strip spaces
          while( ' ' == line.back() ) line.pop_back();
          break;
        }
        line.pop_back();
      }
    }
    process_string(line);
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
int read_kallsyms(const char *name)
{
  return s_ksyms.read_kallsyms(name);
}

int read_ksyms(const char *name)
{
  return s_ksyms.read_ksyms(name);
}

int read_system_map()
{
  struct utsname luname;
  if ( uname(&luname) == -1 )
  {
    printf("cannot uname, error %d\n", errno);
    return errno;
  }
  std::string cname = "/boot/System.map-";
  cname += luname.release;
  return read_ksyms(cname.c_str());
}

size_t fill_bpf_protos(std::list<one_bpf_proto> &out_res)
{
  return s_ksyms.fill_bpf_protos(out_res);
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

const char *lower_name_by_addr_with_off(a64 addr, size_t *off)
{
  return s_ksyms.lower_name_by_addr_with_off(addr, off);
}

struct addr_sym *get_in_range(a64 start, a64 end, size_t *count)
{
  return s_ksyms.get_in_range(start, end, count);
}

struct addr_sym *start_with(const char *prefix, a64 start, a64 end, size_t *count)
{
  return s_ksyms.start_with(prefix, start, end, count);
}

#ifdef HAS_ELFIO
int read_syms(const ELFIO::elfio& reader, ELFIO::symbol_section_accessor &ssa)
{
  return s_ksyms.read_syms(reader, ssa);
}
#endif /* HAS_ELFIO */
