#include <stdio.h>
#include <list>
#include <fstream>
#include <cstring>
#include "kmods.h"

struct one_mod
{
  std::string name;
  unsigned long start;
  unsigned long len;
};

class mods_storage
{
  public:
    int read_mods();
    const char *find(unsigned long addr);
  protected:
    std::list<one_mod> m_list;
};

static mods_storage s_mod_stg;

const char *mods_storage::find(unsigned long addr)
{
  for ( auto &c: m_list )
  {
    if ( (addr >= c.start) &&
         (addr < (c.start + c.len) )
       )
     return c.name.c_str();
  }
  return NULL;
}

int mods_storage::read_mods()
{
  std::ifstream f;
  f.open("/proc/modules");
  if ( !f.is_open() )
    return errno;
  std::string s;
  while( std::getline(f, s) )
  {
    // find first space
    const char *w = s.c_str();
    while ( *w && !isspace(*w) )
      w++;
    std::string cn(s.c_str(), w);
    one_mod tmp;
    tmp.name = cn;
    tmp.len = atoi(w + 1);
    // now find "Live 0x"
    const char *rest = strstr(w + 1, "Live 0x");
    if ( rest == NULL )
      continue;
    char *end;
    tmp.start = strtoul(rest + 7, &end, 0x10);
    if ( !tmp.start )
     continue;
    m_list.push_back(tmp);
  }
  return 0;
}

const char *find_kmod(unsigned long addr)
{
  return s_mod_stg.find(addr);
}

int init_kmods()
{
  return s_mod_stg.read_mods();
}