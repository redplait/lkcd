#include <set>
#include <stdlib.h>
#include "jmem.h"

std::set<void *> s_stg;

void jmem_store(void *addr)
{
  s_stg.insert(addr);
}

void jmem_remove(void *addr)
{
  auto a = s_stg.find(addr);
  if ( a == s_stg.end() )
    return;
  s_stg.erase(addr);
}

void jmem_clear()
{
  for ( auto addr: s_stg )
    free(addr);
  s_stg.clear();
}