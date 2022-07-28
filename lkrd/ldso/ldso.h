#pragma once
#include "x64_disasm.h"

class ldso: public x64_disasm
{
  public:
    ldso(ELFIO::elfio* reader)
     : x64_disasm(reader)
    {
      library_path = NULL;
      rtld_search_dirs = NULL;
    }
    int process();
    void dump() const;
  protected:
    int find_lpath(ptrdiff_t off);
    ptrdiff_t next_call(ptrdiff_t off);
    int find_rtld_search_dirs(ptrdiff_t off);

    ptrdiff_t library_path;
    ptrdiff_t rtld_search_dirs;
};