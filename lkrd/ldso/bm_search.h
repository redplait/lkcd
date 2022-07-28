#pragma once
#include "../types.h"
#include <stddef.h>

class bm_search
{
  public:
    bm_search(unsigned char *pattern, DWORD plen);
    bm_search();
   ~bm_search();
    int set(unsigned char *pattern, DWORD plen);
    const unsigned char *search(unsigned char *mem, size_t mlen);
  protected:
    int make(unsigned char *pattern, DWORD plen);
    LONG occ[0x100];
    unsigned char *m_pattern;
    DWORD m_plen;
    PDWORD m_skip;
};
