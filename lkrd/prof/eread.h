#pragma once
#include <elfio/elfio.hpp>

class elf_dread
{
  public:
   elf_dread(ELFIO::elfio *rdr): m_rdr(rdr)
   {}
   int process();
   ptrdiff_t get_mcount() const
   { return m_mcount; }
   ptrdiff_t get_func_enter() const
   { return m_func_enter; }
  protected:
   ELFIO::elfio *m_rdr;
   // offset in dynsym
   ptrdiff_t s_mcount = 0;
   ptrdiff_t s_cyg_profile_func_enter = 0;
   ptrdiff_t s_cyg_profile_func_exit = 0;
   // offset in GOT
   ptrdiff_t m_mcount = 0;
   ptrdiff_t m_func_enter = 0;
};