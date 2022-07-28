#pragma once
#include <map>
#include <set>
#include <vector>
#include "../types.h"
#undef min
#include <elfio/elfio_dump.hpp>

class dis_base
{
  public:
    dis_base(ELFIO::elfio* reader)
     : m_reader(reader)
    {
    }
    virtual ~dis_base() = default;
    inline ELFIO::elfio *get_elfio() const
    {
      return m_reader;
    }
    int read_syms();
  protected:
    inline ELFIO::section *in_section(const char *psp)
    {
      ELFIO::Elf_Half n = m_reader->sections.size();
      if ( !n )
        return 0;
      for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
        ELFIO::section* sec = m_reader->sections[i];
        if ( sec->get_type() == SHT_PROGBITS )
        {
          const char *curr = (const char *)sec->get_data();
          const char *end  = (const char *)((char *)curr + sec->get_size());
          if ( psp >= curr && psp < end )
            return sec;
        }
      }
      return 0;
    }
    inline ELFIO::section *in_section(ptrdiff_t psp)
    {
      ELFIO::Elf_Half n = m_reader->sections.size();
      if ( !n )
        return 0;
      for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
        ELFIO::section* sec = m_reader->sections[i];
        if ( sec->get_type() == SHT_PROGBITS )
        {
          auto start = sec->get_address();
          auto end  = start + sec->get_size();
          if ( psp >= start && psp < end )
            return sec;
        }
      }
      return 0;
    }
    inline ELFIO::section *in_xsection(const char *psp)
    {
      ELFIO::Elf_Half n = m_reader->sections.size();
      if ( !n )
        return 0;
      for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
        ELFIO::section* sec = m_reader->sections[i];
        if ( (sec->get_type() == SHT_PROGBITS) && (sec->get_flags() & SHF_EXECINSTR) )
        {
          const char *curr = (const char *)sec->get_data();
          const char *end  = (const char *)((char *)curr + sec->get_size());
          if ( psp >= curr && psp < end )
            return sec;
        }
      }
      return 0;
    }
    inline ELFIO::section *in_xsection(ptrdiff_t psp)
    {
      ELFIO::Elf_Half n = m_reader->sections.size();
      if ( !n )
        return 0;
      for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
        ELFIO::section* sec = m_reader->sections[i];
        if ( (sec->get_type() == SHT_PROGBITS) && (sec->get_flags() & SHF_EXECINSTR) )
        {
          auto start = sec->get_address();
          auto end  = start + sec->get_size();
          if ( psp >= start && psp < end )
            return sec;
        }
      }
      return 0;
    }
    template <typename F>
    int for_each_section(F func)
    {
      ELFIO::Elf_Half n = m_reader->sections.size();
      if ( !n )
        return 0;
      for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
        ELFIO::section* sec = m_reader->sections[i];
        if ( sec->get_type() == SHT_PROGBITS )
        {
          int res = func(sec);
          if ( res )
            return res;
        }
      }
      return 0;
    }
    template <typename F>
    int for_each_xsection(F func)
    {
      ELFIO::Elf_Half n = m_reader->sections.size();
      if ( !n )
        return 0;
      for (ELFIO::Elf_Half i = 0; i < n; ++i ) { // For all sections
        ELFIO::section* sec = m_reader->sections[i];
        if ( (sec->get_type() == SHT_PROGBITS) && (sec->get_flags() & SHF_EXECINSTR) )
        {
          int res = func(sec);
          if ( res )
            return res;
        }
      }
      return 0;
    }
    ptrdiff_t find_cstr(const char *);
    // data
    std::map<std::string, ptrdiff_t> m_syms;
    ELFIO::elfio *m_reader;
};