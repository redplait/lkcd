#include "dis_base.h"
#include "bm_search.h"

using namespace ELFIO;

ptrdiff_t dis_base::find_cstr(const char *s)
{
   Elf_Half n = m_reader->sections.size();
   if ( !n )
     return 0;
   for (Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = m_reader->sections[i];
     if ( sec->get_type() == SHT_PROGBITS )
     {
        bm_search bm((unsigned char *)s, strlen(s) + 1);
        unsigned char *curr = (unsigned char*)sec->get_data();
        auto res = bm.search(curr, sec->get_size());
        if ( NULL == res )
          continue;
        return res - curr + sec->get_address();
     }
   }
   return 0;
}

int dis_base::read_syms()
{
  if ( m_reader == NULL )
    return 0;
  Elf_Half n = m_reader->sections.size();
  if ( !n )
    return 0;
  int res = 0;
  for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = m_reader->sections[i];
     if ( SHT_SYMTAB == sec->get_type() ||
          SHT_DYNSYM == sec->get_type() ) 
     {
       symbol_section_accessor symbols( *m_reader, sec );
       Elf_Xword sym_no = symbols.get_symbols_num();
       if ( !sym_no )
         continue;
       res++;
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
          // add only symbols with address
          if ( value )
            m_syms[name] = value;
       }
     }
  }
  return res;
}
