#include "eread.h"

using namespace ELFIO;

section *find_sec(elfio *rdr, Elf_Xword addr)
{
  Elf_Half n = rdr->sections.size();
  for ( Elf_Half i = 0; i < n; ++i )
  {
    section *s = rdr->sections[i];
    if ( s->get_address() == addr )
      return s;
  }
  return nullptr;
}

int elf_dread::process()
{
  Elf_Xword symtab = 0, jmptab = 0, rela = 0;
  // find section for dynamic
  Elf_Half n = m_rdr->sections.size();
  for ( Elf_Half i = 0; i < n; ++i )
  {
    section *s = m_rdr->sections[i];
    if ( SHT_DYNAMIC != s->get_type() ) continue;
    // process it filling symtab & jmptab
    dynamic_section_accessor dyn(*m_rdr, s);
    Elf_Xword dn = dyn.get_entries_num();
    for ( Elf_Xword j = 0; j < dn; ++j )
    {
      Elf_Xword tag = 0, value = 0;
      std::string str;
      dyn.get_entry(j, tag, value, str);
      if ( DT_NULL == tag ) break;
      if ( DT_JMPREL == tag ) jmptab = value;
      else if ( DT_SYMTAB == tag ) symtab = value;
      else if ( DT_RELA == tag ) rela = value;
    }
    break;
  }
  if ( !symtab )
  {
    printf("cannot find dynamic symtab\n"); return -1;
  }
  auto syms = find_sec(m_rdr, symtab);
  if ( !syms )
  {
    printf("cannot find section for dynamic symtab\n"); return -1;
  }
  if ( !jmptab )
  {
    printf("cannot find jmptab\n"); return -1;
  }
  // read dynamic symtab
  symbol_section_accessor ds( *m_rdr, syms );
  Elf_Xword sym_no = ds.get_symbols_num();
  for ( Elf_Xword i = 0; i < sym_no; ++i )
  {
    std::string name;
    Elf64_Addr value = 0;
    Elf_Xword size = 0;
    unsigned char bind = 0, type = 0, other = 0;
    Elf_Half section = 0;
    ds.get_symbol(i, name, value, size, bind, type, section, other);
    if ( name.empty() ) continue;
    if ( !strcmp(name.c_str(), "mcount") ) s_mcount = i;
    else if ( !strcmp(name.c_str(), "__cyg_profile_func_enter") ) s_cyg_profile_func_enter = i;
    else if ( !strcmp(name.c_str(), "__cyg_profile_func_exit") ) s_cyg_profile_func_exit = i;
 #ifdef DEBUG
    printf("%d %s value %lX\n", i, name.c_str(), value);
 #endif   
  }
  // this is non-profileable elf compiled without -pg or -finstrument-functions options 
  if ( !s_mcount && !s_cyg_profile_func_enter && !s_cyg_profile_func_exit )
    return 0;
  // parse jmptab
  auto js = find_sec(m_rdr, jmptab);
  if ( !js )
  {
    printf("cannot find section for jmptab\n"); return -1;
  }
  relocation_section_accessor rs( *m_rdr, js );
  sym_no = rs.get_entries_num();
  for ( Elf_Xword i = 0; i < sym_no; ++i )
  {
    Elf64_Addr addr = 0;
    Elf_Word sym_idx = 0;
    unsigned type = 0;
    Elf_Sxword add = 0;
    rs.get_entry(i, addr, sym_idx, type, add);
    if ( !sym_idx || (type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) ) continue;
    if ( sym_idx == s_mcount ) m_mcount = addr;
    else if ( sym_idx == s_cyg_profile_func_enter ) m_func_enter = addr;
  }
  // mcount can be stored in rela with R_X86_64_GLOB_DAT reloc
  if ( s_mcount && rela )
  {
   auto ra = find_sec(m_rdr, rela);
   if ( !ra )
   {
     printf("cannot find section for rela\n");
   } else {
     relocation_section_accessor rs( *m_rdr, ra );
     sym_no = rs.get_entries_num();
     for ( Elf_Xword i = 0; i < sym_no; ++i )
     {
       Elf64_Addr addr = 0;
       Elf_Word sym_idx = 0;
       unsigned type = 0;
       Elf_Sxword add = 0;
       rs.get_entry(i, addr, sym_idx, type, add);
       if ( !sym_idx || type != R_X86_64_GLOB_DAT ) continue;
       if ( sym_idx == s_mcount ) m_mcount = addr;
     }
   } 
  }
  return 1;
}