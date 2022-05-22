#include <elfio/elfio.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <fixup.hpp>
#include <name.hpp>
#include <offset.hpp>

struct loong_relocs
{
  // This function is called when the user invokes the plugin.
  bool idaapi run(size_t);
 protected:
  int read_symbols();
  void apply_relocs();
  int fill_fd(fixup_data_t &fd, ea_t offset, int symbol, bool force = false);
  void make_off(ea_t offset, ea_t target);
  void rename_j(ea_t offset);

  ELFIO::elfio reader;
  std::map<int, ea_t> m_symbols;
  std::map<int, std::string> m_external;
  std::string imp;
};

// ripped from binutils-gdb/include/elf/loongarch.h 
#define R_LARCH_32		1
#define R_LARCH_64 		2
#define R_LARCH_RELATIVE 	3
#define R_LARCH_COPY		4
#define R_LARCH_JUMP_SLOT	5
#define R_LARCH_TLS_DTPMOD32	6
#define R_LARCH_TLS_DTPMOD64	7
#define R_LARCH_TLS_DTPREL32	8
#define R_LARCH_TLS_DTPREL64	9
#define R_LARCH_TLS_TPREL32	10
#define R_LARCH_TLS_TPREL64	11

using namespace ELFIO;

void loong_relocs::rename_j(ea_t offset)
{
 // first check that we have the only reffered function
 ea_t prev = BADADDR;
 for ( ea_t addr = get_first_dref_to(offset); addr != BADADDR; addr = get_next_dref_to(offset, addr) )
 {
#ifdef _DEBUG
   msg("dto %a %a\n", offset, addr);
#endif
   auto s = getseg(addr);
   if ( s == NULL )
     return;
   qstring sname;
   if ( -1 == get_segm_name(&sname, s, 0) )
     return;
   // ignore all xrefs from LOAD section
   if ( !strcmp(sname.c_str(), "LOAD") )
     continue;
   if ( prev != BADADDR )
     return;
   prev = addr;
 }
 if ( prev == BADADDR )
    return;
 auto f = get_func(prev);
 if ( f == NULL )
   return;
 qstring fname = "j_";
 fname += imp.c_str();
 set_name(f->start_ea, fname.c_str(), SN_AUTO | SN_NOCHECK | SN_PUBLIC);
}

int loong_relocs::fill_fd(fixup_data_t &fd, ea_t offset, int symbol, bool force)
{
  fd.set_type(FIXUP_OFF64);
  auto si = m_symbols.find(symbol);
  if ( si != m_symbols.end() )
     fd.off = si->second;
  else {
     auto ei = m_external.find(symbol);
     if ( ei == m_external.end() )
     {
       msg("unknown symbol %d\n", symbol);
       return 0;
     }
     fd.off = get_name_ea(BADADDR, ei->second.c_str());
     if ( fd.off == BADADDR )
     {
        msg("unknown symbol %d: %s\n", symbol, ei->second.c_str());
        return 0;
     }
     imp = ei->second;
  }
  auto val = get_qword(offset);
  if ( !val || force )
  {
    patch_qword(offset, fd.off);
    make_off(offset, fd.off);
  }
  return 1;
}

void loong_relocs::make_off(ea_t offset, ea_t target)
{
  op_offset(offset, 0, REF_OFF64, target);
  add_dref(offset, target, dr_O);
}

void loong_relocs::apply_relocs()
{
  int total_relocs = 0;
  int res = 0;
  int unknown = 0;
  int not_found = 0;
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if (sec->get_type() != SHT_RELA)
       continue;
     const_relocation_section_accessor rsa(reader, sec);
     Elf_Xword relno = rsa.get_entries_num();
     total_relocs += relno;
     for ( int i = 0; i < relno; i++ ) 
     {
       Elf64_Addr offset;
       Elf_Word   symbol;
       Elf_Word   type;
       Elf_Sxword addend;
       rsa.get_entry(i, offset, symbol, type, addend );
       fixup_data_t fd;
       switch(type)
       {
         case R_LARCH_64:
           // reloc to symbol or external
           if ( !fill_fd(fd, offset, symbol) )
           {
             not_found++;
             break;
           }
           set_fixup(offset, fd);
           res++;
          break;
         case R_LARCH_RELATIVE:
           // check if such fixup already exists
           if ( exists_fixup(offset) )
             continue;
           fd.set_type(FIXUP_OFF64);
           fd.off = get_qword(offset);
           set_fixup(offset, fd);
           make_off(offset, fd.off);
           res++;
          break;
         case R_LARCH_JUMP_SLOT:
           if ( symbol )
           {
             if ( !fill_fd(fd, offset, symbol, true) )
             {
               not_found++;
               break;
             }
             set_fixup(offset, fd);
             // rename only reffered function with "j_" prefix
             if ( !imp.empty() )
               rename_j(offset);
             imp.clear();
             res++;
           }
          break;
         default:
          unknown++;
          msg("unknown reltype %d at %a\n", type, offset);
       }   
     }
  }
  msg("total_relocs %d, processed %d, unknown relocs %d, not found symbols %d\n", total_relocs, res, unknown, not_found);
}

int loong_relocs::read_symbols()
{
  int res = 0;
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
    section* sec = reader.sections[i];
    if ( SHT_SYMTAB != sec->get_type() &&
         SHT_DYNSYM != sec->get_type() )
      continue;
    symbol_section_accessor symbols( reader, sec );
    Elf_Xword sym_no = symbols.get_symbols_num();
    if ( !sym_no )
      continue;
    res += sym_no;
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
      if ( value )
        m_symbols[i] = value;
      else if ( !name.empty() )
        m_external[i] = name;
    }
  }
  return res;
}

bool idaapi loong_relocs::run(size_t unused)
{
  // 1) get input file-name
  char buf[1024];
  if ( !get_input_file_path(buf, _countof(buf)) )
  {
    msg("get_input_file_path failed\n");
    return false;
  }
  // 2) read elf
  if ( !reader.load(buf) )
  {
    msg("File %s is not found or it is not an ELF file\n", buf);
    return false;
  }
  // 3) read symbols
  if ( !read_symbols() )
  {
    msg("cannot read symbols from %s\n", buf);
    return false;
  }
  // 4) apply relocs
  apply_relocs();
  return true;
}

bool idaapi loong_relocs_run(size_t unused)
{
  loong_relocs rel;
  return rel.run(unused);
}

static plugmod_t *idaapi loong_init()
{
  if ( inf_get_filetype() != f_ELF )
    return PLUGIN_SKIP;
  processor_t &ph = PH;
msg("loongrel: %X\n", ph.id);
  if ( ph.id != 0x8001 ) // see loongson/reg.cpp
    return PLUGIN_SKIP;
  return PLUGIN_OK;
}

static const char comment[] = "loongson elf relocs plugin";
static const char help[] =
  "loongson ELF relocs plugin\n"
  "\n"
  "bcs you can't just go ahead and implement your own proc_def_t.\n";
static const char desired_name[] = "loongson elf relocs plugin";
static const char desired_hotkey[] = "";

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_UNL, // plugin flags
  loong_init,              // initialize
  nullptr,
  loong_relocs_run,
  comment,              // long comment about the plugin. not used.
  help,                 // multiline help about the plugin. not used.
  desired_name,         // the preferred short name of the plugin
  desired_hotkey        // the preferred hotkey to run the plugin
};
