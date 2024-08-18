#include <stdio.h>
#include <list>
#include <getopt.h>
#include <elfio/elfio_dump.hpp>
#include "ksyms.h"
#include "x64_disasm.h"
#include "arm64_disasm.h"
#include "arm64relocs.h"
#include "mips_disasm.h"
#include "thunks.inc"

using namespace ELFIO;

int g_opt_d = 0;

void usage(const char *prog)
{
  printf("%s usage: [options] elf-file [symbols]\n", prog);
  printf("Options:\n");
  printf("-d - show disasm\n");
  printf("-l - LSM hooks\n");
  exit(6);
}

void rcf(const char *name)
{
  fprintf(stderr, "cannot find %s\n", name);
}

int main(int argc, char **argv)
{
  if ( argc < 2 ) usage(argv[0]);
  int opt_l = 0;
  // process options
  while (1)
  {
    auto c = getopt(argc, argv, "dl");
     if (c == -1)
      break;
    if ( c == 'd' ) g_opt_d = 1;
    else if ( c == 'l' ) opt_l = 1;
    else usage(argv[0]);
  }
  if (optind == argc)
     usage(argv[0]);
  Elf64_Addr text_start = 0;
  Elf_Xword text_size = 0;
  section *text_section = NULL, *data_section = NULL, *bss_section = NULL;
  elfio reader;
  if ( !reader.load( argv[optind] ) )
  {
     fprintf(stderr,  "File %s is not found or it is not an ELF file\n", argv[optind] );
     return 1;
  }
  int has_syms = 0;
  // iterate on sections
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( SHT_SYMTAB == sec->get_type() ||
          SHT_DYNSYM == sec->get_type() )
     {
       symbol_section_accessor symbols( reader, sec );
       if ( !read_syms(reader, symbols) )
         has_syms++;
       continue;
     }
     if ( sec->get_name() == ".text" )
     {
       text_start = sec->get_address();
       text_size  = sec->get_size();
       text_section = sec;
       continue;
     }
     if ( sec->get_name() == ".data" )
     {
       data_section = sec;
       continue;
     }
     if ( (sec->get_type() & SHT_NOBITS) && 
          (sec->get_name() == ".bss" )
        )
     {
       bss_section = sec;
       continue;
     }
  }
  // check that we have all sections
  if ( !text_section ) {
    fprintf(stderr, "cannot find text section in %s\n", argv[optind]);
    return 1;
  }
  if ( !data_section ) {
    fprintf(stderr, "cannot find data section in %s\n", argv[optind]);
    return 1;
  }
  if ( !has_syms )
  {
    if ( optind + 1 == argc ) {
     fprintf(stderr, "symbols need for %s\n", argv[optind]);
     return 2;
    }
    int err = read_ksyms(argv[optind + 1]);
    if ( err )
    {
      fprintf(stderr, "cannot read symbols from %s, error %d\n", argv[optind + 1], err);
      return err;
    }
  }
  // check machine type
  dis_base *bd = NULL;
  auto m = reader.get_machine();
  if ( m == 183 )
  {
    arm64_disasm *ad = new arm64_disasm(text_start, text_size, text_section->get_data(), 
      data_section->get_address(), data_section->get_size());
    a64 addr = get_addr("__stack_chk_fail");
    // aarch64 specific init
    if ( addr )
      ad->add_noreturn(addr);
    else
      rcf("__stack_chk_fail");
    bd = ad;
  } else if ( m == EM_X86_64 )
  {
    x64_disasm *x64 = new x64_disasm(text_start, text_size, text_section->get_data(),
       data_section->get_address(), data_section->get_size());
    // x86_64 specific init
    for ( auto &c: s_x64_thunks )
    {
       a64 thunk_addr = get_addr(c.name);
       if ( !thunk_addr )
         printf("cannot find %s\n", c.name);
       else
         x64->set_indirect_thunk(thunk_addr, c.reg);
    }
   bd = x64;
  } else if ( m == EM_MIPS )
  {
    mips_disasm *md = new mips_disasm(reader.get_encoding() == ELFDATA2MSB,
       reader.get_class() == ELFCLASS32 ? 32 : 64,
       text_start, text_size, text_section->get_data(),
       data_section->get_address(), data_section->get_size());
    a64 addr = get_addr("__stack_chk_fail");
    // mips specific init
    if ( addr )
      md->add_noreturn(addr);
    else
      rcf("__stack_chk_fail");
    bd = md;
  } else {
   printf("dont know how process machine %d, endianess %d\n", m, reader.get_encoding());
   return 1;
  }
  if ( bss_section )
    bd->set_bss(bss_section->get_address(), bss_section->get_size());
  // bpf_target
  auto entry = get_addr("bpf_iter_reg_target");
  auto mlock = get_addr("mutex_lock");
  if ( !entry )
    rcf("bpf_iter_reg_target");
  else if ( !mlock )
    rcf("mutex_lock");
  else {
    auto bpf_target = bd->process_bpf_target(entry, mlock);
    if ( bpf_target )
     printf("bpf_target %p\n", bpf_target);
  }
  // kfunc_set_tab offset
  auto kf = get_addr("btf_free_kfunc_set_tab");
  if ( !kf )
    rcf("btf_free_kfunc_set_tab");
  else {
   int off = bd->find_kfunc_set_tab_off(kf);
   if ( off )
     printf("kfunc_set_tab offset %d\n", off);
  }
  // find trace_event_call.filter offset
  entry = get_addr("trace_remove_event_call");
  auto free_evt = get_addr("free_event_filter");
  if ( !entry )
    rcf("trace_remove_event_call");
  else if ( !free_evt )
    rcf("free_event_filter");
  else {
    int event_foff = bd->process_trace_remove_event_call(entry, free_evt);
    if ( event_foff )
      printf("trace_event_call.filter offset %d\n", event_foff);
  }
  // lsm
  auto list_head = get_addr("security_hook_heads");
  if ( !list_head )
    rcf("security_hook_heads");
  else {
    bd->set_shook(list_head);
    auto test = get_addr("security_bpf_map_free");
    if ( test )
    {
      std::vector<lsm_hook> v(1);
      v[0].addr = test;
      int res = bd->process_sl(v);
      if ( res )
        printf("security_bpf_map_free list: %p\n", v[0].list);
    }
  }
  // cleanup
  if ( bd != NULL )
    delete bd;
}