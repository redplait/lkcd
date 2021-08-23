#include <iostream>
#include <elfio/elfio_dump.hpp>
#include "ksyms.h"
#include "getopt.h"
#include "x64_disasm.h"
#include "arm64relocs.h"

int g_opt_v = 0;

using namespace ELFIO;

struct x64_thunk
{
  const char *name;
  ud_type reg;
};

void usage(const char *prog)
{
  printf("%s usage: [options] image [symbols]\n", prog);
  printf("Options:\n");
  printf("-b - check .bss section\n");
  printf("-d - use disasm\n");
  printf("-f - dump ftraces\n");
  printf("-v - verbose mode\n");
  exit(6);
}

static const x64_thunk s_x64_thunks[] = {
  { "__x86_indirect_thunk_rax", UD_R_RAX },
  { "__x86_indirect_thunk_rbx", UD_R_RBX },
  { "__x86_indirect_thunk_rcx", UD_R_RCX },
  { "__x86_indirect_thunk_rdx", UD_R_RDX },
  { "__x86_indirect_thunk_rsi", UD_R_RSI },
  { "__x86_indirect_thunk_rdi", UD_R_RDI },
  { "__x86_indirect_thunk_rbp", UD_R_RBP },
  { "__x86_indirect_thunk_r8",  UD_R_R8 },
  { "__x86_indirect_thunk_r9",  UD_R_R9 },
  { "__x86_indirect_thunk_r10", UD_R_R10 },
  { "__x86_indirect_thunk_r11", UD_R_R11 },
  { "__x86_indirect_thunk_r12", UD_R_R12 },
  { "__x86_indirect_thunk_r13", UD_R_R13 },
  { "__x86_indirect_thunk_r14", UD_R_R14 },
  { "__x86_indirect_thunk_r15", UD_R_R15 },
};

section* find_section(const elfio& reader, a64 addr)
{
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i ) 
  {
    section* sec = reader.sections[i];
    auto start = sec->get_address();
    if ( (addr >= start) &&
         addr < (start + sec->get_size())
       )
      return sec;
  }
  return NULL;
}

const char *find_addr(const elfio& reader, a64 addr)
{
  section *s = find_section(reader, addr);
  if ( NULL == s )
    return NULL;
  if ( s->get_type() & SHT_NOBITS )
    return NULL;
  return s->get_data() + (addr - s->get_address());
}

void dump_arm64_fraces(const elfio& reader, a64 start, a64 end)
{
  Elf_Half n = reader.sections.size();
  if ( !n )
    return;
  for ( Elf_Half i = 0; i < n; ++i ) 
  {
    section* sec = reader.sections[i];
    if ( sec->get_type() == SHT_RELA )
    {
      const_relocation_section_accessor rsa(reader, sec);
      Elf_Xword relno = rsa.get_entries_num();
      for ( int i = 0; i < relno; i++ )
      {
         Elf64_Addr offset;
         Elf_Word   symbol;
         Elf_Word   type;
         Elf_Sxword addend;
         rsa.get_entry(i, offset, symbol, type, addend);
         if ( offset < start || offset > end )
           continue;
         if ( type != R_AARCH64_RELATIVE )
           continue;
         const char *name = lower_name_by_addr(addend);
         if ( name != NULL )
           printf("%p # %s\n", (void *)addend, name);
         else
           printf("%p\n", (void *)addend);
      }
    }
  }
}

size_t filter_arm64_relocs(const elfio& reader, a64 start, a64 end, a64 fstart, a64 fend)
{
  size_t res = 0;
  Elf_Half n = reader.sections.size();
  if ( !n )
    return 0;
  for ( Elf_Half i = 0; i < n; ++i ) 
  {
    section* sec = reader.sections[i];
    if ( sec->get_type() == SHT_RELA )
    {
      const_relocation_section_accessor rsa(reader, sec);
      Elf_Xword relno = rsa.get_entries_num();
      for ( int i = 0; i < relno; i++ )
      {
         Elf64_Addr offset;
         Elf_Word   symbol;
         Elf_Word   type;
         Elf_Sxword addend;
         rsa.get_entry(i, offset, symbol, type, addend);
         if ( offset < start || offset > end )
           continue;
         if ( type != R_AARCH64_RELATIVE )
           continue;
         if ( addend >= fstart && addend < fend )
           res++;
      }
    }
  }
  return res;
}

int main(int argc, char **argv)
{
   // read options
   int opt_f = 0,
       opt_d = 0,
       opt_b = 0;
   int c;
   while (1)
   {
     c = getopt(argc, argv, "bfvd");
     if (c == -1)
	break;

     switch (c)
     {
        case 'b':
          opt_b = 1;
         break;
 	case 'f':
 	  opt_f = 1;
         break;
        case 'v':
          g_opt_v = 1;
         break;
        case 'd':
          opt_d = 1;
         break;
        default:
         usage(argv[0]);
     }
   }
   if (optind == argc)
     usage(argv[0]);

   elfio reader;
   int has_syms = 0;
   if ( !reader.load( argv[optind] ) ) 
   {
      printf( "File %s is not found or it is not an ELF file\n", argv[optind] );
      return 1;
   }
   optind++;
   Elf_Half n = reader.sections.size();
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( SHT_SYMTAB == sec->get_type() ||
          SHT_DYNSYM == sec->get_type() ) 
     {
       symbol_section_accessor symbols( reader, sec );
       if ( !read_syms(reader, symbols) )
         has_syms++;
     }
   }
   // try to find symbols
   if ( optind != argc )
   {
     int err = read_ksyms(argv[optind]);
     if ( err )
     {
       printf("cannot read %s, error %d\n", argv[optind], err);
       return err;
     }
     has_syms = 1;
   }
   if ( has_syms )
   {
     // make some tests

     auto a1 = get_addr("__start_mcount_loc");
     printf("__start_mcount_loc: %p\n", (void *)a1);
     auto a2 = get_addr("__stop_mcount_loc");
     printf("__stop_mcount_loc: %p\n", (void *)a2);
     if ( opt_f && a1 && a2 )
     {
       // under arm64 we need process relocs
       if ( reader.get_machine() == 183 )
         dump_arm64_fraces(reader, a1, a2);
       else {
         const a64 *data = (const a64 *)find_addr(reader, a1);
         if ( data != NULL )
         {
           for ( a64 i = a1; i < a2; i += sizeof(a64) )
           {
             a64 addr = *data;
             const char *name = lower_name_by_addr(addr);
             if ( name != NULL )
               printf("%p # %s\n", (void *)addr, name);
             else
               printf("%p\n", (void *)addr);
             data++;
           }
         }
       }
     }
   }
   // enum sections
   Elf64_Addr text_start = 0;
   Elf_Xword text_size = 0;
   section *text_section = NULL;
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( sec->get_name() == ".text" )
     {
       text_start = sec->get_address();
       text_size  = sec->get_size();
       text_section = sec;
       break;
     }
   }
   if ( !text_start )
   {
     printf("cannot find .text\n");
     return 1;
   }
   for ( Elf_Half i = 0; i < n; ++i ) 
   {
     section* sec = reader.sections[i];
     if ( sec->get_name() == ".data" )
     {
       std::map<a64, a64> filled;
       auto off = sec->get_offset();
       printf(".data section offset %lX\n", off);
       size_t count = 0;
       // under arm64 we need count relocs in .data section       
       if ( reader.get_machine() == 183 )
       {
         a64 dstart = (a64)sec->get_address();
         count = filter_arm64_relocs(reader, dstart, dstart + sec->get_size(), (a64)text_start, (a64)(text_start + text_size));
         printf("found %d\n", count);
       } else {
         a64 *curr = (a64 *)sec->get_data();
         a64 *end  = (a64 *)((char *)curr + sec->get_size());
         a64 curr_addr = sec->get_address();
         const endianess_convertor &conv = reader.get_convertor();
         for ( ; curr < end; curr++, curr_addr += sizeof(a64) )
         {
           auto addr = conv(*curr);
           if ( addr >= (a64)text_start &&
                addr < (a64)(text_start + text_size)
              )
           {
             count++;
             filled[curr_addr] = addr;
             if ( g_opt_v )
             {
               size_t off = 0;
               const char *name = lower_name_by_addr_with_off(curr_addr, &off);
               if ( name != NULL )
               {
                 const char *pto = name_by_addr(addr);
                 if ( pto != NULL )
                 {
                   if ( off )
                     printf("# %s+%lX -> %s\n", name, off, pto);
                   else
                     printf("# %s -> %s\n", name, pto);
                 } else {
                   if ( off )
                     printf("# %s+%lX\n", name, off);
                   else
                     printf("# %s\n", name);
                 }
               }
               printf("%p\n", (void *)curr_addr);
             }
           }
         }
         printf("found %ld\n", count);
         if ( opt_d )
         {
           x64_disasm dis(text_start, text_size, text_section->get_data(), sec->get_address(), sec->get_size());
           // find bss if we need
           if ( opt_b )
           {
             for ( Elf_Half j = 0; j < n; ++j )
             {
               section* s = reader.sections[j];
               if ( (s->get_type() & SHT_NOBITS) && 
                    (s->get_name() == ".bss" )
                  )
               {
                 a64 bss_addr = s->get_address();
                 if ( g_opt_v )
                   printf(".bss address %p size %lX\n", (void *)bss_addr, s->get_size());
                 dis.set_bss(bss_addr, s->get_size());
                 break;
               }
             }
           }
           // fill indirect thunks
           for ( auto &c: s_x64_thunks )
           {
             a64 thunk_addr = get_addr(c.name);
             if ( !thunk_addr )
               printf("cannot find %s\n", c.name);
             else
               dis.set_indirect_thunk(thunk_addr, c.reg);
           }
           std::set<a64> out_res;
           size_t tcount = 0;
           struct addr_sym *tsyms = get_in_range(text_start, text_start + text_size, &tcount);
           if (tsyms != NULL)
           {
             for (size_t i = 0; i < tcount; i++)
               dis.process(tsyms[i].addr, filled, out_res);
             free(tsyms);
           }
           else
           {
             // now disasm some funcs - security_load_policy
             a64 faddr = get_addr("rcu_sched_clock_irq");
             if (faddr)
             {
               dis.process(faddr, filled, out_res);
             }
           }
           printf("found with disasm: %ld\n", out_res.size());
           if ( g_opt_v )
           {
             for ( auto c: out_res )
             {
               size_t off = 0;
               const char *name = lower_name_by_addr_with_off(c, &off);
               if ( name != NULL )
               {
                 if ( off )
                   printf("# %s+%lX\n", name, off);
                 else
                   printf("# %s\n", name);
               }
               printf("%p\n", (void *)c);
             }
           }
         }
       }
       break;
     }
   }
}
