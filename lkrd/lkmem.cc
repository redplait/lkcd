#ifndef _MSC_VER
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

#include <iostream>
#include <elfio/elfio_dump.hpp>
#include "ksyms.h"
#include "getopt.h"
#include "x64_disasm.h"
#include "arm64relocs.h"
#ifndef _MSC_VER
#include "../shared.h"
#include "kmods.h"
#include "lk.h"
#endif

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
  printf("-c - check memory. Achtung - you must first load lkcd driver\n");
  printf("-d - use disasm\n");
  printf("-f - dump ftraces\n");
  printf("-r - check .rodata section\n");
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

size_t filter_arm64_relocs(const elfio& reader, a64 start, a64 end, a64 fstart, a64 fend, std::map<a64, a64> &filled)
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
         {
           filled[offset] = addend;
           res++;
         }
      }
    }
  }
  return res;
}

void dump_patched(a64 curr_addr, char *ptr, char *arg, sa64 delta)
{
   size_t off = 0;
   const char *name = lower_name_by_addr_with_off(curr_addr, &off);
   if ( name != NULL )
   {
     const char *pto = name_by_addr((a64)(arg - delta));
     if ( pto != NULL )
     {
        if ( off )
          printf("mem at %p (%s+%lX) patched to %p (%s)\n", ptr, name, off, arg, pto);
        else
          printf("mem at %p (%s) patched to %p (%s)\n", ptr, name, arg, pto);
      } else {
        if ( off )
          printf("mem at %p (%s+%lX) patched to %p\n", ptr, name, off, arg);
        else
          printf("mem at %p (%s) patched to %p\n", ptr, name, arg);
      }
  } else
     printf("mem at %p patched to %p\n", ptr, arg);
}

void dump_and_check(int fd, int opt_c, sa64 delta, int has_syms, std::map<a64, a64> &filled)
{
  for ( auto &c: filled )
  {
    auto curr_addr = c.first;
    auto addr = c.second;
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
#ifndef _MSC_VER
      if ( opt_c )
      {
         char *ptr = (char *)curr_addr + delta;
         char *arg = ptr;
         int err = ioctl(fd, IOCTL_READ_PTR, (int *)&arg);
         if ( err )
         {
           printf("read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
           continue;
         }
         char *real = (char *)addr + delta;
         if ( real != arg )
         {
           if ( is_inside_kernel((unsigned long)arg) )
           {
              if ( !has_syms )
                printf("mem at %p: %p (must be %p)\n", ptr, arg, real);
              else 
              {
                size_t off = 0;
                const char *name = lower_name_by_addr_with_off(curr_addr, &off);
                if ( name != NULL )
                {
                  const char *pto = name_by_addr((a64)(arg - delta));
                  if ( pto != NULL )
                  {
                     if ( off )
                       printf("mem at %p (%s+%lX) patched to %p (%s)\n", ptr, name, off, arg, pto);
                     else
                       printf("mem at %p (%s) patched to %p (%s)\n", ptr, name, arg, pto);
                   } else {
                     if ( off )
                       printf("mem at %p (%s+%lX) patched to %p\n", ptr, name, off, arg);
                     else
                       printf("mem at %p (%s) patched to %p\n", ptr, name, arg);
                   }
                } else
                   printf("mem at %p: %p (must be %p)\n", ptr, arg, real);
              }
           } else 
           { // address not in kernel
              const char *mname = find_kmod((unsigned long)arg);
              if ( mname )
                printf("mem at %p: %p (must be %p) - patched by %s\n", ptr, arg, real, mname);
              else
                printf("mem at %p: %p (must be %p) - patched by UNKNOWN\n", ptr, arg, real);
            }
         }
      } /* opt_c */
#endif /* !_MSC_VER */
  }
}

int is_nop(unsigned char *body)
{
  // nop dword ptr [rax+rax+00h] - 0F 1F 44 00 00
  if ( body[0] == 0xF  &&
       body[1] == 0x1F &&
       body[2] == 0x44 &&
       body[3] == 0    &&
       body[4] == 0
     )
   return 1;
  // just 90
  if ( body[0] == 0x90 &&
       body[1] == 0x90 &&
       body[2] == 0x90 &&
       body[3] == 0x90 &&
       body[4] == 0x90
     )
   return 1;
  return 0;
}

int main(int argc, char **argv)
{
   // read options
   int opt_f = 0,
       opt_d = 0,
       opt_c = 0,
       opt_r = 0,
       opt_b = 0;
   int c;
   int fd = 0;
   while (1)
   {
     c = getopt(argc, argv, "bcdfrv");
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
        case 'c':
          opt_c = 1;
         break;
        case 'r':
          opt_r = 1;
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
   sa64 delta = 0;
#ifndef _MSC_VER
   // open driver
   if ( opt_c ) 
   {
     fd = open("/dev/lkcd", 0);
     if ( -1 == fd )
     {
       printf("cannot open device, error %d\n", errno);
       opt_c = 0;
       goto end;
     }
     // find delta between symbols from system.map and loaded kernel
     auto symbol_a = get_addr("group_balance_cpu");
     if ( !symbol_a )
     {
       close(fd);
       fd = 0;
       opt_c = 0;
       goto end;
     } else {
       if ( read_kernel_area(fd) )
       {
         close(fd);
         fd = 0;
         opt_c = 0;
         goto end;
       }
       int err = init_kmods();
       if ( err )
       {
         printf("init_kmods failed, error %d\n", err);
         goto end;
       }
       printf("group_balance_cpu from symbols: %p\n", (void *)symbol_a);
       union ksym_params kparm;
       strcpy(kparm.name, "group_balance_cpu");
       err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
       if ( err )
       {
         printf("IOCTL_RKSYM test failed, error %d\n", err);
         close(fd);
         fd = 0;
         opt_c = 0;
       } else {
         printf("group_balance_cpu: %p\n", (void *)kparm.addr);
         delta = (char *)kparm.addr - (char *)symbol_a;
         printf("delta: %lX\n", delta);
       }
     }
   }
end:
#endif /* _MSC_VER */
   // find .text section
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
   if ( has_syms )
   {
     // make some tests
     auto a1 = get_addr("__start_mcount_loc");
     printf("__start_mcount_loc: %p\n", (void *)a1);
     auto a2 = get_addr("__stop_mcount_loc");
     printf("__stop_mcount_loc: %p\n", (void *)a2);
     // if we had -f option
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
#ifndef _MSC_VER
             if ( opt_c )
             {
               // filter out maybe discarded sections like .init.text
               if ( text_section != NULL &&
                    ( (addr < text_start) || (addr > (text_start + text_size)) )
                  )
                 continue;
               char *ptr = (char *)addr + delta;
               char *arg = ptr;
               int err = ioctl(fd, IOCTL_READ_PTR, (int *)&arg);
               if ( err )
                 printf("read ftrace at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
               else if ( !is_nop((unsigned char *)&arg) )
                 HexDump((unsigned char *)&arg, sizeof(arg));
             }
#endif /* !_MSC_VER */
           }
         }
       }
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
     if ( opt_r && sec->get_name() == ".rodata" )
     {
       std::map<a64, a64> filled;
       auto off = sec->get_offset();
       printf(".rodata section offset %lX\n", off);
       size_t count = 0;
       a64 curr_addr;
       // under arm64 we need count relocs in .data section       
       if ( reader.get_machine() == 183 )
       {
         a64 dstart = (a64)sec->get_address();
         count = filter_arm64_relocs(reader, dstart, dstart + sec->get_size(), (a64)text_start, (a64)(text_start + text_size), filled);
       } else {
         a64 *curr = (a64 *)sec->get_data();
         a64 *end  = (a64 *)((char *)curr + sec->get_size());
         curr_addr = sec->get_address();
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
           }
         }
       }
       printf("found in .rodata %ld\n", count);
       // dump or check collected addresses
       if ( g_opt_v || opt_c )
         dump_and_check(fd, opt_c, delta, has_syms, filled);
       continue;
     }
     if ( sec->get_name() == ".data" )
     {
       std::map<a64, a64> filled;
       auto off = sec->get_offset();
       printf(".data section offset %lX\n", off);
       size_t count = 0;
       a64 curr_addr;
       // under arm64 we need count relocs in .data section       
       if ( reader.get_machine() == 183 )
       {
         a64 dstart = (a64)sec->get_address();
         count = filter_arm64_relocs(reader, dstart, dstart + sec->get_size(), (a64)text_start, (a64)(text_start + text_size), filled);
       } else {
         a64 *curr = (a64 *)sec->get_data();
         a64 *end  = (a64 *)((char *)curr + sec->get_size());
         curr_addr = sec->get_address();
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
           }
         }
       }
       printf("found %ld\n", count);
       // dump or check collected addresses
       if ( g_opt_v || opt_c )
         dump_and_check(fd, opt_c, delta, has_syms, filled);
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
#ifndef _MSC_VER
          if ( opt_c )
          {
            for ( auto c: out_res )
            {
              char *ptr = (char *)c + delta;
              char *arg = ptr;
              int err = ioctl(fd, IOCTL_READ_PTR, (int *)&arg);
              if ( err )
                printf("read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
              else if ( arg != NULL )
              {
                 if ( is_inside_kernel((unsigned long)arg) )
                 {
                    if ( !has_syms )
                      printf("mem at %p: %p\n", ptr, arg);
                    else
                      dump_patched(c, ptr, arg, delta);
                 } else {
                    const char *mname = find_kmod((unsigned long)arg);
                    if ( mname )
                      printf("mem at %p: %p - patched by %s\n", ptr, arg, mname);
                    else
                      printf("mem at %p: %p - patched by UNKNOWN\n", ptr, arg);
                 }
              }
            }
          } // opt_c
#endif /* !_MSC_VER */
       } // opt_d
       break;
     }
   }
#ifndef _MSC_VER
   if ( fd )
     close(fd);
#endif /* _MSC_VER */
}
