#include <iostream>
#include <elfio/elfio_dump.hpp>
#include "ksyms.h"
#include "getopt.h"

// ripped from https://github.com/unicorn-engine/unicorn/blob/master/qemu/include/elf.h
/* ARM Aarch64 relocation types */
#define R_AARCH64_NONE                256 /* also accepts R_ARM_NONE (0) */
/* static data relocations */
#define R_AARCH64_ABS64               257
#define R_AARCH64_ABS32               258
#define R_AARCH64_ABS16               259
#define R_AARCH64_PREL64              260
#define R_AARCH64_PREL32              261
#define R_AARCH64_PREL16              262
/* static aarch64 group relocations */
/* group relocs to create unsigned data value or address inline */
#define R_AARCH64_MOVW_UABS_G0        263
#define R_AARCH64_MOVW_UABS_G0_NC     264
#define R_AARCH64_MOVW_UABS_G1        265
#define R_AARCH64_MOVW_UABS_G1_NC     266
#define R_AARCH64_MOVW_UABS_G2        267
#define R_AARCH64_MOVW_UABS_G2_NC     268
#define R_AARCH64_MOVW_UABS_G3        269
/* group relocs to create signed data or offset value inline */
#define R_AARCH64_MOVW_SABS_G0        270
#define R_AARCH64_MOVW_SABS_G1        271
#define R_AARCH64_MOVW_SABS_G2        272
/* relocs to generate 19, 21, and 33 bit PC-relative addresses */
#define R_AARCH64_LD_PREL_LO19        273
#define R_AARCH64_ADR_PREL_LO21       274
#define R_AARCH64_ADR_PREL_PG_HI21    275
#define R_AARCH64_ADR_PREL_PG_HI21_NC 276
#define R_AARCH64_ADD_ABS_LO12_NC     277
#define R_AARCH64_LDST8_ABS_LO12_NC   278
/* relocs for control-flow - all offsets as multiple of 4 */
#define R_AARCH64_TSTBR14             279
#define R_AARCH64_CONDBR19            280
#define R_AARCH64_JUMP26              282
#define R_AARCH64_CALL26              283

#define R_AARCH64_LDST16_ABS_LO12_NC  284
#define R_AARCH64_LDST32_ABS_LO12_NC  285
#define R_AARCH64_LDST64_ABS_LO12_NC  286
/* group relocs to create pc-relative offset inline */
#define R_AARCH64_MOVW_PREL_G0        287
#define R_AARCH64_MOVW_PREL_G0_NC     288
#define R_AARCH64_MOVW_PREL_G1        289
#define R_AARCH64_MOVW_PREL_G1_NC     290
#define R_AARCH64_MOVW_PREL_G2        291
#define R_AARCH64_MOVW_PREL_G2_NC     292
#define R_AARCH64_MOVW_PREL_G3        293
#define R_AARCH64_LDST128_ABS_LO12_NC 299
/* group relocs to create a GOT-relative offset inline */
#define R_AARCH64_MOVW_GOTOFF_G0      300
#define R_AARCH64_MOVW_GOTOFF_G0_NC   301
#define R_AARCH64_MOVW_GOTOFF_G1      302
#define R_AARCH64_MOVW_GOTOFF_G1_NC   303
#define R_AARCH64_MOVW_GOTOFF_G2      304
#define R_AARCH64_MOVW_GOTOFF_G2_NC   305
#define R_AARCH64_MOVW_GOTOFF_G3      306
/* GOT-relative data relocs */
#define R_AARCH64_GOTREL64            307
#define R_AARCH64_GOTREL32            308
/* GOT-relative instr relocs */
#define R_AARCH64_GOT_LD_PREL19       309
#define R_AARCH64_LD64_GOTOFF_LO15    310
#define R_AARCH64_ADR_GOT_PAGE        311
#define R_AARCH64_LD64_GOT_LO12_NC    312
#define R_AARCH64_LD64_GOTPAGE_LO15   313
/* General Dynamic TLS relocations */
#define R_AARCH64_TLSGD_ADR_PREL21            512
#define R_AARCH64_TLSGD_ADR_PAGE21            513
#define R_AARCH64_TLSGD_ADD_LO12_NC           514
#define R_AARCH64_TLSGD_MOVW_G1               515
#define R_AARCH64_TLSGD_MOVW_G0_NC            516
/* Local Dynamic TLS relocations */
#define R_AARCH64_TLSLD_ADR_PREL21            517
#define R_AARCH64_TLSLD_ADR_PAGE21            518
#define R_AARCH64_TLSLD_ADD_LO12_NC           519
#define R_AARCH64_TLSLD_MOVW_G1               520
#define R_AARCH64_TLSLD_MOVW_G0_NC            521
#define R_AARCH64_TLSLD_LD_PREL19             522
#define R_AARCH64_TLSLD_MOVW_DTPREL_G2        523
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1        524
#define R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC     525
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0        526
#define R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC     527
#define R_AARCH64_TLSLD_ADD_DTPREL_HI12       528
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12       529
#define R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC    530
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12     531
#define R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC  532
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12    533
#define R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC 534
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12    535
#define R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC 536
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12    537
#define R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC 538
/* initial exec TLS relocations */
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G1      539
#define R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC   540
#define R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21   541
#define R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC 542
#define R_AARCH64_TLSIE_LD_GOTTPREL_PREL19    543
/* local exec TLS relocations */
#define R_AARCH64_TLSLE_MOVW_TPREL_G2         544
#define R_AARCH64_TLSLE_MOVW_TPREL_G1         545
#define R_AARCH64_TLSLE_MOVW_TPREL_G1_NC      546
#define R_AARCH64_TLSLE_MOVW_TPREL_G0         547
#define R_AARCH64_TLSLE_MOVW_TPREL_G0_NC      548
#define R_AARCH64_TLSLE_ADD_TPREL_HI12        549
#define R_AARCH64_TLSLE_ADD_TPREL_LO12        550
#define R_AARCH64_TLSLE_ADD_TPREL_LO12_NC     551
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12      552
#define R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC   553
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12     554
#define R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC  555
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12     556
#define R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC  557
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12     558
#define R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC  559
/* Dynamic Relocations */
#define R_AARCH64_COPY         1024
#define R_AARCH64_GLOB_DAT     1025
#define R_AARCH64_JUMP_SLOT    1026
#define R_AARCH64_RELATIVE     1027
#define R_AARCH64_TLS_DTPREL64 1028
#define R_AARCH64_TLS_DTPMOD64 1029
#define R_AARCH64_TLS_TPREL64  1030
#define R_AARCH64_TLS_DTPREL32 1031
#define R_AARCH64_TLS_DTPMOD32 1032
#define R_AARCH64_TLS_TPREL32  1033

using namespace ELFIO;

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
   int opt_f = 0;
   int opt_v = 0;
   int c;
   while (1)
   {
     c = getopt(argc, argv, "fv");
     if (c == -1)
	break;

     switch (c)
     {
 	case 'f':
 	  opt_f = 1;
         break;
        case 'v':
          opt_v = 1;
         break;
     }
   }
   if (optind == argc)
   {
     printf("%s usage: image [symbols]\n", argv[0]);
     return 1;
   }
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
   // enum sections
   Elf64_Addr text_start = 0;
   Elf_Xword text_size = 0;
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( sec->get_name() == ".text" )
     {
       text_start = sec->get_address();
       text_size  = sec->get_size();
       break;
     }
   }
   if ( !text_start )
   {
     printf("cannot find .text\n");
     return 1;
   }
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( sec->get_name() == ".data" )
     {
       auto off = sec->get_offset();
       printf(".data section offset %llX\n", off);
       size_t count = 0;
       // under arm64 we need count relocs in .data section       
       if ( reader.get_machine() == 183 )
       {
         a64 dstart = (a64)sec->get_address();
         count = filter_arm64_relocs(reader, dstart, dstart + sec->get_size(), (a64)text_start, (a64)(text_start + text_size));
       } else {
         a64 *curr = (a64 *)sec->get_data();
         a64 *end  = (a64 *)((char *)curr + sec->get_size());
         const endianess_convertor &conv = reader.get_convertor();
         for ( ; curr < end; curr++ )
         {
           auto addr = conv(*curr);
           if ( addr >= (a64)text_start &&
                addr < (a64)(text_start + text_size)
              )
            count++;
         }
       }
       printf("found %d\n", count);
       break;
     }
   }
}
