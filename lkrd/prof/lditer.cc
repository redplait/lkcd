// unfortunately you cannot mix link.h with elfio so all dl_iterate_phdr must be in separate file

#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "lditer.h"

static const struct segment_flag_table_t
{
    const Elf32_Word key;
    const char*    str;
} segment_flag_table[] = {
    { 0, "   " }, { 1, "  E" }, { 2, " W " }, { 3, " WE" },
    { 4, "R  " }, { 5, "R E" }, { 6, "RW " }, { 7, "RWE" },
};

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
   printf("name=%s addr %p (%d segments)\n", info->dlpi_name, info->dlpi_addr, info->dlpi_phnum);

   for (int j = 0; j < info->dlpi_phnum; j++)
         printf("\t\t header %2d: address=%10p size %d %s\n", j,
             (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr), info->dlpi_phdr[j].p_memsz,
             segment_flag_table[ info->dlpi_phdr[j].p_flags & 7 ].str
         );
    return 0;
}

void ld_iter()
{
  dl_iterate_phdr(callback, NULL);
}

int cmp_sonames(const char *full, const char *pat)
{
  if ( !full ) return 0;
  size_t flen = strlen(full), plen = strlen(pat);
  if ( flen < plen ) return 0;
  if ( flen == plen ) return !strcmp(full, pat);
  size_t pref = flen - plen;
  if ( full[pref-1] != '/' ) return 0;
  return !strcmp(full + pref, pat);
}

static int cb2(struct dl_phdr_info *info, size_t size, void *data)
{
  ld_data *ld = (ld_data *)data;
  if ( !cmp_sonames(info->dlpi_name, ld->name) ) return 0;
  ld->base = (char *)info->dlpi_addr;
  ld->x_start = nullptr;
  ld->x_size = 0;
  for (int j = 0; j < info->dlpi_phnum; j++)
  {
    // skip non-executable sections
    if ( !(info->dlpi_phdr[j].p_flags & 1) ) continue;
    if ( !ld->x_start )
    {
      ld->x_start = (char *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
      ld->x_size = info->dlpi_phdr[j].p_memsz;
    } else {
      char *end = (char *)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz);
      ld->x_size = end - ld->x_start;
    }
  }
  return 0;
}

int ld_iter(struct ld_data *ld)
{
  ld->base = nullptr;
  dl_iterate_phdr(cb2, ld);
  return ld->base != nullptr;
}