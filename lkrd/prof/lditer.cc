// unfortunately you cannot mix link.h with elfio so all dl_iterate_phdr must be in separate file

#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>

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