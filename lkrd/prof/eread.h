#pragma once
#include <stddef.h>

struct prof_data {
   // offset in GOT
   ptrdiff_t m_mcount = 0;
   ptrdiff_t m_func_enter = 0;
   ptrdiff_t m_func_exit = 0;
};

int process_elf(const char *, struct prof_data *);