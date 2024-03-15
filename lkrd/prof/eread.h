#pragma once
#include <stddef.h>

struct prof_data {
   // DT_FLAGS
   long flags = 0;
   // DT_FLAGS_1
   long flags1 = 0;
   inline int is_bind_now() const
   { return (flags & 8) || (flags1 & 1); }
   // offset in GOT
   ptrdiff_t m_mcount = 0;
   ptrdiff_t m_func_enter = 0;
   ptrdiff_t m_func_exit = 0;
};

int process_elf(const char *, struct prof_data *);