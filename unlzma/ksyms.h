#pragma once
#include "types.h"

struct addr_sym
{
  const char *name;
  a64 addr;
};

// plain C interface to /proc/kallsyms
#ifdef __cplusplus
extern "C" {
#endif

typedef void (*syms_cb)(struct addr_sym *, char type);

int read_ksyms(const char *name);
#ifdef HAS_ELFIO
int read_syms(const ELFIO::elfio& reader, ELFIO::symbol_section_accessor &);
#endif /* HAS_ELFIO */
const char *name_by_addr(a64);
const char *lower_name_by_addr(a64);
const char *lower_name_by_addr_with_off(a64, size_t *);
a64 get_addr(const char *);
struct addr_sym *get_in_range(a64 start, a64 end, size_t *count);
struct addr_sym *start_with(const char *prefix, a64 start, a64 end, size_t *count);
void enum_symbols(syms_cb);

#ifdef __cplusplus
};
#endif