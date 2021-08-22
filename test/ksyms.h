#pragma once

#ifdef _MSC_VER
typedef unsigned __int64 a64;
#else
typedef unsigned long a64;
#endif

struct addr_sym
{
  const char *name;
  a64 addr;
};

// plain C interface to /proc/kallsyms
#ifdef __cplusplus
extern "C" {
#endif

int read_ksyms(const char *name);
#ifdef HAS_ELFIO
int read_syms(const ELFIO::elfio& reader, ELFIO::symbol_section_accessor &);
#endif /* HAS_ELFIO */
const char *name_by_addr(a64);
const char *lower_name_by_addr(a64);
const char *lower_name_by_addr_with_off(a64, size_t *);
a64 get_addr(const char *);
struct addr_sym *get_in_range(a64 start, a64 end, size_t *count);

#ifdef __cplusplus
};
#endif