#pragma once

#ifdef _MSC_VER
typedef unsigned __int64 a64;
#else
typedef unsigned long a64;
#endif

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
a64 get_addr(const char *);

#ifdef __cplusplus
};
#endif