#pragma once
#include "types.h"

struct addr_sym
{
  const char *name;
  a64 addr;
};

struct one_bpf_proto
{
  struct addr_sym proto;
  struct addr_sym func;
};

// plain C interface to /proc/kallsyms
#ifdef __cplusplus
size_t fill_bpf_protos(std::list<one_bpf_proto> &out_res);

extern "C" {
#endif

int read_system_map();
int read_ksyms(const char *name);
int read_kallsyms(const char *name);
#ifdef HAS_ELFIO
int read_syms(const ELFIO::elfio& reader, ELFIO::symbol_section_accessor &);
#endif /* HAS_ELFIO */
const char *name_by_addr(a64);
const char *lower_name_by_addr(a64);
const char *lower_name_by_addr_with_off(a64, size_t *);
const char *lower_name_by_addr_with_off2(a64, size_t *, a64 *sym_addr);
a64 get_addr(const char *);
struct addr_sym *get_in_range(a64 start, a64 end, size_t *count);
struct addr_sym *start_with(const char *prefix, a64 start, a64 end, size_t *count);

#ifdef __cplusplus
};
#endif