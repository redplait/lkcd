#include "arm64bti.h"

#ifdef HAS_ARM64_THUNKS

#include "arm64thunk.c"
#include <linux/mm.h>

// size of one thunk
#define THUNK_SIZE  8
// how much pages allocate for thunks
#define THUNKS_PAGES 1

unsigned long lkcd_lookup_name(const char *name);

// typedefs
typedef void *(*t_vmalloc_node_range)(unsigned long, unsigned long, unsigned long, unsigned long, gfp_t,
                        pgprot_t, unsigned long, int, const void *);
typedef int (*t_set_memory_x)(unsigned long addr, int numpages);
typedef int (*t_set_memory_ro)(unsigned long addr, int numpages);

// static vars
static t_vmalloc_node_range s_vmalloc_node_range = NULL;
static t_set_memory_x s_set_memory_x = NULL;
static t_set_memory_ro s_set_memory_ro = NULL;
static int has_bti = 0;
static u8 *s_thunks = NULL;
static u8 *s_next_thunk = NULL;

int init_bti_thunks(void)
{
  unsigned long start;
  has_bti = cpus_have_const_cap(ARM64_BTI);
  if ( !has_bti )
    return 1;
  s_vmalloc_node_range = (t_vmalloc_node_range)lkcd_lookup_name("__vmalloc_node_range");
  if ( !s_vmalloc_node_range )
  {
    printk("cannot find __vmalloc_node_range");
    return 0;
  }
  if ( !func_has_bti(s_vmalloc_node_range) )
  {
    printk("__vmalloc_node_range is not BTI-compatible");
    return 0;
  }
  s_set_memory_x = (t_set_memory_x)lkcd_lookup_name("set_memory_x");
  if ( !s_set_memory_x )
  {
    printk("cannot find set_memory_x");
    return 0;
  }
  if ( !func_has_bti(s_set_memory_x) )
  {
    printk("set_memory_x is not BTI-compatible");
    return 0;
  }
  s_set_memory_ro = (t_set_memory_ro)lkcd_lookup_name("set_memory_ro");
  if ( !s_set_memory_ro )
  {
    printk("cannot find set_memory_ro");
    return 0;
  }
  if ( !func_has_bti(s_set_memory_ro) )
  {
    printk("set_memory_ro is not BTI-compatible");
    return 0;
  }
  start = (unsigned long)s_vmalloc_node_range;
  // params ripped from https://elixir.bootlin.com/linux/v5.14/source/arch/arm64/net/bpf_jit_comp.c#L1139
  s_thunks = s_vmalloc_node_range(
    PAGE_SIZE * THUNKS_PAGES, // size
    PAGE_SIZE,    // align
    PAGE_ALIGN(start - SZ_64M), // start - address of __vmalloc_node_range - 64Mb
    PAGE_ALIGN(start), // end - till __vmalloc_node_range which located somewhere inside kernel
    GFP_KERNEL,   // mask
    PAGE_KERNEL,  // prot
    0,            // vm_flags
    NUMA_NO_NODE, // node
    __builtin_return_address(0) // caller
  );
  if ( !s_thunks )
  {
    printk("cannot alloc memory for BTI thunks");
    return 0;
  }
  s_next_thunk = s_thunks;
  return 1;
}

void finit_bti_thunks(void)
{
  if ( s_thunks )
    vfree(s_thunks);
  s_thunks = s_next_thunk = NULL;
}

void bti_thunks_lock_ro(void)
{
  if ( !has_bti )
    return;
  s_set_memory_ro((unsigned long)s_thunks, THUNKS_PAGES);
  s_set_memory_x((unsigned long)s_thunks, THUNKS_PAGES);
}

void *alloc_bti_thunk(void *addr, const char *sym_name)
{
  if ( !has_bti )
    return addr; // not need to care about bcs this cpu don`t support BTI
  if ( func_has_bti(addr) )
    return addr;
  else {
    u8 *thunk;
    if ( !s_thunks )
      return NULL;
    if ( s_next_thunk >= s_thunks + PAGE_SIZE * THUNKS_PAGES )
    {
      printk("no free bti thunk for %s", sym_name);
      return NULL;
    }
    thunk = s_next_thunk;
    s_next_thunk += THUNK_SIZE;
    if ( !arm64_make_thunk(thunk, addr) )
      return thunk;
    printk("cannot make bti thunk for %s, offset %lX", sym_name, (long)addr - (long)s_next_thunk);
    s_next_thunk -= THUNK_SIZE;
    return NULL;
  }
}

void *bti_wrap(const char *sym_name)
{
  void *addr = (void *)lkcd_lookup_name(sym_name);
  if ( !addr )
  {
    printk("cannot find %s", sym_name);
    return addr;
  }
  return alloc_bti_thunk(addr, sym_name);
}
#endif /* HAS_ARM64_THUNKS */