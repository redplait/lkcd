#ifndef _ARM64_BTI_H
#define _ARM64_BTI_H

#include <linux/sizes.h>
#include <linux/vmalloc.h>

#if defined(CONFIG_ARM64) && defined(CONFIG_ARM64_BTI_KERNEL)
#define HAS_ARM64_THUNKS

#include <asm/cpufeature.h>
#include "arm64thunk.h"

// return 1 if all ok
int init_bti_thunks(void);
int is_bti_thunk(unsigned long addr);
void *alloc_bti_thunk(void *, const char *sym_name);
void *bti_wrap(const char *sym_name);
void bti_thunks_lock_ro(void);
void finit_bti_thunks(void);

#endif

#endif /* _ARM64_BTI_H */