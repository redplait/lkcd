#include "../types.h"
#include "../sort.h"
#include "../extable.h"
#include "nops.h"
#include "ptrace.h"

#define CONFIG_X86_64

extern const unsigned char * const x86_nops[ASM_NOP_MAX+1];

# ifdef CONFIG_X86_64
#  define RETPOLINE_RCX_BPF_JIT_SIZE	17
#  define RETPOLINE_RCX_BPF_JIT()				\
do {								\
	EMIT1_off32(0xE8, 7);	 /* callq do_rop */		\
	/* spec_trap: */					\
	EMIT2(0xF3, 0x90);       /* pause */			\
	EMIT3(0x0F, 0xAE, 0xE8); /* lfence */			\
	EMIT2(0xEB, 0xF9);       /* jmp spec_trap */		\
	/* do_rop: */						\
	EMIT4(0x48, 0x89, 0x0C, 0x24); /* mov %rcx,(%rsp) */	\
	EMIT1(0xC3);             /* retq */			\
} while (0)
# else /* !CONFIG_X86_64 */
#  define RETPOLINE_EDX_BPF_JIT()				\
do {								\
	EMIT1_off32(0xE8, 7);	 /* call do_rop */		\
	/* spec_trap: */					\
	EMIT2(0xF3, 0x90);       /* pause */			\
	EMIT3(0x0F, 0xAE, 0xE8); /* lfence */			\
	EMIT2(0xEB, 0xF9);       /* jmp spec_trap */		\
	/* do_rop: */						\
	EMIT3(0x89, 0x14, 0x24); /* mov %edx,(%esp) */		\
	EMIT1(0xC3);             /* ret */			\
} while (0)
# endif
