#include "../types.h"
#include "../sort.h"
#include "../extable.h"

#define PAGE_SHIFT   13

#define PAGE_SIZE    (1UL << PAGE_SHIFT)
#define PAGE_MASK    (~(PAGE_SIZE-1))
#define STACK_BIAS		2047

#define ASI_N			0x04 /* Nucleus				*/
#define ASI_NL			0x0c /* Nucleus, little endian		*/
#define ASI_AIUP		0x10 /* Primary, user			*/
#define ASI_AIUS		0x11 /* Secondary, user			*/
#define ASI_AIUPL		0x18 /* Primary, user, little endian	*/
#define ASI_AIUSL		0x19 /* Secondary, user, little endian	*/
#define ASI_P			0x80 /* Primary, implicit		*/
#define ASI_S			0x81 /* Secondary, implicit		*/
#define ASI_PNF			0x82 /* Primary, no fault		*/
#define ASI_SNF			0x83 /* Secondary, no fault		*/
#define ASI_PL			0x88 /* Primary, implicit, l-endian	*/
#define ASI_SL			0x89 /* Secondary, implicit, l-endian	*/
#define ASI_PNFL		0x8a /* Primary, no fault, l-endian	*/
#define ASI_SNFL		0x8b /* Secondary, no fault, l-endian	*/

/* Solaris compatible AT_HWCAP bits. */
#define AV_SPARC_MUL32		0x00000100 /* 32x32 multiply is efficient */
#define AV_SPARC_DIV32		0x00000200 /* 32x32 divide is efficient */
#define AV_SPARC_FSMULD		0x00000400 /* 'fsmuld' is efficient */
#define AV_SPARC_V8PLUS		0x00000800 /* v9 insn available to 32bit */
#define AV_SPARC_POPC		0x00001000 /* 'popc' is efficient */
#define AV_SPARC_VIS		0x00002000 /* VIS insns available */
#define AV_SPARC_VIS2		0x00004000 /* VIS2 insns available */
#define AV_SPARC_ASI_BLK_INIT	0x00008000 /* block init ASIs available */
#define AV_SPARC_FMAF		0x00010000 /* fused multiply-add */
#define AV_SPARC_VIS3		0x00020000 /* VIS3 insns available */
#define AV_SPARC_HPC		0x00040000 /* HPC insns available */
#define AV_SPARC_RANDOM		0x00080000 /* 'random' insn available */
#define AV_SPARC_TRANS		0x00100000 /* transaction insns available */
#define AV_SPARC_FJFMAU		0x00200000 /* unfused multiply-add */
#define AV_SPARC_IMA		0x00400000 /* integer multiply-add */
#define AV_SPARC_ASI_CACHE_SPARING \
				0x00800000 /* cache sparing ASIs available */
#define AV_SPARC_PAUSE		0x01000000 /* PAUSE available */
#define AV_SPARC_CBCOND		0x02000000 /* CBCOND insns available */
