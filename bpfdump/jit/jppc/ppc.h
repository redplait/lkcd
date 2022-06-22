#include "../types.h"
#include "../sort.h"
#include "../extable.h"

#define PPC_LR_STKOFF	16
#define PPC_MIN_STKFRM	112
#define BREAKPOINT_INSTRUCTION	0x7fe00008	/* trap */
#define STACK_FRAME_MIN_SIZE	32
#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))