#include "../types.h"
#include "../sort.h"
#include "../extable.h"

#define PAGE_SHIFT	(12)
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE - 1))
