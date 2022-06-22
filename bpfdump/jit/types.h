/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#define __EXPORTED_HEADERS__
#include <asm-generic/int-l64.h>
#include <asm-generic/errno-base.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>

#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define ALIGN(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
#define READ_ONCE(x)		(*(const volatile typeof(x) *)&(x))

#define ENOTSUPP	524	/* Operation is not supported */

#define BUG_ON(__BUG_ON_cond) assert(!(__BUG_ON_cond))

#define WRITE_ONCE(x, val)						\
do {									\
	*(volatile typeof(x) *)&(x) = (val);				\
} while (0)

#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - offsetof(type, member))); })

#define pr_err(...) fprintf(stderr,  __VA_ARGS__)
#define pr_info(...) fprintf(stderr, __VA_ARGS__)
#define pr_err_ratelimited(...) fprintf(stderr, __VA_ARGS__)
#define BUILD_BUG_ON(x)

#define GFP_KERNEL 0

#ifndef __ASSEMBLY__

extern const unsigned char * const *ideal_nops;

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]

#define BPF_TRAMP_F_RESTORE_REGS	BIT(0)
/* Call original function after fentry progs, but before fexit progs.
 * Makes sense for fentry/fexit, normal calls and indirect calls.
 */
#define BPF_TRAMP_F_CALL_ORIG		BIT(1)
/* Skip current frame and return to parent.  Makes sense for fentry/fexit
 * programs only. Should not be used with normal calls and indirect calls.
 */
#define BPF_TRAMP_F_SKIP_FRAME		BIT(2)

#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))

typedef __s8  s8;
typedef __u8  u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

#ifdef __CHECKER__
#define __bitwise	__attribute__((bitwise))
#else
#define __bitwise
#endif

/* The kernel doesn't use this legacy form, but user space does */
#define __bitwise__ __bitwise

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

#include "bpf.h"

/* Optimization barrier */
#ifndef barrier
/* The "volatile" is due to gcc bugs */
# define barrier() __asm__ __volatile__("": : :"memory")
#endif

#define BIT(nr)			((unsigned long)1 << (nr))

typedef u32 __kernel_dev_t;

#ifndef __kernel_long_t
typedef long		__kernel_long_t;
typedef unsigned long	__kernel_ulong_t;
#endif

#ifndef __kernel_ino_t
typedef __kernel_ulong_t __kernel_ino_t;
#endif

#ifndef __kernel_mode_t
typedef unsigned int	__kernel_mode_t;
#endif

#ifndef __kernel_pid_t
typedef int		__kernel_pid_t;
#endif

#ifndef __kernel_daddr_t
typedef int		__kernel_daddr_t;
#endif

typedef int		       __kernel_suseconds_t;
#define __kernel_suseconds_t __kernel_suseconds_t

typedef __kernel_long_t	__kernel_off_t;
typedef long long	__kernel_loff_t;
typedef int __kernel_key_t;

typedef __kernel_ino_t		ino_t;
typedef __kernel_mode_t		mode_t;
typedef unsigned short		umode_t;
typedef __kernel_off_t		off_t;
typedef __kernel_pid_t		pid_t;
typedef __kernel_daddr_t	daddr_t;
typedef __kernel_key_t		key_t;
//typedef __kernel_suseconds_t	suseconds_t;
//typedef __kernel_timer_t	timer_t;
//typedef __kernel_clockid_t	clockid_t;
//typedef __kernel_mqd_t		mqd_t;

#ifndef __kernel_uid32_t
typedef unsigned int	__kernel_uid32_t;
typedef unsigned int	__kernel_gid32_t;
#endif

typedef unsigned short	__kernel_uid16_t;
typedef unsigned short	__kernel_gid16_t;

typedef __kernel_uid32_t	uid_t;
typedef __kernel_gid32_t	gid_t;
typedef __kernel_uid16_t        uid16_t;
typedef __kernel_gid16_t        gid16_t;

typedef unsigned long		uintptr_t;

#ifdef CONFIG_HAVE_UID16
/* This is defined by include/asm-{arch}/posix_types.h */
typedef __kernel_old_uid_t	old_uid_t;
typedef __kernel_old_gid_t	old_gid_t;
#endif /* CONFIG_UID16 */

/*
 * The following typedefs are also protected by individual ifdefs for
 * historical reasons:
 */
#ifndef __kernel_size_t
#if __BITS_PER_LONG != 64
//typedef unsigned int	__kernel_size_t;
//typedef int		__kernel_ssize_t;
//typedef int		__kernel_ptrdiff_t;
#else
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t	__kernel_ssize_t;
typedef __kernel_long_t	__kernel_ptrdiff_t;
#endif
#endif

typedef u16  __le16;
typedef u16  __be16;
typedef u32  __le32;
typedef u32  __be32;
typedef u64  __le64;
typedef u64  __be64;

typedef __u16  __sum16;
typedef __u32  __wsum;

#ifndef _PTRDIFF_T
#define _PTRDIFF_T
// typedef __kernel_ptrdiff_t	ptrdiff_t;
#endif

#ifndef _TIME_T
typedef __kernel_long_t	__kernel_old_time_t;
#define _TIME_T
typedef __kernel_old_time_t	time_t;
#endif

#ifndef _CLOCK_T
typedef __kernel_long_t	__kernel_clock_t;
#define _CLOCK_T
typedef __kernel_clock_t	clock_t;
#endif

#ifndef _CADDR_T
typedef char *		__kernel_caddr_t;
#define _CADDR_T
typedef __kernel_caddr_t	caddr_t;
#endif

/* bsd */
typedef unsigned char		u_char;
typedef unsigned short		u_short;
typedef unsigned int		u_int;
typedef unsigned long		u_long;

/* sysv */
typedef unsigned char		unchar;
typedef unsigned short		ushort;
typedef unsigned int		uint;
typedef unsigned long		ulong;

#ifndef __BIT_TYPES_DEFINED__
#define __BIT_TYPES_DEFINED__

typedef u8			u_int8_t;
typedef u16			u_int16_t;
typedef s16			int16_t;
typedef u32			u_int32_t;
typedef s32			int32_t;

#endif /* !(__BIT_TYPES_DEFINED__) */

typedef u8			uint8_t;
typedef u16			uint16_t;
typedef u32			uint32_t;

//#if defined(__GNUC__)
//typedef u64			uint64_t;
//typedef u64			u_int64_t;
//typedef s64			int64_t;
//#endif

/* this is a special 64bit data type that is 8-byte aligned */
#define aligned_u64		__aligned_u64
#define aligned_be64		__aligned_be64
#define aligned_le64		__aligned_le64

/**
 * The type used for indexing onto a disc or disc partition.
 *
 * Linux always considers sectors to be 512 bytes long independently
 * of the devices real block size.
 *
 * blkcnt_t is the type of the inode's block count.
 */
typedef u64 sector_t;

/*
 * The type of an index into the pagecache.
 */
#define pgoff_t unsigned long

/*
 * A dma_addr_t can hold any valid DMA address, i.e., any address returned
 * by the DMA API.
 *
 * If the DMA API only uses 32-bit addresses, dma_addr_t need only be 32
 * bits wide.  Bus addresses, e.g., PCI BARs, may be wider than 32 bits,
 * but drivers do memory-mapped I/O to ioremapped kernel virtual addresses,
 * so they don't care about the size of the actual bus addresses.
 */
#ifdef CONFIG_ARCH_DMA_ADDR_T_64BIT
typedef u64 dma_addr_t;
#else
typedef u32 dma_addr_t;
#endif

typedef unsigned int /*__bitwise */ gfp_t;
typedef unsigned int /*__bitwise */ slab_flags_t;
typedef unsigned int /*__bitwise */ fmode_t;

#ifdef CONFIG_PHYS_ADDR_T_64BIT
typedef u64 phys_addr_t;
#else
typedef u32 phys_addr_t;
#endif

typedef phys_addr_t resource_size_t;

/*
 * This type is the placeholder for a hardware interrupt number. It has to be
 * big enough to enclose whatever representation is used by a given platform.
 */
typedef unsigned long irq_hw_number_t;

typedef struct {
	int counter;
} atomic_t;

#ifdef CONFIG_64BIT
typedef struct {
	s64 counter;
} atomic64_t;
#endif

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

struct ustat {
	__kernel_daddr_t	f_tfree;
	__kernel_ino_t		f_tinode;
	char			f_fname[6];
	char			f_fpack[6];
};

/**
 * struct callback_head - callback structure for use with RCU and task_work
 * @next: next update requests in a list
 * @func: actual update function to call after the grace period.
 *
 * The struct is aligned to size of pointer. On most architectures it happens
 * naturally due ABI requirements, but some architectures (like CRIS) have
 * weird ABI and we need to ask it explicitly.
 *
 * The alignment is required to guarantee that bit 0 of @next will be
 * clear under normal conditions -- as long as we use call_rcu() or
 * call_srcu() to queue the callback.
 *
 * This guarantee is important for few reasons:
 *  - future call_rcu_lazy() will make use of lower bits in the pointer;
 *  - the structure shares storage space in struct page with @compound_head,
 *    which encode PageTail() in bit 0. The guarantee is needed to avoid
 *    false-positive PageTail().
 */
struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head

void cond_resched();

typedef void (*rcu_callback_t)(struct rcu_head *head);
typedef void (*call_rcu_func_t)(struct rcu_head *head, rcu_callback_t func);

typedef void (*swap_func_t)(void *a, void *b, int size);

typedef int (*cmp_r_func_t)(const void *a, const void *b, const void *priv);
typedef int (*cmp_func_t)(const void *a, const void *b);

void kfree(void *ptr);
void *kzalloc(size_t size, int);
void *kcalloc(size_t n, size_t size, int flags);
void *kmalloc_array(size_t n, size_t size, int flags);
void *kvcalloc(size_t n, size_t size, int flags);
void kvfree(void *addr);
bool IS_ERR(const void *ptr);

void smp_wmb();

#endif /*  __ASSEMBLY__ */
#endif /* _LINUX_TYPES_H */
