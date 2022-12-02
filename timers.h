// ripped from https://elixir.bootlin.com/linux/v5.14/source/kernel/time/timer.c#L198

/* Size of each clock level */
#define LVL_BITS	6
#define LVL_SIZE	(1UL << LVL_BITS)

/* Level depth */
#if HZ > 100
# define LVL_DEPTH	9
# else
# define LVL_DEPTH	8
#endif

#define WHEEL_SIZE	(LVL_SIZE * LVL_DEPTH)

#ifdef CONFIG_NO_HZ_COMMON
# define NR_BASES	2
# define BASE_STD	0
# define BASE_DEF	1
#else
# define NR_BASES	1
# define BASE_STD	0
# define BASE_DEF	0
#endif

struct timer_base {
    raw_spinlock_t		lock;
    struct timer_list	*running_timer;
#ifdef CONFIG_PREEMPT_RT
    spinlock_t		expiry_lock;
    atomic_t		timer_waiters;
#endif
    unsigned long		clk;
    unsigned long		next_expiry;
    unsigned int		cpu;
    bool			next_expiry_recalc;
    bool			is_idle;
    bool			timers_pending;
    DECLARE_BITMAP(pending_map, WHEEL_SIZE);
    struct hlist_head	vectors[WHEEL_SIZE];
} ____cacheline_aligned;