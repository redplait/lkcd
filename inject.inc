/* until 5.17 the grass was greener and the world was simpler
   You could just call profile_event_register with profile_type .eq. PROFILE_TASK_EXIT
   Then this evil clowns calling themselves maintainers killed it and instead ask to use
   trace_sched_process_exit which is even cannot be found in elixir.bootlin or other piece of dead code
   register_trace_prio_sched_process_free/register_trace_prio_sched_process_exit (and they still can`t decide
   which one is more trve: https://lkml.iu.edu/hypermail/linux/kernel/2008.0/05105.html)

   Cewl, nah, old tricks always much more reliable so for newer kernels just plain old
   register_kprobe on do_exit
 */
typedef long (*restart_fn)(struct restart_block *);

static int exit_hook_installed = 0;
static struct mutex exit_hook_mutex;

/* internal data structure presenting data for inject
 * second mutex required to access of it`s fields - no, you can`t use exit_hook_mutex here
 * consider what happened when your exit_hook called while your driver is removing and running in cleanup_module
 * Driver will hold exit_hook_mutex trying to remove hook (or kprobe)
 * hook handler can at the same time could acquire the same mutex and suddenly it will be destroyed
 * Horror story
 */
struct inject_data
{
  struct mutex lock;
  /* states:
      0 - ready for work
      1 - submitted
      2 - successfull
      3 - mmap error stored in err
      4 - copy error stored in err
      5 - protect error stored in err
      6 - patch error
      7 - process died, well, sh*t happens
   */
  int state;
  int err;
  unsigned long kbuf_len; // size of kbuf
  unsigned long kbuf_off; // offset to data inside kbuf
  char *kbuf;
  unsigned long vaddr; // VA of injected stub
  void *old_restart;
  struct task_struct *victim;
};

static struct inject_data sinj;

// Warning! must be called holding id->lock
static inline void clear_sinj(struct inject_data *id)
{
  if ( id->kbuf ) { kfree(id->kbuf); id->kbuf = 0; }
  id->kbuf_len = id->kbuf_off = 0;
  id->old_restart = 0;
}

static void wash_floors(struct inject_data *id)
{
  id->state = 0; // ready for next adventure
  id->err = 0;
  id->vaddr = 0;
  id->victim = 0;
  clear_sinj(id);
}

static int do_inject(struct inject_data *id)
{
  unsigned long paddr1, paddr2, asize = PAGE_ALIGN(id->kbuf_len);
  unsigned long *params = (unsigned long *)(id->kbuf + id->kbuf_off);
  // try to alloc
  id->vaddr = vm_mmap(NULL, 0, asize, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0);
  if ( IS_ERR((void *)id->vaddr) )
  {
    id->err = PTR_ERR((void *)id->vaddr);
    return id->state = 3;
  }
  // copy to process
  if ( copy_to_user((void*)id->vaddr, id->kbuf, id->kbuf_len) > 0 )
  {
    id->err = -EFAULT;
    return id->state = 4;
  }
  // read old values
  if ( copy_from_user(&params[1], (void *)params[0], sizeof(params[1])) > 0 )
    printk("warning: copy old value1 from %lX failed\n", params[0]);
  if ( params[2] && copy_from_user(&params[3], (void *)params[2], sizeof(params[3])) > 0 )
    printk("warning: copy old value2 from %lX failed\n", params[2]);
  // mprotect
  id->err = s_mprotect(id->vaddr, asize, PROT_READ | PROT_EXEC, -1);
  if ( id->err )
    return id->state = 5;
  // patch glibc - at params[0] & params[2]
  paddr1 = id->vaddr;
  // unfortunately code to inject must know lot more dirty intimate details about injection stub than I would like
#ifdef __aarch64__
  paddr2 = id->vaddr + 0x10;
#else
  paddr2 = id->vaddr + 0xd; // offset to __free_hook entry
#endif
printk("patch %lX to %lX and %lX to %lX\n", params[0], paddr1, params[2], paddr2);
  if ( copy_to_user((void*)params[0], &paddr1, sizeof(paddr1)) > 0 ||
       (params[2] && copy_to_user((void*)params[2], &paddr2, sizeof(paddr2)) > 0) )
  {
    id->err = -EFAULT;
    return id->state = 6;
  }
#ifdef DEBUG
  // check patch - for debug only
  paddr1 = paddr2 = 0;
  if ( !copy_from_user(&paddr1, (void*)params[0], sizeof(paddr1)) &&
       !copy_from_user(&paddr2, (void*)params[2], sizeof(paddr2)) )
printk("patched %lX: %lX and %lX: %lX\n", params[0], paddr1, params[2], paddr2);
#endif
  return id->state = 2;
}

/* task_struct->restart_block.fn is not called. lkmem -p PID shows
   PID 576513 at 0xffff90e28c4c0000
    thread.flags: 0
    flags: 400000
    sched_class: 0xffffffff976f4818 - kernel!fair_sched_class
    restart_block.fn: 0xffffffffc12d9a80 - lkcd!main_horror
   while for normal process something like
    restart_block.fn: 0xffffffff960cfbc0 - kernel!do_no_restart_syscall
#define INJECT_RESTART
*/

#ifdef INJECT_RESTART
#include <linux/atomic/atomic-long.h>

static long main_horror(struct restart_block *b)
{
  restart_fn f = NULL;
  mutex_lock(&sinj.lock);
  if ( sinj.state == 1 )
  {
    // return old restart fn and store it in f
#ifdef __x86_64__
    xchg_ptrs(&current->restart_block.fn, &sinj.old_restart);
    f = (restart_fn)sinj.old_restart;
#else
    f = (restart_fn)raw_atomic_long_xchg((atomic_long_t *)&current->restart_block.fn, (long)sinj.old_restart);
#endif
    do_inject(&sinj);
  }
  mutex_unlock(&sinj.lock);
#ifdef DEBUG
 printk("main_horror called for PID %d state %d error %d", current->pid, sinj.state, sinj.err);
#endif
  return f ? f(b) : 0;
}
#else
static void main_horror(struct callback_head *head)
{
  mutex_lock(&sinj.lock);
  if ( sinj.state == 1 ) do_inject(&sinj);
  mutex_unlock(&sinj.lock);
#ifdef DEBUG
 printk("main_horror called for PID %d state %d error %d", current->pid, sinj.state, sinj.err);
#endif
}

static struct callback_head s_inj_work = {
 .func = &main_horror
};
#endif /* INJECT_RESTART */


static void inline revert_restart_fn(struct inject_data *id)
{
#ifdef INJECT_RESTART
#ifdef __x86_64__
    xchg_ptrs(&id->victim->restart_block.fn, &id->old_restart);
#else
    raw_atomic_long_xchg((atomic_long_t *)&id->victim->restart_block.fn, (long)id->old_restart);
#endif
#else
    s_my_task_work_cancel(id->victim, &main_horror);
#endif
}

static void inline cancel_restart_fn(struct task_struct *task, struct inject_data *id)
{
#ifdef INJECT_RESTART
#ifdef __x86_64__
    xchg_ptrs(&task->restart_block.fn, &id->old_restart);
#else
    raw_atomic_long_xchg((atomic_long_t *)&task->restart_block.fn, (long)id->old_restart);
#endif
#else
    s_my_task_work_cancel(id->victim, &main_horror);
#endif
}

static int cancel_inject(struct task_struct *task)
{
  int err = 0;
  mutex_lock(&sinj.lock);
  if ( 1 != sinj.state )
    err = -EBUSY; // too late
  else if ( task != sinj.victim )
    err = -ESRCH;
  else {
    // revert restart fn
    cancel_restart_fn(task, &sinj);
    wash_floors(&sinj);
  }
  mutex_unlock(&sinj.lock);
  return err;
}

/* out params in buf
    buf[0] - state
    buf[1] - error
    buf[2] - VA if moon was in the right phase
*/
static int get_inj_state(struct task_struct *task, unsigned long *buf)
{
  mutex_lock(&sinj.lock);
  if ( sinj.state != 7 && task != sinj.victim )
  {
    mutex_unlock(&sinj.lock);
    return -ESRCH;
  }
  buf[0] = sinj.state;
  buf[1] = buf[2] = 0;
  switch(sinj.state)
  {
    case 0: // nothing in - nothing out
     mutex_unlock(&sinj.lock);
     return -ENODATA;
    case 1: // well, we can only wait and pray
      mutex_unlock(&sinj.lock);
      return 0;
    // you are lucky man
    case 2: buf[2] = (unsigned long)sinj.vaddr;
     break;
    case 3:
    case 4:
    case 5:
    case 6: buf[1] = sinj.err;
     break;
  }
  // wash the floors
  wash_floors(&sinj);
  // unlock
  mutex_unlock(&sinj.lock);
  return 0;
}

static void process_died(void)
{
  mutex_lock(&sinj.lock);
  if ( current == sinj.victim )
  {
    sinj.state = 7;
    clear_sinj(&sinj);
  }
  mutex_unlock(&sinj.lock);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,17,0)
/* warm vacuum lamp method via profile_event_register */
#include <linux/profile.h>

static int task_exit_notify(struct notifier_block *self, unsigned long val, void *data)
{
  process_died();
  return 0;
}

static struct notifier_block task_exit_nb = {
    .notifier_call = task_exit_notify,
    .priority = 0,
};

static int register_exit_ntfy(void)
{
  return profile_event_register(PROFILE_TASK_EXIT, &task_exit_nb);
}

static void unregister_exit_ntfy(void)
{
  profile_event_unregister(PROFILE_TASK_EXIT, &task_exit_nb);
}
#elif defined(CONFIG_TRACING)
// try track process death with __tracepoint_sched_process_exit
static struct tracepoint *s_proc_exit = 0;

static int register_exit_ntfy(void)
{
  s_proc_exit = (struct tracepoint *)lkcd_lookup_name("__tracepoint_sched_process_exit");
  if ( !s_proc_exit ) return -ENOTNAM;
  return tracepoint_probe_register(s_proc_exit, &process_died, NULL);
}

static void unregister_exit_ntfy(void)
{
  if ( s_proc_exit )
    tracepoint_probe_unregister(s_proc_exit, &process_died, NULL);
}

#elif defined(CONFIG_KPROBES)
// install kprobe on do_exit
static int pexit_pre(struct kprobe *p, struct pt_regs *regs)
{
  process_died();
  return 0;
}

static struct kprobe pexit_kp = {
    .pre_handler = pexit_pre,
    .symbol_name = "do_exit",
};

static int register_exit_ntfy(void)
{
  return register_kprobe(&pexit_kp);
}

static void unregister_exit_ntfy(void)
{
  unregister_kprobe(&pexit_kp);
}

#else
#error "I give up, your kernel is too young to have old good profile_event_register and at the same time it does not have CONFIG_TRACING & CONFIG_KPROBES"
#endif

static int submit_inject(struct task_struct *victim, unsigned long ksize, unsigned long koff, char *buf)
{
  int ret = 0;
  mutex_lock(&sinj.lock);
  if ( sinj.state )
  {
    mutex_unlock(&sinj.lock);
    return -EBUSY;
  }
  mutex_unlock(&sinj.lock);
  // check process watchdog
  mutex_lock(&exit_hook_mutex);
  if ( !exit_hook_installed )
  {
    // run process watchdog
    ret = register_exit_ntfy();
    if ( ret )
    {
      mutex_unlock(&exit_hook_mutex);
      return ret;
    }
    exit_hook_installed = 1;
  }
  mutex_unlock(&exit_hook_mutex);
  // form inject data
  mutex_lock(&sinj.lock);
  if ( sinj.state )
  {
    mutex_unlock(&sinj.lock);
    return -EBUSY;
  }
  sinj.victim = victim;
  sinj.err = 0;
  sinj.kbuf_len = ksize;
  sinj.kbuf_off = koff;
  sinj.kbuf = buf;
  // submit into right process work
#ifdef INJECT_RESTART
#ifdef __x86_64__
  {
    sinj.old_restart = (void *)&main_horror;
    xchg_ptrs(&victim->restart_block.fn, &sinj.old_restart);
  }
#else
  sinj.old_restart = (void *)raw_atomic_long_xchg((atomic_long_t *)&victim->restart_block.fn, (long)&main_horror);
#endif
#else
  ret = s_task_work_add(victim, &s_inj_work, 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
   TWA_RESUME);
#else
   1);
#endif
#endif /* INJECT_RESTART */
  sinj.state = 1;
  mutex_unlock(&sinj.lock);
#ifdef DEBUG
 printk("submit_inject old %p ret %d", sinj.old_restart, ret);
#endif
  return 0;
}

static void init_inject(void)
{
  mutex_init(&exit_hook_mutex);
  // init sinj
  mutex_init(&sinj.lock);
  sinj.state = 0;
  sinj.victim = 0;
  sinj.kbuf = 0;
  sinj.kbuf_len = 0;
}

static void finit_inject(void)
{
  // first we must remove hook
  if ( exit_hook_installed )
  {
    mutex_lock(&exit_hook_mutex);
    unregister_exit_ntfy();
    exit_hook_installed = 0;
printk("unregister process exit");
    mutex_unlock(&exit_hook_mutex);
  }
  // and only then cleanup sinj
  mutex_lock(&sinj.lock);
  if ( sinj.state == 1 ) revert_restart_fn(&sinj);
  clear_sinj(&sinj);
  mutex_unlock(&sinj.lock);
}