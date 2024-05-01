/* until 5.17 the grass was greener and the world was simpler
   You could just call profile_event_register with profile_type .eq. PROFILE_TASK_EXIT
   Then this evil clowns calling themselves maintainers killed it and instead ask to use
   trace_sched_process_exit which is even cannot be found in elixir.bootlin or other piece of dead code
   register_trace_prio_sched_process_free/register_trace_prio_sched_process_exit (and they still can`t decide
   which one is more trve: https://lkml.iu.edu/hypermail/linux/kernel/2008.0/05105.html)

   Cewl, nah, old tricks always much more reliable so for newer kernels just plain old
   register_kprobe on do_exit
 */

#include <linux/atomic/atomic-long.h>

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

static long main_horror(struct restart_block *b)
{
  restart_fn f = NULL;
  mutex_lock(&sinj.lock);
  if ( sinj.state == 1 )
  {
    unsigned long alloced, alloced2;
    unsigned long *params = (unsigned long *)(sinj.kbuf + sinj.kbuf_off);
    // return old restart fn and store it in f
#ifdef __x86_64__
    xchg_ptrs(&current->restart_block.fn, &sinj.old_restart);
    f = (restart_fn)sinj.old_restart;
#else
    f = (restart_fn)raw_atomic_long_xchg((atomic_long_t *)&current->restart_block.fn, (long)sinj.old_restart);
#endif
    // try to alloc
    sinj.vaddr = vm_mmap(NULL, 0, PAGE_ALIGN(sinj.kbuf_len), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0);
    if ( IS_ERR((void *)sinj.vaddr) )
    {
      sinj.state = 3;
      sinj.err = PTR_ERR((void *)sinj.vaddr);
      goto out;
    }
    // copy to process
    if ( copy_to_user((void*)sinj.vaddr, sinj.kbuf, sinj.kbuf_len) > 0 )
    {
      sinj.state = 4;
      sinj.err = -EFAULT;
      goto out;
    }
    // mprotect
    sinj.err = s_mprotect(sinj.vaddr, PAGE_ALIGN(sinj.kbuf_len), PROT_READ | PROT_EXEC, -1);
    if ( sinj.err )
    {
      sinj.state = 5;
      goto out;
    }
    // patch glibc - at params[0] & params[2]
    alloced = sinj.vaddr;
    alloced = sinj.vaddr + 9;
    if ( copy_to_user((void*)params[0], &alloced, sizeof(alloced)) > 0 ||
         copy_to_user((void*)params[2], &alloced2, sizeof(alloced2)) > 0 )
    {
      sinj.state = 6;
      sinj.err = -EFAULT;
      goto out;
    }
    sinj.state = 2;
  }
out:
  mutex_unlock(&sinj.lock);
printk("main_horror called for PID %d state %d error %d", current->pid, sinj.state, sinj.err);
  return f ? f(b) : 0;
}

static void inline revert_restart_fn(struct inject_data *id)
{
#ifdef __x86_64__
    xchg_ptrs(&id->victim->restart_block.fn, &id->old_restart);
#else
    raw_atomic_long_xchg((atomic_long_t *)&id->victim->restart_block.fn, (long)id->old_restart);
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
#ifdef __x86_64__
    xchg_ptrs(&task->restart_block.fn, &sinj.old_restart);
#else
    raw_atomic_long_xchg((atomic_long_t *)&task->restart_block.fn, (long)sinj.old_restart);
#endif
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
    int ret = register_exit_ntfy();
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
#ifdef __x86_64__
  {
    sinj.old_restart = (void *)&main_horror;
    xchg_ptrs(&victim->restart_block.fn, &sinj.old_restart);
  }
#else
    sinj.old_restart = (void *)raw_atomic_long_xchg((atomic_long_t *)&victim->restart_block.fn, (long)&main_horror);
#endif
  sinj.state = 1;
  mutex_unlock(&sinj.lock);
printk("submit_inject old %p", sinj.old_restart);
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