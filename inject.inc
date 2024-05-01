/* until 5.17 the grass was greener and the world was simpler
   You could just call profile_event_register with profile_type .eq. PROFILE_TASK_EXIT
   Then this evil clowns calling themselves maintainers killed it and instead ask to use
   trace_sched_process_exit which is even cannot be found in elixir.bootlin or other piece of dead code
   register_trace_prio_sched_process_free/register_trace_prio_sched_process_exit (and they still can`t decide
   which one is more trve: https://lkml.iu.edu/hypermail/linux/kernel/2008.0/05105.html)

   Cewl, nah, old tricks always much more reliable so for newer kernels just plain old
   register_kprobe on do_exit
 */

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
      6 - process died, well, sh*t happens
   */
  int state;
  int err;
  unsigned long kbuf_len; // size of kbuf
  unsigned long kbuf_off; // offset to data inside kbuf
  char *kbuf;
  char *vaddr; // VA of injected stub
  struct task_struct *victim;
};

static struct inject_data sinj;

// Warning! must be called holding id->lock
static inline void clear_sinj(struct inject_data *id)
{
  if ( id->kbuf ) { kfree(id->kbuf); id->kbuf = 0; }
  id->kbuf_len = id->kbuf_off = 0;
}

/* out params in buf
    buf[0] - state
    buf[1] - error
    buf[2] - VA if moon was in the right phase
*/
static int get_inj_state(struct task_struct *task, unsigned long *buf)
{
  mutex_lock(&sinj.lock);
  if ( sinj.state != 6 && task != sinj.victim )
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
    case 5: buf[1] = sinj.err;
     break;
  }
  // wash the floors
  sinj.state = 0; // ready for next adventure
  sinj.err = 0;
  sinj.vaddr = 0;
  sinj.victim = 0;
  clear_sinj(&sinj);
  // unlock
  mutex_unlock(&sinj.lock);
  return 0;
}

static void process_died(void)
{
  mutex_lock(&sinj.lock);
  if ( current == sinj.victim )
  {
    sinj.state = 6;
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
// ok, lets try with __tracepoint_sched_process_exit
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
  
  sinj.state = 1;
  mutex_unlock(&sinj.lock);
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
    mutex_unlock(&exit_hook_mutex);
  }
  // and only then cleanup sinj
  mutex_lock(&sinj.lock);
  clear_sinj(&sinj);
  mutex_unlock(&sinj.lock);
}