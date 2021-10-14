#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/profile.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include "sched.h"

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "tstop";
static const char debug_filename[] = "tstop";

// this one is exported but no prototype in include
extern struct dentry *debugfs_create_file(const char *name, umode_t mode,
				   struct dentry *parent, void *data,
				   const struct file_operations *fops);

// this one is not exported (do not even hope)
typedef struct task_struct *(*und_find_task_by_vpid)(pid_t nr);
und_find_task_by_vpid my_find_task_by_vpid = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#include <linux/static_call.h>

static unsigned long lkcd_lookup_name_scinit(const char *name);
unsigned long kallsyms_lookup_name_c(const char *name)
{
	return 0;
}

DEFINE_STATIC_CALL(lkcd_lookup_name_sc, lkcd_lookup_name_scinit);
#endif

// read kernel symbols from the /proc
#define KALLSYMS_PATH "/proc/kallsyms"
#define BUFF_SIZE 256

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)

static unsigned long lkcd_lookup_name(const char *name)
{
	unsigned int i = 0, first_space_idx = 0, second_space_idx = 0; /* Read Index and indexes of spaces */
	struct file *proc_ksyms = NULL;
	loff_t pos = 0;
	unsigned long ret = 0;
	ssize_t read = 0;
	int err = 0;
	const size_t name_len = strlen(name);

	/*
	 * Buffer for each line of kallsyms file.
	 * The symbol names are limited to KSYM_NAME_LEN=128. When Linux is
	 * compiled with clang's Control Flow Integrity, there are large symbols
	 * such as
	 * __typeid__ZTSFvPvP15ieee80211_local11set_key_cmdP21ieee80211_sub_if_dataP13ieee80211_staP18ieee80211_key_confE_global_addr
	 * which lead to a line with 142 characters.
	 * Some use a buffer which can hold 256 characters, to be safe.
	 */
	char proc_ksyms_entry[256] = {0};

	proc_ksyms = filp_open("/proc/kallsyms", O_RDONLY, 0);
	if (proc_ksyms == NULL)
		goto cleanup;

	read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &pos);
	while (read == 1) {
		if (proc_ksyms_entry[i] == '\n' || (size_t)i == sizeof(proc_ksyms_entry) - 1) {
			/* Prefix-match the name with the 3rd field of the line, after the second space */
			if (second_space_idx > 0 &&
			    second_space_idx + 1 + name_len <= sizeof(proc_ksyms_entry) &&
			    !strncmp(proc_ksyms_entry + second_space_idx + 1, name, name_len)) {
				printk(KERN_INFO "[+] %s: %.*s\n", name,
				       i, proc_ksyms_entry);
				/* Decode the address, which is in hexadecimal */
				proc_ksyms_entry[first_space_idx] = '\0';
				err = kstrtoul(proc_ksyms_entry, 16, &ret);
				if (err) {
					printk(KERN_ERR "kstrtoul returned error %d while parsing %.*s\n",
					       err, first_space_idx, proc_ksyms_entry);
					ret = 0;
					goto cleanup;
				}
				goto cleanup;
			}

			i = 0;
			first_space_idx = 0;
			second_space_idx = 0;
			memset(proc_ksyms_entry, 0, sizeof(proc_ksyms_entry));
		} else {
			if (proc_ksyms_entry[i] == ' ') {
				if (first_space_idx == 0) {
					first_space_idx = i;
				} else if (second_space_idx == 0) {
					second_space_idx = i;
				}
			}
			i++;
		}
		read = kernel_read(proc_ksyms, proc_ksyms_entry + i, 1, &pos);
	}
	printk(KERN_ERR "symbol not found in kallsyms: %s\n", name);

cleanup:
	if (proc_ksyms != NULL)
		filp_close(proc_ksyms, 0);
	return ret;
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name",
	.flags = KPROBE_FLAG_DISABLED
};

static unsigned long lkcd_lookup_name_scinit(const char *name)
{
	unsigned long (*lkcd_lookup_name_fp)(const char *name) = NULL;
	int kp_ret;

	// try kprobes first, but have a fallback as they might be disabled
	kp_ret = register_kprobe(&kp);
	if (kp_ret < 0) {
		printk(KERN_DEBUG "register_kprobe failed, returned %d", kp_ret);
	} else {
		lkcd_lookup_name_fp = (unsigned long (*) (const char *name))kp.addr;
		unregister_kprobe(&kp);
	}

	// brute force by doing a symbolic search via sprint_symbol
	if (!lkcd_lookup_name_fp) {
		char name[KSYM_SYMBOL_LEN];
		unsigned long start = (unsigned long) sprint_symbol;
		unsigned long end = start - 32 * 1024;
		unsigned long addr, offset;
		char *off_ptr;

		for (addr = start; addr > end; addr--) {
			if (sprint_symbol(name, addr) <= 0)
				break;
			if (!strncmp(name, "0x", 2))
				break;
			off_ptr = strchr(name, '+');
			if (!off_ptr)
				break;
			if (sscanf(off_ptr, "+%lx", &offset) != 1)
				break;
			addr -= offset;
			if (off_ptr - name == 20 &&
			    !strncmp(name, "kallsyms_lookup_name", 20))
			{
				lkcd_lookup_name_fp = (void *)addr;
				break;
			}
		}

		if (!lkcd_lookup_name_fp)
			printk(KERN_DEBUG "lookup via sprint_symbol() failed, too");
	}

	if (lkcd_lookup_name_fp) {
		static_call_update(lkcd_lookup_name_sc, lkcd_lookup_name_fp);
		return static_call(lkcd_lookup_name_sc)(name);
	}

	return 0;
}

static unsigned long lkcd_lookup_name(const char *name)
{
 return static_call(lkcd_lookup_name_sc)(name);
}

#else
unsigned long lkcd_lookup_name(const char *name)
{
 return kallsyms_lookup_name(name);
}
#endif

struct tracked_task
{
  struct rhash_head head;
  pid_t pid;
  const struct sched_class *old_sched;
};

#define NR_CPUS_HINT 192

static const struct rhashtable_params tracked_hash_params = {
	.nelem_hint = NR_CPUS_HINT,
	.head_offset = offsetof(struct tracked_task, head),
	.key_offset = offsetof(struct tracked_task, pid),
	.key_len = sizeof(pid_t),
	.max_size = NR_CPUS,
	.min_size = 2,
	.automatic_shrinking = true,
};

void uninst_sched(struct tracked_task *tn)
{
  struct task_struct *task;
  if ( !tn->old_sched )
    return;
  task = my_find_task_by_vpid(tn->pid);
  if ( !task )
    return;
  printk("uninst_sched PID %d\n", tn->pid);
  task->sched_class = tn->old_sched;
  tn->old_sched = 0;
}

static void free_tracked_nodes(void *ptr, void *arg)
{
  struct tracked_task *tn = (struct tracked_task *)ptr;
  // unistall scheduler
  uninst_sched(tn);
  kfree(tn);
}

static rwlock_t hlock;
static struct rhashtable *tracked_ht = 0;

static struct sched_class *stop_sched = 0;
static struct sched_class *fair_sched = 0;
static struct sched_class my_hybrid_sched;
struct dentry *pde = 0;

void construct_hybrid(void)
{
  memcpy(&my_hybrid_sched, fair_sched, sizeof(my_hybrid_sched));
  // borrow enqueue_task & dequeue_task from stop scheduler
  my_hybrid_sched.enqueue_task = stop_sched->enqueue_task;
  my_hybrid_sched.dequeue_task = stop_sched->dequeue_task;
}

void process_pid(int p_id, int is_remove)
{
  struct tracked_task *res;
  do_raw_write_trylock(&hlock);
  res = rhashtable_lookup(tracked_ht, &p_id, tracked_hash_params);
  if ( res && is_remove )
  {
    uninst_sched(res);
    rhashtable_remove_fast(tracked_ht, &res->head, tracked_hash_params);
  }
  if ( !res && !is_remove )
  {
    // add new
    struct task_struct *task = my_find_task_by_vpid(p_id);
    if ( task )
    {
      struct tracked_task *add = (struct tracked_task *)kzalloc(sizeof(struct tracked_task), GFP_KERNEL);
      if ( add )
      {
        add->pid = p_id;
        add->old_sched = task->sched_class;
        task->sched_class = &my_hybrid_sched;
        rhashtable_insert_fast(tracked_ht, &add->head, tracked_hash_params);
      }
    } else {
      printk("pid %d not found\n", p_id);
    }
  }
  do_raw_write_unlock(&hlock);
}

// process exit notificator
static int
task_exit_notify(struct notifier_block *self, unsigned long val, void *data)
{
  struct task_struct *task = data;
  pid_t pid = task_pid_nr(task);
  struct tracked_task *res = 0;
  do_raw_write_trylock(&hlock);
  res = rhashtable_lookup(tracked_ht, &pid, tracked_hash_params);
  if ( res )
    rhashtable_remove_fast(tracked_ht, &res->head, tracked_hash_params);
  do_raw_write_unlock(&hlock);
  return NOTIFY_OK;
}

static struct notifier_block task_exit_nb = {
	.notifier_call	= task_exit_notify,
};

static void *tstop_seq_start(struct seq_file *m, loff_t *pos)
{
  struct rhashtable_iter *iter = (struct rhashtable_iter *)m->private;
  loff_t n = *pos;
  // get read lock
  do_raw_read_trylock(&hlock);
  rhashtable_walk_enter(tracked_ht, iter);
  rhashtable_walk_start(iter);
  if ( n == 0 )
    return rhashtable_walk_next(iter);
  // seek
  do {
    void *res = rhashtable_walk_next(iter);
    if ( !res )
      return NULL;
  } while(--n);
  return rhashtable_walk_next(iter);
}

static void *tstop_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
  struct rhashtable_iter *iter = (struct rhashtable_iter *)m->private;
  ++(*pos);
  return rhashtable_walk_next(iter);
}

static void tstop_seq_stop(struct seq_file *m, void *v)
{
  struct rhashtable_iter *iter = (struct rhashtable_iter *)m->private;
  rhashtable_walk_stop(iter);
  rhashtable_walk_exit(iter);
  // unlock
  do_raw_read_unlock(&hlock);
}

static int tstop_seq_show(struct seq_file *m, void *v)
{
  struct tracked_task *tn = (struct tracked_task *)v;
  seq_printf(m, "%d\n", tn->pid);
  return 0;
}

// seq ops to show content of our file
static const struct seq_operations tstop_seq_ops = {
	.start = tstop_seq_start,
	.next  = tstop_seq_next,
	.stop  = tstop_seq_stop,
	.show  = tstop_seq_show,
};

static int debug_tstop_open(struct inode *inode, struct file *file)
{
  return seq_open_private(file, &tstop_seq_ops, sizeof(struct rhashtable_iter));
}

// ripped from https://tuxthink.blogspot.com/2012/07/module-to-find-task-from-its-pid.html
ssize_t debug_tstop_write(struct file *file,const char *buf,size_t count, loff_t *ptr)
{
  char kbuf[27];
  int remove = 0;
  char *start = kbuf;
  int copy_count = count;
  int p_id = 0;

  if ( copy_count > 26 )
    copy_count = 26;
  if (copy_from_user(kbuf,buf,copy_count))
    return -EFAULT;
  if ( kbuf[0] == '-' )
  {
    start++;
    remove = 1;
  }
  p_id = simple_strtoul(start,NULL,0);
  if ( p_id )
    process_pid(p_id, remove);
  return copy_count;
}

static const struct file_operations debug_ops = {
	.owner		= THIS_MODULE,
	.open		= debug_tstop_open,
	.write          = debug_tstop_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_private,
};

// init
int __init
init_module (void)
{
  int ret;
  stop_sched = (struct sched_class *)lkcd_lookup_name("stop_sched_class");
  if ( !stop_sched )
  {
    printk("Unable to find stop_sched\n");
    return -ENOENT;
  }
  fair_sched = (struct sched_class *)lkcd_lookup_name("fair_sched_class");
  if ( !fair_sched )
  {
    printk("Unable to find fair_sched\n");
    return -ENOENT;
  }
  construct_hybrid();
  my_find_task_by_vpid = (und_find_task_by_vpid)lkcd_lookup_name("find_task_by_vpid");
  if ( !my_find_task_by_vpid )
  {
    printk("Unable to find find_task_by_vpid\n");
    return -ENOENT;
  }
  rwlock_init(&hlock);
  tracked_ht = kzalloc(sizeof(*tracked_ht), GFP_KERNEL);
  if ( !tracked_ht )
  {
    return -ENOMEM;
  }
  ret = rhashtable_init(tracked_ht, &tracked_hash_params);
  if ( ret )
  {
    kfree(tracked_ht);
    tracked_ht = NULL;
    return ret;
  }
  // register notification on process exit
  ret = profile_event_register(PROFILE_TASK_EXIT, &task_exit_nb);
  if ( ret )
  {
    printk("Unable to register event, err %d\n", ret);
    kfree(tracked_ht);
    tracked_ht = NULL;
    return ret;
  }
  pde = debugfs_create_file(debug_filename, S_IRUGO | S_IWUGO, NULL, 0, &debug_ops);
  if ( !pde )
  {
    printk("Unable to debugfs_create_file(%s)\n", debug_filename);
    profile_event_unregister(PROFILE_TASK_EXIT, &task_exit_nb);
    kfree(tracked_ht);
    tracked_ht = NULL;
    return -EBADF;
  }
  return 0;
}

void cleanup_module(void)
{
  if ( pde )
  {
    debugfs_remove(pde);
    pde = 0;
  }
  profile_event_unregister(PROFILE_TASK_EXIT, &task_exit_nb);
  if ( tracked_ht )
  {
    do_raw_write_trylock(&hlock);
    rhashtable_free_and_destroy(tracked_ht, free_tracked_nodes, NULL);
    kfree(tracked_ht);
    tracked_ht = NULL;
    do_raw_write_unlock(&hlock);
  }
}