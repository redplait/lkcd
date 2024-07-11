#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/bpf.h>
#include <linux/sched/clock.h>
#include <linux/miscdevice.h>
#include "shared.h"

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "bmc";

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
	char proc_ksyms_entry[BUFF_SIZE] = {0};

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

// driver machinery
static atomic_t s_open_count = ATOMIC_INIT(0); // allow open device in exclusive mode
static struct bpf_map *s_map = NULL;
static int kprobe_installed = 0;
// polling ripped from https://embetronicx.com/tutorials/linux/device-drivers/poll-linux-example-device-driver/
DECLARE_WAIT_QUEUE_HEAD(wait_queue_etx_data);
// bfp maps
typedef struct bpf_map *(*my_get_map)(u32 ufd);
my_get_map s_get_map = NULL;
static struct idr *bmaps = NULL;
static spinlock_t *block = NULL;

static int open_bmc(struct inode *inode, struct file *file)
{
  int old_val = atomic_fetch_add_unless(&s_open_count, 1, 1);
  if ( old_val ) return -EBUSY;
  try_module_get(THIS_MODULE);
  return 0;
}

static int pexit_pre(struct kprobe *p, struct pt_regs *regs)
{
  if ( s_map ) {
    int err = 0;
    struct proc_dead pd;
    pd.timestamp = local_clock();
    pd.exit_code = current->exit_code;
    // write to map - ripped from https://elixir.bootlin.com/linux/v5.18.19/source/kernel/bpf/syscall.c#L178
    rcu_read_lock();
    err = s_map->ops->map_update_elem(s_map, &current->pid, &pd, BPF_NOEXIST);
    rcu_read_unlock();
    if ( !err ) wake_up(&wait_queue_etx_data);
    else printk("update failed, pid %d err %d\n", current->pid, err);
  }
  return 0;
}

static struct kprobe pexit_kp = {
    .pre_handler = pexit_pre,
    .symbol_name = "do_exit",
};

static int report_map(void)
{
  int res;
  // it would be good idea to check sizes of key & value here to make sure we have map
  // compatible with shared.h!proc_dead structure
  printk("map %p key_size %d value_size %d\n", s_map, s_map->key_size, s_map->value_size);
  if ( s_map->value_size != sizeof(struct proc_dead) ) {
    printk("bad map value_size %d must be %d\n", s_map->value_size, (int)sizeof(struct proc_dead));
    return -EINVAL;
  }
  res = register_kprobe(&pexit_kp);
  if ( !res )
    kprobe_installed = 1;
  return res;
}

static int close_bmc(struct inode *inode, struct file *file)
{
  printk("close called, kprobe %d s_map %p\n", kprobe_installed, s_map);
  if ( kprobe_installed ) {
    unregister_kprobe(&pexit_kp);
    // renew kprobe for next registration
    memset(&pexit_kp, 0, sizeof(pexit_kp));
    pexit_kp.pre_handler = pexit_pre;
    pexit_kp.symbol_name = "do_exit";
    kprobe_installed = 0;
  }
  if ( s_map ) {
    bpf_map_put(s_map);
    s_map = NULL;
  }
  atomic_dec(&s_open_count);
  module_put(THIS_MODULE);
  return 0;
}

static long bmc_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  unsigned long ptrbuf;
#define COPY_ARG     if ( copy_from_user( (void*)&ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )  return -EFAULT;
  switch(ioctl_num)
  {
    case IOCTL_FROM_FD:
      if ( s_map ) return -EAGAIN;
      if ( !s_get_map ) return -ENOCSI;
      COPY_ARG
      s_map = s_get_map(ptrbuf);
      if (IS_ERR(s_map)) {
        long res = PTR_ERR(s_map);
        printk("get_map failed, err %ld\n", res);
        return res;
      }
      return report_map();
     break;

    case IOCTL_BY_ID:
      if ( s_map ) return -EAGAIN;
      if ( !bmaps || !block ) return -ENOCSI;
      COPY_ARG
      else { // ripped from lkcd IOCTL_GET_BPF_MAPS
        unsigned int id;
        struct bpf_map *map;
        idr_preload(GFP_KERNEL);
        // lock
        spin_lock_bh(block);
        idr_for_each_entry(bmaps, map, id)
        {
          if ( id == ptrbuf ) {
            s_map = map;
            atomic64_inc(&s_map->refcnt);
            break;
          }
        }
        // unlock
        spin_unlock_bh(block);
        if ( !s_map ) return -ENOENT;
        return report_map();
      }
     break;

    default:
     return -EBADRQC;
  }
  return 0;
}

static unsigned int bmc_poll(struct file *filp, struct poll_table_struct *wait)
{
  __poll_t mask = 0;
  poll_wait(filp, &wait_queue_etx_data, wait);
  mask |= ( POLLIN | POLLRDNORM );
  return mask;
}

static const struct file_operations bmc_fops = {
 .open           = open_bmc,
 .release        = close_bmc,
 .unlocked_ioctl = bmc_ioctl,
 .poll           = bmc_poll,
};

static struct miscdevice bmc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "bmc",
    .fops = &bmc_fops
};

// init
int __init
init_module (void)
{
  int res;
  bmaps = (struct idr *)lkcd_lookup_name("map_idr");
  if ( !bmaps )
   printk("cannot find %s\n", "map_idr");
  block = (spinlock_t *)lkcd_lookup_name("map_idr_lock");
  if ( !block )
   printk("cannot find %s\n", "map_idr_lock");
  // theoretically bpf_map_get marked as EXPORT_SYMBOL
  // hovewer ld gives ERROR: modpost: "bpf_map_get" [/home/redp/disc/lkcd/bmc/bmc.ko] undefined!
  // and everything about these freaks is so f*ckd up
  s_get_map = (my_get_map)lkcd_lookup_name("bpf_map_get");
  if ( !s_get_map )
    printk("cannot find %s\n", "bpf_get_map");
  // register driver
  res = misc_register(&bmc_dev);
  if ( res )
  {
    printk("Unable to register the bmc device\n");
    return res;
  }
  // all good
  return 0;
}

void cleanup_module(void)
{
  misc_deregister(&bmc_dev);
}