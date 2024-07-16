#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/tty.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/binfmts.h>
#include <linux/sysrq.h>
#include <linux/slab.h>
#include <linux/hugetlb.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
#ifdef CONFIG_SLAB
#include <linux/slab_def.h>
#endif
#ifdef CONFIG_SLUB
#include <linux/slub_def.h>
#endif
#endif
#include <asm/io.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/namei.h>
#include <linux/kernfs.h>
#include <linux/console.h>
#ifdef __x86_64__
#include <asm/segment.h>
#include <asm/uaccess.h>
#endif
#include <linux/rbtree.h>
#ifdef CONFIG_UPROBES
#include <linux/uprobes.h>
#endif
#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#endif
#ifdef CONFIG_FSNOTIFY
#include <linux/fsnotify_backend.h>
#include <linux/mount.h>
#include "mnt.h"
#endif /* CONFIG_FSNOTIFY */
#include <linux/smp.h>
#include <linux/cpufreq.h>
#include <linux/clk.h>
#include <linux/devfreq.h>
#include <linux/miscdevice.h>
#include <linux/notifier.h>
#ifdef CONFIG_USER_RETURN_NOTIFIER
#include <linux/user-return-notifier.h>
#endif /* CONFIG_USER_RETURN_NOTIFIER */
#include <linux/percpu.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#ifdef CONFIG_TRACING
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#include <linux/trace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <linux/trace_events.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
#include <linux/tracepoint-defs.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#include <linux/ftrace_event.h>
#endif
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#include <linux/ftrace.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
#include <uapi/linux/btf.h>
#endif
#ifdef CONFIG_NETFILTER
#include <linux/netfilter/x_tables.h>
#endif
#include <linux/task_work.h>
#include "uprobes.h"
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/fib_rules.h>
#include <net/udp_tunnel.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>
#include <net/tcp.h>
#include <linux/sock_diag.h>
#include <net/protocol.h>
#include <linux/rhashtable.h>
#include "netlink.h"
#ifdef CONFIG_XFRM
#include <net/xfrm.h>
#endif
#include <linux/crypto.h>
#include <crypto/algapi.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <linux/lsm_hooks.h>
#endif
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/input.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/alarmtimer.h>
#ifdef CONFIG_NETFILTER
#include <net/netfilter/nf_log.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
#include <net/netfilter/nf_tables.h>
#endif
#endif
#ifdef CONFIG_WIRELESS_EXT
#include <net/iw_handler.h>
#endif
#ifdef CONFIG_KEYS
#include <linux/key-type.h>
#include <linux/key.h>
#endif
#ifdef CONFIG_ZPOOL
#include <linux/zpool.h>
#endif
#include "timers.h"
#include "bpf.h"
#include "event.h"
#include "sub_priv.h"
#include "shared.h"
#include "arm64.bti/arm64bti.h"

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "lkcd";

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#define strlcpy strscpy
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
static unsigned int *s_fib_notifier_net_id = NULL;
#endif
static struct mm_struct *s_init_mm = 0;
#ifdef __x86_64__
typedef pte_t *(*my_lookup_address)(unsigned long address, unsigned int *level);
static my_lookup_address s_lookup_address = 0;
#endif
#ifdef CONFIG_HUGETLB_PAGE
typedef int (*my_pmd_huge)(pmd_t pmd);
typedef int (*my_pud_huge)(pud_t pmd);
my_pmd_huge s_pmd_huge = 0;
my_pud_huge s_pud_huge = 0;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
static spinlock_t *s_vmap_area_lock = 0;
static spinlock_t *s_purge_vmap_area_lock = 0;
static struct list_head *s_vmap_area_list = 0;
static struct list_head *s_purge_vmap_area_list = 0;
#endif
static void **s_sys_table = 0;
#ifdef __x86_64__
static void **s_ia32_sys_table = 0;
static void **s_x32_sys_table = 0;
#endif
static struct cred *s_init_cred = 0;
static struct rw_semaphore *s_net = 0;
static rwlock_t *s_dev_base_lock = 0;
static struct sock_diag_handler **s_sock_diag_handlers = 0;
static struct mutex *s_sock_diag_table_mutex = 0;
#ifdef CONFIG_NETFILTER
static struct mutex *s_nf_hook_mutex = 0;
static struct mutex *s_nf_log_mutex = 0;
static struct xt_af *s_xt = 0;
#endif /* CONFIG_NETFILTER */
#ifdef CONFIG_XFRM
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
static spinlock_t *s_xfrm_state_afinfo_lock = 0;
static struct xfrm_state_afinfo **s_xfrm_state_afinfo = 0;
#endif
static spinlock_t *s_xfrm_km_lock = 0;
static struct list_head *s_xfrm_km_list = 0;
static spinlock_t *s_xfrm_policy_afinfo_lock = 0;
static struct xfrm_policy_afinfo **s_xfrm_policy_afinfo = 0;
static spinlock_t *s_xfrm_input_afinfo_lock = 0;
// xfrm protocols
static struct mutex *s_xfrm4_protocol_mutex = 0;
static struct xfrm4_protocol **x4p[3] = { 0, 0, 0 }; // esp4_handlers, ah4_handlers, ipcomp4_handlers
static struct mutex *s_xfrm6_protocol_mutex = 0;
static struct xfrm6_protocol **x6p[3] = { 0, 0, 0 }; // esp6_handlers, ah6_handlers, ipcomp6_handlers
// xfrm tunnels
static struct mutex *s_tunnel4_mutex = 0;
static struct xfrm_tunnel **x4t[3] = { 0, 0, 0 }; // tunnel4_handlers, tunnel64_handlers, tunnelmpls4_handlers 
static struct mutex *s_tunnel6_mutex = 0;
static struct xfrm6_tunnel **x6t[3] = { 0, 0, 0 }; // tunnel6_handlers, tunnel46_handlers, tunnelmpls6_handlers
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
# define XFRM_MAX (AF_INET6 + 1)
#else
# define XFRM_MAX AF_MAX
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
static spinlock_t *s_xfrm_translator_lock = 0;
static struct xfrm_translator **s_xfrm_translator = 0;
#endif
#endif /* CONFIG_XFRM */
#ifdef CONFIG_KEYS
typedef struct key *(*my_key_lookup)(key_serial_t id);
static my_key_lookup f_key_lookup = 0;
static struct rw_semaphore *s_key_types_sem = 0;
static struct list_head *s_key_types_list = 0;
static struct rb_root *s_key_serial_tree = 0;
static spinlock_t *s_key_serial_lock = 0;
#endif /* CONFIG_KEYS */
static struct ftrace_ops *s_ftrace_end = 0;
static void *delayed_timer = 0;
static struct alarm_base *s_alarm = 0;

#ifdef CONFIG_INPUT
static struct list_head *s_input_handler_list = 0;
static struct list_head *s_input_dev_list = 0;
static struct mutex *s_input_mutex = 0;
#endif

#ifdef CONFIG_DYNAMIC_DEBUG
static struct list_head *s_ddebug_tables = 0;
static struct mutex *s_ddebug_lock = 0;
#endif

#ifdef CONFIG_MAGIC_SYSRQ
// size of sysrq_key_table is different depending on kernel version
// on 3.x & 4.x it is 36
// since 5.10 it is 62
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#define MAGIC_SIZE 62
#else
#define MAGIC_SIZE 32
#endif
static spinlock_t *s_sysrq_key_table_lock = 0;
static struct sysrq_key_op **s_sysrq_key_table = 0;
#endif

typedef int (*my_mprotect_pkey)(unsigned long start, size_t len, unsigned long prot, int pkey);
static my_mprotect_pkey s_mprotect = 0;

typedef int (*my_lookup)(unsigned long addr, char *symname);
my_lookup s_lookup = 0;
static struct mutex *s_module_mutex = 0;
static struct list_head *s_modules = 0;
static struct list_head *s_formats = 0; // totally uniq name, yeah
rwlock_t *s_binfmt_lock = 0;
typedef int (*my_vmalloc_or_module_addr)(const void *);
static my_vmalloc_or_module_addr s_vmalloc_or_module_addr = 0;

typedef struct callback_head *(*my_task_work_cancel)(struct task_struct *task, task_work_func_t func);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
typedef int (*my_task_work_add)(struct task_struct *task, struct callback_head *work, enum task_work_notify_mode notify);
#else
typedef int (*my_task_work_add)(struct task_struct *task, struct callback_head *work, int);
#endif
static my_task_work_cancel s_my_task_work_cancel = 0;
static my_task_work_add s_task_work_add = 0;

#ifdef CONFIG_ZPOOL
static struct list_head *z_drivers_head = 0;
static spinlock_t *z_drivers_lock = 0;
#endif
static struct list_head *s_slab_caches = 0;
static struct mutex *s_slab_mutex = 0;

#define KPROBE_HASH_BITS 6
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)

#ifdef __x86_64__
// asm functions in getgs.asm
extern void *get_gs(long offset);
extern void *get_this_gs(long this_cpu, long offset);
extern unsigned int get_gs_dword(long offset);
extern unsigned short get_gs_word(long offset);
extern unsigned char get_gs_byte(long offset);
extern void *xchg_ptrs(void *, void *);
#endif /* __x86_64__ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
#include <linux/static_call.h>

static unsigned long lkcd_lookup_name_scinit(const char *name);
DEFINE_STATIC_CALL(lkcd_lookup_name_sc, lkcd_lookup_name_scinit);
#endif

// read kernel symbols from the /proc
#define KALLSYMS_PATH "/proc/kallsyms"
// Warning! When change this size you must patch size of ksym_params in lk.h too
#define BUFF_SIZE 256

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0) && LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)

unsigned long lkcd_lookup_name(const char *name)
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
	char proc_ksyms_entry[KSYM_NAME_LEN] = {0};

	proc_ksyms = filp_open(KALLSYMS_PATH, O_RDONLY, 0);
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
static unsigned long lkcd_lookup_name(const char *name)
{
 return kallsyms_lookup_name(name);
}
#endif

static int open_lkcd(struct inode *inode, struct file *file)
{
  try_module_get(THIS_MODULE);
  return 0;
}

static int close_lkcd(struct inode *inode, struct file *file) 
{
  module_put(THIS_MODULE);
  return 0;
}

#ifdef CONFIG_BPF
static const char *get_ioctl_name(unsigned int num)
{
  switch(num)
  {
    case IOCTL_GET_BPF_USED_MAPS:
      return "IOCTL_GET_BPF_USED_MAPS";
    case IOCTL_GET_BPF_OPCODES:
      return "IOCTL_GET_BPF_OPCODES";
    case IOCTL_GET_BPF_PROG_BODY:
      return "IOCTL_GET_BPF_PROG_BODY";
  }
  return "unknown";
}
#endif

// ripped from https://stackoverflow.com/questions/1184274/read-write-files-within-a-linux-kernel-module
static struct file *file_open(const char *path, int flags, int rights, int *err) 
{
    struct file *filp = NULL;
    const struct cred *old_real = NULL, *old;
    *err = 0;

    if ( s_init_cred )
    {
      old_real = current->real_cred;
      old = current->cred;
      rcu_assign_pointer(current->real_cred, s_init_cred);
      rcu_assign_pointer(current->cred, s_init_cred);
    }
    filp = filp_open(path, flags, rights);
    if ( old_real != NULL )
    {
      rcu_assign_pointer(current->real_cred, old_real);
      rcu_assign_pointer(current->cred, old);
    }
    if (IS_ERR(filp)) {
        *err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

static inline void file_close(struct file *file)
{
    filp_close(file, NULL);
}

static const struct file_operations *s_dbg_open = 0;
static const struct file_operations *s_dbg_full = 0;
static void *k_pre_handler_kretprobe = 0;

static inline int is_dbgfs(const struct file_operations *in)
{
  return (in == s_dbg_open) || (in == s_dbg_full);
}

// css_next_child is not exported so css_for_each_child not compiling. as usually
typedef struct cgroup_subsys_state *(*kcss_next_child)(struct cgroup_subsys_state *pos, struct cgroup_subsys_state *parent);
static kcss_next_child css_next_child_ptr = 0;
#ifdef CONFIG_BPF
static struct undoc_btf_ops **s_kind_ops = NULL;
// bpf_prog_put was not exported till 4.1
typedef void (*my_bpf_prog_put)(struct bpf_prog *prog);
my_bpf_prog_put s_bpf_prog_put = 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
typedef int (*kcgroup_bpf_detach)(struct cgroup *cgrp, struct bpf_prog *prog, enum bpf_attach_type type);
static kcgroup_bpf_detach cgroup_bpf_detach_ptr = 0;
#endif

// kernfs_node_from_dentry is not exported
typedef struct kernfs_node *(*krnf_node_type)(struct dentry *dentry);
static krnf_node_type krnf_node_ptr = 0;

typedef void (*und_iterate_supers)(void (*f)(struct super_block *, void *), void *arg);
static und_iterate_supers iterate_supers_ptr = 0;
static seqlock_t *mount_lock = 0;

static inline void lock_mount_hash(void)
{
  write_seqlock(mount_lock);
}

static inline void unlock_mount_hash(void)
{
  write_sequnlock(mount_lock);
}

// trace events list and semaphore
static struct rw_semaphore *s_trace_event_sem = 0;
static struct mutex *s_event_mutex = 0;
static struct list_head *s_ftrace_events = 0;
static struct mutex *s_bpf_event_mutex = 0;
static struct mutex *s_tracepoints_mutex = 0;
static struct mutex *s_tracepoint_module_list_mutex = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
typedef int (*und_bpf_prog_array_length)(struct bpf_prog_array *progs);
static und_bpf_prog_array_length bpf_prog_array_length_ptr = 0;
#endif

// x86 only
// on arm64 there is aarch64_insn_write but it accepts whole instruction with len 4 bytes
// on arm there is __patch_text and it also accepts whole instruction with len 4 bytes
#ifdef CONFIG_ARM64
typedef int (*t_patch_text)(void *addr, u32 insn);
static const char *s_patch_name = "aarch64_insn_patch_text_nosync";
#else
typedef void *(*t_patch_text)(void *addr, const void *opcode, size_t len);
static const char *s_patch_name = "text_poke_kgdb";
#endif
static t_patch_text s_patch_text = 0;

#if CONFIG_FSNOTIFY && LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
typedef struct fsnotify_mark *(*und_fsnotify_first_mark)(struct fsnotify_mark_connector **connp);
typedef struct fsnotify_mark *(*und_fsnotify_next_mark)(struct fsnotify_mark *mark);
static struct srcu_struct *fsnotify_mark_srcu_ptr = 0;
static und_fsnotify_first_mark fsnotify_first_mark_ptr = 0;
static und_fsnotify_next_mark  fsnotify_next_mark_ptr  = 0;

static struct fsnotify_mark *my_fsnotify_first_mark(struct fsnotify_mark_connector **connp)
{
	struct fsnotify_mark_connector *conn;
	struct hlist_node *node = NULL;

	conn = srcu_dereference(*connp, fsnotify_mark_srcu_ptr);
	if (conn)
		node = srcu_dereference(conn->list.first, fsnotify_mark_srcu_ptr);

	return hlist_entry_safe(node, struct fsnotify_mark, obj_list);
}

static struct fsnotify_mark *my_fsnotify_next_mark(struct fsnotify_mark *mark)
{
	struct hlist_node *node = NULL;

	if (mark)
		node = srcu_dereference(mark->obj_list.next,
					fsnotify_mark_srcu_ptr);

	return hlist_entry_safe(node, struct fsnotify_mark, obj_list);
}

struct super_mark_args
{
  void *sb_addr;
  int found;
  unsigned long cnt;
  unsigned long *curr;
  struct one_fsnotify *data;
};

static void count_superblock_marks(struct super_block *sb, void *arg)
{
  struct super_mark_args *args = (struct super_mark_args *)arg;
  if ( (void *)sb != args->sb_addr )
    return;
  else {
    struct fsnotify_mark *mark;
    args->found |= 1;
    for ( mark = fsnotify_first_mark_ptr(&sb->s_fsnotify_marks);
            mark != NULL;
            mark = fsnotify_next_mark_ptr(mark)
          )
      args->cnt++;
  }
}

static void fill_superblock_marks(struct super_block *sb, void *arg)
{
  struct super_mark_args *args = (struct super_mark_args *)arg;
  if ( (void *)sb != args->sb_addr )
    return;
  else {
    struct fsnotify_mark *mark;
    args->found |= 1;
    for ( mark = fsnotify_first_mark_ptr(&sb->s_fsnotify_marks);
          mark != NULL && args->curr[0] < args->cnt;
          mark = fsnotify_next_mark_ptr(mark), args->curr[0]++
        )
     {
        unsigned long index = args->curr[0];
        args->data[index].mark_addr = (void *)mark;
        args->data[index].mask = mark->mask;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)        
        args->data[index].ignored_mask = mark->ignored_mask;
#else
        args->data[index].ignored_mask = mark->ignore_mask;
#endif        
        args->data[index].flags = mark->flags;
        if ( mark->group )
        {
          args->data[index].group = (void *)mark->group;
          args->data[index].ops   = (void *)mark->group->ops;
        } else {
          args->data[index].group = NULL;
          args->data[index].ops = NULL;
        }
     }
  }
}

struct inode_mark_args
{
  void *sb_addr;
  void *inode_addr;
  int found;
  unsigned long cnt;
  unsigned long *curr;
  struct one_fsnotify *data;
};

static void fill_mount_marks(struct super_block *sb, void *arg)
{
  struct inode_mark_args *args = (struct inode_mark_args *)arg;
  if ( (void *)sb != args->sb_addr )
    return;
  else {
    struct mount *mnt;
    struct fsnotify_mark *mark;
    args->found |= 1;
    lock_mount_hash();
    list_for_each_entry(mnt, &sb->s_mounts, mnt_instance)
    {
      if ( (void *)mnt != args->inode_addr )
        continue;
      args->found |= 2;
      for ( mark = fsnotify_first_mark_ptr(&mnt->mnt_fsnotify_marks);
            mark != NULL && args->curr[0] < args->cnt;
            mark = fsnotify_next_mark_ptr(mark), args->curr[0]++
          )
      {
        unsigned long index = args->curr[0];
        args->data[index].mark_addr = (void *)mark;
        args->data[index].mask = mark->mask;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)        
        args->data[index].ignored_mask = mark->ignored_mask;
#else
        args->data[index].ignored_mask = mark->ignore_mask;
#endif        
        args->data[index].flags = mark->flags;
        if ( mark->group )
        {
          args->data[index].group = (void *)mark->group;
          args->data[index].ops   = (void *)mark->group->ops;
        } else {
          args->data[index].group = NULL;
          args->data[index].ops = NULL;
        }
      }
      break;
    }
    unlock_mount_hash();
  }
}

static void fill_inode_marks(struct super_block *sb, void *arg)
{
  struct inode_mark_args *args = (struct inode_mark_args *)arg;
  if ( (void *)sb != args->sb_addr )
    return;
  else {
    struct inode *inode;
    struct fsnotify_mark *mark;
    args->found |= 1;
    // iterate on inodes
    spin_lock(&sb->s_inode_list_lock);
    list_for_each_entry(inode, &sb->s_inodes, i_sb_list)
    {      
      if ( (void *)inode != args->inode_addr )
        continue;
      args->found |= 2;
      for ( mark = fsnotify_first_mark_ptr(&inode->i_fsnotify_marks);
            mark != NULL && args->curr[0] < args->cnt;
            mark = fsnotify_next_mark_ptr(mark), args->curr[0]++
          )
      {
        unsigned long index = args->curr[0];
        args->data[index].mark_addr = (void *)mark;
        args->data[index].mask = mark->mask;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)        
        args->data[index].ignored_mask = mark->ignored_mask;
#else
        args->data[index].ignored_mask = mark->ignore_mask;
#endif        
        args->data[index].flags = mark->flags;
        if ( mark->group )
        {
          args->data[index].group = (void *)mark->group;
          args->data[index].ops   = (void *)mark->group->ops;
        } else {
          args->data[index].group = NULL;
          args->data[index].ops = NULL;
        }
      }
      break;
    }
    spin_unlock(&sb->s_inode_list_lock);
  }
}
#endif /* CONFIG_FSNOTIFY */

struct super_inodes_args
{
  void *sb_addr;
  int found;
  unsigned long cnt;
  unsigned long *curr;
  struct one_inode *data;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
// used in fill_super_block_inodes & fill_super_blocks
static spinlock_t *s_inode_sb_list_lock = 0;
#endif

static void fill_super_block_inodes(struct super_block *sb, void *arg)
{
  struct super_inodes_args *args = (struct super_inodes_args *)arg;
  if ( (void *)sb != args->sb_addr )
    return;
  else {
    struct inode *inode;
    args->found++;
    // iterate on inodes
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
    spin_lock(s_inode_sb_list_lock);
#else
    spin_lock(&sb->s_inode_list_lock);
#endif
    list_for_each_entry(inode, &sb->s_inodes, i_sb_list)
    {
      unsigned long index = args->curr[0];
      if ( args->curr[0] >= args->cnt )
        break;
      // copy data for this inode
      args->data[index].addr    = (void *)inode;
      args->data[index].i_mode  = inode->i_mode;
      args->data[index].i_ino   = inode->i_ino;
      args->data[index].i_flags = inode->i_flags;
#if CONFIG_FSNOTIFY && LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
      args->data[index].i_fsnotify_mask = inode->i_fsnotify_mask;
      args->data[index].i_fsnotify_marks = (void *)inode->i_fsnotify_marks;
      args->data[index].mark_count = 0;
      // iterate on marks
      if ( fsnotify_first_mark_ptr && fsnotify_next_mark_ptr )
      {
        struct fsnotify_mark *mark;
        for ( mark = fsnotify_first_mark_ptr(&inode->i_fsnotify_marks); mark != NULL; mark = fsnotify_next_mark_ptr(mark) )
          args->data[index].mark_count++;
      }
#endif /* CONFIG_FSNOTIFY */
      // inc count for next iteration
      args->curr[0]++;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
    spin_unlock(s_inode_sb_list_lock);
#else
    spin_unlock(&sb->s_inode_list_lock);
#endif
  }
}

struct super_mount_args
{
  void *sb_addr;
  int found;
  unsigned long cnt;
  unsigned long *curr;
  struct one_mount *data;
};

static void fill_super_block_mounts(struct super_block *sb, void *arg)
{
  struct super_mount_args *args = (struct super_mount_args *)arg;
  if ( (void *)sb != args->sb_addr )
    return;
  else {
    struct mount *mnt;
    args->found++;
    lock_mount_hash();
    list_for_each_entry(mnt, &sb->s_mounts, mnt_instance)
    {
      unsigned long index = args->curr[0];
      if ( args->curr[0] >= args->cnt )
        break;
      // copy data for this inode
      args->data[index].addr = (void *)mnt;
      args->data[index].mnt_id = mnt->mnt_id;
      if ( mnt->mnt_mountpoint )
        dentry_path_raw(mnt->mnt_mountpoint, args->data[index].root, sizeof(args->data[index].root));
      else
        args->data[index].root[0] = 0;
      if ( mnt->mnt.mnt_root )
      {
//        struct path mnt_path = { .dentry = mnt->mnt.mnt_root, .mnt = &mnt->mnt };
//        d_path(&mnt_path, args->data[index].mnt_root, sizeof(args->data[index].mnt_root));
        dentry_path_raw(mnt->mnt.mnt_root, args->data[index].mnt_root, sizeof(args->data[index].mnt_root));
      } else
        args->data[index].mnt_root[0] = 0;
      if ( mnt->mnt_mp )
        dentry_path_raw(mnt->mnt_mp->m_dentry, args->data[index].mnt_mp, sizeof(args->data[index].mnt_mp));
      else
        args->data[index].mnt_mp[0] = 0;
      args->data[index].mark_count = 0;
#if CONFIG_FSNOTIFY && LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
      // iterate on marks
      if ( fsnotify_first_mark_ptr && fsnotify_next_mark_ptr )
      {
        struct fsnotify_mark *mark;
        for ( mark = fsnotify_first_mark_ptr(&mnt->mnt_fsnotify_marks); mark != NULL; mark = fsnotify_next_mark_ptr(mark) )
          args->data[index].mark_count++;
      }
#endif /* CONFIG_FSNOTIFY */
      // inc count for next iteration
      args->curr[0]++;
    }
    unlock_mount_hash();
  }
}

struct super_args
{
   unsigned long cnt;
   unsigned long *curr;
   struct one_super_block *data;
};

static void count_super_blocks(struct super_block *sb, void *arg)
{
  (*(unsigned long *)arg)++;
}

static void fill_super_blocks(struct super_block *sb, void *arg)
{
  struct super_args *args = (struct super_args *)arg;
  unsigned long index = args->curr[0];
  struct inode *inode;
  struct mount *mnt;
  if ( index >= args->cnt )
    return;
  // copy data from super-block
  args->data[index].addr      = sb;
  args->data[index].dev       = sb->s_dev;
  args->data[index].s_flags   = sb->s_flags;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
  args->data[index].s_iflags  = sb->s_iflags;
#else
  args->data[index].s_iflags  = 0;
#endif
#ifdef CONFIG_FS_ENCRYPTION
  args->data[index].s_cop     = (void *)sb->s_cop;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,7,0)
  if ( sb->s_shrink ) {
    args->data[index].count_objects = (void *)sb->s_shrink->count_objects;
    args->data[index].scan_objects = (void *)sb->s_shrink->scan_objects;
  }
#else
  args->data[index].count_objects = (void *)sb->s_shrink.count_objects;
  args->data[index].scan_objects = (void *)sb->s_shrink.scan_objects;
#endif
  args->data[index].s_fs_info = (void *)sb->s_fs_info;
  args->data[index].s_op      = (void *)sb->s_op;
  args->data[index].s_type    = sb->s_type;
  args->data[index].dq_op     = (void *)sb->dq_op;
  args->data[index].s_qcop    = (void *)sb->s_qcop;
  args->data[index].s_export_op = (void *)sb->s_export_op;
  args->data[index].s_d_op    = (void *)sb->s_d_op;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
  args->data[index].s_user_ns = (void *)sb->s_user_ns;
#else
  args->data[index].s_user_ns = 0;
#endif
  args->data[index].inodes_cnt = 0;
  args->data[index].s_root    = (void *)sb->s_root;
  if ( sb->s_root )
    dentry_path_raw(sb->s_root, args->data[index].root, sizeof(args->data[index].root));
  else
    args->data[index].root[0] = 0;
  args->data[index].mount_count = 0;
  list_for_each_entry(mnt, &sb->s_mounts, mnt_instance)
    args->data[index].mount_count++;
#if CONFIG_FSNOTIFY && LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
  args->data[index].s_fsnotify_mask = sb->s_fsnotify_mask;
  args->data[index].s_fsnotify_marks = sb->s_fsnotify_marks;
#endif /* CONFIG_FSNOTIFY */
  strncpy(args->data[index].s_id, sb->s_id, 31);
  // iterate on inodes
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
  spin_lock(s_inode_sb_list_lock);
#else
  spin_lock(&sb->s_inode_list_lock);
#endif
  list_for_each_entry(inode, &sb->s_inodes, i_sb_list)
    args->data[index].inodes_cnt++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
  spin_unlock(s_inode_sb_list_lock);
#else
  spin_unlock(&sb->s_inode_list_lock);
#endif
  // inc index for next
  args->curr[0]++;
}

#ifdef CONFIG_UPROBES
// some uprobe functions
typedef struct und_uprobe *(*find_uprobe)(struct inode *inode, loff_t offset);
typedef struct und_uprobe *(*get_uprobe)(struct und_uprobe *uprobe);
typedef void (*put_uprobe)(struct und_uprobe *uprobe);
static find_uprobe find_uprobe_ptr = 0;
static get_uprobe  get_uprobe_ptr =  0;
static put_uprobe  put_uprobe_ptr =  0;
// delayed uprobes
static struct list_head *s_delayed_uprobe_list = NULL;
static struct mutex *s_delayed_uprobe_lock = NULL;

static void copy1uprobe(struct und_uprobe *up, struct one_uprobe *curr)
{
  struct uprobe_consumer **con;
  curr->addr = up;
  curr->inode = up->inode;
  curr->ref_ctr_offset = up->ref_ctr_offset;
  curr->offset = up->offset;
  curr->i_no = 0;
  curr->flags = up->flags;
  // try get filename from inode
  curr->name[0] = 0;
  if ( up->inode )
  {
    struct dentry *de = d_find_any_alias(up->inode);
    curr->i_no = up->inode->i_ino;
    if ( de )
      dentry_path_raw(de, curr->name, sizeof(curr->name));
  }
  // calc count of consumers
  curr->cons_cnt = 0;
  down_read(&up->consumer_rwsem);
  for (con = &up->consumers; *con; con = &(*con)->next)
    curr->cons_cnt++;
  up_read(&up->consumer_rwsem);
}

static struct und_uprobe *my_get_uprobe(struct und_uprobe *uprobe)
{
	refcount_inc(&uprobe->ref);
	return uprobe;
}

static struct inode *debuggee_inode = NULL;
#define DEBUGGEE_FILE_OFFSET	0x4710 /* getenv@plt */

// ripped from https://github.com/kentaost/uprobes_sample/blob/master/uprobes_sample.c
static int uprobe_sample_handler(struct uprobe_consumer *con,
		struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
  u64 ip = regs->pc;
#elif defined(CONFIG_X86)
  u64 ip = regs->ip;
#elif defined(CONFIG_MIPS)
  unsigned long ip = regs->cp0_epc;
#endif
  printk("uprobe handler in PID %d executed, ip = %lx\n", task_pid_nr(current), (unsigned long)ip);
  return 0;
}

static int uprobe_sample_ret_handler(struct uprobe_consumer *con,
					unsigned long func,
					struct pt_regs *regs)
{
#if defined(CONFIG_ARM64)
  u64 ip = regs->pc;
#elif defined(CONFIG_X86)
  u64 ip = regs->ip;
#elif defined(CONFIG_MIPS)
  unsigned long ip = regs->cp0_epc;
#endif
  printk("uprobe ret_handler is executed, ip = %lX\n", (unsigned long)ip);
  return 0;
}

static struct uprobe_consumer s_uc = {
	.handler = uprobe_sample_handler,
	.ret_handler = uprobe_sample_ret_handler
};
#endif /* CONFIG_UPROBES */
 
#ifdef CONFIG_USER_RETURN_NOTIFIER
static int urn_installed = 0;
#endif

#ifdef CONFIG_KPROBES
static int test_kprobe_installed = 0;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#ifdef CONFIG_X86
	printk(KERN_INFO "pre_handler: p->addr = 0x%p, ip = %lx,"
			" flags = 0x%lx\n",
		p->addr, regs->ip, regs->flags);
#endif
	/* A dump_stack() here will give a stack backtrace */
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
#ifdef CONFIG_X86
	printk(KERN_INFO "post_handler: p->addr = 0x%p, flags = 0x%lx\n",
		p->addr, regs->flags);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 * Was removed in kernel 5.14
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}
#endif

static struct kprobe test_kp = {
	.pre_handler = handler_pre,
	.post_handler = handler_post,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)  
	.fault_handler = handler_fault,
#endif
	.symbol_name	= "__x64_sys_fork", // try better do_int3, he-he
};

static unsigned long kprobe_aggr = 0;
static struct list_head *s_kprobe_blacklist = 0;

// ripped from kernel/kprobes.c
static int is_krpobe_aggregated(struct kprobe *p)
{
  return (unsigned long)p->pre_handler == kprobe_aggr;
}

static void patch_kprobe(struct kprobe *p, unsigned long reason)
{
  if ( reason )
    p->flags &= ~KPROBE_FLAG_DISABLED;
  else
    p->flags |= KPROBE_FLAG_DISABLED;
}
#endif /* CONFIG_KPROBES */

#ifdef CONFIG_USER_RETURN_NOTIFIER
static void test_dummy_urn(struct user_return_notifier *urn)
{
}

static struct user_return_notifier s_urn = {
 .on_user_return = test_dummy_urn, 
 .link = NULL
};

struct urn_params
{
  unsigned long this_cpu_off;
  unsigned long offset;
  unsigned long count;
  unsigned long *out_data;
};

static void copy_lrn(void *info)
{
  struct urn_params *params = (struct urn_params *)info;
  unsigned long *buf = params->out_data + 1;
  struct hlist_head *head = (struct hlist_head *)get_this_gs(params->this_cpu_off, params->offset);
  unsigned long curr_cnt = 0;
  *(params->out_data) = 0;
  if ( !head )
    return;
  else {
    struct user_return_notifier *urn;
    struct hlist_node *tmp2;
    // traverse
    hlist_for_each_entry_safe(urn, tmp2, head, link)
    {
       if ( curr_cnt >= params->count )
         break;
       buf[curr_cnt++] = (unsigned long)urn->on_user_return;
    }
    *(params->out_data) = curr_cnt;
  }
}

static void count_lrn(void *info)
{
  unsigned long *buf = (unsigned long *)info;
  struct hlist_head *head = (struct hlist_head *)get_this_gs(buf[1], buf[2]);
  buf[0] = (unsigned long)head;
  buf[1] = 0;
  if ( !head )
    return;
  else {
    struct user_return_notifier *urn;
    struct hlist_node *tmp2;
    // traverse
    hlist_for_each_entry_safe(urn, tmp2, head, link)
     buf[1]++;
  }
}
#endif /* CONFIG_USER_RETURN_NOTIFIER */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
// assumed that all locks was taken before calling of this function
static unsigned long copy_trace_bpfs(const struct trace_event_call *c, unsigned long lim, unsigned long *out_buf)
{
  unsigned long cnt, i;
  out_buf[0] = 0;
  if ( !c->prog_array )
    return 0;
  cnt = bpf_prog_array_length_ptr(c->prog_array);
  for ( i = 0; i < cnt; ++i )
  {
    if ( i >= lim )
      return lim;
    out_buf[i + 1] = (unsigned long)c->prog_array->items[i].prog;
    out_buf[0]++;
  }
  return i;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static void copy_trace_event_call(const struct trace_event_call *c, struct one_trace_event_call *out_data)
{
  struct hlist_head *list;
  out_data->addr = (void *)c;
  out_data->evt_class = (void *)c->class; // nice to use c++ keyword
  out_data->tp = (void *)c->tp;
  out_data->filter = (void *)c->filter;
  out_data->flags = c->flags;
  out_data->perf_cnt = 0;
  out_data->bpf_cnt = 0;
#ifdef CONFIG_PERF_EVENTS
  out_data->perf_perm = (void *)c->perf_perm;
  if ( c->prog_array && s_bpf_event_mutex )
  {
    mutex_lock(s_bpf_event_mutex);
    out_data->bpf_prog = (void *)c->prog_array->items[0].prog;
    if ( bpf_prog_array_length_ptr )
      out_data->bpf_cnt = bpf_prog_array_length_ptr(c->prog_array);
    mutex_unlock(s_bpf_event_mutex);
  }
  list = this_cpu_ptr(c->perf_events);
  if ( list )
  {
    struct perf_event *pe;
    hlist_for_each_entry(pe, list, hlist_entry)
      out_data->perf_cnt++;
  }
#endif
}
#else
static void copy_trace_event_call(const struct ftrace_event_call *c, struct one_trace_event_call *out_data)
{
  struct hlist_head *list;
  out_data->addr = (void *)c;
  out_data->evt_class = (void *)c->class; // nice to use c++ keyword
  out_data->tp = (void *)c->tp;
  out_data->filter = (void *)c->filter;
  out_data->flags = c->flags;
  out_data->perf_cnt = 0;
  out_data->bpf_cnt = 0;
#ifdef CONFIG_PERF_EVENTS
  out_data->perf_perm = (void *)c->perf_perm;
  list = this_cpu_ptr(c->perf_events);
  if ( list )
  {
    struct perf_event *pe;
    hlist_for_each_entry(pe, list, hlist_entry)
      out_data->perf_cnt++;
  }
#endif
}
#endif

static void fill_one_cgroup(struct one_cgroup *grp, struct cgroup_subsys_state *css)
{
  int i;
  // bcs self (type cgroup_subsys_state) is first field in cgroup
  struct cgroup *cg = (struct cgroup *)css;
  // cgroup_bpf was introduced in 4.10 + CONFIG_CGROUP_BPF
#if defined(CONFIG_CGROUP_BPF) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  const int bpf_cgsize = sizeof(cg->bpf.effective) / sizeof(cg->bpf.effective[0]);
#endif
  grp->addr = (void *)cg;
  grp->ss = (void *)css->ss;
  grp->root = (void *)cg->root;
  if ( css->parent )
    grp->parent_ss = (void *)css->parent->ss;
  else
    grp->parent_ss = 0;
  grp->agent_work = (void *)cg->release_agent_work.func;  
  grp->serial_nr = css->serial_nr;
  grp->flags = cg->flags;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  grp->level = cg->level;
#endif
  grp->kn = (void *)cg->kn;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
  grp->id = cgroup_id(cg);
#else
  grp->id = cg->id;
#endif
  for ( i = 0; i < CGROUP_SUBSYS_COUNT; i++ )
    if ( rcu_dereference_raw(cg->subsys[i]) ) grp->ss_cnt++;
#if defined(CONFIG_CGROUP_BPF) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  for ( i = 0; i < bpf_cgsize && i < CG_BPF_MAX; i++ )
  {
    grp->prog_array[i] = (void *)cg->bpf.effective[i];
    if ( cg->bpf.effective[i] && bpf_prog_array_length_ptr )
    {
      grp->prog_array_cnt[i] = bpf_prog_array_length_ptr(cg->bpf.effective[i]);
    } else
      grp->prog_array_cnt[i] = 0;
    grp->bpf_flags[i] = cg->bpf.flags[i];
  }
  // copy release_work func
  grp->bpf_release_func = (unsigned long)cg->bpf.release_work.func;
  // calc count of attached bpf_cgroup_storage
  {
    // ripped from cgroup_bpf_release
    struct list_head *storages = &cg->bpf.storages;
    struct bpf_cgroup_storage *storage, *stmp;
    list_for_each_entry_safe(storage, stmp, storages, list_cg)
      grp->stg_cnt++;
  }
#endif
}

static void fill_bpf_prog(struct one_bpf_prog *curr, struct bpf_prog *prog)
{
  curr->prog = (void *)prog;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
  curr->prog_type = (int)prog->type;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
  curr->expected_attach_type = (int)prog->expected_attach_type;
#endif
  curr->len = prog->len;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
  curr->jited_len = prog->jited_len;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  memcpy(curr->tag, prog->tag, 8);
#endif
  curr->bpf_func = (void *)prog->bpf_func;
  curr->aux = (void *)prog->aux;
  if ( prog->aux )
  {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    curr->aux_id = prog->aux->id;
    curr->stack_depth = prog->aux->stack_depth;
#endif
    curr->used_map_cnt = prog->aux->used_map_cnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,12,0)
    curr->used_btf_cnt = prog->aux->used_btf_cnt;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
    curr->func_cnt = prog->aux->func_cnt;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
    curr->num_exentries = prog->aux->num_exentries;
#endif
  } else {
    curr->aux_id = 0;
    curr->used_map_cnt = curr->used_btf_cnt = curr->func_cnt = curr->stack_depth = curr->num_exentries = 0;
  }
}

// to avoid deadlock you must call up_read(s_net) somewhere below
static struct net *peek_net(unsigned long addr)
{
  struct net *res;
  down_read(s_net);
  for_each_net(res)
    if ( (unsigned long)res == addr ) return res;
  return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
static noinline void *my_net_generic(const struct net *net, unsigned int id)
{
	struct net_generic *ng;
	void *ptr = NULL;

	rcu_read_lock();
	ng = rcu_dereference(net->gen);
  if ( ng )
	  ptr = ng->ptr[id];
	rcu_read_unlock();

	return ptr;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
static unsigned int module_total_size(struct module *mod)
{
 int size = 0;

 for_each_mod_mem_type(type)
   size += mod->mem[type].size;
 return size;
}
#endif

// warning - size of string is hardcoded BUFF_SIZE 
static void read_user_string(char *name, unsigned long ioctl_param)
{
  int i;
  char ch, *temp = (char *) ioctl_param;
  get_user(ch, temp++);
  name[0] = ch;
  for (i = 1; ch && i < BUFF_SIZE - 1; i++, temp++) 
  {
    get_user(ch, temp);
    name[i] = ch;
  }
}

// extract subsys_private from file
static int extract_sp(struct file *file, struct subsys_private **sp)
{
  struct kobject *kobj;
  struct kernfs_node *k = krnf_node_ptr(file->f_path.dentry);
  if ( !k ) return -EBADF;
  if ( !(k->flags & KERNFS_DIR) ) return -ENOTDIR;
  kobj = k->priv;
  if ( !kobj ) return -ENOTTY;
  *sp = to_subsys_private(kobj);
  return 0;
}

#ifdef CONFIG_XFRM
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
static void copy_xfrm_type_off(const struct xfrm_type_offload *off, struct s_xfrm_type_offload *to)
{
  to->addr = off;
  if ( !off ) return;
  to->proto = off->proto;
  to->encap = (unsigned long)off->encap;
  to->input_tail = (unsigned long)off->input_tail;
  to->xmit = (unsigned long)off->xmit;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
static void copy_xfrm_type(const struct xfrm_type *t, struct s_xfrm_type *to)
{
  to->addr = t;
  if ( !t ) return;
  to->proto = t->proto;
  to->flags = t->flags;
  to->init_state = (unsigned long)t->init_state;
  to->destructor = (unsigned long)t->destructor;
  to->input = (unsigned long)t->input;
  to->output = (unsigned long)t->output;
  to->reject = (unsigned long)t->reject;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
  to->hdr_offset = (unsigned long)t->hdr_offset;
#endif  
}
#endif
#endif /* CONFIG_XFRM */

#ifdef CONFIG_NET_XGRESS
#include <linux/bpf_mprog.h>

static unsigned long count_mprog_count(struct bpf_mprog_entry *entry)
{
  const struct bpf_mprog_fp *fp;
  const struct bpf_prog *tmp;
  unsigned long res = 0;
  if ( !entry ) return res;
  bpf_mprog_foreach_prog(entry, fp, tmp) res++;
  return res;
}
#endif /* CONFIG_NET_XGRESS */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <crypto/aead.h>
#include <crypto/rng.h>
#endif

static void copy_rng(struct one_kcalgo *curr, struct crypto_alg *q)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
  struct rng_alg *r = &q->cra_u.rng;
  curr->rng.rng_make_random = (unsigned long)r->rng_make_random;
  curr->rng.rng_reset = (unsigned long)r->rng_reset;
#else
  struct rng_alg *r = container_of(q, struct rng_alg, base);
  curr->addr = r;
  curr->rng.generate = (unsigned long)r->generate;
  curr->rng.seed = (unsigned long)r->seed;
  curr->rng.set_ent = (unsigned long)r->set_ent;
#endif
  curr->what = 0xc;
  curr->rng.seedsize = r->seedsize;
}

static void copy_aead(struct one_kcalgo *curr, struct crypto_alg *q)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
  struct aead_alg *aead = &q->cra_u.aead;
#else
  struct aead_alg *aead = container_of(q, struct aead_alg, base);
  curr->addr = aead;
#endif
  curr->aead.setkey = (unsigned long)aead->setkey;
  curr->aead.setauthsize = (unsigned long)aead->setauthsize;
  curr->aead.encrypt = (unsigned long)aead->encrypt;
  curr->aead.decrypt = (unsigned long)aead->decrypt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
  curr->aead.givencrypt = (unsigned long)aead->givencrypt;
  curr->aead.givdecrypt = (unsigned long)aead->givdecrypt;
#else
  curr->aead.init = (unsigned long)aead->init;
  curr->aead.exit = (unsigned long)aead->exit;
#endif
  curr->aead.ivsize = aead->ivsize;
  curr->aead.maxauthsize = aead->maxauthsize;
}

#include <crypto/hash.h>

static void copy_shash(struct one_kcalgo *curr, struct crypto_alg *q)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
  struct shash_alg *s = container_of(q, struct shash_alg, base);
#else
  struct shash_alg *s = container_of(q, struct shash_alg, halg.base);
#endif
  curr->addr = s;
  curr->what = 0xe;
  curr->shash.init = (unsigned long)s->init;
  curr->shash.update = (unsigned long)s->update;
  curr->shash.final = (unsigned long)s->final;
  curr->shash.finup = (unsigned long)s->finup;
  curr->shash.digest = (unsigned long)s->digest;
  curr->shash._exp = (unsigned long)s->export;
  curr->shash._imp = (unsigned long)s->import;
  curr->shash.setkey = (unsigned long)s->setkey;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5,6,0)
  curr->shash.init_tfm = (unsigned long)s->init_tfm;
  curr->shash.exit_tfm = (unsigned long)s->exit_tfm;
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(6,4,0)
  curr->shash.clone_tfm = (unsigned long)s->clone_tfm;
#endif
  curr->shash.descsize = s->descsize;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,4,0)
  curr->shash.digestsize = s->digestsize;
  curr->shash.statesize = s->statesize;
#else
  curr->shash.digestsize = s->halg.digestsize;
  curr->shash.statesize = s->halg.statesize;
#endif
}

static void copy_ahash(struct one_kcalgo *curr, struct crypto_alg *q)
{
  struct ahash_alg *s = container_of(q, struct ahash_alg, halg.base);
  curr->addr = s;
  curr->what = 0xf;
  curr->shash.init = (unsigned long)s->init;
  curr->shash.update = (unsigned long)s->update;
  curr->shash.final = (unsigned long)s->final;
  curr->shash.finup = (unsigned long)s->finup;
  curr->shash.digest = (unsigned long)s->digest;
  curr->shash._exp = (unsigned long)s->export;
  curr->shash._imp = (unsigned long)s->import;
  curr->shash.setkey = (unsigned long)s->setkey;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5,6,0)
  curr->shash.init_tfm = (unsigned long)s->init_tfm;
  curr->shash.exit_tfm = (unsigned long)s->exit_tfm;
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(6,4,0)
  curr->shash.clone_tfm = (unsigned long)s->clone_tfm;
#endif
  curr->shash.digestsize = s->halg.digestsize;
  curr->shash.statesize = s->halg.statesize;
}

#ifdef CRYPTO_ALG_TYPE_SCOMPRESS
#include <crypto/internal/scompress.h>

static void copy_scomp(struct one_kcalgo *curr, struct crypto_alg *q)
{
  struct scomp_alg *s = container_of(q, struct scomp_alg, base);
  curr->addr = s;
  curr->what = 0xb;
  curr->scomp.alloc_ctx = (unsigned long)s->alloc_ctx;
  curr->scomp.free_ctx = (unsigned long)s->free_ctx;
  curr->scomp.compress = (unsigned long)s->compress;
  curr->scomp.decompress = (unsigned long)s->decompress;
}
#endif

#ifdef CRYPTO_ALG_TYPE_SCOMPRESS
#include <crypto/internal/acompress.h>

static void copy_acomp(struct one_kcalgo *curr, struct crypto_alg *q)
{
  struct acomp_alg *s = container_of(q, struct acomp_alg, base);
  curr->addr = s;
  curr->what = 0xa;
  curr->acomp.init = (unsigned long)s->init;
  curr->acomp.exit = (unsigned long)s->exit;
  curr->acomp.compress = (unsigned long)s->compress;
  curr->acomp.decompress = (unsigned long)s->decompress;
  curr->acomp.dst_free = (unsigned long)s->dst_free;
  curr->acomp.reqsize = s->reqsize;
}
#endif

#ifdef CRYPTO_ALG_TYPE_KPP
#include <crypto/kpp.h>

static void copy_kpp(struct one_kcalgo *curr, struct crypto_alg *q)
{
  struct kpp_alg *s = container_of(q, struct kpp_alg, base);
  curr->addr = s;
  curr->what = 0x8;
  curr->kpp.set_secret = (unsigned long)s->set_secret;
  curr->kpp.generate_public_key = (unsigned long)s->generate_public_key;
  curr->kpp.compute_shared_secret = (unsigned long)s->compute_shared_secret;
  curr->kpp.max_size = (unsigned long)s->max_size;
  curr->kpp.init = (unsigned long)s->init;
  curr->kpp.exit = (unsigned long)s->exit;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,2,0)
  curr->kpp.reqsize = s->reqsize;
#endif
}
#endif

#ifdef CRYPTO_ALG_TYPE_BLKCIPHER
static void copy_blkcipher(struct one_kcalgo *curr, struct crypto_alg *q)
{
  struct blkcipher_alg *bl = &q->cra_u.blkcipher;
  curr->blk.setkey = (unsigned long)bl->setkey;
  curr->blk.encrypt = (unsigned long)bl->encrypt;
  curr->blk.decrypt = (unsigned long)bl->decrypt;
  curr->blk.min_keysize = bl->min_keysize;
  curr->blk.max_keysize = bl->max_keysize;
  curr->blk.ivsize = bl->ivsize;
}
#endif

#ifdef CRYPTO_ALG_TYPE_ABLKCIPHER
static void copy_ablkcipher(struct one_kcalgo *curr, struct crypto_alg *q)
{
  struct ablkcipher_alg *bl = &q->cra_u.ablkcipher;
  curr->ablk.setkey = (unsigned long)bl->setkey;
  curr->ablk.encrypt = (unsigned long)bl->encrypt;
  curr->ablk.decrypt = (unsigned long)bl->decrypt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
  curr->ablk.givencrypt = (unsigned long)bl->givencrypt;
  curr->ablk.givdecrypt = (unsigned long)bl->givdecrypt;
#endif
  curr->ablk.min_keysize = bl->min_keysize;
  curr->ablk.max_keysize = bl->max_keysize;
  curr->ablk.ivsize = bl->ivsize;
}
#endif

#ifdef CRYPTO_ALG_TYPE_AKCIPHER
#include <crypto/akcipher.h>

static void copy_akcipher(struct one_kcalgo *curr, struct crypto_alg *q)
{
  struct akcipher_alg *ac = container_of(q, struct akcipher_alg, base);
  curr->addr = ac;
  curr->what = 0xd;
  curr->ak.sign = (unsigned long)ac->sign;
  curr->ak.verify = (unsigned long)ac->verify;
  curr->ak.encrypt = (unsigned long)ac->encrypt;
  curr->ak.decrypt = (unsigned long)ac->decrypt;
  curr->ak.set_pub_key = (unsigned long)ac->set_pub_key;
  curr->ak.set_priv_key = (unsigned long)ac->set_priv_key;
  curr->ak.max_size = (unsigned long)ac->max_size;
  curr->ak.init = (unsigned long)ac->init;
  curr->ak.exit = (unsigned long)ac->exit;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
  curr->ak.reqsize = ac->reqsize;
#endif
}
#endif

// functions to check NX on some page
// arc has __PAGE_EXECUTE
// loongarch has _PAGE_NO_EXEC
// powerpc has _PAGE_EXEC
// s390 hash _PAGE_NOEXEC
#ifdef CONFIG_PGTABLE_LEVELS
static inline int pgd_nx(pgd_t *p)
{
#ifdef __x86_64__
 return pgd_flags(*p) & _PAGE_NX ? 1 : 0;
#elif defined(CONFIG_ARM64)
 return _PAGE_KERNEL_EXEC != (pgd_val(*p) & _PAGE_KERNEL_EXEC) ? 1 : 0;
#else
 return 0;
#endif
}

static inline int p4d_nx(p4d_t *p)
{
#ifdef __x86_64__
 return p4d_flags(*p) & _PAGE_NX ? 1 : 0;
#elif defined(CONFIG_ARM64)
 return _PAGE_KERNEL_EXEC != (p4d_val(*p) & _PAGE_KERNEL_EXEC) ? 1 : 0;
#else
 return 0;
#endif
}

static inline int pud_nx(pud_t *p)
{
#ifdef __x86_64__
 return pud_flags(*p) & _PAGE_NX ? 1 : 0;
#elif defined(CONFIG_ARM64)
 return _PAGE_KERNEL_EXEC != (pud_val(*p) & _PAGE_KERNEL_EXEC) ? 1 : 0;
#else
 return 0;
#endif
}

static inline int pmd_nx(pmd_t *p)
{
#ifdef __x86_64__
 return pmd_flags(*p) & _PAGE_NX ? 1 : 0;
#elif defined(CONFIG_ARM64)
 return _PAGE_KERNEL_EXEC != (pmd_val(*p) & _PAGE_KERNEL_EXEC) ? 1 : 0;
#else
 return 0;
#endif
}

static inline int pte_nx(pte_t *p)
{
#ifdef __x86_64__
 return pte_flags(*p) & _PAGE_NX ? 1 : 0;
#elif defined(CONFIG_ARM64)
 return _PAGE_KERNEL_EXEC != (pte_val(*p) & _PAGE_KERNEL_EXEC) ? 1 : 0;
#else
 return 0;
#endif
}
#endif

#include "rn.h"
#include "inject.inc"

static long lkcd_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  unsigned long ptrbuf[16]; // keep it at least 16 items bcs test case in IOCTL_VMEM_SCAN can use all 16
  unsigned long count = 0;
  size_t kbuf_size = 0;
  unsigned long *kbuf = NULL;

#define COPY_ARG     if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )  return -EFAULT;
#define COPY_ARGS(n) if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * n ) > 0 ) return -EFAULT;

  switch(ioctl_num)
  {
    case IOCTL_READ_PTR:
       COPY_ARG
#ifdef __x86_64__
       if ( s_lookup_address ) {
         unsigned int unused = 0;
         pte_t *pte = s_lookup_address(ptrbuf[0], &unused);
         if ( !pte ) return -EFAULT;
         if ( pte_none(*pte) || !pte_present(*pte) ) return -EFAULT;
       } else
#endif
       if ( !virt_addr_valid((void *)ptrbuf[0]) &&
         (s_vmalloc_or_module_addr && !s_vmalloc_or_module_addr((const void *)ptrbuf[0])) ) return -EFAULT;
       if ( copy_to_user((void*)ioctl_param, (void*)ptrbuf[0], sizeof(void *)) > 0 )
         return -EFAULT;
     break; /* IOCTL_READ_PTR */

    case IOCTL_RKSYM:
     {
       char name[BUFF_SIZE];
       read_user_string(name, ioctl_param);
       ptrbuf[0] = lkcd_lookup_name(name);
       goto copy_ptrbuf0;
      }
      break; /* IOCTL_RKSYM */

    case IOCTL_LOOKUP_SYM:
       if ( !s_lookup ) return -ENOCSI;
       COPY_ARG
       else {
        int err;
        kbuf = (unsigned long *)kmalloc(KSYM_NAME_LEN, GFP_KERNEL);
        if ( !kbuf )
          return -ENOMEM;
        err = s_lookup(ptrbuf[0], (char *)kbuf);
        if ( err ) { kfree(kbuf); return err; }
        kbuf_size = 1 + strlen((char *)kbuf);
        if ( kbuf_size > BUFF_SIZE )
        {
          ((char *)kbuf)[BUFF_SIZE - 1] = 0;
          kbuf_size = BUFF_SIZE;
        }
        goto copy_kbuf;
       }
      break; /* IOCTL_LOOKUP_SYM */

#define ALLOC_KBUF(type, size) type *curr; \
 kbuf_size = sizeof(unsigned long) + size * sizeof(type); \
 kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO); \
 if ( !kbuf ) return -ENOMEM; \
 curr = (type *)(kbuf + 1);

#ifdef CONFIG_MODULES
    case IOCTL_MODULE1_GUTS:
       if ( !s_modules || !s_module_mutex ) return -ENOCSI;
       COPY_ARGS(3)
       else {
#ifdef CONFIG_TREE_SRCU
        unsigned int i = 0;
        int found = 0;
        struct module *mod;
        ALLOC_KBUF(struct one_srcu, ptrbuf[1])
        mutex_lock(s_module_mutex);
        list_for_each_entry(mod, s_modules, list)
        {
          if ( (unsigned long)mod != ptrbuf[0] ) continue;
          found = 1;
          for ( i = 0; i < mod->num_srcu_structs; i++ )
          {
            if ( count >= ptrbuf[1] ) break;
            curr->addr = mod->srcu_struct_ptrs[i];
            curr->per_cpu_off = (unsigned long)mod->srcu_struct_ptrs[i]->sda;
            // for next iter
            count++; curr++;
          }
          break;
        }
        mutex_unlock(s_module_mutex);
        if ( !found ) { kfree(kbuf); return -ENOENT; }
        kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_srcu);
        goto copy_kbuf_count;
#endif
       }
      break; /* IOCTL_MODULE1_GUTS */

    case IOCTL_READ_MODULES:
       if ( !s_modules || !s_module_mutex ) return -ENOCSI;
       COPY_ARGS(2)
       if ( !ptrbuf[0] )
       {
        struct module *mod;
        mutex_lock(s_module_mutex);
        list_for_each_entry(mod, s_modules, list)
        {
          if ( mod->state == MODULE_STATE_LIVE ) count++;
        }
        mutex_unlock(s_module_mutex);
        goto copy_count;
       } else {
        struct module *mod;
        if ( !ptrbuf[1] )
        {
          ALLOC_KBUF(struct one_module, ptrbuf[0])
          mutex_lock(s_module_mutex);
          list_for_each_entry(mod, s_modules, list)
          {
            if ( mod->state != MODULE_STATE_LIVE ) continue;
            if ( count >= ptrbuf[0] ) break;
            // ripped from module/procfs.c function m_show
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
            curr->base = mod->mem[MOD_TEXT].base;
            curr->size = module_total_size(mod);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
            curr->base = mod->module_core;
            curr->size = mod->init_size + mod->core_size;
#else
            curr->base = mod->core_layout.base;
            curr->size = mod->init_layout.size + mod->core_layout.size;
#ifdef CONFIG_ARCH_WANTS_MODULES_DATA_IN_VMALLOC
            curr->size += mod->data_layout.size;
#endif
#endif /* new modules format since 6.4 */
            strlcpy(curr->name, mod->name, sizeof(curr->name));
            // for next module
            count++;
            curr++;
          }
          mutex_unlock(s_module_mutex);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_module);
          goto copy_kbuf_count;
        } else {
          ALLOC_KBUF(struct one_module1, ptrbuf[0])
          mutex_lock(s_module_mutex);
          list_for_each_entry(mod, s_modules, list)
          {
            if ( mod->state != MODULE_STATE_LIVE ) continue;
            if ( count >= ptrbuf[0] ) break;
            curr->addr = mod;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
            curr->base = mod->mem[MOD_TEXT].base;
            curr->module_init = mod->mem[MOD_INIT_TEXT].base;
            curr->init_size = mod->mem[MOD_INIT_TEXT].size;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
            curr->base = mod->module_core;
            curr->module_init = mod->module_init;
            curr->init_size = mod->init_size;
#else
            curr->base = mod->core_layout.base;
            curr->module_init = mod->init_layout.base;
            curr->init_size = mod->init_layout.size;
#endif
            curr->init = mod->init;
#ifdef CONFIG_MODULE_UNLOAD
            curr->exit = mod->exit;
#endif
#ifdef CONFIG_SMP
            curr->percpu_size = mod->percpu_size;
#endif
#ifdef CONFIG_TRACEPOINTS
            curr->num_tracepoints = mod->num_tracepoints;
            curr->tracepoints_ptrs = (unsigned long)mod->tracepoints_ptrs;
#endif
#ifdef CONFIG_BPF_EVENTS
            curr->num_bpf_raw_events = mod->num_bpf_raw_events;
            curr->bpf_raw_events = (unsigned long)mod->bpf_raw_events;
#endif
#ifdef CONFIG_DEBUG_INFO_BTF_MODULES
            curr->btf_data = (unsigned long)mod->btf_data;
            curr->btf_data_size = mod->btf_data_size;
#endif
#ifdef CONFIG_EVENT_TRACING
            curr->num_trace_events = mod->num_trace_events;
            curr->trace_events = (unsigned long)mod->trace_events;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
            curr->num_trace_evals = mod->num_trace_evals;
            curr->trace_evals = (unsigned long)mod->trace_evals;
#endif
#endif
#ifdef CONFIG_ARCH_USES_CFI_TRAPS
            curr->kcfi_traps = (unsigned long)mod->kcfi_traps;
            curr->kcfi_traps_end = (unsigned long)mod->kcfi_traps_end;
#endif
#ifdef CONFIG_TREE_SRCU
            curr->num_srcu_structs = mod->num_srcu_structs;
            curr->srcu_struct_ptrs = (unsigned long)mod->srcu_struct_ptrs;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0) && defined(CONFIG_KPROBES)
            curr->kprobes_text_start = (unsigned long)mod->kprobes_text_start;
            curr->kprobes_text_size = mod->kprobes_text_size;
            curr->kprobe_blacklist = (unsigned long)mod->kprobe_blacklist;
            curr->num_kprobe_blacklist = mod->num_kprobe_blacklist;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0) && defined(CONFIG_FUNCTION_ERROR_INJECTION)
            curr->ei_funcs = (unsigned long)mod->ei_funcs;
            curr->num_ei_funcs = mod->num_ei_funcs;
#endif
            // for next module
            count++;
            curr++;
          }
          mutex_unlock(s_module_mutex);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_module1);
          goto copy_kbuf_count;
        }
       }
      break; /* IOCTL_READ_MODULES */
#endif /* CONFIG_MODULES */

    case IOCTL_GET_NETDEV_CHAIN:
       COPY_ARGS(2)
       if ( !ptrbuf[1] )
       {
         struct notifier_block *b;
         struct raw_notifier_head *head = (struct raw_notifier_head *)ptrbuf[0];
         rtnl_lock();
         for ( b = head->head; b != NULL; b = b->next )
            count++;
         rtnl_unlock();
         goto copy_count;
       } else {
         struct notifier_block *b;
         struct raw_notifier_head *head = (struct raw_notifier_head *)ptrbuf[0];
         kbuf = (unsigned long *)kmalloc_array(ptrbuf[1] + 1, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf ) return -ENOMEM;
         rtnl_lock();
         for ( b = head->head; b != NULL; b = b->next )
         {
           if ( count >= ptrbuf[1] )
             break;
           kbuf[count + 1] = (unsigned long)b->notifier_call;
           count++;
         }
         rtnl_unlock();
         kbuf_size = sizeof(unsigned long) * (1 + count);
         goto copy_kbuf_count;
       }
      break; /* IOCTL_GET_NETDEV_CHAIN */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
    case READ_CPUFREQ_NTFY:
       COPY_ARGS(3)
        else {
          struct cpufreq_policy *cf = cpufreq_cpu_get(ptrbuf[0]);
          struct notifier_block *b;
          struct blocking_notifier_head *head;
          if ( !cf ) return -ENODATA;
          // cals size
          kbuf_size = (1 + ptrbuf[1]) * sizeof(unsigned long);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
          {
            cpufreq_cpu_put(cf);  
            return -ENOMEM;
          }
          if ( !ptrbuf[2] )
            head = &cf->constraints.min_freq_notifiers;
          else
            head = &cf->constraints.max_freq_notifiers;
          down_read(&head->rwsem);
          kbuf[0] = 0;
          for ( b = head->head; count < ptrbuf[1] && b != NULL; b = b->next, ++count )
          {
            kbuf[count + 1] = (unsigned long)b->notifier_call;
          }
          up_read(&head->rwsem);
          cpufreq_cpu_put(cf);
          kbuf_size = sizeof(unsigned long) * (count + 1);
          goto copy_kbuf_count;
        }
      break; /* READ_CPUFREQ_NTFY */

    case READ_CPUFREQ_CNT:
       COPY_ARG
        else {
         struct cpufreq_policy *cf = cpufreq_cpu_get(ptrbuf[0]);
         unsigned long out_buf[3] = { 0, 0, 0 };
         struct notifier_block *b;
         if ( !cf )
           return -ENODATA;
         out_buf[0] = (unsigned long)cf;
         // count ntfy
         down_read(&cf->constraints.min_freq_notifiers.rwsem);
         if ( cf->constraints.min_freq_notifiers.head != NULL )
         {
           for ( b = cf->constraints.min_freq_notifiers.head; b != NULL; b = b->next )
             out_buf[1]++;
         }
         up_read(&cf->constraints.min_freq_notifiers.rwsem);
         down_read(&cf->constraints.max_freq_notifiers.rwsem);
         if ( cf->constraints.max_freq_notifiers.head != NULL )
         {
           for ( b = cf->constraints.max_freq_notifiers.head; b != NULL; b = b->next )
             out_buf[2]++;
         }
         up_read(&cf->constraints.max_freq_notifiers.rwsem);
         cpufreq_cpu_put(cf);
         if ( copy_to_user((void*)(ioctl_param), (void*)out_buf, sizeof(out_buf)) > 0 )
           return -EFAULT;
        }
      break; /* READ_CPUFREQ_CNT */
#endif

    case IOCTL_REM_BNTFY:
       COPY_ARGS(2)
        else {
         struct blocking_notifier_head *nb = (struct blocking_notifier_head *)ptrbuf[0];
         void *ntfy = (void *)ptrbuf[1];
         struct notifier_block *b, *target = NULL;
         // lock
         down_write(&nb->rwsem);
         if ( nb->head != NULL )
         {
          for ( b = nb->head; b != NULL; b = b->next )
            if ( ntfy == b->notifier_call )
            {
              target = b;
              break;
            }
         }
         // unlock
         up_write(&nb->rwsem);
         if ( target )
         {
           blocking_notifier_chain_unregister(nb, target);
           ptrbuf[0] = 1;
         } else
           ptrbuf[0] = 0;
         // copy result to user-mode
         goto copy_ptrbuf0;
        }
      break; /* IOCTL_REM_BNTFY */

    case IOCTL_REM_ANTFY:
       COPY_ARGS(2)
        else {
         struct atomic_notifier_head *nb = (struct atomic_notifier_head *)ptrbuf[0];
         void *ntfy = (void *)ptrbuf[1];
         struct notifier_block *b, *target = NULL;
         unsigned long flags;
         // lock
         spin_lock_irqsave(&nb->lock, flags);
         if ( nb->head != NULL )
         {
          for ( b = nb->head; b != NULL; b = b->next )
            if ( ntfy == b->notifier_call )
            {
              target = b;
              break;
            }
         }
         // unlock
         spin_unlock_irqrestore(&nb->lock, flags);
         if ( target )
         {
           atomic_notifier_chain_unregister(nb, target);
           ptrbuf[0] = 1;
         } else
           ptrbuf[0] = 0;
         // copy result to user-mode
         goto copy_ptrbuf0;
        }
      break; /* IOCTL_REM_ANTFY */

    case IOCTL_REM_SNTFY:
       COPY_ARGS(2)
        else {
         struct srcu_notifier_head *nb = (struct srcu_notifier_head *)ptrbuf[0];
         void *ntfy = (void *)ptrbuf[1];
         struct notifier_block *b, *target = NULL;
         // lock
         mutex_lock(&nb->mutex);
         if ( nb->head != NULL )
         {
          for ( b = nb->head; b != NULL; b = b->next )
            if ( ntfy == b->notifier_call )
            {
              target = b;
              break;
            }
         }
         // unlock
         mutex_unlock(&nb->mutex);
         synchronize_srcu(&nb->srcu);
         if ( target )
         {
           srcu_notifier_chain_unregister(nb, target);
           ptrbuf[0] = 1;
         } else
           ptrbuf[0] = 0;
         // copy result to user-mode
         goto copy_ptrbuf0;
        }
      break; /* IOCTL_REM_SNTFY */

    case IOCTL_CNTNTFYCHAIN:
      COPY_ARG
      else
      {
       // copy address of blocking_notifier_head from user-mode
       struct blocking_notifier_head *nb = (struct blocking_notifier_head *)ptrbuf[0];
       struct notifier_block *b;
       // lock
       down_read(&nb->rwsem);
       // traverse
       if ( nb->head != NULL )
       {
          for ( b = nb->head; b != NULL; b = b->next )
            count++;
       }
       // unlock
       up_read(&nb->rwsem);
       goto copy_count;
     }
     break; /* IOCTL_CNTNTFYCHAIN */

    case IOCTL_ENUMNTFYCHAIN:
     COPY_ARGS(2)
     else
     {
       // copy address of blocking_notifier_head and count from user-mode
       struct blocking_notifier_head *nb = (struct blocking_notifier_head *)ptrbuf[0];
       count = ptrbuf[1];
       // validation
       if ( !ptrbuf[1] ) goto copy_count;
       if ( !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         kbuf = (unsigned long *)kmalloc_array(count + 1, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         down_read(&nb->rwsem);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < count); b = b->next )
            {
              kbuf[res + 1] = (unsigned long)b->notifier_call;
              res++;
            }
         }
         // unlock
         up_read(&nb->rwsem);
         kbuf[0] = res;
         kbuf_size = (1 + res) * sizeof(unsigned long);
         goto copy_kbuf;
       }
     }
     break; /* IOCTL_ENUMNTFYCHAIN */

    case IOCTL_ENUMANTFYCHAIN:
     COPY_ARGS(2)
     else
     {
       // copy address of atomic_notifier_head and count from user-mode
       struct atomic_notifier_head *nb = (struct atomic_notifier_head *)ptrbuf[0];
       unsigned long flags;
       count = ptrbuf[1];
       // validation
       if ( !ptrbuf[1] ) goto copy_count;
       if ( !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         kbuf = (unsigned long *)kmalloc_array(count + 1, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         spin_lock_irqsave(&nb->lock, flags);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < count); b = b->next )
            {
              kbuf[res + 1] = (unsigned long)b->notifier_call;
              res++;
            }
         }
         // unlock
         spin_unlock_irqrestore(&nb->lock, flags);
         kbuf[0] = res;
         kbuf_size = (1 + res) * sizeof(unsigned long);
         goto copy_kbuf;
       }
     }
     break; /* IOCTL_ENUMANTFYCHAIN */

    case IOCTL_CNTANTFYCHAIN:
     COPY_ARG
     else
     {
       // copy address of atomic_notifier_head from user-mode
       struct atomic_notifier_head *nb = (struct atomic_notifier_head *)ptrbuf[0];
       struct notifier_block *b;
       unsigned long flags;
       // lock
       spin_lock_irqsave(&nb->lock, flags);
       // traverse
       if ( nb->head != NULL )
       {
          for ( b = nb->head; b != NULL; b = b->next )
            count++;
       }
       // unlock
       spin_unlock_irqrestore(&nb->lock, flags);
       goto copy_count;
     }
     break; /* IOCTL_CNTANTFYCHAIN */

    case READ_CLK_NTFY:
       COPY_ARGS(3)
       else {
         struct clk_notifier *cn;
         struct list_head *head = (struct list_head *)ptrbuf[0];
         struct mutex *m = (struct mutex *)ptrbuf[1];
         struct notifier_block *b;
         if ( !ptrbuf[2] )
         {
           mutex_lock(m);
           list_for_each_entry(cn, head, node)
           {
             int idx = srcu_read_lock(&cn->notifier_head.srcu);
             for ( b = cn->notifier_head.head; b != NULL; b = b->next )
               count++;
             srcu_read_unlock(&cn->notifier_head.srcu, idx);
           }
           mutex_unlock(m);
           goto copy_count;
         } else {
           ALLOC_KBUF(struct clk_ntfy, ptrbuf[2])
           mutex_lock(m);
           list_for_each_entry(cn, head, node)
           {
             if ( count >= ptrbuf[2] )
               break;
             else {
               int idx = srcu_read_lock(&cn->notifier_head.srcu);
               for ( b = cn->notifier_head.head; b != NULL && count < ptrbuf[2]; b = b->next, ++count )
               {
                 curr->clk = (unsigned long)cn;
                 curr->ntfy = (unsigned long)b->notifier_call;
                 ++curr;
               }
               srcu_read_unlock(&cn->notifier_head.srcu, idx);
             }
           }
           mutex_unlock(m);
           kbuf_size = sizeof(unsigned long) + count * sizeof(struct clk_ntfy);
           // copy data to user-mode
           goto copy_kbuf_count;
         }
       }
     break; /* READ_CLK_NTFY */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
    case READ_DEVFREQ_NTFY:
       COPY_ARGS(3)
       else {
         struct devfreq *cn;
         struct list_head *head = (struct list_head *)ptrbuf[0];
         struct mutex *m = (struct mutex *)ptrbuf[1];
         struct notifier_block *b;
         if ( !ptrbuf[2] )
         {
           mutex_lock(m);
           list_for_each_entry(cn, head, node)
           {
             int idx = srcu_read_lock(&cn->transition_notifier_list.srcu);
             for ( b = cn->transition_notifier_list.head; b != NULL; b = b->next )
               count++;
             srcu_read_unlock(&cn->transition_notifier_list.srcu, idx);
           }
           mutex_unlock(m);
           goto copy_count;
         } else {
           ALLOC_KBUF(struct clk_ntfy, ptrbuf[2])
           mutex_lock(m);
           list_for_each_entry(cn, head, node)
           {
             if ( count >= ptrbuf[2] )
               break;
             else {
               int idx = srcu_read_lock(&cn->transition_notifier_list.srcu);
               for ( b = cn->transition_notifier_list.head; b != NULL && count < ptrbuf[2]; b = b->next, ++count )
               {
                 curr->clk = (unsigned long)cn;
                 curr->ntfy = (unsigned long)b->notifier_call;
                 ++curr;
               }
               srcu_read_unlock(&cn->transition_notifier_list.srcu, idx);
             }
           }
           mutex_unlock(m);
           kbuf_size = sizeof(unsigned long) + count * sizeof(struct clk_ntfy);
           // copy data to user-mode
           goto copy_kbuf_count;
         }
       }
     break; /* READ_DEVFREQ_NTFY */
#endif

    case IOCTL_ENUMSNTFYCHAIN:
     COPY_ARGS(2)
     if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
     else {
       struct notifier_block *b;
       unsigned long res = 0; // how many ntfy in reality
       struct srcu_notifier_head *nb = (struct srcu_notifier_head *)ptrbuf[0];
       count = ptrbuf[1];
       kbuf = (unsigned long *)kmalloc_array(count + 1, sizeof(unsigned long), GFP_KERNEL);
       if ( !kbuf ) return -ENOMEM;
       // lock
       mutex_lock(&nb->mutex);
       // traverse
       if ( nb->head != NULL )
       {
         for ( b = nb->head; (b != NULL) && (res < count); b = b->next )
         {
           kbuf[res + 1] = (unsigned long)b->notifier_call;
           res++;
         }
       }
       // unlock
       mutex_unlock(&nb->mutex);
       kbuf[0] = res;
       kbuf_size = (1 + res) * sizeof(unsigned long);
       goto copy_kbuf;
     }
     break; /* IOCTL_ENUMSNTFYCHAIN */

    case IOCTL_CNTSNTFYCHAIN:
      // copy address of srcu_notifier_head from user-mode
      COPY_ARG
      if ( !ptrbuf[0] ) return -EINVAL;
      else {
       struct srcu_notifier_head *nb = (struct srcu_notifier_head *)ptrbuf[0];
       struct notifier_block *b;
       // lock
       mutex_lock(&nb->mutex);
       // traverse
       if ( nb->head != NULL )
       {
          for ( b = nb->head; b != NULL; b = b->next )
            count++;
       }
       // unlock
       mutex_unlock(&nb->mutex);
       goto copy_count;
     }
     break; /* IOCTL_CNTSNTFYCHAIN */

    case IOCTL_INJECT:
      if ( !s_mprotect || !s_task_work_add || !s_my_task_work_cancel  ) return -ENOCSI;
      COPY_ARGS(3)
      else {
        int err = 0;
        struct pid *p = NULL;
        struct task_struct *task = NULL;
        if ( ptrbuf[0] )
        {
          // get task_struct
          p = find_get_pid((pid_t)(ptrbuf[0]));
          if ( !p) return -ESRCH;
          task = pid_task(p, PIDTYPE_PID);
        }
        // zero length - get state
        if ( !ptrbuf[1] )
        {
          err = get_inj_state(task, ptrbuf);
          if ( p ) put_pid(p);
          if ( err ) return err;
          kbuf_size = 3;
          goto copy_ptrbuf;
        }
        if ( 1 == ptrbuf[1] )
        {
          // cancel current inject request
          if ( !task ) err = -EINVAL;
          else err = cancel_inject(task);
          if ( p ) put_pid(p);
          return err;  
        }
        // yes, this is real inject request
        if ( !task ) err = -ESRCH;
        // check that tab offset + content lesser length 
        else if ( ptrbuf[3] + s_dtab_size >= ptrbuf[2] ) err = -EINVAL;
        else {
          // alloc and copy
          kbuf = kmalloc(ptrbuf[1], GFP_KERNEL);
          if ( !kbuf ) err = -ENOMEM;
          else if ( copy_from_user( (void*)kbuf, (void*)(ioctl_param + sizeof(unsigned long) * 3), ptrbuf[1]) > 0 ) err = -EFAULT;
          else err = submit_inject(task, ptrbuf[1], ptrbuf[2], (char *)kbuf);
          if ( err ) kfree(kbuf);
        }
        if ( p ) put_pid(p);
        return err;
      }
     break; /* IOCTL_INJECT */

    case IOCTL_TEST_MMAP:
      COPY_ARGS(2)
      else {
        unsigned long alloced = vm_mmap(NULL, 0, ptrbuf[0], ptrbuf[1], MAP_ANONYMOUS | MAP_PRIVATE, 0);
        if ( IS_ERR((void *)alloced) )
        {
          // printk("vm_mmap returned %ld", PTR_ERR((void *)alloced));
          return PTR_ERR((void *)alloced);
        }
        if ( copy_to_user((void*)ioctl_param, (void*)&alloced, sizeof(alloced)) > 0 ) return -EFAULT;
      }
     break; /* IOCTL_TEST_MMAP */

    case IOCTL_TEST_MPROTECT:
      if ( !s_mprotect ) return -ENOCSI;
      COPY_ARGS(3)
      else {
        int err = s_mprotect(ptrbuf[0], ptrbuf[1], ptrbuf[2], -1);
        if ( err ) return err;
      }
     break; /* IOCTL_TEST_MPROTECT */

    case IOCTL_TASK_WORKS:
      COPY_ARGS(2)
      if ((pid_t)(ptrbuf[0]) <= 0) return -EINVAL;
      if ( !ptrbuf[1] ) goto copy_count;
      else {
        unsigned long flags;
        struct task_struct *task;
        struct callback_head **pprev, *work;
        struct pid *p = find_get_pid((pid_t)(ptrbuf[0]));
        if ( !p) return -ESRCH;
        kbuf_size = sizeof(unsigned long) * (1 + ptrbuf[1]);
        kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
        if ( !kbuf ) return -ENOMEM;
        rcu_read_lock();
        task = pid_task(p, PIDTYPE_PID);
        if ( !task ) {
          rcu_read_unlock();
          kfree(kbuf);
          put_pid(p);
          return -ESRCH;
        }
        pprev = &task->task_works;
        raw_spin_lock_irqsave(&task->pi_lock, flags);
        while ((work = READ_ONCE(*pprev))) {
          if ( count >= ptrbuf[1] ) break;
          pprev = &work->next;
          kbuf[count + 1] = (unsigned long)work->func;
          count++;
        }
        raw_spin_unlock_irqrestore(&task->pi_lock, flags);
        rcu_read_unlock();
        put_pid(p);
        // copy to user
        kbuf_size = sizeof(unsigned long) * (1 + count);
        goto copy_kbuf_count;
      }
     break; /* IOCTL_TASK_WORKS */

    case IOCTL_TASK_INFO:
      COPY_ARG
      if ((pid_t)(ptrbuf[0]) <= 0) return -EINVAL;
      else {
        struct pid *p;
        p = find_get_pid((pid_t)(ptrbuf[0]));
        if ( !p) return -ESRCH;
        else {
          struct one_task_info ti;
          struct task_struct *task;
          struct callback_head **pprev, *work;
          unsigned long flags;
#ifdef CONFIG_PERF_EVENTS
          struct perf_event *event;
#endif

          rcu_read_lock();
          task = pid_task(p, PIDTYPE_PID);
          if ( !task ) {
            rcu_read_unlock();
            put_pid(p);
            return -ESRCH;
          }
          ti.addr = task;
          ti.sched_class = (void *)task->sched_class;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
          ti.restart_fn = (void *)task->restart_block.fn;
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
          ti.thread_flags = task->thread_info.flags;
#else
          ti.thread_flags = 0;
#endif
#ifdef CONFIG_IO_URING
          ti.io_uring = (void *)task->io_uring;
#else
          ti.io_uring = 0;
#endif
          ti.flags = task->flags;
          ti.ptrace = task->ptrace;
#if defined(CONFIG_X86_MCE) && LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
          ti.mce_kill_me = (void *)task->mce_kill_me.func;
#else
          ti.mce_kill_me = 0;
#endif
#ifdef CONFIG_SECCOMP
          ti.seccomp_filter = task->seccomp.filter;
#else
          ti.seccomp_filter = 0;
#endif
          ti.perf_event_cnt = 0;
#ifdef CONFIG_PERF_EVENTS
          ti.perf_event_ctxp = task->perf_event_ctxp;
          mutex_lock(&task->perf_event_mutex);
          list_for_each_entry(event, &task->perf_event_list, owner_entry) ti.perf_event_cnt++;
          mutex_unlock(&task->perf_event_mutex); 
#else
          ti.perf_event_ctxp = NULL;
#endif
          ti.works_count = 0;
          pprev = &task->task_works;
          raw_spin_lock_irqsave(&task->pi_lock, flags);
          while ((work = READ_ONCE(*pprev))) {
            pprev = &work->next;
            ti.works_count++;
          }
          raw_spin_unlock_irqrestore(&task->pi_lock, flags);
          rcu_read_unlock();
          put_pid(p);
          // copy to user
          if ( copy_to_user((void*)ioctl_param, (void*)&ti, sizeof(ti)) > 0 )
            return -EFAULT;
        }
      }
     break; /* IOCTL_TASK_INFO */

#ifdef CONFIG_TRACEPOINTS
    case IOCTL_TRACEV_CNT:
      COPY_ARGS(3)
      if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
      else
     {
       struct rw_semaphore *sem = (struct rw_semaphore *)ptrbuf[0];
       struct hlist_head *hash = (struct hlist_head *)ptrbuf[1];
       struct trace_event *event;
       hash += ptrbuf[2];
       // lock
       down_read(sem);
       // traverse
       hlist_for_each_entry(event, hash, node) {
         count++;
       }
       // unlock
       up_read(sem);
       goto copy_count;
     }
     break; /* IOCTL_TRACEV_CNT */

    case IOCTL_TRACEVENTS:
     COPY_ARGS(4)
     if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
     else {
       struct rw_semaphore *sem = (struct rw_semaphore *)ptrbuf[0];
       struct hlist_head *hash = (struct hlist_head *)ptrbuf[1];
       hash += ptrbuf[2];
       if ( !ptrbuf[3] ) return -EINVAL;
       else
       {
         struct trace_event *event;
         ALLOC_KBUF(struct one_trace_event, ptrbuf[3])
         // lock
         down_read(sem);
         // traverse
         hlist_for_each_entry(event, hash, node) {
           if ( count >= ptrbuf[3] )
             break;
           curr->addr = event;
           curr->type = event->type;
           if ( event->funcs )
           {
             curr->trace  = event->funcs->trace;
             curr->raw    = event->funcs->raw;
             curr->hex    = event->funcs->hex;
             curr->binary = event->funcs->binary;
           }
           // for next iteration
           curr++;
           count++;
         }
         // unlock
         up_read(sem);
         kbuf_size = sizeof(struct one_trace_event) * count + sizeof(unsigned long);
         goto copy_kbuf_count;
       }
     }
     break; /* IOCTL_TRACEVENTS */

    case IOCTL_MOD_TRACEPOINTS:
      COPY_ARGS(2)
      if ( !ptrbuf[1] ) goto copy_count;
      if ( s_vmalloc_or_module_addr && !s_vmalloc_or_module_addr((const void *)ptrbuf[0]) ) return -EFAULT;
      else {
        struct one_mod_tracepoint *curr;
        // tracepoint_ptr_t and tracepoint_ptr_deref were intriduced in 4.19
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
        tracepoint_ptr_t *begin = (tracepoint_ptr_t *)ptrbuf[0],
           *end = begin + ptrbuf[1], *iter;
#else
        struct tracepoint **begin = (struct tracepoint **)ptrbuf[0],
           **end = begin + ptrbuf[1], **iter;
#endif
        kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_mod_tracepoint);
        kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
        if ( !kbuf ) return -ENOMEM;
        curr = (struct one_mod_tracepoint *)(kbuf + 1);
        // lock
        if ( s_tracepoint_module_list_mutex ) mutex_lock(s_tracepoint_module_list_mutex);
        for ( iter = begin; count < ptrbuf[1] && iter < end; count++, curr++, iter++ )
        {
           struct tracepoint_func *func;
           struct tracepoint *tp =
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
             tracepoint_ptr_deref(iter);
#else
             *iter;
#endif
           curr->addr = tp;
           curr->enabled = atomic_read(&tp->key.enabled);
           curr->regfunc = (unsigned long)tp->regfunc;
           curr->unregfunc = (unsigned long)tp->unregfunc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
           curr->iterator = (unsigned long)tp->iterator;
#endif
           // lock
           if ( s_tracepoints_mutex )
             mutex_lock(s_tracepoints_mutex);
           else
             rcu_read_lock();
           func = tp->funcs;
           if ( func )
           do {
             curr->f_count++;
           } while((++func)->func);
           // unlock
           if ( s_tracepoints_mutex )
             mutex_unlock(s_tracepoints_mutex);
           else
             rcu_read_unlock();
         }
         // unlock
         if ( s_tracepoint_module_list_mutex ) mutex_unlock(s_tracepoint_module_list_mutex);
         // copy to usermode
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_mod_tracepoint);
         goto copy_kbuf_count;
      }
     break; /* IOCTL_MOD_TRACEPOINTS */

    case IOCTL_TRACEPOINT_INFO:
     COPY_ARG
     else
     {
       struct tracepoint *tp = (struct tracepoint *)ptrbuf[0];
       struct tracepoint_func *func;
       ptrbuf[0] = atomic_read(&tp->key.enabled);
       ptrbuf[1] = (unsigned long)tp->regfunc;
       ptrbuf[2] = (unsigned long)tp->unregfunc;
       ptrbuf[3] = 0;
       // lock
       if ( s_tracepoints_mutex )
         mutex_lock(s_tracepoints_mutex);
       else
         rcu_read_lock();
       func = tp->funcs;
       if ( func )
        do {
          ptrbuf[3]++;
        } while((++func)->func);
       // unlock
       if ( s_tracepoints_mutex )
         mutex_unlock(s_tracepoints_mutex);
       else
         rcu_read_unlock();
       // copy to usermode
       kbuf_size = 4;
       goto copy_ptrbuf;
     }
     break; /* IOCTL_TRACEPOINT_INFO */

    case IOCTL_TRACEPOINT_FUNCS:
     COPY_ARGS(2)
     {
       struct tracepoint *tp = (struct tracepoint *)ptrbuf[0];
       struct tracepoint_func *func;
       unsigned long res = 0;
       struct one_tracepoint_func *curr;

       count = ptrbuf[1];
       if ( !ptrbuf[1] ) goto copy_count;
       if ( !tp ) return -EINVAL;

       kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_tracepoint_func);
       kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
       if ( !kbuf ) return -ENOMEM;
       curr = (struct one_tracepoint_func *)(kbuf + 1);

       // lock
       if ( s_tracepoints_mutex )
         mutex_lock(s_tracepoints_mutex);
       else
         rcu_read_lock();
       func = tp->funcs;
       if ( func )
        do {
          if ( res >= count )
            break;
          curr->addr = (unsigned long)func->func;
          curr->data = (unsigned long)func->data;
          // for next iteration
          res++;
          curr++;
        } while((++func)->func);
       // unlock
       if ( s_tracepoints_mutex )
         mutex_unlock(s_tracepoints_mutex);
       else
         rcu_read_unlock();

       kbuf[0] = res;
       kbuf_size = sizeof(unsigned long) + res * sizeof(struct one_tracepoint_func);
       // copy to usermode
       goto copy_kbuf;
     }
     break; /* IOCTL_TRACEPOINT_FUNCS */
#endif /* CONFIG_TRACEPOINTS */

    case IOCTL_BUS_NTFY:
      if ( krnf_node_ptr == NULL ) return -EFAULT;
      COPY_ARG
      else if ( !ptrbuf[0] ) break;
      else {
        char name[BUFF_SIZE]; // input file name
        struct file *file;
        struct subsys_private *sp;
        struct notifier_block *b;
        int err;
        read_user_string(name, ioctl_param + sizeof(unsigned long));
        // open file
        file = file_open(name, 0, 0, &err);
        if ( NULL == file )
        {
          printk(KERN_INFO "[lkcd] cannot open file %s, error %d\n", name, err);
          return err;
        }
        err = extract_sp(file, &sp);
        if ( err )
        {
          file_close(file);
          return err;
        }
        if ( !sp->bus_notifier.head )
        {
          file_close(file);
          ptrbuf[0] = 0;
          goto copy_ptrbuf0;
        }
        // they really have some notifiers
        kbuf_size = (1 + ptrbuf[0]) * sizeof(unsigned long);
        kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
        if ( !kbuf )
        {
          file_close(file);
          return -ENOMEM;
        }
        down_read(&sp->bus_notifier.rwsem);
        for ( b = sp->bus_notifier.head; b != NULL; b = b->next )
        {
          if ( count >= ptrbuf[0] ) break;
          kbuf[count + 1] = (unsigned long)b->notifier_call;
          count++;
        }
        up_read(&sp->bus_notifier.rwsem);
        // done
        file_close(file);
        kbuf_size = (1 + count) * sizeof(unsigned long);
        goto copy_kbuf_count;
      }
     break; /* IOCTL_BUS_NTFY */

    case IOCTL_READ_BUS:
      if ( krnf_node_ptr == NULL ) return -EFAULT;
      else {
       union {
         char name[BUFF_SIZE]; // input file name
         struct one_priv p;    // output data - just to save stack space it shares memory with name
       } u;
       struct file *file;
       struct subsys_private *sp;
       int err;
       read_user_string(u.name, ioctl_param);
       // open file
       file = file_open(u.name, 0, 0, &err);
       if ( NULL == file )
       {
         printk(KERN_INFO "[lkcd] cannot open file %s, error %d\n", u.name, err);
         return err;
       }
       err = extract_sp(file, &sp);
       if ( err )
       {
         file_close(file);
         return err;
       }
       u.p.uevent_ops = (void *)sp->subsys.uevent_ops;
       if ( u.p.uevent_ops )
       {
         u.p.filter = sp->subsys.uevent_ops->filter;
         u.p.name   = sp->subsys.uevent_ops->name;
         u.p.uevent = sp->subsys.uevent_ops->uevent;
       } else u.p.filter = u.p.name = u.p.uevent = 0;
       u.p.bus = (void *)sp->bus;
       if ( u.p.bus )
       {
         u.p.match = sp->bus->match;
         u.p.bus_uevent = sp->bus->uevent;
         u.p.probe = sp->bus->probe;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
         u.p.sync_state = sp->bus->sync_state;
#else
         u.p.sync_state = 0;
#endif
         u.p.remove = sp->bus->remove;
         u.p.shutdown = sp->bus->shutdown;
         u.p.online = sp->bus->online;
         u.p.offline = sp->bus->offline;
         u.p.suspend = sp->bus->suspend;
         u.p.resume = sp->bus->resume;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
         u.p.num_vf = sp->bus->num_vf;
#else
         u.p.num_vf = 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
         u.p.dma_configure = sp->bus->dma_configure;
#else
         u.p.dma_configure = 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,19,0)
         u.p.dma_cleanup = sp->bus->dma_cleanup;
#else
         u.p.dma_cleanup = 0;
#endif
         u.p.pm = (void *)sp->bus->pm;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,8,0)
         u.p.iommu_ops = (void *)sp->bus->iommu_ops;
#else
         u.p.iommu_ops = 0;
#endif
       }
       u.p._class = (void *)sp->class;
       if ( u.p._class )
       {
        u.p.dev_uevent = sp->class->dev_uevent;
        u.p.devnode = sp->class->devnode;
        u.p.class_release = sp->class->class_release;
        u.p.dev_release = sp->class->dev_release;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
        u.p.c_susped = sp->class->suspend;
        u.p.c_resume = sp->class->resume;
#else
        u.p.c_susped = u.p.c_resume = 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,10)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
        u.p.c_shutdown = sp->class->shutdown_pre;
#else
        u.p.c_shutdown = sp->class->shutdown;
#endif
#else
        u.p.c_shutdown = 0;
#endif
        u.p.c_ns_type = (void *)sp->class->ns_type;
        u.p.c_namespace = sp->class->namespace;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
        u.p.c_getownership = sp->class->get_ownership;
#else
        u.p.c_getownership = 0;
#endif
       }
       // calc notifiers
       u.p.ntfy_cnt = 0;
       if ( sp->bus_notifier.head )
       {
        struct notifier_block *b;
        down_read(&sp->bus_notifier.rwsem);
        for ( b = sp->bus_notifier.head; b != NULL; b = b->next )
          u.p.ntfy_cnt++;
        up_read(&sp->bus_notifier.rwsem);
       }
       // done
       file_close(file);
       if (copy_to_user((void*)ioctl_param, (void*)&u.p, sizeof(u.p)) > 0)
         return -EFAULT;
     }
     break; /* IOCTL_READ_BUS */

    case IOCTL_KERNFS_NODE:
     if ( krnf_node_ptr == NULL ) return -EFAULT;
     else
     {
       char name[BUFF_SIZE];
       struct file *file;
       struct kernfs_node *k;
       struct kobject *kobj = NULL;
       int err, i;
       if ( krnf_node_ptr == NULL )
         return -EFAULT;
       read_user_string(name, ioctl_param);
       // open file
       file = file_open(name, 0, 0, &err);
       if ( NULL == file )
       {
         printk(KERN_INFO "[lkcd] cannot open file %s, error %d\n", name, err);
         return err;
       }
       k = krnf_node_ptr(file->f_path.dentry);
       ptrbuf[0] = (unsigned long)k;
       for ( i = 1; i < 13; ++i ) ptrbuf[i] = 0;
       if ( k )
       {
         ptrbuf[7] = k->flags;
         ptrbuf[8] = (unsigned long)k->priv;
         if (k->flags & KERNFS_FILE)
           kobj = k->parent->priv;
         else if ( k->flags & KERNFS_DIR )
           kobj = k->priv;
         ptrbuf[1] = (unsigned long)kobj;
         if ( kobj )
         {
           ptrbuf[2] = (unsigned long)kobj->ktype;
           if ( kobj->ktype )
           {
             ptrbuf[3] = (unsigned long)kobj->ktype->sysfs_ops;
             if ( kobj->ktype->sysfs_ops )
             {
               ptrbuf[4] = (unsigned long)kobj->ktype->sysfs_ops->show;
               ptrbuf[5] = (unsigned long)kobj->ktype->sysfs_ops->store;
             }
             ptrbuf[9] = (unsigned long)kobj->ktype->release;
             ptrbuf[10] = (unsigned long)kobj->ktype->child_ns_type;
             ptrbuf[11] = (unsigned long)kobj->ktype->namespace;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,0)
             ptrbuf[12] = (unsigned long)kobj->ktype->get_ownership;
#else
             ptrbuf[12] = 0;
#endif
           }
         }
       } else if ( !k ) 
       {
         struct inode *node = file->f_path.dentry->d_inode;
         ptrbuf[6] = (unsigned long)file->f_path.dentry->d_sb->s_op;
         ptrbuf[7] = (unsigned long)node;
         if ( node )
         {
           int is_dbg = is_dbgfs(node->i_fop);
           ptrbuf[8] = (unsigned long)node->i_fop;
           if ( is_dbg )
           {
             struct seq_file *seq = (struct seq_file *)file->private_data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
             ptrbuf[2] = (unsigned long)debugfs_real_fops(file);
#else
             ptrbuf[2] = 0;
#endif
             if ( seq && S_ISREG(file->f_path.dentry->d_inode->i_mode) )
               ptrbuf[3] = (unsigned long)seq->op;
           }
         }
       }

       file_close(file);
       kbuf_size = 13;
       goto copy_ptrbuf;
      }
     break; /* IOCTL_KERNFS_NODE */

#if defined(CONFIG_FSNOTIFY) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
     case IOCTL_GET_INODE_MARKS:
       if ( !iterate_supers_ptr )
         return -ENOCSI;
       COPY_ARGS(3)
       // check size
       if ( !ptrbuf[2] )
         return -EINVAL;
       else {
         struct inode_mark_args args;
         kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_fsnotify);
         // fill inode_mark_args
         args.sb_addr    = (void *)ptrbuf[0];
         args.inode_addr = (void *)ptrbuf[1];
         args.cnt        = ptrbuf[2];
         args.found      = 0;
         args.curr = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !args.curr )
           return -ENOMEM;
         args.data = (struct one_fsnotify *)(args.curr + 1);
         args.curr[0] = 0;
         iterate_supers_ptr(fill_inode_marks, (void*)&args);
         if ( args.found != 3 )
         {
           kfree(args.curr);
           return -ENOENT;
         }
         kbuf_size = sizeof(unsigned long) + args.curr[0] * sizeof(struct one_fsnotify);
         if (copy_to_user((void*)ioctl_param, (void*)args.curr, kbuf_size) > 0)
         {
           kfree(args.curr);
           return -EFAULT;
         }
         kfree(args.curr);
       }
       break; /* IOCTL_GET_INODE_MARKS */

     case IOCTL_GET_SUPERBLOCK_MARKS:
         if ( !iterate_supers_ptr )
           return -ENOCSI;
         COPY_ARGS(2)
         if ( !ptrbuf[1] )
         {
           struct super_mark_args sbargs = {
            .sb_addr = (void *)ptrbuf[0],
            .cnt = 0,
            .found = 0,
           };
           iterate_supers_ptr(count_superblock_marks, (void*)&sbargs);
           if ( !sbargs.found )
             return -ENOENT;
           // copy result to user
           if (copy_to_user((void*)ioctl_param, (void*)&sbargs.cnt, sizeof(sbargs.cnt)) > 0)
             return -EFAULT;
         } else {
           struct super_mark_args sbargs;
           kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_fsnotify);
           // fill inode_mark_args
           sbargs.sb_addr    = (void *)ptrbuf[0];
           sbargs.cnt        = ptrbuf[1];
           sbargs.found      = 0;
           sbargs.curr = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
           if ( !sbargs.curr )
             return -ENOMEM;
           sbargs.data = (struct one_fsnotify *)(sbargs.curr + 1);
           sbargs.curr[0] = 0;
           iterate_supers_ptr(fill_superblock_marks, (void*)&sbargs);
           if ( !sbargs.found  )
           {
             kfree(sbargs.curr);
             return -ENOENT;
           }
           kbuf_size = sizeof(unsigned long) + sbargs.curr[0] * sizeof(struct one_fsnotify);
           if (copy_to_user((void*)ioctl_param, (void*)sbargs.curr, kbuf_size) > 0)
           {
             kfree(sbargs.curr);
             return -EFAULT;
           }
           kfree(sbargs.curr);
         }
       break; /* IOCTL_GET_SUPERBLOCK_MARKS */

     case IOCTL_GET_MOUNT_MARKS:
       if ( !iterate_supers_ptr || !mount_lock)
         return -ENOCSI;
       COPY_ARGS(3)
       // check size
       if ( !ptrbuf[2] )
         return -EINVAL;
       else {
         struct inode_mark_args args;
         kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_fsnotify);
         // fill inode_mark_args
         args.sb_addr    = (void *)ptrbuf[0];
         args.inode_addr = (void *)ptrbuf[1]; // mnt address actually but I am too lazy to add new structure
         args.cnt        = ptrbuf[2];
         args.found      = 0;
         args.curr = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !args.curr )
           return -ENOMEM;
         args.data = (struct one_fsnotify *)(args.curr + 1);
         args.curr[0] = 0;
         iterate_supers_ptr(fill_mount_marks, (void*)&args);
         if ( args.found != 3 )
         {
           kfree(args.curr);
           return -ENOENT;
         }
         kbuf_size = sizeof(unsigned long) + args.curr[0] * sizeof(struct one_fsnotify);
         if (copy_to_user((void*)ioctl_param, (void*)args.curr, kbuf_size) > 0)
         {
           kfree(args.curr);
           return -EFAULT;
         }
         kfree(args.curr);
       }
      break; /* IOCTL_GET_MOUNT_MARKS */
#endif /* CONFIG_FSNOTIFY */

     case IOCTL_GET_SUPERBLOCK_INODES:
       if ( !iterate_supers_ptr ) return -ENOCSI;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
       if ( !s_inode_sb_list_lock ) return -ENOCSI;
#endif
       COPY_ARGS(2)
       // check size
       if ( !ptrbuf[1] )
         return -EINVAL;
       else {
         struct super_inodes_args sargs;
         kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_inode);
         // fill super_inodes_args
         sargs.sb_addr = (void *)ptrbuf[0];
         sargs.cnt     = ptrbuf[1];
         sargs.found   = 0;
         sargs.curr = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !sargs.curr )
           return -ENOMEM;
         sargs.data = (struct one_inode *)(sargs.curr + 1);
         sargs.curr[0] = 0;
         iterate_supers_ptr(fill_super_block_inodes, (void*)&sargs);
         if ( !sargs.found )
         {
           kfree(sargs.curr);
           return -ENOENT;
         }
         kbuf_size = sizeof(unsigned long) + sargs.curr[0] * sizeof(struct one_inode);
         if (copy_to_user((void*)ioctl_param, (void*)sargs.curr, kbuf_size) > 0)
         {
           kfree(sargs.curr);
           return -EFAULT;
         }
         kfree(sargs.curr);
       }
      break; /* IOCTL_GET_SUPERBLOCK_INODES */

     case IOCTL_GET_SUPERBLOCK_MOUNTS:
       if ( !iterate_supers_ptr || !mount_lock)
         return -ENOCSI;
       COPY_ARGS(2)
       // check size
       if ( !ptrbuf[1] )
         return -EINVAL;
       else {
         struct super_mount_args sargs;
         kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_mount);
         // fill super_inodes_args
         sargs.sb_addr = (void *)ptrbuf[0];
         sargs.cnt     = ptrbuf[1];
         sargs.found   = 0;
         sargs.curr = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !sargs.curr )
           return -ENOMEM;
         sargs.data = (struct one_mount *)(sargs.curr + 1);
         sargs.curr[0] = 0;
         iterate_supers_ptr(fill_super_block_mounts, (void*)&sargs);
         if ( !sargs.found )
         {
           kfree(sargs.curr);
           return -ENOENT;
         }
         kbuf_size = sizeof(unsigned long) + sargs.curr[0] * sizeof(struct one_mount);
         if (copy_to_user((void*)ioctl_param, (void*)sargs.curr, kbuf_size) > 0)
         {
           kfree(sargs.curr);
           return -EFAULT;
         }
         kfree(sargs.curr);
       }
      break; /* IOCTL_GET_SUPERBLOCK_MOUNTS */

     case IOCTL_GET_SUPERBLOCKS:
       if ( !iterate_supers_ptr ) return -EFAULT;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
       if ( !s_inode_sb_list_lock ) return -ENOCSI;
#endif
       COPY_ARG 
       if ( !ptrbuf[0] )
       {
         ptrbuf[0] = 0;
         iterate_supers_ptr(count_super_blocks, (void*)ptrbuf);
         goto copy_ptrbuf0;
       } else {
         struct super_args sargs;
         size_t ksize = sizeof(unsigned long) + ptrbuf[0] * sizeof(struct one_super_block);
         sargs.cnt = ptrbuf[0];
         sargs.curr = (unsigned long *)kmalloc(ksize, GFP_KERNEL);
         if ( !sargs.curr )
           return -ENOMEM;
         sargs.data = (struct one_super_block *)(sargs.curr + 1);
         sargs.curr[0] = 0;
         iterate_supers_ptr(fill_super_blocks, (void*)&sargs);
         ksize = sizeof(unsigned long) + sargs.curr[0] * sizeof(struct one_super_block);
         if (copy_to_user((void*)ioctl_param, (void*)sargs.curr, ksize) > 0)
         {
           kfree(sargs.curr);
           return -EFAULT;
         }
         kfree(sargs.curr);
       }
      break; /* IOCTL_GET_SUPERBLOCKS */

#ifdef CONFIG_UPROBES
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
     case IOCTL_TRACE_UPROBE_BPFS:
        if ( !bpf_prog_array_length_ptr )
          return -ENOCSI;
        COPY_ARGS(5)
        else {
          struct rb_root *root = (struct rb_root *)ptrbuf[0];
          spinlock_t *lock = (spinlock_t *)ptrbuf[1];
          struct trace_uprobe *tup = NULL;
          struct rb_node *iter;
          kbuf_size = (1 + ptrbuf[4]) * sizeof(unsigned long);
          kbuf = (unsigned long *)kzalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          // lock
          spin_lock(lock);
          for ( iter = rb_first(root); iter != NULL; iter = rb_next(iter) )
          {
            struct uprobe_consumer *con;
            struct und_uprobe *up = rb_entry(iter, struct und_uprobe, rb_node);
            if ( (unsigned long)up != ptrbuf[2] )
              continue;
            down_read(&up->consumer_rwsem);
            for (con = up->consumers; con; con = con->next )
            {
              if ( (unsigned long)con != ptrbuf[3] )
                continue;
              tup = container_of(con, struct trace_uprobe, consumer);
              break;
            }
            if ( tup != NULL )
              copy_trace_bpfs(&tup->tp.event->call, ptrbuf[4], kbuf);
            up_read(&up->consumer_rwsem);
            break;
          }
          // unlock
          spin_unlock(lock);
          if ( tup == NULL )
          {
            kfree(kbuf);
            return -ENOENT;
          }
          // copy to usermode
          goto copy_kbuf;
        }
       break; /* IOCTL_TRACE_UPROBE_BPFS */
#endif

     case IOCTL_TRACE_UPROBE:
        COPY_ARGS(4)
        else {
          struct rb_root *root = (struct rb_root *)ptrbuf[0];
          spinlock_t *lock = (spinlock_t *)ptrbuf[1];
          struct trace_uprobe *tup = NULL;
          struct rb_node *iter;
          struct one_trace_event_call buf;
          // lock
          spin_lock(lock);
          for ( iter = rb_first(root); iter != NULL; iter = rb_next(iter) )
          {
            struct uprobe_consumer *con;
            struct und_uprobe *up = rb_entry(iter, struct und_uprobe, rb_node);
            if ( (unsigned long)up != ptrbuf[2] )
              continue;
            down_read(&up->consumer_rwsem);
            for (con = up->consumers; con; con = con->next )
            {
              if ( (unsigned long)con != ptrbuf[3] )
                continue;
              tup = container_of(con, struct trace_uprobe, consumer);
              break;
            }
            if ( tup != NULL )
              copy_trace_event_call(&tup->tp.event->call, &buf);
            up_read(&up->consumer_rwsem);
            break;
          }
          // unlock
          spin_unlock(lock);
          if ( tup == NULL )
            return -ENOENT;
          // copy to usermode
          if (copy_to_user((void*)ioctl_param, (void*)&buf, sizeof(buf)) > 0)
            return -EFAULT;
        }
       break; /* IOCTL_TRACE_UPROBE */

     case IOCTL_UPROBES_CONS:
       COPY_ARGS(4)
       // 2 - uprobe, 3 - size
       if ( !ptrbuf[3] )
         return -EINVAL;
       else {
         struct rb_root *root = (struct rb_root *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct rb_node *iter;
         int found = 0;
         ALLOC_KBUF(struct one_uprobe_consumer, ptrbuf[3])
         // lock
         spin_lock(lock);
         // traverse tree
         for ( iter = rb_first(root); iter != NULL; iter = rb_next(iter) )
         {
           struct uprobe_consumer *con;
           struct und_uprobe *up = rb_entry(iter, struct und_uprobe, rb_node);
           if ( (unsigned long)up != ptrbuf[2] )
             continue;
           found++;
           down_read(&up->consumer_rwsem);
           for (con = up->consumers; con && count < ptrbuf[3]; con = con->next, count++)
           {
             curr[count].addr        = (void *)con;
             curr[count].handler     = con->handler;
             curr[count].ret_handler = con->ret_handler;
             curr[count].filter      = con->filter;
           }
           up_read(&up->consumer_rwsem);
           // bcs we processing only one uprobe and it is found - no sense to continue tree traversal
           break;
         }
         // unlock
         spin_unlock(lock);
         if ( !found )
         {
           kfree(kbuf);
           return -ENOENT;
         }
         // copy to user
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_uprobe_consumer);
         goto copy_kbuf_count;
       }
       break; /* IOCTL_UPROBES_CONS */

     case IOCTL_UPROBES:
       COPY_ARGS(3)
       if ( !ptrbuf[2] ) {
         // calc count of uprobes
         struct rb_root *root = (struct rb_root *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct rb_node *iter;
         // lock
         spin_lock(lock);
         // traverse tree
         for ( iter = rb_first(root); iter != NULL; iter = rb_next(iter) )
           count++;
         // unlock
         spin_unlock(lock);
         goto copy_count;
       } else {
         struct rb_root *root = (struct rb_root *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct rb_node *iter;
         ALLOC_KBUF(struct one_uprobe, ptrbuf[2])
         // lock
         spin_lock(lock);
         // traverse tree
         for ( iter = rb_first(root); iter != NULL && count < ptrbuf[2]; iter = rb_next(iter), count++ )
         {
           copy1uprobe(rb_entry(iter, struct und_uprobe, rb_node), &curr[count]);
         }
         // unlock
         spin_unlock(lock);
         // copy to user
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_uprobe);
         goto copy_kbuf_count;
      }
      break; /* IOCTL_UPROBES */

     case IOCTL_DELAYED_UPROBES:
       COPY_ARG
       if ( !s_delayed_uprobe_list || !s_delayed_uprobe_lock ) return -ENOCSI;
       if ( !ptrbuf[0] ) {
         // calc count of delayed uprobes
         struct delayed_uprobe *du;
         mutex_lock(s_delayed_uprobe_lock);
         list_for_each_entry(du, s_delayed_uprobe_list, list) {
          if ( du->uprobe ) count++;
         }
         mutex_unlock(s_delayed_uprobe_lock);
         goto copy_count;
       } else {
         struct delayed_uprobe *du;
         ALLOC_KBUF(struct one_uprobe, ptrbuf[0])
         // lock
         mutex_lock(s_delayed_uprobe_lock);
         // traverse
         list_for_each_entry(du, s_delayed_uprobe_list, list) {
          if ( count >= ptrbuf[0] ) break;
          if ( du->uprobe )
            copy1uprobe(du->uprobe, &curr[count]);
         }
         // unlock
         mutex_unlock(s_delayed_uprobe_lock);
         // copy to user
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_uprobe);
         goto copy_kbuf_count;
       }
      break;

     case IOCTL_TEST_UPROBE:
       COPY_ARG
       if ( ptrbuf[0] && !debuggee_inode )
       {
         int ret;
	 struct path path;
	 ret = kern_path("/usr/bin/ls", LOOKUP_FOLLOW, &path);
	 if (ret)
	   return ret;
         debuggee_inode = igrab(path.dentry->d_inode);
	 path_put(&path);
         ret = uprobe_register(debuggee_inode, DEBUGGEE_FILE_OFFSET, &s_uc);
	 if (ret < 0)
	   return ret;
       }
       if ( !ptrbuf[0] && debuggee_inode )
       {
         uprobe_unregister(debuggee_inode, DEBUGGEE_FILE_OFFSET, &s_uc);
         debuggee_inode = 0;
       }
      break; /* IOCTL_TEST_UPROBE */
#endif /* CONFIG_UPROBES */

#ifdef CONFIG_KPROBES
     case IOCTL_TEST_KPROBE:
       COPY_ARG
       if ( ptrbuf[0] && !test_kprobe_installed )
       {
          int ret = register_kprobe(&test_kp);
          if ( ret )
          {
            printk(KERN_INFO "[lkcd] register_kprobe failed, returned %d\n", ret);
            return ret;
          }
          test_kprobe_installed = 1;
          printk(KERN_INFO "[lkcd] test kprobe installed at %p\n", test_kp.addr);
       }
       if ( !ptrbuf[0] && test_kprobe_installed )
       {
         unregister_kprobe(&test_kp);
         test_kprobe_installed = 0;
       }
      break; /* IOCTL_TEST_KPROBE */

     case IOCTL_KPROBE_DISABLE:
       COPY_ARGS(5)
       else {
         struct hlist_head *head;
         struct mutex *m = (struct mutex *)ptrbuf[1];
         struct kprobe *p;
         long found = 0;
         if ( ptrbuf[2] >= KPROBE_TABLE_SIZE )
           return -EFBIG;
         // lock
         mutex_lock(m);
         head = (struct hlist_head *)ptrbuf[0] + ptrbuf[2];
         // traverse
         hlist_for_each_entry(p, head, hlist)
         {
           if ( (unsigned long)p != ptrbuf[3] )
           {
             struct kprobe *kp;
             if ( !is_krpobe_aggregated(p) )
               continue;
             list_for_each_entry_rcu(kp, &p->list, list)
             {
               if ( (unsigned long)kp == ptrbuf[3] )
               {
                 found = 1;
                 patch_kprobe(kp, ptrbuf[4]);
                 break;
               }
             }
             if ( found )
               break;
           } else {
             found = 1;
             patch_kprobe(p, ptrbuf[4]);
             break;
           }
         }
         // unlock
         mutex_unlock(m);
         // copy to user
         if (copy_to_user((void*)ioctl_param, (void*)&found, sizeof(found)) > 0)
           return -EFAULT;
       }
      break; /* IOCTL_KPROBE_DISABLE */

     case IOCTL_CNT_KPROBE_BUCKET:
       COPY_ARGS(3)
       else {
         struct hlist_head *head;
         struct mutex *m = (struct mutex *)ptrbuf[1];
         struct kprobe *p;
         if ( ptrbuf[2] >= KPROBE_TABLE_SIZE )
           return -EFBIG;
         // lock
         mutex_lock(m);
         head = (struct hlist_head *)ptrbuf[0] + ptrbuf[2];
         // traverse
         hlist_for_each_entry(p, head, hlist)
           count++;
         // unlock
         mutex_unlock(m);
         goto copy_count;
       }
      break; /* IOCTL_CNT_KPROBE_BUCKET */

     case IOCTL_KPROBES_BLACKLIST:
       if ( !s_kprobe_blacklist ) return -ENOCSI;
       COPY_ARGS(2)
       if ( !ptrbuf[0] ) return -EINVAL;
       else if ( !ptrbuf[1] )
       { // calc count
         struct mutex *m = (struct mutex *)ptrbuf[0];
         struct kprobe_blacklist_entry *ent;
         mutex_lock(m);
         list_for_each_entry(ent, s_kprobe_blacklist, list)
           count++;
         mutex_unlock(m);
         goto copy_count;
       } else {
         struct mutex *m = (struct mutex *)ptrbuf[0];
         struct kprobe_blacklist_entry *ent;
         ALLOC_KBUF(struct one_bl_kprobe, ptrbuf[1])
         // lock
         mutex_lock(m);
         list_for_each_entry(ent, s_kprobe_blacklist, list)
         {
           if ( count >= ptrbuf[1] ) break;
           curr->start = ent->start_addr;
           curr->end = ent->end_addr;
           count++; curr++;
         }
         // unlock
         mutex_unlock(m);
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_bl_kprobe);
         goto copy_kbuf_count;
       }
      break;

     case IOCTL_GET_AGGR_KPROBE:
       COPY_ARGS(5)
       else {
         struct hlist_head *head;
         struct kprobe *p, *kp;
         struct mutex *m = (struct mutex *)ptrbuf[1];
         int found = 0;
         if ( ptrbuf[2] >= KPROBE_TABLE_SIZE )
           return -EFBIG;
         if ( !ptrbuf[3] )
           break;
         head = (struct hlist_head *)ptrbuf[0] + ptrbuf[2];
         // check if we need just count
         if ( !ptrbuf[4] )
         {
           // lock
           mutex_lock(m);
           // traverse
           hlist_for_each_entry(p, head, hlist)
           {
             if ( (unsigned long)p != ptrbuf[3] )
               continue;
             found++;
             if ( !is_krpobe_aggregated(p) )
               break;
             list_for_each_entry_rcu(kp, &p->list, list)
             {
               count++;
             }
             break;
           }
           // unlock
           mutex_unlock(m);
           if ( !found )
             return -ENOENT;
           goto copy_count;
         } else {
            struct one_kprobe *out_buf;
            unsigned long curr = 0;
            kbuf_size = sizeof(unsigned long) + ptrbuf[4] * sizeof(struct one_kprobe);
            kbuf = (unsigned long *)kzalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !kbuf )
              return -ENOMEM;
            out_buf = (struct one_kprobe *)(kbuf + 1);
            // lock
            mutex_lock(m);
            // traverse
            hlist_for_each_entry(p, head, hlist)
            {
              if ( (unsigned long)p != ptrbuf[3] )
                continue;
              if ( !is_krpobe_aggregated(p) )
                break;
              found++;
              // found our aggregated krobe
              list_for_each_entry_rcu(kp, &p->list, list)
              {
                if ( curr >= ptrbuf[4] )
                  break;
                out_buf[curr].kaddr = (void *)kp;
                out_buf[curr].addr = (void *)kp->addr;
                out_buf[curr].pre_handler = (void *)kp->pre_handler;
                out_buf[curr].post_handler = (void *)kp->post_handler;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
                out_buf[curr].fault_handler = (void *)kp->fault_handler;
#endif
                out_buf[curr].flags = (unsigned int)kp->flags;
                out_buf[curr].is_aggr = is_krpobe_aggregated(kp);
                // check for kretprobe
                if ( !out_buf[curr].is_aggr && kp->pre_handler == k_pre_handler_kretprobe )
                {
                  struct kretprobe *rkp = container_of(kp, struct kretprobe, kp);
                  out_buf[curr].is_retprobe = 1;
                  if ( rkp )
                  {
                    out_buf[curr].kret_handler = rkp->handler;
                    out_buf[curr].kret_entry_handler = rkp->entry_handler;
                  }
                }
                curr++;
              }
              break;
            }
            // unlock
            mutex_unlock(m);
            if ( !found )
            {
              kfree(kbuf);
              return -ENOENT;
            }
            kbuf[0] = curr;
            // copy to user
            goto copy_kbuf;
         }
       }
      break; /* IOCTL_GET_AGGR_KPROBE */

     case IOCTL_GET_KPROBE_BUCKET:
       COPY_ARGS(4)
       else {
         if ( ptrbuf[2] >= KPROBE_TABLE_SIZE )
           return -EFBIG;
         if ( !ptrbuf[3] )
           break;
         // alloc enough memory
         kbuf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_kprobe);
         kbuf = (unsigned long *)kzalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
         if ( !kbuf )
           return -ENOMEM;
         else {
           struct hlist_head *head;
           struct kprobe *p;
           unsigned long curr = 0;
           struct mutex *m = (struct mutex *)ptrbuf[1];
           struct one_kprobe *out_buf = (struct one_kprobe *)(kbuf + 1);
           // lock
           mutex_lock(m);
           head = (struct hlist_head *)ptrbuf[0] + ptrbuf[2];
           // traverse
           hlist_for_each_entry(p, head, hlist)
           {
             if ( curr >= ptrbuf[3] )
               break;
             out_buf[curr].kaddr = (void *)p;
             out_buf[curr].addr = (void *)p->addr;
             out_buf[curr].pre_handler = (void *)p->pre_handler;
             out_buf[curr].post_handler = (void *)p->post_handler;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,14,0)
             out_buf[curr].fault_handler = (void *)p->fault_handler;
#endif
             out_buf[curr].flags = (unsigned int)p->flags;
             out_buf[curr].is_aggr = is_krpobe_aggregated(p);
             // check for kretprobe
             if ( !out_buf[curr].is_aggr && out_buf[curr].pre_handler == k_pre_handler_kretprobe )
             {
                  struct kretprobe *rkp = container_of(p, struct kretprobe, kp);
                  out_buf[curr].is_retprobe = 1;
                  if ( rkp )
                  {
                    out_buf[curr].kret_handler = rkp->handler;
                    out_buf[curr].kret_entry_handler = rkp->entry_handler;
                  }
             }
             curr++;
           }
           // unlock
           mutex_unlock(m);
           // store count of processed
           kbuf[0] = curr;
           // copy to user
           goto copy_kbuf;
         }
       }
      break; /* IOCTL_GET_KPROBE_BUCKET */
#endif /* CONFIG_KPROBES */

#ifdef CONFIG_USER_RETURN_NOTIFIER
     case IOCTL_TEST_URN:
       COPY_ARG
       if ( ptrbuf[0] && !urn_installed )
       {
         user_return_notifier_register(&s_urn);
         urn_installed++;
       }
       if ( !ptrbuf[0] && urn_installed )
       {
         user_return_notifier_unregister(&s_urn);
         urn_installed = 0;
       }
       break; /* IOCTL_TEST_URN */

     case IOCTL_CNT_RNL_PER_CPU:
      COPY_ARGS(3)
      else
      {
        int err;
        unsigned long cpu_n = ptrbuf[0];
        err = smp_call_function_single(cpu_n, count_lrn, (void*)ptrbuf, 1);
        if ( err )
        {
          printk(KERN_INFO "[+] IOCTL_CNT_RNL_PER_CPU on cpu %ld failed, error %d\n", cpu_n, err);
          return err;
        }
        // copy result back to user-space
        kbuf_size = 2;
        goto copy_ptrbuf;
       }
      break; /* IOCTL_CNT_RNL_PER_CPU */

     case IOCTL_RNL_PER_CPU:
      COPY_ARGS(4)
      else
      {
        struct urn_params params;
        params.out_data = NULL;
        // check size
        if ( !ptrbuf[3] )
          break;
        else {
          int err;
          unsigned long cpu_n = ptrbuf[0];
          params.out_data = (unsigned long *)kmalloc_array(ptrbuf[3] + 1, sizeof(unsigned long), GFP_KERNEL);
          if ( !params.out_data )
          {
            printk(KERN_INFO "[+] IOCTL_RNL_PER_CPU on cpu %ld cannot alloc %ld elements\n", cpu_n, ptrbuf[3] + 1);
            return -ENOMEM;
          }
          // copy params
          params.this_cpu_off = ptrbuf[1];
          params.offset       = ptrbuf[2];
          params.count        = ptrbuf[3];
          err = smp_call_function_single(cpu_n, copy_lrn, (void*)&params, 1);
          if ( err )
          {
            printk(KERN_INFO "[+] IOCTL_RNL_PER_CPU on cpu %ld failed, error %d\n", cpu_n, err);
            kfree(params.out_data);
            return err;
          }
          // copy to user
          if (copy_to_user((void*)ioctl_param, (void*)params.out_data, sizeof(params.out_data[0]) * (1 + params.out_data[0])) > 0)
          {
            kfree(params.out_data);
            return -EFAULT;
          }
        }
        if ( params.out_data )
          kfree(params.out_data);
      }
      break; /* IOCTL_RNL_PER_CPU */
#endif /* CONFIG_USER_RETURN_NOTIFIER */

     case IOCTL_READ_CONSOLES:
       // read cnt
       COPY_ARG
       if ( !ptrbuf[0] )
       {
         // just count amount of registered consoles
         struct console *con;
         console_lock();
         // achtung! don`t try to use printk or something like this until console_unlock call
         for_each_console(con)
         {
           count++;
         }
         // unlock
         console_unlock();
         goto copy_count;
       } else {
         struct console *con;
         ALLOC_KBUF(struct one_console, ptrbuf[0])
         console_lock();
         // achtung! don`t try to use printk or something like this until console_unlock call
         for_each_console(con)
         {
          count++;
          if ( count > ptrbuf[0] )
            break;
          curr->addr = con;
          strlcpy(curr->name, con->name, 16);
          curr->write = con->write;
          curr->read  = con->read;
          curr->device = con->device;
          curr->unblank = con->unblank;
          curr->setup = con->setup;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
          curr->exit = con->exit;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
          curr->match = con->match;
#endif
          // curr->dropped = con->dropped;
          curr->flags = con->flags;
          curr->index = con->index;
          // curr->cflags = con->cflags;
          // for next console
          curr++;
         }
         // unlock
         console_unlock();
         // copy to user mode
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_console);
         goto copy_kbuf_count;
       }
       break; /* IOCTL_READ_CONSOLES */

     case IOCTL_GET_SOCK_DIAG:
        // check pre-req
        if ( !s_sock_diag_handlers || !s_sock_diag_table_mutex )
          return -ENOCSI;
        // read index
        COPY_ARG
        if ( ptrbuf[0] >= AF_MAX) return -EINVAL;
        else {
          struct one_sock_diag params;
          // lock
          mutex_lock(s_sock_diag_table_mutex);
          // fill out params
          params.addr = (void *)s_sock_diag_handlers[ptrbuf[0]];
          if ( params.addr )
          {
            params.dump = (void *)s_sock_diag_handlers[ptrbuf[0]]->dump;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
            params.get_info = (void *)s_sock_diag_handlers[ptrbuf[0]]->get_info;
#else
            params.get_info = 0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
            params.destroy = (void *)s_sock_diag_handlers[ptrbuf[0]]->destroy;
#else
            params.destroy = 0;
#endif
          } else
            params.dump = params.get_info = params.destroy = 0;
          // unlock
          mutex_unlock(s_sock_diag_table_mutex);
          // copy to user
          if (copy_to_user((void*)ioctl_param, (void*)&params, sizeof(params)) > 0)
            return -EFAULT;
        }
       break; /* IOCTL_GET_SOCK_DIAG */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
     case IOCTL_GET_ULP_OPS:
        COPY_ARGS(3)
        if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
        else {
          struct list_head *list = (struct list_head *)ptrbuf[0];
          spinlock_t *lock = (spinlock_t *)ptrbuf[1];
          struct list_head *p;
          if ( !ptrbuf[2] )
          {
            // just calc count
            spin_lock(lock);
            list_for_each(p, list)
              count++;
            // unlock
            spin_unlock(lock);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_tcp_ulp_ops, ptrbuf[2])
            spin_lock(lock);
            list_for_each(p, list)
            {
              struct tcp_ulp_ops *ulp = list_entry(p, struct tcp_ulp_ops, list);
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)ulp;
              curr->init = (void *)ulp->init;
              curr->update = (void *)ulp->update;
              curr->release = (void *)ulp->release;
              curr->get_info = (void *)ulp->get_info;
              curr->get_info_size = (void *)ulp->get_info_size;
              curr->clone = (void *)ulp->clone;
              strlcpy(curr->name, ulp->name, 16);
              // for next iteration
              count++;
              curr++;
            }
            // unlock
            spin_unlock(lock);
            // copy to user
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_tcp_ulp_ops);
            goto copy_kbuf_count;
          }
        }
       break; /* IOCTL_GET_ULP_OPS */
#endif

     case IOCTL_GET_PROTOS:
        COPY_ARGS(3)
        if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
        else {
          struct list_head *list = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          struct list_head *p;
          if ( !ptrbuf[2] )
          {
            // just calc count
            mutex_lock(m);
            list_for_each(p, list)
              count++;
            // unlock
            mutex_unlock(m);
            goto copy_count;
          } else {
            kbuf_size = sizeof(unsigned long) * (ptrbuf[2] + 1);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            mutex_lock(m);
            list_for_each(p, list)
            {
              struct proto *prot = list_entry(p, struct proto, node);
              if ( count >= ptrbuf[2] )
                break;
              kbuf[count+1] = (unsigned long)prot;
              count++;
            }
            // unlock
            mutex_unlock(m);
            // copy to user
            kbuf_size = sizeof(unsigned long) * (count + 1);
            goto copy_kbuf_count;
          }
        }
       break; /* IOCTL_GET_PROTOS */

     case IOCTL_GET_PROTOSW:
        COPY_ARGS(4)
        if ( ptrbuf[2] >= SOCK_MAX ) return -EINVAL;
        else {
          struct list_head *isw_list = (struct list_head *)ptrbuf[0];
          spinlock_t *lock = (spinlock_t *)ptrbuf[1];
          struct inet_protosw *answer;
          struct list_head *lh;
          isw_list += ptrbuf[2];
          if ( !ptrbuf[3] )
          {
            // just count size
            spin_lock_bh(lock);
            list_for_each(lh, isw_list)
              count++;
            spin_unlock_bh(lock);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_protosw, ptrbuf[3])
            spin_lock_bh(lock);
            list_for_each(lh, isw_list)
            {
              answer = list_entry(lh, struct inet_protosw, list);
              if ( count >= ptrbuf[3] )
                break;
              curr->addr = (void *)answer;
              curr->type = answer->type;
              curr->protocol = answer->protocol;
              curr->prot = (void *)answer->prot;
              curr->ops = (void *)answer->ops;
              count++;
              curr++;
            }
            spin_unlock_bh(lock);
            // copy to user
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_protosw);
            goto copy_kbuf_count;
          }
        }
      break; /* IOCTL_GET_PROTOSW */

#ifdef CONFIG_NETFILTER
     case IOCTL_GET_NFXT:
       if ( !s_xt ) return -ENOCSI;
       COPY_ARGS(3)
       if ( ptrbuf[0] >= NFPROTO_NUMPROTO ) return -EINVAL;
       if ( ptrbuf[1] != 0 && ptrbuf[1] != 1 ) return -EINVAL;
       if ( !ptrbuf[2] ) {
         mutex_lock(&s_xt[ptrbuf[0]].mutex);
         // calc count
         if ( !ptrbuf[1] ) // of targets
         {
           struct xt_target *t;
           list_for_each_entry(t, &s_xt[ptrbuf[0]].target, list) count++;
         } else { // of matches
           struct xt_match *m;
           list_for_each_entry(m, &s_xt[ptrbuf[0]].match, list) count++;
         }
         mutex_unlock(&s_xt[ptrbuf[0]].mutex);
         goto copy_count;
       } else {
         ALLOC_KBUF(struct xt_common, ptrbuf[2])
         // lock
         mutex_lock(&s_xt[ptrbuf[0]].mutex);
         if ( !ptrbuf[1] ) // targets
         {
           struct xt_target *t;
           list_for_each_entry(t, &s_xt[ptrbuf[0]].target, list)
           {
             if ( count >= ptrbuf[2] ) break;
             curr->addr = t;
             strlcpy(curr->name, t->name, sizeof(curr->name));
             curr->match = (unsigned long)t->target;
             curr->checkentry = (unsigned long)t->checkentry;
             curr->destroy = (unsigned long)t->destroy;
#ifdef CONFIG_NETFILTER_XTABLES_COMPAT
             curr->compat_from_user = (unsigned long)t->compat_from_user;
             curr->compat_to_user = (unsigned long)t->compat_to_user;
#endif
             curr->hooks = t->hooks;
             curr->proto = t->proto;
             curr->family = t->family;
             // for next iteration
             count++;
             curr++;
           }
         } else { // matches
           struct xt_match *m;
           list_for_each_entry(m, &s_xt[ptrbuf[0]].match, list)
           {
             if ( count >= ptrbuf[2] ) break;
             curr->addr = m;
             strlcpy(curr->name, m->name, sizeof(curr->name));
             curr->match = (unsigned long)m->match;
             curr->checkentry = (unsigned long)m->checkentry;
             curr->destroy = (unsigned long)m->destroy;
#ifdef CONFIG_NETFILTER_XTABLES_COMPAT
             curr->compat_from_user = (unsigned long)m->compat_from_user;
             curr->compat_to_user = (unsigned long)m->compat_to_user;
#endif
             curr->hooks = m->hooks;
             curr->proto = m->proto;
             curr->family = m->family;
             // for next iteration
             count++;
             curr++;
           }
         }
         // unlock
         mutex_unlock(&s_xt[ptrbuf[0]].mutex);
         // copy to user
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct xt_common);
         goto copy_kbuf_count;
       }
      break; /* IOCTL_GET_NFXT */

     case IOCTL_NFIEHOOKS:
        COPY_ARGS(4)
#ifndef CONFIG_NETFILTER_EGRESS
        if ( ptrbuf[3] ) goto copy_count;
#endif
#ifndef CONFIG_NETFILTER_INGRESS
        if ( !ptrbuf[3] ) goto copy_count;
#endif
        if ( !s_net || !s_dev_base_lock || !s_nf_hook_mutex )
          return -ENOCSI;
        if ( !ptrbuf[2] ) goto copy_count;
        else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
          struct nf_hook_entries *nfh = NULL;
#else
          struct list_head *nfh = NULL;
          struct nf_hook_ops *elem;
#endif
          struct net_device *dev, *right_dev = NULL;
          struct net *net;
          kbuf_size = sizeof(unsigned long) * (1 + ptrbuf[2]);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          net = peek_net(ptrbuf[0]);
          if ( !net )
          {
            up_read(s_net);
            return -ENOENT;
          }
          // find right net_dev
          read_lock(s_dev_base_lock);
          for_each_netdev(net, dev)
          {
            if ( (unsigned long)dev == ptrbuf[1] )
            {
              right_dev = dev;
              break;
            }
          }
          if ( !right_dev )
          {
            read_unlock(s_dev_base_lock);
            up_read(s_net);
            kfree(kbuf);
            return -ENODEV;
          }
#ifdef CONFIG_NETFILTER_EGRESS
          if ( ptrbuf[3] )
          {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
            nfh = right_dev->nf_hooks_egress;
#else
            nfh = &right_dev->nf_hooks_egress;
#endif
          }
#endif
#ifdef CONFIG_NETFILTER_INGRESS
          if ( !ptrbuf[3] )
          {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
           nfh = right_dev->nf_hooks_ingress;
#else
           nfh = &right_dev->nf_hooks_ingress;
#endif
          }
#endif
          if ( !nfh )
          {
            read_unlock(s_dev_base_lock);
            up_read(s_net);
            kfree(kbuf);
            goto copy_count;
          }
          // ok, copy hooks
          mutex_lock(s_nf_hook_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
          // nf_hook_entry was introduced in 4.9, on more old kernels is just list of nf_hook_ops
          for ( ; count < nfh->num_hook_entries && count < ptrbuf[2]; ++count )
            kbuf[1 + count] = (unsigned long)nfh->hooks[count].hook;
#else
         list_for_each_entry(elem, nfh, list)
         {
           if ( count >= ptrbuf[2] ) break;
           kbuf[1 + count] = (unsigned long)elem->hook;
           count++;
         }
#endif
          mutex_unlock(s_nf_hook_mutex);
          read_unlock(s_dev_base_lock);
          up_read(s_net);
          if ( !count ) goto copy_count;
          kbuf_size = sizeof(unsigned long) * (1 + count);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_NFIEHOOKS */

     case IOCTL_NFHOOKS:
        // check pre-req
        if ( !s_net || !s_nf_log_mutex )
          return -ENOCSI;
        // read params
        COPY_ARGS(2)
        if ( !ptrbuf[1] )
        {
          struct net *net = peek_net(ptrbuf[0]);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
          int i;
#endif
          if ( !net )
          {
            up_read(s_net);
            return -ENOENT;
          }
          mutex_lock(s_nf_log_mutex);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks); ++i )
          {
            int j;
            for ( j = 0; j < ARRAY_SIZE(net->nf.hooks[i]); ++j )
              if ( net->nf.hooks[i][j] ) count++;
          }
#endif
#else
          // ipv4
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks_ipv4); ++i )
            if ( net->nf.hooks_ipv4[i] ) count += net->nf.hooks_ipv4[i]->num_hook_entries;
          // ipv6
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks_ipv6); ++i )
            if ( net->nf.hooks_ipv6[i] ) count += net->nf.hooks_ipv6[i]->num_hook_entries;
#ifdef CONFIG_NETFILTER_FAMILY_ARP
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks_arp); ++i )
            if ( net->nf.hooks_arp[i] ) count += net->nf.hooks_arp[i]->num_hook_entries;
#endif
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks_bridge); ++i )
            if ( net->nf.hooks_bridge[i] ) count += net->nf.hooks_bridge[i]->num_hook_entries;
#endif
#if IS_ENABLED(CONFIG_DECNET) && LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,117)
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks_decnet); ++i )
            if ( net->nf.hooks_decnet[i] ) count += net->nf.hooks_decnet[i]->num_hook_entries;
#endif
#endif
          mutex_unlock(s_nf_log_mutex);
          up_read(s_net);
          goto copy_count;
        } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
          int i, j;
#endif
          struct net *net;
          ALLOC_KBUF(struct one_nf_logger, ptrbuf[1])
          net = peek_net(ptrbuf[0]);
          if ( !net )
          {
            up_read(s_net);
            kfree(kbuf);
            return -ENOENT;
          }
          mutex_lock(s_nf_log_mutex);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks); ++i )
          {
            for ( j = 0; j < ARRAY_SIZE(net->nf.hooks[i]); ++j )
            {
              if ( !net->nf.hooks[i][j] ) continue;
              if ( count >= ptrbuf[1] ) break;
              curr->fn = net->nf.hooks[i][j]->hook;
              curr->type = i;
              curr->idx = j;
              // for next iteraton
              count++; curr++;
            }
          }
#endif
#else
#define ENUM_NF_TAB(tab, proto) \
    for ( i = 0; i < ARRAY_SIZE(net->nf.tab); ++i ) { \
      if ( !net->nf.tab[i] ) continue; \
      for ( j = 0; j < net->nf.tab[i]->num_hook_entries; j++ ) { \
        if ( !net->nf.tab[i]->hooks[j].hook ) continue; \
        if ( count >= ptrbuf[1] ) goto skip_hooks; \
        curr->fn = net->nf.tab[i]->hooks[j].hook; \
        curr->type = proto; \
        curr->idx = j; \
        count++; curr++; \
      } \
    }
          // ipv4
          ENUM_NF_TAB(hooks_ipv4, NFPROTO_IPV4)
          // ipv6
          ENUM_NF_TAB(hooks_ipv6, NFPROTO_IPV6)
#ifdef CONFIG_NETFILTER_FAMILY_ARP
          ENUM_NF_TAB(hooks_arp, NFPROTO_ARP)
#endif
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
          ENUM_NF_TAB(hooks_bridge, NFPROTO_BRIDGE)
#endif
#if IS_ENABLED(CONFIG_DECNET) && LINUX_VERSION_CODE <= KERNEL_VERSION(5,15,117)
          ENUM_NF_TAB(hooks_decnet, NFPROTO_DECNET)
#endif
     skip_hooks: // actual count > provided from user mode
#endif
          mutex_unlock(s_nf_log_mutex);
          up_read(s_net);
          if ( !count ) goto copy_count;
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_nf_logger);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_NFHOOKS */

     case IOCTL_NFLOGGERS:
        // check pre-req
        if ( !s_net || !s_nf_log_mutex )
          return -ENOCSI;
        // read params
        COPY_ARGS(2)
        if ( !ptrbuf[1] )
        {
          struct net *net = peek_net(ptrbuf[0]);
          int i;
          if ( !net )
          {
            up_read(s_net);
            return -ENOENT;
          }
          mutex_lock(s_nf_log_mutex);
          for ( i = 0; i < ARRAY_SIZE(net->nf.nf_loggers); i++ )
            if ( net->nf.nf_loggers[i] ) count++;
          mutex_unlock(s_nf_log_mutex);
          up_read(s_net);
          goto copy_count;
        } else {
          struct net *net; 
          int i;
          ALLOC_KBUF(struct one_nf_logger, ptrbuf[1])
          net = peek_net(ptrbuf[0]);
          if ( !net )
          {
            up_read(s_net);
            kfree(kbuf);
            return -ENOENT;
          }
          mutex_lock(s_nf_log_mutex);
          for ( i = 0; i < ARRAY_SIZE(net->nf.nf_loggers) && count < ptrbuf[1]; i++ )
          {
            if ( !net->nf.nf_loggers[i] ) continue;
            curr->type = net->nf.nf_loggers[i]->type;
            curr->idx = i;
            curr->fn = net->nf.nf_loggers[i]->logfn;
            curr++; count++;
          }
          mutex_unlock(s_nf_log_mutex);
          up_read(s_net);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_nf_logger);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_NFLOGGERS */
#endif /* CONFIG_NETFILTER */

     case IOCTL_GET_NET_DEVS:
        // check pre-req
        if ( !s_net || !s_dev_base_lock )
          return -ENOCSI;
        COPY_ARGS(2)
        if ( !ptrbuf[1] )
        { // read count
          struct net_device *dev;
          struct net *net = peek_net(ptrbuf[0]);
          if ( !net )
          {
            up_read(s_net);
            return -ENOENT;
          }
          read_lock(s_dev_base_lock);
          for_each_netdev(net, dev)
            count++;
          read_unlock(s_dev_base_lock);
          up_read(s_net);
          goto copy_count;
        } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
          int xdp;
#endif
          struct net *net;
          struct net_device *dev;
          int found = 0;
          ALLOC_KBUF(struct one_net_dev, ptrbuf[1])
          down_read(s_net);
          for_each_net(net)
          {
            if ( ptrbuf[0] != (unsigned long)net )
              continue;
            found++;
            read_lock(s_dev_base_lock);
            for_each_netdev(net, dev)
            {
              if ( kbuf[0] >= ptrbuf[1] )
                break;
              // fill one_net_dev
              curr->addr = (void *)dev;
              strlcpy(curr->name, dev->name, IFNAMSIZ);
              curr->flags       = dev->flags;
              curr->mtu         = dev->mtu;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
              curr->min_mtu     = dev->min_mtu;
              curr->max_mtu     = dev->max_mtu;
#endif
              curr->type        = dev->type;
              curr->netdev_ops  = (void *)dev->netdev_ops;
              curr->ethtool_ops = (void *)dev->ethtool_ops;
              curr->header_ops  = (void *)dev->header_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,9)
              curr->priv_destructor = (void *)dev->priv_destructor;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
              curr->xdp_prog    = (void *)dev->xdp_prog;
#endif
              curr->rx_handler  = (void *)dev->rx_handler;
              curr->rtnl_link_ops = (void *)dev->rtnl_link_ops;
#ifdef CONFIG_WIRELESS_EXT
              if ( dev->wireless_handlers )
              {
                curr->wireless_handler = (void *)dev->wireless_handlers->standard;
                curr->wireless_get_stat = (void *)dev->wireless_handlers->get_wireless_stats;
              }
#endif
#ifdef CONFIG_NET_XGRESS
              if ( dev->tcx_ingress ) curr->tcx_in_cnt = count_mprog_count(dev->tcx_ingress);
              if ( dev->tcx_egress )  curr->tcx_e_cnt = count_mprog_count(dev->tcx_egress);
#endif
#ifdef CONFIG_NETFILTER_EGRESS
              curr->nf_hooks_egress = (void *)dev->nf_hooks_egress;
              if ( dev->nf_hooks_egress )
                curr->num_ehook_entries = dev->nf_hooks_egress->num_hook_entries;

#endif
#ifdef CONFIG_NETFILTER_INGRESS
              curr->nf_hooks_ingress = (void *)dev->nf_hooks_ingress;
              if ( dev->nf_hooks_ingress )
                curr->num_ihook_entries = dev->nf_hooks_ingress->num_hook_entries;
#endif
#ifdef CONFIG_NET_L3_MASTER_DEV
              curr->l3mdev_ops = (void *)dev->l3mdev_ops;
#endif
#if defined(CONFIG_IPV6) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
              curr->ndisc_ops = (void *)dev->ndisc_ops;
#endif
#ifdef CONFIG_XFRM_OFFLOAD
              curr->xfrmdev_ops = (void *)dev->xfrmdev_ops;
              if ( dev->xfrmdev_ops ) {
                curr->xdo_dev_state_add = (unsigned long)dev->xfrmdev_ops->xdo_dev_state_add;
                curr->xdo_dev_state_delete = (unsigned long)dev->xfrmdev_ops->xdo_dev_state_delete;
                curr->xdo_dev_state_free = (unsigned long)dev->xfrmdev_ops->xdo_dev_state_free;
                curr->xdo_dev_offload_ok = (unsigned long)dev->xfrmdev_ops->xdo_dev_offload_ok;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,16,0)
                curr->xdo_dev_state_advance_esn = (unsigned long)dev->xfrmdev_ops->xdo_dev_state_advance_esn;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0)
                curr->xdo_dev_policy_add = (unsigned long)dev->xfrmdev_ops->xdo_dev_policy_add;
                curr->xdo_dev_policy_delete = (unsigned long)dev->xfrmdev_ops->xdo_dev_policy_delete;
                curr->xdo_dev_policy_free = (unsigned long)dev->xfrmdev_ops->xdo_dev_policy_free;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
                curr->xdo_dev_state_update_stats = (unsigned long)dev->xfrmdev_ops->xdo_dev_state_update_stats;
#else
                curr->xdo_dev_state_update_stats = (unsigned long)dev->xfrmdev_ops->xdo_dev_state_update_curlft;
#endif
#endif
              }
#endif
#ifdef CONFIG_TLS_DEVICE
              curr->tlsdev_ops = (void *)dev->tlsdev_ops;
#endif
#ifdef CONFIG_DCB
              curr->dcbnl_ops = (void *)dev->dcbnl_ops;
#endif
#ifdef CONFIG_MACSEC
              curr->macsec_ops = (void *)dev->macsec_ops;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
              // copy udp_tunnel_nic_info
              curr->udp_tunnel_nic_info = (unsigned long)dev->udp_tunnel_nic_info;
              if ( dev->udp_tunnel_nic_info ) {
                curr->set_port = (unsigned long)dev->udp_tunnel_nic_info->set_port;
                curr->unset_port = (unsigned long)dev->udp_tunnel_nic_info->unset_port;
                curr->sync_table = (unsigned long)dev->udp_tunnel_nic_info->sync_table;
              }
              // copy xdp_state
              rtnl_lock();
              for ( xdp = 0; xdp < 3; xdp++ )
              {
                curr->bpf_prog[xdp] = (void *)dev->xdp_state[xdp].prog;
                curr->bpf_link[xdp] = (void *)dev->xdp_state[xdp].link;
              }
              rtnl_unlock();
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
              if ( dev->net_notifier_list.next != NULL )
              {
                struct netdev_net_notifier *nn;
                list_for_each_entry(nn, &dev->net_notifier_list, list)
                 curr->netdev_chain_cnt++;
              }
#endif
              // for next iteration
              curr++;
              kbuf[0]++;
            }
            read_unlock(s_dev_base_lock);
            break;
          }
          up_read(s_net);
          if ( !found )
          {
            kfree(kbuf);
            return -ENOENT;
          }
          // copy to user
          kbuf_size = sizeof(unsigned long) + kbuf[0] * sizeof(struct one_net_dev);
          goto copy_kbuf;
        }
      break; /* IOCTL_GET_NET_DEVS */

     case IOCTL_GET_LINKS_OPS:
        COPY_ARGS(2)
        if ( !ptrbuf[0] ) return -EINVAL;
        if ( !ptrbuf[1] )
        {
          // count number of links_ops
          struct list_head *l = (struct list_head *)ptrbuf[0];
          const struct rtnl_link_ops *ops;
          rtnl_lock();
          list_for_each_entry(ops, l, list)
            count++;
          rtnl_unlock();
          goto copy_count;
        } else {
          struct list_head *l = (struct list_head *)ptrbuf[0];
          const struct rtnl_link_ops *ops;
          ALLOC_KBUF(struct one_rtlink_ops, ptrbuf[1])
          rtnl_lock();
          list_for_each_entry(ops, l, list)
          {
            if ( count >= ptrbuf[1] )
             break;
            curr->addr = (void *)ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
            curr->alloc = (unsigned long)ops->alloc;
#endif
            curr->setup = (unsigned long)ops->setup;
            curr->validate = (unsigned long)ops->validate;
            curr->newlink = (unsigned long)ops->newlink;
            curr->changelink = (unsigned long)ops->changelink;
            curr->dellink = (unsigned long)ops->dellink;
            curr->get_size = (unsigned long)ops->get_size;
            curr->fill_info = (unsigned long)ops->fill_info;
            curr->get_xstats_size = (unsigned long)ops->get_xstats_size;
            curr->fill_xstats = (unsigned long)ops->fill_xstats;
            curr->get_num_tx_queues = (unsigned long)ops->get_num_tx_queues;
            curr->get_num_rx_queues = (unsigned long)ops->get_num_rx_queues;
            curr->slave_changelink = (unsigned long)ops->slave_changelink;
            curr->get_slave_size = (unsigned long)ops->get_slave_size;
            curr->fill_slave_info = (unsigned long)ops->fill_slave_info;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
            curr->get_link_net = (unsigned long)ops->get_link_net;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
            curr->get_linkxstats_size = (unsigned long)ops->get_linkxstats_size;
            curr->fill_linkxstats = (unsigned long)ops->fill_linkxstats;
#endif
            // for next iteration
            count++; curr++;
          }
          rtnl_unlock();
          // copy to user
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_rtlink_ops);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_GET_LINKS_OPS */

     case IOCTL_GET_PERNET_OPS:
        COPY_ARGS(3)
        if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
        if ( !ptrbuf[2] )
        {
          // count num of pernet_operations
          struct list_head *l = (struct list_head *)ptrbuf[0];
          struct rw_semaphore *lock = (struct rw_semaphore *)ptrbuf[1];
          struct pernet_operations *ops;
          down_read(lock);
          list_for_each_entry(ops, l, list)
            count++;
          up_read(lock);
          goto copy_count;
        } else {
          struct list_head *l = (struct list_head *)ptrbuf[0];
          struct rw_semaphore *lock = (struct rw_semaphore *)ptrbuf[1];
          struct pernet_operations *ops;
          ALLOC_KBUF(struct one_pernet_ops, ptrbuf[2])
          down_read(lock);
          list_for_each_entry(ops, l, list)
          {
            if ( kbuf[0] >= ptrbuf[2] )
              break;
            curr->addr = (void *)ops;
            curr->init = (void *)ops->init;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
            curr->pre_exit = (void *)ops->pre_exit;
#endif
            curr->exit = (void *)ops->exit;
            curr->exit_batch = (void *)ops->exit_batch;
            curr->id = ops->id;
            if ( ops->id ) curr->id_value = *ops->id;
            curr->size = ops->size;
            curr++;
            kbuf[0]++;
          }
          up_read(lock);
          // copy to user
          kbuf_size = sizeof(unsigned long) + kbuf[0] * sizeof(struct one_pernet_ops);
          goto copy_kbuf;
        }
      break; /* IOCTL_GET_PERNET_OPS */

     case IOCTL_ENUM_NFT_AF:
        // check pre-req
        if ( !s_net )
          return -ENOCSI;
        // read net addr & count
        COPY_ARGS(2)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,15,0)
      return -EPROTO;
#else
        else {
          struct net *net;
          struct nft_af_info *afi;
          if ( !ptrbuf[1] ) // just count nft_af_info on some net
          {
            net = peek_net(ptrbuf[0]);
            if ( !net )
            {
              up_read(s_net);
              return -ENODEV;  
            }
            list_for_each_entry(afi, &net->nft.af_info, list) count++;
            up_read(s_net);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_nft_af, ptrbuf[1])
            net = peek_net(ptrbuf[0]);
            if ( !net )
            {
              up_read(s_net);
              kfree(kbuf);
              return -ENODEV;
            }
            list_for_each_entry(afi, &net->nft.af_info, list)
            {
              int ih;
              if ( count >= ptrbuf[1] ) break;
              // fill curr
              curr->addr = (void *)afi;
              curr->family = afi->family;
              curr->nhooks = afi->nhooks;
              curr->ops_init = (void *)afi->hook_ops_init;
              for ( ih = 0; ih < 8; ++ih ) curr->hooks[ih] = (void *)afi->hooks[ih];
              // for next item
              curr++; count++;
            }
            up_read(s_net);  
            // copy to user
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_nft_af);
            goto copy_kbuf_count;
          }
        }
#endif
      break; /* IOCTL_ENUM_NFT_AF */

     case IOCTL_FIB_NTFY:
        if ( !s_net )
          return -ENOCSI;
        // read net addr & count
        COPY_ARGS(2)
        if ( !ptrbuf[0] ) return -EINVAL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
        return -EPROTO;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
  // since 5.4 fib_notifier_ops stored in (not available within include) struct fib_notifier_net
  // see for example https://elixir.bootlin.com/linux/v5.18.19/source/net/core/fib_notifier.c#L13
  // it can be gathered with net_generic where index is fib_notifier_net_id
        if ( !s_fib_notifier_net_id ) return -ENOCSI;
        else {
          struct net *net;
          struct fib_notifier_ops *fno;
          struct fib_notifier_net *fn_net;
          if ( !ptrbuf[1] ) // just count fib_notifier_ops on given net
          {
            net = peek_net(ptrbuf[0]);
            if ( !net )
            {
              up_read(s_net);
              return -ENODEV;
            }
            fn_net = (struct fib_notifier_net *)my_net_generic(net, *s_fib_notifier_net_id);
            if ( !fn_net )
            {
              up_read(s_net);
              goto copy_count;
            }
            rcu_read_lock();
            list_for_each_entry(fno, &fn_net->fib_notifier_ops, list) count++;
            rcu_read_unlock();
            up_read(s_net);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_fib_ntfy, ptrbuf[1])
            net = peek_net(ptrbuf[0]);
            if ( !net )
            {
              up_read(s_net);
              kfree(kbuf);
              return -ENODEV;
            }
            fn_net = (struct fib_notifier_net *)my_net_generic(net, *s_fib_notifier_net_id);
            if ( !fn_net )
            {
              up_read(s_net);
              kfree(kbuf);
              goto copy_count;
            }
            rcu_read_lock();
            list_for_each_entry(fno, &fn_net->fib_notifier_ops, list)
            {
              if ( count >= ptrbuf[1] ) break;
              curr->addr = (void *)fno;
              curr->family = fno->family;
              curr->fib_seq_read = (unsigned long)fno->fib_seq_read;
              curr->fib_dump = (unsigned long)fno->fib_dump;
              // for next iteration
              count++; curr++;
            }
            rcu_read_unlock();
            up_read(s_net);
            // copy to user
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_fib_ntfy);
            goto copy_kbuf_count;
          }
        }
#else
        else {
          struct net *net;
          struct fib_notifier_ops *fno;
          if ( !ptrbuf[1] ) // just count nft_af_info on some net
          {
            net = peek_net(ptrbuf[0]);
            if ( !net )
            {
              up_read(s_net);
              return -ENODEV;
            }
            list_for_each_entry(fno, &net->fib_notifier_ops, list) count++;
            up_read(s_net);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_fib_ntfy, ptrbuf[1])
            net = peek_net(ptrbuf[0]);
            if ( !net )
            {
              up_read(s_net);
              kfree(kbuf);
              return -ENODEV;
            }
            list_for_each_entry(fno, &net->fib_notifier_ops, list)
            {
              if ( count >= ptrbuf[1] ) break;
              curr->addr = (void *)fno;
              curr->family = fno->family;
              curr->fib_seq_read = (unsigned long)fno->fib_seq_read;
              curr->fib_dump = (unsigned long)fno->fib_dump;
              // for next iteration
              count++; curr++;
            }
            up_read(s_net);
            // copy to user
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_fib_ntfy);
            goto copy_kbuf_count;
          }
        }
#endif
      break /* IOCTL_FIB_NTFY */;

     case IOCTL_FIB_RULES:
        // check pre-req
        if ( !s_net ) return -ENOCSI;
        // read net addr & count
        COPY_ARGS(2)
        if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
        else {
          struct net *net;
          struct fib_rules_ops *ops;
          ALLOC_KBUF(struct one_fib_rule, ptrbuf[1])
          net = peek_net(ptrbuf[0]);
          if ( !net )
          {
            up_read(s_net);
            kfree(kbuf);
            return -ENODEV;
          }
          rcu_read_lock();
          list_for_each_entry_rcu(ops, &net->rules_ops, list)
          {
            if ( count >= ptrbuf[1] ) break;
            curr->addr = ops;
            curr->family = ops->family;
            curr->rule_size = ops->rule_size;
            curr->addr_size = ops->addr_size;
            curr->action = (unsigned long)ops->action;
            curr->suppress = (unsigned long)ops->suppress;
            curr->match = (unsigned long)ops->match;
            curr->configure = (unsigned long)ops->configure;
            curr->del_ = (unsigned long)ops->delete;
            curr->compare = (unsigned long)ops->compare;
            curr->fill = (unsigned long)ops->fill;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
            curr->default_pref = (unsigned long)ops->default_pref;
#endif
            curr->nlmsg_payload = (unsigned long)ops->nlmsg_payload;
            curr->flush_cache = (unsigned long)ops->flush_cache;
            // for next iteration
            ++count; ++curr;
          }
          rcu_read_unlock();
          up_read(s_net);  
          // copy to user
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_fib_rule);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_FIB_RULES */

     case IOCTL_GET_NETS:
        // check pre-req
        if ( !s_net ) return -ENOCSI;
        // read count
        COPY_ARG
        if ( !ptrbuf[0] )
        {
          struct net *net;
          down_read(s_net);
          for_each_net(net)
            count++;
          up_read(s_net);
          goto copy_count;
        } else {
          struct net *net;
          struct fib_rules_ops *ops;

          ALLOC_KBUF(struct one_net, ptrbuf[0])
          down_read(s_net);
          for_each_net(net)
          {
            if ( kbuf[0] >= ptrbuf[0] )
              break;
            // fill loot
            curr->addr = (void *)net;
            curr->ifindex = net->ifindex;
            curr->rtnl = (void *)net->rtnl;

            if ( net->rtnl )
            {
               curr->rtnl_proto = (void *)net->rtnl->sk_prot;
               if ( net->rtnl->sk_filter && net->rtnl->sk_filter->prog )
                 curr->rtnl_filter = (void *)net->rtnl->sk_filter->prog->bpf_func;
            }
            curr->genl_sock = (void *)net->genl_sock;
            if ( net->genl_sock )
            {
               curr->genl_sock_proto = (void *)net->genl_sock->sk_prot;
               if ( net->genl_sock->sk_filter && net->genl_sock->sk_filter->prog )
                 curr->genl_sock_filter = (void *)net->genl_sock->sk_filter->prog->bpf_func;
            }
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,17,0)
            curr->uevent_sock = (void *)net->uevent_sock;
#endif
            curr->diag_nlsk = (void *)net->diag_nlsk;
            if ( net->diag_nlsk )
            {
               curr->diag_nlsk_proto = (void *)net->diag_nlsk->sk_prot;
               if ( net->diag_nlsk->sk_filter && net->diag_nlsk->sk_filter->prog )
                 curr->diag_nlsk_filter = (void *)net->diag_nlsk->sk_filter->prog->bpf_func;
            }
            curr->dev_cnt = curr->rules_cnt = curr->netdev_chain_cnt = 0;
            // calc rules_cnt
            rcu_read_lock();
            list_for_each_entry_rcu(ops, &net->rules_ops, list) curr->rules_cnt++;
            rcu_read_unlock();
#if LINUX_VERSION_CODE > KERNEL_VERSION(5,5,0)
            if ( net->netdev_chain.head != NULL )
            {
              struct notifier_block *b;
              for ( b = net->netdev_chain.head; b != NULL; b = rcu_dereference_raw(b->next) )
               curr->netdev_chain_cnt++;
            }
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(5,10,0)
            if ( net->nexthop.notifier_chain.head != NULL )
            {
              struct notifier_block *nb;
              down_read(&net->nexthop.notifier_chain.rwsem);
              for ( nb = net->nexthop.notifier_chain.head; nb != NULL; nb = nb->next )
               curr->hop_ntfy_cnt++;
              up_read(&net->nexthop.notifier_chain.rwsem);
            }
#endif
            if ( s_dev_base_lock )
            {
              struct net_device *dev;
              read_lock(s_dev_base_lock);
              for_each_netdev(net, dev)
                curr->dev_cnt++;
              read_unlock(s_dev_base_lock);
            }
#if defined(CONFIG_NETFILTER) && LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
            if ( net->nf.queue_handler )
            {
              curr->nf_outfn = net->nf.queue_handler->outfn;
              curr->nf_hook_drop = net->nf.queue_handler->nf_hook_drop;
            }
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
            // copy netns_bpf
            curr->progs[0] = net->bpf.progs[0];
            curr->progs[1] = net->bpf.progs[1];
            if ( bpf_prog_array_length_ptr )
            {
              if ( net->bpf.run_array[0] )
               curr->bpf_cnt[0] = bpf_prog_array_length_ptr(net->bpf.run_array[0]);
              if ( net->bpf.run_array[1] )
               curr->bpf_cnt[1] = bpf_prog_array_length_ptr(net->bpf.run_array[1]);
            }
#endif
            curr++;
            kbuf[0]++;
          }
          up_read(s_net);
          // copy to user
          kbuf_size = sizeof(unsigned long) + kbuf[0] * sizeof(struct one_net);
          goto copy_kbuf;
        }
      break; /* IOCTL_GET_NETS */

    case IOCTL_GET_RTNL_AF_OPS:
        COPY_ARGS(2)
        if ( !ptrbuf[1] )
        {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct list_head *lh;
          rtnl_lock();
          list_for_each(lh, head)
            count++;
          rtnl_unlock();
          goto copy_count;
        } else {
          struct rtnl_af_ops *ops;
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct list_head *lh;
          ALLOC_KBUF(struct one_af_ops, ptrbuf[1])
          rtnl_lock();
          list_for_each(lh, head)
          {
            if ( count >= ptrbuf[1] )
              break;
            ops = list_entry(lh, struct rtnl_af_ops, list);
            curr->addr = (void *)ops;
            curr->fill_link_af = (unsigned long)ops->fill_link_af;
            curr->get_link_af_size = (unsigned long)ops->get_link_af_size;
            curr->validate_link_af = (unsigned long)ops->validate_link_af;
            curr->set_link_af = (unsigned long)ops->set_link_af;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
            curr->fill_stats_af = (unsigned long)ops->fill_stats_af;
            curr->get_stats_af_size = (unsigned long)ops->get_stats_af_size;
#endif
            // for next iteration
            count++; curr++;
          }
          rtnl_unlock();
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_af_ops);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_GET_RTNL_AF_OPS */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
    case IOCTL_GET_NLTAB:
        COPY_ARGS(3)
        if ( ptrbuf[2] >= MAX_LINKS ) return -EFBIG;
        else {
          struct netlink_table *tab = *(struct netlink_table **)ptrbuf[0] + ptrbuf[2];
          rwlock_t *lock = (rwlock_t *)ptrbuf[1];
          struct one_nltab res;
          struct rhashtable_iter iter;
          int err = 0;
          res.addr = (void *)tab;
          res.bind = (void *)tab->bind;
          res.unbind = (void *)tab->unbind;
          res.compare = (void *)tab->compare;
          res.registered = tab->registered;
          res.sk_count = 0;
          // lock
          read_lock(lock);
          // iterate
          rhashtable_walk_enter(&tab->hash, &iter);
          rhashtable_walk_start(&iter);
          for (;;) {
            struct netlink_sock *ns = rhashtable_walk_next(&iter);
            if (IS_ERR(ns)) {
              if (PTR_ERR(ns) == -EAGAIN) continue;
              err = PTR_ERR(ns);
              break;
            } else if (!ns)
              break;
            res.sk_count++;
          }
          rhashtable_walk_stop(&iter);
          rhashtable_walk_exit(&iter);
          // unlock
          read_unlock(lock);
          if ( err )
            return err;
          // copy to user
          if (copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0)
            return -EFAULT;
        }
      break; /* IOCTL_GET_NLTAB */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    case IOCTL_DEL_CGROUP_BPF:
        if ( !cgroup_bpf_detach_ptr )
         return -ENOCSI;
        COPY_ARGS(6) 
        // check index (4 param)
        if ( ptrbuf[4] >= MAX_BPF_ATTACH_TYPE ) return -EINVAL;
        else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          void *root = (void *)ptrbuf[2];
          void *cgrp = (void *)ptrbuf[3];
          struct bpf_prog *prog = (struct bpf_prog *)ptrbuf[5];
          struct cgroup_root *item;
          struct cgroup *found = 0;
          unsigned int hierarchy_id;
          // lock
          mutex_lock(m);
          // iterate on roots
          idr_for_each_entry(genl, item, hierarchy_id)
          {
             struct cgroup_subsys_state *child;
             if ( (void *)item != root )
               continue;
             rcu_read_lock();
             // iterate on childres
             for (child = css_next_descendant_pre(NULL, &item->cgrp.self); child; child = css_next_descendant_pre(child, &item->cgrp.self) )
             {
               if ( (void *)child != cgrp ) continue;
               found = (struct cgroup *)child;
               break;
             }
             rcu_read_unlock();
             break;
          }
          // unlock
          mutex_unlock(m);
          if ( !found )
             return -ENOENT;
          return cgroup_bpf_detach_ptr(found, prog, (enum bpf_attach_type)ptrbuf[4]);
        }
      break; /* IOCTL_DEL_CGROUP_BPF */
#endif // cgroup ebpf since 4.15

    case IOCTL_GET_PMUS:
        COPY_ARGS(3)
        else
        {
          struct idr *pmus = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned int id;
          struct pmu *pmu;
          // check cnt
          if ( !ptrbuf[2] )
          {
            ptrbuf[0] = 0;
            // lock
            mutex_lock(m);
            // iterate
            idr_for_each_entry(pmus, pmu, id)
              ptrbuf[0]++;
            // unlock
            mutex_unlock(m);
            goto copy_ptrbuf0;
          } else {
            ALLOC_KBUF(struct one_pmu, ptrbuf[2])
            // lock
            mutex_lock(m);
            // iterate
            idr_for_each_entry(pmus, pmu, id)
            {
              if ( count < ptrbuf[2] )
              {
                curr->addr = (void *)pmu;
                curr->type = pmu->type;
                curr->capabilities = pmu->capabilities;
                curr->pmu_enable = (void *)pmu->pmu_enable;
                curr->pmu_disable = (void *)pmu->pmu_disable;
                curr->event_init = (void *)pmu->event_init;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
                curr->event_mapped = (void *)pmu->event_mapped;
                curr->event_unmapped = (void *)pmu->event_unmapped;
#endif
                curr->add = (void *)pmu->add;
                curr->del = (void *)pmu->del;
                curr->start = (void *)pmu->start;
                curr->stop = (void *)pmu->stop;
                curr->read = (void *)pmu->read;
                curr->start_txn = (void *)pmu->start_txn;
                curr->commit_txn = (void *)pmu->commit_txn;
                curr->cancel_txn = (void *)pmu->cancel_txn;
                curr->event_idx = (void *)pmu->event_idx;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
                curr->sched_task = (void *)pmu->sched_task;
                curr->setup_aux = (void *)pmu->setup_aux;
                curr->free_aux = (void *)pmu->free_aux;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
                curr->swap_task_ctx = (void *)pmu->swap_task_ctx;
                curr->snapshot_aux = (void *)pmu->snapshot_aux;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
                curr->addr_filters_validate = (void *)pmu->addr_filters_validate;
                curr->addr_filters_sync = (void *)pmu->addr_filters_sync;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
                curr->aux_output_match = (void *)pmu->aux_output_match;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
                curr->filter_match = (void *)pmu->filter_match;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,19,24)
                curr->check_period = (void *)pmu->check_period;
#endif
                curr++;
              }
              count++;
            }
            // unlock
            mutex_unlock(m);
            // copy to user
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_pmu);
            goto copy_kbuf_count;
          }
        }
      break; /* IOCTL_GET_PMUS */

    case IOCTL_GET_BPF_MAPS:
      COPY_ARGS(3)
      else {
        struct idr *bmaps = (struct idr *)ptrbuf[0];
        spinlock_t *lock = (spinlock_t *)ptrbuf[1];
        unsigned int id;
        struct bpf_map *map;
        // check cnt
        if ( !ptrbuf[2] )
        {
          ptrbuf[0] = 0;
          idr_preload(GFP_KERNEL);
          // lock
          spin_lock_bh(lock);
          // iterate
          idr_for_each_entry(bmaps, map, id)
            ptrbuf[0]++;
          // unlock
          spin_unlock_bh(lock);
          idr_preload_end();
          goto copy_ptrbuf0;
        } else {
          ALLOC_KBUF(struct one_bpf_map, ptrbuf[2])
          idr_preload(GFP_KERNEL);
          // lock
          spin_lock_bh(lock);
          // iterate
          idr_for_each_entry(bmaps, map, id)
          {
            if ( count < ptrbuf[2] )
            {
              curr->addr = map;
              curr->ops = map->ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
              curr->inner_map_meta = map->inner_map_meta;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
              curr->btf = map->btf;
#endif
              curr->map_type = map->map_type;
              curr->key_size = map->key_size;
              curr->value_size = map->value_size;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
              curr->id = map->id;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
              strlcpy(curr->name, map->name, 16);
#endif
              curr++; count++;
            } else break;
          }
          // unlock
          spin_unlock_bh(lock);
          idr_preload_end();
          // copy to user
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_bpf_map);
          goto copy_kbuf_count;
        }
      }
      break; /* IOCTL_GET_BPF_MAPS */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
    case IOCTL_GET_CGROUP_BPF:
        if ( !bpf_prog_array_length_ptr )
          return -ENOCSI;
        COPY_ARGS(6)  
        // check index (4 param)
        if ( ptrbuf[4] >= MAX_BPF_ATTACH_TYPE ) return -EINVAL;
        if ( !ptrbuf[5] ) goto copy_count;
        else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          void *root = (void *)ptrbuf[2];
          void *cgrp = (void *)ptrbuf[3];
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          int found = 0;
          ALLOC_KBUF(struct one_bpf_prog, ptrbuf[5])
          // lock
          mutex_lock(m);
          // iterate on roots
          idr_for_each_entry(genl, item, hierarchy_id)
          {
             struct cgroup_subsys_state *child;
             if ( (void *)item != root )
               continue;
             found |= 1;
             rcu_read_lock();
             // iterate on childres
             for (child = css_next_descendant_pre(NULL, &item->cgrp.self); child; child = css_next_descendant_pre(child, &item->cgrp.self) )
             {
               struct cgroup *cg = (struct cgroup *)child;
               if ( (void *)child != cgrp ) continue;
               found |= 3;
               if ( cg->bpf.effective[ptrbuf[4]] )
               {
                 int total = bpf_prog_array_length_ptr(cg->bpf.effective[ptrbuf[4]]);
                 for ( count = 0; count < total && count < ptrbuf[5]; count++, curr++ )
                 {
                   curr->prog = cg->bpf.effective[ptrbuf[4]]->items[count].prog;
                   if ( !curr->prog )
                     break;
                   fill_bpf_prog(curr, cg->bpf.effective[ptrbuf[4]]->items[count].prog);
                 }
               }
               break;
             }
             rcu_read_unlock();
             break;
          }
          // unlock
          mutex_unlock(m);
          // check that we found root and cgroup
          if ( 3 != found )
          {
             kfree(kbuf);
             return -ENOENT;
          }
          // copy to usermode
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_bpf_prog);
          goto copy_kbuf_count;
       }
      break; /* IOCTL_GET_CGROUP_BPF */
#endif

    case IOCTL_GET_CGROUP_SS:
        COPY_ARGS(5)
        if ( !ptrbuf[4] ) goto copy_count;
        else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          void *root = (void *)ptrbuf[2];
          void *cgrp = (void *)ptrbuf[3];
          unsigned long cnt = 2 * ptrbuf[4];
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          int found = 0;
          kbuf_size = sizeof(unsigned long) * (1 + cnt);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          // lock
          mutex_lock(m);
          // iterate on roots
          idr_for_each_entry(genl, item, hierarchy_id)
          {
             struct cgroup_subsys_state *child;
             if ( (void *)item != root )
               continue;
             found |= 1;
             rcu_read_lock();
             // iterate on childres
             for (child = css_next_descendant_pre(NULL, &item->cgrp.self); child; child = css_next_descendant_pre(child, &item->cgrp.self) )
             {
               int i;
               struct cgroup *cg = (struct cgroup *)child;
               if ( (void *)child != cgrp ) continue;
               found |= 3;
               // fill kbuf
               for ( i = 0; i < CGROUP_SUBSYS_COUNT; i++ )
               {
                 struct cgroup_subsys_state *what_ss = rcu_dereference_raw(cg->subsys[i]);
                 if ( !what_ss ) continue;
                 if ( count >= cnt ) break;
                 kbuf[1 + count] = (unsigned long)what_ss;
                 kbuf[2 + count] = (unsigned long)what_ss->ss;
                 count += 2;
               }
               break;
             }
             rcu_read_unlock();
             break;
          }
          // unlock
          mutex_unlock(m);
          // check that we found root and cgroup
          if ( 3 != found )
          {
             kfree(kbuf);
             return -ENOENT;
          }
          // copy to usermode
          kbuf_size = sizeof(unsigned long) * (1 + count);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_GET_CGROUP_SS */

    case IOCTL_GET_CGROUPS:
        COPY_ARGS(4)
        else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          void *root = (void *)ptrbuf[2];
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          int found = 0;
          ALLOC_KBUF(struct one_cgroup, ptrbuf[3])
          // lock
          mutex_lock(m);
          // iterate on roots
          idr_for_each_entry(genl, item, hierarchy_id)
          {
             struct cgroup_subsys_state *child;
             if ( (void *)item != root )
               continue;
             found++;
             rcu_read_lock();
             // iterate on childres
             for (child = css_next_descendant_pre(NULL, &item->cgrp.self); child && count < ptrbuf[3]; child = css_next_descendant_pre(child, &item->cgrp.self) )
             {
               if ( child == &item->cgrp.self ) continue;
               fill_one_cgroup(curr, child);
               count++; curr++;
             }
             rcu_read_unlock();
             break;
          }
          // unlock
          mutex_unlock(m);
          if ( !found )
          {
             kfree(kbuf);
             return -ENOENT;
          }
          // copy to usermode
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_cgroup);
          goto copy_kbuf_count;
        }
      break; /* IOCTL_GET_CGROUPS */

    case IOCTL_GET_CGRP_ROOTS:
        COPY_ARGS(3)
        else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            idr_for_each_entry(genl, item, hierarchy_id)
              count++;
            mutex_unlock(m);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_group_root, ptrbuf[2])
            mutex_lock(m);
            // iterate
            idr_for_each_entry(genl, item, hierarchy_id)
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)item;
              curr->kf_root = (void *)item->kf_root;
              curr->subsys_mask = item->subsys_mask;
              curr->hierarchy_id = item->hierarchy_id;
              curr->nr_cgrps = atomic_read(&item->nr_cgrps);
              curr->real_cnt = 0;
              // calc count of children manually - ripped from css_has_online_children
              if ( css_next_child_ptr )
              {
                struct cgroup_subsys_state *child;
                rcu_read_lock();
                for (child = css_next_descendant_pre(NULL, &item->cgrp.self); child; child = css_next_descendant_pre(child, &item->cgrp.self))
                {
                  if ( child == &item->cgrp.self ) continue;
                  curr->real_cnt++;
                }
                rcu_read_unlock();
              }
              curr->flags = item->flags;
              strlcpy(curr->name, item->name, 64);
              // fill this cgroup
              fill_one_cgroup(&curr->grp, &item->cgrp.self);
              // next iteration
              count++;
              curr++;
            }
            // unlock
            mutex_unlock(m);
            // copy to usermode
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_group_root);
            goto copy_kbuf_count;
          }
        }
      break; /* IOCTL_GET_CGRP_ROOTS */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
    case IOCTL_GENL_SMALLOPS:
       COPY_ARGS(3)
       // 0 - address of genl_fam_idr 
       // 1 - address of family
       // 2 - count
       if ( !ptrbuf[0] || !ptrbuf[1] || !ptrbuf[2] ) return -EINVAL;
       else {
        int found = 0;
        struct idr *genl = (struct idr *)ptrbuf[0];
        const struct genl_family *family;
        unsigned int id;
        ALLOC_KBUF(struct one_small_genlops, ptrbuf[2])
        genl_lock();
        idr_for_each_entry(genl, family, id)
        {
          if ( (unsigned long)family != ptrbuf[1] ) continue;
          found = 1;
          for ( count = 0; count < ptrbuf[2] && count < family->n_small_ops; count++, curr++ )
          {
            curr->addr = (void *)&family->small_ops[count];
            curr->doit = (unsigned long)family->small_ops[count].doit;
            curr->dumpit = (unsigned long)family->small_ops[count].dumpit;
            curr->cmd = family->small_ops[count].cmd;
            curr->flags = family->small_ops[count].flags;
          }
          break;
        }
        genl_unlock();
        if ( !found ) {
          kfree(kbuf);
          return -ENOENT;
        }
        kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_small_genlops);
        goto copy_kbuf_count;
       }
      break; /* IOCTL_GENL_SMALLOPS */
#endif

    case IOCTL_GET_GENL_FAMILIES:
        COPY_ARGS(2)
        else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          const struct genl_family *family;
          unsigned int id;
          if ( !ptrbuf[1] )
          {
            genl_lock();
            idr_for_each_entry(genl, family, id)
              count++;
            genl_unlock();
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_genl_family, ptrbuf[1])
            genl_lock();
            idr_for_each_entry(genl, family, id)
            {
              if ( count >= ptrbuf[1] )
                break;
              curr->addr = (void *)family;
              curr->id = family->id;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
              curr->policy = (void *)family->policy;
#endif
              curr->pre_doit = (unsigned long)family->pre_doit;
              curr->post_doit = (unsigned long)family->post_doit;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,8,0)
              curr->sock_priv_init = (unsigned long)family->sock_priv_init;
              curr->sock_priv_destroy = (unsigned long)family->sock_priv_destroy;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,7,10) && LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
              curr->mcast_bind = (void *)family->mcast_bind;
              curr->mcast_unbind = (void *)family->mcast_unbind;
#endif
              curr->ops = (void *)family->ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
              curr->small_ops = (void *)family->small_ops;
              curr->n_small_ops = family->n_small_ops;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0)
              curr->split_ops = (void *)family->split_ops;
              curr->n_split_ops = family->n_split_ops;
#endif
              strlcpy(curr->name, family->name, GENL_NAMSIZ);
              // next iteration
              count++;
              curr++;
            }
            genl_unlock();
            // copy to usermode
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_genl_family);
            goto copy_kbuf_count;
          }
        }
      break; /* IOCTL_GET_GENL_FAMILIES */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
    case IOCTL_GET_NL_SK:
        COPY_ARGS(4)
        if ( !ptrbuf[3] ) return -EINVAL;
        if ( ptrbuf[2] >= MAX_LINKS ) return -EFBIG;
        else {
          struct netlink_table *tab = *(struct netlink_table **)ptrbuf[0] + ptrbuf[2];
          rwlock_t *lock = (rwlock_t *)ptrbuf[1];
          int err = 0;
          struct rhashtable_iter iter;
          ALLOC_KBUF(struct one_nl_socket, ptrbuf[3])
          // lock
          read_lock(lock);
          // iterate
          rhashtable_walk_enter(&tab->hash, &iter);
          rhashtable_walk_start(&iter);
          for (;;) {
            struct netlink_sock *ns = rhashtable_walk_next(&iter);
            if (IS_ERR(ns)) {
              if (PTR_ERR(ns) == -EAGAIN) continue;
              err = PTR_ERR(ns);
              break;
            } else if (!ns)
              break;
            if ( count >= ptrbuf[3] )
              break;
            // copy fields
            curr->addr = (void *)ns;
            curr->portid = ns->portid;
            curr->dst_portid = ns->dst_portid;
            curr->state = ns->state;
            curr->flags  = ns->flags;
            curr->subscriptions = ns->subscriptions;
            curr->sk_type = ns->sk.sk_type;
            curr->sk_protocol = ns->sk.sk_protocol;
            curr->netlink_rcv = ns->netlink_rcv;
            curr->netlink_bind = ns->netlink_bind;
            curr->netlink_unbind = ns->netlink_unbind;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
            curr->netlink_release = ns->netlink_release;
#endif
            curr->cb_dump = ns->cb.dump;
            curr->cb_done = ns->cb.done;
            curr->sk_state_change = (void *)ns->sk.sk_state_change;
            curr->sk_data_ready = (void *)ns->sk.sk_data_ready;
            curr->sk_write_space = (void *)ns->sk.sk_write_space;
            curr->sk_error_report = (void *)ns->sk.sk_error_report;
            curr->sk_backlog_rcv = (void *)ns->sk.sk_backlog_rcv;
            curr->sk_destruct = (void *)ns->sk.sk_destruct;
#ifdef CONFIG_SOCK_VALIDATE_XMIT
            curr->sk_validate_xmit_skb = (void *)ns->sk.sk_validate_xmit_skb;
#endif
            // for next iteration
            count++;
            curr++;
          }
          rhashtable_walk_stop(&iter);
          rhashtable_walk_exit(&iter);
          // unlock
          read_unlock(lock);
          if ( err )
          {
            kfree(kbuf);
            return err;
          }
          // copy to user
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_nl_socket);
          goto copy_kbuf_count;
       }
     break; /* IOCTL_GET_NL_SK */
#endif

#ifdef CONFIG_BPF
    case IOCTL_GET_BTF:
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,18,0)
      return -EBADRQC;
#else
      COPY_ARG
      if ( !s_kind_ops ) return -ENOCSI;
      else if ( ptrbuf[0] == -1 )
      {
        // return NR_BTF_KINDS
        count = NR_BTF_KINDS;
        goto copy_count;
      } else if ( ptrbuf[0] >= NR_BTF_KINDS ) return -EINVAL;
      else if ( !s_kind_ops[ptrbuf[0]] )
        return -ENOENT;
      else {
        struct btf_op out_res;
        memset(&out_res, 0, sizeof(out_res));
        out_res.addr = (void *)s_kind_ops[ptrbuf[0]];
        out_res.check_meta = s_kind_ops[ptrbuf[0]]->check_meta;
        out_res.resolve = s_kind_ops[ptrbuf[0]]->resolve;
        out_res.check_member = s_kind_ops[ptrbuf[0]]->check_member;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
        out_res.check_kflag_member = s_kind_ops[ptrbuf[0]]->check_kflag_member;
#endif
        out_res.log_details = s_kind_ops[ptrbuf[0]]->log_details;
        out_res.show = s_kind_ops[ptrbuf[0]]->show;
        if ( copy_to_user((void*)ioctl_param, (void*)&out_res, sizeof(out_res)) > 0 )
         return -EFAULT;
      }
#endif /* >= 4.18 */
     break; /* IOCTL_GET_BTF*/

    case IOCTL_GET_BPF_USED_MAPS:
    case IOCTL_GET_BPF_OPCODES:
    case IOCTL_GET_BPF_PROG_BODY:
       COPY_ARGS(4)
       if ( !s_bpf_prog_put ) return -ENOCSI;
       else if ( !ptrbuf[3] )
         return -EINVAL;
       else {
         struct idr *links = (struct idr *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct bpf_prog *target = (struct bpf_prog *)ptrbuf[2];
         struct bpf_prog *prog;
         char *body = NULL;
         unsigned int id;

         spin_lock_bh(lock);
         idr_for_each_entry(links, prog, id)
         {
           if ( prog == target )
           {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
             atomic_inc(&prog->aux->refcnt);
#else
             bpf_prog_inc(prog);
#endif
             if ( IOCTL_GET_BPF_PROG_BODY == ioctl_num )
               body = (char *)prog->bpf_func;
             else if ( IOCTL_GET_BPF_USED_MAPS == ioctl_num && prog->aux )
               body = (char *)prog->aux->used_maps;
             else
               body = (char *)&prog->insnsi;
             break;
           }
         }
         spin_unlock_bh(lock);
         if ( !body )
           return -ENOENT;
         printk("ioctl %s body %p size %ld\n", get_ioctl_name(ioctl_num), body, ptrbuf[3]);
         // copy to user
         if (copy_to_user((void*)ioctl_param, (void*)body, ptrbuf[3]) > 0)
         {
           s_bpf_prog_put(prog);
           return -EFAULT;
         }
         s_bpf_prog_put(prog);
       }
     break; /* IOCTL_GET_BPF_PROG_BODY */

    case IOCTL_GET_BPF_PROGS:
       COPY_ARGS(3)
       else {
         struct idr *links = (struct idr *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct bpf_prog *prog;
         unsigned int id;
         if ( !ptrbuf[2] )
         {
            spin_lock_bh(lock);
            idr_for_each_entry(links, prog, id)
              count++;
            spin_unlock_bh(lock);
            goto copy_count;
         } else {
            ALLOC_KBUF(struct one_bpf_prog, ptrbuf[2])
            spin_lock_bh(lock);
            idr_for_each_entry(links, prog, id)
            {
              if ( count >= ptrbuf[1] )
                break;
              fill_bpf_prog(curr, prog);
              // next iteration
              count++;
              curr++;
            }
            spin_unlock_bh(lock);
            // copy to usermode
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_bpf_prog);
            goto copy_kbuf_count;
         }
       }
     break; /* IOCTL_GET_BPF_PROGS */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
    case IOCTL_GET_BPF_LINKS:
       COPY_ARGS(3)
       else {
         struct idr *links = (struct idr *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct bpf_link *link;
         unsigned int id;
         if ( !ptrbuf[2] )
         {
            spin_lock_bh(lock);
            idr_for_each_entry(links, link, id)
              count++;
            spin_unlock_bh(lock);
            goto copy_count;
         } else {
            ALLOC_KBUF(struct one_bpf_links, ptrbuf[2])
            spin_lock_bh(lock);
            idr_for_each_entry(links, link, id)
            {
              if ( count >= ptrbuf[1] )
                break;
              curr->addr = (void *)link;
              curr->id = link->id;
              curr->type = (int)link->type;
              curr->ops = (void *)link->ops;
              if ( link->ops )
              {
                curr->release = (void *)link->ops->release;
                curr->dealloc = (void *)link->ops->dealloc;
                curr->detach  = (void *)link->ops->detach;
                curr->update_prog = (void *)link->ops->update_prog;
                curr->show_fdinfo = (void *)link->ops->show_fdinfo;
                curr->fill_link_info = (void *)link->ops->fill_link_info;
              }
              curr->prog.prog = (void *)link->prog;
              if ( link->prog )
              {
                curr->prog.prog_type = (int)link->prog->type;
                curr->prog.expected_attach_type = (int)link->prog->expected_attach_type;
                curr->prog.len = link->prog->len;
                curr->prog.jited_len = link->prog->jited_len;
                curr->prog.bpf_func = (void *)link->prog->bpf_func;
                curr->prog.aux = (void *)link->prog->aux;
                if ( link->prog->aux )
                  curr->prog.aux_id = link->prog->aux->id;
              }
              // next iteration
              count++;
              curr++;
            }
            spin_unlock_bh(lock);
            // copy to usermode
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_bpf_links);
            goto copy_kbuf_count;
         }
       }
     break; /* IOCTL_GET_BPF_LINKS */
#endif
#endif /* CONFIG_BPF */

#if defined(CONFIG_TRACING) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
    case IOCTL_GET_TRACE_EXPORTS:
        COPY_ARGS(3)
        else {
          struct trace_export *te = *(struct trace_export **)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            while( te )
            {
              count++;
              te = te->next;
            }
            mutex_unlock(m);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_trace_export, ptrbuf[2])
            mutex_lock(m);
            while( te )
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr  = (void *)te;
              curr->write = (void *)te->write;
              curr->flags = te->flags;
              // next iteration
              te = te->next;
              curr++;
              count++;
            }
            mutex_unlock(m);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_export) * count;
            goto copy_kbuf_count;
          }
        }
     break; /* IOCTL_GET_TRACE_EXPORTS */
#endif

#if defined(CONFIG_BPF) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    case IOCTL_GET_BPF_RAW_EVENTS:
    case IOCTL_GET_BPF_RAW_EVENTS2:
        COPY_ARGS(3)
        else {
          struct bpf_raw_event_map *start = (struct bpf_raw_event_map *)ptrbuf[0];
          struct bpf_raw_event_map *end = (struct bpf_raw_event_map *)ptrbuf[1];
          if ( ioctl_num == IOCTL_GET_BPF_RAW_EVENTS2 ) end = start + ptrbuf[1];
          if ( !ptrbuf[2] )
          {
            count = end - start;
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_bpf_raw_event, ptrbuf[2])
            for ( ; start < end; start++ )
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)start;
              curr->tp = (void *)start->tp;
              curr->func = (void *)start->bpf_func;
              curr->num_args = start->num_args;
              curr++;
              count++;
            }
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_raw_event) * count;
            goto copy_kbuf_count;
          }
        }
     break; /* IOCTL_GET_BPF_RAW_EVENTS */
#endif /* CONFIG_BPF */

#ifdef CONFIG_FUNCTION_TRACER
    case IOCTL_GET_FTRACE_OPS:
        if ( !s_ftrace_end )
          return -ENOCSI;
        COPY_ARGS(3)
        else
        {
          struct ftrace_ops **head = (struct ftrace_ops **)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          struct ftrace_ops *p;
          if ( !ptrbuf[2] )
          {
            // lock
            mutex_lock(m);
            for ( p = *head; p != s_ftrace_end; p = p->next )
              count++;
            // unlock
            mutex_unlock(m);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_ftrace_ops, ptrbuf[2])
            // lock
            mutex_lock(m);
            // iterate
            for ( p = *head; p != s_ftrace_end; p = p->next )
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)p;
              curr->func = (void *)p->func;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,5)
              curr->saved_func = (void *)p->saved_func;
#endif
              curr->flags = p->flags;
              curr++;
              count++;
            }
            // unlock
            mutex_unlock(m);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_ftrace_ops) * count;
            goto copy_kbuf_count;
          }
        }
     break; /* IOCTL_GET_FTRACE_OPS */
#endif /* CONFIG_FUNCTION_TRACER */

    case IOCTL_GET_FTRACE_CMDS:
        COPY_ARGS(3)
        else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          struct ftrace_func_command *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              count++;
            mutex_unlock(m);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_tracefunc_cmd, ptrbuf[2])
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)ti;
              curr->func = ti->func;
              strlcpy(curr->name, ti->name, sizeof(curr->name));
              curr++;
              count++;
            }
            mutex_unlock(m);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_tracefunc_cmd) * count;
            goto copy_kbuf_count;
          }
        }
     break; /* IOCTL_GET_FTRACE_CMDS */

#ifdef CONFIG_DYNAMIC_EVENTS
    case IOCTL_GET_DYN_EVENTS:
        COPY_ARGS(3)
        else {
          struct dyn_event *pos;
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(pos, head, list)
              count++;
            mutex_unlock(m);
#ifdef _DEBUG
            printk("IOCTL_GET_DYN_EVENTS %ld\n", cnt);
#endif /* _DEBUG */
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_tracepoint_func, ptrbuf[2])
            mutex_lock(m);
            list_for_each_entry(pos, head, list)
            {
              if ( kbuf[0] >= ptrbuf[1] )
                break;
              curr->addr = (unsigned long)pos;
              curr->data = (unsigned long)pos->ops;
              curr++;
              kbuf[0]++;
            }
            mutex_unlock(m);
            kbuf_size = sizeof(unsigned long) + kbuf[0] * sizeof(struct one_tracepoint_func);
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_DYN_EVENTS */

    case IOCTL_GET_DYN_EVT_OPS:
        COPY_ARGS(3)
        else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          struct dyn_event_operations *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              count++;
            mutex_unlock(m);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_dyn_event_op, ptrbuf[2])
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)ti;
              curr->create     = ti->create;
              curr->show       = ti->show;
              curr->is_busy    = ti->is_busy;
              curr->free       = ti->free;
              curr->match      = ti->match;
              curr++;
              count++;
            }
            mutex_unlock(m);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_dyn_event_op) * count;
            goto copy_kbuf_count;
          }
        }
     break; /* IOCTL_GET_DYN_EVT_OPS */
#endif /* CONFIG_DYNAMIC_EVENTS */

    case IOCTL_GET_EVT_CALLS:
        if ( !s_trace_event_sem || !s_event_mutex || !s_ftrace_events )
          return -ENOCSI;
        COPY_ARGS(2)
        if ( !ptrbuf[0] )
        {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
          struct trace_event_call *call, *p;
#else
          struct ftrace_event_call *call, *p;
#endif
          if ( !ptrbuf[1] )
          {
            // just count of registered events
            down_read(s_trace_event_sem);
            list_for_each_entry_safe(call, p, s_ftrace_events, list)
              count++;
            up_read(s_trace_event_sem);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_trace_event_call, ptrbuf[1])
            down_read(s_trace_event_sem);
            list_for_each_entry_safe(call, p, s_ftrace_events, list)
            {
              if ( count >= ptrbuf[1] )
                break;
              copy_trace_event_call(call, curr);
              // for next iteration
              count++;
              curr++;
            }
            up_read(s_trace_event_sem);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_event_call) * count;
            goto copy_kbuf_count;
          }
        } else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
        if ( !s_bpf_event_mutex ) return -ENOCSI;
        else {
          // copy bpf_progs for some event
          int found = 0;
          struct trace_event_call *call, *p;
          ALLOC_KBUF(struct one_bpf_prog, ptrbuf[1])
          down_read(s_trace_event_sem);
          list_for_each_entry_safe(call, p, s_ftrace_events, list)
          {
             int total;
             if ( (unsigned long)call != ptrbuf[0] )
               continue;
             if ( !call->prog_array )
               break;
             mutex_lock(s_bpf_event_mutex);
             total = bpf_prog_array_length_ptr(call->prog_array);
             for ( count = 0; count < total && count < ptrbuf[1]; count++, curr++ )
             {
               curr->prog = call->prog_array->items[count].prog;
               if ( !curr->prog )
                 break;
               fill_bpf_prog(curr, call->prog_array->items[count].prog);
             }
             mutex_unlock(s_bpf_event_mutex);
             found++;
             break;
          }
          up_read(s_trace_event_sem);
          if ( !found )
          {
             kfree(kbuf);
             return -ENOENT;
          }
          kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_prog) * count;
          goto copy_kbuf_count;
          }
#else
          return -EBADRQC;
#endif
        }
     break; /* IOCTL_GET_EVT_CALLS */

    case IOCTL_GET_EVENT_CMDS:
        COPY_ARGS(3)
        else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          struct event_command *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              count++;
            mutex_unlock(m);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_event_command, ptrbuf[2])
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)ti;
              curr->func            = ti->func;
              curr->reg             = ti->reg;
              curr->unreg           = ti->unreg;
              curr->unreg_all       = ti->unreg_all;
              curr->set_filter      = ti->set_filter;
              curr->get_trigger_ops = ti->get_trigger_ops;
              curr->trigger_type    = (int)ti->trigger_type;
              curr->flags           = ti->flags;
              strlcpy(curr->name, ti->name, sizeof(curr->name));
              curr++;
              count++;
            }
            mutex_unlock(m);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_event_command) * count;
            goto copy_kbuf_count;
          }
        }
     break; /* IOCTL_GET_EVENT_CMDS */

#if defined(CONFIG_BPF) && LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
    case IOCTL_GET_BPF_REGS:
        COPY_ARGS(3)
        else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          struct bpf_iter_target_info *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              count++;
            mutex_unlock(m);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_bpf_reg, ptrbuf[2])
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( count >= ptrbuf[2] )
                break;
              if ( !ti->reg_info )
                continue;
              curr->addr = (void *)ti->reg_info;
              curr->attach_target   = (void *)ti->reg_info->attach_target;
              curr->detach_target   = (void *)ti->reg_info->detach_target;
              curr->show_fdinfo     = (void *)ti->reg_info->show_fdinfo;
              curr->fill_link_info  = (void *)ti->reg_info->fill_link_info;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,9,0)
              curr->seq_info        = (void *)ti->reg_info->seq_info;
              if ( curr->seq_info )
              {
                curr->seq_ops = (void *)ti->reg_info->seq_info->seq_ops;
                curr->init_seq_private = (void *)ti->reg_info->seq_info->init_seq_private;
                curr->fini_seq_private = (void *)ti->reg_info->seq_info->fini_seq_private;
              }
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
              curr->feature         = ti->reg_info->feature;
#endif
              curr++;
              count++;
            }
            mutex_unlock(m);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_reg) * count;
            goto copy_kbuf_count;
          }
        }
     break; /* IOCTL_GET_BPF_REGS */

    case IOCTL_GET_BPF_KSYMS:
        COPY_ARGS(3)
        else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          spinlock_t *lock = (spinlock_t *)ptrbuf[1];
          struct bpf_ksym *ti;
          if ( !ptrbuf[2] )
          {
            spin_lock_bh(lock);
            list_for_each_entry(ti, head, lnode)
              count++;
            spin_unlock_bh(lock);
            goto copy_count;
          } else {
            ALLOC_KBUF(struct one_bpf_ksym, ptrbuf[2])
            spin_lock_bh(lock);
            list_for_each_entry(ti, head, lnode)
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = ti;
              curr->start = ti->start;
              curr->end = ti->end;
              curr->prog = ti->prog;
              strlcpy(curr->name, ti->name, sizeof(curr->name));
              curr++;
              count++;
            }
            spin_unlock_bh(lock);
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_ksym) * count;
            goto copy_kbuf_count;
          }
       }
     break; /* IOCTL_GET_BPF_KSYMS */
#endif /* CONFIG_BPF */

#ifdef CONFIG_ZPOOL
    case IOCTL_GET_ZPOOL_DRV:
      if ( !z_drivers_head || !z_drivers_lock ) return -ENOCSI;
      COPY_ARG
      if ( !ptrbuf[0] )
      {
        // count of registered zpool drivers
        struct zpool_driver *driver;
        spin_lock(z_drivers_lock);
        list_for_each_entry(driver, z_drivers_head, list) count++;
        spin_unlock(z_drivers_lock);
        goto copy_count;
      } else {
        struct zpool_driver *driver;
        ALLOC_KBUF(struct one_zpool, ptrbuf[0])
        // lock
        spin_lock(z_drivers_lock);
        // iterate
        list_for_each_entry(driver, z_drivers_head, list)
        {
          if ( count >= ptrbuf[0] ) break;
          curr->addr = driver;
          curr->module = driver->owner;
          curr->create = (unsigned long)driver->create;
          curr->destroy = (unsigned long)driver->destroy;
          curr->malloc = (unsigned long)driver->malloc;
          curr->free = (unsigned long)driver->free;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
          curr->shrink = (unsigned long)driver->shrink;
#endif
          curr->map = (unsigned long)driver->map;
          curr->unmap = (unsigned long)driver->unmap;
          curr->total_size = (unsigned long)driver->total_size;
          // for next
          count++; curr++;
        }
        // unlock
        spin_unlock(z_drivers_lock);
        // copy to user
        kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_zpool);
        goto copy_kbuf_count;
      }
     break; /* IOCTL_GET_ZPOOL_DRV */
#endif /* CONFIG_ZPOOL */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,0,0)
// for some unknown reason in this case kmem_cache defined in non-includeable mm/slab.h file
#ifndef CONFIG_SLOB
    case IOCTL_SLAB_NAME:
      if ( !s_slab_caches || !s_slab_mutex ) return -ENOCSI;
      COPY_ARGS(2)
      if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
      else {
        struct kmem_cache *cachep;
        int found = 0;
        kbuf = kmalloc(ptrbuf[1], GFP_KERNEL | __GFP_ZERO);
        if ( !kbuf ) return -ENOMEM;
        // lock
        mutex_lock(s_slab_mutex);
        list_for_each_entry(cachep, s_slab_caches, list)
        {
          if ( (unsigned long)cachep != ptrbuf[0] ) continue;
          found = 1;
          if ( cachep->name )
           {
             kbuf_size = 1 + strlen(cachep->name);
             if ( kbuf_size > ptrbuf[1] ) kbuf_size = ptrbuf[1];
             strlcpy((char *)kbuf, cachep->name, kbuf_size);
           }
           break;
        }
        // unlock
        mutex_unlock(s_slab_mutex);
        if ( !found ) { kfree(kbuf); return -ENOENT; }
        if ( !kbuf_size ) { kfree(kbuf); return -ENOTNAM; }
        goto copy_kbuf;
      }
     break; /* IOCTL_SLAB_NAME */

    case IOCTL_GET_SLABS:
      if ( !s_slab_caches || !s_slab_mutex ) return -ENOCSI;
      COPY_ARG
      if ( !ptrbuf[0] )
      {
        struct kmem_cache *cachep;
        mutex_lock(s_slab_mutex);
        list_for_each_entry(cachep, s_slab_caches, list) count++;
        mutex_unlock(s_slab_mutex);
        goto copy_count;
      } else {
        struct kmem_cache *cachep;
        ALLOC_KBUF(struct one_slab, ptrbuf[0])
        // lock
        mutex_lock(s_slab_mutex);
        list_for_each_entry(cachep, s_slab_caches, list)
        {
          if ( count >= ptrbuf[0] ) break;
          curr->addr = (void *)cachep;
          curr->size = cachep->size;
          if ( cachep->name ) curr->l_name = 1 + strlen(cachep->name);
          curr->ctor = (unsigned long)cachep->ctor;
#ifdef CONFIG_SLUB
          curr->object_size = cachep->object_size;
#endif
          // for next iter
          count++; curr++;
        }
        // unlock
        mutex_unlock(s_slab_mutex);
        kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_slab);
        goto copy_kbuf_count;
      }
     break; /* IOCTL_GET_SLABS */
#endif /* CONFIG_SLOB */
#endif

#ifdef CONFIG_MAGIC_SYSRQ
    case IOCTL_SYSRQ_KEYS:
     if ( !s_sysrq_key_table_lock || !s_sysrq_key_table ) return -ENOCSI;
     COPY_ARG
      if ( !ptrbuf[0] )
      {
        int i;
        spin_lock(s_sysrq_key_table_lock);
        for ( i = 0; i < MAGIC_SIZE; ++i )
          if ( s_sysrq_key_table[i] ) count++;
        spin_unlock(s_sysrq_key_table_lock);
        goto copy_count;
      } else {
        int i;
        ALLOC_KBUF(struct one_sysrq_key, ptrbuf[0])
        spin_lock(s_sysrq_key_table_lock);
        for ( i = 0; i < MAGIC_SIZE; ++i )
        {
          if ( count >= ptrbuf[0] ) break;
          if ( !s_sysrq_key_table[i] ) continue;
          curr->addr = s_sysrq_key_table[i];
          curr->handler = s_sysrq_key_table[i]->handler;
          curr->mask = s_sysrq_key_table[i]->enable_mask;
          curr->idx = i;
          // for next iteration
          curr++; count++;
        }
        spin_unlock(s_sysrq_key_table_lock);
        kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_sysrq_key);
        goto copy_kbuf_count;
      }
     break; /* IOCTL_SYSRQ_KEYS */
#endif

    case IOCTL_BINFMT:
      if ( !s_formats || !s_binfmt_lock ) return -ENOCSI;
      COPY_ARG
      if ( !ptrbuf[0] )
      {
        struct linux_binfmt *fmt;
        read_lock(s_binfmt_lock);
        list_for_each_entry(fmt, s_formats, lh) count++;
        read_unlock(s_binfmt_lock);
        goto copy_count;
      } else {
        struct linux_binfmt *fmt;
        ALLOC_KBUF(struct one_binfmt, ptrbuf[0])
        read_lock(s_binfmt_lock);
        list_for_each_entry(fmt, s_formats, lh)
        {
          if ( count >= ptrbuf[0] ) break;
          curr->addr = fmt;
          curr->mod = fmt->module;
          curr->load_binary = fmt->load_binary;
          curr->load_shlib = fmt->load_shlib;
          curr->core_dump = fmt->core_dump;
          // for next iteration
          count++; curr++;
        }
        read_unlock(s_binfmt_lock);
        kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_binfmt);
        goto copy_kbuf_count;
      }
     break;

    case IOCTL_ENUM_CALGO:
     COPY_ARGS(3)
     else {
       struct list_head *head = (struct list_head *)ptrbuf[0];
       struct rw_semaphore *cs = (struct rw_semaphore *)ptrbuf[1];
       struct crypto_alg *q;
       if ( !ptrbuf[2] )
       {
         down_read(cs);
         list_for_each_entry(q, head, cra_list) count++;
         up_read(cs);
         goto copy_count;
       } else {
          ALLOC_KBUF(struct one_kcalgo, ptrbuf[2])
          down_read(cs);
          list_for_each_entry(q, head, cra_list)
          {
            if ( count >= ptrbuf[2] )
               break;
            curr->addr = q;
            curr->flags = q->cra_flags;
            curr->c_blocksize = q->cra_blocksize;
            curr->c_ctxsize = q->cra_ctxsize;
            strlcpy(curr->name, q->cra_name, sizeof(curr->name));
            curr->c_type = (void *)q->cra_type;
            if ( curr->c_type )
            {
              curr->ctxsize = q->cra_type->ctxsize;
              curr->extsize = q->cra_type->extsize;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,5,0)
              curr->init = q->cra_type->init;
#endif
              curr->init_tfm = q->cra_type->init_tfm;
              curr->show = q->cra_type->show;
              curr->report = q->cra_type->report;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,2,0)
              curr->free = q->cra_type->free;
#endif
              curr->tfmsize = q->cra_type->tfmsize;
            }
            curr->what = q->cra_flags & CRYPTO_ALG_TYPE_MASK;
            // copy algo methods
            if ( curr->what == CRYPTO_ALG_TYPE_COMPRESS )
            {
              curr->comp.coa_compress = (unsigned long)q->cra_u.compress.coa_compress;
              curr->comp.coa_decompress = (unsigned long)q->cra_u.compress.coa_decompress;
            } else if ( curr->what == CRYPTO_ALG_TYPE_CIPHER ) {
              curr->cip.cia_min_keysize = q->cra_u.cipher.cia_min_keysize;
              curr->cip.cia_max_keysize = q->cra_u.cipher.cia_max_keysize;
              curr->cip.cia_setkey = (unsigned long)q->cra_u.cipher.cia_setkey;
              curr->cip.cia_encrypt = (unsigned long)q->cra_u.cipher.cia_encrypt;
              curr->cip.cia_decrypt = (unsigned long)q->cra_u.cipher.cia_decrypt;
            } else if ( curr->what == CRYPTO_ALG_TYPE_SHASH )
              copy_shash(curr, q);
            else if ( curr->what == CRYPTO_ALG_TYPE_AHASH )
              copy_ahash(curr, q);
            else if ( curr->what == CRYPTO_ALG_TYPE_AEAD )
              copy_aead(curr, q);
            else if ( curr->what == CRYPTO_ALG_TYPE_RNG )
              copy_rng(curr, q);
#ifdef CRYPTO_ALG_TYPE_SCOMPRESS
            else if ( curr->what == CRYPTO_ALG_TYPE_SCOMPRESS )
              copy_scomp(curr, q);
#endif
#ifdef CRYPTO_ALG_TYPE_ACOMPRESS
            else if ( curr->what == CRYPTO_ALG_TYPE_ACOMPRESS )
              copy_acomp(curr, q);
#endif
#ifdef CRYPTO_ALG_TYPE_KPP
            else if ( curr->what == CRYPTO_ALG_TYPE_KPP )
              copy_kpp(curr, q);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,5,0)
            else if ( curr->what == CRYPTO_ALG_TYPE_BLKCIPHER )
              copy_blkcipher(curr, q);
            else if ( curr->what == CRYPTO_ALG_TYPE_ABLKCIPHER )
              copy_ablkcipher(curr, q);
#endif
#ifdef CRYPTO_ALG_TYPE_AKCIPHER
            else if ( curr->what == CRYPTO_ALG_TYPE_AKCIPHER )
              copy_akcipher(curr, q);
#endif
            curr->cra_init = q->cra_init;
            curr->cra_exit = q->cra_exit;
            curr->cra_destroy = q->cra_destroy;
            curr++;
            count++;
          }
          up_read(cs);
          kbuf_size = sizeof(unsigned long) + sizeof(struct one_kcalgo) * count;
          goto copy_kbuf_count;
       }
     }
     break; /* IOCTL_ENUM_CALGO */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
    case IOCTL_GET_LSM_HOOKS:
     COPY_ARGS(2)
     else {
       struct security_hook_list *shl;
       struct hlist_head *head = (struct hlist_head *)ptrbuf[0];
         // there is no sync - all numerous security_xxx just call call_xx_hook
         if ( !ptrbuf[1] )
        {
          hlist_for_each_entry(shl, head, list)
            count++;
          goto copy_count;
        } else {
          kbuf_size = sizeof(unsigned long) * (ptrbuf[1] + 1);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
            return -ENOMEM;
          hlist_for_each_entry(shl, head, list)
          {
            if ( count >= ptrbuf[1] )
              break;
            kbuf[1 + count] = *(unsigned long *)(&shl->hook);
            count++;
          }
          kbuf_size = sizeof(unsigned long) * (count + 1);
          goto copy_kbuf_count;
        }
      }
      break; /* IOCTL_GET_LSM_HOOKS */
#endif // lsm hooks where introduced since 4.2

#ifdef CONFIG_INPUT
    case IOCTL_INPUT_DEV_NAME:
      if ( !s_input_dev_list || !s_input_mutex ) return -ENOCSI;
       COPY_ARGS(3)
       if ( !ptrbuf[0] || !ptrbuf[1] || ptrbuf[2] > 3 ) return -EINVAL;
       if ( ptrbuf[2] == 3 ) {
        int found = 0;
        struct input_dev *dev;
        kbuf = kmalloc((1 + ptrbuf[1]) * sizeof(unsigned long), GFP_KERNEL);
        if ( !kbuf ) return -ENOMEM;
        // lock
        mutex_lock(s_input_mutex);
        list_for_each_entry(dev, s_input_dev_list, node)
        {
          struct input_handle *handle, *next;
          if ( ptrbuf[0] != (unsigned long)dev ) continue;
          found = 1;
          list_for_each_entry_safe(handle, next, &dev->h_list, d_node) {
            if ( count >= ptrbuf[1] ) break;
            kbuf[count + 1] = (unsigned long)handle->handler;
            count++;
          }
          break;
        }
        // unlock
        mutex_unlock(s_input_mutex);
        if ( !found ) { kfree(kbuf); return -ENOENT; }
        kbuf_size = (1 + count) * sizeof(unsigned long);
        goto copy_kbuf_count;
       } else {
        int found = 0;
        struct input_dev *dev;
        const char *sbuf = NULL;
        kbuf = kmalloc(ptrbuf[1], GFP_KERNEL | __GFP_ZERO);
        if ( !kbuf ) return -ENOMEM;
        // lock
        mutex_lock(s_input_mutex);
        list_for_each_entry(dev, s_input_dev_list, node)
        {
          if ( ptrbuf[0] != (unsigned long)dev ) continue;
          found = 1;
          switch(ptrbuf[2])
          {
            case 0: sbuf = dev->name; break;
            case 1: sbuf = dev->phys; break;
            case 2: sbuf = dev->uniq; break;
          }
          if ( sbuf )
          {
            kbuf_size = 1 + strlen(sbuf);
            if ( kbuf_size > ptrbuf[1] ) kbuf_size = ptrbuf[1];
            strlcpy((char *)kbuf, sbuf, kbuf_size);
          }
          break;
        }
        // unlock
        mutex_unlock(s_input_mutex);
        if ( !found ) { kfree(kbuf); return -ENOENT; }
        if ( !kbuf_size ) { kfree(kbuf); return -ENOTNAM; }
        goto copy_kbuf;
       }
     break; /* IOCTL_INPUT_DEV_NAME */

    case IOCTL_INPUT_DEVS:
      if ( !s_input_dev_list || !s_input_mutex ) return -ENOCSI;
       COPY_ARG
       if ( !ptrbuf[0] )
       {
         struct input_dev *dev;
         // calc count
         mutex_lock(s_input_mutex);
         list_for_each_entry(dev, s_input_dev_list, node) count++;
         mutex_unlock(s_input_mutex);
         goto copy_count;
       } else {
          struct input_dev *dev;
          ALLOC_KBUF(struct one_input_dev, ptrbuf[0])
          // lock
          mutex_lock(s_input_mutex);
          // iterate
          list_for_each_entry(dev, s_input_dev_list, node)
          {
            struct input_handle *handle, *next;
            if ( count >= ptrbuf[0] ) break;
            curr->addr = dev;
            if ( dev->name ) curr->l_name = 1 + strlen(dev->name);
            if ( dev->phys ) curr->l_phys = 1 + strlen(dev->phys);
            if ( dev->uniq ) curr->l_uniq = 1 + strlen(dev->uniq);
            curr->setkeycode = (void *)dev->setkeycode;
            curr->getkeycode = (void *)dev->getkeycode;
            curr->open = (void *)dev->open;
            curr->close = (void *)dev->close;
            curr->flush = (void *)dev->flush;
            curr->event = (void *)dev->event;
            curr->ff = dev->ff;
            if ( dev->ff ) {
              curr->ff_upload = (void *)dev->ff->upload;
              curr->ff_erase = (void *)dev->ff->erase;
              curr->ff_playback = (void *)dev->ff->playback;
              curr->ff_set_gain = (void *)dev->ff->set_gain;
              curr->ff_set_autocenter = (void *)dev->ff->set_autocenter;
              curr->ff_destroy = (void *)dev->ff->destroy;
            }
            // count handlers
            list_for_each_entry_safe(handle, next, &dev->h_list, d_node) curr->h_cnt++;
            // for next iteration
            curr++; count++;
          }
          // unlock
          mutex_unlock(s_input_mutex);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_input_dev);
          goto copy_kbuf_count;
       }
     break; /* IOCTL_INPUT_DEVS */

    case IOCTL_INPUT_HANDLER_NAME:
       if ( !s_input_handler_list || !s_input_mutex ) return -ENOCSI;
       COPY_ARGS(2)
       if ( !ptrbuf[0] || !ptrbuf[1] ) return -EINVAL;
       else {
         struct input_handler *handler;
         int found = 0;
         kbuf = kmalloc(ptrbuf[1], GFP_KERNEL | __GFP_ZERO);
         if ( !kbuf )
          return -ENOMEM;
         mutex_lock(s_input_mutex);
         list_for_each_entry(handler, s_input_handler_list, node) {
           if ( ptrbuf[0] != (unsigned long)handler ) continue;
           found = 1;
           if ( handler->name )
           {
             kbuf_size = 1 + strlen(handler->name);
             if ( kbuf_size > ptrbuf[1] ) kbuf_size = ptrbuf[1];
             strlcpy((char *)kbuf, handler->name, kbuf_size);
           }
           break;
         }
         mutex_unlock(s_input_mutex);
         if ( !found ) { kfree(kbuf); return -ENOENT; }
         if ( !kbuf_size ) { kfree(kbuf); return -ENOTNAM; }
         goto copy_kbuf;
       }
     break; /* IOCTL_INPUT_HANDLER_NAME */

    case IOCTL_INPUT_HANDLERS:
       if ( !s_input_handler_list || !s_input_mutex ) return -ENOCSI;
       COPY_ARG
       if ( !ptrbuf[0] )
       {
         struct input_handler *handler;
         // calc count
         mutex_lock(s_input_mutex);
         list_for_each_entry(handler, s_input_handler_list, node) count++;
         mutex_unlock(s_input_mutex);
         goto copy_count;
       } else {
          struct input_handler *handler;
          ALLOC_KBUF(struct one_input_handler, ptrbuf[0])
          // lock
          mutex_lock(s_input_mutex);
          // iterate
          list_for_each_entry(handler, s_input_handler_list, node) {
            if ( count >= ptrbuf[0] ) break;
            curr->addr = handler;
            curr->event = (void *)handler->event;
            curr->events = (void *)handler->events;
            curr->filter = (void *)handler->filter;
            curr->match = (void *)handler->match;
            curr->connect = (void *)handler->connect;
            curr->disconnect = (void *)handler->disconnect;
            curr->start = (void *)handler->start;
            if ( handler->name )
              curr->l_name = 1 + strlen(handler->name);
            // for next iteration
            curr++; count++;
          }
          // unlock
          mutex_unlock(s_input_mutex);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_input_handler);
          goto copy_kbuf_count;
       } 
      break; /* IOCTL_INPUT_HANDLERS */
#endif /* CONFIG_INPUT */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
    case IOCTL_GET_ALARMS:
      if ( !s_alarm ) return -ENOCSI;
      COPY_ARGS(2)
      if ( ptrbuf[0] >= ALARM_NUMTYPE )
        return -EINVAL;
      else {
        struct alarm_base *ca = s_alarm + ptrbuf[0];
        struct rb_node *iter;
        unsigned long flags;
        if ( !ptrbuf[1] )
        {
          // calc count of alarms
          ptrbuf[0] = 0;
          // lock
          spin_lock_irqsave(&ca->lock, flags);
          // before 4.14 timerqueue_head has head & next fields
          for ( iter = rb_first(&ca->timerqueue.rb_root.rb_root); iter != NULL; iter = rb_next(iter) )
            ptrbuf[0]++;
          // unlock
          spin_unlock_irqrestore(&ca->lock, flags);
          ptrbuf[1] = (unsigned long)ca->get_ktime;
          ptrbuf[2] = (unsigned long)ca->get_timespec;
          // copy to user-mode
          kbuf_size = 3;
          goto copy_ptrbuf;
        } else {
          ALLOC_KBUF(struct one_alarm, ptrbuf[1])
          // lock
          spin_lock_irqsave(&ca->lock, flags);
          for ( iter = rb_first(&ca->timerqueue.rb_root.rb_root); iter != NULL && count < ptrbuf[1]; iter = rb_next(iter) )
          {
            struct timerqueue_node *node = rb_entry(iter, struct timerqueue_node, node);
            struct alarm *a = (struct alarm *)node;
            curr->addr = node;
            curr->hr_timer = a->timer.function;
            curr->func = a->function;
            // for next iteration
            count++;
            curr++;
          }
          // unlock
          spin_unlock_irqrestore(&ca->lock, flags);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_alarm);
          // copy collected data to user-mode
          goto copy_kbuf_count;
        }
      }
     break; /* IOCTL_GET_ALARMS */

    case IOCTL_GET_KTIMERS:
     COPY_ARGS(2)
     else {
      struct timer_base *tb = (struct timer_base *)ptrbuf[0];
      unsigned long flags = 0;
      int idx;
      struct timer_list *tl;
      if ( !ptrbuf[1] )
      {
        // calc count of timers
        raw_spin_lock_irqsave(&tb->lock, flags);
        for ( idx = 0; idx < WHEEL_SIZE; idx++ )
        {
          hlist_for_each_entry(tl, &tb->vectors[idx], entry)
            count++;
        }
        // unlock
        raw_spin_unlock_irqrestore(&tb->lock, flags);
#if (BASE_STD	!= BASE_DEF)
        tb++;
        // lock
        raw_spin_lock_irqsave(&tb->lock, flags);
        for ( idx = 0; idx < WHEEL_SIZE; idx++ )
        {
          hlist_for_each_entry(tl, &tb->vectors[idx], entry)
            count++;
        }
        // unlock
        raw_spin_unlock_irqrestore(&tb->lock, flags);
#endif
        goto copy_count;
      } else {
         ALLOC_KBUF(struct ktimer, ptrbuf[1])
         // lock
         raw_spin_lock_irqsave(&tb->lock, flags);
         for ( idx = 0; idx < WHEEL_SIZE && count < ptrbuf[1]; idx++ )
         {
           hlist_for_each_entry(tl, &tb->vectors[idx], entry)
           {
             if ( count >= ptrbuf[1] )
               break;
             curr->addr = tl;
             curr->wq_addr = NULL;
             curr->exp = tl->expires;
             if ( delayed_timer == tl->function )
             {
               struct delayed_work *dwork = from_timer(dwork, tl, timer);
               curr->wq_addr = dwork;
               curr->func = dwork->work.func;
             } else
               curr->func = tl->function;
             curr->flags = tl->flags;
             curr++;
             count++;
           }
         }
         // unlock
         raw_spin_unlock_irqrestore(&tb->lock, flags);
#if (BASE_STD	!= BASE_DEF)
         tb++;
         // lock
         raw_spin_lock_irqsave(&tb->lock, flags);
         for ( idx = 0; idx < WHEEL_SIZE && count < ptrbuf[1]; idx++ )
         {
           hlist_for_each_entry(tl, &tb->vectors[idx], entry)
           {
             if ( count >= ptrbuf[1] )
               break;
             curr->addr = tl;
             curr->wq_addr = NULL;
             curr->exp = tl->expires;
             if ( delayed_timer == tl->function )
             {
               struct delayed_work *dwork = from_timer(dwork, tl, timer);
               curr->wq_addr = dwork;
               curr->func = dwork->work.func;
             } else
               curr->func = tl->function;
             curr->flags = tl->flags;
             curr++;
             count++;
           }
         }
         // unlock
         raw_spin_unlock_irqrestore(&tb->lock, flags);
#endif
         // copy collected data to user-mode
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct ktimer);
         goto copy_kbuf_count;
      }
     }
     break; /* IOCTL_GET_KTIMERS */
#endif

#ifdef CONFIG_KEYS
    case IOCTL_KEYTYPE_NAME:
      if ( !s_key_types_sem ) return -ENOCSI;
      COPY_ARG
      else {
        struct key_type *p;
        size_t len;
        int err;
        down_read(s_key_types_sem);
        list_for_each_entry(p, s_key_types_list, link)
        {
          if ( (unsigned long)p != ptrbuf[0] ) continue;
          if ( !p->name ) {
            up_read(s_key_types_sem);
            return -ENOTNAM;    
          }
          len = strlen(p->name);
          err = copy_to_user((void*)ioctl_param, (void*)p->name, len + 1);
          up_read(s_key_types_sem);
          return (err > 0) ? -EFAULT : 0;
        }
        up_read(s_key_types_sem);
        return -ENOKEY;
      }
     break; /* IOCTL_KEYTYPE_NAME */

    case IOCTL_READ_KEY:
      if ( !f_key_lookup)
        return -ENOCSI;
      COPY_ARGS(2)
      else {
        struct key *k = f_key_lookup((key_serial_t)ptrbuf[0]);
        if ( IS_ERR(k) ) return PTR_ERR(k);
        if ( !k->datalen || !k->type || !k->type->read ) 
        {
          key_put(k);
          return -ENODATA;
        } else {
          long ret;
          kbuf_size = ptrbuf[1];
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
          {
            key_put(k);
            return -ENOMEM;
          }
          // ripped from __keyctl_read_key
          down_read(&k->sem);
          ret = key_validate(k);
          if ( ret == 0 ) ret = k->type->read(k, (char *)kbuf, kbuf_size);
          up_read(&k->sem);
          key_put(k);
          if ( ret <= 0 )
          {
            kfree(kbuf);
            return ret;
          }
          goto copy_kbuf;
        }
      }
     break; /* IOCTL_READ_KEY */

    case IOCTL_GET_KEY_DESC:
      if ( !f_key_lookup)
        return -ENOCSI;
      COPY_ARG
      else {
        int len, err;
        struct key *k = f_key_lookup((key_serial_t)ptrbuf[0]);
        if ( IS_ERR(k) ) return PTR_ERR(k);
 #if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
 # define KEY_DESC_LEN(k) k->len_desc
 #else
 # define KEY_DESC_LEN(k) k->index_key.desc_len
 #endif 
        if ( !(KEY_DESC_LEN(k) & 0xffff) || !k->description )
        {
          key_put(k);
          return -ENOTNAM;
        }
        len = KEY_DESC_LEN(k) & 0xffff;
        err = copy_to_user((void*)ioctl_param, (void*)k->description, len + 1);
        key_put(k);
        return (err > 0) ? -EFAULT : 0;
      }
     break; /* IOCTL_GET_KEY_DESC */

    case IOCTL_ENUM_KEYS:
      if ( !s_key_serial_tree || !s_key_serial_lock )
        return -ENOCSI;
      COPY_ARG
      else {
        struct rb_node *iter;
        if ( !ptrbuf[0] )
        {
          spin_lock(s_key_serial_lock);
          for ( iter = rb_first(s_key_serial_tree); iter != NULL; iter = rb_next(iter) )
            count++;
          spin_unlock(s_key_serial_lock);
          goto copy_count;
        } else {
          struct key *xkey;
          ALLOC_KBUF(struct one_key, ptrbuf[0])
          // lock
          spin_lock(s_key_serial_lock);
          for ( iter = rb_first(s_key_serial_tree); iter != NULL; iter = rb_next(iter) )
          {
            if ( count >= ptrbuf[0] ) break;
            xkey = rb_entry(iter, struct key, serial_node);
            curr->addr = (void *)xkey;
            curr->serial = xkey->serial;
            curr->expiry = xkey->expiry;
            curr->last_used = xkey->last_used_at;
            curr->uid = xkey->uid.val;
            curr->gid = xkey->gid.val;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,10)
            curr->state = xkey->state;
#endif
            curr->perm = xkey->perm;
            curr->datalen = xkey->datalen;
            curr->len_desc = KEY_DESC_LEN(xkey);
            curr->flags = xkey->flags;
            curr->type = xkey->type;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
            if ( xkey->restrict_link )
              curr->rest_check = (void *)xkey->restrict_link->check;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
            curr->rest_check = (void *)xkey->restrict_link;
#endif
            // for next iteration
            curr++; count++;
          }
          // unlock
          spin_unlock(s_key_serial_lock);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_key);
          goto copy_kbuf_count;
        }
      }
     break; /* IOCTL_ENUM_KEYS */

    case IOCTL_KEY_TYPES:
      if ( !s_key_types_sem || !s_key_types_list )
        return -ENOCSI;
      COPY_ARG
      else {
        struct key_type *p;
        if ( !ptrbuf[0] )
        {
          down_read(s_key_types_sem);
          list_for_each_entry(p, s_key_types_list, link) count++;
          up_read(s_key_types_sem);
          goto copy_count;
        } else {
          ALLOC_KBUF(struct one_key_type, ptrbuf[0])
          down_read(s_key_types_sem);
          list_for_each_entry(p, s_key_types_list, link)
          {
            if ( count >= ptrbuf[0] ) break;
            curr->addr = (void *)p;
            if ( p->name )
              curr->len_name = strlen(p->name);
            curr->def_datalen = p->def_datalen;
            curr->vet_description = (void *)p->vet_description;
            curr->preparse = (void *)p->preparse;
            curr->free_preparse = (void *)p->free_preparse;
            curr->instantiate = (void *)p->instantiate;
            curr->update = (void *)p->update;
            curr->match_preparse = (void *)p->match_preparse;
            curr->match_free = (void *)p->match_free;
            curr->revoke = (void *)p->revoke;
            curr->destroy = (void *)p->destroy;
            curr->describe = (void *)p->describe;
            curr->read = (void *)p->read;
            curr->request_key = (void *)p->request_key;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
            curr->lookup_restriction = (void *)p->lookup_restriction;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
            curr->asym_query = (void *)p->asym_query;
            curr->asym_eds_op = (void *)p->asym_eds_op;
            curr->asym_verify_signature = (void *)p->asym_verify_signature;
#endif
            // for next iter
            count++; curr++;
          }
          up_read(s_key_types_sem);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_key_type);
          goto copy_kbuf_count;
        }
      }
     break; /* IOCTL_KEY_TYPES */
#endif /* CONFIG_KEYS */

#ifdef CONFIG_XFRM
    case IOCTL_XFRM_GUTS:
      COPY_ARGS(3)
      if ( !ptrbuf[0] ) // copy xfrm_policy_afinfo, index in ptrbuf[1]
      {
        struct s_xfrm_policy_afinfo *curr = NULL;
        if ( !s_xfrm_policy_afinfo || !s_xfrm_policy_afinfo_lock ) return -ENOCSI;
        if ( ptrbuf[1] >= XFRM_MAX ) return -EINVAL;
        // check if it presents
        if ( !s_xfrm_policy_afinfo[ptrbuf[1]] )
        {
          ptrbuf[0] = 0;
          goto copy_ptrbuf0;
        }
        // alloc out buffer
        kbuf_size = sizeof(struct s_xfrm_policy_afinfo);
        kbuf = kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO );
        if ( !kbuf )
          return -ENOMEM;
        spin_lock(s_xfrm_policy_afinfo_lock);
        curr = (struct s_xfrm_policy_afinfo *)kbuf;
        curr->addr = s_xfrm_policy_afinfo[ptrbuf[1]];
        if ( curr->addr )
        {
          struct xfrm_policy_afinfo *xp = s_xfrm_policy_afinfo[ptrbuf[1]];
          curr->dst_ops.addr = xp->dst_ops;
          if ( xp->dst_ops )
          {
            curr->dst_ops.family = xp->dst_ops->family;
            curr->dst_ops.gc = (unsigned long)xp->dst_ops->gc;
            curr->dst_ops.check = (unsigned long)xp->dst_ops->check;
            curr->dst_ops.default_advmss = (unsigned long)xp->dst_ops->default_advmss;
            curr->dst_ops.mtu = (unsigned long)xp->dst_ops->mtu;
            curr->dst_ops.cow_metrics = (unsigned long)xp->dst_ops->cow_metrics;
            curr->dst_ops.destroy = (unsigned long)xp->dst_ops->destroy;
            curr->dst_ops.ifdown = (unsigned long)xp->dst_ops->ifdown;
            curr->dst_ops.negative_advice = (unsigned long)xp->dst_ops->negative_advice;
            curr->dst_ops.link_failure = (unsigned long)xp->dst_ops->link_failure;
            curr->dst_ops.update_pmtu = (unsigned long)xp->dst_ops->update_pmtu;
            curr->dst_ops.redirect = (unsigned long)xp->dst_ops->redirect;
            curr->dst_ops.local_out = (unsigned long)xp->dst_ops->local_out;
            curr->dst_ops.neigh_lookup = (unsigned long)xp->dst_ops->neigh_lookup;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
            curr->dst_ops.confirm_neigh = (unsigned long)xp->dst_ops->confirm_neigh;
#endif
          }
          curr->dst_lookup = (unsigned long)xp->dst_lookup;
          curr->get_saddr = (unsigned long)xp->get_saddr;
          curr->fill_dst = (unsigned long)xp->fill_dst;
          curr->blackhole_route = (unsigned long)xp->blackhole_route;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
          curr->garbage_collect = (unsigned long)xp->garbage_collect;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
          curr->init_dst = (unsigned long)xp->init_dst;
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
          curr->decode_session = (unsigned long)xp->decode_session;
          curr->get_tos = (unsigned long)xp->get_tos;
          curr->init_path = (unsigned long)xp->init_path;
#endif
        }
        spin_unlock(s_xfrm_policy_afinfo_lock);
        goto copy_kbuf;
      } else if ( 1 == ptrbuf[0] )
      {
        struct xfrm_mgr *km;
        if ( !s_xfrm_km_lock || !s_xfrm_km_list ) return -ENOCSI;
        if ( !ptrbuf[1] )
        { // calc size of list
          spin_lock_bh(s_xfrm_km_lock);
          list_for_each_entry(km, s_xfrm_km_list, list) count++;
          spin_unlock_bh(s_xfrm_km_lock);
          goto copy_count;
        } else {
          ALLOC_KBUF(struct s_xfrm_mgr, ptrbuf[1])
          spin_lock_bh(s_xfrm_km_lock);
          list_for_each_entry(km, s_xfrm_km_list, list)
          {
            if ( count >= ptrbuf[1] ) break;
            curr->addr = km;
            curr->notify = (unsigned long)km->notify;
            curr->acquire = (unsigned long)km->acquire;
            curr->compile_policy = (unsigned long)km->compile_policy;
            curr->new_mapping = (unsigned long)km->new_mapping;
            curr->notify_policy = (unsigned long)km->notify_policy;
            curr->report = (unsigned long)km->report;
            curr->migrate = (unsigned long)km->migrate;
            curr->is_alive = (unsigned long)km->is_alive;
            // for next iteration
            ++count; ++curr;
          }
          // unlock
          spin_unlock_bh(s_xfrm_km_lock);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct s_xfrm_mgr);
          goto copy_kbuf_count;
        }
      } else if ( 4 == ptrbuf[0] ) { // copy xfrm4_protocols
        int idx = ptrbuf[1];
        struct xfrm4_protocol *x4;
        if ( !s_xfrm4_protocol_mutex ) return -ENOCSI;
        if ( idx < 0 || idx >= ARRAY_SIZE(x4p) ) return -EINVAL;
        if ( !x4p[idx] ) return -ENOCSI;
        if ( !*x4p[idx] ) goto copy_count;
        if ( !ptrbuf[2] ) { // calc count
          mutex_lock(s_xfrm4_protocol_mutex);
          for ( x4 = rcu_dereference(*x4p[idx]); x4 != NULL; x4 = x4->next ) count++;
          mutex_unlock(s_xfrm4_protocol_mutex);
          goto copy_count;
        } else {
          ALLOC_KBUF(struct s_xfrm_protocol, ptrbuf[2])
          mutex_lock(s_xfrm4_protocol_mutex);
          for ( x4 = rcu_dereference(*x4p[idx]); x4 != NULL; x4 = x4->next )
          {
            if ( count >= ptrbuf[2] ) break;
            curr->addr = x4;
            curr->handler = (unsigned long)x4->handler;
            curr->cb_handler = (unsigned long)x4->cb_handler;
            curr->err_handler = (unsigned long)x4->err_handler;
            curr->input_handler = (unsigned long)x4->input_handler;
            curr++; count++;
          }
          mutex_unlock(s_xfrm4_protocol_mutex);
          kbuf_size = (unsigned long) + count * sizeof(struct s_xfrm_protocol);
          goto copy_kbuf_count;
        }
      } else if ( 5 == ptrbuf[0] ) { // // copy xfrm6_protocols
        struct xfrm6_protocol *x6;
        int idx = ptrbuf[1];
        if ( !s_xfrm6_protocol_mutex ) return -ENOCSI;
        if ( idx < 0 || idx >= ARRAY_SIZE(x6p) ) return -EINVAL;
        if ( !x6p[idx] ) return -ENOCSI;
        if ( !*x6p[idx] ) goto copy_count;
        if ( !ptrbuf[2] ) { // calc count
          mutex_lock(s_xfrm6_protocol_mutex);
          for ( x6 = rcu_dereference(*x6p[idx]); x6 != NULL; x6 = x6->next ) count++;
          mutex_unlock(s_xfrm6_protocol_mutex);
          goto copy_count;
        } else {
          ALLOC_KBUF(struct s_xfrm_protocol, ptrbuf[2])
          mutex_lock(s_xfrm6_protocol_mutex);
          for ( x6 = rcu_dereference(*x6p[idx]); x6 != NULL; x6 = x6->next )
          {
            if ( count >= ptrbuf[2] ) break;
            curr->addr = x6;
            curr->handler = (unsigned long)x6->handler;
            curr->cb_handler = (unsigned long)x6->cb_handler;
            curr->err_handler = (unsigned long)x6->err_handler;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
            curr->input_handler = (unsigned long)x6->input_handler;
#endif
            curr++; count++;
          }
          mutex_unlock(s_xfrm6_protocol_mutex);
          kbuf_size = (unsigned long) + count * sizeof(struct s_xfrm_protocol);
          goto copy_kbuf_count;
        }
      } else if ( 6 == ptrbuf[0] ) { // copy xfrm_tunnels
        struct xfrm_tunnel *xt;
        int idx = ptrbuf[1];
        if ( !s_tunnel4_mutex ) return -ENOCSI;
        if ( idx < 0 || idx >= ARRAY_SIZE(x4t) ) return -EINVAL;
        if ( !x4t[idx] ) return -ENOCSI;
        if ( !*x4t[idx] ) goto copy_count;
        if ( !ptrbuf[2] ) { // calc count
          mutex_lock(s_tunnel4_mutex);
          for ( xt = rcu_dereference(*x4t[idx]); xt != NULL; xt = xt->next ) count++;
          mutex_unlock(s_tunnel4_mutex);
          goto copy_count;
        } else {
          ALLOC_KBUF(struct s_xfrm_tunnel, ptrbuf[2])
          mutex_lock(s_tunnel4_mutex);
          for ( xt = rcu_dereference(*x4t[idx]); xt != NULL; xt = xt->next )
          {
            if ( count >= ptrbuf[2] ) break;
            curr->addr = xt;
            curr->handler = (unsigned long)xt->handler;
            curr->err_handler = (unsigned long)xt->err_handler;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
            curr->cb_handler = (unsigned long)xt->cb_handler;
#endif
            curr++; count++;
          }
          mutex_unlock(s_tunnel4_mutex);
          kbuf_size = (unsigned long) + count * sizeof(struct s_xfrm_tunnel);
          goto copy_kbuf_count;
        }
      } else if ( 7 == ptrbuf[0] ) { // copy xfrm6_tunnels
        struct xfrm6_tunnel *t6;
        int idx = ptrbuf[1];
        if ( !s_tunnel6_mutex ) return -ENOCSI;
        if ( idx < 0 || idx >= ARRAY_SIZE(x6t) ) return -EINVAL;
        if ( !x6t[idx] ) return -ENOCSI;
        if ( !*x6t[idx] ) goto copy_count;
        if ( !ptrbuf[2] ) { // calc count
          mutex_lock(s_tunnel6_mutex);
          for ( t6 = rcu_dereference(*x6t[idx]); t6 != NULL; t6 = t6->next ) count++;
          mutex_unlock(s_tunnel6_mutex);
          goto copy_count;
        } else {
          ALLOC_KBUF(struct s_xfrm_tunnel, ptrbuf[2])
          mutex_lock(s_tunnel6_mutex);
          for ( t6 = rcu_dereference(*x6t[idx]); t6 != NULL; t6 = t6->next )
          {
            if ( count >= ptrbuf[2] ) break;
            curr->addr = t6;
            curr->handler = (unsigned long)t6->handler;
            curr->err_handler = (unsigned long)t6->err_handler;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
            curr->cb_handler = (unsigned long)t6->cb_handler;
#endif
            curr++; count++;
          }
          mutex_unlock(s_tunnel6_mutex);
          kbuf_size = (unsigned long) + count * sizeof(struct s_xfrm_tunnel);
          goto copy_kbuf_count;
        }
      }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
      else if ( 2 == ptrbuf[0] )
      {
        struct s_xfrm_translator *curr = (struct s_xfrm_translator *)ptrbuf;
        if ( !s_xfrm_translator || !s_xfrm_translator_lock ) return -ENOCSI;
        ptrbuf[0] = (unsigned long)*s_xfrm_translator;
        if ( !ptrbuf[0] ) goto copy_ptrbuf0;
        spin_lock_bh(s_xfrm_translator_lock);
        curr->addr = *s_xfrm_translator;
        kbuf_size = sizeof(curr->addr);
        if ( curr->addr ) {
          kbuf_size = sizeof(*curr);
          curr->alloc_compat = (unsigned long)(*s_xfrm_translator)->alloc_compat;
          curr->rcv_msg_compat = (unsigned long)(*s_xfrm_translator)->rcv_msg_compat;
          curr->xlate_user_policy_sockptr = (unsigned long)(*s_xfrm_translator)->xlate_user_policy_sockptr;
        }
        spin_unlock_bh(s_xfrm_translator_lock);
        // copy to user
        if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, kbuf_size) > 0)
          return -EFAULT;
        return 0;
      }
#endif /* >= 5.10 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
      else if ( 3 == ptrbuf[0] )
      {
        int i;
        if ( !s_xfrm_state_afinfo_lock || !s_xfrm_state_afinfo ) return -ENOCSI;
        if ( !ptrbuf[1] )
        { // calc amount
          spin_lock_bh(s_xfrm_state_afinfo_lock);
          for ( i = 0; i < AF_MAX; ++i )
            if ( s_xfrm_state_afinfo[i] ) count++;
          spin_unlock_bh(s_xfrm_state_afinfo_lock);
          goto copy_count;
        } else {
          ALLOC_KBUF(struct s_xfrm_state_afinfo, ptrbuf[1])
          spin_lock_bh(s_xfrm_state_afinfo_lock);
          for ( i = 0; i < AF_MAX; ++i )
          {
            if ( count >= ptrbuf[1] ) break;
            if ( !s_xfrm_state_afinfo[i] ) continue;
            curr->addr = s_xfrm_state_afinfo[i];
            curr->proto = s_xfrm_state_afinfo[i]->proto;
            copy_xfrm_type_off(s_xfrm_state_afinfo[i]->type_offload_esp, &curr->off_esp);
            copy_xfrm_type(s_xfrm_state_afinfo[i]->type_esp, &curr->type_esp);
            copy_xfrm_type(s_xfrm_state_afinfo[i]->type_ipip, &curr->type_ipip);
            copy_xfrm_type(s_xfrm_state_afinfo[i]->type_ipip6, &curr->type_ipip6);
            copy_xfrm_type(s_xfrm_state_afinfo[i]->type_comp, &curr->type_comp);
            copy_xfrm_type(s_xfrm_state_afinfo[i]->type_ah, &curr->type_ah);
            copy_xfrm_type(s_xfrm_state_afinfo[i]->type_routing, &curr->type_routing);
            copy_xfrm_type(s_xfrm_state_afinfo[i]->type_dstopts, &curr->type_dstopts);
            curr->output = (unsigned long)s_xfrm_state_afinfo[i]->output;
            curr->transport_finish = (unsigned long)s_xfrm_state_afinfo[i]->transport_finish;
            curr->local_error = (unsigned long)s_xfrm_state_afinfo[i]->local_error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,8,0)
            curr->output_finish = (unsigned long)s_xfrm_state_afinfo[i]->output_finish;
            curr->extract_input = (unsigned long)s_xfrm_state_afinfo[i]->extract_input;
            curr->extract_output = (unsigned long)s_xfrm_state_afinfo[i]->extract_output;
#endif
            // for next iteration
            count++; curr++;
          }
          spin_unlock_bh(s_xfrm_state_afinfo_lock);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct s_xfrm_state_afinfo);
          goto copy_kbuf_count;
        }
      }
#endif /* >= 5.3 */
       else return -EBADRQC;
     break; /* IOCTL_XFRM_GUTS */
#endif /* CONFIG_XFRM */

// it seems that CONFIG_PGTABLE_LEVELS appeared since 4.10
// I don't know how memory paging was processed on more old kernels and too lazy to investigate this ancient wisdom
#ifdef CONFIG_PGTABLE_LEVELS
    case IOCTL_VMEM_SCAN:
      COPY_ARGS(3)
      if ( !ptrbuf[0] )
      {
        ptrbuf[0] = CONFIG_PGTABLE_LEVELS;
        ptrbuf[1] = PAGE_SIZE;
        ptrbuf[2] = PGDIR_SHIFT;
#if CONFIG_PGTABLE_LEVELS > 4
        ptrbuf[3] = P4D_SHIFT;
#else
        ptrbuf[3] = 0;
#endif
        ptrbuf[4] = PUD_SHIFT;
        ptrbuf[5] = PMD_SHIFT;
        kbuf_size = 6;
        goto copy_ptrbuf;
      } else if ( !s_init_mm )
        return -ENOCSI;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
      else if ( ptrbuf[0] == 40 ) {
        if ( !s_vmap_area_list || !s_vmap_area_lock ) return -ENOCSI;
        if ( !ptrbuf[1] )
        { // calc count of items in purge_vmap_area_list
          struct vmap_area *va;
	        spin_lock(s_vmap_area_lock);
	        list_for_each_entry(va, s_vmap_area_list, list) {
            if ( !va->vm ) continue;
            if ( va->vm->flags & VM_ALLOC )
              count++;
          }
          spin_unlock(s_vmap_area_lock);
          goto copy_count;
        } else {
          struct vmap_area *va;
          ALLOC_KBUF(struct one_vmap_area, ptrbuf[1])
          spin_lock(s_vmap_area_lock);
          list_for_each_entry(va, s_vmap_area_list, list) {
            if ( count >= ptrbuf[1] ) break;
            if ( !va->vm ) continue;
            if ( !(va->vm->flags & VM_ALLOC) ) continue;
            curr->start = va->va_start;
            curr->size = va->va_end - va->va_start;
            curr->caller = (unsigned long)va->vm->caller;
            // for next iteration
            count++; curr++;
          }
          spin_unlock(s_vmap_area_lock);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_vmap_area);
          goto copy_kbuf_count;
        }
      } else if ( ptrbuf[0] == 41 ) {
        if ( !s_purge_vmap_area_list || !s_purge_vmap_area_lock ) return -ENOCSI;
        if ( !ptrbuf[1] )
        { // calc count of items in purge_vmap_area_list
          struct vmap_area *va;
	        spin_lock(s_purge_vmap_area_lock);
	        list_for_each_entry(va, s_purge_vmap_area_list, list) count++;
          spin_unlock(s_purge_vmap_area_lock);
          goto copy_count;
        } else {
          struct vmap_area *va;
          ALLOC_KBUF(struct one_purge_area, ptrbuf[1])
	        spin_lock(s_purge_vmap_area_lock);
	        list_for_each_entry(va, s_purge_vmap_area_list, list) {
            if ( count >= ptrbuf[1] ) break;
            curr->start = va->va_start;
            curr->end = va->va_end;
            // for next iteration
            curr++; count++;
          }
          spin_unlock(s_purge_vmap_area_lock);
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_purge_area);
          goto copy_kbuf_count;
        }
      }
#endif
#ifdef __x86_64__
      else if ( ptrbuf[0] == 43 ) // return pte_t from lookup_address(ptrbuf[1])
      {
        unsigned int unused = 0;
        if ( !s_lookup_address ) return -ENOCSI;
        ptrbuf[0] = (unsigned long)s_lookup_address(ptrbuf[1], &unused);
        goto copy_ptrbuf0;
      }
#endif
      else if ( ptrbuf[0] == 42 ) // test, address in ptrbuf[1]
      { // code ripped from https://elixir.bootlin.com/linux/v6.9.3/source/mm/vmalloc.c
        // out result: ptrbuf[0] - last succeed level
        // 1, 2, 3 - index, ptr & value of PXX for this level
        unsigned long addr = ptrbuf[1];
        int i = 1, 
            idx = pgd_index(addr);
        pgd_t *pgd = s_init_mm->pgd + idx;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        ptrbuf[0] = i;
        ptrbuf[1] = idx;
        kbuf_size = 4;
        ptrbuf[i+1] = (unsigned long)pgd;
        if ( pgd_none(*pgd) ) {
          ptrbuf[i+2] = 0;
          goto copy_ptrbuf;
        }
        ptrbuf[i+2] = pgd_val(*pgd);
        if ( pgd_leaf(*pgd) || pgd_bad(*pgd) )
          goto copy_ptrbuf;
        // p4
        i += 3; kbuf_size += 3; ptrbuf[0]++;
#if CONFIG_PGTABLE_LEVELS > 4
        ptrbuf[i] = p4d_index(addr);
#else
        ptrbuf[i] = idx;
#endif
        p4d = p4d_offset(pgd, addr);
        ptrbuf[i+1] = (unsigned long)p4d;
        if ( p4d_none(*p4d) ) {
          ptrbuf[i+2] = 0;
          goto copy_ptrbuf;
        }
        ptrbuf[i+2] = p4d_val(*p4d);
        if ( p4d_leaf(*p4d) || p4d_bad(*p4d) )
          goto copy_ptrbuf;
        // pud
        i += 3; kbuf_size += 3; ptrbuf[0]++;
        ptrbuf[i] = pud_index(addr);
        pud = pud_offset(p4d, addr);
        ptrbuf[i+1] = (unsigned long)pud;
        if ( pud_none(*pud) ) {
          ptrbuf[i+2] = 0;
          goto copy_ptrbuf;
        }
        ptrbuf[i+2] = pud_val(*pud);
        if ( pud_leaf(*pud) || pud_bad(*pud) )
          goto copy_ptrbuf;
        // pmd
        i += 3; kbuf_size += 3; ptrbuf[0]++;
        ptrbuf[i] = pmd_index(addr);
        pmd = pmd_offset(pud, addr);
        ptrbuf[i+1] = (unsigned long)pmd;
        if ( pmd_none(*pmd) ) {
          ptrbuf[i+2] = 0;
          goto copy_ptrbuf;
        }
        ptrbuf[i+2] = pmd_val(*pmd);
        if ( pmd_leaf(*pmd) || pmd_bad(*pmd) )
          goto copy_ptrbuf;
        // finally pte
        i += 3; kbuf_size += 3; ptrbuf[0]++;
        ptrbuf[i] = pte_index(addr);
        pte = pte_offset_kernel(pmd, addr);
        ptrbuf[i+1] = (unsigned long)pte;
        if ( pte_none(*pte) ) {
          ptrbuf[i+2] = 0;
          goto copy_ptrbuf;
        }
        ptrbuf[i+2] = pte_val(*pte);
        goto copy_ptrbuf;
      } else if ( ptrbuf[0] > 5 ) return -EINVAL;
      else {
        int i;
        // alloc vlevel_res
        struct vlevel_res *data;
        kbuf_size = sizeof(struct vlevel_res);
        kbuf = kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
        if ( !kbuf ) return -ENOMEM;
        // till end of this block don't use return, instead goto bad_p to kfree alloced memory
        data = (struct vlevel_res *)kbuf;
        if ( ptrbuf[0] == 1 )
        { // read pgd
          pgd_t *pgd;
          i = pgd_index(ptrbuf[1]);
          if ( i >= VITEMS_CNT ) goto bad_p;
          pgd = s_init_mm->pgd + i;
          do {
            data->items[i].ptr = pgd;
            if ( !pgd_none(*pgd) )
            {
              data->items[i].value = pgd->pgd;
#ifdef pgd_leaf // since 5.8?
              // xx_leaf should be checked before xx_bad
              if ( pgd_leaf(*pgd) ) {
                data->items[i].large = 1;
                data->items[i].nx = pgd_nx(pgd);
              } else
#endif
              if ( pgd_bad(*pgd) )
                data->items[i].bad = 1;
#ifdef __x86_64__
              if ( pgd_flags(*pgd) & _PAGE_PRESENT )
#else
              if ( pgd_present(*pgd) )
#endif
              {
                data->items[i].present = 1;
                data->live++;
              }
            }
            i++; pgd++;
          } while( i < VITEMS_CNT );
          goto copy_kbuf;
        } else if ( ptrbuf[0] == 2 )
        { // read p4d - no huge 4pd exists in 2024
#if CONFIG_PGTABLE_LEVELS > 4
          p4d_t *p4;
          if ( !ptrbuf[2] ) goto bad_p;
          i = p4d_index(ptrbuf[1]);
          if ( i >= VITEMS_CNT ) goto bad_p;
          p4 = p4d_offset((pgd_t *)ptrbuf[2], ptrbuf[1]);
          if ( !p4 ) goto bad_p;
          do {
            data->items[i].ptr = p4;
            if ( !p4d_none(*p4) )
            {
              data->items[i].value = p4->p4d;
              // xx_leaf should be checked before xx_bad
              if ( p4d_leaf(*p4) ) {
                data->items[i].large = 1;
                data->items[i].nx = p4d_nx(p4);
              } else if ( p4d_bad(*p4) )
                data->items[i].bad = 1;
              if ( p4d_present(*p4) )
              {
                data->items[i].present = 1;
                data->live++;
              }
            }
            i++;
            ptrbuf[1] += 1UL << P4D_SHIFT;
            p4 = p4d_offset((pgd_t *)ptrbuf[2], ptrbuf[1]);
          } while( i < VITEMS_CNT );
          goto copy_kbuf;
#else
          goto bad_p;
#endif
        }
#if CONFIG_PGTABLE_LEVELS > 3
        else if ( ptrbuf[0] == 3 )
        { // read pud
          pud_t *pud;
          if ( !ptrbuf[2] ) goto bad_p;
          i = pud_index(ptrbuf[1]);
          if ( i >= VITEMS_CNT ) goto bad_p;
          pud = pud_offset((p4d_t *)ptrbuf[2], ptrbuf[1]);
          if ( !pud ) goto bad_p;
          do {
            data->items[i].ptr = pud;
            if ( !pud_none(*pud) )
            {
              data->items[i].value = pud->pud;
              // xx_leaf should be checked before xx_bad
#ifdef pud_leaf
              if ( pud_leaf(*pud) ) {
                data->items[i].large = 1;
                data->items[i].nx = pud_nx(pud);
              } else
#endif
#ifdef CONFIG_HUGETLB_PAGE
              if ( s_pud_huge && s_pud_huge(*pud) ) {
                data->items[i].huge = 1;
                data->items[i].nx = pud_nx(pud);
              } else
#endif
              if ( pud_bad(*pud) )
                data->items[i].bad = 1;
              if ( pud_present(*pud) )
              {
                data->items[i].present = 1;
                data->live++;
              }
            }
            i++; pud++;
          } while( i < VITEMS_CNT );
          goto copy_kbuf;
        }
#endif
#if CONFIG_PGTABLE_LEVELS > 2
        else if ( ptrbuf[0] == 4 )
        { // read pmd
          pmd_t *pmd;
          if ( !ptrbuf[2] ) goto bad_p;
          i = pmd_index(ptrbuf[1]);
          if ( i >= VITEMS_CNT ) goto bad_p;
          pmd = pmd_offset((pud_t *)ptrbuf[2], ptrbuf[1]);
          if ( !pmd ) goto bad_p;
          do {
            data->items[i].ptr = pmd;
            if ( !pmd_none(*pmd) )
            {
              data->items[i].value = pmd->pmd;
              // xx_leaf should be checked before xx_bad
#ifdef pmd_leaf
              if ( pmd_leaf(*pmd) ) {
                data->items[i].large = 1;
                data->items[i].nx = pmd_nx(pmd);
              } else
#endif
#ifdef CONFIG_HUGETLB_PAGE
              if ( s_pmd_huge && s_pmd_huge(*pmd) ) {
                data->items[i].huge = 1;
                data->items[i].nx = pmd_nx(pmd);
              } else
#endif
              if ( pmd_bad(*pmd) )
                data->items[i].bad = 1;
              if ( pmd_present(*pmd) )
              {
                data->items[i].present = 1;
                data->live++;
              }
            }
            i++; pmd++;
          } while( i < VITEMS_CNT );
          goto copy_kbuf;
        }
#endif
        else if ( ptrbuf[0] == 5 )
        { // read pte
          pte_t *pte;
          if ( !ptrbuf[2] ) goto bad_p;
          if ( s_vmalloc_or_module_addr && !s_vmalloc_or_module_addr((const void *)ptrbuf[1]) ) goto bad_p;
          i = pte_index(ptrbuf[1]);
          if ( i >= VITEMS_CNT ) goto bad_p;
          pte = pte_offset_kernel((pmd_t *)ptrbuf[2], ptrbuf[1]);
          if ( !pte ) goto bad_p;
          do {
            data->items[i].ptr = pte;
            if ( pte_present(*pte) )
            {
              data->live++;
              data->items[i].value = pte->pte;
              data->items[i].present = 1;
              data->items[i].nx = pte_nx(pte);
            }
            i++; pte++;
          } while( i < VITEMS_CNT );
          goto copy_kbuf;
        }
        kfree(kbuf);
        return -EBADRQC;
bad_p:
        kfree(kbuf);
        return -EINVAL;
      }
     break; /* IOCTL_VMEM_SCAN */
#endif /* CONFIG_PGTABLE_LEVELS */

    case IOCTL_SYS_TABLE:
      if ( !s_sys_table ) return -ENOCSI;
      COPY_ARG
      if ( !ptrbuf[0] ) {
        ptrbuf[0] = (unsigned long)s_sys_table;
        { // also X32_NR_syscalls & IA32_NR_syscalls
#include <uapi/asm/unistd.h>
          ptrbuf[1] = NR_syscalls;
        }
        kbuf_size = 2;
        goto copy_ptrbuf;
      } else {
        if ( copy_to_user((void*)ioctl_param, (void*)s_sys_table, ptrbuf[0] * sizeof(s_sys_table[0])) > 0)
         return -EFAULT;
      }
     break; /* IOCTL_SYS_TABLE */


    case IOCTL_PATCH_KTEXT1:
      if ( !s_patch_text ) return -ENOCSI;
      COPY_ARGS(2)
      else {
#ifdef CONFIG_ARM64
        s_patch_text((void*)ptrbuf[0], (u32)ptrbuf[1]);
#else
        s_patch_text((void*)ptrbuf[0], ptrbuf + 1, 1);
#endif
      }
      break; /* IOCTL_PATCH_KTEXT1 */

    default:
     return -EBADRQC;
  }
  return 0;
copy_ptrbuf:
  if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, kbuf_size * sizeof(ptrbuf[0])) > 0)
    return -EFAULT;
  return 0;
copy_ptrbuf0:
  if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
    return -EFAULT;
  return 0;
copy_count:
  if (copy_to_user((void*)ioctl_param, (void*)&count, sizeof(count)) > 0)
    return -EFAULT;
  return 0;
copy_kbuf_count:
  kbuf[0] = count;
copy_kbuf:
  if ( copy_to_user((void*)ioctl_param, (void*)kbuf, kbuf_size) > 0 )
  {
    kfree(kbuf);
    return -EFAULT;
  }
  // cleanup
  kfree(kbuf);
  return 0;
}

static loff_t memory_lseek(struct file *file, loff_t offset, int orig)
{
	loff_t ret;

#ifdef _DEBUG
 printk(KERN_INFO "[+] lkcd_seek: %llX\n", offset);
#endif /* _DEBUG */

#ifndef fallthrough
# define fallthrough __attribute__ ((fallthrough))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	inode_lock(file_inode(file));
#else
  mutex_lock(&file_inode(file)->i_mutex);
#endif
	switch (orig) {
	case SEEK_CUR:
		offset += file->f_pos;
		fallthrough;
	case SEEK_SET:
		/* to avoid userland mistaking f_pos=-9 as -EBADF=-9 */
		if ((unsigned long long)offset >= -MAX_ERRNO) {
#ifdef _DEBUG
  printk(KERN_INFO "[+] lkcd_seek overflow: %llX\n", offset);
#endif /* _DEBUG */
			ret = -EOVERFLOW;
			break;
		}
		file->f_pos = offset;
		ret = file->f_pos;
		force_successful_syscall_return();
		break;
	default:
		ret = -EINVAL;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
	inode_unlock(file_inode(file));
#else
  mutex_unlock(&file_inode(file)->i_mutex);
#endif
#ifdef _DEBUG
  printk(KERN_INFO "[+] lkcd_seek: %llX ret %lld\n", offset, ret);
#endif /* _DEBUG */
	return ret;
}

static inline unsigned long size_inside_page(unsigned long start, unsigned long size)
{
	unsigned long sz;

	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

	return min(sz, size);
}

static inline bool should_stop_iteration(void)
{
	if (need_resched())
		cond_resched();
	return fatal_signal_pending(current);
}

static ssize_t invalid_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
  return -EPERM;
}

// ripped from drivers/char/mem.c
static ssize_t read_kmem(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t low_count, read, sz;
	char *kbuf; /* k-addr because vread() takes vmlist_lock rwlock */
	int err = 0;

#ifdef CONFIG_64BIT
 printk(KERN_INFO "[+] lkcd_read: %lX at %lX\n", count, p);
#else
 printk(KERN_INFO "[+] lkcd_read: %X at %lX\n", count, p);
#endif

	read = 0;
	if (p < (unsigned long) high_memory) {
		low_count = count;
		if (count > (unsigned long)high_memory - p)
			low_count = (unsigned long)high_memory - p;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
		/* we don't have page 0 mapped on sparc and m68k.. */
		if (p < PAGE_SIZE && low_count > 0) {
			sz = size_inside_page(p, low_count);
			if (clear_user(buf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			read += sz;
			low_count -= sz;
			count -= sz;
		}
#endif
		while (low_count > 0) {
			sz = size_inside_page(p, low_count);

			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur
			 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
      kbuf = (char *)p;
#else
			kbuf = xlate_dev_kmem_ptr((void *)p);
#endif
			if (!virt_addr_valid(kbuf))
				return -ENXIO;

			if (copy_to_user(buf, kbuf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			read += sz;
			low_count -= sz;
			count -= sz;
			if (should_stop_iteration()) {
				count = 0;
				break;
			}
		}
	}

	if (count > 0) {
		if (copy_to_user(buf, (const void *)p, count)) {
			err = -EFAULT;
		} else {
      p += count;
      read += count;
		}
	}
	*ppos = p;
	return read ? read : err;
}

static const struct file_operations kmem_fops = {
	.llseek		= memory_lseek,
	.read		  = read_kmem,
	.write    = invalid_write,
	.open		  = open_lkcd,
	.release        = close_lkcd,
	.unlocked_ioctl	= lkcd_ioctl,
};

static struct miscdevice lkcd_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "lkcd",
    .fops = &kmem_fops,
 // https://stackoverflow.com/questions/23424884/linux-kernel-setting-the-permissions-for-a-dev-file-that-was-created-via-crea
    .mode = 0444
};

const char report_fmt[] RDSection = "cannot find %s\n";
static const char no_reg[] RDSection = "Unable to register the lkcd device, err %d\n";
_RN(sys_call_table, sys_call_table)
_RN(vmap_area_list, vmap_area_list)
_RN(vmap_area_lock, vmap_area_lock)
#ifdef __x86_64__
_RN(ia32_sys_call_table, ia32_sys_call_table)
_RN(x32_sys_call_table, x32_sys_call_table)
#endif
_RN(init_cred, init_cred)
_RN(pre_hkret, pre_handler_kretprobe)
_RN(dbg_open, debugfs_open_proxy_file_operations)
_RN(dbg_full, debugfs_full_proxy_file_operations)
_RN(mod_mutex, module_mutex)
_RN(check_mem, is_vmalloc_or_module_addr)
_RN(krnf_node, kernfs_node_from_dentry)

#ifdef HAS_ARM64_THUNKS
#define SYM_LOAD(name, type, val)  val = (type)bti_wrap(name);
#else
#define SYM_LOAD(name, type, val)  val = (type)lkcd_lookup_name(name); if ( !val ) printk(report_fmt, name); 
#endif

#define REPORT(s, sname)  if ( !s ) printk(report_fmt, sname);

int __init
init_module (void)
{
  int ret = misc_register(&lkcd_dev);
  if (ret)
  {
    printk(no_reg, ret);
    return ret;
  }
#ifdef HAS_ARM64_THUNKS
  if ( !init_bti_thunks() )
  {
    misc_deregister(&lkcd_dev);
    return -ENOMEM;
  }
#endif /* HAS_ARM64_THUNKS */
// since 6.9 evil clowns changed memory managament - now vmap_nodes is array with size nr_vmap_nodes
// besides struct vmap_node declared inside vmalloc.c. nah
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,9,0)
  s_vmap_area_lock = (spinlock_t *)lkcd_lookup_name(_GN(vmap_area_lock));
  REPORT(s_vmap_area_lock, _GN(vmap_area_lock))
  s_vmap_area_list = (struct list_head *)lkcd_lookup_name(_GN(vmap_area_list));
  REPORT(s_vmap_area_list, _GN(vmap_area_list))
  s_purge_vmap_area_list = (struct list_head *)lkcd_lookup_name("purge_vmap_area_list");
  REPORT(s_purge_vmap_area_list, "purge_vmap_area_list")
  s_purge_vmap_area_lock = (spinlock_t *)lkcd_lookup_name("purge_vmap_area_lock");
  REPORT(s_purge_vmap_area_lock, "purge_vmap_area_lock")
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
  s_fib_notifier_net_id = (unsigned int *)lkcd_lookup_name("fib_notifier_net_id");
  REPORT(s_fib_notifier_net_id, "fib_notifier_net_id")
#endif
  s_init_mm = (struct mm_struct *)lkcd_lookup_name("init_mm");
  REPORT(s_init_mm, "init_mm")
  s_sys_table = (void **)lkcd_lookup_name(_GN(sys_call_table));
  REPORT(s_sys_table, _GN(sys_call_table))
#ifdef __x86_64__
  SYM_LOAD("lookup_address", my_lookup_address, s_lookup_address)
  s_ia32_sys_table = (void **)lkcd_lookup_name(_GN(ia32_sys_call_table));
  REPORT(s_ia32_sys_table, _GN(ia32_sys_call_table))
  s_x32_sys_table = (void **)lkcd_lookup_name(_GN(x32_sys_call_table));
  REPORT(s_x32_sys_table, _GN(x32_sys_call_table))
#endif
  s_init_cred = (struct cred *)lkcd_lookup_name(_GN(init_cred));
  REPORT(s_init_cred, _GN(init_cred))
  k_pre_handler_kretprobe = (void *)lkcd_lookup_name(_GN(pre_hkret));
  REPORT(k_pre_handler_kretprobe, _GN(pre_hkret))
  s_dbg_open = (const struct file_operations *)lkcd_lookup_name(_GN(dbg_open));
  REPORT(s_dbg_open, _GN(dbg_open))
  s_dbg_full = (const struct file_operations *)lkcd_lookup_name(_GN(dbg_full));
  REPORT(s_dbg_full, _GN(dbg_full))
  SYM_LOAD(_GN(check_mem), my_vmalloc_or_module_addr, s_vmalloc_or_module_addr);
  SYM_LOAD(_GN(krnf_node), krnf_node_type, krnf_node_ptr)
  SYM_LOAD("iterate_supers", und_iterate_supers, iterate_supers_ptr)
  SYM_LOAD("do_mprotect_pkey", my_mprotect_pkey, s_mprotect)
  SYM_LOAD("lookup_module_symbol_name", my_lookup, s_lookup)
  s_modules = (struct list_head *)lkcd_lookup_name("modules");
  REPORT(s_modules, "modules")
  s_module_mutex = (struct mutex *)lkcd_lookup_name(_GN(mod_mutex));
  REPORT(s_module_mutex, _GN(mod_mutex));
  s_formats = (struct list_head *)lkcd_lookup_name("formats");
  REPORT(s_formats, "formats");
  s_binfmt_lock = (rwlock_t *)lkcd_lookup_name("binfmt_lock");
  REPORT(s_binfmt_lock, "binfmt_lock")
  mount_lock = (seqlock_t *)lkcd_lookup_name("mount_lock");
  REPORT(mount_lock, "mount_lock");
  s_net = (struct rw_semaphore *)lkcd_lookup_name("net_rwsem");
  REPORT(s_net, "net_rwsem")
  s_dev_base_lock = (rwlock_t *)lkcd_lookup_name("dev_base_lock");
  REPORT(s_dev_base_lock, "dev_base_lock")
  s_sock_diag_handlers = (struct sock_diag_handler **)lkcd_lookup_name("sock_diag_handlers");
  REPORT(s_sock_diag_handlers, "sock_diag_handlers")
  s_sock_diag_table_mutex = (struct mutex *)lkcd_lookup_name("sock_diag_table_mutex");
  REPORT(s_sock_diag_table_mutex, "sock_diag_table_mutex")
  s_my_task_work_cancel = (my_task_work_cancel)lkcd_lookup_name("task_work_cancel");
  REPORT(s_my_task_work_cancel, "task_work_cancel")
  s_task_work_add = (my_task_work_add)lkcd_lookup_name("task_work_add");
  REPORT(s_task_work_add, "task_work_add")
#ifdef CONFIG_NETFILTER
  s_nf_hook_mutex = (struct mutex *)lkcd_lookup_name("nf_hook_mutex");
  REPORT(s_nf_hook_mutex, "nf_hook_mutex")
  s_nf_log_mutex = (struct mutex *)lkcd_lookup_name("nf_log_mutex");
  REPORT(s_nf_log_mutex, "nf_log_mutex")
  s_xt = (struct xt_af *)lkcd_lookup_name("xt");
  REPORT(s_xt, "xt")
  if ( s_xt )
    s_xt = *(struct xt_af **)s_xt;
#endif
#ifdef CONFIG_XFRM
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
  s_xfrm_state_afinfo_lock = (spinlock_t *)lkcd_lookup_name("xfrm_state_afinfo_lock");
  REPORT(s_xfrm_state_afinfo_lock, "xfrm_state_afinfo_lock")
  s_xfrm_state_afinfo = (struct xfrm_state_afinfo **)lkcd_lookup_name("xfrm_state_afinfo");
  REPORT(s_xfrm_state_afinfo, "xfrm_state_afinfo")
#endif
  s_xfrm_km_lock = (spinlock_t *)lkcd_lookup_name("xfrm_km_lock");
  REPORT(s_xfrm_km_lock, "xfrm_km_lock")
  s_xfrm_km_list = (struct list_head *)lkcd_lookup_name("xfrm_km_list");
  REPORT(s_xfrm_km_list, "xfrm_km_list")
  s_xfrm_policy_afinfo_lock = (spinlock_t *)lkcd_lookup_name("xfrm_policy_afinfo_lock");
  REPORT(s_xfrm_policy_afinfo_lock, "xfrm_policy_afinfo_lock")
  s_xfrm_policy_afinfo = (struct xfrm_policy_afinfo **)lkcd_lookup_name("xfrm_policy_afinfo");
  REPORT(s_xfrm_policy_afinfo, "xfrm_policy_afinfo")
  s_xfrm6_protocol_mutex = (struct mutex *)lkcd_lookup_name("xfrm6_protocol_mutex");
  REPORT(s_xfrm6_protocol_mutex, "xfrm6_protocol_mutex")
  s_xfrm4_protocol_mutex = (struct mutex *)lkcd_lookup_name("xfrm4_protocol_mutex");
  REPORT(s_xfrm4_protocol_mutex, "xfrm4_protocol_mutex")
  // fill x4p
  if ( s_xfrm4_protocol_mutex )
  {
    x4p[0] = (struct xfrm4_protocol **)lkcd_lookup_name("esp4_handlers");
    x4p[1] = (struct xfrm4_protocol **)lkcd_lookup_name("ah4_handlers");
    x4p[2] = (struct xfrm4_protocol **)lkcd_lookup_name("ipcomp4_handlers");
  }
  s_tunnel4_mutex = (struct mutex *)lkcd_lookup_name("tunnel4_mutex");
  REPORT(s_tunnel4_mutex, "tunnel4_mutex")
  s_tunnel6_mutex = (struct mutex *)lkcd_lookup_name("tunnel6_mutex");
  REPORT(s_tunnel6_mutex, "tunnel6_mutex")
  // fill x6p
  if ( s_xfrm6_protocol_mutex )
  {
    x6p[0] = (struct xfrm6_protocol **)lkcd_lookup_name("esp6_handlers");
    x6p[1] = (struct xfrm6_protocol **)lkcd_lookup_name("ah6_handlers");
    x6p[2] = (struct xfrm6_protocol **)lkcd_lookup_name("ipcomp6_handlers");
  }
  // fill x4t
  if ( s_tunnel4_mutex )
  {
    x4t[0] = (struct xfrm_tunnel **)lkcd_lookup_name("tunnel4_handlers");
    x4t[1] = (struct xfrm_tunnel **)lkcd_lookup_name("tunnel64_handlers");
    x4t[2] = (struct xfrm_tunnel **)lkcd_lookup_name("tunnelmpls4_handlers");
  }
  // fill x6t
  if ( s_tunnel6_mutex )
  {
    x6t[0] = (struct xfrm6_tunnel **)lkcd_lookup_name("tunnel6_handlers");
    x6t[1] = (struct xfrm6_tunnel **)lkcd_lookup_name("tunnel46_handlers");
    x6t[2] = (struct xfrm6_tunnel **)lkcd_lookup_name("tunnelmpls6_handlers");
  }
  s_xfrm_input_afinfo_lock = (spinlock_t *)lkcd_lookup_name("xfrm_input_afinfo_lock");
  REPORT(s_xfrm_input_afinfo_lock, "xfrm_input_afinfo_lock")
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,10,0)
  s_xfrm_translator_lock = (spinlock_t *)lkcd_lookup_name("xfrm_translator_lock");
  REPORT(s_xfrm_translator_lock, "xfrm_translator_lock")
  s_xfrm_translator = (struct xfrm_translator **)lkcd_lookup_name("xfrm_translator");
  REPORT(s_xfrm_translator, "xfrm_translator")
#endif
#endif /* CONFIG_XFRM */
  // keys
#ifdef CONFIG_KEYS
  SYM_LOAD("key_lookup", my_key_lookup, f_key_lookup)
  s_key_types_sem = (struct rw_semaphore *)lkcd_lookup_name("key_types_sem");
  REPORT(s_key_types_sem, "key_types_sem")
  s_key_types_list = (struct list_head *)lkcd_lookup_name("key_types_list");
  REPORT(s_key_types_list, "key_types_list")
  s_key_serial_tree = (struct rb_root *)lkcd_lookup_name("key_serial_tree");
  REPORT(s_key_serial_tree, "key_serial_tree")
  s_key_serial_lock = (spinlock_t *)lkcd_lookup_name("key_serial_lock");
  REPORT(s_key_serial_lock, "key_serial_lock")
#endif
#ifdef CONFIG_ZPOOL
  z_drivers_head = (struct list_head *)lkcd_lookup_name("drivers_head");
  REPORT(z_drivers_head, "drivers_head")
  z_drivers_lock = (spinlock_t *)lkcd_lookup_name("drivers_lock");
  REPORT(z_drivers_lock, "drivers_lock")
#endif
  s_slab_caches = (struct list_head *)lkcd_lookup_name("slab_caches");
  REPORT(s_slab_caches, "slab_caches")
  s_slab_mutex = (struct mutex *)lkcd_lookup_name("slab_mutex");
  REPORT(s_slab_mutex, "slab_mutex")
  // trace events data
  s_ftrace_end = (struct ftrace_ops *)lkcd_lookup_name("ftrace_list_end");
  REPORT(s_ftrace_end, "ftrace_list_end")
  s_trace_event_sem = (struct rw_semaphore *)lkcd_lookup_name("trace_event_sem");
  REPORT(s_trace_event_sem, "trace_event_sem")
  s_event_mutex = (struct mutex *)lkcd_lookup_name("event_mutex");
  REPORT(s_event_mutex, "event_mutex")
  s_ftrace_events = (struct list_head *)lkcd_lookup_name("ftrace_events");
  REPORT(s_ftrace_events, "ftrace_events")
#ifdef CONFIG_BPF
  s_kind_ops = (struct undoc_btf_ops **)lkcd_lookup_name("kind_ops");
  REPORT(s_kind_ops, "kind_ops")
  s_bpf_event_mutex = (struct mutex *)lkcd_lookup_name("bpf_event_mutex");
  REPORT(s_bpf_event_mutex, "bpf_event_mutex")
  SYM_LOAD("bpf_prog_put", my_bpf_prog_put, s_bpf_prog_put)
#endif
  s_tracepoints_mutex = (struct mutex *)lkcd_lookup_name("tracepoints_mutex");
  REPORT(s_tracepoints_mutex, "tracepoints_mutex")
  s_tracepoint_module_list_mutex = (struct mutex *)lkcd_lookup_name("tracepoint_module_list_mutex");
  REPORT(s_tracepoint_module_list_mutex, "tracepoint_module_list_mutex")
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)  
  SYM_LOAD("bpf_prog_array_length", und_bpf_prog_array_length, bpf_prog_array_length_ptr)
  SYM_LOAD("cgroup_bpf_detach", kcgroup_bpf_detach, cgroup_bpf_detach_ptr)
#endif
  css_next_child_ptr = (kcss_next_child)lkcd_lookup_name("css_next_child");
  REPORT(css_next_child_ptr, "css_next_child")
  SYM_LOAD(s_patch_name, t_patch_text, s_patch_text)
  delayed_timer = (void *)lkcd_lookup_name("delayed_work_timer_fn");
  REPORT(delayed_timer, "delayed_work_timer_fn")
  s_alarm = (struct alarm_base *)lkcd_lookup_name("alarm_bases");
  REPORT(s_alarm, "alarm_bases")
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
  s_inode_sb_list_lock = (spinlock_t *)lkcd_lookup_name("inode_sb_list_lock");
  REPORT(s_inode_sb_list_lock, "inode_sb_list_lock")
#endif
#ifdef CONFIG_HUGETLB_PAGE
 SYM_LOAD("pmd_huge", my_pmd_huge, s_pmd_huge)
 SYM_LOAD("pud_huge", my_pud_huge, s_pud_huge)
#endif
#if CONFIG_FSNOTIFY && LINUX_VERSION_CODE >= KERNEL_VERSION(4,15,0)
  fsnotify_mark_srcu_ptr = (struct srcu_struct *)lkcd_lookup_name("fsnotify_mark_srcu");
  SYM_LOAD("fsnotify_first_mark", und_fsnotify_first_mark, fsnotify_first_mark_ptr)
  if ( !fsnotify_first_mark_ptr )
  {
    if ( fsnotify_mark_srcu_ptr )
      fsnotify_first_mark_ptr = my_fsnotify_first_mark;
  }
  SYM_LOAD("fsnotify_next_mark", und_fsnotify_next_mark, fsnotify_next_mark_ptr) 
  if ( !fsnotify_next_mark_ptr )
  {
    if ( fsnotify_mark_srcu_ptr )
      fsnotify_next_mark_ptr = my_fsnotify_next_mark;
  }
#endif /* CONFIG_FSNOTIFY */
#ifdef CONFIG_INPUT
  s_input_handler_list = (struct list_head *)lkcd_lookup_name("input_handler_list");
  REPORT(s_input_handler_list, "input_handler_list");
  s_input_dev_list = (struct list_head *)lkcd_lookup_name("input_dev_list");
  REPORT(s_input_dev_list, "input_dev_list");
  s_input_mutex = (struct mutex *)lkcd_lookup_name("input_mutex");
  REPORT(s_input_mutex, "input_mutex");
#endif /* CONFIG_INPUT */
#ifdef CONFIG_KPROBES
  kprobe_aggr = (unsigned long)lkcd_lookup_name("aggr_pre_handler");
  s_kprobe_blacklist = (struct list_head *)lkcd_lookup_name("kprobe_blacklist");
  REPORT(s_kprobe_blacklist, "kprobe_blacklist");
#endif /* CONFIG_KPROBES */
#ifdef CONFIG_UPROBES
  find_uprobe_ptr = (find_uprobe)lkcd_lookup_name("find_uprobe");
  get_uprobe_ptr = (get_uprobe)lkcd_lookup_name("get_uprobe");
  if ( !get_uprobe_ptr ) get_uprobe_ptr = my_get_uprobe;
  put_uprobe_ptr = (put_uprobe)lkcd_lookup_name("put_uprobe");
  REPORT(put_uprobe_ptr, "put_uprobe")
  s_delayed_uprobe_list = (struct list_head *)lkcd_lookup_name("delayed_uprobe_list");
  REPORT(s_delayed_uprobe_list, "delayed_uprobe_list")
  s_delayed_uprobe_lock = (struct mutex *)lkcd_lookup_name("delayed_uprobe_lock");
  REPORT(s_delayed_uprobe_lock, "delayed_uprobe_lock")
#endif /* CONFIG_UPROBES */
#ifdef CONFIG_DYNAMIC_DEBUG
  s_ddebug_tables = (struct list_head *)lkcd_lookup_name("ddebug_tables");
  REPORT(s_ddebug_tables, "ddebug_tables")
  s_ddebug_lock = (struct mutex *)lkcd_lookup_name("ddebug_lock");
  REPORT(s_ddebug_lock, "ddebug_lock")
#endif /* CONFIG_DYNAMIC_DEBUG */
#ifdef CONFIG_MAGIC_SYSRQ
  s_sysrq_key_table_lock = (spinlock_t *)lkcd_lookup_name("sysrq_key_table_lock");
  REPORT(s_sysrq_key_table_lock, "sysrq_key_table_lock")
  s_sysrq_key_table = (struct sysrq_key_op **)lkcd_lookup_name("sysrq_key_table");
  REPORT(s_sysrq_key_table, "sysrq_key_table")
#endif /* CONFIG_MAGIC_SYSRQ */
#ifdef HAS_ARM64_THUNKS
  bti_thunks_lock_ro();
#endif
  init_inject();
  return 0;
}

void cleanup_module (void)
{
  finit_inject();
#ifdef __x86_64__
  if ( urn_installed )
  {
     user_return_notifier_unregister(&s_urn);
     urn_installed = 0;
  }
#endif /* __x86_64__ */
#ifdef CONFIG_KPROBES
  if ( test_kprobe_installed )
  {
     unregister_kprobe(&test_kp);
     test_kprobe_installed = 0;
  }
#endif
#ifdef CONFIG_UPROBES
  if ( debuggee_inode )
  {
     uprobe_unregister(debuggee_inode, DEBUGGEE_FILE_OFFSET, &s_uc);
     debuggee_inode = 0;
  }
#endif
#ifdef HAS_ARM64_THUNKS
  finit_bti_thunks();
#endif
  misc_deregister(&lkcd_dev);
}
