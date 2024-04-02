#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/tty.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <asm/io.h>
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
#include <linux/uprobes.h>
#include <linux/kprobes.h>
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
#include <linux/trace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#include <linux/ftrace.h>
#endif
#include <linux/trace_events.h>
#include "uprobes.h"
#include <linux/tracepoint-defs.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <net/rtnetlink.h>
#include <net/genetlink.h>
#include <net/tcp.h>
#include <linux/sock_diag.h>
#include <net/protocol.h>
#include <linux/rhashtable.h>
#include "netlink.h"
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <linux/lsm_hooks.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/alarmtimer.h>
#ifdef CONFIG_NETFILTER
#include <net/netfilter/nf_log.h>
#endif
#ifdef CONFIG_WIRELESS_EXT
#include <net/iw_handler.h>
#endif
#ifdef CONFIG_KEYS
#include <linux/key-type.h>
#include <linux/key.h>
#endif
#include "timers.h"
#include "bpf.h"
#include "event.h"
#include "shared.h"
#include "arm64.bti/arm64bti.h"

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "lkcd";

struct rw_semaphore *s_net = 0;
rwlock_t *s_dev_base_lock = 0;
struct sock_diag_handler **s_sock_diag_handlers = 0;
struct mutex *s_sock_diag_table_mutex = 0;
#ifdef CONFIG_NETFILTER
struct mutex *s_nf_hook_mutex = 0;
struct mutex *s_nf_log_mutex = 0;
#endif /* CONFIG_NETFILTER */
#ifdef CONFIG_KEYS
struct rw_semaphore *s_key_types_sem = 0;
struct list_head *s_key_types_list = 0;
struct rb_root *s_key_serial_tree = 0;
spinlock_t *s_key_serial_lock = 0;
#endif /* CONFIG_KEYS */
struct ftrace_ops *s_ftrace_end = 0;
void *delayed_timer = 0;
struct alarm_base *s_alarm = 0;

#define KPROBE_HASH_BITS 6
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)

#ifdef __x86_64__
// asm functions in getgs.asm
extern void *get_gs(long offset);
extern void *get_this_gs(long this_cpu, long offset);
extern unsigned int get_gs_dword(long offset);
extern unsigned short get_gs_word(long offset);
extern unsigned char get_gs_byte(long offset);
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

unsigned long lkcd_lookup_name(const char *name)
{
 return static_call(lkcd_lookup_name_sc)(name);
}

#else
unsigned long lkcd_lookup_name(const char *name)
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

const char *get_ioctl_name(unsigned int num)
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

// ripped from https://stackoverflow.com/questions/1184274/read-write-files-within-a-linux-kernel-module
struct file *file_open(const char *path, int flags, int rights, int *err) 
{
    struct file *filp = NULL;
    *err = 0;

    filp = filp_open(path, flags, rights);
    if (IS_ERR(filp)) {
        *err = PTR_ERR(filp);
        return NULL;
    }
    return filp;
}

void file_close(struct file *file) 
{
    filp_close(file, NULL);
}

const struct file_operations *s_dbg_open = 0;
const struct file_operations *s_dbg_full = 0;
void *k_pre_handler_kretprobe = 0;

int is_dbgfs(const struct file_operations *in)
{
  return (in == s_dbg_open) || (in == s_dbg_full);
}

// css_next_child is not exported so css_for_each_child not compiling. as usually
typedef struct cgroup_subsys_state *(*kcss_next_child)(struct cgroup_subsys_state *pos, struct cgroup_subsys_state *parent);
static kcss_next_child css_next_child_ptr = 0;
typedef int (*kcgroup_bpf_detach)(struct cgroup *cgrp, struct bpf_prog *prog, enum bpf_attach_type type);
static kcgroup_bpf_detach cgroup_bpf_detach_ptr = 0;

// kernfs_node_from_dentry is not exported
typedef struct kernfs_node *(*krnf_node_type)(struct dentry *dentry);
static krnf_node_type krnf_node_ptr = 0;

typedef void (*und_iterate_supers)(void (*f)(struct super_block *, void *), void *arg);
und_iterate_supers iterate_supers_ptr = 0;
seqlock_t *mount_lock = 0;

inline void lock_mount_hash(void)
{
  write_seqlock(mount_lock);
}

inline void unlock_mount_hash(void)
{
  write_sequnlock(mount_lock);
}

// trace events list and semaphore
struct rw_semaphore *s_trace_event_sem = 0;
struct mutex *s_event_mutex = 0;
struct list_head *s_ftrace_events = 0;
struct mutex *s_bpf_event_mutex = 0;
struct mutex *s_tracepoints_mutex = 0;
typedef int (*und_bpf_prog_array_length)(struct bpf_prog_array *progs);
und_bpf_prog_array_length bpf_prog_array_length_ptr = 0;

typedef void *(*t_patch_text)(void *addr, const void *opcode, size_t len);
t_patch_text s_patch_text = 0;

#ifdef CONFIG_FSNOTIFY
typedef struct fsnotify_mark *(*und_fsnotify_first_mark)(struct fsnotify_mark_connector **connp);
typedef struct fsnotify_mark *(*und_fsnotify_next_mark)(struct fsnotify_mark *mark);
struct srcu_struct *fsnotify_mark_srcu_ptr = 0;
und_fsnotify_first_mark fsnotify_first_mark_ptr = 0;
und_fsnotify_next_mark  fsnotify_next_mark_ptr  = 0;

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

void count_superblock_marks(struct super_block *sb, void *arg)
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

void fill_superblock_marks(struct super_block *sb, void *arg)
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

void fill_mount_marks(struct super_block *sb, void *arg)
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

void fill_inode_marks(struct super_block *sb, void *arg)
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

void fill_super_block_inodes(struct super_block *sb, void *arg)
{
  struct super_inodes_args *args = (struct super_inodes_args *)arg;
  if ( (void *)sb != args->sb_addr )
    return;
  else {
    struct inode *inode;
    args->found++;
    // iterate on inodes
    spin_lock(&sb->s_inode_list_lock);
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
#ifdef CONFIG_FSNOTIFY
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
    spin_unlock(&sb->s_inode_list_lock);
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

void fill_super_block_mounts(struct super_block *sb, void *arg)
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
#ifdef CONFIG_FSNOTIFY
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

void count_super_blocks(struct super_block *sb, void *arg)
{
  (*(unsigned long *)arg)++;
}

void fill_super_blocks(struct super_block *sb, void *arg)
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
  args->data[index].s_iflags  = sb->s_iflags;
  args->data[index].s_op      = (void *)sb->s_op;
  args->data[index].s_type    = sb->s_type;
  args->data[index].dq_op     = (void *)sb->dq_op;
  args->data[index].s_qcop    = (void *)sb->s_qcop;
  args->data[index].s_export_op = (void *)sb->s_export_op;
  args->data[index].s_d_op    = (void *)sb->s_d_op;
  args->data[index].s_user_ns = (void *)sb->s_user_ns;
  args->data[index].inodes_cnt = 0;
  args->data[index].s_root    = (void *)sb->s_root;
  if ( sb->s_root )
    dentry_path_raw(sb->s_root, args->data[index].root, sizeof(args->data[index].root));
  else
    args->data[index].root[0] = 0;
  args->data[index].mount_count = 0;
  list_for_each_entry(mnt, &sb->s_mounts, mnt_instance)
    args->data[index].mount_count++;
#ifdef CONFIG_FSNOTIFY
  args->data[index].s_fsnotify_mask = sb->s_fsnotify_mask;
  args->data[index].s_fsnotify_marks = sb->s_fsnotify_marks;
#endif /* CONFIG_FSNOTIFY */
  strncpy(args->data[index].s_id, sb->s_id, 31);
  // iterate on inodes
  spin_lock(&sb->s_inode_list_lock);
  list_for_each_entry(inode, &sb->s_inodes, i_sb_list)
    args->data[index].inodes_cnt++;
  spin_unlock(&sb->s_inode_list_lock);
  // inc index for next
  args->curr[0]++;
}

#ifdef CONFIG_UPROBES
// some uprobe functions
typedef struct und_uprobe *(*find_uprobe)(struct inode *inode, loff_t offset);
typedef struct und_uprobe *(*get_uprobe)(struct und_uprobe *uprobe);
typedef void (*put_uprobe)(struct und_uprobe *uprobe);
find_uprobe find_uprobe_ptr = 0;
get_uprobe  get_uprobe_ptr =  0;
put_uprobe  put_uprobe_ptr =  0;

struct und_uprobe *my_get_uprobe(struct und_uprobe *uprobe)
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
#else
  u64 ip = regs->ip;
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
#else
  u64 ip = regs->ip;
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

// ripped from kernel/kprobes.c
int is_krpobe_aggregated(struct kprobe *p)
{
  return (unsigned long)p->pre_handler == kprobe_aggr;
}

void patch_kprobe(struct kprobe *p, unsigned long reason)
{
  if ( reason )
    p->flags &= ~KPROBE_FLAG_DISABLED;
  else
    p->flags |= KPROBE_FLAG_DISABLED;
}

#ifdef CONFIG_USER_RETURN_NOTIFIER
void test_dummy_urn(struct user_return_notifier *urn)
{
}

static struct user_return_notifier s_urn = {
 .on_user_return = test_dummy_urn, 
 .link = NULL
};
#endif

struct urn_params
{
  unsigned long this_cpu_off;
  unsigned long offset;
  unsigned long count;
  unsigned long *out_data;
};

#ifdef CONFIG_USER_RETURN_NOTIFIER
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
  if ( c->prog_array )
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

void fill_one_cgroup(struct one_cgroup *grp, struct cgroup_subsys_state *css)
{
  int i;
  // bcs self (type cgroup_subsys_state) is first field in cgroup
  struct cgroup *cg = (struct cgroup *)css;
  grp->addr = (void *)cg;
  grp->ss = (void *)css->ss;
  grp->serial_nr = css->serial_nr;
  grp->flags = cg->flags;
  grp->level = cg->level;
  grp->kn = (void *)cg->kn;
  grp->id = cgroup_id(cg);
  for ( i = 0; i < MAX_BPF_ATTACH_TYPE && i < CG_BPF_MAX; i++ )
  {
    grp->prog_array[i] = (void *)cg->bpf.effective[i];
    if ( cg->bpf.effective[i] && bpf_prog_array_length_ptr )
    {
      grp->prog_array_cnt[i] = bpf_prog_array_length_ptr(cg->bpf.effective[i]);
    } else
      grp->prog_array_cnt[i] = 0;
    grp->bpf_flags[i] = cg->bpf.flags[i];
  }
}

void fill_bpf_prog(struct one_bpf_prog *curr, struct bpf_prog *prog)
{
  curr->prog = (void *)prog;
  curr->prog_type = (int)prog->type;
  curr->expected_attach_type = (int)prog->expected_attach_type;
  curr->len = prog->len;
  curr->jited_len = prog->jited_len;
  memcpy(curr->tag, prog->tag, 8);
  curr->bpf_func = (void *)prog->bpf_func;
  curr->aux = (void *)prog->aux;
  if ( prog->aux )
  {
    curr->aux_id = prog->aux->id;
    curr->used_map_cnt = prog->aux->used_map_cnt;
    curr->used_btf_cnt = prog->aux->used_btf_cnt;
    curr->func_cnt = prog->aux->func_cnt;
    curr->stack_depth = prog->aux->stack_depth;
    curr->num_exentries = prog->aux->num_exentries;
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

static long lkcd_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  unsigned long ptrbuf[16];
  unsigned long count = 0;
  size_t kbuf_size = 0;
  unsigned long *kbuf = NULL;
  switch(ioctl_num)
  {
    case IOCTL_READ_PTR:
     {
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
       if ( copy_to_user((void*)ioctl_param, (void*)ptrbuf[0], sizeof(void *)) > 0 )
         return -EFAULT;
     }
     break; /* IOCTL_READ_PTR */

    case IOCTL_RKSYM:
     {
       char name[BUFF_SIZE];
       int i;
       char ch;
       char *temp = (char *) ioctl_param;
       get_user(ch, temp++);
       name[0] = ch;
       for (i = 1; ch && i < BUFF_SIZE - 1; i++, temp++) 
       {
          get_user(ch, temp);
          name[i] = ch;
       }
       ptrbuf[0] = lkcd_lookup_name(name);
       if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
         return -EFAULT;
      }
      break; /* IOCTL_RKSYM */

    case IOCTL_GET_NETDEV_CHAIN:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
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
         unsigned long *kbuf = (unsigned long *)kmalloc_array(ptrbuf[1] + 1, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         rtnl_lock();
         for ( b = head->head; b != NULL; b = b->next )
         {
           if ( count >= ptrbuf[1] )
             break;
           kbuf[count + 1] = (unsigned long)b->notifier_call;
           count++;
         }
         rtnl_unlock();
         kbuf[0] = count;
         if ( copy_to_user((void*)(ioctl_param), (void*)kbuf, sizeof(unsigned long) * (1 + count)) > 0 )
         {
           kfree(kbuf);
           return -EFAULT;
         }
         kfree(kbuf);
       }
      break; /* IOCTL_GET_NETDEV_CHAIN */

    case READ_CPUFREQ_NTFY:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
        else {
          struct cpufreq_policy *cf = cpufreq_cpu_get(ptrbuf[0]);
          struct notifier_block *b;
          struct blocking_notifier_head *head;
          unsigned long i;
          if ( !cf )
           return -ENODATA;
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
          down_write(&head->rwsem);
          kbuf[0] = 0;
          i = 0;
          for ( b = head->head; i < ptrbuf[1] && b != NULL; b = b->next, ++i )
          {
            kbuf[1 + i] = (unsigned long)b->notifier_call;
          }
          up_write(&head->rwsem);
          cpufreq_cpu_put(cf);
          kbuf[0] = i;
          kbuf_size = sizeof(unsigned long) * (i + 1);
          goto copy_kbuf;
        }
      break; /* READ_CPUFREQ_NTFY */

    case READ_CPUFREQ_CNT:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
        else {
         struct cpufreq_policy *cf = cpufreq_cpu_get(ptrbuf[0]);
         unsigned long out_buf[3] = { 0, 0, 0 };
         struct notifier_block *b;
         if ( !cf )
           return -ENODATA;
         out_buf[0] = (unsigned long)cf;
         // count ntfy
         down_write(&cf->constraints.min_freq_notifiers.rwsem);
         if ( cf->constraints.min_freq_notifiers.head != NULL )
         {
           for ( b = cf->constraints.min_freq_notifiers.head; b != NULL; b = b->next )
             out_buf[1]++;
         }  
         up_write(&cf->constraints.min_freq_notifiers.rwsem);
         down_write(&cf->constraints.max_freq_notifiers.rwsem);
         if ( cf->constraints.max_freq_notifiers.head != NULL )
         {
           for ( b = cf->constraints.max_freq_notifiers.head; b != NULL; b = b->next )
             out_buf[2]++;
         }  
         up_write(&cf->constraints.max_freq_notifiers.rwsem);
         cpufreq_cpu_put(cf);
         if ( copy_to_user((void*)(ioctl_param), (void*)out_buf, sizeof(out_buf)) > 0 )
           return -EFAULT;
        }
      break; /* READ_CPUFREQ_CNT */

    case IOCTL_REM_BNTFY:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
        else {
         struct blocking_notifier_head *nb = (struct blocking_notifier_head *)ptrbuf[9];
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
         if ( copy_to_user((void*)(ioctl_param), (void*)ptrbuf, sizeof(ptrbuf[0])) > 0 )
           return -EFAULT;
        }
      break; /* IOCTL_REM_BNTFY */

    case IOCTL_REM_ANTFY:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
        else {
         struct atomic_notifier_head *nb = (struct atomic_notifier_head *)ptrbuf[9];
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
         if ( copy_to_user((void*)(ioctl_param), (void*)ptrbuf, sizeof(ptrbuf[0])) > 0 )
           return -EFAULT;
        }
      break; /* IOCTL_REM_ANTFY */

    case IOCTL_REM_SNTFY:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
        else {
         struct srcu_notifier_head *nb = (struct srcu_notifier_head *)ptrbuf[9];
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
         if ( copy_to_user((void*)(ioctl_param), (void*)ptrbuf, sizeof(ptrbuf[0])) > 0 )
           return -EFAULT;
        }
      break; /* IOCTL_REM_SNTFY */

    case IOCTL_CNTNTFYCHAIN:
     {
       // copy address of blocking_notifier_head from user-mode
       struct blocking_notifier_head *nb;
       struct notifier_block *b;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
       nb = (struct blocking_notifier_head *)ptrbuf[0];
       // lock
       down_write(&nb->rwsem);
       // traverse
       if ( nb->head != NULL )
       {
          for ( b = nb->head; b != NULL; b = b->next )
            count++;
       }
       // unlock
       up_write(&nb->rwsem);
       goto copy_count;
     }
     break; /* IOCTL_CNTNTFYCHAIN */

    case IOCTL_ENUMNTFYCHAIN:
     {
       // copy address of blocking_notifier_head and count from user-mode
       struct blocking_notifier_head *nb;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
       nb = (struct blocking_notifier_head *)ptrbuf[0];
       count = ptrbuf[1];
       // validation
       if ( !count || !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         unsigned long *kbuf = (unsigned long *)kmalloc_array(count, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         down_write(&nb->rwsem);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < count); b = b->next )
            {
              kbuf[res] = (unsigned long)b->notifier_call;
              res++;
            }
         }
         // unlock
         up_write(&nb->rwsem);
         // copy count to user-mode
         if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
         {
           kfree(kbuf);
           return -EFAULT;
         }
         if ( res )
         {
           if ( copy_to_user((void*)(ioctl_param + sizeof(res)), (void*)kbuf, sizeof(unsigned long) * res) > 0 )
           {
             kfree(kbuf);
             return -EFAULT;
           }
         }
         // cleanup
         kfree(kbuf);
       }
     }
     break; /* IOCTL_ENUMNTFYCHAIN */

    case IOCTL_ENUMANTFYCHAIN:
     {
       // copy address of atomic_notifier_head and count from user-mode
       struct atomic_notifier_head *nb;
       unsigned long flags;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
       nb = (struct atomic_notifier_head *)ptrbuf[0];
       count = ptrbuf[1];
       // validation
       if ( !count || !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         unsigned long *kbuf = (unsigned long *)kmalloc_array(count, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         spin_lock_irqsave(&nb->lock, flags);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < count); b = b->next )
            {
              kbuf[res] = (unsigned long)b->notifier_call;
              res++;
            }
         }
         // unlock
         spin_unlock_irqrestore(&nb->lock, flags);
         // copy count to user-mode
         if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
         {
           kfree(kbuf);
           return -EFAULT;
         }
         if ( res )
         {
           if ( copy_to_user((void*)(ioctl_param + sizeof(res)), (void*)kbuf, sizeof(unsigned long) * res) > 0 )
           {
             kfree(kbuf);
             return -EFAULT;
           }
         }
         // cleanup
         kfree(kbuf);
       }
     }
     break; /* IOCTL_ENUMANTFYCHAIN */

    case IOCTL_CNTANTFYCHAIN:
     {
       // copy address of atomic_notifier_head from user-mode
       struct atomic_notifier_head *nb;
       struct notifier_block *b;
       unsigned long flags;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
       nb = (struct atomic_notifier_head *)ptrbuf[0];
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
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
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
           struct clk_ntfy *curr;
           kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct clk_ntfy);
           kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
           if ( !kbuf )
             return -ENOMEM;
           curr = (struct clk_ntfy *)(kbuf + 1);
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
           kbuf[0] = count;
           kbuf_size = sizeof(unsigned long) + count * sizeof(struct clk_ntfy);
           // copy data to user-mode
           goto copy_kbuf;
         }
       }
     break; /* READ_CLK_NTFY */

    case READ_DEVFREQ_NTFY:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
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
           struct clk_ntfy *curr;
           kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct clk_ntfy);
           kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
           if ( !kbuf )
             return -ENOMEM;
           curr = (struct clk_ntfy *)(kbuf + 1);
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
           kbuf[0] = count;
           kbuf_size = sizeof(unsigned long) + count * sizeof(struct clk_ntfy);
           // copy data to user-mode
           goto copy_kbuf;
         }
       }
     break; /* READ_DEVFREQ_NTFY */

    case IOCTL_ENUMSNTFYCHAIN:
     {
       // copy args from user-mode
       struct srcu_notifier_head *nb;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
       nb = (struct srcu_notifier_head *)ptrbuf[0];
       count = ptrbuf[1];
       // validation
       if ( !count || !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         kbuf = (unsigned long *)kmalloc_array(count, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         mutex_lock(&nb->mutex);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < count); b = b->next )
            {
              kbuf[res] = (unsigned long)b->notifier_call;
              res++;
            }
         }
         // unlock
         mutex_unlock(&nb->mutex);
         // copy count to user-mode
         if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
         {
           kfree(kbuf);
           return -EFAULT;
         }
         if ( res )
         {
           if ( copy_to_user((void*)(ioctl_param + sizeof(res)), (void*)kbuf, sizeof(unsigned long) * res) > 0 )
           {
             kfree(kbuf);
             return -EFAULT;
           }
         }
         // cleanup
         kfree(kbuf);
       }
     }
     break; /* IOCTL_ENUMSNTFYCHAIN */

    case IOCTL_CNTSNTFYCHAIN:
     {
       // copy address of srcu_notifier_head from user-mode
       struct srcu_notifier_head *nb;
       struct notifier_block *b;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
 	 return -EFAULT;
       nb = (struct srcu_notifier_head *)ptrbuf[0];
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

    case IOCTL_TRACEV_CNT:
     {
       struct rw_semaphore *sem;
       struct hlist_head *hash;
       struct trace_event *event;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
 	 return -EFAULT;
       sem = (struct rw_semaphore *)ptrbuf[0];
       hash = (struct hlist_head *)ptrbuf[1];
       hash += ptrbuf[2];
       // lock
       down_write(sem);
       // traverse
       hlist_for_each_entry(event, hash, node) {
         count++;
       }
       // unlock
       up_write(sem);
       goto copy_count;
     }
     break; /* IOCTL_TRACEV_CNT */

    case IOCTL_TRACEVENTS:
     {
       struct rw_semaphore *sem;
       struct hlist_head *hash;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
 	 return -EFAULT;
       sem = (struct rw_semaphore *)ptrbuf[0];
       hash = (struct hlist_head *)ptrbuf[1];
       hash += ptrbuf[2];
       count = ptrbuf[3];
       if ( !count )
         return -EINVAL;
       else
       {
         struct trace_event *event;
         unsigned long kbuf_size = count * sizeof(struct one_trace_event);
         unsigned long res = 0; // how many events in reality
         struct one_trace_event *curr;
         char *kbuf = (char *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         curr = (struct one_trace_event *)kbuf;
         // lock
         down_write(sem);
         // traverse
         hlist_for_each_entry(event, hash, node) {
           if ( res >= count )
             break;
           curr->addr = event;
           curr->type = event->type;
           if ( event->funcs )
           {
             curr->trace  = event->funcs->trace;
             curr->raw    = event->funcs->raw;
             curr->hex    = event->funcs->hex;
             curr->binary = event->funcs->binary;
           } else
            curr->trace = curr->raw = curr->hex = curr->binary = NULL;
           // for next iteration
           curr++;
           res++;
         }
         // unlock
         up_write(sem);
         // write res
         if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
         {
           kfree(kbuf);
           return -EFAULT;
         }
         if ( res )
         {
           // write to usermode
           if ( copy_to_user((void*)(ioctl_param + sizeof(res)), (void*)kbuf, sizeof(struct one_trace_event) * res) > 0 )
           {
              kfree(kbuf);
              return -EFAULT;
           }
         }
         // cleanup
         kfree(kbuf);
       }
     }
     break; /* IOCTL_TRACEVENTS */

    case IOCTL_TRACEPOINT_INFO:
     {
       struct tracepoint *tp;
       struct tracepoint_func *func;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
 	 return -EFAULT;
       tp = (struct tracepoint *)ptrbuf[0];
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
       if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0]) * 4) > 0)
 	 return -EFAULT;
     }
     break; /* IOCTL_TRACEPOINT_INFO */

    case IOCTL_TRACEPOINT_FUNCS:
     {
       struct tracepoint *tp;
       struct tracepoint_func *func;
       unsigned long res = 0;
       struct one_tracepoint_func *curr;

       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
 	 return -EFAULT;
       tp = (struct tracepoint *)ptrbuf[0];
       count = ptrbuf[1];
       if ( !tp || !count )
         return -EINVAL;

       kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_tracepoint_func);
       kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
       if ( !kbuf )
         return -ENOMEM;
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

    case IOCTL_KERNFS_NODE:
     {
       char name[BUFF_SIZE];
       struct file *file;
       struct kernfs_node *k;
       int i, err;
       char ch;
       char *temp = (char *)ioctl_param;
       if ( krnf_node_ptr == NULL )
         return -EFAULT;
       get_user(ch, temp++);
       name[0] = ch;
       for (i = 1; ch && i < BUFF_SIZE - 1; i++, temp++) 
       {
          get_user(ch, temp);
          name[i] = ch;
       }
       // open file
       file = file_open(name, 0, 0, &err);
       if ( NULL == file )
       {
         printk(KERN_INFO "[lkcd] cannot open file %s, error %d\n", name, err);
         return -err;
       }
       k = krnf_node_ptr(file->f_path.dentry);
       ptrbuf[0] = (unsigned long)k;
       ptrbuf[1] = ptrbuf[2] = ptrbuf[3] = ptrbuf[4] = ptrbuf[5] = ptrbuf[6] = ptrbuf[7] = ptrbuf[8] = 0;
       if ( k && (k->flags & KERNFS_FILE) )
       {
         struct kobject *kobj = k->parent->priv;
         ptrbuf[1] = (unsigned long)kobj;
         ptrbuf[7] = k->flags;
         ptrbuf[8] = (unsigned long)k->priv;
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
             ptrbuf[2] = (unsigned long)debugfs_real_fops(file);
             if ( seq && S_ISREG(file->f_path.dentry->d_inode->i_mode) )
               ptrbuf[3] = (unsigned long)seq->op;
           }
         }
       }

       file_close(file);
       if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0]) * 9) > 0)
         return -EFAULT;
      }
     break; /* IOCTL_KERNFS_NODE */

#ifdef CONFIG_FSNOTIFY
     case IOCTL_GET_INODE_MARKS:
       if ( !iterate_supers_ptr )
         return -ENOCSI;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
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
         if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
           return -EFAULT;
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

     case IOCTL_GET_SUPERBLOCK_INODES:
       if ( !iterate_supers_ptr )
         return -ENOCSI;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
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

     case IOCTL_GET_MOUNT_MARKS:
       if ( !iterate_supers_ptr || !mount_lock)
         return -ENOCSI;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
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

     case IOCTL_GET_SUPERBLOCK_MOUNTS:
       if ( !iterate_supers_ptr || !mount_lock)
         return -ENOCSI;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
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
       if ( !iterate_supers_ptr )
         return -EFAULT;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
       if ( !ptrbuf[0] )
       {
         ptrbuf[0] = 0;
         iterate_supers_ptr(count_super_blocks, (void*)ptrbuf);
         if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
           return -EFAULT;
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

#endif /* CONFIG_FSNOTIFY */

// #ifdef __x86_64__
     case IOCTL_CNT_UPROBES:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
         return -EFAULT;
       else {
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
       }
       break; /* IOCTL_CNT_UPROBES */

     case IOCTL_TRACE_UPROBE_BPFS:
        if ( !bpf_prog_array_length_ptr )
          return -ENOCSI;
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 5) > 0 )
          return -EFAULT;
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
            down_write(&up->consumer_rwsem);
            for (con = up->consumers; con; con = con->next )
            {
              if ( (unsigned long)con != ptrbuf[3] )
                continue;
              tup = container_of(con, struct trace_uprobe, consumer);
              break;
            }
            if ( tup != NULL )
              copy_trace_bpfs(&tup->tp.event->call, ptrbuf[4], kbuf);
            up_write(&up->consumer_rwsem);
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

     case IOCTL_TRACE_UPROBE:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
          return -EFAULT;
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
            down_write(&up->consumer_rwsem);
            for (con = up->consumers; con; con = con->next )
            {
              if ( (unsigned long)con != ptrbuf[3] )
                continue;
              tup = container_of(con, struct trace_uprobe, consumer);
              break;
            }
            if ( tup != NULL )
              copy_trace_event_call(&tup->tp.event->call, &buf);
            up_write(&up->consumer_rwsem);
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

#ifdef CONFIG_UPROBES
     case IOCTL_UPROBES_CONS:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
         return -EFAULT;
       // 2 - uprobe, 3 - size
       if ( !ptrbuf[3] )
         return -EINVAL;
       else {
         struct rb_root *root = (struct rb_root *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct rb_node *iter;
         int found = 0;
         struct one_uprobe_consumer *curr;
         kbuf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_uprobe_consumer);
         kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         curr = (struct one_uprobe_consumer *)(kbuf + 1);
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
           down_write(&up->consumer_rwsem);
           for (con = up->consumers; con && count < ptrbuf[3]; con = con->next, count++)
           {
             curr[count].addr        = (void *)con;
             curr[count].handler     = con->handler;
             curr[count].ret_handler = con->ret_handler;
             curr[count].filter      = con->filter;
           }
           up_write(&up->consumer_rwsem);
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
         kbuf[0] = count;
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_uprobe_consumer);
         goto copy_kbuf;
       }
       break; /* IOCTL_UPROBES_CONS */

     case IOCTL_UPROBES:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
       if ( !ptrbuf[2] )
         return -EINVAL;
       else {
         struct rb_root *root = (struct rb_root *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         struct rb_node *iter;
         struct one_uprobe *curr;
         kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_uprobe);
         kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         curr = (struct one_uprobe *)(kbuf + 1);
         // lock
         spin_lock(lock);
         // traverse tree
         for ( iter = rb_first(root); iter != NULL && count < ptrbuf[2]; iter = rb_next(iter), count++ )
         {
           struct uprobe_consumer **con;
           struct und_uprobe *up = rb_entry(iter, struct und_uprobe, rb_node);
           curr[count].addr = up;
           curr[count].inode = up->inode;
           curr[count].ref_ctr_offset = up->ref_ctr_offset;
           curr[count].offset = up->offset;
           curr[count].i_no = 0;
           curr[count].flags = up->flags;
           // try get filename from inode
           curr[count].name[0] = 0;
           if ( up->inode )
           {
             struct dentry *de = d_find_any_alias(up->inode);
             curr[count].i_no = up->inode->i_ino;
             if ( de )
               dentry_path_raw(de, curr[count].name, sizeof(curr[count].name));
           }
           // calc count of consumers
           curr[count].cons_cnt = 0;
           down_write(&up->consumer_rwsem);
           for (con = &up->consumers; *con; con = &(*con)->next)
             curr[count].cons_cnt++;
           up_write(&up->consumer_rwsem);
         }
         // unlock
         spin_unlock(lock);
         // copy to user
         kbuf[0] = count;
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_uprobe);
         goto copy_kbuf;
      }
      break; /* IOCTL_UPROBES */

     case IOCTL_TEST_UPROBE:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
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

     case IOCTL_TEST_KPROBE:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
       if ( ptrbuf[0] && !test_kprobe_installed )
       {
          int ret = register_kprobe(&test_kp);
          if ( ret )
          {
            printk(KERN_INFO "[lkcd] register_kprobe failed, returned %d\n", ret);
            return ret;
          }
          test_kprobe_installed = 1;
          printk(KERN_INFO "[lkcd] test kprobe installed at %p\n", kp.addr);
       }
       if ( !ptrbuf[0] && test_kprobe_installed )
       {
         unregister_kprobe(&test_kp);
         test_kprobe_installed = 0;
       }
      break; /* IOCTL_TEST_KPROBE */

     case IOCTL_KPROBE_DISABLE:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 5) > 0 )
         return -EFAULT;
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
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
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

     case IOCTL_GET_AGGR_KPROBE:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 5) > 0 )
         return -EFAULT;
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
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
         return -EFAULT;
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
         if ( kbuf )
           kfree(kbuf);
       }
      break; /* IOCTL_GET_KPROBE_BUCKET */

#ifdef CONFIG_USER_RETURN_NOTIFIER
     case IOCTL_TEST_URN:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
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
      {
        int err;
        unsigned long cpu_n;
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
          return -EFAULT;
        cpu_n = ptrbuf[0];
        err = smp_call_function_single(cpu_n, count_lrn, (void*)ptrbuf, 1);
        if ( err )
        {
          printk(KERN_INFO "[+] IOCTL_CNT_RNL_PER_CPU on cpu %ld failed, error %d\n", cpu_n, err);
          return err;
        }
        // copy result back to user-space
        if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0]) * 2) > 0)
          return -EFAULT;
       }
      break; /* IOCTL_CNT_RNL_PER_CPU */

     case IOCTL_RNL_PER_CPU:
      {
        struct urn_params params;
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
  	  return -EFAULT;
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
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
  	      return -EFAULT;
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
         struct one_console *curr;
         kbuf_size = sizeof(unsigned long) + ptrbuf[0] * sizeof(struct one_console);
         kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
         if ( !kbuf )
           return -ENOMEM;
         curr = (struct one_console *)(kbuf + 1);
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
          curr->exit = con->exit;
          curr->match = con->match;
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
         kbuf[0] = count;
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_console);
         goto copy_kbuf;
       }
       break; /* IOCTL_READ_CONSOLES */

     case IOCTL_GET_SOCK_DIAG:
        // check pre-req
        if ( !s_sock_diag_handlers || !s_sock_diag_table_mutex )
          return -ENOCSI;
        // read index
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
  	      return -EFAULT;
  	if ( ptrbuf[0] >= AF_MAX)
          return -EINVAL;
        else {
          struct one_sock_diag params;
          // lock
          mutex_lock(s_sock_diag_table_mutex);
          // fill out params
          params.addr = (void *)s_sock_diag_handlers[ptrbuf[0]];
          if ( params.addr )
          {
            params.dump = (void *)s_sock_diag_handlers[ptrbuf[0]]->dump;
            params.get_info = (void *)s_sock_diag_handlers[ptrbuf[0]]->get_info;
            params.destroy = (void *)s_sock_diag_handlers[ptrbuf[0]]->destroy;
          } else
            params.dump = params.get_info = params.destroy = 0;
          // unlock
          mutex_unlock(s_sock_diag_table_mutex);
          // copy to user
          if (copy_to_user((void*)ioctl_param, (void*)&params, sizeof(params)) > 0)
            return -EFAULT;
        }
       break; /* IOCTL_GET_SOCK_DIAG */

     case IOCTL_GET_ULP_OPS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_tcp_ulp_ops *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_tcp_ulp_ops);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_tcp_ulp_ops *)(kbuf + 1);
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
            kbuf[0] = count;
            // copy to user
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_tcp_ulp_ops);
            goto copy_kbuf;
          }
        }
       break; /* IOCTL_GET_ULP_OPS */

     case IOCTL_GET_PROTOS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            kbuf[0] = count;
            // copy to user
            kbuf_size = sizeof(unsigned long) * (kbuf[0] + 1);
            goto copy_kbuf;
          }
        }
       break; /* IOCTL_GET_PROTOS */

     case IOCTL_GET_PROTOSW:
        // read count
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
  	  return -EFAULT;
  	if ( ptrbuf[2] >= SOCK_MAX )
          return -EINVAL;
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
            struct one_protosw *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_protosw);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_protosw *)(kbuf + 1);
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
            kbuf[0] = count;
            // copy to user
            kbuf_size = sizeof(unsigned long) + kbuf[0] * sizeof(struct one_protosw);
            goto copy_kbuf;
          }
        }
      break; /* IOCTL_GET_PROTOSW */

#ifdef CONFIG_NETFILTER
     case IOCTL_NFIEHOOKS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
  	     return -EFAULT;
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
          struct nf_hook_entries *nfh = NULL;
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
          if ( ptrbuf[3] ) nfh = right_dev->nf_hooks_egress;
#endif
#ifndef CONFIG_NETFILTER_INGRESS
          if ( !ptrbuf[3] ) nfh = right_dev->nf_hooks_ingress;
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
          for ( ; count < nfh->num_hook_entries && count < ptrbuf[2]; ++count )
            kbuf[1 + count] = (unsigned long)nfh->hooks[count].hook;
          mutex_unlock(s_nf_hook_mutex);
          read_unlock(s_dev_base_lock);
          up_read(s_net);
          if ( !count ) goto copy_count;
          kbuf_size = sizeof(unsigned long) * (1 + count);
          kbuf[0] = count;
          goto copy_kbuf;
        }
      break; /* IOCTL_NFIEHOOKS */

     case IOCTL_NFHOOKS:
        // check pre-req
        if ( !s_net || !s_nf_log_mutex )
          return -ENOCSI;
        // read params
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	     return -EFAULT;
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
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,0)
          for ( i = 0; i < ARRAY_SIZE(net->nf.hooks); ++i )
          {
            int j;
            for ( j = 0; j < ARRAY_SIZE(net->nf.hooks[i]); ++j )
              if ( net->nf.hooks[i][j] ) count++;
          }
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
          int i, j;
          struct net *net;
          struct one_nf_logger *curr;
          kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_nf_logger);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          net = peek_net(ptrbuf[0]);
          if ( !net )
          {
            up_read(s_net);
            kfree(kbuf);
            return -ENOENT;
          }
          curr = (struct one_nf_logger *)(kbuf + 1);
          mutex_lock(s_nf_log_mutex);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,15,0)
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
          kbuf[0] = count;
          goto copy_kbuf;
        }
      break; /* IOCTL_NFHOOKS */

     case IOCTL_NFLOGGERS:
        // check pre-req
        if ( !s_net || !s_nf_log_mutex )
          return -ENOCSI;
        // read params
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	     return -EFAULT;
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
          struct one_nf_logger *curr;
          struct net *net; 
          int i;
          kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_nf_logger);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          net = peek_net(ptrbuf[0]);
          if ( !net )
          {
            up_read(s_net);
            kfree(kbuf);
            return -ENOENT;
          }
          curr = (struct one_nf_logger *)(kbuf + 1);
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
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_nf_logger);
          goto copy_kbuf;
        }
      break; /* IOCTL_NFLOGGERS */
#endif /* CONFIG_NETFILTER */

     case IOCTL_GET_NET_DEVS:
        // check pre-req
        if ( !s_net || !s_dev_base_lock )
          return -ENOCSI;
        // read count
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	     return -EFAULT;
  	  if ( !ptrbuf[1] )
  	  {
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
          int xdp;
          struct net *net;
          struct net_device *dev;
          struct one_net_dev *curr;
          int found = 0;
          kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_net_dev);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_net_dev *)(kbuf + 1);
          kbuf[0] = 0;
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
              curr->min_mtu     = dev->min_mtu;
              curr->max_mtu     = dev->max_mtu;
              curr->type        = dev->type;
              curr->netdev_ops  = (void *)dev->netdev_ops;
              curr->ethtool_ops = (void *)dev->ethtool_ops;
              curr->header_ops  = (void *)dev->header_ops;
              curr->xdp_prog    = (void *)dev->xdp_prog;
              curr->rx_handler  = (void *)dev->rx_handler;
              curr->rtnl_link_ops = (void *)dev->rtnl_link_ops;
#ifdef CONFIG_WIRELESS_EXT
              if ( dev->wireless_handlers )
              {
                curr->wireless_handler = (void *)dev->wireless_handlers->standard;
                curr->wireless_get_stat = (void *)dev->wireless_handlers->get_wireless_stats;
              }
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
#ifdef CONFIG_IPV6
              curr->ndisc_ops = (void *)dev->ndisc_ops;
#endif
#ifdef CONFIG_XFRM_OFFLOAD
              curr->xfrmdev_ops = (void *)dev->xfrmdev_ops;
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
              // copy xdp_state
              rtnl_lock();
              for ( xdp = 0; xdp < 3; xdp++ )
              {
                curr->bpf_prog[xdp] = (void *)dev->xdp_state[xdp].prog;
                curr->bpf_link[xdp] = (void *)dev->xdp_state[xdp].link;
              }
              rtnl_unlock();
              if ( dev->net_notifier_list.next != NULL )
              {
                struct netdev_net_notifier *nn;
                list_for_each_entry(nn, &dev->net_notifier_list, list)
                 curr->netdev_chain_cnt++;
              }
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
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
  	if ( !ptrbuf[0] )
          return -EINVAL;
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
          kbuf_size = sizeof(unsigned long) * (1 + ptrbuf[1]);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
            return -ENOMEM;
          rtnl_lock();
          list_for_each_entry(ops, l, list)
          {
            if ( count >= ptrbuf[1] )
             break;
            kbuf[1 + count] = (unsigned long)ops;
            count++;
          }
          rtnl_unlock();
          kbuf[0] = count;
          // copy to user
          kbuf_size = sizeof(unsigned long) * (count + 1);
          goto copy_kbuf;
        }
      break; /* IOCTL_GET_LINKS_OPS */

     case IOCTL_GET_PERNET_OPS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	if ( !ptrbuf[0] || !ptrbuf[1] )
          return -EINVAL;
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
          struct one_pernet_ops *curr;
          struct pernet_operations *ops;
          kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_pernet_ops);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_pernet_ops *)(kbuf + 1);
          kbuf[0] = 0;
          down_read(lock);
          list_for_each_entry(ops, l, list)
          {
            if ( kbuf[0] >= ptrbuf[2] )
              break;
            curr->addr = (void *)ops;
            curr->init = (void *)ops->init;
            curr->exit = (void *)ops->exit;
            curr->exit_batch = (void *)ops->exit_batch;
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
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	     return -EFAULT;
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
            struct one_nft_af *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_nft_af);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_nft_af *)(kbuf + 1);
            net = peek_net(ptrbuf[0]);
            if ( !net )
            {
              up_read(s_net);
              kfree(buf);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + buf[0] * sizeof(struct one_nft_af);
            goto copy_kbuf;
          }
        }
#endif
      break; /* IOCTL_ENUM_NFT_AF */
       
     case IOCTL_GET_NETS:
        // check pre-req
        if ( !s_net )
          return -ENOCSI;
        // read count
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
  	  return -EFAULT;
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
          struct one_net *curr;
          kbuf_size = sizeof(unsigned long) + ptrbuf[0] * sizeof(struct one_net);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_net *)(kbuf + 1);
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
            curr->uevent_sock = (void *)net->uevent_sock;
            curr->diag_nlsk = (void *)net->diag_nlsk;
            if ( net->diag_nlsk )
            {
               curr->diag_nlsk_proto = (void *)net->diag_nlsk->sk_prot;
               if ( net->diag_nlsk->sk_filter && net->diag_nlsk->sk_filter->prog )
                 curr->diag_nlsk_filter = (void *)net->diag_nlsk->sk_filter->prog->bpf_func;
            }
            curr->netdev_chain_cnt = 0;
            curr->dev_cnt = 0;
            if ( net->netdev_chain.head != NULL )
            {
              struct notifier_block *b;
              for ( b = net->netdev_chain.head; b != NULL; b = b->next )
               curr->netdev_chain_cnt++;
            }
            if ( s_dev_base_lock )
            {
              struct net_device *dev;
              read_lock(s_dev_base_lock);
              for_each_netdev(net, dev)
                curr->dev_cnt++;
              read_unlock(s_dev_base_lock);
            }
#if defined(CONFIG_NETFILTER) && LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
            if ( net->queue_handler )
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
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
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
          kbuf_size = sizeof(unsigned long) * (ptrbuf[1] + 1);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
            return -ENOMEM;
          rtnl_lock();
          list_for_each(lh, head)
          {
            if ( count >= ptrbuf[1] )
              break;
            ops = list_entry(lh, struct rtnl_af_ops, list);
            kbuf[1 + count] = (unsigned long)ops;
            count++;
          }
          rtnl_unlock();
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) * (count + 1);
          goto copy_kbuf;
        }
      break; /* IOCTL_GET_RTNL_AF_OPS */

    case IOCTL_GET_NLTAB:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	if ( ptrbuf[2] >= MAX_LINKS )
  	  return -EFBIG;
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
	       if (PTR_ERR(ns) == -EAGAIN)
	 	 continue;
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

    case IOCTL_DEL_CGROUP_BPF:
        if ( !cgroup_bpf_detach_ptr )
         return -ENOCSI;
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 6) > 0 )
  	  return -EFAULT;
  	// check index (4 param)
  	if ( ptrbuf[4] >= MAX_BPF_ATTACH_TYPE )
          return -EINVAL;
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
               if ( (void *)child != cgrp )
	         continue;
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

    case IOCTL_GET_PMUS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
              return -EFAULT;
          } else {
            struct one_pmu *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_pmu);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_pmu *)(kbuf + 1);
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
                curr->event_mapped = (void *)pmu->event_mapped;
                curr->event_unmapped = (void *)pmu->event_unmapped;
                curr->add = (void *)pmu->add;
                curr->del = (void *)pmu->del;
                curr->start = (void *)pmu->start;
                curr->stop = (void *)pmu->stop;
                curr->read = (void *)pmu->read;
                curr->start_txn = (void *)pmu->start_txn;
                curr->commit_txn = (void *)pmu->commit_txn;
                curr->cancel_txn = (void *)pmu->cancel_txn;
                curr->event_idx = (void *)pmu->event_idx;
                curr->sched_task = (void *)pmu->sched_task;
                curr->swap_task_ctx = (void *)pmu->swap_task_ctx;
                curr->setup_aux = (void *)pmu->setup_aux;
                curr->free_aux = (void *)pmu->free_aux;
                curr->snapshot_aux = (void *)pmu->snapshot_aux;
                curr->addr_filters_validate = (void *)pmu->addr_filters_validate;
                curr->addr_filters_sync = (void *)pmu->addr_filters_sync;
                curr->aux_output_match = (void *)pmu->aux_output_match;
                curr->filter_match = (void *)pmu->filter_match;
                curr->check_period = (void *)pmu->check_period;
                curr++;
              }
              count++;
            }
            // unlock
            mutex_unlock(m);
            // copy to user
            kbuf[0] = count;
            goto copy_kbuf;
          }
        }
      break; /* IOCTL_GET_PMUS */

    case IOCTL_GET_BPF_MAPS:
      if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
        return -EFAULT;
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
          if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
            return -EFAULT;
        } else {
          struct one_bpf_map *curr;
          kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_bpf_map);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
          if ( !kbuf )
             return -ENOMEM;
          curr = (struct one_bpf_map *)(kbuf + 1);
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
              curr->inner_map_meta = map->inner_map_meta;
              curr->btf = map->btf;
              curr->map_type = map->map_type;
              curr->key_size = map->key_size;
              curr->value_size = map->value_size;
              curr->id = map->id;
              strlcpy(curr->name, map->name, 16);
              curr++; count++;
            } else break;
          }
          // unlock
          spin_unlock_bh(lock);
          idr_preload_end();
          // copy to user
          kbuf[0] = count;
          goto copy_kbuf;
        }
      }
      break; /* IOCTL_GET_BPF_MAPS */

    case IOCTL_GET_CGROUP_BPF:
        if ( !bpf_prog_array_length_ptr )
          return -ENOCSI;
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 6) > 0 )
  	  return -EFAULT;
  	// check index (4 param)
  	if ( ptrbuf[4] >= MAX_BPF_ATTACH_TYPE )
          return -EINVAL;
  	else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          void *root = (void *)ptrbuf[2];
          void *cgrp = (void *)ptrbuf[3];
          unsigned long cnt = ptrbuf[5];
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          struct one_bpf_prog *curr;
          int found = 0;
          kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_bpf_prog);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_bpf_prog *)(kbuf + 1);
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
               if ( (void *)child != cgrp )
	         continue;
	       found |= 3;
               if ( cg->bpf.effective[ptrbuf[4]] )
               {
                 int total = bpf_prog_array_length_ptr(cg->bpf.effective[ptrbuf[4]]);
                 for ( cnt = 0; cnt < total && cnt < ptrbuf[5]; cnt++, curr++ )
                 {
                   curr->prog = cg->bpf.effective[ptrbuf[4]]->items[cnt].prog;
                   if ( !curr->prog )
                     break;
                   fill_bpf_prog(curr, cg->bpf.effective[ptrbuf[4]]->items[cnt].prog);
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
          kbuf[0] = cnt;
          kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_bpf_prog);
          goto copy_kbuf;
   	}
      break; /* IOCTL_GET_CGROUP_BPF */

    case IOCTL_GET_CGROUPS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
  	  return -EFAULT;
  	else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          void *root = (void *)ptrbuf[2];
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          struct one_cgroup *curr;
          int found = 0;
          kbuf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_cgroup);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_cgroup *)(kbuf + 1);
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
               if ( child == &item->cgrp.self )
	         continue;
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
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_cgroup);
          goto copy_kbuf;
        }
      break; /* IOCTL_GET_CGROUPS */

    case IOCTL_GET_CGRP_ROOTS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_group_root *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_group_root);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_group_root *)(kbuf + 1);
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
	          if ( child == &item->cgrp.self )
	            continue;
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_group_root);
            goto copy_kbuf;
          }
        }
      break; /* IOCTL_GET_CGRP_ROOTS */

    case IOCTL_GET_GENL_FAMILIES:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
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
            struct one_genl_family *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_genl_family);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_genl_family *)(kbuf + 1);
            genl_lock();
            idr_for_each_entry(genl, family, id)
            {
              if ( count >= ptrbuf[1] )
                break;
              curr->addr = (void *)family;
              curr->id = family->id;
              curr->pre_doit = (void *)family->pre_doit;
              curr->post_doit = (void *)family->post_doit;
              curr->ops = (void *)family->ops;
              curr->small_ops = (void *)family->small_ops;
              strlcpy(curr->name, family->name, GENL_NAMSIZ);
              // next iteration
              count++;
              curr++;
            }
            genl_unlock();
            // copy to usermode
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_genl_family);
            goto copy_kbuf;
          }
        }
      break; /* IOCTL_GET_GENL_FAMILIES */

    case IOCTL_GET_NL_SK:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
  	  return -EFAULT;
  	if ( !ptrbuf[3] )
          return -EINVAL;
  	if ( ptrbuf[2] >= MAX_LINKS )
  	  return -EFBIG;
        else {
          struct netlink_table *tab = *(struct netlink_table **)ptrbuf[0] + ptrbuf[2];
          rwlock_t *lock = (rwlock_t *)ptrbuf[1];
          int err = 0;
          struct rhashtable_iter iter;
          struct one_nl_socket *curr;
          kbuf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_nl_socket);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_nl_socket *)(kbuf + 1);
          // lock
          read_lock(lock);
          // iterate
          rhashtable_walk_enter(&tab->hash, &iter);
          rhashtable_walk_start(&iter);
          for (;;) {
            struct netlink_sock *ns = rhashtable_walk_next(&iter);
            if (IS_ERR(ns)) {
	       if (PTR_ERR(ns) == -EAGAIN)
	 	 continue;
	       err = PTR_ERR(ns);
	       break;
            } else if (!ns)
              break;
            if ( count >= ptrbuf[3] )
              break;
            // copy fields
            curr->addr = (void *)ns;
            curr->portid = ns->portid;
            curr->flags  = ns->flags;
            curr->subscriptions = ns->subscriptions;
            curr->sk_type = ns->sk.sk_type;
            curr->sk_protocol = ns->sk.sk_protocol;
            curr->netlink_rcv = ns->netlink_rcv;
            curr->netlink_bind = ns->netlink_bind;
            curr->netlink_unbind = ns->netlink_unbind;
            curr->cb_dump = ns->cb.dump;
            curr->cb_done = ns->cb.done;
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
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_nl_socket);
          goto copy_kbuf;
       }
     break; /* IOCTL_GET_NL_SK */

    case IOCTL_GET_BPF_USED_MAPS:
    case IOCTL_GET_BPF_OPCODES:
    case IOCTL_GET_BPF_PROG_BODY:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
         return -EFAULT;
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
             bpf_prog_inc(prog);
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
           bpf_prog_put(prog);
           return -EFAULT;
         }
         bpf_prog_put(prog);
       }
     break; /* IOCTL_GET_BPF_PROG_BODY */

    case IOCTL_GET_BPF_PROGS:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
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
            struct one_bpf_prog *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_bpf_prog);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_bpf_prog *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_bpf_prog);
            goto copy_kbuf;
         }
       }
     break; /* IOCTL_GET_BPF_PROGS */

    case IOCTL_GET_BPF_LINKS:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
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
            struct one_bpf_links *curr;
            kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_bpf_links);
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_bpf_links *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_bpf_links);
            goto copy_kbuf;
         }
       }
     break; /* IOCTL_GET_BPF_LINKS */

    case IOCTL_GET_TRACE_EXPORTS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_trace_export *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_export) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_trace_export *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_export) * count;
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_TRACE_EXPORTS */

    case IOCTL_GET_BPF_RAW_EVENTS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct bpf_raw_event_map *start = (struct bpf_raw_event_map *)ptrbuf[0];
          struct bpf_raw_event_map *end = (struct bpf_raw_event_map *)ptrbuf[1];
          if ( !ptrbuf[2] )
          {
            count = end - start;
            goto copy_count;
          } else {
            struct one_bpf_raw_event *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_raw_event) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_bpf_raw_event *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_raw_event) * count;
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_BPF_RAW_EVENTS */

#ifdef CONFIG_FUNCTION_TRACER
    case IOCTL_GET_FTRACE_OPS:
        if ( !s_ftrace_end )
          return -ENOCSI;
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_ftrace_ops *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_ftrace_ops) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_ftrace_ops *)(kbuf + 1);
            // lock
            mutex_lock(m);
            // iterate
            for ( p = *head; p != s_ftrace_end; p = p->next )
            {
              if ( count >= ptrbuf[2] )
                break;
              curr->addr = (void *)p;
              curr->func = (void *)p->func;
              curr->saved_func = (void *)p->saved_func;
              curr->flags = p->flags;
              curr++;
              count++;
            }
            // unlock
            mutex_unlock(m);
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_ftrace_ops) * count;
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_FTRACE_OPS */
#endif /* CONFIG_FUNCTION_TRACER */

    case IOCTL_GET_FTRACE_CMDS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_tracefunc_cmd *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_tracefunc_cmd) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_tracefunc_cmd *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_tracefunc_cmd) * count;
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_FTRACE_CMDS */

    case IOCTL_GET_DYN_EVENTS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_tracepoint_func *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_tracepoint_func) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_tracepoint_func *)(kbuf + 1);
            kbuf[0] = 0;
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
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_DYN_EVENTS */

    case IOCTL_GET_DYN_EVT_OPS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_dyn_event_op *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_dyn_event_op) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_dyn_event_op *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_dyn_event_op) * count;
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_DYN_EVT_OPS */

    case IOCTL_GET_EVT_CALLS:
        if ( !s_trace_event_sem || !s_event_mutex || !s_ftrace_events || !s_bpf_event_mutex )
          return -ENOCSI;
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
  	if ( !ptrbuf[0] )
        {
          struct trace_event_call *call, *p;
          if ( !ptrbuf[1] )
          {
            // just count of registered events
            down_read(s_trace_event_sem);
            list_for_each_entry_safe(call, p, s_ftrace_events, list)
              count++;
            up_read(s_trace_event_sem);
            goto copy_count;
          } else {
            struct one_trace_event_call *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_event_call) * ptrbuf[1];
            kbuf = (unsigned long *)kzalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_trace_event_call *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_event_call) * count;
            goto copy_kbuf;
          }
        } else {
          // copy bpf_progs for some event
          struct one_bpf_prog *curr;
          int found = 0;
          struct trace_event_call *call, *p;
          kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_prog) * ptrbuf[1];
          kbuf = (unsigned long *)kzalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_bpf_prog *)(kbuf + 1);
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
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_prog) * count;
          goto copy_kbuf;
        }
     break; /* IOCTL_GET_EVT_CALLS */

    case IOCTL_GET_EVENT_CMDS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_event_command *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_event_command) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_event_command *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_event_command) * count;
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_EVENT_CMDS */

    case IOCTL_GET_BPF_REGS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_bpf_reg *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_reg) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_bpf_reg *)(kbuf + 1);
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
              curr->seq_info        = (void *)ti->reg_info->seq_info;
              curr->feature         = ti->reg_info->feature;
              curr++;
              count++;
            }
            mutex_unlock(m);
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_reg) * count;
            goto copy_kbuf;
          }
        }
     break; /* IOCTL_GET_BPF_REGS */

    case IOCTL_GET_BPF_KSYMS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
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
            struct one_bpf_ksym *curr;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_ksym) * ptrbuf[2];
            kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !kbuf )
              return -ENOMEM;
            curr = (struct one_bpf_ksym *)(kbuf + 1);
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
            kbuf[0] = count;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_ksym) * count;
            goto copy_kbuf;
          }
       }
     break; /* IOCTL_GET_BPF_KSYMS */

    case IOCTL_ENUM_CALGO:
     if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	   return -EFAULT;
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
          struct one_kcalgo *curr;
          kbuf_size = sizeof(unsigned long) + sizeof(struct one_kcalgo) * ptrbuf[2];
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_kcalgo *)(kbuf + 1);
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
              curr->init = q->cra_type->init;
              curr->init_tfm = q->cra_type->init_tfm;
              curr->show = q->cra_type->show;
              curr->report = q->cra_type->report;
              curr->free = q->cra_type->free;
              curr->tfmsize = q->cra_type->tfmsize;
            }
            // copy algo methods
            if ( q->cra_flags & CRYPTO_ALG_TYPE_COMPRESS )
            {
              curr->coa_compress = q->cra_u.compress.coa_compress;
              curr->coa_decompress = q->cra_u.compress.coa_decompress;
            } else {
              curr->cia_min_keysize = q->cra_u.cipher.cia_min_keysize;
              curr->cia_max_keysize = q->cra_u.cipher.cia_max_keysize;
              curr->cia_setkey = q->cra_u.cipher.cia_setkey;
              curr->cia_encrypt = q->cra_u.cipher.cia_encrypt;
              curr->cia_decrypt = q->cra_u.cipher.cia_decrypt;
            }
            curr->cra_init = q->cra_init;
            curr->cra_exit = q->cra_exit;
            curr->cra_destroy = q->cra_destroy;
            curr++;
            count++;
          }
          up_read(cs);
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + sizeof(struct one_kcalgo) * count;
          goto copy_kbuf;
       }
     }
     break; /* IOCTL_ENUM_CALGO */

    case IOCTL_GET_LSM_HOOKS:
     if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
  	 else {
       struct security_hook_list *shl;
       struct hlist_head *head = (struct hlist_head *)ptrbuf[0];
  	   // there is no sync - all numerous security_xxx just call call_xx_hook
    	 if ( !ptrbuf[1] )
  	   {
          ptrbuf[0] = 0;
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
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) * (count + 1);
          goto copy_kbuf;
        }
      }
      break; /* IOCTL_GET_LSM_HOOKS */

    case IOCTL_GET_ALARMS:
      if ( !s_alarm )
        return -ENOCSI;
      if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	    return -EFAULT;
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
          for ( iter = rb_first(&ca->timerqueue.rb_root.rb_root); iter != NULL; iter = rb_next(iter) )
            ptrbuf[0]++;
          // unlock
          spin_unlock_irqrestore(&ca->lock, flags);
          ptrbuf[1] = (unsigned long)ca->get_ktime;
          ptrbuf[2] = (unsigned long)ca->get_timespec;
          // copy to user-mode
          if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0]) * 3) > 0)
            return -EFAULT;
        } else {
          struct one_alarm *curr;
          kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_alarm);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_alarm *)(kbuf + 1);
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
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_alarm);
          // copy collected data to user-mode
          goto copy_kbuf;
        }
      }
     break; /* IOCTL_GET_ALARMS */

    case IOCTL_GET_KTIMERS:
     if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
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
         struct ktimer *curr;
         kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct ktimer);
         kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
         if ( !kbuf )
          return -ENOMEM;
         curr = (struct ktimer *)(kbuf + 1);
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
         kbuf[0] = count;
         kbuf_size = sizeof(unsigned long) + count * sizeof(struct ktimer);
         goto copy_kbuf;
      }
     }
     break; /* IOCTL_GET_KTIMERS */

#ifdef CONFIG_KEYS
    case IOCTL_KEYTYPE_NAME:
      if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
  	    return -EFAULT;
      else {
        struct key_type *p;
        size_t len;
        int err;
        down_write(s_key_types_sem);
        list_for_each_entry(p, s_key_types_list, link)
        {
          if ( (unsigned long)p != ptrbuf[0] ) continue;
          if ( !p->name ) {
            up_write(s_key_types_sem);
            return -ENOTNAM;    
          }
          len = strlen(p->name);
          err = copy_to_user((void*)ioctl_param, (void*)p->name, len + 1);
          up_write(s_key_types_sem);
          return (err > 0) ? -EFAULT : 0;
        }
        up_write(s_key_types_sem);
        return -ENOKEY;
      }
     break; /* IOCTL_KEYTYPE_NAME */

    case IOCTL_ENUM_KEYS:
      if ( !s_key_serial_tree || !s_key_serial_lock )
        return -ENOCSI;
      if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
  	    return -EFAULT;
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
          struct one_key *curr;
          kbuf_size = sizeof(unsigned long) + ptrbuf[0] * sizeof(struct one_key);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_key *)(kbuf + 1);
          // lock
          spin_lock(s_key_serial_lock);
          for ( iter = rb_first(s_key_serial_tree); iter != NULL; iter = rb_next(iter) )
          {
            if ( count >= ptrbuf[0] ) break;
            xkey = rb_entry(iter, struct key, serial_node);
            curr->addr = (void *)xkey;
            curr->serial = xkey->serial;
            curr->expiry = xkey->expiry;
            curr->uid = xkey->uid.val;
            curr->gid = xkey->gid.val;
            curr->state = xkey->state;
            curr->perm = xkey->perm;
            curr->datalen = xkey->datalen;
            curr->flags = xkey->flags;
            curr->type = xkey->type;
            if ( xkey->restrict_link )
              curr->rest_check = (void *)xkey->restrict_link->check;
            // for next iteration
            curr++; count++;
          }
          // unlock
          spin_unlock(s_key_serial_lock);
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_key);
          goto copy_kbuf;
        }
      }
     break; /* IOCTL_ENUM_KEYS */

    case IOCTL_KEY_TYPES:
      if ( !s_key_types_sem || !s_key_types_list )
        return -ENOCSI;
      if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
  	    return -EFAULT;
      else {
        struct key_type *p;
        if ( !ptrbuf[0] )
        {
          down_write(s_key_types_sem);
          list_for_each_entry(p, s_key_types_list, link) count++;
          up_write(s_key_types_sem);
          goto copy_count;
        } else {
          struct one_key_type *curr;
          kbuf_size = sizeof(unsigned long) + ptrbuf[0] * sizeof(struct one_key_type);
          kbuf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !kbuf )
            return -ENOMEM;
          curr = (struct one_key_type *)(kbuf + 1);
          down_write(s_key_types_sem);
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
          up_write(s_key_types_sem);
          kbuf[0] = count;
          kbuf_size = sizeof(unsigned long) + count * sizeof(struct one_key_type);
          goto copy_kbuf;
        }
      }
     break; /* IOCTL_KEY_TYPES */
#endif /* CONFIG_KEYS */

    case IOCTL_PATCH_KTEXT1:
      if ( !s_patch_text )
          return -ENOCSI;
      if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	    return -EFAULT;
      else {
        s_patch_text((void*)ptrbuf[0], ptrbuf + 1, 1);
      }
      break; /* IOCTL_PATCH_KTEXT1 */     

    default:
     return -EBADRQC;
  }
  return 0;
copy_count:
  if (copy_to_user((void*)ioctl_param, (void*)&count, sizeof(count)) > 0)
    return -EFAULT;
  return 0;
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

	inode_lock(file_inode(file));
	switch (orig) {
	case SEEK_CUR:
		offset += file->f_pos;
		/* fall through */
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
	inode_unlock(file_inode(file));
#ifdef _DEBUG
  printk(KERN_INFO "[+] lkcd_seek: %llX ret %lld\n", offset, ret);
#endif /* _DEBUG */
	return ret;
}

static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
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

static ssize_t read_kmem(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t low_count, read, sz;
	char *kbuf; /* k-addr because vread() takes vmlist_lock rwlock */
	int err = 0;

 printk(KERN_INFO "[+] lkcd_read: %lX at %lX\n", count, p);

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
	.read		= read_kmem,
	.write          = invalid_write,
	.open		= open_lkcd,
	.release        = close_lkcd,
	.unlocked_ioctl	= lkcd_ioctl,
};

static struct miscdevice lkcd_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "lkcd",
    .fops = &kmem_fops
};

#ifdef HAS_ARM64_THUNKS
#define SYM_LOAD(name, type, val)  val = (type)bti_wrap(name);
#else
#define SYM_LOAD(name, type, val)  val = (type)lkcd_lookup_name(name); if ( !val ) printk("cannot find %s", name); 
#endif

int __init
init_module (void)
{
  int ret = misc_register(&lkcd_dev);
  if (ret)
  {
    printk("Unable to register the lkcd device\n");
    return ret;
  }
#ifdef HAS_ARM64_THUNKS
  if ( !init_bti_thunks() )
  {
    misc_deregister(&lkcd_dev);
    return -ENOMEM;
  }
#endif /* HAS_ARM64_THUNKS */
  k_pre_handler_kretprobe = (void *)lkcd_lookup_name("pre_handler_kretprobe");
  if ( !k_pre_handler_kretprobe )
    printk("cannot find pre_handler_kretprobe\n");  
  s_dbg_open = (const struct file_operations *)lkcd_lookup_name("debugfs_open_proxy_file_operations");
  if ( !s_dbg_open )
    printk("cannot find debugfs_open_proxy_file_operations\n");
  s_dbg_full = (const struct file_operations *)lkcd_lookup_name("debugfs_full_proxy_file_operations");
  if ( !s_dbg_full )
    printk("cannot find debugfs_full_proxy_file_operations\n");
  SYM_LOAD("kernfs_node_from_dentry", krnf_node_type, krnf_node_ptr)
  SYM_LOAD("iterate_supers", und_iterate_supers, iterate_supers_ptr)
  mount_lock = (seqlock_t *)lkcd_lookup_name("mount_lock");
  if ( !mount_lock )
    printk("cannot find mount_lock\n");
  s_net = (struct rw_semaphore *)lkcd_lookup_name("net_rwsem");
  if ( !s_net )
    printk("cannot find net_rwsem\n");
  s_dev_base_lock = (rwlock_t *)lkcd_lookup_name("dev_base_lock");
  if ( !s_dev_base_lock )
    printk("cannot find dev_base_lock\n");
  s_sock_diag_handlers = (struct sock_diag_handler **)lkcd_lookup_name("sock_diag_handlers");
  if ( !s_sock_diag_handlers )
    printk("cannot find sock_diag_handlers\n");
  s_sock_diag_table_mutex = (struct mutex *)lkcd_lookup_name("sock_diag_table_mutex");
  if ( !s_sock_diag_table_mutex )
    printk("cannot find sock_diag_table_mutex\n");
#ifdef CONFIG_NETFILTER
  s_nf_hook_mutex = (struct mutex *)lkcd_lookup_name("nf_hook_mutex");
  if ( !s_nf_hook_mutex )
    printk("cannot find nf_hook_mutex\n");
  s_nf_log_mutex = (struct mutex *)lkcd_lookup_name("nf_log_mutex");
  if ( !s_nf_log_mutex )
    printk("cannot find nf_log_mutex\n");
#endif
  // keys
#ifdef CONFIG_KEYS
  s_key_types_sem = (struct rw_semaphore *)lkcd_lookup_name("key_types_sem");
  if ( !s_key_types_sem )
    printk("cannot find key_types_sem");
  s_key_types_list = (struct list_head *)lkcd_lookup_name("key_types_list");
  if ( !s_key_types_list )
    printk("cannot find key_types_list");
  s_key_serial_tree = (struct rb_root *)lkcd_lookup_name("key_serial_tree");
  if ( !s_key_serial_tree )
    printk("cannot find key_serial_tree");
  s_key_serial_lock = (spinlock_t *)lkcd_lookup_name("key_serial_lock");
  if ( !s_key_serial_lock )
    printk("cannot find s_key_serial_lock");
#endif
  // trace events data
  s_ftrace_end = (struct ftrace_ops *)lkcd_lookup_name("ftrace_list_end");
  if ( !s_ftrace_end )
    printk("cannot find ftrace_list_end\n");
  s_trace_event_sem = (struct rw_semaphore *)lkcd_lookup_name("trace_event_sem");
  if ( !s_trace_event_sem )
    printk("cannot find trace_event_sem\n");
  s_event_mutex = (struct mutex *)lkcd_lookup_name("event_mutex");
  if ( !s_event_mutex )
    printk("cannot find event_mutex\n");
  s_ftrace_events = (struct list_head *)lkcd_lookup_name("ftrace_events");
  if ( !s_ftrace_events )
    printk("cannot find ftrace_events\n");
  s_bpf_event_mutex = (struct mutex *)lkcd_lookup_name("bpf_event_mutex");
  if ( !s_bpf_event_mutex )
    printk("cannot find bpf_event_mutex\n");
  s_tracepoints_mutex = (struct mutex *)lkcd_lookup_name("tracepoints_mutex");
  if ( !s_tracepoints_mutex )
    printk("cannot find tracepoints_mutex\n");
  SYM_LOAD("bpf_prog_array_length", und_bpf_prog_array_length, bpf_prog_array_length_ptr)
  css_next_child_ptr = (kcss_next_child)lkcd_lookup_name("css_next_child");
  if ( !css_next_child_ptr )
    printk("cannot find css_next_child\n");
  SYM_LOAD("cgroup_bpf_detach", kcgroup_bpf_detach, cgroup_bpf_detach_ptr)
  SYM_LOAD("text_poke_kgdb", t_patch_text, s_patch_text)
  delayed_timer = (void *)lkcd_lookup_name("delayed_work_timer_fn");
  if ( !delayed_timer )
    printk("cannot find delayed_work_timer_fn");
  s_alarm = (struct alarm_base *)lkcd_lookup_name("alarm_bases");
  if ( !s_alarm )
    printk("cannot find alarm_bases");
#ifdef CONFIG_FSNOTIFY
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
  kprobe_aggr = (unsigned long)lkcd_lookup_name("aggr_pre_handler");
#ifdef CONFIG_UPROBES
  find_uprobe_ptr = (find_uprobe)lkcd_lookup_name("find_uprobe");
  get_uprobe_ptr = (get_uprobe)lkcd_lookup_name("get_uprobe");
  if ( !get_uprobe_ptr )
    get_uprobe_ptr = my_get_uprobe;
  put_uprobe_ptr = (put_uprobe)lkcd_lookup_name("put_uprobe");
#endif
#ifdef HAS_ARM64_THUNKS
  bti_thunks_lock_ro();
#endif
  return 0;
}

void cleanup_module (void)
{
#ifdef __x86_64__
  if ( urn_installed )
  {
     user_return_notifier_unregister(&s_urn);
     urn_installed = 0;
  }
#endif /* __x86_64__ */
  if ( test_kprobe_installed )
  {
     unregister_kprobe(&test_kp);
     test_kprobe_installed = 0;
  }
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
