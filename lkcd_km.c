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
#ifdef __x86_64__
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/rbtree.h>
#include <linux/uprobes.h>
#include <linux/kprobes.h>
#include "uprobes.h"
#endif
#ifdef CONFIG_FSNOTIFY
#include <linux/fsnotify_backend.h>
#include <linux/mount.h>
#include "mnt.h"
#endif /* CONFIG_FSNOTIFY */
#include <linux/smp.h>
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
#include <linux/trace_events.h>
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
#include <linux/lsm_hooks.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include "bpf.h"
#include "event.h"
#include "shared.h"

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "lkcd";

struct rw_semaphore *s_net = 0;
rwlock_t *s_dev_base_lock = 0;
struct sock_diag_handler **s_sock_diag_handlers = 0;
struct mutex *s_sock_diag_table_mutex = 0;
struct ftrace_ops *s_ftrace_end = 0;

#ifdef __x86_64__
#define KPROBE_HASH_BITS 6
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)

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
        args->data[index].ignored_mask = mark->ignored_mask;
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
        args->data[index].ignored_mask = mark->ignored_mask;
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
        args->data[index].ignored_mask = mark->ignored_mask;
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

#ifdef __x86_64__
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

#define DEBUGGEE_FILE_OFFSET	0x4710 /* getenv@plt */
 
static struct inode *debuggee_inode = NULL;
static int urn_installed = 0;
static int test_kprobe_installed = 0;

// ripped from https://github.com/kentaost/uprobes_sample/blob/master/uprobes_sample.c
static int uprobe_sample_handler(struct uprobe_consumer *con,
		struct pt_regs *regs)
{
  printk("uprobe handler in PID %d executed, ip = %lx\n", task_pid_nr(current), regs->ip);
  return 0;
}

static int uprobe_sample_ret_handler(struct uprobe_consumer *con,
					unsigned long func,
					struct pt_regs *regs)
{
  printk("uprobe ret_handler is executed, ip = %lX\n", regs->ip);
  return 0;
}

static struct uprobe_consumer s_uc = {
	.handler = uprobe_sample_handler,
	.ret_handler = uprobe_sample_ret_handler
};

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

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
		p->addr, trapnr);
	/* Return 0 because we don't handle the fault. */
	return 0;
}

static struct kprobe test_kp = {
	.pre_handler = handler_pre,
	.post_handler = handler_post,
	.fault_handler = handler_fault,
	.symbol_name	= "__x64_sys_fork", // try better do_int3, he-he
};

static unsigned long kprobe_aggr = 0;

// ripped from kernel/kprobes.c
int is_krpobe_aggregated(struct kprobe *p)
{
  return (unsigned long)p->pre_handler == kprobe_aggr;
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
#endif /* __x86_64__ */

static void copy_trace_event_call(const struct trace_event_call *c, struct one_trace_event_call *out_data)
{
  struct hlist_head *list;
  out_data->addr = (void *)c;
  out_data->evt_class = (void *)c->class; // nice to use c++ keyword
  out_data->tp = (void *)c->tp;
  out_data->filter = (void *)c->filter;
  out_data->flags = c->flags;
  out_data->perf_cnt = 0;
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

static long lkcd_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  unsigned long ptrbuf[16];
//  unsigned long *ptr = ptrbuf;
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
         unsigned long cnt = 0;
         struct notifier_block *b;
         struct raw_notifier_head *head = (struct raw_notifier_head *)ptrbuf[0];
         rtnl_lock();
         for ( b = head->head; b != NULL; b = b->next )
            cnt++;
         rtnl_unlock();
         // copy count to user-mode
         if ( copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0 )
   	   return -EFAULT;
       } else {
         struct notifier_block *b;
         unsigned long cnt = 0;
         struct raw_notifier_head *head = (struct raw_notifier_head *)ptrbuf[0];
         unsigned long *kbuf = (unsigned long *)kmalloc_array(ptrbuf[1] + 1, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         rtnl_lock();
         for ( b = head->head; b != NULL; b = b->next )
         {
           if ( cnt >= ptrbuf[1] )
             break;
           kbuf[cnt + 1] = (unsigned long)b->notifier_call;
           cnt++;
         }
         rtnl_unlock();
         kbuf[0] = cnt;
         if ( copy_to_user((void*)(ioctl_param), (void*)kbuf, sizeof(unsigned long) * (1 + cnt)) > 0 )
         {
           kfree(kbuf);
           return -EFAULT;
         }
         kfree(kbuf);
       }
      break; /* IOCTL_GET_NETDEV_CHAIN */

    case IOCTL_CNTNTFYCHAIN:
     {
       // copy address of blocking_notifier_head from user-mode
       struct blocking_notifier_head *nb;
       struct notifier_block *b;
       unsigned long res = 0;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
 	 return -EFAULT;
       nb = (struct blocking_notifier_head *)ptrbuf[0];
       // lock
       down_write(&nb->rwsem);
       // traverse
       if ( nb->head != NULL )
       {
          for ( b = nb->head; b != NULL; b = b->next )
            res++;
       }
       // unlock
       up_write(&nb->rwsem);
       // copy count to user-mode
       if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
 	 return -EFAULT;
     }
     break; /* IOCTL_CNTNTFYCHAIN */

    case IOCTL_ENUMNTFYCHAIN:
     {
       // copy address of blocking_notifier_head and count from user-mode
       struct blocking_notifier_head *nb;
       unsigned long cnt;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
 	 return -EFAULT;
       nb = (struct blocking_notifier_head *)ptrbuf[0];
       cnt = ptrbuf[1];
       // validation
       if ( !cnt || !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         unsigned long *kbuf = (unsigned long *)kmalloc_array(cnt, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         down_write(&nb->rwsem);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < cnt); b = b->next )
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
       unsigned long cnt;
       unsigned long flags;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
 	 return -EFAULT;
       nb = (struct atomic_notifier_head *)ptrbuf[0];
       cnt = ptrbuf[1];
       // validation
       if ( !cnt || !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         unsigned long *kbuf = (unsigned long *)kmalloc_array(cnt, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         spin_lock_irqsave(&nb->lock, flags);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < cnt); b = b->next )
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
       unsigned long res = 0;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
 	 return -EFAULT;
       nb = (struct atomic_notifier_head *)ptrbuf[0];
       // lock
       spin_lock_irqsave(&nb->lock, flags);
       // traverse
       if ( nb->head != NULL )
       {
          for ( b = nb->head; b != NULL; b = b->next )
            res++;
       }
       // unlock
       spin_unlock_irqrestore(&nb->lock, flags);
       // copy count to user-mode
       if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
 	 return -EFAULT;
     }
     break; /* IOCTL_CNTANTFYCHAIN */

    case IOCTL_ENUMSNTFYCHAIN:
     {
       // copy address of srcu_notifier_head and count from user-mode
       struct srcu_notifier_head *nb;
       unsigned long cnt;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
 	 return -EFAULT;
       nb = (struct srcu_notifier_head *)ptrbuf[0];
       cnt = ptrbuf[1];
       // validation
       if ( !cnt || !nb )
         return -EINVAL;
       else
       {
         struct notifier_block *b;
         unsigned long res = 0; // how many ntfy in reality
         unsigned long *kbuf = (unsigned long *)kmalloc_array(cnt, sizeof(unsigned long), GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         // lock
         mutex_lock(&nb->mutex);
         // traverse
         if ( nb->head != NULL )
         {
            for ( b = nb->head; (b != NULL) && (res < cnt); b = b->next )
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
       unsigned long res = 0;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
 	 return -EFAULT;
       nb = (struct srcu_notifier_head *)ptrbuf[0];
       // lock
       mutex_lock(&nb->mutex);
       // traverse
       if ( nb->head != NULL )
       {
          for ( b = nb->head; b != NULL; b = b->next )
            res++;
       }
       // unlock
       mutex_unlock(&nb->mutex);
       // copy count to user-mode
       if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
 	 return -EFAULT;
     }
     break; /* IOCTL_CNTSNTFYCHAIN */

    case IOCTL_TRACEV_CNT:
     {
       struct rw_semaphore *sem;
       struct hlist_head *hash;
       struct trace_event *event;
       unsigned long res = 0;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
 	 return -EFAULT;
       sem = (struct rw_semaphore *)ptrbuf[0];
       hash = (struct hlist_head *)ptrbuf[1];
       hash += ptrbuf[2];
       // lock
       down_write(sem);
       // traverse
       hlist_for_each_entry(event, hash, node) {
         res++;
       }
       // unlock
       up_write(sem);
       // copy count to user-mode
       if ( copy_to_user((void*)ioctl_param, (void*)&res, sizeof(res)) > 0 )
 	 return -EFAULT;
     }
     break; /* IOCTL_TRACEV_CNT */

    case IOCTL_TRACEVENTS:
     {
       struct rw_semaphore *sem;
       struct hlist_head *hash;
       unsigned long cnt;
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
 	 return -EFAULT;
       sem = (struct rw_semaphore *)ptrbuf[0];
       hash = (struct hlist_head *)ptrbuf[1];
       hash += ptrbuf[2];
       cnt = ptrbuf[3];
       if ( !cnt )
         return -EINVAL;
       else
       {
         struct trace_event *event;
         unsigned long kbuf_size = cnt * sizeof(struct one_trace_event);
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
           if ( res >= cnt )
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
       unsigned long cnt, res = 0;
       unsigned long *kbuf = NULL;
       size_t ksize;
       struct one_tracepoint_func *curr;

       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
 	 return -EFAULT;
       tp = (struct tracepoint *)ptrbuf[0];
       cnt = ptrbuf[1];
       if ( !tp || !cnt )
         return -EINVAL;

       ksize = sizeof(unsigned long) + cnt * sizeof(struct one_tracepoint_func);
       kbuf = (unsigned long *)kmalloc(ksize, GFP_KERNEL);
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
          if ( res >= cnt )
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
       ksize = sizeof(unsigned long) + res * sizeof(struct one_tracepoint_func);
       // copy to usermode
       if ( copy_to_user((void*)ioctl_param, (void*)kbuf, ksize) > 0 )
       {
          kfree(kbuf);
          return -EFAULT;
       }
       // cleanup
       kfree(kbuf);
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
         size_t ksize = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_fsnotify);
         // fill inode_mark_args
         args.sb_addr    = (void *)ptrbuf[0];
         args.inode_addr = (void *)ptrbuf[1];
         args.cnt        = ptrbuf[2];
         args.found      = 0;
         args.curr = (unsigned long *)kmalloc(ksize, GFP_KERNEL);
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
         ksize = sizeof(unsigned long) + args.curr[0] * sizeof(struct one_fsnotify);
         if (copy_to_user((void*)ioctl_param, (void*)args.curr, ksize) > 0)
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
           size_t ksize = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_fsnotify);
           // fill inode_mark_args
           sbargs.sb_addr    = (void *)ptrbuf[0];
           sbargs.cnt        = ptrbuf[1];
           sbargs.found      = 0;
           sbargs.curr = (unsigned long *)kmalloc(ksize, GFP_KERNEL);
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
           ksize = sizeof(unsigned long) + sbargs.curr[0] * sizeof(struct one_fsnotify);
           if (copy_to_user((void*)ioctl_param, (void*)sbargs.curr, ksize) > 0)
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
         size_t ksize = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_inode);
         // fill super_inodes_args
         sargs.sb_addr = (void *)ptrbuf[0];
         sargs.cnt     = ptrbuf[1];
         sargs.found   = 0;
         sargs.curr = (unsigned long *)kmalloc(ksize, GFP_KERNEL);
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
         ksize = sizeof(unsigned long) + sargs.curr[0] * sizeof(struct one_inode);
         if (copy_to_user((void*)ioctl_param, (void*)sargs.curr, ksize) > 0)
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
         size_t ksize = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_fsnotify);
         // fill inode_mark_args
         args.sb_addr    = (void *)ptrbuf[0];
         args.inode_addr = (void *)ptrbuf[1]; // mnt address actually but I am too lazy to add new structure
         args.cnt        = ptrbuf[2];
         args.found      = 0;
         args.curr = (unsigned long *)kmalloc(ksize, GFP_KERNEL);
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
         ksize = sizeof(unsigned long) + args.curr[0] * sizeof(struct one_fsnotify);
         if (copy_to_user((void*)ioctl_param, (void*)args.curr, ksize) > 0)
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
         size_t ksize = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_mount);
         // fill super_inodes_args
         sargs.sb_addr = (void *)ptrbuf[0];
         sargs.cnt     = ptrbuf[1];
         sargs.found   = 0;
         sargs.curr = (unsigned long *)kmalloc(ksize, GFP_KERNEL);
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
         ksize = sizeof(unsigned long) + sargs.curr[0] * sizeof(struct one_mount);
         if (copy_to_user((void*)ioctl_param, (void*)sargs.curr, ksize) > 0)
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

#ifdef __x86_64__
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
         ptrbuf[0] = 0;
         for ( iter = rb_first(root); iter != NULL; iter = rb_next(iter) )
           ptrbuf[0]++;
         // unlock
         spin_unlock(lock);
         // copy result to user-mode
         if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
           return -EFAULT;
       }
       break; /* IOCTL_CNT_UPROBES */

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
         unsigned long cnt = 0;
         int found = 0;
         struct one_uprobe_consumer *curr;
         size_t size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_uprobe_consumer);
         char *kbuf = (char *)kmalloc(size, GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         curr = (struct one_uprobe_consumer *)(kbuf + sizeof(unsigned long));
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
           for (con = up->consumers; con && cnt < ptrbuf[3]; con = con->next, cnt++)
           {
             curr[cnt].addr        = (void *)con;
             curr[cnt].handler     = con->handler;
             curr[cnt].ret_handler = con->ret_handler;
             curr[cnt].filter      = con->filter;
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
         *(unsigned long *)kbuf = cnt;
         size = sizeof(unsigned long) + cnt * sizeof(struct one_uprobe_consumer);
         if (copy_to_user((void*)ioctl_param, (void*)kbuf, size) > 0)
         {
           kfree(kbuf);
           return -EFAULT;
         }
         kfree(kbuf);
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
         unsigned long cnt = 0;
         struct one_uprobe *curr;
         size_t size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_uprobe);
         char *kbuf = (char *)kmalloc(size, GFP_KERNEL);
         if ( !kbuf )
           return -ENOMEM;
         curr = (struct one_uprobe *)(kbuf + sizeof(unsigned long));
         // lock
         spin_lock(lock);
         // traverse tree
         for ( iter = rb_first(root); iter != NULL && cnt < ptrbuf[2]; iter = rb_next(iter), cnt++ )
         {
           struct uprobe_consumer **con;
           struct und_uprobe *up = rb_entry(iter, struct und_uprobe, rb_node);
           curr[cnt].addr = up;
           curr[cnt].inode = up->inode;
           curr[cnt].offset = up->offset;
           curr[cnt].i_no = 0;
           curr[cnt].flags = up->flags;
           // try get filename from inode
           curr[cnt].name[0] = 0;
           if ( up->inode )
           {
             struct dentry *de = d_find_any_alias(up->inode);
             curr[cnt].i_no = up->inode->i_ino;
             if ( de )
               dentry_path_raw(de, curr[cnt].name, sizeof(curr[cnt].name));
           }
           // calc count of consumers
           curr[cnt].cons_cnt = 0;
           down_write(&up->consumer_rwsem);
           for (con = &up->consumers; *con; con = &(*con)->next)
             curr[cnt].cons_cnt++;
           up_write(&up->consumer_rwsem);
         }
         // unlock
         spin_unlock(lock);
         // copy to user
         *(unsigned long *)kbuf = cnt;
         size = sizeof(unsigned long) + cnt * sizeof(struct one_uprobe);
         if (copy_to_user((void*)ioctl_param, (void*)kbuf, size) > 0)
         {
           kfree(kbuf);
           return -EFAULT;
         }
         kfree(kbuf);
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
         ptrbuf[0] = 0;
         // traverse
         hlist_for_each_entry(p, head, hlist)
           ptrbuf[0]++;
	 // unlock
         mutex_unlock(m);
         // copy to user
         if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
           return -EFAULT;
       }
      break; /* IOCTL_CNT_KPROBE_BUCKET */

     case IOCTL_GET_AGGR_KPROBE:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 5) > 0 )
         return -EFAULT;
       else {
         struct hlist_head *head;
         struct kprobe *p, *kp;
         struct mutex *m = (struct mutex *)ptrbuf[1];
         size_t kbuf_size = 0;
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
               kbuf_size++;
             }
             break;
           }
           // unlock
           mutex_unlock(m);
           if ( !found )
             return -ENOENT;
           // copy count to user
           if (copy_to_user((void*)ioctl_param, (void*)&kbuf_size, sizeof(kbuf_size)) > 0)
             return -EFAULT;
         } else {
            struct one_kprobe *out_buf;
            unsigned long *buf = NULL;
            unsigned long curr = 0;
            kbuf_size = sizeof(unsigned long) + ptrbuf[4] * sizeof(struct one_kprobe);
            buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            out_buf = (struct one_kprobe *)(buf + 1);
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
              // found our aggregated krobe
              list_for_each_entry_rcu(kp, &p->list, list)
              {
                if ( curr >= ptrbuf[4] )
                  break;
                out_buf[curr].kaddr = (void *)kp;
                out_buf[curr].addr = (void *)kp->addr;
                out_buf[curr].pre_handler = (void *)kp->pre_handler;
                out_buf[curr].post_handler = (void *)kp->post_handler;
                out_buf[curr].flags = (unsigned int)kp->flags;
                out_buf[curr].is_aggr = is_krpobe_aggregated(kp);
                curr++;
              }
              break;
            }
            // unlock
            mutex_unlock(m);
            if ( !found )
            {
              kfree(buf);
              return -ENOENT;
            }
            buf[0] = curr;
            // copy to user
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
         }
       }
      break; /* IOCTL_GET_AGGR_KPROBE */

     case IOCTL_GET_KPROBE_BUCKET:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
         return -EFAULT;
       else {
         unsigned long *buf = NULL;
         size_t kbuf_size;
         if ( ptrbuf[2] >= KPROBE_TABLE_SIZE )
           return -EFBIG;
         if ( !ptrbuf[3] )
           break;
         // alloc enough memory
         kbuf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_kprobe);
         buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
         if ( !buf )
           return -ENOMEM;
         else {
           struct hlist_head *head;
           struct kprobe *p;
           unsigned long curr = 0;
           struct mutex *m = (struct mutex *)ptrbuf[1];
           struct one_kprobe *out_buf = (struct one_kprobe *)(buf + 1);
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
             out_buf[curr].flags = (unsigned int)p->flags;
             out_buf[curr].is_aggr = is_krpobe_aggregated(p);
             curr++;
           }
           // unlock
           mutex_unlock(m);
           // store count of processed
           buf[0] = curr;
           // copy to user
           if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
           {
             kfree(buf);
             return -EFAULT;
           }
         }
         if ( buf )
           kfree(buf);
       }
      break; /* IOCTL_GET_KPROBE_BUCKET */

     case IOCTL_TEST_URN:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long)) > 0 )
         return -EFAULT;
#ifdef CONFIG_USER_RETURN_NOTIFIER
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
#endif /* CONFIG_USER_RETURN_NOTIFIER */
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
#endif /* __x86_64__ */

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
          unsigned long cnt = 0;
          if ( !ptrbuf[2] )
          {
            // just calc count
            spin_lock(lock);
            list_for_each(p, list)
              cnt++;
	    // unlock
            spin_unlock(lock);
            // copy to user
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            size_t buf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_tcp_ulp_ops);
            unsigned long *buf = (unsigned long *)kmalloc(buf_size, GFP_KERNEL);
            struct one_tcp_ulp_ops *curr;
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_tcp_ulp_ops *)(buf + 1);
            spin_lock(lock);
            list_for_each(p, list)
            {
              struct tcp_ulp_ops *ulp = list_entry(p, struct tcp_ulp_ops, list);
              if ( cnt >= ptrbuf[2] )
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
              cnt++;
              curr++;
            }
            // unlock
            spin_unlock(lock);
            buf[0] = cnt;
            // copy to user
            buf_size = sizeof(unsigned long) + cnt * sizeof(struct one_tcp_ulp_ops);
            if (copy_to_user((void*)ioctl_param, (void*)buf, buf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
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
          unsigned long cnt = 0;
          if ( !ptrbuf[2] )
          {
            // just calc count
            mutex_lock(m);
            list_for_each(p, list)
              cnt++;
	    // unlock
            mutex_unlock(m);
            // copy to user
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            size_t buf_size = sizeof(unsigned long) * (ptrbuf[2] + 1);
            unsigned long *buf = (unsigned long *)kmalloc(buf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            mutex_lock(m);
            list_for_each(p, list)
            {
              struct proto *prot = list_entry(p, struct proto, node);
              if ( cnt >= ptrbuf[2] )
                break;
              buf[cnt+1] = (unsigned long)prot;
              cnt++;
            }
	    // unlock
            mutex_unlock(m);
            buf[0] = cnt;
            // copy to user
            buf_size = sizeof(unsigned long) * (buf[0] + 1);
            if (copy_to_user((void*)ioctl_param, (void*)buf, buf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
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
          unsigned long cnt = 0;
          struct list_head *lh;
          isw_list += ptrbuf[2];
          if ( !ptrbuf[3] )
          {
            // just count size
            spin_lock_bh(lock);
            list_for_each(lh, isw_list)
              cnt++;
            spin_unlock_bh(lock);
            // copy count to user
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            size_t buf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_protosw);
            unsigned long *buf = (unsigned long *)kmalloc(buf_size, GFP_KERNEL);
            struct one_protosw *curr;
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_protosw *)(buf + 1);
            spin_lock_bh(lock);
            list_for_each(lh, isw_list)
            {
              answer = list_entry(lh, struct inet_protosw, list);
              if ( cnt >= ptrbuf[3] )
                break;
              curr->addr = (void *)answer;
              curr->type = answer->type;
              curr->protocol = answer->protocol;
              curr->prot = (void *)answer->prot;
              curr->ops = (void *)answer->ops;
              cnt++;
              curr++;
            }
            spin_unlock_bh(lock);
            buf[0] = cnt;
            // copy to user
            buf_size = sizeof(unsigned long) + buf[0] * sizeof(struct one_protosw);
            if (copy_to_user((void*)ioctl_param, (void*)buf, buf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        }
      break; /* IOCTL_GET_PROTOSW */

     case IOCTL_GET_NET_DEVS:
        // check pre-req
        if ( !s_net || !s_dev_base_lock )
          return -ENOCSI;
        // read count
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
  	if ( !ptrbuf[1] )
  	{
          struct net *net;
          struct net_device *dev;
          int found = 0;
          unsigned long count = 0;
          down_read(s_net);
          for_each_net(net)
          {
            if ( ptrbuf[0] != (unsigned long)net )
              continue;
            found++;
            read_lock(s_dev_base_lock);
            for_each_netdev(net, dev)
              count++;
            read_unlock(s_dev_base_lock);
            break;
          }
          up_read(s_net);
          if ( !found )
            return -ENOENT;
          // copy count to user
          if (copy_to_user((void*)ioctl_param, (void*)&count, sizeof(count)) > 0)
            return -EFAULT;
        } else {
          int xdp;
          struct net *net;
          struct net_device *dev;
          struct one_net_dev *curr;
          int found = 0;
          size_t kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_net_dev);
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !buf )
            return -ENOMEM;
          curr = (struct one_net_dev *)(buf + 1);
          buf[0] = 0;
          down_read(s_net);
          for_each_net(net)
          {
            if ( ptrbuf[0] != (unsigned long)net )
              continue;
            found++;
            read_lock(s_dev_base_lock);
            for_each_netdev(net, dev)
            {
              if ( buf[0] >= ptrbuf[1] )
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
#ifdef CONFIG_NETFILTER_INGRESS
              curr->nf_hooks_ingress = (void *)dev->nf_hooks_ingress;
              if ( dev->nf_hooks_ingress )
                curr->num_hook_entries = dev->nf_hooks_ingress->num_hook_entries;
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
              buf[0]++;
            }
            read_unlock(s_dev_base_lock);
            break;
          }
          up_read(s_net);
          if ( !found )
          {
            kfree(buf);
            return -ENOENT;
          }
          // copy to user
          kbuf_size = sizeof(unsigned long) + buf[0] * sizeof(struct one_net_dev);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);
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
          unsigned long cnt = 0;
          const struct rtnl_link_ops *ops;
          rtnl_lock();
          list_for_each_entry(ops, l, list)
            cnt++;
          rtnl_unlock();
          if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
            return -EFAULT;
        } else {
          struct list_head *l = (struct list_head *)ptrbuf[0];
          const struct rtnl_link_ops *ops;
          unsigned long cnt = 0;
          size_t kbuf_size = sizeof(unsigned long) * (1 + ptrbuf[1]);
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !buf )
            return -ENOMEM;
          rtnl_lock();
          list_for_each_entry(ops, l, list)
          {
            if ( cnt >= ptrbuf[1] )
             break;
            buf[1 + cnt] = (unsigned long)ops;
            cnt++;
          }
          rtnl_unlock();
          buf[0] = cnt;
          // copy to user
          kbuf_size = sizeof(unsigned long) * (cnt + 1);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);          
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
          ptrbuf[0] = 0;
          down_read(lock);
          list_for_each_entry(ops, l, list)
            ptrbuf[0]++;
          up_read(lock);
          if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
            return -EFAULT;
        } else {
          struct list_head *l = (struct list_head *)ptrbuf[0];
          struct rw_semaphore *lock = (struct rw_semaphore *)ptrbuf[1];
          struct one_pernet_ops *curr;
          struct pernet_operations *ops;
          size_t kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_pernet_ops);
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !buf )
            return -ENOMEM;
          curr = (struct one_pernet_ops *)(buf + 1);
          buf[0] = 0;
          down_read(lock);
          list_for_each_entry(ops, l, list)
          {
            if ( buf[0] >= ptrbuf[2] )
              break;
            curr->addr = (void *)ops;
            curr->init = (void *)ops->init;
            curr->exit = (void *)ops->exit;
            curr->exit_batch = (void *)ops->exit_batch;
            curr++;
            buf[0]++;
          }
          up_read(lock);
          // copy to user
          kbuf_size = sizeof(unsigned long) + buf[0] * sizeof(struct one_pernet_ops);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);
        }
      break; /* IOCTL_GET_PERNET_OPS */

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
            ptrbuf[0]++;
          up_read(s_net);
          if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
            return -EFAULT;
  	} else {
          struct net *net;
          struct one_net *curr;
          size_t kbuf_size = sizeof(unsigned long) + ptrbuf[0] * sizeof(struct one_net);
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          if ( !buf )
            return -ENOMEM;
          curr = (struct one_net *)(buf + 1);
          down_read(s_net);
          for_each_net(net)
          {
            if ( buf[0] >= ptrbuf[0] )
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
            buf[0]++;
          }
          up_read(s_net);
          // copy to user
          kbuf_size = sizeof(unsigned long) + buf[0] * sizeof(struct one_net);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);
        }
      break; /* IOCTL_GET_NETS */

    case IOCTL_GET_RTNL_AF_OPS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
  	if ( !ptrbuf[1] )
  	{
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct list_head *lh;
          ptrbuf[0] = 0;
          rtnl_lock();
          list_for_each(lh, head)
            ptrbuf[0]++;
          rtnl_unlock();
          if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
            return -EFAULT;
        } else {
          unsigned long cnt = 0;
          struct rtnl_af_ops *ops;
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct list_head *lh;
          size_t kbuf_size = sizeof(unsigned long) * (ptrbuf[1] + 1);
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !buf )
            return -ENOMEM;
          rtnl_lock();
          list_for_each(lh, head)
          {
            if ( cnt >= ptrbuf[1] )
              break;
            ops = list_entry(lh, struct rtnl_af_ops, list);
            buf[1 + cnt] = (unsigned long)ops;
            cnt++;
          }
          rtnl_unlock();
          buf[0] = cnt;
          kbuf_size = sizeof(unsigned long) * (cnt + 1);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);
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
            unsigned long cnt = 0;
            size_t kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_pmu);
            struct one_pmu *curr;
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_pmu *)(buf + 1);
            // lock
            mutex_lock(m);
            // iterate
            idr_for_each_entry(pmus, pmu, id)
            {
              if ( cnt < ptrbuf[2] )
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
              cnt++;
            }
            // unlock
            mutex_unlock(m);
            // copy to user
            buf[0] = cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
               kfree(buf);
               return -EFAULT;
            }
            kfree(buf);
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
          unsigned long cnt = 0;
          size_t kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_bpf_map);
          struct one_bpf_map *curr;
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
          if ( !buf )
             return -ENOMEM;
          curr = (struct one_bpf_map *)(buf + 1);
          idr_preload(GFP_KERNEL);
          // lock
          spin_lock_bh(lock);
          // iterate
          idr_for_each_entry(bmaps, map, id)
          {
            if ( cnt < ptrbuf[2] )
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
              curr++;
            }
            cnt++;
          }
          // unlock
          spin_unlock_bh(lock);
          idr_preload_end();
          // copy to user
          buf[0] = cnt;
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
             kfree(buf);
             return -EFAULT;
          }
          kfree(buf);
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
          int found = 0;
          size_t kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_bpf_prog);
          struct one_bpf_prog *curr;
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
          if ( !buf )
            return -ENOMEM;
          curr = (struct one_bpf_prog *)(buf + 1);
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
             kfree(buf);
             return -ENOENT;
          }
          // copy to usermode
          buf[0] = cnt;
          kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_bpf_prog);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);          
   	}
      break; /* IOCTL_GET_CGROUP_BPF */

    case IOCTL_GET_CGROUPS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 4) > 0 )
  	  return -EFAULT;
  	else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          void *root = (void *)ptrbuf[2];
          unsigned long cnt = ptrbuf[3];
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          int found = 0;
          size_t kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_cgroup);
          struct one_cgroup *curr;
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
          if ( !buf )
            return -ENOMEM;
          curr = (struct one_cgroup *)(buf + 1);
          cnt = 0;
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
             for (child = css_next_descendant_pre(NULL, &item->cgrp.self); child && cnt < ptrbuf[3]; child = css_next_descendant_pre(child, &item->cgrp.self) )
             {
               if ( child == &item->cgrp.self )
	         continue;
               fill_one_cgroup(curr, child);
               cnt++; curr++;
             }
             rcu_read_unlock();
             break;
          }
          // unlock
          mutex_unlock(m);
          if ( !found )
          {
             kfree(buf);
             return -ENOENT;
          }
          // copy to usermode
          buf[0] = cnt;
          kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_cgroup);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);          
        }
      break; /* IOCTL_GET_CGROUPS */

    case IOCTL_GET_CGRP_ROOTS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned long cnt = 0;
          unsigned int hierarchy_id;
          struct cgroup_root *item;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            idr_for_each_entry(genl, item, hierarchy_id)
              cnt++;
            mutex_unlock(m);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            size_t kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_group_root);
            struct one_group_root *curr;
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL  | __GFP_ZERO);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_group_root *)(buf + 1);
            mutex_lock(m);
            // iterate
            idr_for_each_entry(genl, item, hierarchy_id)
            {
              if ( cnt >= ptrbuf[2] )
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
              cnt++;
              curr++;
            }
            // unlock
            mutex_unlock(m);
            // copy to usermode
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_group_root);
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);          
          }
        }
      break; /* IOCTL_GET_CGRP_ROOTS */

    case IOCTL_GET_GENL_FAMILIES:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
  	  return -EFAULT;
  	else {
          struct idr *genl = (struct idr *)ptrbuf[0];
          unsigned long cnt = 0;
          const struct genl_family *family;
          unsigned int id;
          if ( !ptrbuf[1] )
          {
            genl_lock();
            idr_for_each_entry(genl, family, id)
              cnt++;
            genl_unlock();
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            size_t kbuf_size = sizeof(unsigned long) + ptrbuf[1] * sizeof(struct one_genl_family);
            struct one_genl_family *curr;
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_genl_family *)(buf + 1);
            genl_lock();
            idr_for_each_entry(genl, family, id)
            {
              if ( cnt >= ptrbuf[1] )
                break;
              curr->addr = (void *)family;
              curr->id = family->id;
              curr->pre_doit = (void *)family->pre_doit;
              curr->post_doit = (void *)family->post_doit;
              curr->ops = (void *)family->ops;
              curr->small_ops = (void *)family->small_ops;
              strlcpy(curr->name, family->name, GENL_NAMSIZ);
              // next iteration
              cnt++;
              curr++;
            }
            genl_unlock();
            // copy to usermode
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_genl_family);
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);          
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
          unsigned long cnt = 0;
          size_t kbuf_size = sizeof(unsigned long) + ptrbuf[3] * sizeof(struct one_nl_socket);
          struct rhashtable_iter iter;
          struct one_nl_socket *curr;
          unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
          if ( !buf )
            return -ENOMEM;
          curr = (struct one_nl_socket *)(buf + 1);
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
            if ( cnt >= ptrbuf[3] )
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
            cnt++;
            curr++;
          }
          rhashtable_walk_stop(&iter);
          rhashtable_walk_exit(&iter);
          // unlock
          read_unlock(lock);
          if ( err )
          {
            kfree(buf);
            return err;
          }
          // copy to user
          buf[0] = cnt;
          kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_nl_socket);
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);          
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
         // copy to user
         if (copy_to_user((void*)ioctl_param, (void*)body, ptrbuf[3]) > 0)
           return -EFAULT;
       }
     break; /* IOCTL_GET_BPF_PROG_BODY */

    case IOCTL_GET_BPF_PROGS:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
       else {
         struct idr *links = (struct idr *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         unsigned long cnt = 0;
         struct bpf_prog *prog;
         unsigned int id;
         if ( !ptrbuf[2] )
         {
            spin_lock_bh(lock);
            idr_for_each_entry(links, prog, id)
              cnt++;
            spin_unlock_bh(lock);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
         } else {
            size_t kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_bpf_prog);
            struct one_bpf_prog *curr;
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_bpf_prog *)(buf + 1);
            spin_lock_bh(lock);
            idr_for_each_entry(links, prog, id)
            {
              if ( cnt >= ptrbuf[1] )
                break;
              fill_bpf_prog(curr, prog);
              // next iteration
              cnt++;
              curr++;
            }
            spin_unlock_bh(lock);
            // copy to usermode
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_bpf_prog);
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);          
         }
       }
     break; /* IOCTL_GET_BPF_PROGS */

    case IOCTL_GET_BPF_LINKS:
       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
         return -EFAULT;
       else {
         struct idr *links = (struct idr *)ptrbuf[0];
         spinlock_t *lock = (spinlock_t *)ptrbuf[1];
         unsigned long cnt = 0;
         struct bpf_link *link;
         unsigned int id;
         if ( !ptrbuf[2] )
         {
            spin_lock_bh(lock);
            idr_for_each_entry(links, link, id)
              cnt++;
            spin_unlock_bh(lock);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
         } else {
            size_t kbuf_size = sizeof(unsigned long) + ptrbuf[2] * sizeof(struct one_bpf_links);
            struct one_bpf_links *curr;
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_bpf_links *)(buf + 1);
            spin_lock_bh(lock);
            idr_for_each_entry(links, link, id)
            {
              if ( cnt >= ptrbuf[1] )
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
              cnt++;
              curr++;
            }
            spin_unlock_bh(lock);
            // copy to usermode
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + cnt * sizeof(struct one_bpf_links);
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);          
         }
       }
     break; /* IOCTL_GET_BPF_LINKS */

    case IOCTL_GET_TRACE_EXPORTS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct trace_export *te = *(struct trace_export **)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned long cnt = 0;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            while( te )
            {
              cnt++;
              te = te->next;
            }
            mutex_unlock(m);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_trace_export *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_export) * ptrbuf[2];
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_trace_export *)(buf + 1);
            mutex_lock(m);
            while( te )
            {
              if ( cnt >= ptrbuf[2] )
                break;
              curr->addr  = (void *)te;
              curr->write = (void *)te->write;
              curr->flags = te->flags;
              // next iteration
              te = te->next;
              curr++;
              cnt++;
            }
            mutex_unlock(m);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_export) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        }
     break; /* IOCTL_GET_TRACE_EXPORTS */

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
          unsigned long cnt = 0;
          if ( !ptrbuf[2] )
          {
            // lock
            mutex_lock(m);
            for ( p = *head; p != s_ftrace_end; p = p->next )
              cnt++;
            // unlock
            mutex_unlock(m);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_ftrace_ops *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_ftrace_ops) * ptrbuf[2];
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_ftrace_ops *)(buf + 1);
            // lock
            mutex_lock(m);
            // iterate
            for ( p = *head; p != s_ftrace_end; p = p->next )
            {
              if ( cnt >= ptrbuf[2] )
                break;
              curr->addr = (void *)p;
              curr->func = (void *)p->func;
              curr->saved_func = (void *)p->saved_func;
              curr->flags = p->flags;
              curr++;
              cnt++;
            }
            // unlock
            mutex_unlock(m);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_ftrace_ops) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        }
     break; /* IOCTL_GET_FTRACE_OPS */

    case IOCTL_GET_FTRACE_CMDS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned long cnt = 0;
          struct ftrace_func_command *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              cnt++;
            mutex_unlock(m);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_tracefunc_cmd *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_tracefunc_cmd) * ptrbuf[2];
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_tracefunc_cmd *)(buf + 1);
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( cnt >= ptrbuf[2] )
                break;
              curr->addr = (void *)ti;
              curr->func = ti->func;
              strlcpy(curr->name, ti->name, sizeof(curr->name));
              curr++;
              cnt++;
            }
            mutex_unlock(m);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_tracefunc_cmd) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        }
     break; /* IOCTL_GET_FTRACE_CMDS */

    case IOCTL_GET_DYN_EVT_OPS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned long cnt = 0;
          struct dyn_event_operations *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              cnt++;
            mutex_unlock(m);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_dyn_event_op *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_dyn_event_op) * ptrbuf[2];
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_dyn_event_op *)(buf + 1);
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( cnt >= ptrbuf[2] )
                break;
              curr->addr = (void *)ti;
              curr->create     = ti->create;
              curr->show       = ti->show;
              curr->is_busy    = ti->is_busy;
              curr->free       = ti->free;
              curr->match      = ti->match;
              curr++;
              cnt++;
            }
            mutex_unlock(m);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_dyn_event_op) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
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
          unsigned long cnt = 0;
          struct trace_event_call *call, *p;
          if ( !ptrbuf[1] )
          {
            // just count of registered events
            down_read(s_trace_event_sem);
            list_for_each_entry_safe(call, p, s_ftrace_events, list)
              cnt++;
            up_read(s_trace_event_sem);
            // copy to usermode
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_trace_event_call *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_event_call) * ptrbuf[1];
            unsigned long *buf = (unsigned long *)kzalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_trace_event_call *)(buf + 1);
            down_read(s_trace_event_sem);
            list_for_each_entry_safe(call, p, s_ftrace_events, list)
            {
              if ( cnt >= ptrbuf[1] )
                break;
              copy_trace_event_call(call, curr);
              // for next iteration
              cnt++;
              curr++;
            }
            up_read(s_trace_event_sem);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_trace_event_call) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        } else {
          // copy bpf_progs for some event
          unsigned long cnt;
          struct one_bpf_prog *curr;
          int found = 0;
          size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_prog) * ptrbuf[1];
          unsigned long *buf = (unsigned long *)kzalloc(kbuf_size, GFP_KERNEL | __GFP_ZERO);
          struct trace_event_call *call, *p;
          if ( !buf )
            return -ENOMEM;
          curr = (struct one_bpf_prog *)(buf + 1);
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
             for ( cnt = 0; cnt < total && cnt < ptrbuf[1]; cnt++, curr++ )
             {
               curr->prog = call->prog_array->items[cnt].prog;
               if ( !curr->prog )
                 break;
               fill_bpf_prog(curr, call->prog_array->items[cnt].prog);
             }
             mutex_unlock(s_bpf_event_mutex);
             found++;
             break;
          }
          up_read(s_trace_event_sem);
          if ( !found )
          {
             kfree(buf);
             return -ENOENT;
          }
          buf[0] = cnt;
          kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_prog) * cnt;
          if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
          {
            kfree(buf);
            return -EFAULT;
          }
          kfree(buf);
        }
     break; /* IOCTL_GET_EVT_CALLS */

    case IOCTL_GET_EVENT_CMDS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned long cnt = 0;
          struct event_command *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              cnt++;
            mutex_unlock(m);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_event_command *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_event_command) * ptrbuf[2];
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_event_command *)(buf + 1);
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( cnt >= ptrbuf[2] )
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
              cnt++;
            }
            mutex_unlock(m);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_event_command) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        }
     break; /* IOCTL_GET_EVENT_CMDS */

    case IOCTL_GET_BPF_REGS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          struct mutex *m = (struct mutex *)ptrbuf[1];
          unsigned long cnt = 0;
          struct bpf_iter_target_info *ti;
          if ( !ptrbuf[2] )
          {
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
              cnt++;
            mutex_unlock(m);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_bpf_reg *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_reg) * ptrbuf[2];
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_bpf_reg *)(buf + 1);
            mutex_lock(m);
            list_for_each_entry(ti, head, list)
            {
              if ( cnt >= ptrbuf[2] )
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
              cnt++;
            }
            mutex_unlock(m);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_reg) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        }
     break; /* IOCTL_GET_BPF_REGS */

    case IOCTL_GET_BPF_KSYMS:
        if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 3) > 0 )
  	  return -EFAULT;
  	else {
          struct list_head *head = (struct list_head *)ptrbuf[0];
          spinlock_t *lock = (spinlock_t *)ptrbuf[1];
          unsigned long cnt = 0;
          struct bpf_ksym *ti;
          if ( !ptrbuf[2] )
          {
            spin_lock_bh(lock);
            list_for_each_entry(ti, head, lnode)
              cnt++;
            spin_unlock_bh(lock);
            if (copy_to_user((void*)ioctl_param, (void*)&cnt, sizeof(cnt)) > 0)
              return -EFAULT;
          } else {
            struct one_bpf_ksym *curr;
            size_t kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_ksym) * ptrbuf[2];
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            curr = (struct one_bpf_ksym *)(buf + 1);
            spin_lock_bh(lock);
            list_for_each_entry(ti, head, lnode)
            {
              if ( cnt >= ptrbuf[2] )
                break;
              curr->addr = ti;
              curr->start = ti->start;
              curr->end = ti->end;
              curr->prog = ti->prog;
              strlcpy(curr->name, ti->name, sizeof(curr->name));
              curr++;
              cnt++;
            }
            spin_unlock_bh(lock);
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) + sizeof(struct one_bpf_ksym) * cnt;
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
       }
     break; /* IOCTL_GET_BPF_KSYMS */

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
              ptrbuf[0]++;
            if (copy_to_user((void*)ioctl_param, (void*)ptrbuf, sizeof(ptrbuf[0])) > 0)
              return -EFAULT;
          } else {
            unsigned long cnt = 0;
            size_t kbuf_size = sizeof(unsigned long) * (ptrbuf[1] + 1);
            unsigned long *buf = (unsigned long *)kmalloc(kbuf_size, GFP_KERNEL);
            if ( !buf )
              return -ENOMEM;
            hlist_for_each_entry(shl, head, list)
            {
              if ( cnt >= ptrbuf[1] )
                break;
              buf[1 + cnt] = *(unsigned long *)(&shl->hook);
              cnt++;
            }
            buf[0] = cnt;
            kbuf_size = sizeof(unsigned long) * (cnt + 1);
            if (copy_to_user((void*)ioctl_param, (void*)buf, kbuf_size) > 0)
            {
              kfree(buf);
              return -EFAULT;
            }
            kfree(buf);
          }
        }
      break; /* IOCTL_GET_LSM_HOOKS */

    default:
     return -EBADRQC;
  }
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

int __init
init_module (void)
{
  int ret = misc_register(&lkcd_dev);
  if (ret)
  {
    printk("Unable to register the lkcd device\n");
    return ret;
  }
  s_dbg_open = (const struct file_operations *)lkcd_lookup_name("debugfs_open_proxy_file_operations");
  if ( !s_dbg_open )
    printk("cannot find debugfs_open_proxy_file_operations\n");
  s_dbg_full = (const struct file_operations *)lkcd_lookup_name("debugfs_full_proxy_file_operations");
  if ( !s_dbg_full )
    printk("cannot find debugfs_full_proxy_file_operations\n");
  krnf_node_ptr = (krnf_node_type)lkcd_lookup_name("kernfs_node_from_dentry");
  iterate_supers_ptr = (und_iterate_supers)lkcd_lookup_name("iterate_supers");
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
  bpf_prog_array_length_ptr = (und_bpf_prog_array_length)lkcd_lookup_name("bpf_prog_array_length");
  if ( !bpf_prog_array_length_ptr )
    printk("cannot find bpf_prog_array_length\n");
  css_next_child_ptr = (kcss_next_child)lkcd_lookup_name("css_next_child");
  if ( !css_next_child_ptr )
    printk("cannot find css_next_child\n");
  cgroup_bpf_detach_ptr = (kcgroup_bpf_detach)lkcd_lookup_name("cgroup_bpf_detach");
  if ( !cgroup_bpf_detach_ptr )
    printk("cannot find cgroup_bpf_detach\n");
#ifdef CONFIG_FSNOTIFY
  fsnotify_mark_srcu_ptr = (struct srcu_struct *)lkcd_lookup_name("fsnotify_mark_srcu");
  fsnotify_first_mark_ptr = (und_fsnotify_first_mark)lkcd_lookup_name("fsnotify_first_mark");
  if ( !fsnotify_first_mark_ptr )
  {
    printk("cannot find fsnotify_first_mark\n");
    if ( fsnotify_mark_srcu_ptr )
      fsnotify_first_mark_ptr = my_fsnotify_first_mark;
  }
  fsnotify_next_mark_ptr = (und_fsnotify_next_mark)lkcd_lookup_name("fsnotify_next_mark");
  if ( !fsnotify_next_mark_ptr )
  {
    printk("cannot find fsnotify_next_mark\n");
    if ( fsnotify_mark_srcu_ptr )
      fsnotify_next_mark_ptr = my_fsnotify_next_mark;
  }
#endif /* CONFIG_FSNOTIFY */
#ifdef __x86_64__
  kprobe_aggr = (unsigned long)lkcd_lookup_name("aggr_pre_handler");
  find_uprobe_ptr = (find_uprobe)lkcd_lookup_name("find_uprobe");
  get_uprobe_ptr = (get_uprobe)lkcd_lookup_name("get_uprobe");
  if ( !get_uprobe_ptr )
    get_uprobe_ptr = my_get_uprobe;
  put_uprobe_ptr = (put_uprobe)lkcd_lookup_name("put_uprobe");
#endif /* __x86_64__ */
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
  if ( test_kprobe_installed )
  {
     unregister_kprobe(&test_kp);
     test_kprobe_installed = 0;
  }
  if ( debuggee_inode )
  {
     uprobe_unregister(debuggee_inode, DEBUGGEE_FILE_OFFSET, &s_uc);
     debuggee_inode = 0;
  }
#endif /* __x86_64__ */
  misc_deregister(&lkcd_dev);
}
