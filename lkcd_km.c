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
#include <linux/trace_events.h>
#include <linux/tracepoint-defs.h>
#include "shared.h"

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "lkcd";

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

static long lkcd_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
//  int numargs = 0;
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
       rcu_read_lock();
       func = tp->funcs;
       if ( func )
        do {
          ptrbuf[3]++;
        } while((++func)->func);
       // unlock
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

       if ( copy_from_user( (void*)ptrbuf, (void*)ioctl_param, sizeof(long) * 2) > 0 )
 	 return -EFAULT;
       tp = (struct tracepoint *)ptrbuf[0];
       cnt = ptrbuf[1];
       if ( !tp || !cnt )
         return -EINVAL;

       kbuf = (unsigned long *)kmalloc_array(cnt, sizeof(unsigned long), GFP_KERNEL);
       if ( !kbuf )
         return -ENOMEM;

       // lock
       rcu_read_lock();
       func = tp->funcs;
       if ( func )
        do {
          kbuf[res++] = (unsigned long)func->func;
          if ( res >= cnt )
            break;
        } while((++func)->func);
       // unlock
       rcu_read_unlock();

       // copy to usermode
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
         return -EFAULT;
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

     case IOCTL_GET_SUPERBLOCK_INODES:
       if ( !iterate_supers_ptr )
         return -EFAULT;
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
         return -EFAULT;
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
         return -EFAULT;
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
           return -EBADF;
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
			kbuf = xlate_dev_kmem_ptr((void *)p);
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
