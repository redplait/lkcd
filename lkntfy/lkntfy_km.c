#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fsnotify_backend.h>
#include <linux/miscdevice.h>
#include "shared.h"

MODULE_LICENSE("GPL");
// Char we show before each debug print
const char program_name[] = "lkntfy";

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

struct tracked_inode
{
  struct rhash_head head;
  struct inode *node;
};

#define NR_CPUS_HINT 192

static const struct rhashtable_params tracked_hash_params = {
	.nelem_hint = NR_CPUS_HINT,
	.head_offset = offsetof(struct tracked_inode, head),
	.key_offset = offsetof(struct tracked_inode, node),
	.key_len = sizeof(struct inode *),
	.max_size = NR_CPUS,
	.min_size = 2,
	.automatic_shrinking = true,
};

static rwlock_t hlock;
static struct rhashtable *tracked_ht = 0;
static struct fsnotify_group *lkntfy_group = 0;

static void free_tracked_nodes(void *ptr, void *arg)
{
  struct tracked_inode *tn = (struct tracked_inode *)ptr;
  if ( tn->node )
  {
    struct fsnotify_mark *fsn_mark = fsnotify_find_mark(&tn->node->i_fsnotify_marks, lkntfy_group);
    if ( fsn_mark )
    {
      printk("free_tracked_nodes mark %p ref %X\n", fsn_mark, atomic_read(&fsn_mark->refcnt.refs));
      fsnotify_destroy_mark(fsn_mark, lkntfy_group);
      fsnotify_put_mark(fsn_mark);
    }
    iput(tn->node);
  }
  kfree(tn);
}

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

// driver machinery
static int open_lkntfy(struct inode *inode, struct file *file)
{
  try_module_get(THIS_MODULE);
  return 0;
}

static int close_lkntfy(struct inode *inode, struct file *file) 
{ 
  module_put(THIS_MODULE);  
  return 0;
} 

// check if this node already in tracked_ht
static int in_tracked(struct inode *node)
{
  struct tracked_inode *res = 0;
  do_raw_read_trylock(&hlock);
  res = rhashtable_lookup(tracked_ht, &node, tracked_hash_params);
  do_raw_read_unlock(&hlock);
  return (res != 0);
}

// add node to tracked_ht
static int add_tracked(struct inode *node)
{
  int ret;
  struct tracked_inode *res = (struct tracked_inode *)kzalloc(sizeof(struct tracked_inode), GFP_KERNEL);
  if ( !res )
    return -ENOMEM;
  do_raw_write_trylock(&hlock);
  res->node = node;
  // __iget(node);
  atomic_inc(&node->i_count);
  ret = rhashtable_insert_fast(tracked_ht, &res->head, tracked_hash_params);
  do_raw_write_unlock(&hlock);
  if ( ret )
  {
    iput(res->node);
    kfree(res);
  }
  return ret;
}

// delete node from tracked_ht
static int del_tracked(struct inode *node)
{
  struct tracked_inode *res = 0;
  do_raw_write_trylock(&hlock);
  res = rhashtable_lookup(tracked_ht, &node, tracked_hash_params);
  if ( res )
    rhashtable_remove_fast(tracked_ht, &res->head, tracked_hash_params);
  do_raw_write_unlock(&hlock);
  if ( res )
    free_tracked_nodes(res, NULL);
  return (res != 0);
}

#define BUFF_SIZE 256

static long lkntfy_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
  unsigned int mask;
  int err = 0;
  switch(ioctl_num)
  {
    case IOCTL_ADDFILE:
      if ( copy_from_user( (void*)&mask, (void*)ioctl_param, sizeof(unsigned int)) > 0 )
	 return -EFAULT;
      if ( !mask )
         return -EFAULT;
      else {
        struct file *file;
        char name[BUFF_SIZE];
        int i;
        char ch;
        char *temp = (char *)(ioctl_param + sizeof(unsigned int));
        // copy file name
        get_user(ch, temp++);
        name[0] = ch;
        for (i = 1; ch && i < BUFF_SIZE - 1; i++, temp++) 
        {
          get_user(ch, temp);
          name[i] = ch;
        }
        file = file_open(name, 0, 0, &err);
        if ( !file )
          return -err;
        if ( !S_ISREG(file->f_path.dentry->d_inode->i_mode) )
        {
          file_close(file);
          return -EBADF;
        }
        printk("IOCTL_ADDFILE: inode %p ino %ld\n", file->f_path.dentry->d_inode, file->f_path.dentry->d_inode->i_ino);
        // lookup
        if ( !in_tracked(file->f_path.dentry->d_inode) )
        {
          struct fsnotify_mark *fsn_mark = fsnotify_find_mark(&file->f_path.dentry->d_inode->i_fsnotify_marks, lkntfy_group);
          if ( !fsn_mark )
          {
            // alloc new mark
            fsn_mark = (struct fsnotify_mark *)kzalloc(sizeof(*fsn_mark), GFP_KERNEL);
            if ( !fsn_mark )
              err = -ENOMEM;
            else {
              fsnotify_init_mark(fsn_mark, lkntfy_group);
              printk("fsn_mark %p ref %X\n", fsn_mark, atomic_read(&fsn_mark->refcnt.refs));
              fsn_mark->mask = mask;
              err = fsnotify_add_mark(fsn_mark, &file->f_path.dentry->d_inode->i_fsnotify_marks, FSNOTIFY_OBJ_TYPE_INODE, 0, NULL);
              if ( !err )
              {
                printk("added fsn_mark %p ref %X node %ld\n", fsn_mark, atomic_read(&fsn_mark->refcnt.refs), file->f_path.dentry->d_inode->i_ino);
                err = add_tracked(file->f_path.dentry->d_inode);
              } else
                fsnotify_put_mark(fsn_mark);
            }
          }
        }
        file_close(file);
      }
      return err;
     break; /* IOCTL_ADDFILE */

    case IOCTL_DELFILE:
     {
       int err = 0;
       struct file *file;
       char name[BUFF_SIZE];
       int i;
       char ch;
       char *temp = (char *)ioctl_param;
       // copy file name
       get_user(ch, temp++);
       name[0] = ch;
       for (i = 1; ch && i < BUFF_SIZE - 1; i++, temp++) 
       {
         get_user(ch, temp);
         name[i] = ch;
       }
       file = file_open(name, 0, 0, &err);
       if ( !file )
         return -err;
       printk("IOCTL_DELFILE: inode %p ino %ld\n", file->f_path.dentry->d_inode, file->f_path.dentry->d_inode->i_ino);
       if ( in_tracked(file->f_path.dentry->d_inode) )
       {
          printk("IOCTL_DELFILE: found node %ld\n", file->f_path.dentry->d_inode->i_ino);
          del_tracked(file->f_path.dentry->d_inode);
       }
       file_close(file);
     }
     break; /* IOCTL_DELFILE */

    default:
     return -EINVAL;     
  }
  return 0;
}

static void lkntfy_file_fsnotify_free_mark(struct fsnotify_mark *mark, struct fsnotify_group *group)
{
  printk("lkntfy_file_fsnotify_free_mark: %p\n", mark);
  kfree(mark);
}

static int
lkntfy_file_fsnotify_handle_event(struct fsnotify_mark *mark, u32 mask,
				struct inode *inode, struct inode *dir,
				const struct qstr *name, u32 cookie)
{
  if ( name && name->name )
    printk("lkntfy PID %d mask %X %s mark %p ref %X\n", task_pid_nr(current), mask, name->name, mark, atomic_read(&mark->refcnt.refs));
  else
    printk("lkntfy PID %d mask %X inode %ld mark %p ref %X\n", task_pid_nr(current), mask, inode->i_ino, mark, atomic_read(&mark->refcnt.refs));
  return 0;
}

const struct fsnotify_ops lkntfy_ntfy_ops = {
  .handle_inode_event = lkntfy_file_fsnotify_handle_event,
  .freeing_mark = lkntfy_file_fsnotify_free_mark
};

static const struct file_operations lkntfy_fops = {
	.open		= open_lkntfy,
	.release        = close_lkntfy,
	.unlocked_ioctl	= lkntfy_ioctl,
};

static struct miscdevice lkntfy_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "lkntfy",
    .fops = &lkntfy_fops
};

typedef void (*und_fsnotify_destroy_group)(struct fsnotify_group *group);
und_fsnotify_destroy_group fsnotify_destroy_group_ptr = 0;

// init
int __init
init_module (void)
{
  int ret;
  fsnotify_destroy_group_ptr = (und_fsnotify_destroy_group)lkcd_lookup_name("fsnotify_destroy_group");
  if ( !fsnotify_destroy_group_ptr )
  {
    printk("Unable to find fsnotify_destroy_group\n");
  }
  ret = misc_register(&lkntfy_dev);
  if (ret)
  {
    printk("Unable to register the lkntfy device\n");
    return ret;
  }
  rwlock_init(&hlock);
  tracked_ht = kzalloc(sizeof(*tracked_ht), GFP_KERNEL);
  if ( !tracked_ht )
  {
    ret = -ENOMEM;
    goto fail;
  }
  ret = rhashtable_init(tracked_ht, &tracked_hash_params);
  if (ret < 0) {
	goto fail;
  }
  // alloc fsnotify_group
  lkntfy_group = fsnotify_alloc_group(&lkntfy_ntfy_ops);
  if ( !lkntfy_group )
  {
    ret = -ENOMEM;
    goto fail;
  }
  return 0;
fail:
  if ( tracked_ht )
  {
    kfree(tracked_ht);
    tracked_ht = NULL;
  }
  if ( lkntfy_group )
  {
    fsnotify_put_group(lkntfy_group);
    lkntfy_group = 0;
  }
  misc_deregister(&lkntfy_dev);
  return ret;
}

void cleanup_module(void)
{
  if ( tracked_ht )
  {
    do_raw_write_trylock(&hlock);
    rhashtable_free_and_destroy(tracked_ht, free_tracked_nodes, NULL);
    kfree(tracked_ht);
    tracked_ht = NULL;
    do_raw_write_unlock(&hlock);
  }
  if ( lkntfy_group )
  {
    if ( fsnotify_destroy_group_ptr )
      fsnotify_destroy_group_ptr(lkntfy_group);
    else {
      spin_lock(&lkntfy_group->notification_lock);
      lkntfy_group->shutdown = true;
      spin_unlock(&lkntfy_group->notification_lock);    
      fsnotify_wait_marks_destroyed();
    }
    fsnotify_put_group(lkntfy_group);
  }
  misc_deregister(&lkntfy_dev);
}