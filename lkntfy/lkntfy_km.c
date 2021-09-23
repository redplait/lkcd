#include <linux/module.h>
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
	.key_len = sizeof_field(struct tracked_inode, node),
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
      fsnotify_destroy_mark(fsn_mark, lkntfy_group);
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
  res = rhashtable_lookup(tracked_ht, node, tracked_hash_params);
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
  res = rhashtable_lookup(tracked_ht, node, tracked_hash_params);
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
              fsn_mark->mask = mask;
              err = fsnotify_add_mark(fsn_mark, &file->f_path.dentry->d_inode->i_fsnotify_marks, FSNOTIFY_OBJ_TYPE_INODE, 0, NULL);
              if ( !err )
                err = add_tracked(file->f_path.dentry->d_inode);
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
       if ( in_tracked(file->f_path.dentry->d_inode) )
          del_tracked(file->f_path.dentry->d_inode);
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
    printk("lkntfy PID %d mask %X %s\n", task_pid_nr(current), mask, name->name);
  else
    printk("lkntfy PID %d mask %X inode %ld\n", task_pid_nr(current), mask, inode->i_ino);
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

// init
int __init
init_module (void)
{
  int ret = misc_register(&lkntfy_dev);
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
    fsnotify_put_group(lkntfy_group);
  misc_deregister(&lkntfy_dev);
}