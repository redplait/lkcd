#ifndef LKCD_SHARED_H
# define LKCD_SHARED_H

#define IOCTL_NUM 'L'

#define IOCTL_BASE                     _IO(IOCTL_NUM, 0)
#define IOCTL_RKSYM                    _IOR(IOCTL_NUM, 0x1, int*)
// for blocking_notifier_chain_register
#define IOCTL_CNTNTFYCHAIN             _IOR(IOCTL_NUM, 0x2, int*)
#define IOCTL_ENUMNTFYCHAIN            _IOR(IOCTL_NUM, 0x3, int*)
// for atomic_notifier_chain_register
#define IOCTL_CNTANTFYCHAIN            _IOR(IOCTL_NUM, 0x4, int*)
#define IOCTL_ENUMANTFYCHAIN           _IOR(IOCTL_NUM, 0x5, int*)
// for srcu_notifier_chain_register
#define IOCTL_CNTSNTFYCHAIN            _IOR(IOCTL_NUM, 0x6, int*)
#define IOCTL_ENUMSNTFYCHAIN           _IOR(IOCTL_NUM, 0x7, int*)

// get registered trace_event count
// in params:
//  0 - rw_semaphore * (trace_event_sem)
//  1 - event_hash address
//  2 - index in event_hash
#define IOCTL_TRACEV_CNT               _IOR(IOCTL_NUM, 0x8, int*)

// output struct
struct one_trace_event
{
  void *addr;
  int type;
  // callbacks from struct trace_event_functions *funcs;
  void *trace;
  void *raw;
  void *hex;
  void *binary;
};
// get registered trace_events
// in params - the same as for IOCTL_TRACEV_CNT +
//  3 - cnt
// out params - long size + N * one_trace_event
#define IOCTL_TRACEVENTS               _IOR(IOCTL_NUM, 0x9, int*)

// read one ptr at kernel addr
#define IOCTL_READ_PTR                 _IOR(IOCTL_NUM, 0xa, int*)

// read tracepoint info
// in params:
//  0 - address of tracepoint
// out params
//  0 - key.enabled
//  1 - regfunc
//  2 - unregfunc
//  3 - funcs count
#define IOCTL_TRACEPOINT_INFO          _IOR(IOCTL_NUM, 0xb, int*)

// read tracepoint funcs
// in params:
//  0 - address of tracepoint
//  1 - size
#define IOCTL_TRACEPOINT_FUNCS         _IOR(IOCTL_NUM, 0xc, int*)

// get kernfs_node for some file in /sys
// out params
// 0 - kernfs_node
// 1 - kobject (kernfs_node->priv)
// 2 - ktype
// 3 - ktype->sysfs_ops
// 4 - ktype->sysfs_ops->show
// 5 - ktype->sysfs_ops->store
// 6 - dentry->d_sb->s_op    if kernfs_node is null
// 7 - kernfs_node->flags    dentry->inode if kernfs_node is null
// 8 - kernfs_node->priv     dentry->inode->i_fop if kernfs_node is null
#define IOCTL_KERNFS_NODE              _IOR(IOCTL_NUM, 0xd, int*)

// get per-cpu return_notifier_list count for some cpu
// in params:
//  0 - cpu index
//  1 - this_cpu_off
//  2 - offset
// out params:
//  0 - address of list head
//  1 - count
#define IOCTL_CNT_RNL_PER_CPU          _IOR(IOCTL_NUM, 0xe, int*)

// install/remove test user_return_notifier
// in param 0 - 1 to install, 0 to remove
#define IOCTL_TEST_URN                 _IOR(IOCTL_NUM, 0xf, int*)

// get per-cpu return_notifier_list for some cpu
// in params:
//  0 - cpu index
//  1 - this_cpu_off
//  2 - offset
//  3 - count (gathered with IOCTL_CNT_RNL_PER_CPU)
// out params - long size + N * pvoid
#define IOCTL_RNL_PER_CPU              _IOR(IOCTL_NUM, 0x10, int*)

// install/remove test kprobe
// in param 0 - 1 to install, 0 to remove
#define IOCTL_TEST_KPROBE              _IOR(IOCTL_NUM, 0x11, int*)

// get cnt of kprobes for kprobe_table[index]
// in params:
//  0 - kprobe_table address
//  1 - kprobe_mutex address
//  2 - index (must be between 0 and nonincluded KPROBE_TABLE_SIZE)
// out params:
//  0 - cnt
#define IOCTL_CNT_KPROBE_BUCKET        _IOR(IOCTL_NUM, 0x12, int*)

struct one_kprobe
{
  void *kaddr; // address of this kprobe
  void *addr;  // kprobe.addr
  void *pre_handler;
  void *post_handler;
  unsigned int flags;
};

// get kprobes for kprobe_table[index]
// in params:
//  0 - kprobe_table address
//  1 - kprobe_mutex address
//  2 - index (must be between 0 and nonincluded KPROBE_TABLE_SIZE)
//  3 - cnt (gathered with IOCTL_CNT_KPROBE_BUCKET)
// out params - long size + N * one_kprobe
#define IOCTL_GET_KPROBE_BUCKET        _IOR(IOCTL_NUM, 0x13, int*)

// install/remove test uprobe for /usr/bin/ls
// in param 0 - 1 to install, 0 to remove
#define IOCTL_TEST_UPROBE              _IOR(IOCTL_NUM, 0x14, int*)

// get cnt of uprobes (from uprobes_tree)
// in params:
//  0 - uprobes_tree address
//  1 - uprobes_treelock address
// out params:
//  0 - cnt
#define IOCTL_CNT_UPROBES              _IOR(IOCTL_NUM, 0x15, int*)

struct one_uprobe
{
  void *addr; // address of this uprobe - can be used to get consumers
  void *inode;
  unsigned long cons_cnt;
  unsigned long i_no; // from inode
  unsigned long offset;
  unsigned long flags;
  char name[256];
};

// get uprobes (from uprobes_tree)
// in params:
//  0 - uprobes_tree address
//  1 - uprobes_treelock address
//  2 - cnt (gathered with IOCTL_CNT_UPROBES)
// out params - long size + N * one_uprobe
#define IOCTL_UPROBES                  _IOR(IOCTL_NUM, 0x16, int*)

struct one_uprobe_consumer
{
  void *addr;
  void *handler;
  void *ret_handler;
  void *filter;
};

// get consumers of some uprobe
// in params:
//  0 - uprobes_tree address
//  1 - uprobes_treelock address
//  2 - address of uprobe. it can be removed so return error EBADF
//  3 - cnt (gathered with IOCTL_CNT_UPROBES)
// out params - long size + N * one_uprobe_consumer
#define IOCTL_UPROBES_CONS             _IOR(IOCTL_NUM, 0x17, int*)

struct one_super_block
{
  void *addr;
  unsigned long dev;
  void *s_type;
  void *s_op;
  void *dq_op;
  void *s_qcop;
  void *s_export_op;
  void *s_d_op;
  void *s_user_ns;
  unsigned long s_flags;
  unsigned long s_iflags;
  unsigned long inodes_cnt;
  unsigned long s_fsnotify_mask;
  void *s_fsnotify_marks;
  char s_id[32];
};

// get super-blocks
// in params:
//   0 - count of super-blocks (if zero - return count)
// out params:
//   if 0 param is zero - count of super-blocks
//   else long size + N * one_super_block
#define IOCTL_GET_SUPERBLOCKS          _IOR(IOCTL_NUM, 0x18, int*)

struct one_inode
{
  void *addr;
  unsigned long i_mode;
  unsigned long i_ino;
  unsigned int i_flags;
  unsigned long mark_count;
  unsigned long i_fsnotify_mask;
  void *i_fsnotify_marks;
};

// get inodes for some superblock
// in params:
//  0 - superblock address
//  1 - count
// out params - long size + N * one_inode
#define IOCTL_GET_SUPERBLOCK_INODES    _IOR(IOCTL_NUM, 0x19, int*)

struct one_fsnotify
{
  void *mark_addr;    // address of fsnotify_mark
  unsigned int mask;  // fsnotify_mark.mask
  unsigned int ignored_mask; // fsnotify_mark.ignored_mask
  unsigned int flags; // fsnotify_mark.flags
  void *group;        // address of fsnotify_group
  void *ops;          // fsnotify_group->fsnotify_ops
};

// get fsnotify_mark/fsnotify_group/fsnotify_ops for some inode
// in params:
//  0 - superblock address
//  1 - inode address
//  2 - count
// out params - long size + N * one_fsnotify
#define IOCTL_GET_INODE_MARKS          _IOR(IOCTL_NUM, 0x1a, int*)

#endif /* LKCD_SHARED_H */
