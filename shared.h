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

#endif /* LKCD_SHARED_H */
