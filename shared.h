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

/*
 *  kprobes & uprobes
 */

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
  int is_aggr;
};

// get kprobes for kprobe_table[index]
// in params:
//  0 - kprobe_table address
//  1 - kprobe_mutex address
//  2 - index (must be between 0 and nonincluded KPROBE_TABLE_SIZE)
//  3 - cnt (gathered with IOCTL_CNT_KPROBE_BUCKET)
// out params - long size + N * one_kprobe
#define IOCTL_GET_KPROBE_BUCKET        _IOR(IOCTL_NUM, 0x13, int*)

// get aggrageted kprobes
// in params:
//  0 - kprobe_table address
//  1 - kprobe_mutex address
//  2 - index (must be between 0 and nonincluded KPROBE_TABLE_SIZE)
//  3 - kprobe address
//  4 - cnt
// out params:
//  if ( !cnt ) - long - count of aggreagted kprobes
//  else long size + N * one_kprobe
#define IOCTL_GET_AGGR_KPROBE          _IOR(IOCTL_NUM, 0x14, int*)

// install/remove test uprobe for /usr/bin/ls
// in param 0 - 1 to install, 0 to remove
#define IOCTL_TEST_UPROBE              _IOR(IOCTL_NUM, 0x15, int*)

// get cnt of uprobes (from uprobes_tree)
// in params:
//  0 - uprobes_tree address
//  1 - uprobes_treelock address
// out params:
//  0 - cnt
#define IOCTL_CNT_UPROBES              _IOR(IOCTL_NUM, 0x16, int*)

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
#define IOCTL_UPROBES                  _IOR(IOCTL_NUM, 0x17, int*)

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
#define IOCTL_UPROBES_CONS             _IOR(IOCTL_NUM, 0x18, int*)

/*
 *  marks on inodes/mounts/syperblocks
 */

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
  void *s_root;
  char root[256];
  unsigned long mount_count;
};

// get super-blocks
// in params:
//   0 - count of super-blocks (if zero - return count)
// out params:
//   if count is zero - count of super-blocks
//   else long size + N * one_super_block
#define IOCTL_GET_SUPERBLOCKS          _IOR(IOCTL_NUM, 0x19, int*)

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

struct one_fsnotify
{
  void *mark_addr;    // address of fsnotify_mark
  unsigned int mask;  // fsnotify_mark.mask
  unsigned int ignored_mask; // fsnotify_mark.ignored_mask
  unsigned int flags; // fsnotify_mark.flags
  void *group;        // address of fsnotify_group
  void *ops;          // fsnotify_group->fsnotify_ops
};

// get fsnotify_mark/fsnotify_group/fsnotify_ops for super-blocks 
// in params:
//  0 - superblock address
//  1 - count
// out params - long size + N * one_fsnotify
#define IOCTL_GET_SUPERBLOCK_MARKS     _IOR(IOCTL_NUM, 0x1b, int*)

// get inodes for some superblock
// in params:
//  0 - superblock address
//  1 - count
// out params - long size + N * one_inode
#define IOCTL_GET_SUPERBLOCK_INODES    _IOR(IOCTL_NUM, 0x1c, int*)

// get fsnotify_mark/fsnotify_group/fsnotify_ops for some inode
// in params:
//  0 - superblock address
//  1 - inode address
//  2 - count
// out params - long size + N * one_fsnotify
#define IOCTL_GET_INODE_MARKS          _IOR(IOCTL_NUM, 0x1d, int*)

struct one_mount
{
  void *addr;
  int mnt_id;
  unsigned long mark_count;
  char mnt_root[256]; // mnt.mnt_root
  char root[256];     // from mnt_mountpoint
  char mnt_mp[256];   // mnt_mp
};

// get super-block mount points
// in params:
//  0 - superblock address
//  1 - count
// out params - long size + N * one_mount
#define IOCTL_GET_SUPERBLOCK_MOUNTS    _IOR(IOCTL_NUM, 0x1e, int*)

// get fsnotify_mark/fsnotify_group/fsnotify_ops for some mount point 
// in params:
//  0 - superblock address
//  1 - mount address
//  2 - count
// out params - long size + N * one_fsnotify
#define IOCTL_GET_MOUNT_MARKS          _IOR(IOCTL_NUM, 0x1f, int*)

/*
 *  network data
 */

struct one_net
{
  void *addr;
  void *rtnl;
  void *rtnl_proto;
  void *rtnl_filter; // sk_filter->prog->bpf_func
  void *genl_sock;
  void *genl_sock_proto;
  void *genl_sock_filter;
  void *uevent_sock;
  void *diag_nlsk;
  void *diag_nlsk_proto;
  void *diag_nlsk_filter;
  int ifindex;
  unsigned long dev_cnt;
  unsigned long netdev_chain_cnt;
};

// read net from net_namespace_list
// in params:
//   0 - count
// out params:
//   if count is zero - count of nets
//   else long size + N * one_net
#define IOCTL_GET_NETS                 _IOR(IOCTL_NUM, 0x20, int*)

struct one_net_dev
{
  void *addr;
  char name[IFNAMSIZ];
  void *netdev_ops;
  void *ethtool_ops;
  void *l3mdev_ops;  // if CONFIG_NET_L3_MASTER_DEV
  void *ndisc_ops;   // if CONFIG_IPV6
  void *xfrmdev_ops; // if CONFIG_XFRM_OFFLOAD
  void *tlsdev_ops;  // if CONFIG_TLS_DEVICE
  unsigned int 		flags;
  unsigned int		mtu;
  unsigned int		min_mtu;
  unsigned int		max_mtu;
  unsigned short	type;
  void *header_ops;
  void *xdp_prog;
  void *rx_handler;
  void *rtnl_link_ops;
  void *nf_hooks_ingress;
  unsigned long num_hook_entries; // nf_hooks_ingress->num_hook_entries
  unsigned long netdev_chain_cnt; // count of net_notifier_list
};

// read netdevs
// in params:
//  0 - net addr
//  1 - count
// out params:
//  if count is zero - count of nets
//  else long size + N * one_net_dev
#define IOCTL_GET_NET_DEVS             _IOR(IOCTL_NUM, 0x21, int*)

// sock_diag_handler *sock_diag_handlers[AF_MAX]
struct one_sock_diag
{
  void *addr;
  void *dump;
  void *get_info;
  void *destroy;
};

// read sock_diag_handler
// in params:
//  0 - index
// out params:
//  one_sock_diag
#define IOCTL_GET_SOCK_DIAG            _IOR(IOCTL_NUM, 0x22, int*)

// read netdev chain
// in params:
//  0 - address of netdev_chain - struct raw_notifier_head *
//  1 - count
// out params:
//  if count is zero - count of netdev ntfy
//  else long size + N * void*
#define IOCTL_GET_NETDEV_CHAIN         _IOR(IOCTL_NUM, 0x23, int*)

struct one_pernet_ops
{
  void *addr;
  void *init;
  void *exit;
  void *exit_batch;
};

// read pernet ops
// in params:
//  0 - address of pernet_list
//  1 - address of pernet_ops_rwsem
//  2 - count
// out params:
//  if count is zero - count of registered pernet ops
//  else long size + N * one_pernet_ops
#define IOCTL_GET_PERNET_OPS           _IOR(IOCTL_NUM, 0x24, int*)

// read link ops
// in params:
//  0 - address of link_ops list
//  1 - count
// out params:
//   if count is zero - count of netdev ntfy
//   else long size + N * void*
#define IOCTL_GET_LINKS_OPS            _IOR(IOCTL_NUM, 0x25, int*)

struct one_protosw
{
  void *addr;
  unsigned short type;
  unsigned short protocol;
  void *prot;
  void *ops;
};

// read protosw list
// in params:
//  0 - list addr (inetsw or inetsw6)
//  1 - spinlock addr (inetsw_lock or inetsw6_lock)
//  2 - index
//  3 - count
// out params:
//  if count is zero - count of inet_protosw
//  else long size + N * one_protosw
#define IOCTL_GET_PROTOSW              _IOR(IOCTL_NUM, 0x26, int*)

// read rtnl_af_ops
// in params:
//  0 - list addr (rtnl_af_ops)
//  1 - count
// out params:
//  if count is zero - count of rtnl_af_ops
//  else long size + N * void *
#define IOCTL_GET_RTNL_AF_OPS          _IOR(IOCTL_NUM, 0x27, int*)

struct one_nltab
{
  void *addr;
  unsigned long sk_count; // count of sockets from netlink_table.hash
  void *bind;
  void *unbind;
  void *compare;
  int registered;
};

// read netlink table
// in params:
//  0 - table addr (nl_table)
//  1 - nl_table_lock
//  2 - index
// out params
//  struct one_nltab
#define IOCTL_GET_NLTAB                _IOR(IOCTL_NUM, 0x28, int*)

struct one_nl_socket
{
  void *addr;
  unsigned int portid;
  unsigned int flags;
  unsigned int subscriptions;
  unsigned short sk_type;
  unsigned short sk_protocol;
  void *netlink_rcv;
  void *netlink_bind;
  void *netlink_unbind;
  void *cb_dump; // netlink_callback.dump
  void *cb_done; // netlink_callback.done  
};

// read netlink sockets
// in params:
//  0 - table addr (nl_table)
//  1 - nl_table_lock
//  2 - index
//  3 - cnt
// out params
//  struct one_nl_socket
#define IOCTL_GET_NL_SK                _IOR(IOCTL_NUM, 0x29, int*)

// read registered proto`s
// in params:
//  0 - proto_list address
//  1 - proto_list_mutex address
//  2 - cnt
// out params
//  if count is zero - count of protos
//  else long size + N * void *
#define IOCTL_GET_PROTOS               _IOR(IOCTL_NUM, 0x2a, int*)

struct one_tcp_ulp_ops
{
  void *addr;
  void *init;
  void *update;
  void *release;
  void *get_info;
  void *get_info_size;
  void *clone;
  char name[16];
};

// read tcp_ulp_ops
// in params:
//  0 - tcp_ulp_list address
//  1 - tcp_ulp_list_lock address
//  2 - cnt
// out params
//  if count is zero - count of ops
//  else long size + N * one_tcp_ulp_ops
#define IOCTL_GET_ULP_OPS              _IOR(IOCTL_NUM, 0x2b, int*)


// read lsm hooks
// in params:
//  0 - list addr
//  1 - count
// out params:
//   if count is zero - count of lsm hooks
//   else long size + N * security_hook_list->hook
#define IOCTL_GET_LSM_HOOKS            _IOR(IOCTL_NUM, 0x2c, int*)

struct one_bpf_reg
{
  void *addr;
  void *attach_target;
  void *detach_target;
  void *show_fdinfo;
  void *fill_link_info;
  void *seq_info;
  unsigned int feature;
};

// read registered bpf_iter_reg
// in params:
//  0 - list address (targets)
//  1 - targets_mutex address
//  2 - cnt
// out params
//  if count is zero - count of targets
//  else long size + N * one_bpf_reg
#define IOCTL_GET_BPF_REGS             _IOR(IOCTL_NUM, 0x2d, int*)

struct one_event_command
{
  void *addr;
  void *func;
  void *reg;
  void *unreg;
  void *unreg_all;
  void *set_filter;
  void *get_trigger_ops;
  int trigger_type;
  int flags;
  char name[128];
};

// read registered event_commands
// in params:
//  0 - list address (trigger_commands)
//  1 - trigger_cmd_mutex address
//  2 - cnt
// out params
//  if count is zero - count of targets
//  else long size + N * one_event_command
#define IOCTL_GET_EVENT_CMDS           _IOR(IOCTL_NUM, 0x2e, int*)

struct one_trace_export
{
  void *addr;
  void *write;
  int flags;
};

// read registered trace_exports
// in params:
//  0 - list address (ftrace_exports_list)
//  1 - ftrace_export_lock address
//  2 - cnt
// out params
//  if count is zero - count of trace_exports
//  else long size + N * one_trace_export
#define IOCTL_GET_TRACE_EXPORTS        _IOR(IOCTL_NUM, 0x2f, int*)

struct one_tracefunc_cmd
{
  void *addr;
  void *func;
  char name[128];
};

// read ftrace_func_commands
// in params:
//  0 - list address (ftrace_commands)
//  1 - ftrace_cmd_mutex address
//  2 - cnt
// out params
//  if count is zero - count of ftrace_func_commands
//  else long size + N * one_tracefunc_cmd
#define IOCTL_GET_FTRACE_CMDS          _IOR(IOCTL_NUM, 0x30, int*)

struct one_dyn_event_op
{
  void *addr;
  void *create;
  void *show;
  void *is_busy;
  void *free;
  void *match;
};

// read registered dyn_event_operations
// in params:
//  0 - list address (dyn_event_ops_list)
//  1 - dyn_event_ops_mutex address
//  2 - cnt
// out params
//  if count is zero - count of ftrace_func_commands
//  else long size + N * one_tracefunc_cmd
#define IOCTL_GET_DYN_EVT_OPS          _IOR(IOCTL_NUM, 0x31, int*)

#endif /* LKCD_SHARED_H */
