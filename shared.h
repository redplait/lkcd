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

struct one_mod_tracepoint
{
  void *addr;
  unsigned long regfunc;
  unsigned long unregfunc;
  unsigned long f_count;
  unsigned long iterator;
  int enabled;
};

// read tracepoint for some module
// in params:
//  0 - tracepoint_ptr_t *
//  1 - size
// out params:
//  N + N * one_mod_tracepoint
#define IOCTL_MOD_TRACEPOINTS          _IOR(IOCTL_NUM, 0x65, int*)

struct one_tracepoint_func
{
  unsigned long addr;
  unsigned long data;
};

// read tracepoint funcs
// in params:
//  0 - address of tracepoint
//  1 - cnt
// out params:
//  size + N * one_tracepoint_func
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

// install/remove my own test kprobe
// in param 0 - 1 to install, 0 to remove
#define IOCTL_TEST_KPROBE              _IOR(IOCTL_NUM, 0x11, int*)

struct one_bl_kprobe
{
  unsigned long start, end;
};

// get kprobe blacklist
// in params:
//  0 - kprobe_mutex address
//  1 - cnt
// out params:
// N + N * one_bl_kprobe
#define IOCTL_KPROBES_BLACKLIST        _IOR(IOCTL_NUM, 0x6F, int*)

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
  void *fault_handler; // was removed in 5.14
  unsigned int flags;
  int is_aggr;
  int is_retprobe;
  // from kretprobe
  void *kret_handler;
  void *kret_entry_handler;
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
  unsigned long ref_ctr_offset;
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
  unsigned long rules_cnt;
  // since 5.8 net->nexthop.notifier_chain count, atomic, since 5.10 - blocking
  unsigned long hop_ntfy_cnt;
  // nf_queue_handler
  void *nf_outfn;
  void *nf_hook_drop;
  // netns_bpf - introduced in 5.x. MAX_NETNS_BPF_ATTACH_TYPE .eq. 2
  void *progs[2];
  unsigned long bpf_cnt[2];
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
  void *wireless_handler;  // CONFIG_WIRELESS_EXT - wireless_handlers->standard
  void *wireless_get_stat; // CONFIG_WIRELESS_EXT - wireless_handlers->get_wireless_stats
  void *l3mdev_ops;  // if CONFIG_NET_L3_MASTER_DEV
  void *ndisc_ops;   // if CONFIG_IPV6
  void *xfrmdev_ops; // if CONFIG_XFRM_OFFLOAD
  void *tlsdev_ops;  // if CONFIG_TLS_DEVICE
  void *dcbnl_ops;   // if CONFIG_DCB
  void *macsec_ops;  // if CONFIG_MACSEC
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
  void *nf_hooks_egress;
  void *priv_destructor; // since 4.1.9
  unsigned long tcx_in_cnt; // since 6.6 - bpf count if tcx_ingress
  unsigned long tcx_e_cnt;  // since 6.6 - bpf count if tcx_egress
  unsigned long num_ihook_entries; // nf_hooks_ingress->num_hook_entries
  unsigned long num_ehook_entries; // nf_hooks_egress->num_hook_entries
  unsigned long netdev_chain_cnt;  // count of net_notifier_list
  // xfrmdev_ops - CONFIG_XFRM_OFFLOAD
  unsigned long xdo_dev_state_add, xdo_dev_state_delete, xdo_dev_state_free, xdo_dev_offload_ok,
  // since 4.16
   xdo_dev_state_advance_esn,
  // since 6.2
    xdo_dev_state_update_stats, xdo_dev_policy_add, xdo_dev_policy_delete, xdo_dev_policy_free;
  // xdp_state
  void *bpf_prog[3];
  void *bpf_link[3];
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
  void *netlink_release;
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
  void *seq_info; // since 5.9
  void *seq_ops, *init_seq_private, *fini_seq_private;
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

struct one_genl_family
{
  void *addr;
  int id;
  char name[GENL_NAMSIZ];
  void *pre_doit;
  void *post_doit;
  // till 5.7.10
  void *mcast_bind;
  void *mcast_unbind;
  void *ops;
  void *small_ops;
  void *split_ops; // since 6.2
  void *policy;
};

// read registered genl_family
// in params:
//  0 - idr address (genl_fam_idr). lock functions are exported genl_lock & genl_unlock
//  1 - cnt
// out params
//  if count is zero - count of genl_families
//  else long size + N * one_genl_family
#define IOCTL_GET_GENL_FAMILIES        _IOR(IOCTL_NUM, 0x32, int*)

struct one_bpf_prog
{
  void *prog;
  int prog_type;
  int expected_attach_type;
  unsigned int len;
  unsigned int jited_len;
  unsigned char tag[8];
  void *bpf_func;
  // all field below from bpf_prog_aux 
  void *aux;
  unsigned int aux_id;
  unsigned int used_map_cnt;
  unsigned int used_btf_cnt;
  unsigned int func_cnt;
  unsigned int stack_depth;
  unsigned int num_exentries;
};

struct one_bpf_links
{
  void *addr;
  unsigned int id;
  int type;
  void *ops;
  // bpf_link_ops
  void *release;
  void *dealloc;
  void *detach;
  void *update_prog;
  void *show_fdinfo;
  void *fill_link_info;
  // prog
  struct one_bpf_prog prog;
};

// read bpf links
// in params:
//  0 - idr address (link_idr)
//  1 - link_idr_lock spinlock_t
//  2 - cnt
// out params
//  if count is zero - count of bpf_links
//  else long size + N * one_bpf_links
#define IOCTL_GET_BPF_LINKS            _IOR(IOCTL_NUM, 0x33, int*)

struct one_trace_event_call
{
  void *addr;
  void *evt_class; // trace_event_class
  void *tp;        // tracepoint
  void *filter;    // event_filter
  int flags;
  int bpf_cnt;
  unsigned long perf_cnt; // count of perf_events
  void *perf_perm;
  void *bpf_prog;  // prog_array->bpf_prog
};

// read registered trace_event_calls
// if address is 0
//  if cnt is 0 - return count of registered in ftrace_events trace_event_calls
//  if cnt is not 0 - copy trace_event_call for all registered trace_event_calls
// in params:
//  0 - address
//  1 - cnt
// output
//  if (!cnt && !address) - cnt of registered in ftrace_events trace_event_calls
//  else long size + N * one_trace_event_call
// if address is not 0 - read bpf_progs for some trace_event_call
// in params:
//  0 - address
//  1 - bpf_cnt
// output
//  long size + N * one_trace_event_call
#define IOCTL_GET_EVT_CALLS            _IOR(IOCTL_NUM, 0x34, int*)

// read bpf progs
// in params:
//  0 - idr address (prog_idr)
//  1 - prog_idr_lock spinlock_t
//  2 - cnt
// out params
//  if count is zero - count of bpf_progs
//  else long size + N * one_bpf_prog
#define IOCTL_GET_BPF_PROGS            _IOR(IOCTL_NUM, 0x35, int*)

// read bpf jit prog body
// in params:
//  0 - idr address (prog_idr)
//  1 - prog_idr_lock spinlock_t
//  2 - address of bpf_prog
//  3 - length
#define IOCTL_GET_BPF_PROG_BODY        _IOR(IOCTL_NUM, 0x36, int*)

// read bpf opcodes
// in params:
//  0 - idr address (prog_idr)
//  1 - prog_idr_lock spinlock_t
//  2 - address of bpf_prog
//  3 - length
#define IOCTL_GET_BPF_OPCODES          _IOR(IOCTL_NUM, 0x37, int*)

// read bpf aux->used_maps, count in used_map_cnt
// in params:
//  0 - idr address (prog_idr)
//  1 - prog_idr_lock spinlock_t
//  2 - address of bpf_prog
//  3 - length
#define IOCTL_GET_BPF_USED_MAPS        _IOR(IOCTL_NUM, 0x38, int*)

#define CG_BPF_MAX	38

struct one_cgroup
{
  // from cgroup_subsys_state
  void *addr;
  void *ss;
  void *parent_ss;
  void *root;
  void *agent_work;
  unsigned long serial_nr;
  // from cgroup
  void *kn;
  unsigned long id; // from cgroup_id
  unsigned long flags;
  int level;
  int ss_cnt; // count of populated cgroup.sybys
  // from cgroup_bpf
  void *prog_array[CG_BPF_MAX];
  unsigned long prog_array_cnt[CG_BPF_MAX];
  unsigned int bpf_flags[CG_BPF_MAX];
};

struct one_group_root
{
  void *addr;
  void *kf_root;
  unsigned int subsys_mask;
  int hierarchy_id;
  unsigned long nr_cgrps;
  unsigned long real_cnt;
  unsigned int flags;
  char name[64];
  struct one_cgroup grp;
};

// read cgroup roots
// in params:
//  0 - idr address (cgroup_hierarchy_idr)
//  1 - cgroup_mutex
//  2 - cnt
// out params
//  if count is zero - count of cgroup roots
//  else long size + N * one_group_root
#define IOCTL_GET_CGRP_ROOTS           _IOR(IOCTL_NUM, 0x39, int*)

// read cgroups for some root
// in params:
//  0 - idr address (cgroup_hierarchy_idr)
//  1 - cgroup_mutex
//  2 - address of cgroups root - gathered with IOCTL_GET_CGRP_ROOTS
//  3 - cnt
// out params
//  unsigned long + N * one_cgroup
#define IOCTL_GET_CGROUPS              _IOR(IOCTL_NUM, 0x3A, int*)

// read BPF progs for some cgroup
// in params:
//  0 - idr address (cgroup_hierarchy_idr)
//  1 - cgroup_mutex
//  2 - address of cgroups root - gathered with IOCTL_GET_CGRP_ROOTS
//  3 - address of cgroup to read BPF progs
//  4 - index in cg->bpf.effective
//  5 - cnt
// out params
//  unsigned long + N * one_bpf_prog
#define IOCTL_GET_CGROUP_BPF           _IOR(IOCTL_NUM, 0x3B, int*)

// Achtung! This ioctl is very dangerous!
// remove bpf program for some cgroup
// in params:
//  0 - idr address (cgroup_hierarchy_idr)
//  1 - cgroup_mutex
//  2 - address of cgroups root - gathered with IOCTL_GET_CGRP_ROOTS
//  3 - address of cgroup to remove BPF prog
//  4 - bpf_attach_type - index in cg->bpf.effective
//  5 - bpf address
#define IOCTL_DEL_CGROUP_BPF           _IOR(IOCTL_NUM, 0x3C, int*)

struct one_bpf_map
{
  void *addr;
  const void *ops;
  void *inner_map_meta;
  void *btf;
  int map_type; // bpf_map_type
  unsigned int key_size;
  unsigned int value_size;
  unsigned int id;
  char name[16]; // BPF_OBJ_NAME_LEN
};

// read BPF maps
// in params:
//  0 - address of map_idr
//  1 - address of map_idr_lock
//  2 - cnt
// out params
//  unsigned long + N * one_bpf_map
#define IOCTL_GET_BPF_MAPS             _IOR(IOCTL_NUM, 0x3D, int*)

struct one_bpf_ksym
{
  void *addr;
  char name[128];
  unsigned long start;
  unsigned long end;
  int prog;
};

// read bpf ksyms
// in params:
//  0 - address of bpf_kallsyms
//  1 - address of bpf_lock
//  2 - cnt
// out params
//  unsigned long + N * one_bpf_ksym
#define IOCTL_GET_BPF_KSYMS            _IOR(IOCTL_NUM, 0x3E, int*)

struct one_pmu
{
  void *addr;
  int type;
  int capabilities;
  // callbacks
  void *pmu_enable;
  void *pmu_disable;
  void *event_init;
  void *event_mapped;
  void *event_unmapped;
  void *add;
  void *del;
  void *start;
  void *stop;
  void *read;
  void *start_txn;
  void *commit_txn;
  void *cancel_txn;
  void *event_idx;
  void *sched_task;
  void *swap_task_ctx;
  void *setup_aux;
  void *free_aux;
  void *snapshot_aux;
  void *addr_filters_validate;
  void *addr_filters_sync;
  void *aux_output_match;
  void *filter_match;
  void *check_period;
};

// read registered PMUs
// in params:
//  0 - address of pmu_idr
//  1 - address of pmus_lock
//  2 - cnt
// out params
//  unsigned long + N * one_bpf_ksym
#define IOCTL_GET_PMUS                 _IOR(IOCTL_NUM, 0x3F, int*)

struct one_ftrace_ops
{
  void *addr;
  void *func;
  void *saved_func;
  unsigned long	flags;
};

// read registered ftrace_ops
// in params:
//  0 - address of ftrace_ops_list
//  1 - address of ftrace_lock - mutex
//  2 - cnt
// out params
//  unsigned long + N * one_ftrace_ops
#define IOCTL_GET_FTRACE_OPS           _IOR(IOCTL_NUM, 0x40, int*)

struct one_bpf_raw_event
{
  void *addr;
  void *tp; // tracepoint
  void *func;
  unsigned int num_args;
};

// read bpf_raw_event_map between __start__bpf_raw_tp & __stop__bpf_raw_tp
// in params:
//  0 - address of __start__bpf_raw_tp
//  1 - address of __stop__bpf_raw_tp
//  2 - cnt
// out params
//  unsigned long + N * one_bpf_raw_event
#define IOCTL_GET_BPF_RAW_EVENTS       _IOR(IOCTL_NUM, 0x41, int*)

// the same as IOCTL_GET_BPF_RAW_EVENTS but for modules
// param[1] is number of bpf_raw_event_map, not stop address
#define IOCTL_GET_BPF_RAW_EVENTS2      _IOR(IOCTL_NUM, 0x64, int*)

// read dyn events
// in params:
//  0 - address of dyn_event_list
//  1 - address of event_mutex
//  2 - cnt
// out params
//  unsigned long + N * one_tracepoint_func
#define IOCTL_GET_DYN_EVENTS           _IOR(IOCTL_NUM, 0x42, int*)

// read trace_uprobe for some uprobe consumer
// in params:
//  0 - uprobes_tree address
//  1 - uprobes_treelock address
//  2 - address of uprobe. it can be removed so return error ENOENT
//  3 - address of consumer
// out params
//  one_trace_event_call
#define IOCTL_TRACE_UPROBE             _IOR(IOCTL_NUM, 0x43, int*)

// read all bpf progs from some uprobe
// in params:
//  0 - uprobes_tree address
//  1 - uprobes_treelock address
//  2 - address of uprobe. it can be removed so return error ENOENT
//  3 - address of consumer
//  4 - count (taken from one_trace_event_call->bpf_cnt)
// out params
//  N + bpf_prog* * N
#define IOCTL_TRACE_UPROBE_BPFS        _IOR(IOCTL_NUM, 0x44, int*)

// most fields ripped from https://elixir.bootlin.com/linux/latest/source/include/linux/console.h#L140
struct one_console
{
  void *addr;
  char name[16];
  void *write;
  void *read;
  void *device;
  void *unblank;
  void *setup;
  void *exit;
  void *match;
  // unsigned long dropped;
  short flags;
  short index;
  // int cflags;
};

// read consoles list
// in params
//  0 - count
// out params
// N + one_console * N
#define IOCTL_READ_CONSOLES            _IOR(IOCTL_NUM, 0x45, int*)

// read cpufreq_policy address and count of notifiers
// in params:
//  0 - processor index
// out params
//  0 - address of cpufreq_policy
//  1 - count of cpufreq_policy.constraints.min_freq_notifiers
//  2 - count of cpufreq_policy.constraints.max_freq_notifiers
#define READ_CPUFREQ_CNT               _IOR(IOCTL_NUM, 0x46, int*)

// read cpufreq_policy.constraints notifiers
// in params:
//  0 - processor index
//  1 - count
//  2 - 0 for min_freq_notifiers else max_freq_notifiers
// out params
//  N + N * void*
#define READ_CPUFREQ_NTFY              _IOR(IOCTL_NUM, 0x47, int*)

struct clk_ntfy
{
  unsigned long clk;
  unsigned long ntfy;
};

// read clk_notifier_register notifiers
// in params:
//  0 - address of clk_notifier_list
//  1 - address of prepare_lock mutex
//  2 - count, if zero - just return count
// out params
//  N + N * clk_ntfy
#define READ_CLK_NTFY                  _IOR(IOCTL_NUM, 0x48, int*)

// read notifiers registered with devfreq_register_notifier
// in params:
//  0 - address of devfreq_list
//  1 - address of devfreq_list_lock mutex
//  2 - count, if zero - just return count
// out params
//  N + N * clk_ntfy
#define READ_DEVFREQ_NTFY              _IOR(IOCTL_NUM, 0x49, int*)

// test kprobes disabling
// in params:
//  0 - kprobe_table address
//  1 - kprobe_mutex address
//  2 - index (must be between 0 and nonincluded KPROBE_TABLE_SIZE)
//  3 - address of kprobe
//  4 - 0 if disable, 1 if enable
// out params
//  0 - 1 if some action was successfull, 0 else
#define IOCTL_KPROBE_DISABLE           _IOR(IOCTL_NUM, 0x4a, int*)

// patch 1 byte in kernel text
// in params:
//  0 - address
//  1 - byte to patch
#define IOCTL_PATCH_KTEXT1             _IOR(IOCTL_NUM, 0x4b, int*)

// remove notifier for tests
// for all ioctls
// in params
//  0 - address of block
//  1 - address of notifier
// out params:
//  0 - 1 if notifier was found, 0 else

// for blocking_notifier_chain_register
#define IOCTL_REM_BNTFY                 _IOR(IOCTL_NUM, 0x4c, int*)
// for atomic_notifier_chain_register
#define IOCTL_REM_ANTFY                 _IOR(IOCTL_NUM, 0x4d, int*)
// for srcu_notifier_chain_register
#define IOCTL_REM_SNTFY                 _IOR(IOCTL_NUM, 0x4e, int*)

struct ktimer
{
  void *addr;
  void *wq_addr;
  unsigned long exp;
  void *func;
  unsigned int flags;
};

// dump kernel timers
// in params:
//  0 - timer_bases address
//  1 - count
// out params
//  N + N * ktimer
#define IOCTL_GET_KTIMERS               _IOR(IOCTL_NUM, 0x4f, int*)

struct one_alarm
{
  void *addr;
  void *hr_timer;
  void *func;
};

// dump alarm timers
// in params:
//  0 - index
//  1 - count
// out params
//  if !count: 0 - count 1 - get_ktime 2 - get_timespec
// else N + N * one_alarm
#define IOCTL_GET_ALARMS                _IOR(IOCTL_NUM, 0x50, int*)

struct one_kcalgo
{
  void *addr;
  unsigned int flags; // cra_flags
  unsigned int c_blocksize;
  unsigned int c_ctxsize;
  char name[128];
  void *c_type;
  // from crypto_type *cra_type
  void *ctxsize;
  void *extsize;
  void *init;
  void *init_tfm;
  void *show;
  void *report;
  void *free;
  unsigned int tfmsize;
  // for compress - methods from compress_alg
  void *coa_compress;
  void *coa_decompress;
  // from cipher_alg
  unsigned int cia_min_keysize;
  unsigned int cia_max_keysize;
  void *cia_setkey;
  void *cia_encrypt;
  void *cia_decrypt;
  // remained methods
  void *cra_init;
  void *cra_exit;
  void *cra_destroy;
};

// dump kernel crypto algos
// in params:
//  0 - crypto_alg_list address
//  1 - crypto_alg_sem address
//  2 - count
// out params
//  N + N * one_kcalgo
#define IOCTL_ENUM_CALGO                _IOR(IOCTL_NUM, 0x51, int*)

/* netfilter ioctls
 * net->nf exists only if CONFIG_NETFILTER presents
 */

// struct nft_af_info
struct one_nft_af
{
  void *addr;
  int family;
  unsigned int nhooks;
  void *ops_init;
  void *hooks[8]; // NF_MAX_HOOKS
};

// dump nft_af_info
// in params:
//  0 - address of net from IOCTL_GET_NETS
//  1 - count
// out params
//  N + N * one_nft_af
#define IOCTL_ENUM_NFT_AF               _IOR(IOCTL_NUM, 0x52, int*)

// get nf_hook_entries for net_dev ingress/egress
// in params:
// 0 - address of net from IOCTL_GET_NETS
// 1 - address of net_dev
// 2 - count - from one_net_dev num_ihook_entries/num_ehook_entries
// 3 - 0 for ingress, otherwise for egress
// out params
//  N + N * hooks
#define IOCTL_NFIEHOOKS                 _IOR(IOCTL_NUM, 0x53, int*)

struct one_nf_logger
{
  int type;
  int idx;
  void *fn;
};

// get nf loggers for some net->nf
// in params:
//  0 - address of net from IOCTL_GET_NETS
//  1 - count
// out params:
//  N + N * one_nf_logger
#define IOCTL_NFLOGGERS                 _IOR(IOCTL_NUM, 0x54, int*)

// read NF hooks for some net->nf
// in params:
//  0 - address of net from IOCTL_GET_NETS
//  1 - count
// out params:
//  N + N * one_nf_logger
#define IOCTL_NFHOOKS                   _IOR(IOCTL_NUM, 0x55, int*)

struct one_fib_rule
{
  void *addr;
  int family, rule_size, addr_size;
  unsigned long action, suppress, match, configure, del_, compare, fill, default_pref, nlmsg_payload, flush_cache;
};

// read fib_rules
// in params:
//  0 - address of net from IOCTL_GET_NETS
//  1 - count
// out params:
// N + N * one_fib_rule
#define IOCTL_FIB_RULES                 _IOR(IOCTL_NUM, 0x72, int*)

/*
 * keys ioclts if CONFIG_NETFILTER presents
 */
struct one_key_type
{
  void *addr;
  size_t len_name;
  size_t def_datalen;
  void *vet_description;
  void *preparse;
  void *free_preparse;
  void *instantiate;
  void *update;
  void *match_preparse;
  void *match_free;
  void *revoke;
  void *destroy;
  void *describe;
  void *read;
  void *request_key;
  // since 4.12
  void *lookup_restriction;
  // since 4.20
  void *asym_query;
  void *asym_eds_op;
  void *asym_verify_signature;
};

// read key_types
// in params:
// 0 - count
// out params:
//  N + N * one_key_type
#define IOCTL_KEY_TYPES                 _IOR(IOCTL_NUM, 0x56, int*)

// read name of key_type
// in params:
// 0 - address of key_type from IOCTL_KEY_TYPES
// out params:
//  string
#define IOCTL_KEYTYPE_NAME             _IOR(IOCTL_NUM, 0x57, int*)

struct one_key
{
  void *addr;
  int serial, len_desc;
  int64_t expiry, last_used;
  short gid, uid, state;
  unsigned short datalen;
  unsigned int perm;
  unsigned long flags;
  void *type;
  void *rest_check; // restrict_link->check
};

// enum keys
// in params:
//  0 - count
// out:
//  N + N * one_key
#define IOCTL_ENUM_KEYS                _IOR(IOCTL_NUM, 0x58, int*)

// read key description
// in params:
//  0 - serial
// out:
//  string
#define IOCTL_GET_KEY_DESC             _IOR(IOCTL_NUM, 0x59, int*)

// read key
// in params:
//  0 - serial
//  1 - size (from key->datalen)
// out:
//  data with size
#define IOCTL_READ_KEY                 _IOR(IOCTL_NUM, 0x5A, int*)

struct one_task_info
{
  void *addr;
  void *sched_class;
  void *restart_fn;
  void *io_uring;
  void *mce_kill_me;
  unsigned long thread_flags; // from thread_info.flags
  unsigned int flags;
  unsigned int ptrace;
  unsigned long works_count;
  void *seccomp_filter;
};

// get task info
// in params:
//  0 - pid
// out params
//  one_task_info
#define IOCTL_TASK_INFO                    _IOR(IOCTL_NUM, 0x5B, int*)

// get task works
// in params:
//  0 - pid
//  1 - size
// out params: N + N * void*
#define IOCTL_TASK_WORKS                   _IOR(IOCTL_NUM, 0x67, int*)

// test mmap
// in params:
//  0 - size
//  1 - prot
// out: address
#define IOCTL_TEST_MMAP                    _IOR(IOCTL_NUM, 0x5C, int*)

// test mprotect
// in params:
//  0 - address
//  1 - size
//  2 - prot
// out: address
#define IOCTL_TEST_MPROTECT                _IOR(IOCTL_NUM, 0x5D, int*)

// wrapper around lookup_module_symbol_name
// in param - address
// out param - string
#define IOCTL_LOOKUP_SYM                   _IOR(IOCTL_NUM, 0x5E, int*)

#define MAX_MODULE_LENGTH (64 - sizeof(unsigned long))
struct one_module
{
  void *base;
  unsigned long size;
  char name[MAX_MODULE_LENGTH];
};

struct one_module1
{
  void *addr;
  void *base;
  void *init;
  void *exit;
  void *module_init;
  unsigned long init_size;
  unsigned int percpu_size;
  unsigned int num_tracepoints;
  unsigned int num_bpf_raw_events;
  unsigned int num_trace_events;
  unsigned int num_trace_evals;
  unsigned int num_srcu_structs;
  unsigned int kprobes_text_size;
  unsigned int num_kprobe_blacklist;
  unsigned int num_ei_funcs;
  unsigned long tracepoints_ptrs;
  unsigned long bpf_raw_events;
  unsigned long trace_events;
  unsigned long trace_evals;
  unsigned long srcu_struct_ptrs;
  // since 5.8.0
  unsigned long kprobes_text_start;
  unsigned long kprobe_blacklist;
  // CONFIG_FUNCTION_ERROR_INJECTION, since 4.16
  unsigned long ei_funcs;
};

// wrapper to read /proc/modules from non-root
// in params:
//  0 - size
//  1 - type, 0 - one_module, 1 - one_module1
// out params:
//  N + N * one_module or one_module1
#define IOCTL_READ_MODULES                 _IOR(IOCTL_NUM, 0x5F, int*)

struct one_srcu {
  void *addr;
  unsigned long per_cpu_off;
};
// extract additional info for some lkm
// in params:
//  0 address of module - from one_module1
//  1 - size
//  2 - type, currently only one_srcu
#define IOCTL_MODULE1_GUTS                 _IOR(IOCTL_NUM, 0x6D, int*)

struct one_priv
{
  void *uevent_ops; // below 3 fields from it
  void *filter;
  void *name;
  void *uevent;
  unsigned long ntfy_cnt; // count of notifiers in bus_notifier
  void *bus;
  // fields from bus_type
  void *match;
  void *bus_uevent;
  void *probe;
  void *sync_state;
  void *remove;
  void *shutdown;
  void *online;
  void *offline;
  void *suspend;
  void *resume;
  void *num_vf;
  void *dma_configure;
  void *dma_cleanup;
  void *pm;
  void *iommu_ops;
  void *_class;
  // fields from class
  void *dev_uevent;
  void *devnode;
  void *class_release;
  void *dev_release;
  void *c_susped;
  void *c_resume;
  void *c_shutdown;
  void *c_ns_type;
  void *c_namespace;
  void *c_getownership;
};

// extract kbus_type for /sys/bus/XXX
// in param - name of file
// out param - one_priv
#define IOCTL_READ_BUS                     _IOR(IOCTL_NUM, 0x60, int*)

// extract bus nofifiers
// in param:
//  0 - size
//  1 - string - name of file
// out params: N + N * void*
#define IOCTL_BUS_NTFY                     _IOR(IOCTL_NUM, 0x61, int*)

// read subsys for some cgroup
// in params:
//  0 - idr address (cgroup_hierarchy_idr)
//  1 - cgroup_mutex
//  2 - address of cgroups root - gathered with IOCTL_GET_CGRP_ROOTS
//  3 - address of cgroup to read subsys
//  4 - cnt
// out params
//  unsigned long + N * (pair subsys + ss)
#define IOCTL_GET_CGROUP_SS                 _IOR(IOCTL_NUM, 0x62, int*)

struct one_zpool
{
  void *addr;
  void *module;
  unsigned long create,
    destroy,
    malloc,
    free,
    shrink, // removed since 6.5
    map,
    unmap,
    total_size;
};

// read zpool_drivers
// in param - size
// out params: unsigned long + N * one_zpool
#define IOCTL_GET_ZPOOL_DRV                 _IOR(IOCTL_NUM, 0x63, int*)

struct one_slab
{
  void *addr;
  unsigned int size;
  unsigned int object_size, l_name;
  unsigned long ctor;
};

// read slabs. unfortunately works only for 5.x kernels
// in param - size
// out params: unsigned long + N * one_slab
#define IOCTL_GET_SLABS                     _IOR(IOCTL_NUM, 0x66, int*)

// read slab name
// in params:
// 0 - slab addr from one_slab
// 1 - len
#define IOCTL_SLAB_NAME                     _IOR(IOCTL_NUM, 0x6E, int*)

// inject
// in params
//  0 - PID
//  1 - length, if zero - get state of inject, 1 - cancel
//  2 - offset
//  3 ... - body of inject stub
// out params
//  0 - state, see comment in inject_data
//  1 - error (if any)
//  2 - injected stub address (if state was 2)
#define IOCTL_INJECT                        _IOR(IOCTL_NUM, 0x68, int*)

struct one_input_handler
{
  void *addr;
  void *event, *events, *filter, *match, *connect, *disconnect, *start;
  unsigned long l_name;
};

// enum input handlers
// in params - size
// out params
//  N + N * one_input_handler
#define IOCTL_INPUT_HANDLERS                _IOR(IOCTL_NUM, 0x69, int*)

// get name of input_handler
// in params:
//  0 - addr of input_handler
//  1 - size
#define IOCTL_INPUT_HANDLER_NAME            _IOR(IOCTL_NUM, 0x6A, int*)

struct one_input_dev
{
  void *addr;
  void *setkeycode;
  void *getkeycode;
  void *open;
  void *close;
  void *flush;
  void *event;
  unsigned long h_cnt; // count of handlers on this input-dev
  unsigned long l_name, l_phys, l_uniq;
  void *ff; // next 6 methods from ff_device
  void *ff_upload, *ff_erase, *ff_playback, *ff_set_gain, *ff_set_autocenter, *ff_destroy;
};

// enum input devs
// in params - size
// out params
//  N + N * one_input_dev
#define IOCTL_INPUT_DEVS                    _IOR(IOCTL_NUM, 0x6B, int*)

// get name of input dev
// in params:
//  0 - add of input dev
//  1 - length of buffer (for type 3 - in items)
//  2 - 0 for name, 1 for phys, 2 for uniq, 3 - special case to collect handlers
// out params:
// just string, for type 3 - N + N * handlers ptrs
#define IOCTL_INPUT_DEV_NAME                _IOR(IOCTL_NUM, 0x6C, int*)

struct one_binfmt
{
  void *addr;
  void *mod;
  void *load_binary;
  void *load_shlib;
  void *core_dump;
};

// get registered bin formats
// in param - N (or zero)
// out params: N + N * one_binfmt
#define IOCTL_BINFMT                        _IOR(IOCTL_NUM, 0x70, int*)

struct one_sysrq_key
{
  void *addr;
  void *handler;
  int mask;
  int idx;
};

// get sysrq handlers
// in param - N (or zero)
// out params: N + N * one_sysrq_key
#define IOCTL_SYSRQ_KEYS                    _IOR(IOCTL_NUM, 0x71, int*)

// till 5.1
struct s_xfrm_mode {
  void *addr;
  unsigned long input, input2, output, output2;
  // since 4.12
  unsigned long gso_segment, xmit;
};

// since 4.12
struct s_xfrm_type_offload {
  const void *addr;
  int proto;
  unsigned long encap, input_tail, xmit;
};

struct s_dst_ops {
  void *addr;
  unsigned short family;
  unsigned long gc, check, default_advmss, mtu, cow_metrics, destroy, ifdown, negative_advice,
   link_failure, update_pmtu, redirect, local_out, neigh_lookup,
   // since 4.11
   confirm_neigh;
};

struct s_xfrm_policy_afinfo {
 void *addr;
 struct s_dst_ops dst_ops;
 // in 5.2+ only 4: dst_lookup get_saddr fill_dst blackhole_route
 unsigned long garbage_collect, // < 4.11
  init_dst, // < 4.3
  dst_lookup, get_saddr, decode_session, get_tos, init_path, fill_dst, blackhole_route;
};

struct s_xfrm_mgr {
 void *addr;
 unsigned long notify, acquire, compile_policy, new_mapping, notify_policy, report, migrate, is_alive;
};

struct s_xfrm_translator {
 void *addr;
 unsigned long alloc_compat, rcv_msg_compat, xlate_user_policy_sockptr;
};

struct s_xfrm_type {
  const void *addr;
  unsigned char proto, flags;
  unsigned long init_state, destructor, input, output, reject,
  // < 5.14
  hdr_offset;
};

struct s_xfrm_state_afinfo {
  void *addr;
  unsigned char proto;
  struct s_xfrm_type_offload off_esp;
  struct s_xfrm_type type_esp, type_ipip, type_ipip6, type_comp, type_ah, type_routing, type_dstopts;
  unsigned long output, transport_finish, local_error,
  // < 5.8
   output_finish, extract_input, extract_output;
};

// read xfrm internals
// in params - must be at least 3
// first - kind of what to read
//  case 0 - read xfrm_policy_afinfo, second - index, must be < XFRM_MAX
//   out param - s_xfrm_policy_afinfo
//  case 1 - read list of xfrm_mgr, second - zero or N
//   out params - N + N * s_xfrm_mgr
//  case 2 (since 5.10) - read xfrm_translator
//   out param - s_xfrm_translator
//  case 3 - (since 5.3) read xfrm_state_afinfo, second - zero or N
//   oit param - N + N * s_xfrm_state_afinfo
#define IOCTL_XFRM_GUTS                     _IOR(IOCTL_NUM, 0x73, int*)

#endif /* LKCD_SHARED_H */
