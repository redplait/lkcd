#pragma once

// ripped from https://elixir.bootlin.com/linux/v4.20.17/source/net/netfilter/x_tables.c#L50
// basically we need 3 field only but to iterate over array of xt we need all
struct compat_delta {
    unsigned int offset; /* offset in kernel */
    int delta; /* delta in 32bit user land */
};

struct xt_af {
  struct mutex mutex;
  struct list_head match;
  struct list_head target;
#ifdef CONFIG_COMPAT
    struct mutex compat_mutex;
    struct compat_delta *compat_tab;
    unsigned int number; /* number of slots in compat_tab[] */
    unsigned int cur; /* number of used slots in compat_tab[] */
#endif
};

// ripped from https://elixir.bootlin.com/linux/v5.11/source/net/netlink/af_netlink.h#L23
struct netlink_sock {
	/* struct sock has to be the first member of netlink_sock */
	struct sock		sk;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,55)
	unsigned long		flags;
#endif
	u32			portid;
	u32			dst_portid;
	u32			dst_group;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,1,55)
	u32			flags;
#endif
	u32			subscriptions;
	u32			ngroups;
	unsigned long		*groups;
	unsigned long		state;
	size_t			max_recvmsg_len;
	wait_queue_head_t	wait;
	bool			bound;
	bool			cb_running;
	int			dump_done_errno;
	struct netlink_callback	cb;
	struct mutex		*cb_mutex;
	struct mutex		cb_def_mutex;
	void			(*netlink_rcv)(struct sk_buff *skb);
	int			(*netlink_bind)(struct net *net, int group);
	void			(*netlink_unbind)(struct net *net, int group);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,6,0)
	void			(*netlink_release)(struct sock *sk,
			   unsigned long *groups);
#endif
	struct module		*module;

	struct rhash_head	node;
	struct rcu_head		rcu;
	struct work_struct	work;
};

struct netlink_table {
	struct rhashtable	hash;
	struct hlist_head	mc_list;
	struct listeners __rcu	*listeners;
	unsigned int		flags;
	unsigned int		groups;
	struct mutex		*cb_mutex;
	struct module		*module;
	int			(*bind)(struct net *net, int group);
	void			(*unbind)(struct net *net, int group);
	bool			(*compare)(struct net *net, struct sock *sock);
	int			registered;
};
