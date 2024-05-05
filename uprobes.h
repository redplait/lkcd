#pragma once

// ripped from https://elixir.bootlin.com/linux/v5.11/source/kernel/events/uprobes.c#L55

struct und_uprobe {
	struct rb_node		rb_node;	/* node in the rb tree */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	refcount_t		ref;
#else
	atomic_t		ref;
#endif
	struct rw_semaphore	register_rwsem;
	struct rw_semaphore	consumer_rwsem;
	struct list_head	pending_list;
	struct uprobe_consumer	*consumers;
	struct inode		*inode;		/* Also hold a ref to inode */
	loff_t			offset;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
	loff_t			ref_ctr_offset;
#endif
	unsigned long		flags;
};

// ripped from https://elixir.bootlin.com/linux/v5.13/source/kernel/events/uprobes.c#L80
struct delayed_uprobe {
  struct list_head list;
  struct und_uprobe *uprobe;
};

// ripped from https://elixir.bootlin.com/linux/latest/source/kernel/trace/trace_dynevent.h#L61
struct dyn_event {
	struct list_head		list;
	void *ops;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,4,0)
// https://elixir.bootlin.com/linux/v5.13/source/kernel/trace/trace_probe.h#L232
struct trace_probe_event {
	unsigned int			flags;	/* For TP_FLAG_* */
	struct trace_event_class	class;
	struct trace_event_call		call;
 // remaining fields omitted	
};
#endif

// https://elixir.bootlin.com/linux/v5.13/source/kernel/trace/trace_probe.h#L241
struct trace_probe {
	struct list_head		list;
	struct trace_probe_event	*event;
	ssize_t				size;
 // remaining fields omitted	
};

// https://elixir.bootlin.com/linux/v5.13/source/kernel/trace/trace_uprobe.c#L55
struct trace_uprobe {
	struct dyn_event		devent;
	struct uprobe_consumer		consumer;
	struct path			path;
	struct inode			*inode;
	char				*filename;
	unsigned long			offset;
	unsigned long			ref_ctr_offset;
	unsigned long			nhit;
	struct trace_probe		tp;
};