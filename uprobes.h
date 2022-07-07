#pragma once

// ripped from https://elixir.bootlin.com/linux/v5.11/source/kernel/events/uprobes.c#L55

struct und_uprobe {
	struct rb_node		rb_node;	/* node in the rb tree */
	refcount_t		ref;
	struct rw_semaphore	register_rwsem;
	struct rw_semaphore	consumer_rwsem;
	struct list_head	pending_list;
	struct uprobe_consumer	*consumers;
	struct inode		*inode;		/* Also hold a ref to inode */
	loff_t			offset;
	loff_t			ref_ctr_offset;
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

// https://elixir.bootlin.com/linux/v5.13/source/kernel/trace/trace_probe.h#L232
struct trace_probe_event {
	unsigned int			flags;	/* For TP_FLAG_* */
	struct trace_event_class	class;
	struct trace_event_call		call;
 // remaining fields omitted	
};

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