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