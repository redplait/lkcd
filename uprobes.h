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