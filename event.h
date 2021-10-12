#pragma once

// ripped from https://elixir.bootlin.com/linux/v5.11/source/kernel/trace/trace.h#L1736

struct event_command {
	struct list_head	list;
	char			*name;
	enum event_trigger_type	trigger_type;
	int			flags;
	void *func;
	void *reg;
	void *unreg;
	void *unreg_all;
	void *set_filter;
	void *get_trigger_ops;
};

// ripped from https://elixir.bootlin.com/linux/v5.11/source/kernel/trace/trace.h#L959

struct ftrace_func_command {
	struct list_head list;
	char		*name;
	void*		*func;
};