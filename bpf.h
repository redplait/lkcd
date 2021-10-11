#pragma once

// ripped from https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/bpf_iter.c#L9

struct bpf_iter_target_info {
	struct list_head list;
	const struct bpf_iter_reg *reg_info;
	u32 btf_id;	/* cached value */
};