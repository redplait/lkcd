#pragma once

// ripped from https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/bpf_iter.c#L9

struct bpf_iter_target_info {
	struct list_head list;
	const struct bpf_iter_reg *reg_info;
	u32 btf_id;	/* cached value */
};

// ripped from https://elixir.bootlin.com/linux/v6.9.7/source/kernel/bpf/btf.c#L440
struct undoc_btf_ops {
  unsigned long check_meta,
   resolve,
   check_member,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
   check_kflag_member,
#endif
   log_details,
   show;
};