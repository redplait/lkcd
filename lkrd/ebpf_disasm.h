#pragma once

struct bpf_insn {
  unsigned char	code;		/* opcode */
  unsigned char dst_reg:4;	/* dest register */
  unsigned char src_reg:4;	/* source register */
  short	off;			/* signed offset */
  int	imm;			/* signed immediate constant */
};

void ebpf_disasm(unsigned char *, long len, FILE *);