#pragma once
// api to usermode ebpf jit

int ujit_open(const char *);
int ujit2mem(unsigned char *, long len, unsigned int stack_depth, size_t &out_size, unsigned char **);
int ujit2file(int idx, unsigned char *, long len, unsigned int stack_depth);
int put_kdata(unsigned long base, unsigned long enter, unsigned long ex);
int put_orig_jit_addr(void *);
int ujit_opened();
void ujit_close();