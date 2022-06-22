#pragma once
// api to usermode ebpf jit

int ujit_open(const char *);
int ujit(int idx, unsigned char *, long len, unsigned int stack_depth);
int put_kdata(unsigned long base, unsigned long enter, unsigned long ex);
int ujit_opened();
void ujit_close();