#pragma once
// api to usermode ebpf jit

int ujit_open(const char *);
int ujit(int idx, unsigned char *, long len);
void ujit_close();