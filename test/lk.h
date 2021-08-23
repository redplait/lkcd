#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// ksym
union ksym_params {
  unsigned long addr;
  char name[256];
};

int is_inside_kernel(unsigned long a);
int read_kernel_area(int fd);
void HexDump(unsigned char *From, int Len);

#ifdef __cplusplus
};
#endif