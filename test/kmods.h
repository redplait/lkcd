#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int init_kmods(int fd);
const char *find_kmod(unsigned long addr);

#ifdef __cplusplus
};
#endif