#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int init_kmods(int fd);
int init_kmod_ex(int fd);
// return 0 if ok
const char *find_kmod(unsigned long addr);
const char *find_kmod_ex(unsigned long addr);

#ifdef __cplusplus
};
#endif