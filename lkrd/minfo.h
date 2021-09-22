#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int init_mountinfo();
const char *get_mnt(int id);

#ifdef __cplusplus
};
#endif