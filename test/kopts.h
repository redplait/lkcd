#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int init_kopts();
int has_option(const char *);
const char *get_option(const char *);

#ifdef __cplusplus
};
#endif