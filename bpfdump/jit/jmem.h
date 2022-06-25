#pragma once

#if __cplusplus
 extern "C" {
#endif

void jmem_store(void *addr);
void jmem_remove(void *addr);
void jmem_clear();

#if __cplusplus
};
#endif