#include <dlfcn.h>
#include <link.h>
#include <stdio.h>
#include "injparams.h"

extern void *__libc_dlopen_mode(const char *__name, int __mode);
extern void *__libc_dlsym(void *__map, const char *__name);

int fill_myself(inj_params *res)
{
  std::string libc;
  if ( !find_libc(&libc) )
  {
    printf("cannot find libc\n");
    libc = "libc.so.6";
  } else {
    printf("libc: %s\n", libc.c_str());
  }
  auto c = dlopen(libc.c_str(), RTLD_NOLOAD);
  auto sym_m = dlsym(c, "__malloc_hook");
  if ( !sym_m )
  {
    printf("cannot find malloc_hook\n");
    return 0;
  }
  res->mh = (char *)sym_m;
  auto sym_f = dlsym(c, "__free_hook");
  if ( !sym_f )
  {
    printf("cannot find free_hook\n");
    return 0;
  }
  res->fh = (char *)sym_f;
  res->dlopen = (char *)dlsym(c, "__libc_dlopen_mode");
  res->dlsym = (char *)dlsym(c, "__libc_dlsym");
  return 1;
}

struct ld_data
{
  char *dlopen;
  std::string *res;
};

static int
ld_cb(struct dl_phdr_info *info, size_t size, void *data)
{
  ld_data *ld = (ld_data *)data;
  if ( !ld->res->empty() ) return 0; // already found
  size_t curr = 0;
  for (int j = 0; j < info->dlpi_phnum; j++ )
  {
     size_t end = info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz;
     curr = std::max(curr, end);
  }
  if ( ld->dlopen > (char *)info->dlpi_addr && ld->dlopen < (char *)info->dlpi_addr + curr )
  {
   ld->res->assign(info->dlpi_name);
  }
  return 0;
}

// you can`t use public from .rodata bcs it will be just copied with R_X86_64_COPY
// extern "C" char _nl_default_dirname[];
extern "C" char *__free_hook;
extern "C" char *hack(char *);

int find_libc(std::string *res)
{
  ld_data ld{ (char *)&__free_hook, res };
printf("dlopen %p %p\n", ld.dlopen, &__free_hook);
  dl_iterate_phdr(ld_cb, &ld);
  return !res->empty();
}