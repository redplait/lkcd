#include <dlfcn.h>
#include <stdio.h>
#include "injparams.h"

int fill_myself(inj_params *res)
{
  auto c = dlopen("libc.so.6", RTLD_NOLOAD);
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
  res->dlopen = (char *)dlsym(c, "dlopen");
  res->dlsym = (char *)dlsym(c, "dlsym");
  return 1;
}