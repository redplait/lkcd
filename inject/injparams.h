#pragma once
#include <string>

struct inj_params
{
  char *mh = nullptr,
       *fh = nullptr,
       *mh_old = nullptr,
       *fh_old = nullptr,
       *dlopen = nullptr,
       *dlsym = nullptr;
};

int fill_myself(inj_params *);
int find_libc(std::string *);
