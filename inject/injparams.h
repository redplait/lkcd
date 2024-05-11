#pragma once
#include <string>

struct inj_params
{
  // asm stub - filled in main
  const unsigned char *stub;
  size_t stub_size;
  // addresses for dtab
  char *mh = nullptr,
       *fh = nullptr,
       *mh_old = nullptr,
       *fh_old = nullptr,
       *dlopen = nullptr,
       *dlsym = nullptr;
};

int fill_myself(inj_params *);
int fill_params(long pid, inj_params *);
int find_libc(std::string *);
void HexDump(unsigned char *From, int Len);

