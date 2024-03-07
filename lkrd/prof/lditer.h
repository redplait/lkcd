#pragma once

void ld_iter();

struct ld_data
{
  // in param
  const char *name;
  // output
  char *base;
  char *x_start;
  long x_size;
};

int cmp_sonames(const char *, const char *);
int ld_iter(struct ld_data *);
