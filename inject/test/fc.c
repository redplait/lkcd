#include <stdio.h>
#include <math.h>

const double non_static_arr[4] = { 0.1, 0.22, 0.33, 0.44 };
static const double s_arr[4] = { -0.1, 0.22, -0.33, 0.44 };
static const char fmt_msg[] = "enter with %d\n";

double senseless_calc(int _i)
{
  double res = 0.0;
  int i;
  printf(fmt_msg, _i);
  for ( i = 0; i < _i && i < sizeof(s_arr) / sizeof(s_arr[0]); i++ )
  {
    res += asin(non_static_arr[i]) + atan(s_arr[i]);
  }
  printf("const string %f\n", res);
  return res + 0.1415;
}

double __attribute__ ((section (".init.text"))) fake_init(int i)
{
  printf("fake_init called, arg %d\n", i);
  return senseless_calc(i);
}