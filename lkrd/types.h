#pragma once

#ifdef _MSC_VER
#include <windows.h>
typedef unsigned __int64 a64;
typedef __int64 sa64;
#else
typedef unsigned long a64;
typedef long sa64;
typedef unsigned int DWORD;
typedef unsigned int *PDWORD;
typedef long LONG;
#endif
