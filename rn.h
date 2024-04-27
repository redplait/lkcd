#pragma once
/* There are several bugs to prevent placing string literals into unloaded section like Windows can do
  1) stupid gcc can`t put string literals in section different from .rodata(.str?)
    so this couple of macros try to alloc string in .init.rodata
  2) linux kernel anyway keeps .init.rodata during all driver llfetome so this attempt is useless for now
  3) if you replace __initconst with __attribute__ ((section (".init.text"))) you will get from gcc
'var' causes a section type conflict with ‘init_module’
   Possible solutions (dirty hacks mostly):
  - gcc plugin to force attributes on all string literals reffered from functions in .init.text section
  - patch gcc/varasm.cc function get_section:
      https://github.com/redplait/dwarfdump/commit/5223d8cb7e2bd412f4bceb4c06c50655a3a14bd7
     for gcc12
  - perl script to make .S file from _RN markers like
.section .init.text
label:
.string "your string here"
*/

#define RSection __attribute__ ((__section__ (".init.text")))
// for non-patched gcc change this macro to __initconst
#define RDSection __attribute__ ((__section__ (".init.text")))

// place some string to .init.rodata section
// ugly construction but seems that gcc unable expant ##X## in ""
#define _RN(name) static const char rn_##name##__[] RDSection  =

// get string from .init.rodata section
#define _GN(name) rn_##name##__

// can be used for example in arm64.bti/arm64thunk.c
extern const char report_fmt[];