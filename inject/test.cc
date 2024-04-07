#include <string>
#include <iostream>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

const unsigned char payload[] = {
#include "hm.inc"
};

int inject()
{
 // find marker
 size_t paysize = std::size(payload);
 size_t off = 0;
 for ( size_t i = 0; i < paysize - 8; ++i )
 {
   if ( 'E' != payload[i] ) continue;
   if ( 'b' != payload[i+1] ) continue;
   if ( !strncmp((const char *)(payload + i + 2), "iGusej", 6) ) { off = i; break; }
 }
 if ( !off )
 {
   printf("cannot find marker");
   return 0;
 }
 // alloc
 char *alloced = (char *)mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
 if ( MAP_FAILED == alloced )
 {
   printf("cannot mmap, errno %d (%s)", errno, strerror(errno));
   return 0;
 }
 printf("alloced at %p\n", alloced);
 // copy and fill
 memcpy(alloced, payload, paysize);
 void **tab = (void **)(alloced + off);
 auto c = dlopen("libc.so.6", RTLD_NOLOAD);
 auto sym_m = dlsym(c, "__malloc_hook");
 if ( !sym_m )
 {
   printf("cannot find malloc_hook\n");
   return 0;
 }
 tab[0] = sym_m;
 auto sym_f = dlsym(c, "__free_hook");
 if ( !sym_f )
 {
   printf("cannot find free_hook\n");
   return 0;
 }
 tab[2] = sym_f;
 tab[4] = dlsym(c, "dlopen");
 tab[5] = dlsym(c, "dlsym");
 // mprotect
 if ( mprotect(alloced, 4096, PROT_READ | PROT_EXEC ) )
 {
   printf("cannot mprotect, errno %d (%s)", errno, strerror(errno));
   return 0;
 }
 // set hooks
 *(void **)sym_m = alloced;
 *(void **)sym_f = alloced + 9;
 return 1;
}

int main()
{
  if ( !inject() ) return 1;
  printf("pid %d\n", getpid());
  do {
     std::string s;
     std::cin >> s;
  } while(1);
}