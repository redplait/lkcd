#include <iostream>
#include "ldso.h"

enum r_dir_status { unknown, nonexisting, existing };

// ripped from https://code.woboq.org/userspace/glibc/sysdeps/generic/ldsodefs.h.html#r_search_path_elem
struct r_search_path_elem
{
    /* This link is only used in the `all_dirs' member of `r_search_path'.  */
    struct r_search_path_elem *next;
    /* Strings saying where the definition came from.  */
    const char *what;
    const char *where;
    /* Basename for this search path element.  The string must end with
       a slash character.  */
    const char *dirname;
    size_t dirnamelen;
    enum r_dir_status status[0];
};

struct r_search_path_struct
{
    struct r_search_path_elem **dirs;
    int malloced;
};

int main(int argc, char **argv)
{
  if ( argc != 2 )
  {
    fprintf(stderr, "Usage: %s path\n", argv[0]);
    return 6;
  }
  ELFIO::elfio rdr;
  if ( !rdr.load( argv[1] ) ) 
  {
     printf( "File %s is not found or it is not an ELF file\n", argv[1] );
     return 1;
  }
  ldso ld(&rdr);
  if ( ld.process() )
  {
    ld.dump();
    std::ifstream f;
    f.open("/proc/self/maps");
    if ( !f.is_open() )
      return errno;
    std::string s;
    int found = 0;
    while( std::getline(f, s) )
    {
      if ( s.length() < 74 )
        continue;
      const char *cs = s.c_str() + 73;
#ifdef _DEBUG
      printf("%s\n", cs);
#endif
      if ( !strcmp(argv[1], cs) )
      {
        found++;
        char *unused = NULL;
        unsigned long addr = strtoul(s.c_str(), &unused, 16);
        printf("base %lX\n", addr);
        char **ldp = (char **)((char *)addr + ld.get_ldp());
        if ( *ldp )
          printf("%p %s\n", *ldp, *ldp);
        else
          printf("%p\n", *ldp);
        ldp = (char **)((char *)addr + ld.get_rtld());
        if ( *ldp )
        {
          printf("%p\n", *ldp);
          r_search_path_struct *rp = (r_search_path_struct *)ldp;
          for ( r_search_path_elem *re = *rp->dirs; re; re = re->next )
          {
            printf("%s %s %s\n", re->what ? re->what : "", re->where ? re->where : "", re->dirname);
          }
        }
        break;
      }
    }
    if ( !found )
      printf("cannot find %s\n", argv[1]);
  }
}
