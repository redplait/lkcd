#include <map>
#include <fstream>
#include <cstring>
#include <sys/utsname.h>
#include "kopts.h"

class kopts
{
  public:
   kopts() = default;
   int init();
   int has_option(const char *optname)
   {
     if ( optname == NULL )
       return 0;
     auto iter = m_kopts.find(optname);
     if ( iter == m_kopts.end() )
       return 0;
     return 1;
   }
   const char *get_option(const char *optname)
   {
     if ( optname == NULL )
       return NULL;
     auto iter = m_kopts.find(optname);
     if ( iter == m_kopts.end() )
       return NULL;
     return iter->second.c_str();
   }
  protected:
   struct utsname m_uname;
   // kopts
   std::map<std::string, std::string> m_kopts;
};

int kopts::init()
{
  if ( uname(&m_uname) == -1 )
  {
    printf("cannot uname, error %d\n", errno);
    return errno;
  }
  printf("kernel %s\n", m_uname.release);
  // make filename
  std::string cname = "/boot/config-";
  cname += m_uname.release;
  printf("try read config %s\n", cname.c_str());
  std::ifstream f;
  f.open(cname);
  if ( !f.is_open() )
  {
    printf("cannot open %s\n", cname.c_str());
    return errno;
  }
  std::string s;
  while( std::getline(f, s) )
  {
    // find first space
    const char *w = s.c_str();
    while ( *w && isspace(*w) )
      w++;
    if ( !*w )
      continue;
    if ( *w == '#' )
      continue;
    const char *asgn = w;
    while( *asgn && *asgn != '=' )
      asgn++;
    if ( !*asgn )
      continue;
    std::string keyname(w, asgn-1);
    m_kopts[keyname] = asgn+1;
//    printf("%s %s\n", keyname.c_str(), asgn+1);
  }
  return 0;
}

static kopts s_kopts;

// old plain C interface
int init_kopts()
{
  return s_kopts.init();
}

int has_option(const char *optname)
{
  return s_kopts.has_option(optname);
}

const char *get_option(const char *optname)
{
  return s_kopts.get_option(optname);
}