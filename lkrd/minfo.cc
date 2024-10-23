#include <unordered_map>
#include <fstream>
#include <cstring>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "minfo.h"

class mountinfo
{
  public:
    mountinfo() = default;
    int read(std::string &);
    const char *get_mnt(int id) const;
  protected:
    std::unordered_map<int, std::string> m_map;
};

const char *mountinfo::get_mnt(int id) const
{
  auto citer = m_map.find(id);
  if ( citer == m_map.end() )
    return NULL;
  return citer->second.c_str();
}

// format of mountinfo file
// 23 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
// first is id
// next - root id
// then dev nodes
// / - ???
// and then path
// so we need find ' / '
int mountinfo::read(std::string &fname)
{
  std::ifstream f;
  f.open(fname);
  if ( !f.is_open() )
    return errno;
  std::string s;
  while( std::getline(f, s) )
  {
    int id = atoi(s.c_str());
    int state = 0;
    const char *c = s.c_str();
    for ( ; *c; c++ )
    {
      if ( *c == '/' && state )
      {
        state++;
        continue;
      }
      if ( *c == ' ' )
      {
        if ( !state )
        {
          state++;
          continue;
        }
        if ( 2 == state )
        {
          c++;
          break;
        }
      }
      state = 0;
    }
#ifdef _DEBUG
 printf("%s id %d c %s\n", s.c_str(), id, c);
#endif
    m_map[id] = c;
  }
  return 0;
}

static mountinfo s_mountinfo;

const char *get_mnt(int id)
{
  return s_mountinfo.get_mnt(id);
}

int init_mountinfo()
{
  std::string path = "/proc/" + std::to_string(getpid()) + "/mountinfo";
  return s_mountinfo.read(path);
}