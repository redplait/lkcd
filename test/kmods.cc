#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include "../shared.h"
#include "kmods.h"

struct one_mod
{
  std::string name;
  unsigned long start;
  unsigned long len;
};

class mods_storage
{
  public:
    int read_mods();
    int read_from_driver(int fd);
    int read_from_driver2(int fd);
    const char *find(unsigned long addr);
  protected:
    void fill(unsigned long *buf);
    std::vector<one_mod> m_list;
    static auto constexpr cloj = [](const one_mod &a, const one_mod &b) { return a.start < b.start; };
};

static mods_storage s_mod_stg, s_mod_stg_ex;

const char *mods_storage::find(unsigned long addr)
{
  one_mod tmp;
  tmp.start = addr;
  auto w = std::upper_bound( m_list.begin(), m_list.end(), tmp, cloj);
  if ( w == m_list.begin() )
    return NULL;
  w--;
  if ( (addr >= w->start) &&
         (addr < (w->start + w->len) )
       )
     return w->name.c_str();
  return NULL;
}

void mods_storage::fill(unsigned long *buf)
{
  one_module *mod = (one_module *)(buf + 1);
#ifdef DEBUG
  printf("%ld modules\n", buf[0]);
#endif
  m_list.resize(buf[0]);
  for ( unsigned long cnt = 0; cnt < buf[0]; cnt++, mod++ )
  {
    m_list[cnt].name = mod->name;
    m_list[cnt].start = (unsigned long)mod->base;
    m_list[cnt].len = mod->size;
#ifdef DEBUG
    printf("%s %lX %lX\n", m_list[cnt].name.c_str(), m_list[cnt].start, m_list[cnt].len);
#endif
  }
  std::sort( m_list.begin(), m_list.end(), cloj);
}

int mods_storage::read_from_driver(int fd)
{
  unsigned long args[2] = { 0, 0 };
  int err = ioctl(fd, IOCTL_READ_MODULES, (int *)&args);
  if ( err )
  {
    printf("IOCTL_READ_MODULES count failed, errno %d (%s)\n", errno, strerror(errno));
    return errno;
  }
  if ( !args[0] ) return 0;
  size_t size = sizeof(unsigned long) + sizeof(one_module) * args[0];
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc %lX bytes for modules, errno %d (%s)\n", size, errno, strerror(errno));
    return errno;
  }
  buf[0] = args[0];
  buf[1] = 0;
  err = ioctl(fd, IOCTL_READ_MODULES, (int *)buf);
  if ( err )
  {
    printf("IOCTL_READ_MODULES failed, errno %d (%s)\n", errno, strerror(errno));
    free(buf);
    return errno;
  }
  fill(buf);
  free(buf);
  return 0;
}

int mods_storage::read_from_driver2(int fd)
{
  unsigned long args[2] = { 0, 2 };
  int err = ioctl(fd, IOCTL_READ_MODULES, (int *)&args);
  if ( err )
  {
    printf("IOCTL_READ_MODULES(2) count failed, errno %d (%s)\n", errno, strerror(errno));
    return errno;
  }
  if ( !args[0] ) return 0;
  size_t size = sizeof(unsigned long) + sizeof(one_module) * args[0];
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc %lX bytes for modules, errno %d (%s)\n", size, errno, strerror(errno));
    return errno;
  }
  buf[0] = args[0];
  buf[1] = 2;
  err = ioctl(fd, IOCTL_READ_MODULES, (int *)buf);
  if ( err )
  {
    printf("IOCTL_READ_MODULES(2) failed, errno %d (%s)\n", errno, strerror(errno));
    free(buf);
    return errno;
  }
  fill(buf);
  free(buf);
  return 0;
}

int mods_storage::read_mods()
{
  std::ifstream f;
  f.open("/proc/modules");
  if ( !f.is_open() )
    return errno;
  std::string s;
  while( std::getline(f, s) )
  {
    // find first space
    const char *w = s.c_str();
    while ( *w && !isspace(*w) )
      w++;
    std::string cn(s.c_str(), w);
    one_mod tmp;
    tmp.name = cn;
    tmp.len = atoi(w + 1);
    // now find "Live 0x"
    const char *rest = strstr(w + 1, "Live 0x");
    if ( rest == NULL )
      continue;
    char *end;
    tmp.start = strtoul(rest + 7, &end, 0x10);
    if ( !tmp.start )
     continue;
    m_list.push_back(tmp);
  }
  std::sort( m_list.begin(), m_list.end(), cloj);
  return 0;
}

const char *find_kmod(unsigned long addr)
{
  return s_mod_stg.find(addr);
}


const char *find_kmod_ex(unsigned long addr)
{
  return s_mod_stg_ex.find(addr);
}

int init_kmods(int fd)
{
  if ( !getuid() )
    return s_mod_stg.read_mods();
  return s_mod_stg.read_from_driver(fd);
}

int init_kmod_ex(int fd)
{
  return s_mod_stg_ex.read_from_driver2(fd);
}