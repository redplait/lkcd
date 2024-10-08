#ifndef _MSC_VER
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <inttypes.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/genetlink.h>
#endif

#include <iostream>
#include <list>
#include <set>
#include <elfio/elfio_dump.hpp>
#include "ksyms.h"
#include "getopt.h"
#include "x64_disasm.h"
#include "arm64_disasm.h"
#include "arm64relocs.h"
#include "ebpf_disasm.h"
#ifndef _MSC_VER
#include "../shared.h"
#include "kmods.h"
#include "lk.h"
#include "minfo.h"
#include "ujit.h"
#endif

int g_opt_v = 0,
    g_opt_d = 0,
    g_opt_h = 0;
int g_dump_bpf_ops = 0;
int g_event_foff = 0;
std::set<unsigned long> g_kpe, g_kpd; // enable-disable kprobe, key is just address
int g_fd = -1;
int g_kallsyms = 0;

using namespace ELFIO;

void usage(const char *prog)
{
  printf("%s usage: [options] image [symbols]\n", prog);
  printf("Options:\n");
  printf("-B - dump BPF\n");
  printf("-b - check .bss section\n");
  printf("-c - check memory. Achtung - you must first load lkcd driver\n");
  printf("-C - dump consoles\n");
  printf("-d - use disasm\n");
  printf("-F - dump super-blocks\n");
  printf("-f - dump ftraces\n");  
  printf("-g - dump cgroups\n");
  printf("-h - hexdump\n");
  printf("-j jit.so\n");
  printf("-H - dump BPF opcodes\n");
  printf("-K - dump keys\n");
  printf("-k - dump kprobes\n");
  printf("-kp addr byte - patch kernel\n");
  printf("-kpd addr - disable kprobe\n");
  printf("-kpe addr - enable kprobe\n");
  printf("-m - dump (zpool) drivers\n");
  printf("-M - scan virtual memory, WARNING: highly dangerous experimental feature\n");
  printf("-n - dump nets\n");
  printf("-p PID list. mutually exclusive option with -s\n");
  printf("-r - check .rodata section\n");
  printf("-S - check security_hooks\n");
  printf("-s - check fs_ops for sysfs files\n");
  printf("-t - dump tracepoints\n");
  printf("-T - dump timers\n");
  printf("-u - dump usb_monitor\n");
  printf("-v - verbose mode\n");
  exit(6);
}

inline void margin(int idx) {
  for ( int i = 0; i < idx; i++ ) putc(' ', stdout);
}

void rcf(const char *name)
{
  fprintf(stderr, "cannot find %s\n", name);
}

void rcf(const char *fname, const char *name)
{
  fprintf(stderr, "%s: cannot find %s\n", fname, name);
}

static a64 s_security_hook_heads = 0;

#include "lsm.inc"
#include "thunks.inc"

section* find_section(const elfio& reader, a64 addr)
{
  Elf_Half n = reader.sections.size();
  for ( Elf_Half i = 0; i < n; ++i ) 
  {
    section* sec = reader.sections[i];
    auto start = sec->get_address();
    if ( (addr >= start) &&
         addr < (start + sec->get_size())
       )
      return sec;
  }
  return NULL;
}

const char *find_addr(const elfio& reader, a64 addr)
{
  section *s = find_section(reader, addr);
  if ( NULL == s )
    return NULL;
  if ( s->get_type() & SHT_NOBITS )
    return NULL;
  return s->get_data() + (addr - s->get_address());
}

void dump_time(time_t *t, bool endl = true)
{
  struct tm tm;
  localtime_r(t, &tm);
  char ts[260];
  strftime(ts, sizeof(ts) - 1, "%c", &tm);
  ts[sizeof(ts) - 1] = 0;
  if ( endl )
   printf("%s\n", ts);
  else
   printf("%s", ts);
}

template <typename F>
void dump_arm64_ftraces(const elfio& reader, a64 start, a64 end, F func)
{
  Elf_Half n = reader.sections.size();
  if ( !n )
    return;
  for ( Elf_Half i = 0; i < n; ++i ) 
  {
    section* sec = reader.sections[i];
    if ( sec->get_type() == SHT_RELA )
    {
      const_relocation_section_accessor rsa(reader, sec);
      Elf_Xword relno = rsa.get_entries_num();
      for ( int i = 0; i < relno; i++ )
      {
         Elf64_Addr offset;
         Elf_Word   symbol;
         Elf_Word   type;
         Elf_Sxword addend;
         rsa.get_entry(i, offset, symbol, type, addend);
         if ( offset < start || offset > end )
           continue;
         if ( type != R_AARCH64_RELATIVE )
           continue;
         func(addend);
      }
    }
  }
}

size_t filter_arm64_relocs(const elfio& reader, a64 start, a64 end, a64 fstart, a64 fend, std::map<a64, a64> &filled)
{
  size_t res = 0;
  Elf_Half n = reader.sections.size();
  if ( !n )
    return 0;
  for ( Elf_Half i = 0; i < n; ++i ) 
  {
    section* sec = reader.sections[i];
    if ( sec->get_type() == SHT_RELA )
    {
      const_relocation_section_accessor rsa(reader, sec);
      Elf_Xword relno = rsa.get_entries_num();
      for ( int i = 0; i < relno; i++ )
      {
         Elf64_Addr offset;
         Elf_Word   symbol;
         Elf_Word   type;
         Elf_Sxword addend;
         rsa.get_entry(i, offset, symbol, type, addend);
         if ( offset < start || offset > end )
           continue;
         if ( type != R_AARCH64_RELATIVE )
           continue;
         if ( addend >= fstart && addend < fend )
         {
           filled[offset] = addend;
           res++;
         }
      }
    }
  }
  return res;
}

void dump_patched(a64 curr_addr, char *ptr, char *arg, sa64 delta)
{
   size_t off = 0;
   const char *name = lower_name_by_addr_with_off(curr_addr, &off);
   if ( name != NULL )
   {
     const char *pto = name_by_addr((a64)(arg - delta));
     if ( pto != NULL )
     {
        if ( off )
          printf("mem at %p (%s+%lX) patched to %p (%s)\n", ptr, name, off, arg, pto);
        else
          printf("mem at %p (%s) patched to %p (%s)\n", ptr, name, arg, pto);
      } else {
        if ( off )
          printf("mem at %p (%s+%lX) patched to %p\n", ptr, name, off, arg);
        else
          printf("mem at %p (%s) patched to %p\n", ptr, name, arg);
      }
  } else
     printf("mem at %p patched to %p\n", ptr, arg);
}

void dump_and_check(int opt_c, sa64 delta, int has_syms, std::map<a64, a64> &filled)
{
  for ( auto &c: filled )
  {
    auto curr_addr = c.first;
    auto addr = c.second;
    if ( g_opt_v )
    {
      size_t off = 0;
      const char *name = lower_name_by_addr_with_off(curr_addr, &off);
      if ( name != NULL )
      {
         const char *pto = name_by_addr(addr);
         if ( pto != NULL )
         {
           if ( off )
             printf("# %s+%lX -> %s\n", name, off, pto);
           else
             printf("# %s -> %s\n", name, pto);
           } else {
             if ( off )
               printf("# %s+%lX\n", name, off);
             else
               printf("# %s\n", name);
           }
         }
         printf("%p\n", (void *)curr_addr);
      }
#ifndef _MSC_VER
      if ( opt_c )
      {
         char *ptr = (char *)curr_addr + delta;
         char *arg = ptr;
         int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
         if ( err )
         {
           printf("read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
           continue;
         }
         char *real = (char *)addr + delta;
         if ( real != arg )
         {
           if ( is_inside_kernel((unsigned long)arg) )
           {
              if ( !has_syms )
                printf("mem at %p: %p (must be %p)\n", ptr, arg, real);
              else 
              {
                size_t off = 0;
                const char *name = lower_name_by_addr_with_off(curr_addr, &off);
                if ( name != NULL )
                {
                  const char *pto = name_by_addr((a64)(arg - delta));
                  if ( pto != NULL )
                  {
                     if ( off )
                       printf("mem at %p (%s+%lX) patched to %p (%s)\n", ptr, name, off, arg, pto);
                     else
                       printf("mem at %p (%s) patched to %p (%s)\n", ptr, name, arg, pto);
                   } else {
                     if ( off )
                       printf("mem at %p (%s+%lX) patched to %p\n", ptr, name, off, arg);
                     else
                       printf("mem at %p (%s) patched to %p\n", ptr, name, arg);
                   }
                } else
                   printf("mem at %p: %p (must be %p)\n", ptr, arg, real);
              }
           } else 
           { // address not in kernel
              const char *mname = find_kmod((unsigned long)arg);
              if ( mname )
                printf("mem at %p: %p (must be %p) - patched by %s\n", ptr, arg, real, mname);
              else
                printf("mem at %p: %p (must be %p) - patched by UNKNOWN\n", ptr, arg, real);
            }
         }
      } /* opt_c */
#endif /* !_MSC_VER */
  }
}

#ifndef _MSC_VER
char *extract_name(unsigned long l, ksym_params &kp)
{
  kp.addr = l;
  int err = ioctl(g_fd, IOCTL_LOOKUP_SYM, (int *)&kp);
  if ( err ) return NULL;
  return kp.name;
}

#define GET_NAME(l) const char *sname = NULL; ksym_params tmp_kp; \
  if ( g_kallsyms ) sname = name_by_addr(l); \
  else sname = extract_name(l, tmp_kp);

void dump_unnamed_kptr(unsigned long l, sa64 delta, bool skip_unknown = false)
{
  if ( is_inside_kernel(l) )
  {
    const char *sname = name_by_addr(l - delta);
    if (sname != NULL)
      printf(" %p - kernel!%s\n", (void *)l, sname);
    else
      printf(" %p - kernel\n", (void *)l);
  } else {
    const char *mname = find_kmod(l);
    if ( mname )
    {
      GET_NAME(l);
      if ( sname )
        printf(" %p - %s!%s\n", (void *)l, mname, sname);
      else
        printf(" %p - %s\n", (void *)l, mname);
    } else {
     if ( !skip_unknown )
       printf(" %p UNKNOWN\n", (void *)l);
     else
       printf(" %p\n", (void *)l);
    }
  }
}

void dump_kptr(unsigned long l, const char *name, sa64 delta)
{
  if (is_inside_kernel(l))
  {
    const char *sname = name_by_addr(l - delta);
    if (sname != NULL)
      printf(" %s: %p - kernel!%s\n", name, (void *)l, sname);
    else
      printf(" %s: %p - kernel\n", name, (void *)l);
  }
  else {
    const char *mname = find_kmod(l);
    if (mname)
    {
      GET_NAME(l);
      if ( sname )
        printf(" %s: %p - %s!%s\n", name, (void *)l, mname, sname);
      else
        printf(" %s: %p - %s\n", name, (void *)l, mname);
    } else
      printf(" %s: %p - UNKNOWN\n", name, (void *)l);
  }
}

// dump pointer belonging to some module or allocated in heap
// in last case don`t print UNKNOWN like dump_kptr do
void dump_kptr2(unsigned long l, const char *name, sa64 delta)
{
  if (is_inside_kernel(l))
  {
    const char *sname = name_by_addr(l - delta);
    if (sname != NULL)
      printf(" %s: %p - kernel!%s\n", name, (void *)l, sname);
    else
      printf(" %s: %p - kernel\n", name, (void *)l);
  }
  else {
    const char *mname = find_kmod(l);
    if (mname)
    {
      GET_NAME(l);
      if ( sname )
        printf(" %s: %p - %s!%s\n", name, (void *)l, mname, sname);
      else
        printf(" %s: %p - %s\n", name, (void *)l, mname);
    } else
      printf(" %s: %p\n", name, (void *)l);
  }
}

int dump_pte_addr(unsigned long l)
{
  if ( is_inside_kernel(l) ) {
   printf(" kernel");
   return 1;
  }
  const char *mname = find_kmod_ex(l);
  if ( mname ) {
    printf(" %s", mname);
    return 2;
  }
  return 0;
}

// some template magic
template <typename T>
class dumb_free
{
  public:
   dumb_free()
   {
     m_ptr = NULL;
   }
   dumb_free(T *ptr)
    : m_ptr(ptr)
   { }
   ~dumb_free()
   {
     if ( m_ptr )
       free(m_ptr);
   }
   void operator=(T *arg)
   {
     if ( (m_ptr != NULL) && (m_ptr != arg) )
       free(m_ptr);
     m_ptr = arg;
   }
  protected:
   void *m_ptr;
};

void patch_kernel(std::map<unsigned long, unsigned char> &what)
{
  unsigned long args[2];
  for ( auto iter: what )
  {
    args[0] = iter.first;
    args[1] = iter.second;
    int err = ioctl(g_fd, IOCTL_PATCH_KTEXT1, (int *)args);
    if ( err )
      printf("IOCTL_PATCH_KTEXT1 on %p failed, error %d (%s)\n", (void *)iter.first, errno, strerror(errno));
  }
}

template <typename T>
size_t calc_data_size(size_t n)
{
  return n * sizeof(T) + sizeof(unsigned long);
}

void dump_keys(sa64 delta)
{
  unsigned long cnt = 0;
  int err = ioctl(g_fd, IOCTL_KEY_TYPES, (int *)&cnt);
  if ( err )
  {
    printf("IOCTL_KEY_TYPES count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("registered key types: %ld\n", cnt);
  if ( !cnt )
    return;
  size_t size = calc_data_size<one_key_type>(cnt);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for key types, len %lX\n", size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = cnt;
  err = ioctl(g_fd, IOCTL_KEY_TYPES, (int *)buf);
  if ( err )
  {
    printf("IOCTL_KEY_TYPES failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  // dump
  size = buf[0];
  one_key_type *curr = (one_key_type *)(buf + 1);
  // calc max name length
  size_t len = sizeof(unsigned long);
  for ( size_t idx = 0; idx < size; idx++ )
    len = std::max(len, curr[idx].len_name + 1);
  char *kt_name = (char *)malloc(len);
  std::map<void *, std::string> t_names;
  for ( size_t idx = 0; idx < size; idx++, curr++ )
  {
    bool has_name = false;
    if ( curr->len_name && kt_name )
    {
      *(unsigned long *)kt_name = (unsigned long)curr->addr;
      if ( !ioctl(g_fd, IOCTL_KEYTYPE_NAME, (int *)kt_name) ) has_name = true;
    }
    if ( has_name )
    {
      printf("[%ld] %s at %p def_datalen %lX\n", idx, kt_name, curr->addr, curr->def_datalen);
      t_names[curr->addr] = kt_name;
    } else
      printf("[%ld] at %p def_datalen %lX\n", idx, curr->addr, curr->def_datalen);
    if ( curr->vet_description )
      dump_kptr((unsigned long)curr->vet_description, "  vet_description", delta);
    if ( curr->preparse )
      dump_kptr((unsigned long)curr->preparse, "  preparse", delta);
    if ( curr->free_preparse )
      dump_kptr((unsigned long)curr->free_preparse, "  free_preparse", delta);
    if ( curr->instantiate )
      dump_kptr((unsigned long)curr->instantiate, "  instantiate", delta);
    if ( curr->update )
      dump_kptr((unsigned long)curr->update, "  update", delta);
    if ( curr->match_preparse )
      dump_kptr((unsigned long)curr->match_preparse, "  match_preparse", delta);
    if ( curr->match_free )
      dump_kptr((unsigned long)curr->match_free, "  match_free", delta);
    if ( curr->revoke )
      dump_kptr((unsigned long)curr->revoke, "  revoke", delta);
    if ( curr->destroy )
      dump_kptr((unsigned long)curr->destroy, "  destroy", delta);
    if ( curr->describe )
      dump_kptr((unsigned long)curr->describe, "  describe", delta);
    if ( curr->read )
      dump_kptr((unsigned long)curr->read, "  read", delta);
    if ( curr->request_key )
      dump_kptr((unsigned long)curr->request_key, "  request_key", delta);
    if ( curr->lookup_restriction )
      dump_kptr((unsigned long)curr->lookup_restriction, "  lookup_restriction", delta);
    if ( curr->asym_query )
      dump_kptr((unsigned long)curr->asym_query, "  asym_query", delta);
    if ( curr->asym_eds_op )
      dump_kptr((unsigned long)curr->asym_eds_op, "  asym_eds_op", delta);
    if ( curr->asym_verify_signature )
      dump_kptr((unsigned long)curr->asym_verify_signature, "  asym_verify_signature", delta);
  }
  if ( kt_name ) free(kt_name);
  kt_name = 0;
  // enum keys
  cnt = 0;
  err = ioctl(g_fd, IOCTL_ENUM_KEYS, (int *)&cnt);
  if ( err )
  {
    printf("IOCTL_ENUM_KEYS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\n%ld registered keys\n", cnt);
  size_t klen = calc_data_size<one_key>(cnt);
  unsigned long *kbuf = (unsigned long *)malloc(klen);
  if ( !kbuf )
  {
    printf("cannot alloc buffer for keys, len %lX\n", klen);
    return;
  }
  dumb_free<unsigned long> tmp2(kbuf);
  kbuf[0] = cnt;
  err = ioctl(g_fd, IOCTL_ENUM_KEYS, (int *)kbuf);
  if ( err )
  {
    printf("IOCTL_ENUM_KEYS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  // calc max description length & key len
  len = 0;
  const unsigned short k_add = (unsigned short)(sizeof(unsigned long) * 2);
  unsigned short key_len = 0;
  one_key *kc = (one_key *)(kbuf + 1);
  for ( size_t idx = 0; idx < kbuf[0]; idx++ )
  {
    int ld = kc[idx].len_desc & 0xffff;
    // description
    if ( ld )
      len = std::max(len, (size_t)(ld + 1));
    if ( kc[idx].datalen )
      key_len = std::max(kc[idx].datalen, key_len);
  }
  if ( len ) // IOCTL_GET_KEY_DESC has 1 arg
    len = std::max(sizeof(unsigned long), len);
  if ( key_len ) // IOCTL_READ_KEY has 2 args
    key_len = std::max(k_add, key_len);
  len = std::max(len, (size_t)key_len);
  if ( len )
    kt_name = (char *)malloc(len);
  // iterate on keys
  kc = (one_key *)(kbuf + 1);
  for ( size_t idx = 0; idx < kbuf[0]; idx++, kc++ )
  {
    auto titer = t_names.find(kc->type);
    if ( titer == t_names.end() )
      printf(" [%ld] %p serial %lX uid %d gid %d state %d perm %X flags %lX type %p len %d\n",
        idx, kc->addr, kc->serial, kc->uid, kc->gid, kc->state, kc->perm, kc->flags, kc->type, kc->datalen
      );
    else
      printf(" [%ld] %p serial %lX uid %d gid %d state %d perm %X flags %lX type %p (%s) len %d\n",
        idx, kc->addr, kc->serial, kc->uid, kc->gid, kc->state, kc->perm, kc->flags, kc->type, titer->second.c_str(), kc->datalen
      );
    int dlen = kc->len_desc & 0xffff;
    if ( dlen )
    {
      printf("  desc_len %X\n", dlen);
      bool has_desc = false;
      if ( kt_name )
      {
        *(unsigned long *)kt_name = (unsigned long)kc->serial;
        if ( !ioctl(g_fd, IOCTL_GET_KEY_DESC, (int *)kt_name) ) has_desc = true;
      }
      if ( has_desc ) printf("  desc: %s\n", kt_name);
    }
    if ( kc->datalen && kt_name )
    {
      unsigned long *kargs = (unsigned long *)kt_name;
      kargs[0] = kc->serial;
      kargs[1] = kc->datalen;
      err = ioctl(g_fd, IOCTL_READ_KEY, (int *)kt_name);
      if ( err )
        printf("IOCTL_READ_KEY failed, error %d (%s)\n", errno, strerror(errno));
      else
        HexDump((unsigned char *)kt_name, kc->datalen);
    }
    if ( kc->expiry )
    {
      printf("  expiry: ");
      dump_time((time_t *)&kc->expiry);
    }
    if ( kc->last_used )
    {
      printf("  last_used: ");
      dump_time((time_t *)&kc->last_used);
    }
  }
  if ( kt_name ) free(kt_name);
}

template <typename T, typename F>
void apply_for_each(unsigned long *buf, F func)
{
  size_t size = buf[0];
  T *curr = (T *)(buf + 1);
  for ( size_t idx = 0; idx < size; idx++, curr++ )
    func(idx, curr);
}

template <typename T, typename F>
void dump_data_noarg(int code, const char *ioctl_name, const char *bname, F func)
{
  unsigned long arg = 0;
  int err = ioctl(g_fd, code, (int *)&arg);
  if ( err )
  {
    printf("%s count failed, error %d (%s)\n", ioctl_name, errno, strerror(errno));
    return;
  }
  printf("\n%s count: %ld\n", bname, arg);
  if ( !arg )
    return;
  size_t size = calc_data_size<T>(arg);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for %s, len %lX\n", bname, size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = arg;
  err = ioctl(g_fd, code, (int *)buf);
  if ( err )
    printf("%s failed, error %d (%s)\n", ioctl_name, errno, strerror(errno));
  else
    apply_for_each<T>(buf, func);
}

template <typename T, typename F>
void dump_data_ul1(unsigned long a1, int code, const char *ioctl_name, const char *bname, F func)
{
  unsigned long args[2] = { a1, 0 };
  int err = ioctl(g_fd, code, (int *)args);
  if ( err )
  {
    printf("%s(%ld) count failed, error %d (%s)\n", ioctl_name, a1, errno, strerror(errno));
    return;
  }
  printf("\n%s count: %ld\n", bname, args[0]);
  if ( !args[0] )
    return;
  size_t size = calc_data_size<T>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for %s, len %lX\n", bname, size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = a1;
  buf[1] = args[0];
  err = ioctl(g_fd, code, (int *)buf);
  if ( err )
    printf("%s(%ld) failed, error %d (%s)\n", ioctl_name, a1, errno, strerror(errno));
  else
    apply_for_each<T>(buf, func);
}

template <typename T, typename F>
void dump_data_ul2(unsigned long a1, unsigned long a2, sa64 delta, int code, const char *ioctl_name, const char *bname, F func)
{
  unsigned long args[3] = { a1, a2, 0 };
  int err = ioctl(g_fd, code, (int *)args);
  if ( err )
  {
    printf("%s(%ld, %ld) count failed, error %d (%s)\n", ioctl_name, a1, a2, errno, strerror(errno));
    return;
  }
  printf("\n%s count: %ld\n", bname, args[0]);
  if ( !args[0] )
    return;
  size_t size = calc_data_size<T>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for %s, len %lX\n", bname, size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = a1;
  buf[2] = a2;
  buf[2] = args[0];
  err = ioctl(g_fd, code, (int *)buf);
  if ( err )
    printf("%s(%ld, %ld) failed, error %d (%s)\n", ioctl_name, a1, a2, errno, strerror(errno));
  else
    apply_for_each<T>(buf, func);
}

void dump_consoles(sa64 delta)
{
  dump_data_noarg<one_console>(IOCTL_READ_CONSOLES, "IOCTL_READ_CONSOLES", "registered consoles",
   [=](size_t idx, const one_console *curr) {
    printf("[%ld] %s at %p flags %X index %d\n", idx, curr->name, curr->addr, curr->flags, curr->index);
    if ( curr->write )
      dump_kptr((unsigned long)curr->write, "  write", delta);
    if ( curr->read )
      dump_kptr((unsigned long)curr->read, "  read", delta);
    if ( curr->device )
      dump_kptr((unsigned long)curr->device, "  device", delta);
    if ( curr->unblank )
      dump_kptr((unsigned long)curr->unblank, "  unblank", delta);
    if ( curr->setup )
      dump_kptr((unsigned long)curr->setup, "  setup", delta);
    if ( curr->exit )
      dump_kptr((unsigned long)curr->exit, "  exit", delta);
    if ( curr->match )
      dump_kptr((unsigned long)curr->match, "  match", delta);
  });
}

void dump_binfmt(sa64 delta)
{
  dump_data_noarg<one_binfmt>(IOCTL_BINFMT, "IOCTL_BINFMT", "binfmts",
   [=](size_t idx, const one_binfmt *zp) {
    printf("[%ld] at ", idx);
    dump_unnamed_kptr((unsigned long)zp->addr, delta, true);
    if ( zp->mod ) printf(" owner: %p\n", zp->mod);
    if ( zp->load_binary ) dump_kptr((unsigned long)zp->load_binary, "load_binary", delta);
    if ( zp->load_shlib ) dump_kptr((unsigned long)zp->load_shlib, "load_shlib", delta);
    if ( zp->core_dump ) dump_kptr((unsigned long)zp->core_dump, "core_dump", delta);
   });
}

void dump_pools(sa64 delta)
{
  dump_data_noarg<one_zpool>(IOCTL_GET_ZPOOL_DRV, "IOCTL_GET_ZPOOL_DRV", "zpool_drivers",
   [=](size_t idx, const one_zpool *zp) {
    printf("[%ld] at ", idx);
    dump_unnamed_kptr((unsigned long)zp->addr, delta, true);
    if ( zp->module ) printf(" owner: %p\n", zp->module);
    if ( zp->create ) dump_kptr(zp->create, "create", delta);
    if ( zp->destroy ) dump_kptr(zp->destroy, "destroy", delta);
    if ( zp->malloc ) dump_kptr(zp->malloc, "malloc", delta);
    if ( zp->free ) dump_kptr(zp->free, "free", delta);
    if ( zp->shrink ) dump_kptr(zp->shrink, "shrink", delta);
    if ( zp->map ) dump_kptr(zp->map, "map", delta);
    if ( zp->unmap ) dump_kptr(zp->unmap, "unmap", delta);
    if ( zp->total_size ) dump_kptr(zp->total_size, "total_size", delta);
   }
  );
}

int read_ioctled_name(void *addr, unsigned long len, char *buf, int _ctl)
{
  unsigned long *args = (unsigned long *)buf;
  args[0] = (unsigned long)addr;
  args[1] = len;
  int err = ioctl(g_fd, _ctl, (int *)args);
  return err ? 0 : 1;
}

void dump_slabs(sa64 delta)
{
  unsigned int args_size = 2 * sizeof(unsigned long);
  char *name_buf = nullptr;
  size_t name_len = 0;
  dump_data_noarg<one_slab>(IOCTL_GET_SLABS, "IOCTL_GET_SLABS", "kmem_caches",
   [&](size_t idx, const one_slab *sl) {
     printf("[%ld] at", idx);
     dump_unnamed_kptr((unsigned long)sl->addr, delta, true);
     if ( sl->l_name ) {
      auto cl = std::max(sl->l_name, args_size);
      if ( cl > name_len ) {
        if ( name_buf ) free(name_buf);
        name_buf = (char *)malloc(cl);
        if (name_buf) name_len = cl; else cl = name_len = 0;
      }
      if ( cl && read_ioctled_name(sl->addr, cl, name_buf, IOCTL_SLAB_NAME) ) {
       printf(" Name: %s\n", name_buf);
      }
     }
     if ( sl->size ) printf(" size %d\n", sl->size);
     if ( sl->object_size ) printf(" object_size %d\n", sl->size);
     if ( sl->ctor ) dump_kptr(sl->ctor, "ctor", delta);
   }
  );
  if ( name_buf ) free(name_buf);
}

template <typename T, typename F>
void dump_data1arg(a64 list, sa64 delta, int code, const char *header, const char *ioctl_name, const char *bname, F func)
{
  unsigned long args[2] = { list + delta, 0 };
  int err = ioctl(g_fd, code, (int *)args);
  if ( err )
  {
    printf("%s count failed, error %d (%s)\n", ioctl_name, errno, strerror(errno));
    return;
  }
  if ( header )
    printf("\n%s at %p: %ld\n", header, (void *)(list + delta), args[0]);
  else
    printf("\n%ld %s\n", args[0], bname);
  if ( !args[0] )
    return;
  size_t size = calc_data_size<T>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for %s, len %lX\n", bname, size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = list + delta;
  buf[1] = args[0];
  err = ioctl(g_fd, code, (int *)buf);
  if ( err )
    printf("%s failed, error %d (%s)\n", ioctl_name, errno, strerror(errno));
  else
    apply_for_each<T>(buf, func);
}

template <typename T, typename F>
void dump_data2arg(a64 list, a64 lock, sa64 delta, int code, const char *header, const char *ioctl_name, const char *bname, F func)
{
  unsigned long args[3] = { list + delta, lock + delta, 0 };
  int err = ioctl(g_fd, code, (int *)args);
  if ( err )
  {
    printf("%s count failed, error %d (%s)\n", ioctl_name, errno, strerror(errno));
    return;
  }
  printf("\n%s at %p: %ld\n", header, (void *)(list + delta), args[0]);
  if ( !args[0] )
    return;
  size_t size = calc_data_size<T>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for %s, len %lX\n", bname, size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = list + delta;
  buf[1] = lock + delta;
  buf[2] = args[0];
  err = ioctl(g_fd, code, (int *)buf);
  if ( err )
    printf("%s failed, error %d (%s)\n", ioctl_name, errno, strerror(errno));
  else
    apply_for_each<T>(buf, func);
}

// ripped from https://elixir.bootlin.com/linux/v5.11/source/include/uapi/linux/bpf.h#L171
static const char *const bpf_prog_type_names[] = {
 "BPF_PROG_TYPE_UNSPEC",
 "BPF_PROG_TYPE_SOCKET_FILTER",
 "BPF_PROG_TYPE_KPROBE",
 "BPF_PROG_TYPE_SCHED_CLS",
 "BPF_PROG_TYPE_SCHED_ACT",
 "BPF_PROG_TYPE_TRACEPOINT",
 "BPF_PROG_TYPE_XDP",
 "BPF_PROG_TYPE_PERF_EVENT",
 "BPF_PROG_TYPE_CGROUP_SKB",
 "BPF_PROG_TYPE_CGROUP_SOCK",
 "BPF_PROG_TYPE_LWT_IN",
 "BPF_PROG_TYPE_LWT_OUT",
 "BPF_PROG_TYPE_LWT_XMIT",
 "BPF_PROG_TYPE_SOCK_OPS",
 "BPF_PROG_TYPE_SK_SKB",
 "BPF_PROG_TYPE_CGROUP_DEVICE",
 "BPF_PROG_TYPE_SK_MSG",
 "BPF_PROG_TYPE_RAW_TRACEPOINT",
 "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
 "BPF_PROG_TYPE_LWT_SEG6LOCAL",
 "BPF_PROG_TYPE_LIRC_MODE2",
 "BPF_PROG_TYPE_SK_REUSEPORT",
 "BPF_PROG_TYPE_FLOW_DISSECTOR",
 "BPF_PROG_TYPE_CGROUP_SYSCTL",
 "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
 "BPF_PROG_TYPE_CGROUP_SOCKOPT",
 "BPF_PROG_TYPE_TRACING",
 "BPF_PROG_TYPE_STRUCT_OPS",
 "BPF_PROG_TYPE_EXT",
 "BPF_PROG_TYPE_LSM",
 "BPF_PROG_TYPE_SK_LOOKUP",
 "BPF_PROG_TYPE_SYSCALL",
 "BPF_PROG_TYPE_NETFILTER",
};

static const char *get_bpf_prog_type_name(int idx)
{
  if ( idx >= sizeof(bpf_prog_type_names) / sizeof(bpf_prog_type_names[0]) )
    return "";
  return bpf_prog_type_names[idx];
}

void dump_verops(sa64 delta)
{
  dump_data_noarg<one_bpf_verops>(IOCTL_BPF_VEROPS, "IOCTL_BPF_VEROPS", "bpf_verifier_ops",
   [=](size_t idx, const one_bpf_verops *vp) {
    auto pt = get_bpf_prog_type_name(vp->idx);
    if ( *pt )
      printf("[%ld] type %s at", idx, pt);
    else
      printf("[%ld] type %d at", idx, vp->idx);
    dump_unnamed_kptr((unsigned long)vp->addr, delta, true);
    if ( vp->get_func_proto ) dump_kptr(vp->get_func_proto, " get_func_proto", delta);
    if ( vp->is_valid_access ) dump_kptr(vp->is_valid_access, " is_valid_access", delta);
    if ( vp->gen_prologue ) dump_kptr(vp->gen_prologue, " gen_prologue", delta);
    if ( vp->gen_ld_abs ) dump_kptr(vp->gen_ld_abs, " gen_ld_abs", delta);
    if ( vp->convert_ctx_access ) dump_kptr(vp->convert_ctx_access, " convert_ctx_access", delta);
    if ( vp->btf_struct_access ) dump_kptr(vp->btf_struct_access, " btf_struct_access", delta);
   }
  );
}

void dump_struct_ops(sa64 delta)
{
  unsigned long cnt = -1;
  int err = ioctl(g_fd, IOCTL_GET_BTF, (int *)&cnt);
  if ( err )
  {
    printf("IOCTL_GET_BTF cnt failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\nNR_BTF_KINDS: %ld\n", cnt);
  btf_op ops;
  unsigned long *arg = (unsigned long *)&ops;
  for ( unsigned long i = 0; i < cnt; i++ )
  {
    *arg = i;
    err = ioctl(g_fd, IOCTL_GET_BTF, (int *)&ops);
    if ( err )
    {
      if ( errno != ENOENT )
        printf("IOCTL_GET_BTF(%ld) failed, error %d (%s)\n", i, errno, strerror(errno));
      continue;
    }
    printf("btf_ops[%ld] at", i);
    dump_unnamed_kptr((unsigned long)ops.addr, delta, true);
    if ( ops.check_meta )
      dump_kptr(ops.check_meta, " check_meta", delta);
    if ( ops.resolve )
      dump_kptr(ops.resolve, " resolve", delta);
    if ( ops.check_member )
      dump_kptr(ops.check_member, " check_member", delta);
    if ( ops.check_kflag_member )
      dump_kptr(ops.check_kflag_member, " check_kflag_member", delta);
    if ( ops.log_details )
      dump_kptr(ops.log_details, " log_details", delta);
    if ( ops.show )
      dump_kptr(ops.show, " show", delta);
  }
}

void check_bpf_protos(sa64 delta)
{
  std::list<one_bpf_proto> bpf_protos;
  if ( !fill_bpf_protos(bpf_protos) )
    return;
  for ( auto &c: bpf_protos )
  {    
    char *ptr = (char *)c.proto.addr + delta;
    char *arg = ptr;
    int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
    if ( err )
    {
       printf("read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
       continue;
    }
    char *real = (char *)c.func.addr + delta;
    if ( real != arg )
      printf("proto %s at %p patched, func %s at %p must be %p\n", c.proto.name, (char *)c.proto.addr + delta, c.func.name, arg, (char *)c.func.addr + delta);
  }
}

void dump_devfreq_ntfy(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_devfreq_ntfy", "devfreq_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_devfreq_ntfy", "devfreq_list_lock");
    return;
  }
  dump_data2arg<clk_ntfy>(list, lock, delta, READ_DEVFREQ_NTFY, "devfreq_list", "READ_DEVFREQ_NTFY", "clk_ntfy",
   [=](size_t idx, const clk_ntfy *curr) {
    printf(" [%ld] devfreq at %p", idx, (void *)curr->clk);
    dump_kptr((unsigned long)curr->ntfy, " ntfy", delta);
   }
  );
}

void dump_clk_ntfy(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_clk_ntfy", "clk_notifier_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_clk_ntfy", "prepare_lock");
    return;
  }
  dump_data2arg<clk_ntfy>(list, lock, delta, READ_CLK_NTFY, "clk_notifier_list", "READ_CLK_NTFY", "clk_ntfy",
   [=](size_t idx, const clk_ntfy *curr) {
    printf(" [%ld] clk at %p", idx, (void *)curr->clk);
    dump_kptr((unsigned long)curr->ntfy, " ntfy", delta);
   }
  );
}

void dump_ftrace_ops(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_ftrace_ops", "ftrace_ops_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_ftrace_ops", "ftrace_lock");
    return;
  }
  dump_data2arg<one_ftrace_ops>(list, lock, delta, IOCTL_GET_FTRACE_OPS, "ftrace_ops_list", "IOCTL_GET_FTRACE_OPS", "ftrace_ops",
   [=](size_t idx, const one_ftrace_ops *curr) {
    printf(" [%ld] flags %lX at", idx, curr->flags);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->func )
      dump_kptr((unsigned long)curr->func, "  func", delta);
    if ( curr->saved_func )
      dump_kptr((unsigned long)curr->saved_func, "  saved_func", delta);
   }
  );
}

void dump_dynamic_events(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_dynamic_events", "dyn_event_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_dynamic_events", "event_mutex");
    return;
  }
  dump_data2arg<one_tracepoint_func>(list, lock, delta, IOCTL_GET_DYN_EVENTS, "dyn_event_list", "IOCTL_GET_DYN_EVENTS", "dyn_event_list",
   [=](size_t idx, const one_tracepoint_func *curr) {
    printf(" [%ld] at", idx);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->data )
      dump_kptr((unsigned long)curr->data, "  ops", delta);
    }
  );
}

void dump_dynevents_ops(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_dynevents_ops", "dyn_event_ops_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_dynevents_ops", "dyn_event_ops_mutex");
    return;
  }
  dump_data2arg<one_dyn_event_op>(list, lock, delta, IOCTL_GET_DYN_EVT_OPS, "dyn_event_ops_list", "IOCTL_GET_DYN_EVT_OPS", "dynevents_ops",
   [=](size_t idx, const one_dyn_event_op *curr) {
    printf(" [%ld] at", idx);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->create )
      dump_kptr((unsigned long)curr->create, "  create", delta);
    if ( curr->show )
      dump_kptr((unsigned long)curr->show, "  show", delta);
    if ( curr->is_busy )
      dump_kptr((unsigned long)curr->is_busy, "  is_busy", delta);
    if ( curr->free )
      dump_kptr((unsigned long)curr->free, "  free", delta);
    if ( curr->match )
      dump_kptr((unsigned long)curr->match, "  match", delta);
   }
  );
}

void dump_tracefunc_cmds(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_tracefunc_cmds", "ftrace_commands");
    return;
  }
  if ( !lock )
  {
    rcf("dump_tracefunc_cmds", "ftrace_cmd_mutex");
    return;
  }
  dump_data2arg<one_tracefunc_cmd>(list, lock, delta, IOCTL_GET_FTRACE_CMDS, "ftrace_commands", "IOCTL_GET_FTRACE_CMDS", "ftrace_func_commands", 
   [=](size_t idx, const one_tracefunc_cmd *curr) {
    printf(" [%ld] %s at", idx, curr->name);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->func )
      dump_kptr((unsigned long)curr->func, "  func", delta);
   }
  );
}

void dump_trace_exports(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_trace_exports", "ftrace_exports_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_trace_exports", "ftrace_export_lock");
    return;
  }
  dump_data2arg<one_trace_export>(list, lock, delta, IOCTL_GET_TRACE_EXPORTS, "trace_exports", "IOCTL_GET_TRACE_EXPORTS", "trace_exports",
   [=](size_t idx, const one_trace_export *curr) {
    printf(" [%ld] flags %d at", idx, curr->flags);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->write )
      dump_kptr((unsigned long)curr->write, "  write", delta);
    }
  );
}

void dump_perf_guest_cbs(sa64 delta)
{
  perf_cbs pc;
  int err = ioctl(g_fd, IOCTL_PERF_CBS, (int *)&pc);
  if ( err )
  {
    printf("IOCTL_PERF_CBS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  if ( pc.state )
    dump_kptr(pc.state, "state", delta);
  if ( pc.is_in_guest )
    dump_kptr(pc.is_in_guest, "is_in_guest", delta);
  if ( pc.is_user_mode )
    dump_kptr(pc.is_user_mode, "is_user_mode", delta);
  if ( pc.get_guest_ip )
    dump_kptr(pc.get_guest_ip, "get_guest_ip", delta);
  if ( pc.handle_intel_pt_intr )
    dump_kptr(pc.handle_intel_pt_intr, "handle_intel_pt_intr", delta);
}

void dump_pmus(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_pmus", "pmu_idr");
    return;
  }
  if ( !lock )
  {
    rcf("dump_pmus", "pmus_lock");
    return;
  }
  dump_data2arg<one_pmu>(list, lock, delta, IOCTL_GET_PMUS, "pmus", "IOCTL_GET_PMUS", "pmus",
   [=](size_t idx, const one_pmu *curr) {
     printf(" [%ld] type %X capabilities %X at ", idx, curr->type, curr->capabilities);
     dump_unnamed_kptr((unsigned long)curr->addr, delta, true);
     if ( curr->pmu_enable )
       dump_kptr((unsigned long)curr->pmu_enable, "  pmu_enable", delta);
     if ( curr->pmu_disable )
       dump_kptr((unsigned long)curr->pmu_disable, "  pmu_disable", delta);
     if ( curr->event_init )
       dump_kptr((unsigned long)curr->event_init, "  event_init", delta);
     if ( curr->event_mapped )
       dump_kptr((unsigned long)curr->event_mapped, "  event_mapped", delta);
     if ( curr->event_unmapped )
       dump_kptr((unsigned long)curr->event_unmapped, "  event_unmapped", delta);
     if ( curr->add )
       dump_kptr((unsigned long)curr->add, "  add", delta);
     if ( curr->del )
       dump_kptr((unsigned long)curr->del, "  del", delta);
     if ( curr->start )
       dump_kptr((unsigned long)curr->start, "  start", delta);
     if ( curr->stop )
       dump_kptr((unsigned long)curr->stop, "  stop", delta);
     if ( curr->read )
       dump_kptr((unsigned long)curr->read, "  read", delta);
     if ( curr->start_txn )
       dump_kptr((unsigned long)curr->start_txn, "  start_txn", delta);
     if ( curr->commit_txn )
       dump_kptr((unsigned long)curr->commit_txn, "  commit_txn", delta);
     if ( curr->cancel_txn )
       dump_kptr((unsigned long)curr->cancel_txn, "  cancel_txn", delta);
     if ( curr->event_idx )
       dump_kptr((unsigned long)curr->event_idx, "  event_idx", delta);
     if ( curr->sched_task )
       dump_kptr((unsigned long)curr->sched_task, "  sched_task", delta);
     if ( curr->swap_task_ctx )
       dump_kptr((unsigned long)curr->swap_task_ctx, "  swap_task_ctx", delta);
     if ( curr->setup_aux )
       dump_kptr((unsigned long)curr->setup_aux, "  setup_aux", delta);
     if ( curr->free_aux )
       dump_kptr((unsigned long)curr->free_aux, "  free_aux", delta);
     if ( curr->snapshot_aux )
       dump_kptr((unsigned long)curr->snapshot_aux, "  snapshot_aux", delta);
     if ( curr->addr_filters_validate )
       dump_kptr((unsigned long)curr->addr_filters_validate, "  addr_filters_validate", delta);
     if ( curr->addr_filters_sync )
       dump_kptr((unsigned long)curr->addr_filters_sync, "  addr_filters_sync", delta);
     if ( curr->aux_output_match )
       dump_kptr((unsigned long)curr->aux_output_match, "  aux_output_match", delta);
     if ( curr->filter_match )
       dump_kptr((unsigned long)curr->filter_match, "  filter_match", delta);
     if ( curr->check_period )
       dump_kptr((unsigned long)curr->check_period, "  check_period", delta);
   }
  );
}

void dump_event_cmds(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_event_cmds", "trigger_commands");
    return;
  }
  if ( !lock )
  {
    rcf("dump_event_cmds", "trigger_cmd_mutex");
    return;
  }
  dump_data2arg<one_event_command>(list, lock, delta, IOCTL_GET_EVENT_CMDS, "trigger_commands", "IOCTL_GET_EVENT_CMDS", "trigger_commands",
   [=](size_t idx, const one_event_command *curr) {
    printf(" [%ld] %s trigger_type %d flags %d at", idx, curr->name, curr->trigger_type, curr->flags);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->func )
      dump_kptr((unsigned long)curr->func, "  func", delta);
    if ( curr->reg )
      dump_kptr((unsigned long)curr->reg, "  reg", delta);
    if ( curr->unreg )
      dump_kptr((unsigned long)curr->unreg, "  unreg", delta);
    if ( curr->unreg_all )
      dump_kptr((unsigned long)curr->unreg_all, "  unreg_all", delta);
    if ( curr->set_filter )
      dump_kptr((unsigned long)curr->set_filter, "  set_filter", delta);
    if ( curr->get_trigger_ops )
      dump_kptr((unsigned long)curr->get_trigger_ops, "  get_trigger_ops", delta);
   }
  );
}

// ripped from https://elixir.bootlin.com/linux/v5.18/source/include/uapi/linux/bpf.h#L957
static const char *const bpf_attach_type_names[] = {
 "BPF_CGROUP_INET_INGRESS",
 "BPF_CGROUP_INET_EGRESS",
 "BPF_CGROUP_INET_SOCK_CREATE",
 "BPF_CGROUP_SOCK_OPS",
 "BPF_SK_SKB_STREAM_PARSER",
 "BPF_SK_SKB_STREAM_VERDICT",
 "BPF_CGROUP_DEVICE",
 "BPF_SK_MSG_VERDICT",
 "BPF_CGROUP_INET4_BIND",
 "BPF_CGROUP_INET6_BIND",
 "BPF_CGROUP_INET4_CONNECT",
 "BPF_CGROUP_INET6_CONNECT",
 "BPF_CGROUP_INET4_POST_BIND",
 "BPF_CGROUP_INET6_POST_BIND",
 "BPF_CGROUP_UDP4_SENDMSG",
 "BPF_CGROUP_UDP6_SENDMSG",
 "BPF_LIRC_MODE2",
 "BPF_FLOW_DISSECTOR",
 "BPF_CGROUP_SYSCTL",
 "BPF_CGROUP_UDP4_RECVMSG",
 "BPF_CGROUP_UDP6_RECVMSG",
 "BPF_CGROUP_GETSOCKOPT",
 "BPF_CGROUP_SETSOCKOPT",
 "BPF_TRACE_RAW_TP",
 "BPF_TRACE_FENTRY",
 "BPF_TRACE_FEXIT",
 "BPF_MODIFY_RETURN",
 "BPF_LSM_MAC",
 "BPF_TRACE_ITER",
 "BPF_CGROUP_INET4_GETPEERNAME",
 "BPF_CGROUP_INET6_GETPEERNAME",
 "BPF_CGROUP_INET4_GETSOCKNAME",
 "BPF_CGROUP_INET6_GETSOCKNAME",
 "BPF_XDP_DEVMAP",
 "BPF_CGROUP_INET_SOCK_RELEASE",
 "BPF_XDP_CPUMAP",
 "BPF_SK_LOOKUP",
 "BPF_XDP",
 "BPF_SK_SKB_VERDICT",
 "BPF_SK_REUSEPORT_SELECT",
 "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE",
 "BPF_PERF_EVENT",
 "BPF_TRACE_KPROBE_MULTI",
 "BPF_LSM_CGROUP",
 "BPF_STRUCT_OPS",
 "BPF_NETFILTER",
 "BPF_TCX_INGRESS",
 "BPF_TCX_EGRESS",
 "BPF_TRACE_UPROBE_MULTI",
 "BPF_CGROUP_UNIX_CONNECT",
 "BPF_CGROUP_UNIX_SENDMSG",
 "BPF_CGROUP_UNIX_RECVMSG",
 "BPF_CGROUP_UNIX_GETPEERNAME",
 "BPF_CGROUP_UNIX_GETSOCKNAME",
 "BPF_NETKIT_PRIMARY",
 "BPF_NETKIT_PEER",
 "BPF_TRACE_KPROBE_SESSION",
};

static const char *get_bpf_attach_type_name(int idx)
{
  if ( idx >= sizeof(bpf_attach_type_names) / sizeof(bpf_attach_type_names[0]) )
    return "";
  return bpf_attach_type_names[idx];
}

void show_bpf_progs(size_t bpf_size, const one_bpf_prog *curr, sa64 delta)
{
  for ( size_t j = 0; j < bpf_size; j++, curr++ )
  {
    printf("  [%ld] prog %p id %d type %d len %d jited_len %d aux %p used_maps %d used_btf %d func_cnt %d\n", j, curr->prog, curr->aux_id, curr->prog_type, curr->len, curr->jited_len, 
      curr->aux, curr->used_map_cnt, curr->used_btf_cnt, curr->func_cnt);
    printf("        tag:");
    for ( int i = 0; i < 8; i++ )
      printf(" %2.2X", curr->tag[i]);
    printf("\n");
    if ( curr->bpf_func )
      dump_kptr2((unsigned long)curr->bpf_func, "  bpf_func", delta);
  }
}

struct uprobe_args
{
  unsigned long a1, a2, a3, a4;
};

void dump_trace_event_call(size_t idx, one_trace_event_call *curr, sa64 delta, uprobe_args *ua = NULL)
{
    if ( curr->bpf_prog )
    {
      if ( curr->perf_cnt )
        printf(" [%ld] flags %X filter %p perf_cnt %ld bpf_cnt %d at", idx, curr->flags, curr->filter, curr->perf_cnt, curr->bpf_cnt);
      else
        printf(" [%ld] flags %X filter %p bpf_cnt %d at", idx, curr->flags, curr->filter, curr->bpf_cnt);
    } else {
      if ( curr->perf_cnt )
        printf(" [%ld] flags %X filter %p perf_cnt %ld at", idx, curr->flags, curr->filter, curr->perf_cnt);
      else
        printf(" [%ld] flags %X filter %p at", idx, curr->flags, curr->filter);
    }
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->evt_class )
      dump_kptr((unsigned long)curr->evt_class, "  evt_class", delta);
    if ( curr->tp && (curr->flags & 0x10) )
      dump_kptr((unsigned long)curr->tp, "  tp", delta);
    if ( curr->perf_perm )
      dump_kptr((unsigned long)curr->perf_perm, "  perf_perm", delta);
    if ( curr->bpf_prog )
      printf("   bpf_prog: %p\n", (void *)curr->bpf_prog);
    if ( !curr->bpf_cnt )
      return;
    if ( ua )
    {
      // if curr->bpf_cnt == 1 then we already dumped it
      if ( curr->bpf_cnt == 1 )
        return;
      // dump addresses of bpf progs for some uprobe
      const size_t args_size = sizeof(unsigned long) * 5;
      size_t bpf_size = (1 + curr->bpf_cnt) * sizeof(unsigned long);
      size_t bsize = bpf_size;
      if ( bsize < args_size )
        bsize = args_size;
      unsigned long *bpf_buf = (unsigned long *)malloc(bsize);
      if ( !bpf_buf )
      {
        printf("dump_trace_event_call: cannot alloc %ld bytes for uprobe %ld bpf_progs\n", bsize, idx);
        return;
      }
      dumb_free<unsigned long> tmp2(bpf_buf);
      bpf_buf[0] = ua->a1;
      bpf_buf[1] = ua->a2;
      bpf_buf[2] = ua->a3;
      bpf_buf[3] = ua->a4;
      bpf_buf[4] = curr->bpf_cnt;
      int err = ioctl(g_fd, IOCTL_TRACE_UPROBE_BPFS, (int *)bpf_buf);
      if ( err )
      {
        printf("IOCTL_TRACE_UPROBE_BPFS for uprobe %ld bpf_progs failed, error %d (%s)\n", idx, errno, strerror(errno));
        return;
      }
      for ( unsigned long i = 0; i < bpf_buf[0]; ++i )
        printf("  [%ld] %p\n", i, (void *)bpf_buf[i + 1]);
    } else {
      // dump bpf progs for some tracepoint
      size_t bpf_size = calc_data_size<one_bpf_prog>(curr->bpf_cnt);
      unsigned long *bpf_buf = (unsigned long *)malloc(bpf_size);
      if ( !bpf_buf )
      {
        printf("dump_trace_event_call: cannot alloc %ld bytes for tracepoint %ld bpf_progs\n", bpf_size, idx);
        return;
      }
      dumb_free<unsigned long> tmp2(bpf_buf);
      bpf_buf[0] = (unsigned long)curr->addr;
      bpf_buf[1] = curr->bpf_cnt;
      int err = ioctl(g_fd, IOCTL_GET_EVT_CALLS, (int *)bpf_buf);
      if ( err )
      {
        printf("IOCTL_GET_EVT_CALLS for tracepoint %ld bpf_progs failed, error %d (%s)\n", idx, errno, strerror(errno));
        return;
      }
      one_bpf_prog *curr2 = (one_bpf_prog *)(bpf_buf + 1);
      show_bpf_progs(bpf_buf[0], curr2, delta);
   }
}

void dump_registered_trace_event_calls(sa64 delta)
{
  unsigned long args[2] = { 0, 0 };
  int err = ioctl(g_fd, IOCTL_GET_EVT_CALLS, (int *)args);
  if ( err )
  {
    printf("IOCTL_GET_EVT_CALLS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\nregistered trace_event_calls: %ld\n", args[0]);
  if ( !args[0] )
    return;
  size_t size = calc_data_size<one_trace_event_call>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for trace_event_calls, len %lX\n", size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = 0;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_GET_EVT_CALLS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_EVT_CALLS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size = buf[0];
  one_trace_event_call *curr = (one_trace_event_call *)(buf + 1);
  for ( size_t idx = 0; idx < size; idx++, curr++ )
  {
    dump_trace_event_call(idx, curr, delta);
  }
}

void dump_bpf_ksyms(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_bpf_ksyms", "bpf_kallsyms");
    return;
  }
  if ( !lock )
  {
    rcf("dump_bpf_ksyms", "bpf_lock");
    return;
  }
  dump_data2arg<one_bpf_ksym>(list, lock, delta, IOCTL_GET_BPF_KSYMS, "bpf_kallsyms", "IOCTL_GET_BPF_KSYMS", "bpf_ksyms",
   [](size_t idx, const one_bpf_ksym *curr) {
     printf(" [%ld] ksym %p %p %p %d %s\n", idx, curr->addr, (void *)curr->start, (void *)curr->end, curr->prog ? 1 : 0, curr->name);
   }
  );
}

void dump_holes(const char *body, std::list<const char *> *holes)
{
  printf("holes %ld\n", holes->size());
  for ( auto c: *holes )
   printf("%p %lX\n", c, c - body);
}

void dump_bpf_progs(a64 list, a64 lock, sa64 delta, std::map<void *, std::string> &map_names)
{
  if ( !list )
  {
    rcf("dump_bpf_progs", "prog_idr");
    return;
  }
  if ( !lock )
  {
    rcf("dump_bpf_progs", "prog_idr_lock");
    return;
  }
  dump_data2arg<one_bpf_prog>(list, lock, delta, IOCTL_GET_BPF_PROGS, "prog_idr", "IOCTL_GET_BPF_PROGS", "bpf_progs",
   [=,&map_names](size_t idx, const one_bpf_prog *curr) {
    printf(" [%ld] prog %p id %d len %d jited_len %d aux %p used_maps %d used_btf %d func_cnt %d\n", idx, curr->prog, curr->aux_id, curr->len, curr->jited_len,
      curr->aux, curr->used_map_cnt, curr->used_btf_cnt, curr->func_cnt
    );
    printf("     tag:");
    for ( int i = 0; i < 8; i++ )
      printf(" %2.2X", curr->tag[i]);
    printf("\n");
    printf("  stack_depth: %d\n", curr->stack_depth);
    printf("  num_exentries: %d\n", curr->num_exentries);
    printf("  type: %d %s\n", curr->prog_type, get_bpf_prog_type_name(curr->prog_type));
    printf("  expected_attach_type: %d %s\n", curr->expected_attach_type, get_bpf_attach_type_name(curr->expected_attach_type));
    if ( curr->used_map_cnt )
    {
      // dump body
      const size_t args_len = sizeof(unsigned long) * 4;
      size_t body_len = curr->used_map_cnt * sizeof(void *);
      size_t len = body_len;
#ifdef _DEBUG
      printf("body_len %ld\n", body_len);
#endif /* _DEBUG */
      if ( body_len < args_len )
        len = args_len;
      unsigned long *l = (unsigned long *)malloc(len);
      if ( !l )
      {
        printf("cannot alloc memory for bpf used maps\n");
        return;
      }
      dumb_free<unsigned long> tmp(l);
      l[0] = list + delta;
      l[1] = lock + delta;
      l[2] = (unsigned long)curr->prog;
      l[3] = body_len;
      int err = ioctl(g_fd, IOCTL_GET_BPF_USED_MAPS, (int *)l);
      if ( err )
      {
        printf("IOCTL_GET_BPF_USED_MAPS failed, error %d (%s)\n", errno, strerror(errno));
        return;
      }
      // dump used maps
      printf("  used maps:\n");
      for ( int i = 0; i < curr->used_map_cnt; i++ )
      {
        void *map_addr = (void *)l[i];
        auto mi = map_names.find(map_addr);
        if ( mi == map_names.end() )
          printf("   [%d] %p\n", i, map_addr);
        else
          printf("   [%d] %p - %s\n", i, map_addr, mi->second.c_str());
      }      
    }
    unsigned long *jit_body = NULL;
    unsigned char *curr_jit;
    dumb_free<unsigned long> jit_tmp;
    std::list<const char *> holes;
    if ( curr->bpf_func && curr->jited_len )
    {
      dump_kptr2((unsigned long)curr->bpf_func, "  bpf_func", delta);
      // dump body
      const size_t args_len = sizeof(unsigned long) * 4;
      size_t body_len = curr->jited_len;
      if ( body_len < args_len )
        body_len = args_len;
      jit_body = (unsigned long *)malloc(body_len);
      if ( !jit_body )
      {
        printf("cannot alloc memory for bpf jit code\n");
        return;
      }
      jit_tmp = jit_body;
      curr_jit = (unsigned char *)jit_body;
      jit_body[0] = list + delta;
      jit_body[1] = lock + delta;
      jit_body[2] = (unsigned long)curr->prog;
      jit_body[3] = curr->jited_len;
      int err = ioctl(g_fd, IOCTL_GET_BPF_PROG_BODY, (int *)jit_body);
      if ( err )
      {
        printf("IOCTL_GET_BPF_PROG_BODY failed, error %d (%s)\n", errno, strerror(errno));
        return;
      }
      if ( g_opt_h )
        HexDump(curr_jit, curr->jited_len);
      x64_jit_disasm dis((a64)curr->bpf_func, (const char *)curr_jit, curr->jited_len);
      dis.disasm(delta, map_names, &holes);
      dump_holes((const char *)curr_jit, &holes);
    }
    if ( curr->len )
    {
      // dump opcodes, each have size 64bit
      const size_t args_len = sizeof(unsigned long) * 4;
      size_t body_len = curr->len * 8;
      if ( body_len < args_len )
        body_len = args_len;
      unsigned long *l = (unsigned long *)malloc(body_len);
      if ( !l )
      {
        printf("cannot alloc memory for bpf body\n");
        return;
      }
      dumb_free<unsigned long> tmp(l);
      l[0] = list + delta;
      l[1] = lock + delta;
      l[2] = (unsigned long)curr->prog;
      l[3] = curr->len * 8;
      int err = ioctl(g_fd, IOCTL_GET_BPF_OPCODES, (int *)l);
      if ( err )
      {
        printf("IOCTL_GET_BPF_OPCODES failed, error %d (%s)\n", errno, strerror(errno));
        return;
      }
      if ( g_dump_bpf_ops )
        HexDump((unsigned char *)l, curr->len * 8);
      ebpf_disasm((unsigned char *)l, curr->len, stdout);
      put_orig_jit_addr(curr->bpf_func);
      if ( jit_body )
      {
        jitted_code jc;
        x64_jit_nops skipper;
        ujit2mem((unsigned char *)l, curr->len, curr->stack_depth, jc);
        int orig_skip = skipper.skip((const char *)curr_jit, curr->jited_len);
        curr_jit += orig_skip;
        if ( jc.body )
        {
          int my_skip = skipper.skip((const char *)jc.body, jc.size);
          jc.size -= my_skip;
          jc.body += my_skip;
        }
        if ( jc.size != curr->jited_len - orig_skip)
        {
          printf("jit id %ld has different length - in kernel %d, jitted %ld\n", idx, curr->jited_len, jc.size);
          if ( jc.size )
          {
            x64_jit_disasm dis((a64)curr->bpf_func, (const char *)jc.body, jc.size);
            dis.disasm(delta, map_names, NULL);
          }
        } else {
          int patched = 0;
          std::list<const char *>::iterator hiter = holes.begin();
          for ( size_t i = 0; i < jc.size; i++ )
          {
            if ( jc.body[i] != curr_jit[i] )
            {
              patched++;
              printf(" patched at %p, %X - %X\n", i + orig_skip + (char *)curr->bpf_func, jc.body[i], curr_jit[i]);
            }
            if ( hiter != holes.end() && (const char *)(curr_jit + i) == *hiter )
            {
              i += 4;
              ++hiter;
            }
          }
          if ( patched )
            printf("total %d bytes patched\n", patched);
        }
      } else
        ujit2file(idx, (unsigned char *)l, curr->len, curr->stack_depth);
    }
    printf("\n");
   }
  );
}

// ripped from https://elixir.bootlin.com/linux/v5.18/source/include/uapi/linux/bpf.h#L880
static const char *const bpf_map_type_names[] = {
 "BPF_MAP_TYPE_UNSPEC",
 "BPF_MAP_TYPE_HASH",
 "BPF_MAP_TYPE_ARRAY",
 "BPF_MAP_TYPE_PROG_ARRAY",
 "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
 "BPF_MAP_TYPE_PERCPU_HASH",
 "BPF_MAP_TYPE_PERCPU_ARRAY",
 "BPF_MAP_TYPE_STACK_TRACE",
 "BPF_MAP_TYPE_CGROUP_ARRAY",
 "BPF_MAP_TYPE_LRU_HASH",
 "BPF_MAP_TYPE_LRU_PERCPU_HASH",
 "BPF_MAP_TYPE_LPM_TRIE",
 "BPF_MAP_TYPE_ARRAY_OF_MAPS",
 "BPF_MAP_TYPE_HASH_OF_MAPS",
 "BPF_MAP_TYPE_DEVMAP",
 "BPF_MAP_TYPE_SOCKMAP",
 "BPF_MAP_TYPE_CPUMAP",
 "BPF_MAP_TYPE_XSKMAP",
 "BPF_MAP_TYPE_SOCKHASH",
 "BPF_MAP_TYPE_CGROUP_STORAGE",
 "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
 "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
 "BPF_MAP_TYPE_QUEUE",
 "BPF_MAP_TYPE_STACK",
 "BPF_MAP_TYPE_SK_STORAGE",
 "BPF_MAP_TYPE_DEVMAP_HASH",
 "BPF_MAP_TYPE_STRUCT_OPS",
 "BPF_MAP_TYPE_RINGBUF",
 "BPF_MAP_TYPE_INODE_STORAGE",
 "BPF_MAP_TYPE_TASK_STORAGE",
 "BPF_MAP_TYPE_BLOOM_FILTER",
 "BPF_MAP_TYPE_USER_RINGBUF",
 "BPF_MAP_TYPE_CGRP_STORAGE",
 "BPF_MAP_TYPE_ARENA",
};

static const char *get_bpf_map_type_name(int idx)
{
  if ( idx >= sizeof(bpf_map_type_names) / sizeof(bpf_map_type_names[0]) )
    return "";
  return bpf_map_type_names[idx];
}


// ripped from https://elixir.bootlin.com/linux/v5.18/source/include/uapi/linux/bpf.h#L1006
static const char *const bpf_link_type_names[] = {
 "BPF_LINK_TYPE_UNSPEC",
 "BPF_LINK_TYPE_RAW_TRACEPOINT",
 "BPF_LINK_TYPE_TRACING",
 "BPF_LINK_TYPE_CGROUP",
 "BPF_LINK_TYPE_ITER",
 "BPF_LINK_TYPE_NETNS",
 "BPF_LINK_TYPE_XDP",
 "BPF_LINK_TYPE_PERF_EVENT",
 "BPF_LINK_TYPE_KPROBE_MULTI",
};

static const char *get_bpf_link_type_name(int idx)
{
  if ( idx >= sizeof(bpf_link_type_names) / sizeof(bpf_link_type_names[0]) )
    return "";
  return bpf_link_type_names[idx];
}

void dump_bpf_links(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_bpf_links", "link_idr");
    return;
  }
  if ( !lock )
  {
    rcf("dump_bpf_links", "link_idr_lock");
    return;
  }
  dump_data2arg<one_bpf_links>(list, lock, delta, IOCTL_GET_BPF_LINKS, "link_idr", "IOCTL_GET_BPF_LINKS", "bpf_links",
   [=](size_t idx, const one_bpf_links *curr) {
    printf(" [%ld] at %p id %d\n", idx, curr->addr, curr->id);
    printf("  type: %d %s\n", curr->type, get_bpf_link_type_name(curr->type));
    if ( curr->ops )
    {
      dump_kptr((unsigned long)curr->ops, " ops", delta);
      if ( curr->release )
        dump_kptr((unsigned long)curr->release, "  release", delta);
      if ( curr->dealloc )
        dump_kptr((unsigned long)curr->dealloc, "  dealloc", delta);
      if ( curr->detach )
        dump_kptr((unsigned long)curr->detach, "  detach", delta);
      if ( curr->update_prog )
        dump_kptr((unsigned long)curr->update_prog, "  update_prog", delta);
      if ( curr->show_fdinfo )
        dump_kptr((unsigned long)curr->show_fdinfo, "  show_fdinfo", delta);
      if ( curr->fill_link_info )
        dump_kptr((unsigned long)curr->fill_link_info, "  fill_link_info", delta);
    }
    if ( curr->prog.prog )
    {
      printf("  prog %p id %d type %d len %d jited_len %d\n", curr->prog.prog, curr->prog.aux_id, curr->prog.prog_type, curr->prog.len, curr->prog.jited_len);
      if ( curr->prog.bpf_func )
        dump_kptr2((unsigned long)curr->prog.bpf_func, "  bpf_func", delta);     
    }
   }
  );
}

template <typename T>
void dump_jit_option(a64 addr, sa64 delta, const char *fmt)
{
  char *ptr = (char *)addr + delta;
  char *arg = ptr;
  int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
  if ( err )
  {
     printf("read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
     return;
  }
  T val = *(T *)&arg;
  printf(fmt, val);
}

void dump_ftrace_options(sa64 delta)
{
  auto addr = get_addr("ftrace_enabled");
  if ( addr )
    dump_jit_option<int>(addr, delta, "ftrace_enabled: %d\n");
  addr = get_addr("ftrace_disabled");
  if ( addr )
    dump_jit_option<int>(addr, delta, "ftrace_disabled: %d\n");
  addr = get_addr("last_ftrace_enabled");
  if ( addr )
    dump_jit_option<int>(addr, delta, "last_ftrace_enabled: %d\n");
  addr = get_addr("ftrace_profile_enabled");
  if ( addr )
    dump_jit_option<int>(addr, delta, "ftrace_profile_enabled: %d\n");
  addr = get_addr("ftrace_graph_active");
  if ( addr )
    dump_jit_option<int>(addr, delta, "ftrace_graph_active: %d\n");
  addr = get_addr("ftrace_direct_func_count");
  if ( addr )
    dump_jit_option<int>(addr, delta, "ftrace_direct_func_count: %d\n");
  addr = get_addr("ftrace_number_of_groups");
  if ( addr )
    dump_jit_option<int>(addr, delta, "ftrace_number_of_groups: %d\n");
}

void dump_jit_options(sa64 delta)
{
  auto addr = get_addr("bpf_jit_enable");
  if ( addr )
    dump_jit_option<int>(addr, delta, "bpf_jit_enable: %d\n");
  addr = get_addr("bpf_jit_harden");
  if ( addr )
    dump_jit_option<int>(addr, delta, "bpf_jit_harden: %d\n");
  addr = get_addr("bpf_jit_kallsyms");
  if ( addr )
    dump_jit_option<int>(addr, delta, "bpf_jit_kallsyms: %d\n");
  addr = get_addr("bpf_jit_limit");
  if ( addr )
    dump_jit_option<long>(addr, delta, "bpf_jit_limit: %ld\n");
  addr = get_addr("bpf_jit_limit_max");
  if ( addr )
    dump_jit_option<long>(addr, delta, "bpf_jit_limit_max: %ld\n");
}

void _dump_bpf_raw_events(a64 start, a64 end, sa64 delta, int code, const char *code_name)
{
  if ( !start )
  {
    rcf("__start__bpf_raw_tp");
    return;
  }
  if ( !end )
  {
    rcf("__stop__bpf_raw_tp");
    return;
  }
  dump_data2arg<one_bpf_raw_event>(start, end, delta, code, "bpf_raw_tps", code_name, "bpf_raw_tps",
   [=](size_t idx, const one_bpf_raw_event *curr) {
     printf(" [%ld] num_args %d ", idx, curr->num_args);
     dump_kptr2((unsigned long)curr->addr, "addr", delta);
     if ( curr->tp )
       dump_kptr((unsigned long)curr->tp, "  tp", delta);
     if ( curr->func )
       dump_kptr((unsigned long)curr->func, "  func", delta);
   }
  );
}

void dump_bpf_raw_events(a64 start, a64 end, sa64 delta)
{
  _dump_bpf_raw_events(start, end, delta, IOCTL_GET_BPF_RAW_EVENTS, "IOCTL_GET_BPF_RAW_EVENTS");
}

void dump_bpf_raw_events2(a64 start, a64 end)
{
  _dump_bpf_raw_events(start, end, 0, IOCTL_GET_BPF_RAW_EVENTS2, "IOCTL_GET_BPF_RAW_EVENTS2");
}

void dump_bpf_maps(a64 list, a64 lock, sa64 delta, std::map<void *, std::string> &map_names)
{
  if ( !list )
  {
    rcf("dump_bpf_maps", "map_idr");
    return;
  }
  if ( !lock )
  {
    rcf("dump_bpf_maps", "map_idr_lock");
    return;
  }
  dump_data2arg<one_bpf_map>(list, lock, delta, IOCTL_GET_BPF_MAPS, "bpf_maps", "IOCTL_GET_BPF_MAPS", "bpf_maps",
   [=,&map_names](size_t idx, const one_bpf_map *curr) {
      printf(" [%ld] id %d %s at %p\n", idx, curr->id, curr->name, curr->addr);
      if ( curr->ops )
        dump_kptr((unsigned long)curr->ops, "  ops", delta);
      map_names[curr->addr] = curr->name;
      printf("  type: %d %s\n", curr->map_type, get_bpf_map_type_name(curr->map_type));
      printf("  key_size %d value_size %d\n", curr->key_size, curr->value_size);
      if ( curr->btf )
        dump_kptr((unsigned long)curr->btf, "  btf", delta);
   }
  );
}

int read_input_dev_name(void *addr, unsigned long len, unsigned long what, char *buf)
{
  unsigned long *args = (unsigned long *)buf;
  args[0] = (unsigned long)addr;
  args[1] = len;
  args[2] = what;
  int err = ioctl(g_fd, IOCTL_INPUT_DEV_NAME, (int *)args);
  return err ? 0 : 1;
}

int read_dev_handlers(void *addr, unsigned long len, sa64 delta, std::map<void *, std::string> &hmap)
{
  // args 3 longs at least
  auto alen = std::max(3UL, 1 + len);
  alen *= sizeof(unsigned long);
  unsigned long *args = (unsigned long *)malloc(alen);
  if ( !args ) return 0;
  dumb_free<unsigned long> tmp(args);
  args[0] = (unsigned long)addr;
  args[1] = len;
  args[2] = 3;
  int err = ioctl(g_fd, IOCTL_INPUT_DEV_NAME, (int *)args);
  if ( err ) return 0;
  for ( unsigned long i = 0; i < args[0]; ++i )
  {
    addr = (void *)args[i+1];
    auto known = hmap.find(addr);
    printf("  [%ld]", i);
    if ( known != hmap.end() ) printf(" %p %s\n", addr, known->second.c_str());
    else { printf(" UNREGGED"); dump_unnamed_kptr(args[i+1], delta, true); }
  }
  return 1;
}

void dump_avc_cbs(sa64 delta)
{
  dump_data_noarg<one_avc>(IOCTL_AVC_CBS, "IOCTL_AVC_CBS", "avc callbacks",
   [&](size_t idx, const one_avc *id) {
    printf(" [%ld] events %X at", idx, id->events);
    dump_unnamed_kptr(id->cb, delta);
   });
}

void dump_sysrq_keys(sa64 delta)
{
  dump_data_noarg<one_sysrq_key>(IOCTL_SYSRQ_KEYS, "IOCTL_SYSRQ_KEYS", "sysrq key handlers",
   [&](size_t idx, const one_sysrq_key *id) {
    printf(" [%ld] mask %X at", id->idx, id->mask);
    dump_kptr2((unsigned long)id->addr, "addr", delta);
    dump_kptr2((unsigned long)id->handler, " handler", delta);
   });
}

void dump_input_devs(sa64 delta, std::map<void *, std::string> &hmap)
{
  const unsigned long args_len = 3 * sizeof(unsigned long);
  char *name_buf = nullptr;
  size_t name_len = 0;
  dump_data_noarg<one_input_dev>(IOCTL_INPUT_DEVS, "IOCTL_INPUT_DEVS", "input devs",
   [&](size_t idx, const one_input_dev *id) {
    printf(" [%ld] input_dev at", idx);
    dump_kptr2((unsigned long)id->addr, "addr", delta);
    auto cl = std::max(id->l_name, std::max(id->l_phys, id->l_uniq));
    if ( cl ) {
      cl = std::max(cl, args_len);
      if ( cl > name_len ) {
        if ( name_buf ) free(name_buf);
        name_buf = (char *)malloc(cl);
        if (name_buf) name_len = cl; else cl = name_len = 0;
      }
    }
    if ( cl && id->l_name && read_input_dev_name(id->addr, cl, 0, name_buf) )
      printf(" name: %s\n", name_buf);
    if ( cl && id->l_phys && read_input_dev_name(id->addr, cl, 1, name_buf) )
      printf(" phys: %s\n", name_buf);
    if ( cl && id->l_uniq && read_input_dev_name(id->addr, cl, 2, name_buf) )
      printf(" uniq: %s\n", name_buf);
    printf(" handlers: %ld\n", id->h_cnt);
    if ( id->h_cnt ) {
      read_dev_handlers(id->addr, id->h_cnt, delta, hmap);
    }
    if ( id->setkeycode )
      dump_kptr2((unsigned long)id->setkeycode, "  setkeycode", delta);
    if ( id->getkeycode )
      dump_kptr2((unsigned long)id->getkeycode, "  getkeycode", delta);
    if ( id->open )
      dump_kptr2((unsigned long)id->open, "  open", delta);
    if ( id->close )
      dump_kptr2((unsigned long)id->close, "  close", delta);
    if ( id->flush )
      dump_kptr2((unsigned long)id->flush, "  flush", delta);
    if ( id->event )
      dump_kptr2((unsigned long)id->event, "  event", delta);
    if ( id->ff )
    {
      dump_kptr2((unsigned long)id->ff, "  ff", delta);
      if ( id->ff_upload )
        dump_kptr2((unsigned long)id->ff_upload, "  ff.upload", delta);
      if ( id->ff_erase )
        dump_kptr2((unsigned long)id->ff_erase, "  ff.erase", delta);
      if ( id->ff_playback )
        dump_kptr2((unsigned long)id->ff_playback, "  ff.playback", delta);
      if ( id->ff_set_gain )
        dump_kptr2((unsigned long)id->ff_set_gain, "  ff.set_gain", delta);
      if ( id->ff_set_autocenter )
        dump_kptr2((unsigned long)id->ff_set_autocenter, "  ff.set_autocenter", delta);
      if ( id->ff_destroy )
        dump_kptr2((unsigned long)id->ff_destroy, "  ff.destroy", delta);
    }
   });
   if ( name_buf ) free(name_buf);
}

void dump_input_handlers(sa64 delta, std::map<void *, std::string> &hmap)
{
  const unsigned long args_len = 2 * sizeof(unsigned long);
  char *name_buf = nullptr;
  size_t name_len = 0;
  dump_data_noarg<one_input_handler>(IOCTL_INPUT_HANDLERS, "IOCTL_INPUT_HANDLERS", "input handlers",
   [&](size_t idx, const one_input_handler *curr) {
    printf(" [%ld] input_handler at", idx);
    dump_kptr2((unsigned long)curr->addr, "addr", delta);
    const char *curr_name = nullptr;
    if ( curr->l_name )
    {
      auto cl = std::max(curr->l_name, args_len);
      if ( cl > name_len ) {
        if ( name_buf ) free(name_buf);
        name_buf = (char *)malloc(cl);
        if (name_buf) name_len = cl; else cl = name_len = 0;
      }
      if ( cl && read_ioctled_name(curr->addr, cl, name_buf, IOCTL_INPUT_HANDLER_NAME) ) {
       printf("  Name: %s\n", name_buf);
       curr_name = name_buf;
      }
    }
    // insert into hmap
    if ( !curr_name ) hmap[curr->addr] = "";
    else hmap[curr->addr] = curr_name;
    if ( curr->event )
      dump_kptr2((unsigned long)curr->event, "  event", delta);
    if ( curr->events )
      dump_kptr2((unsigned long)curr->events, "  events", delta);
    if ( curr->filter )
      dump_kptr2((unsigned long)curr->filter, "  filter", delta);
    if ( curr->match )
      dump_kptr2((unsigned long)curr->match, "  match", delta);
    if ( curr->connect )
      dump_kptr2((unsigned long)curr->connect, "  connect", delta);
    if ( curr->disconnect )
      dump_kptr2((unsigned long)curr->disconnect, "  disconnect", delta);
    if ( curr->start )
      dump_kptr2((unsigned long)curr->start, "  start", delta);
  });
  if ( name_buf ) free(name_buf);
}

static void cdump_aead(const crypt_aead &a, sa64 delta)
{
  if ( a.setkey )
    dump_kptr2(a.setkey, "  setkey", delta);
  if ( a.setauthsize )
    dump_kptr2(a.setauthsize, "  setauthsize", delta);
  if ( a.encrypt )
    dump_kptr2(a.encrypt, "  encrypt", delta);
  if ( a.decrypt )
    dump_kptr2(a.decrypt, "  decrypt", delta);
  if ( a.init )
    dump_kptr2(a.init, "  init", delta);
  if ( a.exit )
    dump_kptr2(a.exit, "  exit", delta);
  if ( a.givencrypt )
    dump_kptr2(a.givencrypt, "  givencrypt", delta);
  if ( a.givdecrypt )
    dump_kptr2(a.givdecrypt, "  givdecrypt", delta);
  if ( a.ivsize || a.maxauthsize )
    printf("  ivsize %d maxauthsize %d\n", a.ivsize, a.maxauthsize);
}

static void cdump_ak(const crypt_akcipher &a, sa64 delta)
{
  if ( a.sign )
    dump_kptr2(a.sign, "  sign", delta);
  if ( a.verify )
    dump_kptr2(a.verify, "  verify", delta);
  if ( a.encrypt )
    dump_kptr2(a.encrypt, "  encrypt", delta);
  if ( a.decrypt )
    dump_kptr2(a.decrypt, "  decrypt", delta);
  if ( a.set_pub_key )
    dump_kptr2(a.set_pub_key, "  set_pub_key", delta);
  if ( a.set_priv_key )
    dump_kptr2(a.set_priv_key, "  set_priv_key", delta);
  if ( a.max_size )
    dump_kptr2(a.max_size, "  max_size", delta);
  if ( a.init )
    dump_kptr2(a.init, "  init", delta);
  if ( a.exit )
    dump_kptr2(a.exit, "  exit", delta);
  if ( a.reqsize )
    printf("  reqsize: %d\n", a.reqsize);
}

static void cdump_rng(const crypt_rng &r, sa64 delta)
{
  if ( r.rng_make_random )
    dump_kptr2(r.rng_make_random, "  rng_make_random", delta);
  if ( r.rng_reset )
    dump_kptr2(r.rng_reset, "  rng_reset", delta);
  if ( r.generate )
    dump_kptr2(r.generate, "  generate", delta);
  if ( r.seed )
    dump_kptr2(r.seed, "  seed", delta);
  if ( r.set_ent )
    dump_kptr2(r.set_ent, "  set_ent", delta);
  if ( r.seedsize )
    printf("  seedsize: %d\n", r.seedsize);
}

static void cdump_kpp(const crypt_kpp &k, sa64 delta)
{
  if ( k.set_secret )
    dump_kptr2(k.set_secret, "  set_secret", delta);
  if ( k.generate_public_key )
    dump_kptr2(k.generate_public_key, "  generate_public_key", delta);
  if ( k.compute_shared_secret )
    dump_kptr2(k.compute_shared_secret, "  compute_shared_secret", delta);
  if ( k.max_size )
    dump_kptr2(k.max_size, "  max_size", delta);
  if ( k.init )
    dump_kptr2(k.init, "  init", delta);
  if ( k.exit )
    dump_kptr2(k.exit, "  exit", delta);
  if ( k.reqsize )
    printf("  reqsize: %d\n", k.reqsize);
}

static void cdump_scomp(const crypt_scomp &s, sa64 delta)
{
  if ( s.alloc_ctx )  dump_kptr2(s.alloc_ctx, "  alloc_ctx", delta);
  if ( s.free_ctx )   dump_kptr2(s.free_ctx, "  free_ctx", delta);
  if ( s.compress )   dump_kptr2(s.compress, "  compress", delta);
  if ( s.decompress ) dump_kptr2(s.decompress, "  decompress", delta);
}

static void cdump_acomp(const crypt_acomp &s, sa64 delta)
{
  if ( s.compress )   dump_kptr2(s.compress, "  compress", delta);
  if ( s.decompress ) dump_kptr2(s.decompress, "  decompress", delta);
  if ( s.dst_free )   dump_kptr2(s.dst_free, "  dst_free", delta);
  if ( s.init ) dump_kptr2(s.init, "  init", delta);
  if ( s.exit ) dump_kptr2(s.exit, "  exit", delta);
  if ( s.reqsize )
    printf("  reqsize: %d\n", s.reqsize);
}

static void cdump_hash(const crypt_shash &h, sa64 delta)
{
  if ( h.init )
   dump_kptr2(h.init, "  init", delta);
  if ( h.update )
   dump_kptr2(h.update, "  update", delta);
  if ( h.final )
    dump_kptr2(h.final, "  final", delta);
  if ( h.finup )
    dump_kptr2(h.finup, "  finup", delta);
  if ( h.digest )
    dump_kptr2(h.digest, "  digest", delta);
  if ( h._exp )
    dump_kptr2(h._exp, "  export", delta);
  if ( h._imp )
    dump_kptr2(h._imp, "  import", delta);
  if ( h.setkey )
    dump_kptr2(h.setkey, "  setkey", delta);
  if ( h.init_tfm )
    dump_kptr2(h.init_tfm, "  init_tfm", delta);
  if ( h.exit_tfm )
    dump_kptr2(h.exit_tfm, "  exit_tfm", delta);
  if ( h.clone_tfm )
    dump_kptr2(h.clone_tfm, "  clone_tfm", delta);
}

void dump_ckalgos(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_ckalgos", "crypto_alg_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_ckalgos", "crypto_alg_sem");
    return;
  }
  dump_data2arg<one_kcalgo>(list, lock, delta, IOCTL_ENUM_CALGO, "crypto_algos", "IOCTL_ENUM_CALGO", "crypto_algo",
   [=](size_t idx, const one_kcalgo *curr) {
     printf(" [%ld] flags %X what %X %s", idx, curr->flags, curr->what, curr->name);
     dump_kptr2((unsigned long)curr->addr, "addr", delta);
     printf("  blocksize %d ctxsize %d tfmsize %d\n", curr->c_blocksize, curr->c_ctxsize, curr->tfmsize);
     if ( curr->c_type )
     {
       dump_kptr2((unsigned long)curr->c_type, "  type", delta);
       if ( curr->ctxsize )
         dump_kptr2((unsigned long)curr->ctxsize, "   ctxsize", delta);
       if ( curr->extsize )
         dump_kptr2((unsigned long)curr->extsize, "   extsize", delta);
       if ( curr->init )
         dump_kptr2((unsigned long)curr->init, "   init", delta);
       if ( curr->init_tfm )
         dump_kptr2((unsigned long)curr->init_tfm, "   init_tfm", delta);
       if ( curr->show )
         dump_kptr2((unsigned long)curr->show, "   show", delta);
       if ( curr->report )
         dump_kptr2((unsigned long)curr->report, "   report", delta);
       if ( curr->free )
         dump_kptr2((unsigned long)curr->free, "   free", delta);
     }
     switch(curr->what)
     {
      case 1:
       if ( curr->cip.cia_min_keysize || curr->cip.cia_max_keysize )
       printf("  cia_min_keysize %d cia_max_keysize %d\n", curr->cip.cia_min_keysize, curr->cip.cia_max_keysize);
       if ( curr->cip.cia_setkey )
         dump_kptr2(curr->cip.cia_setkey, "  cia_setkey", delta);
       if ( curr->cip.cia_encrypt )
         dump_kptr2(curr->cip.cia_encrypt, "  cia_encrypt", delta);
       if ( curr->cip.cia_decrypt )
         dump_kptr2(curr->cip.cia_decrypt, "  cia_decrypt", delta);
        break;
      case 2:
       if ( curr->comp.coa_compress )
         dump_kptr2(curr->comp.coa_compress, "  coa_compress", delta);
       if ( curr->comp.coa_decompress )
         dump_kptr2(curr->comp.coa_decompress, "  coa_decompress", delta);
       break;
      case 3: cdump_aead(curr->aead, delta);
       break;
      case 8: cdump_kpp(curr->kpp, delta);
       break;
      case 0xa: cdump_acomp(curr->acomp, delta);
       break;
      case 0xb: cdump_scomp(curr->scomp, delta);
       break;
      case 0xc: cdump_rng(curr->rng, delta);
        break;
      case 0xd: cdump_ak(curr->ak, delta);
       break;
      case 0xe:
      case 0xf: cdump_hash(curr->shash, delta);
       break;
     }
     if ( curr->cra_init )
       dump_kptr2((unsigned long)curr->cra_init, "  cra_init", delta);
     if ( curr->cra_exit )
       dump_kptr2((unsigned long)curr->cra_exit, "  cra_exit", delta);
     if ( curr->cra_destroy )
       dump_kptr2((unsigned long)curr->cra_destroy, "  cra_destroy", delta);
   }
  );
  printf("\n");
}

void dump_bpf_targets(a64 list, a64 lock, sa64 delta)
{
  if ( !list )
  {
    rcf("dump_bpf_targets", "targets");
    return;
  }
  if ( !lock )
  {
    rcf("dump_bpf_targets", "targets_mutex");
    return;
  }
  dump_data2arg<one_bpf_reg>(list, lock, delta, IOCTL_GET_BPF_REGS, "bpf_iter_reg", "IOCTL_GET_BPF_REGS", "bpf_regs",
   [=](size_t idx, const one_bpf_reg *curr) {
    printf(" [%ld] feature %d at", idx, curr->feature);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->attach_target )
      dump_kptr((unsigned long)curr->attach_target, "  attach_target", delta);
    if ( curr->detach_target )
      dump_kptr((unsigned long)curr->detach_target, "  detach_target", delta);
    if ( curr->show_fdinfo )
      dump_kptr((unsigned long)curr->show_fdinfo, "  show_fdinfo", delta);
    if ( curr->fill_link_info )
      dump_kptr((unsigned long)curr->fill_link_info, "  fill_link_info", delta);
    if ( curr->seq_info )
      dump_kptr((unsigned long)curr->seq_info, "  seq_info", delta);
    if ( curr->seq_ops )
      dump_kptr((unsigned long)curr->seq_ops, "  seq_ops", delta);
    if ( curr->init_seq_private )
      dump_kptr((unsigned long)curr->init_seq_private, "  init_seq_private", delta);
    if ( curr->fini_seq_private )
      dump_kptr((unsigned long)curr->fini_seq_private, "  fini_seq_private", delta);
   }
  );
}

void dump_lsm(sa64 delta)
{
  for ( auto &c: s_hooks )
  {
    if ( !c.list )
      continue;
    unsigned long args[2] = { c.list + delta, 0 };
    if ( !is_inside_kernel(args[0]) )
    {
      printf("%s list has strange address %p\n", c.name.c_str(), (void *)args[0]);
      continue;
    }
#ifdef _DEBUG
    printf("%s at %p\n", c.name.c_str(), (void *)args[0]);
#endif /* _DEBUG */
    int err = ioctl(g_fd, IOCTL_GET_LSM_HOOKS, (int *)&args);
    if ( err )
    {
      printf("IOCTL_GET_LSM_HOOKS for %s failed, error %d (%s)\n", c.name.c_str(), errno, strerror(errno));
      continue;
    }
    if ( !args[0] )
      continue;
    printf("%s: %ld\n", c.name.c_str(), args[0]);
    size_t size = (1 + args[0]) * sizeof(unsigned long);
    unsigned long *buf = (unsigned long *)malloc(size);
    if ( !buf )
      continue;
    dumb_free<unsigned long> tmp(buf);
    // fill args
    buf[0] = c.list + delta;
    buf[1] = args[0];
    err = err = ioctl(g_fd, IOCTL_GET_LSM_HOOKS, (int *)buf);
    if ( err )
    {
      printf("IOCTL_GET_LSM_HOOKS for %s failed, error %d (%s)\n", c.name.c_str(), errno, strerror(errno));
      continue;
    }
    size = buf[0];
    for ( auto idx = 0; idx < size; idx++ )
      dump_unnamed_kptr(buf[1 + idx], delta);
  }
}

size_t calc_cgroup_bpf_size(unsigned long n)
{
  const size_t args_size = 6 * sizeof(unsigned long);
  size_t res = sizeof(unsigned long) + n * sizeof(one_bpf_prog);
  return res < args_size ? args_size : res;
}

void dump_cgroup(const one_cgroup *cg, sa64 delta, unsigned long a1, unsigned long a2, unsigned long root, bool dump_root = false)
{
  printf(" cgroup at %p id %ld serial_nr %ld flags %lX level %d kn %p\n", 
    cg->addr, cg->id, cg->serial_nr, cg->flags, cg->level, cg->kn);
  if ( dump_root && cg->root ) dump_kptr2((unsigned long)cg->root, "root", delta);
  if ( cg->ss_cnt ) {
    printf("  subsys count: %d\n", cg->ss_cnt);
    size_t args_size = sizeof(unsigned long) * std::max(1 + 2 * cg->ss_cnt, 5);
    unsigned long *ss_buf = (unsigned long *)malloc(args_size);
    if ( ss_buf )
    {
      dumb_free<unsigned long> tmp(ss_buf);
      // fill args for IOCTL_GET_CGROUP_SS
      ss_buf[0] = a1;
      ss_buf[1] = a2;
      ss_buf[2] = root;
      ss_buf[3] = (unsigned long)cg->addr;
      ss_buf[4] = cg->ss_cnt;
      int err = ioctl(g_fd, IOCTL_GET_CGROUP_SS, (int *)ss_buf);
      if ( err )
        printf("IOCTL_GET_CGROUP_SS for cgroup %p failed, error %d (%s)\n", cg->addr, errno, strerror(errno));
      else {
        // dump ss
        for ( unsigned long ssi = 0; ssi < ss_buf[0]; ssi += 2 )
        {
          printf("   subsys[%ld]", ssi);
          dump_unnamed_kptr(ss_buf[ssi + 1], delta, true);
          if ( ss_buf[ssi + 2] ) dump_kptr(ss_buf[ssi + 2], "  ss", delta);
        }
      }
    }
  }
  if ( cg->ss )
    dump_kptr((unsigned long)cg->ss, "ss", delta);
  if ( cg->parent_ss )
    dump_kptr((unsigned long)cg->parent_ss, "parent.ss", delta);
  if ( cg->agent_work )
    dump_kptr((unsigned long)cg->agent_work, "release_agent_work", delta);
  int i = 0;
  int has_bpf = 0;
  for ( i = 0; i < CG_BPF_MAX; i++ )
  {
    if ( cg->prog_array_cnt[i] )
    {
      has_bpf = 1;
      break;
    }
  }
  if ( !has_bpf )
    return;
  if ( cg->bpf_release_func )
    dump_kptr(cg->bpf_release_func, "bpf.release_agent.work", delta);
  if ( cg->stg_cnt )
    printf(" BPF stg count: %d\n", cg->stg_cnt);
  printf(" cgroup BPF:\n");
  for ( i = 0; i < CG_BPF_MAX; i++ )
  {
    if ( !cg->prog_array_cnt[i] )
      continue;
    printf("  %s: %p cnt %ld flags %X\n", get_bpf_attach_type_name(i), cg->prog_array[i], cg->prog_array_cnt[i], cg->bpf_flags[i]);
    size_t size = calc_cgroup_bpf_size(cg->prog_array_cnt[i]);
    unsigned long *buf = (unsigned long *)malloc(size);
    if ( !buf )
      continue;
    dumb_free<unsigned long> tmp(buf);
    // fill args for IOCTL_GET_CGROUP_BPF
    buf[0] = a1;
    buf[1] = a2;
    buf[2] = root;
    buf[3] = (unsigned long)cg->addr;
    buf[4] = i;
    buf[5] = cg->prog_array_cnt[i];
    int err = ioctl(g_fd, IOCTL_GET_CGROUP_BPF, (int *)buf);
    if ( err )
    {
      printf("OCTL_GET_CGROUP_BPF for cgroup %p and index %d failed, error %d (%s)\n", cg->addr, i, errno, strerror(errno));
      continue;
    }
    one_bpf_prog *bpf = (one_bpf_prog *)(buf + 1);
    show_bpf_progs(buf[0], bpf, delta);
  }
}

void dump_groups(sa64 delta)
{
  unsigned long a1 = get_addr("cgroup_hierarchy_idr");
  if ( !a1 )
  {
    rcf("dump_groups", "cgroup_hierarchy_idr");
    return;
  }
  unsigned long a2 = get_addr("cgroup_mutex");
  if ( !a2 )
  {
    rcf("dump_groups", "cgroup_mutex");
    return;
  }
  unsigned long params[3] = { a1 + delta, a2 + delta, 0 };
  int err = ioctl(g_fd, IOCTL_GET_CGRP_ROOTS, (int *)&params);
  if ( err )
  {
    printf("IOCTL_GET_CGRP_ROOTS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\ncgroup_hierarchy_idr at %p: %ld\n", (void *)(a1 + delta), params[0]);
  if ( !params[0] )
    return;
  size_t size = calc_data_size<one_group_root>(params[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for group_roots, len %lX\n", size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = a1 + delta;
  buf[1] = a2 + delta;
  buf[2] = params[0];
  err = ioctl(g_fd, IOCTL_GET_CGRP_ROOTS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_CGRP_ROOTS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  one_group_root *gr = (one_group_root *)(buf + 1);
  for ( auto cnt = 0; cnt < buf[0]; cnt++, gr++ )
  {
    printf("[%d] %s at %p flags %X hierarchy_id %d nr_cgrps %ld real_cnt %ld mask %X\n",
      cnt, gr->name, gr->addr, gr->flags, gr->hierarchy_id, gr->nr_cgrps, gr->real_cnt, gr->subsys_mask);
    dump_cgroup(&gr->grp, delta, a1 + delta, a2 + delta, (unsigned long)gr->addr, true);
    if ( !gr->real_cnt )
      continue;
    size = calc_data_size<one_cgroup>(gr->real_cnt);
    unsigned long *cbuf = (unsigned long *)malloc(size);
    if ( !cbuf )
      continue;
    dumb_free<unsigned long> ctmp(cbuf);
    // fill params for IOCTL_GET_CGROUPS
    cbuf[0] = a1 + delta;
    cbuf[1] = a2 + delta;
    cbuf[2] = (unsigned long)gr->addr;
    cbuf[3] = gr->real_cnt;
    err = ioctl(g_fd, IOCTL_GET_CGROUPS, (int *)cbuf);
    if ( err )
    {
      printf("IOCTL_GET_CGROUPS failed, error %d (%s)\n", errno, strerror(errno));
      continue;
    }
    one_cgroup *cg = (one_cgroup *)(cbuf + 1);
    for ( auto cgnt = 0; cgnt < cbuf[0]; cgnt++, cg++ )
    {
      printf(" child %d:\n", cgnt);
      dump_cgroup(cg, delta, a1 + delta, a2 + delta, (unsigned long)gr->addr);
    }
  }
}

void dump_uprobes(unsigned long *buf, unsigned long a1, unsigned long a2, sa64 delta)
{
  unsigned long ud = get_addr("uprobe_dispatcher");
  one_uprobe *up = (one_uprobe *)(buf + 1);
  for ( auto cnt = 0; cnt < buf[0]; cnt++ )
  {
      printf("[%d] addr %p inode %p ino %ld clnts %ld offset %lX ref_ctr_offset %lX flags %lX %s\n", 
        cnt, up[cnt].addr, up[cnt].inode, up[cnt].i_no, up[cnt].cons_cnt, up[cnt].offset, up[cnt].ref_ctr_offset, up[cnt].flags, up[cnt].name);
      if ( !up[cnt].cons_cnt )
        continue;
      size_t client_size = calc_data_size<one_uprobe_consumer>(up[cnt].cons_cnt);
      unsigned long *cbuf = (unsigned long *)malloc(client_size);
      if ( !cbuf )
      {
        printf("cannot alloc buffer for uprobe %p consumers, len %lX\n", up[cnt].addr, client_size);
        continue;
      }
      dumb_free<unsigned long> tmp2(cbuf);
      // form params for IOCTL_CNT_UPROBES
      cbuf[0] = a1;
      cbuf[1] = a2;
      cbuf[2] = (unsigned long)up[cnt].addr;
      cbuf[3] = up[cnt].cons_cnt;
      int err = ioctl(g_fd, IOCTL_UPROBES_CONS, (int *)cbuf);
      if ( err )
      {
        printf("IOCTL_UPROBES_CONS for %p failed, error %d (%s)\n", up[cnt].addr, errno, strerror(errno));
        continue;
      }
      // dump consumers
      one_uprobe_consumer *uc = (one_uprobe_consumer *)(cbuf + 1);
      for ( auto cnt2 = 0; cnt2 < cbuf[0]; cnt2++ )
      {
        printf(" consumer[%d] at %p\n", cnt2, uc[cnt2].addr);
        if ( uc[cnt2].handler )
          dump_kptr((unsigned long)uc[cnt2].handler, "  handler", delta);
        if ( uc[cnt2].ret_handler )
          dump_kptr((unsigned long)uc[cnt2].ret_handler, "  ret_handler", delta);
        if ( uc[cnt2].filter )
          dump_kptr((unsigned long)uc[cnt2].filter, "  filter", delta);
        if ( !ud )
          continue;
        if ( (unsigned long)uc[cnt2].handler != ud + delta )
          continue;
#ifdef _DEBUG
        printf("IOCTL_TRACE_UPROBE required\n");
#endif /* _DEBUG */
        size_t ut_size = sizeof(one_trace_event_call);
        if ( ut_size < 4 * sizeof(unsigned long) )
          ut_size = 4 * sizeof(unsigned long);
        unsigned long *cbuf = (unsigned long *)malloc(ut_size);
        if ( !cbuf )
          continue;
        dumb_free<unsigned long> tmp3(cbuf);
        cbuf[0] = a1;
        cbuf[1] = a2;
        cbuf[2] = (unsigned long)up[cnt].addr;
        cbuf[3] = (unsigned long)uc[cnt2].addr;
        err = ioctl(g_fd, IOCTL_TRACE_UPROBE, (int *)cbuf);
        if ( err )
        {
          printf("IOCTL_TRACE_UPROBE for %p failed, error %d (%s)\n", up[cnt].addr, errno, strerror(errno));
          continue;
        }
        uprobe_args ua { a1, a2, (unsigned long)up[cnt].addr, (unsigned long)uc[cnt2].addr };
        dump_trace_event_call(cnt2, (one_trace_event_call *)cbuf, delta, &ua);
      }
  }
}

void dump_uprobes(sa64 delta)
{
  unsigned long a1 = get_addr("uprobes_tree");
  if ( !a1 )
  {
    rcf("dump_uprobes", "uprobes_tree");
    return;
  }
  unsigned long a2 = get_addr("uprobes_treelock");
  if ( !a2 )
  {
    rcf("dump_uprobes", "uprobes_treelock");
    return;
  }
  unsigned long params[3] = { a1 + delta, a2 + delta, 0 };
  int err = ioctl(g_fd, IOCTL_UPROBES, (int *)&params);
  if ( err )
  {
    printf("IOCTL_UPROBES count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\nuprobes: %ld\n", params[0]);
  if ( params[0] )
  {
    size_t size = calc_data_size<one_uprobe>(params[0]);
    unsigned long *buf = (unsigned long *)malloc(size);
    if ( !buf )
    {
      printf("cannot alloc buffer for uprobes, len %lX\n", size);
      return;
    }
    dumb_free<unsigned long> tmp(buf);
    buf[0] = a1 + delta;
    buf[1] = a2 + delta;
    buf[2] = params[0];
    err = ioctl(g_fd, IOCTL_UPROBES, (int *)buf);
    if ( err )
    {
      printf("IOCTL_UPROBES failed, error %d (%s)\n", errno, strerror(errno));
      return;
    }
    dump_uprobes(buf, a1 + delta, a2 + delta, delta);
  }
  // dump delayed uprobes
  params[0] = 0;
  err = ioctl(g_fd, IOCTL_DELAYED_UPROBES, (int *)params);
  if ( err )
  {
    printf("IOCTL_DELAYED_UPROBES count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\ndelayed uprobes: %ld\n", params[0]);
  if ( !params[0] ) return;
  size_t size = calc_data_size<one_uprobe>(params[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc buffer for delayed uprobes, len %lX\n", size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = params[0];
  err = ioctl(g_fd, IOCTL_DELAYED_UPROBES, (int *)buf);
  if ( err )
  {
    printf("IOCTL_DELAYED_UPROBES failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  dump_uprobes(buf, a1 + delta, a2 + delta, delta);
}

void dump_protosw(a64 list, a64 lock, sa64 delta, const char *what)
{
  printf("\n%s at %p:\n", what, (void *)(list + delta));
  for ( int i = 0; i < 11; i++ )
  {
    unsigned long args[4] = { list + delta, lock + delta, (unsigned long)i, 0 };
    int err = ioctl(g_fd, IOCTL_GET_PROTOSW, (int *)args);
    if ( err )
    {
      printf("IOCTL_GET_PROTOSW count for %d failed, error %d (%s)\n", i, errno, strerror(errno));
      continue;
    }
    if ( !args[0] )
      continue;
    size_t size = calc_data_size<one_protosw>(args[0]);
    unsigned long *buf = (unsigned long *)malloc(size);
    if ( !buf )
      continue;
    dumb_free<unsigned long> tmp(buf);
    buf[0] = list + delta;
    buf[1] = lock + delta;
    buf[2] = i;
    buf[3] = args[0];
    err = ioctl(g_fd, IOCTL_GET_PROTOSW, (int *)buf);
    if ( err )
    {
      printf("IOCTL_GET_PROTOSW for %d failed, error %d (%s)\n", i, errno, strerror(errno));
      continue;
    }
    size = buf[0];
    printf("[%d]: count %ld\n", i, size);
    struct one_protosw *sb = (struct one_protosw *)(buf + 1);
    for ( size_t idx = 0; idx < size; idx++, sb++ )
    {
      printf(" addr %p type %d protocol %d\n", sb->addr, sb->type, sb->protocol);
      if ( sb->prot )
        dump_kptr((unsigned long)sb->prot, " prot", delta);
      if ( sb->ops )
        dump_kptr((unsigned long)sb->ops, " ops", delta);
    }
  }
}

void dump_rtnl_af_ops(a64 nca, sa64 delta)
{
  unsigned long args[2] = { nca + delta, 0 };
  int err = ioctl(g_fd, IOCTL_GET_RTNL_AF_OPS, (int *)args);
  if ( err )
  {
    printf("IOCTL_GET_RTNL_AF_OPS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\nrtnl_af_ops at %p: %ld\n", (void *)(nca + delta), args[0]);
  if ( !args[0] )
    return;
  unsigned long m = calc_data_size<one_af_ops>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(m);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = nca + delta;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_GET_RTNL_AF_OPS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_RTNL_AF_OPS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  one_af_ops *curr = (one_af_ops *)(buf + 1);
  for ( size_t j = 0; j < buf[0]; j++, curr++ )
  {
    printf(" [%ld] addr", j);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->fill_link_af )
      dump_kptr(curr->fill_link_af, "  fill_link_af", delta);
    if ( curr->get_link_af_size )
      dump_kptr(curr->get_link_af_size, "  get_link_af_size", delta);
    if ( curr->validate_link_af )
      dump_kptr(curr->validate_link_af, "  validate_link_af", delta);
    if ( curr->set_link_af )
      dump_kptr(curr->set_link_af, "  set_link_af", delta);
    if ( curr->fill_stats_af )
      dump_kptr(curr->fill_stats_af, "  fill_stats_af", delta);
    if ( curr->get_stats_af_size )
      dump_kptr(curr->get_stats_af_size, "  get_stats_af_size", delta);
  }
}

void dump_link_ops(a64 nca, sa64 delta)
{
  unsigned long args[2] = { nca + delta, 0 };
  int err = ioctl(g_fd, IOCTL_GET_LINKS_OPS, (int *)args);
  if ( err )
  {
    printf("IOCTL_GET_LINKS_OPS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\nlink_ops at %p: %ld\n", (void *)(nca + delta), args[0]);
  if ( !args[0] )
    return;
  unsigned long m = calc_data_size<one_rtlink_ops>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(m);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = nca + delta;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_GET_LINKS_OPS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_LINKS_OPS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  one_rtlink_ops *curr = (one_rtlink_ops *)(buf + 1);
  for ( size_t j = 0; j < buf[0]; j++, curr++ )
  {
    printf(" [%ld] addr", j);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->alloc )
      dump_kptr(curr->alloc, "  alloc", delta);
    if ( curr->setup )
      dump_kptr(curr->setup, "  setup", delta);
    if ( curr->validate )
      dump_kptr(curr->validate, "  validate", delta);
    if ( curr->newlink )
      dump_kptr(curr->newlink, "  newlink", delta);
    if ( curr->changelink )
      dump_kptr(curr->changelink, "  changelink", delta);
    if ( curr->dellink )
      dump_kptr(curr->dellink, "  dellink", delta);
    if ( curr->get_size )
      dump_kptr(curr->get_size, "  get_size", delta);
    if ( curr->fill_info )
      dump_kptr(curr->fill_info, "  fill_info", delta);
    if ( curr->get_xstats_size )
      dump_kptr(curr->get_xstats_size, "  get_xstats_size", delta);
    if ( curr->fill_xstats )
      dump_kptr(curr->fill_xstats, "  fill_xstats", delta);
    if ( curr->get_num_tx_queues )
      dump_kptr(curr->get_num_tx_queues, "  get_num_tx_queues", delta);
    if ( curr->get_num_rx_queues )
      dump_kptr(curr->get_num_rx_queues, "  get_num_rx_queues", delta);
    if ( curr->slave_changelink )
      dump_kptr(curr->slave_changelink, "  slave_changelink", delta);
    if ( curr->get_slave_size )
      dump_kptr(curr->get_slave_size, "  get_slave_size", delta);
    if ( curr->fill_slave_info )
      dump_kptr(curr->fill_slave_info, "  fill_slave_info", delta);
    if ( curr->get_link_net )
      dump_kptr(curr->get_link_net, "  get_link_net", delta);
    if ( curr->get_linkxstats_size )
      dump_kptr(curr->get_linkxstats_size, "  get_linkxstats_size", delta);
    if ( curr->fill_linkxstats )
      dump_kptr(curr->fill_linkxstats, "  fill_linkxstats", delta);
  }
}

void dump_ulps(a64 nca, a64 plock, sa64 delta)
{
  if ( !nca )
  {
    rcf("dump_ulps", "tcp_ulp_list");
    return;
  }
  if ( !plock )
  {
    rcf("dump_ulps", "tcp_ulp_list_lock");
    return;
  }
  dump_data2arg<one_tcp_ulp_ops>(nca, plock, delta, IOCTL_GET_ULP_OPS, "tcp_ulp_list", "IOCTL_GET_ULP_OPS", "tcp_ulp_ops",
   [=](size_t idx, const one_tcp_ulp_ops *sb) {
    printf(" [%ld] at %p %s", idx, sb->addr, sb->name);
    dump_unnamed_kptr((unsigned long)sb->addr, delta);
    if ( sb->init )
     dump_kptr((unsigned long)sb->init, " init", delta);
    if ( sb->update )
     dump_kptr((unsigned long)sb->update, " update", delta);
    if ( sb->release )
     dump_kptr((unsigned long)sb->release, " release", delta);
    if ( sb->get_info )
     dump_kptr((unsigned long)sb->get_info, " get_info", delta);
    if ( sb->get_info_size )
     dump_kptr((unsigned long)sb->get_info_size, " get_info_size", delta);
    if ( sb->clone )
     dump_kptr((unsigned long)sb->clone, " clone", delta);
   }
  );
}

void dump_pernet_ops(a64 nca, a64 plock, sa64 delta)
{
  if ( !nca )
  {
    rcf("dump_pernet_ops", "pernet_list");
    return;
  }
  if ( !plock )
  {
    rcf("dump_pernet_ops", "pernet_ops_rwsem");
    return;
  }
  dump_data2arg<one_pernet_ops>(nca, plock, delta, IOCTL_GET_PERNET_OPS, "pernet_ops", "IOCTL_GET_PERNET_OPS", "pernet_ops",
   [=](size_t idx, const one_pernet_ops *sb) {
    printf(" [%ld] size %lx at %p", idx, sb->size, sb->addr);
    dump_unnamed_kptr((unsigned long)sb->addr, delta);
    if ( sb->init )
     dump_kptr((unsigned long)sb->init, " init", delta);
    if ( sb->pre_exit )
      dump_kptr((unsigned long)sb->pre_exit, " pre_exit", delta);
    if ( sb->exit )
     dump_kptr((unsigned long)sb->exit, " exit", delta);
    if ( sb->exit_batch )
     dump_kptr((unsigned long)sb->exit_batch, " exit_batch", delta);
    if ( sb->id ) {
      printf("  id %d at", sb->id_value);
      dump_unnamed_kptr((unsigned long)sb->id, delta, true);
    }

   }
  );
}

static size_t calc_net_chains_size(size_t n)
{
  return (n + 1) * sizeof(unsigned long);
}

void dump_block_chain(a64 nca, sa64 delta, const char *name)
{
  unsigned long val = nca + delta;
  int err = ioctl(g_fd, IOCTL_CNTNTFYCHAIN, (int *)&val);
  if ( err )
  {
    printf("IOCTL_CNTSNTFYCHAIN for %s failed, error %d (%s)\n", name, errno, strerror(errno));
    return;
  }
  printf("\n%s at %p: count %ld\n", name, (void *)(nca + delta), val);
  if ( !val )
    return;
  size_t size = calc_net_chains_size(val);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = nca + delta;
  buf[1] = val;
  err = ioctl(g_fd, IOCTL_ENUMNTFYCHAIN, (int *)buf);
  if ( err )
  {
    printf("IOCTL_ENUMNTFYCHAIN for %s failed, error %d (%s)\n", name, errno, strerror(errno));
    return;
  }
  for ( size_t i = 0; i < buf[0]; i++ )
  {
    printf(" [%ld]", i);
    dump_unnamed_kptr(buf[i+1], delta);
  }
}

void dump_net_chains(a64 nca, size_t cnt, sa64 delta)
{
  size_t size = calc_net_chains_size(cnt);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = nca + delta;
  buf[1] = cnt;
  int err = ioctl(g_fd, IOCTL_GET_NETDEV_CHAIN, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_NETDEV_CHAIN failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size = buf[0];
  for ( size_t j = 0; j < size; j++ )
  {
    dump_unnamed_kptr(buf[1 + j], delta);
  }
}

void dump_genl(a64 addr, sa64 delta)
{
  if ( !addr )
  {
    rcf("dump_genl", "genl_fam_idr");
    return;
  }
  unsigned long args[2] = { addr + delta, 0 };
  int err = ioctl(g_fd, IOCTL_GET_GENL_FAMILIES, (int *)args);
  if ( err )
  {
    printf("IOCTL_GET_GENL_FAMILIES count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\ngenl_fam_idr at %p: %ld\n", (void *)(addr + delta), args[0]);
  if ( !args[0] )
    return;
  size_t size = calc_data_size<one_genl_family>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = addr + delta;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_GET_GENL_FAMILIES, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_GENL_FAMILIES failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size = buf[0];
  one_genl_family *curr = (one_genl_family *)(buf + 1);
  int small_cnt = 0;
  for ( size_t j = 0; j < size; j++ )
    small_cnt = std::max(small_cnt, curr[j].n_small_ops);
  unsigned long *small_buf = nullptr;
  if ( small_cnt ) {
    auto small_size = calc_data_size<one_small_genlops>(small_cnt);
    small_buf = (unsigned long *)malloc(small_size);
    if ( !small_buf )
      printf("cannot alloc %lX bytes for small_genlops\n", small_size);
  }
  dumb_free<unsigned long> small_tmp(small_buf);
  for ( size_t j = 0; j < size; j++, curr++ )
  {
    printf(" [%ld] at %p id %d %s", j, curr->addr, curr->id, curr->name);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    if ( curr->pre_doit )
      dump_kptr(curr->pre_doit, " pre_doit", delta);
    if ( curr->post_doit )
      dump_kptr(curr->post_doit, " post_doit", delta);
    if ( curr->mcast_bind )
      dump_kptr((unsigned long)curr->mcast_bind, " mcast_bind", delta);
    if ( curr->mcast_unbind )
      dump_kptr((unsigned long)curr->mcast_unbind, " mcast_unbind", delta);
    if ( curr->sock_priv_init )
      dump_kptr(curr->sock_priv_init, " sock_priv_init", delta);
    if ( curr->sock_priv_destroy )
      dump_kptr(curr->sock_priv_destroy, " sock_priv_destroy", delta);
    if ( curr->ops )
      dump_kptr((unsigned long)curr->ops, " ops", delta);
    if ( curr->small_ops ) {
      printf("  n %d", curr->n_small_ops);
      dump_kptr((unsigned long)curr->small_ops, "small_ops", delta);
      if ( small_buf ) {
        small_buf[0] = addr + delta;
        small_buf[1] = (unsigned long)curr->addr;
        small_buf[2] = curr->n_small_ops;
        err = ioctl(g_fd, IOCTL_GENL_SMALLOPS, (int *)small_buf);
        if ( err )
          printf("IOCTL_GENL_SMALLOPS for %d failed, error %d (%s)\n", j, errno, strerror(errno));
        else {
          one_small_genlops *sg = (one_small_genlops *)(small_buf + 1);
          for ( size_t k = 0; k < small_buf[0]; k++, sg++ )
          {
            printf("   small[%ld] cmd %X flag %X at", k, sg->cmd, sg->flags);
            dump_unnamed_kptr((unsigned long)sg->addr, delta);
            if ( sg->doit )
              dump_kptr(sg->doit, "   doit", delta);
            if ( sg->dumpit )
              dump_kptr(sg->dumpit, "   dumpit", delta);
          }
        }
      }
    }
    if ( curr->split_ops ) {
      printf("  n %d", curr->n_split_ops);
      dump_kptr((unsigned long)curr->split_ops, "split_ops", delta);
    }
  }
}

union netlink_args
{
  unsigned long args[3];
  struct one_nltab out;
};

static const char *const nlk_names[MAX_LINKS] = {
 "ROUTE",
 NULL,
 "USERSOCK",
 "FIREWALL",
 "SOCK_DIAG",
 "NFLOG",
 "XFRM",
 "SELINUX",
 "ISCSI",
 "AUDIT",
 "FIB_LOOKUP",
 "CONNECTOR",
 "NETFILTER",
 "IP6_FW",
 "DNRTMSG",
 "KOBJECT_UEVENT",
 "GENERIC",
 NULL,
 "SCSITRANSPORT",
 "ECRYPTFS",
 "RDMA",
 "CRYPTO",
 "SMC",
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
 NULL,
};

void dump_netlinks(a64 nca, a64 lock, sa64 delta)
{
  netlink_args args;
  if ( !nca )
  {
    printf("cannot get nl_table\n");
    return;
  }
  if ( !lock )
  {
    printf("cannot get nl_table_lock\n");
    return;
  }
  for ( int i = 0; i < MAX_LINKS; i++ )
  {
    args.args[0] = nca + delta;
    args.args[1] = lock + delta;
    args.args[2] = (unsigned long)i;
    int err = ioctl(g_fd, IOCTL_GET_NLTAB, (int *)&args);
    if ( err )
    {
      printf("IOCTL_GET_NLTAB index %d failed, error %d (%s)\n", i, errno, strerror(errno));
      return;
    }
    if ( nlk_names[i] )
      printf("nl_tab[%s] at %p registered %d sockets %ld\n", nlk_names[i], args.out.addr, args.out.registered, args.out.sk_count);
    else
      printf("nl_tab[%d] at %p registered %d sockets %ld\n", i, args.out.addr, args.out.registered, args.out.sk_count);
    if ( args.out.bind )
      dump_kptr((unsigned long)args.out.bind, "bind", delta);
    if ( args.out.unbind )
      dump_kptr((unsigned long)args.out.unbind, "unbind", delta);
    if ( args.out.compare )
      dump_kptr((unsigned long)args.out.compare, "compare", delta);
    if ( !args.out.sk_count )
      continue;
    size_t buf_size = calc_data_size<one_nl_socket>(args.out.sk_count);
    unsigned long *buf = (unsigned long *)malloc(buf_size);
    if ( !buf )
      continue;
    dumb_free<unsigned long> tmp(buf);
    buf[0] = nca + delta;
    buf[1] = lock + delta;
    buf[2] = (unsigned long)i;
    buf[3] = args.out.sk_count;
    err = ioctl(g_fd, IOCTL_GET_NL_SK, (int *)buf);
    if ( err )
    {
      printf("IOCTL_GET_NL_SK index %d failed, error %d (%s)\n", i, errno, strerror(errno));
      continue;
    }
    buf_size = buf[0];
    one_nl_socket *curr = (one_nl_socket *)(buf + 1);
    for ( size_t j = 0; j < buf_size; j++, curr++ )
    {
      printf(" sock[%ld] at %p portid %d dst_portid %d sk_type %d sk_protocol %d flags %X subscriptions %d state %lX\n",
       j, curr->addr, curr->portid, curr->dst_portid, curr->sk_type, curr->sk_protocol, curr->flags, 
         curr->subscriptions, curr->state
      );
      if ( curr->netlink_rcv )
        dump_kptr((unsigned long)curr->netlink_rcv, " netlink_rcv", delta);
      if ( curr->netlink_bind )
        dump_kptr((unsigned long)curr->netlink_bind, " netlink_bind", delta);
      if ( curr->netlink_unbind )
        dump_kptr((unsigned long)curr->netlink_unbind, " netlink_unbind", delta);
      if ( curr->netlink_release )
        dump_kptr((unsigned long)curr->netlink_release, " netlink_release", delta);
      if ( curr->cb_dump )
        dump_kptr((unsigned long)curr->cb_dump, " cb.dump", delta);
      if ( curr->cb_done )
        dump_kptr((unsigned long)curr->cb_done, " cb.done", delta);
      if ( curr->sk_state_change )
        dump_kptr((unsigned long)curr->sk_state_change, " sk.sk_state_change", delta);
      if ( curr->sk_data_ready )
        dump_kptr((unsigned long)curr->sk_data_ready, " sk.data_ready", delta);
      if ( curr->sk_write_space )
        dump_kptr((unsigned long)curr->sk_write_space, " sk.write_space", delta);
      if ( curr->sk_error_report )
        dump_kptr((unsigned long)curr->sk_error_report, " sk.error_report", delta);
      if ( curr->sk_backlog_rcv )
        dump_kptr((unsigned long)curr->sk_backlog_rcv, " sk.backlog_rcv", delta);
      if ( curr->sk_destruct )
        dump_kptr((unsigned long)curr->sk_destruct, " sk.destruct", delta);
      if ( curr->sk_validate_xmit_skb )
        dump_kptr((unsigned long)curr->sk_validate_xmit_skb, " sk.validate_xmit_skb", delta);
    }
  }
}

static size_t calc_proto_size(size_t n)
{
  if ( n < 2 )
    n = 2;
  return (n + 1) * sizeof(unsigned long);
}

void dump_protos(a64 nca, a64 lock, sa64 delta)
{
  if ( !nca )
  {
    rcf("dump_protos", "proto_list");
    return;
  }
  if ( !lock )
  {
    rcf("dump_protos", "proto_list_mutex");
    return;
  }
  unsigned long args[3] = { nca + delta, lock + delta, 0 };
  int err = ioctl(g_fd, IOCTL_GET_PROTOS, (int *)args);
  if ( err )
  {
    printf("IOCTL_GET_PROTOS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("\nproto_list at %p: %ld\n", (void *)(nca + delta), args[0]);
  if ( !args[0] )
    return;
  size_t size = calc_proto_size(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = nca + delta;
  buf[1] = lock + delta;
  buf[2] = args[0];
  err = ioctl(g_fd, IOCTL_GET_PROTOS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_PROTOS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size = buf[0];
  for ( size_t i = 0; i < size; i++ )
  {
    if ( buf[1 + i] ) {
      printf(" [%ld] ", i);
      dump_unnamed_kptr(buf[1 + i], delta);
    }
  }
}

void dump_netf(sa64 delta, void *net)
{
  unsigned long args[2] = { (unsigned long)net, 0 };
  int err = ioctl(g_fd, IOCTL_ENUM_NFT_AF, (int *)&args);
  if ( err )
  {
    if ( errno != 71 /* EPROTO */ )
      printf("IOCTL_ENUM_NFT_AF count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size_t size = calc_data_size<one_nft_af>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = (unsigned long)net;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_ENUM_NFT_AF, (int *)buf);
  if ( err )
  {
    printf("IOCTL_ENUM_NFT_AF failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size = buf[0];
  struct one_nft_af *af = (struct one_nft_af *)(buf + 1);
  for ( size_t idx = 0; idx < size; idx++, af++ )
  {
    printf(" NFT_AF[%ld]: %p family %d nhooks %d\n", idx, af->addr, af->family, af->nhooks);
    if ( af->ops_init )
      dump_kptr((unsigned long)af->ops_init, " ops_init", delta);
    for ( int i = 0; i < 8; i++ )
    {
      if ( !af->hooks[i] ) continue;
      printf("  hook %d:", i);
      dump_unnamed_kptr((unsigned long)af->ops_init, delta);
    }
  }
}

const char *get_nfproto(int i)
{
  // https://elixir.bootlin.com/linux/v4.14.336/source/include/uapi/linux/netfilter.h#L69
  switch(i)
  {
    case 0: return "UNSPEC";
    case 1: return "INET";
    case 2: return "IPV4";
    case 3: return "ARP";
    case 5: return "NETDEV";
    case 7: return "BRIDGE";
    case 10: return "IPV6";
    case 12: return "DECNET";
  }
  return NULL;
}

void dum_nf_list(sa64 delta, unsigned long *buf)
{
  one_nf_logger *curr = (one_nf_logger *)(buf + 1);
  for ( unsigned long i = 0; i < buf[0]; i++, curr++ )
  {
    printf("   [%ld] type %2.2d ", i, curr->type);
    auto name = get_nfproto(curr->type);
    if ( name )
      printf("%s idx %d", name, curr->idx);
    else
      printf(" idx %d", curr->idx);
    dump_unnamed_kptr((unsigned long)curr->fn, delta);
  }
}

void dump_nf_loggers(sa64 delta, void *net)
{
  unsigned long args[2] = { (unsigned long)net, 0 };
  int err = ioctl(g_fd, IOCTL_NFLOGGERS, (int *)args);
  if ( err )
  {
    printf("IOCTL_NFLOGGERS cont failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  if ( !args[0] ) return;
  size_t size = calc_data_size<one_nf_logger>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = (unsigned long)net;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_NFLOGGERS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_NFLOGGERS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("  %ld nf loggers:\n", buf[0]);
  dum_nf_list(delta, buf);
}

void dump_nf_hooks(sa64 delta, void *net)
{
  unsigned long args[2] = { (unsigned long)net, 0 };
  int err = ioctl(g_fd, IOCTL_NFHOOKS, (int *)args);
  if ( err )
  {
    printf("IOCTL_NFHOOKS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  if ( !args[0] ) return;
  size_t size = calc_data_size<one_nf_logger>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = (unsigned long)net;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_NFHOOKS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_NFHOOKS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("  %ld nf hooks:\n", buf[0]);
  dum_nf_list(delta, buf);
}

void dump_nf_hooks(sa64 delta, const char *pfx, unsigned long *d)
{
  int err = ioctl(g_fd, IOCTL_NFIEHOOKS, (int *)d);
  if ( err )
  {
    printf("IOCTL_NFIEHOOKS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  if ( !d[0] ) return;
  printf("  %sgress hooks:", pfx);
  for ( int i = 0; i < d[0]; i++ )
  {
    if ( !d[i+1] ) continue;
    printf("   [%d]", i);
    dump_unnamed_kptr((unsigned long)d[i+1], delta);
  }
}

void dump_fib_ntfy(void *net, sa64 delta)
{
  unsigned long args[2] = { (unsigned long)net, 0 };
  int err = ioctl(g_fd, IOCTL_FIB_NTFY, (int *)&args);
  if ( err )
  {
    if ( errno != 71 /* EPROTO */)
      printf("IOCTL_FIB_NTFY count for %p failed, error %d (%s)\n", net, errno, strerror(errno));
    return;
  }
  if ( !args[0] ) return;
  auto size = calc_data_size<one_fib_ntfy>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = (unsigned long)net;
  buf[1] = args[0];
  err = ioctl(g_fd, IOCTL_FIB_NTFY, (int *)buf);
  if ( err )
  {
    printf("IOCTL_FIB_NTFY for %p failed, error %d (%s)\n", net, errno, strerror(errno));
    return;
  }
  one_fib_ntfy *curr = (one_fib_ntfy *)(buf + 1);
  printf("  fib_notifier_ops: %ld\n", buf[0]);
  for ( unsigned long i = 0; i < buf[0]; i++, curr++ )
  {
    printf("   [%ld] family %d addr", i, curr->family);
    dump_unnamed_kptr((unsigned long)curr->addr, delta, true);
    if ( curr->fib_seq_read )
      dump_kptr(curr->fib_seq_read, "    fib_seq_read", delta);
    if ( curr->fib_dump )
      dump_kptr(curr->fib_dump, "    fib_dump", delta);
  }
}

void dump_fb_rules(void *net, unsigned long cnt, unsigned long *buf, sa64 delta)
{
  buf[0] = (unsigned long)net;
  buf[1] = cnt;
  int err = ioctl(g_fd, IOCTL_FIB_RULES, (int *)buf);
  if ( err )
  {
    printf("IOCTL_FIB_RULES for %p failed, error %d (%s)\n", net, errno, strerror(errno));
    return;
  }
  one_fib_rule *sb = (one_fib_rule *)(buf + 1);
  for ( size_t idx = 0; idx < buf[0]; idx++, sb++ )
  {
    printf(" [%ld] family %d rule_size %d addr_size %d at", idx, sb->family, sb->rule_size, sb->addr_size);
    dump_unnamed_kptr((unsigned long)sb->addr, delta, true);
    if ( sb->action )
     dump_kptr(sb->action, " action", delta);
    if ( sb->suppress )
     dump_kptr(sb->suppress, " suppress", delta);
    if ( sb->match )
     dump_kptr(sb->match, " match", delta);
    if ( sb->configure )
     dump_kptr(sb->configure, " configure", delta);
    if ( sb->del_ )
     dump_kptr(sb->del_, " delete", delta);
    if ( sb->compare )
     dump_kptr(sb->compare, " compare", delta);
    if ( sb->fill )
     dump_kptr(sb->fill, " fill", delta);
    if ( sb->default_pref )
     dump_kptr(sb->default_pref, " default_pref", delta);
    if ( sb->nlmsg_payload )
     dump_kptr(sb->nlmsg_payload, " nlmsg_payload", delta);
    if ( sb->flush_cache )
     dump_kptr(sb->flush_cache, " flush_cache", delta);
  }
}

void dump_xfrm_offload(const s_xfrm_type_offload *xo, sa64 delta)
{
  printf(" xfrm_type_offload proto %d at", xo->proto);
  dump_unnamed_kptr((unsigned long)xo->addr, delta, true);
  if ( xo->encap )
    dump_kptr(xo->encap, "  encap", delta);
  if ( xo->input_tail )
    dump_kptr(xo->input_tail, "  input_tail", delta);
  if ( xo->xmit )
    dump_kptr(xo->xmit, "  xmit", delta);
}

void dump_xfrm_type(const char *pfx, const s_xfrm_type *xt, sa64 delta)
{
  printf("  %s proto %d flags %d at", pfx, xt->proto, xt->flags);
  dump_unnamed_kptr((unsigned long)xt->addr, delta, true);
  if ( xt->init_state )
    dump_kptr(xt->init_state, "   init_state", delta);
  if ( xt->destructor )
    dump_kptr(xt->destructor, "   destructor", delta);
  if ( xt->input )
    dump_kptr(xt->input, "   input", delta);
  if ( xt->output )
    dump_kptr(xt->output, "   output", delta);
  if ( xt->reject )
    dump_kptr(xt->reject, "   reject", delta);
  if ( xt->hdr_offset )
    dump_kptr(xt->hdr_offset, "   hdr_offset", delta);
}

void dump_xfrm_pt(sa64 delta)
{
  auto dump_proto = [delta](size_t idx, const s_xfrm_protocol *xp) {
   printf(" [%ld] at", idx);
   dump_unnamed_kptr((unsigned long)xp->addr, delta, true);
   if ( xp->handler )
      dump_kptr(xp->handler, "  handler", delta);
   if ( xp->cb_handler )
      dump_kptr(xp->cb_handler, "  cb_handler", delta);
   if ( xp->err_handler )
      dump_kptr(xp->err_handler, "  err_handler", delta);
   if ( xp->input_handler )
      dump_kptr(xp->input_handler, "  input_handler", delta);
  };
  auto dump_tunnel = [delta](size_t idx, const s_xfrm_tunnel *xt) {
   printf(" [%ld] at", idx);
   dump_unnamed_kptr((unsigned long)xt->addr, delta, true);
   if ( xt->handler )
      dump_kptr(xt->handler, "  handler", delta);
   if ( xt->err_handler )
      dump_kptr(xt->err_handler, "  err_handler", delta);
   if ( xt->cb_handler )
      dump_kptr(xt->cb_handler, "  cb_handler", delta);
  };
  static const char *p4[3] = {
    "esp4_handlers", "ah4_handlers", "ipcomp4_handlers"
  };
  static const char *p6[3] = {
    "esp6_handlers", "ah6_handlers", "ipcomp6_handlers"
  };
  static const char *t4[] = {
    "tunnel4_handlers", "tunnel64_handlers", "tunnelmpls4_handlers"
  };
  static const char *t6[] = {
    "tunnel6_handlers", "tunnel46_handlers", "tunnelmpls6_handlers"
  };
  unsigned long a2;
  for ( a2 = 0; a2 < 3; a2++ )
    dump_data_ul2<s_xfrm_protocol>(4, a2, delta, IOCTL_XFRM_GUTS, "IOCTL_XFRM_GUTS", p4[a2], dump_proto);
  for ( a2 = 0; a2 < 3; a2++ )
    dump_data_ul2<s_xfrm_protocol>(5, a2, delta, IOCTL_XFRM_GUTS, "IOCTL_XFRM_GUTS", p6[a2], dump_proto);
  for ( a2 = 0; a2 < 3; a2++ )
    dump_data_ul2<s_xfrm_tunnel>(6, a2, delta, IOCTL_XFRM_GUTS, "IOCTL_XFRM_GUTS", t4[a2], dump_tunnel);
  for ( a2 = 0; a2 < 3; a2++ )
    dump_data_ul2<s_xfrm_tunnel>(7, a2, delta, IOCTL_XFRM_GUTS, "IOCTL_XFRM_GUTS", t6[a2], dump_tunnel);
}

void dump_xfrm(sa64 delta)
{
  dump_data_ul1<s_xfrm_mgr>(1, IOCTL_XFRM_GUTS, "IOCTL_XFRM_GUTS", "xfrm_mgrs",
   [delta](size_t idx, const s_xfrm_mgr *curr) {
     printf(" [%ld] xfrm_mgr at", idx);
     dump_unnamed_kptr((unsigned long)curr->addr, delta, true);
     if ( curr->notify )
       dump_kptr(curr->notify, " notify", delta);
     if ( curr->acquire )
       dump_kptr(curr->acquire, " acquire", delta);
     if ( curr->compile_policy )
       dump_kptr(curr->compile_policy, " compile_policy", delta);
     if ( curr->new_mapping )
       dump_kptr(curr->new_mapping, " new_mapping", delta);
     if ( curr->notify_policy )
       dump_kptr(curr->notify_policy, " notify_policy", delta);
     if ( curr->report )
       dump_kptr(curr->report, " report", delta);
     if ( curr->migrate )
       dump_kptr(curr->migrate, " migrate", delta);
     if ( curr->is_alive )
       dump_kptr(curr->is_alive, " is_alive", delta);
   });
  // xfrm_translator
  s_xfrm_translator tr;
  tr.addr = (void *)2;
  int err = ioctl(g_fd, IOCTL_XFRM_GUTS, (int *)&tr);
  if ( !err && tr.addr )
  {
    printf("\nxfrm_translator at"); dump_unnamed_kptr((unsigned long)tr.addr, delta, true);
    if ( tr.alloc_compat )
     dump_kptr(tr.alloc_compat, " alloc_compat", delta);
    if ( tr.rcv_msg_compat )
     dump_kptr(tr.rcv_msg_compat, " alloc_compat", delta);
    if ( tr.xlate_user_policy_sockptr )
     dump_kptr(tr.xlate_user_policy_sockptr, " xlate_user_policy_sockptr", delta);
  }
  // protocols & tunnels
  dump_xfrm_pt(delta);
  // dump xfrm_state_afinfo
  dump_data_ul1<s_xfrm_state_afinfo>(3, IOCTL_XFRM_GUTS, "IOCTL_XFRM_GUTS", "xfrm_state_afinfos",
   [delta](size_t idx, const s_xfrm_state_afinfo *curr) {
     printf(" [%ld] xfrm_state_afinfo proto %d at", idx, curr->proto);
     dump_unnamed_kptr((unsigned long)curr->addr, delta, true);
     if ( curr->off_esp.addr ) dump_xfrm_offload(&curr->off_esp, delta);
     if ( curr->type_esp.addr ) dump_xfrm_type("type_esp", &curr->type_esp, delta);
     if ( curr->type_ipip.addr ) dump_xfrm_type("type_ipip", &curr->type_ipip, delta);
     if ( curr->type_ipip6.addr ) dump_xfrm_type("type_ipip6", &curr->type_ipip6, delta);
     if ( curr->type_comp.addr ) dump_xfrm_type("type_comp", &curr->type_comp, delta);
     if ( curr->type_ah.addr ) dump_xfrm_type("type_ah", &curr->type_ah, delta);
     if ( curr->type_routing.addr ) dump_xfrm_type("type_routing", &curr->type_routing, delta);
     if ( curr->type_dstopts.addr ) dump_xfrm_type("type_dstopts", &curr->type_dstopts, delta);
     if ( curr->output )
       dump_kptr(curr->output, "  output", delta);
     if ( curr->transport_finish )
       dump_kptr(curr->transport_finish, "  transport_finish", delta);
     if ( curr->local_error )
       dump_kptr(curr->local_error, "  local_error", delta);
     if ( curr->output_finish )
       dump_kptr(curr->output_finish, "  output_finish", delta);
     if ( curr->extract_input )
       dump_kptr(curr->extract_input, "  extract_input", delta);
     if ( curr->extract_output )
       dump_kptr(curr->extract_output, "  extract_output", delta);
   });
  // read xfrm_policy_afinfo
  int latch = 0;
  s_xfrm_policy_afinfo sp;
  unsigned long *args = (unsigned long *)&sp;
  for ( int i = 0; i < AF_MAX; i++ )
  {
    args[0] = 0;
    args[1] = i;
    err = ioctl(g_fd, IOCTL_XFRM_GUTS, (int *)args);
    if ( err ) continue;
    if ( !sp.addr ) continue;
    if ( !latch ) { printf("\n"); latch++; }
    printf("xfrm_policy_afinfo[%d] at", i);
    dump_unnamed_kptr((unsigned long)sp.addr, delta, true);
    if ( sp.dst_ops.addr )
    {
      printf(" dst_ops family %d at", sp.dst_ops.family);
      dump_unnamed_kptr((unsigned long)sp.dst_ops.addr, delta, true);
      if ( sp.dst_ops.gc )
        dump_kptr(sp.dst_ops.gc, "  gc", delta);
      if ( sp.dst_ops.check )
        dump_kptr(sp.dst_ops.check, "  check", delta);
      if ( sp.dst_ops.default_advmss )
        dump_kptr(sp.dst_ops.default_advmss, "  default_advmss", delta);
      if ( sp.dst_ops.mtu )
        dump_kptr(sp.dst_ops.mtu, "  mtu", delta);
      if ( sp.dst_ops.cow_metrics )
        dump_kptr(sp.dst_ops.cow_metrics, "  cow_metrics", delta);
      if ( sp.dst_ops.destroy )
        dump_kptr(sp.dst_ops.destroy, "  destroy", delta);
      if ( sp.dst_ops.ifdown )
        dump_kptr(sp.dst_ops.ifdown, "  ifdown", delta);
      if ( sp.dst_ops.negative_advice )
        dump_kptr(sp.dst_ops.negative_advice, "  negative_advice", delta);
      if ( sp.dst_ops.link_failure )
        dump_kptr(sp.dst_ops.link_failure, "  link_failure", delta);
      if ( sp.dst_ops.update_pmtu )
        dump_kptr(sp.dst_ops.update_pmtu, "  update_pmtu", delta);
      if ( sp.dst_ops.redirect )
        dump_kptr(sp.dst_ops.redirect, "  redirect", delta);
      if ( sp.dst_ops.local_out )
        dump_kptr(sp.dst_ops.local_out, "  local_out", delta);
      if ( sp.dst_ops.neigh_lookup )
        dump_kptr(sp.dst_ops.neigh_lookup, "  neigh_lookup", delta);
    }
    if ( sp.dst_lookup )
      dump_kptr(sp.dst_lookup, " dst_lookup", delta);
    if ( sp.get_saddr )
      dump_kptr(sp.get_saddr, " get_saddr", delta);
    if ( sp.fill_dst )
      dump_kptr(sp.fill_dst, " fill_dst", delta);
    if ( sp.blackhole_route )
      dump_kptr(sp.blackhole_route, " blackhole_route", delta);
    if ( sp.garbage_collect )
      dump_kptr(sp.garbage_collect, " garbage_collect", delta);
    if ( sp.init_dst )
      dump_kptr(sp.init_dst, " init_dst", delta);
    if ( sp.decode_session )
      dump_kptr(sp.decode_session, " decode_session", delta);
    if ( sp.get_tos )
      dump_kptr(sp.get_tos, " get_tos", delta);
    if ( sp.init_path )
      dump_kptr(sp.init_path, " init_path", delta);
  }
}

void dump_nfxt(unsigned long *buf, int idx, int what, sa64 delta)
{
  if ( !buf[0]) return;
  printf("NF[%d] %s: %ld:\n", idx, what ? "matches" : "targets", buf[0]);
  xt_common *xc = (xt_common *)(buf + 1);
  for ( unsigned long i = 0; i < buf[0]; i++, xc++ )
  {
    printf(" [%ld] %s hooks %d proto %d family %d addr", i, xc->name, xc->hooks, xc->proto, xc->family);
    dump_unnamed_kptr((unsigned long)xc->addr, delta, true);
    if ( xc->match )
      dump_kptr(xc->match, what ? " match" : " target", delta);
    if ( xc->checkentry )
      dump_kptr(xc->checkentry, " checkentry", delta);
    if ( xc->destroy )
      dump_kptr(xc->destroy, " destroy", delta);
    if ( xc->compat_from_user )
      dump_kptr(xc->compat_from_user, " compat_from_user", delta);
    if ( xc->compat_to_user )
      dump_kptr(xc->compat_to_user, " compat_to_user", delta);
  }
}

void dump_nfxt(sa64 delta)
{
  // lets first calc max count
  unsigned long max_items = 0;
  unsigned long args[3];
  for ( int i = 0; i < NFPROTO_NUMPROTO; i++ )
  {
    args[0] = i;
    args[1] = 0;
    args[2] = 0;
    int err = ioctl(g_fd, IOCTL_GET_NFXT, (int *)&args);
    if ( err ) continue;
    max_items = std::max(max_items, args[0]);
    // and the same for matches
    args[0] = i;
    args[1] = 1;
    args[2] = 0;
    err = ioctl(g_fd, IOCTL_GET_NFXT, (int *)&args);
    if ( err ) continue;
    max_items = std::max(max_items, args[0]);
  }
  printf("\nnfxt: max %ld\n", max_items);
  if ( !max_items ) return;
  // alloc mem
  size_t size = calc_data_size<xt_common>(max_items);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf ) {
    printf("dump_nfxt: cannot alloc %lX bytes\n", size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  for ( int i = 0; i < NFPROTO_NUMPROTO; i++ )
  {
    buf[0] = i;
    buf[1] = 0; // targets
    buf[2] = max_items;
    int err = ioctl(g_fd, IOCTL_GET_NFXT, (int *)buf);
    if ( err ) {
      printf("IOCTL_GET_NFXT targets failed, error %d (%s)\n", errno, strerror(errno));
    } else if ( buf[0] )
      dump_nfxt(buf, i, 0, delta);
    buf[0] = i;
    buf[1] = 1; // matches
    buf[2] = max_items;
    err = ioctl(g_fd, IOCTL_GET_NFXT, (int *)buf);
    if ( err ) {
      printf("IOCTL_GET_NFXT matches failed, error %d (%s)\n", errno, strerror(errno));
    } else if ( buf[0] )
      dump_nfxt(buf, i, 1, delta);
  }
}

void dump_nets(sa64 delta)
{
  unsigned long cnt = 0;
  int err = ioctl(g_fd, IOCTL_GET_NETS, (int *)&cnt);
  if ( err )
  {
    printf("IOCTL_GET_NETS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("nets: %ld\n", cnt);
  if ( !cnt )
    return;
  size_t size = calc_data_size<one_net>(cnt);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = cnt;
  err = ioctl(g_fd, IOCTL_GET_NETS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_NETS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size = buf[0];
  struct one_net *sb = (struct one_net *)(buf + 1);
  struct one_net *sr = sb;
  // calc max rules count
  unsigned long rsize = 0;
  for ( size_t idx = 0; idx < size; idx++, sr++ )
    rsize = std::max(rsize, sr->rules_cnt);
  unsigned long *rules = nullptr;
  if ( rsize )
  {
    rules = (unsigned long *)malloc( calc_data_size<one_fib_rule>(rsize) );
    if ( !rules ) printf("cannot alloc buffer for %ld find_rules\n", rsize);
  }
  dumb_free<unsigned long> rtmp(rules);
  for ( size_t idx = 0; idx < size; idx++, sb++ )
  {
    printf("Net[%ld]: %p ifindex %d rtnl %p genl_sock %p diag_nlsk %p uevent_sock %p dev_cnt %ld netdev_chain_cnt %ld\n",
      idx, sb->addr, sb->ifindex, sb->rtnl, sb->genl_sock, sb->diag_nlsk, sb->uevent_sock, sb->dev_cnt, sb->netdev_chain_cnt
    );
    if ( sb->hop_ntfy_cnt )
      printf(" nexthop.notifier_chain: %ld\n", sb->hop_ntfy_cnt);
    if ( sb->rtnl_proto )
      dump_kptr((unsigned long)sb->rtnl_proto, "rtnl_proto", delta);
    if ( sb->rtnl_filter )
      dump_kptr((unsigned long)sb->rtnl_filter, "rtnl_filter", delta);
    if ( sb->genl_sock_proto )
      dump_kptr((unsigned long)sb->genl_sock_proto, "genl_sock_proto", delta);
    if ( sb->genl_sock_filter )
      dump_kptr((unsigned long)sb->genl_sock_filter, "genl_sock_filter", delta);
    if ( sb->diag_nlsk_proto )
      dump_kptr((unsigned long)sb->diag_nlsk_proto, "diag_nlsk_proto", delta);
    if ( sb->diag_nlsk_filter )
      dump_kptr((unsigned long)sb->diag_nlsk_filter, "diag_nlsk_filter", delta);
    if ( sb->nf_outfn )
      dump_kptr((unsigned long)sb->nf_outfn, "nf.queue_handler.outfn", delta);
    if ( sb->nf_hook_drop )
      dump_kptr((unsigned long)sb->nf_hook_drop, "nf.queue_handler.nf_hook_drop", delta);
    // dump netfilter
    dump_nf_hooks(delta, sb->addr);
    dump_netf(delta, sb->addr);
    dump_nf_loggers(delta, sb->addr);
    // dump bpf
    if ( sb->progs[0] )
      printf(" netns_bpf[0]: %p\n", sb->progs[0]);
    if ( sb->bpf_cnt[0] )
      printf(" bpf_cnt[0]: %ld\n", sb->bpf_cnt[0]);
    if ( sb->progs[1] )
      printf(" netns_bpf[1]: %p\n", sb->progs[1]);
    if ( sb->bpf_cnt[1] )
      printf(" bpf_cnt[1]: %ld\n", sb->bpf_cnt[1]);
    // fib ntfy
    dump_fib_ntfy(sb->addr, delta);
    // fib rules
    if ( sb->rules_cnt ) {
      printf(" rules_cnt: %ld\n", sb->rules_cnt);
      if ( rules ) dump_fb_rules(sb->addr, sb->rules_cnt, rules, delta);
    }
    if ( !sb->dev_cnt )
      continue;
    size_t dsize = calc_data_size<one_net_dev>(sb->dev_cnt);
    unsigned long *dbuf = (unsigned long *)malloc(dsize);
    if ( !dbuf )
     continue;
    dumb_free<unsigned long> tmp2(dbuf);
    dbuf[0] = (unsigned long)sb->addr;
    dbuf[1] = sb->dev_cnt;
    err = ioctl(g_fd, IOCTL_GET_NET_DEVS, (int *)dbuf);
    if ( err )
    {
      printf("IOCTL_GET_NET_DEVS failed, error %d (%s)\n", errno, strerror(errno));
      continue;
    }
    dsize = dbuf[0];
    struct one_net_dev *nd = (struct one_net_dev *)(dbuf + 1);
    for ( size_t j = 0; j < dsize; j++, nd++ )
    {
      printf(" Dev[%ld]: %p %s ntfy_cnt %ld type %d mtu %d min_mtu %d max_mtu %d\n", 
        j, nd->addr, nd->name, nd->netdev_chain_cnt, nd->type, nd->mtu, nd->min_mtu, nd->max_mtu
      );
      if ( nd->priv_destructor )
        dump_kptr((unsigned long)nd->priv_destructor, " priv_destructor", delta);
      if ( nd->wireless_handler )
        dump_kptr((unsigned long)nd->wireless_handler, " wireless_handler", delta);
      if ( nd->wireless_get_stat )
        dump_kptr((unsigned long)nd->wireless_get_stat, " wireless_get_stat", delta);
      if ( nd->netdev_ops )
        dump_kptr((unsigned long)nd->netdev_ops, " netdev_ops", delta);
      if ( nd->ethtool_ops )
        dump_kptr((unsigned long)nd->ethtool_ops, " ethtool_ops", delta);
      if ( nd->l3mdev_ops )
        dump_kptr((unsigned long)nd->l3mdev_ops, " l3mdev_ops", delta);
      if ( nd->ndisc_ops )
        dump_kptr((unsigned long)nd->ndisc_ops, " ndisc_ops", delta);
      if ( nd->xfrmdev_ops )
      {
        dump_kptr((unsigned long)nd->xfrmdev_ops, " xfrmdev_ops", delta);
        if ( nd->xdo_dev_state_add )
          dump_kptr(nd->xdo_dev_state_add, "  xdo_dev_state_add", delta);
        if ( nd->xdo_dev_state_delete )
          dump_kptr(nd->xdo_dev_state_delete, "  xdo_dev_state_delete", delta);
        if ( nd->xdo_dev_state_free )
          dump_kptr(nd->xdo_dev_state_free, "  xdo_dev_state_free", delta);
        if ( nd->xdo_dev_offload_ok )
          dump_kptr(nd->xdo_dev_offload_ok, "  xdo_dev_offload_ok", delta);
        if ( nd->xdo_dev_state_advance_esn )
          dump_kptr(nd->xdo_dev_state_advance_esn, "  xdo_dev_state_advance_esn", delta);
        if ( nd->xdo_dev_state_update_stats )
          dump_kptr(nd->xdo_dev_state_update_stats, "  xdo_dev_state_update_stats", delta);
        if ( nd->xdo_dev_policy_add )
          dump_kptr(nd->xdo_dev_policy_add, "  xdo_dev_policy_add", delta);
        if ( nd->xdo_dev_policy_delete )
          dump_kptr(nd->xdo_dev_policy_delete, "  xdo_dev_policy_delete", delta);
        if ( nd->xdo_dev_policy_free )
          dump_kptr(nd->xdo_dev_policy_free, "  xdo_dev_policy_free", delta);
      }
      if ( nd->udp_tunnel_nic_info ) {
        dump_kptr2(nd->udp_tunnel_nic_info, " udp_tunnel_nic_info", delta);
        if ( nd->set_port )
          dump_kptr(nd->set_port, "  set_port", delta);
        if ( nd->unset_port )
          dump_kptr(nd->unset_port, "  unset_port", delta);
        if ( nd->sync_table )
          dump_kptr(nd->sync_table, "  sync_table", delta);
      }
      if ( nd->tlsdev_ops )
        dump_kptr((unsigned long)nd->tlsdev_ops, " tlsdev_ops", delta);
      if ( nd->header_ops )
        dump_kptr((unsigned long)nd->header_ops, " header_ops", delta);
      if ( nd->xdp_prog )
        dump_kptr((unsigned long)nd->xdp_prog, " xdp_prog", delta);
      if ( nd->rx_handler )
        dump_kptr((unsigned long)nd->rx_handler, " rx_handler", delta);
      if ( nd->rtnl_link_ops )
        dump_kptr((unsigned long)nd->rtnl_link_ops, " rtnl_link_ops", delta);
      if ( nd->dcbnl_ops )
        dump_kptr((unsigned long)nd->dcbnl_ops, " dcbnl_ops", delta);
      if ( nd->macsec_ops )
        dump_kptr((unsigned long)nd->macsec_ops, " macsec_ops", delta);
      // since 6.6
      if ( nd->tcx_in_cnt ) printf("   tcx_ingress bpf: %ld\n", nd->tcx_in_cnt);
      if ( nd->tcx_e_cnt )  printf("   tcx_egress bpf: %ld\n", nd->tcx_e_cnt);
      const size_t l4size = 4 * sizeof(unsigned long);
      if ( nd->num_ihook_entries )
      {
        printf("ingress num_hook_entries: %ld at %p\n", nd->num_ihook_entries, nd->nf_hooks_ingress);
        // TODO: add nf_hook_entry dunp for nf_hooks_ingress
        size_t dsize = std::max(l4size, sizeof(unsigned long) * (1 + nd->num_ihook_entries));
        unsigned long *ing = (unsigned long *)malloc(dsize);
        if ( ing )
        {
          dumb_free<unsigned long> tmp(ing);
          ing[0] = (unsigned long)sb->addr;
          ing[1] = (unsigned long)nd->addr;
          ing[2] = nd->num_ihook_entries;
          ing[3] = 0;
          dump_nf_hooks(delta, "in", ing);
        }
      }
      if ( nd->num_ehook_entries )
      {
        printf("egress num_hook_entries: %ld at %p\n", nd->num_ehook_entries, nd->nf_hooks_egress);
        // TODO: add nf_hook_entry dunp for nf_hooks_egress
        size_t dsize = std::max(l4size, sizeof(unsigned long) * (1 + nd->num_ehook_entries));
        unsigned long *ing = (unsigned long *)malloc(dsize);
        if ( ing )
        {
          dumb_free<unsigned long> tmp(ing);
          ing[0] = (unsigned long)sb->addr;
          ing[1] = (unsigned long)nd->addr;
          ing[2] = nd->num_ehook_entries;
          ing[3] = 1;
          dump_nf_hooks(delta, "e", ing);
        }
      }

      // dump xdp_state
      for ( int xdp = 0; xdp < 3; xdp++ )
      {
        if ( !nd->bpf_prog[xdp] && !nd->bpf_link[xdp] )
          continue;
        printf("  xdp_state[%d] prog %p link %p\n", xdp, nd->bpf_prog[xdp], nd->bpf_link[xdp]);
      }
    }
  }
  // sock diags
  for ( int i = 0; i < AF_MAX; i++ )
  {
    one_sock_diag sd;
    sd.addr = (void *)i;
    err = ioctl(g_fd, IOCTL_GET_SOCK_DIAG, (int *)&sd);
    if ( err )
    {
      printf("IOCTL_GET_SOCK_DIAG(%d) failed, error %d (%s)\n", i, errno, strerror(errno));
      continue;
    }
    if ( !sd.addr )
      continue;
    printf("sock_diag[%d]: %p\n", i, sd.addr);
    if ( sd.dump )
      dump_kptr((unsigned long)sd.dump, "dump", delta);
    if ( sd.get_info )
      dump_kptr((unsigned long)sd.get_info, "get_info", delta);
    if ( sd.destroy )
      dump_kptr((unsigned long)sd.destroy, "destroy", delta);
  }
  // netdev chains
  unsigned long nca = get_addr("netdev_chain");
  if ( nca )
  {
    unsigned long nc[2];
    nc[0] = nca + delta;
    nc[1] = 0;
    err = ioctl(g_fd, IOCTL_GET_NETDEV_CHAIN, (int *)nc);
    if ( err )
      printf("IOCTL_GET_NETDEV_CHAIN failed, error %d (%s)\n", errno, strerror(errno));
    else {
      printf("\nnetdev_chain at %p: %ld\n", (void *)(nca + delta), nc[0]);
      if ( nc[0] )
        dump_net_chains(nca, nc[0], delta);
    }
  } else
    rcf("netdev_chain");
  // proto list
  nca = get_addr("proto_list");
  auto plock = get_addr("proto_list_mutex");
  dump_protos(nca, plock, delta);
  // tcp congestion
  dump_data_noarg<one_tcp_cong>(IOCTL_TCP_CONG, "IOCTL_TCP_CONG", "tcp congestion" , 
    [&](size_t idx, const one_tcp_cong *c) {
      printf(" [%d] %s flags %X at", idx, c->name, c->flags);
      dump_unnamed_kptr((unsigned long)c->addr, delta, true);
      if ( c->init ) dump_kptr2(c->init, "  init", delta);
      if ( c->release ) dump_kptr2(c->release, "  release", delta);
      if ( c->ssthresh ) dump_kptr2(c->ssthresh, "  ssthresh", delta);
      if ( c->cong_avoid ) dump_kptr2(c->cong_avoid, "  cong_avoid", delta);
      if ( c->set_state ) dump_kptr2(c->set_state, "  set_state", delta);
      if ( c->cwnd_event ) dump_kptr2(c->cwnd_event, "  cwnd_event", delta);
      if ( c->in_ack_event ) dump_kptr2(c->in_ack_event, "  in_ack_event", delta);
      if ( c->undo_cwnd ) dump_kptr2(c->undo_cwnd, "  undo_cwnd", delta);
      if ( c->pkts_acked ) dump_kptr2(c->pkts_acked, "  pkts_acked", delta);
      if ( c->tso_segs_goal ) dump_kptr2(c->tso_segs_goal, "  tso_segs_goal", delta);
      if ( c->min_tso_segs ) dump_kptr2(c->min_tso_segs, "  min_tso_segs", delta);
      if ( c->sndbuf_expand ) dump_kptr2(c->sndbuf_expand, "  sndbuf_expand", delta);
      if ( c->cong_control ) dump_kptr2(c->cong_control, "  cong_control", delta);
      if ( c->get_info ) dump_kptr2(c->get_info, "  get_info", delta);
    }
  );
  // ulp ops
  nca = get_addr("tcp_ulp_list"); 
  plock = get_addr("tcp_ulp_list_lock");
  dump_ulps(nca, plock, delta);
  // pernet ops
  nca = get_addr("pernet_list");
  plock = get_addr("pernet_ops_rwsem");
  dump_pernet_ops(nca, plock, delta);
  // link ops
  nca = get_addr("link_ops");
  if ( !nca )
    rcf("link_ops");
  else
    dump_link_ops(nca, delta);
  // rtnl_af_ops
  nca = get_addr("rtnl_af_ops");
  if ( !nca )
    rcf("rtnl_af_ops");
  else
    dump_rtnl_af_ops(nca, delta);
  // protosw
  nca = get_addr("inetsw");
  plock = get_addr("inetsw_lock");
  if ( !nca )
    rcf("inetsw");
  else if ( !plock )
    rcf("inetsw_lock");
  else
    dump_protosw(nca, plock, delta, "inetsw");
  nca = get_addr("inetsw6");
  plock = get_addr("inetsw6_lock");
  if ( nca && plock )
    dump_protosw(nca, plock, delta, "inetsw6");
  // network block chains
  nca = get_addr("netlink_chain");
  if ( nca )
    dump_block_chain(nca, delta, "netlink_chain");
  nca = get_addr("inetaddr_chain");
  if ( nca )
    dump_block_chain(nca, delta, "inetaddr_chain");
//  inet6addr_chain is ATOMIC_NOTIFIER
//  nca = get_addr("inet6addr_chain");
//  if ( nca )
//    dump_block_chain(fd, nca, delta, "inet6addr_chain");
  nca = get_addr("inetaddr_validator_chain");
  if ( nca )
    dump_block_chain(nca, delta, "inetaddr_validator_chain");
  nca = get_addr("inet6addr_validator_chain");
  if ( nca )
    dump_block_chain(nca, delta, "inet6addr_validator_chain");
  // dump netlinks
  nca = get_addr("nl_table");
  plock = get_addr("nl_table_lock");
  dump_netlinks(nca, plock, delta);
  nca = get_addr("genl_fam_idr");
  dump_genl(nca, delta);
}

// ripped from include/uapi/linux/stat.h
const char *get_mod_name(unsigned long mod)
{
   auto what = mod & 00170000;
   if ( what == 0140000 )
     return "SOCK";
   if ( what == 0120000 )
     return "LNK";
   if ( what == 0100000 )
     return "FILE";
   if ( what == 060000 )
     return "BLK";
   if ( what == 040000 )
     return "DIR";
   if ( what == 020000 )
     return "CHR";
   if ( what == 010000 )
     return "FIFO";
   return "???";
}

void dump_marks(unsigned long size, one_fsnotify *of, sa64 delta, const char *margin = "")
{
  std::string m = margin;
  m += " ops";
  for ( size_t k = 0; k < size; k++ )
  {
    printf("%s fsnotify[%ld] %p mask %X ignored_mask %X flags %X\n", margin, k, of[k].mark_addr, of[k].mask, of[k].ignored_mask, of[k].flags);
    if ( of[k].group )
      printf("%s group: %p\n", margin, of[k].group);
    if ( of[k].ops )
      dump_kptr((unsigned long)of[k].ops, m.c_str(), delta);
  }
}

void dump_super_blocks(sa64 delta)
{
  unsigned long cnt = 0;
  int err = ioctl(g_fd, IOCTL_GET_SUPERBLOCKS, (int *)&cnt);
  if ( err )
  {
    printf("IOCTL_GET_SUPERBLOCKS count failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("super-blocks: %ld\n", cnt);
  if ( !cnt )
    return;
  size_t size = calc_data_size<one_super_block>(cnt);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
    return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = cnt;
  err = ioctl(g_fd, IOCTL_GET_SUPERBLOCKS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_GET_SUPERBLOCKS failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  size = buf[0];
//  printf("size %ld\n", size);
  init_mountinfo();
  struct one_super_block *sb = (struct one_super_block *)(buf + 1);
  for ( size_t idx = 0; idx < size; idx++ )
  {
    printf("superblock[%ld] at %p dev %ld flags %lX inodes %ld %s mnt_count %ld fs_info %p root %p %s\n", idx, sb[idx].addr, sb[idx].dev, sb[idx].s_flags, sb[idx].inodes_cnt, sb[idx].s_id, 
      sb[idx].mount_count, sb[idx].s_fs_info, sb[idx].s_root, sb[idx].root
    );
    if ( sb[idx].s_type )
      dump_kptr((unsigned long)sb[idx].s_type, "s_type", delta);
    if ( sb[idx].s_op )
      dump_kptr((unsigned long)sb[idx].s_op, "s_op", delta);
    if ( sb[idx].dq_op )
      dump_kptr((unsigned long)sb[idx].dq_op, "dq_op", delta);
    if ( sb[idx].s_qcop )
      dump_kptr((unsigned long)sb[idx].s_qcop, "s_qcop", delta);
    if ( sb[idx].s_export_op )
      dump_kptr((unsigned long)sb[idx].s_export_op, "s_export_op", delta);
    if ( sb[idx].s_cop )
      dump_kptr((unsigned long)sb[idx].s_cop, "s_cop", delta);
    if ( sb[idx].s_d_op )
      dump_kptr((unsigned long)sb[idx].s_d_op, "s_d_op", delta);
    if ( sb[idx].count_objects )
      dump_kptr((unsigned long)sb[idx].count_objects, " s_shrink.count_objects", delta);
    if ( sb[idx].scan_objects )
      dump_kptr((unsigned long)sb[idx].scan_objects, " s_shrink.scan_objects", delta);
    if ( sb[idx].s_fsnotify_mask || sb[idx].s_fsnotify_marks )
      printf(" s_fsnotify_mask: %lX s_fsnotify_marks %p\n", sb[idx].s_fsnotify_mask, sb[idx].s_fsnotify_marks);
    // dump super-block marks
    unsigned long sb_marks_arg[2] = { (unsigned long)sb[idx].addr, 0 };
    err = ioctl(g_fd, IOCTL_GET_SUPERBLOCK_MARKS, (int *)sb_marks_arg);
    if ( err )
    {
      printf("IOCTL_GET_SUPERBLOCK_MARKS count failed, error %d (%s)\n", errno, strerror(errno));
    } else if ( sb_marks_arg[1] )
    {
      size_t mmsize = calc_data_size<one_fsnotify>(sb_marks_arg[1]);
      unsigned long *mmbuf = (unsigned long *)malloc(mmsize);
      if ( mmbuf )
      {
        // params for IOCTL_GET_SUPERBLOCK_MARKS
        mmbuf[0] = (unsigned long)sb[idx].addr;
        mmbuf[1] = sb_marks_arg[1];
        err = ioctl(g_fd, IOCTL_GET_SUPERBLOCK_MARKS, (int *)mmbuf);
        if ( err )
          printf("IOCTL_GET_SUPERBLOCK_MARKS failed, error %d (%s)\n", errno, strerror(errno));
        else
          dump_marks(mmbuf[0], (one_fsnotify *)(mmbuf + 1), delta);
        free(mmbuf);
      }
    }
    // dump mounts
    if ( sb[idx].mount_count )
    {
      size_t msize = calc_data_size<one_mount>(sb[idx].mount_count);
      unsigned long *mbuf = (unsigned long *)malloc(msize);
      if ( mbuf )
      {
        // params for IOCTL_GET_SUPERBLOCK_MOUNTS
        mbuf[0] = (unsigned long)sb[idx].addr;
        mbuf[1] = sb[idx].mount_count;
        err = ioctl(g_fd, IOCTL_GET_SUPERBLOCK_MOUNTS, (int *)mbuf);
        if ( err )
        {
          printf("IOCTL_GET_SUPERBLOCK_MOUNTS failed, error %d (%s)\n", errno, strerror(errno));
        } else {
          msize = mbuf[0];
          struct one_mount *mnt = (struct one_mount *)(mbuf + 1);
          for ( size_t j = 0; j < msize; j++ )
          {
            const char *path = NULL;
            if ( mnt[j].mnt_root[0] )
              path = mnt[j].mnt_root;
            else if ( mnt[j].root[0] )
              path = mnt[j].root;
            else if ( mnt[j].mnt_mp[0] )
              path = mnt[j].mnt_mp;
            else
              path = get_mnt(mnt[j].mnt_id);
            printf(" mnt[%ld] %p mark_cnt %ld mnt_id %d %s\n", j, mnt[j].addr, mnt[j].mark_count, mnt[j].mnt_id, path ? path : "");
            if ( !mnt[j].mark_count )
              continue;
            size_t mmsize = calc_data_size<one_fsnotify>(mnt[j].mark_count);
            unsigned long *mmbuf = (unsigned long *)malloc(mmsize);
            if ( !mmbuf )
              continue;
            // params for IOCTL_GET_MOUNT_MARKS
            mmbuf[0] = (unsigned long)sb[idx].addr;
            mmbuf[1] = (unsigned long)mnt[j].addr;
            mmbuf[2] = mnt[j].mark_count;
            err = ioctl(g_fd, IOCTL_GET_MOUNT_MARKS, (int *)mmbuf);
            if ( err )
            {
               printf("IOCTL_GET_MOUNT_MARKS failed, error %d (%s)\n", errno, strerror(errno));
               free(mmbuf);
               continue;
            }
            dump_marks(mmbuf[0], (one_fsnotify *)(mmbuf + 1), delta, "   ");
            free(mmbuf);
          }
        }
        free(mbuf);
      }
    }
    // dump inodes
    if ( !sb[idx].inodes_cnt )
      continue;
    auto isize = calc_data_size<one_inode>(sb[idx].inodes_cnt);
    unsigned long *ibuf = (unsigned long *)malloc(isize);
    if ( !ibuf )
      continue;
    dumb_free<unsigned long> itmp(ibuf);
    // params for IOCTL_GET_SUPERBLOCK_INODES
    ibuf[0] = (unsigned long)sb[idx].addr;
    ibuf[1] = sb[idx].inodes_cnt;
    err = ioctl(g_fd, IOCTL_GET_SUPERBLOCK_INODES, (int *)ibuf);
    if ( err )
    {
      printf("IOCTL_GET_SUPERBLOCK_INODES failed, error %d (%s)\n", errno, strerror(errno));
      continue;
    }
    isize = ibuf[0];
    struct one_inode *inod = (struct one_inode *)(ibuf + 1);
    for ( size_t j = 0; j < isize; j++ )
    {
      if ( !g_opt_v && !inod[j].i_fsnotify_mask && !inod[j].i_fsnotify_marks )
        continue;
      const char *mod = get_mod_name(inod[j].i_mode);
      printf("  inode[%ld] %p i_no %ld i_flags %X %s\n", j, inod[j].addr, inod[j].i_ino, inod[j].i_flags, mod);
      if ( inod[j].i_fsnotify_mask || inod[j].i_fsnotify_marks )
        printf("    i_fsnotify_mask: %lX i_fsnotify_marks %p count %ld\n", inod[j].i_fsnotify_mask, inod[j].i_fsnotify_marks, inod[j].mark_count);
      if ( !inod[j].mark_count )
        continue;
      size_t msize = calc_data_size<one_fsnotify>(inod[j].mark_count);
      unsigned long *fbuf = (unsigned long *)malloc(msize);
      if ( !fbuf )
        continue;
      // params for IOCTL_GET_INODE_MARKS
      fbuf[0] = (unsigned long)sb[idx].addr;
      fbuf[1] = (unsigned long)inod[j].addr;
      fbuf[2] = inod[j].mark_count;
      err = ioctl(g_fd, IOCTL_GET_INODE_MARKS, (int *)fbuf);
      if ( err )
      {
        printf("IOCTL_GET_INODE_MARKS failed, error %d (%s)\n", errno, strerror(errno));
        free(fbuf);
        continue;
      }
      dump_marks(fbuf[0], (one_fsnotify *)(fbuf + 1), delta, "   ");
      free(fbuf);
    }
  }
}

int patch_kprobe(unsigned long a1, unsigned long a2, int idx, void *addr, int action)
{
  unsigned long args[5] = { a1, a2, (unsigned long)idx, (unsigned long)addr, (unsigned long)action };
  int err = ioctl(g_fd, IOCTL_KPROBE_DISABLE, (int *)&args);
  if ( err )
  {
    printf("IOCTL_KPROBE_DISABLE(%p) failed, error %d (%s)\n", addr, errno, strerror(errno));
    return -1;
  }
  if ( args[0] )
  {
    printf("found\n");
    return 1;
  }
  printf("not found\n");
  return 0;
}

void dump_sys_tab(sa64 delta)
{
  unsigned long cnt[2] = { 0, 0 };
  int err = ioctl(g_fd, IOCTL_SYS_TABLE, (int *)&cnt);
  if ( err )
  {
    printf("IOCTL_SYS_TABLE failed, error %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("sys_tab size %ld at", cnt[1]); dump_unnamed_kptr(cnt[0], delta);
  size_t ts = cnt[1] * sizeof(unsigned long);
  unsigned long *tab = (unsigned long *)malloc(ts);
  if ( !tab ) {
    printf("cannot alloc %X bytes for sys_table\n", ts);
    return;
  }
  dumb_free<unsigned long> tmp(tab);
  tab[0] = cnt[1];
  err = ioctl(g_fd, IOCTL_SYS_TABLE, (int *)tab);
  if ( err )
  {
    printf("IOCTL_SYS_TABLE(%ld) failed, error %d (%s)\n", cnt[1], errno, strerror(errno));
    return;
  }
  for ( size_t i = 0; i < cnt[1]; ++i )
  {
    if ( is_inside_kernel(tab[i] )) {
      if ( g_opt_v ) {
       printf("[%d]", i); dump_unnamed_kptr(tab[i], delta); }
      continue;
    }
    printf("sys_table entry %d patched: ", i); dump_unnamed_kptr(tab[i], delta);
  }
}

void dump_kprobes(sa64 delta)
{
  unsigned long a1 = get_addr("kprobe_table");
  if ( !a1 )
  {
    rcf("dump_kprobes", "kprobe_table");
    return;
  }
  unsigned long a2 = get_addr("kprobe_mutex");
  if ( !a2 )
  {
    rcf("dump_kprobes", "kprobe_mutex");
    return;
  }
  dump_data1arg<one_bl_kprobe>(a2, delta, IOCTL_KPROBES_BLACKLIST, nullptr, "IOCTL_KPROBES_BLACKLIST", "kprobes blacklist",
   [delta](int idx, const one_bl_kprobe *bl) {
     printf(" [%d] size %lX", idx, bl->end - bl->start);
     dump_unnamed_kptr(bl->start, delta, true);
   }
  );
  size_t curr_n = 3;
  size_t ksize = calc_data_size<one_kprobe>(curr_n);
  unsigned long *buf = (unsigned long *)malloc(ksize);
  if ( !buf )
    return;
  for ( int i = 0; i < 64; i++ )
  {
    unsigned long params[3] = { a1 + delta, a2 + delta, (unsigned long)i };
    int err = ioctl(g_fd, IOCTL_CNT_KPROBE_BUCKET, (int *)&params);
    if ( err )
    {
      printf("IOCTL_CNT_KPROBE_BUCKET(%d) failed, error %d (%s)\n", i, errno, strerror(errno));
      continue;
    }
    if ( !params[0] )
      continue;
    printf("kprobes[%d]: %ld\n", i, params[0]);
    // ok, we have some kprobes, read them all
    if ( params[0] > curr_n )
    {
      unsigned long *tmp;
      ksize = calc_data_size<one_kprobe>(params[0]);
      tmp = (unsigned long *)malloc(ksize);
      if ( tmp == NULL )
        break;
      curr_n = params[0];
      free(buf);
      buf = tmp;
    }
    // fill params
    buf[0] = a1 + delta;
    buf[1] = a2 + delta;
    buf[2] = (unsigned long)i;
    buf[3] = params[0];
    err = ioctl(g_fd, IOCTL_GET_KPROBE_BUCKET, (int *)buf);
    if ( err )
    {
      printf("IOCTL_GET_KPROBE_BUCKET(%d) failed, error %d (%s)\n", i, errno, strerror(errno));
      continue;
    }
    // dump
    ksize = buf[0];
    struct one_kprobe *kp = (struct one_kprobe *)(buf + 1);
    for ( size_t idx = 0; idx < ksize; idx++ )
    {
      if ( kp[idx].is_aggr )
        printf(" kprobe at %p flags %X aggregated\n", kp[idx].kaddr, kp[idx].flags);
      else {
        if ( kp[idx].is_retprobe )
          printf(" kprobe at %p flags %X retprobe\n", kp[idx].kaddr, kp[idx].flags);
        else
          printf(" kprobe at %p flags %X\n", kp[idx].kaddr, kp[idx].flags);
        auto is_d = g_kpd.find((unsigned long)kp[idx].kaddr);
        if ( is_d != g_kpd.end() )
        {
          printf("disable kprobe: ");
          patch_kprobe(a1 + delta, a2 + delta, i, kp[idx].kaddr, 0);
        }  
        auto is_e = g_kpe.find((unsigned long)kp[idx].kaddr);
        if ( is_e != g_kpe.end() )
        {
          printf("enable kprobe: ");
          patch_kprobe(a1 + delta, a2 + delta, i, kp[idx].kaddr, 1);
        }  
      }
      dump_kptr((unsigned long)kp[idx].addr, " addr", delta);
      if ( kp[idx].pre_handler )
        dump_kptr((unsigned long)kp[idx].pre_handler, " pre_handler", delta);
      if ( kp[idx].post_handler )
        dump_kptr((unsigned long)kp[idx].post_handler, " post_handler", delta);
      if ( kp[idx].fault_handler )
        dump_kptr((unsigned long)kp[idx].fault_handler, " fault_handler", delta);
      if ( kp[idx].is_retprobe )
      {
        if ( kp[idx].kret_handler )
          dump_kptr((unsigned long)kp[idx].kret_handler, " kret_handler", delta);
        if ( kp[idx].kret_entry_handler )
          dump_kptr((unsigned long)kp[idx].kret_entry_handler, " kret_entry_handler", delta);
      }
      // dump aggregated kprobes
      if ( kp[idx].is_aggr )
      {
        unsigned long cbuf[5] = { 
          a1 + delta,
          a2 + delta,
          (unsigned long)i,
          (unsigned long)kp[idx].kaddr,
          0
        };
        err = ioctl(g_fd, IOCTL_GET_AGGR_KPROBE, (int *)cbuf);
        if ( err )
        {
          printf("IOCTL_GET_AGGR_KPROBE cnt for %p failed, error %d (%s)\n", kp[idx].kaddr, errno, strerror(errno));
          continue;
        }
        if ( !cbuf[0] )
          continue;
        printf("  %ld aggregated kprobes:\n", cbuf[0]);
        auto isize = calc_data_size<one_kprobe>(cbuf[0]);
        unsigned long *ibuf = (unsigned long *)malloc(isize);
        if ( !ibuf )
          continue;
        dumb_free<unsigned long> itmp(ibuf);
        // fill params for real aggregated kprobes extracting
        ibuf[0] = a1 + delta;
        ibuf[1] = a2 + delta;
        ibuf[2] = (unsigned long)i;
        ibuf[3] = (unsigned long)kp[idx].kaddr;
        ibuf[4] = cbuf[0];
        err = ioctl(g_fd, IOCTL_GET_AGGR_KPROBE, (int *)ibuf);
        if ( err )
        {
          printf("IOCTL_GET_AGGR_KPROBE for %p failed, error %d (%s)\n", kp[idx].kaddr, errno, strerror(errno));
          continue;
        }
        auto agsize = ibuf[0];
        struct one_kprobe *kp = (struct one_kprobe *)(ibuf + 1);
        for ( size_t idx2 = 0; idx2 < agsize; idx2++ )
        {
          printf("  [%ld] at %p", idx2, kp[idx2].kaddr);
          if ( kp[idx2].is_retprobe )
            printf(" kretprobe");
          printf("\n");
          auto is_d = g_kpd.find((unsigned long)kp[idx2].kaddr);
          if ( is_d != g_kpd.end() )
          {
            printf("disable kprobe: ");
            patch_kprobe(a1 + delta, a2 + delta, i, kp[idx2].kaddr, 0);
          }  
          auto is_e = g_kpe.find((unsigned long)kp[idx2].kaddr);
          if ( is_e != g_kpe.end() )
          {
            printf("enable kprobe: ");
            patch_kprobe(a1 + delta, a2 + delta, i, kp[idx2].kaddr, 1);
          }  

          if ( kp[idx2].pre_handler )
            dump_kptr((unsigned long)kp[idx2].pre_handler, "    pre_handler", delta);
          if ( kp[idx2].post_handler )
            dump_kptr((unsigned long)kp[idx2].post_handler, "    post_handler", delta);
          if ( kp[idx2].fault_handler )
            dump_kptr((unsigned long)kp[idx2].fault_handler, "    fault_handler", delta);
          if ( kp[idx2].is_retprobe )
          {
            if ( kp[idx2].kret_handler )
              dump_kptr((unsigned long)kp[idx2].kret_handler, "    kret_handler", delta);
            if ( kp[idx2].kret_entry_handler )
              dump_kptr((unsigned long)kp[idx2].kret_entry_handler, "    kret_entry_handler", delta);
          }
        }
      }
    }
  }
  if ( buf != NULL )
    free(buf);
}

void install_urn(int action)
{
  unsigned long param = action;
  int err = ioctl(g_fd, IOCTL_TEST_URN, (int *)&param);
  if ( err )
    printf("install_urn(%d) failed, error %d (%s)\n", action, errno, strerror(errno));
}

static size_t calc_urntfy_size(size_t n)
{
  return (n + 1) * sizeof(unsigned long);
}

static size_t calc_freq_ntfy_size(size_t n)
{
  if ( n < 2 )
    return 3 * sizeof(unsigned long);
  return (n + 1) * sizeof(unsigned long);
}

void dump_freq_ntfy(const char *pfx, unsigned long *buf, sa64 delta)
{
  int err = ioctl(g_fd, READ_CPUFREQ_NTFY, buf);
  if ( err )
  {
    fprintf(stderr, "dump_freq_ntfy for %s failed, error %d (%s)\n", pfx, err, strerror(err));
    return;
  }
  for ( size_t i = 0; i < buf[0]; i++ )
  {
    printf(" %s[%ld]", pfx, i);
    dump_unnamed_kptr(buf[i+1], delta);
  }
}

void dump_freq_ntfy(sa64 delta)
{
  int cpu_num = get_nprocs();
  unsigned long arg[3] = { 0, 0, 0 };
  for ( int i = 0; i < cpu_num; i++ )
  {
    arg[0] = i;
    int err = ioctl(g_fd, READ_CPUFREQ_CNT, (int *)&arg);
    if ( err )
    {
      printf("dump_freq_ntfy count for cpu_id %d failed, error %d (%s)\n", i, errno, strerror(errno));
      break;
    }
    printf("cpufreq_policy[%d] at %p min_cnt %ld max_cnt %ld\n", i, (void *)arg[0], arg[1], arg[2]);
    if ( !arg[1] && !arg[2] )
      continue;
    size_t cnt_size = calc_freq_ntfy_size(std::max(arg[1], arg[2]));
    unsigned long *buf = (unsigned long *)malloc(cnt_size);
    if ( !buf )
    {
      printf("cannot alloc %ld bytes of memory for cpufreq_policy[%d]\n", cnt_size, i);
      continue;
    }
    dumb_free<unsigned long> tmp(buf);
    if ( arg[1] )
    {
      buf[0] = i;
      buf[1] = arg[1];
      buf[2] = 0;
      dump_freq_ntfy("min", buf, delta);
    }
    if ( arg[2] )
    {
      buf[0] = i;
      buf[1] = arg[2];
      buf[2] = 1;
      dump_freq_ntfy("max", buf, delta);
    }
  }
}

void dump_return_notifier_list(unsigned long this_off, unsigned long off, sa64 delta)
{
  int cpu_num = get_nprocs();
  size_t curr_n = 3;
  size_t size = calc_urntfy_size(curr_n);
  unsigned long *ntfy = (unsigned long *)malloc(size);
  if ( ntfy == NULL )
    return;
  for ( int i = 0; i < cpu_num; i++ )
  {
    unsigned long buf[3] = { (unsigned long)i, this_off, off };
    int err = ioctl(g_fd, IOCTL_CNT_RNL_PER_CPU, (int *)buf);
    if ( err )
    {
      printf("dump_return_notifier_list count for cpu_id %d failed, error %d (%s)\n", i, errno, strerror(errno));
      break;
    }
    if ( buf[0] )
      printf("cpu[%d]: head %p %ld\n", i, (void *)buf[0], buf[1]);
    else
      printf("cpu[%d]: %ld\n", i, buf[1]);
    if ( !buf[1] )
      continue; // no ntfy on this cpu
    // read ntfy
    if ( buf[1] > curr_n )
    {
      unsigned long *tmp;
      size = calc_urntfy_size(buf[1]);
      tmp = (unsigned long *)malloc(size);
      if ( tmp == NULL )
        break;
      curr_n = buf[1];
      free(ntfy);
      ntfy = tmp;
    }
    // fill params
    ntfy[0] = (unsigned long)i;
    ntfy[1] = this_off;
    ntfy[2] = off;
    ntfy[3] = buf[1];
    err = ioctl(g_fd, IOCTL_RNL_PER_CPU, (int *)ntfy);
    if ( err )
    {
      printf("dump_return_notifier_list for cpu_id %d cnt %ld failed, error %d (%s)\n", i, buf[1], errno, strerror(errno));
      break;
    }
    // dump
    size = ntfy[0];
    for ( size_t j = 0; j < size; j++ )
    {
      dump_kptr(ntfy[1 + j], "ntfy", delta);
    }
  }
  if ( ntfy != NULL )
    free(ntfy);
}

void dump_efivar_ops_field(char *ptr, const char *fname, sa64 delta)
{
  char *arg = ptr;
  int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
   if ( err )
     printf("cannot read %s at %p, err %d\n", fname, ptr, err);
   else if ( arg )
     dump_kptr((unsigned long)arg, fname, delta);
}

// generic_efivars is struct efivars - 2nd ptr is efivar_operations which has 5 function pointers
// see https://elixir.bootlin.com/linux/v5.14-rc7/source/include/linux/efi.h#L948
void dump_efivars(a64 saddr, sa64 delta)
{
   char *ptr = (char *)saddr + delta + 2 * sizeof(void *);
   char *arg = ptr;
   int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
   if ( err )
   {
      printf("dump_efivars: read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
      return;
   }
   if ( !arg )
     return;
   if ( is_inside_kernel((unsigned long)arg) )
      printf("efivar_operations at %p: %p - kernel\n", ptr, arg);
   else {
     const char *mname = find_kmod((unsigned long)arg);
     if ( mname )
     {
       GET_NAME((unsigned long)arg);
       if ( sname )
         printf("efivar_operations at %p: %p - %s!%s\n", ptr, arg, mname, sname);
       else
         printf("efivar_operations at %p: %p - %s\n", ptr, arg, mname);
     } else
       printf("efivar_operations at %p: %p UNKNOWN\n", ptr, arg);
   }
   // dump all five fields
   ptr = arg;
   dump_efivar_ops_field(ptr, "get_variable", delta);

   ptr += sizeof(void *);
   dump_efivar_ops_field(ptr, "get_variable_next", delta);

   ptr += sizeof(void *);
   dump_efivar_ops_field(ptr, "set_variable", delta);

   ptr += sizeof(void *);
   dump_efivar_ops_field(ptr, "set_variable_nonblocking", delta);

   ptr += sizeof(void *);
   dump_efivar_ops_field(ptr, "query_variable_store", delta);
}

void dump_usb_mon(a64 saddr, sa64 delta)
{
   char *ptr = (char *)saddr + delta;
   char *arg = ptr;
   int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
   if ( err )
   {
      printf("dump_usb_mon: read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
      return;
   }
   if ( arg )
   {
     if ( is_inside_kernel((unsigned long)arg) )
       printf("mon_ops at %p: %p - kernel\n", (char *)saddr + delta, arg);
     else {
       const char *mname = find_kmod((unsigned long)arg);
       if ( mname )
       {
         GET_NAME((unsigned long)arg)
         if ( sname )
           printf("mon_ops at %p: %p - %s!%s\n", (char *)saddr + delta, arg, mname, sname);
         else
           printf("mon_ops at %p: %p - %s\n", (char *)saddr + delta, arg, mname);
       } else
         printf("mon_ops at %p: %p UNKNOWN\n", (char *)saddr + delta, arg);
     }
   } else 
     printf("mon_ops at %p: %p\n", (char *)saddr + delta, arg);
   if ( !arg )
     return;
   // see https://elixir.bootlin.com/linux/v5.14-rc7/source/include/linux/usb/hcd.h#L702
   // we need read 3 pointers at ptr
   ptr = arg;
   dump_efivar_ops_field(ptr, "urb_submit", delta);

   ptr += sizeof(void *);
   dump_efivar_ops_field(ptr, "urb_submit_error", delta);
 
   ptr += sizeof(void *);
   dump_efivar_ops_field(ptr, "urb_complete", delta);
}

static size_t calc_tp_size(size_t n)
{
  return sizeof(unsigned long) + n * sizeof(one_tracepoint_func);
}

void dump_tp_funcs(sa64 delta, unsigned long *ntfy)
{
  one_tracepoint_func *curr = (one_tracepoint_func *)(ntfy + 1);
  for ( size_t j = 0; j < ntfy[0]; j++ , curr++ )
  {
    printf("  [%ld] data %p", j, (void *)curr->data);
    dump_unnamed_kptr(curr->addr, delta);
  }
}

void dump_mod_tracepoints(sa64 delta, unsigned long begin, unsigned int num)
{
   size_t size = calc_data_size<one_mod_tracepoint>(num);
   unsigned long *buf = (unsigned long *)malloc(size);
   if ( !buf )
   {
     printf("cannot alloc %lX bytes for nodule tracepoints\n", size);
     return;
   }
   dumb_free<unsigned long> itmp(buf);
   buf[0] = begin;
   buf[1] = num;
   int err = ioctl(g_fd, IOCTL_MOD_TRACEPOINTS, (int *)buf);
   if ( err )
   {
      printf("IOCTL_MOD_TRACEPOINTS count error %d (%s)\n", err, strerror(errno));
      return;
   }
   one_mod_tracepoint *curr = (one_mod_tracepoint *)(buf + 1);
   // calc number of tracepoint functions
   size_t fnum = 0;
   for ( unsigned long l = 0; l < buf[0]; l++ )
     fnum = std::max(fnum, curr[l].f_count);
   // alloc mem for tracepoint functions
   if ( fnum ) fnum = calc_tp_size(fnum);
   unsigned long *tmp = nullptr;
   if ( fnum ) tmp = (unsigned long *)malloc(fnum);
   // iterate
   for ( unsigned long l = 0; l < buf[0]; l++ )
   {
      printf(" [%ld] at %p: enabled %d cnt %d\n", l, curr[l].addr, (int)curr[l].enabled, (int)curr[l].f_count);
      if ( curr[l].iterator ) dump_kptr(curr[l].iterator, " iterator", delta);
      if ( curr[l].regfunc ) dump_kptr(curr[l].regfunc, " regfunc", delta);
      if ( curr[l].unregfunc ) dump_kptr(curr[l].regfunc, " unregfunc", delta);
      if ( !curr[l].f_count ) continue;
      // dump funcs
      tmp[0] = (unsigned long)curr[l].addr;
      tmp[1] = curr[l].f_count;
      err = ioctl(g_fd, IOCTL_TRACEPOINT_FUNCS, (int *)tmp);
      if ( err )
      {
        printf("error %d while read tracepoint funcs at %p\n", errno, curr[l].addr);
        continue;
      }
      dump_tp_funcs(delta, tmp);
   }
   if ( tmp ) free(tmp);
}

void check_tracepoints(sa64 delta, addr_sym *tsyms, size_t tcount)
{
  // alloc enough memory for tracepoint info
  size_t i, j, curr_n = 3;
  size_t size = calc_tp_size(curr_n);
  unsigned long *ntfy = (unsigned long *)malloc(size);
  if ( ntfy == NULL )
    return;
  for ( i = 0; i < tcount; i++ )
  {
    a64 addr = (a64)((char *)tsyms[i].addr + delta);
    ntfy[0] = addr;
    int err = ioctl(g_fd, IOCTL_TRACEPOINT_INFO, (int *)ntfy);
    if ( err )
    {
      printf("error %d while read tracepoint info for %s at %p\n", errno, tsyms[i].name, (void *)addr);
      continue;
    }
    printf(" %s at %p: enabled %d cnt %d\n", tsyms[i].name, (void *)addr, (int)ntfy[0], (int)ntfy[3]);
    // 1 - regfunc
    if ( ntfy[1] )
       dump_kptr(ntfy[1], " regfunc", delta);
    // 2 - unregfunc
    if ( ntfy[2] )
       dump_kptr(ntfy[2], " unregfunc", delta);
    if ( !ntfy[3] )
      continue;
    auto curr_cnt = ntfy[3];
    if ( curr_cnt > curr_n )
    {
      unsigned long *tmp;
      size = calc_tp_size(curr_cnt);
      tmp = (unsigned long *)malloc(size);
      if ( tmp == NULL )
        break;
      curr_n = curr_cnt;
      free(ntfy);
      ntfy = tmp;
    }
    // dump funcs
    ntfy[0] = addr;
    ntfy[1] = curr_cnt;
    err = ioctl(g_fd, IOCTL_TRACEPOINT_FUNCS, (int *)ntfy);
    if ( err )
    {
      printf("error %d while read tracepoint funcs for %s at %p\n", errno, tsyms[i].name, (void *)addr);
      continue;
    }
    dump_tp_funcs(delta, ntfy);
  }
  free(ntfy);
}

void dunp_kalarms(sa64 delta)
{
  for ( int i = 0; i < 2; ++i )
  {
    unsigned long params[3] = { (unsigned long)i, 0, 0 };
    int err = ioctl(g_fd, IOCTL_GET_ALARMS, (int *)&params);
    if ( err )
    {
      printf("error %d while read IOCTL_GET_ALARMS %d cnt\n", err, i);
      continue;
    }
    printf("kalarms %d: cnt %ld\n", i, params[0]);
    if ( params[1] )
      dump_kptr(params[1], " get_ktime", delta);
    if ( params[2] )
      dump_kptr(params[2], " get_timespec", delta);
    if ( !params[0] )
      continue;
    size_t size = calc_data_size<one_alarm>(params[0]);
    unsigned long *buf = (unsigned long *)malloc(size);
    if ( !buf )
    {
      printf("cannot alloc buffer for kalarmss, len %lX\n", size);
      continue;
    }
    dumb_free<unsigned long> tmp(buf);
    // fill params
    buf[0] = (unsigned long)i;
    buf[1] = params[0];
    err = ioctl(g_fd, IOCTL_GET_ALARMS, (int *)buf);
    if ( err )
    {
      printf("error %d while read IOCTL_GET_ALARMS %d\n", errno, i);
      continue;
    }
    one_alarm *k = (one_alarm *)(buf + 1);
    for ( unsigned long l = 0; l < buf[0]; ++k, ++l )
    {
      printf(" %p\n", k->addr);
      if ( k->hr_timer )
        dump_kptr((unsigned long)k->hr_timer, " hr_timer", delta);
      if ( k->func )
        dump_kptr((unsigned long)k->func, " func", delta);
    }
  }
}

size_t calc_tsize(unsigned long c)
{
  return sizeof(unsigned long) + c * sizeof(ktimer);
}

void dump_ktimers(a64 off, a64 poff, sa64 delta)
{
  if ( !poff )
  {
    rcf("dump_ktimers", "__per_cpu_offset");
    return;
  }
  int cpu_num = get_nprocs();
  int i;
  // fill per_cpu offsets
  unsigned long *per = (unsigned long *)calloc(cpu_num, sizeof(unsigned long));
  if ( NULL == per )
  {
    printf("cannot alloc per-cpu array\n");
    return;
  }
  dumb_free<unsigned long> ptmp { per };
  poff += delta;
  printf("__per_cpu_offset at %p\n", (void *)poff);
  for ( i = 0; i < cpu_num; i++ )
  {
    unsigned long addr = poff + i * sizeof(unsigned long);
    int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&addr);
    if ( err )
    {
      printf("error %d while read per_cpu %d\n", err, i);
      continue;
    }
    per[i] = addr;
    printf("per_cpu[%d]: %p\n", i, (void *)per[i] ); 
  }
  unsigned long tmax = 0;
  for ( i = 0; i < cpu_num; i++ )
  {
    if ( !per[i] )
      continue;
    unsigned long par[2] = { per[i] + off, 0 };
    int err = ioctl(g_fd, IOCTL_GET_KTIMERS, (int *)par);
    if ( err )
    {
      printf("error %d while read timers count for cpu %d\n", err, i);
      continue;
    }
    if ( par[0] > tmax )
      tmax = par[0];
  }
  if ( !tmax )
    return;
  // alloc enough memory
#ifdef _DEBUG
  printf("tmax %ld\n", tmax);
#endif  
  size_t tsize = calc_tsize(tmax);
  unsigned long *buf = (unsigned long *)malloc(tsize);
  if ( !buf )
  {
    printf("cannot alloc buffer for timers, len %lX\n", tsize);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  for ( i = 0; i < cpu_num; i++ )
  {
    if ( !per[i] )
      continue;
    buf[0] = per[i] + off;
    buf[1] = tmax;
    int err = ioctl(g_fd, IOCTL_GET_KTIMERS, (int *)buf);
    if ( err )
    {
      printf("error %d while read timers for cpu %d\n", err, i);
      continue;
    }
    ktimer *k = (ktimer *)(buf + 1);
    printf("timers for cpu %d %ld:\n", i, buf[0]);
    for ( unsigned long l = 0; l < buf[0]; ++k, ++l )
    {
      if ( k->wq_addr )
        printf(" %p wq %p flags %X %p", k->addr, k->wq_addr, k->flags, k->func);
      else
        printf(" %p flags %X %p", k->addr, k->flags, k->func);
      dump_unnamed_kptr((unsigned long)k->func, delta);
    }
  }
}
#endif /* !_MSC_VER */

int is_nop(unsigned char *body)
{
  // nop dword ptr [rax+rax+00h] - 0F 1F 44 00 00
  if ( body[0] == 0xF  &&
       body[1] == 0x1F &&
       body[2] == 0x44 &&
       body[3] == 0    &&
       body[4] == 0
     )
   return 1;
  // just 90
  if ( body[0] == 0x90 &&
       body[1] == 0x90 &&
       body[2] == 0x90 &&
       body[3] == 0x90 &&
       body[4] == 0x90
     )
   return 1;
  return 0;
}

void dump_addr_name(a64 addr)
{
   const char *name = lower_name_by_addr(addr);
   if ( name != NULL )
      printf("%p # %s\n", (void *)addr, name);
   else
      printf("%p\n", (void *)addr);
}

void dump_kernfs(kernfs_res &res, sa64 delta)
{
  if ( res.addr )
  {
    // dump flags
    printf(" flags: %lX", res.flags);
    if ( res.flags & 1 )
      printf(" DIR");
    if ( res.flags & 2 )
      printf(" FILE");
    if ( res.flags & 4 )
      printf(" LINK");
    printf("\n");

    printf(" priv: %p\n", (void *)res.priv);
    if ( res.kobject )
      printf("kobject: %p\n", (void *)res.kobject);
    if ( res.ktype )
      dump_kptr(res.ktype, "ktype", delta);
    if ( res.release )
      dump_kptr(res.release, "ktype.release", delta);
    if ( res.child_ns_type )
      dump_kptr(res.child_ns_type, "ktype.child_ns_type", delta);
    if ( res.ns )
      dump_kptr(res.ns, "ktype.namespace", delta);
    if ( res.get_ownership )
      dump_kptr(res.get_ownership, "ktype.get_ownership", delta);
    if ( res.sysfs_ops )
      dump_kptr(res.sysfs_ops, "sysfs_ops", delta);
    if ( res.show )
      dump_kptr(res.show, "sysfs_ops.show", delta);
    if ( res.store )
      dump_kptr(res.store, "sysfs_ops.store", delta);
  } else {
    printf(" inode: %p\n", (void *)res.flags);
    if ( res.s_op )
      dump_kptr(res.s_op, "s_op", delta);
    if ( res.priv )
      dump_kptr(res.priv, "inode->i_fop", delta);
    if ( res.ktype )
      dump_kptr(res.ktype, "debugfs_real_fops", delta);
    if ( res.sysfs_ops )
      dump_kptr(res.sysfs_ops, "private_data", delta);
  }
}

void dump_bus(one_priv &p, sa64 delta, const char *fname)
{
  if ( p.uevent_ops )
  {
    dump_kptr((unsigned long)p.uevent_ops, "uevent_ops", delta);
    if ( p.filter )
      dump_kptr((unsigned long)p.filter, "  filter", delta);
    if ( p.name )
      dump_kptr((unsigned long)p.name, "  name", delta);
    if ( p.uevent )
      dump_kptr((unsigned long)p.uevent, "  uevent", delta);
  }
  if ( p.bus )
  {
    dump_kptr2((unsigned long)p.bus, "bus", delta);
    if ( p.match )
      dump_kptr((unsigned long)p.match, "  match", delta);
    if ( p.bus_uevent )
      dump_kptr((unsigned long)p.bus_uevent, "  bus.uevent", delta);
    if ( p.probe )
      dump_kptr((unsigned long)p.probe, "  probe", delta);
    if ( p.sync_state )
      dump_kptr((unsigned long)p.sync_state, "  sync_state", delta);
    if ( p.remove )
      dump_kptr((unsigned long)p.remove, "  remove", delta);
    if ( p.shutdown )
      dump_kptr((unsigned long)p.shutdown, "  shutdown", delta);
    if ( p.online )
      dump_kptr((unsigned long)p.online, "  online", delta);
    if ( p.offline )
      dump_kptr((unsigned long)p.offline, "  offline", delta);
    if ( p.suspend )
      dump_kptr((unsigned long)p.suspend, "  suspend", delta);
    if ( p.resume )
      dump_kptr((unsigned long)p.resume, "  resume", delta);
    if ( p.num_vf )
      dump_kptr((unsigned long)p.num_vf, "  num_vf", delta);
    if ( p.dma_configure )
      dump_kptr((unsigned long)p.dma_configure, "  dma_configure", delta);
    if ( p.dma_cleanup )
      dump_kptr((unsigned long)p.dma_cleanup, "  dma_cleanup", delta);
    if ( p.pm )
      dump_kptr((unsigned long)p.pm, "  pm", delta);
    if ( p.iommu_ops )
      dump_kptr((unsigned long)p.iommu_ops, "  iommu_ops", delta);
  }
  if ( p._class )
  {
    dump_kptr2((unsigned long)p._class, "class", delta);
    if ( p.dev_uevent )
      dump_kptr((unsigned long)p.dev_uevent, "  dev_uevent", delta);
    if ( p.devnode )
      dump_kptr((unsigned long)p.devnode, "  devnode", delta);
    if ( p.class_release )
      dump_kptr((unsigned long)p.class_release, "  class_release", delta);
    if ( p.dev_release )
      dump_kptr((unsigned long)p.dev_release, "  dev_release", delta);
    if ( p.c_susped )
      dump_kptr((unsigned long)p.c_susped, "  suspend", delta);
    if ( p.c_resume )
      dump_kptr((unsigned long)p.c_resume, "  resume", delta);
    if ( p.c_shutdown )
      dump_kptr((unsigned long)p.c_shutdown, "  shutdown", delta);
    if ( p.c_ns_type )
      dump_kptr((unsigned long)p.c_ns_type, "  ns_type", delta);
    if ( p.c_namespace )
      dump_kptr((unsigned long)p.c_namespace, "  namespace", delta);
    if ( p.c_getownership )
      dump_kptr((unsigned long)p.c_getownership, "  get_ownership", delta);
  }
  if ( p.ntfy_cnt ) printf(" ntfy_cnt: %ld\n", p.ntfy_cnt);
  else return;
  // in params: ptr + fname + 1 zero byte
  size_t buf_size = sizeof(unsigned long) + 1 + strlen(fname);
  // out params: N + N unsigned longs
  buf_size = std::max(buf_size, sizeof(unsigned long) * (1 + p.ntfy_cnt));
  unsigned long *buf = (unsigned long *)malloc(buf_size);
  if ( !buf )
  {
    printf("cannot alloc buffer for bus notifiers, len %lX\n", buf_size);
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  // form in params
  buf[0] = p.ntfy_cnt;
  strcpy((char *)(buf + 1), fname);
  int err = ioctl(g_fd, IOCTL_BUS_NTFY, (int *)buf);
  if ( err )
  {
    printf("error %d while read IOCTL_BUS_NTFY for %s\n", errno, fname);
    return;
  }
  for ( unsigned long i = 0; i < buf[0]; ++i )
  {
    printf("  [%d]", i);
    dump_unnamed_kptr(buf[i+1], delta);
  }
}

int dump_srcus(void *addr, unsigned long n, sa64 delta)
{
  const unsigned long args_size = 3 * sizeof(unsigned long);
  unsigned long size = std::max(args_size, n * sizeof(one_srcu));
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf ) return 0;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = (unsigned long)addr;
  buf[1] = n;
  buf[2] = 0;
  int err = ioctl(g_fd, IOCTL_MODULE1_GUTS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_MODULE1_GUTS failed, errno %d (%s)\n", errno, strerror(errno));
    return 0;
  }
  one_srcu *curr = (one_srcu *)(buf + 1);
  for ( unsigned long i = 0; i < buf[0]; ++i, curr++ )
  {
    printf("  [%ld]", i);
    dump_unnamed_kptr((unsigned long)curr->addr, delta);
    printf("    per_cpu offset %lX\n", curr->per_cpu_off);
  }
  return 1;
}

void dump_mods(sa64 delta, int opt_t)
{
  unsigned long args[2] = { 0, 0 };
  int err = ioctl(g_fd, IOCTL_READ_MODULES, (int *)&args);
  if ( err )
  {
    printf("IOCTL_READ_MODULES count failed, errno %d (%s)\n", errno, strerror(errno));
    return;
  }
  if ( !args[0] ) return;
  size_t size = calc_data_size<one_module1>(args[0]);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf )
  {
    printf("cannot alloc %lX bytes for modules, errno %d (%s)\n", size, errno, strerror(errno));
    return;
  }
  dumb_free<unsigned long> tmp(buf);
  buf[0] = args[0];
  buf[1] = 1;
  err = ioctl(g_fd, IOCTL_READ_MODULES, (int *)buf);
  if ( err )
  {
    printf("IOCTL_READ_MODULES failed, errno %d (%s)\n", errno, strerror(errno));
    return;
  }
  one_module1 *curr = (one_module1 *)(buf + 1);
  for ( unsigned long i = 0; i < buf[0]; ++i, curr++ )
  {
    printf("Mod[%ld] %p base %p", i, curr->addr, curr->base);
    auto name = find_kmod((unsigned long)curr->base);
    if ( name ) printf(" %s\n", name);
    else printf("\n");
    if ( curr->module_init ) printf(" module_init %p\n", curr->module_init);
    if ( curr->init ) dump_kptr2((unsigned long)curr->init, "init", 0);
    if ( curr->exit ) dump_kptr((unsigned long)curr->exit, "exit", 0);
    if ( curr->percpu_size ) printf(" percpu_size: %lX\n", curr->percpu_size);
    if ( curr->num_srcu_structs ) {
      printf(" num_srcu_structs: %ld\n", curr->num_srcu_structs);
      dump_srcus(curr->addr, curr->num_srcu_structs, delta);
    }
    if ( curr->num_tracepoints ) {
      dump_kptr(curr->tracepoints_ptrs, "tracepoints", 0);
      printf(" num_tracepoints: %ld\n", curr->num_tracepoints);
      if ( opt_t )
        dump_mod_tracepoints(delta, curr->tracepoints_ptrs, curr->num_tracepoints);
    }
    if ( curr->num_bpf_raw_events ) {
      dump_kptr(curr->bpf_raw_events, "bpf_raw_events", 0);
      printf(" num_bpf_raw_events: %ld\n", curr->num_bpf_raw_events);
      if ( opt_t )
        dump_bpf_raw_events2(curr->bpf_raw_events, curr->num_bpf_raw_events);
    }
    if ( curr->num_trace_events ) {
      dump_kptr(curr->trace_events, "trace_events", 0);
      printf(" num_trace_events: %ld\n", curr->num_trace_events);
    }
    if ( curr->num_trace_evals ) {
      dump_kptr(curr->trace_evals, "trace_evals", 0);
      printf(" num_trace_evals: %ld\n", curr->num_trace_evals);
    }
    if ( curr->num_kprobe_blacklist ) {
      dump_kptr(curr->kprobe_blacklist, "kprobe_blacklist", 0);
      printf(" num_kprobe_blacklist: %ld\n", curr->num_kprobe_blacklist);
    }
    if ( curr->kprobes_text_start ) {
      dump_kptr(curr->kprobes_text_start, "kprobes_text_start", 0);
      printf(" kprobes_text_size: %lX\n", curr->kprobes_text_size);
    }
    if ( curr->num_ei_funcs )
    {
      dump_kptr(curr->ei_funcs, "ei_funcs", 0);
      printf(" num_ei_funcs: %ld\n", curr->num_ei_funcs);
    }
    if ( curr->btf_data ) {
      printf(" btf_data_size %lX at", curr->btf_data_size);
      dump_unnamed_kptr(curr->btf_data, delta);
    }
  }
}

static int s_page_size = 0;
static unsigned long s_initial;
static vlevel_res vmem[5];
static const char *p_names[5] = { "PGD", "P4D", "PUD", "PMD", "PTE" };
typedef std::pair<unsigned long, unsigned long> parea;
static std::vector<parea> s_purged;
struct vmap_desc {
  size_t size = 0;
  unsigned long caller = 0;
};
static std::map<unsigned long, vmap_desc> s_vmaps;

int is_purged(unsigned long addr)
{
  if ( s_purged.empty() ) return 0;
  parea p { addr, 0 };
  auto up = std::upper_bound(s_purged.cbegin(), s_purged.cend(), p);
  if ( up == s_purged.cend() )
  {
    // check last
    return (addr >= s_purged.back().first) && (addr < s_purged.back().second);
  } else {
    up--;
    if ( up == s_purged.cend() ) return 0;
    return (addr >= up->first) && (addr < up->second);
  }
}

// under x86_64 & arm64 all pgd/p4d/pud/pmd/pte has size 9 bits
// for pte shift is just s_page_size, idx 5
// for pmd shift is 9 + s_page_size, idx 4
// for pud shift is 18 + s_page_size, idx 3
// for p4d shift is 27 + s_page_size, idx 2
// for pgd shift is 36 + s_page_size, idx 1
// so we can use ditry hack - shift original index << 9 (5 - idx) times and then shift on s_page_size
// Warning! rewrite this function for other arches
unsigned long gen_mask(unsigned long v, int idx)
{
  int shift = (5 - idx) * 9 + s_page_size;
  return (v & 0x1ff) << shift;
}

static unsigned long try_find_caller(unsigned long addr)
{
  if ( s_vmaps.empty() ) return 0;
  auto vi = s_vmaps.find(addr);
  if ( vi != s_vmaps.end() ) return vi->second.caller;
  // ok, may be this is not first PTE
  if ( addr < s_vmaps.cbegin()->first ) return 0; // addr less that most left address in vmaps
  vi = s_vmaps.upper_bound(addr);
  vi--;
  if ( vi == s_vmaps.end() ) return 0;
  if ( addr >= vi->first && addr <= (vi->first + vi->second.size) ) return vi->second.caller;
  return 0;
}

struct mem_summary {
  size_t unk = 0;
  std::map<unsigned long, size_t> execs;
  typedef std::pair<unsigned long, size_t> tp;
  int empty() const
  {
    return !unk && execs.empty();
  }
  void summary(sa64 delta)
  {
    if ( empty() ) return;
    std::vector<tp> tmp;
    tmp.reserve(execs.size());
    for ( auto &c: execs ) tmp.push_back( { c.first, c.second } );
    std::sort(tmp.begin(), tmp.end(), [](const auto &a, const auto &b) { return a.second > b.second; });
    printf("Memory summary:\n");
    if ( unk ) printf("Unknown: %d\n", unk);
    for ( auto &t: tmp ) {
       printf("%d %p", t.second, t.first);
       size_t off = 0;
       auto cname = lower_name_by_addr_with_off((a64)t.first - delta, &off);
       if ( cname )
        {
          if ( off )
            printf(" %s+%X", cname, off);
          else
            printf(" %s", cname);
        }
        printf("\n");
    }   
  }
};

static a64 kprobe_addr = 0;
static int is_kprobe(a64 addr)
{
  if ( !kprobe_addr ) return 0;
  return addr == kprobe_addr;
}

void disasm_kprobe(unsigned long addr, sa64 delta)
{
  // warning! size is very arch-specific
  char body[400];
  unsigned long *arg = (unsigned long *)body;
  arg[0] = addr;
  arg[1] = sizeof(body);
  int err = ioctl(g_fd, IOCTL_READ_VMEM, (int *)arg);
  if ( err )
  {
    printf("IOCTL_READ_VMEM(%p) failed, errno %d (%s)\n", addr, errno, strerror(errno));
    return;
  }
  x64_jit_disasm kd(addr, body, sizeof(body));
  kd.disasm_kprobe(delta);
}

static inline void _dump_pte_addr(unsigned long addr, sa64 delta, mem_summary &ms, int &_is_kprobe)
{
  if ( is_purged(addr) )
    printf(" [purged]");
  else
    if ( !dump_pte_addr(addr) )
    {
      auto caller = try_find_caller(addr);
      if ( !caller )
      {
        printf(" UNK_MEM");
        ms.unk += 1 << s_page_size;
      } else {
        ms.execs[caller] += 1 << s_page_size;
        size_t off = 0;
        a64 alloc_addr = 0;
        auto cname = lower_name_by_addr_with_off2((a64)caller - delta, &off, &alloc_addr);
        if ( cname )
        {
          _is_kprobe = is_kprobe(alloc_addr);
          if ( off )
            printf(" alloced by %s+%X", cname, off);
          else
            printf(" alloced by %s", cname);
          if ( _is_kprobe ) printf(" KPROBE");
        } else
         printf(" unnamed caddr %lX", caller);
      }
    }
  putc('\n', stdout);
}

void dump_next(unsigned long addr, void *prev_addr, int idx, sa64 delta, mem_summary &ms)
{
  vlevel_res *pgds = &vmem[idx - 1];
  unsigned long *ptr = (unsigned long *)pgds;
  // 3 args: level address
  ptr[0] = idx;
  ptr[1] = addr;
  ptr[2] = (unsigned long)prev_addr;
  int err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)ptr);
  if ( err )
  {
    // pte out of valid kernel memory. whatever that means - just to reduce output noise
    if ( (idx == 5) && (errno == 22) /* EINVAL*/) return;
    printf("IOCTL_VMEM_SCAN(%d) %s failed, errno %d (%s)\n", idx, p_names[idx-1], errno, strerror(errno));
    return;
  }
  for ( int i = 0; i < VITEMS_CNT; i++ )
  {
    int is_kprobe = 0;
    if ( pgds->items[i].bad ) continue;
    if ( !pgds->items[i].present ) continue;
    if ( pgds->items[i].huge ) {
      if ( pgds->items[i].nx ) continue;
      margin(idx);
      unsigned long final_addr = addr | gen_mask(i, idx);
      printf("[%d] huge %s %p %lX addr %p", i, p_names[idx-1], pgds->items[i].ptr, pgds->items[i].value, (void *)final_addr);
      _dump_pte_addr(final_addr, delta, ms, is_kprobe);
      // I hope kprobe cannot be in huge pages
      continue;
    }
    if ( pgds->items[i].large ) {
      if ( pgds->items[i].nx ) continue;
      margin(idx);
      unsigned long final_addr = addr | gen_mask(i, idx);
      printf("[%d] large %s %p %lX addr %p", i, p_names[idx-1], pgds->items[i].ptr, pgds->items[i].value, (void *)final_addr);
      _dump_pte_addr(final_addr, delta, ms, is_kprobe);
      // I hope kprobe cannot be in large pages
      continue;
    }
    if ( 5 == idx && pgds->items[i].nx ) continue;
    margin(idx);
    if ( idx != 5 )
    {
      printf("[%d] %s %p %lX addr %lX\n", i, p_names[idx-1], pgds->items[i].ptr, pgds->items[i].value, addr);
      dump_next(addr | gen_mask(i, idx), pgds->items[i].ptr, 1 + idx, delta, ms);
    } else {
      // this is PTE without NX bit
      auto pte_val = gen_mask(i, idx);
      unsigned long final_addr = addr | pte_val;
      printf("[%d] %s %p %lX addr %lX final_addr %lX", i, p_names[idx-1], pgds->items[i].ptr, pgds->items[i].value, 
       addr, final_addr);
      _dump_pte_addr(final_addr, delta, ms, is_kprobe);
      if ( is_kprobe && g_opt_d )
        disasm_kprobe(final_addr, delta);
    }
  }
}

static void _scan_vmem(sa64 delta)
{
  // TODO: this symbol is very arch specific
  kprobe_addr = get_addr("arch_ftrace_update_trampoline");
  if ( !kprobe_addr ) rcf("arch_ftrace_update_trampoline");
  int err;
  extern unsigned long g_kstart;
  unsigned long targs[16];
  auto dump_test = [&](unsigned long what) {
    printf("last processed level for %lX: %ld\n", what, targs[0]);
    for ( int i = 0; i < targs[0]; i++ )
    {
      // on x86_64 machine with CONFIG_PGTABLE_LEVELS == 5 for address FFFFFFFFAEC00000 p4d_index *always* returns 0
      // srsly? FFFFFFFFAEC00000 >> 39 = 1FFFFFF. God hates us all (c) Slayer
      printf("%d: %ld %p %lX\n", i, targs[i * 3 + 1], (void *)targs[i * 3 + 2], targs[i * 3 + 3]);
    }
  };
  if ( g_opt_v ) {
    targs[0] = 42;
    targs[1] = g_kstart;
    err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)targs);
    if ( err ) {
      printf("IOCTL_VMEM_SCAN test failed, errno %d (%s)\n", errno, strerror(errno));
    } else
      dump_test(g_kstart);
  }
  // 1) get page size and translation levels
  unsigned long args[6] = { 0, 0, 0 };
  err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)args);
  if ( err ) {
    printf("IOCTL_VMEM_SCAN failed, errno %d (%s)\n", errno, strerror(errno));
    return;
  }
  printf("page_size %lX, translation level %ld pgd_shift %ld", args[1], args[0], args[2]);
  if ( args[0] > 4 ) printf(" p4d_shift %ld", args[3]);
  printf(" pud_shift %ld pmd_shift %ld\n", args[4], args[5]);
  // for 5level run another test with decreased PGD
  if ( g_opt_v && 5 == args[0] )
  {
    unsigned long pgd_dec = g_kstart;
    memset(targs, 0, sizeof(targs));
    pgd_dec -= 1UL << args[2];
    targs[0] = 42;
    targs[1] = pgd_dec;
    err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)targs);
    if ( err )
      printf("second IOCTL_VMEM_SCAN test failed, errno %d (%s)\n", errno, strerror(errno));
    else
      dump_test(pgd_dec);
  }
  switch(args[1])
  {
    // 4kb
    case 0x1000: s_page_size = 12;
      if ( 5 == args[0] ) // 57 bit, upper 64 - 57 = 7 should be 1
      {
         if ( args[2] == 39 )
          s_initial = 0xffff000000000000;
         else
          s_initial = 0xfe00000000000000;
      } else if ( 4 == args[0] ) // 48 bit, upper 64 - 48 = 16 should be 1
        s_initial = 0xffff000000000000;
      else {
        printf("unknown translation level\n");
        return;
      }
     break;
     // 8kb
    case 0x2000: s_page_size = 13;
     break;
     // 16kb
    case 0x4000: s_page_size = 14;
     break;
     // 32kb
    case 0x8000: s_page_size = 15;
     break;
     // 64kb
    case 0x10000: s_page_size = 16;
     break;
    default:
     printf("unknown page size\n");
     return;
  }
  // ok, lets try to read PGD
  vlevel_res *pgds = &vmem[0];
  unsigned long *ptr = (unsigned long *)pgds;
  int next = 2;
  if ( args[0] == 5 && args[2] == 39 ) next = 3;
  else if ( args[0] == 4 ) next = 3;
  else if ( args[0] == 3 ) next = 4;
  // 2 args: level address, 3rd ignored for PGD
  ptr[0] = 1;
  ptr[1] = s_initial;
  err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)ptr);
  if ( err )
  {
    printf("IOCTL_VMEM_SCAN PGD failed, errno %d (%s)\n", errno, strerror(errno));
    return;
  }
  mem_summary ms;
  printf("next level %d initial %p\n", next, s_initial);
  for ( int i = 0; i < VITEMS_CNT; i++ )
  {
    if ( pgds->items[i].bad ) continue;
    if ( !pgds->items[i].present ) continue;
    auto next_mask = gen_mask(i, next - 1);
    printf("[%d] pgd %p %lX next %d mask %lX\n", i, pgds->items[i].ptr, pgds->items[i].value, next, next_mask);
    // dump next level
    dump_next(s_initial | next_mask, pgds->items[i].ptr, next, delta, ms);
  }
  ms.summary(delta);
}

void scan_vmem(sa64 delta)
{
  // read purged
  unsigned long args[3] = { 41, 0, 0 };
  int err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)args);
  if ( err )
    printf("IOCTL_VMEM_SCAN purged count failed, errno %d (%s)\n", errno, strerror(errno));
  else if ( args[0] ) {
    printf("%ld purged areas\n", args[0]);
    size_t psize = calc_data_size<one_purge_area>(args[0]);
    unsigned long *buf = (unsigned long *)malloc(psize);
    if ( !buf )
     printf("cannot alloc %lX bytes for purged areas\n", psize);
    else {
      dumb_free<unsigned long> tmp(buf);
      buf[0] = 41;
      buf[1] = args[0];
      err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)buf);
      if ( err )
        printf("IOCTL_VMEM_SCAN purged failed, errno %d (%s)\n", errno, strerror(errno));
      else {
        one_purge_area *curr = (one_purge_area *)(buf + 1);
        for ( unsigned long i = 0; i < buf[0]; ++i, ++curr )
        {
          if ( g_opt_v )
            printf("%lx - %lx\n", curr->start, curr->end);
          s_purged.push_back( { curr->start, curr->end});
        }
      }
    }
  }
  // read vmap_area_list
  args[0] = 40;
  args[1] = 0;
  err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)args);
  if ( err )
    printf("IOCTL_VMEM_SCAN vmap count failed, errno %d (%s)\n", errno, strerror(errno));
  else if ( args[0] ) {
    printf("%ld vmap areas\n", args[0]);
    size_t psize = calc_data_size<one_vmap_area>(args[0]);
    unsigned long *buf = (unsigned long *)malloc(psize);
    if ( !buf )
     printf("cannot alloc %lX bytes for vmap areas\n", psize);
    else {
      dumb_free<unsigned long> tmp(buf);
      buf[0] = 40;
      buf[1] = args[0];
      err = ioctl(g_fd, IOCTL_VMEM_SCAN, (int *)buf);
      if ( err )
        printf("IOCTL_VMEM_SCAN vmap failed, errno %d (%s)\n", errno, strerror(errno));
      else {
        one_vmap_area *curr = (one_vmap_area *)(buf + 1);
        for ( unsigned long i = 0; i < buf[0]; ++i, ++curr )
        {
          auto im = find_kmod_ex(curr->start);
          if ( im ) continue; // skip modules
          if ( g_opt_v )
            printf("%lx - %lx caller %lX\n", curr->start, curr->start + curr->size, curr->caller);
          s_vmaps[curr->start] = { curr->size, curr->caller};
        }
      }
    }
  }
  _scan_vmem(delta);
  s_purged.clear();
  s_vmaps.clear();
}

void dump_task_perf_events(int pid, unsigned long cnt, sa64 delta)
{
  size_t size = sizeof(unsigned long) + cnt * sizeof(one_perf_event);
  unsigned long *buf = (unsigned long *)malloc(size);
  if ( !buf ) return;
  dumb_free<unsigned long> tmp(buf);
  buf[0] = pid;
  buf[1] = cnt;
  buf[2] = 1;
  int err = ioctl(g_fd, IOCTL_TASK_WORKS, (int *)buf);
  if ( err )
  {
    printf("IOCTL_TASK_WORKS(1) for PID %d failed, errno %d (%s)\n", pid, errno, strerror(errno));
    return;
  }
  // HexDump((unsigned char *)buf, size);
  one_perf_event *curr = (one_perf_event *)(buf + 1);
  for ( unsigned long l = 0; l < buf[0] && l < cnt; ++l, ++curr )
  {
    printf(" perf_event[%ld]: %p id %ld attach_state %ld\n", l, curr->addr, curr->id, curr->attach_state);
    if ( curr->event_caps || curr->group_caps )
      printf("  event_caps %d group_caps %d\n", curr->event_caps, curr->group_caps);
    if ( curr->pmu )
     dump_kptr2((unsigned long)curr->pmu, " pmu", delta);
    if ( curr->destroy )
     dump_kptr2((unsigned long)curr->destroy, " destroy", delta);
    if ( curr->clock )
     dump_kptr2((unsigned long)curr->clock, " clock", delta);
    if ( curr->overflow_handler )
     dump_kptr2((unsigned long)curr->overflow_handler, " overflow_handler", delta);
    if ( curr->tp_event )
     dump_kptr2((unsigned long)curr->tp_event, " tp_event", delta);
    if ( curr->bpf )
     printf("  bpf %p bpf_id %ld\n", curr->bpf, curr->bpf_id);
  }
}

void dump_task(sa64 delta, int pid)
{
  one_task_info ti;
  ti.addr = (void *)pid;
  int err = ioctl(g_fd, IOCTL_TASK_INFO, (int *)&ti);
  if ( err )
  {
    printf("IOCTL_TASK_INFO for PID %d failed, errno %d (%s)\n", pid, errno, strerror(errno));
    return;
  }
  printf("PID %d at %p\n", pid, ti.addr);
  printf(" thread.flags: %lX\n", ti.thread_flags);
  printf(" flags: %lX\n", ti.flags);
  if ( ti.perf_event_ctxp ) {
    printf(" perf_event_ctxp at");
    dump_unnamed_kptr((unsigned long)ti.perf_event_ctxp, delta, true);
  }
  if ( ti.perf_event_cnt ) {
    printf(" perf_event_cnt: %ld\n", ti.perf_event_cnt);
    dump_task_perf_events(pid, ti.perf_event_cnt, delta);
  }
  if ( ti.io_uring ) dump_kptr2((unsigned long)ti.io_uring, "io_uring", delta);
  if ( ti.ptrace ) printf(" ptrace: %lX\n", ti.ptrace);
  if ( ti.works_count ) {
    printf(" works_count: %ld\n", ti.works_count);
    size_t ksize = sizeof(unsigned long) * std::max(3UL, 1 + ti.works_count);
    unsigned long *kbuf = (unsigned long *)malloc(ksize);
    if ( kbuf )
    {
      kbuf[0] = pid;
      kbuf[1] = ti.works_count;
      kbuf[2] = 0; // task works
      err = ioctl(g_fd, IOCTL_TASK_WORKS, (int *)kbuf);
      if ( err )
      {
        printf("IOCTL_TASK_WORKS for PID %d failed, errno %d (%s)\n", pid, errno, strerror(errno));
      } else {
        for ( unsigned long wi = 0; wi < kbuf[0]; ++wi )
        {
          printf("  work[%ld]", wi);
          dump_unnamed_kptr(kbuf[1 + wi], delta);
        }
      }
      free(kbuf);
    }
  }
  if ( ti.sched_class ) dump_kptr((unsigned long)ti.sched_class, "sched_class", delta);
  if ( ti.restart_fn ) dump_kptr((unsigned long)ti.restart_fn, "restart_block.fn", delta);
  if ( ti.seccomp_filter ) dump_kptr((unsigned long)ti.seccomp_filter, "seccomp_filter", delta);
  if ( ti.mce_kill_me ) dump_kptr((unsigned long)ti.mce_kill_me, "mce_kill_me", delta);
}

int main(int argc, char **argv)
{
   // read options
   int opt_f = 0, opt_F = 0,
       opt_g = 0,
       opt_c = 0, opt_C = 0,
       opt_k = 0, opt_K = 0,
       opt_m = 0, opt_M = 0,
       opt_n = 0,
       opt_p = 0,
       opt_r = 0,
       opt_s = 0, opt_S = 0,
       opt_t = 0, opt_T = 0,
       opt_b = 0, opt_B = 0,
       opt_u = 0;
   int c;
   int need_driver = 0;
   char *unused;
   std::map<unsigned long, unsigned char> patches;
   while (1)
   {
     if ( !strcmp(argv[optind],"-kp") )
     {
       optind++;
       if ( optind >= argc )
         usage(argv[0]);
       unsigned long v = strtoul(argv[optind], &unused, 16);
       if ( !v )
         usage(argv[0]);
       optind++;
       if ( optind >= argc )
         usage(argv[0]);
       unsigned long value = strtoul(argv[optind], &unused, 16);
       patches[v] = (unsigned char)(value & 0xff);
       optind++; need_driver = 1;
       continue;
     }
     if ( !strcmp(argv[optind],"-kpd") )
     {
       optind++;
       if ( optind >= argc )
         usage(argv[0]);
       unsigned long v = strtoul(argv[optind], &unused, 16);
       if ( !v )
         usage(argv[0]);
       g_kpd.insert(v);
       optind++; need_driver = 1;
       continue;
     }
     if ( !strcmp(argv[optind],"-kpe") )
     {
       optind++;
       if ( optind >= argc )
         usage(argv[0]);
       char *unused;
       unsigned long v = strtoul(argv[optind], &unused, 16);
       if ( !v )
         usage(argv[0]);
       g_kpe.insert(v);
       optind++; need_driver = 1;
       continue;
     }
     c = getopt(argc, argv, "BbCcdFfghHKkMmnprSstTuvj:");
     if (c == -1)
      break;

     switch (c)
     {
#ifndef _MSC_VER
        case 'j':
          if ( !ujit_open(optarg) )
           fprintf(stderr, "cannot dlopen %s, err %d\n", optarg, errno);
         break;
#endif /* _MSC_VER */
        case 'B':
          opt_B = 1;
          need_driver = 1;
         break;
        case 'b':
          opt_b = 1;
         break;
 	case 'F':
 	  opt_F = 1; need_driver = 1;
         break;
 	case 'f':
 	  opt_f = 1; need_driver = 1;
         break;
        case 'g':
 	  opt_g = 1; need_driver = 1;
         break;
        case 'h':
 	  g_opt_h = 1;
         break;
        case 'H':
          g_dump_bpf_ops = 1;
         break;
        case 'v':
          g_opt_v = 1;
         break;
        case 'd':
          g_opt_d = 1;
         break;
        case 'C':
          opt_C = 1; need_driver = 1;
         break;
        case 'c':
          opt_c = 1;
         break;
        case 'K':
          opt_K = 1; need_driver = 1;
         break;
        case 'k':
          opt_k = 1; need_driver = 1;
         break;
        case 'm':
          opt_m = 1; need_driver = 1;
         break;
        case 'M':
          opt_M = 1; need_driver = 1;
         break;
        case 'n':
          opt_n = 1; need_driver = 1;
         break;
        case 'p':
          opt_p = 1; need_driver = 1;
         break;
        case 'r':
          opt_r = 1;
         break;
        case 's':
          opt_s = 1; need_driver = 1;
         break;
        case 'S':
          opt_S = 1; need_driver = 1;
         break;
        case 'u':
          opt_u = 1; need_driver = 1;
         break;
        case 't':
          opt_t = 1; need_driver = 1;
         break;
        case 'T':
          opt_T = 1; need_driver = 1;
         break;
        default:
         usage(argv[0]);
     }
   }
   if (optind == argc)
     usage(argv[0]);

   if ( opt_p && opt_s )
   {
     printf("-p & s are mutually exclusive options\n");
     return 1;
   }

   elfio reader;
   int has_syms = 0;
   if ( !reader.load( argv[optind] ) ) 
   {
      printf( "File %s is not found or it is not an ELF file\n", argv[optind] );
      return 1;
   }
   optind++;
   Elf_Half n = reader.sections.size();
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( SHT_SYMTAB == sec->get_type() ||
          SHT_DYNSYM == sec->get_type() ) 
     {
       symbol_section_accessor symbols( reader, sec );
       if ( !read_syms(reader, symbols) )
         has_syms++;
     }
   }
   // try to find symbols
   if ( !has_syms )
   {
     if ( optind == argc )
     {
       if ( !getuid() )
       {
        // try to read /proc/kallsyms
        int err = read_kallsyms("/proc/kallsyms");
        if ( err )
        {
         printf("cannot read symbols from /proc/kallsyms, error %d\n", err);
         return err;
        }
        has_syms = g_kallsyms = 1;
       } else {
         printf("missed symbols\n");
         usage(argv[0]);
       }
     } else {
       int err = read_ksyms(argv[optind]);
       if ( err )
       {
         printf("cannot read symbols from %s, error %d\n", argv[optind], err);
         return err;
       }
       has_syms = 1;
       optind++;
     }
   }
   sa64 delta = 0;
   a64 bpf_target = 0;
#ifndef _MSC_VER
   // open driver
   if ( opt_c || need_driver ) 
   {
     g_fd = open("/dev/lkcd", 0);
     if ( -1 == g_fd )
     {
       printf("cannot open device, error %d (%s)\n", errno, strerror(errno));
       opt_c = 0;
       goto end;
     }
     // find delta between symbols from system.map and loaded kernel
     auto symbol_a = get_addr("group_balance_cpu");
     if ( !symbol_a )
     {
       close(g_fd);
       g_fd = 0;
       opt_c = 0;
       goto end;
     } else {
       if ( read_kernel_area(g_fd) )
       {
         close(g_fd);
         g_fd = -1;
         opt_c = 0;
         goto end;
       }
       int err = init_kmods(g_fd);
       if ( err )
       {
         printf("init_kmods failed, error %d\n", err);
         goto end;
       }
       printf("group_balance_cpu from symbols: %p\n", (void *)symbol_a);
       union ksym_params kparm;
       strcpy(kparm.name, "group_balance_cpu");
       err = ioctl(g_fd, IOCTL_RKSYM, (int *)&kparm);
       if ( err )
       {
         printf("IOCTL_RKSYM test failed, error %d\n", err);
         close(g_fd);
         g_fd = 0;
         opt_c = 0;
       } else {
         printf("group_balance_cpu: %p\n", (void *)kparm.addr);
         delta = (char *)kparm.addr - (char *)symbol_a;
         printf("delta: %lX\n", delta);
       }
     }
     if ( -1 != g_fd && !patches.empty() )
        patch_kernel(patches);
     // dump keys
     if ( -1 != g_fd && opt_K )
       dump_keys(delta);
     // dump consoles
     if ( -1 != g_fd && opt_C )
       dump_consoles(delta);
     if ( -1 != g_fd && opt_M )
     {
       if ( init_kmod_ex(g_fd) ) {
        printf("cannot read executable pages for modules\n");
       } else {
        scan_vmem(delta);
       }
     }
     // -m
     if ( -1 != g_fd && opt_m )
     {
       dump_mods(delta, opt_t);
       dump_binfmt(delta);
       dump_slabs(delta);
       dump_pools(delta);
     }
     // dump kprobes
     if ( -1 != g_fd && opt_k )
     {
       dump_sys_tab(delta);
       dump_kprobes(delta);
       dump_uprobes(delta);
     }
     // dump super-blocks
     if ( -1 != g_fd && opt_F )
       dump_super_blocks(delta);
     if ( -1 != g_fd && opt_n )
     {
       dump_nets(delta);
       dump_xfrm(delta);
       dump_nfxt(delta);
     }
     if ( -1 != g_fd && opt_p )
     {
       for ( int idx = optind; idx < argc; idx++ )
       {
         int pid = atoi(argv[idx]);
         if ( !pid )
         {
           printf("bad pid '%s'\n", argv[idx]);
           continue;
         }
         dump_task(delta, pid);
       }
     }
     // check sysfs f_ops
     if ( -1 != g_fd && opt_s )
     {
       if ( optind == argc )
       {
         printf("where is file(s)?\n");
         exit(6);
       }
       auto bus_type = get_addr("bus_ktype");
       auto cl_type = get_addr("class_ktype");
       if ( bus_type ) bus_type += delta;
       if ( cl_type) cl_type += delta; 
       union kernfs_params kparm;
       for ( int idx = optind; idx < argc; idx++ )
       {
         strncpy(kparm.name, argv[idx], sizeof(kparm.name) - 1);
         kparm.name[sizeof(kparm.name) - 1] = 0;
         int err = ioctl(g_fd, IOCTL_KERNFS_NODE, (int *)&kparm);
         if ( err )
         {
           printf("IOCTL_KERNFS_NODE(%s) failed, error %d (%s)\n", argv[idx], errno, strerror(errno));
           continue;
         }
         printf("\nres %s: %p\n", argv[idx], (void *)kparm.res.addr);
         dump_kernfs(kparm.res, delta);
         // dir with ktype == bus_type ?
         if ( kparm.res.addr && (kparm.res.flags & 1) )
         if ( (bus_type && bus_type == kparm.res.ktype) || (cl_type && cl_type == kparm.res.ktype) )
         {
           strncpy(kparm.name, argv[idx], sizeof(kparm.name) - 1);
           kparm.name[sizeof(kparm.name) - 1] = 0;
           err = ioctl(g_fd, IOCTL_READ_BUS, (int *)&kparm);
           if ( err )
           {
             printf("IOCTL_READ_BUS(%s) failed, error %d (%s)\n", argv[idx], errno, strerror(errno));
             continue;
           }
           dump_bus(kparm.priv, delta, argv[idx]);
         }
       }
     }
   }
end:
#endif /* _MSC_VER */
   // find .text section
   Elf64_Addr text_start = 0;
   Elf_Xword text_size = 0;
   section *text_section = NULL;
   for ( Elf_Half i = 0; i < n; ++i ) { // For all sections
     section* sec = reader.sections[i];
     if ( sec->get_name() == ".text" )
     {
       text_start = sec->get_address();
       text_size  = sec->get_size();
       text_section = sec;
       break;
     }
   }
   if ( has_syms )
   {
     // make some tests
     auto a1 = get_addr("__start_mcount_loc");
     printf("__start_mcount_loc: %p\n", (void *)a1);
     auto a2 = get_addr("__stop_mcount_loc");
     printf("__stop_mcount_loc: %p\n", (void *)a2);
     // if we had -f option
     if ( opt_f && a1 && a2 )
     {
       // under arm64 we need process relocs
       if ( reader.get_machine() == 183 )
         dump_arm64_ftraces(reader, a1, a2, [](Elf_Sxword addend) 
          { 
            dump_addr_name(addend);
          }
         );
       else {
         const a64 *data = (const a64 *)find_addr(reader, a1);
         if ( data != NULL )
         {
           for ( a64 i = a1; i < a2; i += sizeof(a64) )
           {
             a64 addr = *data;
             dump_addr_name(addr);
             data++;
#ifndef _MSC_VER
             if ( opt_c )
             {
               // filter out maybe discarded sections like .init.text
               if ( text_section != NULL &&
                    ( (addr < text_start) || (addr > (text_start + text_size)) )
                  )
                 continue;
               char *ptr = (char *)addr + delta;
               char *arg = ptr;
               int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
               if ( err )
                 printf("read ftrace at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
               else if ( !is_nop((unsigned char *)&arg) )
                 HexDump((unsigned char *)&arg, sizeof(arg));
             }
#endif /* !_MSC_VER */
           }
         }
       }
     }
   }

   if ( !text_start )
   {
     printf("cannot find .text\n");
     return 1;
   }
   for ( Elf_Half i = 0; i < n; ++i ) 
   {
     section* sec = reader.sections[i];
     if ( opt_r && sec->get_name() == ".rodata" )
     {
       std::map<a64, a64> filled;
       auto off = sec->get_offset();
       printf(".rodata section offset %lX\n", off);
       size_t count = 0;
       a64 curr_addr;
       // under arm64 we need count relocs in .data section       
       if ( reader.get_machine() == 183 )
       {
         a64 dstart = (a64)sec->get_address();
         count = filter_arm64_relocs(reader, dstart, dstart + sec->get_size(), (a64)text_start, (a64)(text_start + text_size), filled);
       } else {
         a64 *curr = (a64 *)sec->get_data();
         a64 *end  = (a64 *)((char *)curr + sec->get_size());
         curr_addr = sec->get_address();
         const endianess_convertor &conv = reader.get_convertor();
         for ( ; curr < end; curr++, curr_addr += sizeof(a64) )
         {
           auto addr = conv(*curr);
           if ( addr >= (a64)text_start &&
                addr < (a64)(text_start + text_size)
              )
           {
             count++;
             filled[curr_addr] = addr;
           }
         }
       }
       printf("found in .rodata %ld\n", count);
       // dump or check collected addresses
       if ( g_opt_v || opt_c )
         dump_and_check(opt_c, delta, has_syms, filled);
       continue;
     }
     if ( sec->get_name() == ".data" )
     {
       std::map<a64, a64> filled;
       auto off = sec->get_offset();
       printf(".data section offset %lX\n", off);
       size_t count = 0;
       a64 curr_addr;
       // dump cgroups
       if ( opt_g && -1 != g_fd && has_syms )
       {
#ifndef _MSC_VER
         dump_groups(delta);
#endif  /* !_MSC_VER */
       }
       if ( opt_u && -1 != g_fd && has_syms )
       {
         a64 addr = get_addr("mon_ops");
         if ( !addr )
           rcf("mon_ops");
#ifndef _MSC_VER
         else
           dump_usb_mon(addr, delta);
#endif /* !_MSC_VER */
         addr = get_addr("generic_efivars");
         if ( !addr )
           rcf("generic_efivars");
#ifndef _MSC_VER
         else
           dump_efivars(addr, delta);
#endif /* !_MSC_VER */
       }
       if ( opt_T && -1 != g_fd && has_syms )
       {
         a64 off = (a64)get_addr("timer_bases");
         if ( off )
         {
          printf("timer_bases %p\n", (void *)off);
          if ( opt_c )
          {
            a64 poff = (a64)get_addr("__per_cpu_offset");
            dump_ktimers(off, poff, delta);
          }
         }
         dunp_kalarms(delta);
       }
       if ( opt_t && has_syms )
       {
         size_t tcount = 0;
         a64 dstart = (a64)sec->get_address();
         struct addr_sym *tsyms = start_with("__tracepoint_", dstart, dstart + sec->get_size(), &tcount);
         if ( tsyms != NULL )
         {
           printf("found %ld tracepoints\n", tcount);
#ifdef _MSC_VER
           if ( g_opt_v )
           {
             for ( size_t i = 0; i < tcount; i++ )
               printf(" %p: %s\n", (void *)(tsyms[i].addr), tsyms[i].name);
           }
#else
           if ( -1 != g_fd )
             check_tracepoints(delta, tsyms, tcount);
#endif /* _MSC_VER */
           free(tsyms);
         }
         if ( -1 != g_fd )
           dump_ftrace_options(delta);
         // dump bpf raw events
         auto start = get_addr("__start__bpf_raw_tp");
         auto end   = get_addr("__stop__bpf_raw_tp");
         dump_bpf_raw_events(start, end, delta);
         // dump ftrace_ops
         auto fops = get_addr("ftrace_ops_list");
         auto m = get_addr("ftrace_lock");
         dump_ftrace_ops(fops, m, delta);
         // dump ftrace events
         auto ev_start = get_addr("__start_ftrace_events");
         auto ev_stop  = get_addr("__stop_ftrace_events");
         if ( !ev_start )
           rcf("__start_ftrace_events");
         else if ( !ev_stop )
           rcf("__stop_ftrace_events");
         else {
           printf("__start_ftrace_events: %p\n", (void *)ev_start);
           printf("__stop_ftrace_events: %p\n", (void *)ev_stop);
           std::set<a64> events;
           if ( reader.get_machine() == 183 )
           {
             dump_arm64_ftraces(reader, ev_start, ev_stop, [&events](Elf_Sxword addend) 
              {
               if ( g_opt_v )
                 dump_addr_name(addend);
               events.insert((a64)addend);
              }
             );
           } else {
             const a64 *data = (const a64 *)find_addr(reader, ev_start);
             if ( data != NULL )
               for ( a64 i = ev_start; i < ev_stop; i += sizeof(a64) )
               {
                 if ( g_opt_v )
                   dump_addr_name(*data);
                 events.insert(*data);
                 data++;
               }
           }
         }
#ifndef _MSC_VER
         if ( opt_c )
         {
           auto idr = get_addr("pmu_idr");
           auto m = get_addr("pmus_lock");
           dump_pmus(idr, m, delta);
           // perf_guest_cbs
           dump_perf_guest_cbs(delta);
           // registered trace_event_calls
           dump_registered_trace_event_calls(delta);
           // event cmds
           auto ecl = get_addr("trigger_commands");
           auto ecm = get_addr("trigger_cmd_mutex");
           dump_event_cmds(ecl, ecm, delta);
           // trace exports
           ecl = get_addr("ftrace_exports_list");
           ecm = get_addr("ftrace_export_lock");
           dump_trace_exports(ecl, ecm, delta);
           // ftrace cmds
           ecl = get_addr("ftrace_commands");
           ecm = get_addr("ftrace_cmd_mutex");
           dump_tracefunc_cmds(ecl, ecm, delta);
           // dynamic events ops
           ecl = get_addr("dyn_event_ops_list");
           ecm = get_addr("dyn_event_ops_mutex");
           dump_dynevents_ops(ecl, ecm, delta);
           // dump dynamic events
           ecl = get_addr("dyn_event_list");
           ecm = get_addr("event_mutex");
           dump_dynamic_events(ecl, ecm, delta);
         }
#endif /* _MSC_VER */
       }
       // under arm64 we need count relocs in .data section       
       if ( reader.get_machine() == 183 )
       {
         a64 dstart = (a64)sec->get_address();
         count = filter_arm64_relocs(reader, dstart, dstart + sec->get_size(), (a64)text_start, (a64)(text_start + text_size), filled);
       } else {
         a64 *curr = (a64 *)sec->get_data();
         a64 *end  = (a64 *)((char *)curr + sec->get_size());
         curr_addr = sec->get_address();
         const endianess_convertor &conv = reader.get_convertor();
         for ( ; curr < end; curr++, curr_addr += sizeof(a64) )
         {
           auto addr = conv(*curr);
           if ( addr >= (a64)text_start &&
                addr < (a64)(text_start + text_size)
              )
           {
             count++;
             filled[curr_addr] = addr;
           }
         }
       }
       printf("found %ld\n", count);
       // dump or check collected addresses
       if ( g_opt_v || opt_c )
         dump_and_check(opt_c, delta, has_syms, filled);
       if ( opt_c )
       {
         dump_freq_ntfy(delta);
         dump_clk_ntfy(get_addr("clk_notifier_list"), get_addr("prepare_lock"), delta);
         dump_devfreq_ntfy(get_addr("devfreq_list"), get_addr("devfreq_list_lock"), delta);
       }
       if ( opt_S ) {
         std::map<void *, std::string> hmap;
         dump_input_handlers(delta, hmap);
         dump_input_devs(delta, hmap);
         dump_sysrq_keys(delta);
         dump_avc_cbs(delta);
       }
       if ( opt_B ) // read BTF struct_ops
       {
          dump_verops(delta);
          dump_struct_ops(delta);
       }
       if ( g_opt_d )
       {
          dis_base *bd = NULL;
          if ( reader.get_machine() == 183 )
          {
            arm64_disasm *ad = new arm64_disasm(text_start, text_size, text_section->get_data(), sec->get_address(), sec->get_size());
            a64 addr = get_addr("__stack_chk_fail");
            if ( addr )
              ad->add_noreturn(addr);
            bd = ad;
          } else if ( reader.get_machine() == EM_X86_64 )
          {
            x64_disasm *x64 = new x64_disasm(text_start, text_size, text_section->get_data(), sec->get_address(), sec->get_size());
            // fill indirect thunks
            for ( auto &c: s_x64_thunks )
            {
              a64 thunk_addr = get_addr(c.name);
              if ( !thunk_addr )
                printf("cannot find %s\n", c.name);
              else
                x64->set_indirect_thunk(thunk_addr, c.reg);
             }
             a64 ntfy_addr = get_addr("fire_user_return_notifiers");
             if ( !ntfy_addr )
               rcf("fire_user_return_notifiers");
             else {
               if ( x64->find_return_notifier_list(ntfy_addr) )
               {
                 unsigned long this_cpu_off = 0,
                               return_notifier_list = 0;
                 if ( x64->get_return_notifier_list(this_cpu_off, return_notifier_list) )
                 {
                   printf("this_cpu_off: %lX, return_notifier_list: %lX\n", this_cpu_off, return_notifier_list);
#ifndef _MSC_VER
                   if ( opt_c )
                   {
                     install_urn(1);
                     dump_return_notifier_list(this_cpu_off, return_notifier_list, delta);
                     install_urn(0);
                   }
#endif
                 }
               } else
                 printf("cannot extract return_notifier_list\n");
             }
             bd = x64;
          } else {
            printf("no disasm for machine %d\n", reader.get_machine());
            break;
          }
          if ( opt_B || opt_t )
          {
            // read bpf_protos
            check_bpf_protos(delta);
            // find bpf targets
            auto entry = get_addr("bpf_iter_reg_target");
            auto mlock = get_addr("mutex_lock");
            if ( !entry )
              rcf("bpf_iter_reg_target");
            else if ( !mlock )
              rcf("mutex_lock");
            else
              bpf_target = bd->process_bpf_target(entry, mlock);
            // dump bpf
            if ( opt_B && -1 != g_fd && has_syms )
            {
#ifndef _MSC_VER
               dump_jit_options(delta);
               auto tgm = get_addr("targets_mutex");
               dump_bpf_targets(bpf_target, tgm, delta);
               // bpf maps
               std::map<void *, std::string> names;
               auto entry = get_addr("map_idr");
               tgm = get_addr("map_idr_lock");
               dump_bpf_maps(entry, tgm, delta, names);
               // bpf ksyms
               entry = get_addr("bpf_kallsyms");
               tgm = get_addr("bpf_lock");
               dump_bpf_ksyms(entry, tgm, delta);
               // bpf progs
               if ( ujit_opened() )
               {
                 a64 base = get_addr("__bpf_call_base");
                 a64 enter = get_addr("__bpf_prog_enter");
                 a64 ex = get_addr("__bpf_prog_exit");
                 if ( base && enter && ex )
                 {
                   printf("__bpf_call_base %lX\n", base + delta);
                   put_kdata(base + delta, enter + delta, ex + delta);
                 }
               }
               entry = get_addr("prog_idr");
               tgm = get_addr("prog_idr_lock");
               dump_bpf_progs(entry, tgm, delta, names);
               // bpf links
               entry = get_addr("link_idr");
               tgm = get_addr("link_idr_lock");
               dump_bpf_links(entry, tgm, delta);
#endif /* !_MSC_VER */
            }
          }
          if ( opt_t )
          {
            // find trace_event_call.filter offset
            auto entry = get_addr("trace_remove_event_call");
            auto free_evt = get_addr("free_event_filter");
            if ( !entry )
              rcf("trace_remove_event_call");
            else if ( !free_evt )
              rcf("free_event_filter");
            else
              g_event_foff = bd->process_trace_remove_event_call(entry, free_evt);
          }
          if ( opt_S )
          {
            auto sem = get_addr("crypto_alg_sem");
            auto cal = get_addr("crypto_alg_list");
            dump_ckalgos(cal, sem, delta);
            s_security_hook_heads = get_addr("security_hook_heads");
            if ( !s_security_hook_heads )
            {
              rcf("security_hook_heads");
              opt_S = 0;
            } else {
              int res = 0;
              bd->set_shook(s_security_hook_heads);
              for ( auto &sl: s_hooks )
              {
                std::string sl_name = "security_";
                sl_name += sl.name;
                sl.addr = get_addr(sl_name.c_str());
                if ( sl.addr )
                  res++;
              }
              if ( res )
                res = bd->process_sl(s_hooks);
              if ( !res )
                opt_S = 0;
              else 
              {
                if ( g_opt_v )
                {
                  for ( auto &sl: s_hooks )
                  {
                    if ( !sl.list )
                      continue;
                    printf("%s: %p\n", sl.name.c_str(), (void *)sl.list);
                  }
                }
#ifndef _MSC_VER
                if ( -1 != g_fd )
                  dump_lsm(delta);
#endif /* !_MSC_VER */
              }
            }
          }
          // find bss if we need
          if ( opt_b )
          {
            for ( Elf_Half j = 0; j < n; ++j )
            {
              section* s = reader.sections[j];
              if ( (s->get_type() & SHT_NOBITS) && 
                   (s->get_name() == ".bss" )
                 )
              {
                a64 bss_addr = s->get_address();
                if ( g_opt_v )
                  printf(".bss address %p size %lX\n", (void *)bss_addr, s->get_size());
                bd->set_bss(bss_addr, s->get_size());
                break;
              }
            }
          }
          std::set<a64> out_res;
          size_t tcount = 0;
          struct addr_sym *tsyms = get_in_range(text_start, text_start + text_size, &tcount);
          if (tsyms != NULL)
          {
#ifdef _DEBUG
            a64 taddr = get_addr("netdev_store.isra.14");
            if ( taddr )
              bd->process(taddr, filled, out_res);
#endif /* _DEBUG */
            for (size_t i = 0; i < tcount; i++)
            {
#ifdef _DEBUG
              printf("%s:\n", tsyms[i].name);
#endif /* _DEBUG */
              bd->process(tsyms[i].addr, filled, out_res);
            }
            free(tsyms);
          }
          else
          {
            // now disasm some funcs - security_load_policy
            a64 faddr = get_addr("rcu_sched_clock_irq");
            if (faddr)
            {
              bd->process(faddr, filled, out_res);
            }
          }
          delete bd;
          printf("found with disasm: %ld\n", out_res.size());
          if ( g_opt_v )
          {
            for ( auto c: out_res )
            {
              size_t off = 0;
              const char *name = lower_name_by_addr_with_off(c, &off);
              if ( name != NULL )
              {
                if ( off )
                  printf("# %s+%lX\n", name, off);
                else
                  printf("# %s\n", name);
              }
              printf("%p\n", (void *)c);
            }
          }
#ifndef _MSC_VER
          if ( opt_c )
          {
            for ( auto c: out_res )
            {
              char *ptr = (char *)c + delta;
              char *arg = ptr;
              int err = ioctl(g_fd, IOCTL_READ_PTR, (int *)&arg);
              if ( err )
                printf("read at %p failed, error %d (%s)\n", ptr, errno, strerror(errno));
              else if ( arg != NULL )
              {
                 if ( is_inside_kernel((unsigned long)arg) )
                 {
                    if ( !has_syms )
                      printf("mem at %p: %p\n", ptr, arg);
                    else
                      dump_patched(c, ptr, arg, delta);
                 } else {
                    const char *mname = find_kmod((unsigned long)arg);
                    if ( mname )
                      printf("mem at %p: %p - patched by %s\n", ptr, arg, mname);
                    else
                      printf("mem at %p: %p - patched by UNKNOWN\n", ptr, arg);
                 }
              }
            }
          } // opt_c
#endif /* !_MSC_VER */
       } // g_opt_d
       break;
     }
   }
#ifndef _MSC_VER
   if ( g_fd != -1 )
     close(g_fd);
   ujit_close();
#endif /* _MSC_VER */
}
