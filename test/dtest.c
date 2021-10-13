#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libgen.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include "shared.h"
#include "kmods.h"
#include "kopts.h"
#include "lk.h"
#include "getopt.h"
#include "drvname.h"

// some kernel typedefs
typedef uint64_t u64;
// from include/linux/types.h
struct list_head {
	struct list_head *next, *prev;
};

struct chains
{
  const char *fname;
  const char *block_name;
};

// registered with blocking_notifier_chain_register
static const struct chains s_chains[] = {
 { "backlight_register_notifier", "backlight_notifier" },
 { "register_tracepoint_module_notifier", "tracepoint_notify_list" },
 { "pm_qos_add_notifier", "pm_qos_array" },
 { "mce_register_decode_chain", "x86_mce_decoder_chain" },
 { "mce_register_injector_chain", "mce_injector_chain" },
 { "iosf_mbi_register_pmic_bus_access_notifier", "iosf_mbi_pmic_bus_access_notifier" },
 { "register_oom_notifier", "oom_notify_list" },
 { "register_reboot_notifier", "reboot_notifier_list" },
 { "register_module_notifier", "module_notify_list" },
 { "register_pm_notifier", "pm_chain_head" },
 { "profile_event_register",  "munmap_notifier" },
 { "profile_event_register", "task_exit_notifier" },
 { "register_vmap_purge_notifier", "vmap_notify_list" },
 { "register_blocking_lsm_notifier", "blocking_lsm_notifier_chain" },
 { "crypto_register_notifier", "crypto_chain" },
 { "fb_register_client", "fb_notifier_list" },
 { "acpi_reconfig_notifier_register", "acpi_reconfig_chain" },
 { "register_acpi_notifier", "acpi_chain_head" },
 { "acpi_lid_notifier_register", "acpi_lid_notifier" },
 { "register_acpi_hed_notifier", "acpi_hed_notify_list" },
 { "unregister_xenstore_notifier", "xenstore_chain" },
 { "register_memory_notifier", "memory_chain" },
 { "usb_register_notify", "usb_notifier_list" },
 { "cpufreq_register_notifier", "cpufreq_policy_notifier_list" },
};

// registered with atomic_notifier_chain_register
static const struct chains a_chains[] = {
 { "xen_panic_handler_init", "panic_notifier_list" },
 { "register_die_notifier", "die_chain" },
 { "register_restart_handler", "restart_handler_list" },
 { "task_handoff_register", "task_free_notifier" },
 { "register_keyboard_notifier", "keyboard_notifier_list" },
 { "register_vt_notifier", "vt_notifier_list" },
 { "amd_iommu_register_ppr_notifier", "ppr_notifier" },
 { "power_supply_reg_notifier", "power_supply_notifier" },
 { "register_netevent_notifier", "netevent_notif_chain" },
 { "register_inet6addr_notifier", "inet6addr_chain" },
 { "register_dcbevent_notifier", "dcbevent_notif_chain" },
 { "register_switchdev_notifier", "switchdev_notif_chain" },
};

// registered with srcu_notifier_chain_register
static const struct chains srcu_chains[] = {
// { "cpufreq_register_notifier", "cpufreq_transition_notifier_list" },
 { "lease_register_notifier", "lease_notifier_chain" },
};

static size_t calc_ntfy_size(size_t n)
{
  return (n + 1) * sizeof(unsigned long);
}

void dump_chains(int fd, const struct chains *inchains, int count, int cnt_ioctl, int enum_ioctl)
{
  union ksym_params kparm;
  unsigned long addr;
  int err;
  size_t i, j, curr_n = 3;
  size_t size = calc_ntfy_size(curr_n);
  unsigned long *ntfy = (unsigned long *)malloc(size);
  if ( ntfy == NULL )
    return;
  for ( i = 0; i < count; i++ )
  {
    strcpy(kparm.name, inchains[i].block_name);
    err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
    if ( err )
    {
      printf("cannot get %s, error %d\n", inchains[i].block_name, err);
      continue;
    }
    printf("%s: %p\n", inchains[i].block_name, (void *)kparm.addr);
    if ( !kparm.addr )
      continue;
    // try read count
    addr = kparm.addr;
    err = ioctl(fd, cnt_ioctl, (int *)&addr);
    if ( err )
    {
      printf("cannot get count in %s, error %d\n", inchains[i].block_name, err);
      continue;
    }
    printf("%s cnt: %ld\n", inchains[i].block_name, addr);
    if ( !addr )
      continue;
    // try read ntfy
    if ( addr > curr_n )
    {
      unsigned long *tmp;
      size = calc_ntfy_size(addr);
      tmp = (unsigned long *)malloc(size);
      if ( tmp == NULL )
        break;
      curr_n = addr;
      free(ntfy);
      ntfy = tmp;
    }
    ntfy[0] = kparm.addr;
    ntfy[1] = addr;
    err = ioctl(fd, enum_ioctl, (int *)ntfy);
    if ( err )
    {
      printf("cannot enum %s, error %d\n", inchains[i].block_name, err);
      continue;
    }
    size = ntfy[0];
    for ( j = 0; j < size; j++ )
    {
      if ( is_inside_kernel(ntfy[1 + j]) )
        printf(" %p - kernel\n", (void *)ntfy[1 + j]);
      else {
        const char *mname = find_kmod(ntfy[1 + j]);
        if ( mname )
          printf(" %p - %s\n", (void *)ntfy[1 + j], mname);
        else
          printf(" %p UNKNOWN\n", (void *)ntfy[1 + j]);
      }
    }
  }
  if ( ntfy != NULL )
    free(ntfy);
}

static size_t calc_trace_size(size_t n)
{
  return sizeof(unsigned long) + n * sizeof(struct one_trace_event);
}

void dump_trace_func(unsigned long addr, const char *fname)
{
   if ( is_inside_kernel(addr) )
     printf("  %s %p - kernel\n", fname, (void *)addr);
   else {
    const char *mname = find_kmod(addr);
    if ( mname )
      printf("  %s %p - %s\n", fname, (void *)addr, mname);
    else
      printf("  %s %p UNKNOWN\n", fname, (void *)addr);
   }
}

void dump_trace_events(int fd, unsigned long trace_sem, unsigned long event_hash)
{
  int err;
  size_t i, j, curr_n = 3;
  size_t size = calc_trace_size(curr_n);
  unsigned long *traces = (unsigned long *)malloc(size);
  struct one_trace_event *curr;
  if ( traces == NULL )
    return;
  for ( i = 0; i < 128; i++ )
  {
    unsigned long cnt_param[3] = { trace_sem, event_hash, i };
    err = ioctl(fd, IOCTL_TRACEV_CNT, (int *)cnt_param);
    if ( err )
    {
      printf("cannot get count of trace_event for index %ld, error %d\n", i, err);
      continue;
    }
    printf(" index[%ld]: %ld\n", i, cnt_param[0]);
    if ( !cnt_param[0] )
      continue;
    if ( cnt_param[0] > curr_n )
    {
      unsigned long *tmp;
      size = calc_trace_size(cnt_param[0]);
      tmp = (unsigned long *)malloc(size);
      if ( tmp == NULL )
        break;
      curr_n = cnt_param[0];
      free(traces);
      traces = tmp;
    }
    // ok, read bodies
    traces[0] = trace_sem;
    traces[1] = event_hash;
    traces[2] = i;
    traces[3] = cnt_param[0];
    err = ioctl(fd, IOCTL_TRACEVENTS, (int *)traces);
    if ( err )
    {
      printf("cannot get trace_events for index %ld, error %d\n", i, err);
      continue;
    }
    // dump
    size = traces[0];
    curr = (struct one_trace_event *)(traces + 1);
    for ( j = 0; j < size; j++, curr++ )
    {
      printf(" [%ld] at %p type %d\n", j, curr->addr, curr->type);
      if ( curr->trace )
         dump_trace_func((unsigned long)curr->trace, "trace");
      if ( curr->raw )
         dump_trace_func((unsigned long)curr->raw, "raw");
      if ( curr->hex )
         dump_trace_func((unsigned long)curr->hex, "hex");
      if ( curr->binary )
         dump_trace_func((unsigned long)curr->binary, "binary");
    }
  }
  // cleanup
  if ( traces != NULL )
    free(traces);
}

void dump_kptr(unsigned long l, const char *name)
{
  if ( is_inside_kernel(l) )
    printf(" %s: %p - kernel\n", name, (void *)l);
  else {
    const char *mname = find_kmod(l);
    if ( mname )
      printf(" %s: %p - %s\n", name, (void *)l, mname);
    else
      printf(" %s: %p - UNKNOWN\n", name, (void *)l);
  }
}

int main(int argc, char **argv)
{
  int opt_s = 0,
      opt_t = 0; 
  int fd;
  union ksym_params kparm;
  unsigned long addr;
  unsigned long trace_sem = 0;
  unsigned long event_hash = 0;
  int err = 0;
  size_t i;
  // read options
   while (1)
   {
     int c = getopt(argc, argv, "st");
     if (c == -1)
	break;

     switch (c)
     {
        case 's':
          opt_s = 1;
         break;
        case 't':
          opt_t = 1;
         break;
     }
   }
  
  // open device
  fd = open(DRV_FILENAME, 0);
  if ( -1 == fd )
  {
    printf("cannot open device, error %d\n", errno);
    exit(errno);
  }
  // read list of modules
  err = init_kmods();
  if ( err )
  {
    printf("init_kmods failed, error %d\n", err);
    goto end;
  }
  err = init_kopts();
  if ( err )
  {
    printf("init_kopts failed, error %d\n", err);
    goto end;
  }
  // first try to extract some well known exported symbol
  strcpy(kparm.name, "jiffies");
  err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
  if ( err )
  {
    printf("IOCTL_RKSYM test failed, error %d\n", err);
    goto end;
  }
  printf("jiffies: %p\n", (void *)kparm.addr);
  strcpy(kparm.name, "mktime64");
  err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
  if ( err )
  {
    printf("IOCTL_RKSYM test failed, error %d\n", err);
    goto end;
  }
  printf("mktime64: %p\n", (void *)kparm.addr);
  // kernel start and end
  err = read_kernel_area(fd);
  if ( err )
    goto end;
  // test chained ntfy (default)
  if ( !opt_s && !opt_t )
  {
    printf("chained ntfy:\n");
    dump_chains(fd, srcu_chains, sizeof(srcu_chains) / sizeof(srcu_chains[0]), IOCTL_CNTSNTFYCHAIN, IOCTL_ENUMSNTFYCHAIN);
    printf("\nsrcu chained ntfy:\n");
    dump_chains(fd, s_chains, sizeof(s_chains) / sizeof(s_chains[0]), IOCTL_CNTNTFYCHAIN, IOCTL_ENUMNTFYCHAIN);
    printf("\natomic chained ntfy:\n");
    dump_chains(fd, a_chains, sizeof(a_chains) / sizeof(a_chains[0]), IOCTL_CNTANTFYCHAIN, IOCTL_ENUMANTFYCHAIN);
  }
  if ( opt_s )
  {
    int idx;
    union kernfs_params kparm;
    if ( optind == argc )
    {
      printf("where is files?\n");
      exit(6);
    }
    for ( idx = optind; idx < argc; idx++ )
    {
      strncpy(kparm.name, argv[idx], sizeof(kparm.name) - 1);
      kparm.name[sizeof(kparm.name) - 1] = 0;
      err = ioctl(fd, IOCTL_KERNFS_NODE, (int *)&kparm);
      if ( err )
      {
        printf("IOCTL_KERNFS_NODE(%s) failed, error %d\n", argv[idx], err);
        goto end;
      }
      printf("res %s: %p\n", argv[idx], (void *)kparm.res.addr);
      if ( kparm.res.addr )
      {
        // dump flags
        printf(" flags: %lX", kparm.res.flags);
        if ( kparm.res.flags & 1 )
          printf(" DIR");
        if ( kparm.res.flags & 2 )
          printf(" FILE");
        if ( kparm.res.flags & 4 )
          printf(" LINK");
        printf("\n");

        printf(" priv: %p\n", (void *)kparm.res.priv);
        if ( kparm.res.kobject )
          printf("kobject: %p\n", (void *)kparm.res.kobject);
        if ( kparm.res.ktype )
          dump_kptr(kparm.res.ktype, "ktype");
        if ( kparm.res.sysfs_ops )
          dump_kptr(kparm.res.sysfs_ops, "sysfs_ops");
        if ( kparm.res.show )
          dump_kptr(kparm.res.sysfs_ops, "sysfs_ops.show");
        if ( kparm.res.store )
          dump_kptr(kparm.res.sysfs_ops, "sysfs_ops.store");
      } else {
        printf(" inode: %p\n", (void *)kparm.res.flags);
        if ( kparm.res.s_op )
          dump_kptr(kparm.res.s_op, "s_op");
        if ( kparm.res.priv )
          dump_kptr(kparm.res.priv, "inode->i_fop");
      }
    }
  }
  if ( opt_t )
  {
    // trace events
    strcpy(kparm.name, "trace_event_sem");
    err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
    if ( err )
    {
      printf("IOCTL_RKSYM trace_event_sem failed, error %d\n", err);
      goto end;
    }
    trace_sem = kparm.addr;
    strcpy(kparm.name, "event_hash");
    err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
    if ( err )
    {
      printf("IOCTL_RKSYM event_hash failed, error %d\n", err);
      goto end;
    }
    event_hash = kparm.addr;
    if ( event_hash && kparm.addr )
    {
      printf("\ntrace events: trace_sem %p event_hash %p\n", (void *)trace_sem, (void *)event_hash);
      dump_trace_events(fd, trace_sem, event_hash);
    }
  }
end:
  // cleanup
  close(fd);
  return err;
};