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
#include "shared.h"
#include "kmods.h"

// some kernel typedefs
typedef uint64_t u64;
// from include/linux/types.h
struct list_head {
	struct list_head *next, *prev;
};

// ksym
union ksym_params {
  unsigned long addr;
  char name[256];
};

// kernel base and end
unsigned long g_kstart = 0;
unsigned long g_kend = 0;

int is_inside_kernel(unsigned long a)
{
  return (a >= g_kstart) && (a < g_kend);
}

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

int main(int argc, char **argv)
{
  int fd;
  union ksym_params kparm;
  unsigned long addr;
  int err = 0;
  size_t i;
  // open device
  fd = open("/dev/lkcd", 0);
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
  strcpy(kparm.name, "startup_64");
  err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
  if ( err )
  {
    printf("IOCTL_RKSYM startup_64 failed, error %d\n", err);
    goto end;
  }
  g_kstart = kparm.addr;
  strcpy(kparm.name, "__end_of_kernel_reserve");
  err = ioctl(fd, IOCTL_RKSYM, (int *)&kparm);
  if ( err )
  {
    printf("IOCTL_RKSYM end_of_kernel failed, error %d\n", err);
    goto end;
  }
  g_kend = kparm.addr;
  // next test chained ntfy
  dump_chains(fd, srcu_chains, sizeof(srcu_chains) / sizeof(srcu_chains[0]), IOCTL_CNTSNTFYCHAIN, IOCTL_ENUMSNTFYCHAIN);
  dump_chains(fd, s_chains, sizeof(s_chains) / sizeof(s_chains[0]), IOCTL_CNTNTFYCHAIN, IOCTL_ENUMNTFYCHAIN);
  // atomic chains
  dump_chains(fd, a_chains, sizeof(a_chains) / sizeof(a_chains[0]), IOCTL_CNTANTFYCHAIN, IOCTL_ENUMANTFYCHAIN);
end:
  // cleanup
  close(fd);
  return err;
};