#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// ksym
union ksym_params {
  unsigned long addr;
  char name[256];
};

// for IOCTL_KERNFS_NODE
struct kernfs_res
{
  unsigned long addr;
  unsigned long kobject;
  unsigned long ktype;
  unsigned long sysfs_ops;
  unsigned long show;
  unsigned long store;
  unsigned long s_op;      // 6
  unsigned long flags;     // 7 inode
  unsigned long priv;      // 8 inode->i_fop
  // fields from kobj_type
  unsigned long release;   // 9
  unsigned long child_ns_type;
  unsigned long ns;        // 11
  unsigned long get_ownership;
};

union kernfs_params
{
  char name[256];
  struct kernfs_res res;
};

int is_inside_kernel(unsigned long a);
int read_kernel_area(int fd);
void HexDump(unsigned char *From, int Len);

#ifdef __cplusplus
};
#endif