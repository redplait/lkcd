#define IOCTL_NUM 'N'

struct proc_dead {
  unsigned long timestamp;
  int exit_code;
};

// BPF_OBJ_NAME_LEN
#define MAX_MAP_NAME  16

#define IOCTL_BASE                     _IO(IOCTL_NUM, 0)
#define IOCTL_FROM_FD                  _IOR(IOCTL_NUM, 0x1, int*)
#define IOCTL_BY_ID                    _IOR(IOCTL_NUM, 0x2, int*)
#define IOCTL_BY_NAME                  _IOR(IOCTL_NUM, 0x3, int*)
