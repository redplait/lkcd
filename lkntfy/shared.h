#define IOCTL_NUM 'N'

#define IOCTL_BASE                     _IO(IOCTL_NUM, 0)
#define IOCTL_ADDFILE                  _IOR(IOCTL_NUM, 0x1, int*)
#define IOCTL_DELFILE                  _IOR(IOCTL_NUM, 0x2, int*)
