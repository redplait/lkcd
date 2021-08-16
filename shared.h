#ifndef LKCD_SHARED_H
# define LKCD_SHARED_H

#define IOCTL_NUM 'L'

#define IOCTL_BASE                     _IO(IOCTL_NUM, 0)
#define IOCTL_RKSYM                    _IOR(IOCTL_NUM, 0x1, int*)
// for blocking_notifier_chain_register
#define IOCTL_CNTNTFYCHAIN             _IOR(IOCTL_NUM, 0x2, int*)
#define IOCTL_ENUMNTFYCHAIN            _IOR(IOCTL_NUM, 0x3, int*)
// for atomic_notifier_chain_register
#define IOCTL_CNTANTFYCHAIN            _IOR(IOCTL_NUM, 0x4, int*)
#define IOCTL_ENUMANTFYCHAIN           _IOR(IOCTL_NUM, 0x5, int*)
// for srcu_notifier_chain_register
#define IOCTL_CNTSNTFYCHAIN            _IOR(IOCTL_NUM, 0x6, int*)
#define IOCTL_ENUMSNTFYCHAIN           _IOR(IOCTL_NUM, 0x7, int*)

// get registered trace_event count
// in params:
//  0 - rw_semaphore * (trace_event_sem)
//  1 - event_hash address
//  2 - index in event_hash
#define IOCTL_TRACEV_CNT               _IOR(IOCTL_NUM, 0x8, int*)

// output struct
struct one_trace_event
{
  void *addr;
  int type;
  // callbacks from struct trace_event_functions *funcs;
  void *trace;
  void *raw;
  void *hex;
  void *binary;
};
// get registered trace_events
// in params - the same as for IOCTL_TRACEV_CNT +
//  3 - cnt
// out params - long size + N * one_trace_event
#define IOCTL_TRACEVENTS               _IOR(IOCTL_NUM, 0x9, int*)

#endif /* LKCD_SHARED_H */
