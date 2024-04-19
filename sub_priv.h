// ripped from https://elixir.bootlin.com/linux/v6.9-rc4/source/drivers/base/base.h#L42
struct subsys_private {
    struct kset subsys;
    struct kset *devices_kset;
    struct list_head interfaces;
    struct mutex mutex;

    struct kset *drivers_kset;
    struct klist klist_devices;
    struct klist klist_drivers;
    struct blocking_notifier_head bus_notifier;
    unsigned int drivers_autoprobe:1;
    const struct bus_type *bus;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,4,0)
    struct device *dev_root;
#endif
    struct kset glue_dirs;
    const struct class *class;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    struct lock_class_key lock_key;
#endif
};
#define to_subsys_private(obj) container_of(obj, struct subsys_private, subsys.kobj)