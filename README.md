# lkcd
Small pet project to find and dump some linux kernel guts like
* notification chains
* function pointers in .data section
* check them with -c option (you need load driver lkcd first)
* function pointers in .bss section - with some disasm magic
* ftrace addresses
etc etc

Sure contains poorly written buggy driver

Sample of checking on x64 5.8.0-63

```
mem at 0xffffffff8b633058 (x86_cpuinit+8) patched to 0xffffffff8a075d50 (kvm_setup_secondary_clock)
mem at 0xffffffff8b6331c0 (i8259A_chip+40) patched to 0xffffffff8a0373a0 (disable_8259A_irq)
mem at 0xffffffff8b6365c8 (machine_check_vector) patched to 0xffffffff8ab74bf0 (do_machine_check)
mem at 0xffffffff8b6365d0 (mce_adjust_timer) patched to 0xffffffff8a04f200 (cmci_intel_adjust_timer)
mem at 0xffffffff8b638848 (__acpi_register_gsi) patched to 0xffffffff8a060d40 (acpi_register_gsi_ioapic)
mem at 0xffffffff8b641a28 (pv_ops+8) patched to 0xffffffff8a075cb0 (kvm_sched_clock_read)
mem at 0xffffffff8b652c08 (alg+8) patched to 0xffffffff8a089550 (crc32c_pcl_intel_update)
mem at 0xffffffff8b652c18 (alg+18) patched to 0xffffffff8a089530 (crc32c_pcl_intel_finup)
mem at 0xffffffff8b652c20 (alg+20) patched to 0xffffffff8a089510 (crc32c_pcl_intel_digest)
mem at 0xffffffff8b7d2d70 (ecap_perms+30) patched to 0xffffffff8a82f0f0 (vfio_default_config_read)
mem at 0xffffffff8b7d2dd0 (ecap_perms+90) patched to 0xffffffff8a82f0f0 (vfio_default_config_read)
mem at 0xffffffff8b7d3230 (cap_perms+10) patched to 0xffffffff8a82f320 (vfio_basic_config_read)
mem at 0xffffffff8b7d3250 (cap_perms+30) patched to 0xffffffff8a82f0f0 (vfio_default_config_read)
mem at 0xffffffff8b7d3290 (cap_perms+70) patched to 0xffffffff8a82f0f0 (vfio_default_config_read)
mem at 0xffffffff8b7d3310 (cap_perms+F0) patched to 0xffffffff8a82f0f0 (vfio_default_config_read)
mem at 0xffffffff8b7d3430 (cap_perms+210) patched to 0xffffffff8a82f0f0 (vfio_default_config_read)
mem at 0xffffffff8b7d3490 (cap_perms+270) patched to 0xffffffff8a82f0f0 (vfio_default_config_read)
mem at 0xffffffff8b81f1e0 (pcibios_disable_irq) patched to 0xffffffff8a643760 (acpi_pci_irq_disable)
mem at 0xffffffff8b81f1e8 (pcibios_enable_irq) patched to 0xffffffff8a6434d0 (acpi_pci_irq_enable)
```


# dependencies
* elfio (https://github.com/serge1/ELFIO)
* libudis86 (https://github.com/vmt/udis86)

