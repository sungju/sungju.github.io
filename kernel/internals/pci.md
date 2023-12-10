# PCI 

### Peripheral Component Interconnect ###

- It is a local computer bus for attaching hardware devices in a computer
- It is part of the PCI Local Bus standard
- The PCI bus supports the functions found on a processor bus, but in a standardized format that is independent of any particular processor's native bus.
  - Devices appear to a bus master to be connected directly to its own bus
  - Devices are assigned in the processor's address space
  - It is a parallel bus, synchronous to a single bus clock

### Auto configuration ###

- PCI provides separate memory and I/O port address spaces for the x86 processor family
  - It's assigned by software
- PCI Configuration Space
  - It uses a fixed addressing scheme
  - Allows software to determine the amount of memory and I/O address space needed by each device
  - Each device can request up to six areas of memory space or I/O port space via configuration space registers
  - 256 bytes memory is used to respond to the BIOS.
    - BIOS scans for devices and assigns Memory and I/O address ranges to them.

![PCI Configuration Space](https://sungju.github.io/kernel/internals/pci_config_space.png)

  - Device ID (DID) and Vendor ID (VID) registers identify the device and also called the PCI ID
  - Status register reports
    - which features are supported
    - whether certain kinds of errors have occured
  - Command register contains a bitmask of features that can be individually enabled and disabled
  - Subsystem ID (SSID) and Subsystem Vendor ID (SVID) differentiate specific model such as an add-in card
    - While the Vendor ID is that of the chipset manufacturer, the Subsystem Vendor ID is that of the card manufacturer.
    - The Subsystem ID is assigned by the subsystem vendor from the same number space as the Device ID.
    - Example:

```
$ lspci -kx
...
02:02.0 Multimedia audio controller: Ensoniq ES1371/ES1373 / Creative Labs CT2518 (rev 02)
        Subsystem: Ensoniq Audio PCI 64V/128/5200 / Creative CT4810/CT5803/CT5806 [Sound Blaster PCI]
        Kernel driver in use: snd_ens1371
        Kernel modules: snd_ens1371
00: 74 12 71 13 07 00 90 02 02 00 01 04 00 40 00 00
10: 41 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00
20: 00 00 00 00 00 00 00 00 00 00 00 00 74 12 71 13
30: 00 00 00 00 40 00 00 00 00 00 00 00 09 01 06 ff
...
$ lspci -n
...
02:02.0 0401: 1274:1371 (rev 02)
...
```

- Checking the vendor id shows the below.

```
http://pcidatabase.com/search.php?vendor_search_str=1274&vendor_search.x=0&vendor_search.y=0&vendor_search=search+vendors

Returning 1 match for: "1274"
Sorted by: Vendor ID

Vendor Id Vendor Name
0x1274  Ensoniq
```

- The reason the module snd_ens1371 was loaded in the above.

```
$ grep pci modules.alias | grep 1274 | grep 1371
alias pci:v00001274d00005880sv*sd*bc*sc*i* snd_ens1371
alias pci:v00001274d00001371sv*sd*bc*sc*i* snd_ens1371
$ pwd
/lib/modules/3.10.0-514.el7.x86_64
$
```

- Checking the current PCI devices information can be found under /sys/class/pci_bus/

```
$ tree /sys/class/pci_bus/
/sys/class/pci_bus/
├── 0000:00 -> ../../devices/pci0000:00/pci_bus/0000:00
├── 0000:01 -> ../../devices/pci0000:00/0000:00:01.0/pci_bus/0000:01
├── 0000:02 -> ../../devices/pci0000:00/0000:00:11.0/pci_bus/0000:02
├── 0000:03 -> ../../devices/pci0000:00/0000:00:15.0/pci_bus/0000:03
├── 0000:04 -> ../../devices/pci0000:00/0000:00:15.1/pci_bus/0000:04
├── 0000:05 -> ../../devices/pci0000:00/0000:00:15.2/pci_bus/0000:05
├── 0000:06 -> ../../devices/pci0000:00/0000:00:15.3/pci_bus/0000:06
├── 0000:07 -> ../../devices/pci0000:00/0000:00:15.4/pci_bus/0000:07
├── 0000:08 -> ../../devices/pci0000:00/0000:00:15.5/pci_bus/0000:08
├── 0000:09 -> ../../devices/pci0000:00/0000:00:15.6/pci_bus/0000:09
├── 0000:0a -> ../../devices/pci0000:00/0000:00:15.7/pci_bus/0000:0a
├── 0000:0b -> ../../devices/pci0000:00/0000:00:16.0/pci_bus/0000:0b
├── 0000:0c -> ../../devices/pci0000:00/0000:00:16.1/pci_bus/0000:0c
├── 0000:0d -> ../../devices/pci0000:00/0000:00:16.2/pci_bus/0000:0d
├── 0000:0e -> ../../devices/pci0000:00/0000:00:16.3/pci_bus/0000:0e
├── 0000:0f -> ../../devices/pci0000:00/0000:00:16.4/pci_bus/0000:0f
├── 0000:10 -> ../../devices/pci0000:00/0000:00:16.5/pci_bus/0000:10
├── 0000:11 -> ../../devices/pci0000:00/0000:00:16.6/pci_bus/0000:11
├── 0000:12 -> ../../devices/pci0000:00/0000:00:16.7/pci_bus/0000:12
├── 0000:13 -> ../../devices/pci0000:00/0000:00:17.0/pci_bus/0000:13
├── 0000:14 -> ../../devices/pci0000:00/0000:00:17.1/pci_bus/0000:14
├── 0000:15 -> ../../devices/pci0000:00/0000:00:17.2/pci_bus/0000:15
├── 0000:16 -> ../../devices/pci0000:00/0000:00:17.3/pci_bus/0000:16
├── 0000:17 -> ../../devices/pci0000:00/0000:00:17.4/pci_bus/0000:17
├── 0000:18 -> ../../devices/pci0000:00/0000:00:17.5/pci_bus/0000:18
├── 0000:19 -> ../../devices/pci0000:00/0000:00:17.6/pci_bus/0000:19
├── 0000:1a -> ../../devices/pci0000:00/0000:00:17.7/pci_bus/0000:1a
├── 0000:1b -> ../../devices/pci0000:00/0000:00:18.0/pci_bus/0000:1b
├── 0000:1c -> ../../devices/pci0000:00/0000:00:18.1/pci_bus/0000:1c
├── 0000:1d -> ../../devices/pci0000:00/0000:00:18.2/pci_bus/0000:1d
├── 0000:1e -> ../../devices/pci0000:00/0000:00:18.3/pci_bus/0000:1e
├── 0000:1f -> ../../devices/pci0000:00/0000:00:18.4/pci_bus/0000:1f
├── 0000:20 -> ../../devices/pci0000:00/0000:00:18.5/pci_bus/0000:20
├── 0000:21 -> ../../devices/pci0000:00/0000:00:18.6/pci_bus/0000:21
└── 0000:22 -> ../../devices/pci0000:00/0000:00:18.7/pci_bus/0000:22

35 directories, 0 files
```

- PCI device identifier is implemented with four numbers
    - Bus number
      - Allows 256 buses
      - In general, PC has 1 or 2 buses
    - Device number
      - Each bus can have maximum 32 devices
    - Function number
      - Each device can have 8 functions
    - Domain number
      - Linux provides this as a upper layer on bus numbers
    - Format:
      - domain:bus:device.function

### How to register your driver for a PCI device ###

- Related data structure and functions

```
struct pci_driver {
  struct list_head node;
  const char *name;
  const struct pci_device_id *id_table; /* must be non-NULL for probe to be called */
  int  (*probe)  (struct pci_dev *dev, const struct pci_device_id *id); /* New device inserted */
  void (*remove) (struct pci_dev *dev); /* Device removed (NULL if not a hot-plug capable driver) */
  int  (*suspend) (struct pci_dev *dev, pm_message_t state);  /* Device suspended */
  int  (*suspend_late) (struct pci_dev *dev, pm_message_t state);
  int  (*resume_early) (struct pci_dev *dev);
  int  (*resume) (struct pci_dev *dev);                 /* Device woken up */
  void (*shutdown) (struct pci_dev *dev);
  int (*sriov_configure) (struct pci_dev *dev, int num_vfs); /* PF pdev */
  const struct pci_error_handlers *err_handler;
  struct device_driver  driver;
  struct pci_dynids dynids;

  /* Extension to accomodate future upstream changes to this structure
   * yet maintain RHEL7 KABI.  For Red Hat internal use only!
  struct pci_driver_rh  *pci_driver_rh;
};

int pci_register_driver(struct pci_driver *drv);
void pci_unregister_driver(struct pci_driver *drv);

/**
 * module_pci_driver() - Helper macro for registering a PCI driver
 * @__pci_driver: pci_driver struct
 *
 * Helper macro for PCI drivers which do not do anything special in module
 * init/exit. This eliminates a lot of boilerplate. Each module may only
 * use this macro once, and calling it replaces module_init() and module_exit()
 */
#define module_pci_driver(__pci_driver) \
  module_driver(__pci_driver, pci_register_driver, \
           pci_unregister_driver)
```

- From pci_driver structure, below are the most important fields.
  - id_table : Specifying device list you are interested in this driver
  - probe : It's called when there's a matching device
  - remove : It's called when the device is going to be removed
  - suspend : It's called before the device goes into sleep mode
  - resume : It's called once the device is back active 
- id_table is type 'pci_device_id' which you specify the device ID's that you can find in pci_configuration_table

```
#define PCI_ANY_ID (~0)

struct pci_device_id {
  __u32 vendor, device;   /* Vendor and device ID or PCI_ANY_ID*/
  __u32 subvendor, subdevice; /* Subsystem ID's or PCI_ANY_ID */
  __u32 class, class_mask;  /* (class,subclass,prog-if) triplet */
  kernel_ulong_t driver_data; /* Data private to the driver */
};
```

- Example :

```
#define PCI_VENDOR_ID_ENSONIQ   0x1274

...

static const struct pci_device_id snd_audiopci_ids[] = {
#ifdef CHIP1370
  { PCI_VDEVICE(ENSONIQ, 0x5000), 0, }, /* ES1370 */
#endif
#ifdef CHIP1371
  { PCI_VDEVICE(ENSONIQ, 0x1371), 0, }, /* ES1371 */
  { PCI_VDEVICE(ENSONIQ, 0x5880), 0, }, /* ES1373 - CT5880 */
  { PCI_VDEVICE(ECTIVA, 0x8938), 0, },  /* Ectiva EV1938 */
#endif
  { 0, }
};

MODULE_DEVICE_TABLE(pci, snd_audiopci_ids);

...


static struct pci_driver ens137x_driver = {
  .name = KBUILD_MODNAME,
  .id_table = snd_audiopci_ids,
  .probe = snd_audiopci_probe,
  .remove = snd_audiopci_remove,
  .driver = {
    .pm = SND_ENSONIQ_PM_OPS,
  },
};

module_pci_driver(ens137x_driver);
```

- MODULE_DEVICE_TABLE macro is used to let the system knows what devices can be handled by this module

```
#define MODULE_DEVICE_TABLE(type,name)    \
  MODULE_GENERIC_TABLE(type##_device,name)
  
extern const struct gtype##_id __mod_##gtype##_table    \
  __attribute__ ((unused, alias(__stringify(name)))) 
```

### Checking PCI device dtails ###

- If you want to see the PCI devices currently attached to the system, you can use 'pci_dev' structure.

```
/*
 * The pci_dev structure is used to describe PCI devices.
 */
struct pci_dev {
  struct list_head bus_list;  /* node in per-bus list */
  struct pci_bus  *bus;   /* bus this device is on */
  struct pci_bus  *subordinate; /* bus this device bridges to */

  void    *sysdata; /* hook for sys-specific extension */
  struct proc_dir_entry *procent; /* device entry in /proc/bus/pci */
  struct pci_slot *slot;    /* Physical slot this device is in */

  unsigned int  devfn;    /* encoded device & function kernel/internals/index */
  unsigned short  vendor;
  unsigned short  device;
  unsigned short  subsystem_vendor;
  unsigned short  subsystem_device;
  unsigned int  class;    /* 3 bytes: (base,sub,prog-if) */
  u8    revision; /* PCI revision, low byte of class word */
  u8    hdr_type; /* PCI header type (`multi' flag masked out) */
  u8    pcie_cap; /* PCIe capability offset */
  u8    msi_cap;  /* MSI capability offset */
  u8    msix_cap; /* MSI-X capability offset */
  u8    pcie_mpss:3;  /* PCIe Max Payload Size Supported */
  u8    rom_base_reg; /* which config register controls the ROM */
  u8    pin;    /* which interrupt pin this device uses */
  u16   pcie_flags_reg; /* cached PCIe Capabilities Register */

  struct pci_driver *driver;  /* which driver has allocated this device */
  u64   dma_mask; /* Mask of the bits of bus address this
             device implements.  Normally this is
             0xffffffff.  You only need to change
             this if your device has broken DMA
             or supports 64-bit transfers.  */

  struct device_dma_parameters dma_parms;

  pci_power_t     current_state;  /* Current operating state. In ACPI-speak,
             this is D0-D3, D0 being fully functional,
             and D3 being off. */
  u8    pm_cap;   /* PM capability offset */
  unsigned int  pme_support:5;  /* Bitmask of states from which PME#
             can be generated */
  unsigned int  pme_interrupt:1;
  unsigned int  pme_poll:1; /* Poll device's PME status bit */
  unsigned int  d1_support:1; /* Low power state D1 is supported */
  unsigned int  d2_support:1; /* Low power state D2 is supported */
  unsigned int  no_d1d2:1;  /* D1 and D2 are forbidden */
  unsigned int  no_d3cold:1;  /* D3cold is forbidden */
  unsigned int  d3cold_allowed:1; /* D3cold is allowed by user */
  unsigned int  mmio_always_on:1; /* disallow turning off io/mem
               decoding during bar sizing */
  unsigned int  wakeup_prepared:1;
  unsigned int  runtime_d3cold:1; /* whether go through runtime
               D3cold, not set for devices
               powered on/off by the
               corresponding bridge */
  RH_KABI_FILL_HOLE(unsigned int  ignore_hotplug:1)
  unsigned int  d3_delay; /* D3->D0 transition time in ms */
  unsigned int  d3cold_delay; /* D3cold->D0 transition time in ms */

#ifdef CONFIG_PCIEASPM
  struct pcie_link_state  *link_state;  /* ASPM link state */
#endif
  
  pci_channel_state_t error_state;  /* current connectivity state */
  struct  device  dev;    /* Generic device interface */
  
  int   cfg_size; /* Size of configuration space */
  
  /*
   * Instead of touching interrupt line and base address registers
   * directly, use the values stored here. They might be different!
   */
  unsigned int  irq;
  struct resource resource[DEVICE_COUNT_RESOURCE]; /* I/O and memory regions + expansion ROMs */

  bool match_driver;    /* Skip attaching driver */
  /* These fields are used by common fixups */
  unsigned int  transparent:1;  /* Subtractive decode PCI bridge */
  unsigned int  multifunction:1;/* Part of multi-function device */
  /* keep track of device state */
  unsigned int  is_added:1;
  unsigned int  is_busmaster:1; /* device is busmaster */
  unsigned int  no_msi:1; /* device may not use msi */
  unsigned int  block_cfg_access:1; /* config space access is blocked */
  unsigned int  broken_parity_status:1; /* Device generates false positive parity */
  unsigned int  irq_reroute_variant:2;  /* device needs IRQ rerouting variant */
  unsigned int  msi_enabled:1;
  unsigned int  msix_enabled:1;
  unsigned int  ari_enabled:1;  /* ARI forwarding */
  unsigned int  is_managed:1;
  unsigned int    needs_freset:1; /* Dev requires fundamental reset */
  unsigned int  state_saved:1;
  unsigned int  is_physfn:1;                                                      
  unsigned int  is_virtfn:1;
  unsigned int  reset_fn:1;
  unsigned int    is_hotplug_bridge:1;
  unsigned int    __aer_firmware_first_valid:1;
  unsigned int  __aer_firmware_first:1;
  unsigned int  broken_intx_masking:1;
  unsigned int  io_window_1k:1; /* Intel P2P bridge 1K I/O windows */
  RH_KABI_FILL_HOLE(unsigned int no_64bit_msi:1) /* device may only use 32-bit MSIs */
  RH_KABI_FILL_HOLE(unsigned int irq_managed:1)
  pci_dev_flags_t dev_flags;                                                     
  atomic_t  enable_cnt; /* pci_enable_device has been called */
  
  u32   saved_config_space[16]; /* config space saved at suspend time */
  struct hlist_head saved_cap_space;
  struct bin_attribute *rom_attr; /* attribute descriptor for sysfs ROM entry */
  int rom_attr_enabled;   /* has display of the rom attribute been enabled? */
  struct bin_attribute *res_attr[DEVICE_COUNT_RESOURCE]; /* sysfs file for resources */
  struct bin_attribute *res_attr_wc[DEVICE_COUNT_RESOURCE]; /* sysfs file for WC mapping of resources */
#ifdef CONFIG_PCI_MSI
  struct list_head msi_list;
  struct kset *msi_kset;    /* obsolete as of RHEL7.1 */
  const struct attribute_group **msi_irq_groups;
#endif
  struct pci_vpd *vpd;
#ifdef CONFIG_PCI_ATS                                                            
  union {
    struct pci_sriov *sriov;  /* SR-IOV capability related */
    struct pci_dev *physfn; /* the PF this VF is associated with */              
   };
  struct pci_ats  *ats; /* Address Translation Service */
#endif
  phys_addr_t rom; /* Physical address of ROM if it's not from the BAR */
  size_t romlen; /* Length of ROM if it's not from the BAR */
  
  /* Extension to accomodate future upstream changes to this structure             * yet maintain RHEL7 KABI.  For Red Hat internal use only!
   */                                                                            
  struct pci_dev_rh  *pci_dev_rh;
};
```

- PCI device checking functions

```
/**
 * pci_get_device - begin or continue searching for a PCI device by vendor/device id
 * @vendor: PCI vendor id to match, or %PCI_ANY_ID to match all vendor ids
 * @device: PCI device id to match, or %PCI_ANY_ID to match all device ids
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices.  If a PCI device is
 * found with a matching @vendor and @device, the reference count to the
 * device is incremented and a pointer to its device structure is returned.
 * Otherwise, %NULL is returned.  A new search is initiated by passing %NULL
 * as the @from argument.  Otherwise if @from is not %NULL, searches continue
 * from next device on the global list.  The reference count for @from is
 * always decremented if it is not %NULL.
 */
struct pci_dev *pci_get_device(unsigned int vendor, unsigned int device,
             struct pci_dev *from);
             
             
/**
 * pci_get_class - begin or continue searching for a PCI device by class
 * @class: search for a PCI device with this class designation
 * @from: Previous PCI device found in search, or %NULL for new search.
 *
 * Iterates through the list of known PCI devices.  If a PCI device is
 * found with a matching @class, the reference count to the device is
 * incremented and a pointer to its device structure is returned.
 * Otherwise, %NULL is returned.
 * A new search is initiated by passing %NULL as the @from argument.
 * Otherwise if @from is not %NULL, searches continue from next device
 * on the global list.  The reference count for @from is always decremented
 * if it is not %NULL.
 */
struct pci_dev *pci_get_class(unsigned int class, struct pci_dev *from);
```

- Example: pci_view.c

```
/* pci_view */
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/init.h>

int __init my_init(void)
{
  u16 dval;
  char byte;
  int j = 0;
  struct pci_dev *pdev = NULL;

  printk("Loading the pci device finder\n");

  while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev))) {
    printk("\n FOUND PCI DEVICE # j = %d, ", j++);
    pci_read_config_word(pdev, PCI_VENDOR_ID, &dval);
    printk("PCI_VENDOR_ID=%x ", dval);
    pci_read_config_word(pdev, PCI_DEVICE_ID, &dval);
    printk("PCI_DEVICE_ID=%x ", dval);
    pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &byte);
    printk("irq = %d\n", byte);
  }
  return -1;
}

void __exit my_exit(void)
{
}

module_init(my_init);
module_exit(my_exit);
```

- Running

```
$ make
make[1]: Entering directory `/usr/src/kernels/3.10.0-514.el7.x86_64'
  CC [M]  /root/Study/Kernel/pci_view.o
  Building modules, stage 2.
  MODPOST 12 modules
  CC      /root/Study/Kernel/pci_view.mod.o
  LD [M]  /root/Study/Kernel/pci_view.ko
make[1]: Leaving directory `/usr/src/kernels/3.10.0-514.el7.x86_64'
$ insmod pci_view.ko
insmod: ERROR: could not insert module pci_view.ko: Operation not permitted
$ tail /var/log/messages
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 36, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=7a0 irq = -1
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 37, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=7a0 irq = -1
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 38, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=7a0 irq = -1
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 39, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=7a0 irq = -1
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 40, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=7a0 irq = -1
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 41, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=774 irq = 10
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 42, PCI_VENDOR_ID=8086 PCI_DEVICE_ID=100f irq = 5
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 43, PCI_VENDOR_ID=1274 PCI_DEVICE_ID=1371 irq = 9
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 44, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=770 irq = 11
Jan 24 09:42:20 devel kernel: #012 FOUND PCI DEVICE # j = 45, PCI_VENDOR_ID=15ad PCI_DEVICE_ID=7e0 irq = 5
```

- To read PCI configuration space's data, you can use one of the below functions depends on the data size

```
/* Read from PCI configuration space */
int pci_read_config_byte(const struct pci_dev *dev, int where, u8 *val);
int pci_read_config_word(const struct pci_dev *dev, int where, u16 *val);
int pci_read_config_dword(const struct pci_dev *dev, int where, u32 *val);

/* Write into PCI configuration space */
int pci_write_config_byte(const struct pci_dev *dev, int where, u8 val);
int pci_write_config_word(const struct pci_dev *dev, int where, u16 val);
int pci_write_config_dword(const struct pci_dev *dev, int where, u32 val);
```

- PCI device memory or IO address can be checked with the below functions

```
/* these helpers provide future and backwards compatibility
 * for accessing popular PCI BAR info */
#define pci_resource_start(dev, bar)  ((dev)->resource[(bar)].start)
#define pci_resource_end(dev, bar)  ((dev)->resource[(bar)].end)
#define pci_resource_flags(dev, bar)  ((dev)->resource[(bar)].flags)
#define pci_resource_len(dev,bar) \
  ((pci_resource_start((dev), (bar)) == 0 &&  \
    pci_resource_end((dev), (bar)) ==   \
    pci_resource_start((dev), (bar))) ? 0 : \
              \
   (pci_resource_end((dev), (bar)) -    \
    pci_resource_start((dev), (bar)) + 1))
``` 

### Running as a pci driver ###

- To run as a pci driver, you need to implement 'probe' and do additional operations for the actual device registeration such as character/block/network device driver.

```
/* pci_probe_test.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>

struct pci_device_id ids[] = {
        { PCI_DEVICE(PCI_ANY_ID, PCI_ANY_ID), },
        { 0, }
};

MODULE_DEVICE_TABLE(pci, ids);

int my_probe(struct pci_dev *dev, const struct pci_device_id *id) {
        u8 bval;
        u16 wval;

        /* pci_enabled_device(dev); */
        pci_read_config_word(dev, PCI_VENDOR_ID, &wval);
        pci_read_config_byte(dev, PCI_REVISION_ID, &bval);

        printk(" Vendor ID = 0x%x, revision = 0x%x\n", wval, bval);
        return 0;
}

void remove(struct pci_dev *dev) {
        printk("device removed\n");
}

struct pci_driver my_driver = {
        .name = "my_pci",
        .id_table = ids,
        .probe = my_probe,
        .remove = remove,
};

int __init my_init(void) {
        return pci_register_driver(&my_driver);
}

void __exit my_exit(void) {
        pci_unregister_driver(&my_driver);
}

module_init(my_init);
module_exit(my_exit);
```

- Running

```
$ make
make[1]: Entering directory `/usr/src/kernels/3.10.0-514.el7.x86_64'
  CC [M]  /root/Study/Kernel/pci_probe_test.o
  Building modules, stage 2.
  MODPOST 13 modules
  LD [M]  /root/Study/Kernel/pci_probe_test.ko
make[1]: Leaving directory `/usr/src/kernels/3.10.0-514.el7.x86_64'
$ insmod pci_probe_test.ko
$ tail /var/log/messages
Jan 24 10:31:08 devel nm-dispatcher: req:1 'dhcp4-change' [ens33]: start running ordered scripts...
Jan 24 10:31:43 devel chronyd[816]: Selected source 204.2.134.164
Jan 24 10:31:43 devel chronyd[816]: Can't synchronise: no majority
Jan 24 10:32:48 devel chronyd[816]: Selected source 27.124.125.252
Jan 24 10:33:53 devel chronyd[816]: Selected source 204.2.134.164
Jan 24 10:34:57 devel chronyd[816]: Selected source 13.54.31.227
Jan 24 10:35:32 devel kernel: Vendor ID = 0x8086, revision = 0x1
Jan 24 10:35:32 devel kernel: Vendor ID = 0x8086, revision = 0x8
Jan 24 10:35:32 devel kernel: Vendor ID = 0x8086, revision = 0x8
Jan 24 10:35:32 devel kernel: Vendor ID = 0x15ad, revision = 0x2
```

- Example from the kernel source

```
static const struct pci_device_id tg3_pci_tbl[] = {
  {PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5700)},
  {PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5701)},
  {PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5702)},
  {PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5703)},
  {PCI_DEVICE(PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_TIGON3_5704)},
  ...
}
  
static struct pci_driver tg3_driver = {
  .name   = DRV_MODULE_NAME,
  .id_table = tg3_pci_tbl,
  .probe    = tg3_init_one,
  .remove   = tg3_remove_one,
  .err_handler  = &tg3_err_handler,
  .driver.pm  = &tg3_pm_ops,
  .shutdown = tg3_shutdown,
};

...

static int tg3_init_one(struct pci_dev *pdev,
          const struct pci_device_id *ent)
{
  struct net_device *dev;
  struct tg3 *tp;
...
  err = pci_enable_device(pdev);
  if (err) {
    dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
    return err;
  }

  err = pci_request_regions(pdev, DRV_MODULE_NAME);
  if (err) {
    dev_err(&pdev->dev, "Cannot obtain PCI resources, aborting\n");
    goto err_out_disable_pdev;
  }
...
  tg3_timer_init(tp);

  tg3_carrier_off(tp);

  err = register_netdev(dev);
...
  return err;
}
```


---
[Back to topic list](https://sungju.github.io/kernel/internals/index)
