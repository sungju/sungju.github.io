# Module Programming #

### Module code layout ###

#### Let's try and fail ####

```
$ cat simple_module.c
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Module Author");
MODULE_DESCRIPTION("Module Description");

static int __init my_init(void) {
  return 0; 
}

static void __exit my_exit(void) {
  return;
}

module_init(my_init);
module_exit(my_exit);
```

* To compile a module, it's required to have kernel source structure
* We can do it by installing 'kernel-devel' package. This contains kernel structure, but not actual source code

```
$ yum install kernel-devel
or
$ yum install kernel-devel-<version-number>
```

* Super simple compile method! but not recommended :)

```
$ cat Makefile
obj-m += simple_module.o

$ make -C /lib/modules/$(uname -r)/build M=$PWD modules
```

#### Module related commands and files ####

* Loading a module with full path : insmod

```
$ insmod module_name_with_full_path [module parameters...]

example)
insmod ./hello.ko count=50 delay=6
```

* Module checking

```
$ lsmod
or
$ cat /proc/modules
```

* Removing module from kernel
  * If the module is dependent to other module, that module must be unloaded first
  * If reference count is not 0, it won't be unloaded

```
$ rmmod <module name> [<module name> ...]
```

* Module database update
  * It's updating text based module database located under /lib/modules/kernel-X.XX/
  * It's used by modprobe to find a proper dependencies and the locations of a module
  * It requires to be run once you make any chnages in /etc/modprobe.conf, /etc/modprobe.d/* or /lib/modules/$(uname -r)/.
  * One common issue we are seeing in RHEL6 as of missing modules.dep : [Kernel panic with error "FATAL: Could not load modules.dep no such file or directory".](https://access.redhat.com/solutions/507183)

```
$ depmod

example)
$ depmod -ae
```

* modprobe : Better way to load a module
  * This module name should be in /lib/modules/$(uname -r)/modules.dep
  * If the module is dependent to other modules and those are not loaded yet, it'll load it automatically

```
$ modprobe <module name> [arguments...]

example)
$ modprobe hello count=50 delay=7
```

* modprobe.conf
  * Make it do some additonal operations before/after module loading/unloading
  * Alter the default parameters when it's not specified in the command line

```
install <module name> <command>
remove <module name> <command>
options <module name> <options>
```
#### More decent module layout ####

- Use custom init and exit function names

```
/* hello.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

int irq;
module_param(irq, int, 0644);
int sample;
module_param_named(test, sample, int, 0);

int arr_data[10];
int arr_cnt;
module_param_array(arr_data, int, &arr_cnt, 0);

int my_data __initdata = 5;

int __init my_init(void) {
        printk("irq = %d\n", irq);
        return 0;
}

void __exit my_exit(void) {
        printk("Bye. Bye..%d\n", irq);
}
module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sungju");
MODULE_DESCRIPTION("Hello..description");
```

- More conveint Makefile

```
obj-m += hello.o

export KROOT=/lib/modules/`uname -r`/build

allofit:   modules
modules:
        @$(MAKE) -C $(KROOT) M=$(PWD) modules
modules_install:
        @$(MAKE) -C $(KROOT) M=$(PWD) modules_install
clean:
        rm -rf   *.o *.ko .*cmd *.mod.c .tmp_versions .*.d .*.tmp Module.symvers
```

- How to pass parameters to module

```
#define module_param(name, type, perm)

/* Actually copy string: maxlen param is usually sizeof(string). */
#define module_param_string(name, string, len, perm)

/* Helper functions: type is byte, short, ushort, int, uint, long,
ulong, charp, bool or invbool, or XXX if you define param_get_XXX, param_set_XXX and param_check_XXX. */
#define module_param_named(name, value, type, perm)

#define module_param_array(name, type, nump, perm)

/* Comma-separated array: *nump is set to number they actually specified. */
#define module_param_array_named(name, array, type, nump, perm)
```

- Parameter types you can use

```
short: short
ushort: short
int: int
uint: unsigned int 
long: long
ulong: unsigned long 
charp: char *
bool: int
invbool: int
intarray: int *
```

- permission in module_param() will be used to access /sys/module/<module name>/parameters/

```
$ ls -l /sys/module/hello/parameters/
total 0
-rw-r--r--. 1 root 4.0K Aug 25 17:08 irq
$ cat /sys/module/hello/parameters/irq
10
$ echo 50 > /sys/module/hello/parameters/irq
$ cat /sys/module/hello/parameters/irq
50
```


- Other macros you can use in module

```
MODULE_AUTHOR(name);
MODULE_DESCRIPTION(desc);
MODULE_SUPPORTED_DEVICE(name);
MODULE_PARM_DESC(var,desc);
MODULE_FIRMWARE(filename);
MODULE_LICENSE(license);
MODULE_VERSION(version);
```

#### How hot-plug module works? ####

- To module loaded automatically for a new device attaching and removing itself once it's detached, you can specify that with the below macro

```
MODULE_DEVICE_TABLE(type, name)
```

  * For the type, you can use one of the below.

```
usb
pci
ieee1394
pcmcia
i2c
input
eisa
pnp
serio
```

  * Actual type is ended with __device. eg) pci == pci_device

```
#define MODULE_DEVICE_TABLE(type,name)    \
  MODULE_GENERIC_TABLE(type##_device,name)
```

  * This information is saved in one of the below files when 'depmod' command runs

```
$ ls modules.*map
modules.ccwmap  modules.ieee1394map  modules.inputmap  modules.isapnpmap  modules.ofmap  modules.pcimap  modules.seriomap  modules.usbmap

$ head modules.pcimap 
# pci module         vendor     device     subvendor  subdevice  class      class_mask driver_data
shpchp               0xffffffff 0xffffffff 0xffffffff 0xffffffff 0x00060400 0xffffffff 0x0
rivafb               0x000012d2 0x00000018 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
rivafb               0x000010de 0x00000020 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
...
```

  * Example

```
#define PCI_DEVICE_ID_NX2_57710   CHIP_NUM_57710

#define CHIP_NUM(bp)      (bp->common.chip_id >> 16)
#define CHIP_NUM_57710      0x164e
#define CHIP_NUM_57711      0x164f
#define CHIP_NUM_57711E     0x1650
#define CHIP_NUM_57712      0x1662
#define CHIP_NUM_57712_MF   0x1663

#define PCI_VDEVICE(vendor, device)   \
  PCI_VENDOR_ID_##vendor, (device), \
  PCI_ANY_ID, PCI_ANY_ID, 0, 0
  
static const struct pci_device_id bnx2x_pci_tbl[] = {
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57710), BCM57710 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57711), BCM57711 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57711E), BCM57711E },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57712), BCM57712 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57712_MF), BCM57712_MF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57712_VF), BCM57712_VF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57800), BCM57800 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57800_MF), BCM57800_MF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57800_VF), BCM57800_VF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57810), BCM57810 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57810_MF), BCM57810_MF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57840_O), BCM57840_O },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57840_4_10), BCM57840_4_10 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57840_2_20), BCM57840_2_20 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57810_VF), BCM57810_VF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57840_MFO), BCM57840_MFO },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57840_MF), BCM57840_MF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57840_VF), BCM57840_VF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57811), BCM57811 },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57811_MF), BCM57811_MF },
  { PCI_VDEVICE(BROADCOM, PCI_DEVICE_ID_NX2_57811_VF), BCM57811_VF },
  { 0 }
};

MODULE_DEVICE_TABLE(pci, bnx2x_pci_tbl);
```

  * Related pcimap file

```
$ grep 0x0000164 modules.pcimap 
tg3                  0x000014e4 0x00001644 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x000014e4 0x00001645 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x000014e4 0x00001646 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x000014e4 0x00001647 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x000014e4 0x00001648 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x000014e4 0x0000164d 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x000014e4 0x00001649 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x000014e4 0x00001643 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
tg3                  0x0000106b 0x00001645 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
bnx2                 0x000014e4 0x0000164a 0x0000103c 0x00003101 0x00000000 0x00000000 0x0
bnx2                 0x000014e4 0x0000164a 0x0000103c 0x00003106 0x00000000 0x00000000 0x0
bnx2                 0x000014e4 0x0000164a 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
bnx2                 0x000014e4 0x0000164c 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
bnx2x                0x000014e4 0x0000164e 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
bnx2x                0x000014e4 0x0000164f 0xffffffff 0xffffffff 0x00000000 0x00000000 0x0
```

  * It'll load related module when the signal happens in PCI layer by checking modules.pcimap
  * Same applies for USB and other devices

#### Module license policy ####

  * Each module needs to specify license policy with 'MODULE_LICENSE()' macro

```
example)
MODULE_LICENSE("GPL v2")
```

  * You can find available license keyword in include/linux/module.h

Keyword | Description
--- | ---
GPL | GNU Public License v2 or later
GPL v2 | GNU Public License v2
GPL and additional rights | GNU Public License v2 rights and more
Dual BSD/GPL | GNU Public License v2 or BSD license choice
Dual MIT/GPL | GNU Public License v2 or MIT license choice
Dual MPL/GPL | GNU Public License v2 or Mozilla license choice
Proprietary | Non free products

  * If license is not specified or specified as 'Proprietary', it will be marked as 'tainted' in /proc/sys/kernel/tainted
  * It also can cause of restriction in referencing other module/kernel's functions

#### How to export/import symbols in a module ####

- importing a symbol - function or varilable - is simple. Just saying 'extern' with symbol name

```
extern var_name;
extern void other_func();
```

- But, importing PER_CPU variable requires to use the below macro before use it

```
DECLARE_PER_CPU(type, name)
```

- exporting can be achieved by using the one of the below

```
EXPORT_SYMBOL(sym)
EXPORT_SYMBOL_GPL(sym)
```

- example

```
/* first.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

int __init my_init(void) {
  printk("Hello, I'm first\n");

  return 0;
}
void __exit my_exit(void) {
  printk("Bye, I'm first\n");
}

void first_func(void) {
  printk("You call me, I'm first_func\n");
}

EXPORT_SYMBOL(first_func);

module_init(my_init);
module_exit(my_exit);
```

```
/* second.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

extern void first_func();

MODULE_LICENSE("GPL");

int __init my_init(void) {
  printk("Hello, I'm second\n");
  first_func();
  return 0;
}
void __exit my_exit(void) {
  printk("Goodbye, I'm second\n");
}

module_init(my_init);
module_exit(my_exit);
```

* If the symbol you are trying to export is PER_CPU type, you need to use the below instead

```
EXPORT_PER_CPU_SYMBOL(var)
EXPORT_PER_CPU_SYMBOL_GPL(var)
```

#### How to load a module from a module ####

- You can load a module manually from kernel code

```
extern int __request_module(bool wait, const char *name, ...) \
  __attribute__((format(printf, 2, 3)));
#define request_module(mod...) __request_module(true, mod)
```

- It can use module name or alias as well

```
static int misc_open(struct inode * inode, struct file * file)
{ 
  int minor = iminor(inode);
  struct miscdevice *c;
  int err = -ENODEV;
  const struct file_operations *old_fops, *new_fops = NULL;
  
  lock_kernel();
  mutex_lock(&misc_mtx);
  
  list_for_each_entry(c, &misc_list, list) {
    if (c->minor == minor) {
      new_fops = fops_get(c->fops);
      break;
    }
  }  
     
  if (!new_fops) {
    mutex_unlock(&misc_mtx);
    request_module("char-major-%d-%d", MISC_MAJOR, minor);
    mutex_lock(&misc_mtx);
...
```

## Check it in vmcore ##

* Where the module information is located

```
crash> mod | grep <module name>
example)
crash> mod | grep bnx2i
ffffffff88cb5f00  bnx2i                    86312  /cores/retrace/repos/kernel/x86_64/usr/lib/debug/lib/modules/2.6.18-348.el5/kernel/drivers/scsi/bnx2i/bnx2i.ko.debug 

crash> module.name,module_init,init,exit,args,module_core ffffffff88cb5f00
  name = "bnx2i\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
  module_init = 0x0
  init = 0xffffffff88412000 <init_sg>
  exit = 0xffffffff88caf380 <bnx2i_mod_exit>
  args = 0xffff81207c9605a0 ""
  module_core = 0xffffffff88ca9000 <bnx2i_find_hba_for_cnic>
```

---
[Back to topic list](https://sungju.github.io/kernel/internals/index)
