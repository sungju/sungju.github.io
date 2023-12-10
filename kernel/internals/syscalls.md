# System Calls #

- Understand some custom modules' system call hooking mechanism
- It can help us to understand the situation and how to troubleshoot it

#### How it's implemented ####

- System calls are the way invoke kernel functions from application side
- This is providing services to the application that can't be achieved with process priviledge
- Kernel keeps all the system calls in an array and the number of syscalls are kept in __NR_syscalls macro

```
#define __NR_syscalls 274
```

- Array is defined as sys_call_table, but the symbol is not exported to the outside of the file to prevent a possible viruses or hacking

```
extern const unsigned long sys_call_table[];
```

- It's used in the system call handler which is called via 'int 0x80' (arch/x86/kernel/entry_64.S)

```
/* 
 * Register setup:
 * rax  system call number
 * rdi  arg0
 * rcx  return address for syscall/sysret, C arg3
 * rsi  arg1
 * rdx  arg2  
 * r10  arg3  (--> moved to rcx for C)
 * r8   arg4
 * r9   arg5
 * r11  eflags for syscall/sysret, temporary for C
 * r12-r15,rbp,rbx saved by C code, not touched.
 * 
 * Interrupts are off on entry.
 * Only called from user space.
 * 
 * XXX  if we had a free scratch register we could save the RSP into the stack frame    
 *      and report it properly in ps. Unfortunately we haven't.
 * 
 * When user can change the frames always force IRET. That is because
 * it deals with uncanonical addresses better. SYSRET has trouble
 * with them due to bugs in both AMD and Intel CPUs.
 */

ENTRY(system_call)
  CFI_STARTPROC simple
  CFI_SIGNAL_FRAME
...

  ja badsys
  movq %r10,%rcx
  call *sys_call_table(,%rax,8)  # XXX:  rip relative
```

- Each function needs to be defined with the help of macro SYSCALL_DEFINEx()

```
SYSCALL_DEFINE1(exit, int, error_code)
{
  do_exit((error_code&0xff)<<8);
}
```

- The kernel/internals/index for an entry in the array is defined as '__NR_functioname'

```
/* kernel/exit.c */
#define __NR_exit 93
__SYSCALL(__NR_exit, sys_exit)
```

#### Example ####

- open() system call hooking example

```
/* mysyscall.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/unistd.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/syscalls.h> 

unsigned long syscall_addr;
module_param(syscall_addr, ulong, 0);

typedef long syscall_handler_t(void);
syscall_handler_t **sys_call_table;

asmlinkage long (*orig_open)(const char __user *filename, int flags, umode_t mode);

//SYSCALL_DEFINE3(myopen, const char __user *, filename, int, flags, umode_t, mode)
asmlinkage long myopen(const char __user *filename, int flags, umode_t mode)
{
  char tmpname[256];
  int length;

  length = 256 - copy_from_user(tmpname, filename, 255);
  printk("opening %s by %s\n", tmpname, current->comm);
  if (!orig_open)
    return -1;

  return orig_open(filename, flags, mode);
}

int __init my_init(void)
{
  int i;
  sys_call_table = (void *)syscall_addr;

  for (i = 0; i < 20; i++) {
    printk("syscall[%i] = %p\n", i, sys_call_table[i]);
  }
  printk("open is at %d = %p\n", __NR_open, sys_call_table[__NR_open]);
  orig_open = (void *)sys_call_table[__NR_open];
  sys_call_table[__NR_open] = (syscall_handler_t *)myopen;
  
  return 0;
}

void __exit my_exit(void)
{
  sys_call_table[__NR_open] = (syscall_handler_t *)orig_open;
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Kwon");
MODULE_DESCRIPTION("System call hooking example");
```

- Shell script to run the code (mysyscall.sh)

```
#!/bin/bash

sys_call_table_addr_hex=$(grep ' sys_call_table' /boot/System.map-$(uname -r) | awk '{ print "0x" $1}')
sys_call_table_addr_dec=$(printf "%u\n" $sys_call_table_addr_hex)

insmod ./mysyscall.ko syscall_addr=$sys_call_table_addr_dec
```

- Running example

```
$ make
$ sh mysyscall.sh
$ ls
$ rmmod mysyscall
$ tail /var/log/messages -n 40
```

---
[Back to topic list](https://sungju.github.io/kernel/internals/index)
