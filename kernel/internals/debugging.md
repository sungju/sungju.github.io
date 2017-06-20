# Debugging mechanism #

### kprobes ###

- KProbes is a debugging mechanism for the Linux kernel which can also be used for monitoring events inside a production system.
- Good article at [https://lwn.net/Articles/132196/](https://lwn.net/Articles/132196/) - An introduction to KProbes
- You can monitor a specific function or operation in a function with kprobe

- Before registering kprobe handler, you need to fill 'struct kprobe' with the functions wanted to be called

```
struct kprobe {
  struct hlist_node hlist;

  /* list of kprobes for multi-handler support */
  struct list_head list;

  /*count the number of times this probe was temporarily disarmed */
  unsigned long nmissed;

  /* location of the probe point */
  kprobe_opcode_t *addr;

  /* Allow user to indicate symbol name of the probe point */
  const char *symbol_name;

  /* Offset into the symbol */
  unsigned int offset;

  /* Called before addr is executed. */
  kprobe_pre_handler_t pre_handler;

  /* Called after addr is executed, unless... */
  kprobe_post_handler_t post_handler;

  /*
   * ... called if executing addr causes a fault (eg. page fault).
   * Return 1 if it handled fault, otherwise kernel will see it.
   */
  kprobe_fault_handler_t fault_handler;

  /*
   * ... called if breakpoint trap occurs in probe handler.
   * Return 1 if it handled break, otherwise kernel will see it.
   */
  kprobe_break_handler_t break_handler;

  /* Saved opcode (which has been replaced with breakpoint) */
  kprobe_opcode_t opcode;

  /* copy of the original instruction */
  struct arch_specific_insn ainsn;

  /*
   * Indicates various status flags.
   * Protected by kprobe_mutex after this kprobe is registered.
   */
  u32 flags;
};
```

- There are four handler functions based on when you want it to be called
	- pre_handler : before call the target function
	- post_handler : after call the target function
	- fault_handler : if the target function is causing of fault such as page fault
	- break_handler : if the target has breakpoint and trap occured

- Target function can be addressed with one of the below two method
	- kprobe_opcode_t *addr : Use the address of the target function
	- const char *symbol_name : Using the symbol name. Only works if the function is exported

- Registering/Unregistering can be done with the below functions

```
int register_kprobe(struct kprobe *p);
void unregister_kprobe(struct kprobe *p);
```

- Example
	- Call handlers before and after a specific function

```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/version.h>

static unsigned long address = 0x0;
static char *name = 0;
module_param(address, ulong, S_IRUGO);
module_param(name, charp, S_IRUGO);

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
  printk("pre_handler called before p->addr=0x%p\n", p->addr);
  dump_stack();
  return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,
       unsigned long flags)
{
  printk("post_handler called after p->addr=0x%p\n", p->addr);
  dump_stack();
}

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
  printk("fault_handler called during calling p->addr=0x%p\n", p->addr);
  dump_stack();
  return 0;
}

static int __init my_init(void)
{
  if (address == 0 && (name == 0 || strlen(name) == 0)) {
    printk
        ("Target function is not specified. Please use address or name to monitoring it\n");
    return -1;
  }
  kp.pre_handler = handler_pre;
  kp.post_handler = handler_post;
  kp.fault_handler = handler_fault;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
  if (name != NULL)
    address = kallsyms_lookup_name(name);
#endif

  if (!address) {
    printk("Can't find the target address for %s\n", name);
    return -1;
  }

  kp.addr = (kprobe_opcode_t *) address;

  if (register_kprobe(&kp)) {
    printk("Can't register kprobe on %s\n", name);
    return -1;
  }
  printk("Hello, kprobe is registered\n");

  return 0;
}

static void __exit my_exit(void)
{
  unregister_kprobe(&kp);
  printk("Bye bye\n");
}
  
module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
```

- Running

```
$ make
$ insmod kprobe_test.ko name="do_fork"
$ ls
kprobe_test.c   kprobe_test.mod.c  kprobe_test.o  modules.order
kprobe_test.ko  kprobe_test.mod.o  Makefile       Module.symvers

$ tail /var/log/messages
Jun  5 15:52:33 devel kernel: 0000000000000282 00000000392dcf20 ffff8801cfe17df0 ffffffff81686e13
Jun  5 15:52:33 devel kernel: ffff8801cfe17e00 ffffffffa0797080 ffff8801cfe17e40 ffffffff81692368
Jun  5 15:52:33 devel kernel: ffffffff81084de5 ffffffff81ae79e0 0000000000008000 ffffffff81084de0
Jun  5 15:52:33 devel kernel: Call Trace:
Jun  5 15:52:33 devel kernel: [<ffffffff81686e13>] dump_stack+0x19/0x1b
Jun  5 15:52:33 devel kernel: [<ffffffffa0797080>] handler_pre+0x20/0x24 [kprobe_test]
Jun  5 15:52:33 devel kernel: [<ffffffff81692368>] kprobe_ftrace_handler+0xb8/0x120
Jun  5 15:52:33 devel kernel: [<ffffffff81084de5>] ? do_fork+0x5/0x2c0
Jun  5 15:52:33 devel kernel: [<ffffffff81084de0>] ? fork_idle+0xd0/0xd0

$ rmmod kprobe_test
```

- Checking out if kprobe was installed in a specific function from vmcore
	- If it has 'callq ftrace_regs_caller', it has kprobe on this function

```
crash> dis -lr do_fork+0x5
/usr/src/debug/kernel-3.10.0-514.21.1.el7/linux-3.10.0-514.21.1.el7.x86_64/kernel/fork.c: 1690
0xffffffff81084de0 <do_fork>:	callq  0xffffffff81699230 <ftrace_regs_caller>
0xffffffff81084de5 <do_fork+5>:	push   %rbp
```

- If kprobe_ftrace_handler is in one of ftrace_ops structures, it has kprobe installed on the system

```
crash> ftrace_ops_list
ftrace_ops_list = $5 = (struct ftrace_ops *) 0xffffffff81ae79e0 <kprobe_ftrace_ops>
crash> list -o ftrace_ops.next -s ftrace_ops.func 0xffffffff81ae79e0
ffffffff81ae79e0
  func = 0xffffffff816922b0 <kprobe_ftrace_handler>
ffffffff81ae8380
  func = 0xffffffff81699220 <ftrace_stub>
```

- kprobe structures are saved in 'kprobe_table[]'

```
crash> kprobe_table
kprobe_table = $6 = 
 { {
    first = 0x0
  }, {
    first = 0x0
  }, {
    first = 0x0
  }, {
...
    first = 0x0
  }, {
    first = 0xffffffffa0799240
  }, {
    first = 0x0
...

crash> kprobe 0xffffffffa0799240
struct kprobe {
  hlist = {
    next = 0x0, 
    pprev = 0xffffffff81e6ff30 <kprobe_table+144>
  }, 
  list = {
    next = 0xffffffffa0799250, 
    prev = 0xffffffffa0799250
  }, 
  nmissed = 0, 
  addr = 0xffffffff81084de0 <do_fork> "\350KDa", 
  symbol_name = 0x0, 
  offset = 0, 
  pre_handler = 0xffffffffa0797060, 
  post_handler = 0xffffffffa0797030, 
  fault_handler = 0xffffffffa0797000, 
  break_handler = 0x0, 
  opcode = 0 '\000', 
  ainsn = {
    insn = 0x0, 
    boostable = -1, 
    if_modifier = false
  }, 
  flags = 8
}
```

### jprobes ###

- jprobes is using similar techniques as kprobes, but instead of specifying multiples function for pre, post, fault, and trap events, it's providing a way to wrap the original function
- Registering/Unregistering happen via the below functions with 'struct jprobe'

```
int __kprobes register_jprobe(struct jprobe *jp);
void __kprobes unregister_jprobe(struct jprobe *jp);
```

- 'struct jprobe' is based on kprobe and has one more entry which is pointing a new function (wrapper)

```
struct jprobe {
  struct kprobe kp;
  void *entry;  /* probe handling code to jump to */
};
```

- Example

```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

static long my_fork(unsigned long clone_flags, unsigned long stack_start,
                    struct pt_regs *regs, unsigned long stack_size,
                    int __user *parent_tidptr, int __user *child_tidptr)
{
  printk("jprobe my_fork: clone_flags = 0x%lx, stack_size = 0x%lx\n",
      clone_flags, stack_size);

  jprobe_return();

  printk("After actual do_fork()? No, not going to be called\n");
  return 0;
}

static struct jprobe my_jprobe = {
  .entry = my_fork,
  .kp = {
    .symbol_name = "do_fork",
  },
};

static int __init my_init(void)
{
  int ret;

  ret = register_jprobe(&my_jprobe);
  if (ret < 0) {
    printk("register_jprobe failed with %d\n", ret);
    return -1;
  }

  printk("register_jprobe installed\n");
  return 0;
}

static void __exit my_exit(void)
{
  unregister_jprobe(&my_jprobe);
  printk("jprobe unregistered\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
```

- Running

```
$ insmod jprobe_test.ko
$ rmmod jprobe_test
root@devel:kprobes$ tail /var/log/messages
...
Jun  6 11:17:45 devel kernel: register_jprobe installed
Jun  6 11:17:50 devel kernel: jprobe my_fork: clone_flags = 0x1200011, stack_size = 0x0
Jun  6 11:17:50 devel kernel: jprobe my_fork: clone_flags = 0x1200011, stack_size = 0x0
Jun  6 11:17:50 devel kernel: jprobe my_fork: clone_flags = 0x1200011, stack_size = 0x0
Jun  6 11:18:04 devel systemd: Time has been changed
Jun  6 11:18:23 devel kernel: jprobe my_fork: clone_flags = 0x1200011, stack_size = 0x0
Jun  6 11:18:23 devel kernel: jprobe my_fork: clone_flags = 0x1200011, stack_size = 0x0
Jun  6 11:18:24 devel kernel: jprobe my_fork: clone_flags = 0x1200011, stack_size = 0x0
Jun  6 11:18:24 devel kernel: jprobe unregistered
```

- Checking jprobes
	- It is using the same method just like kprobe

```
crash> dis -l do_fork | head -n 3
/usr/src/debug/kernel-3.10.0-514.21.1.el7/linux-3.10.0-514.21.1.el7.x86_64/kernel/fork.c: 1690
0xffffffff81084de0 <do_fork>:   callq  0xffffffff81699230 <ftrace_regs_caller>
0xffffffff81084de5 <do_fork+5>: push   %rbp

crash> kprobe_table
kprobe_table = $1 = 
 { {
 ...
    first = 0x0
  }, {
    first = 0xffffffffa0794000
  }, {
    first = 0x0
...

crash> sym 0xffffffffa0794000
ffffffffa0794000 (d) my_jprobe [jprobe_test] 
crash> jprobe ffffffffa0794000
struct jprobe {
  kp = {
    hlist = {
      next = 0x0, 
      pprev = 0xffffffff81e6ff30 <kprobe_table+144>
    }, 
    list = {
      next = 0xffffffffa0794010, 
      prev = 0xffffffffa0794010
    }, 
    nmissed = 0, 
    addr = 0xffffffff81084de0 <do_fork> "\350KDa", 
    symbol_name = 0xffffffffa07930f0 "do_fork", 
    offset = 0, 
    pre_handler = 0xffffffff816918e0 <setjmp_pre_handler>, 
    post_handler = 0x0, 
    fault_handler = 0x0, 
    break_handler = 0xffffffff81691980 <longjmp_break_handler>, 
    opcode = 0 '\000', 
    ainsn = {
      insn = 0x0, 
      boostable = -1, 
      if_modifier = false
    }, 
    flags = 8
  }, 
  entry = 0xffffffffa0792000
}
crash> sym 0xffffffffa0792000
ffffffffa0792000 (t) my_fork [jprobe_test] 
```

### SystemTap ###

- SystemTap ( stap ) is a scripting language and tool for dynamically instrumenting running production Linux kernel-based operating systems. System administrators can use SystemTap to extract, filter and summarize data in order to enable diagnosis of complex performance or functional problems - [https://en.wikipedia.org/wiki/SystemTap](https://en.wikipedia.org/wiki/SystemTap)

- To use SystemTap, you need to install SystemTap as well as kernel-debuginfo, kernel-devl to compile and run it

- Installing the environment

```
$ yum install -y systemtap systemtap-runtime
$ subscription-manager repos --enable=rhel-7-variant-debug-rpms
$ yum install -y kernel-devel-$(uname -r)  kernel-debuginfo-$(uname -r)  kernel-debuginfo-common-$(uname -m)-$(uname -r)
```

- Testing
	- SystemTap script can be passed via command line argument or via a file

```
$ stap -v -e 'probe vfs.read {printf("read performed\n"); exit()}'  
Pass 1: parsed user script and 122 library scripts using 227708virt/40776res/3264shr/37692data kb, in 280usr/10sys/300real ms.
Pass 2: analyzed script: 1 probe, 1 function, 4 embeds, 0 globals using 359100virt/173276res/4464shr/169084data kb, in 1330usr/180sys/1506real ms.
Pass 3: using cached /root/.systemtap/cache/e3/stap_e32b328321382df05d3041933d344e8c_1682.c
Pass 4: using cached /root/.systemtap/cache/e3/stap_e32b328321382df05d3041933d344e8c_1682.ko
Pass 5: starting run.
read performed
Pass 5: run completed in 10usr/60sys/387real ms.
```

- Internal implementation

```
$ stap -v -e 'probe vfs.read {printf("read performed\n"); exit()}' -p3
Pass 1: parsed user script and 122 library scripts using 227576virt/40768res/3264shr/37560data kb, in 290usr/10sys/285real ms.
Pass 2: analyzed script: 1 probe, 1 function, 4 embeds, 0 globals using 359088virt/173260res/4464shr/169072data kb, in 1340usr/190sys/1439real ms.

...
static int systemtap_module_init (void) {
 ...
}

static void systemtap_module_refresh (const char *modname) {
  ...
}


static void systemtap_module_exit (void) {
  ...
}
...
static int
stapkp_register_probe(struct stap_kprobe_probe *skp)
{
   if (skp->registered_p)
      return 0;

   return skp->return_p ? stapkp_register_kretprobe(skp)
                        : stapkp_register_kprobe(skp);
}

static int
stapkp_register_kprobe(struct stap_kprobe_probe *skp)
{
   int ret = stapkp_prepare_kprobe(skp);
   if (ret == 0)
      ret = stapkp_arch_register_kprobe(skp);
   return ret;
}

static int
stapkp_arch_register_kprobe(struct stap_kprobe_probe *skp)
{
   int ret = 0;
   struct kprobe *kp = &skp->kprobe->u.kp;
...
   ret = register_kprobe(&skp->kprobe->dummy);
...
   return ret;
}
```

- Tracing it in crash

```
crash> sym sys_futex
ffffffff810f8540 (T) sys_futex /usr/src/debug/kernel-3.10.0-514.16.1.el7/linux-3.10.0-514.16.1.el7.x86_64/kernel/futex.c: 2978

crash> dis -l ffffffff810f8540 | head -n 2
/usr/src/debug/kernel-3.10.0-514.16.1.el7/linux-3.10.0-514.16.1.el7.x86_64/kernel/futex.c: 2978
0xffffffff810f8540 <sys_futex>: callq  0xffffffff81698df0 <ftrace_regs_caller>


ENTRY(ftrace_regs_caller)
  /* Save the current flags before compare (in SS location)*/
  pushfq
  ...
callq  0xffffffff81141330 <ftrace_ops_list_func>
...
  jmp ftrace_return

  popfq
  jmp  ftrace_stub
  
  


static void ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
         struct ftrace_ops *op, struct pt_regs *regs)
{
  __ftrace_ops_list_func(ip, parent_ip, NULL, regs);
}

static inline void
__ftrace_ops_list_func(unsigned long ip, unsigned long parent_ip,
           struct ftrace_ops *ignored, struct pt_regs *regs)
{
...
  do_for_each_ftrace_op(op, ftrace_ops_list) {
    if (ftrace_ops_test(op, ip, regs))
      op->func(ip, parent_ip, op, regs);
  } while_for_each_ftrace_op(op);
...
}


crash> ftrace_ops_list
ftrace_ops_list = $2 = (struct ftrace_ops *) 0xffffffff81ae38a0 <kprobe_ftrace_ops>
crash> struct ftrace_ops.func,next 0xffffffff81ae38a0
  func = 0xffffffff81691e70 <kprobe_ftrace_handler>
  next = 0xffffffff81ae4240 <ftrace_list_end>

crash> kprobe_table
kprobe_table = $3 = 
...
  }, {
    first = 0xffffffffa07b5f40
  }, {
...

crash> kprobe.addr,pre_handler,post_handler 0xffffffffa07b5f40
  addr = 0xffffffff810f8540 <SyS_futex> "\350\253\bZ"
  pre_handler = 0xffffffff81692eb0 <pre_handler_kretprobe>
  post_handler = 0x0
  
crash> kretprobe.free_instances 0xffffffffa07b5f40
  free_instances = {
    first = 0xffff8801d8f91b80
  }
  
crash> kretprobe.entry_handler,handler,free_instances 0xffffffffa07b5f40
  entry_handler = 0xffffffffa07af170
  handler = 0xffffffffa07af190
  free_instances = {
    first = 0xffff8801d8f91c40
  }   

crash> dis -l 0xffffffffa07af170 7
dis: WARNING: ffffffffa07af170: no associated kernel symbol found
   0xffffffffa07af170:  nopl   0x0(%rax,%rax,1)
   0xffffffffa07af175:  push   %rbp
   0xffffffffa07af176:  mov    $0x1,%edx
   0xffffffffa07af17b:  mov    %rsp,%rbp
   0xffffffffa07af17e:  callq  0xffffffffa07aee50
   0xffffffffa07af183:  pop    %rbp
   0xffffffffa07af184:  retq  
   
   
crash> dis -l 0xffffffffa07af190 7
WARNING: ffffffffa07af190: no associated kernel symbol found
   0xffffffffa07af190:  nopl   0x0(%rax,%rax,1)
   0xffffffffa07af195:  push   %rbp
   0xffffffffa07af196:  xor    %edx,%edx
   0xffffffffa07af198:  mov    %rsp,%rbp
   0xffffffffa07af19b:  callq  0xffffffffa07aee50
   0xffffffffa07af1a0:  pop    %rbp
   0xffffffffa07af1a1:  retq   
   
   
crash> dis -l 0xffffffffa07aee50 15
WARNING: ffffffffa07aee50: no associated kernel symbol found
   0xffffffffa07aee50:  nopl   0x0(%rax,%rax,1)
   0xffffffffa07aee55:  push   %rbp
   0xffffffffa07aee56:  mov    %rsp,%rbp
   0xffffffffa07aee59:  push   %r15
   0xffffffffa07aee5b:  push   %r14
   0xffffffffa07aee5d:  push   %r13
   0xffffffffa07aee5f:  push   %r12
   0xffffffffa07aee61:  mov    %edx,%r12d
   0xffffffffa07aee64:  push   %rbx
   0xffffffffa07aee65:  sub    $0x20,%rsp
   0xffffffffa07aee69:  mov    0x6740(%rip),%rbx        # 0xffffffffa07b55b0
   0xffffffffa07aee70:  mov    %gs:0x28,%rax
   0xffffffffa07aee79:  mov    %rax,-0x30(%rbp)
   0xffffffffa07aee7d:  xor    %eax,%eax
   0xffffffffa07aee7f:  test   %edx,%edx
```

### Ftrace ###

- A tracing utility built directly into the Linux Kernel
	- It provides the ability to see what is happening inside the kernel
	- [Debugging the kernel using Ftrace - part 1](https://lwn.net/Articles/365835/)
	- [Debugging the kernel using Ftrace - part 2](https://lwn.net/Articles/366796/)

#### Setting up Ftrace ####

- Ftrace is located in debugfs file system

```
$ cd /sys/kernel/debug/tracing
$ ls
available_events            max_graph_depth      stack_trace
available_filter_functions  options/             stack_trace_filter
available_tracers           per_cpu/             trace
buffer_size_kb              printk_formats       trace_clock
buffer_total_size_kb        README               trace_marker
current_tracer              saved_cmdlines       trace_options
dyn_ftrace_total_info       saved_cmdlines_size  trace_pipe
enabled_functions           set_event            trace_stat/
events/                     set_ftrace_filter    tracing_cpumask
free_buffer                 set_ftrace_notrace   tracing_max_latency
function_profile_enabled    set_ftrace_pid       tracing_on
instances/                  set_graph_function   tracing_thresh
kprobe_events               snapshot             uprobe_events
kprobe_profile              stack_max_size       uprobe_profile
```

- To use ftrace, the below should be enabled which are enabled in RHEL

```
$ grep CONFIG_DYNAMIC_FTRACE= config-3.10.0-514.21.1.el7.x86_64
CONFIG_DYNAMIC_FTRACE=y

$ grep TRACER=y config-3.10.0-514.21.1.el7.x86_64
CONFIG_NOP_TRACER=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_GENERIC_TRACER=y
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_SCHED_TRACER=y
CONFIG_STACK_TRACER=y
```

- When CONFIG_DYNAMIC_FTRACE is configured the call is converted to a NOP at boot time to keep the system running at 100% performance
- When tracer is not working

```
crash> dis -l do_fork | head -n 3
/usr/src/debug/kernel-3.10.0-514.16.1.el7/linux-3.10.0-514.16.1.el7.x86_64/kernel/fork.c: 1690
0xffffffff81084de0 <do_fork>:   nopl   0x0(%rax,%rax,1) [FTRACE NOP]
0xffffffff81084de5 <do_fork+5>: push   %rbp
```

- When tracer is ON

```
/usr/src/debug/kernel-3.10.0-514.16.1.el7/linux-3.10.0-514.16.1.el7.x86_64/kernel/fork.c: 1690
0xffffffff81084de0 <do_fork>:   callq  0xffffffff81698d50 <ftrace_caller>
0xffffffff81084de5 <do_fork+5>: push   %rbp
```

- Check available tracers

```
$ cat available_tracers 
blk function_graph wakeup_dl wakeup_rt wakeup function nop
```

- Checking available tracers from vmcore

```
crash> trace_types
trace_types = $4 = (struct tracer *) 0xffffffff81ae4b00 <blk_tracer>
crash> list 0xffffffff81ae4b00 -o tracer.next -s tracer.name,init
ffffffff81ae4b00
  name = 0xffffffff818da5c3 "blk"
  init = 0xffffffff81159800 <blk_tracer_init>
ffffffff81ae4a60
  name = 0xffffffff818da38a "function_graph"
  init = 0xffffffff81157c30 <graph_trace_init>
ffffffff81ae4720
  name = 0xffffffff818da1e3 "wakeup_dl"
  init = 0xffffffff81156e90 <wakeup_dl_tracer_init>
ffffffff81ae47c0
  name = 0xffffffff818da1ed "wakeup_rt"
  init = 0xffffffff81156eb0 <wakeup_rt_tracer_init>
ffffffff81ae4860
  name = 0xffffffff81937866 "wakeup"
  init = 0xffffffff81156ed0 <wakeup_tracer_init>
ffffffff81ae45c0
  name = 0xffffffff818d99b4 "function"
  init = 0xffffffff81155ff0 <function_trace_init>
ffffffff81ae4960
  name = 0xffffffff818f3ad6 "nop"
  init = 0xffffffff81157130 <nop_trace_init>
```

##### Function tracer #####

- every function in the kernel call a special function "mcount()"

```
$ echo function > /sys/kernel/debug/tracing/current_tracer
$ cat /sys/kernel/debug/tracing/current_tracer
function
```

- Checking the function calls
	- The first two items are the traced task name and PID
	- The CPU that the trace was executed on is within the brackets
	- The timestamp is the time since boot, followed by the function name
	- The function in this case is the function being traced with its parent following the "<-" symbol.

```
$ cat /sys/kernel/debug/tracing/trace | head -n 20
# tracer: function
#
# entries-in-buffer/entries-written: 102499/11907819   #P:2
#
#                              _-----=> irqs-off
#                             / _----=> need-resched
#                            | / _---=> hardirq/softirq
#                            || / _--=> preempt-depth
#                            ||| /     delay
#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
#              | |       |   ||||       |         |
      irqbalance-810   [001] .... 89262.130446: irq_to_desc <-show_interrupts
      irqbalance-810   [001] .... 89262.130447: _raw_spin_lock_irqsave <-show_interrupts
      irqbalance-810   [001] d... 89262.130447: kstat_irqs_cpu <-show_interrupts
      irqbalance-810   [001] d... 89262.130447: kstat_irqs_cpu <-show_interrupts
      irqbalance-810   [001] d... 89262.130447: seq_printf <-show_interrupts
      irqbalance-810   [001] d... 89262.130447: seq_vprintf <-seq_printf
      irqbalance-810   [001] d... 89262.130448: kstat_irqs_cpu <-show_interrupts
      irqbalance-810   [001] d... 89262.130448: seq_printf <-show_interrupts
      irqbalance-810   [001] d... 89262.130448: seq_vprintf <-seq_printf
```

##### function_graph tracer #####

- A bit hard to understand 'function' output
	- function_graph traces both the entry and exit of a function, which gives the tracer the ability to know the depth of functions that are called
	- This gives the start and end of a function denoted with the C like annotation of "{" to start a function and "}" at the end
	- Leaf functions, which do not call other functions, simply end with a ";"
	- The DURATION column shows the time spent in the corresponding function
- The function graph tracer records the time the function was entered and exited and reports the difference as the duration. These numbers only appear with the leaf functions and the "}" symbol. Note that this time also includes the overhead of all functions within a nested function as well as the overhead of the function graph tracer itself. 

```
$ echo function_graph > /sys/kernel/debug/tracing/current_tracer
root@devel:boot$ cat /sys/kernel/debug/tracing/trace | head -n 20
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
   0)   0.087 us    |            } /* page_remove_rmap */
   0)   0.042 us    |            put_page();
   0)   0.073 us    |            _raw_spin_unlock();
   0)   0.045 us    |            put_page();
   0) + 17.010 us   |          } /* wp_page_copy.isra.56 */
   0) + 20.751 us   |        } /* do_wp_page */
   0) + 22.275 us   |      } /* handle_mm_fault */
   0)   0.042 us    |      up_read();
   0) + 24.347 us   |    } /* __do_page_fault */
   0) + 24.754 us   |  } /* do_page_fault */
   0)               |  do_page_fault() {
   0)               |    __do_page_fault() {
   0)   0.043 us    |      down_read_trylock();
   0)   0.042 us    |      _cond_resched();
   0)   0.068 us    |      find_vma();
   0)               |      handle_mm_fault() {
```

- When a function spent more than 10 microseconds, it prints '+' in front of the time

```
$ cat /sys/kernel/debug/tracing/trace | grep '+' | head
   0) + 10.394 us   |          }
   0) + 12.787 us   |        } /* do_wp_page */
   0) + 13.661 us   |      } /* handle_mm_fault */
   0) + 14.992 us   |    } /* __do_page_fault */
   0) + 15.220 us   |  } /* do_page_fault */
   0) + 10.413 us   |          }
   0) + 12.719 us   |        }
   0) + 13.565 us   |      }
   0) + 14.815 us   |    }
   0) + 15.083 us   |  }
```

- When a function spent more than 100 microseconds, it prints '!' in front of the time

```
$ cat /sys/kernel/debug/tracing/trace | grep '!' | head
   1) ! 106.320 us  |                    } /* free_pages_and_swap_cache */
   1) ! 141.339 us  |                  } /* tlb_flush_mmu.part.61 */
   1) ! 145.374 us  |                } /* tlb_finish_mmu */
   1) ! 1087.709 us |              } /* exit_mmap */
   1) ! 1094.262 us |            } /* mmput */
   1) ! 1106.230 us |          } /* flush_old_exec */
   1) ! 140.495 us  |          }
   1) ! 1527.120 us |        } /* load_elf_binary */
   1) ! 1533.974 us |      } /* search_binary_handler */
   1) ! 1832.817 us |    } /* do_execve_common.isra.25 */
```

##### On/Off Tracing #####

- Turning off tracing

```
$ echo 0 > /sys/kernel/debug/tracing/tracing_on
$ cat /sys/kernel/debug/tracing/trace | head -n 10
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
   1)   0.509 us    |            } /* tty_write_room */
   1)   5.245 us    |          } /* n_tty_poll */
   1)               |          tty_ldisc_deref() {
   1)   0.045 us    |            ldsem_up_read();
   1)   0.481 us    |          }
   1)   8.481 us    |        } /* tty_poll */
$ sleep 5
$ cat /sys/kernel/debug/tracing/trace | head -n 10
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
   1)   0.509 us    |            } /* tty_write_room */
   1)   5.245 us    |          } /* n_tty_poll */
   1)               |          tty_ldisc_deref() {
   1)   0.045 us    |            ldsem_up_read();
   1)   0.481 us    |          }
   1)   8.481 us    |        } /* tty_poll */
```

- Turning on tracing

```
$ echo 1 > /sys/kernel/debug/tracing/tracing_on
$ cat /sys/kernel/debug/tracing/trace | head -n 10
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
   1)   0.030 us    |          } /* _raw_spin_lock */
   1)               |          do_set_pte() {
   1)   0.031 us    |            add_mm_counter_fast();
   1)   0.033 us    |            page_add_file_rmap();
   1)   0.537 us    |          }
   1)   0.030 us    |          _raw_spin_unlock();
$ sleep 5
$ cat /sys/kernel/debug/tracing/trace | head -n 10
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
   1)   0.044 us    |          } /* mutex_unlock */
   1)               |          __vma_link_rb() {
   1)   0.045 us    |            vma_compute_subtree_gap();
   1)               |            vma_gap_callbacks_rotate() {
   1)   0.055 us    |              vma_compute_subtree_gap();
   1)   0.455 us    |            }
```


---
[Back to topic list](http://file.bne.redhat.com/~dkwon/sbr_kernel_training)
