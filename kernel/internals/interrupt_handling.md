# Interrupt Handling #

Reference : [Interrupts and Interrupt Handling](http://www.tldp.org/LDP/tlk/dd/interrupts.html)

### What's interrupt? ###

- An interrupt is a signal from a device attached to a computer or from a program within the computer that causes the main program that operates the computer (the operating system ) to stop and figure out what to do next.
- Interrupt is a mechanism by which an I/O or an instruction can suspend the normal execution of processor and get itself serviced.

- General flow of interrupt handling

![How interrupt happens](https://sungju.github.io/kernel/internals/how_interrupts.png)

### PIC (Programmable Interrupt Controller) ###

- [The Intel 8259 is a Programmable Interrupt Controller (PIC) designed for the Intel 8085 and Intel 8086 microprocessors](https://en.wikipedia.org/wiki/Intel_8259)
- It's named *Programmable* as it can change the IRQ (Interrupt ReQuest) number of the signaled pin.
- On x86 architecture, two 8259 chips (Master PIC and Slave PIC) are used to make 15 IRQs

![8259 PIC](https://sungju.github.io/kernel/internals/8259.png)

### How Linux kernel handles interrupt ###

- 8259 related code can be found at 'arch/x86_64/kernel/i8259.c'
- When there's an interrupt, CPU calls a function assigned to a specific location in interrupt vector table
- Kernel is responsible to set this vector before handling any interrupts
- During the boot, kernel registers all the interrupt handlers for the corresponding IRQ number

```
void __init init_IRQ(void)
{ 
  int i;
  
  init_ISA_irqs();
  /*
   * Cover the whole vector space, no vector can escape
   * us. (some of these will be overridden and become
   * 'special' SMP interrupts)
   */
  for (i = 0; i < (NR_VECTORS - FIRST_EXTERNAL_VECTOR); i++) {
    int vector = FIRST_EXTERNAL_VECTOR + i;
    if (i >= NR_IRQS)
      break;
    if (vector != IA32_SYSCALL_VECTOR)
      set_intr_gate(vector, interrupt[i]);
  }
  ...
}
```

- interrupt[] is containing IRQxx_interrupt functions addresses

```
#define IRQ(x,y) \
  IRQ##x##y##_interrupt

#define IRQLIST_16(x) \
  IRQ(x,0), IRQ(x,1), IRQ(x,2), IRQ(x,3), \
  IRQ(x,4), IRQ(x,5), IRQ(x,6), IRQ(x,7), \
  IRQ(x,8), IRQ(x,9), IRQ(x,a), IRQ(x,b), \
  IRQ(x,c), IRQ(x,d), IRQ(x,e), IRQ(x,f)

#define IRQLIST_15(x) \
  IRQ(x,0), IRQ(x,1), IRQ(x,2), IRQ(x,3), \
  IRQ(x,4), IRQ(x,5), IRQ(x,6), IRQ(x,7), \
  IRQ(x,8), IRQ(x,9), IRQ(x,a), IRQ(x,b), \
  IRQ(x,c), IRQ(x,d), IRQ(x,e)

void (*interrupt[NR_IRQS])(void) = {
  IRQLIST_16(0x0),

#ifdef CONFIG_X86_IO_APIC
       IRQLIST_16(0x1), IRQLIST_16(0x2), IRQLIST_16(0x3),
  IRQLIST_16(0x4), IRQLIST_16(0x5), IRQLIST_16(0x6), IRQLIST_16(0x7),
  IRQLIST_16(0x8), IRQLIST_16(0x9), IRQLIST_16(0xa), IRQLIST_16(0xb),
  IRQLIST_16(0xc), IRQLIST_16(0xd)

#ifdef CONFIG_PCI_MSI
  , IRQLIST_15(0xe)
#endif

#endif
};
```

- They are having their own name based on IRQ, but all jumping to the same function - 'common_interrupt'

```
crash> sym -l | grep IRQ
ffffffff80010d6f (T) handle_IRQ_event
ffffffff8005e2a4 (t) IRQ0x00_interrupt
ffffffff8005e2ab (t) IRQ0x01_interrupt
ffffffff8005e2b2 (t) IRQ0x02_interrupt
ffffffff8005e2b9 (t) IRQ0x03_interrupt
ffffffff8005e2c0 (t) IRQ0x04_interrupt
...

crash> dis -l ffffffff8005e2a4
0xffffffff8005e2a4 <IRQ0x00_interrupt>: pushq  $0xffffffffffffffff
0xffffffff8005e2a6 <IRQ0x00_interrupt+0x2>:     jmpq   0xffffffff8005d5c4 <common_interrupt>

ENTRY(common_interrupt)
  XCPT_FRAME
  interrupt do_IRQ
  /* 0(%rsp): oldrsp-ARGOFFSET */
ret_from_intr:
  cli 
  TRACE_IRQS_OFF
  decl %gs:pda_irqcount
  leaveq
  CFI_DEF_CFA_REGISTER  rsp
  CFI_ADJUST_CFA_OFFSET -8
exit_intr:
  GET_THREAD_INFO(%rcx)
  testl $3,CS-ARGOFFSET(%rsp)
  je retint_kernel
  
  
  /* 0(%rsp): interrupt number */
  .macro interrupt func
  cld
  SAVE_ARGS
  leaq -ARGOFFSET(%rsp),%rdi  # arg1 for handler
  pushq %rbp
  CFI_ADJUST_CFA_OFFSET 8
  CFI_REL_OFFSET    rbp, 0
  movq %rsp,%rbp    
  CFI_DEF_CFA_REGISTER  rbp
  testl $3,CS(%rdi)
  je 1f 
  swapgs
1:  incl  %gs:pda_irqcount  # RED-PEN should check preempt count
  cmoveq %gs:pda_irqstackptr,%rsp
  push    %rbp      # backlink for old unwinder
  CFI_ADJUST_CFA_OFFSET 8
  CFI_REL_OFFSET rbp,0
  /*
   * We entered an interrupt context - irqs are off:
   */
  TRACE_IRQS_OFF
  call \func
  .endm
```

- common_interrupt() is calling *do_IRQ()* internally which is handling the actual interrupt handling

![do_IRQ()](https://sungju.github.io/kernel/internals/do_IRQ.png)

- do_IRQ() handles registered IRQ handler list after changing to interrupt context

```
/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
unsigned int __irq_entry do_IRQ(struct pt_regs *regs)
{ 
...
  exit_idle();
  irq_enter();  <-- change to interrupt context
  
  irq = __get_cpu_var(vector_irq)[vector];
  
  if (!handle_irq(irq, regs)) {
    ack_APIC_irq();
    
    if (printk_ratelimit())
      pr_emerg("%s: %d.%d No irq handler for vector (irq %d)\n",
        __func__, smp_processor_id(), vector, irq);
  }

  irq_exit();
...
}
```


```
bool handle_irq(unsigned irq, struct pt_regs *regs)
{
  struct irq_desc *desc;
  
  stack_overflow_check(regs);
  
  desc = irq_to_desc(irq);
  if (unlikely(!desc))
    return false;
    
  generic_handle_irq_desc(irq, desc);
  return true;
}


/*
 * Architectures call this to let the generic IRQ layer
 * handle an interrupt. If the descriptor is attached to an
 * irqchip-style controller then we call the ->handle_irq() handler,
 * and it calls __do_IRQ() if it's attached to an irqtype-style controller.
 */
static inline void generic_handle_irq_desc(unsigned int irq, struct irq_desc *desc)
{
#ifdef CONFIG_GENERIC_HARDIRQS_NO__DO_IRQ
  desc->handle_irq(irq, desc);
#else
  if (likely(desc->handle_irq))
    desc->handle_irq(irq, desc);
  else
    __do_IRQ(irq);
#endif
}
```



```
/**
 * __do_IRQ - original all in one highlevel IRQ handler
 * @irq:  the interrupt number
 *
 * __do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 *
 * This is the original x86 implementation which is used for every
 * interrupt type.
 */
unsigned int __do_IRQ(unsigned int irq)
{ 
  struct irq_desc *desc = irq_to_desc(irq);
  struct irqaction *action;
  unsigned int status;

...

  spin_lock(&desc->lock);
  if (desc->chip->ack)
    desc->chip->ack(irq);

...  

  /*
   * Edge triggered interrupts need to remember
   * pending events.
   * This applies to any hw interrupts that allow a second
   * instance of the same irq to arrive while we are in do_IRQ
   * or in the handler. But the code here only handles the _second_
   * instance of the irq, not the third or fourth. So it is mostly
   * useful for irq hardware that does not mask cleanly in an
   * SMP environment.
   */
  for (;;) {
    irqreturn_t action_ret;
    
...

    action_ret = handle_IRQ_event(irq, action);

...

out:
  /*
   * The ->end() handler has to deal with interrupts which got
   * disabled while the handler was running.
   */
  desc->chip->end(irq);
 
...

   return 1;
}


irqreturn_t handle_IRQ_event(unsigned int irq, struct irqaction *action)
{
  irqreturn_t ret, retval = IRQ_NONE;
  unsigned int status = 0;

  if (!(action->flags & IRQF_DISABLED))
    local_irq_enable_in_hardirq();

  do {
   ...
    ret = action->handler(irq, action->dev_id);
    ...
    action = action->next;
  } while (action);
  
  if (status & IRQF_SAMPLE_RANDOM)
    add_interrupt_randomness(irq);
  local_irq_disable();

  return retval;
}

# define local_irq_enable_in_hardirq()  local_irq_enable()
#define local_irq_enable() \
  do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
static inline void raw_local_irq_enable(void)
{
  native_irq_enable();
}

static inline void native_irq_disable(void)
{
  asm volatile("cli": : :"memory");
}

static inline void native_irq_enable(void)
{ 
  asm volatile("sti": : :"memory");
} 
```

- How irq acks for a specific hardware interrupt?
  - In RHEL6 or higher

```
crash> sym irq_desc_ptrs
ffffffff81c0b570 (D) irq_desc_ptrs
crash> rd ffffffff81c0b570
ffffffff81c0b570:  ffff88107fe7c000                    ........
crash> rd ffff88107fe7c000 10
ffff88107fe7c000:  ffffffff81a83240 ffffffff81a83340   @2......@3......
ffff88107fe7c010:  ffffffff81a83440 ffffffff81a83540   @4......@5......
ffff88107fe7c020:  ffffffff81a83640 ffffffff81a83740   @6......@7......
ffff88107fe7c030:  ffffffff81a83840 ffffffff81a83940   @8......@9......
ffff88107fe7c040:  ffffffff81a83a40 ffffffff81a83b40   @:......@;......
crash> irq_desc.irq,handle_irq,chip,action ffffffff81a83240
  irq = 0
  handle_irq = 0xffffffff810ed310 <handle_edge_irq>
  chip = 0xffffffff81c088e0 <ir_ioapic_chip>
  action = 0xffffffff81a8f3a0 <irq0>
crash> irq_chip.ack 0xffffffff81c088e0
  ack = 0xffffffff81035530 <ir_ack_apic_edge>
  
crash> irq0
irq0 = $3 = {
  handler = 0xffffffff8006fbb2 <timer_interrupt>, 
  flags = 32, 
  mask = {
    bits = {0, 0, 0, 0}
  }, 
  name = 0xffffffff802cddd1 "timer", 
  dev_id = 0x0, 
  next = 0x0, 
  irq = 0, 
  dir = 0x0
}
```

  - In RHEL5

```
crash> struct irq_desc | grep SIZE
SIZE: 256
crash> sym irq_desc
ffffffff8044e380 (D) irq_desc
crash> px 0xffffffff8044e380+(218*256)
$11 = 0xffffffff8045bd80
crash> struct irq_desc.handle_irq,chip,action 0xffffffff8045bd80
  handle_irq = 0x0
  chip = 0xffffffff80343a20 <msix_irq_type>
  action = 0xffff81083d839f40
crash> irqaction 0xffff81083d839f40
struct irqaction {
  handler = 0xffffffff88257e59 <netxen_msix_intr>, 
  flags = 64, 
  mask = {
    bits = {0, 0, 0, 0}
  }, 
  name = 0xffff81083ff21b88 "eth1[3]", 
  dev_id = 0xffff81083ff21ab8, 
  next = 0x0, 
  irq = 218, 
  dir = 0xffff81083de9d480
}
```

- If irqaction.next has an address, it'll keep calling the chain until it sees 'next = 0x0'.


### Registering interrupt handler ###

- We don't touch the interrupt table directly. Instead, we are registering interrupt handlers in the irq_desc's action linked list
- It means we can register multiple interrupt handlers on one IRQ and they will all be called one by one

```
static inline int __must_check
request_irq(unsigned int irq, irq_handler_t handler, unsigned long flags,
      const char *name, void *dev);
      
void free_irq(unsigned int irq, void *dev_id);
```

- Meaning of each arguments in request_irq
  - *irq*: IRQ number to register the handler
  - *handler*: interrupt handler's address
  - *flags* : Describe the characteristics of the handler
    - *IRQF_DISABLED* - keep irqs disabled when calling the action handler
    - *IRQF_SAMPLE_RANDOM* - irq is used to feed the random generator
    - *IRQF_SHARED* - allow sharing the irq among several device
    - *IRQF_ONESHOT* - Interrupt is not reenabled after the hardirq handler finished. Used by threaded interrupts which need to keep the irq line disabled until the threaded handler has been run.
  - *name* : Interrupt handler name that you can find in /proc/interrupts
  - *dev* : additional data you can pass to the handler. Useful when you are using a handler for the multiple IRQs with different data set
- When you unregister the handler, you should specify two things that you were using when you register the handler

- Example

```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

static int my_dev_id[NR_IRQS];

irqreturn_t my_handler(int irq, void *data)
{
  return IRQ_HANDLED;
}

static int __init my_init(void) {
  int irq;
  int ret;
  for (irq = 0; irq < NR_IRQS; irq++) {
    ret = request_irq(irq, my_handler, IRQF_SHARED, "myirq", &(my_dev_id[irq]));
    if (ret < 0) {
      my_dev_id[irq] = -1;
    } else {
      my_dev_id[irq] = irq;
      printk("myirq is regstered on %d\n", irq);
    }
  }
  return 0;
}

static void __exit my_exit(void) {
  int irq;
  for (irq = 0; irq < NR_IRQS; irq++) {
    if (my_dev_id[irq] >= 0) {
      free_irq(irq, &(my_dev_id[irq]));
    }
  }
}
module_init(my_init);
module_exit(my_exit);
```

```
$ cat Makefile
obj-m += myinterrupt.o

export KROOT=/lib/modules/`uname -r`/build

allofit:   modules
modules:
  @$(MAKE) -C $(KROOT) M=$(PWD) modules
modules_install:
  @$(MAKE) -C $(KROOT) M=$(PWD) modules_install
clean:
  rm -rf   *.o *.ko .*cmd *.mod.c .tmp_versions .*.d .*.tmp Module.symvers
```

- Once the module is loaded, you will see that most of the IRQs have the interrupt handler - myirq - at the end of the line
- Some doesn't have it as the original interrupt handler was registered without IRQF_SHARED

```
$ insmod myinterrupt.ko
$ head -n 20 /proc/interrupts 
            CPU0       CPU1       
   0:         82          0   IO-APIC-edge      timer
   1:         77        496   IO-APIC-edge      i8042, myirq
   2:          0          0    XT-PIC-XT-PIC    myirq
   3:          0          0   IO-APIC-edge      myirq
   4:          0          0   IO-APIC-edge      myirq
   5:          0          0   IO-APIC-edge      myirq
   6:          0          0   IO-APIC-edge      myirq
   7:          0          0   IO-APIC-edge      myirq
   8:          1          0   IO-APIC-edge      rtc0
   9:          0          0   IO-APIC-fasteoi   acpi, myirq
  10:          0          0   IO-APIC-edge      myirq
  11:          0          0   IO-APIC-edge      myirq
  12:       2763          0   IO-APIC-edge      i8042, myirq
  13:          0          0   IO-APIC-edge      myirq
  14:          0          0   IO-APIC-edge      ata_piix, myirq
  15:          0          0   IO-APIC-edge      ata_piix, myirq
  16:       1575       1449   IO-APIC-fasteoi   vmwgfx, snd_ens1371, myirq
  17:      14898       3895   IO-APIC-fasteoi   ehci_hcd:usb1, ioc0, myirq
  18:        312          0   IO-APIC-fasteoi   uhci_hcd:usb2, myirq
```

- This module is failed to register on some IRQs. Below is the one example and it's because existing interrupt handler was registered without 'IRQF_SHARED' flag.

```
$ egrep -e '16:' -e '58:' /proc/interrupts 
  16:       7739      26593   IO-APIC-fasteoi   vmwgfx, snd_ens1371, myirq
  58:          0          0   PCI-MSI-edge      vmw_vmci


crash> irq 16
 IRQ   IRQ_DESC/_DATA      IRQACTION      NAME
 16   ffff88003503da00  ffff8801374f3380  "vmwgfx"
                        ffff880137b26700  "snd_ens1371"
                        ffff8800b33cdc80  "myirq"


crash> irqaction ffff8800b33cdc80
struct irqaction {
  handler = 0xffffffffa06bd000, 
  dev_id = 0xffffffffa06bf280, 
  percpu_dev_id = 0x0, 
  next = 0x0, 
  thread_fn = 0x0, 
  thread = 0x0, 
  irq = 16, 
  flags = 128, 
  thread_flags = 0, 
  thread_mask = 0, 
  name = 0xffffffffa06be024 "myirq", 
  dir = 0xffff8800b33cce00
}

crash> irqaction ffff8801374f3380
struct irqaction {
  handler = 0xffffffffa01d0de0, 
  dev_id = 0xffff8801324de800, 
  percpu_dev_id = 0x0, 
  next = 0xffff880137b26700, 
  thread_fn = 0x0, 
  thread = 0x0, 
  irq = 16, 
  flags = 128,       <--- IRQF_SHARED
  thread_flags = 0, 
  thread_mask = 0, 
  name = 0xffffffffa01e19a9 "vmwgfx", 
  dir = 0xffff8801374f2180
}


crash> irq 58
 IRQ   IRQ_DESC/_DATA      IRQACTION      NAME
 58   ffff8800ba9e8d00  ffff8800b9783e00  "vmw_vmci"
crash> irqaction ffff8800b9783e00
struct irqaction {
  handler = 0xffffffffa0412000, 
  dev_id = 0xffff880035f24198, 
  percpu_dev_id = 0x0, 
  next = 0x0, 
  thread_fn = 0x0, 
  thread = 0x0, 
  irq = 58, 
  flags = 0, 
  thread_flags = 0, 
  thread_mask = 0, 
  name = 0xffffffffa041a270 "vmw_vmci", 
  dir = 0xffff880035f252c0
}


#define IRQF_SHARED   0x00000080
crash> px 128
$1 = 0x80
```

### Interrupt enable/disable ###

- *local_irq_disable()* : Disable all local CPU IRQ. It's using 'cli' in x86
- *local_irq_enable()* : Enable all local CPU IRQ. It's using 'sti' in x86
- *local_irq_save(unsigned long flags)* : Saving local IRQ status and disable all local IRQs
- *local_irq_restore(unsigned long flags)* : Restoring IRQ status based on 'flags'
- *disable_irq(unsigned int irq)* : Disable a specific 'irq'
- *enable_irq(unsigned int irq)* : Enable a specific 'irq'
- *irqs_enabled()* : If the local irq is disabled, it returns 0, otherwise returns a value not 0.
- *in_interrupt()* : If it's not in interrupt context, returns 0, otherwise returns a value not 0.
- *in_irq()* : If it's in an interrupt handler, returns a value not 0, otherwise returns 0.

### Bottom Half? - Deferrable function ###

- Interrupt handler shouldn't take CPU for too long, otherwise it'll block other operations includes other interrupts
- To overcome this issue, Linux kernel uses a concept of top half and bottom half.
- It is basically split the interrupt handler into two parts
  - top half: The routine that needs to be handled right away. Execution number is important
  - bottom half: The routine that can be run later time. Execution number is not important, but still needs to be executed.
- Two types of bottom halves
  - SoftIRQ and Tasklet
  - Work queue

#### Tasklet ####

- Tasklets are a deferral scheme that you can schedule for a registered function to run later. The top half (the interrupt handler) performs a small amount of work, and then schedules the tasklet to execute later at the bottom half. [Kernel APIs, Part 2: Deferrable functions, kernel tasklets, and work queues](http://www.ibm.com/developerworks/library/l-tasklets/)
- Tasklet is managed internally by tasklet_struct
- This is used to set the function to be executed later

```
struct tasklet_struct
{
  struct tasklet_struct *next;
  unsigned long state;
  atomic_t count;
  void (*func)(unsigned long);
  unsigned long data;
};
```

- Related functions to set the function and register it into tasklet list

```
#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }

#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }

void tasklet_init(struct tasklet_struct *t,
       void (*func)(unsigned long), unsigned long data);
static inline void tasklet_schedule(struct tasklet_struct *t);
void tasklet_kill(struct tasklet_struct *t);
void tasklet_enable(struct tasklet_struct *t);
void tasklet_disable(struct tasklet_struct *t);
```

- Below is a simple example without interrupt context which is not useful in real world (This is just to show you how to set and register tasklet).

```
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>

MODULE_LICENSE("GPL");

static void tasklet_func(unsigned long data)
{
  printk("Tasklet called.\n");
}

DECLARE_TASKLET(tl_descr, tasklet_func, 0L);

static int __init drv_init(void)
{
  printk("drv_init called\n");
  tasklet_schedule(&tl_descr);
  return 0;
}

static void __exit drv_exit(void)
{
  printk("drv_exit called\n");
  tasklet_kill(&tl_descr);
}

module_init(drv_init);
module_exit(drv_exit);
```

- Let's see how tasklet works and what can be a difference between putting this in the interrupt handler and splitting it as a bottom half.
- Below module will be registered to a specified IRQ and will run tasklet later with a specified delay (default is 0).

```
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

int irq, my_dev_id, irq_counter = 0;
module_param(irq, int, 0);

int delay = 0;
module_param(delay, int, 0);

atomic_t counter_bh, counter_th;

struct my_dat {
  unsigned long jiffies;
};
struct my_dat my_data;

void t_func(unsigned long t_arg) {
  struct my_dat *data = (struct my_dat *)t_arg;
  atomic_inc(&counter_bh);
  printk("In BH: counter_th = %d, counter_bh = %d, jiffies = %ld,%ld\n",
      atomic_read(&counter_th), atomic_read(&counter_bh),
      data->jiffies, jiffies);
}

DECLARE_TASKLET(t_name, t_func, (unsigned long)&my_data);

irqreturn_t my_interrupt(int irq, void *dev_id) {
  struct my_dat *data = (struct my_dat *)dev_id;
  atomic_inc(&counter_th);
  data->jiffies = jiffies;
  tasklet_schedule(&t_name);
  mdelay(delay);
  return IRQ_NONE;
}

int __init my_init(void) {
  int ret;
  atomic_set(&counter_th, 0);
  atomic_set(&counter_bh, 0);
  ret = request_irq(irq, my_interrupt, IRQF_SHARED, "my_int", &my_data);
  printk("Successfully loaded\n");
  return 0;
}

void __exit my_exit(void) {
  free_irq(irq, &my_data);
  printk("counter_th = %d, counter_bh = %d\n",
      atomic_read(&counter_th), atomic_read(&counter_bh));
}

module_init(my_init);
module_exit(my_exit);
```

- Makefile

```
obj-m += tasklet_intr.o

export KROOT=/lib/modules/`uname -r`/build

allofit:   modules
modules:
  @$(MAKE) -C $(KROOT) M=$(PWD) modules
modules_install:
  @$(MAKE) -C $(KROOT) M=$(PWD) modules_install
clean:
  rm -rf   *.o *.ko .*cmd *.mod.c .tmp_versions .*.d .*.tmp Module.symvers
```

- Build and test it. Your interrupt number may different from what I have. Please check the output of the second command in the below and use that number in third command.

```
$ make
make[1]: Entering directory `/usr/src/kernels/3.10.0-327.10.1.el7.x86_64'
  Building modules, stage 2.
  MODPOST 3 modules
make[1]: Leaving directory `/usr/src/kernels/3.10.0-327.10.1.el7.x86_64'

$ grep eno /proc/interrupts 
  19:        249       2271   IO-APIC-fasteoi   eno16777736

$ insmod tasklet_intr.ko irq=19

$ tail /var/log/messages
Mar 22 12:12:29 devel kernel: In BH: counter_th = 55, counter_bh = 55, jiffies = 4295985979,4295985979
Mar 22 12:12:29 devel kernel: In BH: counter_th = 56, counter_bh = 56, jiffies = 4295986116,4295986116
Mar 22 12:12:29 devel kernel: In BH: counter_th = 57, counter_bh = 57, jiffies = 4295986138,4295986138
Mar 22 12:12:29 devel kernel: In BH: counter_th = 58, counter_bh = 58, jiffies = 4295986139,4295986139
...

$ rmmod tasklet_intr
$
```

- Above shows that the bottom half (tasklet) has been called.
- Let's try with some delay in tasklet. Compare 'counter_bh' and 'counter_bh' values.

```
$ insmod tasklet_intr.ko irq=19 delay=100
$ ping google.com
PING google.com (216.58.199.46) 56(84) bytes of data.
64 bytes from syd09s12-in-f14.1e100.net (216.58.199.46): icmp_seq=1 ttl=128 time=97.9 ms
^C
--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/maxev = 97.960/97.960/97.960/0.000 ms
$ rmmod tasklet_intr
$ tail /var/log/messages
Mar 22 12:15:55 devel kernel: In BH: counter_th = 76, counter_bh = 47, jiffies = 4296192152,4296192252
Mar 22 12:15:56 devel kernel: In BH: counter_th = 78, counter_bh = 48, jiffies = 4296192353,4296192453
Mar 22 12:15:56 devel kernel: In BH: counter_th = 80, counter_bh = 49, jiffies = 4296192554,4296192654
Mar 22 12:15:56 devel kernel: In BH: counter_th = 82, counter_bh = 50, jiffies = 4296192755,4296192855
...
```

- From the above, we can see that tasklet was called less time than the interrupt handler execution times.
- If the code needed to be called for each interrupts, it is needed to be in top half (interrupt handler). If the number of calls is not important, but just need to be called, bottom half (tasklet, workqueue) can be used.

#### softirq ####

- tasklet is implemented using softirq mechanism
- softirq is implemented to replace bottom half used in the 2.4 or earlier version of kernel (mark_bh())
- It's called at the end of the interrupt context

```
unsigned int __irq_entry do_IRQ(struct pt_regs *regs)
{ 
...
  if (!handle_irq(irq, regs)) {
...

  irq_exit();
...
}

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
  account_system_vtime(current);
  trace_hardirq_exit();
  sub_preempt_count(IRQ_EXIT_OFFSET);
  if (!in_interrupt() && local_softirq_pending())
    invoke_softirq();

#ifdef CONFIG_NO_HZ
  /* Make sure that timer wheel updates are propagated */
  rcu_irq_exit();
  if (idle_cpu(smp_processor_id()) && !in_interrupt() && !need_resched())
    tick_nohz_stop_sched_tick(0);
#endif
  preempt_enable_no_resched();
}

# define sub_preempt_count(val) do { preempt_count() -= (val); } while (0)
#define in_interrupt()    (irq_count())
#define irq_count() (preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK \
         | NMI_MASK))
#define preempt_count() (current_thread_info()->preempt_count)
```

- SoftIRQ is running in hard interrupt context, but only calls when the irq_count() is 0 which means if there were multiple interrupts happened while running this interrupt handler, it'll be skipped and only will be called when the last one is exiting.
- It still is not a good idea to hold the CPU from this as it'll cause of soft lockup if it's spending more than 60 seconds (default).
- So, it's recommended to do not sleep in softirq and tasklet.

```
#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
# define invoke_softirq() __do_softirq()
#else
# define invoke_softirq() do_softirq()
#endif

asmlinkage void do_softirq(void)
{
  __u32 pending;
  unsigned long flags;
  
  if (in_interrupt())
    return;
    
  local_irq_save(flags);
  pending = local_softirq_pending();
  /* Switch to interrupt stack */
  if (pending) {
    call_softirq();
    WARN_ON_ONCE(softirq_count());
  } 
  local_irq_restore(flags);
} 


ENTRY(call_softirq)
  CFI_STARTPROC
  push %rbp
  CFI_ADJUST_CFA_OFFSET 8
  CFI_REL_OFFSET rbp,0
  mov  %rsp,%rbp 
  CFI_DEF_CFA_REGISTER rbp
  incl PER_CPU_VAR(irq_count)
  cmove PER_CPU_VAR(irq_stack_ptr),%rsp
  push  %rbp      # backlink for old unwinder
  call __do_softirq
  leaveq
  CFI_DEF_CFA_REGISTER  rsp
  CFI_ADJUST_CFA_OFFSET   -8
  decl PER_CPU_VAR(irq_count)
  ret
  CFI_ENDPROC
END(call_softirq)
```

- Actual operation is happening in '__do_softirq()'.

```
asmlinkage void __do_softirq(void)
{
  struct softirq_action *h;
  __u32 pending;
...
  pending = local_softirq_pending();
....
restart:
...
  local_irq_enable();
  
  h = softirq_vec;

  do {
    if (pending & 1) {
...
      h->action(h);
...
    } 
    h++;
    pending >>= 1;
  } while (pending);
  
  local_irq_disable();
...
}
```

- soft IRQ uses fixed set of array

```
enum
{ 
  HI_SOFTIRQ=0,
  TIMER_SOFTIRQ,
  NET_TX_SOFTIRQ,
  NET_RX_SOFTIRQ,
  BLOCK_SOFTIRQ,
  BLOCK_IOPOLL_SOFTIRQ,
  TASKLET_SOFTIRQ,
  SCHED_SOFTIRQ,
  HRTIMER_SOFTIRQ,
  RCU_SOFTIRQ,  /* Preferable RCU should always be the last softirq */
  
  NR_SOFTIRQS
};

struct softirq_action
{
  void  (*action)(struct softirq_action *);
};

static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;
char *softirq_to_name[NR_SOFTIRQS] = {
  "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "BLOCK_IOPOLL",
  "TASKLET", "SCHED", "HRTIMER",  "RCU"
};
```


- You can find registered actions in vmcore


```markdown
crash> softirq_vec
softirq_vec = $1 = 
 \{{
    action = 0xffffffff810802b0 <tasklet_hi_action>
  }, {
    action = 0xffffffff8108a310 <run_timer_softirq>
  }, {
    action = 0xffffffff81468240 <net_tx_action>
  }, {
    action = 0xffffffff81470a30 <net_rx_action>
  }, {
    action = 0xffffffff8127ca50 <blk_done_softirq>
  }, {
    action = 0xffffffff8127d300 <blk_iopoll_softirq>
  }, {
    action = 0xffffffff810803d0 <tasklet_action>
  }, {
    action = 0xffffffff8106b920 <run_rebalance_domains>
  }, {
    action = 0xffffffff810a6290 <run_hrtimer_softirq>
  }, {
    action = 0xffffffff810f36b0 <rcu_process_callbacks>
  \}}

```

- Registering a new softirq is not recommended as it's required to modify vector. If you want to run an action, it's better to register a function as a tasklet or tasklet_hi.
- Registering can be done with the below function (even though it's not recommended).

```
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
  softirq_vec[nr].action = action;
}
```

- When you want to run a bottom half in interrupt context, you can raise softirq which will make it to be checked at the end of the do_IRQ()
- Example

```
/*
 * Called by the local, per-CPU timer interrupt on SMP.
 */
void run_local_timers(void)
{
  hrtimer_run_queues();
  raise_softirq(TIMER_SOFTIRQ);
}
```

- How does tasklet works in softirq? tasklet_action is registered for TASKLET_SOFTIRQ entry.
- tasklet_action is checking tasklet_vec list.
- Adding a new entry in this tasklet_vec is happening via tasklet_schedule().

```
static inline void tasklet_schedule(struct tasklet_struct *t)
{
  if (!test_and_set_bit(TASKLET_STATE_SCHED, &t->state))
    __tasklet_schedule(t);
}
void __tasklet_schedule(struct tasklet_struct *t)
{
  unsigned long flags;

  local_irq_save(flags);
  t->next = NULL;
  *__get_cpu_var(tasklet_vec).tail = t;
  __get_cpu_var(tasklet_vec).tail = &(t->next);
  raise_softirq_irqoff(TASKLET_SOFTIRQ);
  local_irq_restore(flags);
}
```

- It adds the tasklet_struct to the linked list and raise softirq for TASKLET_SOFTIRQ.  TASKLET_HI_SOFTIRQ if it's called with tasklet_hi_schedule().
- Once the falg is raised, softirq will run tasklet_action()

```
static void tasklet_action(struct softirq_action *a)
{
  struct tasklet_struct *list;
  
  local_irq_disable();
  list = __get_cpu_var(tasklet_vec).head;
  __get_cpu_var(tasklet_vec).head = NULL;
  __get_cpu_var(tasklet_vec).tail = &__get_cpu_var(tasklet_vec).head;
  local_irq_enable();
  
  while (list) {
    struct tasklet_struct *t = list;
    
    list = list->next;
    
    if (tasklet_trylock(t)) {
      if (!atomic_read(&t->count)) {
        if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
          BUG();
        t->func(t->data);
        tasklet_unlock(t);
        continue;
      }
      tasklet_unlock(t);
    }

    local_irq_disable();
    t->next = NULL;
    *__get_cpu_var(tasklet_vec).tail = t;
    __get_cpu_var(tasklet_vec).tail = &(t->next);
    __raise_softirq_irqoff(TASKLET_SOFTIRQ);
    local_irq_enable();
  }
}
```

- There's nothing new. It's traveling tasklet_vec list and run each tasklet_struct's func().

#### workqueues ####

- Work queues are a more recent deferral mechanism, added in the 2.5 Linux kernel version. Rather than providing a one-shot deferral scheme as is the case with tasklets, work queues are a generic deferral mechanism in which the handler function for the work queue can sleep (not possible in the tasklet model). Work queues can have higher latency than tasklets but include a richer API for work deferral. Deferral used to be managed by task queues through keventd but is now managed by kernel worker threads named events/X.

- The difference between softirq (tasklet) and workqueue is that workqueue is running in a process context (keventd or events/X).
- It means it can go to sleep (interruptible or uninterruptible sleep) while tasklet can't do it
- workqueue has its own structure which is work_struct.

```
typedef void (*work_func_t)(struct work_struct *work);

struct work_struct {
  atomic_long_t data;
#define WORK_STRUCT_PENDING 0   /* T if work item pending execution */
#define WORK_STRUCT_FLAG_MASK (3UL)
#define WORK_STRUCT_WQ_DATA_MASK (~WORK_STRUCT_FLAG_MASK)
  struct list_head entry;
  work_func_t func;
#ifdef CONFIG_LOCKDEP
  struct lockdep_map lockdep_map;
#endif
};
```

- Initializing can be done with one of the below functions.

```
INIT_WORK( work, func );
INIT_DELAYED_WORK( work, func );
INIT_DELAYED_WORK_DEFERRABLE( work, func );
```

- Requesting to run a workqueue can be done with one of the below functions.

```
int queue_work( struct workqueue_struct *wq, struct work_struct *work );
int queue_work_on( int cpu, struct workqueue_struct *wq, struct work_struct *work );

int queue_delayed_work( struct workqueue_struct *wq,
      struct delayed_work *dwork, unsigned long delay );

int queue_delayed_work_on( int cpu, struct workqueue_struct *wq,
      struct delayed_work *dwork, unsigned long delay );
```

- If you want all the workqueues to be finished to do a next thing, you can call one of the below functions.

```
int flush_work( struct work_struct *work );
int flush_workqueue( struct workqueue_struct *wq );
void flush_scheduled_work( void );
```

- You can cancel a workqueue which is not yet executed

```
int cancel_work_sync( struct work_struct *work );
int cancel_delayed_work_sync( struct delayed_work *dwork );
```

- Want to check if a workqueue is yet started?

```
work_pending( work );
delayed_work_pending( work );
```

- If you are not specifying a workqueue to put 'work_struct', it'll use the default which will be handled by 'events/X' .
- It's simpler method and generally accepted in most situation
- But, if a work_struct ahead of yours went to sleep, your work_struct needs to be wait until the already running one is finished. If time is important (not super urgent like tasklet, tho), you better to have your own workqueue (your own process to handle your work_struct)
- You can create your own workqueue handler by run the below functions.

```
struct workqueue_struct *create_workqueue( name );
void destroy_workqueue( struct workqueue_struct * );
```

- Example (deferred_intr.c)

```
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/delay.h>

int irq, my_dev_id, irq_counter = 0;
module_param(irq, int, 0);

int delay = 0;
module_param(delay, int, 0);

atomic_t counter_bh, counter_th, counter_wq;

struct my_dat {
  unsigned long jiffies;
};
struct my_dat my_data;

void t_func(unsigned long t_arg) {
  struct my_dat *data = (struct my_dat *)t_arg;
  atomic_inc(&counter_bh);
  printk("In tasklet: counter_th = %d, counter_bh = %d, jiffies = %ld,%ld\n",
      atomic_read(&counter_th), atomic_read(&counter_bh),
      data->jiffies, jiffies);
}

DECLARE_TASKLET(t_name, t_func, (unsigned long)&my_data);

struct workqueue_struct *my_workqueue;

void w_func(struct work_struct *work)
{
  atomic_inc(&counter_wq);
  printk("In workqueue: counter_th = %d, counter_wq = %d, jiffies = %ld,%ld\n",
      atomic_read(&counter_th), atomic_read(&counter_wq),
      my_data.jiffies, jiffies);
}
DECLARE_WORK(w_name, w_func);


irqreturn_t my_interrupt(int irq, void *dev_id) {
  struct my_dat *data = (struct my_dat *)dev_id;
  atomic_inc(&counter_th);
  data->jiffies = jiffies;

  tasklet_schedule(&t_name);
  queue_work(my_workqueue, &w_name);

  mdelay(delay);
  return IRQ_NONE;
}

int __init my_init(void) {
  int ret;
  my_workqueue = create_workqueue("my_work");

  atomic_set(&counter_th, 0);
  atomic_set(&counter_bh, 0);
  atomic_set(&counter_wq, 0);
  ret = request_irq(irq, my_interrupt, IRQF_SHARED, "my_int", &my_data);
  printk("Successfully loaded\n");
  return 0;
}

void __exit my_exit(void) {
  free_irq(irq, &my_data);
  printk("counter_th = %d, counter_wq = %d, counter_bh = %d\n",
      atomic_read(&counter_th), atomic_read(&counter_wq), atomic_read(&counter_bh));
  destroy_workqueue(my_workqueue);
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
```

- Running this will create it's own workqueue which is 'my_work'. 
- It will create process(es) depends on how many CPUs are active on your system in RHEL6 or earlier. In RHEL7, it'll create one.

```
$ ps aux | grep my_work
root     64322  0.0  0.0      0     0 ?        S    10:24   0:00 [my_work/0]
root     64323  0.0  0.0      0     0 ?        S    10:24   0:00 [my_work/1]
root     64324  0.0  0.0      0     0 ?        S    10:24   0:00 [my_work/2]
root     64325  0.0  0.0      0     0 ?        S    10:24   0:00 [my_work/3]
root     64327  0.0  0.0 103308   856 pts/3    S+   10:24   0:00 grep my_work
```

---
[Back to topic list](https://sungju.github.io/kernel/internals/index)
