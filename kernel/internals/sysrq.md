# SysRq #

### Simplest method to debug kernel related information ###

* You can trigger SysRq functionalities with one of the below two methods.
	* Method 1:
		* echo 1 > /proc/sys/kernel/sysrq
		* In console: Alt + SysRq + [key]
		* In GUI: Alt + Ctrl + SysRq + [key]
	* Method 2:
		* echo [key] > /proc/sysrq-trigger
* You can find out the list of functionalities by issued 'h' (help)

```
$ echo h > /proc/sysrq-trigger 
$ tail /var/log/messages -n 1
May 30 15:24:52 localhost kernel: SysRq : HELP : loglevel(0-9) reBoot Crash terminate-all-tasks(E) memory-full-oom-kill(F) kill-all-tasks(I) thaw-filesystems(J) saK show-backtrace-all-active-cpus(L) show-memory-usage(M) nice-all-RT-tasks(N) powerOff show-registers(P) show-all-timers(Q) unRaw Sync show-task-states(T) Unmount show-blocked-tasks(W) dump-ftrace-buffer(Z) 
```

### Registering/Unregistering SysRq functionalities ###

* Registering and unregistering require a 'key' and 'sysrq_key_op' which contains function pointer

```
/* Register a new SysRq key */
int register_sysrq_key(int key, struct sysrq_key_op *op);
/* Unregister SysRq key */
int unregister_sysrq_key(int key, struct sysrq_key_op *op);
```

* It saves the sysrq_key_op based on the 'key' in 'sysrq_key_table'
	* 'key' is converted into to a number and the order is in range of '0'~'9', 'a'-'z'

```
crash> sysrq_key_table
sysrq_key_table = $18 = 
 {0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0xffffffff81b12f20 <sysrq_loglevel_op>, 0x0, 0xffffffff81b12f40 <sysrq_reboot_op>, 0xffffffff81b12f60 <sysrq_crash_op>, 0x0, 0xffffffff81b12f80 <sysrq_term_op>, 0xffffffff81b12fa0 <sysrq_moom_op>, 0x0, 0x0, 0xffffffff81b12fc0 <sysrq_kill_op>, 0xffffffff81b12fe0 <sysrq_thaw_op>, 0xffffffff81b13000 <sysrq_SAK_op>, 0xffffffff81b13020 <sysrq_showallcpus_op>, 0xffffffff81b13040 <sysrq_showmem_op>, 0xffffffff81b13060 <sysrq_unrt_op>, 0xffffffff81ab8860 <sysrq_poweroff_op>, 0xffffffff81b13080 <sysrq_showregs_op>, 0xffffffff81b130a0 <sysrq_show_timers_op>, 0xffffffff81b130c0 <sysrq_unraw_op>, 0xffffffff81b130e0 <sysrq_sync_op>, 0xffffffff81b13100 <sysrq_showstate_op>, 0xffffffff81b13120 <sysrq_mountro_op>, 0x0, 0xffffffff81b13140 <sysrq_showstate_blocked_op>, 0x0, 0x0, 0xffffffff81b13160 <sysrq_ftrace_dump_op>}
```

* Finding the sysrq_key_op for a specific key can be done by the below.

```
struct sysrq_key_op *__sysrq_get_key_op(int key);
```

* Actual trigger is happening in 'handle_sysrq()'

```
void handle_sysrq(int key);
```

* sysrq_key_op contains the handler and other key related messages.

```
crash> sysrq_key_op
struct sysrq_key_op {
    void (*handler)(int, struct tty_struct *);
    char *help_msg;
    char *action_msg;
    int enable_mask;
}
SIZE: 0x20
```

* For example, 'b' is rebooting the system right away by calling 'sysrq_handle_reboot'

```
crash> sysrq_key_op sysrq_reboot_op
struct sysrq_key_op {
  handler = 0xffffffff8135d0d0 <sysrq_handle_reboot>, 
  help_msg = 0xffffffff817f7660 "reBoot", 
  action_msg = 0xffffffff817f7667 "Resetting", 
  enable_mask = 0x80
}


static void sysrq_handle_reboot(int key)
{
  lockdep_off();
  local_irq_enable();
  emergency_restart();
}
```

* Let's make a simple SysRq example that prints out all the tasks in the system

```
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sysrq.h>
#include <linux/sched.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static void my_sysrq_task_list(int key, struct pt_regs *ptregs,
                              struct tty_struct *ttystruct)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
static void my_sysrq_task_list(int key, struct tty_struct *ttystruct)
#else
static void my_sysrq_task_list(int key)
#endif
{
  struct task_struct *p;

  printk("*** Start to dump task list ***\n");

  for_each_process(p) {
    printk("%s(%d) is %s Runnable\n",
          p->comm, p->pid,
          p->state == TASK_RUNNING ? "" : "Not");
  }
  printk("*** End of task dumping ***\n");
}

static struct sysrq_key_op my_sysrq_op = {
  .handler = my_sysrq_task_list,
  .help_msg = "dump-All-tasks",
  .action_msg = "Show All Task List",
};

static int __init my_init(void)
{
  int ret = register_sysrq_key('a', &my_sysrq_op);

  printk("SysRq function is %sregistered\n", ret ? "" : "Not ");
  return ret;
}

static void __exit my_exit(void)
{
  unregister_sysrq_key('a', &my_sysrq_op);
}

module_init(my_init);
module_exit(my_exit);

MODULE_LICENSE("GPL");
```

* Running

```
$ insmod ./sysrq_task.ko
$ echo h > /proc/sysrq-trigger 

$ tail /var/log/messages -n 1
May 30 16:24:48 devel kernel: SysRq : HELP : loglevel(0-9) dump-All-tasks reboot(b) crash(c) terminate-all-tasks(e) memory-full-oom-kill(f) kill-all-tasks(i) thaw-filesystems(j) sak(k) show-backtrace-all-active-cpus(l) show-memory-usage(m) nice-all-RT-tasks(n) poweroff(o) show-registers(p) show-all-timers(q) unraw(r) sync(s) show-task-states(t) unmount(u) show-blocked-tasks(w) dump-ftrace-buffer(z) 

$ echo a > /proc/sysrq-trigger 
$ grep "Show All Task List" /var/log/messages -A 5
May 30 16:25:03 devel kernel: SysRq : Show All Task List
May 30 16:25:03 devel kernel: *** Start to dump task list ***
May 30 16:25:03 devel kernel: systemd(1) is Not Runnable
May 30 16:25:03 devel kernel: kthreadd(2) is Not Runnable
May 30 16:25:03 devel kernel: ksoftirqd/0(3) is Not Runnable
May 30 16:25:03 devel kernel: migration/0(7) is Not Runnable
```
