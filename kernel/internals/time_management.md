# Time Management #

### jiffies ###

- Heartbeat of Linux kernel
- In RHEL6 or later version is using tickless timer, so, the calculation is a bit complicate
- Time is managed in 'jiffies_64'

```
/*
 * The 64-bit value is not atomic - you MUST NOT read it
 * without sampling the sequence number in xtime_lock.
 * get_jiffies_64() will do this for you as appropriate.
 */
extern u64 __jiffy_data jiffies_64;
extern unsigned long volatile __jiffy_data jiffies;
```

- It's increased during timer interrupt handling
- Difference between RHEL5 and RHEL6/7 is that RHEL6/7 is using tickless scheduling
  - It doesn't trigger timer interrupt in regular basis, but based on anything coming up with other/scheduled interrupts 
  - It needs to find out how much time had been passed which is saved in 'ticks'

```
void do_timer(unsigned long ticks)
{
  jiffies_64 += ticks;
  update_wall_time();
  calc_global_load(ticks);
}

static void tick_do_update_jiffies64(ktime_t now)
{
  unsigned long ticks = 0;
  ktime_t delta;

  /*
   * Do a quick check without holding xtime_lock:
   */
  delta = ktime_sub(now, last_jiffies_update);
  if (delta.tv64 < tick_period.tv64)
    return;

  /* Reevalute with xtime_lock held */
  write_seqlock(&xtime_lock);

  delta = ktime_sub(now, last_jiffies_update);         <---- Counting missed ticks
  if (delta.tv64 >= tick_period.tv64) {

    delta = ktime_sub(delta, tick_period);
    last_jiffies_update = ktime_add(last_jiffies_update,
            tick_period);

    /* Slow path for long timeouts */
    if (unlikely(delta.tv64 >= tick_period.tv64)) {
      s64 incr = ktime_to_ns(tick_period);

      ticks = ktime_divns(delta, incr);

      last_jiffies_update = ktime_add_ns(last_jiffies_update,
                 incr * ticks);
    }
    do_timer(++ticks);

    /* Keep the tick_next_period variable up to date */
    tick_next_period = ktime_add(last_jiffies_update, tick_period);
  }
  write_sequnlock(&xtime_lock);
}
```

- 'ticks' value is calculated based on the difference between current time (now) and last update time (last_jiffies_update).
- The current time (now) is from the below

```
static void tick_nohz_update_jiffies(ktime_t now)
{
...
  tick_do_update_jiffies64(now);
}

static inline void tick_check_nohz(int cpu)
{
  struct tick_sched *ts = &per_cpu(tick_cpu_sched, cpu);
  ktime_t now;

  if (!ts->idle_active && !ts->tick_stopped)
    return;
  now = ktime_get();             <----- Get the time
  if (ts->idle_active)
    tick_nohz_stop_idle(cpu, now);
  if (ts->tick_stopped) {
    tick_nohz_update_jiffies(now);
    tick_nohz_kick_tick(cpu, now);
  }
}

ktime_t ktime_get(void)
{
..
  do {
...
    secs = timekeeper.xtime.tv_sec +
        timekeeper.wall_to_monotonic.tv_sec;
    nsecs = timekeeper.xtime.tv_nsec +
        timekeeper.wall_to_monotonic.tv_nsec;
    nsecs += timekeeping_get_ns();               <---- get the time in ns
    /* If arch requires, add in gettimeoffset() */
    nsecs += arch_gettimeoffset();
    
  } while (read_seqretry(&timekeeper.lock, seq));
..
  return ktime_add_ns(ktime_set(secs, 0), nsecs);
}

/* Timekeeper helper functions. */
static inline s64 timekeeping_get_ns(void)
{
  cycle_t cycle_now, cycle_delta;
  struct clocksource *clock;

  /* read clocksource: */
  clock = timekeeper.clock;
  cycle_now = clock->read(clock);

  /* calculate the delta since the last update_wall_time: */
  cycle_delta = (cycle_now - clock->cycle_last) & clock->mask;

  /* return delta convert to nanoseconds using ntp adjusted mult. */
  return clocksource_cyc2ns(cycle_delta, timekeeper.mult,
          timekeeper.shift);
}
```

- The actual time is gathered from clock source via 'clock->read(clock)'.
- This 'tick_check_nohz()' is called whenever there's an interrupt

```
/*
 * Called from irq_enter to notify about the possible interruption of idle()
 */
void tick_check_idle(int cpu)
{
  tick_check_oneshot_broadcast(cpu);
  tick_check_nohz(cpu);
}

void irq_enter(void)
{
...
    tick_check_idle(cpu);
...
}

unsigned int __irq_entry do_IRQ(struct pt_regs *regs)
{ 
...
  irq_enter();
...
}
```

- In RHEL5 or earlier version, it's much easier. It's called from 'timer_interrupt()'

```

static irqreturn_t timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
...
  main_timer_handler(regs);
...
}

void main_timer_handler(struct pt_regs *regs)
{
...
    do_timer_tsc_timekeeping(regs);
...
}

static void do_timer_tsc_timekeeping(struct pt_regs *regs)
{
...
      do_timer_jiffy(regs);
...
}

static void do_timer_jiffy(struct pt_regs *regs)
{
  do_timer(regs);
...
}

void do_timer(struct pt_regs *regs)
{
  jiffies_64++;
  ...
}
```

- How to use jiffies in kernel to check time progress
  - Below is a wrong way to check it. It can't handle overflow situation

```
if (jiffies > expected_time) {
  do_work();
}
```

- Proper way to check is using kernle provided macros shown in the below

```
time_after(a, b);
time_before(a, b);
time_after_eq(a, b);
time_before_eq(a, b);
```

- Example

```
if (time_after(jiffies, expected_time)) {
  do_work();
}
```

### How to make a delay in Kernel ###

- Using jiffies is simpler way, but can't make a delay lower than HZ
  -  jiffies is increased in every 1 ms when HZ = 1000, in every 10 ms when HZ=100

```
int delay = 5;

work_time = jiffies + delay * HZ; // 5 secs later
while (time_before(jiffies, work_time)) {
  ;
}
```

- Functions for smaller delay than HZ
  - ndelay: nano seconds delay
  - udelay: micro seonds delay
  - mdelay: milli seconds delay
  - msleep, msleep_interruptible: milli seconds delay without looping in CPU as it goes to sleep. interruptible() version is sleep in TASK_INTERRUPTIBLE.

```
#include <linux/delay.h>

void ndelay(unsigned long nanoseconds);
void udelay(unsigned long microseconds);
void mdelay(unsigned long milliseconds);

void msleep (unsigned int milliseconds);
unsigned long msleep_interruptible (unsigned int milliseconds);
```

### Kernel Timer ###

- Looping in CPU is the worst way to wait until the specified time comes
- Linux Kernel provides a mechanism that helps to execute functions scheduled to run after some specific time

```
struct timer_list {
  struct list_head entry;
  unsigned long expires;
  
  void (*function)(unsigned long);
  unsigned long data;
  ...
};

void init_timer (struct timer_list *timer);
void add_timer (struct timer_list *timer);
void mod_timer (struct timer_list *timer, unsigned long expires); 
int del_timer (struct timer_list *timer);
int del_timer_sync (struct timer_list *timer);
```

- Simple example to show how to use timer

```
/* timer_drv.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

#define MYDEV_NAME  "mycdrv"
int mycdrv_ma_no;
struct timer_list my_timer;

void my_timer_function(unsigned long ptr)
{
  printk("my_timer_function(), jiffies=%ld\n", jiffies);
  printk("my data = %d, my pid=%d\n", (int)ptr, (int)current->pid);
}

ssize_t my_write(struct file *file, const char *buf, size_t lbuf, loff_t * ppos)
{
  static int len = 100;

  printk("my_write(),current->pid=%d\n", (int)current->pid);
  init_timer(&my_timer);
  my_timer.function = my_timer_function;
  my_timer.expires = jiffies + HZ;
  my_timer.data = len;
  printk("Adding timer at jiffies = %ld\n", jiffies);
  add_timer(&my_timer);
  len += 10;
  return lbuf;
}

struct file_operations fops = {
  .owner = THIS_MODULE,
  .write = my_write,
};

int my_init(void)
{
  mycdrv_ma_no = register_chrdev(0, MYDEV_NAME, &fops);
  return 0;
}

void my_exit(void)
{
  unregister_chrdev(mycdrv_ma_no, MYDEV_NAME);
}

module_init(my_init);
module_exit(my_exit);
```

- It'll trigger a timer when any writting is happening on this device

```
$ insmod timer_drv.ko
$ grep mycdrv /proc/devices 
248 mycdrv
$ mknod mydrv c 248 0
$ echo hello > ./mydrv
$ tail -n 4 /var/log/messages
Apr 26 12:32:32 devel kernel: my_write(),current->pid=8809
Apr 26 12:32:32 devel kernel: Adding timer at jiffies = 4295896395
Apr 26 12:32:33 devel kernel: my_timer_function(), jiffies=4295897397
Apr 26 12:32:33 devel kernel: my data = 100, my pid=0
$ rmmod timer_drv
```

- You can see the difference in between two jiffies - 4295896395 and 4295897397. This difference is not exactly 1 second (1000).


- Periodic timer. If the function needs to be run periodically, you can use 'mod_timer'

```
/* periodic_timer.c */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

struct timer_list timer;
struct kt_data {
  unsigned long period;
  unsigned long start_time;
} data;

void ktfun(unsigned long var)
{
  struct kt_data *tdata = (struct kt_data *)var;
  printk("ktimer:period=%ld elapsed =%ld\n",
         tdata->period, jiffies - tdata->start_time);
  mod_timer(&timer, tdata->period + jiffies);
}

int init_module(void)
{
  data.period = 2 * HZ;
  init_timer(&timer);
  timer.function = ktfun;
  timer.data = (unsigned long)&data;
  timer.expires = jiffies + data.period;
  data.start_time = jiffies;
  add_timer(&timer);
  return 0;
}

void cleanup_module(void)
{
  printk("Delete timer,rc=%d\n", del_timer_sync(&timer));
}
```

- In cleanup_module(), it's using del_timer_sync() just in case the timer function is running when the deleting is happening.

```
$ insmod period_timer.ko
$ tail /var/log/messages
Apr 26 12:47:20 devel kernel: ktimer:period=2000 elapsed =12029
Apr 26 12:47:22 devel kernel: ktimer:period=2000 elapsed =14033
Apr 26 12:47:24 devel kernel: ktimer:period=2000 elapsed =16037
Apr 26 12:47:26 devel kernel: ktimer:period=2000 elapsed =18041
Apr 26 12:47:28 devel kernel: ktimer:period=2000 elapsed =20045
Apr 26 12:47:30 devel kernel: ktimer:period=2000 elapsed =22049
Apr 26 12:47:32 devel kernel: ktimer:period=2000 elapsed =24053
Apr 26 12:47:34 devel kernel: ktimer:period=2000 elapsed =26057
Apr 26 12:47:36 devel kernel: ktimer:period=2000 elapsed =28061
Apr 26 12:47:38 devel kernel: ktimer:period=2000 elapsed =30065
$ rmmod period_timer
```

### clock source ###

- The reason of the below message

```
2013-07-16T05:00:05.181538-04:00 xxxxxx kernel: Clocksource tsc unstable (delta = -95170507948 ns).  Enable clocksource failover by adding clocksource_failover kernel parameter.
```

- This message is generated from the watchdog timer function
- clocksource_watchdog is handled with watchdog_timer and started in clocksource_start_watchdog()

```
static struct timer_list watchdog_timer;

static inline void clocksource_start_watchdog(void)
{                                                                  
  if (watchdog_running || !watchdog || list_empty(&watchdog_list))   
    return;
  init_timer(&watchdog_timer);
  watchdog_timer.function = clocksource_watchdog;
  watchdog_timer.expires = jiffies + WATCHDOG_INTERVAL;
  add_timer_on(&watchdog_timer, cpumask_first(cpu_online_mask));
  watchdog_running = 1;
}
```

- clocksource_watchdog() is checking each clock sources and see if there's any big differences in the time value.

```
static void clocksource_watchdog(unsigned long data)
{
  struct clocksource *cs;
  cycle_t csnow, wdnow;
  int64_t wd_nsec, cs_nsec;
  int next_cpu;
  
  spin_lock(&watchdog_lock);
  if (!watchdog_running)
    goto out;
    
  list_for_each_entry(cs, &watchdog_list, wd_list) {
  
    /* Clocksource already marked unstable? */
    if (cs->flags & CLOCK_SOURCE_UNSTABLE) {
      if (finished_booting)
        schedule_work(&watchdog_work);
      continue;
    }

    local_irq_disable();
    csnow = cs->read(cs);
    wdnow = watchdog->read(watchdog);
    local_irq_enable();

    /* Clocksource initialized ? */
    if (!(cs->flags & CLOCK_SOURCE_WATCHDOG)) {
      cs->flags |= CLOCK_SOURCE_WATCHDOG;
      cs->wd_last = wdnow;
      cs->cs_last = csnow;
      continue;
    }

    wd_nsec = clocksource_cyc2ns((wdnow - cs->wd_last) & watchdog->mask,
               watchdog->mult, watchdog->shift);

    cs_nsec = clocksource_cyc2ns((csnow - cs->cs_last) &
               cs->mask, cs->mult, cs->shift);
    cs->cs_last = csnow;
    cs->wd_last = wdnow;

    /* Check the deviation from the watchdog clocksource. */
    if (abs(cs_nsec - wd_nsec) > WATCHDOG_THRESHOLD) {
      if (clocksource_failover)
        clocksource_unstable(cs, cs_nsec - wd_nsec);
      else
        printk(KERN_WARNING "Clocksource %s unstable (delta = %Ld ns).  Enable clocksource failover by adding clocksource_failover kernel parameter.\n",
               cs->name, cs_nsec - wd_nsec);
      continue;
    }

    if (!(cs->flags & CLOCK_SOURCE_VALID_FOR_HRES) &&
        (cs->flags & CLOCK_SOURCE_IS_CONTINUOUS) &&
        (watchdog->flags & CLOCK_SOURCE_IS_CONTINUOUS)) {
      cs->flags |= CLOCK_SOURCE_VALID_FOR_HRES;
      /*
       * We just marked the clocksource as highres-capable,
       * notify the rest of the system as well so that we
       * transition into high-res mode:
       */
      tick_clock_notify();
    }
  }

  /*
   * Cycle through CPUs to check if the CPUs stay synchronized
   * to each other.
   */
  next_cpu = cpumask_next(raw_smp_processor_id(), cpu_online_mask);
  if (next_cpu >= nr_cpu_ids)
    next_cpu = cpumask_first(cpu_online_mask);
  watchdog_timer.expires += WATCHDOG_INTERVAL;
  add_timer_on(&watchdog_timer, next_cpu);
out:
  spin_unlock(&watchdog_lock);
}
```

- Why this checking is happening?
  - clocksource is used to get smaller time differences than the time interrupt can handles (100ms or 10ms depends on kernel HZ).
  - By checking the clock source value, we can check if the clock source is providing reliable value.

```
/* Timekeeper helper functions. */
static inline s64 timekeeping_get_ns(void)
{
  cycle_t cycle_now, cycle_delta;
  struct clocksource *clock;

  /* read clocksource: */
  clock = timekeeper.clock;
  cycle_now = clock->read(clock);

  /* calculate the delta since the last update_wall_time: */
  cycle_delta = (cycle_now - clock->cycle_last) & clock->mask;

  /* return delta convert to nanoseconds using ntp adjusted mult. */
  return clocksource_cyc2ns(cycle_delta, timekeeper.mult,
          timekeeper.shift);
}
```


---
[Back to topic list](https://sungju.github.io/kernel/internals/index)

