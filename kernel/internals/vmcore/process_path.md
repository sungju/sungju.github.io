# How to find binary path of a process in vmcore

In general, vmcore does not containing user space data which is useful to check process related information. If the vmcore is collected with user space data as well, you can use `ps -a <pid>` to get some process details like below.

![ps -a](https://sungju.github.io/kernel/internals/vmcore/ps_a.png)

It still doesn’t show binary path, though. To get binary details, you can use `mm_struct.exe_file` as shown in the below.

![struct task_struct.mm](https://sungju.github.io/kernel/internals/vmcore/task_struct_mm.png)

If this steps are too much, you can use `psinfo -t <task addr>` from my pycrashext extension located at [https://github.com/sungju/pycrashext](https://github.com/sungju/pycrashext).

![psinfo -t](https://sungju.github.io/kernel/internals/vmcore/psinfo_t.png)

---
[Back to topic list](https://sungju.github.io/kernel/internals/vmcore/index)
