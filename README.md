# process-and-memory
In this project, we will create a custom system call from scratch that takes in a PID, named `get_pid_info()`, and returns a struct that contains the information of the PID. We will also be re-implementing the `wait(2)`, `kill(2)` and `fork(2)` system calls. Most of the resources here can be obtained from [Understanding the linux kernel](http://gauss.ececs.uc.edu/Courses/e4022/code/memory/understanding.pdf)

## Prerequisites
### Processes and threads
From the kernel, a process is a **group of allocated resources** like memory locations, priority, threads etc. when a processs is created, it shares the text section (code) with its parent however have different memory locations so memory operations in the child wont be affecting the parent.

You might also notice that the process also groups threads. These threads contains the actual execution flow of the program. The **kernel and system executes threads ONLY**. The processes are there to give context to those threads.

A process descriptor is a data type / struct that contains actual information about the process. In linux, this structure is defined by the type `task_struct` 

![image](https://github.com/neosizzle/process-and-memory/assets/44501267/52bc0f8c-fb25-4835-9f89-6504ce881ef4)

In any kernel function, we can use the `current` macro to get the process descriptor of the current process. We are able to use this information for our `get_pid_info()`

### Signals
Signals are introduced by the unix system to facilitate Inter Process Communication **IPC** between user process or kernel to user process.

A signal is a short message that may be sent to a process or a **group of processes**. There is a table in every UNIX system to identify individual signals called the **signal table**.

Besides **regular signals** the POSIX standard also introduced a new class of signals; **real-time signals** (32 - 63) The main difference is that read-time signals are always queued so **multiple signals can be fully received**. 

The signal transmission process is split into two phases
1. Signal generation (Kernel updates a data structure __pending, sig___, to represent that a new signal is being sent)
2. Signal delivery (Kernel forces the process to react to signal by changing its execution state, running its **signal handler**)

