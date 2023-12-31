# process-and-memory
In this project, we will create a custom system call from scratch that takes in a PID, and returns a struct that contains the information of the PID. We will also be re-implementing the `wait(2)`, `kill(2)` and `fork(2)` system calls. Most of the resources here can be obtained from [Understanding the linux kernel](http://gauss.ececs.uc.edu/Courses/e4022/code/memory/understanding.pdf)

## Prerequisites
### Processes and threads
From the kernel, a process is a **group of allocated resources** like memory locations, priority, threads etc. when a processs is created, it shares the text section (code) with its parent however have different memory locations so memory operations in the child wont be affecting the parent.

You might also notice that the process also groups threads. These threads contains the actual execution flow of the program. The **kernel and system executes threads ONLY**. The processes are there to give context to those threads.

A process descriptor
