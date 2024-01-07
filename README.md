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
1. Signal generation (Kernel updates a data structure __pending, sig__, to represent that a new signal is being sent)
2. Signal delivery (Kernel forces the process to react to signal by changing its execution state, running its **signal handler**)

### Process creation
Unix operating systems rely heavily on process creation to satisfy user requests. The `fork()` syscall initializes and sets some values and then calls `clone()` syscall underlying to clone the actual process. The detailed steps will be discussed later. 

### Syscalls
System calls are kernel-defined, which means every different system may have different implementations of system calls. To expose syscalls to the user as an interface, the kernel compiles with a certain table which denotes the number of the syscall, the function to call and its argument and types. The .tbl file is THE file kernel reads to reoute syscalls. the SYSCALL_DEFINEN macro is used to register logic implementation to certain syscall numbers.

## Implementation
### ft_kill
The implementation for this is quite simple, this just sends a SIGKILL signal to the process looked up using the pid found in the parameter.
```c
SYSCALL_DEFINE2(ft_kill, long, pid, int, sig)
{
	struct siginfo info;
	struct task_struct *task = find_task_by_vpid(pid);

	info.si_signo = sig;
	info.si_errno = 0;
	info.si_code = SI_USER;

	if (!task->pid)
		return -1;
	return send_sig_info(sig, &info, task);
}
```

### ft_wait
For ft_wait, its also quite straightforward; We set the current task stae to sleeping and we start an infinite loop to block the current procedure from ending. In every iteration, we check if the process specified in the input has exited. If its exited, or we recieve an interrupt signal, just set the status code and return from the function.
```c
SYSCALL_DEFINE1(ft_wait, int __user *, status)
{

	struct task_struct *child_task;
	int child_state = 0;
	
	// set current state to sleep
	current->state = TASK_INTERRUPTIBLE;

	// start loop
	while (!child_state)
	{
		// iterate children to check if any of them return (change state to exit zombie)
		list_for_each_entry(child_task, &current->children, sibling) {

			// if one of them dies, change child state to exit dead and return status code
			if (child_task->state > 0)
			{
				child_state = child_task->state;
				copy_to_user(status, &(child_task->exit_code), sizeof(int));
			}
		}

		// Check if a signal is pending
		if (signal_pending(current)) {
			// Handle the signal interruption
			return -EINTR;
		}

	}	
	return 0;
}
```

### ft_fork
The complete implementation of fork is a lengthy one, but the summary is like so : 
1. Create a slab which task_Structs can be allocated
2. Check for flag and adjust the soon created task_struct based on those flags (tracing, vfork, parent trace)
3. Call copy_process(), which should return a new task_struct with all the correct configuration

copy_process does the following things:
1. Check for flag compatibility
2. Duplicate static values to the new task_struct
3. Set up mutexes and allocate new child id
4. Update parent refrence counting and delay accounting
5. Allocate memory for some other structs
6. Create memmory policy
7. Scheduler setup, cpu assignation
8. Initialize shared memory namagement and copy the rest of the process information
9. Set up signals, parent relationship, cgroup policies
10. React to pending signals
11. Set up ptrace and userspace probes
12. Return the newly created task struct
