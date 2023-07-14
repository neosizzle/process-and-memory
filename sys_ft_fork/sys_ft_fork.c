#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/wait.h>
#include <linux/signal_types.h>
#include <linux/pid.h>
#include <linux/completion.h>
#include <linux/freezer.h>

static struct task_struct *ft_copy_process(
					unsigned long clone_flags,
					unsigned long stack_start,
					unsigned long stack_size,
					int __user *child_tidptr,
					struct pid *pid,
					int trace,
					unsigned long tls,
					int node)
{
	return 0;
}

static int wait_for_vfork_done(struct task_struct *child,
				struct completion *vfork)
{
	int killed;

	freezer_do_not_count();
	killed = wait_for_completion_killable(vfork);
	freezer_count();

	if (killed) {
		task_lock(child);
		child->vfork_done = NULL;
		task_unlock(child);
	}

	put_task_struct(child);
	return killed;
}

long ft_do_fork(
	unsigned long clone_flags,
	unsigned long stack_start,
	unsigned long stack_size,
	int __user *parent_tidptr,
	int __user *child_tidptr,
	unsigned long tls
)
{
	int trace_child;
	struct task_struct *child;
	struct siginfo info;
	long child_pid;
	struct pid *child_pid_struct;
	struct completion vfork;

	trace_child = 0;
	// allocated new PID (not needed, copy_process() did it for us (?))

	// check ptrace of current process
	if (current->ptrace)
	{
		// if not 0, check CLONE_PTRACE flag to determine
		if (clone_flags & CLONE_PTRACE)
		{
			// if child would be traced or not
			printk("[DEBUG] setting trace_child to 1\n");
			trace_child = PTRACE_EVENT_FORK;
		}
	}

	// call copy_process(), the returning task_struct is the new child struct
	child = copy_process(clone_flags, stack_start, stack_size,
		child_tidptr, NULL, trace_child, tls, NUMA_NO_NODE);

	if (!child)
	{
		printk("[DEBUG] copy_process failed \n");
		return -1;
	}

	// if clone_stopped set (not in 4.17) or child process is traced
	if (trace_child)
	{
		printk("[DEBUG] trace child, sending stop signal\n");
		// set child status to TASK_STOPPED and send pending SIGSTOP signal to it
		trace_child->state = TASK_STOPPED;

		info.si_signo = SIGSTOP;
		info.si_errno = 0;
		info.si_code = SI_KERNEL;
		send_sig_info(SIGSTOP, &info, child);
	}
	else
	{
		printk("[DEBUG] wake_up_new_task\n");
		// else, call wake_up_new_task()		
		wake_up_new_task(child);
	}
	
	child_pid_struct = get_task_pid(child, PIDTYPE_PID);
	child_pid = pid_vnr(child_pid_struct);

	// cnofigure vfork options
	if (clone_flags & CLONE_VFORK) {
		printk("[DEBUG] configuring vfork.. \n");
		child->vfork_done = &vfork;
		init_completion(&vfork);
		get_task_struct(child);
	}

	// if parent is traced, store PID of child in current ptrace->message and call
	// ptrace_notify() (ptrace_event_pid()) for 4.17?
	if (current->ptrace)
	{
		printk("[DEBUG] sending ptrace event to parent \n");
		current->ptrace_message = child_pid;
		ptrace_event_pid(trace_child, child_pid_struct);
	}

	// if  CLONE_VFORK flag is set, insert parent in waitqueue and suspend it until child
	if (clone_flags & CLONE_VFORK) {
			printk("[DEBUG] waiting for vfork done \n");
		// releases its address space (terminate or execve)
		if (!wait_for_vfork_done(child, &vfork))
			ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
	}

	printk("[DEBUG] returning child pid... \n");
	return child_pid;
}

SYSCALL_DEFINE0(ft_fork)
{
	return ft_do_fork(
		SIGCHLD,
		0,
		0,
		NULL,
		NULL,
		0
	);
}