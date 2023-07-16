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
#include <linux/slab.h>
#include <linux/slab_def.h>
#include <linux/kthread.h>

static struct kmem_cache *task_struct_cachep;
static inline struct task_struct *ft_alloc_task_struct_node(int node)
{
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}

static inline void ft_free_task_struct(struct task_struct *tsk)
{
	kmem_cache_free(task_struct_cachep, tsk);
}

static struct task_struct * ft_dup_task_struct(struct task_struct *orig, int node)
{
	struct task_struct *tsk;
	unsigned long *stack;
	struct vm_struct *stack_vm_area;

	// non uniform memory address node
	if (node == NUMA_NO_NODE)
		node = tsk_fork_get_node(orig);

	// allocate a fresh task_struct with the numa node type
	tsk = ft_alloc_task_struct_node(node);
	if (!tsk)
		return NULL;

	// allocate new stack for kernel thread
	if ((stack = alloc_thread_stack_node(tsk, node)) == NULL)
	{
		printk("[ERROR] alloc_thread_stack_node failed\n");
		return NULL;
	}

	// allocate and manage new stack in vm area  
	// if ((stack_vm_area = task_stack_vm_area(tsk)) == NULL)
	// {
	// 	printk("[ERROR] task_stack_vm_area failed\n");
	// 	return NULL;
	// }

	*tsk = *orig;
	
	// reassign stacks
	tsk->stack = stack;
	// tsk->stack_vm_area = stack_vm_area;

	return tsk;
}


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
	struct task_struct *tsk;

	// check for flag compatibility
	printk("[DEBUG] checking flag compatibility...\n");
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);
	
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);
	
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);

	// security checks (ommiting :P)

	// dup_task_struct
	printk("[DEBUG] dup_task_struct...\n");
	tsk = ft_dup_task_struct(current, node);
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
	child = ft_copy_process(clone_flags, stack_start, stack_size,
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
		child->state = TASK_STOPPED;

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
			ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, child_pid_struct);
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