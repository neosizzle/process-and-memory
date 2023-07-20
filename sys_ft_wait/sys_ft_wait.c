#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <linux/list.h>

int condition_check(void)
{
	printk("condition checked\n");
	return 0;
}

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