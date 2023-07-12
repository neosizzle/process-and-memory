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
	// testing stuff
	// current->state = TASK_INTERRUPTIBLE;

	// DECLARE_WAIT_QUEUE_HEAD(my_wait_queue);


	// wait_event_interruptible(my_wait_queue, condition_check());
	// printk("wait_event return\n");
	
	// struct wait_queue_entry wait;
	// init_waitqueue_entry(&wait, current);
	// current->state = TASK_INTERRUPTIBLE;
	// add_wait_queue(&my_wait_queue,&wait); /* wq points to the wait queue head */
	// schedule();
	// wake_up(&my_wait_queue);
	// remove_wait_queue(&my_wait_queue, &wait);



	// set current state to sleep
	current->state = TASK_INTERRUPTIBLE;

	// start loop
	while (1)
	{
		// Check if a signal is pending
		if (signal_pending(current)) {
			// Handle the signal interruption
			return -EINTR;
		}

		// iterate children to check if any of them return (change state to exit zombie)
		list_for_each_entry(child_task, &current->children, sibling) {
			printk("child status %d, exit_state %d, exit_code %d, exit_signal %d\n",
			child_task->state,
			child_task->exit_state,
			child_task->exit_code,
			child_task->exit_signal
			);

			// if one of them dies, change child state to exit dead and return status code
			if (child_task->state > 0)
				break ;
		}

	}
	
	printk("queue return, kernel pid %d\n", current->pid);
	return 0;
}