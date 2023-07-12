#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/wait.h>

SYSCALL_DEFINE1(ft_wait, int __user *, status)
{
	// testing stuff
	current->state = TASK_INTERRUPTIBLE;

	DECLARE_WAIT_QUEUE_HEAD(my_wait_queue);
	wait_event(my_wait_queue, 0);
	printk("wait_event return\n");
	// schedule();



	// set current state to sleep

	// start loop 
		// check if current state changed

		// iterate children to check if any of them return (change state to exit zombie)

		// if one of them does, change child state to exit dead and return status code
	printk("kernel pid %d\n", current->pid);
	return 0;
}