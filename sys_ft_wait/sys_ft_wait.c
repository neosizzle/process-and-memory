#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/sched.h>

SYSCALL_DEFINE1(ft_wait, int __user *, status)
{
	// testing stuff
	current->state = TASK_INTERRUPTIBLE;


	// set current state to sleep

	// start loop 
		// check if current state changed

		// iterate children to check if any of them return (change state to exit zombie)

		// if one of them does, change child state to exit dead and return status code
	printk("kernel pid %d\n", current->pid);
	return 0;
}