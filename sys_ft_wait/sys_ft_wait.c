#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/wait.h>

int condition_check()
{
	printk("condition checked\n");
	return 0;
}

SYSCALL_DEFINE1(ft_wait, int __user *, status)
{
	// testing stuff
	// current->state = TASK_INTERRUPTIBLE;

	DECLARE_WAIT_QUEUE_HEAD(my_wait_queue);


	// wait_event_interruptible(my_wait_queue, condition_check());
	// printk("wait_event return\n");
	// schedule();

	struct wait_queue_entry wait;
	init_waitqueue_entry(&wait, current);
	current->state = TASK_INTERRUPTIBLE;
	add_wait_queue(&my_wait_queue,&wait); /* wq points to the wait queue head */
	schedule();
	int i = 0;
	while (i++ < 62420)
	{
		// check children here
		printk("tick i %d\n", i);
	}
	wake_up(&my_wait_queue);
	remove_wait_queue(&my_wait_queue, &wait);



	// set current state to sleep

	// start loop 
		// check if current state changed

		// iterate children to check if any of them return (change state to exit zombie)

		// if one of them does, change child state to exit dead and return status code
	printk("queue return, kernel pid %d\n", current->pid);
	return 0;
}