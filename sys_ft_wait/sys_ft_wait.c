#include <linux/linkage.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE1(ft_wait, int __user *, status)
{
	printk("kernel pid %d\n", current->pid);
	unsigned long max = 	2147483647;
	while (1)
	{
	}
	
	return 0;
}