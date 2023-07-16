#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/timekeeping.h>
#include <linux/slab.h>
#include <linux/string.h>

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


/**
 * Module Init. Registers a USB device and creates a misc device in /dev/ft_module_keyboard
*/
int init_module(void)
{
	
	return 0;
}

void cleanup_module(void)
{

	
}

MODULE_LICENSE("GPL");