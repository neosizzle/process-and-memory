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

struct pid_info
{
	long     pid;
	long     state;
	void*   process_stack;
	long    age;
	long*   children;
	long	parent_pid;
	char*	root;
	char*	pwd;
};

static struct pid_info create_pid_info(int pid)
{
	struct pid_info res;
	struct task_struct *task = pid_task(find_get_pid(pid), PIDTYPE_PID);

	res.pid = task->pid;
	res.state = task->state;
	res.process_stack = task->stack;
	// age...
	s64  uptime;
    uptime = ktime_divns((ktime_get_boottime() * 1000), NSEC_PER_SEC);
	res.age = uptime - (task->start_time - 100);

	res.parent_pid = task->real_parent->pid;
	res.root = task->fs->root.dentry->d_name.name;
	res.pwd = task->fs->pwd.dentry->d_name.name;

	// children...
	struct list_head *og_child = &(task->children);

	// add first child
	// struct list_head head = list_entry(og_child, struct task_struct, children);
	struct task_struct *child_task = list_entry(og_child, struct task_struct, children);
	if (child_task == 0)
		return res;

	struct list_head *curr_child = og_child->next;
	while (curr_child != og_child)
	{
		// add subsequent children...
		child_task = list_entry(curr_child, struct task_struct, children);
		printk("next child %d\n", child_task->pid);
		curr_child = curr_child->next;
	}

	return res;
}

/**
 * Module Init. Registers a USB device and creates a misc device in /dev/ft_module_keyboard
*/
int init_module(void)
{
	printk("currpid %d\n\n", 1);
	struct pid_info res = create_pid_info(1);
	return 0;
}

void cleanup_module(void)
{

	
}

MODULE_LICENSE("GPL");