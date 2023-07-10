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

struct pid_info
{
	long     pid;
	long     state;
	long   process_stack;
	long    age;
	long*   children;
	long	parent_pid;
	const char*	root;
	const char*	pwd;
};

static long get_uptime(void)
{
	struct timespec uptime;
	get_monotonic_boottime(&uptime);
	return uptime.tv_sec;
}

static void walk_to_root(struct dentry *entry)
{
	int walk = 0;
	char *res = kmalloc(1234, GFP_KERNEL);
	res[0] = '/';
	res[1] = 0;

	while (entry)
	{
		char *curr_dir_name = entry->d_name.name;
		// printk("strcmp(%s, /) = %d\n",curr_dir_name, strcmp(curr_dir_name, "/"));
		if (strcmp(curr_dir_name, "/") == 0)
			break;
		strcat(res, curr_dir_name);
		entry = entry->d_parent;
		++walk;
	}
	printk("res %s\n", res);
}

static struct pid_info *create_pid_info(int pid)
{
	struct pid_info *res;
	struct task_struct *task = pid_task(find_get_pid(pid), PIDTYPE_PID);
	struct task_struct *child_task;
	int children_length;
	int i;
	long *children;

	res = kmalloc(sizeof(struct pid_info), GFP_USER);
	res->pid = task->pid;
	res->state = task->state;
	res->process_stack = task->mm->start_stack;
	res->parent_pid = task->real_parent->pid;
	res->root = task->fs->root.dentry->d_name.name;
	res->pwd = task->fs->pwd.dentry->d_name.name;
	walk_to_root(task->fs->pwd.dentry);

	// age
	res->age = get_uptime() - ((task->real_start_time / 10000000) / (HZ / 10));
	
	// children
	children_length = 0;
	i = 0;
	list_for_each_entry(child_task, &task->children, sibling) {
   		// printk(KERN_INFO "Child PID: %d\n", child_task->pid);
		++children_length;
	}

	children = kmalloc(sizeof(long) * (children_length + 1), GFP_KERNEL);

	list_for_each_entry(child_task, &task->children, sibling) {
   		children[i++] = child_task->pid;
	}
	children[i] = 0;
	res->children = children;

	return res;
}

/**
 * Module Init. Registers a USB device and creates a misc device in /dev/ft_module_keyboard
*/
int init_module(void)
{
	printk("currpid %d\n\n", 2278);
	struct pid_info * pidinfo = create_pid_info(2278);
	printk("pid_str, %d\nstate_str, %d\nppid, %d\nage, %ld\nstack, %ld\ncwd, %s\n",
	pidinfo->pid,
	pidinfo->state,
	pidinfo->parent_pid,
	pidinfo->age,
	pidinfo->process_stack,
	pidinfo->pwd
	);
	return 0;
}

void cleanup_module(void)
{

	
}

MODULE_LICENSE("GPL");