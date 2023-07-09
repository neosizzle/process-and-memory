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
	res.parent_pid = task->real_parent->pid;
	res.root = task->fs->root.dentry->d_name.name;
	res.pwd = task->fs->pwd.dentry->d_name.name;

	// age
	s64  uptime;
    uptime = ktime_divns((ktime_get_boottime() * 1000), NSEC_PER_SEC);
	res.age = uptime - (task->start_time - 100);
	
	// children
	struct task_struct *child_task;
	int children_length;
	int i;

	children_length = 0;
	i = 0;
	long *children;
	list_for_each_entry(child_task, &task->children, sibling) {
   		printk(KERN_INFO "Child PID: %d\n", child_task->pid);
		++children_length;
	}
	children = kmalloc(sizeof(children_length + 1), GFP_USER);
	list_for_each_entry(child_task, &task->children, sibling) {
   		children[i++] = child_task->pid;
	}
	children[i] = NULL;
	res.children = children;

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