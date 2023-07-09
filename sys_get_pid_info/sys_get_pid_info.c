#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/timekeeping.h>
#include <linux/slab.h>

#define  _SC_CLK_TCK  100

struct pid_info
{
	long     pid;
	long     state;
	void*   process_stack;
	long    age;
	long*   children;
	long	parent_pid;
	const char*	root;
	const char*	pwd;
};

static struct pid_info *create_pid_info(int pid)
{
	struct pid_info *res;
	struct task_struct *task = pid_task(find_get_pid(pid), PIDTYPE_PID);
	s64  uptime;
	struct task_struct *child_task;
	int children_length;
	int i;
	long *children;

	res = kmalloc(sizeof(struct pid_info), GFP_USER);
	res->pid = task->pid;
	res->state = task->state;
	res->process_stack = task->stack;
	res->parent_pid = task->real_parent->pid;
	res->root = task->fs->root.dentry->d_name.name;
	res->pwd = task->fs->pwd.dentry->d_name.name;

	// age
    uptime = ktime_divns((ktime_get_boottime() * 1000), NSEC_PER_SEC);
	res->age = uptime - (task->start_time - 100);
	
	// children
	children_length = 0;
	i = 0;
	list_for_each_entry(child_task, &task->children, sibling) {
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

asmlinkage long sys_get_pid_info(struct pid_info *ret, int pid)
{
	struct pid_info *res = create_pid_info(pid);
	// if (copy_to_user(ret, res, sizeof(struct pid_info)) != 0) {
	// 	return -1;
	// }
	printk("returning address %p\n", res);
	return 0;
}

asmlinkage long __x64_sys_get_pid_info(struct pid_info *ret, int pid)
{
	return sys_get_pid_info(ret, pid);
}