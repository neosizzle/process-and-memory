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
#include <linux/syscalls.h>

#define  _SC_CLK_TCK  100

// struct pid_info
// {
// 	long     pid;
// 	long     state;
// 	void*   process_stack;
// 	long    age;
// 	long*   children;
// 	long	parent_pid;
// 	const char*	root;
// 	const char*	pwd;
// };

static struct pid_info create_pid_info(int pid)
{
	struct pid_info res;
	struct task_struct *task = find_task_by_vpid(pid);
	s64  uptime;
	struct task_struct *child_task;
	int children_length;
	int i;
	long *children;

	printk("[DEBUG] createpidinfo 0\n");
	// res = kmalloc(sizeof(struct pid_info), GFP_USER);
	if (!task)
	{
		printk("[DEBUG] cant find task? \n");
		res.pid = 0;
		res.children = kmalloc(sizeof(long) * (1), GFP_USER);
		res.children[0] = 0;

		return res;
	}
	res.pid = task->pid;
	res.state = task->state;
	res.process_stack = task->stack;
	res.parent_pid = task->real_parent->pid;
	res.root = task->fs->root.dentry->d_name.name;
	res.pwd = task->fs->pwd.dentry->d_name.name;

	printk("[DEBUG] createpidinfo 1 \n");
	// age
    uptime = ktime_divns((ktime_get_boottime() * 1000), NSEC_PER_SEC);
	res.age = uptime - (task->start_time - 100);
	
	printk("[DEBUG] createpidinfo 2 \n");
	// children
	children_length = 0;
	i = 0;
	list_for_each_entry(child_task, &task->children, sibling) {
		++children_length;
	}

	children = kmalloc(sizeof(long) * (children_length + 1), GFP_USER);

	list_for_each_entry(child_task, &task->children, sibling) {
   		children[i++] = child_task->pid;
	}
	children[i] = 0;
	res.children = children;

	printk("[DEBUG] createpidinfo 3 \n");
	return res;
}

// long sys_get_pid_info(struct pid_info __user *ret, int pid)
// {
// 	struct pid_info *res = create_pid_info(pid);
// 	printk("[DEBUG] createpidinfo 4 \n");
// 	if (copy_to_user(ret, res, sizeof(struct pid_info)) != 0) {
// 		return -1;
// 	}
// 	printk("returning address %p\n", res);
// 	return 0;
// }


SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, info, int, pid)
{
	struct pid_info res = create_pid_info(pid);
	printk("[DEBUG] createpidinfo 4 \n");
	// if (copy_to_user(info, res, sizeof(struct pid_info)) != 0) {
	// 	return -1;
	// }

	if (copy_to_user(&(info->pid), &(res.pid), sizeof(long)) != 0) {
		return -1;
	}
	printk("returning address %p\n", res);
	return 0;
}