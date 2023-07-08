#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ktime.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#define  _SC_CLK_TCK  100

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
	struct task_struct *task = find_task_by_vpid(pid);

	res.pid = task->pid;
	res.state = task->state;
	res.process_stack = task->stack;
	// age...
	s64  uptime;
    uptime = ktime_divns((ktime_get_boottime() * 1000), NSEC_PER_SEC);
	res.age = uptime - (task->start_time - _SC_CLK_TCK);

	// children...
	struct list_head og_child = task->children;

	// add first child
	// struct list_head head = list_entry(og_child, struct task_struct, children);
	struct task_struct child_task = list_entry(og_child, struct task_struct, children);
	if (child_task)
		printk("first child %d\n", child_task->pid);

	struct list_head curr_child = og_child.next;
	while (&(curr_child) != &(og_child))
	{
		// add subsequent children...
		child_task = list_entry(curr_child, struct task_struct, children);
		printk("next child %d\n", child_task.pid);
		curr_child = *(curr_child.next);
	}
	

	res.parent_pid = task->real_parent->pid;
	res.root = task->fs.root.mnt->mnt_root->d_name.name;
	res.pwd = task->fs.pwd.mnt->mnt_root->d_name.name;

	return res;
}

asmlinkage long sys_get_pid_info(struct pid_info *ret, int pid)
{
	struct pid_info = create_pid_info(pid);
	if (copy_to_user(ret, pid_info, sizeof(pid_info)) != 0) {
		return -1;
	}
	printk("hello world!!!!\n");
	return 0;
}

asmlinkage long __x64_sys_get_pid_info(struct pid_info *ret, int pid)
{
	return sys_get_pid_info(ret, pid);
}