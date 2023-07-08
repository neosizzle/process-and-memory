#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/sched.h>

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
	// children...
	// parent pid... 
	
	res.root = task->fs->root.dentry->d_name.name;
	res.pwd = task->fs->pwd.dentry->d_name.name;

	return res;
}

asmlinkage long sys_get_pid_info(struct pid_info *ret, int pid)
{

	printk("hello world!!!!\n");
	return 0;
}

asmlinkage long __x64_sys_get_pid_info(struct pid_info *ret, int pid)
{
	return sys_get_pid_info(ret, pid);
}