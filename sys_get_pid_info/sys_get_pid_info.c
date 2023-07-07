#include <linux/linkage.h>
#include <linux/kernel.h>

struct pid_info
{
	long     pid;
	int     state;
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