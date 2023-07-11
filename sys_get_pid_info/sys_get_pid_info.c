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
#include <linux/string.h>

#define  _SC_CLK_TCK  100

// struct pid_info
// {
// 	long     pid;
// 	long     state;
// 	long   process_stack;
// 	long    age;
// 	long*   children;
// 	long	parent_pid;
// 	const char*	root;
// 	const char*	pwd;
// };

/**
 * len_long - counts number of elements in array with null at the end
*/
static int len_long(long *arr)
{
	int res;

	res = -1;
	while (arr[++res])
	{}

	return res;
}

/**
 * get_uptime - returns boottime in seconds
*/
static long get_uptime(void)
{
	struct timespec uptime;
	get_monotonic_boottime(&uptime);
	return uptime.tv_sec;
}

static char	*ft_strdup(const char *s1)
{
	char	*dest;
	int		s1_len;
	int		i;

	s1_len = 0;
	while (s1[s1_len])
		s1_len++;
	if (!(dest = (char *)kmalloc(sizeof(char) * (s1_len + 1), GFP_KERNEL)))
		return (NULL);
	i = 0;
	while (i < s1_len)
	{
		dest[i] = s1[i];
		i++;
	}
	dest[i] = '\0';
	return (dest);
}

static char *walk_to_root(struct dentry *entry)
{
	int walk = 0;
	char *temp = kmalloc(1, GFP_KERNEL);
	temp[0] = 0;
	char *res;

	while (entry)
	{
		char *curr_dir_name = entry->d_name.name;
		if (strcmp(curr_dir_name, "/") == 0)
			break;
		res = kmalloc(strlen(curr_dir_name) + strlen(temp) + 2, GFP_KERNEL);
		strcpy(res, curr_dir_name);
		if (walk)
			strcat(res, "/");
		else
			++walk;
		strcat(res, temp);
		kfree(temp);
		temp = ft_strdup(res);
		entry = entry->d_parent;
		++walk;
	}
	res = kmalloc(strlen(temp) + 2, GFP_KERNEL);
	strcpy(res, "/");
	strcat(res, temp);
	kfree(temp);
	return res;
}


static struct pid_info create_pid_info(int pid)
{
	struct pid_info res;
	struct task_struct *task = find_task_by_vpid(pid);
	struct task_struct *child_task;
	int children_length;
	int i;
	long *children;

	printk("[DEBUG] createpidinfo 0\n");
	// res = kmalloc(sizeof(struct pid_info), GFP_USER);
	if (!task || !task->pid)
	{
		printk("[DEBUG] cant find task? \n");
		res.pid = 0;
		res.children = kmalloc(sizeof(long) * (1), GFP_USER);
		res.children[0] = 0;
		res.root = "";
		res.pwd = "";

		return res;
	}
	res.pid = task->pid;
	res.state = task->state;
	res.process_stack = task->mm->start_stack;
	res.parent_pid = task->real_parent->pid;
	res.root = task->fs->root.dentry->d_name.name;
	res.pwd = walk_to_root(task->fs->pwd.dentry);

	printk("[DEBUG] createpidinfo 1 \n");
	// age
	res.age = get_uptime() - ((task->real_start_time / 10000000) / (HZ / 10));
	
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

	// TODO copy everything
	if (copy_to_user(&(info->pid), &(res.pid), sizeof(long)) != 0)
		return -1;
	if (copy_to_user(&(info->state), &(res.state), sizeof(long)) != 0)
		return -1;
	if (copy_to_user(&(info->process_stack), &(res.process_stack), sizeof(long)) != 0) // fix this
		return -1;
	if (copy_to_user(&(info->age), &(res.age), sizeof(long)) != 0)
		return -1;
	if (copy_to_user(&(info->parent_pid), &(res.parent_pid), sizeof(long)) != 0)
		return -1;

	// copy strings
	if (copy_to_user(info->root, res.root, strlen(res.root)) != 0) // duplicate this
		return -1;
	if (copy_to_user(info->pwd, res.pwd, strlen(res.pwd)) != 0) // duplicate this
		return -1;

	// copy special
	if (copy_to_user(info->children, res.children, (len_long(res.children) + 1) * sizeof(long)) != 0) // duplicate this
		return -1;

	// printk("returning address %p\n", res);
	return 0;
}