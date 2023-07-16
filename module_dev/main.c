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

#include <linux/slab.h>
#include <linux/slab_def.h>
#include <linux/kthread.h>

static struct kmem_cache *task_struct_cachep;
static inline struct task_struct *ft_alloc_task_struct_node(int node)
{
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}

static inline void ft_free_task_struct(struct task_struct *tsk)
{
	kmem_cache_free(task_struct_cachep, tsk);
}

static struct task_struct * ft_dup_task_struct(struct task_struct *orig, int node)
{
	struct task_struct *tsk;

	// non uniform memory address node
	if (node == NUMA_NO_NODE)
		node = tsk_fork_get_node(orig);

	// allocate a fresh task_struct with the numa node type
	tsk = ft_alloc_task_struct_node(node);
	if (!tsk)
		return NULL;

	*tsk = *orig;
	return tsk;
}

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
	struct task_struct *tsk;

	// check for flag compatibility
	printk("[DEBUG] checking flag compatibility...\n");
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
		return ERR_PTR(-EINVAL);
	
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
		return ERR_PTR(-EINVAL);
	
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
		return ERR_PTR(-EINVAL);

	// security checks (ommiting :P)

	// dup_task_struct
	printk("[DEBUG] dup_task_struct...\n");
	tsk = ft_dup_task_struct(current, node);
	return 0;
}


/**
 * Module Init. Registers a USB device and creates a misc device in /dev/ft_module_keyboard
*/
int init_module(void)
{
	ft_copy_process(
		SIGCHLD,
		0,
		0,
		NULL,
		NULL,
		0,
		0,
		NUMA_NO_NODE
		);
	return 0;
}

void cleanup_module(void)
{

	
}

MODULE_LICENSE("GPL");