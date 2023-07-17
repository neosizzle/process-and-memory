#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/wait.h>
#include <linux/signal_types.h>
#include <linux/pid.h>
#include <linux/completion.h>
#include <linux/freezer.h>
#include <linux/slab.h>
#include <linux/slab_def.h>
#include <linux/kthread.h>
#include <linux/user-return-notifier.h>
#include <linux/gfp.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/cred.h>
#include <linux/delayacct.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/signal.h>
#include <linux/sched/cputime.h>
#include <linux/cgroup.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/timekeeping.h>
#include <linux/perf_event.h>
#include <linux/audit.h>
#include <linux/tsacct_kern.h>
#include <linux/shm.h>
#include <linux/sem.h>
#include <linux/nsproxy.h>
#include <linux/ptrace.h>
#include <linux/latencytop.h>

void ft_proc_caches_init(void);
int copy_files(unsigned long clone_flags, struct task_struct *tsk);
int copy_fs(unsigned long clone_flags, struct task_struct *tsk);
int copy_sighand(unsigned long clone_flags, struct task_struct *tsk);
int copy_mm(unsigned long clone_flags, struct task_struct *tsk);
int copy_io(unsigned long clone_flags, struct task_struct *tsk);

// use kernel/fork.c variables
extern unsigned long total_forks;	/* Handle normal Linux uptimes. */
extern int nr_threads;			/* The idle threads do not count.. */

extern int max_threads;		/* tunable limit on nr_threads */

static struct kmem_cache *task_struct_cachep;

// allocate raw memory for task_struct
static inline struct task_struct *ft_alloc_task_struct_node(int node)
{
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}

static inline void ft_free_task_struct(struct task_struct *tsk)
{
	kmem_cache_free(task_struct_cachep, tsk);
}
 
// no idea - allocate new stack for kernel thread
static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
{
	struct page *page = alloc_pages_node(node, THREADINFO_GFP,
					     THREAD_SIZE_ORDER);

	return page ? page_address(page) : NULL;
}

// change page state counters 
static void account_kernel_stack(struct task_struct *tsk, int account)
{
	void *stack = task_stack_page(tsk);
	struct vm_struct *vm = task_stack_vm_area(tsk);

	if (vm) {
		int i;

		BUG_ON(vm->nr_pages != THREAD_SIZE / PAGE_SIZE);

		for (i = 0; i < THREAD_SIZE / PAGE_SIZE; i++) {
			mod_zone_page_state(page_zone(vm->pages[i]),
					    NR_KERNEL_STACK_KB,
					    PAGE_SIZE / 1024 * account);
		}

		/* All stack pages belong to the same memcg. */
		mod_memcg_page_state(vm->pages[0], MEMCG_KERNEL_STACK_KB,
				     account * (THREAD_SIZE / 1024));
	} else {
		/*
		 * All stack pages are in the same zone and belong to the
		 * same memcg.
		 */
		struct page *first_page = virt_to_page(stack);

		mod_zone_page_state(page_zone(first_page), NR_KERNEL_STACK_KB,
				    THREAD_SIZE / 1024 * account);

		mod_memcg_page_state(first_page, MEMCG_KERNEL_STACK_KB,
				     account * (THREAD_SIZE / 1024));
	}
}

static struct task_struct * ft_dup_task_struct(struct task_struct *orig, int node)
{
	struct task_struct *tsk;
	unsigned long *stack;
	struct vm_struct *stack_vm_area;

	// non uniform memory address node
	if (node == NUMA_NO_NODE)
		node = tsk_fork_get_node(orig);

	// allocate a fresh task_struct with the numa node type
	tsk = ft_alloc_task_struct_node(node);
	if (!(tsk = ft_alloc_task_struct_node(node)))
	{
		printk("[ERROR] ft_alloc_task_struct_node failed\n");
		return NULL;
	}

	// allocate new stack for kernel thread
	if ((stack = alloc_thread_stack_node(tsk, node)) == NULL)
	{
		printk("[ERROR] alloc_thread_stack_node failed\n");
		return NULL;
	}

	// get the childs vm area ? should be stuff inside
	// preconfigured ig  
	stack_vm_area = task_stack_vm_area(tsk);

	*tsk = *orig;
	
	// reassign stacks
	tsk->stack = stack;
	// tsk->stack_vm_area = stack_vm_area; // CONFIG_VMAP_STACK

	// configures stack
	setup_thread_stack(tsk, orig);

	// clear 'notify kernel of userspace return' flag
	clear_user_return_notifier(tsk);

	// clear 'rescheduling necessary' flag
	clear_tsk_need_resched(tsk);

	// set the tasks stack end magic number to be valid
	set_task_stack_end_magic(tsk);

	// set tsk->usage to 2 to spicify that the descriptor is in use
	// and that the process is alive
	atomic_set(&tsk->usage, 2);

	// init some variables to NULL (pipe variables?)
	tsk->splice_pipe = NULL;
	tsk->task_frag.page = NULL;
	tsk->wake_q.next = NULL;

	// modify page state coutners
	account_kernel_stack(tsk, 1);

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
	struct task_struct *p;

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
	p = ft_dup_task_struct(current, node);
	if (!p)
	{
		printk("[ERROR] dup_task_struct fail...\n");
		return 0;
	}

	// set up function tracing graph
	ftrace_graph_init_task(p);

	// initialize real-time mutexes
	raw_spin_lock_init(&p->pi_lock);
	p->pi_waiters = RB_ROOT_CACHED;
	p->pi_top_task = NULL;
	p->pi_blocked_on = NULL;

	// check if task had reached processor limit for user
	if (atomic_read(&p->real_cred->user->processes) >=
				task_rlimit(p, 1024)) {
		if (p->real_cred->user != INIT_USER &&
			!capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))
		{
			printk("[ERROR] Max processes reached and user is not root.");
			return 0;
		}
		}
	
	// update parent flags about number of forks
	current->flags &= ~PF_NPROC_EXCEEDED;

	// copy user and group credentials
	if (copy_creds(p, clone_flags) < 0)
	{
		printk("[ERROR] copy_creds failed.");
		return 0;
	}

	// check threads
	if (nr_threads >= max_threads)
	{
		printk("[ERROR] nr_threads >= max_threads.");
		return 0;
	}

	// initialize delay accounting
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */

	// set some flags and initialize children and sibling lists
	p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER | PF_IDLE);
	p->flags |= PF_FORKNOEXEC;
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);

	// set vfork_done property
	// set time values to 0
	// init allocation lock
	// init pending signals list
	p->vfork_done = NULL;
	p->utime = p->stime = p->gtime = 0;
	spin_lock_init(&p->alloc_lock);
	init_sigpending(&p->pending);

	// init cputime (?)
	prev_cputime_init(&p->prev_cputime);

	// default_timer_slack_ns -> rounding of timeout values in syscalls
	// select() poll() nanosleep()
	p->default_timer_slack_ns = current->timer_slack_ns;

	// io accounting
	task_io_accounting_init(&p->ioac);
	acct_clear_integrals(p);

	// cpu timers init
	p->cputime_expires.prof_exp = 0;
	p->cputime_expires.virt_exp = 0;
	p->cputime_expires.sched_exp = 0;
	INIT_LIST_HEAD(&p->cpu_timers[0]);
	INIT_LIST_HEAD(&p->cpu_timers[1]);
	INIT_LIST_HEAD(&p->cpu_timers[2]);

	// set cpu times
	p->start_time = ktime_get_ns();
	p->real_start_time = ktime_get_boot_ns();

	// set vm states
	p->io_context = NULL;
	p->audit_context = NULL;

	// cgroup
	cgroup_fork(p);

	// enable pagefaults
	p->pagefault_disabled = 0;

	// scheduler setup, cpu assignation
	if (sched_fork(clone_flags, p))
	{
		printk("[ERROR] sched_fork failed.");
		return 0;
	}

	// performance event
	if (perf_event_init_task(p))
	{
		printk("[ERROR] perf_event_init_task failed.");
		return 0;
	}

	// alloc autidting
	if (audit_alloc(p))
	{
		printk("[ERROR] audit_alloc failed.");
		return 0;
	}

	// initialize shared memory managment
	shm_init_task(p);

	// init copy chackes first
	ft_proc_caches_init();

	// copy process information
	if (copy_semundo(clone_flags, p))
	{
		printk("[ERROR] copy_semundo failed.");
		return 0;
	}
	if (copy_files(clone_flags, p))
	{
		printk("[ERROR] copy_files failed.");
		return 0;
	}
	if (copy_fs(clone_flags, p))
	{
		printk("[ERROR] copy_fs failed.");
		return 0;
	}
	if (copy_sighand(clone_flags, p))
	{
		printk("[ERROR] copy_sighand failed.");
		return 0;
	}
	if (copy_signal(clone_flags, p))
	{
		printk("[ERROR] copy_signal failed.");
		return 0;
	}
	if (copy_mm(clone_flags, p))
	{
		printk("[ERROR] copy_mm failed.");
		return 0;
	}
	if (copy_namespaces(clone_flags, p))
	{
		printk("[ERROR] copy_namespaces failed.");
		return 0;
	}
	if (copy_io(clone_flags, p))
	{
		printk("[ERROR] copy_io failed.");
		return 0;
	}
	if (copy_thread_tls(clone_flags, p))
	{
		printk("[ERROR] copy_thread_tls failed.");
		return 0;
	}
	
	// allocate a pid struct if there is none
	if (!pid)
		pid = alloc_pid(p->nsproxy->pid_ns_for_children);
	
	// if pid is error
	if (IS_ERR(pid))
	{
		printk("[ERROR] alloc_pid failed.");
		return 0;
	}

	// set some other properties..
	p->robust_list = NULL; // robust futexes
	INIT_LIST_HEAD(&p->pi_state_list);
	p->pi_state_cache = NULL;

	// sigaltstack should be cleared when sharing the same VM
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
		sas_ss_reset(p);

	// Syscall tracing and stepping should be turned off in the
	// child regardless of CLONE_PTRACE.
	user_disable_single_step(p);
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);

	clear_all_latency_tracing(p);

	// set pid to the one we created, or in the args
	p->pid = pid_nr(pid);
	printk("child pid %d\n". p->pid);

	return 0;
}

static int wait_for_vfork_done(struct task_struct *child,
				struct completion *vfork)
{
	int killed;

	freezer_do_not_count();
	killed = wait_for_completion_killable(vfork);
	freezer_count();

	if (killed) {
		task_lock(child);
		child->vfork_done = NULL;
		task_unlock(child);
	}

	put_task_struct(child);
	return killed;
}

long ft_do_fork(
	unsigned long clone_flags,
	unsigned long stack_start,
	unsigned long stack_size,
	int __user *parent_tidptr,
	int __user *child_tidptr,
	unsigned long tls
)
{
	int trace_child;
	struct task_struct *child;
	struct siginfo info;
	long child_pid;
	struct pid *child_pid_struct;
	struct completion vfork;

	trace_child = 0;
	// allocated new PID (not needed, copy_process() did it for us (?))

	// check ptrace of current process
	if (current->ptrace)
	{
		// if not 0, check CLONE_PTRACE flag to determine
		if (clone_flags & CLONE_PTRACE)
		{
			// if child would be traced or not
			printk("[DEBUG] setting trace_child to 1\n");
			trace_child = PTRACE_EVENT_FORK;
		}
	}

	// call copy_process(), the returning task_struct is the new child struct
	child = ft_copy_process(clone_flags, stack_start, stack_size,
		child_tidptr, NULL, trace_child, tls, NUMA_NO_NODE);

	if (!child)
	{
		printk("[ERROR] copy_process failed \n");
		return -1;
	}

	// if clone_stopped set (not in 4.17) or child process is traced
	if (trace_child)
	{
		printk("[DEBUG] trace child, sending stop signal\n");
		// set child status to TASK_STOPPED and send pending SIGSTOP signal to it
		child->state = TASK_STOPPED;

		info.si_signo = SIGSTOP;
		info.si_errno = 0;
		info.si_code = SI_KERNEL;
		send_sig_info(SIGSTOP, &info, child);
	}
	else
	{
		printk("[DEBUG] wake_up_new_task\n");
		// else, call wake_up_new_task()		
		wake_up_new_task(child);
	}
	
	child_pid_struct = get_task_pid(child, PIDTYPE_PID);
	child_pid = pid_vnr(child_pid_struct);

	// cnofigure vfork options
	if (clone_flags & CLONE_VFORK) {
		printk("[DEBUG] configuring vfork.. \n");
		child->vfork_done = &vfork;
		init_completion(&vfork);
		get_task_struct(child);
	}

	// if parent is traced, store PID of child in current ptrace->message and call
	// ptrace_notify() (ptrace_event_pid()) for 4.17?
	if (current->ptrace)
	{
		printk("[DEBUG] sending ptrace event to parent \n");
		current->ptrace_message = child_pid;
		ptrace_event_pid(trace_child, child_pid_struct);
	}

	// if  CLONE_VFORK flag is set, insert parent in waitqueue and suspend it until child
	if (clone_flags & CLONE_VFORK) {
			printk("[DEBUG] waiting for vfork done \n");
		// releases its address space (terminate or execve)
		if (!wait_for_vfork_done(child, &vfork))
			ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, child_pid_struct);
	}

	printk("[DEBUG] returning child pid... \n");
	return child_pid;
}

static void task_struct_whitelist(unsigned long *offset, unsigned long *size)
{
	/* Fetch thread_struct whitelist for the architecture. */
	arch_thread_struct_whitelist(offset, size);

	/*
	 * Handle zero-sized whitelist or empty thread_struct, otherwise
	 * adjust offset to position of thread_struct in task_struct.
	 */
	if (unlikely(*size == 0))
		*offset = 0;
	else
		*offset += offsetof(struct task_struct, thread);
}

void init_globals(void)
{
	if (!task_struct_cachep)
	{
		int align = max_t(int, L1_CACHE_BYTES, ARCH_MIN_TASKALIGN);
		unsigned long useroffset, usersize;

		/* create a slab on which task_structs can be allocated */
		task_struct_whitelist(&useroffset, &usersize);
		task_struct_cachep = kmem_cache_create_usercopy("task_struct",
				arch_task_struct_size, align,
				SLAB_PANIC|SLAB_ACCOUNT,
				useroffset, usersize, NULL);
	}
}

SYSCALL_DEFINE0(ft_fork)
{
	// initializes globals
	init_globals();

	// do actual forking
	return ft_do_fork(
		SIGCHLD,
		0,
		0,
		NULL,
		NULL,
		0
	);
}