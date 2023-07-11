#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

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

SYSCALL_DEFINE2(ft_kill, long, pid, int, sig)
{
	printk("ft_kill %ld, %d\n", pid, sig);
	// struct siginfo info;
	// struct task_struct *task = find_task_by_vpid(pid);

	// info.si_signo = sig;
	// info.si_errno = 0;
	// info.si_code = SI_USER;

	// return send_sig_info(sig, &info, task);
	return 0;
}