#include <linux/sched/signal.h>
#include <uapi/asm-generic/siginfo.h>
#include <linux/sched.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE2(ft_kill, long, pid, int, sig)
{
	printk("ft_kill\n");
	// struct siginfo info;
	// struct task_struct *task = find_task_by_vpid(pid);

	// info.si_signo = sig;
	// info.si_errno = 0;
	// info.si_code = SI_USER;

	// return send_sig_info(sig, &info, task);
	return 0;
}