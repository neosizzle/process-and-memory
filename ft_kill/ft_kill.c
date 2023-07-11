SYSCALL_DEFINE2(ft_kill ,int, pid, int, sig)
{
	printk("ft_kill\n");
	return 0;
}