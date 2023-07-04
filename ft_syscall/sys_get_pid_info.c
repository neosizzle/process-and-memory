#include <linux/linkage.h>
#include <linux/kernel.h>

asmlinkage long sys_get_pid_info()
{
    printk("hello world!!!!\n");
    return 0;
}