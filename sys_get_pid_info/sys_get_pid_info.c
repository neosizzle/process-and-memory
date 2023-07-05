#include <linux/linkage.h>
#include <linux/kernel.h>

asmlinkage long sys_get_pid_info(void)
{
    printk("hello world!!!!\n");
    return 0;
}

// asmlinkage long __x64_sys_get_pid_info(void)
// {
//     return sys_get_pid_info();
// }