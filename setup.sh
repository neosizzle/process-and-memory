ver=$(uname -r)
cp -r sys_get_pid_info/ /usr/src/kernel-$ver/linux-$ver/
echo "666	common	get_pid_info	sys_get_pid_info" >> /usr/src/kernel-$ver/linux-$ver/arch/x86/entry/syscalls/syscall_64.tbl
echo "asmlinkage long sys_get_pid_info();" >> /usr/src/kernel-$ver/linux-$ver/include/linux/syscalls.h
# edit makefile here??