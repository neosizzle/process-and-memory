KERNEL_VER = $(shell uname -r)

all :
	@echo "copying files "
	@cp -R sys_get_pid_info /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/
	@echo "copying syscall table"
	@cp syscall_64.tbl /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/arch/x86/entry/syscalls/syscall_64.tbl
	@echo "copying header"
	@cp syscalls.h /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/include/linux/syscalls.h
	@echo "compiling kernel"
	@make -C /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/
