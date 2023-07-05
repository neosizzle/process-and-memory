KERNEL_VER = $(shell uname -r)

# Style constants
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[0;33m
BLUE=\033[0;34m
PURPLE=\033[0;35m
CYAN=\033[0;36m
NC=\033[0m # No Color

all :
	@echo "${GREEN}📇  Copying sources sys_get_pid_info/..${NC}"
	@cp -R sys_get_pid_info /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/
	@echo "${GREEN}📇  Copying syscall_64.tbl..${NC}"
	@cp syscall_64.tbl /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/arch/x86/entry/syscalls/syscall_64.tbl
	@echo "${GREEN}📇  Copying syscalls.h..${NC}"
	@cp syscalls.h /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/include/linux/syscalls.h
	@echo "${GREEN}📇  Copying Makefile ..${NC}"
	@cp kernel.Makefile /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/Makefile
	@echo "${GREEN}📇  Compiling /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/..${NC}"
	@make -C /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/
	@echo "${GREEN}📇  Replacing kernel and reinstalling bootloader.."
	@cp /paht/to/bzimage /boot/vmlinuz-6.1.11-jng
	@grub-install /dev/sda

test :
	@echo "${CYAN}📇  Descending to /tests..${NC}"
	@make -C tests

clean : 
	@make -C /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/ clean