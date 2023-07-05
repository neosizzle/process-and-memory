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
	@echo "📇  Copying sources sys_get_pid_info/.."
	@cp -R sys_get_pid_info /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/
	@echo "📇  Copying syscall_64.tbl.."
	@cp syscall_64.tbl /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/arch/x86/entry/syscalls/syscall_64.tbl
	@echo "📇  Copying syscalls.h.."
	@cp syscalls.h /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/include/linux/syscalls.h
	@echo "📇  Copying Makefile .."
	@cp kernel.Makefile /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/Makefile
	@echo "📇  Compiling /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/.."
	@make -C /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/
	@echo "📇  Replacing kernel and reinstalling bootloader.."
	@cp /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/arch/x86/boot/bzImage /boot/vmlinuz-6.1.11-jng
	@grub-install /dev/sda

test :
	@echo "📇  Descending to /tests.."
	@make -C tests

clean : 
	@make -C /usr/src/kernel-$(KERNEL_VER)/linux-$(KERNEL_VER)/ clean