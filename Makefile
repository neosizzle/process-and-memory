KERNEL_VER = $(shell uname -r)

all :
	@echo "copying files " ${KERNEL_VER}
	# @cp -R sys_get_pid_info 