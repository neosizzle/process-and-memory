#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define SYSCALL_NUM 333

struct pid_info
{
	long     pid;
	int     state;
	void*   process_stack;
	long    age;
	long*   children;
	long	parent_pid;
	char*	root;
	char*	pwd;
};

long sys_get_pid_info(struct pid_info *ret, int pid)
{
	return syscall(333, ret, pid);
}

int main()
{
	long pid;

	// read from input
	printf("Type a pid: \n");
	scanf("%ld", &pid);

	printf("PID entered is %ld\n", pid);

	// read from /proc/pid stat
	char *path = (char *)malloc(69420);
	sprintf(path, "/proc/%ld/stat", pid);

	// read from stat
	// int fd = open(path, O_RDONLY);
	// if (read(fd, )) 

	// long int amma = syscall(333);
	// printf("System call test0 returned %ld\n", amma);
	// if (amma == -1)
	// {
	// printf("errmsg %s \n", strerror(errno));
	// }
	free(path);
	return 0;
}