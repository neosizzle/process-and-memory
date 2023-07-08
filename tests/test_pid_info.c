#include <stdio.h>
#include <stdlib.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "libft.h"

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

void read_from_vfs(long pid)
{
	// read from /proc/pid stat
	char *path = (char *)malloc(69420);
	sprintf(path, "/proc/%ld/stat", pid);

	// read from stat
	char *stat_str = (char *)malloc(69420);
	long fd = open(path, O_RDONLY);
	if (fd < 0)
	{
		printf("open error diu %s\n", strerror(errno));
		free(stat_str);
		free(path);
		return ;
	}
	if (read(fd, stat_str, 69419) < 0);
		printf("read error diu %s\n", strerror(errno));

	printf("stat is %s\n", stat_str);
	char **stat = ft_split(stat_str, ' ');

	// extract available info
	char*	pid_str = stat[0];
	char*	state_str = stat[2];
	char*	ppid_str = stat[3];
	char*	age_str = stat[21]; // should divide sysconf(_SC_CLK_TCK) and minus curr time
	char*	stack_str = stat[27];
	
	printf("pid_str, %s\nstate_str, %s\nppid, %s\nage, %s\nstack, %s\n",
	pid_str,
	state_str,
	ppid_str,
	age_str,
	stack_str
	);

	// read from /proc/pid/root to get root pwd
	sprintf(path, "/proc/%ld/root", pid);
	char*	root_str = malloc(1234);
	if (readlink(path, root_str, 1233) < 0)
		printf("rl error diu %s\n", strerror(errno));
	printf("root, %s\n", root_str);

	// read from /proc/pid/cwd to get cwd
	sprintf(path, "/proc/%ld/cwd", pid);
	char*	cwd_str = malloc(1234);
	if (readlink(path, cwd_str, 1233) < 0)
		printf("rl error diu %s\n", strerror(errno));
	printf("cwd, %s\n", cwd_str);

	// gonna do pgrep now 
	int my_pipe[2];
	int pipe_in = 1;
	int pipe_out = 0;
	pipe(my_pipe);
	char *const argv[] = {"/usr/bin/pgrep", "-P", pid_str, NULL};
	char *const envp[] = {NULL};
	int pgrp_pid = fork();
	if (pgrp_pid == 0)
	{
		dup2(my_pipe[pipe_in], STDOUT_FILENO);
		execve(argv[0], argv, envp);
	}
	else
	{
		wait();
		char *buf = malloc(1234);
		close(my_pipe[pipe_in]);
		read(my_pipe[pipe_out], buf, 1233);
		printf("children, \n%s\n", buf);
	}

	free(stat);
	free(stat_str);
	free(path);
}

int main()
{
	long pid;

	// read from input
	printf("Type a pid: \n");
	scanf("%ld", &pid);

	printf("PID entered is %ld\n", pid);
	read_from_vfs(pid);

	// long int amma = syscall(333);
	// printf("System call test0 returned %ld\n", amma);
	// if (amma == -1)
	// {
	// printf("errmsg %s \n", strerror(errno));
	// }
	return 0;
}