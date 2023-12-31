#include <stdio.h>
#include <stdlib.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/sysinfo.h>

#include "libft.h"

#define SYSCALL_NUM 333

struct pid_info
{
	long     pid;
	long     state;
	long   process_stack;
	long    age;
	long*   children;
	long	parent_pid;
	char*	root;
	char*	pwd;
};

long get_pid_info(struct pid_info *ret, int pid)
{
	return syscall(333, ret, pid);
}

long get_uptime() {
    FILE* file = fopen("/proc/uptime", "r");
    if (file == NULL) {
        perror("fopen");
        exit(1);
    }
    
    double uptime;
    fscanf(file, "%lf", &uptime);
    fclose(file);
    
    return (long)uptime;
}

void read_from_syscall(long pid, int iterate_parent_and_children)
{
	struct pid_info* pidinfo = (struct pid_info*) malloc(sizeof(struct pid_info));
	pidinfo->pid =  0;
	pidinfo->root = ft_calloc(1024, 1);
	pidinfo->pwd = ft_calloc(1024, 1);
	pidinfo->children = ft_calloc(1024, sizeof(long));

	if (pid == 0)
	{
		printf("You have reached the kernel!!!\n");
		return ;
	}

	long syscall_ret = get_pid_info(pidinfo, pid);
	if (syscall_ret < 0)
		printf("syscall error diu %s\n", strerror(errno));

	if (!pidinfo->pid)
	{
		printf("No process found\n");
		return;
	}

	// state conversion
	char *state;
	if (pidinfo->state == 0)
		state = ft_strdup("Runnable");
	else if (pidinfo->state < 0)
		state = ft_strdup("Unrunnable");
	else
		state = ft_strdup("Stopped");

	printf("pid_str, %ld\nstate_str, %s\nppid, %ld\nage, %ld\nstack, %ld\nroot, %s\ncwd, %s\n",
		pidinfo->pid,
		state,
		pidinfo->parent_pid,
		pidinfo->age,
		pidinfo->process_stack,
		pidinfo->root,
		pidinfo->pwd
	);

	// printf("IM GONNA DEREFRENCE: %ld\n", pidinfo->process_stack);
	// printf("%c\n", (char)(*((char *)pidinfo->process_stack)));

	// print children
	printf("children,\n");
	int child_i = -1;
	while (pidinfo->children[++child_i])
	{
		printf("%ld\n",pidinfo->children[child_i]);
	}

	// todo implement children iteration
	if (iterate_parent_and_children)
	{
		printf("\n========PARENT========\n");
		read_from_syscall(pidinfo->parent_pid, 0);

		int child_i = -1;
		while (pidinfo->children[++child_i])
		{
			printf("\n========CHILD========\n");
			read_from_syscall(pidinfo->children[child_i], 0);
		}
	}	
}

void read_from_vfs(long pid, int iterate_parent_and_children)
{

	// check pid 0
	if (pid == 0)
	{
		printf("You have reached the kernel!!\n");
		return ;
	}

	// read from /proc/pid stat
	char *path = (char *)malloc(69420);
	sprintf(path, "/proc/%ld/stat", pid);

	// read from stat
	char *stat_str = (char *)malloc(69420);
	long fd = open(path, O_RDONLY);
	if (fd < 0)
	{
		printf("open error diu %s\n", strerror(errno));
		if (errno == ENOENT)
			printf("No process found\n");
		free(stat_str);
		free(path);
		return ;
	}
	if (read(fd, stat_str, 69419) < 0)
		printf("read error diu %s\n", strerror(errno));

	char **stat = ft_split(stat_str, ' ');

	// extract available info
	char*	pid_str = stat[0];
	char*	state_str = stat[2];
	char*	ppid_str = stat[3];
	char*	age_str = stat[21]; // should divide sysconf(_SC_CLK_TCK) and minus curr time
	char*	stack_str = stat[27];
	
	// age math
	long age = ft_atoi(age_str);
	long time = get_uptime() - (age / sysconf(_SC_CLK_TCK));

	// state conversion
	char *state;
	if (ft_strcmp(state_str, "R"))
		state = ft_strdup("Stopped");
	else if (ft_strcmp(state_str, "D"))
		state = ft_strdup("Runnable");
	else
		state = ft_strdup("Unrunnable");

	printf("pid_str, %s\nstate_str, %s\nppid, %s\nage, %ld\nstack, %s\n",
	pid_str,
	state,
	ppid_str,
	time,
	stack_str
	);

	// read from /proc/pid/root to get root pwd
	sprintf(path, "/proc/%ld/root", pid);
	char*	root_str = ft_calloc(1234, 1);
	if (readlink(path, root_str, 123) < 0)
		printf("rl error diu %s\n", strerror(errno));
	printf("root, %s\n", root_str);

	// read from /proc/pid/cwd to get cwd
	sprintf(path, "/proc/%ld/cwd", pid);
	char*	cwd_str = ft_calloc(1234, 1);
	if (readlink(path, cwd_str, 1200) < 0)
		printf("rl error diu %s\n", strerror(errno));
	printf("cwd, %s\n", cwd_str);

	// gonna do pgrep now 
	char *children_str = ft_calloc(1234, 1);
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
		wait(0);
		close(my_pipe[pipe_in]);
		read(my_pipe[pipe_out], children_str, 1233);
		close(my_pipe[pipe_out]);
		printf("children, \n%s\n", children_str);
		if (iterate_parent_and_children)
		{
			printf("\n========PARENT========\n");
			read_from_vfs(ft_atoi(ppid_str), 0);

			char **children_pids_str = ft_split(children_str, '\n');
			int children_idx = -1;
			while (children_pids_str[++children_idx])
			{
				printf("\n========CHILD========\n");
				read_from_vfs(ft_atoi(children_pids_str[children_idx]), 0);
			}
			
		}
	}

	free(stat);
	free(stat_str);
	free(path);
}

int main(int argc)
{
	long pid;
	int iterate_parent_and_children;

	if (argc >= 2)
		iterate_parent_and_children = 1;
	else
		iterate_parent_and_children = 0;

	// read from input
	printf("Type a pid: \n");
	scanf("%ld", &pid);

	printf("PID entered is %ld\n", pid);
	printf("\n=====================\n");
	printf("\n======USERSPACE======\n");
	printf("\n=====================\n");
	read_from_vfs(pid, iterate_parent_and_children);


	printf("\n=======================\n");
	printf("\n======KERNELSPACE======\n");
	printf("\n=======================\n");
	read_from_syscall(pid, iterate_parent_and_children);

	return 0;
}