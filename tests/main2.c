#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

/**
 * 			A 		-> main process
 * 		B		C	
 * 	D
*/
int main(void) {
	printf("a_pid: %d\n", getpid());
	long b_pid = fork();

	if (!b_pid)
	{
		long d_pid = fork();
		if (!d_pid)
			while (1) {}
		else
		{
			printf("d_pid: %ld\n", d_pid);
			wait(0);
		}
		while (1) {}
	}
	else
	{
		printf("b_pid: %ld\n", b_pid);
		long c_pid = fork();
		if (!c_pid)
			while (1) {}
		else
		{
			printf("c_pid: %ld\n", c_pid);
			wait(0);
		}
		wait(0);
	}
}
