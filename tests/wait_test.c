#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <unistd.h>
 #include <signal.h>
int main(int argc, char const *argv[])
{
	int gay;

	int ppid = getpid();
	int pid = fork();

	if (!pid)
	{
		// while (1){}
		exit(69);
	}
	else
	{
		printf("syscall begin pid %d\n", getpid());
		syscall(353, &gay);
		printf("syscall over\n");
	}
	return 0;
}
