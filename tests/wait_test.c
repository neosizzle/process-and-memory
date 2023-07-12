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
		return 2;
	}
	else
	{
		printf("syscall begin pid %d\n", getpid());
		syscall(353, &gay);
		printf("syscall over status %d\n". gay);
	}
	return 0;
}
