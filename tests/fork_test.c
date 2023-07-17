#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <unistd.h>
 #include <signal.h>

int main(int argc, char const *argv[])
{
	int pid = syscall(363);
	printf("[USER] fork return %d\n", pid);
	return 0;
}
