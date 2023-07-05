#include <stdio.h>
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main()
{
	long int amma = syscall(332);
	printf("System call  test1 returned %ld\n", amma);
	if (amma == -1)
	{
	printf("errmsg %s \n", strerror(errno));
	}
	return 0;
}