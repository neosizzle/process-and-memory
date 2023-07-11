#include "minitalk.h"

static t_message	g_message;

static void	init_message(void)
{
	g_message.byte = 0;
	g_message.offset = 0;
}

static void	handle_sig(int sig)
{
	int	bit;

	if (sig == SIGUSR1)
		bit = 1;
	else
		bit = 0;
	g_message.byte += (bit << g_message.offset);
	g_message.offset++;
	if (g_message.offset == 7)
	{
		write(1, &g_message.byte, 1);
		if (g_message.byte == '\0')
			write(1, "\n", 1);
		init_message();
	}
}

int	main(int argc, char *argv[])
{
	struct sigaction	sa;

	(void) argv;
	if (argc == 1)
	{
		write(1, "Server PID : ", 13);
		ft_putnbr_fd((int) getpid(), 1);
		write(1, "\n", 1);
		sa.sa_handler = handle_sig;
		sigaction(SIGUSR1, &sa, NULL);
		sigaction(SIGUSR2, &sa, NULL);
		while (1)
			pause();
	}
	else
		write(1, "Usage: ./server\n", 16);
	return (0);
}
