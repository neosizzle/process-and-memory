CLIENT=client
SERVER=server
CLIENT_SRCS= srcs/ft_client.c
SERVER_SRCS= srcs/ft_server.c
CLIENT_BONUS=client_bonus
SERVER_BONUS=server_bonus
CLIENT_BONUS_SRCS= srcs/ft_client_bonus.c
SERVER_BONUS_SRCS= srcs/ft_server_bonus.c
LIBFT= libft/*.c
GCC=gcc -Wall -Werror -Wextra -I .

all:${CLIENT} ${SERVER}

bonus:${CLIENT_BONUS} ${SERVER_BONUS}

${CLIENT} : 
	${GCC} ${CLIENT_SRCS} ${LIBFT} -o ${CLIENT}

${SERVER} : 
	${GCC} ${SERVER_SRCS} ${LIBFT} -o ${SERVER}

${CLIENT_BONUS} : 
	${GCC} ${CLIENT_BONUS_SRCS} ${LIBFT} -o ${CLIENT_BONUS}

${SERVER_BONUS} : 
	${GCC} ${SERVER_BONUS_SRCS} ${LIBFT} -o ${SERVER_BONUS}

clean:
	rm -f *.o
	rm -f libft/*.o

fclean:
	rm -f *.o ${CLIENT} ${SERVER} ${CLIENT_BONUS} ${SERVER_BONUS}
	rm -f libft/*.o

re: fclean all

.PHONY: all bonus clean fclean re