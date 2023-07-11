CLIENT=client
SERVER=server
CLIENT_SRCS= srcs/ft_client.c
SERVER_SRCS= srcs/ft_server.c
LIBFT= libft/libft.a
GCC=gcc  -I .

all:${CLIENT} ${SERVER}


${CLIENT} : 
	${GCC} ${CLIENT_SRCS} ${LIBFT} -o ${CLIENT}

${SERVER} : 
	${GCC} ${SERVER_SRCS} ${LIBFT} -o ${SERVER}

clean:
	rm -f *.o
	rm -f libft/*.o

fclean:
	rm -f *.o ${CLIENT} ${SERVER} 
	rm -f libft/*.o

re: fclean all

.PHONY: all bonus clean fclean re