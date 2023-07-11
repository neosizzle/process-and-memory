CC = gcc
INCS = inc
BUILDDIR=build/
C_FLAGS = -I${INCS}

NAME_0 = test_pid_info
SRCS_0 = test_pid_info.c
OBJS_0 = ${SRCS_0:.c=.o}

NAME_1 = forker
SRCS_1 = forker.c
OBJS_1 = ${SRCS_1:.c=.o}

NAME_2 = wait_test
SRCS_2 = wait_test.c
OBJS_2 = ${SRCS_2:.c=.o}

OBJS_TARGET_0=${addprefix ${BUILDDIR},${subst /,_,${OBJS_0}}}
OBJS_TARGET_1=${addprefix ${BUILDDIR},${subst /,_,${OBJS_1}}}
OBJS_TARGET_2=${addprefix ${BUILDDIR},${subst /,_,${OBJS_2}}}

# Style constants
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[0;33m
BLUE=\033[0;34m
PURPLE=\033[0;35m
CYAN=\033[0;36m
NC=\033[0m # No Color


all : ${NAME_1} ${NAME_0} ${NAME_2}
	@echo "${GREEN}✔️  Done build..${NC}"

# Linking
${NAME_0}: ${OBJS_TARGET_0}
	@echo "${GREEN}😏  Linking  ${foreach obj,${OBJS_0},${BUILDDIR}${obj}}.. ${NC}"
	@${CC} ${foreach obj,${OBJS_0},${BUILDDIR}${obj}} libft.a ${C_FLAGS} -o ${NAME_0} 

${NAME_1}: ${OBJS_TARGET_1}
	@echo "${GREEN}😏  Linking ${foreach obj,${OBJS_1},${BUILDDIR}${obj}}.. ${NC}"
	@${CC} ${foreach obj,${OBJS_1},${BUILDDIR}${obj}} ${C_FLAGS} -o ${NAME_1}

${NAME_2}: ${OBJS_TARGET_2}
	@echo "${GREEN}😏  Linking ${foreach obj,${OBJS_2},${BUILDDIR}${obj}}.. ${NC}"
	@${CC} ${foreach obj,${OBJS_2},${BUILDDIR}${obj}} ${C_FLAGS} -o ${NAME_2}

# Compiling
build/%.o : ${OBJS_0} ${OBJS_1} ${OBJS_2}
	@echo "${GREEN}📇  Compile finish..${NC}"


.c.o : 
	@echo "${GREEN}📇  Compiling $<..${NC}"
	@${CC} ${C_FLAGS} -c $< -o ${BUILDDIR}${subst /,_,$@}

clean : 
	@echo "${YELLOW}🗑️  Removing Objects..${NC}"
	@rm -rf ${BUILDDIR}*.o

fclean : clean
	@echo "${YELLOW}🗑️  Removing ${NAME_0}..${NC}"
	@rm -rf ${NAME_0}
	@echo "${YELLOW}🗑️  Removing ${NAME_1}..${NC}"
	@rm -rf ${NAME_1}
	@echo "${YELLOW}🗑️  Removing ${NAME_2}..${NC}"
	@rm -rf ${NAME_2}

re : fclean all

.PHONY : re clean fclean all