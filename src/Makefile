CFLAGS = -Wall -Wextra -Werror -lpcap -g -pedantic
OBJ = main.o
EXEC = pacstalker

all: ${EXEC}

${EXEC}: ${OBJ}
	${CC} ${CFLAGS} ${OBJ} -o $@

debug: CFLAGS += -DDEBUG
debug: ${EXEC}

clean:
	${RM} -rf ${OBJ} ${EXEC}
