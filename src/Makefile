CFLAGS = -Wall -lpcap -g
OBJ = main.o
EXEC = pacstalker

all: pacstalker

pacstalker: ${OBJ}
	${CC} ${CFLAGS} ${OBJ} -o $@

debug: CFLAGS += -DDEBUG
debug: ${OBJ}
	${CC} ${CFLAGS} ${OBJ} -o ${EXEC}

clean:
	${RM} -rf ${OBJ} pacstalker
