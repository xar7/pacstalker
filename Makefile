CFLAGS = -Wall -Wextra -Werror -lpcap -g -pedantic
OBJ = src/main.o
EXEC = bin/pacstalker

.PHONY: clean debug

all: ${EXEC}

${EXEC}: ${OBJ}
	mkdir -p bin
	${CC} ${CFLAGS} ${OBJ} -o $@

debug: CFLAGS += -DDEBUG
debug: ${EXEC}

clean:
	${RM} -rf ${OBJ} bin/ --
