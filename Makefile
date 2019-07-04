CFLAGS = -Wall -Wextra -Werror -lpcap -g -pedantic
OBJ = src/main.o
EXEC = bin/pacstalker

.PHONY: all
all: ${EXEC}

${EXEC}: ${OBJ}
	mkdir -p bin
	${CC} ${CFLAGS} ${OBJ} -o $@

.PHONY: debug
debug: CFLAGS += -DDEBUG
debug: ${EXEC}

.PHONY: clean
clean:
	${RM} -rf ${OBJ} bin/ --
