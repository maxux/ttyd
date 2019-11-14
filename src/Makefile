EXEC = corex
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

CFLAGS += -g -std=gnu99 -O2 -W -Wall -Wextra -I/usr/include/json-c
LDFLAGS += -static -lresolv -pthread -rdynamic -ljson-c -lz -ldbus-1 -lwebsockets -lcap -lutil -lssl -lcrypto -lm -ldl -lz -ldbus-1

all: html $(EXEC)

html:
	xxd -i index.html html.h

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) *.o

mrproper: clean
	$(RM) $(EXEC)
	$(RM) *.gcno *.gcda *.gcov

