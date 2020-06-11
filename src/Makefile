EXEC = corex
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

CFLAGS += -g -std=gnu99 -O2 -W -Wall -Wextra -no-pie -static
LDFLAGS += -static -no-pie -pthread -ljson-c -lz -lwebsockets -lcap -lutil -lssl -lcrypto -lm 

all: html $(EXEC)

html:
	xxd -i index.html html.h
	xxd -i ../html/homepage/index.html homepage.h

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) *.o

mrproper: clean
	$(RM) $(EXEC)
	$(RM) *.gcno *.gcda *.gcov

