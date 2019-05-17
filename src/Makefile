EXEC = ttyd
SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)

CFLAGS += -D_GNU_SOURCE -std=c99 -O2 -I/usr/include/json-c
LDFLAGS += -Wl,-Bstatic -pthread -lwebsockets -ljson-c -lz -lssl -lcrypto -lutil -Wl,-Bdynamic -lpthread -ldl

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -fv *.o

mrproper: clean
	rm -fv $(EXEC)

