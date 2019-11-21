CC=gcc
CFLAGS= -O -D UNIX -Wall
LDFLAGS= -l pthread
EXEC=uweb


all: $(EXEC)

$(EXEC): uweb.c log.c cmd_line.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm $(EXEC)
