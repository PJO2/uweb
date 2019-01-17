CC=gcc
CFLAGS= -O -D UNIX
LDFLAGS= -l pthread
EXEC=uweb


all: $(EXEC)

$(EXEC): uweb.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	rm $(EXEC)
