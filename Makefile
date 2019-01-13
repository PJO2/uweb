CC=gcc
CFLAGS= -g -D UNIX
LDFLAGS= -l pthread -l nsl
EXEC=uweb


all: $(EXEC)

uweb: uweb.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

