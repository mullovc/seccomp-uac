.PHONY: clean, mrproper
CC = gcc
CFLAGS = -g -Wall -lseccomp -DDEBUG

all: uac

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

uac: main.o sandbox.o monitor.o sendfd.o
	$(CC) $(CFLAGS) -o $@ $+


clean:
	rm -f *.o core.*

mrproper: clean
	rm -f uac
