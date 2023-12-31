.PHONY: clean, mrproper
CC = gcc
CFLAGS = -g -Wall -lseccomp -DDEBUG

all: uac

%.o: %.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

uac: main.o sandbox.o monitor.o sendfd.o syscall_handlers.o
	$(CC) $(CFLAGS) -o $@ $+


clean:
	rm -f *.o core.*

mrproper: clean
	rm -f uac
