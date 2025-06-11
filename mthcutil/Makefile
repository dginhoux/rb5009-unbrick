.POSIX:
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11

.PHONY: all clean

all: mthcutil

clean:
	rm -f mthcutil

mthcutil: mthcutil.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)
