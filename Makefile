CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2

all: memscope leak

memscope: memscope.c
	$(CC) $(CFLAGS) -o $@ $<

leak: leak.c
	$(CC) $(CFLAGS) -o $@ $<

# build with sanitizers to catch memory bugs
debug: memscope.c
	$(CC) -std=c11 -Wall -Wextra -g -fsanitize=address,undefined -o memscope $<

clean:
	rm -f memscope leak

.PHONY: all debug clean
