CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS := -lcrypto

SRCS := reduce.c ntt.c cbd.c poly.c shake.c
OBJS := $(SRCS:.c=.o)

.PHONY: test clean

test: test/test_primitives
	./test/test_primitives

test/test_primitives: test/test_primitives.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_primitives.c $(SRCS) $(LDLIBS)

clean:
	rm -f test/test_primitives $(OBJS)
