CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS := -lcrypto -lm

SRCS := ring.c gauss.c

.PHONY: test clean

test: test/test_ring test/test_gauss
	./test/test_ring
	./test/test_gauss

test/test_ring: test/test_ring.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_ring.c $(SRCS) $(LDLIBS)

test/test_gauss: test/test_gauss.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_gauss.c $(SRCS) $(LDLIBS)

clean:
	rm -f test/test_ring test/test_gauss *.o
