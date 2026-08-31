CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS := -lcrypto -lm

SRCS := ring.c gauss.c
SRCS_WOTS := wots.c

.PHONY: test clean

test: test/test_ring test/test_gauss test/test_wots
	./test/test_ring
	./test/test_gauss
	./test/test_wots

test/test_ring: test/test_ring.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_ring.c $(SRCS) $(LDLIBS)

test/test_gauss: test/test_gauss.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_gauss.c $(SRCS) $(LDLIBS)

test/test_wots: test/test_wots.c $(SRCS_WOTS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_wots.c $(SRCS_WOTS) $(LDLIBS)

clean:
	rm -f test/test_ring test/test_gauss test/test_wots *.o
