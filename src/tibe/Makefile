CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS := -lcrypto -lm

SRCS := ring.c gauss.c
SRCS_WOTS := wots.c
SRCS_TIBE := ring.c gauss.c tibe.c
SRCS_IDENTITY := ring.c wots.c identity.c

.PHONY: test clean

test: test/test_ring test/test_gauss test/test_wots test/test_tibe test/test_identity
	./test/test_ring
	./test/test_gauss
	./test/test_wots
	./test/test_tibe
	./test/test_identity

test/test_ring: test/test_ring.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_ring.c $(SRCS) $(LDLIBS)

test/test_gauss: test/test_gauss.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_gauss.c $(SRCS) $(LDLIBS)

test/test_wots: test/test_wots.c $(SRCS_WOTS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_wots.c $(SRCS_WOTS) $(LDLIBS)

test/test_tibe: test/test_tibe.c $(SRCS_TIBE) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_tibe.c $(SRCS_TIBE) $(LDLIBS)

test/test_identity: test/test_identity.c $(SRCS_IDENTITY) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_identity.c $(SRCS_IDENTITY) $(LDLIBS)

clean:
	rm -f test/test_ring test/test_gauss test/test_wots test/test_tibe test/test_identity *.o
