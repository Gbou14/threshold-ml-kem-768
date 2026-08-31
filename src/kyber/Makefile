CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS := -lcrypto

SRCS := reduce.c ntt.c cbd.c poly.c shake.c polyvec.c indcpa.c kem.c threshold.c

.PHONY: test clean

test: test/test_primitives test/test_indcpa test/test_threshold test/test_kem
	./test/test_primitives
	./test/test_indcpa
	./test/test_threshold
	./test/test_kem

test/test_primitives: test/test_primitives.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_primitives.c $(SRCS) $(LDLIBS)

test/test_indcpa: test/test_indcpa.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_indcpa.c $(SRCS) $(LDLIBS)

test/test_threshold: test/test_threshold.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_threshold.c $(SRCS) $(LDLIBS)

test/test_kem: test/test_kem.c $(SRCS) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_kem.c $(SRCS) $(LDLIBS)

clean:
	rm -f test/test_primitives test/test_indcpa test/test_threshold test/test_kem *.o
