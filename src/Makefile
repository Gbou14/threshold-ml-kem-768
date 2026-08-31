CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
COMMON  = shamir.o lagrange.o toy_crypto.o
LD_SH   = -lmicrohttpd
LD_CURL = -lcurl
LD_SSL  = -lssl -lcrypto

all: shareholder dealer coordinator test_openssl

shamir.o: shamir.c shamir.h params.h
	$(CC) $(CFLAGS) -c -o $@ $<

lagrange.o: lagrange.c lagrange.h params.h
	$(CC) $(CFLAGS) -c -o $@ $<

toy_crypto.o: toy_crypto.c toy_crypto.h params.h
	$(CC) $(CFLAGS) -c -o $@ $<

shareholder: shareholder.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_SH)

dealer: dealer.c
	$(CC) $(CFLAGS) -o $@ $< $(LD_CURL) $(LD_SSL)

coordinator: coordinator.c
	$(CC) $(CFLAGS) -o $@ $< $(LD_CURL) $(LD_SSL)

test_openssl: test_openssl.c
	$(CC) $(CFLAGS) -o $@ $< $(LD_SSL)

clean:
	rm -f *.o shareholder dealer coordinator test_openssl
