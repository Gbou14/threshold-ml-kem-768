CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
COMMON  = shamir.o lagrange.o toy_crypto.o
LD_SH   = -lmicrohttpd
LD_CURL = -lcurl

all: shareholder dealer coordinator

shamir.o: shamir.c shamir.h params.h
	$(CC) $(CFLAGS) -c -o $@ $<

lagrange.o: lagrange.c lagrange.h params.h
	$(CC) $(CFLAGS) -c -o $@ $<

toy_crypto.o: toy_crypto.c toy_crypto.h params.h
	$(CC) $(CFLAGS) -c -o $@ $<

shareholder: shareholder.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_SH)

dealer: dealer.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL)

coordinator: coordinator.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL)

clean:
	rm -f *.o shareholder dealer coordinator
