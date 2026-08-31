CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LD_SH   = -lmicrohttpd
LD_CURL = -lcurl
LD_SSL  = -lssl -lcrypto

KYBER_SRCS = kyber/reduce.c kyber/ntt.c kyber/cbd.c kyber/poly.c kyber/shake.c \
             kyber/polyvec.c kyber/indcpa.c kyber/kem.c kyber/threshold.c
KYBER_OBJS = $(KYBER_SRCS:.c=.o)
KYBER_HDRS = $(wildcard kyber/*.h)

all: shareholder dealer coordinator test_openssl

kyber/%.o: kyber/%.c $(KYBER_HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

shareholder: shareholder.c hexutil.c $(KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_SH) $(LD_SSL)

dealer: dealer.c hexutil.c $(KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL) $(LD_SSL)

coordinator: coordinator.c hexutil.c $(KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL) $(LD_SSL)

test_openssl: test_openssl.c
	$(CC) $(CFLAGS) -o $@ $< $(LD_SSL)

clean:
	rm -f *.o kyber/*.o shareholder dealer coordinator test_openssl
