CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LD_SH   = -lmicrohttpd
LD_CURL = -lcurl
LD_SSL  = -lssl -lcrypto
LD_MATH = -lm

KYBER_SRCS = kyber/reduce.c kyber/ntt.c kyber/cbd.c kyber/poly.c kyber/shake.c \
             kyber/polyvec.c kyber/indcpa.c kyber/kem.c kyber/threshold.c
KYBER_OBJS = $(KYBER_SRCS:.c=.o)
KYBER_HDRS = $(wildcard kyber/*.h)

# BCHK+ threshold KEM module (src/tibe/) -- see src/tibe/README.md and
# BCHK_TODO.md. Kept fully separate from the KYBER_* variables above:
# this is a parallel implementation, not a modification of the Kyber
# one, and the two demos (dealer/shareholder/coordinator vs
# tibe_dealer/tibe_shareholder/tibe_coordinator) are independent.
TIBE_SRCS = tibe/ring.c tibe/gauss.c tibe/tibe.c tibe/wots.c tibe/identity.c \
            tibe/threshold.c tibe/tkem.c
TIBE_OBJS = $(TIBE_SRCS:.c=.o)
TIBE_HDRS = $(wildcard tibe/*.h)

all: shareholder dealer coordinator test_openssl tibe_shareholder tibe_dealer tibe_coordinator

kyber/%.o: kyber/%.c $(KYBER_HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

tibe/%.o: tibe/%.c $(TIBE_HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

shareholder: shareholder.c hexutil.c $(KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_SH) $(LD_SSL)

dealer: dealer.c hexutil.c $(KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL) $(LD_SSL)

coordinator: coordinator.c hexutil.c $(KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL) $(LD_SSL)

test_openssl: test_openssl.c
	$(CC) $(CFLAGS) -o $@ $< $(LD_SSL)

tibe_shareholder: tibe_shareholder.c hexutil.c $(TIBE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_SH) $(LD_SSL) $(LD_MATH)

tibe_dealer: tibe_dealer.c hexutil.c $(TIBE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL) $(LD_SSL) $(LD_MATH)

tibe_coordinator: tibe_coordinator.c hexutil.c $(TIBE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LD_CURL) $(LD_SSL) $(LD_MATH)

clean:
	rm -f *.o kyber/*.o tibe/*.o shareholder dealer coordinator test_openssl \
	      tibe_shareholder tibe_dealer tibe_coordinator
