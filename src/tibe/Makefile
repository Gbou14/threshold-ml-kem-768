CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS := -lcrypto -lm

SRCS := ring.c gauss.c
SRCS_WOTS := wots.c
SRCS_TIBE := ring.c gauss.c tibe.c
SRCS_IDENTITY := ring.c wots.c identity.c
SRCS_THRESHOLD := ring.c gauss.c tibe.c wots.c identity.c threshold.c
SRCS_TKEM := ring.c gauss.c tibe.c wots.c identity.c threshold.c tkem.c
SRCS_MERKLE := merkle.c
SRCS_V3S := ring.c gauss.c merkle.c v3s.c
SRCS_DKG := ring.c gauss.c tibe.c wots.c identity.c threshold.c merkle.c v3s.c dkg.c
SRCS_DKG_PUBKEY := ring.c gauss.c tibe.c wots.c identity.c threshold.c merkle.c v3s.c dkg.c dkg_pubkey.c

.PHONY: test clean

test: test/test_ring test/test_gauss test/test_wots test/test_tibe test/test_identity test/test_threshold test/test_tkem test/test_merkle test/test_v3s test/test_dkg test/test_dkg_pubkey
	./test/test_ring
	./test/test_gauss
	./test/test_wots
	./test/test_tibe
	./test/test_identity
	./test/test_threshold
	./test/test_tkem
	./test/test_merkle
	./test/test_v3s
	./test/test_dkg
	./test/test_dkg_pubkey

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

test/test_threshold: test/test_threshold.c $(SRCS_THRESHOLD) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_threshold.c $(SRCS_THRESHOLD) $(LDLIBS)

test/test_tkem: test/test_tkem.c $(SRCS_TKEM) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_tkem.c $(SRCS_TKEM) $(LDLIBS)

test/test_merkle: test/test_merkle.c $(SRCS_MERKLE) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_merkle.c $(SRCS_MERKLE) $(LDLIBS)

test/test_v3s: test/test_v3s.c $(SRCS_V3S) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_v3s.c $(SRCS_V3S) $(LDLIBS)

test/test_dkg: test/test_dkg.c $(SRCS_DKG) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_dkg.c $(SRCS_DKG) $(LDLIBS)

test/test_dkg_pubkey: test/test_dkg_pubkey.c $(SRCS_DKG_PUBKEY) $(wildcard *.h)
	$(CC) $(CFLAGS) -o $@ test/test_dkg_pubkey.c $(SRCS_DKG_PUBKEY) $(LDLIBS)

clean:
	rm -f test/test_ring test/test_gauss test/test_wots test/test_tibe test/test_identity test/test_threshold test/test_tkem test/test_merkle test/test_v3s test/test_dkg test/test_dkg_pubkey *.o
