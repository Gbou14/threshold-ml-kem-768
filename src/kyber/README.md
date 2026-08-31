# ML-KEM-768 primitives (phase 1)

Module-LWE math for ML-KEM-768 (Kyber, k=3): NTT, modular reduction,
centered binomial noise sampling, and polynomial compression/serialization.
Written from FIPS 203 / the Kyber round-3 spec, not copied from any
reference implementation.

Scope: **primitives only**. No KeyGen/Enc/Dec yet (that's `indcpa.c`,
next), and no CCA-secure KEM (the Fujisaki-Okamoto layer -- see the
project's design notes on why that part is the hard, open-ended piece).

## Files

- `params.h` -- public ML-KEM-768 protocol constants
- `reduce.c/h` -- Montgomery and Barrett reduction mod q=3329
- `ntt.c/h` -- forward/inverse NTT and base multiplication; the twiddle
  factor table is generated at init time from the root of unity (zeta=17)
  rather than hardcoded, so it's derived, not transcribed
- `cbd.c/h` -- centered binomial (eta=2) noise sampling
- `shake.c/h` -- SHAKE-128/256 XOF via OpenSSL EVP, and the SHAKE-256 PRF
  used for noise sampling
- `poly.c/h` -- polynomial arithmetic, compression, and serialization

## Validation

`test/test_primitives.c` is a self-contained regression test (`make test`)
-- no external dependency, run it after any change here.

Those pinned values came from a byte-for-byte diff against the
public-domain pq-crystals/kyber reference implementation, run once during
development: `test/dump_ours.c` (kept here) and a matching `dump_ref.c`
(not committed -- lives in a throwaway clone of pq-crystals/kyber) feed
identical inputs to both implementations and their stdout was `diff`'d.
Every function in this module -- zetas table, `ntt`/`invntt`/`basemul`,
Montgomery/Barrett reduction edge cases, CBD sampling, compress/decompress,
serialization, message encode/decode, and SHAKE256-PRF noise sampling --
matched exactly. To redo that full comparison, clone
`https://github.com/pq-crystals/kyber` and re-run `dump_ours.c` against a
`dump_ref.c` built the same way.
