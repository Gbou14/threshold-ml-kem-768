# ML-KEM-768 (phase 1: primitives, phase 2: IND-CPA PKE, phase 3: threshold decryption)

Module-LWE math and IND-CPA-secure PKE for ML-KEM-768 (Kyber, k=3): NTT,
modular reduction, centered binomial noise sampling, polynomial
compression/serialization, and full KeyGen/Enc/Dec. Written from FIPS 203
/ the Kyber round-3 spec, not copied from any reference implementation.

Scope so far: **IND-CPA PKE, not the CCA-secure KEM**. No
Fujisaki-Okamoto layer yet -- see the project's design notes on why that
part is the hard, open-ended piece (and the actual paper-novelty target).

## Files

- `params.h` -- public ML-KEM-768 protocol constants
- `reduce.c/h` -- Montgomery and Barrett reduction mod q=3329
- `ntt.c/h` -- forward/inverse NTT and base multiplication; the twiddle
  factor table is generated at init time from the root of unity (zeta=17)
  rather than hardcoded, so it's derived, not transcribed. Init is called
  automatically by `ntt()`/`invntt()`/`poly_basemul_montgomery()` (see
  "A real bug" below for why that matters)
- `cbd.c/h` -- centered binomial (eta=2) noise sampling
- `shake.c/h` -- SHAKE-128/256 XOF and SHA3-256/512 via OpenSSL EVP, and
  the SHAKE-256 PRF used for noise sampling
- `poly.c/h` -- single-polynomial arithmetic, compression, serialization
- `polyvec.c/h` -- vector-of-K-polynomials versions of the above, plus
  the matrix-vector inner product (`polyvec_basemul_acc_montgomery`)
- `indcpa.c/h` -- matrix generation (SHAKE-128 rejection sampling) and
  KeyGen/Enc/Dec for the IND-CPA-secure PKE. KeyGen/Enc take explicit
  randomness ("derand") rather than calling a system RNG internally, so
  runs are reproducible -- needed for testing now, and for the threshold
  layer later where shareholders need agreed-upon deterministic derivation
- `threshold.c/h` -- Shamir-shares the secret key's 768 (K=3 x N=256)
  NTT-domain coefficients over Z_3329 (via OpenSSL `RAND_bytes`, unlike
  the original toy prototype's `rand()`), lets each shareholder compute
  a partial decryption locally, and Lagrange-combines k partials back
  into the correct plaintext -- without any party, including the
  coordinator, ever holding the secret key. See "The threshold trick"
  below for why this works

## Validation

`test/test_primitives.c` is a self-contained regression test (`make test`)
-- no external dependency, run it after any change here.

Those pinned values came from a byte-for-byte diff against the
public-domain pq-crystals/kyber reference implementation, run once during
development: `test/dump_ours.c` / `test/dump_indcpa_ours.c` (kept here)
and matching `dump_ref.c` / `dump_indcpa_ref.c` (not committed -- live in
a throwaway clone of pq-crystals/kyber) feed identical inputs to both
implementations and their stdout was `diff`'d. Every function matched
exactly: zetas table, `ntt`/`invntt`/`basemul`, Montgomery/Barrett
reduction edge cases, CBD sampling, compress/decompress, serialization,
message encode/decode, SHAKE256-PRF noise sampling, and full
KeyGen/Enc/Dec (public key, secret key, ciphertext, and recovered
message, all bit-exact for a fixed seed). To redo that full comparison,
clone `https://github.com/pq-crystals/kyber` and re-run the `dump_ours`
programs against matching `dump_ref` programs built the same way.

## The threshold trick

`indcpa_dec`'s core step, `mp = polyvec_basemul_acc_montgomery(skpv, b)`,
is linear in `skpv` for a fixed ciphertext `b`. If each of `skpv`'s 768
coefficients is independently Shamir-shared as a degree-(k-1) polynomial
over Z_3329 with the true coefficient at x=0, then running that same
computation on a *share* instead of the real key produces a polynomial
of the same degree, evaluated at that shareholder's x -- because a fixed
linear combination of degree-(k-1) polynomials is still degree (k-1). So
k shareholders' local partial results are themselves points on a
degree-(k-1) polynomial passing through the true `mp` coefficient at
x=0, and Lagrange interpolation recovers it. This is exactly what the
original toy-LWE prototype did (`main.c`'s `shamir_split`/
`lagrange_interpolate_zero` over the scalar dot product `s.u` mod 97) --
`threshold.c` is the same idea applied to real Kyber's NTT-domain module
math, over 768 coefficients instead of 4, mod 3329 instead of 97.

## A real bug this caught

`ntt()`/`invntt()`/`poly_basemul_montgomery()` all read a `zetas[128]`
twiddle-factor table that only gets populated by `kyber_ntt_init()`.
Every *test* program called that explicitly, so phase 1 tests passed --
but the phase 2 `indcpa.c` code never called it anywhere, and nothing
else did either. With `zetas` silently zero, `ntt()` degrades into a
no-op copy (the butterfly's `fq_mul(0, x)` term vanishes), and the
resulting "secret key" was a visibly degenerate repeating byte pattern,
not real key material -- caught immediately by the reference diff on
`indcpa_keypair_derand` output. Fixed by making initialization automatic:
`ntt()`, `invntt()`, and `poly_basemul_montgomery()` now call
`kyber_ntt_init()` themselves (idempotent, cheap after the first call),
so no caller can forget it again.

A second bug in phase 3: `indcpa_dec` calls `poly_invntt_tomont(&mp)`
between computing `mp` and subtracting it from `v` -- easy to miss when
hand-copying the tail of the decrypt flow, and the first version of the
threshold test did exactly that. It's caught by neither an internal
"does Lagrange combination match a direct computation" check (both sides
were consistently missing the same step) nor a crash -- only by the fact
that the *final decoded message* stopped matching, which is why
`test_threshold.c` checks message-level correctness end to end rather
than stopping at intermediate polynomial equality. Fixed by moving the
whole tail sequence (combine, invntt, subtract, reduce, decode) into one
function, `threshold_finish_decrypt`, so it can't be re-derived
incorrectly at each call site.
