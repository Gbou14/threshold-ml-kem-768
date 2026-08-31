# ML-KEM-768 (phases 1-3: primitives / IND-CPA PKE / threshold decryption, phase 5: full CCA-secure threshold Decaps)

Module-LWE math and IND-CPA-secure PKE for ML-KEM-768 (Kyber, k=3): NTT,
modular reduction, centered binomial noise sampling, polynomial
compression/serialization, and full KeyGen/Enc/Dec. Written from FIPS 203
/ the Kyber round-3 spec, not copied from any reference implementation.

Scope: real IND-CPA PKE (phases 1-3) plus a full CCA-secure KEM (`kem.c`,
phase 5) with a threshold-decapsulation path (`threshold_decaps`) that
works under an explicit, narrower trust assumption than full generic-MPC
threshold cryptography -- see "Phase 5" below for exactly what that means
and why it's the honest scope rather than the full research problem.

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
  below for why this works. Also has `threshold_decaps`, which extends
  this to the full CCA-secure KEM below under a narrower, explicit
  trust assumption -- see "Phase 5" below
- `kem.c/h` -- the full CCA-secure ML-KEM-768 KEM: wraps the IND-CPA
  PKE in the Fujisaki-Okamoto-style transform (hash the decrypted
  message, re-encrypt, compare to the real ciphertext, fall back to a
  pseudorandom value on mismatch) that makes it resistant to
  chosen-ciphertext attacks, which the plain PKE alone is not

## Validation

`make test` builds and runs four self-contained regression suites --
`test_primitives`, `test_indcpa`, `test_threshold`, `test_kem` -- with no
external dependency at run time. Run it after any change here.

Those pinned values came from a byte-for-byte diff against the
public-domain pq-crystals/kyber reference implementation, run once during
development: `test/dump_ours.c` / `test/dump_indcpa_ours.c` /
`test/dump_kem_ours.c` (kept here) and matching `dump_ref.c` files (not
committed -- live in a throwaway clone of pq-crystals/kyber) feed
identical inputs to both implementations and their stdout was `diff`'d.
Every function matched exactly: zetas table, `ntt`/`invntt`/`basemul`,
Montgomery/Barrett reduction edge cases, CBD sampling,
compress/decompress, serialization, message encode/decode, SHAKE256-PRF
noise sampling, full KeyGen/Enc/Dec, and the full KEM (public key,
secret key, ciphertext, encapsulated secret, decapsulated secret, *and*
the implicit-rejection value for a corrupted ciphertext -- all bit-exact
for a fixed seed). To redo that full comparison, clone
`https://github.com/pq-crystals/kyber` and re-run the `dump_ours`
programs against matching `dump_ref` programs built the same way.

`threshold.c`'s functions have no public reference to diff against (no
open threshold-Kyber implementation exists) -- those are validated by
internal consistency instead: `test_threshold.c` checks any k-of-n
subset recovers the message and a below-threshold subset doesn't;
`test_kem.c` checks `threshold_decaps` agrees with plain `kyber_decaps`
byte-for-byte, on both the accept and implicit-rejection paths.

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

## Phase 5: full CCA-secure threshold Decaps, and its trust assumption

Real ML-KEM's `Decaps` isn't just PKE decryption -- it wraps it in a
Fujisaki-Okamoto-style transform for CCA2 security:

1. `m' = PKE.Decrypt(dk, c)` -- exactly what `threshold_finish_decrypt`
   already computes, without any party seeing `dk`.
2. `(K', r') = G(m' || H(ek))` -- hash `m'` to derive the real shared
   secret and the randomness used to re-derive the ciphertext.
3. `c' = PKE.Encrypt(ek, m', r')` -- re-encrypt.
4. If `c' == c`, return `K'`; otherwise return a pseudorandom value
   derived from a secret `z`, indistinguishable from a real key to
   anyone without `z`. This is what defeats chosen-ciphertext attacks --
   an attacker submitting a malformed ciphertext gets a useless,
   consistent-looking response instead of a distinguishing signal.

Steps 2-4 aren't linear in the secret key, so the Shamir-sharing trick
that makes step 1 threshold-friendly doesn't extend to them -- they need
`m'` in the clear, and `m'` is what determines the actual KEM output
`K'`. `threshold_decaps` (`threshold.c`) does steps 2-4 in the combiner,
after Lagrange-combining shares to get `m'` -- meaning **the combiner
sees `m'`**, even though it never sees the private key. That's a real,
narrower trust assumption than "no party ever reconstructs anything
secret" -- it's "no party reconstructs the private key, but the combiner
must be trusted not to leak the one message it briefly holds per
decapsulation."

This is a known-hard problem, not a shortcut taken for convenience: it's
exactly why NIST's Multi-Party Threshold Cryptography project lists
ML-KEM as an open target, and the general fix (secret-share `m'` itself,
run the hash and re-encryption as a generic MPC circuit, do a secure
equality test on `c'` vs `c` without ever reconstructing either in the
clear) is a different, much larger undertaking than anything else in
this repo -- closer to its own research project than an extension of
this one. `z` itself isn't newly exposed by any of this: whoever runs
ordinary (non-threshold) `Decaps` already needs `z` for the same
implicit-rejection step, so the combiner holding it is no different from
what a single-party decryptor already does.

`kyber_decaps_from_m` exists specifically so this shared tail (hash,
re-encrypt, compare, select) is written once and used by both
`kyber_decaps` (the ordinary path, computing `m'` via `indcpa_dec`) and
`threshold_decaps` (computing `m'` via Lagrange combination) -- given the
invntt bug two sections down, duplicating this logic by hand a second
time was not a risk worth taking again.

## Live end-to-end proof

Beyond the unit tests, the full system runs as five separate Docker
containers (shareholders) plus a dealer and a coordinator, talking over
real HTTP -- see `../../docker-compose.yml`. As of the run on
2026-08-31: dealer generates a real ML-KEM-768 KEM keypair, Shamir-splits
the secret key, publishes `ek.bin` (1184 bytes) and `z.bin` (32 bytes);
coordinator runs 200 trials of real `kyber_encaps_derand` ->
network round-trip to 3 of the 5 shareholders for partial decryptions ->
`threshold_decaps` -> AES-256-GCM keyed directly from the result.
**200/200 KEM successes, 200/200 AES successes.** No party other than
the coordinator ever held `ek`/`z`, and no party ever held the private
key or a share other than its own. Re-run it yourself with
`docker compose up -d && docker wait coordinator && cat data/results.csv`
from the project root.

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

A third bug, wiring `kem.c` into the Docker demo: `src/Makefile` (the
one the Docker build actually uses -- separate from this directory's
own `Makefile` for `make test`) still listed the old set of kyber source
files without `kem.c`, so `threshold_decaps`'s call to
`kyber_decaps_from_m` failed to link. Local ad-hoc compiles didn't catch
it because they'd been assembling object file lists by hand and happened
to include `kem.o`. Only surfaced on a genuinely clean `docker compose
build` -- a good reminder that "compiles for me locally" and "compiles
from the actual build definition" are different claims, and only one of
them is what a reader can reproduce.
