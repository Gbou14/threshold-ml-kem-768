# TIBE / BCHK+ threshold KEM (Phase 1: ring arithmetic + Gaussian sampling)

This module is the from-scratch implementation of Lapiha & Prest, "A
Lattice-Based IND-CCA Threshold KEM from the BCHK+ Transform" (Asiacrypt
2025, eprint 2025/1958) -- see `../../BCHK_PAPER_SPEC.md` for the full
algorithm transcription this is built against, and
`../../FO_REDESIGN_CONTEXT.md` for why this paper, not a patched
`src/kyber/`. It lives alongside `src/kyber/`, not inside it: the
existing threshold-ML-KEM-768 code is untouched (`git diff master --
src/kyber/` is empty), so it stays available as the working fallback and
comparison point if this redesign doesn't pan out.

**Status: Phase 1 only.** This is ring arithmetic and Gaussian sampling
-- the foundation every later phase (WOTS+, the TIBE algebra, the 3-round
threshold-decryption protocol, the BCHK+ TKEM layer, Docker wiring) is
built on. See `../../BCHK_TODO.md` for the full roadmap and what's not
here yet. Nothing in this module does threshold decryption, encryption,
or signing yet.

## Files

- `params.h` -- concrete numeric constants from the paper's Table 2:
  ring degree `d=4096`, modulus `q` (a specific 101-bit prime), the
  three Gaussian widths this project uses, and this project's `(T,N)`
  choice. See "Parameter choices" below for how `q` was derived and why
  `T=5` (not the paper's proven `T=32`) is safe to use unchanged.
- `gen_params.py` -- the reproducible derivation script for `q` (and,
  for a later phase, the ring-splitting roots `r1`/`r2`). Not part of
  the build; re-run it to independently reproduce every constant in
  `params.h`.
- `ring.c`/`.h` -- `R_q = Z[X]/(X^d + 1)`: add, sub, negate,
  scalar-multiply, negacyclic-convolution multiply, uniform sampling,
  and fixed-width serialization. See "Why BIGNUM" below.
- `gauss.c`/`.h` -- discrete-Gaussian-*approximating* sampling at an
  arbitrary width. See "Gaussian sampling" below for the approximation
  this makes and why.
- `test/test_ring.c`, `test/test_gauss.c` -- the regression suites (see
  "Validation" below).

## Parameter choices

**`q`**: the paper requires a prime `q = 5 (mod 8)` (Lemma 1, so that
`R_q` splits as `F_{d/2} x F_{d/2}`, needed by a later phase's
identity-embedding map) of roughly 100 bits (Table 2). `gen_params.py`
picks the smallest such prime `>= 2^100` via exhaustive search + 64-round
Miller-Rabin, seeded from the paper's eprint number purely for
reproducibility (the *choice* of "smallest prime satisfying a public
condition" doesn't depend on the seed -- only which witnesses
Miller-Rabin happens to draw does, and primality is independently
re-confirmed with `openssl prime -hex 10000000000000000000000115`, a
tool with no relation to this project's own code). Result:

```
q = 1267650600228229401496703205653  (0x10000000000000000000000115), 101 bits, q = 5 (mod 8)
```

**`T=5, N=10`** (not the paper's proven `T=32`): confirmed with the
project owner. The correctness bound (`BCHK_PAPER_SPEC.md` Sec 4.7,
Equation 13) depends on the threshold only through a term proportional
to `sqrt(T*d)` (accumulated per-shareholder blinding noise) -- smaller
`T` only *shrinks* that term, so Table 2's `(sigma_a, sigma, sigma_p,
beta)` values, derived to satisfy correctness at `T=32`, remain valid
(with extra margin, not less) at `T=5`. This is **not** a re-derived,
right-sized parameter set for `T=5` -- it's the `T=32` set, reused at a
smaller threshold, which is conservative for correctness. It is *not*
automatically conservative for the *security* proof's concrete bound
(which was calibrated against `Q_Dec = 2^40` queries at `T=32` -- a
smaller `T` changes the adversary's available corruption sets in a way
this project has not re-analyzed). **Before any publication claim, this
needs either an explicit note that T=5 is a correctness-only
demonstration scale, or a real run at the paper's proven `T=32`** -- see
`BCHK_TODO.md` phase 8.

## Why BIGNUM

`q` is a 101-bit prime -- an order of magnitude past Kyber's 12-bit
`q=3329`, where `src/kyber/reduce.c`'s Montgomery/Barrett tricks work in
plain 16/32-bit arithmetic. Two products of ~101-bit numbers don't fit a
single 128-bit hardware multiply's result cleanly enough to hand-roll a
safe reduction quickly and correctly. This module uses OpenSSL's BIGNUM
library (`libcrypto`, already a project dependency) for all mod-`q`
coefficient arithmetic instead of new hand-written fixed-width modular
code -- confirmed with the project owner as the right tradeoff for this
pass: it costs real performance (a single dense `ring_mul`, the
schoolbook O(d^2) negacyclic convolution, takes about **10 seconds** on
this development machine -- see "Validation" below), but it means the
one genuinely new, unvalidated piece of low-level arithmetic in this
whole redesign is *not* also a hand-rolled modular reduction with no
reference to check it against. If this becomes a real bottleneck later
(e.g. once the full protocol needs many `ring_mul` calls per
decapsulation), NTT-based multiplication is the natural next step --
deliberately deferred, not attempted here (`BCHK_TODO.md` phase 8).

## Gaussian sampling

The paper's protocol needs true discrete-Gaussian sampling,
`D_{R,sigma}`, at several widths -- most strikingly `sigma_p = 2^47` for
the per-shareholder noise-flooding/blinding term. Kyber deliberately
avoids this entirely (its noise comes from the Centered Binomial
Distribution, trivial to sample in constant time from raw random bytes);
an *exact*, constant-time discrete Gaussian sampler (rejection sampling,
a cumulative-distribution table, or a convolution-based construction) is
real, separate cryptographic engineering with its own precision and
side-channel pitfalls, and is explicitly **not** what this module does.

`gauss_sample_coeff` instead draws two uniform doubles from OpenSSL
`RAND_bytes` (53 bits of resolution each, matching the rest of this
project's reliance on OpenSSL's CSPRNG), runs the standard Box-Muller
transform to get a continuous standard-normal sample, scales by `sigma`,
and rounds to the nearest integer. This is a widely-used *practical
approximation* of a discrete Gaussian, not the paper's formal object --
it is not proven statistically close to `D_{R,sigma}` the way a real
discrete Gaussian sampler would be, and it is not constant-time (`log`,
`cos`, `sqrt` and double-precision rounding all have data-dependent
timing on typical hardware). Good enough to validate the *algebra* of
later phases (does noise-flooding correctness hold, does `Decode` round
correctly), not good enough to make a security claim about the resulting
system without replacing it. Flagged here, in `BCHK_PAPER_SPEC.md` open
question #2, and in `BCHK_TODO.md` so it isn't forgotten.

## Validation

No public reference implementation of this scheme exists anywhere (this
is a from-scratch build of a paper with no released code) -- same
situation this project was already in for `src/kyber/threshold.c` and
`threshold_decaps`, handled the same way: internal consistency instead
of a byte-exact diff.

`make test` builds and runs two self-contained suites:

- `test_ring`: ring-axiom checks (additive inverse, scalar-mul identity
  and zero, serialize/deserialize round trip), an explicit
  negacyclic-wraparound check (`X^(D-1) * X == -1`, the one algebraic
  property that distinguishes this ring from plain polynomial
  multiplication), and one dense-random distributivity check
  (`a*(b+c) == a*b + a*c`) -- the real stress test of convolution +
  mod-`q` reduction together. That last check alone takes about 30
  seconds (three full O(d^2) dense multiplies); the sparse
  identity/zero/wraparound checks are much faster in practice, since a
  zero `BIGNUM` operand makes `BN_mod_mul` nearly instant even though
  the O(d^2) loop still runs.
- `test_gauss`: empirical mean/stddev checks (20,000 samples each) at
  every width this project's Table 2 instantiation actually uses
  (`TIBE_SIGMA_A=8`, `TIBE_SIGMA=4`, `TIBE_SIGMA_P=2^47`), with
  tolerances chosen so the check has a wide margin against a passing
  distribution's own sampling noise (see the file for the exact
  numbers) while still catching a genuinely broken sampler.

Both currently pass. Representative output:

```
./test/test_ring
(distributivity dense-multiply check took 29.8s)
test_ring: all tests passed
./test/test_gauss
  sigma=8: n=20000 empirical mean=-0.01435 empirical stddev=8.031
  sigma=4: n=20000 empirical mean=0.04825 empirical stddev=4.019
  sigma=1.41e+14: n=20000 empirical mean=7.94e+11 empirical stddev=1.418e+14
test_gauss: all tests passed
```
