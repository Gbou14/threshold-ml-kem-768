# TIBE / BCHK+ threshold KEM (Phase 1-3: ring arithmetic, Gaussian sampling, WOTS+, TIBE core algebra)

This module is the from-scratch implementation of Lapiha & Prest, "A
Lattice-Based IND-CCA Threshold KEM from the BCHK+ Transform" (Asiacrypt
2025, eprint 2025/1958) -- see `../../BCHK_PAPER_SPEC.md` for the full
algorithm transcription this is built against, and
`../../FO_REDESIGN_CONTEXT.md` for why this paper, not a patched
`src/kyber/`. It lives alongside `src/kyber/`, not inside it: the
existing threshold-ML-KEM-768 code is untouched (`git diff master --
src/kyber/` is empty), so it stays available as the working fallback and
comparison point if this redesign doesn't pan out.

**Status: Phase 1-3.** Ring arithmetic, Gaussian sampling, WOTS+, and
now the core TIBE encryption/decryption algebra (`tibe.c`) -- validated
end to end, but **still non-threshold**: `tibe_setup` produces the
whole master secret in one place, and `tibe_decrypt_direct` is a
single-party stand-in for the real 3-round `ShareExtract`/`Combine`
protocol. See `../../BCHK_TODO.md` for the full roadmap. **Nothing in
this module does actual threshold decryption yet, and Encaps/decaps at
the TKEM/BCHK+ layer (binding a WOTS+ signature to a ciphertext) hasn't
been wired up either** -- both are still ahead.

## The actual trust-model delta vs. `src/kyber/threshold_decaps`

This is the single most important thing to get right about *why* this
redesign exists, worth stating precisely rather than loosely (it's
going into a paper -- see `BCHK_TODO.md` "Future: paper writeups" --
so imprecise claims here would propagate).

**What does NOT change**: in both schemes, the combiner (coordinator)
ends up computing the final message and shared secret in the clear --
that's unavoidable, it's the combiner's whole job. It is **not true**
that "the combiner never holds the decrypted message" in the new
scheme; it does, exactly as it did before. Anyone tempted to write that
sentence in a paper draft should replace it with the precise claim
below.

**What DOES change: who has to be trusted for CCA security to hold at
all.**

- **Old (`src/kyber/threshold_decaps`)**: the ciphertext-validity check
  (the Fujisaki-Okamoto re-encryption comparison, `c' == c?`) can only
  run *after* `m'` has already been reconstructed -- and `m'` can only
  be reconstructed by Lagrange-combining every shareholder's partial
  decryption. So the sequence is: shareholders blindly compute and
  reveal partial decryptions of *whatever ciphertext they're handed*,
  with no way to locally tell a legitimate ciphertext from an
  attacker-crafted one; only then, at the very end, does the combiner
  check validity. If the combiner is compromised or simply skips that
  check, CCA security is gone -- a malicious combiner (or an attacker
  who controls it) can feed shareholders crafted ciphertexts and use
  their honestly-computed partial decryptions as a decryption oracle,
  which is exactly what CCA-security is supposed to prevent. This is
  the "narrower trust assumption" `src/kyber/README.md` Phase 5 and
  `FO_REDESIGN_CONTEXT.md` describe: CCA security itself, not just
  confidentiality of one message, rests on the combiner behaving
  honestly.
- **New (BCHK+, this module)**: every shareholder independently runs
  `assert SIG.Verify(vk, ct, sig) = 1` (`BCHK_PAPER_SPEC.md` Sec 4.6,
  `TKEM.ShareDecaps_j`) **before** doing any partial-decryption work at
  all, in every round -- and this check needs no secret material, so
  every shareholder can (and must) do it independently, without
  trusting the combiner or anyone else to have done it correctly. A
  ciphertext without a valid one-time signature under a properly-formed
  `vk` is rejected by every honest shareholder before it ever produces
  a single partial-decryption value, full stop. **CCA security no
  longer depends on the combiner's honesty at all** -- a fully
  malicious combiner can still refuse to combine, or output garbage,
  but it cannot use the protocol to mount a chosen-ciphertext attack,
  because the shareholders it would need to fool into leaking partial
  decryptions of a malformed ciphertext will already have rejected it
  on their own. The combiner still reconstructs the real message for
  *legitimate* ciphertexts (that's correctness, not a security hole) --
  the delta is that this reconstruction is no longer the point where
  the system's CCA security lives or dies.

One remaining, unrelated trust assumption stays the same in both
schemes and is **not** addressed by this redesign: the dealer
(`TIBE.Setup`/`TKEM.Keygen`) is trusted to generate the master secret
honestly and distribute shares correctly (`BCHK_PAPER_SPEC.md` Sec 5,
"Remark 1") -- matching this repo's existing `src/dealer.c` role
exactly. No distributed key generation exists in either scheme.

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
  fixed-width serialization, general ring-element inversion
  (`ring_inv`, polynomial extended Euclidean algorithm -- needed
  starting Phase 3, see "TIBE core algebra" below for why this ended
  up here rather than in the identity-embedding phase it was
  originally scoped under), and `ring_decomp_beta` (the paper's
  `Decomp_beta`). See "Why BIGNUM" below.
- `gauss.c`/`.h` -- discrete-Gaussian-*approximating* sampling at an
  arbitrary width. See "Gaussian sampling" below for the approximation
  this makes and why.
- `wots.c`/`.h` -- WOTS+, the one-time signature the BCHK+ transform
  binds to each fresh TIBE ciphertext. See "WOTS+" below.
- `tibe.c`/`.h` -- the TIBE core algebra: `Setup` (non-threshold, Phase
  3 scope), `Encode`/`Decode`, `Encrypt`, and `tibe_decrypt_direct` (a
  single-party stand-in for the real threshold-decryption protocol).
  See "TIBE core algebra" below.
- `test/test_ring.c`, `test/test_gauss.c`, `test/test_wots.c`,
  `test/test_tibe.c` -- the regression suites (see "Validation" below).

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

## WOTS+

The paper pins the one-time signature concretely (Theorem 6, Appendix
A): WOTS+ (Hulsing, Africacrypt 2013), `n=256` bits, Winternitz
parameter `w=16`, all four internal hash functions (the chain function
`f`, the seed-expanding `PRF`, and the message/key-compressing
`H_msg`/`H_key`) instantiated as SHA2-256 with a distinct one-byte
domain-separation prefix each (`toByte(0..3, 32)` -- 31 zero bytes then
the constant). Unlike the Gaussian sampler, there's no approximation
here: this is implemented exactly as specified, and the derived
parameters (`l1=64` message digits, `l2=3` checksum digits, `l=67`
chains, 2144-byte signatures) match the paper's stated figure exactly,
which is itself a small internal-consistency check that the
construction was transcribed and implemented correctly.

**One concrete choice the paper leaves open**: `PRF_seed(y)`'s `y`
argument (used to derive the `w-1=15` shared (key, bitmask) pairs from
the public `seed`) isn't given a specified byte-width. This
implementation encodes `y` as a 4-byte big-endian integer -- a
reasonable, standard-adjacent choice (documented in `wots.c`), but,
like the identity-embedding encoding flagged in `BCHK_PAPER_SPEC.md`
open question #4, a place a from-scratch reader could reasonably make a
different concrete choice and still match the paper's abstract
description.

This is a genuine one-time signature: reusing the same `(sk, vk)` pair
to sign two different messages leaks enough intermediate chain values
to forge a signature on a third message (the classical WOTS+ weakness).
Nothing in this module enforces "sign once" -- that's the caller's
responsibility, and it's exactly what the BCHK+ construction relies on:
a fresh `(sk, vk)` pair is generated per `Encaps` call (Sec 3.4 /
4.6), never reused.

## TIBE core algebra

`tibe.c` implements Algorithms 1 (`Setup`), 2-3 (`Encode`/`Decode`), 4
(`Encrypt`), transcribed directly from the paper's own algorithm-box
page images (re-read at higher fidelity than the initial secondhand
extraction -- see `BCHK_PAPER_SPEC.md`'s header note), plus
`tibe_decrypt_direct`: a single-party stand-in for the real threshold
protocol (Algorithms 5-8, Figure 5), used here to validate the core
algebra before Phase 5 adds real Shamir-sharing and the 3-round
`ShareExtract`/`Combine` protocol on top of the same equations. It
collapses Algorithms 7-8 to the case of one "virtual party" holding the
whole unshared secret directly, with every per-shareholder blinding and
masking term set to zero and a trivial Lagrange coefficient of 1.

**One real ambiguity this re-read resolved**: the initial paper
extraction (done by a different pass reading the PDF for the first
time) rendered `TIBE.Encrypt`'s encryption randomness as `s <-
D_{R^3,ς}` (a 3-dimensional vector), which doesn't type-check against
`v := r*s + e' + Encode(msg)` -- `r`, `e'`, and `Encode(msg)` are each
individually a single ring element, so `r*s` must also be a
single-ring-element product, forcing `s` to be a single ring element
too. Re-reading the algorithm box directly (rather than trusting the
secondhand transcription a second time) confirmed this: `s` is a
single ring element, and `F_vk^T * s` in the `u` equation is scalar
broadcast (each of `F_vk`'s 9 entries scaled by the one value `s`), not
a 9-dimensional matrix-vector product. Fixed in `BCHK_PAPER_SPEC.md`'s
own text isn't done here (that file is a preserved snapshot of the
original extraction pass, kept for provenance) -- the correct reading
lives in `tibe.h`'s header comment and this section instead.

**A second issue, caught only empirically**: implementing
`tibe_decrypt_direct` literally per Algorithms 7-8 (with every
per-shareholder term zeroed) does *not* satisfy Algorithm 8 line 7's
own correctness assertion (`F_vk . z == r`) -- confirmed by hand
algebra (substituting `A0 = (d0, a0*d0, b0*d0)` and `b0 = a0*s_a+e_a-
beta` into the dot product leaves a residual `2*(e_a+a0*s_a) - beta`
term that doesn't cancel against `beta`) and independently by a small
symbolic check in a disposable toy ring (D=8, q=97, not committed to
this repo). Both confirmed the same fix: `z2` must be `-c0`, not `+c0`
as Algorithm 7/8's literal transcription reads. This is now what
`tibe_decrypt_direct` implements, with the derivation recorded inline
in `tibe.c`. Two honest possibilities for *why* the transcribed sign
was wrong, neither resolved here: a PDF-extraction artifact in reading
Algorithm 7/8's `z_{i,2}` line, or a sign-convention difference in how
this implementation's `Decomp_beta` centers coefficients versus the
paper's own convention. **Phase 5, which implements the real
`ShareExtract_2`/`Combine` (not this direct stand-in), needs to
re-derive this independently rather than assume the same one-line fix
generalizes unchanged** -- flagged in `BCHK_TODO.md`.

This is exactly the debugging methodology `src/kyber/README.md`
documents finding real bugs with before ("only caught by checking final
message correctness end to end," re: the missing `poly_invntt_tomont`
step) -- hand-verifying dense multi-matrix ring algebra from page
images is genuinely error-prone, and an end-to-end round-trip test
catches what a page-by-page transcription review did not.

## Performance

A full `Setup` + `Encrypt` + `Decrypt` cycle at this module's real
parameters (d=4096, q~2^101) takes **roughly 9-10 minutes** on this
development machine, measured directly (`test_tibe`'s full original
7-cycle run: 63 minutes wall clock, 35 minutes of that in actual CPU
time). `Decrypt` is the most expensive of the three (`ring_inv`'s O(D^2)
polynomial XGCD, on top of ~20 more O(D^2) `ring_mul` calls building
`F_vk` twice and evaluating both dot products). `test_tibe.c`'s trial
counts are kept deliberately small (one full round trip, plus 2 more in
a loop -- not a larger number) specifically because of this; this is
the real cost of "correctness-first BIGNUM, no NTT" showing up beyond
just a single `ring_mul`, and reinforces that NTT-based multiplication
(`BCHK_TODO.md` phase 8) will matter a lot more once Phase 5-7 need many
more ring operations per decapsulation than this phase's single
non-threshold decrypt does.

## Validation

No public reference implementation of this scheme exists anywhere (this
is a from-scratch build of a paper with no released code) -- same
situation this project was already in for `src/kyber/threshold.c` and
`threshold_decaps`, handled the same way: internal consistency instead
of a byte-exact diff.

`make test` builds and runs four self-contained suites:

- `test_ring`: ring-axiom checks (additive inverse, scalar-mul identity
  and zero, serialize/deserialize round trip), an explicit
  negacyclic-wraparound check (`X^(D-1) * X == -1`, the one algebraic
  property that distinguishes this ring from plain polynomial
  multiplication), one dense-random distributivity check (`a*(b+c) ==
  a*b + a*c`, the real stress test of convolution + mod-`q` reduction
  together), `Decomp_beta` reconstruction (`c0*beta+c1 == x`) and
  boundedness (`|c1| <= beta/2`) checks, and `ring_inv` correctness
  (`a * ring_inv(a) == 1` for a random, overwhelmingly-likely-unit
  `a`). The dense multiply and `ring_inv` checks are the slow ones
  (~30s and comparable respectively, both O(d^2)); the sparse
  identity/zero/wraparound checks are much faster in practice, since a
  zero `BIGNUM` operand makes `BN_mod_mul` nearly instant even though
  the O(d^2) loop still runs.
- `test_gauss`: empirical mean/stddev checks (20,000 samples each) at
  every width this project's Table 2 instantiation actually uses
  (`TIBE_SIGMA_A=8`, `TIBE_SIGMA=4`, `TIBE_SIGMA_P=2^47`), with
  tolerances chosen so the check has a wide margin against a passing
  distribution's own sampling noise (see the file for the exact
  numbers) while still catching a genuinely broken sampler.
- `test_wots`: sign-then-verify round trips (including an empty
  message), and that Verify reliably rejects a tampered message, a
  tampered signature byte, and a valid signature checked against the
  wrong `vk` -- plus a sanity check that two `wots_keygen` calls
  produce different keys.
- `test_tibe`: `Decode(Encode(msg)) == msg`, plus full
  `Setup`->`Encrypt`->`tibe_decrypt_direct` round trips (one single
  cycle, plus 2 more under a fresh `Setup` in a loop -- kept small
  because of the ~9-10 minute-per-cycle cost, see "Performance" above)
  that check both `tibe_decrypt_direct`'s own `F_vk*z==r` assertion and
  that the recovered message matches what was encrypted.

All four currently pass (`test_tibe` takes roughly half an hour;
everything else is under a minute). Representative output:

```
./test/test_ring
(distributivity dense-multiply check took 29.3s)
(ring_inv check took 37.6s)
test_ring: all tests passed
./test/test_gauss
  sigma=8: n=20000 empirical mean=-0.01435 empirical stddev=8.031
  sigma=4: n=20000 empirical mean=0.04825 empirical stddev=4.019
  sigma=1.41e+14: n=20000 empirical mean=7.94e+11 empirical stddev=1.418e+14
test_gauss: all tests passed
./test/test_wots
test_wots: all tests passed
./test/test_tibe
test_tibe: all tests passed
```
