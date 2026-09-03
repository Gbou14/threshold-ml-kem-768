# TIBE / BCHK+ threshold KEM (Phase 1-8a/8b: ring arithmetic, Gaussian sampling, WOTS+, TIBE core algebra, identity embedding, the real threshold protocol, the BCHK+ TKEM layer, live Docker demo, below-threshold/malicious-party testing, an exact Gaussian sampler)

This module is the from-scratch implementation of Lapiha & Prest, "A
Lattice-Based IND-CCA Threshold KEM from the BCHK+ Transform" (Asiacrypt
2025, eprint 2025/1958) -- see `../../BCHK_PAPER_SPEC.md` for the full
algorithm transcription this is built against, and
`../../FO_REDESIGN_CONTEXT.md` for why this paper, not a patched
`src/kyber/`. It lives alongside `src/kyber/`, not inside it: the
existing threshold-ML-KEM-768 code is untouched (`git diff master --
src/kyber/` is empty), so it stays available as the working fallback and
comparison point if this redesign doesn't pan out.

**Status: Phase 1-7 -- the full BCHK+ construction works end to end,
live, over real HTTP.** Ring arithmetic, Gaussian sampling, WOTS+, the
TIBE core algebra, the identity-embedding map `E`, the real 3-round
threshold-decryption protocol, the BCHK+ TKEM layer (`tkem.c`):
`Keygen`/`Encaps`/`ShareDecaps_{0,1,2}`/`Combine`, binding a fresh
one-time WOTS+ signature to each ciphertext (so a shareholder rejects
an invalid ciphertext *before* doing any threshold-decryption work --
the actual trust-model delta this whole redesign exists for, see
below) and running the FO-style decapsulation-consistency check on the
now-public message -- and now a live, 12-container Docker demo
(`../../docker-compose.tibe.yml`, `../tibe_dealer.c`,
`../tibe_shareholder.c`, `../tibe_coordinator.c`): a real dealer
keygen + Shamir-share distribution, followed by a real `T=5`-of-`N=10`
decapsulation over actual HTTP across all 3 rounds, confirmed on its
first live run (`TKEM: 1/1, AES: 1/1` -- see `../../BCHK_TODO.md`
Phase 7 for the exact result). See `../../BCHK_TODO.md` for the full
roadmap. **Below-threshold and malicious-party behavior still isn't
tested at the full-protocol level** -- required before scaling to the
paper's proven `T=32` (Phase 8), per the project owner's explicit
ordering instruction.

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
- `gen_params.py` -- the reproducible derivation script for `q` and the
  ring-splitting roots `r1`/`r2`. Not part of the build; re-run it to
  independently reproduce every constant in `params.h`.
- `ring.c`/`.h` -- `R_q = Z[X]/(X^d + 1)`: add, sub, negate,
  scalar-multiply, negacyclic-convolution multiply, uniform sampling,
  fixed-width serialization, general ring-element inversion
  (`ring_inv`, polynomial extended Euclidean algorithm -- needed
  starting Phase 3, see "TIBE core algebra" below for why this ended
  up here rather than in the identity-embedding phase it was
  originally scoped under), `ring_decomp_beta` (the paper's
  `Decomp_beta`), and, new this phase, the `R_q ~ F_{D/2} x F_{D/2}`
  splitting isomorphism (`ring_split`/`ring_unsplit`/`field_mul`/
  `field_elem`) -- see "Identity embedding" below. See "Why BIGNUM"
  below for the module's general BIGNUM-vs-fixed-width rationale.
- `gauss.c`/`.h` -- exact discrete Gaussian sampling (CDT for the two
  small widths, a Micciancio-Walter convolution construction for the
  two huge ones -- see "Gaussian sampling" below), over either
  `RAND_bytes` or a deterministic ("derandomized") pre-squeezed
  SHAKE-256 stream (`gauss_prg`/`gauss_sample_from_prg`, needed for the
  BCHK+ TKEM's FO-style derandomized `Encaps` -- see "The BCHK+ TKEM
  layer" below). Replaced a Box-Muller approximation in Phase 8b.
- `wots.c`/`.h` -- WOTS+, the one-time signature the BCHK+ transform
  binds to each fresh TIBE ciphertext. See "WOTS+" below.
- `tibe.c`/`.h` -- the TIBE core algebra: `Setup` (non-threshold, Phase
  3 scope), `Encode`/`Decode`, `Encrypt`, and `tibe_decrypt_direct` (a
  single-party stand-in for the real threshold-decryption protocol).
  See "TIBE core algebra" below. New this phase: `tibe_encrypt_derand`,
  an explicit-seed form of `Encrypt` (`tibe_encrypt` is now a thin
  wrapper generating a random seed and delegating to it, matching
  `src/kyber/indcpa.c`'s own derand convention) -- needed by the TKEM
  layer's FO-style derandomization, and `tibe_ct_eq`.
- `identity.c`/`.h` -- the identity-embedding map `E`, turning a fresh
  WOTS+ verification key into the unit ring element `tibe_encrypt`/
  `tibe_decrypt_direct` need as `id`. See "Identity embedding" below.
- `threshold.c`/`.h` -- the real 3-round threshold-decryption protocol:
  Shamir-sharing `(s_a, e_a)`, `threshold_round0`/`1`/`2` (Algorithms
  5-7), and `threshold_combine` (Algorithm 8), replacing
  `tibe_decrypt_direct`'s single-party stand-in with genuine
  multi-party decryption. See "The real 3-round threshold protocol"
  below.
- `tkem.c`/`.h` -- the BCHK+ TKEM layer: `Keygen`/`Encaps`/
  `ShareDecaps_{0,1,2}`/`Combine`, binding a fresh WOTS+ signature to
  each ciphertext and running the FO-style decapsulation-consistency
  check. See "The BCHK+ TKEM layer" below.
- `test/test_ring.c`, `test/test_gauss.c`, `test/test_wots.c`,
  `test/test_tibe.c`, `test/test_identity.c`, `test/test_threshold.c`,
  `test/test_tkem.c` -- the regression suites (see "Validation"
  below).

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

**`r1`, `r2`** (Phase 4): the splitting roots satisfying `X^D+1 =
(X^{D/2}-r1)(X^{D/2}-r2) mod q`, needed for `R_q`'s `F_{D/2} x F_{D/2}`
isomorphism. `gen_params.py` computes `r1 = sqrt(-1) mod q` via the
closed-form square-root formula for primes `q = 5 (mod 8)`, `r2 = -r1
mod q`; both `q = 5 (mod 8)` (guaranteeing `-1` is a quadratic residue)
and `r1^2 == -1 (mod q)` are re-checked in the script itself on every
run, not just asserted once by hand.

```
r1 = 1000758434189149340966437569673  (0xca19ff9800da9c26c4d00c489)
r2 = 266892166039080060530265635980  (0x35e60067ff2563d93b2ff3c8c)
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
side-channel pitfalls.

**Through Phase 8a**, `gauss_sample_coeff` drew two uniform doubles from
OpenSSL `RAND_bytes`, ran the standard Box-Muller transform to get a
continuous standard-normal sample, scaled by `sigma`, and rounded to the
nearest integer -- a widely-used *practical approximation* of a discrete
Gaussian, not the paper's formal object, and not constant-time (`log`,
`cos`, `sqrt` all have data-dependent timing on typical hardware). Good
enough to validate the *algebra* of Phases 1-7 (does noise-flooding
correctness hold, does `Decode` round correctly), explicitly flagged as
not good enough to make a security claim about the resulting system.

**Phase 8b** replaces it with an exact sampler, in two pieces:

**Small widths (`TIBE_SIGMA=4`, `TIBE_SIGMA_A=8`): an exact
cumulative-distribution table (CDT).** Built once per distinct sigma
(and cached, same lazy-static-global convention `ring.c`'s
`ring_modulus()` already uses for `q`, `r1`, `r2`) via 256-bit
fixed-point BIGNUM arithmetic: an exact `exp(-y)` via standard range
reduction (`y = n*ln(2) + r`, `0 <= r < ln(2)`, both computed by their
own fast-converging fixed-point series) times a `2^-n` bit shift --
numerically robust, unlike e.g. `erf`'s slowly-converging, cancellation-
prone series at large arguments, which is why this samples the PMF
directly (`rho(k) = exp(-k^2/(2*sigma^2))`) rather than inverting a CDF.
The table covers `k` in `[-tau*sigma, tau*sigma]` for `tau=15`
(`GAUSS_TAU` in `gauss.c`) and is renormalized to sum to exactly 1 over
that truncated range -- the resulting truncation error is the dominant
source of statistical distance from the true (untruncated) discrete
Gaussian, bounded by the standard Gaussian tail estimate at
`~2*exp(-tau^2/2)` per coefficient, which even after a union bound over
one ring element's `TIBE_D=4096` coefficients is about `2^-150` --
comfortably negligible. Every *sample* (not table build, which is a
one-time, public-parameter computation with no timing sensitivity) does
a full, un-early-exited linear scan over all table entries, so the
number of iterations and memory locations touched depends only on the
(public) `sigma`, not on the drawn value.

**Huge widths (`TIBE_SIGMA_PRIME=2^19`, `TIBE_SIGMA_P=2^47`): built from
the small CDT via Micciancio & Walter's convolution theorem** ("Gaussian
Sampling over the Integers: Efficient, Generic, Constant-Time," CRYPTO
2017 / eprint 2017/259, Theorem 2.1, itself building on Peikert's
original convolution theorem). A CDT table directly at `sigma=2^47`
is infeasible (it would need on the order of `sigma` entries). Instead:
if `x1, x2` are independent draws of width `s` and `s >= sqrt(2)*|k|*
eta_eps(Z)` (`eta_eps(Z) < 6` for `eps <= 2^-160`, per that paper),
then `k*x1 + x2` is statistically close to `D_{Z, s*sqrt(k^2+1)}` for
any integer `k` respecting that bound. Starting from an internal base
width of 16 (`GAUSS_CONV_BASE_SIGMA`, chosen with ~1.9x margin above the
`sqrt(2)*6 ~ 8.49` minimum) and greedily maximizing `k` at each step
(capped by that bound, which itself grows with the current width), the
achievable width grows roughly *quadratically* per combination level --
reaching `2^47` takes only ~7 levels (`gauss_build_schedule` in
`gauss.c` derives the exact integer schedule at runtime, per target
sigma, and caches it), i.e. a binary tree of depth 7 needing only
`2^7=128` base-CDT draws total, not the `(2^47/16)^2` a naive
fixed-coefficient sum would need. `TIBE_SIGMA_PRIME=2^19` needs only
~5 levels (32 base draws). The schedule is tuned at its last level to
land within about 1% of the target width, never under it (more
blinding noise is conservative for the flooding/hiding property this
width exists for; the params.h derivation already notes `2^19` clears
Theorem 3's correctness *lower* bound with comfortable margin, so a ~1%
overshoot doesn't threaten correctness either).

**Overall statistical-distance accounting** (see `gauss.c`'s own
comments for the per-piece numbers): CDT truncation dominates, at about
`2^-150` per ring-element sample of a direct-CDT width and about
`2^-140` for a convolution-built width (more leaf draws, each
individually well below that bound); the fixed-point table-construction
precision (256 bits) and the convolution theorem's own approximation
term (bounded by the `eps=2^-160` `eta_eps(Z)` choice, accumulated over
~7 levels) are both far smaller still. This is a computed, documented
bound for a solo research implementation, not a formal, independently
audited security proof -- flagged honestly, same posture as everywhere
else in this project.

**What "constant-time" does and doesn't mean here**, carried over
explicitly from the design decision above: a fixed, sigma-determined
(i.e. determined by a *public* parameter) number of loop iterations and
memory accesses in this module's own C code, with no data-dependent
branch on the *sampled value* or *drawn randomness*. It has **not** been
verified against microarchitectural side channels with a dedicated tool
(e.g. ctgrind, dudect) -- genuinely out of scope for a solo research
project without specialized tooling, and a real, honestly-flagged
limitation rather than a claim this module doesn't back up.

Validated in `test/test_gauss.c`: the same empirical mean/stddev checks
the Box-Muller version used, at all four widths, over both the
`RAND_bytes` and `gauss_prg`-driven paths; plus (new, since sampling is
now exact rather than approximate) a direct empirical-PMF-vs-theoretical
-PMF goodness-of-fit check for the two direct-CDT widths, comparing this
module's BIGNUM fixed-point `exp` against an independently-computed
plain-double `exp` -- a check Box-Muller's continuous approximation
couldn't meaningfully support. See `BCHK_TODO.md` Phase 8b for the
before/after performance numbers.

## WOTS+

The paper pins the one-time signature concretely (Theorem 6, Appendix
A): WOTS+ (Hulsing, Africacrypt 2013), `n=256` bits, Winternitz
parameter `w=16`, all four internal hash functions (the chain function
`f`, the seed-expanding `PRF`, and the message/key-compressing
`H_msg`/`H_key`) instantiated as SHA2-256 with a distinct one-byte
domain-separation prefix each (`toByte(0..3, 32)` -- 31 zero bytes then
the constant). This is implemented exactly as specified (written when
the Gaussian sampler was still the Box-Muller approximation Phase 8b
later replaced -- WOTS+ never had that caveat), and the derived
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

## Identity embedding

`identity.c` implements `E : S_vk -> R_q` (the paper's Sec 4.2
"Identity Embedding"), the map that lets a fresh WOTS+ verification key
serve as a TIBE identity. Two pieces, both in `ring.c`/`identity.c`:

- **`ring_split`/`ring_unsplit`** (`ring.c`): the `R_q ~ F_{D/2} x
  F_{D/2}` isomorphism `f`/`f^-1` from Lemma 1, using the `r1`/`r2`
  splitting roots (see "Parameter choices"). Concretely: writing a ring
  element as `m = m_low + X^{D/2}*m_high` (its low and high halves),
  `f(m) = (m_low + r1*m_high, m_low + r2*m_high)` -- reduction mod each
  of the two factors `X^{D/2}-r1`, `X^{D/2}-r2`. This is automatically
  a ring homomorphism (reduction mod an ideal always is) and, by CRT
  (the two ideals are coprime since `r1 != r2`), an isomorphism onto
  the product -- validated directly, not just asserted: `test_ring.c`
  checks `f` is a mutual inverse of `f^-1`, is additive
  (`f(a+b)==f(a)+f(b)`), and -- the strongest check -- **multiplicative**
  (`f(a*b) == f(a) *_field f(b)`, using each factor's own `field_mul`,
  mod `X^{D/2}-r_i` rather than `R_q`'s `X^D+1`), confirming `f` is a
  genuine ring isomorphism rather than just a convenient additive
  bookkeeping trick.
- **`identity_embed_field`** (`E_F`, `identity.c`): a WOTS+ `vk`
  (`seed || vk1`, 512 bits) hashed via domain-separated SHAKE-256 into
  a nonzero element of `F_{D/2}` (`TIBE_D/2 = 2048` coefficients, each
  reduced mod `q`) -- collision-resistant rather than formally
  injective, which the paper's own analysis says suffices here
  (`BCHK_PAPER_SPEC.md` open question #4: `|S_vk| = 2^512` is
  astronomically smaller than `|F_{D/2}| ~ q^2048`, so a coincidental
  collision that also breaks the security property is independently
  negligible). Retries (domain-separated by a trailing counter byte,
  never expected to actually fire) if a hash output ever lands on the
  zero element.

`identity_embed` (`E`) is then literally `ring_unsplit(y, y)` for `y =
E_F(vk)` -- embedding the *same* field value into both factors, exactly
the paper's own `E(vk) := f^-1(E_F(vk), E_F(vk))` definition, implemented
by calling the general `ring_unsplit` rather than a hand-derived
shortcut. It happens to work out algebraically to "`E(vk)`'s low `D/2`
coefficients are `E_F(vk)`, high `D/2` coefficients are 0" (since
`y1==y2` makes `ring_unsplit`'s `m_high = (y1-y2)*(r1-r2)^-1` term
vanish) -- but that simplification is left for `ring_unsplit` itself to
produce, not special-cased in `identity.c`, so a bug in the "obvious"
shortcut can't silently diverge from the paper's actual definition.

**The security property this all exists for** -- for `vk0 != vk1`,
`E(vk0)-E(vk1)` must be a unit in `R_q` (needed by the paper's security
proof, `BCHK_PAPER_SPEC.md` Sec 3.5) -- is checked directly in
`test_identity.c`, not just argued for: `E(vk0)-E(vk1)` is inverted via
`ring_inv`, and the product with that inverse is checked to equal `1`.
The argument for *why* this holds (embedding the same value into both
factors means the difference's image under `f` is `(d, d)` for `d =
E_F(vk0)-E_F(vk1)`, a nonzero coefficient vector that is therefore
nonzero in *either* factor field regardless of which of the two
different multiplication rules is imposed on it, hence a unit by CRT)
is recorded in `identity.h`'s header comment -- but the test doesn't
trust the argument, it checks the actual inversion succeeds.

## The real 3-round threshold protocol (`threshold.c`)

This is the piece that turns everything built in Phases 1-4 into an
actual *threshold* scheme: `(s_a, e_a)` are genuinely Shamir-shared
across `TIBE_N` parties (coefficient-wise, same construction as
`src/kyber/threshold.c`'s `threshold_split_secret`, generalized from
`int32`/mod-3329 to BIGNUM/mod-`q`), and any `TIBE_T` of them jointly
recover a message via the paper's `ShareExtract_{0,1,2}`/`Combine`
protocol (Algorithms 5-8) -- replacing `tibe_decrypt_direct`'s
single-party stand-in with the real thing. `threshold_setup` also
distributes `d0` directly (not secret-shared -- see `tibe.h`'s
`tibe_msk` comment for why every party needs it un-split) and a
pairwise PRF seed per `{i,j}` pair (both parties get the same seed
from the dealer and derive both directional sub-seeds themselves via
domain-separated hashing), matching the paper's "distributed over a
secure channel" trusted-dealer model (Remark 1) that this repo's
`src/dealer.c` already implements for the Kyber side.

**Two more issues this phase's own testing caught**, on top of Phase
3's `z2` sign fix (re-confirmed here to still apply, unchanged, to the
real multi-party case -- see below):

- **`y_{i,0}`'s formula.** The paper's Algorithm 5 line 2 was initially
  read as the scalar formula `y_{i,0} = a0*p_{i,0}+p_{i,1}`, using raw
  (unpublished) `a0`. Building the real protocol against that reading
  broke down in a way Phase 3's single-party test couldn't have caught:
  a symbolic toy-ring check of the *full* multi-party construction
  (real Shamir shares, real pairwise masking, `T` distinct active
  parties) showed `F_vk*z==r` failing regardless of the `z2` sign,
  even with masking and Lagrange reconstruction independently verified
  correct in isolation. The fix, found by testing the structurally
  obvious alternative: `y_{i,0} = A0.p_i`, a proper 3-vector dot
  product against the *published* `A0` -- exactly mirroring
  `y_{i,1} = (A1-E(vk)*G).x_{i,0}` and `y_{i,2} = A2.x_{i,1}`'s own
  pattern. With that fix, the full toy-ring check (real masking, real
  T-of-N reconstruction, non-trivial active sets) closes exactly. In
  hindsight the original reading breaking the symmetry between the
  three `y_i` lines should have been a signal on its own; the working
  hypothesis is a PDF-extraction slip reading a compact dot-product
  notation as a scalar formula. One consequence: no shareholder needs
  raw `a0` at all -- an `a0` field was briefly added to `tibe_msk`/
  `threshold_share` under the wrong reading and removed once the fix
  landed; only `ek` (for `A0`/`A1`/`A2`/`G`) and `d0` (for
  `Decomp_beta`) are needed beyond a party's own Shamir share.
- **`z2`'s sign, re-verified for the real protocol.** Phase 3 found
  `z2 = -c0` (not the literal `+c0`) for the single-party stand-in.
  That derivation didn't touch the noise-flooding/masking machinery at
  all, so it wasn't obvious in advance whether the same sign would
  keep working once real blinding and masking were layered on top --
  it does, confirmed by the same toy-ring check (with the `y_{i,0}`
  fix above) and by this phase's own full C-level end-to-end test.

**The full round-by-round shape**, matching Algorithms 5-8 directly:

1. **Round 0** (`threshold_round0`): each active party samples fresh
   blinding `(p_i, x_{i,0}, x_{i,1})` (9 ring elements, width
   `TIBE_SIGMA_P = 2^47` -- the "flood and submerge" noise from
   `gauss.c`), computes `w_i = A0.p_i + (A1-E(vk)*G).x_{i,0} + A2.x_{i,1}`,
   and returns only a commitment `H_cmt(w_i)` -- `w_i` itself stays
   private until round 1.
2. **Round 1** (`threshold_round1`): trivial reveal of `w_i`.
3. **Round 2** (`threshold_round2`): every party first checks every
   *other* active party's revealed `w_j` against its round-0
   commitment (Algorithm 7 line 1) -- returns failure immediately if
   any doesn't match, catching a party that lied in round 0/1 before
   any further computation. Then: derive the pairwise mask `m_i` (sum
   of `H_mask(seed_{i->j}, ctnt)` minus `H_mask(seed_{j->i}, ctnt)`
   over every other active `j`, where `ctnt` canonically serializes the
   active set, ciphertext, and every collected `(cmt_j, w_j)` --
   `build_ctnt`/`h_mask` in `threshold.c`), sum `w = sum(w_j)`, derive
   `(c0,c1)` via `Decomp_beta(d0^-1*(r-w))` (needing `ring_inv` again,
   locally, by every active party), and compute this party's
   contribution `(z_i, x_{i,0}, x_{i,1})` using its own Shamir share
   scaled by its Lagrange coefficient.
4. **Combine** (`threshold_combine`): sums every contribution, adds
   `c1` to `z0` and subtracts `c0` from `z2`, rebuilds `F_vk`, and runs
   Algorithm 8 line 7's own correctness assertion (`F_vk*z==r`) before
   decoding -- independently re-deriving `(c0,c1)` from the public
   `w` rather than trusting any one party's already-computed value (a
   deliberate, documented choice to keep the implementation obviously
   correct at the cost of one extra `ring_inv`, not a security
   requirement -- `c0`/`c1` are public-derivable by that point).

**Why this is still the "no implicit trust in the combiner" property**
(see "The actual trust-model delta" above, now with the real protocol
behind it rather than a placeholder): nothing in this round structure
gives the combiner (whoever runs `Combine`) anything a shareholder
didn't already have to reveal to complete the protocol honestly, and
the CCA-relevant validity check (Sec 3.4's `SIG.Verify`) still hasn't
entered the picture at all -- that's the TKEM/BCHK+ layer, Phase 6,
still ahead. What Phase 5 adds is that the *decryption* itself is now
genuinely distributed, with cheating shareholders caught via
commit-then-reveal rather than silently trusted.

## The BCHK+ TKEM layer (`tkem.c`)

This is the layer that actually delivers the trust-model delta
documented at the top of this file: `Keygen`/`Encaps`/
`ShareDecaps_{0,1,2}`/`Combine` (Figure 3 / Sec 4.6), wrapping
everything from Phases 1-5 with the one-time-signature binding that
makes ciphertext validity a public, independently-checkable fact
rather than something only the combiner discovers after the fact.
`tkem_keygen` is literally `tibe_setup` (the paper's `TKEM.Keygen ==
TIBE.Setup`, no TKEM-specific work); the interesting pieces are
`Encaps` and `Combine`:

- **`tkem_encaps`**: samples a random `msg`, derives `rand = G_fo(msg)`
  (a `SHAKE-256`-based 32-byte seed, `TIBE_ENCRYPT_SEED_BYTES`), and
  generates a **fresh** WOTS+ keypair -- every call, never reused, per
  WOTS+'s own one-time-signature requirement (`wots.c`/`README.md`
  "WOTS+"). It then calls `tibe_encrypt_derand(ek, id=E(vk), msg,
  rand)` -- the new derandomized `Encrypt` this phase added -- signs
  the serialized ciphertext with the fresh `sk`, and derives the final
  shared secret `K = H_fo(msg||ct)`.
- **`tkem_verify_ct`**: `SIG.Verify((vk,ct,sig))` -- the actual BCHK
  check, on entirely public values. `tkem_share_decaps_0/1/2` each run
  this *before* doing any of the wrapped `threshold_round0/1/2` work
  (returning 0 immediately on failure, without ever touching a
  shareholder's Shamir share), and `tkem_combine` runs it too --
  matching the paper's Figure 3 exactly, where every `ShareDecaps_j`
  and `Combine` call independently re-checks validity rather than
  trusting an earlier check.
- **`tkem_combine`**: after `SIG.Verify`, calls `threshold_combine`
  (Phase 5, already checks its own `F_vk*z==r` assertion internally)
  to recover `msg`. Then the FO-style consistency check: re-derive
  `rand = G_fo(msg)` and re-run `tibe_encrypt_derand` with the
  *same* `(ek, id, msg, rand)` -- since `Encrypt` is now fully
  derandomized, this must reproduce the *exact* ciphertext
  (`tibe_ct_eq`) for an honestly-generated `ct`. This is the whole
  "avoid FO's threshold problem" trick made concrete: `msg` is already
  public and safely reconstructed by the time this runs, so re-running
  `Encrypt` here needs no thresholdization at all -- it's just a local
  equality check, on the same footing as recomputing a hash.
  `K = H_fo(msg||ct)` on success.

**Derandomization, the piece that made this layer possible**:
`TIBE.Encrypt` (Phase 3) originally sampled its own randomness
(`s`, `e[9]`, `e'`) directly from `RAND_bytes` via `gauss_sample`, with
no way to reproduce the same ciphertext twice. `tibe_encrypt_derand`
takes an explicit 32-byte seed instead, expands it via one large
SHAKE-256 squeeze (`gauss_prg`) into a deterministic byte stream, and
draws every random value from that stream instead
(`gauss_sample_from_prg`) -- sharing the same sampler (originally
Box-Muller, now the exact CDT/convolution sampler from Phase 8b) as the
original `RAND_bytes`-driven path (`gauss.c`), so the two entry points
can't silently drift apart. The `gauss_prg` byte budget itself is no
longer a flat per-element figure (Phase 8b: direct-CDT widths need 32
bytes/coefficient, the convolution-built `TIBE_SIGMA_PRIME` needs far
more) -- `tibe_encrypt_derand` computes it via `gauss_bytes_per_coeff`
rather than a hardcoded constant; see "Gaussian sampling" above.
Validated two ways: the existing `gauss_sample`/`gauss_sample_coeff`
statistical checks still pass unchanged (confirming the refactor didn't
perturb the original path), a new statistical check on the `gauss_prg`
path at `TIBE_SIGMA` (`test_gauss.c`), and, most directly, `test_tibe.c`'s
full `Setup`->`Encrypt`->`Decrypt` suite re-run and re-passing end to
end now that `tibe_encrypt` routes through the derandomized path
internally.

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
(`BCHK_TODO.md` phase 8) matters even more once the real protocol is
involved -- confirmed below.

**The real 3-round protocol is slower still, as expected.** A full
`T=5`-of-`N=10` decapsulation (`test_threshold.c`'s
`test_full_threshold_decapsulation`) took **~35 minutes** wall clock
end to end (measured directly). Each active party's round 0 alone is
~10 `ring_mul`-equivalents (building `A0.p_i` + `(A1-id*G).x_{i,0}` +
`A2.x_{i,1}`, ~100s), times 5 parties; round 2 adds one more `ring_inv`
per party (~35-40s each) plus a handful more multiplies; `Combine`
rebuilds `F_vk` and does the 18-multiply dot-product/assert/decode
sequence, plus its own independent `ring_inv`. `test_threshold.c` runs
this exactly once (not repeated) for the same reason `test_tibe.c`
keeps its trial count small -- see `BCHK_TODO.md` phase 8's now
higher-priority NTT-based-multiplication note, and phase 8's
Docker-wiring implications (Phase 7 will need to budget for this cost
per real decapsulation, not just per test run).

**Phase 8a's two full-protocol checks, measured**: `test_threshold.c`'s
total runtime grew from ~35 minutes to **~47.5 minutes** once the
below-threshold and malicious-party checks landed (`test_full_protocol_gaps`,
sharing one `Setup`/`Encrypt` with both). The below-threshold check
(`T-1=4` honest parties, real round0/round2/`Combine`) costs roughly
`4/5` of a full cycle's round0/round2 work, as expected. The
malicious-party check is much cheaper than a naive "run a full cycle"
estimate would suggest: it reuses a real `T=5` round0 (~500s, the
dominant cost) but the actual detection -- one honest party's round2
call against the corrupted set -- returns almost immediately, since
`threshold_round2`'s commitment-verification loop runs before any of
the expensive `ring_inv`/masking work.

**The full TKEM layer, measured**: `test_tkem.c`'s one full
`Keygen`->`Encaps`->`ShareDecaps`(`T=5`-of-`N=10`)->`Combine` cycle
took **~30 minutes** wall clock -- essentially the same real
threshold-protocol cost as Phase 5's measurement above, plus
`Encaps`'s own `Encrypt` call and `Combine`'s FO re-encryption check
(one more `Encrypt` call each -- not separately isolated/timed here,
but each is a single `Encrypt`'s worth of `ring_mul`s, a small
fraction of the threshold protocol's own cost). The two cheap tests
(`Encaps`+verify round trip, tampered-ciphertext rejection) are each
dominated by exactly one `Encrypt` call (a couple of minutes, not the
threshold protocol's tens of minutes) -- WOTS+ sign/verify itself is
negligible next to the ring arithmetic.

**Phase 8b's exact sampler, measured against the numbers above**: a
full re-run of every test binary (`test_ring` through `test_tkem`)
after replacing Box-Muller confirms the same correctness (all pass)
at a real but modest slowdown, since a CDT lookup (many cheap integer
compares) or a convolution draw (a shallow tree of CDT lookups) does
genuinely more work than one `log`/`cos` call, even though both are
tiny next to this module's dominant cost (`ring_mul`/`ring_inv`):

| test | before 8b | after 8b |
| --- | --- | --- |
| `test_gauss` | (near-instant) | 14s |
| `test_tibe` (Setup+Encrypt+Decrypt) | ~9-10 min | 20m29s |
| `test_threshold` (incl. Phase 8a's gap-closing checks) | ~47.5 min | 57m44s |
| `test_tkem` (Keygen->Encaps->ShareDecaps->Combine) | ~30 min | 34m15s |

`test_tibe` shows the largest relative jump (roughly 2x) since `Setup`
and `Encrypt` are proportionally more Gaussian-sampling-heavy than the
threshold/TKEM tests, where `ring_mul`/`ring_inv` cost dominates even
more heavily and the sampler's slice of the total is smaller. Notably,
sampling the two huge widths (`TIBE_SIGMA_PRIME=2^19`,
`TIBE_SIGMA_P=2^47`) turned out cheap in absolute terms despite going
through a 5-7-level convolution tree per coefficient -- `test_gauss`'s
own huge-width checks (5000 samples each, `check_stats`) complete in a
few seconds -- confirming the convolution construction's whole point
(logarithmically many cheap base draws, not a naive
quadratic-in-sigma cost) actually pays off in practice, not just in the
asymptotic argument. This keeps NTT-based ring multiplication (still
unimplemented) the dominant remaining performance lever, not the
Gaussian sampler -- see `BCHK_TODO.md` phase 8's note on this.

## Validation

No public reference implementation of this scheme exists anywhere (this
is a from-scratch build of a paper with no released code) -- same
situation this project was already in for `src/kyber/threshold.c` and
`threshold_decaps`, handled the same way: internal consistency instead
of a byte-exact diff.

`make test` builds and runs seven self-contained suites:

- `test_ring`: ring-axiom checks (additive inverse, scalar-mul identity
  and zero, serialize/deserialize round trip), an explicit
  negacyclic-wraparound check (`X^(D-1) * X == -1`, the one algebraic
  property that distinguishes this ring from plain polynomial
  multiplication), one dense-random distributivity check (`a*(b+c) ==
  a*b + a*c`, the real stress test of convolution + mod-`q` reduction
  together), `Decomp_beta` reconstruction (`c0*beta+c1 == x`) and
  boundedness (`|c1| <= beta/2`) checks, `ring_inv` correctness
  (`a * ring_inv(a) == 1` for a random, overwhelmingly-likely-unit
  `a`), and the `ring_split`/`ring_unsplit` isomorphism checks
  described in "Identity embedding" above (round trip, additive, and
  multiplicative homomorphism). The dense multiply, `ring_inv`, and
  multiplicative-homomorphism checks are the slow ones (all O(d^2) or
  close to it); the sparse identity/zero/wraparound checks and the
  split/unsplit round-trip/additive checks are much faster in
  practice (the latter are only O(d), not O(d^2)).
- `test_gauss`: empirical mean/stddev checks at all four widths this
  project's Table 2 instantiation uses (`TIBE_SIGMA_A=8`, `TIBE_SIGMA=4`,
  `TIBE_SIGMA_PRIME=2^19`, `TIBE_SIGMA_P=2^47`), on both the
  `RAND_bytes`- and `gauss_prg`-driven paths, with tolerances chosen so
  the check has a wide margin against a passing distribution's own
  sampling noise (see the file for the exact numbers) while still
  catching a genuinely broken sampler; plus, since Phase 8b, a direct
  empirical-PMF-vs-theoretical-PMF goodness-of-fit check at the two
  direct-CDT widths (see "Gaussian sampling" above).
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
- `test_identity`: `E_F(vk)` is nonzero, `E(vk)` actually satisfies its
  own definition (`split(E(vk)) == (E_F(vk), E_F(vk))`), 3 distinct
  `vk`s give 3 pairwise-distinct `E(vk)` values, and -- the one that
  matters for security, not just internal consistency -- `E(vk0) -
  E(vk1)` really is a unit (`ring_inv` succeeds and the product with it
  is `1`) for two distinct freshly-generated `vk`s.
- `test_threshold`: a cheap, direct check (no `ring_mul`, so fast) that
  Shamir-sharing has the real threshold property -- reconstructing
  `s_a`/`e_a` from all `N` or from exactly `T=5` shares (a non-trivial
  subset, `{2,4,6,8,10}`, not just `{1..5}`) matches the original, and
  reconstructing from only `T-1=4` shares does *not* -- plus one full,
  expensive (~35 min, see "Performance") run of the real 3-round
  protocol: real Shamir shares, a real WOTS+-embedded identity, real
  pairwise masking, a non-trivial active set, checking both
  `threshold_combine`'s own `F_vk*z==r` assertion and that the
  recovered message matches what was actually encrypted. **Phase 8a**
  added two more checks at this same *full protocol* level (not just
  the cheap Shamir-only check above), sharing one `Setup`/
  `threshold_setup`/`Encrypt` to amortize the expensive one-time cost:
  `T-1=4` honest parties running the real round0/round1/round2/
  `Combine` sequence do *not* recover the correct message (checked
  directly -- either `Combine`'s `F_vk*z==r` assertion fails, or the
  decoded message is wrong, not assumed from the Shamir property
  alone); and, separately, corrupting one party's revealed `w` after a
  real round0/round1 (simulating it lying about what it committed to)
  is caught by an honest party's round2 -- Algorithm 7 line 1's
  commit-then-reveal check, exercised over the real protocol rather
  than just existing in the code. The malicious-party check is
  comparatively cheap despite reusing a full real round0 (~500s for
  5 parties): `threshold_round2`'s commitment-verification loop runs
  *before* any of the expensive `ring_inv`/masking work, so a caught
  liar returns almost immediately.
- `test_tkem`: a valid `Encaps` output verifies (cheap -- one `Encrypt`
  call, no threshold protocol); a tampered ciphertext (a flipped `v`
  coefficient, or a flipped signature byte) fails verification, and
  `tkem_share_decaps_0` rejects it before doing any TIBE-layer work;
  and one full, expensive (~30 min, see "Performance") end-to-end run
  of `Keygen`->`Encaps`->`ShareDecaps`(`T=5`-of-`N=10`)->`Combine`,
  checking that every step succeeds and that the shared secret
  `Combine` derives matches exactly what `Encaps` produced.

All seven currently pass (`test_tibe` takes roughly half an hour,
`test_threshold` roughly 47 minutes (up from ~35 once Phase 8a's two
extra full-protocol checks landed), `test_tkem` roughly 30 minutes;
everything else is well under 2 minutes each). Representative output:

```
./test/test_ring
(distributivity dense-multiply check took 29.3s)
(ring_inv check took 37.6s)
(split multiplicative-homomorphism check took 15.8s)
test_ring: all tests passed
./test/test_gauss
  sigma=8: n=20000 empirical mean=-0.01435 empirical stddev=8.031
  sigma=4: n=20000 empirical mean=0.04825 empirical stddev=4.019
  sigma=1.41e+14: n=20000 empirical mean=7.94e+11 empirical stddev=1.418e+14
  [prg] sigma=4: n=20000 empirical mean=-0.02695 empirical stddev=3.997
test_gauss: all tests passed
./test/test_wots
test_wots: all tests passed
./test/test_tibe
test_tibe: all tests passed
./test/test_identity
test_identity: all tests passed
./test/test_threshold
test_threshold: all tests passed
./test/test_tkem
test_tkem: all tests passed
```
