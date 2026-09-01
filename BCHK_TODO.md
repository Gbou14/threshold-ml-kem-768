# BCHK+ threshold-KEM redesign — roadmap (branch `bchk-redesign`)

Goal: implement Lapiha & Prest's BCHK+ threshold KEM (Asiacrypt 2025,
eprint 2025/1958) as real, validated code in `src/tibe/`, avoiding the
Fujisaki-Okamoto threshold-unfriendliness that `src/kyber/threshold_decaps`
has (see `src/kyber/README.md` "Phase 5" and `FO_REDESIGN_CONTEXT.md`).
This is a *new module alongside* `src/kyber/`, not a modification of it --
`src/kyber/` is untouched on this branch and stays the working fallback.
See `BCHK_PAPER_SPEC.md` for the full algorithm transcription this is
built against, and `src/tibe/README.md` for Phase 1's design decisions.

**Not "Kyber, patched."** This is a different lattice (MLWE-family)
construction from scratch (threshold IBE + a one-time signature), with
much larger parameters (d=4096 vs 256, q~2^101 vs ~12 bits, ~450 KiB
ciphertexts vs ~1 KB). Still lattice-based/post-quantum; not literally
ML-KEM.

## Status

- [x] Phase 0: literature search, paper selection, full 42-page read ->
      `BCHK_PAPER_SPEC.md`
- [x] Phase 1: ring arithmetic + Gaussian sampling foundation
      (`src/tibe/ring.c`, `src/tibe/gauss.c`)
  - [x] `R_q = Z[X]/(X^4096+1)` over a 101-bit prime `q = 5 (mod 8)`,
        BIGNUM-backed (add/sub/neg/scalar-mul/negacyclic-mul/uniform
        sampling/serialization)
  - [x] Concrete `q` derived and independently confirmed prime
        (`src/tibe/gen_params.py`, `openssl prime`)
  - [x] Gaussian-*approximating* sampler (Box-Muller + round) at the
        three widths this project's Table 2 instantiation needs --
        explicitly flagged as a practical approximation, not the
        paper's formal discrete Gaussian (see `src/tibe/README.md`)
  - [x] `T=5, N=10` chosen for this pass (paper proves `T=32`; confirmed
        safe-for-correctness-but-not-re-derived-for-security with the
        project owner, see `src/tibe/README.md` "Parameter choices")
  - [x] `make test` passes (`test_ring`, `test_gauss`)
- [x] Phase 2: WOTS+ one-time signature (`src/tibe/wots.c`)
  - [x] SHA2-256-based `f`/`PRF`/`H_msg`/`H_key` with the paper's
        `toByte(0..3,32)` domain separation (`BCHK_PAPER_SPEC.md` Sec
        3.3, Theorem 6); n=256, w=16, l1=64, l2=3, l=67, 2144-byte
        signatures -- matches the paper's stated figure exactly
  - [x] `PRF_seed`'s index argument encoded as 4 big-endian bytes -- a
        concrete choice the paper leaves open, documented in
        `src/tibe/wots.c` and `src/tibe/README.md` "WOTS+"
  - [x] `make test` passes (`test_ring`, `test_gauss`, `test_wots`) --
        sign/verify round trips, tampered-message/signature/wrong-vk
        rejection, no public reference to diff against (none exists for
        this exact instantiation)
- [x] Phase 3: TIBE core algebra, non-threshold (`src/tibe/tibe.c`)
  - [x] Re-read the paper's actual algorithm-box page images directly
        (higher fidelity than the initial secondhand extraction) --
        caught and fixed one real transcription issue: `Encrypt`'s
        randomness `s` is a single ring element, not 3-dimensional
        (forced by `v`'s equation type-checking); `BCHK_PAPER_SPEC.md`
        itself is left as the original snapshot for provenance, the
        correction lives in `tibe.h`/`src/tibe/README.md` instead
  - [x] `ring_inv` (general ring-element inversion via polynomial
        extended Euclidean algorithm over the field Z_q) and
        `ring_decomp_beta` added to `ring.c` -- re-scoped here from
        "Phase 4" (see below) since Decrypt's own algebra needs
        `d0^-1` directly, independent of the identity-embedding work
  - [x] `Setup`/`Encode`/`Decode`/`Encrypt`/`tibe_decrypt_direct`
        (a single-party stand-in for the real threshold protocol)
        implemented and validated by full round-trip testing
  - [x] Caught a real algebra bug empirically (not by hand-derivation
        alone): literal Algorithm 7/8 transcription gives `z2 = +c0`,
        which does not satisfy Algorithm 8's own `F_vk*z==r`
        assertion; the fix (`z2 = -c0`) was found via a disposable toy
        symbolic check and confirmed by hand algebra, documented
        in-line in `tibe.c` and in `src/tibe/README.md` "TIBE core
        algebra". **Not yet re-derived against the real (threshold)
        Algorithm 7/8 -- Phase 5 needs to check this independently
        rather than assume the same one-line fix generalizes.**
  - [x] `make test` passes (`test_ring`, `test_gauss`, `test_wots`,
        `test_tibe`) -- full `Setup`->`Encrypt`->`Decrypt` round trips
        recover the original message
  - [x] Measured real performance: ~9-10 minutes per full
        Setup+Encrypt+Decrypt cycle at d=4096 (BIGNUM, no NTT) -- see
        `src/tibe/README.md` "Performance"; raises the priority of
        Phase 8's NTT-based-multiplication stretch goal for when
        Phase 5-7 need many more ring operations per decapsulation
- [x] Phase 4: identity-embedding map `E` (`src/tibe/identity.c`,
      `ring_split`/`ring_unsplit`/`field_mul` in `src/tibe/ring.c`)
  - [x] `r1`, `r2` splitting roots derived and independently
        re-verified (`gen_params.py` re-checks `r1^2 == -1 mod q` on
        every run, not just once by hand)
  - [x] `ring_split`/`ring_unsplit` (the `R_q ~ F_{D/2} x F_{D/2}`
        isomorphism, Lemma 1) validated as a genuine ring isomorphism,
        not just an additive bookkeeping trick: round-trip, additive
        homomorphism, AND multiplicative homomorphism (`field_mul`
        mod `X^{D/2}-r_i` matches `ring_mul` mod `X^D+1` after
        splitting) all checked directly in `test_ring.c`
  - [x] `identity_embed_field` (`E_F`): SHAKE-256-based, WOTS+ `vk` ->
        nonzero `F_{D/2}` element; `identity_embed` (`E`) calls the
        general `ring_unsplit(y,y)` rather than a hand-derived
        shortcut, so a bug in the "obvious" simplification (E(vk)'s
        low D/2 coefficients = E_F(vk), high D/2 = 0) can't silently
        diverge from the paper's actual `f^-1(E_F(vk),E_F(vk))`
        definition
  - [x] The actual security property (`E(vk0)-E(vk1)` is a unit for
        `vk0 != vk1`) checked directly via `ring_inv` succeeding on
        real WOTS+ keypairs in `test_identity.c`, not just argued for
        in a comment
  - [x] `make test` passes (`test_ring`, `test_gauss`, `test_wots`,
        `test_tibe`, `test_identity`) -- `d0` inversion, re-scoped into
        Phase 3 above since it's needed for Decrypt's own algebra, not
        just identity embedding, stays there; Phase 4 turned out to be
        exactly the identity-embedding work its name always implied
- [x] Phase 5: Shamir-share `(s_a, e_a)` + the real 3-round
      `ShareExtract_{0,1,2}`/`Combine` threshold-decryption protocol
      (`src/tibe/threshold.c`)
  - [x] Coefficient-wise `(T,[N])`-Shamir sharing of ring elements,
        generalizing `src/kyber/threshold.c`'s int32/mod-3329
        construction to BIGNUM/mod-q; pairwise PRF seed distribution
        for round-2 masking (dealer hands both parties in a pair the
        same seed, matching Remark 1's trusted-channel model)
  - [x] `z2` sign independently re-verified against the real
        multi-party Algorithm 7/8 (not just copied from Phase 3's
        single-party fix) -- confirmed unchanged (`z2 = -c0`) via a
        symbolic toy-ring check of the full protocol (real masking,
        real T-of-N Lagrange reconstruction) and this phase's own
        end-to-end C test
  - [x] Caught a second, more consequential algebra issue empirically:
        Algorithm 5 line 2's `y_{i,0}` was initially read as the scalar
        `a0*p_{i,0}+p_{i,1}` (raw, unpublished `a0`), which broke the
        full multi-party correctness algebra regardless of the `z2`
        sign, even with masking/Lagrange independently verified
        correct in isolation. Fix: `y_{i,0} = A0.p_i`, a proper
        3-vector dot product against the *published* `A0`, mirroring
        `y_{i,1}`/`y_{i,2}`'s own pattern -- found via a symbolic
        toy-ring check across hypotheses, confirmed exactly (real
        masking, real T-of-N reconstruction, non-trivial active sets)
        and then in the real C implementation. Consequence: no
        shareholder needs raw `a0` at all (an `a0` field briefly added
        to `tibe_msk`/`threshold_share` under the wrong reading was
        removed once the fix landed) -- see `src/tibe/README.md`
        "The real 3-round threshold protocol" for the full writeup.
  - [x] `make test` passes (`test_ring` through `test_threshold`,
        6 suites) -- includes one full, real (not single-party
        stand-in) `T=5`-of-`N=10` decapsulation: real Shamir shares,
        real WOTS+-embedded identity, real pairwise masking, a
        non-trivial active set (`{2,4,6,8,10}`), recovering the
        actual encrypted message. Cost: ~35 minutes for that one
        cycle (see `src/tibe/README.md` "Performance") -- raises
        Phase 8's NTT-based-multiplication priority further, and is a
        real budgeting consideration for Phase 7's Docker wiring.
  - [ ] Not tested end to end at the full-protocol level (documented
        gap, not silently skipped, given per-cycle cost): below-T
        threshold behavior and malicious-party (lying about `w_i`)
        detection. The commit-then-reveal check exists in
        `threshold_round2`'s code; the cheap Shamir-only test covers
        the threshold property directly. A future session should
        decide whether this gap needs closing before any publication
        claim about robustness/cheating-detection specifically (the
        base paper isn't robust either way -- Table 1 in
        `BCHK_PAPER_SPEC.md` -- so this is about validating the
        *detection* property that does exist, not adding
        robustness).
- [ ] Phase 6: the BCHK+ TKEM layer (`Keygen`/`Encaps`/`ShareDecaps`/
      `Combine`, Sec 4.6) -- wraps TIBE + WOTS+ + the FO consistency
      check (`G_fo`/`H_fo`, re-encryption check on the now-public `msg`)
- [ ] Phase 7: wire into `dealer.c`/`shareholder.c`/`coordinator.c`/
      `docker-compose.yml` -- extend the HTTP protocol to 3 rounds,
      N=10/T=5 topology
- [ ] Phase 8 (future/stretch, explicitly out of scope for now):
  - Validate at the paper's actual proven `T=32` before any publication
    claim resting on the security proof (see `src/tibe/README.md`'s
    T=5 caveat)
  - NTT-based ring multiplication if BIGNUM's ~10s/multiply proves too
    slow once the full protocol is wired up
  - An exact, constant-time discrete Gaussian sampler, replacing the
    Box-Muller approximation, if a real security claim needs it
  - Robustness (misbehaving-shareholder detection/recovery -- the 2026
    follow-up paper's Vandermonde-sharing approach, eprint 2026/021, not
    read yet) or distributed key generation (no DKG in the base paper
    either) -- real research extensions, not attempted here

## Future: paper writeups (goal, not yet started)

Two papers, once the implementation is far enough along to have real
results to report -- confirmed with the project owner as the end goal
this whole redesign is in service of:

1. **Implementation paper**: reproducing Lapiha & Prest's BCHK+
   threshold KEM (eprint 2025/1958) as a from-scratch, real, working
   system -- the engineering contribution, in the same spirit as this
   project's own `src/kyber/README.md` (what was built, how it was
   validated with no public reference to check against, what
   concrete choices the paper left open and how they were resolved --
   `BCHK_PAPER_SPEC.md`'s open-questions section and each phase's
   README notes are the running material for this).
2. **Comparison paper**: this implementation vs. `src/kyber/threshold_decaps`
   (the trusted-combiner threshold ML-KEM already built and validated in
   this repo) -- results-based, once both systems can be measured
   side by side (correctness rates, timing/ciphertext-size overhead,
   and the precise trust-model delta written up rigorously; see this
   file's `src/tibe/README.md` companion, "The actual trust-model delta
   vs. `src/kyber/threshold_decaps`", for the precise claim to build on:
   **not** "the new combiner never sees the plaintext" (false in both
   schemes -- the combiner necessarily reconstructs it in both), but
   "CCA security no longer depends on the combiner's honesty," because
   every shareholder independently rejects an invalid ciphertext via a
   public signature check before doing any partial-decryption work,
   rather than the validity check happening only after the fact at the
   combiner.

Not started -- flagged here so it isn't lost, and so any writeup starts
from the precise trust-model claim above rather than the looser
"combiner never holds the key" phrasing that doesn't survive scrutiny.

## Notes for future sessions

- Branch: `bchk-redesign`. `master` is untouched and is the fallback if
  this doesn't pan out.
- Commit style matches the rest of this project: substantive,
  explanatory messages, one per logical unit of work -- see git log for
  the expected level of detail.
- Validation methodology throughout: no public reference implementation
  of BCHK+ exists anywhere, so every phase is validated by internal
  consistency (round-trip correctness, known-identity checks, threshold
  vs below-threshold behavior once Phase 5 lands) rather than a
  byte-exact diff -- the same fallback this project already used for
  `src/kyber/threshold.c` and `threshold_decaps`.
