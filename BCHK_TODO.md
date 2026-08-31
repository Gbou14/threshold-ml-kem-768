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
- [ ] Phase 3: TIBE core algebra, non-threshold (`Setup` with the full
      secret in one place, `Encrypt`, a direct non-threshold `Decrypt`)
      to validate the base algebra (`F_vk`, `Decomp_beta`, the
      correctness equation) before adding Shamir/threshold complexity
- [ ] Phase 4: identity-embedding map `E` (the `F_{d/2} x F_{d/2}`
      ring-splitting isomorphism, `BCHK_PAPER_SPEC.md` Sec 3.5 / open
      question #3) + `d0` inversion (open question #5)
- [ ] Phase 5: Shamir-share `(s_a, e_a)` as ring elements + the 3-round
      `ShareExtract_{0,1,2}`/`Combine` threshold-decryption protocol
      (`BCHK_PAPER_SPEC.md` Sec 4.5) -- commit/reveal + pairwise-PRF
      masking
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
