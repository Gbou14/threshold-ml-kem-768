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
- [x] Phase 6: the BCHK+ TKEM layer (`src/tibe/tkem.c`)
  - [x] `tkem_keygen` (`==tibe_setup`), `tkem_encaps`/
        `tkem_encaps_derand` (fresh WOTS+ keypair every call, `G_fo`
        derandomization, `H_fo` shared-secret derivation),
        `tkem_verify_ct` (the actual BCHK check), `tkem_share_decaps_
        {0,1,2}` (wrap `threshold_round0/1/2` with the verify check
        prepended), `tkem_combine` (wraps `threshold_combine`, then
        the FO re-encryption consistency check)
  - [x] Added `tibe_encrypt_derand` to `tibe.c` (explicit-seed form of
        `Encrypt`; `tibe_encrypt` is now a thin wrapper) and a
        `gauss_prg`/`gauss_sample_from_prg` deterministic sampling
        path to `gauss.c`, refactored to share the same Box-Muller
        core as the original `RAND_bytes`-driven path -- needed so
        `Combine`'s re-encryption check can reproduce a ciphertext
        deterministically from a re-derived seed
      - Validated the refactor didn't perturb the original
        (non-derandomized) path: existing `gauss_sample`/
        `gauss_sample_coeff` statistics unchanged, a new statistical
        check on the `gauss_prg` path, and `test_tibe.c`'s full
        `Setup->Encrypt->Decrypt` suite re-run and still passing now
        that `tibe_encrypt` routes through `tibe_encrypt_derand`
  - [x] `make test` passes (`test_ring` through `test_tkem`, 7 suites)
        -- includes one full, real `Keygen->Encaps->ShareDecaps
        (T=5-of-N=10)->Combine` cycle: real WOTS+ keypair, real
        threshold decryption, real FO-style re-encryption check,
        confirming the shared secret `Combine` derives matches what
        `Encaps` produced. No algebra surprises this phase (unlike
        Phase 5) -- built cleanly on top of already-validated
        primitives. ~30 minutes for that one cycle.
  - Note: the actual trust-model delta this whole redesign targets
    (`src/tibe/README.md` "The actual trust-model delta") is now
    real, not aspirational -- every `tkem_share_decaps_j`/
    `tkem_combine` call independently verifies the WOTS+ signature
    *before* touching a Shamir share or doing any TIBE-layer work,
    confirmed directly by `test_tkem.c`'s tampered-ciphertext test.
- [x] Phase 7: live multi-container Docker demo (`docker-compose.tibe.yml`,
      `src/tibe_dealer.c`, `src/tibe_shareholder.c`, `src/tibe_coordinator.c`)
  - [x] A *separate* compose file/demo, not a modification of
        `docker-compose.yml`/`dealer.c`/`shareholder.c`/`coordinator.c`
        -- the Kyber demo stays fully intact and independently runnable
  - [x] `tibe_dealer`: `tkem_keygen`, `threshold_setup` (real
        Shamir-sharing across `N=10`), writes `ek`/`d0` to the shared
        volume (both quasi-public -- see `src/tibe/tibe.h`'s
        `tibe_msk` comment), POSTs each shareholder's own private
        share over HTTP
  - [x] `tibe_shareholder`: `/health`, `/store_share`, `/round0`,
        `/round1`, `/round2` -- lazily loads `ek` from the shared
        volume on first `/round0` call (can't block on it at startup
        without deadlocking the dealer's wait-for-healthy loop, since
        shareholders must answer `/health` before the dealer can even
        run); one session (one decapsulation) at a time via global
        state, matching `shareholder.c`'s existing architecture
  - [x] `tibe_coordinator`: `tkem_encaps` -> round0 (collect all
        commitments before revealing anything) -> round1 (collect all
        reveals) -> round2 (send the *full* collected set to every
        active party) -> `tkem_combine` -> AES-256-GCM demo round trip,
        `N_TRIALS` defaulting to 1 (not the Kyber demo's 200), given
        the real per-trial cost
  - [x] Payloads are far larger than the Kyber demo's (a ring element
        serializes to ~53 KB; `ek` alone ~692 KB; a full ciphertext
        ~535 KB) -- `tibe_shareholder`'s request-body handling uses a
        dynamically-grown buffer, not `shareholder.c`'s fixed 8 KB one
  - [x] Verified `tibe_shareholder.c` compiles cleanly against real
        `libmicrohttpd` inside the Docker build (couldn't be
        compile-checked on this host -- `libmicrohttpd-dev` isn't
        installed and sudo isn't available -- so the Docker build was
        the first real compile check for that file, and it passed
        clean, no warnings)
  - [x] Found and fixed a real, if latent and harmless-there, bug
        while diagnosing an apparent stall in the first live run:
        every `wait_healthy` helper (this module's and the *existing*
        Kyber demo's `dealer.c`/`coordinator.c`) uses
        `CURLOPT_NOBODY`, which makes curl issue an HTTP `HEAD`
        request -- but `/health` handlers (this module's and the
        existing `shareholder.c`'s) only matched `GET`, so every
        health check 404s and `wait_healthy` always burns its full
        retry budget (~5 minutes for `tibe_coordinator`'s 5 hosts at
        60 retries each) before proceeding anyway. Harmless in the
        existing Kyber demo (`wait_healthy` doesn't gate anything
        there either), but a real, needless multi-minute startup tax
        -- fixed in `tibe_shareholder.c` (accepts GET or HEAD) since
        it's this branch's own new code; the Kyber-side files were
        left untouched, matching the "don't modify Kyber-side files"
        branch policy, even though the same latent bug exists there
  - [x] Dealer keygen + Shamir-sharing + share distribution to all 10
        parties confirmed working live
  - [x] Full `T=5`-of-`N=10` decapsulation confirmed live, first run,
        no algebra surprises (unlike Phase 5): real HTTP across
        round0->round1->round2->`tkem_combine`, active set
        `{2,4,6,8,10}`, recovered the correct shared secret (matching
        what `tkem_encaps` produced) and the AES-256-GCM round trip
        succeeded -- `tibe_results.csv`: `0,1,1,"Hello from threshold
        BCHK+!","Hello from threshold BCHK+!"`. `TKEM: 1/1, AES: 1/1`.
- [ ] Phase 8: everything remaining before the implementation paper is
      written, **in this order (confirmed with the project owner,
      2026-09-01)** -- each item is a real gate on the next, not a
      loose bag of stretch goals:
  1. [ ] **8a -- close Phase 5's testing gap.** Below-threshold and
        malicious-party (lying about `w_i`) behavior tested at the
        *full protocol* level, not just the cheap Shamir-only check
        that already exists. Cheapest place to find a correctness or
        cheating-detection bug is here, at `T=5` (~35 min/cycle), not
        at `T=32` (unknown, likely much larger, cost -- see 8f). This
        is the immediate next piece of work.
  2. [ ] **8b -- the Gaussian sampler.** Replace the Box-Muller
        approximation (`gauss.c`) with an exact, constant-time
        discrete Gaussian sampler. This is the limitation flagged
        most prominently in `src/tibe/README.md` ("Gaussian
        sampling") -- as things stand, no real security claim can be
        made about the deployed system without this. Real
        cryptographic engineering (rejection sampling / CDT / a
        convolution-based construction, each with genuine precision
        and side-channel pitfalls), not a small patch.
  3. [ ] **8c -- robustness.** Misbehaving-shareholder detection is
        already real (the commit-then-reveal check, once 8a confirms
        it end to end); *recovery* (continuing correctly despite a
        misbehaving shareholder, rather than the whole `act` set's
        attempt simply failing) is not, matching the base paper
        itself (Table 1: "Robust: No"). The 2026 follow-up (eprint
        2026/021) reportedly adds this via Vandermonde secret sharing
        at a reduced query bound -- **not read yet**; this needs its
        own literature pass (matching the rigor Phase 0 gave the base
        paper) before any implementation work, not an assumption that
        it's a drop-in change to `threshold_share`'s Shamir-sharing.
  4. [ ] **8d -- distributed key generation (DKG).** Removes the
        trusted-dealer assumption (`Remark 1`, `src/dealer.c`'s Kyber
        role and `src/tibe_dealer.c`'s role alike). **Neither the base
        paper nor the 2026 follow-up specifies a DKG for this
        construction** -- this is a materially different, larger item
        than 8a-8c: not "implement what the paper already fully
        specifies" but either a genuine design contribution built on
        general MPC/DKG literature, or a scoped-down/deferred goal.
        Flagged honestly now rather than assumed to be
        similarly-sized to the items above; worth an explicit
        scope/feasibility discussion before starting.
  5. [ ] **8e -- comparison work.** The systematic, empirical
        side-by-side data-gathering against `src/kyber/threshold_decaps`
        (correctness rates, timing/ciphertext-size overhead) that the
        comparison paper (see "Future: paper writeups" below) needs --
        distinct from that paper's actual writing, which stays a
        separate, later step.
  6. [ ] **8f -- validate at the paper's actual proven `T=32`**, only
        once 8a-8e above are done, not before (smaller, cheaper tests
        first -- same reasoning as 8a's ordering relative to this).
        Before any publication claim resting on the security proof
        (see `src/tibe/README.md`'s T=5 caveat).
  - NTT-based ring multiplication remains a cross-cutting item, not
    tied to one specific step above: revisit if BIGNUM's per-multiply
    cost makes 8f (or 8a's repeated full-protocol runs) impractically
    slow.
  - Once 8a-8f are done, per the project owner: begin the
    implementation paper (see "Future: paper writeups" below) from
    that stronger position -- known gaps closed or explicitly scoped,
    not just Phase 1-7's happy-path validation.

## Future: paper writeups (goal, not yet started)

Two papers, once the implementation is far enough along to have real
results to report -- confirmed with the project owner as the end goal
this whole redesign is in service of. **Start of the implementation
paper is gated on Phase 8a-8f above being done or explicitly scoped
out**, not on Phase 1-7's happy-path validation alone -- confirmed
with the project owner (2026-09-01) specifically so the paper starts
from a position where the known gaps (testing, the Gaussian sampler,
robustness, DKG) are closed or honestly bounded, not silently absent.

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
   this repo) -- results-based, once both systems can be measured side
   by side: correctness rates, timing/ciphertext-size overhead, and
   the precise trust-model delta written up rigorously. Phase 8e above
   is the actual data-gathering this needs; this paper's writing is a
   separate, later step even once 8e's numbers exist. See this
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
