# Context handoff: FO-avoidance redesign research

Read this first if you are picking up this project in a new session with
no memory of prior conversation. It is written to be self-contained.

## What this project is

A real, from-scratch implementation of threshold ML-KEM-768 (Kyber):
Shamir-share the private key across N parties, let any K of them compute
a partial decryption without reconstructing the key, Lagrange-combine to
recover the result -- through the full CCA-secure KEM, not just plain
PKE decryption. The user's long-term goal is a **novel threshold-CCA
lattice KEM design** as the actual research contribution; everything
built so far is the validated baseline that contribution sits on top of.

The user is early-career / building a research portfolio (referenced a
LinkedIn post about "distributed decryption workflow... homomorphic
properties... partial decryption operations... without any single party
ever reconstructing the full plaintext or private key" as the original
inspiration). They asked to be told directly, not flattered: their
LinkedIn description is a fair characterization of what's built, and the
project is real, working cryptography, not a toy demo.

## Where the code lives

`~/Documents/threshold_kyber_research/` (a git repo, local commits; may
have a GitHub remote by the time you read this -- check `git remote -v`
and `README.md`). Also historically duplicated at `~/threshold_kyber_research`,
`~/Downloads/threshold_kyber_research.zip`, `~/Documents/threshold_kyber_research.zip`,
`~/threshold_kyber_research_submission.tar.gz` -- these were snapshots
predating the git repo; the git repo at `~/Documents/threshold_kyber_research`
is canonical. They may have been cleaned up since (see the user's
disk-space-migration plan below) -- don't assume they still exist.

Key files:

- `README.md` -- project orientation, points everywhere else
- `TODO.md` -- full phase-by-phase roadmap and status
- `src/kyber/README.md` -- the cryptographic detail: what's implemented,
  how it was validated, the "Phase 5" section explaining exactly why the
  FO transform breaks the naive threshold extension (read this in full
  before starting redesign work -- it's the precise statement of the
  problem being redesigned around)
- `src/kyber/kem.c`, `.h` -- the current (FO-transform-based) CCA-secure
  KEM, for reference/comparison
- `src/kyber/threshold.c`, `.h` -- `threshold_decaps`, the current
  trusted-combiner threshold decapsulation this redesign aims to improve on
- `src/dealer.c`, `shareholder.c`, `coordinator.c`, `docker-compose.yml`
  -- the live multi-container demo (200/200 trials passing as of the
  last run; see README.md for exact numbers and how to re-run it)

## Status as of this handoff

Phases 1-5b complete and validated:

1. Module-LWE primitives (NTT, reduction, CBD noise, compression) --
   validated byte-exact against the public-domain pq-crystals/kyber
   reference implementation
2. IND-CPA PKE (KeyGen/Enc/Dec) -- same validation
3. Threshold decryption (Shamir-share the secret key's 768 NTT-domain
   coefficients over Z_3329, Lagrange-combine partial decryptions) --
   validated by internal consistency (no public reference exists)
4. Docker demo wired to the real crypto (dealer/shareholder/coordinator
   over HTTP) -- was previously a bare-AES-key ssss demo with no
   public-key encapsulation at all; replaced with a real hybrid KEM
5a. Full CCA-secure ML-KEM-768 KEM (`kem.c`) -- the Fujisaki-Okamoto
    transform (G/H hashing, re-encryption check, implicit rejection) --
    validated byte-exact against the reference, including the
    implicit-rejection fallback path
5b. `threshold_decaps` -- extends threshold decryption through the FO
    transform, but under an explicit, narrower trust assumption: see
    "The actual problem" below

Not attempted: 5c, full generic-MPC threshold-CCA (see TODO.md). **This
document is about starting a different approach to closing that same
gap: redesigning the KEM to not need FO's re-encryption check at all,
rather than wrapping the check in MPC.**

Several real bugs were caught and fixed during 1-5b, each with a
postmortem in `src/kyber/README.md` -- worth reading for the debugging
methodology (byte-exact reference diffing, and the specific case where
comparing intermediate values wasn't enough and only end-to-end message
correctness caught a bug). That methodology should carry forward into
redesign work: validate any new construction against known test vectors
or independent re-derivation wherever possible, not just "it compiles
and runs."

## The actual problem (why FO breaks threshold-friendliness)

Real ML-KEM's `Decaps(dk, c)`:

1. `m' = PKE.Decrypt(dk, c)` -- **linear in the secret key**, so
   Shamir-sharing the key and combining partial results via Lagrange
   interpolation works cleanly. This is what `threshold_finish_decrypt`
   / the first half of `threshold_decaps` does.
2. `(K', r') = G(m' || H(ek))` -- hash `m'`.
3. `c' = PKE.Encrypt(ek, m', r')` -- re-encrypt.
4. If `c' == c`, return `K'` (the real shared secret); else return a
   pseudorandom value derived from a secret `z` (implicit rejection --
   this is what makes it CCA-secure against chosen-ciphertext attacks).

Steps 2-4 are **not linear** in anything shareable the way step 1 is:
hashing and re-encryption don't compose with Shamir/Lagrange. Whoever
runs steps 2-4 needs `m'` in the clear, and `m'` determines the actual
KEM output `K'`. The current implementation (`threshold_decaps`)
concentrates steps 2-4 in the combiner, meaning the combiner briefly
holds `m'` -- a real, narrower trust assumption than "no party
reconstructs anything secret."

## What "avoid FO" means as a research direction

The user's framing: rather than trying to make the FO-transform check
threshold-friendly (e.g., via generic MPC -- secret-share `m'`, run
hash+re-encrypt+compare as an MPC circuit, which is a large systems
undertaking on its own, see TODO.md phase 5c), **look for or design a
CCA-secure lattice KEM construction that doesn't need a re-encryption
check structured this way in the first place** -- i.e., one where the
threshold-friendly property (CCA security achieved via something linear/
shareable, or via a check that doesn't require reconstructing the
message) is designed in from the start, not patched on after.

This is a genuinely open research question. What was discussed before
this handoff (from the assistant's general knowledge, explicitly
flagged as needing verification via real literature search, not treated
as settled fact):

- NIST's Multi-Party Threshold Cryptography project lists ML-KEM as an
  open target specifically because of this class of problem -- check
  NIST's MPTC project page/workshop materials for current state.
- General classes of prior approaches in the threshold-crypto literature
  (from general knowledge, not verified specific citations -- verify
  before citing in any writeup):
  - Generic MPC wrapping of the FO check (the "patch it" approach, not
    what this redesign is trying to do)
  - Structural redesigns of the CCA transform itself to be
    threshold/MPC-friendly (this is the direction of interest)
  - Weaker/relaxed trust models (what's currently implemented)
- Search terms for literature review: "threshold Kyber", "threshold
  ML-KEM", "threshold-friendly KEM", "distributed decapsulation",
  "threshold lattice-based encryption CCA", IACR eprint archive, recent
  (2023-2026) NIST MPTC workshop proceedings.

**Explicit caveat for whoever picks this up:** the assistant in the
prior session was not fully confident in specific paper citations for
this area and recommended the user's research partner do a real
literature search rather than relying on the assistant's recall. Do not
assume any specific named scheme exists without checking IACR eprint or
similar directly.

## Working style notes for continuing this project

- The user wants rigorous validation, not just "it compiles": byte-exact
  reference diffing where a reference exists, strong internal-consistency
  tests where it doesn't, and live end-to-end demonstration (not just
  unit tests) for major milestones.
- The user maintains a TODO.md roadmap and expects it kept up to date;
  update it as part of finishing each unit of work, not as an afterthought.
- Git commits should be substantive (multi-paragraph messages explaining
  why, not just what) -- see existing commit history for the expected
  style and level of detail.
- The user has asked hard, specific technical questions before (e.g.,
  "is threshold IND-CPA PKE actually novel, or is CCA the real
  contribution", "which of these is actually quantum-safe") and wants
  direct, precise, hedged-where-appropriate answers, not reassurance.
- No destructive git operations, no pushing anywhere, without explicit
  confirmation -- this has been a consistent theme; the user has asked
  clarifying questions about exactly what git/GitHub actions were being
  taken before authorizing them.
