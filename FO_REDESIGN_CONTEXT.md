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
check structured this way in the first place**.

## Literature search results (2026-08-31) -- this is a real, active research area

A real literature search (IACR eprint + web search) confirms this is
not a niche question -- there is recent, peer-reviewed work doing
*exactly* this, plus active NIST standardization interest. Summary,
most important result first:

**The key paper:** Oleksandra Lapiha and Thomas Prest, "A Lattice-Based
IND-CCA Threshold KEM from the BCHK+ Transform," **Asiacrypt 2025**,
[eprint 2025/1958](https://eprint.iacr.org/2025/1958.pdf). Peer-reviewed
at a top-tier venue, not an obscure preprint.

**Follow-up (18x smaller ciphertexts):** Katharina Boudgoust, Rafaël
del Pino, Oleksandra Lapiha, Thomas Prest, "IND-CCA Lattice Threshold
KEM under 30 KiB," [eprint 2026/021](https://eprint.iacr.org/2026/021.pdf).

**The core idea (BCHK+ transform) -- this is precisely the "avoid FO"
answer:** Don't use FO for CCA security at all. Use the
**Boneh-Canetti-Halevi-Katz (BCHK) transform** instead (Boneh, Canetti,
Halevi, Katz, EUROCRYPT 2004) -- a *different*, older generic
CPA-to-CCA compiler that builds a CCA PKE from (a threshold) IBE + a
one-time signature, where the ciphertext validity check is on **public
values**, so it doesn't need thresholdizing at all. Boneh-Boyen-Halevi
had already shown this works for threshold PKE in the classical
(non-lattice) setting.

The catch for lattices: BCHK alone doesn't guarantee "decapsulation
consistency" (the same ciphertext decrypting to two different messages
under two different decrypter subsets) because lattice ciphertexts are
inherently noisy. Lapiha-Prest's fix is to *also* run FO, but only to
patch that consistency property -- **not for CCA security, which BCHK
already provides**. Quoting the paper directly: "the input to FO
re-encryption is no longer sensitive and does not need to be
thresholdised." That's the whole trick: FO's re-encryption check still
happens, but on non-sensitive input, because BCHK is doing the actual
security work.

**Important reframing this causes:** the field's realized answer to
"avoid FO" is not a patched/modified ML-KEM -- it's a **different
lattice construction from scratch**, built from a threshold
identity-based encryption scheme (starting from Agrawal-Boneh-Boyen,
later simplified via "ROHIBE") combined with threshold-friendly
signature building blocks (Plover, Esgin et al. EUROCRYPT 2024;
Threshold Raccoon, Katsumata et al. CRYPTO 2024) and a new hardness
assumption ("Coset-Hint-MLWE," a generalization of Hint-MLWE, Kim et
al. CRYPTO 2023, proven hard under standard assumptions). If the user
wants to "redesign to avoid FO," reproducing/extending/implementing
BCHK+ is the concrete, current state of the art to build on or against
-- not a modification of the Kyber/ML-KEM code already in this repo.

**Honest limitations of BCHK+ itself** (from the papers' own framing,
useful for finding a genuine gap to contribute in):
- Selective security, not the stronger adaptive/UC notion some
  competing (heavier) constructions achieve.
- Has a trusted setup.
- The base (Asiacrypt'25) version is not robust (no defense against a
  misbehaving shareholder); the 2026 follow-up adds robustness via
  Vandermonde secret sharing instead of Shamir, but only at a reduced
  query bound (Q=2^25 vs 2^45).
- Ciphertexts, even after the 18x improvement, are ~30 KiB for T=32 --
  compare to plain (non-threshold) ML-KEM-768's ~1KB ciphertext. Real
  efficiency gap remains vs. non-threshold KEMs.
- Not built on Kyber's module-LWE structure specifically -- an open
  question is whether these ideas can be adapted to Kyber's exact
  parameter regime rather than a fresh ABB/ROHIBE-style IBE.

**The cautionary-tale comparison (why generic MPC over FO is bad, now
with a concrete number):** Cong et al., "Gladius: LWR Based Efficient
Hybrid Public Key Encryption with Distributed Decryption" (eprint
2021/096, LWR/Saber-based, not Kyber). Small ciphertexts (512 bytes!)
but requires generic MPC to evaluate the FO hash function: **136,491
rounds for 3 parties**, and the security argument is only heuristic
(can't represent a random oracle as a circuit for the MPC evaluation).
This is the concrete version of "the FO-in-MPC approach is a much
bigger, less practical undertaking" -- worth citing directly if the
paper discusses why BCHK+-style avoidance is preferable to patching.

**Other related work found** (for a fuller related-work section later):
Boneh et al.'s "universal thresholdiser" (ThFHE-based, thresholdizes
*any* functionality including FO) -- theoretical, no parameter set
proposed, slow runtime flagged by the authors themselves as an open
problem. Devevey et al. -- adaptive security + robustness via lossy
encryption + correlation-intractable-hash NIZKs, heavy machinery, no
parameters proposed either. Two IND-CPA-only (not CCA) lattice TPKE
papers based on noise-flooded Lindner-Peikert/Regev variants.

**NIST context, now verified (was previously an unconfirmed claim):**
NIST's Multi-Party Threshold Cryptography project (IR 8214C, "the NIST
Threshold Call") explicitly includes ML-KEM in scope. MPTS 2026 (NIST
Workshop on Multi-Party Threshold Schemes, Jan 26-29 2026) covered
threshold PKE/KEM as a named topic alongside threshold signatures, FHE,
and ZKPs. See
[csrc.nist.gov/Projects/threshold-cryptography](https://csrc.nist.gov/Projects/threshold-cryptography/tcall-1).

**Search terms that worked, for continuing the search further:**
"threshold Kyber ML-KEM decapsulation Fujisaki-Okamoto", "threshold-friendly
CCA-secure lattice KEM without re-encryption check", "NIST call for
multi-party threshold cryptography ML-KEM 2026", "Gladius threshold KEM
Cong lattice MPC". IACR eprint search directly (eprint.iacr.org) is more
reliable than general web search for finding the underlying papers.

**Suggested next step for the user:** given BCHK+ is real, recent,
peer-reviewed, and directly on-target, the practical next decision is
*not* "design a threshold-friendly KEM from nothing" -- it's choosing
among: (a) implement/reproduce BCHK+ (or the 2026 follow-up) as a
systems contribution, applying the same rigorous
validate-against-everything methodology used in this repo's phases 1-5;
(b) find a genuine open gap in it to improve (robustness without the
query-bound tradeoff, adapting it to Kyber's specific module structure,
further ciphertext-size reduction); or (c) use it as a benchmark/point
of comparison for the trusted-combiner `threshold_decaps` already built
here, and write up the tradeoff explicitly (this repo's approach: much
smaller ciphertexts, reuses standard ML-KEM, but weaker trust model;
BCHK+: full threshold-CCA with no trusted combiner, but a different
non-Kyber construction and ~30x-ish larger ciphertexts). This decision
needs the user's input -- don't pick for them.

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
