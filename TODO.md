# Threshold ML-KEM-768 — roadmap

Goal: novel threshold-decryption Kyber/ML-KEM scheme (Shamir-shared secret
key + linear/homomorphic combination of partial decryptions), targeting
full CCA-secure threshold decapsulation as the paper's novelty claim.
See project discussion notes for the CPA-vs-CCA and "quantum-safe" framing.

## Status

- [x] Local git repo initialized in this folder (no GitHub remote; local only)
- [x] Baseline commit of the original toy-LWE prototype (scalar Q=97 version)
- [x] Phase 1: ML-KEM-768 module-LWE primitives (`src/kyber/`)
  - NTT/InvNTT/basemul, Montgomery+Barrett reduction, CBD eta=2 noise,
    SHAKE-128/256 (OpenSSL EVP), poly compress/decompress/serialize
  - Validated byte-exact against pq-crystals/kyber reference on every function
  - `make test` in `src/kyber/` — self-contained regression suite
- [x] Phase 2: IND-CPA Kyber PKE (`src/kyber/indcpa.c`, `polyvec.c`)
  - [x] Matrix generation: SHAKE-128 XOF + rejection sampling from seed rho
  - [x] KeyGen: sample A, s, e; compute t = A*s + e; pack pk/sk
  - [x] Enc: sample r, e1, e2; compute u, v; pack ciphertext
  - [x] Dec: recover message from u, v, s
  - [x] Validate: byte-exact pk/sk/ciphertext/recovered-message against
        reference for a fixed seed, plus round-trip correctness
        (Dec(Enc(m)) == m) over 32 random trials
  - Caught and fixed a real bug here: `kyber_ntt_init()` was never wired
    into the library code path, only into test harnesses -- see
    `src/kyber/README.md` "A real bug this caught"
- [x] Phase 3: Threshold decryption (`src/kyber/threshold.c`)
  - [x] Shamir-share skpv's 768 (K=3 x N=256) NTT-domain coefficients over
        Z_3329, via OpenSSL RAND_bytes (not toy prototype's rand())
  - [x] threshold_partial_decrypt (per-shareholder) + threshold_combine +
        threshold_finish_decrypt (coordinator) recover the message without
        any party reconstructing skpv
  - [x] Validate: any k-of-5 subset (5 different subsets tried) recovers
        the message; 2-of-5 (below THRESHOLD=3) does not; ordinary
        indcpa_dec still works on the un-split key. 10x repeat run with
        fresh random shares each time, no flakiness
  - Caught two real bugs here (see `src/kyber/README.md`): (1) a missing
    `poly_invntt_tomont(&mp)` step hand-copying indcpa_dec's tail, not
    caught by comparing intermediate values since both a manual "ground
    truth" check and the threshold path independently omitted the same
    step -- only caught by checking final message correctness end to end;
    (2) fixed by consolidating the whole tail into `threshold_finish_decrypt`
- [x] Phase 4: Rebuild dealer/shareholder/coordinator Docker flow around real PKE
  - Turned out the *existing* dealer/shareholder/coordinator weren't the
    toy-LWE flow at all -- they'd moved on to splitting a raw AES-256 key
    with the external `ssss` CLI, with **no public-key encapsulation
    anywhere**. Replaced that with a real hybrid KEM: dealer generates an
    ML-KEM-768 keypair, Shamir-shares the secret key (not a bare AES key)
    via `threshold_split_secret`, writes pk to a shared volume; coordinator
    does real `indcpa_enc` to encapsulate a fresh 32-byte value, collects k
    partial decryptions from shareholders over HTTP, Lagrange-combines via
    `threshold_finish_decrypt`, and uses the result (through SHA3-256) as
    an AES-256-GCM key -- so a wrong reconstruction fails GCM tag
    verification instead of silently producing garbage
  - [x] Removed the `ssss`/`libgmp` dependency entirely; added `hexutil.c`
        for JSON-safe wire transport of shares/ciphertexts/partials
  - [x] Fixed a real orchestration bug found while testing: `docker compose
        up --abort-on-container-exit` treats the dealer's expected exit as
        a signal to kill the whole stack (shareholders included) regardless
        of `--exit-code-from` -- documented the correct invocation
        (`up -d` + `docker wait coordinator`) in docker-compose.yml
  - [x] Validated live end-to-end in Docker: 200/200 trials, both KEM
        reconstruction and the AES-256-GCM round trip it gates, across 5
        real shareholder containers over HTTP; below-threshold subset
        correctly refuses to run
- [x] Phase 5a: full CCA-secure ML-KEM-768 KEM (`src/kyber/kem.c`)
  - [x] `kyber_keypair_derand`/`kyber_encaps_derand`/`kyber_decaps`: the
        Fujisaki-Okamoto transform over the IND-CPA PKE (G/H hashing,
        re-encryption check, implicit rejection via J(z,ct))
  - [x] Validated byte-exact against pq-crystals/kyber's crypto_kem_*
        functions -- ek, dk, ct, encapsulated secret, decapsulated
        secret, AND the implicit-rejection value for a corrupted
        ciphertext all match exactly
- [x] Phase 5b: `threshold_decaps` under an explicit trusted-combiner assumption
  - Scoped deliberately narrower than full threshold-CCA: the naive
    extension needs m' (the PKE-decrypted message) in the clear to
    complete the FO re-encryption check, which isn't linear in the
    secret key the way PKE decryption is -- see `src/kyber/README.md`
    "Phase 5" for the full writeup of why, and why the general fix
    (secret-share m', MPC circuit for hash+re-encrypt+compare) is its
    own separate research effort, not something attempted here
  - [x] `threshold_decaps`: combiner Lagrange-combines shares to get m'
        (same as Phase 3), then finishes Decaps locally via the shared
        `kyber_decaps_from_m` tail also used by the plain KEM path
  - [x] Validated: matches plain `kyber_decaps` byte-for-byte on both
        the accept path and the implicit-rejection path for a
        corrupted ciphertext (no public reference for threshold Kyber
        exists, so this is internal-consistency validation, same
        approach as Phase 3)
- [ ] Phase 5c (not attempted, future work): full threshold-CCA via
      generic MPC over the FO check, or a threshold-friendly KEM
      redesign that avoids it structurally. Multi-month-scale systems
      research on its own -- see README for the survey of approaches
- [ ] Wire kem.c/threshold_decaps into the Docker demo (currently still
      uses the IND-CPA-only path from Phase 4) -- straightforward next
      step if wanted, not yet done

## Notes for future sessions

- No GitHub remote exists for this project; git history is local-only
  until the user explicitly asks to push somewhere.
- Reference implementation used for validation only, cloned to scratchpad
  (not part of this repo): `https://github.com/pq-crystals/kyber`
- ML-KEM-768 (k=3) was chosen as the target parameter set.
