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
- [ ] Phase 4: Rebuild dealer/shareholder/coordinator Docker flow around real PKE
  - [ ] Replace `toy_crypto.c` calls with the new Kyber PKE + Shamir layer
  - [ ] Re-run the docker-compose experiment harness, regenerate results.csv
- [ ] Phase 5 (stretch/research): CCA-secure threshold decapsulation
  - [ ] Write up precisely why naively extending Phase 3 to the full
        FO-transform Decaps breaks IND-CCA2 (re-encryption check needs
        full plaintext)
  - [ ] Survey/prototype candidate mitigations (noise flooding, distributed
        re-encryption check, etc.) — this is the paper's actual novelty claim

## Notes for future sessions

- No GitHub remote exists for this project; git history is local-only
  until the user explicitly asks to push somewhere.
- Reference implementation used for validation only, cloned to scratchpad
  (not part of this repo): `https://github.com/pq-crystals/kyber`
- ML-KEM-768 (k=3) was chosen as the target parameter set.
