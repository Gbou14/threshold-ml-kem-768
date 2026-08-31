# Threshold ML-KEM-768

A real, working threshold decryption scheme for ML-KEM-768 (Kyber):
Shamir-share the private key across N parties, let any K of them
compute a partial decryption without ever reconstructing the key, and
combine those partials via Lagrange interpolation to recover the
correct result -- up to and including the full CCA-secure KEM
(Fujisaki-Okamoto transform, implicit rejection), not just the
underlying IND-CPA encryption scheme.

## Status

Real, validated, and demonstrated live over a 5-container Docker setup:
**200/200 trials** of full threshold ML-KEM-768 decapsulation +
AES-256-GCM succeeded on the most recent run. See
[`TODO.md`](TODO.md) for the phase-by-phase roadmap and
[`src/kyber/README.md`](src/kyber/README.md) for the cryptographic
detail, validation methodology, and the one explicit trust assumption
this makes (documented, not hidden -- see "Phase 5" there).

## Where things live

- **`src/kyber/`** -- the actual cryptography. Module-LWE primitives,
  the IND-CPA PKE, the full CCA-secure KEM, and threshold decryption/
  decapsulation. Written from FIPS 203, validated byte-exact against
  the public-domain pq-crystals/kyber reference implementation
  wherever a reference exists, and by internal consistency where it
  doesn't (no public threshold-Kyber implementation exists to diff
  against). Start with [`src/kyber/README.md`](src/kyber/README.md).
- **`docker-compose.yml`, `Dockerfile`, `src/dealer.c`,
  `src/shareholder.c`, `src/coordinator.c`** -- a live multi-container
  demo of the whole system: a dealer generates a keypair and
  distributes shares, five shareholder containers each hold one share
  and never see the private key, and a coordinator encapsulates a
  value, collects partial decryptions over real HTTP, and recovers it.
  See the comment block at the top of `docker-compose.yml` for how to
  run it.
- **`src/main.c`, `src/toy_crypto.c`, `src/shamir.c`, `src/lagrange.c`**
  -- the original toy prototype this project grew out of: a small
  scalar LWE scheme (`Q=97`) with the same threshold-decryption idea,
  used to validate the approach before building the real thing. Kept
  for history, not used by the Docker demo.
- **`shamir-docker/`** -- an earlier, separate Docker experiment
  splitting the toy scheme across containers. Superseded by the
  top-level `docker-compose.yml`, kept for history.
- **`TODO.md`** -- the roadmap: what's done, what's validated, what's
  explicitly out of scope and why.

## Running the demo

```bash
docker compose up -d && docker wait coordinator
docker compose logs coordinator
cat data/results.csv
docker compose down
```

Don't use `docker compose up --abort-on-container-exit` -- see the
comment block in `docker-compose.yml` for why that kills the run.

## What's next

The current scope (documented in `TODO.md` and `src/kyber/README.md`)
makes one explicit trust concession: the party that combines partial
decryptions briefly reconstructs the decrypted message in order to
finish the CCA-secure KEM's re-encryption check, which isn't linear in
the private key the way plain decryption is. That's a real, narrower
guarantee than full threshold-CCA security -- next up is looking at
whether a threshold-friendly CCA-secure lattice KEM can be designed (or
found) that avoids needing that re-encryption check at all, rather than
patching around it.
