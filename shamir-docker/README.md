# Threshold LWE Decryption — Multi-Container Docker Setup

Your original `main.c` experiment, split across 7 Docker containers.

## What changed vs. your original code

| Original `main.c`           | Container equivalent                          |
|-----------------------------|-----------------------------------------------|
| `keygen(s)`                 | `dealer` container                            |
| `shamir_split(s[d], ...)`   | `dealer` distributes via `POST /store_shares` |
| `partial_decrypt(share, u)` | each `sh*` container via `POST /partial_decrypt` |
| `shamir_reconstruct(...)`   | `coordinator` container                       |
| `fprintf(fp, ...)`          | `coordinator` writes `/data/results.csv`      |

**Unchanged files:** `lagrange.c`, `shamir.c`, `toy_crypto.c`, `params.h`

## Architecture

```
                       POST /store_shares (x, share_vec)
 ┌────────┐  ──────────────────────────────────────────►  ┌─────┐
 │        │                                               │ sh1 │  holds share-vec for party 1
 │ dealer │  ──────────────────────────────────────────►  │ sh2 │  holds share-vec for party 2
 │keygen()│  ──────────────────────────────────────────►  │ sh3 │  ...
 │split() │  ──────────────────────────────────────────►  │ sh4 │
 └────────┘  ──────────────────────────────────────────►  │ sh5 │
                                                           └──┬──┘
                       POST /partial_decrypt {u}             │
 ┌─────────────┐  ◄──────────────────────────────────────────┘
 │ coordinator │       GET partial response {x, partial}
 │  encrypt()  │──────────────────────────────────────────►  sh*
 │reconstruct()│
 │  CSV output │
 └─────────────┘
```

## Quick start

```bash
# 1. Install Docker (one-time)
sudo ./setup_ubuntu.sh
newgrp docker

# 2. Create output dir and run
mkdir -p data
docker compose up --build

# Results appear in ./data/results.csv
```

## Experiments

```bash
# Any 3-of-5 subset — should always work
docker compose run -e USE_HOSTS=sh1,sh3,sh5 coordinator
docker compose run -e USE_HOSTS=sh2,sh4,sh5 coordinator

# Below threshold — reconstruction will produce garbage
docker compose run -e USE_HOSTS=sh1,sh2 coordinator

# More trials
docker compose run -e N_TRIALS=1000 coordinator

# Rebuild after editing params.h
docker compose down
docker compose up --build
```

## Tuning params.h

| Param        | Default | Effect                                  |
|--------------|---------|-----------------------------------------|
| `Q`          | 97      | Field modulus                           |
| `VECTOR_DIM` | 4       | LWE secret dimension                   |
| `N_PARTIES`  | 5       | Total shareholders                     |
| `THRESHOLD`  | 3       | Minimum shares to reconstruct          |
| `NOISE_BOUND`| 2       | Encryption noise range `[-B, B]`       |

## File map

```
shamir-docker/
├── Dockerfile
├── docker-compose.yml
├── setup_ubuntu.sh
├── data/                    ← results.csv appears here after run
└── src/
    ├── params.h             ← Q, VECTOR_DIM, N_PARTIES, THRESHOLD, NOISE_BOUND
    ├── lagrange.c/.h        ← YOUR FILE — unchanged
    ├── shamir.c/.h          ← YOUR FILE — unchanged
    ├── toy_crypto.c/.h      ← YOUR FILE — unchanged
    ├── dealer.c             ← new: keygen + split + HTTP distribute
    ├── shareholder.c        ← new: HTTP server, calls partial_decrypt()
    ├── coordinator.c        ← new: experiment loop from main.c over HTTP
    └── Makefile
```
