# ── Build stage ───────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make \
        libmicrohttpd-dev \
        libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/ ./
RUN make

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        libmicrohttpd12 libcurl4 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /data
WORKDIR /app
COPY --from=builder /build/shareholder  .
COPY --from=builder /build/dealer       .
COPY --from=builder /build/coordinator  .

EXPOSE 8080
CMD ["./shareholder", "8080"]
