FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

# nft and ip, nothing else: the helper loads and reads the counting rules in the server's
# namespace and sets its default route without a gateway.
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 && rm -rf /var/lib/apt/lists/*
