# The sandbox's own containers: the sink, the one-shot helper, the reader and the positive
# probe. python3 runs their scripts (mounted read-only from this package at run time, so they
# are part of the tool's content digest); nftables and iproute2 are what the helper and the
# reader need. Nothing else. The target never runs in this image.
#
# Build:  docker build -t mcp-kymograph-sandbox:1 src/mcp_kymograph/sandbox
FROM python@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables iproute2 \
 && rm -rf /var/lib/apt/lists/*
