FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends chromium python3 fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --home-dir /work --uid 1000 check
USER check
WORKDIR /work
