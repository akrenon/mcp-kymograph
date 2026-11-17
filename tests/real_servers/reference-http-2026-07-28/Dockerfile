# A small server on the official Python SDK (mcp 2.3.0), Streamable HTTP, protocol 2026-07-28.
# Everything installed is pinned by version and hash (requirements.txt); nothing but PyPI is
# fetched. Built by tests/real_servers/build.py.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-deps --only-binary :all: --require-hashes \
        -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin server

COPY server.py /app/server.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8000
ENTRYPOINT ["python", "/app/server.py"]
