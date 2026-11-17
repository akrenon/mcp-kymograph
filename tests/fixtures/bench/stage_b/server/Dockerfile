FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
WORKDIR /app
COPY stage_b_server.py /app/stage_b_server.py
ENTRYPOINT ["python", "-B", "/app/stage_b_server.py"]
