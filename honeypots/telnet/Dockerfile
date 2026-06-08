# Honeypot Telnet - image durcie (B12)
FROM python:3.12-slim

RUN pip install --no-cache-dir "jsonschema>=4.21"
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY honeypots/ ./honeypots/
COPY schemas/ ./schemas/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HONEYPOT_LOG_DIR=/logs \
    TELNET_PORT=2323

USER 1000:1000
EXPOSE 2323
CMD ["python", "-m", "honeypots.telnet.server"]
