# Honeypot HTTP - image durcie (B12)
FROM python:3.12-slim

RUN pip install --no-cache-dir "fastapi>=0.110" "uvicorn[standard]>=0.29" "jsonschema>=4.21"
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin appuser

# /logs (volume nomme partage) doit etre accessible en ecriture par l'uid 1000
# pour journaliser les evenements (sinon root:root -> Permission denied).
RUN mkdir -p /logs && chown 1000:1000 /logs

WORKDIR /app
COPY honeypots/ ./honeypots/
COPY schemas/ ./schemas/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HONEYPOT_LOG_DIR=/logs \
    HTTP_PORT=8080

USER 1000:1000
EXPOSE 8080
CMD ["python", "-m", "honeypots.http.server"]
