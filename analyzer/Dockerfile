# Analyzer (API + shipper) - image durcie (B12)
FROM python:3.12-slim

RUN pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn[standard]>=0.29" "jsonschema>=4.21" \
    "psycopg[binary]>=3.1" "httpx>=0.27" "maxminddb>=2.6"
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin appuser

# Le cache SQLite d'AbuseIPDB s'écrit dans /data (volume enrich_data) et le
# shipper (qui reutilise cette image) lit/ecrit /logs. Créer les dossiers et les
# attribuer à l'uid 1000 pour que les volumes nommés héritent de cette propriété
# à leur création (sinon root:root -> écriture refusée).
RUN mkdir -p /data /logs && chown 1000:1000 /data /logs

WORKDIR /app
COPY analyzer/ ./analyzer/
COPY honeypots/common/ ./honeypots/common/
COPY honeypots/__init__.py ./honeypots/__init__.py
COPY schemas/ ./schemas/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HONEYPOT_LOG_DIR=/logs

USER 1000:1000
EXPOSE 8000
CMD ["python", "-m", "analyzer.api"]
