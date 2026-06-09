# secure_app - API REST sécurisée (fil rouge SDLC). Image durcie (B12).
FROM python:3.12-slim

# iputils-ping : binaire requis par /tools/ping (démo anti command-injection).
# Installé proprement puis cache apt purgé (image fine).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "fastapi>=0.110" "uvicorn[standard]>=0.29" "pydantic>=2.6" \
    "argon2-cffi>=23.1" "pyjwt>=2.8" "pyotp>=2.9"

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin appuser

# Répertoire de données accessible en écriture par l'uid 1000 : la base SQLite
# y est créée (le rootfs est monté read-only en production -> cf. compose).
RUN mkdir -p /data && chown 1000:1000 /data

WORKDIR /app
COPY secure_app/ ./secure_app/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    SECURE_APP_ENV=prod \
    SECURE_APP_DB_PATH=/data/secure_app.db

USER 1000:1000
EXPOSE 8000

# uvicorn sert la fabrique d'app (secure_app.main:app). Un seul worker : l'état
# (rate limiter, blacklist JWT) est en mémoire de process (Redis en multi-worker).
CMD ["uvicorn", "secure_app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
