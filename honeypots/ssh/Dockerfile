# Honeypot SSH - image durcie (B12)
FROM python:3.12-slim AS base

# Dépendances minimales, pas de cache pip
RUN pip install --no-cache-dir "asyncssh>=2.14" "jsonschema>=4.21"

# Utilisateur non-root (principe de moindre privilège, NIST SP 800-190)
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app
COPY honeypots/ ./honeypots/
COPY schemas/ ./schemas/

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HONEYPOT_LOG_DIR=/logs \
    SSH_HOST_KEY=/keys/ssh_host_key \
    SSH_PORT=2222

USER 1000:1000
EXPOSE 2222
CMD ["python", "-m", "honeypots.ssh.server"]
