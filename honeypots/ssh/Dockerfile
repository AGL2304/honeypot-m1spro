# Honeypot SSH - image durcie (B12)
FROM python:3.12-slim AS base

# Dépendances minimales, pas de cache pip
RUN pip install --no-cache-dir "asyncssh>=2.14" "jsonschema>=4.21"

# Utilisateur non-root (principe de moindre privilège, NIST SP 800-190)
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin appuser

# La cle hote SSH s'ecrit dans /keys (volume nomme sshkeys). Creer le dossier
# et l'attribuer a l'uid 1000 pour que le volume herite de cette propriete a sa
# creation (sinon root:root -> PermissionError sur /keys/ssh_host_key).
RUN mkdir -p /keys && chown 1000:1000 /keys

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
