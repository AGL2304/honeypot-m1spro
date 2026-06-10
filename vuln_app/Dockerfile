# vuln_app — image de DÉMO volontairement vulnérable (M1SPRO).
# ⚠️ NON DURCIE EXPRÈS (root, pas de read-only, pas de cap_drop) : c'est le
#    contraste avec l'image durcie de secure_app. NE PAS exposer en prod.
FROM python:3.12-slim

WORKDIR /app

# iputils-ping : nécessaire pour démontrer la command injection sur /tools/ping.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY app_telemetry.py .

EXPOSE 8002

# Tourne en root, sans aucune option de sécurité (volontaire).
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
