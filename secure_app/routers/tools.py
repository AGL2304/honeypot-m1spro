"""Route /tools/ping — anti command-injection (J1 / A03, CWE-78).

Reproduit l'exemple canonique du cours, en version SÉCURISÉE :
  1. Validation stricte de l'entrée (IP valide OU hostname whitelisté).
  2. `subprocess.run` avec **liste d'arguments** et **shell=False** : l'entrée
     ne peut jamais être interprétée par un shell.
  3. Binaire résolu par chemin absolu (`shutil.which`), timeout borné.

Anti-pattern interdit (vu en J1) :
    os.system(f"ping -c 4 {host}")          # ❌ RCE: host="x; rm -rf /"
    subprocess.run(cmd, shell=True)         # ❌ shell interprète les métacaractères
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess  # nosec B404 (usage durci : liste d'args, shell=False, binaire absolu)
import sys

from fastapi import APIRouter, HTTPException, status

from ..dependencies import CurrentUser
from ..schemas import PingIn
from ..validators import is_safe_hostname

router = APIRouter(prefix="/tools", tags=["tools"])


def _is_valid_target(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return is_safe_hostname(host)


@router.post("/ping")
def ping(payload: PingIn, user: CurrentUser) -> dict[str, object]:
    """Ping sécurisé d'un hôte (authentification requise).

    400 si l'entrée n'est pas une cible légitime ; l'auth évite d'offrir un
    primitive réseau (scan/SSRF aveugle) à un anonyme.
    """
    host = payload.host
    if not _is_valid_target(host):
        # On rejette AVANT toute exécution : l'injection n'atteint jamais l'OS.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Hôte invalide."
        )

    ping_bin = shutil.which("ping")
    if ping_bin is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="ping indisponible."
        )

    # Drapeau « nombre de paquets » selon l'OS (-n sous Windows, -c ailleurs).
    count_flag = "-n" if sys.platform.startswith("win") else "-c"
    args = [ping_bin, count_flag, "2", host]  # liste d'arguments -> pas de shell

    try:
        result = subprocess.run(  # noqa: S603  # nosec B603 (args validés, binaire absolu, shell=False)
            args,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="Ping timeout."
        ) from None

    return {"host": host, "returncode": result.returncode, "reachable": result.returncode == 0}
