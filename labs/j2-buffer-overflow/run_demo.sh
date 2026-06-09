#!/usr/bin/env bash
# Démo J2 — sécurité mémoire. Compile et compare le comportement face à un
# débordement de pile. À lancer sous Linux/WSL : bash run_demo.sh
set -u
cd "$(dirname "$0")"

PAYLOAD="$(python3 -c 'print("A"*64)')"

make all >/dev/null

echo "================ J2 — Buffer overflow : démonstration ================"

echo
echo "[1] Binaire NON durci — entrée normale (mot de passe correct)"
./vuln_nomit "open sesame"; echo "    rc=$?"

echo
echo "[2] Binaire NON durci — OVERFLOW (64x 'A', AUCUN mot de passe)"
echo "    -> la variable 'authenticated' est écrasée sur la pile :"
./vuln_nomit "$PAYLOAD"; echo "    rc=$?   (ACCES ACCORDE = exploit réussi)"

echo
echo "[3] Même source AVEC canari de pile — même overflow"
echo "    -> la corruption est détectée à la sortie de fonction :"
./vuln_canary "$PAYLOAD"; echo "    rc=$?   (134 = SIGABRT, *** stack smashing detected ***)"

echo
echo "[4] Version CORRIGÉE (bornage) + durcissement — même overflow"
./hardened "$PAYLOAD"; echo "    rc=$?   (Acces refuse, aucun crash : entrée tronquée proprement)"

echo
echo "Conclusion : le bornage du code (4) supprime le bug à la racine ; le canari"
echo "(3) est un filet de sécurité qui transforme un RCE potentiel en simple crash."
echo "Un langage memory-safe (Python/Rust/Go) élimine cette classe entière —"
echo "c'est pourquoi secure_app (FastAPI/Python) n'y est pas exposé."
