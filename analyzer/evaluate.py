"""Évaluation quantitative du classifier comportemental (B14).

Le cahier des charges exige une *matrice de confusion mesurée* et une *précision
> 85 %* sur les sessions de type Hydra (bruteforcer) et Nikto (scanner). Ce module :

1. génère un jeu de sessions étiquetées, déterministe (seed fixe), représentatif
   des 4 profils (scanner_legitime, bruteforcer, bot, humain) ;
2. fait tourner `BehaviorClassifier.classify_session()` dessus ;
3. construit la matrice de confusion et calcule précision / rappel / F1 par profil
   ainsi que l'exactitude globale.

Usage CLI (rapport lisible au tableau pour la démo) ::

    python -m analyzer.evaluate

Le test `tests/test_classifier_metrics.py` rejoue ce module et vérifie le seuil
de 85 % en CI (la métrique est donc non-régressive, pas juste un one-shot).
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

from .classifier import BehaviorClassifier

LABELS: list[str] = ["scanner_legitime", "bruteforcer", "bot", "humain"]
_BASE = datetime(2026, 6, 8, 10, 0, 0, tzinfo=UTC)

# Commandes plausibles pour les sessions « humain » (variété + contexte).
_HUMAN_CMDS = [
    "whoami", "id", "ls -la", "pwd", "uname -a", "cat /etc/passwd", "ps aux",
    "netstat -an", "cd /var/www/html", "cat .env", "history", "wget http://x/y.sh",
    "df -h", "cat ~/.ssh/id_rsa", "sudo su", "crontab -l",
]

Session = list[dict[str, Any]]


def _ts(ms: float) -> str:
    return (_BASE + timedelta(milliseconds=ms)).isoformat()


# --------------------------------------------------------------------------- #
# Générateurs de sessions étiquetées (un par profil)
# --------------------------------------------------------------------------- #

def _gen_bruteforcer(rng: random.Random) -> Session:
    """Hydra-like : 25-70 tentatives, mots de passe distincts, peu/pas de commandes."""
    n = rng.randint(25, 70)
    t = 0.0
    ev: Session = []
    for i in range(n):
        ev.append({
            "timestamp": _ts(t),
            "event_type": "auth_attempt",
            "username": rng.choice(["root", "admin", "user", "test", "oracle"]),
            "password": f"pw{i}-{rng.randint(0, 99999)}",
        })
        t += rng.uniform(60, 900)
    return ev


def _gen_bot(rng: random.Random) -> Session:
    """Bot IoT-like : connexion éclair, 1-2 auth, aucune interaction, < 5 s."""
    t = 0.0
    ev: Session = [{"timestamp": _ts(t), "event_type": "connect"}]
    t += rng.uniform(40, 150)
    for _ in range(rng.randint(1, 2)):
        ev.append({
            "timestamp": _ts(t),
            "event_type": "auth_attempt",
            "username": "root",
            "password": rng.choice(["root", "admin", "123456", "admin123"]),
        })
        t += rng.uniform(40, 150)
    ev.append({"timestamp": _ts(t), "event_type": "disconnect"})
    return ev


def _gen_scanner(rng: random.Random) -> Session:
    """Scanner connu (GreyNoise RIOT) : connexion enrichie known_scanner, banner-grab."""
    t = 0.0
    ev: Session = [{
        "timestamp": _ts(t),
        "event_type": "connect",
        "enrichment": {"known_scanner": True},
    }]
    t += rng.uniform(20, 120)
    if rng.random() < 0.5:
        ev.append({
            "timestamp": _ts(t),
            "event_type": "auth_attempt",
            "username": "root",
            "password": "",
        })
        t += rng.uniform(20, 120)
    ev.append({"timestamp": _ts(t), "event_type": "disconnect"})
    return ev


def _gen_humain(rng: random.Random) -> Session:
    """Opérateur humain : login réussi, 4-9 commandes variées, rythme irrégulier lent."""
    t = 0.0
    ev: Session = [{"timestamp": _ts(t), "event_type": "auth_success", "username": "admin"}]
    t += rng.uniform(1200, 4000)
    for cmd in rng.sample(_HUMAN_CMDS, rng.randint(4, 9)):
        ev.append({"timestamp": _ts(t), "event_type": "command", "command": cmd})
        t += rng.uniform(1200, 5000)
    return ev


_GENERATORS = {
    "scanner_legitime": _gen_scanner,
    "bruteforcer": _gen_bruteforcer,
    "bot": _gen_bot,
    "humain": _gen_humain,
}


# --------------------------------------------------------------------------- #
# Dataset, matrice de confusion, métriques
# --------------------------------------------------------------------------- #

def build_labeled_dataset(per_class: int = 40, seed: int = 1337) -> list[tuple[str, Session]]:
    """Retourne `per_class` sessions par profil, étiquetées et mélangées (seed fixe)."""
    rng = random.Random(seed)
    data: list[tuple[str, Session]] = []
    for label in LABELS:
        gen = _GENERATORS[label]
        for _ in range(per_class):
            data.append((label, gen(rng)))
    rng.shuffle(data)
    return data


def confusion_matrix(
    dataset: list[tuple[str, Session]],
    clf: BehaviorClassifier | None = None,
) -> dict[str, dict[str | None, int]]:
    """Matrice {vrai_profil: {profil_prédit (ou None): compte}}."""
    clf = clf or BehaviorClassifier()
    cols: list[str | None] = [*LABELS, None]
    matrix: dict[str, dict[str | None, int]] = {t: dict.fromkeys(cols, 0) for t in LABELS}
    for true_label, events in dataset:
        pred = clf.classify_session(events)
        matrix[true_label][pred] += 1
    return matrix


def metrics(matrix: dict[str, dict[str | None, int]]) -> dict[str, dict[str, float]]:
    """Précision / rappel / F1 par profil + exactitude globale."""
    res: dict[str, dict[str, float]] = {}
    for label in LABELS:
        tp = matrix[label][label]
        true_total = sum(matrix[label].values())
        pred_total = sum(matrix[t][label] for t in LABELS)
        precision = tp / pred_total if pred_total else 0.0
        recall = tp / true_total if true_total else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        res[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": float(true_total),
        }
    total = sum(sum(row.values()) for row in matrix.values())
    correct = sum(matrix[lbl][lbl] for lbl in LABELS)
    res["overall"] = {"accuracy": correct / total if total else 0.0, "support": float(total)}
    return res


# --------------------------------------------------------------------------- #
# Rapport texte (démo / docs)
# --------------------------------------------------------------------------- #

def format_report(
    matrix: dict[str, dict[str | None, int]],
    m: dict[str, dict[str, float]],
) -> str:
    cols = [*LABELS, "None"]
    width = max(len(c) for c in [*LABELS, *cols]) + 2
    lines = ["Matrice de confusion (lignes = vrai profil, colonnes = prédiction)", ""]
    header = " " * width + "".join(c[:width - 1].rjust(width) for c in cols)
    lines.append(header)
    for true_label in LABELS:
        row = true_label.ljust(width)
        for col in [*LABELS, None]:
            row += str(matrix[true_label][col]).rjust(width)
        lines.append(row)

    lines += ["", "Métriques par profil :", ""]
    lines.append("profil".ljust(width) + "précision".rjust(11) + "rappel".rjust(10) + "f1".rjust(8))
    for label in LABELS:
        d = m[label]
        lines.append(
            label.ljust(width)
            + f"{d['precision']:.2%}".rjust(11)
            + f"{d['recall']:.2%}".rjust(10)
            + f"{d['f1']:.2f}".rjust(8)
        )
    lines += ["", f"Exactitude globale : {m['overall']['accuracy']:.2%} "
                  f"sur {int(m['overall']['support'])} sessions"]
    return "\n".join(lines)


def main() -> None:
    dataset = build_labeled_dataset()
    matrix = confusion_matrix(dataset)
    m = metrics(matrix)
    print(format_report(matrix, m))


if __name__ == "__main__":
    main()
