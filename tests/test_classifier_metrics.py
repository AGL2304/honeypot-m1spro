"""Métriques du classifier (B14) : matrice de confusion + précision > 85 %.

Rejoue analyzer/evaluate.py en CI pour garantir que la précision reste au-dessus
du seuil exigé par le cahier des charges (Hydra → bruteforcer, Nikto → scanner).
"""

from __future__ import annotations

from analyzer.evaluate import (
    LABELS,
    build_labeled_dataset,
    confusion_matrix,
    metrics,
)

_THRESHOLD = 0.85


def _metrics():
    return metrics(confusion_matrix(build_labeled_dataset()))


def test_overall_accuracy_above_threshold():
    assert _metrics()["overall"]["accuracy"] >= _THRESHOLD


def test_precision_per_profile_above_threshold():
    m = _metrics()
    for label in LABELS:
        assert m[label]["precision"] >= _THRESHOLD, (
            f"précision {label} = {m[label]['precision']:.2%} < {_THRESHOLD:.0%}"
        )


def test_hydra_and_nikto_recall():
    # Hydra = bruteforcer, Nikto/scan = scanner_legitime : rappel élevé attendu.
    m = _metrics()
    assert m["bruteforcer"]["recall"] >= _THRESHOLD
    assert m["scanner_legitime"]["recall"] >= _THRESHOLD
